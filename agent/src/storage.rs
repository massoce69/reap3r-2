// ─────────────────────────────────────────────────────────────
// storage.rs – SQLite-backed local durable storage
//   • Job queue  (pending/running/done/failed)
//   • Heartbeat buffer (offline replay)
//   • Config snapshots
//   • Module manifests
//   • Audit log
//   • AES-256-GCM encryption at rest for secrets
// ─────────────────────────────────────────────────────────────
use anyhow::{Result, Context};
use chrono::Utc;
use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};
use tracing::debug;

use crate::agent::AgentConfig;
use crate::protocol::*;

// ═══════════════════════════════════════════════════════════════
//  Database wrapper (thread-safe)
// ═══════════════════════════════════════════════════════════════
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open(config: &AgentConfig) -> Result<Self> {
        let db_path = if config.storage.db_path.is_empty() {
            crate::platform::get_db_path()
        } else {
            std::path::PathBuf::from(&config.storage.db_path)
        };

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)
            .with_context(|| format!("opening SQLite at {}", db_path.display()))?;

        // WAL mode for concurrent reads
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;

        let db = Self { conn: Arc::new(Mutex::new(conn)) };
        db.init_schema()?;
        Ok(db)
    }

    /// Open an in-memory database (for tests)
    #[cfg(test)]
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn: Arc::new(Mutex::new(conn)) };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    // ── Job Queue ────────────────────────────────────────────

    /// Enqueue a new job from the server
    pub fn enqueue_job(&self, job: &JobAssignment) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO queue_jobs
             (id, job_type, payload, status, priority, created_at, max_retries)
             VALUES (?1, ?2, ?3, 'pending', ?4, ?5, 3)",
            params![
                job.job_id,
                serde_json::to_string(&job.job_type)?,
                serde_json::to_string(&job.payload)?,
                job.priority,
                Utc::now().to_rfc3339(),
            ],
        )?;
        debug!(job_id = %job.job_id, "Job enqueued");
        Ok(())
    }

    /// Get next pending job (highest priority first)
    pub fn dequeue_job(&self) -> Result<Option<JobAssignment>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, job_type, payload, priority, created_at
             FROM queue_jobs WHERE status = 'pending'
             ORDER BY priority DESC, created_at ASC LIMIT 1"
        )?;
        let result = stmt.query_row([], |row| {
            let id: String = row.get(0)?;
            let jt: String = row.get(1)?;
            let pl: String = row.get(2)?;
            let pr: u8     = row.get(3)?;
            let ca: String = row.get(4)?;
            Ok((id, jt, pl, pr, ca))
        });

        match result {
            Ok((id, jt, pl, pr, ca)) => {
                // Mark as running
                conn.execute(
                    "UPDATE queue_jobs SET status = 'running', started_at = ?1 WHERE id = ?2",
                    params![Utc::now().to_rfc3339(), id],
                )?;
                let job = JobAssignment {
                    job_id: id,
                    job_type: serde_json::from_str(&jt)?,
                    payload: serde_json::from_str(&pl)?,
                    priority: pr,
                    timeout_secs: 300, // default
                    created_at: chrono::DateTime::parse_from_rfc3339(&ca)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                };
                Ok(Some(job))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Mark a job as completed
    pub fn complete_job(&self, job_id: &str, result: &JobResult) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE queue_jobs SET status = ?1, completed_at = ?2, result = ?3, exit_code = ?4
             WHERE id = ?5",
            params![
                result.status.to_string(),
                Utc::now().to_rfc3339(),
                serde_json::to_string(result)?,
                result.exit_code,
                job_id,
            ],
        )?;
        Ok(())
    }

    /// Count pending jobs
    pub fn count_pending_jobs(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM queue_jobs WHERE status = 'pending'",
            [], |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Clean old completed jobs (retention)
    pub fn cleanup_old_jobs(&self, retention_hours: i64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let cutoff = (Utc::now() - chrono::Duration::hours(retention_hours)).to_rfc3339();
        let deleted = conn.execute(
            "DELETE FROM queue_jobs WHERE status IN ('success','failed','cancelled')
             AND completed_at < ?1",
            params![cutoff],
        )?;
        Ok(deleted)
    }

    // ── Heartbeat Buffer ─────────────────────────────────────

    /// Buffer a heartbeat for later sending
    pub fn buffer_heartbeat(&self, payload: &HeartbeatPayload) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO heartbeat_buffer (payload, created_at)
             VALUES (?1, ?2)",
            params![serde_json::to_string(payload)?, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Get unsent heartbeats (for offline replay)
    pub fn get_unsent_heartbeats(&self, limit: usize) -> Result<Vec<(i64, HeartbeatPayload)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, payload FROM heartbeat_buffer
             WHERE sent = 0 ORDER BY id ASC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let id: i64    = row.get(0)?;
            let pl: String = row.get(1)?;
            Ok((id, pl))
        })?;
        let mut result = Vec::new();
        for r in rows {
            let (id, pl) = r?;
            if let Ok(hb) = serde_json::from_str(&pl) {
                result.push((id, hb));
            }
        }
        Ok(result)
    }

    /// Mark heartbeats as sent
    pub fn mark_heartbeats_sent(&self, ids: &[i64]) -> Result<()> {
        if ids.is_empty() { return Ok(()); }
        let conn = self.conn.lock().unwrap();
        let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "UPDATE heartbeat_buffer SET sent = 1 WHERE id IN ({})",
            placeholders.join(",")
        );
        let params: Vec<Box<dyn rusqlite::types::ToSql>> =
            ids.iter().map(|id| Box::new(*id) as Box<dyn rusqlite::types::ToSql>).collect();
        conn.execute(&sql, rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())))?;
        Ok(())
    }

    /// Count unsent heartbeats
    pub fn count_unsent_heartbeats(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM heartbeat_buffer WHERE sent = 0",
            [], |row| row.get(0),
        )?;
        Ok(count)
    }

    // ── Config Snapshots ─────────────────────────────────────

    pub fn save_config(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO config_snapshots (key, value, updated_at)
             VALUES (?1, ?2, ?3)",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_config(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        match conn.query_row(
            "SELECT value FROM config_snapshots WHERE key = ?1",
            params![key], |row| row.get::<_, String>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    // ── Module Manifests ─────────────────────────────────────

    pub fn save_module_manifest(&self, name: &str, version: &str, hash: &str, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO module_manifests (name, version, hash, status, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![name, version, hash, status, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_module_manifests(&self) -> Result<Vec<(String, String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT name, version, hash, status FROM module_manifests"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // ── Audit Log ────────────────────────────────────────────

    pub fn log_audit(&self, event: &AuditEvent) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_log (event_type, agent_id, operator_id, details, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                serde_json::to_string(&event.event_type)?,
                event.agent_id,
                event.operator_id,
                serde_json::to_string(&event.details)?,
                event.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    // ── Secrets (encrypted storage) ──────────────────────────

    #[allow(dead_code)]
    pub fn save_secret(&self, key: &str, encrypted_value: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO secrets (key, value, updated_at)
             VALUES (?1, ?2, ?3)",
            params![key, encrypted_value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        match conn.query_row(
            "SELECT value FROM secrets WHERE key = ?1",
            params![key], |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  AES-256-GCM encryption at rest
// ═══════════════════════════════════════════════════════════════
pub struct Encryption {
    key: [u8; 32],
}

impl Encryption {
    /// Derive a key from machine-id + salt (deterministic per machine)
    pub fn from_machine_id(machine_id: &str) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(machine_id.as_bytes());
        hasher.update(b"massvision-local-encryption-v2");
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        Self { key }
    }

    /// Encrypt plaintext → nonce(12) || ciphertext || tag(16)
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use aes_gcm::aead::{Aead, KeyInit};
        use rand::RngCore;

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt nonce(12) || ciphertext || tag(16) → plaintext
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use aes_gcm::aead::{Aead, KeyInit};

        if data.len() < 12 {
            anyhow::bail!("ciphertext too short");
        }
        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&data[..12]);
        let plaintext = cipher.decrypt(nonce, &data[12..])
            .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;
        Ok(plaintext)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Schema
// ═══════════════════════════════════════════════════════════════
const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS queue_jobs (
    id          TEXT PRIMARY KEY,
    job_type    TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending',
    priority    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL,
    started_at  TEXT,
    completed_at TEXT,
    result      TEXT,
    exit_code   INTEGER,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON queue_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_priority ON queue_jobs(priority DESC, created_at ASC);

CREATE TABLE IF NOT EXISTS heartbeat_buffer (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    payload    TEXT    NOT NULL,
    sent       INTEGER DEFAULT 0,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_hb_sent ON heartbeat_buffer(sent);

CREATE TABLE IF NOT EXISTS config_snapshots (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS module_manifests (
    name       TEXT PRIMARY KEY,
    version    TEXT NOT NULL,
    hash       TEXT NOT NULL,
    status     TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    operator_id TEXT,
    details     TEXT,
    timestamp   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);

CREATE TABLE IF NOT EXISTS secrets (
    key        TEXT PRIMARY KEY,
    value      BLOB NOT NULL,
    updated_at TEXT NOT NULL
);
"#;

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AgentConfig {
        AgentConfig {
            server: crate::agent::ServerConfig {
                url: "https://test".into(),
                ws_url: "wss://test".into(),
                api_version: "v2".into(),
            },
            agent: crate::agent::AgentSection {
                data_dir: String::new(),
                log_level: "info".into(),
                machine_id: "test-machine".into(),
            },
            heartbeat: crate::agent::HeartbeatConfig {
                interval_secs: 60,
                jitter_secs: 10,
                max_backoff_secs: 300,
            },
            update: crate::agent::UpdateConfig {
                staging_dir: String::new(),
                auto_update: true,
                rollback_on_failure: true,
            },
            security: crate::agent::SecurityConfig {
                verify_signatures: true,
                hmac_algorithm: "sha256".into(),
                enrollment_token: String::new(),
            },
            modules: crate::agent::ModulesConfig {
                metrics_enabled: true,
                metrics_interval_secs: 60,
                script_runner_enabled: true,
                inventory_enabled: true,
                inventory_interval_secs: 3600,
                remote_shell_enabled: true,
                webcam_enabled: false,
                webcam_interval_secs: 300,
                webcam_default_camera: 0,
                webcam_width: 1280,
                webcam_height: 720,
                webcam_quality: 85,
            },
            storage: crate::agent::StorageConfig {
                db_path: ":memory:".into(),
                encrypt_at_rest: false,
                max_queue_size: 1000,
                queue_retention_hours: 72,
            },
        }
    }

    #[test]
    fn test_job_queue() {
        let db = Database::open_memory().unwrap();
        let job = JobAssignment {
            job_id: "j1".into(),
            job_type: JobType::RunScript,
            payload: serde_json::json!({"test": true}),
            timeout_secs: 60,
            priority: 5,
            created_at: Utc::now(),
        };
        db.enqueue_job(&job).unwrap();
        assert_eq!(db.count_pending_jobs().unwrap(), 1);

        let dequeued = db.dequeue_job().unwrap();
        assert!(dequeued.is_some());
        assert_eq!(dequeued.unwrap().job_id, "j1");
        assert_eq!(db.count_pending_jobs().unwrap(), 0);
    }

    #[test]
    fn test_encryption_roundtrip() {
        let enc = Encryption::from_machine_id("test-machine-123");
        let plaintext = b"super secret agent token";
        let encrypted = enc.encrypt(plaintext).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

// ─────────────────────────────────────────────────────────────
// security.rs – Enrollment, HMAC signing, tamper detection,
//               token management, anti-spoof
// ─────────────────────────────────────────────────────────────
use anyhow::{Result, Context};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{info, warn};

use crate::protocol::*;
use crate::platform;
use crate::storage::Encryption;

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_CONFIG_TOML: &str = include_str!("../config.toml");

fn derive_ws_url(server_url: &str) -> String {
    let base = server_url.trim_end_matches('/');
    // Mirror the server's expected WS path: /ws/agents
    let ws_base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if base.starts_with("wss://") || base.starts_with("ws://") {
        base.to_string()
    } else {
        // Best effort (server_url is expected to be http(s)://...)
        base.to_string()
    };
    format!("{}/ws/agents", ws_base.trim_end_matches('/'))
}

fn upsert_config(server_url: &str, machine_id: &str) -> Result<()> {
    let config_path = platform::get_config_path();
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let ws_url = derive_ws_url(server_url);

    // If config exists, update only the relevant lines. Otherwise, write a fresh default config.
    if !config_path.exists() {
        let mut content = DEFAULT_CONFIG_TOML.to_string();
        content = content.replace(
            r#"url         = "https://massvision.example.com""#,
            &format!(r#"url         = "{}""#, server_url),
        );
        content = content.replace(
            r#"ws_url      = "wss://massvision.example.com/ws/agents""#,
            &format!(r#"ws_url      = "{}""#, ws_url),
        );
        content = content.replace(
            r#"machine_id     = """#,
            &format!(r#"machine_id     = "{}""#, machine_id),
        );
        std::fs::write(&config_path, content)?;
        return Ok(());
    }

    let existing = std::fs::read_to_string(&config_path)?;
    let mut current_section: Option<&str> = None;
    let mut out = String::with_capacity(existing.len() + 64);
    for line in existing.lines() {
        let t = line.trim();
        if t.starts_with('[') && t.ends_with(']') {
            current_section = Some(t.trim_matches(&['[', ']'][..]));
            out.push_str(line);
            out.push('\n');
            continue;
        }

        match current_section {
            Some("server") if t.starts_with("url") => {
                out.push_str(&format!(r#"url         = "{}""#, server_url));
                out.push('\n');
                continue;
            }
            Some("server") if t.starts_with("ws_url") => {
                out.push_str(&format!(r#"ws_url      = "{}""#, ws_url));
                out.push('\n');
                continue;
            }
            Some("agent") if t.starts_with("machine_id") => {
                out.push_str(&format!(r#"machine_id     = "{}""#, machine_id));
                out.push('\n');
                continue;
            }
            _ => {}
        }

        out.push_str(line);
        out.push('\n');
    }
    std::fs::write(&config_path, out)?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Enrollment
// ═══════════════════════════════════════════════════════════════

/// One-time enrollment with the MassVision server.
/// Sends machine attestation, receives agent_id + agent_token.
pub async fn enroll(enrollment_token: &str, server_url: &str) -> Result<()> {
    info!("Starting enrollment with {server_url}");

    let machine_id = platform::get_machine_id();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let os_info = platform::get_os_info();

    let payload = EnrollmentPayload {
        enrollment_token: enrollment_token.to_string(),
        machine_id: machine_id.clone(),
        hostname,
        os_info,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let url = format!("{}/api/agents-v2/enroll", server_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .context("enrollment HTTP request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Enrollment failed: HTTP {status} – {body}");
    }

    let enrollment: EnrollmentResponse = resp.json().await
        .context("parsing enrollment response")?;

    // Persist credentials securely
    let data_dir = platform::get_data_dir();
    std::fs::create_dir_all(&data_dir)?;

    // Save agent_id in config snapshot
    let enc = Encryption::from_machine_id(&machine_id);
    let encrypted_token = enc.encrypt(enrollment.agent_token.as_bytes())?;

    // Write a minimal credentials file
    let creds = serde_json::json!({
        "agent_id": enrollment.agent_id,
        "machine_id": machine_id,
        "server_url": server_url,
        "server_public_key": enrollment.server_public_key,
    });
    let creds_path = data_dir.join("credentials.json");
    std::fs::write(&creds_path, serde_json::to_string_pretty(&creds)?)?;

    // Write encrypted token separately
    let token_path = data_dir.join("agent_token.enc");
    std::fs::write(&token_path, &encrypted_token)?;

    // Ensure config.toml exists and points to the right server.
    // This makes "download exe -> enroll -> install" work even if the exe is shipped alone.
    if let Err(e) = upsert_config(server_url, &machine_id) {
        warn!(error = %e, "Failed to write/update config.toml during enrollment");
    }

    info!(agent_id = %enrollment.agent_id, "Enrollment successful");
    println!("✓ Agent enrolled successfully");
    println!("  Agent ID : {}", enrollment.agent_id);
    println!("  Machine  : {}", machine_id);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Token Management
// ═══════════════════════════════════════════════════════════════

#[derive(Clone)]
pub struct TokenManager {
    agent_id: String,
    agent_token: String,
    machine_id: String,
}

impl TokenManager {
    /// Load credentials from disk
    pub fn load() -> Result<Self> {
        let data_dir = platform::get_data_dir();
        let creds_path = data_dir.join("credentials.json");
        let token_path = data_dir.join("agent_token.enc");

        if !creds_path.exists() || !token_path.exists() {
            anyhow::bail!(
                "Agent not enrolled. Run: massvision-agent enroll --token <TOKEN> --server <URL>"
            );
        }

        let creds: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&creds_path)?
        )?;
        let agent_id = creds["agent_id"].as_str().unwrap_or("").to_string();
        let machine_id = creds["machine_id"].as_str().unwrap_or("").to_string();

        // Decrypt token
        let encrypted = std::fs::read(&token_path)?;
        let enc = Encryption::from_machine_id(&machine_id);
        let decrypted = enc.decrypt(&encrypted)
            .context("decrypting agent token – possible tampering")?;
        let agent_token = String::from_utf8(decrypted)?;

        Ok(Self { agent_id, agent_token, machine_id })
    }

    pub fn agent_id(&self) -> &str { &self.agent_id }
    pub fn machine_id(&self) -> &str { &self.machine_id }

    /// Sign a payload with HMAC-SHA256 using agent_token as key.
    /// Returns a SignedEnvelope.
    pub fn sign(&self, payload: &str) -> Result<SignedEnvelope> {
        let timestamp = Utc::now().timestamp_millis();
        let nonce = uuid::Uuid::new_v4().to_string();

        // HMAC(key=agent_token, data = payload || timestamp || nonce)
        let mut mac = HmacSha256::new_from_slice(self.agent_token.as_bytes())
            .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
        mac.update(payload.as_bytes());
        mac.update(&timestamp.to_le_bytes());
        mac.update(nonce.as_bytes());
        let result = mac.finalize();
        let hmac_hex = hex::encode(result.into_bytes());

        Ok(SignedEnvelope {
            payload: payload.to_string(),
            timestamp,
            nonce,
            hmac: hmac_hex,
        })
    }

    /// Verify an incoming signed envelope
    #[allow(dead_code)]
    pub fn verify(&self, envelope: &SignedEnvelope) -> Result<bool> {
        // Check timestamp freshness (±5 min)
        let now = Utc::now().timestamp_millis();
        let age_ms = (now - envelope.timestamp).unsigned_abs();
        if age_ms > 300_000 {
            warn!("Signed message too old: {age_ms}ms");
            return Ok(false);
        }

        let mut mac = HmacSha256::new_from_slice(self.agent_token.as_bytes())
            .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
        mac.update(envelope.payload.as_bytes());
        mac.update(&envelope.timestamp.to_le_bytes());
        mac.update(envelope.nonce.as_bytes());

        let expected = hex::decode(&envelope.hmac)?;
        Ok(mac.verify_slice(&expected).is_ok())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Ed25519 Signature Verification (for updates)
// ═══════════════════════════════════════════════════════════════

pub struct SignatureVerifier {
    public_key: ed25519_dalek::VerifyingKey,
}

impl SignatureVerifier {
    /// Load server public key from credentials
    pub fn from_credentials() -> Result<Self> {
        let data_dir = platform::get_data_dir();
        let creds_path = data_dir.join("credentials.json");
        let creds: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&creds_path)?
        )?;
        let pk_hex = creds["server_public_key"].as_str().unwrap_or("");
        Self::from_hex(pk_hex)
    }

    pub fn from_hex(hex_key: &str) -> Result<Self> {
        let bytes = hex::decode(hex_key)?;
        if bytes.len() != 32 {
            anyhow::bail!("Invalid public key length: {} (expected 32)", bytes.len());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
            .context("invalid Ed25519 public key")?;
        Ok(Self { public_key })
    }

    /// Verify that `signature_hex` is a valid Ed25519 signature of `data`.
    pub fn verify(&self, data: &[u8], signature_hex: &str) -> Result<bool> {
        use ed25519_dalek::Verifier;
        let sig_bytes = hex::decode(signature_hex)?;
        if sig_bytes.len() != 64 {
            return Ok(false);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        Ok(self.public_key.verify(data, &signature).is_ok())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tamper Detection
// ═══════════════════════════════════════════════════════════════

pub struct TamperDetector;

impl TamperDetector {
    /// Verify integrity of critical agent files
    pub fn check_integrity() -> Result<Vec<String>> {
        let mut issues = Vec::new();

        // Check credentials exist
        let data_dir = platform::get_data_dir();
        if !data_dir.join("credentials.json").exists() {
            issues.push("credentials.json missing".into());
        }
        if !data_dir.join("agent_token.enc").exists() {
            issues.push("agent_token.enc missing".into());
        }

        // Check own binary hash (if manifest exists)
        let manifest_path = data_dir.join("binary_manifest.json");
        if manifest_path.exists() {
            if let Ok(manifest) = std::fs::read_to_string(&manifest_path) {
                if let Ok(m) = serde_json::from_str::<serde_json::Value>(&manifest) {
                    if let Some(expected_hash) = m["sha256"].as_str() {
                        match Self::hash_current_binary() {
                            Ok(actual) if actual != expected_hash => {
                                issues.push(format!(
                                    "Binary hash mismatch: expected={expected_hash}, actual={actual}"
                                ));
                            }
                            Err(e) => {
                                issues.push(format!("Cannot hash binary: {e}"));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // Check database
        let db_path = platform::get_db_path();
        if !db_path.exists() {
            issues.push("agent.db missing".into());
        }

        if !issues.is_empty() {
            warn!(issues = ?issues, "Tamper detection found issues");
        }

        Ok(issues)
    }

    fn hash_current_binary() -> Result<String> {
        use sha2::{Sha256, Digest};
        let exe_path = std::env::current_exe()?;
        let bytes = std::fs::read(&exe_path)?;
        let hash = Sha256::digest(&bytes);
        Ok(hex::encode(hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sign_verify() {
        let tm = TokenManager {
            agent_id: "agent-1".into(),
            agent_token: "super-secret-token-123".into(),
            machine_id: "machine-1".into(),
        };
        let payload = r#"{"type":"heartbeat","data":"test"}"#;
        let envelope = tm.sign(payload).unwrap();
        assert!(tm.verify(&envelope).unwrap());

        // Tampered payload should fail
        let mut tampered = envelope.clone();
        tampered.payload = "tampered".into();
        assert!(!tm.verify(&tampered).unwrap());
    }
}

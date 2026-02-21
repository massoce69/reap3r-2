// ─────────────────────────────────────────────────────────────
// agent.rs – Agent Core
//   • Config loading (TOML)
//   • Main event loop (orchestrator)
//   • Job dispatcher
//   • Graceful shutdown
//   • Tamper-check on startup
// ─────────────────────────────────────────────────────────────
use anyhow::{Result, Context};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{error, info, warn};

use crate::modules;
use crate::network::{ApiClient, HeartbeatScheduler, WsClient};
use crate::policy::PolicyEngine;
use crate::protocol::*;
use crate::security::{TamperDetector, TokenManager};
use crate::storage::Database;
use crate::update::UpdateManager;

// ═══════════════════════════════════════════════════════════════
//  Configuration structs (mapped from config.toml)
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    pub server: ServerConfig,
    pub agent: AgentSection,
    pub heartbeat: HeartbeatConfig,
    pub update: UpdateConfig,
    pub security: SecurityConfig,
    pub modules: ModulesConfig,
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub url: String,
    pub ws_url: String,
    pub api_version: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AgentSection {
    pub data_dir: String,
    pub log_level: String,
    pub machine_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeartbeatConfig {
    pub interval_secs: u64,
    pub jitter_secs: u64,
    pub max_backoff_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct UpdateConfig {
    pub staging_dir: String,
    pub auto_update: bool,
    pub rollback_on_failure: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct SecurityConfig {
    pub verify_signatures: bool,
    pub hmac_algorithm: String,
    pub enrollment_token: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ModulesConfig {
    pub metrics_enabled: bool,
    pub metrics_interval_secs: u64,
    pub script_runner_enabled: bool,
    pub inventory_enabled: bool,
    pub inventory_interval_secs: u64,
    pub remote_shell_enabled: bool,
    #[serde(default = "default_false")]
    pub webcam_enabled: bool,
    #[serde(default = "default_webcam_interval")]
    pub webcam_interval_secs: u64,
    #[serde(default)]
    pub webcam_default_camera: u32,
    #[serde(default = "default_webcam_width")]
    pub webcam_width: u32,
    #[serde(default = "default_webcam_height")]
    pub webcam_height: u32,
    #[serde(default = "default_webcam_quality")]
    pub webcam_quality: u8,
}

fn default_false() -> bool { false }
fn default_webcam_interval() -> u64 { 300 }
fn default_webcam_width() -> u32 { 1280 }
fn default_webcam_height() -> u32 { 720 }
fn default_webcam_quality() -> u8 { 85 }

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct StorageConfig {
    pub db_path: String,
    pub encrypt_at_rest: bool,
    pub max_queue_size: u64,
    pub queue_retention_hours: i64,
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        let config_path = crate::platform::get_config_path();
        // Fallback: try local config.toml (for dev / first run)
        let path = if config_path.exists() {
            config_path
        } else {
            let local = crate::platform::get_current_exe_dir().join("config.toml");
            if local.exists() {
                local
            } else {
                anyhow::bail!(
                    "No config.toml found at {} or {}",
                    config_path.display(),
                    local.display()
                );
            }
        };

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let mut config: AgentConfig = toml::from_str(&content)
            .with_context(|| format!("parsing {}", path.display()))?;

        // Auto-fill machine_id if empty
        if config.agent.machine_id.is_empty() {
            config.agent.machine_id = crate::platform::get_machine_id();
        }

        Ok(config)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Agent Core (the orchestrator)
// ═══════════════════════════════════════════════════════════════
pub struct AgentCore {
    config: AgentConfig,
    db: Database,
    token_mgr: TokenManager,
    api: ApiClient,
    policy: Arc<RwLock<PolicyEngine>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl AgentCore {
    pub async fn new() -> Result<Self> {
        let config = AgentConfig::load()?;

        // Ensure required directories exist.
        // Do NOT attempt to install persistence automatically here; that should be an explicit
        // administrative action via the CLI (`massvision-agent install`) or installer scripts.
        crate::platform::ensure_dirs()?;

        // Tamper check
        let issues = TamperDetector::check_integrity()?;
        if !issues.is_empty() {
            warn!(issues = ?issues, "Tamper detection issues found on startup");
            // TODO: trigger repair_update if critical files missing
        }

        // Open database
        let db = Database::open(&config)?;

        // Load credentials
        let token_mgr = TokenManager::load()
            .context("Loading agent credentials failed. Is the agent enrolled?")?;

        // HTTP API client
        let api = ApiClient::new(&config, token_mgr.clone())?;

        // Policy engine
        let policy = PolicyEngine::new(db.clone())?;

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            db,
            token_mgr,
            api,
            policy: Arc::new(RwLock::new(policy)),
            shutdown_tx,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Agent Core starting – machine_id={}", self.token_mgr.machine_id());

        // ── Spawn heartbeat scheduler ────────────────────────
        let hb = HeartbeatScheduler::new(
            self.config.clone(),
            self.api.clone(),
            self.db.clone(),
            self.token_mgr.clone(),
            self.shutdown_tx.subscribe(),
        );
        tokio::spawn(async move { hb.run().await });

        // ── Spawn WebSocket client ───────────────────────────
        let (ws_incoming_tx, mut ws_incoming_rx) = mpsc::channel::<ServerMessage>(256);
        let (ws_outgoing_tx, ws_outgoing_rx) = mpsc::channel::<AgentMessage>(256);

        let ws = WsClient::new(
            self.config.clone(),
            self.token_mgr.clone(),
            ws_incoming_tx,
            ws_outgoing_rx,
            self.shutdown_tx.subscribe(),
        );
        tokio::spawn(async move { ws.run().await });

        // ── Spawn metrics collector ──────────────────────────
        if self.config.modules.metrics_enabled {
            let metrics_collector = modules::metrics::MetricsCollector::new(
                self.config.clone(),
                self.api.clone(),
                self.token_mgr.clone(),
                self.shutdown_tx.subscribe(),
            );
            tokio::spawn(async move { metrics_collector.run().await });
        }

        // ── Spawn inventory collector ────────────────────────
        if self.config.modules.inventory_enabled {
            let inv_collector = modules::inventory::InventoryCollector::new(
                self.config.clone(),
                self.api.clone(),
                self.token_mgr.clone(),
                self.shutdown_tx.subscribe(),
            );
            tokio::spawn(async move { inv_collector.run().await });
        }

        // ── Spawn webcam collector ───────────────────────────
        if self.config.modules.webcam_enabled {
            let webcam_collector = modules::webcam::WebcamCollector::new(
                self.config.clone(),
                self.api.clone(),
                self.token_mgr.clone(),
                self.db.clone(),
                self.shutdown_tx.subscribe(),
            );
            tokio::spawn(async move { webcam_collector.run().await });
        }

        // ── Spawn job queue processor ────────────────────────
        let job_db = self.db.clone();
        let job_api = self.api.clone();
        let job_token = self.token_mgr.clone();
        let job_policy = self.policy.clone();
        let job_config = self.config.clone();
        let mut job_shutdown = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            Self::job_processor(job_db, job_api, job_token, job_policy, job_config, &mut job_shutdown).await;
        });

        // ── Spawn periodic cleanup ───────────────────────────
        let cleanup_db = self.db.clone();
        let retention = self.config.storage.queue_retention_hours;
        let mut cleanup_shutdown = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {
                        if let Ok(n) = cleanup_db.cleanup_old_jobs(retention) {
                            if n > 0 { info!(deleted = n, "Cleaned old jobs"); }
                        }
                    }
                    _ = cleanup_shutdown.recv() => return,
                }
            }
        });

        // ── Main event loop: process WS messages ─────────────
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                Some(msg) = ws_incoming_rx.recv() => {
                    self.handle_server_message(msg, &ws_outgoing_tx).await;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down gracefully");
                    self.shutdown_tx.send(()).ok();
                    break;
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        info!("Agent Core stopped");
        Ok(())
    }

    // ── Server message handler ───────────────────────────────
    async fn handle_server_message(
        &self,
        msg: ServerMessage,
        ws_tx: &mpsc::Sender<AgentMessage>,
    ) {
        match msg {
            ServerMessage::Job(job) => {
                info!(job_id = %job.job_id, job_type = ?job.job_type, "Job received");
                // Audit
                self.db.log_audit(&AuditEvent {
                    event_type: AuditEventType::JobStarted,
                    agent_id: self.token_mgr.agent_id().to_string(),
                    operator_id: None,
                    details: serde_json::json!({"job_id": job.job_id, "job_type": job.job_type}),
                    timestamp: chrono::Utc::now(),
                }).ok();
                if let Err(e) = self.db.enqueue_job(&job) {
                    error!(error = %e, "Failed to enqueue job");
                }
            }
            ServerMessage::PolicyUpdate(payload) => {
                info!("Policy update received (version={})", payload.version);
                let mut policy = self.policy.write().await;
                match policy.apply(&payload) {
                    Ok(changes) => info!(changes = ?changes, "Policy applied"),
                    Err(e) => error!(error = %e, "Policy apply failed"),
                }
            }
            ServerMessage::UpdateAvailable(notif) => {
                info!(version = %notif.version, "Update available");
                let policy = self.policy.read().await;
                if policy.current().auto_update_enabled && policy.in_update_window() {
                    let api = self.api.clone();
                    let config = self.config.clone();
                    let db = self.db.clone();
                    let agent_id = self.token_mgr.agent_id().to_string();
                    tokio::spawn(async move {
                        let mut um = UpdateManager::new(config, api, db);
                        if let Err(e) = um.apply_update(&notif, &agent_id).await {
                            error!(error = %e, "Update failed");
                        }
                    });
                } else {
                    info!("Update deferred (auto_update disabled or outside update window)");
                }
            }
            ServerMessage::Ping { id } => {
                ws_tx.send(AgentMessage::Pong { id }).await.ok();
            }
            ServerMessage::SessionStart(req) => {
                let policy = self.policy.read().await;
                if !policy.current().remote_shell_enabled {
                    warn!("Remote shell disabled by policy");
                    ws_tx.send(AgentMessage::SessionClosed {
                        session_id: req.session_id,
                        reason: "disabled_by_policy".into(),
                    }).await.ok();
                    return;
                }
                // Audit
                self.db.log_audit(&AuditEvent {
                    event_type: AuditEventType::RemoteSessionStarted,
                    agent_id: self.token_mgr.agent_id().to_string(),
                    operator_id: Some(req.operator_id.clone()),
                    details: serde_json::json!({
                        "session_id": req.session_id,
                        "session_type": req.session_type,
                        "ttl_secs": req.ttl_secs,
                    }),
                    timestamp: chrono::Utc::now(),
                }).ok();

                let ws_tx_clone = ws_tx.clone();
                let agent_id = self.token_mgr.agent_id().to_string();
                let db = self.db.clone();
                tokio::spawn(async move {
                    modules::remote_shell::handle_session(req, ws_tx_clone, agent_id, db).await;
                });
            }
            ServerMessage::SessionInput { session_id, data } => {
                modules::remote_shell::forward_input(&session_id, &data).await;
            }
            ServerMessage::SessionEnd { session_id } => {
                modules::remote_shell::end_session(&session_id).await;
            }
        }
    }

    // ── Job queue processor ──────────────────────────────────
    async fn job_processor(
        db: Database,
        api: ApiClient,
        token_mgr: TokenManager,
        policy: Arc<RwLock<PolicyEngine>>,
        config: AgentConfig,
        shutdown: &mut broadcast::Receiver<()>,
    ) {
        info!("Job processor started");
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
                _ = shutdown.recv() => {
                    info!("Job processor shutting down");
                    return;
                }
            }

            let job = match db.dequeue_job() {
                Ok(Some(j)) => j,
                Ok(None) => continue,
                Err(e) => {
                    error!(error = %e, "Failed to dequeue job");
                    continue;
                }
            };

            info!(job_id = %job.job_id, job_type = ?job.job_type, "Processing job");
            let started_at = chrono::Utc::now();

            let result = match job.job_type {
                JobType::RunScript => {
                    let pol = policy.read().await;
                    if !pol.current().script_runner_enabled {
                        warn!("Script runner disabled by policy");
                        JobResult {
                            job_id: job.job_id.clone(),
                            agent_id: token_mgr.agent_id().to_string(),
                            status: JobStatus::Cancelled,
                            exit_code: None,
                            stdout: None,
                            stderr: Some("Script runner disabled by policy".into()),
                            artifacts: Vec::new(),
                            started_at,
                            completed_at: chrono::Utc::now(),
                            duration_ms: 0,
                        }
                    } else {
                        drop(pol);
                        modules::script_runner::execute_script_job(
                            &job,
                            token_mgr.agent_id(),
                            &api,
                        ).await
                    }
                }
                JobType::CollectMetrics => {
                    let metrics = modules::metrics::collect_metrics(
                        token_mgr.agent_id(),
                    );
                    if let Err(e) = api.send_metrics(&metrics).await {
                        error!(error = %e, "Failed to send metrics");
                    }
                    JobResult {
                        job_id: job.job_id.clone(),
                        agent_id: token_mgr.agent_id().to_string(),
                        status: JobStatus::Success,
                        exit_code: Some(0),
                        stdout: None,
                        stderr: None,
                        artifacts: Vec::new(),
                        started_at,
                        completed_at: chrono::Utc::now(),
                        duration_ms: (chrono::Utc::now() - started_at).num_milliseconds() as u64,
                    }
                }
                JobType::CollectInventory => {
                    let inv = modules::inventory::collect_inventory(
                        token_mgr.agent_id(),
                    );
                    if let Err(e) = api.send_inventory(&inv).await {
                        error!(error = %e, "Failed to send inventory");
                    }
                    JobResult {
                        job_id: job.job_id.clone(),
                        agent_id: token_mgr.agent_id().to_string(),
                        status: JobStatus::Success,
                        exit_code: Some(0),
                        stdout: None,
                        stderr: None,
                        artifacts: Vec::new(),
                        started_at,
                        completed_at: chrono::Utc::now(),
                        duration_ms: (chrono::Utc::now() - started_at).num_milliseconds() as u64,
                    }
                }
                JobType::WebcamCapture => {
                    modules::webcam::execute_webcam_job(
                        &job,
                        token_mgr.agent_id(),
                        &api,
                        &db,
                    ).await
                }
                JobType::ListCameras => {
                    let cameras = modules::webcam::list_cameras();
                    JobResult {
                        job_id: job.job_id.clone(),
                        agent_id: token_mgr.agent_id().to_string(),
                        status: JobStatus::Success,
                        exit_code: Some(0),
                        stdout: Some(serde_json::to_string(&cameras).unwrap_or_default()),
                        stderr: None,
                        artifacts: Vec::new(),
                        started_at,
                        completed_at: chrono::Utc::now(),
                        duration_ms: (chrono::Utc::now() - started_at).num_milliseconds() as u64,
                    }
                }
                JobType::RepairUpdate | JobType::ApplyUpdate => {
                    let notif = UpdateNotification {
                        version: job.payload.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown").to_string(),
                        manifest_url: job.payload.get("manifest_url")
                            .and_then(|v| v.as_str())
                            .unwrap_or("").to_string(),
                        mandatory: true,
                        rollout_percentage: 100,
                    };
                    let mut um = UpdateManager::new(config.clone(), api.clone(), db.clone());
                    match um.apply_update(&notif, token_mgr.agent_id()).await {
                        Ok(()) => JobResult {
                            job_id: job.job_id.clone(),
                            agent_id: token_mgr.agent_id().to_string(),
                            status: JobStatus::Success,
                            exit_code: Some(0),
                            stdout: Some("Update applied successfully".into()),
                            stderr: None,
                            artifacts: Vec::new(),
                            started_at,
                            completed_at: chrono::Utc::now(),
                            duration_ms: (chrono::Utc::now() - started_at).num_milliseconds() as u64,
                        },
                        Err(e) => JobResult {
                            job_id: job.job_id.clone(),
                            agent_id: token_mgr.agent_id().to_string(),
                            status: JobStatus::Failed,
                            exit_code: Some(1),
                            stdout: None,
                            stderr: Some(format!("{e}")),
                            artifacts: Vec::new(),
                            started_at,
                            completed_at: chrono::Utc::now(),
                            duration_ms: (chrono::Utc::now() - started_at).num_milliseconds() as u64,
                        },
                    }
                }
                _ => {
                    warn!(job_type = ?job.job_type, "Unhandled job type");
                    JobResult {
                        job_id: job.job_id.clone(),
                        agent_id: token_mgr.agent_id().to_string(),
                        status: JobStatus::Failed,
                        exit_code: None,
                        stdout: None,
                        stderr: Some(format!("Unhandled job type: {:?}", job.job_type)),
                        artifacts: Vec::new(),
                        started_at,
                        completed_at: chrono::Utc::now(),
                        duration_ms: 0,
                    }
                }
            };

            // Persist result
            db.complete_job(&job.job_id, &result).ok();
            // Audit
            db.log_audit(&AuditEvent {
                event_type: AuditEventType::JobCompleted,
                agent_id: token_mgr.agent_id().to_string(),
                operator_id: None,
                details: serde_json::json!({
                    "job_id": job.job_id,
                    "status": result.status,
                    "exit_code": result.exit_code,
                }),
                timestamp: chrono::Utc::now(),
            }).ok();
            // Send to server
            if let Err(e) = api.send_job_result(&result).await {
                warn!(error = %e, "Failed to deliver job result");
            }
        }
    }
}

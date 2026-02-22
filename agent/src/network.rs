// ─────────────────────────────────────────────────────────────
// network.rs – Heartbeat sender, WebSocket client, HTTP API,
//              offline replay, exponential backoff
// ─────────────────────────────────────────────────────────────
use anyhow::{Result, Context};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

use crate::agent::AgentConfig;
use crate::protocol::*;
use crate::security::TokenManager;
use crate::storage::Database;

// ═══════════════════════════════════════════════════════════════
//  HTTP Client (signed requests)
// ═══════════════════════════════════════════════════════════════
#[derive(Clone)]
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
    token_mgr: TokenManager,
}

impl ApiClient {
    pub fn new(config: &AgentConfig, token_mgr: TokenManager) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(false)
            .build()?;
        Ok(Self {
            client,
            // MassVision server mounts the Rust agent v2 API under /api/agents-v2.
            base_url: format!(
                "{}/api/agents-v2",
                config.server.url.trim_end_matches('/')
            ),
            token_mgr,
        })
    }

    /// Send a signed POST request
    pub async fn post_signed(&self, path: &str, body: &impl serde::Serialize) -> Result<reqwest::Response> {
        let json = serde_json::to_string(body)?;
        let envelope = self.token_mgr.sign(&json)?;
        let url = format!("{}{}", self.base_url, path);

        let resp = self.client
            .post(&url)
            .header("X-Agent-Id", self.token_mgr.agent_id())
            .header("X-Machine-Id", self.token_mgr.machine_id())
            .json(&envelope)
            .send()
            .await
            .context("API POST")?;

        Ok(resp)
    }

    /// Send heartbeat via HTTP (fallback when WS is down)
    pub async fn send_heartbeat(&self, payload: &HeartbeatPayload) -> Result<()> {
        let resp = self.post_signed("/heartbeat", payload).await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Heartbeat failed: HTTP {status} – {body}");
        }
        Ok(())
    }

    /// Send job result
    pub async fn send_job_result(&self, result: &JobResult) -> Result<()> {
        let resp = self.post_signed("/jobs/result", result).await?;
        if !resp.status().is_success() {
            warn!(status = %resp.status(), "Job result delivery failed");
        }
        Ok(())
    }

    /// Send metrics
    pub async fn send_metrics(&self, m: &MetricsPayload) -> Result<()> {
        self.post_signed("/metrics", m).await?;
        Ok(())
    }

    /// Send inventory
    pub async fn send_inventory(&self, inv: &InventoryPayload) -> Result<()> {
        self.post_signed("/inventory", inv).await?;
        Ok(())
    }

    /// Send webcam capture
    pub async fn send_webcam_capture(&self, capture: &crate::modules::webcam::CaptureResult) -> Result<()> {
        let resp = self.post_signed("/webcam/capture", capture).await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Webcam upload failed: HTTP {status} – {body}");
        }
        Ok(())
    }

    /// Pull pending jobs from server
    #[allow(dead_code)]
    pub async fn pull_jobs(&self) -> Result<Vec<JobAssignment>> {
        let url = format!(
            "{}/jobs/pending/{}",
            self.base_url,
            self.token_mgr.agent_id()
        );
        let json = serde_json::to_string(&serde_json::json!({
            "agent_id": self.token_mgr.agent_id()
        }))?;
        let envelope = self.token_mgr.sign(&json)?;

        let resp = self.client
            .get(&url)
            .header("X-Agent-Id", self.token_mgr.agent_id())
            .header("X-Machine-Id", self.token_mgr.machine_id())
            .json(&envelope)
            .send()
            .await?;

        if resp.status().is_success() {
            let jobs: Vec<JobAssignment> = resp.json().await.unwrap_or_default();
            Ok(jobs)
        } else {
            Ok(Vec::new())
        }
    }

    /// Download a file (for updates)
    pub async fn download_file(&self, url: &str, dest: &std::path::Path) -> Result<()> {
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("Download failed: HTTP {}", resp.status());
        }
        let bytes = resp.bytes().await?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dest, &bytes)?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Heartbeat Scheduler (interval + jitter + backoff)
// ═══════════════════════════════════════════════════════════════
pub struct HeartbeatScheduler {
    config: AgentConfig,
    api: ApiClient,
    db: Database,
    token_mgr: TokenManager,
    shutdown: broadcast::Receiver<()>,
}

impl HeartbeatScheduler {
    pub fn new(
        config: AgentConfig,
        api: ApiClient,
        db: Database,
        token_mgr: TokenManager,
        shutdown: broadcast::Receiver<()>,
    ) -> Self {
        Self { config, api, db, token_mgr, shutdown }
    }

    pub async fn run(mut self) {
        let base_interval = self.config.heartbeat.interval_secs;
        let jitter = self.config.heartbeat.jitter_secs;
        let max_backoff = self.config.heartbeat.max_backoff_secs;
        let mut consecutive_failures: u32 = 0;

        info!(interval = base_interval, "Heartbeat scheduler started");

        loop {
            // Calculate delay with jitter + backoff
            let backoff = if consecutive_failures > 0 {
                let exp = Duration::from_secs(
                    (base_interval as u64) * 2u64.pow(consecutive_failures.min(8))
                );
                exp.min(Duration::from_secs(max_backoff))
            } else {
                Duration::from_secs(base_interval)
            };
            let jitter_offset = rand::random::<u64>() % (jitter.max(1));
            let delay = backoff + Duration::from_secs(jitter_offset);

            tokio::select! {
                _ = tokio::time::sleep(delay) => {},
                _ = self.shutdown.recv() => {
                    info!("Heartbeat scheduler shutting down");
                    return;
                }
            }

            let payload = self.build_heartbeat();

            // Try sending
            match self.api.send_heartbeat(&payload).await {
                Ok(()) => {
                    debug!("Heartbeat sent");
                    consecutive_failures = 0;
                    // Replay buffered heartbeats
                    self.replay_buffered().await;
                }
                Err(e) => {
                    consecutive_failures += 1;
                    warn!(
                        error = %e,
                        failures = consecutive_failures,
                        "Heartbeat failed — buffering locally"
                    );
                    if let Err(e) = self.db.buffer_heartbeat(&payload) {
                        error!("Failed to buffer heartbeat: {e}");
                    }
                }
            }
        }
    }

    fn build_heartbeat(&self) -> HeartbeatPayload {
        HeartbeatPayload {
            agent_id: self.token_mgr.agent_id().to_string(),
            machine_id: self.token_mgr.machine_id().to_string(),
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_default(),
            os_info: crate::platform::get_os_info(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: {
                sysinfo::System::uptime()
            },
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
            modules: Vec::new(), // filled by agent core
        }
    }

    async fn replay_buffered(&self) {
        match self.db.get_unsent_heartbeats(50) {
            Ok(heartbeats) if !heartbeats.is_empty() => {
                info!(count = heartbeats.len(), "Replaying buffered heartbeats");
                let mut sent_ids = Vec::new();
                for (id, hb) in &heartbeats {
                    if self.api.send_heartbeat(hb).await.is_ok() {
                        sent_ids.push(*id);
                    } else {
                        break; // stop at first failure
                    }
                }
                if !sent_ids.is_empty() {
                    self.db.mark_heartbeats_sent(&sent_ids).ok();
                }
            }
            _ => {}
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  WebSocket Client (real-time commands, auto-reconnect)
// ═══════════════════════════════════════════════════════════════
pub struct WsClient {
    config: AgentConfig,
    token_mgr: TokenManager,
    incoming_tx: mpsc::Sender<ServerMessage>,
    outgoing_rx: mpsc::Receiver<AgentMessage>,
    shutdown: broadcast::Receiver<()>,
}

impl WsClient {
    pub fn new(
        config: AgentConfig,
        token_mgr: TokenManager,
        incoming_tx: mpsc::Sender<ServerMessage>,
        outgoing_rx: mpsc::Receiver<AgentMessage>,
        shutdown: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            config,
            token_mgr,
            incoming_tx,
            outgoing_rx,
            shutdown,
        }
    }

    pub async fn run(mut self) {
        let mut reconnect_delay = Duration::from_secs(1);
        let max_delay = Duration::from_secs(60);

        loop {
            // Check shutdown before connecting
            tokio::select! {
                biased;
                _ = self.shutdown.recv() => {
                    info!("WebSocket client shutting down");
                    return;
                }
                _ = tokio::time::sleep(Duration::ZERO) => {}
            }

            match self.connect_and_run().await {
                Ok(()) => {
                    info!("WebSocket disconnected normally");
                    reconnect_delay = Duration::from_secs(1);
                }
                Err(e) => {
                    warn!(error = %e, "WebSocket error");
                    reconnect_delay = (reconnect_delay * 2).min(max_delay);
                }
            }

            info!(delay = ?reconnect_delay, "Reconnecting WebSocket...");
            tokio::select! {
                _ = tokio::time::sleep(reconnect_delay) => {},
                _ = self.shutdown.recv() => return,
            }
        }
    }

    async fn connect_and_run(&mut self) -> Result<()> {
        let ws_url = format!(
            "{}?agent_id={}&machine_id={}",
            self.config.server.ws_url,
            self.token_mgr.agent_id(),
            self.token_mgr.machine_id(),
        );
        info!(url = %ws_url, "Connecting WebSocket");

        let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
            .await
            .context("WebSocket connect")?;

        let (mut ws_write, mut ws_read) = ws_stream.split();
        info!("WebSocket connected");

        // Send auth message
        let auth_json = serde_json::to_string(&serde_json::json!({
            "type": "auth",
            "agent_id": self.token_mgr.agent_id(),
            "nonce": uuid::Uuid::new_v4().to_string(),
        }))?;
        let envelope = self.token_mgr.sign(&auth_json)?;
        ws_write.send(tokio_tungstenite::tungstenite::Message::Text(
            serde_json::to_string(&envelope)?
        )).await?;

        loop {
            tokio::select! {
                msg = ws_read.next() => {
                    match msg {
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                            match serde_json::from_str::<ServerMessage>(&text) {
                                Ok(server_msg) => {
                                    if self.incoming_tx.send(server_msg).await.is_err() {
                                        return Ok(());
                                    }
                                }
                                Err(e) => {
                                    debug!(error = %e, "Unknown WS message");
                                }
                            }
                        }
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Ping(data))) => {
                            ws_write.send(
                                tokio_tungstenite::tungstenite::Message::Pong(data)
                            ).await.ok();
                        }
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => {
                            return Ok(());
                        }
                        Some(Err(e)) => {
                            return Err(e.into());
                        }
                        _ => {}
                    }
                }
                out = self.outgoing_rx.recv() => {
                    match out {
                        Some(agent_msg) => {
                            if let Ok(json) = serde_json::to_string(&agent_msg) {
                                if ws_write.send(tokio_tungstenite::tungstenite::Message::Text(json)).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                        None => {
                            // Sender dropped, keep WS alive for incoming
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Outbound WS sender (separate task)
// ═══════════════════════════════════════════════════════════════
#[allow(dead_code)]
pub async fn ws_sender_loop(
    mut outgoing_rx: mpsc::Receiver<String>,
    _ws_url: String,
    mut shutdown: broadcast::Receiver<()>,
) {
    // This task forwards outgoing messages from the agent core to the WebSocket
    // In practice, the WS write half is shared; here we use a simple channel
    while let Some(msg) = tokio::select! {
        m = outgoing_rx.recv() => m,
        _ = shutdown.recv() => None,
    } {
        debug!(len = msg.len(), "WS outgoing message queued");
        // In production, this writes to the WS sink
    }
}

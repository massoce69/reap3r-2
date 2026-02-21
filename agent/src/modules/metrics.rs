// ─────────────────────────────────────────────────────────────
// modules/metrics.rs – System metrics collection
//   CPU / RAM / Disk / Uptime / Top Processes / Network
// ─────────────────────────────────────────────────────────────
use chrono::Utc;
use sysinfo::{System, Disks, Networks};
use tokio::sync::broadcast;
use tracing::{debug, info};

use crate::agent::AgentConfig;
use crate::network::ApiClient;
use crate::protocol::*;
use crate::security::TokenManager;

// ═══════════════════════════════════════════════════════════════
//  Periodic Metrics Collector
// ═══════════════════════════════════════════════════════════════
pub struct MetricsCollector {
    config: AgentConfig,
    api: ApiClient,
    token_mgr: TokenManager,
    shutdown: broadcast::Receiver<()>,
}

impl MetricsCollector {
    pub fn new(
        config: AgentConfig,
        api: ApiClient,
        token_mgr: TokenManager,
        shutdown: broadcast::Receiver<()>,
    ) -> Self {
        Self { config, api, token_mgr, shutdown }
    }

    pub async fn run(mut self) {
        let interval = std::time::Duration::from_secs(self.config.modules.metrics_interval_secs);
        info!(interval_secs = self.config.modules.metrics_interval_secs, "Metrics collector started");

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                _ = self.shutdown.recv() => {
                    info!("Metrics collector shutting down");
                    return;
                }
            }

            let metrics = collect_metrics(self.token_mgr.agent_id());
            debug!(
                cpu = metrics.cpu_usage_percent,
                mem = metrics.memory_usage_percent,
                "Metrics collected"
            );

            if let Err(e) = self.api.send_metrics(&metrics).await {
                debug!(error = %e, "Failed to send metrics (will retry)");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  One-shot metrics collection
// ═══════════════════════════════════════════════════════════════
pub fn collect_metrics(agent_id: &str) -> MetricsPayload {
    let mut sys = System::new_all();
    sys.refresh_all();

    // CPU usage (average across all cores)
    let cpu_usage = sys.global_cpu_info().cpu_usage() as f64;

    // Memory
    let total_mem = sys.total_memory() / (1024 * 1024); // bytes → MB
    let used_mem = sys.used_memory() / (1024 * 1024);
    let mem_percent = if total_mem > 0 {
        (used_mem as f64 / total_mem as f64) * 100.0
    } else {
        0.0
    };

    // Disks
    let disks = Disks::new_with_refreshed_list();
    let disk_metrics: Vec<DiskMetric> = disks.iter().map(|d| {
        let total = d.total_space() as f64 / (1024.0 * 1024.0 * 1024.0);
        let available = d.available_space() as f64 / (1024.0 * 1024.0 * 1024.0);
        let used = total - available;
        DiskMetric {
            mount_point: d.mount_point().to_string_lossy().to_string(),
            total_gb: (total * 100.0).round() / 100.0,
            used_gb: (used * 100.0).round() / 100.0,
            usage_percent: if total > 0.0 { ((used / total) * 100.0 * 10.0).round() / 10.0 } else { 0.0 },
        }
    }).collect();

    // Top processes by CPU
    let mut top_processes: Vec<ProcessInfo> = sys.processes().iter().map(|(pid, proc_)| {
        ProcessInfo {
            pid: pid.as_u32(),
            name: proc_.name().to_string(),
            cpu_percent: proc_.cpu_usage(),
            memory_mb: proc_.memory() / (1024 * 1024),
        }
    }).collect();
    top_processes.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(std::cmp::Ordering::Equal));
    top_processes.truncate(20); // Top 20

    // Network interfaces
    let networks = Networks::new_with_refreshed_list();
    let net_info: Vec<NetworkInfo> = networks.iter().map(|(name, data)| {
        NetworkInfo {
            interface: name.to_string(),
            mac_address: data.mac_address().to_string(),
            bytes_sent: data.total_transmitted(),
            bytes_received: data.total_received(),
        }
    }).collect();

    MetricsPayload {
        agent_id: agent_id.to_string(),
        timestamp: Utc::now(),
        cpu_usage_percent: (cpu_usage * 10.0).round() / 10.0,
        memory_total_mb: total_mem,
        memory_used_mb: used_mem,
        memory_usage_percent: (mem_percent * 10.0).round() / 10.0,
        disks: disk_metrics,
        uptime_secs: System::uptime(),
        top_processes,
        network_interfaces: net_info,
    }
}

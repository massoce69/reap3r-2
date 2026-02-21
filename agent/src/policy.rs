// ─────────────────────────────────────────────────────────────
// policy.rs – Policy engine
//   Receives and applies policies from MassVision server.
//   Persists locally for offline operation.
// ─────────────────────────────────────────────────────────────
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::protocol::PolicyPayload;
use crate::storage::Database;

// ═══════════════════════════════════════════════════════════════
//  Effective policy (merged from server defaults + overrides)
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePolicy {
    pub version: u64,
    pub heartbeat_interval_secs: u64,
    pub metrics_enabled: bool,
    pub metrics_interval_secs: u64,
    pub script_runner_enabled: bool,
    pub inventory_enabled: bool,
    pub inventory_interval_secs: u64,
    pub remote_shell_enabled: bool,
    pub allowed_script_hashes: Vec<String>,  // empty = allow all signed
    pub auto_update_enabled: bool,
    pub update_window_start: Option<String>, // "02:00"
    pub update_window_end: Option<String>,   // "05:00"
    pub maintenance_window_start: Option<String>,
    pub maintenance_window_end: Option<String>,
    pub alert_cpu_threshold: f64,
    pub alert_memory_threshold: f64,
    pub alert_disk_threshold: f64,
}

impl Default for EffectivePolicy {
    fn default() -> Self {
        Self {
            version: 0,
            heartbeat_interval_secs: 60,
            metrics_enabled: true,
            metrics_interval_secs: 60,
            script_runner_enabled: true,
            inventory_enabled: true,
            inventory_interval_secs: 3600,
            remote_shell_enabled: true,
            allowed_script_hashes: Vec::new(),
            auto_update_enabled: true,
            update_window_start: None,
            update_window_end: None,
            maintenance_window_start: None,
            maintenance_window_end: None,
            alert_cpu_threshold: 90.0,
            alert_memory_threshold: 90.0,
            alert_disk_threshold: 90.0,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Policy Engine
// ═══════════════════════════════════════════════════════════════
pub struct PolicyEngine {
    db: Database,
    current: EffectivePolicy,
}

impl PolicyEngine {
    pub fn new(db: Database) -> Result<Self> {
        // Try loading from local snapshot
        let current = match db.get_config("policy")? {
            Some(json) => serde_json::from_str(&json).unwrap_or_default(),
            None => EffectivePolicy::default(),
        };
        info!(version = current.version, "Policy loaded");
        Ok(Self { db, current })
    }

    /// Apply a policy update from the server
    pub fn apply(&mut self, update: &PolicyPayload) -> Result<Vec<String>> {
        if update.version <= self.current.version {
            info!(
                server_version = update.version,
                local_version = self.current.version,
                "Policy version not newer, skipping"
            );
            return Ok(Vec::new());
        }

        let mut changes = Vec::new();

        for item in &update.policies {
            match item.key.as_str() {
                "heartbeat_interval_secs" => {
                    if let Some(v) = item.value.as_u64() {
                        self.current.heartbeat_interval_secs = v;
                        changes.push(format!("heartbeat_interval_secs={v}"));
                    }
                }
                "metrics_enabled" => {
                    if let Some(v) = item.value.as_bool() {
                        self.current.metrics_enabled = v;
                        changes.push(format!("metrics_enabled={v}"));
                    }
                }
                "metrics_interval_secs" => {
                    if let Some(v) = item.value.as_u64() {
                        self.current.metrics_interval_secs = v;
                        changes.push(format!("metrics_interval_secs={v}"));
                    }
                }
                "script_runner_enabled" => {
                    if let Some(v) = item.value.as_bool() {
                        self.current.script_runner_enabled = v;
                        changes.push(format!("script_runner_enabled={v}"));
                    }
                }
                "inventory_enabled" => {
                    if let Some(v) = item.value.as_bool() {
                        self.current.inventory_enabled = v;
                        changes.push(format!("inventory_enabled={v}"));
                    }
                }
                "inventory_interval_secs" => {
                    if let Some(v) = item.value.as_u64() {
                        self.current.inventory_interval_secs = v;
                        changes.push(format!("inventory_interval_secs={v}"));
                    }
                }
                "remote_shell_enabled" => {
                    if let Some(v) = item.value.as_bool() {
                        self.current.remote_shell_enabled = v;
                        changes.push(format!("remote_shell_enabled={v}"));
                    }
                }
                "allowed_script_hashes" => {
                    if let Some(arr) = item.value.as_array() {
                        self.current.allowed_script_hashes = arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect();
                        changes.push(format!(
                            "allowed_script_hashes={}",
                            self.current.allowed_script_hashes.len()
                        ));
                    }
                }
                "auto_update_enabled" => {
                    if let Some(v) = item.value.as_bool() {
                        self.current.auto_update_enabled = v;
                        changes.push(format!("auto_update_enabled={v}"));
                    }
                }
                "update_window_start" => {
                    self.current.update_window_start = item.value.as_str().map(String::from);
                    changes.push("update_window_start updated".into());
                }
                "update_window_end" => {
                    self.current.update_window_end = item.value.as_str().map(String::from);
                    changes.push("update_window_end updated".into());
                }
                "alert_cpu_threshold" => {
                    if let Some(v) = item.value.as_f64() {
                        self.current.alert_cpu_threshold = v;
                        changes.push(format!("alert_cpu_threshold={v}"));
                    }
                }
                "alert_memory_threshold" => {
                    if let Some(v) = item.value.as_f64() {
                        self.current.alert_memory_threshold = v;
                        changes.push(format!("alert_memory_threshold={v}"));
                    }
                }
                "alert_disk_threshold" => {
                    if let Some(v) = item.value.as_f64() {
                        self.current.alert_disk_threshold = v;
                        changes.push(format!("alert_disk_threshold={v}"));
                    }
                }
                other => {
                    warn!(key = other, "Unknown policy key, ignoring");
                }
            }
        }

        self.current.version = update.version;

        // Persist
        let json = serde_json::to_string(&self.current)?;
        self.db.save_config("policy", &json)?;

        info!(version = update.version, changes = ?changes, "Policy applied");
        Ok(changes)
    }

    pub fn current(&self) -> &EffectivePolicy {
        &self.current
    }

    /// Check if we're in a maintenance window right now
    #[allow(dead_code)]
    pub fn in_maintenance_window(&self) -> bool {
        let now = chrono::Local::now().format("%H:%M").to_string();
        match (&self.current.maintenance_window_start, &self.current.maintenance_window_end) {
            (Some(start), Some(end)) => now >= *start && now <= *end,
            _ => false,
        }
    }

    /// Check if we're in an update window right now
    pub fn in_update_window(&self) -> bool {
        let now = chrono::Local::now().format("%H:%M").to_string();
        match (&self.current.update_window_start, &self.current.update_window_end) {
            (Some(start), Some(end)) => now >= *start && now <= *end,
            _ => true, // If no window specified, always allowed
        }
    }
}

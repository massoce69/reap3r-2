// ─────────────────────────────────────────────────────────────
// modules/inventory.rs – Hardware & software inventory
// ─────────────────────────────────────────────────────────────
use chrono::Utc;
use sysinfo::{System, Disks};
use tokio::sync::broadcast;
use tracing::info;

use crate::agent::AgentConfig;
use crate::network::ApiClient;
use crate::protocol::*;
use crate::security::TokenManager;

// ═══════════════════════════════════════════════════════════════
//  Periodic Inventory Collector
// ═══════════════════════════════════════════════════════════════
pub struct InventoryCollector {
    config: AgentConfig,
    api: ApiClient,
    token_mgr: TokenManager,
    shutdown: broadcast::Receiver<()>,
}

impl InventoryCollector {
    pub fn new(
        config: AgentConfig,
        api: ApiClient,
        token_mgr: TokenManager,
        shutdown: broadcast::Receiver<()>,
    ) -> Self {
        Self { config, api, token_mgr, shutdown }
    }

    pub async fn run(mut self) {
        let interval = std::time::Duration::from_secs(self.config.modules.inventory_interval_secs);
        info!("Inventory collector started (interval={}s)", self.config.modules.inventory_interval_secs);

        // Collect immediately on start
        let inv = collect_inventory(self.token_mgr.agent_id());
        self.api.send_inventory(&inv).await.ok();

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {},
                _ = self.shutdown.recv() => {
                    info!("Inventory collector shutting down");
                    return;
                }
            }

            let inv = collect_inventory(self.token_mgr.agent_id());
            if let Err(e) = self.api.send_inventory(&inv).await {
                tracing::debug!(error = %e, "Failed to send inventory");
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  One-shot inventory collection
// ═══════════════════════════════════════════════════════════════
pub fn collect_inventory(agent_id: &str) -> InventoryPayload {
    let mut sys = System::new_all();
    sys.refresh_all();

    let os = OsInfo {
        name: System::name().unwrap_or_else(|| "Unknown".into()),
        version: System::os_version().unwrap_or_else(|| "Unknown".into()),
        arch: std::env::consts::ARCH.to_string(),
        kernel: System::kernel_version().unwrap_or_else(|| "Unknown".into()),
    };

    let hardware = HardwareInfo {
        cpu_model: sys.cpus().first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "Unknown".into()),
        cpu_cores: sys.cpus().len() as u32,
        total_ram_mb: sys.total_memory() / (1024 * 1024),
        disks: {
            let disks = Disks::new_with_refreshed_list();
            disks.iter().map(|d| {
                DiskInfo {
                    name: d.name().to_string_lossy().to_string(),
                    total_gb: (d.total_space() as f64 / (1024.0 * 1024.0 * 1024.0) * 100.0).round() / 100.0,
                    disk_type: format!("{:?}", d.kind()),
                }
            }).collect()
        },
    };

    let software = collect_installed_software();

    InventoryPayload {
        agent_id: agent_id.to_string(),
        timestamp: Utc::now(),
        os,
        hardware,
        software,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Installed software enumeration (platform-specific)
// ═══════════════════════════════════════════════════════════════
fn collect_installed_software() -> Vec<SoftwareInfo> {
    #[cfg(windows)]
    { windows_installed_software() }

    #[cfg(target_os = "linux")]
    { linux_installed_software() }

    #[cfg(target_os = "macos")]
    { macos_installed_software() }
}

#[cfg(windows)]
fn windows_installed_software() -> Vec<SoftwareInfo> {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut software = Vec::new();
    let paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    for path in paths {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hklm.open_subkey(path) {
            for subkey_name in key.enum_keys().flatten() {
                if let Ok(subkey) = key.open_subkey(&subkey_name) {
                    let name: String = subkey.get_value("DisplayName").unwrap_or_default();
                    if name.is_empty() { continue; }
                    let version: String = subkey.get_value("DisplayVersion").unwrap_or_default();
                    let publisher: String = subkey.get_value("Publisher").unwrap_or_default();
                    let install_date: String = subkey.get_value("InstallDate").unwrap_or_default();
                    software.push(SoftwareInfo {
                        name,
                        version,
                        publisher: if publisher.is_empty() { None } else { Some(publisher) },
                        install_date: if install_date.is_empty() { None } else { Some(install_date) },
                    });
                }
            }
        }
    }
    software
}

#[cfg(target_os = "linux")]
fn linux_installed_software() -> Vec<SoftwareInfo> {
    let mut software = Vec::new();

    // Try dpkg (Debian/Ubuntu)
    if let Ok(output) = std::process::Command::new("dpkg-query")
        .args(["-W", "-f", "${Package}\t${Version}\t${Maintainer}\n"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts: Vec<&str> = line.splitn(3, '\t').collect();
            if parts.len() >= 2 {
                software.push(SoftwareInfo {
                    name: parts[0].to_string(),
                    version: parts[1].to_string(),
                    publisher: parts.get(2).map(|s| s.to_string()),
                    install_date: None,
                });
            }
        }
    }

    // Try rpm (RHEL/CentOS/Fedora) if dpkg gave nothing
    if software.is_empty() {
        if let Ok(output) = std::process::Command::new("rpm")
            .args(["-qa", "--queryformat", "%{NAME}\t%{VERSION}\t%{VENDOR}\n"])
            .output()
        {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let parts: Vec<&str> = line.splitn(3, '\t').collect();
                if parts.len() >= 2 {
                    software.push(SoftwareInfo {
                        name: parts[0].to_string(),
                        version: parts[1].to_string(),
                        publisher: parts.get(2).map(|s| s.to_string()),
                        install_date: None,
                    });
                }
            }
        }
    }

    software
}

#[cfg(target_os = "macos")]
fn macos_installed_software() -> Vec<SoftwareInfo> {
    let mut software = Vec::new();

    if let Ok(output) = std::process::Command::new("system_profiler")
        .args(["SPApplicationsDataType", "-json"])
        .output()
    {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
            if let Some(apps) = json.get("SPApplicationsDataType")
                .and_then(|v| v.as_array())
            {
                for app in apps {
                    let name = app.get("_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    let version = app.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    let publisher = app.get("obtained_from")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    software.push(SoftwareInfo {
                        name,
                        version,
                        publisher,
                        install_date: None,
                    });
                }
            }
        }
    }

    software
}

// ─────────────────────────────────────────────────────────────
// platform.rs – OS-specific abstractions
//   • Windows service (windows-service crate)
//   • Linux  systemd unit
//   • macOS  launchd plist
//   • Path helpers (data / log / staging)
// ─────────────────────────────────────────────────────────────
use anyhow::{Result, Context};
use std::path::PathBuf;
use tracing::info;

// ── platform paths ───────────────────────────────────────────
pub fn get_data_dir() -> PathBuf {
    #[cfg(windows)]
    { PathBuf::from(r"C:\ProgramData\MassVision") }
    #[cfg(target_os = "macos")]
    { PathBuf::from("/Library/Application Support/MassVision") }
    #[cfg(target_os = "linux")]
    { PathBuf::from("/var/lib/massvision") }
}

pub fn get_log_dir() -> PathBuf {
    #[cfg(windows)]
    { get_data_dir().join("logs") }
    #[cfg(target_os = "macos")]
    { PathBuf::from("/Library/Logs/MassVision") }
    #[cfg(target_os = "linux")]
    { PathBuf::from("/var/log/massvision") }
}

pub fn get_config_path() -> PathBuf {
    #[cfg(windows)]
    { get_data_dir().join("config.toml") }
    #[cfg(not(windows))]
    { PathBuf::from("/etc/massvision/config.toml") }
}

pub fn get_staging_dir() -> PathBuf {
    get_data_dir().join("staging")
}

pub fn get_rollback_dir() -> PathBuf {
    get_data_dir().join("rollback")
}

pub fn get_modules_dir() -> PathBuf {
    get_data_dir().join("modules")
}

pub fn get_scripts_sandbox() -> PathBuf {
    get_data_dir().join("sandbox")
}

pub fn get_db_path() -> PathBuf {
    get_data_dir().join("agent.db")
}

pub fn get_current_exe_dir() -> PathBuf {
    std::env::current_exe()
        .unwrap_or_default()
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf()
}

// ── machine-id ───────────────────────────────────────────────
pub fn get_machine_id() -> String {
    // Try OS-level machine id first, fall back to generated one
    #[cfg(windows)]
    {
        if let Ok(id) = windows_machine_id() {
            return id;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            return id.trim().to_string();
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(uuid) = line.split('"').nth(3) {
                        return uuid.to_string();
                    }
                }
            }
        }
    }
    // Fallback: generate + persist
    let path = get_data_dir().join(".machine-id");
    if let Ok(id) = std::fs::read_to_string(&path) {
        return id.trim().to_string();
    }
    let id = uuid::Uuid::new_v4().to_string();
    std::fs::create_dir_all(get_data_dir()).ok();
    std::fs::write(&path, &id).ok();
    id
}

#[cfg(windows)]
fn windows_machine_id() -> Result<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let subkey = hklm.open_subkey(r"SOFTWARE\Microsoft\Cryptography")?;
    let id: String = subkey.get_value("MachineGuid")?;
    Ok(id)
}

pub fn get_os_info() -> String {
    format!(
        "{} {} ({})",
        sysinfo::System::name().unwrap_or_default(),
        sysinfo::System::os_version().unwrap_or_default(),
        std::env::consts::ARCH,
    )
}

// ── service install / uninstall ──────────────────────────────
pub fn install_service() -> Result<()> {
    ensure_dirs()?;

    #[cfg(windows)]
    { windows_install_service()?; }

    #[cfg(target_os = "linux")]
    { linux_install_service()?; }

    #[cfg(target_os = "macos")]
    { macos_install_service()?; }

    info!("Service installed successfully");
    Ok(())
}

pub fn uninstall_service() -> Result<()> {
    #[cfg(windows)]
    { windows_uninstall_service()?; }

    #[cfg(target_os = "linux")]
    { linux_uninstall_service()?; }

    #[cfg(target_os = "macos")]
    { macos_uninstall_service()?; }

    info!("Service uninstalled");
    Ok(())
}

pub fn ensure_dirs() -> Result<()> {
    for d in [get_data_dir(), get_log_dir(), get_staging_dir(),
              get_rollback_dir(), get_modules_dir(), get_scripts_sandbox()] {
        std::fs::create_dir_all(&d)
            .with_context(|| format!("creating {}", d.display()))?;
    }
    Ok(())
}

// ── Windows Service ──────────────────────────────────────────
#[cfg(windows)]
pub fn run_windows_service() -> Result<()> {
    use windows_service::{
        define_windows_service,
        service_dispatcher,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode,
            ServiceStatus, ServiceState, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    use std::sync::mpsc;
    use std::time::Duration;

    const SERVICE_NAME: &str = "MassVisionAgent";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, massvision_service_main);

    fn massvision_service_main(_arguments: Vec<std::ffi::OsString>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    shutdown_tx.send(()).ok();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = match service_control_handler::register(SERVICE_NAME, event_handler) {
            Ok(h) => h,
            Err(_) => return,
        };

        // Report running
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }).ok();

        // Run agent in a background thread
        let agent_handle = std::thread::spawn(|| {
            if let Err(e) = crate::run_agent_service() {
                tracing::error!("Agent service error: {e}");
            }
        });

        // Wait for stop signal
        let _ = shutdown_rx.recv();

        // Report stopped
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }).ok();

        drop(agent_handle);
    }

    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("Failed to start service dispatcher")?;
    Ok(())
}

#[cfg(windows)]
fn windows_install_service() -> Result<()> {
    use std::process::Command;
    let exe = std::env::current_exe()?;
    // Copy binary to Program Files
    let install_dir = PathBuf::from(r"C:\Program Files\MassVision");
    std::fs::create_dir_all(&install_dir)?;
    let target = install_dir.join("massvision-agent.exe");
    std::fs::copy(&exe, &target)?;
    // Copy config
    let cfg_src = exe.parent().unwrap().join("config.toml");
    if cfg_src.exists() {
        std::fs::copy(&cfg_src, get_config_path())?;
    }
    // Create service via sc.exe
    let output = Command::new("sc.exe")
        .args([
            "create", "MassVisionAgent",
            "binPath=", &format!("\"{}\"", target.display()),
            "start=", "auto",
            "DisplayName=", "MassVision Agent",
        ])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("sc create failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    // Configure recovery (auto restart on failure)
    Command::new("sc.exe")
        .args([
            "failure", "MassVisionAgent",
            "reset=", "86400",
            "actions=", "restart/5000/restart/10000/restart/30000",
        ])
        .output()?;
    // Start the service
    Command::new("sc.exe")
        .args(["start", "MassVisionAgent"])
        .output()?;
    println!("✓ Service MassVisionAgent installed and started");
    Ok(())
}

#[cfg(windows)]
fn windows_uninstall_service() -> Result<()> {
    use std::process::Command;
    Command::new("sc.exe").args(["stop", "MassVisionAgent"]).output().ok();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let output = Command::new("sc.exe")
        .args(["delete", "MassVisionAgent"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("sc delete failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    println!("✓ Service MassVisionAgent removed");
    Ok(())
}

// ── Linux (systemd) ──────────────────────────────────────────
#[cfg(target_os = "linux")]
fn linux_install_service() -> Result<()> {
    let exe = std::env::current_exe()?;
    let install_path = PathBuf::from("/usr/local/bin/massvision-agent");
    std::fs::copy(&exe, &install_path)?;
    // Copy config
    std::fs::create_dir_all("/etc/massvision")?;
    let cfg_src = exe.parent().unwrap().join("config.toml");
    if cfg_src.exists() {
        std::fs::copy(&cfg_src, "/etc/massvision/config.toml")?;
    }

    let unit = r#"[Unit]
Description=MassVision Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/massvision-agent run
Restart=always
RestartSec=5
WatchdogSec=120
User=massvision
Group=massvision
ProtectSystem=strict
ReadWritePaths=/var/lib/massvision /var/log/massvision
PrivateTmp=true
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"#;
    std::fs::write("/etc/systemd/system/massvision-agent.service", unit)?;

    use std::process::Command;
    // Create service user
    Command::new("useradd").args(["-r", "-s", "/usr/sbin/nologin", "massvision"]).output().ok();
    Command::new("systemctl").args(["daemon-reload"]).output()?;
    Command::new("systemctl").args(["enable", "--now", "massvision-agent"]).output()?;
    println!("✓ systemd service installed and started");
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_uninstall_service() -> Result<()> {
    use std::process::Command;
    Command::new("systemctl").args(["stop", "massvision-agent"]).output().ok();
    Command::new("systemctl").args(["disable", "massvision-agent"]).output().ok();
    std::fs::remove_file("/etc/systemd/system/massvision-agent.service").ok();
    Command::new("systemctl").args(["daemon-reload"]).output()?;
    println!("✓ systemd service removed");
    Ok(())
}

// ── macOS (launchd) ──────────────────────────────────────────
#[cfg(target_os = "macos")]
fn macos_install_service() -> Result<()> {
    let exe = std::env::current_exe()?;
    let install_path = PathBuf::from("/usr/local/bin/massvision-agent");
    std::fs::copy(&exe, &install_path)?;
    std::fs::create_dir_all("/etc/massvision")?;
    let cfg_src = exe.parent().unwrap().join("config.toml");
    if cfg_src.exists() {
        std::fs::copy(&cfg_src, "/etc/massvision/config.toml")?;
    }

    let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.massvision.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/massvision-agent</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/MassVision/agent-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/MassVision/agent-stderr.log</string>
</dict>
</plist>
"#;
    let plist_path = "/Library/LaunchDaemons/com.massvision.agent.plist";
    std::fs::write(plist_path, plist)?;

    use std::process::Command;
    Command::new("launchctl")
        .args(["load", "-w", plist_path])
        .output()?;
    println!("✓ launchd service installed and started");
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_uninstall_service() -> Result<()> {
    use std::process::Command;
    let plist_path = "/Library/LaunchDaemons/com.massvision.agent.plist";
    Command::new("launchctl").args(["unload", plist_path]).output().ok();
    std::fs::remove_file(plist_path).ok();
    println!("✓ launchd service removed");
    Ok(())
}

// ── Atomic binary swap (used by update manager) ──────────────
pub fn atomic_binary_swap(staging_path: &std::path::Path, target_path: &std::path::Path) -> Result<()> {
    let rollback = get_rollback_dir().join(
        target_path.file_name().unwrap_or_default()
    );
    // Backup current
    if target_path.exists() {
        std::fs::copy(target_path, &rollback)
            .context("backup current binary")?;
    }
    #[cfg(unix)]
    {
        // symlink swap: staging → temp link → rename over target
        let parent = target_path.parent().unwrap();
        let tmp_link = parent.join(".massvision-update-tmp");
        std::fs::remove_file(&tmp_link).ok();
        std::os::unix::fs::symlink(staging_path, &tmp_link)?;
        std::fs::rename(&tmp_link, target_path)?;
    }
    #[cfg(windows)]
    {
        // rename swap: target → .old, staging → target
        let old = target_path.with_extension("old.exe");
        std::fs::remove_file(&old).ok();
        if target_path.exists() {
            std::fs::rename(target_path, &old)?;
        }
        std::fs::copy(staging_path, target_path)?;
        // Clean up .old on next startup
    }
    Ok(())
}

pub fn rollback_binary(target_path: &std::path::Path) -> Result<()> {
    let rollback = get_rollback_dir().join(
        target_path.file_name().unwrap_or_default()
    );
    if rollback.exists() {
        std::fs::copy(&rollback, target_path)
            .context("rollback binary restore")?;
        info!("Binary rolled back from {}", rollback.display());
    } else {
        anyhow::bail!("No rollback binary found at {}", rollback.display());
    }
    Ok(())
}

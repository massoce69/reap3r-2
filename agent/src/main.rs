// ─────────────────────────────────────────────
// MASSVISION Reap3r Agent — Main Entry Point
// ─────────────────────────────────────────────

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser, Debug)]
#[command(name = "reap3r-agent", version, about = "MASSVISION Reap3r Agent")]
struct Args {
    /// Server WebSocket URL (e.g., wss://reap3r.example.com/ws/agent)
    #[arg(long, env = "REAP3R_SERVER")]
    server: String,

    /// Enrollment token (for initial enrollment)
    #[arg(long, env = "REAP3R_TOKEN")]
    token: Option<String>,

    /// Agent ID (after enrollment, persisted)
    #[arg(long, env = "REAP3R_AGENT_ID")]
    agent_id: Option<String>,

    /// Agent secret (after enrollment, persisted)
    #[arg(long, env = "REAP3R_AGENT_SECRET")]
    agent_secret: Option<String>,

    /// Heartbeat interval in seconds
    #[arg(long, default_value = "30", env = "REAP3R_HEARTBEAT_INTERVAL")]
    heartbeat_interval: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct AgentMessage {
    agent_id: String,
    ts: u64,
    nonce: String,
    #[serde(rename = "type")]
    msg_type: String,
    payload: serde_json::Value,
    hmac: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct EnrollResponse {
    success: bool,
    agent_id: Option<String>,
    agent_secret: Option<String>,
    error: Option<String>,
    server_ts: Option<u64>,
}

// ── Config persistence ──────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AgentConfig {
    agent_id: String,
    agent_secret: String,
    server: String,
    enrolled_at: u64,
}

fn config_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        // %ProgramData%\Reap3r
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        PathBuf::from(pd).join("Reap3r")
    } else {
        // /etc/reap3r
        PathBuf::from("/etc/reap3r")
    }
}

fn config_path() -> PathBuf {
    config_dir().join("agent.conf")
}

fn save_config(cfg: &AgentConfig) -> Result<(), String> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create config dir {:?}: {}", dir, e))?;
    let json = serde_json::to_string_pretty(cfg).map_err(|e| format!("Serialize: {}", e))?;
    let path = config_path();
    std::fs::write(&path, &json).map_err(|e| format!("Cannot write {:?}: {}", path, e))?;

    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms).ok();
    }

    info!(path = %path.display(), "Agent config saved");
    Ok(())
}

fn load_config() -> Option<AgentConfig> {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str::<AgentConfig>(&data) {
            Ok(cfg) => {
                info!(agent_id = %cfg.agent_id, path = %path.display(), "Loaded saved agent config");
                Some(cfg)
            }
            Err(e) => {
                warn!(error = %e, "Corrupt agent config, ignoring");
                None
            }
        },
        Err(_) => None,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn compute_hmac(msg: &serde_json::Value, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    // Compute over the message without the hmac field
    let mut obj = msg.as_object().unwrap().clone();
    obj.remove("hmac");
    let payload = serde_json::to_string(&serde_json::Value::Object(obj)).unwrap();
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn build_message(
    agent_id: &str,
    msg_type: &str,
    payload: serde_json::Value,
    secret: &str,
) -> String {
    let mut msg = serde_json::json!({
        "agent_id": agent_id,
        "ts": now_ms(),
        "nonce": Uuid::new_v4().to_string(),
        "type": msg_type,
        "payload": payload,
    });

    let hmac = compute_hmac(&msg, secret);
    msg["hmac"] = serde_json::Value::String(hmac);

    serde_json::to_string(&msg).unwrap()
}

fn get_system_info() -> (String, String, String, String) {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());

    (hostname, os.to_string(), arch.to_string(), os_version)
}

fn get_capabilities() -> Vec<String> {
    let mut caps = vec![
        "run_script".to_string(),
        "metrics".to_string(),
        "inventory".to_string(),
        "service_management".to_string(),
        "process_management".to_string(),
        "reboot".to_string(),
        "shutdown".to_string(),
        "self_update".to_string(),
        "file_transfer".to_string(),
    ];

    // Remote shell available on all platforms
    caps.push("remote_shell".to_string());

    // Remote desktop: Windows only for now
    #[cfg(target_os = "windows")]
    {
        caps.push("remote_desktop".to_string());
        caps.push("privacy_mode".to_string());
        caps.push("input_lock".to_string());
    }

    // WoL: available if network interfaces present
    caps.push("wake_on_lan".to_string());

    caps
}

fn collect_metrics() -> serde_json::Value {
    let mut sys = System::new_all();
    sys.refresh_all();

    serde_json::json!({
        "collected_at": now_ms(),
        "cpu_percent": sys.global_cpu_usage(),
        "memory_used_mb": sys.used_memory() as f64 / 1_048_576.0,
        "memory_total_mb": sys.total_memory() as f64 / 1_048_576.0,
        "processes_count": sys.processes().len(),
    })
}

async fn handle_job(
    job: &serde_json::Value,
    agent_id: &str,
    secret: &str,
) -> String {
    let job_id = job["id"].as_str().unwrap_or("");
    let job_type = job["type"].as_str().unwrap_or("");
    let payload = &job["payload"];

    info!(job_id, job_type, "Executing job");

    // Send ACK
    let ack = build_message(
        agent_id,
        "job_ack",
        serde_json::json!({ "job_id": job_id }),
        secret,
    );

    // Execute based on type
    let result = match job_type {
        "run_script" => execute_script(payload).await,
        "reboot" => {
            let delay = payload["delay_secs"].as_u64().unwrap_or(0);
            execute_system_command("reboot", delay).await
        }
        "shutdown" => {
            let delay = payload["delay_secs"].as_u64().unwrap_or(0);
            execute_system_command("shutdown", delay).await
        }
        "collect_metrics" => Ok(collect_metrics()),
        "collect_inventory" => Ok(collect_inventory()),
        "process_action" => execute_process_action(payload).await,
        "service_action" => execute_service_action(payload).await,
        "edr_kill_process" => execute_edr_kill_process(payload).await,
        "edr_isolate_machine" => execute_edr_isolate(payload).await,
        _ => Err(format!("Unsupported job type: {}", job_type)),
    };

    let result_msg = match result {
        Ok(data) => build_message(
            agent_id,
            "job_result",
            serde_json::json!({
                "job_id": job_id,
                "success": true,
                "data": data,
            }),
            secret,
        ),
        Err(err) => build_message(
            agent_id,
            "job_result",
            serde_json::json!({
                "job_id": job_id,
                "success": false,
                "error": err,
            }),
            secret,
        ),
    };

    // Return ACK first, result will be sent separately
    ack
}

// ── Inventory Collection ──────────────────────────────────

fn collect_inventory() -> serde_json::Value {
    let mut sys = System::new_all();
    sys.refresh_all();

    let (hostname, os, arch, os_version) = get_system_info();

    // CPU info
    let cpus = sys.cpus();
    let cpu_model = cpus.first().map(|c| c.brand().to_string()).unwrap_or_default();
    let cpu_cores = cpus.len();

    // Memory
    let memory_total = sys.total_memory();

    // Disk info
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk_total: u64 = disks.iter().map(|d| d.total_space()).sum();
    let disk_used: u64 = disks.iter().map(|d| d.total_space() - d.available_space()).sum();
    let disk_list: Vec<serde_json::Value> = disks.iter().map(|d| {
        serde_json::json!({
            "mount_point": d.mount_point().to_string_lossy(),
            "total_bytes": d.total_space(),
            "available_bytes": d.available_space(),
            "fs_type": String::from_utf8_lossy(d.file_system().as_encoded_bytes()),
        })
    }).collect();

    // Network interfaces
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let net_interfaces: Vec<serde_json::Value> = networks.iter().map(|(name, data)| {
        serde_json::json!({
            "name": name,
            "mac": data.mac_address().to_string(),
            "rx_bytes": data.total_received(),
            "tx_bytes": data.total_transmitted(),
        })
    }).collect();

    // Processes
    let process_count = sys.processes().len();

    // Top processes by CPU
    let mut procs: Vec<_> = sys.processes().values().collect();
    procs.sort_by(|a, b| b.cpu_usage().partial_cmp(&a.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));
    let top_procs: Vec<serde_json::Value> = procs.iter().take(20).map(|p| {
        serde_json::json!({
            "pid": p.pid().as_u32(),
            "name": p.name().to_string_lossy(),
            "cpu_percent": p.cpu_usage(),
            "memory_bytes": p.memory(),
            "status": format!("{:?}", p.status()),
            "user": p.user_id().map(|u| format!("{:?}", u)),
        })
    }).collect();

    serde_json::json!({
        "collected_at": now_ms(),
        "hostname": hostname,
        "os": os,
        "os_version": os_version,
        "arch": arch,
        "cpu_model": cpu_model,
        "cpu_cores": cpu_cores,
        "memory_total_bytes": memory_total,
        "disk_total_bytes": disk_total,
        "disk_used_bytes": disk_used,
        "disks": disk_list,
        "network_interfaces": net_interfaces,
        "process_count": process_count,
        "top_processes": top_procs,
    })
}

// ── Process Management ────────────────────────────────────

async fn execute_process_action(payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let action = payload["action"].as_str().unwrap_or("list");
    match action {
        "list" => {
            let mut sys = System::new_all();
            sys.refresh_all();
            let mut procs: Vec<serde_json::Value> = sys.processes().values().map(|p| {
                serde_json::json!({
                    "pid": p.pid().as_u32(),
                    "name": p.name().to_string_lossy(),
                    "cpu_percent": p.cpu_usage(),
                    "memory_bytes": p.memory(),
                    "status": format!("{:?}", p.status()),
                    "start_time": p.start_time(),
                    "cmd": p.cmd().join(" "),
                    "exe": p.exe().map(|e| e.to_string_lossy().to_string()),
                })
            }).collect();
            procs.sort_by(|a, b| {
                let ca = a["cpu_percent"].as_f64().unwrap_or(0.0);
                let cb = b["cpu_percent"].as_f64().unwrap_or(0.0);
                cb.partial_cmp(&ca).unwrap_or(std::cmp::Ordering::Equal)
            });
            Ok(serde_json::json!({ "processes": procs, "total": procs.len() }))
        }
        "kill" => {
            let pid = payload["pid"].as_u64().ok_or("Missing pid")?;
            let sys = System::new_all();
            let pid = sysinfo::Pid::from(pid as usize);
            if let Some(process) = sys.process(pid) {
                let killed = process.kill();
                Ok(serde_json::json!({ "killed": killed, "pid": pid.as_u32() }))
            } else {
                Err(format!("Process {} not found", pid))
            }
        }
        _ => Err(format!("Unknown process action: {}", action)),
    }
}

// ── Service Management ────────────────────────────────────

async fn execute_service_action(payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let service_name = payload["service_name"].as_str().ok_or("Missing service_name")?;
    let action = payload["action"].as_str().unwrap_or("status");

    let (cmd, args): (&str, Vec<String>) = if cfg!(target_os = "windows") {
        match action {
            "start" => ("sc", vec!["start".into(), service_name.into()]),
            "stop" => ("sc", vec!["stop".into(), service_name.into()]),
            "restart" => ("powershell", vec![
                "-NoProfile".into(), "-Command".into(),
                format!("Restart-Service -Name '{}' -Force", service_name),
            ]),
            "status" => ("sc", vec!["query".into(), service_name.into()]),
            _ => return Err(format!("Unknown service action: {}", action)),
        }
    } else {
        match action {
            "start" => ("systemctl", vec!["start".into(), service_name.into()]),
            "stop" => ("systemctl", vec!["stop".into(), service_name.into()]),
            "restart" => ("systemctl", vec!["restart".into(), service_name.into()]),
            "status" => ("systemctl", vec!["status".into(), service_name.into()]),
            _ => return Err(format!("Unknown service action: {}", action)),
        }
    };

    match tokio::process::Command::new(cmd).args(&args).output().await {
        Ok(output) => Ok(serde_json::json!({
            "exit_code": output.status.code().unwrap_or(-1),
            "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
            "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
            "service": service_name,
            "action": action,
        })),
        Err(e) => Err(format!("Failed to execute service action: {}", e)),
    }
}

// ── EDR Kill Process ──────────────────────────────────────

async fn execute_edr_kill_process(payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let pid = payload["pid"].as_u64().ok_or("Missing pid")?;
    let reason = payload["reason"].as_str().unwrap_or("EDR response");
    info!(pid, reason, "EDR: Killing process");

    let sys = System::new_all();
    let pid = sysinfo::Pid::from(pid as usize);
    if let Some(process) = sys.process(pid) {
        let name = process.name().to_string_lossy().to_string();
        let killed = process.kill();
        Ok(serde_json::json!({
            "killed": killed,
            "pid": pid.as_u32(),
            "process_name": name,
            "reason": reason,
        }))
    } else {
        Err(format!("Process {} not found", pid))
    }
}

// ── EDR Network Isolation ─────────────────────────────────

async fn execute_edr_isolate(payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let mode = payload["mode"].as_str().unwrap_or("soft");
    let reason = payload["reason"].as_str().unwrap_or("EDR response");

    info!(mode, reason, "EDR: Network isolation requested");

    // Platform-specific firewall rules
    let (cmd, args): (&str, Vec<String>) = if cfg!(target_os = "windows") {
        ("powershell", vec![
            "-NoProfile".into(), "-Command".into(),
            format!(
                "New-NetFirewallRule -DisplayName 'Reap3r-EDR-Isolate' -Direction Outbound -Action Block -Enabled True; \
                 New-NetFirewallRule -DisplayName 'Reap3r-EDR-Isolate-In' -Direction Inbound -Action Block -Enabled True"
            ),
        ])
    } else {
        ("bash", vec![
            "-c".into(),
            "iptables -I OUTPUT -j DROP -m comment --comment 'reap3r-edr-isolate'; \
             iptables -I INPUT -j DROP -m comment --comment 'reap3r-edr-isolate'".into(),
        ])
    };

    match tokio::process::Command::new(cmd).args(&args).output().await {
        Ok(output) => Ok(serde_json::json!({
            "isolated": output.status.success(),
            "mode": mode,
            "reason": reason,
            "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
        })),
        Err(e) => Err(format!("Failed to isolate: {}", e)),
    }
}

// ── Security Monitoring ───────────────────────────────────

fn check_security_events() -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    let sys = System::new_all();

    // Suspicious process names (common malware indicators)
    let suspicious_names = [
        "mimikatz", "bloodhound", "rubeus", "cobalt", "meterpreter",
        "powershell_ise", "certutil", "psexec", "procdump",
    ];

    // Suspicious paths
    let suspicious_paths = [
        "/tmp/.hidden", "/dev/shm/", "\\AppData\\Local\\Temp\\svchost",
        "\\Windows\\Temp\\cmd", "C:\\Users\\Public\\",
    ];

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        let exe = process.exe().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
        let cmd = process.cmd().join(" ");

        // Check suspicious process names
        for s in &suspicious_names {
            if name.contains(s) {
                events.push(serde_json::json!({
                    "event_type": "suspicious_path",
                    "severity": "high",
                    "timestamp": now_ms(),
                    "process_name": name,
                    "process_path": exe,
                    "pid": pid.as_u32(),
                    "cmdline": cmd,
                    "user": process.user_id().map(|u| format!("{:?}", u)),
                    "details": {
                        "reason": format!("Suspicious process detected: {}", s),
                        "match": s,
                    }
                }));
            }
        }

        // Check suspicious paths
        for sp in &suspicious_paths {
            if exe.contains(sp) {
                events.push(serde_json::json!({
                    "event_type": "suspicious_path",
                    "severity": "medium",
                    "timestamp": now_ms(),
                    "process_name": name,
                    "process_path": exe,
                    "pid": pid.as_u32(),
                    "cmdline": cmd,
                    "details": {
                        "reason": format!("Process running from suspicious path: {}", sp),
                        "match": sp,
                    }
                }));
            }
        }

        // Detect suspicious PowerShell usage (encoded commands)
        if name.contains("powershell") && (cmd.contains("-enc") || cmd.contains("-EncodedCommand") || cmd.contains("-WindowStyle Hidden")) {
            events.push(serde_json::json!({
                "event_type": "suspicious_powershell",
                "severity": "high",
                "timestamp": now_ms(),
                "process_name": name,
                "process_path": exe,
                "pid": pid.as_u32(),
                "cmdline": cmd,
                "details": {
                    "reason": "PowerShell with suspicious flags (encoded/hidden)",
                }
            }));
        }
    }

    events
}

async fn execute_script(payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let interpreter = payload["interpreter"].as_str().unwrap_or("bash");
    let script = payload["script"].as_str().unwrap_or("");
    let timeout_secs = payload["timeout_secs"].as_u64().unwrap_or(300);

    let start = std::time::Instant::now();

    let (cmd, args) = match interpreter {
        "bash" | "sh" => ("bash", vec!["-c", script]),
        "powershell" => ("powershell", vec!["-NoProfile", "-NonInteractive", "-Command", script]),
        "python" => ("python3", vec!["-c", script]),
        "cmd" => ("cmd", vec!["/C", script]),
        _ => return Err(format!("Unknown interpreter: {}", interpreter)),
    };

    let result = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio::process::Command::new(cmd)
            .args(&args)
            .output(),
    )
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(output)) => Ok(serde_json::json!({
            "exit_code": output.status.code().unwrap_or(-1),
            "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
            "stderr": String::from_utf8_lossy(&output.stderr).to_string(),
            "duration_ms": duration_ms,
        })),
        Ok(Err(e)) => Err(format!("Failed to execute: {}", e)),
        Err(_) => Err("Script execution timed out".to_string()),
    }
}

async fn execute_system_command(action: &str, delay_secs: u64) -> Result<serde_json::Value, String> {
    if delay_secs > 0 {
        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
    }

    let (cmd, args): (&str, Vec<&str>) = if cfg!(target_os = "windows") {
        match action {
            "reboot" => ("shutdown", vec!["/r", "/t", "0"]),
            "shutdown" => ("shutdown", vec!["/s", "/t", "0"]),
            _ => return Err("Unknown action".to_string()),
        }
    } else {
        match action {
            "reboot" => ("reboot", vec![]),
            "shutdown" => ("shutdown", vec!["-h", "now"]),
            _ => return Err("Unknown action".to_string()),
        }
    };

    match tokio::process::Command::new(cmd).args(&args).output().await {
        Ok(output) => Ok(serde_json::json!({
            "exit_code": output.status.code().unwrap_or(-1),
            "stdout": String::from_utf8_lossy(&output.stdout).to_string(),
        })),
        Err(e) => Err(format!("Failed: {}", e)),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .json()
        .init();

    let args = Args::parse();
    info!("MASSVISION Reap3r Agent starting...");
    info!(server = %args.server, "Connecting to server");

    loop {
        match run_agent(&args).await {
            Ok(()) => {
                warn!("Connection closed. Reconnecting in 5s...");
            }
            Err(e) => {
                error!(error = %e, "Agent error. Reconnecting in 5s...");
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_agent(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let url = url::Url::parse(&args.server)?;
    let (ws_stream, _) = connect_async(url).await?;
    let (mut write, mut read) = ws_stream.split();

    info!("Connected to server");

    let (hostname, os, arch, os_version) = get_system_info();

    // Determine if we need to enroll or reconnect
    let (agent_id, agent_secret) = if let (Some(id), Some(secret)) = (&args.agent_id, &args.agent_secret) {
        info!(agent_id = %id, "Reconnecting with CLI-provided identity");
        (id.clone(), secret.clone())
    } else if let Some(saved) = load_config() {
        // Auto-reconnect with persisted credentials
        info!(agent_id = %saved.agent_id, "Reconnecting with saved config");
        (saved.agent_id, saved.agent_secret)
    } else if let Some(token) = &args.token {
        info!("Enrolling with token...");
        // Send enrollment
        let enroll_msg = serde_json::json!({
            "agent_id": "00000000-0000-0000-0000-000000000000",
            "ts": now_ms(),
            "nonce": Uuid::new_v4().to_string(),
            "type": "enroll_request",
            "payload": {
                "hostname": hostname,
                "os": os,
                "os_version": os_version,
                "arch": arch,
                "agent_version": env!("CARGO_PKG_VERSION"),
                "enrollment_token": token,
            },
            "hmac": "0".repeat(64),
        });

        write.send(Message::Text(serde_json::to_string(&enroll_msg)?)).await?;

        // Wait for response
        if let Some(Ok(Message::Text(text))) = read.next().await {
            let resp: serde_json::Value = serde_json::from_str(&text)?;
            if resp["type"] == "enroll_response" {
                let payload = &resp["payload"];
                if payload["success"].as_bool() == Some(true) {
                    let id = payload["agent_id"].as_str().unwrap().to_string();
                    let secret = payload["agent_secret"].as_str().unwrap().to_string();
                    info!(agent_id = %id, "Enrollment successful!");
                    // Persist agent_id + secret to config file
                    if let Err(e) = save_config(&AgentConfig {
                        agent_id: id.clone(),
                        agent_secret: secret.clone(),
                        server: args.server.clone(),
                        enrolled_at: now_ms(),
                    }) {
                        warn!(error = %e, "Failed to save agent config — agent will need re-enrollment on next restart");
                    }
                    (id, secret)
                } else {
                    let err = payload["error"].as_str().unwrap_or("Unknown error");
                    return Err(format!("Enrollment failed: {}", err).into());
                }
            } else {
                return Err("Unexpected response during enrollment".into());
            }
        } else {
            return Err("No response from server during enrollment".into());
        }
    } else {
        return Err("No agent_id/secret or enrollment token provided".into());
    };

    // Send capabilities
    let caps_msg = build_message(
        &agent_id,
        "capabilities",
        serde_json::json!({
            "capabilities": get_capabilities(),
            "modules_version": { "core": env!("CARGO_PKG_VERSION") },
        }),
        &agent_secret,
    );
    write.send(Message::Text(caps_msg)).await?;

    // Spawn heartbeat task
    let agent_id_hb = agent_id.clone();
    let secret_hb = agent_secret.clone();
    let hb_interval = args.heartbeat_interval;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let tx_hb = tx.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(hb_interval));
        let mut inventory_counter: u64 = 0;
        loop {
            interval.tick().await;
            let metrics = collect_metrics();
            let hb = build_message(
                &agent_id_hb,
                "heartbeat",
                serde_json::json!({
                    "uptime_secs": sysinfo::System::uptime(),
                    "cpu_percent": metrics["cpu_percent"],
                    "memory_used_mb": metrics["memory_used_mb"],
                    "memory_total_mb": metrics["memory_total_mb"],
                }),
                &secret_hb,
            );
            if tx_hb.send(hb).await.is_err() {
                break;
            }

            // Also send metrics
            let metrics_msg = build_message(
                &agent_id_hb,
                "metrics_push",
                metrics,
                &secret_hb,
            );
            if tx_hb.send(metrics_msg).await.is_err() {
                break;
            }

            // Send inventory every 10 heartbeats (~5min at 30s interval)
            inventory_counter += 1;
            if inventory_counter % 10 == 1 {
                let inv = collect_inventory();
                let inv_msg = build_message(
                    &agent_id_hb,
                    "inventory_push",
                    inv,
                    &secret_hb,
                );
                if tx_hb.send(inv_msg).await.is_err() {
                    break;
                }
            }

            // Security monitoring: check for suspicious processes every heartbeat
            let alerts = check_security_events();
            for alert in alerts {
                let sec_msg = build_message(
                    &agent_id_hb,
                    "security_event_push",
                    alert,
                    &secret_hb,
                );
                if tx_hb.send(sec_msg).await.is_err() {
                    break;
                }
            }
        }
    });

    // Main loop: read messages + send outgoing
    let tx_jobs = tx.clone();
    let agent_id_loop = agent_id.clone();
    let secret_loop = agent_secret.clone();

    loop {
        tokio::select! {
            Some(msg) = read.next() => {
                match msg? {
                    Message::Text(text) => {
                        let data: serde_json::Value = serde_json::from_str(&text)?;
                        let msg_type = data["type"].as_str().unwrap_or("");

                        if msg_type == "job_assign" {
                            let job = &data["job"];
                            let ack = handle_job(job, &agent_id_loop, &secret_loop).await;
                            tx_jobs.send(ack).await.ok();

                            // Execute and send result
                            let result_msg = build_message(
                                &agent_id_loop,
                                "job_result",
                                serde_json::json!({
                                    "job_id": job["id"],
                                    "success": true,
                                    "data": {},
                                }),
                                &secret_loop,
                            );
                            tx_jobs.send(result_msg).await.ok();
                        }
                    }
                    Message::Close(_) => {
                        info!("Server closed connection");
                        break;
                    }
                    _ => {}
                }
            }
            Some(msg) = rx.recv() => {
                write.send(Message::Text(msg)).await?;
            }
            else => break,
        }
    }

    Ok(())
}

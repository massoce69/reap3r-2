// ─────────────────────────────────────────────
// MASSVISION Reap3r Agent — Main Entry Point
// ─────────────────────────────────────────────

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tracing::{error, info, warn};
use uuid::Uuid;

// ── Windows Service imports ───────────────────
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

type HmacSha256 = Hmac<Sha256>;

const MAX_JOB_HISTORY: usize = 256;
const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MB rotate threshold

// ── Remote Desktop global state ───────────────────────────
static RD_ACTIVE: AtomicBool = AtomicBool::new(false);

// ── Global file logger ────────────────────────────────────

/// A simple append-only file logger shared across threads.
struct FileLogger {
    path: PathBuf,
    file: Mutex<std::fs::File>,
}

impl FileLogger {
    fn open(path: &PathBuf) -> Option<Arc<Self>> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok()?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .ok()?;
        Some(Arc::new(Self {
            path: path.clone(),
            file: Mutex::new(file),
        }))
    }

    fn log(&self, level: &str, msg: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let line = format!("[{ts}] [{level:5}] {msg}\n");
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(line.as_bytes());
        }
        // Rotate if oversized (best-effort)
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() > LOG_MAX_BYTES {
                // Rename to .1 and re-open
                let rotated = self.path.with_extension("log.1");
                let _ = std::fs::rename(&self.path, &rotated);
                if let Ok(new_file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                {
                    if let Ok(mut guard) = self.file.lock() {
                        *guard = new_file;
                    }
                }
            }
        }
    }
}

/// Module-level optional file logger, set once during startup.
static FILE_LOGGER: std::sync::OnceLock<Option<Arc<FileLogger>>> = std::sync::OnceLock::new();

fn flog(level: &str, msg: &str) {
    if let Some(Some(logger)) = FILE_LOGGER.get() {
        logger.log(level, msg);
    }
}

macro_rules! finfo  { ($($arg:tt)*) => {{ let s = format!($($arg)*); info!("{}", s);  flog("INFO",  &s); }} }
macro_rules! fwarn  { ($($arg:tt)*) => {{ let s = format!($($arg)*); warn!("{}", s);  flog("WARN",  &s); }} }
macro_rules! ferror { ($($arg:tt)*) => {{ let s = format!($($arg)*); error!("{}", s); flog("ERROR", &s); }} }

// ── CLI Args ──────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "reap3r-agent", version, about = "MASSVISION Reap3r Agent")]
struct Args {
    /// Server WebSocket URL (e.g., wss://reap3r.example.com/ws/agent)
    #[arg(long, env = "REAP3R_SERVER")]
    server: Option<String>,

    /// Enrollment token (for initial enrollment)
    #[arg(long, env = "REAP3R_TOKEN")]
    token: Option<String>,

    /// Agent ID (after enrollment, persisted)
    #[arg(long, env = "REAP3R_AGENT_ID")]
    agent_id: Option<String>,

    /// HMAC key (after enrollment, persisted). Protocol v1 uses a single backend-provided key.
    #[arg(long, env = "REAP3R_HMAC_KEY")]
    hmac_key: Option<String>,

    /// Heartbeat interval in seconds
    #[arg(long, default_value = "30", env = "REAP3R_HEARTBEAT_INTERVAL")]
    heartbeat_interval: u64,

    /// Print diagnostic information (OS, paths, connectivity) and exit
    #[arg(long)]
    diagnose: bool,

    /// Print current loaded configuration and exit
    #[arg(long)]
    print_config: bool,

    /// Allow invalid/self-signed TLS certificates (DEV MODE ONLY — never use in production)
    #[arg(long, env = "REAP3R_INSECURE_TLS")]
    insecure_tls: bool,

    /// Run the agent for N seconds and exit (useful for installation smoke-tests)
    #[arg(long, default_value = "0", env = "REAP3R_RUN_FOR_SECS")]
    run_for_secs: u64,

    /// Custom log file path (overrides automatic detection)
    #[arg(long, env = "REAP3R_LOG_FILE")]
    log_file: Option<PathBuf>,
}

async fn connect_ws(
    server_url: &str,
    insecure_tls: bool,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::Error,
> {
    // ws:// always uses plain TCP, ignore insecure_tls.
    if server_url.starts_with("ws://") || !insecure_tls {
        let (ws, _) = connect_async(server_url).await?;
        return Ok(ws);
    }

    // wss:// with explicit insecure TLS (native-tls connector).
    // DEV ONLY: never use in production.
    let mut builder = native_tls::TlsConnector::builder();
    builder.danger_accept_invalid_certs(true);
    builder.danger_accept_invalid_hostnames(true);
    let tls = builder.build().map_err(|e| {
        tokio_tungstenite::tungstenite::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })?;
    let connector = tokio_tungstenite::Connector::NativeTls(tls);

    let req = server_url.into_client_request()?;
    let (ws, _) = tokio_tungstenite::connect_async_tls_with_config(req, None, false, Some(connector)).await?;
    Ok(ws)
}


// ── Config persistence ──────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AgentConfig {
    agent_id: String,
    hmac_key: String,
    server: String,
    enrolled_at: u64,
}

/// Returns the primary config/data directory.
/// - Windows (admin/SYSTEM): %ProgramData%\Reap3r
/// - Windows (user):         %LocalAppData%\Reap3r  (fallback)
/// - Linux/macOS:            /etc/reap3r
fn config_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        // Try %ProgramData% first (service / admin mode)
        if let Ok(pd) = std::env::var("ProgramData") {
            let p = PathBuf::from(pd).join("Reap3r");
            // Quick write-access probe
            if std::fs::create_dir_all(&p).is_ok() {
                let probe = p.join(".probe");
                if std::fs::write(&probe, b"x").is_ok() {
                    let _ = std::fs::remove_file(probe);
                    return p;
                }
            }
        }
        // Fallback: %LocalAppData%\Reap3r (user mode)
        let local = std::env::var("LocalAppData")
            .unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Local".to_string());
        PathBuf::from(local).join("Reap3r")
    } else {
        PathBuf::from("/etc/reap3r")
    }
}

/// Returns the log directory.
fn log_dir() -> PathBuf {
    config_dir().join("logs")
}

/// Returns the default log file path.
fn default_log_path() -> PathBuf {
    log_dir().join("agent.log")
}

fn config_path() -> PathBuf {
    config_dir().join("agent.conf")
}

fn job_history_path() -> PathBuf {
    config_dir().join("job_history.json")
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct JobHistoryFile {
    job_ids: Vec<String>,
}

fn load_job_history() -> JobHistoryFile {
    let path = job_history_path();
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str::<JobHistoryFile>(&data).unwrap_or_default(),
        Err(_) => JobHistoryFile::default(),
    }
}

fn save_job_history(file: &JobHistoryFile) {
    let path = job_history_path();
    let _ = std::fs::create_dir_all(config_dir());
    if let Ok(json) = serde_json::to_string_pretty(file) {
        let _ = std::fs::write(&path, json);
    }
}

struct AgentRuntimeState {
    job_file: JobHistoryFile,
    job_set: HashSet<String>,
}

impl AgentRuntimeState {
    fn load() -> Self {
        let job_file = load_job_history();
        let job_set = job_file.job_ids.iter().cloned().collect::<HashSet<_>>();
        Self { job_file, job_set }
    }

    fn has_job(&self, job_id: &str) -> bool {
        self.job_set.contains(job_id)
    }

    fn remember_job(&mut self, job_id: &str) {
        if self.job_set.contains(job_id) {
            return;
        }
        self.job_set.insert(job_id.to_string());
        self.job_file.job_ids.push(job_id.to_string());
        if self.job_file.job_ids.len() > MAX_JOB_HISTORY {
            let overflow = self.job_file.job_ids.len() - MAX_JOB_HISTORY;
            for _ in 0..overflow {
                if let Some(old) = self.job_file.job_ids.first().cloned() {
                    self.job_file.job_ids.remove(0);
                    self.job_set.remove(&old);
                }
            }
        }
        save_job_history(&self.job_file);
    }
}

fn save_config(cfg: &AgentConfig) -> Result<(), String> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| {
        // Emit to file log and stderr before returning
        let msg = format!("Cannot create config dir {:?}: {}", dir, e);
        flog("ERROR", &msg);
        msg
    })?;
    let json = serde_json::to_string_pretty(cfg).map_err(|e| format!("Serialize: {}", e))?;
    let path = config_path();
    std::fs::write(&path, &json).map_err(|e| {
        let msg = format!("Cannot write config {:?}: {}", path, e);
        flog("ERROR", &msg);
        msg
    })?;

    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms).ok();
    }

    finfo!("Agent config saved to {}", path.display());
    Ok(())
}

/// Run --diagnose mode: print OS info, paths, connectivity, and exit.
async fn run_diagnostics(args: &Args) {
    let (hostname, os, arch, os_ver) = get_system_info();
    let cfg_dir  = config_dir();
    let log_path = args.log_file.clone().unwrap_or_else(default_log_path);
    let cfg_path = config_path();

    println!("═══════════════════════════════════════════");
    println!("  Reap3r Agent — Diagnostic Report");
    println!("  {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
    println!("═══════════════════════════════════════════");
    println!();
    println!("[ System ]");
    println!("  Hostname  : {}", hostname);
    println!("  OS        : {} ({}) {}", os, arch, os_ver);

    // Admin check
    let is_admin = {
        #[cfg(target_os = "windows")]
        { std::process::Command::new("net").args(["session"]).output().map(|o| o.status.success()).unwrap_or(false) }
        #[cfg(not(target_os = "windows"))]
        { std::process::Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false) }
    };
    println!("  Admin     : {}", if is_admin { "YES" } else { "no (user mode)" });
    println!();
    println!("[ Paths ]");
    println!("  Config dir: {}", cfg_dir.display());
    println!("  Config file: {} [{}]", cfg_path.display(),
        if cfg_path.exists() { "EXISTS" } else { "missing" });
    println!("  Log file  : {}", log_path.display());

    // Writable check
    let writable = std::fs::create_dir_all(&cfg_dir).is_ok() && {
        let probe = cfg_dir.join(".probe");
        let ok = std::fs::write(&probe, b"x").is_ok();
        let _ = std::fs::remove_file(&probe);
        ok
    };
    println!("  Config writable: {}", if writable { "YES" } else { "NO — use --log-file / run as admin" });
    println!();
    println!("[ Saved Config ]");
    match load_config() {
        Some(cfg) => {
            println!("  agent_id   : {}", cfg.agent_id);
            println!("  server     : {}", cfg.server);
            let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(cfg.enrolled_at as i64)
                .map(|d| d.to_rfc3339())
                .unwrap_or_else(|| "?".to_string());
            println!("  enrolled_at: {}", ts);
        }
        None => println!("  (no saved config)"),
    }
    println!();
    println!("[ Connection ]");
    let server_url = args.server.clone()
        .or_else(|| load_config().map(|c| c.server))
        .unwrap_or_else(|| "(not configured)".to_string());
    println!("  Server URL : {}", server_url);

    if !server_url.starts_with("ws://") && !server_url.starts_with("wss://") {
        println!("  [ERROR] URL must start with ws:// or wss://");
    } else {
        // DNS lookup
        let host = url::Url::parse(&server_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default();
        if !host.is_empty() {
            use std::net::ToSocketAddrs;
            let addr = format!("{}:443", host);
            match addr.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(a) = addrs.next() {
                        println!("  DNS resolve : {} → {}", host, a.ip());
                    }
                }
                Err(e) => println!("  DNS resolve : {} FAILED — {}", host, e),
            }
        }
        // Try WS connect
        print!("  WS connect  : attempting...");
        let _ = std::io::stdout().flush();
        match tokio::time::timeout(
            Duration::from_secs(5),
            connect_ws(&server_url, args.insecure_tls),
        ).await {
            Ok(Ok(_)) => println!(" OK"),
            Ok(Err(e)) => println!(" FAILED — {}", e),
            Err(_) => println!(" TIMEOUT (5s)"),
        }
    }
    println!();
    println!("═══════════════════════════════════════════");
    flog("INFO", "Diagnostic run complete");
}

fn load_config() -> Option<AgentConfig> {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str::<AgentConfig>(&data) {
            Ok(cfg) => {
                finfo!("Loaded saved agent config: agent_id={} path={}", cfg.agent_id, path.display());
                Some(cfg)
            }
            Err(e) => {
                fwarn!("Corrupt agent config ({}), ignoring: {}", path.display(), e);
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

fn canonicalize_json(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Null => serde_json::Value::Null,
        serde_json::Value::Bool(b) => serde_json::Value::Bool(*b),
        serde_json::Value::Number(n) => serde_json::Value::Number(n.clone()),
        serde_json::Value::String(s) => serde_json::Value::String(s.clone()),
        serde_json::Value::Array(arr) => serde_json::Value::Array(arr.iter().map(canonicalize_json).collect()),
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(v2) = map.get(k) {
                    out.insert(k.clone(), canonicalize_json(v2));
                }
            }
            serde_json::Value::Object(out)
        }
    }
}

fn compute_sig(msg: &serde_json::Value, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    // Compute over the envelope without the sig field, using canonical JSON encoding (sorted keys).
    let mut obj = msg.as_object().unwrap().clone();
    obj.remove("sig");
    let canonical = canonicalize_json(&serde_json::Value::Object(obj));
    let payload = serde_json::to_string(&canonical).unwrap();
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn verify_sig(msg: &serde_json::Value, secret: &str) -> bool {
    let received = msg.get("sig").and_then(|v| v.as_str()).unwrap_or("");
    if received.is_empty() {
        return false;
    }
    let expected = compute_sig(msg, secret);
    received.eq_ignore_ascii_case(&expected)
}

fn build_message(
    agent_id: &str,
    msg_type: &str,
    payload: serde_json::Value,
    secret: &str,
) -> String {
    let mut msg = serde_json::json!({
        "type": msg_type,
        "ts": now_ms(),
        "nonce": Uuid::new_v4().to_string(),
        "traceId": Uuid::new_v4().to_string(),
        "agentId": agent_id,
        "payload": payload,
    });

    let sig = compute_sig(&msg, secret);
    msg["sig"] = serde_json::Value::String(sig);

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

    let memory_used_bytes = sys.used_memory();
    let memory_total_bytes = sys.total_memory();

    let disks = sysinfo::Disks::new_with_refreshed_list();
    let disk_total_bytes: u64 = disks.iter().map(|d| d.total_space()).sum();
    let disk_used_bytes: u64 = disks
        .iter()
        .map(|d| d.total_space().saturating_sub(d.available_space()))
        .sum();

    // sysinfo returns a floating CPU usage; protocol v1 uses an int percent to avoid
    // cross-language JSON float formatting issues in the signature.
    let cpu_percent = sys.global_cpu_usage().round().clamp(0.0, 100.0) as u64;

    serde_json::json!({
        "ts": now_ms(),
        "cpu_percent": cpu_percent,
        "memory_used_bytes": memory_used_bytes,
        "memory_total_bytes": memory_total_bytes,
        "disk_used_bytes": disk_used_bytes,
        "disk_total_bytes": disk_total_bytes,
        "process_count": sys.processes().len(),
    })
}

async fn handle_job(
    job: &serde_json::Value,
    agent_id: &str,
    secret: &str,
    tx: Option<tokio::sync::mpsc::Sender<String>>,
) -> (String, String, Vec<String>) {
    let job_id = job["job_id"].as_str().unwrap_or("");
    let job_type = job["name"].as_str().unwrap_or("");
    let payload = &job["args"];
    let timeout_sec = job["timeout_sec"].as_u64().unwrap_or(300);

    finfo!("Executing job: id={} type={}", job_id, job_type);

    // Send ACK with "running" status
    let ack = build_message(
        agent_id,
        "job_ack",
        serde_json::json!({ "job_id": job_id, "status": "running" }),
        secret,
    );

    let mut side_effects: Vec<String> = Vec::new();

    // Start timer for duration_ms
    let start_time = std::time::Instant::now();

    // Execute based on type, with timeout.
    let exec = async {
        match job_type {
            "run_script" => execute_script(payload).await,
            "reboot" => {
                let delay = payload["delay_sec"].as_u64().unwrap_or(0);
                execute_system_command("reboot", delay).await
            }
            "shutdown" => {
                let delay = payload["delay_sec"].as_u64().unwrap_or(0);
                execute_system_command("shutdown", delay).await
            }
            "collect_metrics" => Ok(collect_metrics()),
            "collect_inventory" => Ok(collect_inventory()),
            "process_action" => execute_process_action(payload).await,
            "service_action" => execute_service_action(payload).await,
            "edr_kill_process" => execute_edr_kill_process(payload).await,
            "edr_isolate_machine" => execute_edr_isolate(payload).await,
            "remote_desktop_start" => {
                start_remote_desktop(
                    payload,
                    agent_id.to_string(),
                    secret.to_string(),
                    job_id.to_string(),
                    tx.clone(),
                ).await
            }
            "remote_desktop_stop" => {
                RD_ACTIVE.store(false, Ordering::SeqCst);
                finfo!("Remote desktop stopped by job");
                Ok(serde_json::json!({ "exit_code": 0, "stdout": "Remote desktop stopped", "stderr": "" }))
            }
            _ => Err(format!("Unsupported job type: {}", job_type)),
        }
    };

    let result = match tokio::time::timeout(Duration::from_secs(timeout_sec), exec).await {
        Ok(inner) => inner,
        Err(_) => Err("timeout".to_string()),
    };

    let duration_ms = start_time.elapsed().as_millis() as u64;

    // Build result message with proper schema
    let result_msg = match result {
        Ok(data) => {
            // Side effects for "collect_inventory": push inventory snapshot immediately.
            if job_type == "collect_inventory" {
                let inv_msg = build_message(agent_id, "inventory_push", data.clone(), secret);
                side_effects.push(inv_msg);
            }

            // Extract exit_code, stdout, stderr from execution results (if script)
            let (exit_code, stdout, stderr) = if let Some(obj) = data.as_object() {
                (
                    obj.get("exit_code").and_then(|v| v.as_i64()).map(|v| v as i32),
                    obj.get("stdout").and_then(|v| v.as_str()).map(String::from),
                    obj.get("stderr").and_then(|v| v.as_str()).map(String::from),
                )
            } else {
                (None, None, None)
            };

            build_message(
                agent_id,
                "job_result",
                serde_json::json!({
                    "job_id": job_id,
                    "status": "success",
                    "exit_code": exit_code.unwrap_or(0),
                    "stdout": stdout.unwrap_or_default(),
                    "stderr": stderr.unwrap_or_default(),
                    "duration_ms": duration_ms,
                }),
                secret,
            )
        }
        Err(err) => {
            let status = if err == "timeout" { "timeout" } else { "failed" };
            build_message(
                agent_id,
                "job_result",
                serde_json::json!({
                    "job_id": job_id,
                    "status": status,
                    "error": err,
                    "duration_ms": duration_ms,
                }),
                secret,
            )
        }
    };

    // Return both ACK and result
    (ack, result_msg, side_effects)
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
        let cpu_percent = p.cpu_usage().round().clamp(0.0, 100.0) as u64;
        serde_json::json!({
            "pid": p.pid().as_u32(),
            "name": p.name().to_string_lossy(),
            "cpu_percent": cpu_percent,
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
                let cmd = p
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                let cpu_percent = p.cpu_usage().round().clamp(0.0, 100.0) as u64;
                serde_json::json!({
                    "pid": p.pid().as_u32(),
                    "name": p.name().to_string_lossy(),
                    "cpu_percent": cpu_percent,
                    "memory_bytes": p.memory(),
                    "status": format!("{:?}", p.status()),
                    "start_time": p.start_time(),
                    "cmd": cmd,
                    "exe": p.exe().map(|e| e.to_string_lossy().to_string()),
                })
            }).collect();
            procs.sort_by(|a, b| {
                let ca = a["cpu_percent"].as_u64().unwrap_or(0);
                let cb = b["cpu_percent"].as_u64().unwrap_or(0);
                cb.cmp(&ca)
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
        let cmd = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");

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

// ── Remote Desktop (screenshot streaming via PowerShell) ──

/// The PowerShell script that captures a single screenshot and outputs base64 JPEG.
/// Placeholders SCALE_FACTOR and QUALITY_VALUE are replaced at runtime.
const RD_CAPTURE_PS: &str = r#"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$s = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$w = [Math]::Round($s.Width * SCALE_FACTOR)
$h = [Math]::Round($s.Height * SCALE_FACTOR)
$bmp = New-Object System.Drawing.Bitmap($s.Width, $s.Height)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($s.Location, [System.Drawing.Point]::Empty, $s.Size)
$resized = New-Object System.Drawing.Bitmap($w, $h)
$g2 = [System.Drawing.Graphics]::FromImage($resized)
$g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g2.DrawImage($bmp, 0, 0, $w, $h)
$ms = New-Object System.IO.MemoryStream
$enc = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
$ep = New-Object System.Drawing.Imaging.EncoderParameters(1)
$ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, QUALITY_VALUE)
$resized.Save($ms, $enc, $ep)
[Convert]::ToBase64String($ms.ToArray())
$g.Dispose(); $g2.Dispose(); $bmp.Dispose(); $resized.Dispose(); $ms.Dispose()
"#;

async fn start_remote_desktop(
    payload: &serde_json::Value,
    agent_id: String,
    secret: String,
    job_id: String,
    tx: Option<tokio::sync::mpsc::Sender<String>>,
) -> Result<serde_json::Value, String> {
    let tx = tx.ok_or_else(|| "No WS channel available for streaming".to_string())?;

    // Parse parameters
    let fps = payload["fps"].as_u64().unwrap_or(2).clamp(1, 15);
    let quality = payload["quality"].as_u64().unwrap_or(50).clamp(10, 100);
    let scale = payload["scale"].as_f64().unwrap_or(0.5).clamp(0.2, 1.0);

    // Stop any existing session
    RD_ACTIVE.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Start new session
    RD_ACTIVE.store(true, Ordering::SeqCst);

    let session_id = job_id.clone();
    let frame_interval = Duration::from_millis(1000 / fps);

    let script_template = RD_CAPTURE_PS
        .replace("SCALE_FACTOR", &format!("{:.2}", scale))
        .replace("QUALITY_VALUE", &format!("{}", quality));

    finfo!(
        "Remote desktop started: session={} fps={} quality={} scale={:.0}%",
        session_id, fps, quality, scale * 100.0
    );

    // Spawn background capture loop
    tokio::spawn(async move {
        let mut sequence: u64 = 0;

        while RD_ACTIVE.load(Ordering::SeqCst) {
            let frame_start = std::time::Instant::now();

            // Capture screenshot via PowerShell
            match tokio::process::Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script_template])
                .output()
                .await
            {
                Ok(output) if output.status.success() => {
                    let b64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if b64.len() > 100 {
                        // Send stream_output frame
                        let msg = build_message(
                            &agent_id,
                            "stream_output",
                            serde_json::json!({
                                "session_id": session_id,
                                "stream_type": "frame",
                                "data": b64,
                                "sequence": sequence,
                            }),
                            &secret,
                        );
                        if tx.send(msg).await.is_err() {
                            fwarn!("RD: Failed to send frame, stopping");
                            break;
                        }
                        sequence += 1;
                    }
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    fwarn!("RD: PowerShell capture failed: {}", stderr.chars().take(200).collect::<String>());
                }
                Err(e) => {
                    fwarn!("RD: Failed to run PowerShell: {}", e);
                }
            }

            // Wait for next frame interval (minus time already spent capturing)
            let elapsed = frame_start.elapsed();
            if elapsed < frame_interval {
                tokio::time::sleep(frame_interval - elapsed).await;
            }
        }

        RD_ACTIVE.store(false, Ordering::SeqCst);
        finfo!("Remote desktop session ended: session={}", session_id);
    });

    Ok(serde_json::json!({
        "exit_code": 0,
        "stdout": format!("Remote desktop started: fps={} quality={} scale={:.0}%", fps, quality, scale * 100.0),
        "stderr": ""
    }))
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

// ── Windows Service implementation ───────────────────────
// Placed here so finfo!/fwarn!/ferror! macros and all agent functions are in scope.

#[cfg(windows)]
const SERVICE_NAME: &str = "MASSVISION-Reap3r-Agent";

#[cfg(windows)]
define_windows_service!(ffi_service_main, windows_service_main);

#[cfg(windows)]
fn windows_service_main(_svc_args: Vec<std::ffi::OsString>) {
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

    let status_handle = match service_control_handler::register(SERVICE_NAME, move |ctrl| {
        match ctrl {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    }) {
        Ok(h) => h,
        Err(e) => {
            flog("ERROR", &format!("SCM register failed: {}", e));
            return;
        }
    };

    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
    flog("INFO", "Windows Service: Running");

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let args = build_args_from_config();
        let server = match args.server.clone().or_else(|| load_config().map(|c| c.server)) {
            Some(s) => s,
            None => {
                flog("ERROR", "No server URL — cannot start");
                return;
            }
        };
        let mut state = AgentRuntimeState::load();
        let mut backoff: u64 = 1;
        loop {
            if shutdown_rx.try_recv().is_ok() { break; }
            let res = run_agent(&args, &server, &mut state).await;
            match &res {
                Ok(()) => fwarn!("Connection closed. Reconnecting in {}s...", backoff),
                Err(e) => ferror!("Error: {}. Reconnecting in {}s...", e, backoff),
            }
            if shutdown_rx.try_recv().is_ok() { break; }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = if res.is_ok() { 1 } else { (backoff * 2).min(60) };
        }
    });

    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });
    flog("INFO", "Windows Service: Stopped");
}

#[cfg(windows)]
fn build_args_from_config() -> Args {
    let saved = load_config();
    Args {
        server: saved.as_ref().map(|c| c.server.clone())
            .or_else(|| std::env::var("REAP3R_SERVER").ok()),
        token: std::env::var("REAP3R_TOKEN").ok(),
        agent_id: saved.as_ref().map(|c| c.agent_id.clone())
            .or_else(|| std::env::var("REAP3R_AGENT_ID").ok()),
        hmac_key: saved.as_ref().map(|c| c.hmac_key.clone())
            .or_else(|| std::env::var("REAP3R_HMAC_KEY").ok()),
        heartbeat_interval: std::env::var("REAP3R_HEARTBEAT_INTERVAL")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(30),
        diagnose: false,
        print_config: false,
        insecure_tls: std::env::var("REAP3R_INSECURE_TLS").as_deref() == Ok("1"),
        run_for_secs: std::env::var("REAP3R_RUN_FOR_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
        log_file: None,
    }
}

#[tokio::main]
async fn main() {
    // ── Windows: try service dispatcher first ─────────────
    // When launched by Windows SCM, service_dispatcher::start() will block and
    // call windows_service_main(). If we're NOT running as a service (e.g. CLI),
    // it returns an error immediately and we fall through to normal CLI mode.
    #[cfg(windows)]
    {
        // Init file logger early before any other code.
        let log_path = std::env::var("REAP3R_LOG_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_log_path());
        let _ = FILE_LOGGER.set(FileLogger::open(&log_path));

        // If REAP3R_SERVICE_MODE=1, we are running as a Windows service.
        if std::env::var("REAP3R_SERVICE_MODE").as_deref() == Ok("1") {
            flog("INFO", "REAP3R_SERVICE_MODE=1 — starting Windows service dispatcher");
            match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
                Ok(()) => return,
                Err(e) => {
                    flog("ERROR", &format!("service_dispatcher::start failed: {}", e));
                    // Fall through — will fail at Args::parse() if no args, which is fine
                }
            }
        }
    }

    // ── 1. Init tracing (stdout) ──────────────────────────
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(cfg!(not(target_os = "windows")))
        .json()
        .init();

    let args = Args::parse();

    // ── 2. Init file logger ───────────────────────────────
    let log_path = args.log_file.clone().unwrap_or_else(default_log_path);
    let _ = FILE_LOGGER.set(FileLogger::open(&log_path));

    finfo!("═════════════════════════════════════════════════");
    finfo!("MASSVISION Reap3r Agent v{} starting", env!("CARGO_PKG_VERSION"));
    finfo!("Log file: {}", log_path.display());
    finfo!("PID: {}", std::process::id());

    // ── 3. URL validation ─────────────────────────────────
    // Do this before anything else so errors are visible in the log.
    let server_url = args.server.clone().or_else(|| load_config().map(|c| c.server));
    if let Some(ref url) = server_url {
        if !url.starts_with("ws://") && !url.starts_with("wss://") {
            let msg = format!(
                "FATAL: Invalid server URL '{}'. Must start with ws:// or wss://. \
                 Use: reap3r-agent.exe --server wss://YOUR_SERVER/ws/agent --token YOUR_TOKEN",
                url
            );
            ferror!("{}", msg);
            eprintln!("{}", msg);
            std::process::exit(1);
        }
        if cfg!(not(debug_assertions)) && url.starts_with("ws://") {
            fwarn!("WARNING: Using plain ws:// (unencrypted). Production deployments should use wss://");
        }
    }

    // ── 4. Dev-only insecure TLS guard ───────────────────
    if false {
        let msg = "FATAL: --insecure-tls is disabled by policy in this build.\n\
                   Fix your TLS certificate instead.";
        ferror!("{}", msg);
        eprintln!("{}", msg);
        std::process::exit(1);
    }
    if args.insecure_tls {
        fwarn!("WARNING: --insecure-tls active — TLS certificate validation is DISABLED");
    }

    // ── 5. --diagnose mode ────────────────────────────────
    if args.diagnose {
        run_diagnostics(&args).await;
        std::process::exit(0);
    }

    // ── 6. --print-config mode ────────────────────────────
    if args.print_config {
        match load_config() {
            Some(cfg) => {
                println!("Loaded config from: {}", config_path().display());
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap_or_default());
            }
            None => println!("No saved config at: {}", config_path().display()),
        }
        std::process::exit(0);
    }

    // ── 7. Require server (from args or saved config) ─────
    let server = match args.server.clone().or_else(|| load_config().map(|c| c.server)) {
        Some(s) => s,
        None => {
            let msg = "FATAL: No server URL provided and no saved config found.\n\
                       Use: reap3r-agent.exe --server wss://YOUR_SERVER/ws/agent --token YOUR_TOKEN\n\
                       Or run with --diagnose to see what is configured.";
            ferror!("{}", msg);
            eprintln!("{}", msg);
            std::process::exit(2);
        }
    };

    finfo!("Connecting to server: {}", server);
    let mut state = AgentRuntimeState::load();
    let mut backoff_secs: u64 = 1;

    if args.run_for_secs > 0 {
        finfo!("run-for-secs={} => single session (no reconnect loop)", args.run_for_secs);
        match tokio::time::timeout(Duration::from_secs(args.run_for_secs), run_agent(&args, &server, &mut state)).await {
            Ok(Ok(())) => std::process::exit(0),
            Ok(Err(e)) => {
                ferror!("Agent session failed: {}", e);
                std::process::exit(1);
            }
            Err(_) => {
                finfo!("run-for-secs elapsed, exiting");
                std::process::exit(0);
            }
        }
    }

    loop {
        let res = run_agent(&args, &server, &mut state).await;
        match &res {
            Ok(()) => { fwarn!("Connection closed cleanly. Reconnecting in {}s...", backoff_secs) }
            Err(e) => { ferror!("Agent error: {}. Reconnecting in {}s...", e, backoff_secs) }
        }

        let jitter_ms = (Uuid::new_v4().as_u128() % 500) as u64;
        tokio::time::sleep(Duration::from_millis(backoff_secs * 1000 + jitter_ms)).await;
        backoff_secs = if res.is_ok() { 1 } else { (backoff_secs * 2).min(60) };
    }
}

async fn run_agent(args: &Args, server: &str, state: &mut AgentRuntimeState) -> Result<(), Box<dyn std::error::Error>> {
    let url = url::Url::parse(server)?;
    finfo!("Connecting to {}", url.as_str());

    let ws_stream = connect_ws(url.as_str(), args.insecure_tls).await.map_err(|e| {
        let msg = format!("WebSocket connection failed to {}: {}", url, e);
        ferror!("{}", msg);
        // Friendly hint for common TLS errors
        let emsg = e.to_string().to_lowercase();
        if emsg.contains("certificate") || emsg.contains("tls") || emsg.contains("ssl") {
            ferror!("TLS hint: if using a self-signed cert, check your server certificate. \
                     For dev only: run with --insecure-tls");
        }
        msg
    })?;

    let (mut write, mut read) = ws_stream.split();
    finfo!("Connected to server OK");

    let (hostname, os, arch, os_version) = get_system_info();

    // Determine if we need to enroll or reconnect.
    // Priority order:
    //  1. Explicit --agent-id + --hmac-key CLI flags
    //  2. Saved agent.conf (already enrolled on a previous run) ← checked BEFORE token
    //  3. --token provided for first enrollment
    // This ensures that even when --token is permanently baked into a Scheduled Task,
    // we do NOT re-enroll on every restart once agent.conf exists.
    let (agent_id, hmac_key) = if let (Some(id), Some(key)) = (&args.agent_id, &args.hmac_key) {
        finfo!("Reconnecting with CLI-provided identity: agent_id={}", id);
        (id.clone(), key.clone())
    } else if let Some(saved) = load_config().filter(|c| !c.agent_id.is_empty() && !c.hmac_key.is_empty()) {
        finfo!("Reconnecting with saved config: agent_id={}", saved.agent_id);
        (saved.agent_id, saved.hmac_key)
    } else if let Some(token) = &args.token {
        // No saved config → first enrollment with token.
        finfo!("No saved config found — enrolling with token...");
        let enroll_msg = serde_json::json!({
            "agentId": "00000000-0000-0000-0000-000000000000",
            "ts": now_ms(),
            "nonce": Uuid::new_v4().to_string(),
            "traceId": Uuid::new_v4().to_string(),
            "type": "enroll_request",
            "payload": {
                "hostname": hostname,
                "os": os,
                "os_version": os_version,
                "arch": arch,
                "agent_version": env!("CARGO_PKG_VERSION"),
                "enrollment_token": token,
            },
        });

        write.send(Message::Text(serde_json::to_string(&enroll_msg)?)).await?;

        // Wait for response
        if let Some(Ok(Message::Text(text))) = read.next().await {
            let resp: serde_json::Value = serde_json::from_str(&text)?;
            if resp["type"] == "enroll_response" {
                let payload = &resp["payload"];

                if let Some(err) = payload["error"].as_str() {
                    let msg = format!("Enrollment FAILED: {}", err);
                    ferror!("{}", msg);
                    return Err(msg.into());
                }

                let id = payload["agent_id"]
                    .as_str()
                    .ok_or("Enrollment response missing agent_id")?
                    .to_string();

                let key = payload["hmac_key"]
                    .as_str()
                    .or_else(|| payload["agent_secret"].as_str())
                    .ok_or("Enrollment response missing hmac_key/agent_secret")?
                    .to_string();

                finfo!("Enrolled OK — agent_id={}", id);
                // Persist agent_id + hmac_key to config file
                if let Err(e) = save_config(&AgentConfig {
                    agent_id: id.clone(),
                    hmac_key: key.clone(),
                    server: server.to_string(),
                    enrolled_at: now_ms(),
                }) {
                    fwarn!("Failed to save agent config — will need re-enrollment on restart: {}", e);
                }
                (id, key)
            } else {
                return Err("Unexpected response type during enrollment".into());
            }
        } else {
            return Err("No response from server during enrollment".into());
        }
    } else {
        let msg = "No credentials available: provide --server and --token for first enroll, \
                   or ensure agent.conf exists from a previous enrollment.\n\
                   Usage: reap3r-agent.exe --server wss://SERVER/ws/agent --token TOKEN";
        ferror!("{}", msg);
        return Err(msg.into());
    };

    // Send capabilities
    let caps_msg = build_message(
        &agent_id,
        "capabilities",
        serde_json::json!({
            "capabilities": get_capabilities(),
            "modules_version": { "core": env!("CARGO_PKG_VERSION") },
        }),
        &hmac_key,
    );
    write.send(Message::Text(caps_msg)).await?;
    finfo!("Capabilities sent");

    // Spawn heartbeat task
    let agent_id_hb = agent_id.clone();
    let key_hb = hmac_key.clone();
    let hb_interval = args.heartbeat_interval;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    let tx_hb = tx.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(hb_interval));
        let mut inventory_counter: u64 = 0;
        loop {
            interval.tick().await;
            let metrics = collect_metrics();
            let mem_used = metrics["memory_used_bytes"].as_u64().unwrap_or(0);
            let mem_total = metrics["memory_total_bytes"].as_u64().unwrap_or(0);
            let disk_used = metrics["disk_used_bytes"].as_u64().unwrap_or(0);
            let disk_total = metrics["disk_total_bytes"].as_u64().unwrap_or(0);

            let memory_percent = if mem_total > 0 { ((mem_used as f64 / mem_total as f64) * 100.0).round() as u64 } else { 0 };
            let disk_percent = if disk_total > 0 { ((disk_used as f64 / disk_total as f64) * 100.0).round() as u64 } else { 0 };
            let hb = build_message(
                &agent_id_hb,
                "heartbeat",
                serde_json::json!({
                    "uptime_sec": sysinfo::System::uptime(),
                    "memory_percent": memory_percent,
                    "disk_percent": disk_percent,
                }),
                &key_hb,
            );
            finfo!(
                "Heartbeat queued (cpu={}% mem={}% disk={}%)",
                metrics["cpu_percent"].as_u64().unwrap_or(0),
                memory_percent,
                disk_percent
            );
            if tx_hb.send(hb).await.is_err() {
                break;
            }

            // Also send metrics
            let metrics_msg = build_message(
                &agent_id_hb,
                "metrics_push",
                metrics,
                &key_hb,
            );
            finfo!("Metrics queued");
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
                    &key_hb,
                );
                finfo!("Inventory queued");
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
                    &key_hb,
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
    let key_loop = hmac_key.clone();

    loop {
        tokio::select! {
            Some(msg) = read.next() => {
                match msg? {
                    Message::Text(text) => {
                        let data: serde_json::Value = serde_json::from_str(&text)?;
                        let msg_type = data["type"].as_str().unwrap_or("");

                        if msg_type == "job_assign" {
                            if !verify_sig(&data, &key_loop) {
                                fwarn!("Received job_assign with invalid signature, ignoring");
                                continue;
                            }
                            // Backend sends job in payload field (protocol standard)
                            let job = &data["payload"];
                            if job.is_null() {
                                fwarn!("Received job_assign with no payload, ignoring");
                                continue;
                            }

                            let job_id = job["job_id"].as_str().unwrap_or("");
                            let job_type = job["name"].as_str().unwrap_or("unknown");
                            if job_id.is_empty() {
                                fwarn!("Received job_assign with missing job_id, ignoring");
                                continue;
                            }
                            if state.has_job(job_id) {
                                fwarn!("Duplicate job_id={} — rejecting (idempotence)", job_id);
                                let rej = build_message(
                                    &agent_id_loop,
                                    "job_ack",
                                    serde_json::json!({ "job_id": job_id, "status": "rejected", "reason": "duplicate" }),
                                    &key_loop,
                                );
                                tx_jobs.send(rej).await.ok();
                                continue;
                            }

                            finfo!("Job received: id={} type={}", job_id, job_type);
                            let (ack_msg, result_msg, side_effects) = handle_job(job, &agent_id_loop, &key_loop, Some(tx_jobs.clone())).await;
                            // Send ACK first
                            tx_jobs.send(ack_msg).await.ok();
                            // Side-effects (e.g., inventory push for collect_inventory)
                            for m in side_effects {
                                tx_jobs.send(m).await.ok();
                            }
                            // Then send result
                            tx_jobs.send(result_msg).await.ok();
                            state.remember_job(job_id);
                            finfo!("Job completed: id={} type={}", job_id, job_type);
                        }
                    }
                    Message::Ping(p) => {
                        // Respond quickly to keep the connection alive behind proxies/NATs.
                        write.send(Message::Pong(p)).await?;
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

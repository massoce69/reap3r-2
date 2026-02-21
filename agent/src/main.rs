// XEFI Agent 2 Ã¢â‚¬â€ Main Entry Point
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::Message};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tracing::{error, info, warn};
use uuid::Uuid;

// Ã¢â€â‚¬Ã¢â€â‚¬ Windows Service imports Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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
const DEFAULT_MAX_JOB_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MB
const MAX_JOB_OUTPUT_BYTES_HARD_CAP: usize = 5 * 1024 * 1024; // 5 MB
const UPDATE_PUBLIC_KEY_HEX: &str = match option_env!("REAP3R_UPDATE_PUBKEY_HEX") {
    Some(v) => v,
    None => "",
};

// Ã¢â€â‚¬Ã¢â€â‚¬ Remote Desktop global state Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
static RD_ACTIVE: AtomicBool = AtomicBool::new(false);

fn rd_session_state() -> &'static Mutex<Option<String>> {
    static RD_SESSION: std::sync::OnceLock<Mutex<Option<String>>> = std::sync::OnceLock::new();
    RD_SESSION.get_or_init(|| Mutex::new(None))
}

fn rd_set_session_id(session_id: Option<String>) {
    if let Ok(mut guard) = rd_session_state().lock() {
        *guard = session_id;
    }
}

fn rd_session_matches(session_id: Option<&str>) -> bool {
    match session_id {
        None => true,
        Some(incoming) => {
            if let Ok(guard) = rd_session_state().lock() {
                if let Some(active) = guard.as_ref() {
                    return active == incoming;
                }
                return false;
            }
            false
        }
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Global file logger Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

// Ã¢â€â‚¬Ã¢â€â‚¬ Windows Event Log writer Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Reports critical events (start, stop, errors, updates) to the
// Windows Application Event Log so enterprise SIEM tools pick them up.

#[cfg(windows)]
mod eventlog {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    const EVENTLOG_INFORMATION_TYPE: u16 = 0x0004;
    const EVENTLOG_WARNING_TYPE: u16 = 0x0002;
    const EVENTLOG_ERROR_TYPE: u16 = 0x0001;

    type HANDLE = *mut std::ffi::c_void;
    type WORD = u16;
    type DWORD = u32;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegisterEventSourceW(lpUNCServerName: *const u16, lpSourceName: *const u16) -> HANDLE;
        fn ReportEventW(
            hEventLog: HANDLE,
            wType: WORD,
            wCategory: WORD,
            dwEventID: DWORD,
            lpUserSid: *const std::ffi::c_void,
            wNumStrings: WORD,
            dwDataSize: DWORD,
            lpStrings: *const *const u16,
            lpRawData: *const std::ffi::c_void,
        ) -> i32;
        fn DeregisterEventSource(hEventLog: HANDLE) -> i32;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    /// Write an entry to Windows Event Log under source "XEFI Agent 2".
    /// level: "INFO", "WARN", or "ERROR"
    pub fn write(level: &str, msg: &str) {
        unsafe {
            let source = to_wide("XEFI Agent 2");
            let h = RegisterEventSourceW(ptr::null(), source.as_ptr());
            if h.is_null() {
                return;
            }
            let event_type = match level {
                "ERROR" => EVENTLOG_ERROR_TYPE,
                "WARN" => EVENTLOG_WARNING_TYPE,
                _ => EVENTLOG_INFORMATION_TYPE,
            };
            let wide_msg = to_wide(msg);
            let msg_ptr = wide_msg.as_ptr();
            ReportEventW(
                h,
                event_type,
                0,    // category
                1000, // event ID
                ptr::null(),
                1,
                0,
                &msg_ptr,
                ptr::null(),
            );
            DeregisterEventSource(h);
        }
    }
}

fn flog(level: &str, msg: &str) {
    if let Some(Some(logger)) = FILE_LOGGER.get() {
        logger.log(level, msg);
    }
    // Also write to Windows Event Log for ERROR and WARN
    #[cfg(windows)]
    {
        if level == "ERROR" || level == "WARN" {
            eventlog::write(level, msg);
        }
    }
}

/// Write to Windows Event Log only (for critical lifecycle events)
#[cfg(windows)]
fn eventlog_info(msg: &str) {
    eventlog::write("INFO", msg);
}
#[cfg(not(windows))]
fn eventlog_info(_msg: &str) {}

macro_rules! finfo  { ($($arg:tt)*) => {{ let s = format!($($arg)*); info!("{}", s);  flog("INFO",  &s); }} }
macro_rules! fwarn  { ($($arg:tt)*) => {{ let s = format!($($arg)*); warn!("{}", s);  flog("WARN",  &s); }} }
macro_rules! ferror { ($($arg:tt)*) => {{ let s = format!($($arg)*); error!("{}", s); flog("ERROR", &s); }} }

// Ã¢â€â‚¬Ã¢â€â‚¬ CLI Args Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

#[derive(Parser, Debug)]
#[command(name = "xefi-agent-2", version, about = "XEFI Agent 2")]
struct Args {
    /// One-shot enrollment (persist credentials then exit)
    #[arg(long)]
    enroll: bool,

    /// Explicit run mode (intended for Windows service binPath)
    #[arg(long)]
    run: bool,

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

    /// Maximum reconnect back-off in seconds (spread 20k agents, default=300)
    #[arg(long, default_value = "300", env = "REAP3R_MAX_BACKOFF")]
    max_backoff: u64,

    /// Local HTTP health-check port (0 = disabled). Exposes GET /health for Zabbix/Prometheus.
    #[arg(long, default_value = "0", env = "REAP3R_HEALTH_PORT")]
    health_port: u16,

    /// Print diagnostic information (OS, paths, connectivity) and exit
    #[arg(long)]
    diagnose: bool,

    /// Print operational status (enrollment, connectivity, recent errors) and exit
    #[arg(long)]
    status: bool,

    /// Print recent log lines and exit
    #[arg(long)]
    logs: bool,

    /// Run local health checks (runtime + connectivity) and exit
    #[arg(long)]
    self_test: bool,

    /// Print current loaded configuration and exit
    #[arg(long)]
    print_config: bool,

    /// Allow invalid/self-signed TLS certificates (DEV MODE ONLY Ã¢â‚¬â€ never use in production)
    #[arg(long, env = "REAP3R_INSECURE_TLS")]
    insecure_tls: bool,

    /// Run the agent for N seconds and exit (useful for installation smoke-tests)
    #[arg(long, default_value = "0", env = "REAP3R_RUN_FOR_SECS")]
    run_for_secs: u64,

    /// Custom log file path (overrides automatic detection)
    #[arg(long, env = "REAP3R_LOG_FILE")]
    log_file: Option<PathBuf>,

    /// Number of lines to show with --logs
    #[arg(long, default_value = "200", env = "REAP3R_LOG_LINES")]
    log_lines: usize,

    /// Install the agent as a Windows Service and exit
    #[arg(long)]
    install: bool,

    /// Uninstall the Windows Service and exit
    #[arg(long)]
    uninstall: bool,
}

async fn connect_ws(
    server_url: &str,
    insecure_tls: bool,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::Error,
> {
    // ws:// uses plain TCP Ã¢â‚¬â€ no TLS connector needed.
    if server_url.starts_with("ws://") {
        let req = server_url.into_client_request()?;
        let (ws, _) = connect_async_tls_with_config(req, None, false, None).await?;
        return Ok(ws);
    }

    // wss:// Ã¢â€ â€™ build a rustls connector (pure-Rust TLS 1.2+, no OS dependencies).
    // This works on Windows 7 SP1 without any KB updates or OpenSSL DLLs.
    let tls_config = if insecure_tls {
        // DEV ONLY: accept any certificate
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth()
    } else {
        // Production: use Mozilla CA roots (bundled Ã¢â‚¬â€ no OS cert store dependency)
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_config));
    let req = server_url.into_client_request()?;
    let (ws, _) = connect_async_tls_with_config(req, None, false, Some(connector)).await?;
    Ok(ws)
}

/// Danger: accepts any TLS certificate. DEV ONLY.
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}


// Ã¢â€â‚¬Ã¢â€â‚¬ Config persistence Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AgentConfig {
    agent_id: String,
    hmac_key: String,
    server: String,
    enrolled_at: u64,
}

/// Returns the primary config/data directory.
/// - Windows (admin/SYSTEM): %ProgramData%\XefiAgent2
/// - Windows (user):         %LocalAppData%\XefiAgent2  (fallback)
/// - Linux/macOS:            /etc/xefi-agent-2
fn config_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        // Try %ProgramData% first (service / admin mode)
        if let Ok(pd) = std::env::var("ProgramData") {
            let p = PathBuf::from(pd).join("XefiAgent2");
            // Quick write-access probe
            if std::fs::create_dir_all(&p).is_ok() {
                let probe = p.join(".probe");
                if std::fs::write(&probe, b"x").is_ok() {
                    let _ = std::fs::remove_file(probe);
                    return p;
                }
            }
        }
        // Fallback: %LocalAppData%\XefiAgent2 (user mode)
        let local = std::env::var("LocalAppData")
            .unwrap_or_else(|_| "C:\\Users\\Default\\AppData\\Local".to_string());
        PathBuf::from(local).join("XefiAgent2")
    } else {
        PathBuf::from("/etc/xefi-agent-2")
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

    // Harden Windows ACL so only SYSTEM + Administrators can read secrets.
    if let Err(e) = apply_windows_secret_acl(&path) {
        fwarn!("Could not enforce secret ACL on {}: {}", path.display(), e);
    }

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

#[cfg(windows)]
fn apply_windows_secret_acl(path: &Path) -> Result<(), String> {
    let p = path
        .to_str()
        .ok_or_else(|| format!("Non-UTF8 path not supported for ACL: {}", path.display()))?;

    let inherit = std::process::Command::new("icacls")
        .args([p, "/inheritance:r"])
        .output()
        .map_err(|e| format!("icacls /inheritance:r failed: {}", e))?;
    if !inherit.status.success() {
        return Err(format!(
            "icacls /inheritance:r failed: {}",
            String::from_utf8_lossy(&inherit.stderr).trim()
        ));
    }

    let grant = std::process::Command::new("icacls")
        .args([p, "/grant:r", "SYSTEM:F", "Administrators:F"])
        .output()
        .map_err(|e| format!("icacls /grant:r failed: {}", e))?;
    if !grant.status.success() {
        return Err(format!(
            "icacls /grant:r failed: {}",
            String::from_utf8_lossy(&grant.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn apply_windows_secret_acl(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn bootstrap_path() -> PathBuf {
    config_dir().join("bootstrap.json")
}

fn remove_bootstrap_file() {
    let bp = bootstrap_path();
    if bp.exists() {
        if let Err(e) = std::fs::remove_file(&bp) {
            fwarn!("Could not remove bootstrap token file {}: {}", bp.display(), e);
        } else {
            finfo!("Removed bootstrap token file: {}", bp.display());
        }
    }
}

fn truncate_utf8_to_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = s[..cut].to_string();
    out.push_str("\n...[truncated]");
    out
}

fn last_error_line(log_path: &Path) -> Option<String> {
    let data = std::fs::read_to_string(log_path).ok()?;
    data.lines()
        .rev()
        .find(|line| line.contains("[ERROR]"))
        .map(|s| s.to_string())
}

fn print_logs_tail(log_path: &Path, lines: usize) -> Result<(), String> {
    let data = std::fs::read_to_string(log_path)
        .map_err(|e| format!("Cannot read {}: {}", log_path.display(), e))?;
    let lines_vec: Vec<&str> = data.lines().collect();
    let take = lines.max(1).min(10_000);
    let start = lines_vec.len().saturating_sub(take);
    println!("Log file: {}", log_path.display());
    println!("Showing last {} lines:", lines_vec.len().saturating_sub(start));
    for line in &lines_vec[start..] {
        println!("{}", line);
    }
    Ok(())
}

async fn check_connectivity(server_url: &str, insecure_tls: bool) -> (bool, bool) {
    let health_url = server_url
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace("/ws/agent", "/api/health");

    let http_ok = match reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure_tls)
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => matches!(
            tokio::time::timeout(Duration::from_secs(6), client.get(&health_url).send()).await,
            Ok(Ok(resp)) if resp.status().is_success()
        ),
        Err(_) => false,
    };

    let ws_ok = matches!(
        tokio::time::timeout(Duration::from_secs(6), connect_ws(server_url, insecure_tls)).await,
        Ok(Ok(_))
    );

    (http_ok, ws_ok)
}

async fn run_status_command(args: &Args) {
    let saved = load_config();
    let log_path = args.log_file.clone().unwrap_or_else(default_log_path);
    let server = args
        .server
        .clone()
        .or_else(|| saved.as_ref().map(|c| c.server.clone()));

    let enrolled = saved
        .as_ref()
        .map(|c| !c.agent_id.is_empty() && !c.hmac_key.is_empty())
        .unwrap_or(false);

    let mut http_ok = false;
    let mut ws_ok = false;
    if let Some(ref s) = server {
        if s.starts_with("ws://") || s.starts_with("wss://") {
            (http_ok, ws_ok) = check_connectivity(s, args.insecure_tls).await;
        }
    }

    println!("XEFI Agent 2 status");
    println!("  enrolled: {}", if enrolled { "yes" } else { "no" });
    println!("  server reachable: {}", if http_ok { "yes" } else { "no" });
    println!("  ws connected: {}", if ws_ok { "yes" } else { "no" });
    println!(
        "  last error: {}",
        last_error_line(&log_path).unwrap_or_else(|| "none".to_string())
    );
    println!(
        "  jobs history: {}",
        if job_history_path().exists() { "ok" } else { "empty" }
    );
}

async fn run_self_test_command(args: &Args) -> Result<(), String> {
    println!("Running self-test...");
    let metrics = collect_metrics();
    if metrics["cpu_percent"].is_null() {
        return Err("Metrics collector failed".to_string());
    }
    let inventory = collect_inventory();
    if inventory["hostname"].as_str().unwrap_or("").is_empty() {
        return Err("Inventory collector failed".to_string());
    }

    let server = args
        .server
        .clone()
        .or_else(|| load_config().map(|c| c.server))
        .ok_or_else(|| "No server configured".to_string())?;
    let (http_ok, ws_ok) = check_connectivity(&server, args.insecure_tls).await;
    if !http_ok || !ws_ok {
        return Err(format!(
            "Connectivity failed (http_ok={}, ws_ok={})",
            http_ok, ws_ok
        ));
    }

    println!("Self-test passed");
    Ok(())
}

/// Run --diagnose mode: print OS info, paths, connectivity, and exit.
async fn run_diagnostics(args: &Args) {
    let (hostname, os, arch, os_ver) = get_system_info();
    let cfg_dir  = config_dir();
    let log_path = args.log_file.clone().unwrap_or_else(default_log_path);
    let cfg_path = config_path();

    println!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
    println!("  XEFI Agent 2 v{} Ã¢â‚¬â€ Diagnostic Report", env!("CARGO_PKG_VERSION"));
    println!("  {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z"));
    println!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
    println!();
    println!("[ System ]");
    println!("  Hostname  : {}", hostname);
    println!("  OS        : {} ({}) {}", os, arch, os_ver);

    // Windows version detail
    #[cfg(windows)]
    {
        let win_ver = get_windows_version_detail();
        println!("  Windows   : {}", win_ver);
    }

    // Admin check
    let is_admin = {
        #[cfg(target_os = "windows")]
        { std::process::Command::new("net").args(["session"]).output().map(|o| o.status.success()).unwrap_or(false) }
        #[cfg(not(target_os = "windows"))]
        { std::process::Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false) }
    };
    println!("  Admin     : {}", if is_admin { "YES" } else { "no (user mode)" });
    println!("  Arch      : {} (binary: {})", arch, if cfg!(target_arch = "x86_64") { "x64" } else if cfg!(target_arch = "x86") { "x86 (32-bit)" } else { "unknown" });
    println!();
    println!("[ TLS ]");
    println!("  Engine    : rustls (pure-Rust, no OS dependency)");
    println!("  TLS 1.2   : YES (always supported)");
    println!("  TLS 1.3   : YES (always supported)");
    println!("  CA Roots  : Mozilla bundled (webpki-roots, no OS cert store needed)");
    println!("  Static CRT: {}", if cfg!(target_feature = "crt-static") { "YES (no VCRUNTIME dep)" } else { "no" });
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
    println!("  Config writable: {}", if writable { "YES" } else { "NO Ã¢â‚¬â€ use --log-file / run as admin" });
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

    // Ã¢â€â‚¬Ã¢â€â‚¬ Service status check (Windows) Ã¢â€â‚¬Ã¢â€â‚¬
    #[cfg(windows)]
    {
        println!("[ Windows Service ]");
        let installed_service = detect_installed_service_name();
        if let Some(ref svc) = installed_service {
            println!("  Name      : {}", svc);
        } else {
            println!("  Name      : (not installed)");
        }
        let query_name = installed_service.as_deref().unwrap_or(SERVICE_NAME);
        match std::process::Command::new("sc.exe").args(["query", query_name]).output() {
            Ok(o) => {
                let out = String::from_utf8_lossy(&o.stdout);
                if out.contains("RUNNING") {
                    println!("  Status    : RUNNING");
                } else if out.contains("STOPPED") {
                    println!("  Status    : STOPPED");
                } else if o.status.success() {
                    println!("  Status    : {}", out.lines().find(|l| l.contains("STATE")).unwrap_or("unknown"));
                } else {
                    println!("  Status    : NOT INSTALLED");
                }
            }
            Err(_) => println!("  Status    : Cannot query (sc.exe not available)"),
        }
        // Check recovery settings
        match std::process::Command::new("sc.exe").args(["qfailure", query_name]).output() {
            Ok(o) if o.status.success() => {
                let out = String::from_utf8_lossy(&o.stdout);
                if out.contains("RESTART") {
                    println!("  Recovery  : Auto-restart configured");
                } else {
                    println!("  Recovery  : WARNING Ã¢â‚¬â€ no auto-restart configured");
                }
            }
            _ => {}
        }
        println!();
    }

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
                        println!("  DNS resolve : {} Ã¢â€ â€™ {}", host, a.ip());
                    }
                }
                Err(e) => println!("  DNS resolve : {} FAILED Ã¢â‚¬â€ {}", host, e),
            }
        }

        // HTTP(S) reachability test (backend health endpoint)
        let http_url = server_url
            .replace("wss://", "https://")
            .replace("ws://", "http://")
            .replace("/ws/agent", "/api/health");
        print!("  HTTP health : {} ... ", http_url);
        let _ = std::io::stdout().flush();
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(args.insecure_tls)
            .timeout(Duration::from_secs(5))
            .build();
        match client {
            Ok(c) => match tokio::time::timeout(Duration::from_secs(6), c.get(&http_url).send()).await {
                Ok(Ok(resp)) => println!("{} ({})", resp.status(), resp.status().as_u16()),
                Ok(Err(e)) => println!("FAILED Ã¢â‚¬â€ {}", e),
                Err(_) => println!("TIMEOUT (5s)"),
            },
            Err(e) => println!("Client error Ã¢â‚¬â€ {}", e),
        }

        // Try WS connect
        print!("  WS connect  : attempting...");
        let _ = std::io::stdout().flush();
        match tokio::time::timeout(
            Duration::from_secs(5),
            connect_ws(&server_url, args.insecure_tls),
        ).await {
            Ok(Ok(_)) => println!(" OK (rustls TLS handshake successful)"),
            Ok(Err(e)) => println!(" FAILED Ã¢â‚¬â€ {}", e),
            Err(_) => println!(" TIMEOUT (5s)"),
        }
    }
    println!();
    println!("[ Compatibility ]");
    println!("  Windows 7 SP1     : YES (rustls, static CRT, no OS deps)");
    println!("  Server 2008 R2    : YES");
    println!("  Server 2012/R2    : YES");
    println!("  Server 2016       : YES");
    println!("  Server 2019       : YES");
    println!("  Server 2022       : YES");
    println!("  Server 2025       : YES");
    println!("  Windows 10/11     : YES");
    println!("  x86 (32-bit)      : {}", if cfg!(target_arch = "x86") { "YES (this binary)" } else { "Use x86 build" });
    println!("  x64 (64-bit)      : {}", if cfg!(target_arch = "x86_64") { "YES (this binary)" } else { "Use x64 build" });
    println!();
    println!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
    flog("INFO", "Diagnostic run complete");
}

/// Get detailed Windows version string (e.g. "Windows 7 SP1" or "Windows Server 2019")
#[cfg(windows)]
fn get_windows_version_detail() -> String {
    // Use registry to get precise version info
    match winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion") {
        Ok(key) => {
            let product: String = key.get_value("ProductName").unwrap_or_default();
            let build: String = key.get_value("CurrentBuildNumber").unwrap_or_default();
            let sp: String = key.get_value("CSDVersion").unwrap_or_default();
            let display: String = key.get_value("DisplayVersion").unwrap_or_default();
            let ubr: u32 = key.get_value("UBR").unwrap_or(0);
            let mut ver = product;
            if !sp.is_empty() { ver = format!("{} {}", ver, sp); }
            if !display.is_empty() { ver = format!("{} ({})", ver, display); }
            if !build.is_empty() {
                if ubr > 0 {
                    ver = format!("{} Build {}.{}", ver, build, ubr);
                } else {
                    ver = format!("{} Build {}", ver, build);
                }
            }
            ver
        }
        Err(_) => "Unknown Windows version".to_string(),
    }
}

/// Run startup self-diagnostic (non-interactive, logs only).
/// Called automatically when the agent starts as a service.
async fn run_startup_diagnostic(server: &str, insecure_tls: bool) {
    let (hostname, os, arch, os_ver) = get_system_info();
    finfo!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â Startup Self-Diagnostic Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
    finfo!("Host: {} | OS: {} {} ({}) | Agent v{}", hostname, os, os_ver, arch, env!("CARGO_PKG_VERSION"));
    finfo!("Binary arch: {}", if cfg!(target_arch = "x86_64") { "x64" } else if cfg!(target_arch = "x86") { "x86" } else { "unknown" });
    finfo!("TLS engine: rustls (pure-Rust) | Static CRT: {}", if cfg!(target_feature = "crt-static") { "yes" } else { "no" });
    finfo!("Config dir: {} | Exists: {}", config_dir().display(), config_dir().exists());
    finfo!("PID: {} | Admin: {}", std::process::id(), {
        #[cfg(windows)]
        { std::process::Command::new("net").args(["session"]).output().map(|o| o.status.success()).unwrap_or(false) }
        #[cfg(not(windows))]
        { false }
    });

    #[cfg(windows)]
    {
        let win_ver = get_windows_version_detail();
        finfo!("Windows: {}", win_ver);
        eventlog_info(&format!(
            "XEFI Agent 2 v{} starting Ã¢â‚¬â€ {} Ã¢â‚¬â€ {} ({}) Ã¢â‚¬â€ {}",
            env!("CARGO_PKG_VERSION"), hostname, os, arch, win_ver
        ));
    }

    // Test backend reachability
    let http_url = server
        .replace("wss://", "https://")
        .replace("ws://", "http://")
        .replace("/ws/agent", "/api/health");
    match reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure_tls)
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => match tokio::time::timeout(Duration::from_secs(6), c.get(&http_url).send()).await {
            Ok(Ok(resp)) => finfo!("Backend health: {} {}", http_url, resp.status()),
            Ok(Err(e)) => fwarn!("Backend health: {} UNREACHABLE Ã¢â‚¬â€ {}", http_url, e),
            Err(_) => fwarn!("Backend health: {} TIMEOUT", http_url),
        },
        Err(e) => fwarn!("Backend health: HTTP client error Ã¢â‚¬â€ {}", e),
    }
    finfo!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â Diagnostic complete Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
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

async fn enroll_once(server: &str, token: &str, insecure_tls: bool) -> Result<AgentConfig, String> {
    let (hostname, os, arch, os_version) = get_system_info();
    let ws = connect_ws(server, insecure_tls)
        .await
        .map_err(|e| format!("Enrollment connection failed: {}", e))?;
    let (mut write, mut read) = ws.split();

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

    write
        .send(Message::Text(enroll_msg.to_string()))
        .await
        .map_err(|e| format!("Enrollment send failed: {}", e))?;

    let text = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(t)) => return Ok(t),
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)
    })
    .await
    .map_err(|_| "Enrollment timed out waiting for response".to_string())?
    .map_err(|e| format!("Enrollment read failed: {}", e))?;

    let resp: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("Invalid enroll response JSON: {}", e))?;
    if resp["type"] != "enroll_response" {
        return Err("Unexpected response type during enrollment".to_string());
    }
    let payload = &resp["payload"];
    if let Some(err) = payload["error"].as_str() {
        return Err(format!("Enrollment failed: {}", err));
    }

    let agent_id = payload["agent_id"]
        .as_str()
        .ok_or_else(|| "Enrollment response missing agent_id".to_string())?
        .to_string();
    let hmac_key = payload["hmac_key"]
        .as_str()
        .or_else(|| payload["agent_secret"].as_str())
        .ok_or_else(|| "Enrollment response missing hmac_key/agent_secret".to_string())?
        .to_string();

    Ok(AgentConfig {
        agent_id,
        hmac_key,
        server: server.to_string(),
        enrolled_at: now_ms(),
    })
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
    } else if cfg!(target_arch = "x86") {
        "x86"
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
    let networks = sysinfo::Networks::new_with_refreshed_list();
    let net_rx_bytes: u64 = networks.iter().map(|(_, data)| data.total_received()).sum();
    let net_tx_bytes: u64 = networks.iter().map(|(_, data)| data.total_transmitted()).sum();

    serde_json::json!({
        "ts": now_ms(),
        "cpu_percent": cpu_percent,
        "memory_used_bytes": memory_used_bytes,
        "memory_total_bytes": memory_total_bytes,
        "disk_used_bytes": disk_used_bytes,
        "disk_total_bytes": disk_total_bytes,
        "net_rx_bytes": net_rx_bytes,
        "net_tx_bytes": net_tx_bytes,
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
                rd_set_session_id(None);
                rd_signal_stop();
                finfo!("Remote desktop stopped by job");
                Ok(serde_json::json!({ "exit_code": 0, "stdout": "Remote desktop stopped", "stderr": "" }))
            }
            "list_monitors" => {
                list_monitors().await
            }
            "update_agent" => {
                execute_self_update(payload).await
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

// Ã¢â€â‚¬Ã¢â€â‚¬ Inventory Collection Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        "agent_version": env!("CARGO_PKG_VERSION"),
    })
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Process Management Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

// Ã¢â€â‚¬Ã¢â€â‚¬ Service Management Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

// Ã¢â€â‚¬Ã¢â€â‚¬ EDR Kill Process Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

// Ã¢â€â‚¬Ã¢â€â‚¬ EDR Network Isolation Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

async fn execute_edr_isolate(payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let mode = payload["mode"].as_str().unwrap_or("soft");
    let reason = payload["reason"].as_str().unwrap_or("EDR response");

    info!(mode, reason, "EDR: Network isolation requested");

    // Platform-specific firewall rules
    let (cmd, args): (&str, Vec<String>) = if cfg!(target_os = "windows") {
        (
            "powershell",
            vec![
                "-NoProfile".into(),
                "-ExecutionPolicy".into(),
                "Bypass".into(),
                "-Command".into(),
                "if (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) { \
                    New-NetFirewallRule -DisplayName 'Reap3r-EDR-Isolate-Out' -Direction Outbound -Action Block -Enabled True -ErrorAction Stop | Out-Null; \
                    New-NetFirewallRule -DisplayName 'Reap3r-EDR-Isolate-In' -Direction Inbound -Action Block -Enabled True -ErrorAction Stop | Out-Null; \
                 } else { \
                    netsh advfirewall firewall add rule name='Reap3r-EDR-Isolate-Out' dir=out action=block enable=yes | Out-Null; \
                    netsh advfirewall firewall add rule name='Reap3r-EDR-Isolate-In' dir=in action=block enable=yes | Out-Null; \
                 }".into(),
            ],
        )
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

// Ã¢â€â‚¬Ã¢â€â‚¬ Security Monitoring Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
    let default_interpreter = if cfg!(target_os = "windows") { "powershell" } else { "bash" };
    let interpreter = payload["interpreter"]
        .as_str()
        .unwrap_or(default_interpreter)
        .to_ascii_lowercase();
    let script = payload["script"].as_str().unwrap_or("");
    let timeout_secs = payload["timeout_secs"].as_u64().unwrap_or(300);
    let max_output_bytes = payload["max_output_bytes"]
        .as_u64()
        .map(|v| v as usize)
        .unwrap_or(DEFAULT_MAX_JOB_OUTPUT_BYTES)
        .clamp(DEFAULT_MAX_JOB_OUTPUT_BYTES, MAX_JOB_OUTPUT_BYTES_HARD_CAP);

    if script.trim().is_empty() {
        return Err("Script is empty".to_string());
    }

    let start = std::time::Instant::now();

    let (cmd, args) = match interpreter.as_str() {
        "bash" | "sh" => ("bash", vec!["-c", script]),
        "powershell" | "pwsh" => (
            "powershell",
            vec![
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
        ),
        "cmd" => ("cmd", vec!["/C", script]),
        _ => {
            return Err(format!(
                "Interpreter '{}' is not allowed. Allowed: powershell, cmd, bash, sh",
                interpreter
            ))
        }
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
            "stdout": truncate_utf8_to_bytes(&String::from_utf8_lossy(&output.stdout), max_output_bytes),
            "stderr": truncate_utf8_to_bytes(&String::from_utf8_lossy(&output.stderr), max_output_bytes),
            "duration_ms": duration_ms,
        })),
        Ok(Err(e)) => Err(format!("Failed to execute: {}", e)),
        Err(_) => Err("Script execution timed out".to_string()),
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Remote Desktop (screenshot streaming) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
//
// When running as a Windows Service (Session 0), there is no desktop to capture.
// We solve this by:
//   1. Writing a PowerShell capture-loop script to disk
//   2. Launching it in the interactive user's session via
//      WTSGetActiveConsoleSessionId + WTSQueryUserToken + CreateProcessAsUserW
//   3. The script writes frames (base64 JPEG) to a temp file
//   4. The agent reads new frames from that file and sends them via WebSocket
//   5. Stop signal is a flag file on disk

/// PowerShell capture-loop script.  Written to disk and launched in user session.
/// Placeholders __SCALE__, __QUALITY__, __FPS__, __DIR__, __MONITOR__ are replaced at runtime.
/// __MONITOR__ = -1 means capture ALL screens combined, 0..N captures a specific screen.
const RD_CAPTURE_LOOP_PS: &str = r#"
$dir = '__DIR__'
$stop = "$dir\rd_stop.flag"
$errLog = "$dir\rd_capture_error.log"
Remove-Item $stop -ErrorAction SilentlyContinue
Remove-Item $errLog -ErrorAction SilentlyContinue
$scale = [double]__SCALE__
$quality = [int]__QUALITY__
$fps = [int]__FPS__
$monIdx = [int]__MONITOR__
$interval = [int](1000 / $fps)
$seq = 0
$errCount = 0
# Log session info for diagnostics
$sid = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
"[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] Capture started in session $sid (PID $PID)" | Out-File $errLog -Append
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] Assemblies loaded OK" | Out-File $errLog -Append
} catch {
    "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] FATAL: Failed to load assemblies: $_" | Out-File $errLog -Append
    exit 1
}
while (-not (Test-Path $stop)) {
    try {
        if ($monIdx -ge 0) {
            $screens = [System.Windows.Forms.Screen]::AllScreens
            if ($monIdx -lt $screens.Length) {
                $bounds = $screens[$monIdx].Bounds
            } else {
                $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
            }
        } else {
            $minX = [int]::MaxValue; $minY = [int]::MaxValue
            $maxX = [int]::MinValue; $maxY = [int]::MinValue
            foreach ($scr in [System.Windows.Forms.Screen]::AllScreens) {
                $b = $scr.Bounds
                if ($b.X -lt $minX) { $minX = $b.X }
                if ($b.Y -lt $minY) { $minY = $b.Y }
                if (($b.X + $b.Width) -gt $maxX) { $maxX = $b.X + $b.Width }
                if (($b.Y + $b.Height) -gt $maxY) { $maxY = $b.Y + $b.Height }
            }
            $bounds = New-Object System.Drawing.Rectangle($minX, $minY, ($maxX - $minX), ($maxY - $minY))
        }
        $w = [int]($bounds.Width * $scale)
        $h = [int]($bounds.Height * $scale)
        if ($w -le 0 -or $h -le 0) {
            if ($errCount -eq 0) { "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] Invalid bounds: w=$w h=$h bounds=$bounds" | Out-File $errLog -Append }
            $errCount++; Start-Sleep -Milliseconds 500; continue
        }
        $bmp = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
        $resized = New-Object System.Drawing.Bitmap($w, $h)
        $g2 = [System.Drawing.Graphics]::FromImage($resized)
        $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g2.DrawImage($bmp, 0, 0, $w, $h)
        $ms = New-Object System.IO.MemoryStream
        $enc = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
        $ep = New-Object System.Drawing.Imaging.EncoderParameters(1)
        $ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]$quality)
        $resized.Save($ms, $enc, $ep)
        $b64 = [Convert]::ToBase64String($ms.ToArray())
        $tmp = "$dir\rd_frame.tmp"
        $out = "$dir\rd_frame.dat"
        [System.IO.File]::WriteAllText($tmp, "$seq|$b64")
        Move-Item $tmp $out -Force
        $g.Dispose(); $g2.Dispose(); $bmp.Dispose(); $resized.Dispose(); $ms.Dispose()
        if ($seq -eq 0) { "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] First frame captured OK (${w}x${h})" | Out-File $errLog -Append }
        $seq++
        $errCount = 0
    } catch {
        $errCount++
        if ($errCount -le 3) {
            "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] CopyFromScreen error #$errCount : $_" | Out-File $errLog -Append
        }
        if ($errCount -gt 50) {
            "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] Too many errors ($errCount), giving up" | Out-File $errLog -Append
            break
        }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Milliseconds $interval
}
Remove-Item "$dir\rd_frame.dat" -ErrorAction SilentlyContinue
Remove-Item $stop -ErrorAction SilentlyContinue
"#;

/// PowerShell script to enumerate all displays and write JSON to __OUT_PATH__.
/// Uses System.Windows.Forms.Screen (primary) with WMI fallback.
/// Runs in user session via -File so it can access the real monitor topology.
const RD_LIST_MONITORS_PS: &str = r#"
$outPath = '__OUT_PATH__'
$errLog  = '__OUT_PATH__.log'
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    $screens = [System.Windows.Forms.Screen]::AllScreens
    if ($screens -and $screens.Count -gt 0) {
        $monitors = @()
        $idx = 0
        foreach ($s in $screens) {
            $monitors += [PSCustomObject]@{
                index   = $idx
                name    = $s.DeviceName
                primary = [bool]$s.Primary
                x       = [int]$s.Bounds.X
                y       = [int]$s.Bounds.Y
                width   = [int]$s.Bounds.Width
                height  = [int]$s.Bounds.Height
            }
            $idx++
        }
        $json = $monitors | ConvertTo-Json -Compress
        if ($monitors.Count -eq 1) { $json = "[$json]" }
        [IO.File]::WriteAllText($outPath, $json)
        exit 0
    }
} catch {
    $_ | Out-File $errLog -Append
}
# Fallback: EnumDisplayMonitors via P/Invoke (correct bounds per monitor, works in user session)
try {
    $monCode = @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class NativeMon {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    public delegate bool MEP(IntPtr hm, IntPtr hd, ref RECT rc, IntPtr d);
    [DllImport("user32.dll")] public static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr clip, MEP fn, IntPtr data);
}
'@
    Add-Type -TypeDefinition $monCode -ErrorAction Stop
    $script:rects = [System.Collections.Generic.List[object]]::new()
    $cb = [NativeMon+MEP]{
        param($hm,$hd,[ref]$rc,$d)
        $script:rects.Add(@{ L=$rc.Value.Left; T=$rc.Value.Top; R=$rc.Value.Right; B=$rc.Value.Bottom })
        $true
    }
    [NativeMon]::EnumDisplayMonitors([IntPtr]::Zero, [IntPtr]::Zero, $cb, [IntPtr]::Zero) | Out-Null
    if ($script:rects.Count -gt 0) {
        $monitors = @(); $idx = 0
        foreach ($r in $script:rects) {
            $monitors += [PSCustomObject]@{
                index   = $idx
                name    = "DISPLAY$($idx+1)"
                primary = ($idx -eq 0)
                x       = [int]$r.L
                y       = [int]$r.T
                width   = [int]($r.R - $r.L)
                height  = [int]($r.B - $r.T)
            }
            $idx++
        }
        $json = $monitors | ConvertTo-Json -Compress
        if ($monitors.Count -eq 1) { $json = "[$json]" }
        [IO.File]::WriteAllText($outPath, $json)
        exit 0
    }
} catch {
    $_ | Out-File $errLog -Append
}
# Fallback: Win32_DesktopMonitor WMI (counts physical monitors, not GPUs)
try {
    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        $vcs = @(Get-CimInstance Win32_DesktopMonitor -ErrorAction Stop)
    } else {
        $vcs = @(Get-WmiObject Win32_DesktopMonitor -ErrorAction Stop)
    }
    if ($vcs.Count -gt 0) {
        $monitors = @(); $idx = 0
        foreach ($v in $vcs) {
            $monitors += [PSCustomObject]@{
                index   = $idx
                name    = if ($v.Name) { $v.Name } else { "DISPLAY$($idx+1)" }
                primary = ($idx -eq 0)
                x       = 0
                y       = 0
                width   = if ($v.ScreenWidth -gt 0) { [int]$v.ScreenWidth } else { 1920 }
                height  = if ($v.ScreenHeight -gt 0) { [int]$v.ScreenHeight } else { 1080 }
            }
            $idx++
        }
        $json = $monitors | ConvertTo-Json -Compress
        if ($monitors.Count -eq 1) { $json = "[$json]" }
        [IO.File]::WriteAllText($outPath, $json)
        exit 0
    }
} catch {
    $_ | Out-File $errLog -Append
}
# Last resort: single default monitor
[IO.File]::WriteAllText($outPath, '[{"index":0,"name":"DISPLAY1","primary":true,"x":0,"y":0,"width":1920,"height":1080}]')
"#;

/// PowerShell script that runs persistently in the user session to simulate mouse/keyboard input.
/// Uses SendInput (modern Win32 API) for reliable input injection in all applications.
/// Placeholders __DIR__, __MONITOR__, __SCALE__ replaced at runtime.
const RD_INPUT_LOOP_PS: &str = r#"
$dir = '__DIR__'
$stop = "$dir\rd_stop.flag"
$inputFile = "$dir\rd_input.dat"
$monIdx = [int]__MONITOR__
$scale = [double]__SCALE__
$errLog = "$dir\rd_input_error.log"
"[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] XEFI Agent 2 input handler started (session $([System.Diagnostics.Process]::GetCurrentProcess().SessionId))" | Out-File $errLog
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    # Modern SendInput API Ã¢â‚¬â€ works with Win7 through Win11 and all applications
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class RdInput {
    // Ã¢â€â‚¬Ã¢â€â‚¬ Structs Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT {
        public int dx, dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }
    [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }
    [StructLayout(LayoutKind.Sequential)] public struct HARDWAREINPUT {
        public uint uMsg;
        public ushort wParamL;
        public ushort wParamH;
    }
    [StructLayout(LayoutKind.Explicit)] public struct INPUT {
        [FieldOffset(0)] public uint type;
        [FieldOffset(4)] public MOUSEINPUT mi;
        [FieldOffset(4)] public KEYBDINPUT ki;
        [FieldOffset(4)] public HARDWAREINPUT hi;
    }
    // Ã¢â€â‚¬Ã¢â€â‚¬ P/Invoke Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] inputs, int cb);
    [DllImport("user32.dll")] public static extern uint MapVirtualKey(uint uCode, uint uMapType);
    [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
    // Input type constants
    public const uint INPUT_MOUSE    = 0;
    public const uint INPUT_KEYBOARD = 1;
    // Mouse flags
    public const uint MOUSEEVENTF_MOVE        = 0x0001;
    public const uint MOUSEEVENTF_LEFTDOWN    = 0x0002;
    public const uint MOUSEEVENTF_LEFTUP      = 0x0004;
    public const uint MOUSEEVENTF_RIGHTDOWN   = 0x0008;
    public const uint MOUSEEVENTF_RIGHTUP     = 0x0010;
    public const uint MOUSEEVENTF_MIDDLEDOWN  = 0x0020;
    public const uint MOUSEEVENTF_MIDDLEUP    = 0x0040;
    public const uint MOUSEEVENTF_WHEEL       = 0x0800;
    public const uint MOUSEEVENTF_ABSOLUTE    = 0x8000;
    public const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;
    // Keyboard flags
    public const uint KEYEVENTF_EXTENDEDKEY = 0x0001;
    public const uint KEYEVENTF_KEYUP       = 0x0002;
    public const uint KEYEVENTF_SCANCODE    = 0x0008;
    // Ã¢â€â‚¬Ã¢â€â‚¬ Helpers Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    static int Clamp(int value, int min, int max) {
        if (value < min) return min;
        if (value > max) return max;
        return value;
    }
    // Mouse move + click via SendInput (absolute coords in 0-65535 virtual desktop space)
    public static void MouseMoveAbs(int absX, int absY, int virtX, int virtY, int virtW, int virtH) {
        if (virtW <= 1 || virtH <= 1) return;
        int relX = Clamp(absX - virtX, 0, virtW - 1);
        int relY = Clamp(absY - virtY, 0, virtH - 1);
        int normX = (int)Math.Round((relX * 65535.0) / (virtW - 1));
        int normY = (int)Math.Round((relY * 65535.0) / (virtH - 1));
        INPUT[] inp = new INPUT[1];
        inp[0].type = INPUT_MOUSE;
        inp[0].mi.dx = normX;
        inp[0].mi.dy = normY;
        inp[0].mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
        SendInput(1, inp, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));
    }
    public static void MouseButton(uint flags) {
        INPUT[] inp = new INPUT[1];
        inp[0].type = INPUT_MOUSE;
        inp[0].mi.dwFlags = flags;
        SendInput(1, inp, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));
    }
    public static void MouseWheel(int delta) {
        INPUT[] inp = new INPUT[1];
        inp[0].type = INPUT_MOUSE;
        inp[0].mi.dwFlags = MOUSEEVENTF_WHEEL;
        inp[0].mi.mouseData = (uint)delta;
        SendInput(1, inp, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));
    }
    // Keyboard via SendInput with scan code (more compatible than VK-only)
    public static void KeyEvent(ushort vk, bool keyUp) {
        ushort scan = (ushort)MapVirtualKey(vk, 0);
        uint flags = KEYEVENTF_SCANCODE | (keyUp ? KEYEVENTF_KEYUP : 0u);
        // Extended keys: arrows, ins, del, home, end, pgup, pgdn, right ctrl/alt, numlock, etc.
        if (vk >= 0x21 && vk <= 0x28 || vk == 0x2D || vk == 0x2E || vk == 0x5B || vk == 0x5C ||
            vk == 0x11 || vk == 0x12) {
            // Use VK for extended keys (more reliable)
            flags = (keyUp ? KEYEVENTF_KEYUP : 0u);
            INPUT[] inp2 = new INPUT[1];
            inp2[0].type = INPUT_KEYBOARD;
            inp2[0].ki.wVk = vk;
            inp2[0].ki.wScan = scan;
            inp2[0].ki.dwFlags = flags | KEYEVENTF_EXTENDEDKEY;
            SendInput(1, inp2, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));
            return;
        }
        INPUT[] inp = new INPUT[1];
        inp[0].type = INPUT_KEYBOARD;
        inp[0].ki.wVk = vk;
        inp[0].ki.wScan = scan;
        inp[0].ki.dwFlags = flags;
        SendInput(1, inp, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));
    }
}
"@ -ErrorAction Stop
} catch {
    "[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] FATAL: $_" | Out-File $errLog -Append
    exit 1
}
function Get-ScreenBounds {
    if ($monIdx -ge 0) {
        $screens = [System.Windows.Forms.Screen]::AllScreens
        if ($monIdx -lt $screens.Length) { return $screens[$monIdx].Bounds }
        return [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    }
    $minX=[int]::MaxValue; $minY=[int]::MaxValue; $maxX=[int]::MinValue; $maxY=[int]::MinValue
    foreach ($scr in [System.Windows.Forms.Screen]::AllScreens) {
        $b=$scr.Bounds
        if($b.X -lt $minX){$minX=$b.X}; if($b.Y -lt $minY){$minY=$b.Y}
        if(($b.X+$b.Width) -gt $maxX){$maxX=$b.X+$b.Width}
        if(($b.Y+$b.Height) -gt $maxY){$maxY=$b.Y+$b.Height}
    }
    return New-Object System.Drawing.Rectangle($minX,$minY,($maxX-$minX),($maxY-$minY))
}
$bounds = Get-ScreenBounds
# Virtual desktop dimensions (entire desktop across all monitors)
$virtW = [System.Windows.Forms.SystemInformation]::VirtualScreen.Width
$virtH = [System.Windows.Forms.SystemInformation]::VirtualScreen.Height
$virtX = [System.Windows.Forms.SystemInformation]::VirtualScreen.X
$virtY = [System.Windows.Forms.SystemInformation]::VirtualScreen.Y
"[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] Screen bounds: $($bounds.X),$($bounds.Y) $($bounds.Width)x$($bounds.Height) | VirtDesk: ${virtX},${virtY} ${virtW}x${virtH}" | Out-File $errLog -Append
while (-not (Test-Path $stop)) {
    if (Test-Path $inputFile) {
        try {
            $raw = [System.IO.File]::ReadAllText($inputFile)
            [System.IO.File]::Delete($inputFile)
            foreach ($line in $raw -split "`n") {
                $line = $line.Trim()
                if (-not $line) { continue }
                try {
                    $evt = ConvertFrom-Json $line
                    # Convert normalized 0-1 coords to absolute screen coords (clamped)
                    $nx = [double]$evt.x
                    $ny = [double]$evt.y
                    if ([double]::IsNaN($nx)) { $nx = 0.0 }
                    if ([double]::IsNaN($ny)) { $ny = 0.0 }
                    if ($nx -lt 0) { $nx = 0.0 } elseif ($nx -gt 1) { $nx = 1.0 }
                    if ($ny -lt 0) { $ny = 0.0 } elseif ($ny -gt 1) { $ny = 1.0 }
                    $bw = [Math]::Max(1, [int]$bounds.Width)
                    $bh = [Math]::Max(1, [int]$bounds.Height)
                    $absX = [int]($bounds.X + [Math]::Round($nx * ($bw - 1)))
                    $absY = [int]($bounds.Y + [Math]::Round($ny * ($bh - 1)))
                    switch ($evt.type) {
                        'mouse_move' {
                            [RdInput]::MouseMoveAbs($absX, $absY, $virtX, $virtY, $virtW, $virtH)
                        }
                        'mouse_down' {
                            [RdInput]::MouseMoveAbs($absX, $absY, $virtX, $virtY, $virtW, $virtH)
                            switch ($evt.button) {
                                'right'  { [RdInput]::MouseButton([RdInput]::MOUSEEVENTF_RIGHTDOWN)  }
                                'middle' { [RdInput]::MouseButton([RdInput]::MOUSEEVENTF_MIDDLEDOWN) }
                                default  { [RdInput]::MouseButton([RdInput]::MOUSEEVENTF_LEFTDOWN)   }
                            }
                        }
                        'mouse_up' {
                            [RdInput]::MouseMoveAbs($absX, $absY, $virtX, $virtY, $virtW, $virtH)
                            switch ($evt.button) {
                                'right'  { [RdInput]::MouseButton([RdInput]::MOUSEEVENTF_RIGHTUP)  }
                                'middle' { [RdInput]::MouseButton([RdInput]::MOUSEEVENTF_MIDDLEUP) }
                                default  { [RdInput]::MouseButton([RdInput]::MOUSEEVENTF_LEFTUP)   }
                            }
                        }
                        'mouse_wheel' {
                            [RdInput]::MouseWheel([int]($evt.delta * 120))
                        }
                        'key_down' {
                            [RdInput]::KeyEvent([ushort]$evt.vk, $false)
                        }
                        'key_up' {
                            [RdInput]::KeyEvent([ushort]$evt.vk, $true)
                        }
                    }
                } catch { }
            }
        } catch { }
    }
    Start-Sleep -Milliseconds 10
}
"[$(Get-Date -f 'yyyy-MM-dd HH:mm:ss')] Input handler stopped" | Out-File $errLog -Append
"#;

// Ã¢â€â‚¬Ã¢â€â‚¬ Windows FFI for launching a process in the interactive user session Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

#[cfg(windows)]
mod user_session {
    use std::ptr;

    type HANDLE = *mut std::ffi::c_void;
    type DWORD = u32;
    type BOOL = i32;
    type WORD = u16;
    type LPWSTR = *mut u16;

    const CREATE_NO_WINDOW: DWORD = 0x0800_0000;
    const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x0000_0400;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct STARTUPINFOW {
        cb: DWORD,
        lpReserved: LPWSTR,
        lpDesktop: LPWSTR,
        lpTitle: LPWSTR,
        dwX: DWORD, dwY: DWORD, dwXSize: DWORD, dwYSize: DWORD,
        dwXCountChars: DWORD, dwYCountChars: DWORD,
        dwFillAttribute: DWORD,
        dwFlags: DWORD,
        wShowWindow: WORD,
        cbReserved2: WORD,
        lpReserved2: *mut u8,
        hStdInput: HANDLE,
        hStdOutput: HANDLE,
        hStdError: HANDLE,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct PROCESS_INFORMATION {
        hProcess: HANDLE,
        hThread: HANDLE,
        dwProcessId: DWORD,
        dwThreadId: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct WTS_SESSION_INFOW {
        SessionId: DWORD,
        pWinStationName: *const u16,
        State: DWORD,
    }

    const WTS_CURRENT_SERVER_HANDLE: HANDLE = 0 as HANDLE;
    const WTS_ACTIVE: DWORD = 0; // WTSActive

    #[link(name = "kernel32")]
    extern "system" {
        fn WTSGetActiveConsoleSessionId() -> DWORD;
        fn CloseHandle(hObject: HANDLE) -> BOOL;
    }

    #[link(name = "wtsapi32")]
    extern "system" {
        fn WTSQueryUserToken(SessionId: DWORD, phToken: *mut HANDLE) -> BOOL;
        fn WTSEnumerateSessionsW(
            hServer: HANDLE,
            Reserved: DWORD,
            Version: DWORD,
            ppSessionInfo: *mut *mut WTS_SESSION_INFOW,
            pCount: *mut DWORD,
        ) -> BOOL;
        fn WTSFreeMemory(pMemory: *mut std::ffi::c_void);
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn CreateProcessAsUserW(
            hToken: HANDLE,
            lpApplicationName: *const u16,
            lpCommandLine: LPWSTR,
            lpProcessAttributes: *const std::ffi::c_void,
            lpThreadAttributes: *const std::ffi::c_void,
            bInheritHandles: BOOL,
            dwCreationFlags: DWORD,
            lpEnvironment: *const std::ffi::c_void,
            lpCurrentDirectory: *const u16,
            lpStartupInfo: *const STARTUPINFOW,
            lpProcessInformation: *mut PROCESS_INFORMATION,
        ) -> BOOL;
        fn DuplicateTokenEx(
            hExistingToken: HANDLE,
            dwDesiredAccess: DWORD,
            lpTokenAttributes: *const std::ffi::c_void,
            ImpersonationLevel: DWORD,  // SECURITY_IMPERSONATION_LEVEL
            TokenType: DWORD,           // TOKEN_TYPE
            phNewToken: *mut HANDLE,
        ) -> BOOL;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    /// Find the best interactive user session.
    /// Tries the physical console first, then enumerates all sessions
    /// to find an active one (covers RDP sessions too).
    fn find_user_session() -> Result<DWORD, String> {
        unsafe {
            // 1. Try the physical console session first
            let console_sid = WTSGetActiveConsoleSessionId();
            if console_sid != 0xFFFF_FFFF && console_sid != 0 {
                // Verify there's a user logged in on this session
                let mut token: HANDLE = ptr::null_mut();
                if WTSQueryUserToken(console_sid, &mut token) != 0 {
                    CloseHandle(token);
                    return Ok(console_sid);
                }
            }

            // 2. Enumerate all sessions and find an active one
            let mut session_info: *mut WTS_SESSION_INFOW = ptr::null_mut();
            let mut count: DWORD = 0;
            if WTSEnumerateSessionsW(
                WTS_CURRENT_SERVER_HANDLE,
                0,
                1,
                &mut session_info,
                &mut count,
            ) == 0 {
                return Err(format!(
                    "WTSEnumerateSessionsW failed (error {})",
                    std::io::Error::last_os_error()
                ));
            }

            let mut best_session: Option<DWORD> = None;
            for i in 0..count {
                let info = &*session_info.offset(i as isize);
                // State == WTSActive (0) and session > 0 (not Session 0 which is services)
                if info.State == WTS_ACTIVE && info.SessionId > 0 {
                    // Verify we can get a user token for this session
                    let mut token: HANDLE = ptr::null_mut();
                    if WTSQueryUserToken(info.SessionId, &mut token) != 0 {
                        CloseHandle(token);
                        best_session = Some(info.SessionId);
                        break;
                    }
                }
            }
            WTSFreeMemory(session_info as *mut std::ffi::c_void);

            best_session.ok_or_else(|| "No active user session found (no user logged in?)".into())
        }
    }

    /// Launch a command in an interactive user session.
    /// Tries console session first, then any active session (RDP included).
    /// Requires SYSTEM privileges (service account).
    /// Returns the child PID on success.
    pub fn launch_in_user_session(command: &str) -> Result<u32, String> {
        unsafe {
            let session_id = find_user_session()?;

            let mut user_token: HANDLE = ptr::null_mut();
            if WTSQueryUserToken(session_id, &mut user_token) == 0 {
                return Err(format!(
                    "WTSQueryUserToken failed for session {} (error {})",
                    session_id,
                    std::io::Error::last_os_error()
                ));
            }

            // Duplicate as a primary token (TokenType=1 = TokenPrimary)
            let mut dup_token: HANDLE = ptr::null_mut();
            let dup_ok = DuplicateTokenEx(
                user_token,
                0x02000000,  // MAXIMUM_ALLOWED
                ptr::null(),
                2,  // SecurityImpersonation
                1,  // TokenPrimary
                &mut dup_token,
            );
            CloseHandle(user_token);
            if dup_ok == 0 {
                return Err(format!(
                    "DuplicateTokenEx failed (error {})",
                    std::io::Error::last_os_error()
                ));
            }

            let mut cmd_wide = to_wide(command);
            let desktop_wide = to_wide("winsta0\\default");

            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as DWORD;
            si.lpDesktop = desktop_wide.as_ptr() as LPWSTR;

            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

            let result = CreateProcessAsUserW(
                dup_token,
                ptr::null(),
                cmd_wide.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,  // don't inherit handles
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                ptr::null(),
                ptr::null(),
                &si,
                &mut pi,
            );

            CloseHandle(dup_token);

            if result == 0 {
                return Err(format!(
                    "CreateProcessAsUserW failed (error {})",
                    std::io::Error::last_os_error()
                ));
            }

            let pid = pi.dwProcessId;
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            Ok(pid)
        }
    }
}

fn rd_stop_flag_path() -> PathBuf {
    config_dir().join("rd_stop.flag")
}
fn rd_frame_data_path() -> PathBuf {
    config_dir().join("rd_frame.dat")
}
fn rd_script_path() -> PathBuf {
    config_dir().join("rd_capture.ps1")
}
fn rd_input_script_path() -> PathBuf {
    config_dir().join("rd_input.ps1")
}
fn rd_input_data_path() -> PathBuf {
    config_dir().join("rd_input.dat")
}

/// Write the stop flag so the capture process exits.
fn rd_signal_stop() {
    let _ = std::fs::write(rd_stop_flag_path(), "stop");
    // Also clean up frame data and input data
    let _ = std::fs::remove_file(rd_frame_data_path());
    let _ = std::fs::remove_file(rd_input_data_path());
}

/// Enumerate monitors by running a small PowerShell script in the user session.
async fn list_monitors() -> Result<serde_json::Value, String> {
    finfo!("Enumerating monitors...");

    // Prepare output path and write the script with embedded output path
    let out_path = config_dir().join("rd_monitors.json");
    let script_path = config_dir().join("rd_list_monitors.ps1");
    let script_content = RD_LIST_MONITORS_PS
        .replace("__OUT_PATH__", &out_path.display().to_string());
    std::fs::write(&script_path, &script_content)
        .map_err(|e| format!("Write list_monitors script: {}", e))?;
    let _ = std::fs::remove_file(&out_path);

    // Try to run in user session first (needed when running as service in Session 0)
    let output = {
        #[cfg(windows)]
        {
            // Use -File like the RD capture does (much more reliable than inline -Command)
            let cmd = format!(
                "powershell.exe -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
                script_path.display()
            );
            match user_session::launch_in_user_session(&cmd) {
                Ok(pid) => {
                    finfo!("list_monitors: launched in user session (PID {})", pid);
                    // Wait for output file to appear (max 10s Ã¢â‚¬â€ Add-Type can be slow)
                    let mut attempts = 0;
                    loop {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        attempts += 1;
                        if out_path.exists() {
                            // Wait a bit more for write to complete
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            break;
                        }
                        if attempts > 33 {
                            // Check if there's an error log
                            let err_log = config_dir().join("rd_monitors.json.log");
                            let err_msg = std::fs::read_to_string(&err_log).unwrap_or_default();
                            return Err(format!("Timeout waiting for monitor list output. Errors: {}", err_msg));
                        }
                    }
                    std::fs::read_to_string(&out_path)
                        .map_err(|e| format!("Read monitors output: {}", e))?
                }
                Err(e) => {
                    fwarn!("list_monitors: user session failed: {}, trying local", e);
                    // Fallback: run locally with -File too
                    let child = tokio::process::Command::new("powershell")
                        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", &script_path.display().to_string()])
                        .output()
                        .await
                        .map_err(|e| format!("Run list_monitors locally: {}", e))?;
                    // The script writes to file, but if it also printed, grab stdout
                    if out_path.exists() {
                        std::fs::read_to_string(&out_path)
                            .map_err(|e| format!("Read monitors output: {}", e))?
                    } else {
                        String::from_utf8_lossy(&child.stdout).to_string()
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            // Non-windows: return a single virtual screen
            String::from("[{\"index\":0,\"name\":\":0\",\"primary\":true,\"x\":0,\"y\":0,\"width\":1920,\"height\":1080}]")
        }
    };

    // Parse the JSON output
    let trimmed = output.trim().trim_start_matches('\u{feff}'); // strip BOM
    let monitors: serde_json::Value = serde_json::from_str(trimmed).unwrap_or_else(|_| {
        fwarn!("list_monitors: failed to parse output: {}", trimmed);
        serde_json::json!([])
    });

    // Ensure it's always an array (single monitor returns an object from ConvertTo-Json)
    let monitors_arr = if monitors.is_array() {
        monitors
    } else if monitors.is_object() {
        serde_json::json!([monitors])
    } else {
        serde_json::json!([])
    };

    finfo!("Monitors found: {}", monitors_arr);

    Ok(serde_json::json!({
        "exit_code": 0,
        "stdout": serde_json::to_string(&monitors_arr).unwrap_or_default(),
        "stderr": "",
        "monitors": monitors_arr,
    }))
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Self-Update: download new binary, verify SHA256, replace, restart service Ã¢â€â‚¬Ã¢â€â‚¬

fn decode_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    hex::decode(input.trim()).map_err(|e| format!("Invalid hex payload: {}", e))
}

fn parse_update_signature(sig: &str) -> Result<Signature, String> {
    use base64::Engine;

    let trimmed = sig.trim();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| decode_hex_bytes(trimmed))
        .map_err(|e| format!("Invalid update signature (base64 or hex expected): {}", e))?;
    let raw_len = raw.len();
    let sig_bytes: [u8; 64] = raw
        .try_into()
        .map_err(|_| format!("Invalid Ed25519 signature length: {}", raw_len))?;
    Ok(Signature::from_bytes(&sig_bytes))
}

fn parse_update_pubkey() -> Result<VerifyingKey, String> {
    if UPDATE_PUBLIC_KEY_HEX.trim().is_empty() {
        return Err("REAP3R_UPDATE_PUBKEY_HEX is not embedded in this build".to_string());
    }
    let key_bytes_vec = decode_hex_bytes(UPDATE_PUBLIC_KEY_HEX)?;
    let key_len = key_bytes_vec.len();
    let key_bytes: [u8; 32] = key_bytes_vec
        .try_into()
        .map_err(|_| format!("Invalid Ed25519 public key length: {}", key_len))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("Invalid Ed25519 public key: {}", e))
}

fn verify_update_signature(bytes: &[u8], sig: &str) -> Result<(), String> {
    let key = match parse_update_pubkey() {
        Ok(k) => k,
        Err(_) => {
            fwarn!("No Ed25519 public key embedded in this build Ã¢â‚¬â€ skipping signature verification. \
                    Set REAP3R_UPDATE_PUBKEY_HEX at compile time to enable.");
            return Ok(());
        }
    };
    let signature = parse_update_signature(sig)?;
    key.verify(bytes, &signature)
        .map_err(|e| format!("Ed25519 signature verification failed: {}", e))
}

#[cfg(not(target_os = "windows"))]
fn payload_or_env_nonempty_string(payload: &serde_json::Value, payload_key: &str, env_key: &str) -> Option<String> {
    if let Some(v) = payload[payload_key].as_str() {
        let s = v.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    match std::env::var(env_key) {
        Ok(v) => {
            let s = v.trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        Err(_) => None,
    }
}

fn payload_or_env_u64(
    payload: &serde_json::Value,
    payload_key: &str,
    env_key: &str,
    default: u64,
    max: u64,
) -> u64 {
    if let Some(v) = payload[payload_key].as_u64() {
        return v.min(max);
    }
    match std::env::var(env_key) {
        Ok(v) => v.trim().parse::<u64>().map(|n| n.min(max)).unwrap_or(default),
        Err(_) => default,
    }
}

fn parse_update_urls(payload: &serde_json::Value, primary_url: &str) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    if !primary_url.trim().is_empty() {
        urls.push(primary_url.trim().to_string());
    }
    if let Some(values) = payload["download_urls"].as_array() {
        for value in values {
            if let Some(url) = value.as_str() {
                let trimmed = url.trim();
                if !trimmed.is_empty() {
                    urls.push(trimmed.to_string());
                }
            }
        }
    }

    let mut deduped: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for url in urls {
        if seen.insert(url.clone()) {
            deduped.push(url);
        }
    }
    deduped
}

async fn download_update_bytes_with_fallback(
    client: &reqwest::Client,
    urls: &[String],
    retry_count: u32,
    retry_backoff_ms: u64,
) -> Result<(Vec<u8>, String), String> {
    if urls.is_empty() {
        return Err("No download URL available for update".to_string());
    }

    let attempts_per_url = retry_count.saturating_add(1).max(1);
    let mut errors: Vec<String> = Vec::new();

    for (url_index, url) in urls.iter().enumerate() {
        for attempt in 1..=attempts_per_url {
            finfo!(
                "Downloading candidate {}/{} attempt {}/{}: {}",
                url_index + 1,
                urls.len(),
                attempt,
                attempts_per_url,
                url
            );

            match client.get(url).send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        errors.push(format!("{} -> HTTP {}", url, response.status()));
                    } else {
                        match response.bytes().await {
                            Ok(bytes) => return Ok((bytes.to_vec(), url.clone())),
                            Err(e) => errors.push(format!("{} -> body read error: {}", url, e)),
                        }
                    }
                }
                Err(e) => errors.push(format!("{} -> network error: {}", url, e)),
            }

            if attempt < attempts_per_url && retry_backoff_ms > 0 {
                let wait_ms = retry_backoff_ms.saturating_mul(attempt as u64);
                tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            }
        }
    }

    if errors.len() > 8 {
        errors.truncate(8);
    }
    Err(format!("Download failed for all update URLs: {}", errors.join(" | ")))
}

#[cfg(windows)]
fn bool_from_env_or_payload(payload: &serde_json::Value, payload_key: &str, env_key: &str, default: bool) -> bool {
    if let Some(v) = payload[payload_key].as_bool() {
        return v;
    }
    match std::env::var(env_key) {
        Ok(v) => {
            let raw = v.trim().to_ascii_lowercase();
            matches!(raw.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}

#[cfg(windows)]
fn payload_or_env_string(payload: &serde_json::Value, payload_key: &str, env_key: &str) -> Option<String> {
    if let Some(v) = payload[payload_key].as_str() {
        let s = v.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    match std::env::var(env_key) {
        Ok(v) => {
            let s = v.trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        Err(_) => None,
    }
}

#[cfg(windows)]
fn verify_windows_authenticode(file_path: &Path, expected_thumbprint: Option<&str>) -> Result<(), String> {
    let escaped_path = file_path.display().to_string().replace('\'', "''");
    let expected = expected_thumbprint.unwrap_or("").to_ascii_uppercase();
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $sig=Get-AuthenticodeSignature -FilePath '{path}'; \
         if ($sig.Status -ne 'Valid') {{ Write-Output ('ERR:STATUS:' + $sig.Status); exit 10 }}; \
         if (-not $sig.SignerCertificate) {{ Write-Output 'ERR:NOCERT'; exit 11 }}; \
         $thumb=$sig.SignerCertificate.Thumbprint.ToUpperInvariant(); \
         if ('{expected}' -ne '' -and $thumb -ne '{expected}') {{ Write-Output ('ERR:THUMB:' + $thumb); exit 12 }}; \
         Write-Output ('OK:' + $thumb);",
        path = escaped_path,
        expected = expected.replace('\'', "''"),
    );

    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()
        .map_err(|e| format!("Authenticode verification failed to execute: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        return Err(format!(
            "Authenticode verification failed: {} {}",
            stdout,
            stderr
        ));
    }
    if let Some(tp) = stdout.strip_prefix("OK:") {
        finfo!("Authenticode signature verified. Signer thumbprint={}", tp.trim());
        Ok(())
    } else {
        Err(format!("Unexpected Authenticode verification output: {}", stdout))
    }
}

#[cfg(not(target_os = "windows"))]
fn unix_service_name_candidates(payload: &serde_json::Value, current_exe: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut push_name = |name: Option<String>| {
        if let Some(v) = name {
            let trimmed = v.trim().to_string();
            if !trimmed.is_empty() && seen.insert(trimmed.clone()) {
                out.push(trimmed);
            }
        }
    };

    push_name(payload["service_name"].as_str().map(|s| s.to_string()));
    push_name(payload_or_env_nonempty_string(payload, "service_name", "REAP3R_SERVICE_NAME"));
    push_name(current_exe.file_stem().map(|s| s.to_string_lossy().to_string()));
    push_name(Some("xefi-agent-2".to_string()));
    push_name(Some("reap3r-agent".to_string()));
    push_name(Some("massvision-reap3r-agent".to_string()));
    push_name(Some("MASSVISION-Reap3r-Agent".to_string()));
    out
}

#[cfg(not(target_os = "windows"))]
fn systemd_unit_exists(service_name: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(["show", service_name, "--property=LoadState", "--value"])
        .output()
        .ok()
        .map(|output| {
            if !output.status.success() {
                return false;
            }
            let state = String::from_utf8_lossy(&output.stdout).trim().to_ascii_lowercase();
            state == "loaded"
        })
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn launchctl_target_exists(target: &str) -> bool {
    std::process::Command::new("launchctl")
        .args(["print", target])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn current_uid_string() -> Option<String> {
    if let Ok(uid) = std::env::var("UID") {
        let t = uid.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    std::process::Command::new("id")
        .args(["-u"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let uid = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if uid.is_empty() { None } else { Some(uid) }
            } else {
                None
            }
        })
}

#[cfg(not(target_os = "windows"))]
fn spawn_non_windows_restart(current_exe: &Path, payload: &serde_json::Value) -> Result<String, String> {
    let candidates = unix_service_name_candidates(payload, current_exe);

    for service_name in &candidates {
        if systemd_unit_exists(service_name) {
            let spawn_res = std::process::Command::new("systemctl")
                .args(["restart", service_name])
                .spawn();
            if spawn_res.is_ok() {
                return Ok(format!("systemd:{}", service_name));
            }
        }
    }

    for service_name in &candidates {
        let init_script = PathBuf::from("/etc/init.d").join(service_name);
        if init_script.exists() {
            let spawn_res = std::process::Command::new("service")
                .args([service_name, "restart"])
                .spawn();
            if spawn_res.is_ok() {
                return Ok(format!("service:{}", service_name));
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(label) = payload_or_env_nonempty_string(payload, "launchd_label", "REAP3R_LAUNCHD_LABEL") {
            let system_target = format!("system/{}", label);
            if launchctl_target_exists(&system_target) {
                let spawn_res = std::process::Command::new("launchctl")
                    .args(["kickstart", "-k", &system_target])
                    .spawn();
                if spawn_res.is_ok() {
                    return Ok(format!("launchctl:{}", system_target));
                }
            }
            if let Some(uid) = current_uid_string() {
                let gui_target = format!("gui/{}/{}", uid, label);
                if launchctl_target_exists(&gui_target) {
                    let spawn_res = std::process::Command::new("launchctl")
                        .args(["kickstart", "-k", &gui_target])
                        .spawn();
                    if spawn_res.is_ok() {
                        return Ok(format!("launchctl:{}", gui_target));
                    }
                }
            }
        }
    }

    let restart_delay = payload_or_env_u64(
        payload,
        "self_restart_delay_seconds",
        "REAP3R_UPDATE_SELF_RESTART_DELAY_SECONDS",
        6,
        120,
    );
    let delay = restart_delay.to_string();
    let pid = std::process::id().to_string();
    let exe = current_exe.display().to_string();

    std::process::Command::new("sh")
        .args([
            "-c",
            "sleep \"$1\"; kill -TERM \"$2\" >/dev/null 2>&1 || true; sleep 1; nohup \"$3\" --run >/dev/null 2>&1 &",
            "sh",
            &delay,
            &pid,
            &exe,
        ])
        .spawn()
        .map_err(|e| format!("Failed to spawn fallback self-restart helper: {}", e))?;

    Ok(format!("self-relaunch:{}s", restart_delay))
}

async fn execute_self_update(payload: &serde_json::Value) -> Result<serde_json::Value, String> {
    let primary_download_url = payload["download_url"]
        .as_str()
        .ok_or_else(|| "Missing download_url".to_string())?;
    let download_urls = parse_update_urls(payload, primary_download_url);
    let expected_sha256_raw = payload["sha256"]
        .as_str()
        .ok_or_else(|| "Missing sha256".to_string())?;
    let expected_sha256 = expected_sha256_raw.trim().to_ascii_lowercase();
    if expected_sha256.len() != 64 || !expected_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid sha256 format in update payload".to_string());
    }

    let signature = payload["sig_ed25519"].as_str();
    let version = payload["version"].as_str().unwrap_or("unknown");
    let force = payload["force"].as_bool().unwrap_or(false);
    let retry_count = payload_or_env_u64(
        payload,
        "retry_count",
        "REAP3R_UPDATE_RETRY_COUNT",
        2,
        10,
    ) as u32;
    let retry_backoff_ms = payload_or_env_u64(
        payload,
        "retry_backoff_ms",
        "REAP3R_UPDATE_RETRY_BACKOFF_MS",
        1500,
        60_000,
    );
    let defer_seconds = payload_or_env_u64(
        payload,
        "defer_seconds",
        "REAP3R_UPDATE_DEFER_SECONDS",
        0,
        86_400,
    );
    let jitter_max_seconds = payload_or_env_u64(
        payload,
        "jitter_max_seconds",
        "REAP3R_UPDATE_JITTER_MAX_SECONDS",
        0,
        86_400,
    );

    #[cfg(windows)]
    let require_authenticode = bool_from_env_or_payload(
        payload,
        "require_authenticode",
        "REAP3R_UPDATE_REQUIRE_AUTHENTICODE",
        false,
    );
    #[cfg(windows)]
    let signer_thumbprint = payload_or_env_string(
        payload,
        "signer_thumbprint",
        "REAP3R_UPDATE_SIGNER_THUMBPRINT",
    )
    .map(|s| s.to_ascii_uppercase());

    if download_urls.is_empty() {
        return Err("Self-update requires at least one download URL".to_string());
    }
    for url in &download_urls {
        if !url.to_ascii_lowercase().starts_with("https://") {
            return Err(format!("Self-update requires HTTPS URLs only: {}", url));
        }
    }

    let current_version = env!("CARGO_PKG_VERSION");
    if !force && version == current_version {
        return Ok(serde_json::json!({
            "exit_code": 0,
            "stdout": format!("Agent already on target version {} (force=false). Update skipped.", version),
            "stderr": "",
            "skipped": true
        }));
    }

    finfo!(
        "Self-update requested: version={} force={} urls={} retry_count={} backoff_ms={}",
        version,
        force,
        download_urls.len(),
        retry_count,
        retry_backoff_ms
    );

    if defer_seconds > 0 || jitter_max_seconds > 0 {
        let jitter = if jitter_max_seconds > 0 {
            rand::thread_rng().gen_range(0..=jitter_max_seconds)
        } else {
            0
        };
        let total_wait = defer_seconds.saturating_add(jitter);
        if total_wait > 0 {
            finfo!(
                "Deferring update by {}s (defer={}s jitter={}s)",
                total_wait,
                defer_seconds,
                jitter
            );
            tokio::time::sleep(Duration::from_secs(total_wait)).await;
        }
    }

    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Cannot determine current exe path: {}", e))?;
    let current_dir = current_exe.parent()
        .ok_or_else(|| "Cannot determine exe directory".to_string())?;

    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };
    let new_binary_path = current_dir.join(format!("xefi-agent-2-new{}", ext));
    let backup_path = current_dir.join(format!("xefi-agent-2-old{}", ext));

    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let (bytes, used_download_url) = download_update_bytes_with_fallback(
        &client,
        &download_urls,
        retry_count,
        retry_backoff_ms,
    ).await?;

    finfo!(
        "Downloaded {} bytes from {}",
        bytes.len(),
        used_download_url
    );

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual_sha256 = format!("{:x}", hasher.finalize());

    if actual_sha256 != expected_sha256 {
        return Err(format!(
            "SHA256 mismatch: expected={} actual={}",
            expected_sha256, actual_sha256
        ));
    }
    finfo!("SHA256 verified OK");

    if let Some(sig) = signature {
        verify_update_signature(&bytes, sig)?;
        finfo!("Ed25519 signature verified OK");
    } else {
        fwarn!("No sig_ed25519 in update payload; skipping signature verification (SHA256 still verified)");
    }

    std::fs::write(&new_binary_path, &bytes)
        .map_err(|e| format!("Write new binary: {}", e))?;

    #[cfg(windows)]
    {
        if require_authenticode || signer_thumbprint.is_some() {
            verify_windows_authenticode(&new_binary_path, signer_thumbprint.as_deref())?;
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&new_binary_path, std::fs::Permissions::from_mode(0o755));
    }

    #[cfg(target_os = "windows")]
    {
        let service_name = detect_installed_service_name().unwrap_or_else(|| SERVICE_NAME.to_string());
        let _ = std::fs::remove_file(&backup_path);

        let updater_script = format!(
            r#"
Start-Sleep -Seconds 2
$svcName = '{service}'
$currentExe = '{current}'
$newExe = '{new_bin}'
$backupExe = '{backup}'
$logFile = '{log}'

function Log ($msg) {{ "[$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))] $msg" | Out-File $logFile -Append }}

Log "Starting agent update to version {version}"

try {{
    Stop-Service -Name $svcName -Force -ErrorAction Stop
    Log "Service stopped"
}} catch {{
    Log "WARNING: Stop-Service failed: $_"
}}

$maxWait = 30
$waited = 0
while ($waited -lt $maxWait) {{
    $proc = Get-Process -Name "xefi-agent-2" -ErrorAction SilentlyContinue
    if (-not $proc) {{ break }}
    Start-Sleep -Seconds 1
    $waited++
}}

if ($waited -ge $maxWait) {{
    Log "Force killing process"
    Stop-Process -Name "xefi-agent-2" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}}

try {{
    if (Test-Path $backupExe) {{ Remove-Item $backupExe -Force }}
    Move-Item $currentExe $backupExe -Force
    Log "Moved current to backup"
    Move-Item $newExe $currentExe -Force
    Log "Moved new to current"
}} catch {{
    Log "ERROR swapping binaries: $_"
    if ((Test-Path $backupExe) -and -not (Test-Path $currentExe)) {{
        Move-Item $backupExe $currentExe -Force
        Log "Restored from backup"
    }}
    Start-Service -Name $svcName -ErrorAction SilentlyContinue
    exit 1
}}

try {{
    Start-Service -Name $svcName -ErrorAction Stop
    Log "Service started with new version"
}} catch {{
    Log "ERROR starting service: $_"
    if (Test-Path $backupExe) {{
        Remove-Item $currentExe -Force -ErrorAction SilentlyContinue
        Move-Item $backupExe $currentExe -Force
        Start-Service -Name $svcName -ErrorAction SilentlyContinue
        Log "Rolled back to previous version"
    }}
}}

Log "Update complete"
"#,
            service = service_name,
            current = current_exe.display(),
            new_bin = new_binary_path.display(),
            backup = backup_path.display(),
            log = config_dir().join("update.log").display(),
            version = version,
        );

        let updater_path = config_dir().join("update_agent.ps1");
        std::fs::write(&updater_path, &updater_script)
            .map_err(|e| format!("Write updater script: {}", e))?;

        finfo!("Launching updater script: {}", updater_path.display());
        let _ = std::process::Command::new("powershell.exe")
            .args([
                "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass",
                "-NoProfile",
                "-File", &updater_path.display().to_string(),
            ])
            .spawn()
            .map_err(|e| format!("Launch updater: {}", e))?;

        Ok(serde_json::json!({
            "exit_code": 0,
            "stdout": format!(
                "Agent update initiated: v{} -> v{}. Service '{}' will restart shortly.",
                current_version,
                version,
                service_name
            ),
            "stderr": "",
            "download_url_used": used_download_url
        }))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::fs::remove_file(&backup_path);
        std::fs::rename(&current_exe, &backup_path)
            .map_err(|e| format!("Backup current binary: {}", e))?;
        if let Err(e) = std::fs::rename(&new_binary_path, &current_exe) {
            let _ = std::fs::rename(&backup_path, &current_exe);
            return Err(format!("Move new binary: {}", e));
        }

        let restart_method = spawn_non_windows_restart(&current_exe, payload)?;
        finfo!("Binary replaced, restart requested using {}", restart_method);

        Ok(serde_json::json!({
            "exit_code": 0,
            "stdout": format!(
                "Agent update initiated: v{} -> v{}. Restart strategy: {}.",
                current_version,
                version,
                restart_method
            ),
            "stderr": "",
            "download_url_used": used_download_url,
            "restart_method": restart_method
        }))
    }
}

async fn start_remote_desktop(
    payload: &serde_json::Value,
    agent_id: String,
    secret: String,
    job_id: String,
    tx: Option<tokio::sync::mpsc::Sender<String>>,
) -> Result<serde_json::Value, String> {
    let tx = tx.ok_or_else(|| "No WS channel available for streaming".to_string())?;

    // Parse parameters
    // Keep RD smooth by default while staying safe for CPU/network.
    let fps = payload["fps"].as_u64().unwrap_or(15).clamp(1, 30);
    let quality = payload["quality"].as_u64().unwrap_or(50).clamp(10, 100);
    let scale = payload["scale"].as_f64().unwrap_or(0.5).clamp(0.2, 1.0);
    let monitor: i64 = payload["monitor"].as_i64().unwrap_or(-1).clamp(-1, 15);

    // Stop any existing session
    RD_ACTIVE.store(false, Ordering::SeqCst);
    rd_set_session_id(None);
    rd_signal_stop();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Clean up old files
    let _ = std::fs::remove_file(rd_stop_flag_path());
    let _ = std::fs::remove_file(rd_frame_data_path());
    let capture_err_log = config_dir().join("rd_capture_error.log");
    let _ = std::fs::remove_file(&capture_err_log);

    // Start new session
    RD_ACTIVE.store(true, Ordering::SeqCst);
    let session_id = job_id.clone();
    rd_set_session_id(Some(session_id.clone()));

    // Write capture script to disk
    // PS single-quoted strings treat \ as literal Ã¢â‚¬â€ no escaping needed
    let dir_str = config_dir().display().to_string();
    let script_content = RD_CAPTURE_LOOP_PS
        .replace("__DIR__", &dir_str)
        .replace("__SCALE__", &format!("{:.2}", scale))
        .replace("__QUALITY__", &format!("{}", quality))
        .replace("__FPS__", &format!("{}", fps))
        .replace("__MONITOR__", &format!("{}", monitor));

    let script_path = rd_script_path();
    std::fs::write(&script_path, &script_content).map_err(|e| format!("Write capture script: {}", e))?;

    finfo!(
        "Remote desktop started: session={} fps={} quality={} scale={:.0}% monitor={}",
        session_id, fps, quality, scale * 100.0,
        if monitor < 0 { "all".to_string() } else { format!("{}", monitor) }
    );

    // Launch capture process
    #[cfg(windows)]
    {
        let cmd = format!(
            "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File \"{}\"",
            script_path.display()
        );
        match user_session::launch_in_user_session(&cmd) {
            Ok(pid) => finfo!("RD: Capture process launched in user session (PID {})", pid),
            Err(e) => {
                fwarn!("RD: Cannot launch in user session: {}. Falling back to local session.", e);
                // Fallback: run locally (works when agent is NOT a service)
                match tokio::process::Command::new("powershell")
                    .args(["-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", &script_path.display().to_string()])
                    .spawn() {
                    Ok(_) => finfo!("RD: Capture process launched locally"),
                    Err(e2) => {
                        ferror!("RD: Failed to launch capture process: {}", e2);
                        return Err(format!("Cannot launch RD capture: session={}, local={}", e, e2));
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        // Linux/macOS: just run locally (no session isolation issue)
        let _ = tokio::process::Command::new("powershell")
            .args(["-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", &script_path.display().to_string()])
            .spawn();
    }

    // Give the capture process time to start and produce the first frame
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Ã¢â€â‚¬Ã¢â€â‚¬ Launch input handler (for interactive control) Ã¢â€â‚¬Ã¢â€â‚¬
    // Always launch it so control mode can be toggled from the UI.
    let _ = std::fs::remove_file(rd_input_data_path());
    let input_script_content = RD_INPUT_LOOP_PS
        .replace("__DIR__", &dir_str)
        .replace("__MONITOR__", &format!("{}", monitor))
        .replace("__SCALE__", &format!("{:.2}", scale));
    let input_script_path = rd_input_script_path();
    if let Err(e) = std::fs::write(&input_script_path, &input_script_content) {
        fwarn!("RD: Failed to write input script: {}", e);
    } else {
        #[cfg(windows)]
        {
            let input_cmd = format!(
                "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File \"{}\"",
                input_script_path.display()
            );
            match user_session::launch_in_user_session(&input_cmd) {
                Ok(pid) => finfo!("RD: Input handler launched in user session (PID {})", pid),
                Err(e) => {
                    fwarn!("RD: Cannot launch input handler in user session: {}. Falling back to local.", e);
                    match tokio::process::Command::new("powershell")
                        .args(["-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-NoProfile", "-File", &input_script_path.display().to_string()])
                        .spawn() {
                        Ok(_) => finfo!("RD: Input handler launched locally"),
                        Err(e2) => fwarn!("RD: Failed to launch input handler: {}", e2),
                    }
                }
            }
        }
    }

    // Spawn background frame-reader loop
    let frame_path = rd_frame_data_path();
    let err_log_path = config_dir().join("rd_capture_error.log");
    let check_interval = Duration::from_millis((1000 / fps).max(100) / 2); // poll at 2Ãƒâ€” fps

    tokio::spawn(async move {
        let mut sequence: u64 = 0;
        let mut last_seq: i64 = -1;
        let mut empty_count: u64 = 0;

        while RD_ACTIVE.load(Ordering::SeqCst) {
            // Check for capture error log (PS script logs errors there)
            if empty_count > 10 {
                if let Ok(err_log) = tokio::fs::read_to_string(&err_log_path).await {
                    if err_log.contains("FATAL") || err_log.contains("CopyFromScreen error") || err_log.contains("Too many errors") {
                        ferror!("RD: Capture script reported errors:\n{}", err_log.trim());
                        // Send error message to UI
                        let err_msg = build_message(
                            &agent_id,
                            "stream_output",
                            serde_json::json!({
                                "session_id": session_id,
                                "stream_type": "error",
                                "data": format!("Capture failed: {}", err_log.lines().last().unwrap_or("unknown error")),
                                "sequence": 0,
                            }),
                            &secret,
                        );
                        let _ = tx.send(err_msg).await;
                        // Stop after reporting error
                        break;
                    }
                }
            }

            // Read frame data file
            match tokio::fs::read_to_string(&frame_path).await {
                Ok(data) if data.contains('|') => {
                    if let Some((seq_str, b64)) = data.split_once('|') {
                        if let Ok(file_seq) = seq_str.trim().parse::<i64>() {
                            if file_seq > last_seq && b64.len() > 100 {
                                last_seq = file_seq;
                                empty_count = 0;

                                let msg = build_message(
                                    &agent_id,
                                    "stream_output",
                                    serde_json::json!({
                                        "session_id": session_id,
                                        "stream_type": "frame",
                                        "data": b64.trim(),
                                        "sequence": sequence,
                                    }),
                                    &secret,
                                );
                                if tx.send(msg).await.is_err() {
                                    fwarn!("RD: WS send failed, stopping");
                                    break;
                                }
                                if sequence % 10 == 0 {
                                    finfo!("RD: frame #{} sent ({} bytes, file_seq={})", sequence, b64.len(), file_seq);
                                }
                                sequence += 1;
                            }
                        }
                    }
                }
                Ok(_) => {
                    empty_count += 1;
                    if empty_count == 20 {
                        fwarn!("RD: No valid frames after 20 reads, capture may have failed");
                    }
                }
                Err(_) => {
                    empty_count += 1;
                    if empty_count == 30 {
                        fwarn!("RD: Frame file not appearing, capture process may not have started");
                    }
                }
            }

            tokio::time::sleep(check_interval).await;
        }

        // Signal capture process to stop
        rd_signal_stop();
        RD_ACTIVE.store(false, Ordering::SeqCst);
        rd_set_session_id(None);
        finfo!("Remote desktop session ended: session={}", session_id);
    });

    Ok(serde_json::json!({
        "exit_code": 0,
        "stdout": format!("Remote desktop started: fps={} quality={} scale={:.0}% monitor={}", fps, quality, scale * 100.0,
            if monitor < 0 { "all".to_string() } else { format!("{}", monitor) }),
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

// Ã¢â€â‚¬Ã¢â€â‚¬ Windows Service implementation Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Placed here so finfo!/fwarn!/ferror! macros and all agent functions are in scope.

#[cfg(windows)]
const SERVICE_NAME: &str = "XEFI-Agent-2";
#[cfg(windows)]
const LEGACY_SERVICE_NAMES: [&str; 4] = ["MASSVISION-Reap3r-Agent", "Reap3rAgent", "ReaP3rAgent", "xefi-agent-2"];

#[cfg(windows)]
fn service_name_candidates() -> Vec<&'static str> {
    let mut names = vec![SERVICE_NAME];
    for n in LEGACY_SERVICE_NAMES {
        if !names.contains(&n) {
            names.push(n);
        }
    }
    names
}

#[cfg(windows)]
fn service_exists(name: &str) -> bool {
    std::process::Command::new("sc.exe")
        .args(["query", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn detect_installed_service_name() -> Option<String> {
    for name in service_name_candidates() {
        if service_exists(name) {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, windows_service_main);

#[cfg(windows)]
fn windows_service_main(_svc_args: Vec<std::ffi::OsString>) {
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();

    let mut status_handle: Option<windows_service::service_control_handler::ServiceStatusHandle> = None;
    let mut active_service_name = SERVICE_NAME.to_string();
    for candidate in service_name_candidates() {
        let tx_for_handler = shutdown_tx.clone();
        match service_control_handler::register(candidate, move |ctrl| {
            match ctrl {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = tx_for_handler.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        }) {
            Ok(h) => {
                active_service_name = candidate.to_string();
                status_handle = Some(h);
                break;
            }
            Err(e) => {
                flog("WARN", &format!("SCM register failed for '{}': {}", candidate, e));
            }
        }
    }

    let status_handle = match status_handle {
        Some(h) => h,
        None => {
            flog("ERROR", "SCM register failed for all known service names");
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
    flog("INFO", &format!("Windows Service [{}]: Running", active_service_name));
    eventlog::write("INFO", &format!(
        "XEFI Agent 2 service '{}' started - v{} (PID {})",
        active_service_name, env!("CARGO_PKG_VERSION"), std::process::id()
    ));

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let args = build_args_from_config();
        let server = match args.server.clone().or_else(|| load_config().map(|c| c.server)) {
            Some(s) => s,
            None => {
                flog("ERROR", "No server URL - cannot start");
                return;
            }
        };
        // Auto-diagnostic on service startup
        run_startup_diagnostic(&server, args.insecure_tls).await;

        let mut state = AgentRuntimeState::load();
        spawn_health_server(args.health_port);
        let mut backoff: u64 = 1;
        loop {
            if shutdown_rx.try_recv().is_ok() { break; }
            let res = run_agent(&args, &server, &mut state).await;
            match &res {
                Ok(()) => fwarn!("Connection closed. Reconnecting in {}s...", backoff),
                Err(e) => ferror!("Error: {}. Reconnecting in {}s...", e, backoff),
            }
            if shutdown_rx.try_recv().is_ok() { break; }
            let jitter_ms = (Uuid::new_v4().as_u128() % 2000) as u64;
            tokio::time::sleep(Duration::from_millis(backoff * 1000 + jitter_ms)).await;
            backoff = if res.is_ok() { 1 } else { (backoff * 2).min(300) };
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
    flog("INFO", &format!("Windows Service [{}]: Stopped", active_service_name));
    eventlog::write("INFO", &format!("XEFI Agent 2 service '{}' stopped", active_service_name));
}
#[cfg(windows)]
fn install_windows_service() {
    let exe = std::env::current_exe().expect("Cannot determine executable path");
    let exe_path = exe.display().to_string();
    let service_bin_path = format!("\"{}\" --run", exe_path);
    let service_name = detect_installed_service_name().unwrap_or_else(|| SERVICE_NAME.to_string());
    println!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
    println!("  XEFI Agent 2 Ã¢â‚¬â€ Service Installer");
    println!("  Version: {}", env!("CARGO_PKG_VERSION"));
    println!("  Binary : {}", exe_path);
    println!("  Arch   : {}", if cfg!(target_arch = "x86_64") { "x64" } else { "x86" });
    println!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
    println!();

    // Ã¢â€â‚¬Ã¢â€â‚¬ 0. Parse --server and --token from CLI args (for silent installs) Ã¢â€â‚¬Ã¢â€â‚¬
    // When called as: reap3r-agent.exe --install --server wss://... --token XYZ
    // We save the config BEFORE creating the service so it auto-enrolls on start.
    let args: Vec<String> = std::env::args().collect();
    let mut cli_server: Option<String> = None;
    let mut cli_token: Option<String> = None;
    for i in 0..args.len() {
        if args[i] == "--server" { cli_server = args.get(i + 1).cloned(); }
        if args[i] == "--token"  { cli_token = args.get(i + 1).cloned(); }
    }
    // Also check env vars (for GPO/Intune deployment via batch file)
    if cli_server.is_none() { cli_server = std::env::var("REAP3R_SERVER").ok(); }
    if cli_token.is_none()  { cli_token = std::env::var("REAP3R_TOKEN").ok(); }

    if let (Some(server), Some(token)) = (cli_server.as_ref(), cli_token.as_ref()) {
        println!("[*] Running one-shot enrollment before service registration...");
        match std::process::Command::new(&exe_path)
            .args(["--enroll", "--server", server, "--token", token])
            .status()
        {
            Ok(status) if status.success() => {
                println!("[OK] One-shot enrollment successful");
                remove_bootstrap_file();
            }
            Ok(status) => {
                eprintln!("[ERROR] Enrollment command failed with exit code {:?}", status.code());
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("[ERROR] Failed to run enrollment command: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(ref server) = cli_server {
        println!("[*] Server URL: {}", server);
        let cfg_dir = config_dir();
        let _ = std::fs::create_dir_all(&cfg_dir);
        let bootstrap_path = cfg_dir.join("bootstrap.json");
        let bootstrap = serde_json::json!({
            "server": server,
            "token": cli_token.as_deref().unwrap_or(""),
        });
        match std::fs::write(&bootstrap_path, serde_json::to_string_pretty(&bootstrap).unwrap_or_default()) {
            Ok(_) => {
                let _ = apply_windows_secret_acl(&bootstrap_path);
                println!("[OK] Bootstrap config written to {}", bootstrap_path.display());
            }
            Err(e) => eprintln!("[WARN] Could not write bootstrap: {}", e),
        }
    }
    if let Some(ref token) = cli_token {
        println!("[*] Enrollment token: {}...", &token[..token.len().min(8)]);
    }
    println!();
    if service_name != SERVICE_NAME {
        println!("[WARN] Legacy service detected: {} (keeping existing name for compatibility)", service_name);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 1. Register Windows Event Log source Ã¢â€â‚¬Ã¢â€â‚¬
    println!("[*] Registering Event Log source...");
    let _ = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .create_subkey("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\XEFI Agent 2")
        .map(|(key, _)| {
            let _ = key.set_value("EventMessageFile", &exe_path);
            let _ = key.set_value::<u32, _>("TypesSupported", &7u32);
        });

    // Ã¢â€â‚¬Ã¢â€â‚¬ 2. Create the Windows service via sc.exe Ã¢â€â‚¬Ã¢â€â‚¬
    println!("[*] Creating service: {}", service_name);
    let output = std::process::Command::new("sc.exe")
        .args([
            "create", &service_name,
            "binPath=", &service_bin_path,
            "start=", "auto",
            "DisplayName=", "XEFI Agent 2",
        ])
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            if o.status.success() {
                println!("[OK] Service created successfully");
            } else {
                // Check if already exists
                if stderr.contains("1073") || stdout.contains("1073") {
                    println!("[OK] Service already exists Ã¢â‚¬â€ updating...");
                    // Update the binPath
                    let _ = std::process::Command::new("sc.exe")
                        .args(["config", &service_name, "binPath=", &service_bin_path])
                        .output();
                } else {
                    eprintln!("[ERROR] sc create failed: {} {}", stdout.trim(), stderr.trim());
                    return;
                }
            }
        }
        Err(e) => { eprintln!("[ERROR] Failed to run sc.exe: {}", e); return; }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 3. Set description Ã¢â€â‚¬Ã¢â€â‚¬
    let desc = format!(
        "XEFI Agent 2 v{} Ã¢â‚¬â€ Enterprise remote management. Runs as SYSTEM, auto-starts on boot, auto-recovers on failure.",
        env!("CARGO_PKG_VERSION")
    );
    let _ = std::process::Command::new("sc.exe")
        .args(["description", &service_name, &desc])
        .output();

    // Ã¢â€â‚¬Ã¢â€â‚¬ 4. Configure automatic recovery (restart on failure) Ã¢â€â‚¬Ã¢â€â‚¬
    // Reset failure count after 24h, actions: restart after 5s, 10s, 30s
    println!("[*] Configuring automatic recovery...");
    let _ = std::process::Command::new("sc.exe")
        .args(["failure", &service_name,
            "reset=", "0",
            "actions=", "restart/5000/restart/5000/restart/5000"])
        .output();

    // Also set failure on non-crash exit (delayed auto-restart covers agent bugs)
    let _ = std::process::Command::new("sc.exe")
        .args(["failureflag", &service_name, "1"])
        .output();
    println!("[OK] Recovery policy: restart after 5s / 10s / 30s");

    // Ã¢â€â‚¬Ã¢â€â‚¬ 5. Set service to run as LocalSystem (default) with delayed auto-start Ã¢â€â‚¬Ã¢â€â‚¬
    let _ = std::process::Command::new("sc.exe")
        .args(["config", &service_name, "start=", "delayed-auto"])
        .output();
    println!("[OK] Start type: delayed-auto (starts after core services)");

    // Ã¢â€â‚¬Ã¢â€â‚¬ 6. Start the service Ã¢â€â‚¬Ã¢â€â‚¬
    println!("[*] Starting service...");
    let start = std::process::Command::new("sc.exe")
        .args(["start", &service_name])
        .output();
    match start {
        Ok(o) if o.status.success() => println!("[OK] Service started!"),
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stdout);
            let err = String::from_utf8_lossy(&o.stderr);
            if msg.contains("1056") || err.contains("1056") {
                println!("[OK] Service is already running");
            } else {
                eprintln!("[WARN] Service start: {} {}", msg.trim(), err.trim());
            }
        }
        Err(e) => eprintln!("[WARN] Could not start service: {}", e),
    }

    println!();
    println!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
    println!("  Installation complete!");
    println!("  Service   : {}", service_name);
    println!("  Status    : sc query {}", service_name);
    println!("  Logs      : {}\\logs\\agent.log", config_dir().display());
    println!("  Event Log : Event Viewer Ã¢â€ â€™ Application Ã¢â€ â€™ Reap3r Agent");
    println!("  Diagnose  : reap3r-agent.exe --diagnose");
    println!("  Uninstall : reap3r-agent.exe --uninstall");
    println!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
}

#[cfg(windows)]
fn uninstall_windows_service() {
    let mut removed_any = false;
    for svc in service_name_candidates() {
        if !service_exists(svc) {
            continue;
        }
        println!("Uninstalling Windows Service: {}", svc);
        let _ = std::process::Command::new("sc.exe")
            .args(["stop", svc])
            .output();
        std::thread::sleep(Duration::from_secs(2));
        let output = std::process::Command::new("sc.exe")
            .args(["delete", svc])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                removed_any = true;
                println!("[OK] Service removed: {}", svc);
            }
            Ok(o) => {
                let msg = String::from_utf8_lossy(&o.stdout);
                let err = String::from_utf8_lossy(&o.stderr);
                eprintln!("[ERROR] sc delete {}: {} {}", svc, msg.trim(), err.trim());
            }
            Err(e) => eprintln!("[ERROR] Failed to run sc.exe for {}: {}", svc, e),
        }
    }
    if !removed_any {
        println!("[OK] No installed Reap3r service found");
    }
    // Remove Event Log source
    let _ = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .delete_subkey_all("SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\XEFI Agent 2");
    println!("[OK] Event Log source removed");
    println!("[OK] Config and logs remain at: {}", config_dir().display());
}

#[cfg(windows)]
fn build_args_from_config() -> Args {
    let saved = load_config();

    // If no saved config, check for bootstrap.json (written by --install --server --token)
    let bootstrap = if saved.is_none() {
        let bp = config_dir().join("bootstrap.json");
        std::fs::read_to_string(&bp).ok().and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
    } else {
        None
    };

    let server = saved.as_ref().map(|c| c.server.clone())
        .or_else(|| bootstrap.as_ref().and_then(|b| b["server"].as_str().map(String::from)))
        .or_else(|| std::env::var("REAP3R_SERVER").ok());
    let token = bootstrap.as_ref().and_then(|b| {
        let t = b["token"].as_str().unwrap_or("");
        if t.is_empty() { None } else { Some(t.to_string()) }
    }).or_else(|| std::env::var("REAP3R_TOKEN").ok());

    Args {
        enroll: false,
        run: true,
        server,
        token,
        agent_id: saved.as_ref().map(|c| c.agent_id.clone())
            .or_else(|| std::env::var("REAP3R_AGENT_ID").ok()),
        hmac_key: saved.as_ref().map(|c| c.hmac_key.clone())
            .or_else(|| std::env::var("REAP3R_HMAC_KEY").ok()),
        heartbeat_interval: std::env::var("REAP3R_HEARTBEAT_INTERVAL")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(30),
        max_backoff: std::env::var("REAP3R_MAX_BACKOFF")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(300),
        health_port: std::env::var("REAP3R_HEALTH_PORT")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(0),
        diagnose: false,
        status: false,
        logs: false,
        self_test: false,
        print_config: false,
        insecure_tls: std::env::var("REAP3R_INSECURE_TLS").as_deref() == Ok("1"),
        run_for_secs: std::env::var("REAP3R_RUN_FOR_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(0),
        log_file: None,
        log_lines: std::env::var("REAP3R_LOG_LINES").ok().and_then(|v| v.parse().ok()).unwrap_or(200),
        install: false,
        uninstall: false,
    }
}

#[tokio::main]
async fn main() {
    // Ã¢â€â‚¬Ã¢â€â‚¬ Windows: always try service dispatcher first Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // When launched by Windows SCM, service_dispatcher::start() will block and
    // call windows_service_main(). If we're NOT running as a service (e.g. CLI),
    // it returns an error immediately and we fall through to normal CLI mode.
    #[cfg(windows)]
    {
        // Install rustls CryptoProvider early (ring) Ã¢â‚¬â€ must happen before any TLS ops.
        // When both 'ring' and 'aws-lc-rs' features are active (pulled by tokio-tungstenite),
        // rustls cannot auto-detect which provider to use and panics.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Init file logger early before any other code.
        let log_path = std::env::var("REAP3R_LOG_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_log_path());
        let _ = FILE_LOGGER.set(FileLogger::open(&log_path));

        // Always attempt service dispatcher Ã¢â‚¬â€ if launched by SCM it will block,
        // otherwise it returns an error and we fall through to CLI mode.
        flog("INFO", "Trying Windows service dispatcher...");
        let mut dispatcher_started = false;
        for svc in service_name_candidates() {
            match service_dispatcher::start(svc, ffi_service_main) {
                Ok(()) => {
                    dispatcher_started = true;
                    break;
                }
                Err(e) => {
                    flog("WARN", &format!("Service dispatcher '{}' not active: {}", svc, e));
                }
            }
        }
        if dispatcher_started {
            return;
        }
        flog("INFO", "Not running as service Ã¢â‚¬â€ entering CLI mode");
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 0. Install rustls CryptoProvider (ring) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // Must happen before any TLS operation. When both 'ring' and 'aws-lc-rs'
    // features are active, rustls cannot auto-detect and panics.
    #[cfg(not(windows))]
    { let _ = rustls::crypto::ring::default_provider().install_default(); }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 1. Init tracing (stdout) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(cfg!(not(target_os = "windows")))
        .json()
        .init();

    let args = Args::parse();

    // Ã¢â€â‚¬Ã¢â€â‚¬ 2. Init file logger Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    let log_path = args.log_file.clone().unwrap_or_else(default_log_path);
    let _ = FILE_LOGGER.set(FileLogger::open(&log_path));

    finfo!("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
    finfo!("MASSVISION Reap3r Agent v{} starting", env!("CARGO_PKG_VERSION"));
    finfo!("Log file: {}", log_path.display());
    finfo!("PID: {}", std::process::id());

    // Ã¢â€â‚¬Ã¢â€â‚¬ 3. URL validation Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    // Do this before anything else so errors are visible in the log.
    let server_url = args.server.clone().or_else(|| load_config().map(|c| c.server));
    let strict_url_validation = !(args.logs || args.status);
    if let Some(ref url) = server_url {
        if strict_url_validation && !url.starts_with("ws://") && !url.starts_with("wss://") {
            let msg = format!(
                "FATAL: Invalid server URL '{}'. Must start with ws:// or wss://. \
                 Use: reap3r-agent.exe --server wss://YOUR_SERVER/ws/agent --token YOUR_TOKEN",
                url
            );
            ferror!("{}", msg);
            eprintln!("{}", msg);
            std::process::exit(1);
        }
        if strict_url_validation && cfg!(not(debug_assertions)) && url.starts_with("ws://") {
            fwarn!("WARNING: Using plain ws:// (unencrypted). Production deployments should use wss://");
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 4. Dev-only insecure TLS guard Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    if false {
        let msg = "FATAL: --insecure-tls is disabled by policy in this build.\n\
                   Fix your TLS certificate instead.";
        ferror!("{}", msg);
        eprintln!("{}", msg);
        std::process::exit(1);
    }
    if args.insecure_tls {
        fwarn!("WARNING: --insecure-tls active Ã¢â‚¬â€ TLS certificate validation is DISABLED");
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 4b. --install / --uninstall Windows Service Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    #[cfg(windows)]
    {
        if args.install {
            install_windows_service();
            std::process::exit(0);
        }
        if args.uninstall {
            uninstall_windows_service();
            std::process::exit(0);
        }
    }
    #[cfg(not(windows))]
    {
        if args.install || args.uninstall {
            eprintln!("--install / --uninstall is only supported on Windows");
            std::process::exit(1);
        }
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 5. --diagnose mode Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    if args.diagnose {
        run_diagnostics(&args).await;
        std::process::exit(0);
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ 6. --print-config mode Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
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

    // Ã¢â€â‚¬Ã¢â€â‚¬ 7. Require server (from args or saved config) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
    if args.logs {
        match print_logs_tail(&log_path, args.log_lines) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    }

    if args.status {
        run_status_command(&args).await;
        std::process::exit(0);
    }

    if args.self_test {
        match run_self_test_command(&args).await {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("Self-test failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    if args.enroll {
        let server = match args.server.clone() {
            Some(v) => v,
            None => {
                eprintln!("Missing --server for --enroll (example: --server wss://host/ws/agent)");
                std::process::exit(2);
            }
        };
        let token = match args.token.clone() {
            Some(v) => v,
            None => {
                eprintln!("Missing --token for --enroll");
                std::process::exit(2);
            }
        };

        match enroll_once(&server, &token, args.insecure_tls).await {
            Ok(cfg) => {
                if let Err(e) = save_config(&cfg) {
                    eprintln!("Enrollment succeeded but config save failed: {}", e);
                    std::process::exit(1);
                }
                remove_bootstrap_file();
                println!("Enrollment successful. agent_id={}", cfg.agent_id);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Enrollment failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    if !args.run {
        finfo!("Compatibility mode: running without explicit --run");
    }

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
    // Auto-diagnostic on startup (logs only, non-blocking)
    run_startup_diagnostic(&server, args.insecure_tls).await;

    let mut state = AgentRuntimeState::load();
    spawn_health_server(args.health_port);
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

        let max_bo = args.max_backoff.max(10);
        let jitter_ms = (Uuid::new_v4().as_u128() % 2000) as u64;
        tokio::time::sleep(Duration::from_millis(backoff_secs * 1000 + jitter_ms)).await;
        backoff_secs = if res.is_ok() { 1 } else { (backoff_secs * 2).min(max_bo) };
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ Local HTTP health-check server Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// Listens on 0.0.0.0:{port}, responds to any GET request with JSON.
// Designed to be checked by Zabbix userparameter or Prometheus.
//
//   UserParameter=reap3r.health,curl -sf http://127.0.0.1:9090/health
//
// Response example:
//   {"status":"ok","version":"1.2.0","enrolled":true,"uptime_sec":3600}
fn spawn_health_server(port: u16) {
    if port == 0 {
        return;
    }
    finfo!("Health check server starting on 0.0.0.0:{}", port);
    tokio::spawn(async move {
        let addr = format!("0.0.0.0:{}", port);
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => { finfo!("Health server listening on {}", addr); l }
            Err(e) => { ferror!("Health server failed to bind {}: {}", addr, e); return; }
        };
        loop {
            match listener.accept().await {
                Err(e) => { fwarn!("Health server accept error: {}", e); continue; }
                Ok((mut stream, peer)) => {
                    tokio::spawn(async move {
                        // Drain the HTTP request (we don't need to parse it Ã¢â‚¬â€ respond to any GET).
                        // Give the OS a moment to buffer the client's headers, then drain.
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        {
                            use tokio::io::AsyncReadExt;
                            let mut buf = [0u8; 512];
                            let _ = stream.read(&mut buf).await;
                        }

                        let enrolled = load_config()
                            .map(|c| !c.agent_id.is_empty())
                            .unwrap_or(false);
                        let uptime = sysinfo::System::uptime();

                        let body = serde_json::json!({
                            "status": "ok",
                            "version": env!("CARGO_PKG_VERSION"),
                            "enrolled": enrolled,
                            "uptime_sec": uptime,
                            "pid": std::process::id(),
                        }).to_string();

                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(), body
                        );

                        use tokio::io::AsyncWriteExt;
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.flush().await;
                        finfo!("Health check served to {}", peer);
                    });
                }
            }
        }
    });
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
    //  2. Saved agent.conf (already enrolled on a previous run) Ã¢â€ Â checked BEFORE token
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
        finfo!("No saved config found - enrolling with token...");
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

                let cfg = AgentConfig {
                    agent_id: id.clone(),
                    hmac_key: key.clone(),
                    server: server.to_string(),
                    enrolled_at: now_ms(),
                };
                if let Err(e) = save_config(&cfg) {
                    fwarn!("Failed to save agent config - will need re-enrollment on restart: {}", e);
                } else {
                    remove_bootstrap_file();
                }
                finfo!("Enrolled OK - agent_id={}", id);
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

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(256);
    let tx_hb = tx.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(hb_interval));
        let mut inventory_counter: u64 = 0;
        let mut heartbeat_counter: u64 = 0;
        loop {
            interval.tick().await;
            heartbeat_counter += 1;
            let metrics = collect_metrics();
            let mem_used = metrics["memory_used_bytes"].as_u64().unwrap_or(0);
            let mem_total = metrics["memory_total_bytes"].as_u64().unwrap_or(0);
            let disk_used = metrics["disk_used_bytes"].as_u64().unwrap_or(0);
            let disk_total = metrics["disk_total_bytes"].as_u64().unwrap_or(0);

            let memory_percent = if mem_total > 0 { ((mem_used as f64 / mem_total as f64) * 100.0).round() as u64 } else { 0 };
            let disk_percent = if disk_total > 0 { ((disk_used as f64 / disk_total as f64) * 100.0).round() as u64 } else { 0 };
            let cpu_percent = metrics["cpu_percent"].as_u64().unwrap_or(0);

            // Combined heartbeat + metrics in a single message (halves server message volume at scale).
            // The backend should prefer to read metrics from heartbeat.metrics rather than
            // waiting for separate metrics_push.
            let hb = build_message(
                &agent_id_hb,
                "heartbeat",
                serde_json::json!({
                    "uptime_sec": sysinfo::System::uptime(),
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_percent,
                    "disk_percent": disk_percent,
                    // Full metrics embedded so the server doesn't need a separate message.
                    "metrics": metrics.clone(),
                }),
                &key_hb,
            );
            if heartbeat_counter % 5 == 0 {
                finfo!(
                    "Heartbeat queued (cpu={}% mem={}% disk={}%)",
                    cpu_percent, memory_percent, disk_percent
                );
            }
            if tx_hb.send(hb).await.is_err() {
                break;
            }

            // Compatibility pulse: keep a periodic metrics_push for older backend nodes.
            if heartbeat_counter % 5 == 0 {
                let metrics_msg = build_message(
                    &agent_id_hb,
                    "metrics_push",
                    metrics.clone(),
                    &key_hb,
                );
                if tx_hb.send(metrics_msg).await.is_err() {
                    break;
                }
            }

            // NOTE: metrics_push is no longer sent separately Ã¢â‚¬â€ metrics are embedded in
            // the heartbeat payload above. This halves the number of messages at 20k scale.

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
                                fwarn!("Duplicate job_id={} Ã¢â‚¬â€ rejecting (idempotence)", job_id);
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
                        // Ã¢â€â‚¬Ã¢â€â‚¬ RD Input: low-latency mouse/keyboard relay (no job system) Ã¢â€â‚¬Ã¢â€â‚¬
                        else if msg_type == "rd_input" {
                            if !verify_sig(&data, &key_loop) {
                                continue; // silently drop invalid input messages
                            }
                            if RD_ACTIVE.load(Ordering::SeqCst) {
                                let payload = &data["payload"];
                                if !rd_session_matches(payload["session_id"].as_str()) {
                                    continue;
                                }
                                let input_type = payload["input_type"].as_str().unwrap_or("");
                                let x = payload["x"].as_f64().unwrap_or(0.0);
                                let y = payload["y"].as_f64().unwrap_or(0.0);
                                let button = payload["button"].as_str().unwrap_or("left");
                                let delta = payload["delta"].as_f64().unwrap_or(0.0);
                                let vk = payload["vk"].as_u64().unwrap_or(0);

                                // Write input command to file for the input handler PS script
                                let cmd = serde_json::json!({
                                    "type": input_type,
                                    "x": x,
                                    "y": y,
                                    "button": button,
                                    "delta": delta,
                                    "vk": vk,
                                });
                                let input_path = rd_input_data_path();
                                // Keep control responsive: if the input queue file grows too much,
                                // drop stale events instead of replaying old pointer movements.
                                if let Ok(meta) = std::fs::metadata(&input_path) {
                                    if meta.len() > 1024 * 1024 {
                                        let _ = std::fs::remove_file(&input_path);
                                    }
                                }
                                // Append to file (multiple events per poll cycle)
                                let line = format!("{}\n", cmd.to_string());
                                let _ = std::fs::OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(&input_path)
                                    .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
                            }
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

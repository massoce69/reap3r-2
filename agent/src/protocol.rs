// ─────────────────────────────────────────────────────────────
// protocol.rs – All message schemas (agent ↔ server)
// Versioned, serde-tagged, anti-replay ready.
// ─────────────────────────────────────────────────────────────
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
//  Server → Agent  messages (received via WS or pull)
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "job")]
    Job(JobAssignment),
    #[serde(rename = "policy_update")]
    PolicyUpdate(PolicyPayload),
    #[serde(rename = "update_available")]
    UpdateAvailable(UpdateNotification),
    #[serde(rename = "ping")]
    Ping { id: String },
    #[serde(rename = "session_start")]
    SessionStart(SessionRequest),
    #[serde(rename = "session_input")]
    SessionInput { session_id: String, data: String },
    #[serde(rename = "session_end")]
    SessionEnd { session_id: String },

    // Remote Desktop input (low-latency mouse/keyboard injection)
    #[serde(rename = "rd_input")]
    RdInput(RdInputPayload),
}

// ═══════════════════════════════════════════════════════════════
//  Agent → Server  messages (sent via WS or HTTP POST)
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentMessage {
    #[serde(rename = "heartbeat")]
    Heartbeat(HeartbeatPayload),
    #[serde(rename = "job_result")]
    JobResult(JobResult),
    #[serde(rename = "metrics")]
    Metrics(MetricsPayload),
    #[serde(rename = "inventory")]
    Inventory(InventoryPayload),
    #[serde(rename = "pong")]
    Pong { id: String },
    #[serde(rename = "session_output")]
    SessionOutput { session_id: String, data: String },
    #[serde(rename = "session_closed")]
    SessionClosed { session_id: String, reason: String },
    #[serde(rename = "log_stream")]
    LogStream(LogStreamPayload),
    #[serde(rename = "enrollment_request")]
    EnrollmentRequest(EnrollmentPayload),
    #[serde(rename = "audit")]
    Audit(AuditEvent),

    // Stream output (stdout/stderr/frame/error) over WS
    #[serde(rename = "stream_output")]
    StreamOutput(StreamOutputPayload),
}

// ═══════════════════════════════════════════════════════════════
//  Heartbeat
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub agent_id: String,
    pub machine_id: String,
    pub hostname: String,
    pub os_info: String,
    pub agent_version: String,
    pub uptime_secs: u64,
    pub timestamp: DateTime<Utc>,
    pub nonce: String,
    pub modules: Vec<ModuleStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub name: String,
    pub version: String,
    pub status: ModuleState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    Running,
    Stopped,
    Error,
    Disabled,
}

// ═══════════════════════════════════════════════════════════════
//  Jobs
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAssignment {
    pub job_id: String,
    pub job_type: JobType,
    pub payload: serde_json::Value,
    pub timeout_secs: u64,
    pub priority: u8,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JobType {
    RunScript,
    DeployPackage,
    CollectInventory,
    CollectMetrics,
    RepairUpdate,
    ApplyUpdate,
    RemoteSessionStart,
    PatchApply,
    WebcamCapture,
    ListCameras,

    // Remote Desktop
    ListMonitors,
    RemoteDesktopStart,
    RemoteDesktopStop,
}

// ═══════════════════════════════════════════════════════════════
//  Remote Desktop
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteDesktopStartPayload {
    pub mode: String,
    pub fps: u32,
    pub quality: u8,
    pub codec: String,
    pub scale: f32,
    pub monitor: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub index: i32,
    pub name: String,
    pub primary: bool,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdInputPayload {
    pub agent_id: String,
    pub session_id: Option<String>,
    pub input_type: String,
    pub x: Option<f32>,
    pub y: Option<f32>,
    pub button: Option<String>,
    pub delta: Option<i32>,
    pub key: Option<String>,
    pub vk: Option<u16>,
    pub monitor: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamOutputPayload {
    pub session_id: String,
    pub stream_type: String,
    pub data: String,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub job_id: String,
    pub agent_id: String,
    pub status: JobStatus,
    pub exit_code: Option<i32>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub artifacts: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Success,
    Failed,
    Timeout,
    Cancelled,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending   => write!(f, "pending"),
            Self::Running   => write!(f, "running"),
            Self::Success   => write!(f, "success"),
            Self::Failed    => write!(f, "failed"),
            Self::Timeout   => write!(f, "timeout"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Script execution
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptPayload {
    pub script_type: ScriptType,
    pub content: String,
    pub args: Vec<String>,
    pub timeout_secs: u64,
    pub run_as: Option<String>,
    pub env: HashMap<String, String>,
    pub stream_output: bool,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScriptType {
    PowerShell,
    Bash,
    Python,
}

// ═══════════════════════════════════════════════════════════════
//  Metrics
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsPayload {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub cpu_usage_percent: f64,
    pub memory_total_mb: u64,
    pub memory_used_mb: u64,
    pub memory_usage_percent: f64,
    pub disks: Vec<DiskMetric>,
    pub uptime_secs: u64,
    pub top_processes: Vec<ProcessInfo>,
    pub network_interfaces: Vec<NetworkInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMetric {
    pub mount_point: String,
    pub total_gb: f64,
    pub used_gb: f64,
    pub usage_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interface: String,
    pub mac_address: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Inventory
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryPayload {
    pub agent_id: String,
    pub timestamp: DateTime<Utc>,
    pub os: OsInfo,
    pub hardware: HardwareInfo,
    pub software: Vec<SoftwareInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub kernel: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub total_ram_mb: u64,
    pub disks: Vec<DiskInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub total_gb: f64,
    pub disk_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareInfo {
    pub name: String,
    pub version: String,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
//  Update / manifest
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateNotification {
    pub version: String,
    pub manifest_url: String,
    pub mandatory: bool,
    pub rollout_percentage: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub min_agent_version: Option<String>,
    pub sha256: String,
    pub signature: String,
    pub download_url: String,
    pub size_bytes: u64,
    pub modules: Vec<ModuleManifestEntry>,
    pub release_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleManifestEntry {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub download_url: String,
}

// ═══════════════════════════════════════════════════════════════
//  Policy
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub version: u64,
    pub policies: Vec<PolicyItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyItem {
    pub key: String,
    pub value: serde_json::Value,
}

// ═══════════════════════════════════════════════════════════════
//  Enrollment
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentPayload {
    pub enrollment_token: String,
    pub machine_id: String,
    pub hostname: String,
    pub os_info: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub agent_id: String,
    pub agent_token: String,
    pub server_public_key: String,
    pub policies: Vec<PolicyItem>,
}

// ═══════════════════════════════════════════════════════════════
//  Log streaming
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStreamPayload {
    pub job_id: String,
    pub stream: String,    // "stdout" | "stderr"
    pub data: String,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
}

// ═══════════════════════════════════════════════════════════════
//  Remote sessions
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    pub session_id: String,
    pub session_type: String,  // "shell"
    pub ttl_secs: u64,
    pub operator_id: String,
}

// ═══════════════════════════════════════════════════════════════
//  Audit
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub agent_id: String,
    pub operator_id: Option<String>,
    pub details: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    JobStarted,
    JobCompleted,
    RemoteSessionStarted,
    RemoteSessionEnded,
    UpdateApplied,
    UpdateRolledBack,
    PolicyApplied,
    AgentEnrolled,
    TamperDetected,
    WebcamCapture,
}

// ═══════════════════════════════════════════════════════════════
//  Signed request wrapper (anti-replay)
// ═══════════════════════════════════════════════════════════════
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub payload: String,     // JSON-encoded inner message
    pub timestamp: i64,      // epoch ms
    pub nonce: String,       // uuid v4
    pub hmac: String,        // hex-encoded HMAC-SHA256
}

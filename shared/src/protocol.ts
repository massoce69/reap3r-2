// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent Protocol V2
// ─────────────────────────────────────────────
import { z } from 'zod';

// ── Protocol envelope ──
export const AgentMessageSchema = z.object({
  agent_id: z.string().uuid(),
  ts: z.number(),
  nonce: z.string().min(16).max(64),
  type: z.string(),
  payload: z.any(),
  hmac: z.string(),
});
export type AgentMessage = z.infer<typeof AgentMessageSchema>;

export const ANTI_REPLAY_WINDOW_MS = 60_000;

// ── Enrollment ──
export const EnrollRequestPayload = z.object({
  hostname: z.string(),
  os: z.enum(['windows', 'linux', 'macos']),
  os_version: z.string(),
  arch: z.string(),
  agent_version: z.string(),
  enrollment_token: z.string(),
  machine_id: z.string().optional(),
  company_id: z.string().uuid().optional(),
  folder_id: z.string().uuid().optional(),
});
export type EnrollRequest = z.infer<typeof EnrollRequestPayload>;

export const EnrollResponsePayload = z.object({
  agent_id: z.string().uuid(),
  org_id: z.string().uuid(),
  hmac_key: z.string(),
  server_url: z.string().url(),
  heartbeat_interval_sec: z.number(),
});
export type EnrollResponse = z.infer<typeof EnrollResponsePayload>;

// ── Heartbeat ──
export const HeartbeatPayload = z.object({
  uptime_sec: z.number(),
  cpu_percent: z.number().min(0).max(100).optional(),
  memory_percent: z.number().min(0).max(100).optional(),
  disk_percent: z.number().min(0).max(100).optional(),
  ip_addresses: z.array(z.string()).optional(),
  agent_version: z.string().optional(),
  pending_reboot: z.boolean().optional(),
});
export type Heartbeat = z.infer<typeof HeartbeatPayload>;

// ── Capabilities ──
export const CapabilitiesPayload = z.object({
  modules: z.array(z.string()),
  os_features: z.array(z.string()).optional(),
  max_concurrent_jobs: z.number().int().optional(),
  supported_interpreters: z.array(z.string()).optional(),
});
export type Capabilities = z.infer<typeof CapabilitiesPayload>;

// ── Metrics push ──
export const MetricsPushPayload = z.object({
  ts: z.number(),
  cpu_percent: z.number(),
  memory_total_bytes: z.number(),
  memory_used_bytes: z.number(),
  disk_total_bytes: z.number(),
  disk_used_bytes: z.number(),
  net_rx_bytes: z.number().optional(),
  net_tx_bytes: z.number().optional(),
  process_count: z.number().optional(),
  load_avg_1m: z.number().optional(),
  load_avg_5m: z.number().optional(),
  load_avg_15m: z.number().optional(),
});
export type MetricsPush = z.infer<typeof MetricsPushPayload>;

// ── Inventory push ──
export const InventoryPushPayload = z.object({
  hostname: z.string(),
  os: z.string(),
  os_version: z.string(),
  arch: z.string(),
  cpu_model: z.string().optional(),
  cpu_cores: z.number().optional(),
  memory_total_bytes: z.number().optional(),
  disk_total_bytes: z.number().optional(),
  network_interfaces: z.array(z.object({
    name: z.string(),
    mac: z.string().optional(),
    ips: z.array(z.string()),
  })).optional(),
  installed_software: z.array(z.object({
    name: z.string(),
    version: z.string().optional(),
  })).optional(),
  services: z.array(z.object({
    name: z.string(),
    status: z.string(),
    start_type: z.string().optional(),
  })).optional(),
});
export type InventoryPush = z.infer<typeof InventoryPushPayload>;

// ── Security event push (EDR) ──
export const SecurityEventPayload = z.object({
  event_type: z.enum([
    'process_start', 'process_stop',
    'service_created', 'service_modified',
    'persistence_indicator',
    'suspicious_powershell', 'suspicious_path',
    'outbound_connection',
    'tamper_detected',
    'file_modified', 'registry_modified',
  ]),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  timestamp: z.number(),
  details: z.record(z.unknown()),
  process_name: z.string().optional(),
  process_path: z.string().optional(),
  pid: z.number().optional(),
  parent_pid: z.number().optional(),
  cmdline: z.string().optional(),
  user: z.string().optional(),
  sha256: z.string().optional(),
  dest_ip: z.string().optional(),
  dest_port: z.number().optional(),
  dest_domain: z.string().optional(),
});
export type SecurityEvent = z.infer<typeof SecurityEventPayload>;

// ── Stream output (remote shell / desktop) ──
export const StreamOutputPayload = z.object({
  session_id: z.string(),
  stream_type: z.enum(['stdout', 'stderr', 'frame', 'input']),
  data: z.string(), // base64 for binary
  sequence: z.number().int(),
});
export type StreamOutput = z.infer<typeof StreamOutputPayload>;

// ── Job ack ──
export const JobAckPayload = z.object({
  job_id: z.string().uuid(),
  status: z.enum(['running', 'rejected']),
  reason: z.string().optional(),
});

// ── Job result ──
export const JobResultPayload = z.object({
  job_id: z.string().uuid(),
  status: z.enum(['success', 'failed', 'timeout']),
  exit_code: z.number().optional(),
  stdout: z.string().optional(),
  stderr: z.string().optional(),
  artifacts: z.array(z.object({
    name: z.string(),
    size: z.number(),
    sha256: z.string(),
  })).optional(),
  error: z.string().optional(),
  duration_ms: z.number().optional(),
});
export type JobResult = z.infer<typeof JobResultPayload>;

// ── Message types ──
export const MessageType = {
  EnrollRequest: 'enroll_request',
  EnrollResponse: 'enroll_response',
  Heartbeat: 'heartbeat',
  Capabilities: 'capabilities',
  MetricsPush: 'metrics_push',
  InventoryPush: 'inventory_push',
  SecurityEventPush: 'security_event_push',
  JobAssign: 'job_assign',
  JobAck: 'job_ack',
  JobResult: 'job_result',
  StreamOutput: 'stream_output',
} as const;

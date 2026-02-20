// ------------------------------------------------------------
// MASSVISION Reap3r — Agent Protocol v1 (Source of Truth)
// ------------------------------------------------------------
//
// Design goals (P0):
// - One envelope for all WS messages (agent <-> backend).
// - One set of message type strings (MessageType).
// - HMAC signature is deterministic cross-language:
//   sig = HMAC_SHA256(hmac_key, canonical_json(envelope_without_sig))
// - Enrollment is the only unsigned message (agent doesn't have hmac_key yet).
//
import { z } from 'zod';

export const ANTI_REPLAY_WINDOW_MS = 60_000;

// ------------------------------------------------------------
// Message types (exact strings)
// ------------------------------------------------------------
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
  RdInput: 'rd_input',
} as const;
export type MessageTypeValue = (typeof MessageType)[keyof typeof MessageType];

// ------------------------------------------------------------
// Envelope
// ------------------------------------------------------------
export const MessageEnvelopeSchema = z.object({
  type: z.enum([
    MessageType.EnrollRequest,
    MessageType.EnrollResponse,
    MessageType.Heartbeat,
    MessageType.Capabilities,
    MessageType.MetricsPush,
    MessageType.InventoryPush,
    MessageType.SecurityEventPush,
    MessageType.JobAssign,
    MessageType.JobAck,
    MessageType.JobResult,
    MessageType.StreamOutput,
    MessageType.RdInput,
  ]),

  // Always milliseconds since epoch.
  ts: z.number().int().nonnegative(),

  // Anti-replay nonce. Use UUIDv4 string (preferred).
  nonce: z.string().min(16).max(64),

  // Correlation id for logs/audit across agent/backend/UI.
  traceId: z.string().uuid(),

  // "0000..." during enroll_request.
  agentId: z.string().uuid(),

  // Filled by backend in enroll_response (and optionally included afterwards).
  orgId: z.string().uuid().optional(),

  payload: z.unknown(),

  // Hex HMAC SHA256 signature. Required for all messages except enroll_request.
  sig: z.string().regex(/^[0-9a-f]{64}$/i).optional(),
});
export type MessageEnvelope = z.infer<typeof MessageEnvelopeSchema>;

// ------------------------------------------------------------
// Payload schemas
// ------------------------------------------------------------
export const EnrollRequestPayload = z.object({
  hostname: z.string().min(1).max(255),
  os: z.enum(['windows', 'linux', 'macos']),
  os_version: z.string().min(1).max(255),
  arch: z.string().min(1).max(64),
  agent_version: z.string().min(1).max(64),
  enrollment_token: z.string().min(8).max(256),
  machine_id: z.string().optional(),
  company_id: z.string().uuid().optional(),
  folder_id: z.string().uuid().optional(),
});
export type EnrollRequest = z.infer<typeof EnrollRequestPayload>;

export const EnrollResponsePayload = z.object({
  success: z.boolean(),
  agent_id: z.string().uuid().optional(),
  org_id: z.string().uuid().optional(),
  hmac_key: z.string().min(8),
  server_url: z.string().min(1),
  heartbeat_interval_sec: z.number().int().min(5).max(3600),
  error: z.string().optional(),
});
export type EnrollResponse = z.infer<typeof EnrollResponsePayload>;

// Heartbeat (cheap "liveness" message).
export const HeartbeatPayload = z.object({
  uptime_sec: z.number().int().nonnegative(),
  cpu_percent: z.number().int().min(0).max(100).optional(),
  memory_percent: z.number().int().min(0).max(100),
  disk_percent: z.number().int().min(0).max(100),
  // Agent v5 embeds full metrics here to reduce WS message count.
  metrics: z.record(z.unknown()).optional(),
});
export type Heartbeat = z.infer<typeof HeartbeatPayload>;

export const CapabilitiesPayload = z.object({
  capabilities: z.array(z.string()).min(1),
  modules_version: z.record(z.string()).optional(),
  max_concurrent_jobs: z.number().int().min(1).max(64).optional(),
});
export type Capabilities = z.infer<typeof CapabilitiesPayload>;

export const MetricsPushPayload = z.object({
  ts: z.number().int().nonnegative(),
  cpu_percent: z.number().int().min(0).max(100),
  memory_total_bytes: z.number().int().nonnegative(),
  memory_used_bytes: z.number().int().nonnegative(),
  disk_total_bytes: z.number().int().nonnegative(),
  disk_used_bytes: z.number().int().nonnegative(),
  net_rx_bytes: z.number().int().nonnegative().optional(),
  net_tx_bytes: z.number().int().nonnegative().optional(),
  process_count: z.number().int().nonnegative().optional(),
});
export type MetricsPush = z.infer<typeof MetricsPushPayload>;

export const InventoryPushPayload = z.object({
  collected_at: z.number().int().nonnegative().optional(),
  hostname: z.string().min(1),
  os: z.string().min(1),
  os_version: z.string().min(1),
  arch: z.string().min(1),
  cpu_model: z.string().optional(),
  cpu_cores: z.number().int().optional(),
  memory_total_bytes: z.number().int().optional(),
  disk_total_bytes: z.number().int().optional(),
  disk_used_bytes: z.number().int().optional(),
  network_interfaces: z.array(z.object({
    name: z.string(),
    mac: z.string().optional(),
    rx_bytes: z.number().int().optional(),
    tx_bytes: z.number().int().optional(),
    ips: z.array(z.string()).optional(),
  })).optional(),
  process_count: z.number().int().optional(),
  top_processes: z.array(z.object({
    pid: z.number().int(),
    name: z.string(),
    cpu_percent: z.number().optional(),
    memory_bytes: z.number().int().optional(),
    user: z.string().optional(),
  })).optional(),
}).passthrough();
export type InventoryPush = z.infer<typeof InventoryPushPayload>;

export const JobAssignPayload = z.object({
  job_id: z.string().uuid(),
  name: z.string().min(1).max(128),
  args: z.unknown(),
  timeout_sec: z.number().int().min(5).max(86400),
  created_at: z.string(),
});
export type JobAssign = z.infer<typeof JobAssignPayload>;

export const JobAckPayload = z.object({
  job_id: z.string().uuid(),
  status: z.enum(['running', 'rejected']),
  reason: z.string().optional(),
});
export type JobAck = z.infer<typeof JobAckPayload>;

export const JobResultPayload = z.object({
  job_id: z.string().uuid(),
  status: z.enum(['success', 'failed', 'timeout']),
  exit_code: z.number().int().optional(),
  stdout: z.string().optional(),
  stderr: z.string().optional(),
  duration_ms: z.number().int().optional(),
  error: z.string().optional(),
});
export type JobResult = z.infer<typeof JobResultPayload>;

export const SecurityEventPayload = z.object({
  event_type: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  timestamp: z.number().int().nonnegative(),
  details: z.record(z.unknown()),
  process_name: z.string().optional(),
  process_path: z.string().optional(),
  pid: z.number().int().optional(),
  parent_pid: z.number().int().optional(),
  cmdline: z.string().optional(),
  user: z.string().optional(),
  sha256: z.string().optional(),
  dest_ip: z.string().optional(),
  dest_port: z.number().int().optional(),
  dest_domain: z.string().optional(),
});
export type SecurityEvent = z.infer<typeof SecurityEventPayload>;

export const StreamOutputPayload = z.object({
  session_id: z.string(),
  stream_type: z.enum(['stdout', 'stderr', 'frame', 'input', 'error']),
  data: z.string(),
  sequence: z.number().int(),
});
export type StreamOutput = z.infer<typeof StreamOutputPayload>;

// RD Input — low-latency remote desktop input events (mouse/keyboard)
export const RdInputPayload = z.object({
  agent_id: z.string().uuid(),
  input_type: z.enum(['mouse_move', 'mouse_down', 'mouse_up', 'mouse_wheel', 'key_down', 'key_up']),
  // Normalized coordinates 0.0–1.0 (relative to captured screen area)
  x: z.number().min(0).max(1).optional(),
  y: z.number().min(0).max(1).optional(),
  // Mouse button: 'left', 'right', 'middle'
  button: z.enum(['left', 'right', 'middle']).optional(),
  // Wheel delta (positive=up, negative=down)
  delta: z.number().optional(),
  // Key code (DOM KeyboardEvent.code) and virtual key code
  key: z.string().optional(),
  vk: z.number().int().optional(),
  // Monitor index being viewed (-1 = all)
  monitor: z.number().int().min(-1).max(15).default(-1),
});
export type RdInput = z.infer<typeof RdInputPayload>;

// ------------------------------------------------------------
// Canonical JSON encoding for signature (TS side)
// ------------------------------------------------------------
export function canonicalizeJson(value: any): any {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(canonicalizeJson);
  if (typeof value !== 'object') return value;
  const out: Record<string, any> = {};
  for (const k of Object.keys(value).sort()) {
    out[k] = canonicalizeJson(value[k]);
  }
  return out;
}

export function canonicalJsonStringify(value: any): string {
  return JSON.stringify(canonicalizeJson(value));
}

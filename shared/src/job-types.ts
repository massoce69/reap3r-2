// ─────────────────────────────────────────────
// MASSVISION Reap3r — Job Types & Payloads
// ─────────────────────────────────────────────
import { z } from 'zod';

export enum JobType {
  RunScript = 'run_script',
  ServiceAction = 'service_action',
  ProcessAction = 'process_action',
  Reboot = 'reboot',
  Shutdown = 'shutdown',
  RemoteShellStart = 'remote_shell_start',
  RemoteShellStop = 'remote_shell_stop',
  RemoteDesktopStart = 'remote_desktop_start',
  RemoteDesktopStop = 'remote_desktop_stop',
  RemoteDesktopPrivacyModeSet = 'remote_desktop_privacy_mode_set',
  RemoteDesktopInputLockSet = 'remote_desktop_input_lock_set',
  WakeOnLan = 'wake_on_lan',
  UpdateAgent = 'update_agent',
  CollectInventory = 'collect_inventory',
  CollectMetrics = 'collect_metrics',
  // EDR Response
  EdrKillProcess = 'edr_kill_process',
  EdrQuarantineFile = 'edr_quarantine_file',
  EdrIsolateMachine = 'edr_isolate_machine',
  EdrCollectBundle = 'edr_collect_bundle',
  ListMonitors = 'list_monitors',
  // Artifacts
  UploadArtifact = 'upload_artifact',
  DownloadArtifact = 'download_artifact',
}

export enum JobStatus {
  Queued = 'queued',
  Assigned = 'assigned',
  Running = 'running',
  Success = 'success',
  Failed = 'failed',
  Timeout = 'timeout',
  Cancelled = 'cancelled',
}

// ── Payload Schemas ──

export const RunScriptPayload = z.object({
  interpreter: z.enum(['powershell', 'bash', 'python', 'cmd']),
  script: z.string().min(1).max(100_000),
  timeout_sec: z.number().int().min(5).max(3600).default(300),
  run_as: z.string().optional(),
  env: z.record(z.string()).optional(),
  secret_ids: z.array(z.string().uuid()).optional(),
});

export const ServiceActionPayload = z.object({
  service_name: z.string().min(1),
  action: z.enum(['start', 'stop', 'restart', 'status']),
});

export const ProcessActionPayload = z.object({
  action: z.enum(['kill', 'list']),
  pid: z.number().int().optional(),
  name: z.string().optional(),
});

export const RebootPayload = z.object({
  delay_sec: z.number().int().min(0).max(3600).default(0),
  reason: z.string().optional(),
});

export const ShutdownPayload = z.object({
  delay_sec: z.number().int().min(0).max(3600).default(0),
  reason: z.string().optional(),
});

export const RemoteShellStartPayload = z.object({
  shell: z.enum(['powershell', 'bash', 'cmd', 'sh']).optional(),
  cols: z.number().int().optional(),
  rows: z.number().int().optional(),
});

export const RemoteDesktopStartPayload = z.object({
  mode: z.enum(['view', 'control']),
  fps: z.number().int().min(1).max(60).default(15),
  quality: z.number().int().min(10).max(100).default(60),
  scale: z.number().min(0.1).max(1.0).default(0.5),
  codec: z.enum(['jpeg', 'png', 'webp']).default('jpeg'),
  monitor: z.number().int().min(-1).max(15).default(-1).describe('-1 = all monitors, 0-N = specific monitor index'),
});

export const ListMonitorsPayload = z.object({});

export const PrivacyModeSetPayload = z.object({
  enabled: z.boolean(),
  auto_restore_on_end: z.boolean().default(true),
});

export const InputLockSetPayload = z.object({
  enabled: z.boolean(),
  lock: z.array(z.enum(['keyboard', 'mouse'])).min(1),
  ttl_sec: z.number().int().min(0).max(28800).default(3600),
  auto_restore_on_end: z.boolean().default(true),
});

export const WakeOnLanPayload = z.object({
  target_mac: z.string().regex(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/),
  relay_agent_id: z.string().uuid(),
  target_agent_id: z.string().uuid().optional(),
});

export const UpdateAgentPayload = z.object({
  version: z.string(),
  download_url: z.string().url(),
  sha256: z.string().length(64),
  sig_ed25519: z.string().min(64),
  signer_thumbprint: z.string().min(40).max(64).optional(),
  require_authenticode: z.boolean().optional(),
  force: z.boolean().default(false),
});

export const EdrKillProcessPayload = z.object({
  pid: z.number().int(),
  reason: z.string().min(1),
});

export const EdrQuarantineFilePayload = z.object({
  path: z.string().min(1),
  sha256: z.string().length(64).optional(),
  reason: z.string().min(1),
});

export const EdrIsolateMachinePayload = z.object({
  mode: z.enum(['strict', 'soft']),
  reason: z.string().min(1),
  allowed_endpoints: z.array(z.string()).optional(),
});

export const EdrCollectBundlePayload = z.object({
  targets: z.array(z.enum(['logs', 'processes', 'network', 'files', 'registry'])).min(1),
  reason: z.string().optional(),
});

export const CollectInventoryPayload = z.object({}).optional();
export const CollectMetricsPayload = z.object({}).optional();

export const EmptyPayload = z.object({});

export const JobPayloadSchemas: Record<JobType, z.ZodTypeAny> = {
  [JobType.RunScript]: RunScriptPayload,
  [JobType.ServiceAction]: ServiceActionPayload,
  [JobType.ProcessAction]: ProcessActionPayload,
  [JobType.Reboot]: RebootPayload,
  [JobType.Shutdown]: ShutdownPayload,
  [JobType.RemoteShellStart]: RemoteShellStartPayload,
  [JobType.RemoteShellStop]: EmptyPayload,
  [JobType.RemoteDesktopStart]: RemoteDesktopStartPayload,
  [JobType.RemoteDesktopStop]: EmptyPayload,
  [JobType.RemoteDesktopPrivacyModeSet]: PrivacyModeSetPayload,
  [JobType.RemoteDesktopInputLockSet]: InputLockSetPayload,
  [JobType.WakeOnLan]: WakeOnLanPayload,
  [JobType.UpdateAgent]: UpdateAgentPayload,
  [JobType.ListMonitors]: ListMonitorsPayload,
  [JobType.CollectInventory]: EmptyPayload,
  [JobType.CollectMetrics]: EmptyPayload,
  [JobType.EdrKillProcess]: EdrKillProcessPayload,
  [JobType.EdrQuarantineFile]: EdrQuarantineFilePayload,
  [JobType.EdrIsolateMachine]: EdrIsolateMachinePayload,
  [JobType.EdrCollectBundle]: EdrCollectBundlePayload,
  [JobType.UploadArtifact]: EmptyPayload,
  [JobType.DownloadArtifact]: EmptyPayload,
};

// Permission required per job type
export const JobTypePermission: Record<JobType, string> = {
  [JobType.RunScript]: 'job:run_script',
  [JobType.ServiceAction]: 'job:create',
  [JobType.ProcessAction]: 'job:create',
  [JobType.Reboot]: 'job:reboot',
  [JobType.Shutdown]: 'job:shutdown',
  [JobType.RemoteShellStart]: 'remote:shell',
  [JobType.RemoteShellStop]: 'remote:shell',
  [JobType.RemoteDesktopStart]: 'remote:desktop',
  [JobType.RemoteDesktopStop]: 'remote:desktop',
  [JobType.RemoteDesktopPrivacyModeSet]: 'remote:privacy_mode',
  [JobType.RemoteDesktopInputLockSet]: 'remote:input_lock',
  [JobType.WakeOnLan]: 'remote:wake_on_lan',
  [JobType.UpdateAgent]: 'agent:update',
  [JobType.ListMonitors]: 'remote:desktop',
  [JobType.CollectInventory]: 'agent:view',
  [JobType.CollectMetrics]: 'agent:view',
  [JobType.EdrKillProcess]: 'edr:respond',
  [JobType.EdrQuarantineFile]: 'edr:respond',
  [JobType.EdrIsolateMachine]: 'edr:respond',
  [JobType.EdrCollectBundle]: 'edr:respond',
  [JobType.UploadArtifact]: 'artifact:upload',
  [JobType.DownloadArtifact]: 'artifact:download',
};

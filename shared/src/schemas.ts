// ─────────────────────────────────────────────
// MASSVISION Reap3r — API Schemas (Zod DTOs)
// ─────────────────────────────────────────────
import { z } from 'zod';

// ── Pagination ──
export const PaginationQuery = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(200).default(25),
  sort_by: z.string().optional(),
  sort_order: z.enum(['asc', 'desc']).default('desc'),
});

export const PaginatedResponse = <T extends z.ZodTypeAny>(item: T) =>
  z.object({
    data: z.array(item),
    total: z.number(),
    page: z.number(),
    limit: z.number(),
  });

// ── Auth ──
export const LoginRequestSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export const LoginResponseSchema = z.object({
  token: z.string(),
  user: z.object({
    id: z.string().uuid(),
    email: z.string(),
    name: z.string(),
    role: z.string(),
    org_id: z.string().uuid(),
  }),
});

// ── User ──
export const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2).max(100),
  password: z.string().min(8).max(128),
  role: z.string(),
  team_ids: z.array(z.string().uuid()).optional(),
});

export const UpdateUserSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  role: z.string().optional(),
  is_active: z.boolean().optional(),
  team_ids: z.array(z.string().uuid()).optional(),
});

export const UserSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  email: z.string(),
  name: z.string(),
  role: z.string(),
  is_active: z.boolean(),
  mfa_enabled: z.boolean(),
  last_login_at: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

// ── Team ──
export const CreateTeamSchema = z.object({
  name: z.string().min(2).max(100),
  description: z.string().max(500).optional(),
});

export const TeamSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  name: z.string(),
  description: z.string().nullable(),
  member_count: z.number().optional(),
  created_at: z.string(),
});

// ── Company ──
export const CreateCompanySchema = z.object({
  name: z.string().min(1).max(200),
  notes: z.string().max(2000).optional(),
  contact_email: z.string().email().optional(),
  contact_phone: z.string().max(50).optional(),
});

export const UpdateCompanySchema = z.object({
  name: z.string().min(1).max(200).optional(),
  notes: z.string().max(2000).optional(),
  contact_email: z.string().email().optional(),
  contact_phone: z.string().max(50).optional(),
});

export const CompanySchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  name: z.string(),
  notes: z.string().nullable(),
  contact_email: z.string().nullable(),
  contact_phone: z.string().nullable(),
  agent_count: z.number().optional(),
  online_count: z.number().optional(),
  created_at: z.string(),
});

// ── Folder ──
export const CreateFolderSchema = z.object({
  name: z.string().min(1).max(200),
  company_id: z.string().uuid().nullable().optional(),
  parent_folder_id: z.string().uuid().nullable().optional(),
});

export const UpdateFolderSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  company_id: z.string().uuid().nullable().optional(),
  parent_folder_id: z.string().uuid().nullable().optional(),
});

export const FolderSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  name: z.string(),
  company_id: z.string().uuid().nullable(),
  parent_folder_id: z.string().uuid().nullable(),
  agent_count: z.number().optional(),
  created_at: z.string(),
});

// ── Agent ──
export const AgentSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  hostname: z.string(),
  os: z.string(),
  os_version: z.string(),
  arch: z.string(),
  agent_version: z.string(),
  status: z.enum(['online', 'offline', 'degraded', 'isolated']),
  last_seen_at: z.string().nullable(),
  ip_address: z.string().nullable(),
  company_id: z.string().uuid().nullable(),
  company_name: z.string().nullable().optional(),
  folder_ids: z.array(z.string().uuid()).optional(),
  tags: z.array(z.string()).optional(),
  site_id: z.string().uuid().nullable(),
  created_at: z.string(),
});

export const MoveAgentSchema = z.object({
  company_id: z.string().uuid().nullable().optional(),
  folder_ids: z.array(z.string().uuid()).optional(),
});

// ── Job ──
export const CreateJobSchema = z.object({
  agent_id: z.string().uuid(),
  job_type: z.string(),
  payload: z.any(),
  reason: z.string().max(500).optional(),
  priority: z.number().int().min(0).max(10).default(5),
  timeout_sec: z.number().int().min(5).max(86400).optional(),
});

export const JobSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  agent_id: z.string().uuid(),
  created_by: z.string().uuid(),
  job_type: z.string(),
  status: z.string(),
  payload: z.any(),
  priority: z.number(),
  reason: z.string().nullable(),
  assigned_at: z.string().nullable(),
  completed_at: z.string().nullable(),
  dispatch_count: z.number().int().default(0),
  timeout_sec: z.number(),
  created_at: z.string(),
});

// ── Enrollment Token ──
export const CreateEnrollmentTokenSchema = z.object({
  name: z.string().min(1).max(100),
  site_id: z.string().uuid().optional(),
  company_id: z.string().uuid().optional(),
  folder_id: z.string().uuid().optional(),
  expires_at: z.string().optional(),
  max_uses: z.number().int().min(1).max(10000).optional(),
});

export const EnrollmentTokenSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  token: z.string(),
  name: z.string(),
  site_id: z.string().uuid().nullable(),
  company_id: z.string().uuid().nullable(),
  folder_id: z.string().uuid().nullable(),
  is_active: z.boolean(),
  uses: z.number(),
  max_uses: z.number().nullable(),
  expires_at: z.string().nullable(),
  created_at: z.string(),
});

// ── Audit ──
export const AuditLogSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  user_id: z.string().uuid().nullable(),
  agent_id: z.string().uuid().nullable(),
  action: z.string(),
  resource_type: z.string(),
  resource_id: z.string().nullable(),
  details: z.any(),
  ip_address: z.string().nullable(),
  created_at: z.string(),
});

// ── Vault / Secrets ──
export const CreateSecretSchema = z.object({
  name: z.string().min(1).max(200),
  type: z.enum(['password', 'token', 'api_key', 'ssh_key', 'certificate', 'note', 'other']),
  value: z.string().min(1).max(100_000),
  company_id: z.string().uuid().nullable().optional(),
  folder_id: z.string().uuid().nullable().optional(),
  tags: z.array(z.string()).optional(),
  notes: z.string().max(5000).optional(),
  expires_at: z.string().optional(),
  metadata: z.record(z.string()).optional(),
});

export const UpdateSecretSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  value: z.string().min(1).max(100_000).optional(),
  tags: z.array(z.string()).optional(),
  notes: z.string().max(5000).optional(),
  expires_at: z.string().nullable().optional(),
  metadata: z.record(z.string()).optional(),
});

export const SecretSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  name: z.string(),
  type: z.string(),
  company_id: z.string().uuid().nullable(),
  folder_id: z.string().uuid().nullable(),
  tags: z.array(z.string()),
  notes: z.string().nullable(),
  expires_at: z.string().nullable(),
  metadata: z.any(),
  created_by: z.string().uuid(),
  created_at: z.string(),
  updated_at: z.string(),
});

// ── Messaging ──
export const CreateChannelSchema = z.object({
  name: z.string().min(1).max(100),
  type: z.enum(['dm', 'team', 'company', 'folder', 'general']),
  member_ids: z.array(z.string().uuid()).optional(),
  company_id: z.string().uuid().optional(),
});

export const ChannelSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  name: z.string(),
  type: z.string(),
  member_count: z.number().optional(),
  last_message_at: z.string().nullable(),
  created_at: z.string(),
});

export const CreateMessageSchema = z.object({
  body: z.string().min(1).max(10_000),
});

export const MessageSchema = z.object({
  id: z.string().uuid(),
  channel_id: z.string().uuid(),
  user_id: z.string().uuid(),
  user_name: z.string().optional(),
  body: z.string(),
  created_at: z.string(),
});

// ── EDR ──
export const SecurityEventSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  agent_id: z.string().uuid(),
  event_type: z.string(),
  severity: z.string(),
  details: z.any(),
  process_name: z.string().nullable(),
  cmdline: z.string().nullable(),
  sha256: z.string().nullable(),
  created_at: z.string(),
});

export const DetectionSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  agent_id: z.string().uuid(),
  event_id: z.string().uuid(),
  rule_id: z.string(),
  rule_name: z.string(),
  severity: z.string(),
  score: z.number(),
  status: z.enum(['open', 'acknowledged', 'resolved', 'false_positive', 'monitoring']),
  details: z.any(),
  created_at: z.string(),
  // Enriched fields from join
  agent_hostname: z.string().optional(),
  event_cmdline: z.string().nullable().optional(),
  event_process_name: z.string().nullable().optional(),
  event_process_path: z.string().nullable().optional(),
  event_pid: z.number().nullable().optional(),
  event_parent_pid: z.number().nullable().optional(),
  event_username: z.string().nullable().optional(),
  event_sha256: z.string().nullable().optional(),
});

export const IncidentSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  title: z.string(),
  severity: z.string(),
  status: z.enum(['open', 'investigating', 'contained', 'resolved', 'closed']),
  assigned_to: z.string().uuid().nullable(),
  detection_count: z.number().optional(),
  risk_score: z.number().optional(),
  agent_id: z.string().uuid().nullable().optional(),
  agent_hostname: z.string().nullable().optional(),
  auto_created: z.boolean().optional(),
  mitre_tactics: z.array(z.string()).nullable().optional(),
  mitre_techniques: z.array(z.string()).nullable().optional(),
  notes: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
  closed_at: z.string().nullable().optional(),
});

export const CreateIncidentSchema = z.object({
  title: z.string().min(1).max(200),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  detection_ids: z.array(z.string().uuid()).min(1),
  assigned_to: z.string().uuid().optional(),
  notes: z.string().max(5000).optional(),
});

export const EdrRespondSchema = z.object({
  agent_id: z.string().uuid(),
  action: z.enum(['edr_kill_process', 'edr_quarantine_file', 'edr_isolate_machine', 'edr_collect_bundle']),
  payload: z.any(),
  reason: z.string().min(1).max(500),
});

export const EdrRuleSchema = z.object({
  id: z.string().uuid(),
  rule_id: z.string(),
  name: z.string(),
  description: z.string().nullable(),
  severity: z.string(),
  logic: z.any(),
  is_active: z.boolean(),
  is_builtin: z.boolean(),
  org_id: z.string().uuid().nullable(),
  mitre_tactic: z.string().nullable().optional(),
  mitre_technique: z.string().nullable().optional(),
  event_types: z.array(z.string()).optional(),
  tags: z.array(z.string()).optional(),
  dedup_window_sec: z.number().optional(),
  threshold_count: z.number().optional(),
  threshold_window_sec: z.number().optional(),
  monitor_only: z.boolean().optional(),
  created_at: z.string(),
});

export const EdrRuleExceptionSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  rule_id: z.string(),
  scope: z.enum(['org', 'site', 'device']),
  scope_id: z.string().uuid().nullable(),
  field: z.string(),
  pattern: z.string(),
  is_regex: z.boolean(),
  reason: z.string().nullable(),
  created_at: z.string(),
  expires_at: z.string().nullable(),
});

export const IncidentTimelineEntrySchema = z.object({
  id: z.string().uuid(),
  incident_id: z.string().uuid(),
  entry_type: z.string(),
  ref_id: z.string().uuid().nullable(),
  summary: z.string(),
  actor: z.string().uuid().nullable(),
  actor_name: z.string().nullable().optional(),
  metadata: z.any(),
  ts: z.string(),
});

export const DeviceIsolationSchema = z.object({
  agent_id: z.string().uuid(),
  org_id: z.string().uuid(),
  is_isolated: z.boolean(),
  isolated_at: z.string().nullable(),
  isolated_by: z.string().uuid().nullable(),
  reason: z.string().nullable(),
  released_at: z.string().nullable(),
});

export const QuarantineEntrySchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  agent_id: z.string().uuid(),
  original_path: z.string(),
  sha256: z.string(),
  file_size: z.number().nullable(),
  reason: z.string().nullable(),
  status: z.string(),
  quarantined_at: z.string(),
  agent_hostname: z.string().nullable().optional(),
});

// ── Policy ──
export const PolicySchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  name: z.string(),
  category: z.string(),
  settings: z.any(),
  is_active: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});

export const UpdatePolicySchema = z.object({
  settings: z.any(),
  is_active: z.boolean().optional(),
});

// ── Alerting ──
export const CreateAlertRuleSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  rule_type: z.enum(['agent_offline', 'job_failed', 'edr_critical', 'metric_threshold', 'tamper_detected', 'custom']),
  scope_type: z.enum(['all', 'company', 'folder', 'tag']).default('all'),
  scope_value: z.string().max(500).optional(),
  params: z.record(z.any()).default({}),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).default('high'),
  cooldown_sec: z.number().int().min(0).max(86400).default(300),
  is_enabled: z.boolean().default(true),
  escalations: z.array(z.object({
    step: z.number().int().min(1).max(10),
    delay_sec: z.number().int().min(0).max(86400).default(0),
    target_type: z.enum(['user', 'team', 'role']),
    target_id: z.string().uuid().optional(),
    target_role: z.string().max(50).optional(),
    channels: z.array(z.enum(['email', 'teams', 'pagerduty', 'opsgenie', 'webhook'])).min(1).default(['email']),
  })).optional(),
});

export const UpdateAlertRuleSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  description: z.string().max(2000).optional(),
  params: z.record(z.any()).optional(),
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  cooldown_sec: z.number().int().min(0).max(86400).optional(),
  is_enabled: z.boolean().optional(),
  scope_type: z.enum(['all', 'company', 'folder', 'tag']).optional(),
  scope_value: z.string().max(500).optional(),
  escalations: z.array(z.object({
    step: z.number().int().min(1).max(10),
    delay_sec: z.number().int().min(0).max(86400).default(0),
    target_type: z.enum(['user', 'team', 'role']),
    target_id: z.string().uuid().optional(),
    target_role: z.string().max(50).optional(),
    channels: z.array(z.enum(['email', 'teams', 'pagerduty', 'opsgenie', 'webhook'])).min(1).default(['email']),
  })).optional(),
});

export const AlertRuleSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  name: z.string(),
  description: z.string().nullable(),
  rule_type: z.string(),
  scope_type: z.string(),
  scope_value: z.string().nullable(),
  params: z.any(),
  severity: z.string(),
  cooldown_sec: z.number(),
  is_enabled: z.boolean(),
  created_by: z.string().uuid().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
  escalations: z.array(z.object({
    id: z.string().uuid(),
    step: z.number(),
    delay_sec: z.number(),
    target_type: z.string(),
    target_id: z.string().uuid().nullable(),
    target_role: z.string().nullable(),
    channels: z.array(z.string()),
  })).optional(),
});

export const AlertEventSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  rule_id: z.string().uuid().nullable(),
  rule_name: z.string().nullable(),
  entity_type: z.string(),
  entity_id: z.string().uuid().nullable(),
  fingerprint: z.string(),
  severity: z.string(),
  status: z.enum(['open', 'acknowledged', 'resolved', 'snoozed']),
  title: z.string(),
  details: z.any(),
  snoozed_until: z.string().nullable(),
  escalation_step: z.number(),
  resolved_at: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});

export const AlertAckSchema = z.object({
  event_id: z.string().uuid(),
  note: z.string().max(2000).optional(),
});

export const AlertSnoozeSchema = z.object({
  event_id: z.string().uuid(),
  duration_min: z.number().int().min(1).max(10080),
  note: z.string().max(2000).optional(),
});

export const AlertIntegrationSchema = z.object({
  id: z.string().uuid(),
  org_id: z.string().uuid(),
  type: z.string(),
  name: z.string(),
  config: z.any(),
  is_enabled: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});

export const CreateAlertIntegrationSchema = z.object({
  type: z.enum(['email', 'teams', 'pagerduty', 'opsgenie', 'webhook']),
  name: z.string().min(1).max(200),
  config: z.record(z.any()),
  is_enabled: z.boolean().default(true),
});

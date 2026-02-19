// ─────────────────────────────────────────────
// MASSVISION Reap3r — Deploy Types & Schemas
// Zabbix DAT batch deployment system
// ─────────────────────────────────────────────
import { z } from 'zod';

// ═══════════════════════════════════════════
// ENUMS
// ═══════════════════════════════════════════

export enum DeployBatchMode {
  DryRun = 'dry_run',
  Live = 'live',
}

export enum DeployBatchStatus {
  Created = 'created',
  Validating = 'validating',
  Ready = 'ready',
  Running = 'running',
  Done = 'done',
  Failed = 'failed',
  Cancelled = 'cancelled',
}

export enum DeployItemStatus {
  Pending = 'pending',
  Valid = 'valid',
  Invalid = 'invalid',
  Ready = 'ready',
  Running = 'running',
  Success = 'success',
  Failed = 'failed',
  Skipped = 'skipped',
  Cancelled = 'cancelled',
}

// ═══════════════════════════════════════════
// ZOD SCHEMAS
// ═══════════════════════════════════════════

/** DAT format: strict 64 hex chars (one-time token) */
export const DatSchema = z.string().regex(/^[A-Fa-f0-9]{64}$/, 'DAT must be 64 hexadecimal characters');

/** Single row in an imported CSV/XLSX file */
export const DeployImportRowSchema = z.object({
  zabbix_host: z.string().min(1).max(255).trim(),
  dat: DatSchema,
});

/** Import file validation result */
export const DeployImportResultSchema = z.object({
  batch_id: z.string().uuid(),
  filename: z.string(),
  mode: z.nativeEnum(DeployBatchMode),
  total: z.number().int(),
  valid: z.number().int(),
  invalid: z.number().int(),
  duplicates: z.number().int(),
  errors: z.array(z.object({
    row: z.number().int(),
    zabbix_host: z.string().optional(),
    dat: z.string().optional(),
    error: z.string(),
  })),
});

/** Callback body from the PowerShell script */
export const DeployCallbackSchema = z.object({
  batch_id: z.string().uuid(),
  zabbix_host: z.string().min(1).optional(),
  computername: z.string().min(1).optional(),
  exit_code: z.number().int(),
  status: z.string().min(1).max(64),
  message: z.string().max(2000).optional(),
  log_tail: z.string().max(20000).optional(),
  os_version: z.string().max(512).optional(),
  agent_id: z.string().uuid().optional(),
  hostname: z.string().max(255).optional(),
  version: z.string().optional(),
});

/** Create batch request */
export const CreateDeployBatchSchema = z.object({
  mode: z.nativeEnum(DeployBatchMode),
  zabbix_url: z.string().url(),
  zabbix_user: z.string().min(1),
  zabbix_password: z.string().min(1).optional(),
  zabbix_script: z.string().min(1).default('Reap3r Enrollment'),
  server_url: z.string().url(),
});

// ═══════════════════════════════════════════
// TYPESCRIPT INTERFACES
// ═══════════════════════════════════════════

export interface DeployBatch {
  batch_id: string;
  tenant_id: string;
  filename: string;
  server_url: string;
  mode: DeployBatchMode;
  status: DeployBatchStatus;
  created_by: string;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
  total_items: number;
  valid_count: number;
  invalid_count: number;
  success_count: number;
  failed_count: number;
  skipped_count: number;
  zabbix_url: string | null;
  zabbix_user: string | null;
  zabbix_script: string | null;
  error: string | null;
  notes: string | null;
}

export interface DeployItem {
  id: string;
  tenant_id: string;
  batch_id: string;
  row_number: number;
  zabbix_host: string;
  dat: string;
  status: DeployItemStatus;
  validation_error: string | null;
  zabbix_hostid: string | null;
  zabbix_scriptid: string | null;
  zabbix_exec_id: string | null;
  attempt_count: number;
  max_attempts: number;
  last_attempt_at: string | null;
  next_retry_at: string | null;
  last_error: string | null;
  error_category: string | null;
  lock_owner: string | null;
  lock_until: string | null;
  callback_received: boolean;
  callback_at: string | null;
  callback_exit: number | null;
  callback_status: string | null;
  callback_message: string | null;
  proof: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface DeployImportError {
  row: number;
  zabbix_host?: string;
  dat?: string;
  error: string;
}

// ═══════════════════════════════════════════
// CALLBACK EXIT CODES
// ═══════════════════════════════════════════

export const DEPLOY_EXIT_CODES: Record<number, { label: string; retryable: boolean }> = {
  0: { label: 'SUCCESS', retryable: false },
  10: { label: 'ALREADY_INSTALLED', retryable: false },
  20: { label: 'DOWNLOAD_FAILED', retryable: true },
  30: { label: 'INSTALL_FAILED', retryable: true },
  40: { label: 'SERVICE_START_FAILED', retryable: true },
  50: { label: 'CALLBACK_FAILED', retryable: false },
};

// ═══════════════════════════════════════════
// RETRY BACKOFF (minutes)
// ═══════════════════════════════════════════
export const DEPLOY_RETRY_BACKOFF_MINUTES = [1, 5, 20];
export const DEPLOY_MAX_ATTEMPTS = 3;
export const DEPLOY_LOCK_TTL_MINUTES = 20;

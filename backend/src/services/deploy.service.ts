// ─────────────────────────────────────────────
// MASSVISION Reap3r — Deploy Service
// Orchestrates batch CSV/XLSX → Zabbix deployment
// ─────────────────────────────────────────────
import { query, transaction } from '../db/pool.js';
import { ZabbixClient, ZabbixApiError, ZabbixCircuitOpenError } from './zabbix-client.js';
import * as XLSX from 'xlsx';
import {
  DeployBatchMode, DeployBatchStatus, DeployItemStatus,
  DeployImportError, DeployBatch, DeployItem,
  DEPLOY_RETRY_BACKOFF_MINUTES, DEPLOY_MAX_ATTEMPTS, DEPLOY_LOCK_TTL_MINUTES,
  DEPLOY_EXIT_CODES,
} from '@massvision/shared';
import { randomUUID } from 'crypto';

// ═══════════════════════════════════════════
// CSV PARSING
// ═══════════════════════════════════════════

interface ParsedRow {
  row: number;
  zabbix_host: string;
  dat: string;
}

const DAT_HEX_64_RE = /^[A-Fa-f0-9]{64}$/;
const HOST_COLUMNS = ['zabbix_host', 'host', 'hostname', 'server'];
const DAT_COLUMNS = ['dat', 'token', 'key', 'code'];

function parseInputRows(input: Array<{ row: number; zabbix_host: string; dat: string }>): { rows: ParsedRow[]; errors: DeployImportError[] } {
  const rows: ParsedRow[] = [];
  const errors: DeployImportError[] = [];
  const seenHosts = new Set<string>();
  const seenDats = new Set<string>();

  for (const current of input) {
    const zabbix_host = (current.zabbix_host ?? '').trim();
    const dat = (current.dat ?? '').trim();
    const rowNum = current.row;

    if (!zabbix_host) {
      errors.push({ row: rowNum, zabbix_host, dat, error: 'Missing zabbix_host' });
      continue;
    }
    if (!DAT_HEX_64_RE.test(dat)) {
      errors.push({ row: rowNum, zabbix_host, dat, error: 'Invalid DAT format (expected 64 hex chars)' });
      continue;
    }

    const hostKey = zabbix_host.toLowerCase();
    if (seenHosts.has(hostKey)) {
      errors.push({ row: rowNum, zabbix_host, dat, error: 'Duplicate zabbix_host in file' });
      continue;
    }
    if (seenDats.has(dat.toLowerCase())) {
      errors.push({ row: rowNum, zabbix_host, dat, error: 'Duplicate DAT in file' });
      continue;
    }

    seenHosts.add(hostKey);
    seenDats.add(dat.toLowerCase());
    rows.push({ row: rowNum, zabbix_host, dat });
  }

  return { rows, errors };
}

/**
 * Parse CSV text content into rows.
 * Expected columns: zabbix_host (or host/hostname), dat (or token/key)
 * Separator: comma, semicolon, or tab
 */
export function parseCsv(content: string): { rows: ParsedRow[]; errors: DeployImportError[] } {
  const lines = content.split(/\r?\n/).filter(l => l.trim());
  if (lines.length === 0) return { rows: [], errors: [{ row: 0, error: 'Empty file' }] };

  // Detect separator
  const firstLine = lines[0];
  const sep = firstLine.includes('\t') ? '\t' : firstLine.includes(';') ? ';' : ',';

  // Parse header
  const headers = firstLine.split(sep).map(h => h.trim().toLowerCase().replace(/['"]/g, ''));
  let hostCol = headers.findIndex(h => HOST_COLUMNS.includes(h));
  let datCol = headers.findIndex(h => DAT_COLUMNS.includes(h));

  // Heuristic: if headers missing, check if first line looks like data (hex64 + hostname)
  let startIdx = 1;
  if (hostCol === -1 || datCol === -1) {
    const p1 = headers[0];
    const p2 = headers[1];
    if (headers.length >= 2) {
       // Check if col 0 is DAT
       if (DAT_HEX_64_RE.test(p1)) {
         datCol = 0;
         hostCol = 1;
         startIdx = 0; // First line is data
       } else if (DAT_HEX_64_RE.test(p2)) {
         datCol = 1;
         hostCol = 0;
         startIdx = 0;
       }
    }
  }

  if (hostCol === -1 || datCol === -1) {
    return { rows: [], errors: [{ row: 1, error: `Missing required columns. Need: zabbix_host (or host/hostname), dat (or token/key). Found: ${headers.join(', ')}` }] };
  }

  const input: Array<{ row: number; zabbix_host: string; dat: string }> = [];

  for (let i = startIdx; i < lines.length; i++) {
    const cols = lines[i].split(sep).map(c => c.trim().replace(/^["']|["']$/g, ''));
    const zabbix_host = (cols[hostCol] ?? '').trim();
    const dat = (cols[datCol] ?? '').trim();
    const rowNum = i + 1;
    input.push({ row: rowNum, zabbix_host, dat });
  }

  return parseInputRows(input);
}

export function parseXlsxBuffer(content: Buffer): { rows: ParsedRow[]; errors: DeployImportError[] } {
  const wb = XLSX.read(content, { type: 'buffer' });
  const firstSheetName = wb.SheetNames[0];
  if (!firstSheetName) return { rows: [], errors: [{ row: 0, error: 'Empty workbook' }] };
  const sheet = wb.Sheets[firstSheetName];
  const jsonRows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: '' });
  if (jsonRows.length === 0) return { rows: [], errors: [{ row: 0, error: 'Empty sheet' }] };

  const rawHeaders = Object.keys(jsonRows[0]);
  const normalizedToRaw = new Map<string, string>();
  for (const raw of rawHeaders) {
    normalizedToRaw.set(raw.trim().toLowerCase(), raw);
  }
  const hostHeaderNorm = HOST_COLUMNS.find((h) => normalizedToRaw.has(h));
  const datHeaderNorm = DAT_COLUMNS.find((h) => normalizedToRaw.has(h));
  const hostHeader = hostHeaderNorm ? normalizedToRaw.get(hostHeaderNorm) : undefined;
  const datHeader = datHeaderNorm ? normalizedToRaw.get(datHeaderNorm) : undefined;

  if (!hostHeader || !datHeader) {
    return {
      rows: [],
      errors: [{ row: 1, error: `Missing required columns. Need: zabbix_host (or host/hostname), dat (or token/key). Found: ${rawHeaders.join(', ')}` }],
    };
  }

  const input = jsonRows.map((r, idx) => ({
    row: idx + 2,
    zabbix_host: String(r[hostHeader] ?? '').trim(),
    dat: String(r[datHeader] ?? '').trim(),
  }));
  return parseInputRows(input);
}

export function parseImportFile(filename: string, raw: Buffer | string): { rows: ParsedRow[]; errors: DeployImportError[] } {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.xlsx') || lower.endsWith('.xls')) {
    const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
    return parseXlsxBuffer(buf);
  }
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : raw;
  return parseCsv(text);
}

// ═══════════════════════════════════════════
// BATCH MANAGEMENT
// ═══════════════════════════════════════════

export interface CreateBatchInput {
  tenant_id: string;
  created_by: string;
  filename: string;
  mode: DeployBatchMode;
  server_url: string;
  zabbix_url: string;
  zabbix_user: string;
  zabbix_script: string;
  zabbix_password?: string;
  items: ParsedRow[];
}

/**
 * Create a new deploy batch with items.
 */
export async function createBatch(input: CreateBatchInput): Promise<{ batch: DeployBatch; item_count: number }> {
  const batchId = randomUUID();

  return transaction(async (client) => {
    // Insert batch
    const { rows: [batch] } = await client.query<DeployBatch>(
      `INSERT INTO deploy_batches (batch_id, tenant_id, filename, server_url, mode, status, created_by, total_items, zabbix_url, zabbix_user, zabbix_script)
       VALUES ($1, $2, $3, $4, $5, 'created', $6, $7, $8, $9, $10)
       RETURNING *`,
      [batchId, input.tenant_id, input.filename, input.server_url, input.mode, input.created_by,
       input.items.length, input.zabbix_url, input.zabbix_user, input.zabbix_script],
    );

    // Bulk insert items
    if (input.items.length > 0) {
      const values: unknown[] = [];
      const placeholders: string[] = [];
      let idx = 1;

      for (const item of input.items) {
        placeholders.push(`($${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++}, $${idx++})`);
        values.push(randomUUID(), input.tenant_id, batchId, item.row, item.zabbix_host, item.dat);
      }

      await client.query(
        `INSERT INTO deploy_items (id, tenant_id, batch_id, row_number, zabbix_host, dat)
         VALUES ${placeholders.join(', ')}`,
        values,
      );
    }

    if (input.zabbix_password) {
      await client.query(
        `INSERT INTO deploy_batch_secrets (batch_id, tenant_id, zabbix_password)
         VALUES ($1, $2, $3)
         ON CONFLICT (batch_id)
         DO UPDATE SET zabbix_password = EXCLUDED.zabbix_password, updated_at = NOW()`,
        [batchId, input.tenant_id, input.zabbix_password],
      );
    }

    return { batch, item_count: input.items.length };
  });
}

async function getBatchSecret(batchId: string, tenantId: string): Promise<string | null> {
  const { rows } = await query<{ zabbix_password: string }>(
    `SELECT zabbix_password
     FROM deploy_batch_secrets
     WHERE batch_id = $1 AND tenant_id = $2
     LIMIT 1`,
    [batchId, tenantId],
  );
  return rows[0]?.zabbix_password ?? null;
}

/**
 * Get a batch by ID.
 */
export async function getBatch(batchId: string, tenantId: string): Promise<DeployBatch | null> {
  const { rows } = await query<DeployBatch>(
    `SELECT * FROM deploy_batches WHERE batch_id = $1 AND tenant_id = $2`,
    [batchId, tenantId],
  );
  return rows[0] ?? null;
}

/**
 * List batches for a tenant.
 */
export async function listBatches(tenantId: string, page = 1, limit = 25): Promise<{ data: DeployBatch[]; total: number }> {
  const offset = (page - 1) * limit;
  const [dataRes, countRes] = await Promise.all([
    query<DeployBatch>(
      `SELECT * FROM deploy_batches WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [tenantId, limit, offset],
    ),
    query<{ count: string }>(
      `SELECT count(*)::text as count FROM deploy_batches WHERE tenant_id = $1`,
      [tenantId],
    ),
  ]);
  return { data: dataRes.rows, total: parseInt(countRes.rows[0]?.count ?? '0') };
}

/**
 * Get items for a batch.
 */
export async function getBatchItems(batchId: string, tenantId: string, statusFilter?: string): Promise<DeployItem[]> {
  let sql = `SELECT * FROM deploy_items WHERE batch_id = $1 AND tenant_id = $2`;
  const params: unknown[] = [batchId, tenantId];
  if (statusFilter) {
    sql += ` AND status = $3`;
    params.push(statusFilter);
  }
  sql += ` ORDER BY row_number ASC`;
  const { rows } = await query<DeployItem>(sql, params);
  return rows;
}

// ═══════════════════════════════════════════
// VALIDATION (Dry-run + Zabbix check)
// ═══════════════════════════════════════════

/**
 * Validate a batch: resolve hosts in Zabbix, check script exists.
 * This is the dry_run phase — NO script.execute is ever called here.
 */
export async function validateBatch(batchId: string, tenantId: string, zabbixPassword?: string): Promise<{
  valid: number; invalid: number; errors: DeployImportError[];
}> {
  const batch = await getBatch(batchId, tenantId);
  if (!batch) throw new Error('Batch not found');
  if (!['created', 'ready'].includes(batch.status)) throw new Error(`Cannot validate batch in status: ${batch.status}`);
  if (!batch.zabbix_url || !batch.zabbix_user || !batch.zabbix_script) {
    throw new Error('Missing Zabbix configuration on batch');
  }

  // Update status to validating
  await query(`UPDATE deploy_batches SET status = 'validating', updated_at = NOW() WHERE batch_id = $1`, [batchId]);

  const effectivePassword = zabbixPassword || (await getBatchSecret(batchId, tenantId)) || process.env.ZABBIX_PASSWORD;
  if (!effectivePassword) {
    throw new Error('Missing Zabbix password for validation');
  }

  const zbx = new ZabbixClient({
    url: batch.zabbix_url,
    user: batch.zabbix_user,
    password: effectivePassword,
  });

  try {
    await zbx.login();

    // Resolve script by exact name and reject ambiguity.
    const scriptResult = await zbx.scriptResolveExact(batch.zabbix_script);
    if (scriptResult.state !== 'ok' || !scriptResult.entity) {
      const scriptErr =
        scriptResult.state === 'ambiguous'
          ? `Zabbix global script "${batch.zabbix_script}" is ambiguous (${scriptResult.matches?.length ?? 0} matches)`
          : `Zabbix global script "${batch.zabbix_script}" not found`;

      await query(
        `UPDATE deploy_items
           SET status = 'invalid', validation_error = $2, updated_at = NOW()
         WHERE batch_id = $1 AND tenant_id = $3`,
        [batchId, scriptErr, tenantId],
      );
      await query(
        `UPDATE deploy_batches SET status = 'failed', error = $2, updated_at = NOW() WHERE batch_id = $1`,
        [batchId, scriptErr],
      );
      const items = await getBatchItems(batchId, tenantId);
      return {
        valid: 0,
        invalid: items.length,
        errors: [{ row: 0, error: scriptErr }],
      };
    }
    const script = scriptResult.entity;

    // Fetch all items
    const items = await getBatchItems(batchId, tenantId);

    // Batch resolve hosts
    const hostnames = items.map(i => i.zabbix_host);
    const hostMap = await zbx.hostResolveBatchExact(hostnames);

    const errors: DeployImportError[] = [];
    let valid = 0;
    let invalid = 0;

    for (const item of items) {
      const resolution = hostMap.get(item.zabbix_host);
      if (resolution?.state === 'ok' && resolution.entity) {
        await query(
          `UPDATE deploy_items
             SET status = 'valid', validation_error = NULL,
                 zabbix_hostid = $2, zabbix_scriptid = $3, updated_at = NOW()
           WHERE id = $1`,
          [item.id, resolution.entity.hostid, script.scriptid],
        );
        valid++;
      } else {
        const hostError =
          resolution?.state === 'ambiguous'
            ? `Host "${item.zabbix_host}" is ambiguous in Zabbix`
            : `Host "${item.zabbix_host}" not found in Zabbix`;
        await query(
          `UPDATE deploy_items SET status = 'invalid', validation_error = $2, updated_at = NOW()
           WHERE id = $1`,
          [item.id, hostError],
        );
        errors.push({
          row: item.row_number,
          zabbix_host: item.zabbix_host,
          error: resolution?.state === 'ambiguous' ? 'Host ambiguous in Zabbix' : 'Host not found in Zabbix',
        });
        invalid++;
      }
    }

    // Update batch counters + status
    const newStatus = invalid === items.length ? 'failed' : 'ready';
    await query(
      `UPDATE deploy_batches SET status = $2, valid_count = $3, invalid_count = $4, updated_at = NOW()
       WHERE batch_id = $1`,
      [batchId, newStatus, valid, invalid],
    );

    return { valid, invalid, errors };
  } catch (err: any) {
    await query(
      `UPDATE deploy_batches SET status = 'failed', error = $2, updated_at = NOW() WHERE batch_id = $1`,
      [batchId, `Zabbix validation error: ${err.message}`],
    );
    throw err;
  } finally {
    await zbx.logout();
  }
}

// ═══════════════════════════════════════════
// EXECUTION
// ═══════════════════════════════════════════

/**
 * Start a batch: move valid items to 'ready', update batch to 'running'.
 */
export async function startBatch(batchId: string, tenantId: string): Promise<void> {
  const batch = await getBatch(batchId, tenantId);
  if (!batch) throw new Error('Batch not found');
  if (batch.status !== 'ready') throw new Error(`Cannot start batch in status: ${batch.status}`);
  if (batch.mode !== DeployBatchMode.Live) throw new Error('Only live batches can be started');

  await transaction(async (client) => {
    // Mark valid items as ready for execution
    await client.query(
      `UPDATE deploy_items SET status = 'ready', updated_at = NOW()
       WHERE batch_id = $1 AND tenant_id = $2 AND status = 'valid'`,
      [batchId, tenantId],
    );
    // Skip invalid items
    await client.query(
      `UPDATE deploy_items SET status = 'skipped', updated_at = NOW()
       WHERE batch_id = $1 AND tenant_id = $2 AND status = 'invalid'`,
      [batchId, tenantId],
    );
    // Update batch
    await client.query(
      `UPDATE deploy_batches SET status = 'running', started_at = NOW(), updated_at = NOW()
       WHERE batch_id = $1`,
      [batchId],
    );
  });
}

/**
 * Retry failed items in a batch.
 */
export async function retryFailed(batchId: string, tenantId: string): Promise<number> {
  const batch = await getBatch(batchId, tenantId);
  if (!batch) throw new Error('Batch not found');
  if (!['running', 'done', 'failed'].includes(batch.status)) {
    throw new Error(`Cannot retry batch in status: ${batch.status}`);
  }

  const { rowCount } = await query(
    `UPDATE deploy_items SET status = 'ready', last_error = NULL, error_category = NULL,
       next_retry_at = NULL, lock_owner = NULL, lock_until = NULL, updated_at = NOW()
     WHERE batch_id = $1 AND tenant_id = $2
       AND status = 'failed' AND attempt_count < max_attempts`,
    [batchId, tenantId],
  );

  // Re-set batch to running if it was done/failed
  if ((rowCount ?? 0) > 0) {
    await query(
      `UPDATE deploy_batches SET status = 'running', finished_at = NULL, updated_at = NOW()
       WHERE batch_id = $1 AND status IN ('done', 'failed')`,
      [batchId],
    );
  }

  return rowCount ?? 0;
}

/**
 * Cancel a batch: mark running/ready items as cancelled.
 */
export async function cancelBatch(batchId: string, tenantId: string): Promise<void> {
  const batch = await getBatch(batchId, tenantId);
  if (!batch) throw new Error('Batch not found');
  if (!['created', 'validating', 'ready', 'running'].includes(batch.status)) {
    throw new Error(`Cannot cancel batch in status: ${batch.status}`);
  }

  await transaction(async (client) => {
    await client.query(
      `UPDATE deploy_items SET status = 'cancelled', updated_at = NOW()
       WHERE batch_id = $1 AND tenant_id = $2 AND status IN ('pending', 'valid', 'ready', 'running')`,
      [batchId, tenantId],
    );
    await client.query(
      `UPDATE deploy_batches SET status = 'cancelled', finished_at = NOW(), updated_at = NOW()
       WHERE batch_id = $1`,
      [batchId],
    );
  });
}

// ═══════════════════════════════════════════
// ITEM PROCESSING (called by worker)
// ═══════════════════════════════════════════

const WORKER_ID = `worker-${process.pid}-${randomUUID().slice(0, 8)}`;

/**
 * Acquire and lock the next batch of ready items for execution.
 * Uses SELECT ... FOR UPDATE SKIP LOCKED for safe concurrency.
 */
export async function acquireItems(limit = 5): Promise<DeployItem[]> {
  const lockUntil = new Date(Date.now() + DEPLOY_LOCK_TTL_MINUTES * 60 * 1000).toISOString();

  const { rows } = await query<DeployItem>(
    `UPDATE deploy_items SET
       status = 'running',
       lock_owner = $1,
       lock_until = $2,
       attempt_count = attempt_count + 1,
       last_attempt_at = NOW(),
       started_at = COALESCE(started_at, NOW()),
       updated_at = NOW()
     WHERE id IN (
       SELECT id FROM deploy_items
       WHERE status = 'ready'
         AND (next_retry_at IS NULL OR next_retry_at <= NOW())
       ORDER BY row_number ASC
       FOR UPDATE SKIP LOCKED
       LIMIT $3
     )
     RETURNING *`,
    [WORKER_ID, lockUntil, limit],
  );

  return rows;
}

/**
 * Execute a single deploy item via Zabbix script.execute.
 */
export async function executeItem(item: DeployItem, zbxClient: ZabbixClient, serverUrl: string, callbackKey: string): Promise<void> {
  try {
    // Build the command macros/parameters for the Zabbix script
    const result = await zbxClient.scriptExecute(item.zabbix_scriptid!, item.zabbix_hostid!, {
      '{$DAT}': item.dat,
      '{$SERVER}': serverUrl,
      '{$BATCH_ID}': item.batch_id,
      '{$CALLBACK_KEY}': callbackKey,
      DAT: item.dat,
      SERVER_URL: serverUrl,
      BATCH_ID: item.batch_id,
      CALLBACK_KEY: callbackKey,
    });
    const execId = String(result?.value ?? result?.response ?? `exec-${Date.now()}`);

    // Update item: script was sent
    await query(
      `UPDATE deploy_items SET
         zabbix_exec_id = $2, updated_at = NOW(),
         lock_until = $3
       WHERE id = $1`,
      [item.id, execId, new Date(Date.now() + DEPLOY_LOCK_TTL_MINUTES * 60 * 1000).toISOString()],
    );

    // Note: item stays in 'running' status until callback arrives or watchdog times it out
    console.log(`[deploy] Executed script on ${item.zabbix_host} (item ${item.id})`);

  } catch (err: any) {
    const retryable = err instanceof ZabbixApiError ? err.retryable : true;
    const category = retryable ? 'retryable' : 'non_retryable';

    if (retryable && item.attempt_count < item.max_attempts) {
      const backoff = DEPLOY_RETRY_BACKOFF_MINUTES[Math.min(item.attempt_count - 1, DEPLOY_RETRY_BACKOFF_MINUTES.length - 1)];
      const nextRetry = new Date(Date.now() + backoff * 60 * 1000).toISOString();
      await query(
        `UPDATE deploy_items SET
           status = 'ready', last_error = $2, error_category = $3,
           next_retry_at = $4, lock_owner = NULL, lock_until = NULL, updated_at = NOW()
         WHERE id = $1`,
        [item.id, err.message, category, nextRetry],
      );
      console.warn(`[deploy] Retryable error on ${item.zabbix_host}: ${err.message} — retry at ${nextRetry}`);
    } else {
      await query(
        `UPDATE deploy_items SET
           status = 'failed', last_error = $2, error_category = $3,
           finished_at = NOW(), lock_owner = NULL, lock_until = NULL, updated_at = NOW()
         WHERE id = $1`,
        [item.id, err.message, category],
      );
      // Update batch failed count
      await updateBatchCounters(item.batch_id);
      console.error(`[deploy] Final failure on ${item.zabbix_host}: ${err.message}`);
    }
  }
}

// ═══════════════════════════════════════════
// CALLBACK PROCESSING
// ═══════════════════════════════════════════

export interface CallbackData {
  batch_id: string;
  zabbix_host?: string;
  computername?: string;
  exit_code: number;
  status: string;
  message?: string;
  log_tail?: string;
  os_version?: string;
  agent_id?: string;
  hostname?: string;
  version?: string;
}

async function resolveCallbackItem(data: CallbackData): Promise<DeployItem | null> {
  const candidates = Array.from(
    new Set([data.zabbix_host, data.computername, data.hostname].filter((v): v is string => !!v && v.trim().length > 0)),
  );

  for (const hostCandidate of candidates) {
    const byHost = await query<DeployItem>(
      `SELECT * FROM deploy_items
       WHERE batch_id = $1 AND lower(zabbix_host) = lower($2)
         AND status = 'running'
       ORDER BY updated_at DESC
       LIMIT 1`,
      [data.batch_id, hostCandidate],
    );
    if (byHost.rows[0]) return byHost.rows[0];
  }

  const fallback = await query<DeployItem>(
    `SELECT * FROM deploy_items
     WHERE batch_id = $1 AND status = 'running'
     ORDER BY updated_at DESC
     LIMIT 2`,
    [data.batch_id],
  );
  if (fallback.rows.length === 1) return fallback.rows[0];
  return null;
}

/**
 * Process a callback from the PowerShell enrollment script.
 */
export async function processCallback(data: CallbackData): Promise<void> {
  const exitInfo = DEPLOY_EXIT_CODES[data.exit_code] ?? { label: 'UNKNOWN', retryable: false };
  const isSuccess = data.exit_code === 0 || data.exit_code === 10;
  const callbackHost = data.computername || data.hostname || data.zabbix_host || 'unknown';
  const item = await resolveCallbackItem(data);
  if (!item) {
    throw new Error(`No running deploy item found for callback (batch=${data.batch_id}, host=${callbackHost})`);
  }

  const proof = {
    exit_code: data.exit_code,
    status: data.status,
    message: data.message,
    log_tail: data.log_tail,
    os_version: data.os_version,
    computername: callbackHost,
    agent_id: data.agent_id,
    hostname: data.hostname,
    version: data.version,
    received_at: new Date().toISOString(),
  };

  if (isSuccess) {
    await query(
      `UPDATE deploy_items SET
         status = 'success', callback_received = TRUE, callback_at = NOW(),
         callback_exit = $2, callback_status = $3, callback_message = $4,
         proof = $5, finished_at = NOW(), lock_owner = NULL, lock_until = NULL, updated_at = NOW()
       WHERE id = $1`,
      [item.id, data.exit_code, data.status, data.message ?? data.log_tail ?? '', JSON.stringify(proof)],
    );
  } else if (exitInfo.retryable) {
    // Check attempt count and decide retry vs final fail
    if (item && item.attempt_count < item.max_attempts) {
      const backoff = DEPLOY_RETRY_BACKOFF_MINUTES[Math.min(item.attempt_count - 1, DEPLOY_RETRY_BACKOFF_MINUTES.length - 1)];
      const nextRetry = new Date(Date.now() + backoff * 60 * 1000).toISOString();
      await query(
        `UPDATE deploy_items SET
           status = 'ready', callback_received = TRUE, callback_at = NOW(),
           callback_exit = $2, callback_status = $3, callback_message = $4,
           last_error = $5, error_category = 'retryable', next_retry_at = $6,
           lock_owner = NULL, lock_until = NULL, proof = $7, updated_at = NOW()
         WHERE id = $1`,
        [
          item.id,
          data.exit_code,
          data.status,
          data.message ?? data.log_tail ?? '',
          `${exitInfo.label}: ${data.message ?? data.status}`,
          nextRetry,
          JSON.stringify(proof),
        ],
      );
    } else {
      await query(
        `UPDATE deploy_items SET
           status = 'failed', callback_received = TRUE, callback_at = NOW(),
           callback_exit = $2, callback_status = $3, callback_message = $4,
           last_error = $5, error_category = 'non_retryable', proof = $6,
           finished_at = NOW(), lock_owner = NULL, lock_until = NULL, updated_at = NOW()
         WHERE id = $1`,
        [
          item.id,
          data.exit_code,
          data.status,
          data.message ?? data.log_tail ?? '',
          `${exitInfo.label}: ${data.message ?? data.status}`,
          JSON.stringify(proof),
        ],
      );
    }
  } else {
    // Non-retryable failure
    await query(
      `UPDATE deploy_items SET
         status = 'failed', callback_received = TRUE, callback_at = NOW(),
         callback_exit = $2, callback_status = $3, callback_message = $4,
         last_error = $5, error_category = 'non_retryable', proof = $6,
         finished_at = NOW(), lock_owner = NULL, lock_until = NULL, updated_at = NOW()
       WHERE id = $1`,
      [
        item.id,
        data.exit_code,
        data.status,
        data.message ?? data.log_tail ?? '',
        `${exitInfo.label}: ${data.message ?? data.status}`,
        JSON.stringify(proof),
      ],
    );
  }

  // Update batch counters
  await updateBatchCounters(data.batch_id);
}

// ═══════════════════════════════════════════
// BATCH COUNTER SYNC
// ═══════════════════════════════════════════

/**
 * Recalculate and sync batch counters from item statuses.
 * Also auto-finalize batch if all items are terminal.
 */
export async function updateBatchCounters(batchId: string): Promise<void> {
  const { rows } = await query<{ status: string; cnt: string }>(
    `SELECT status, count(*)::text AS cnt FROM deploy_items WHERE batch_id = $1 GROUP BY status`,
    [batchId],
  );

  const counts: Record<string, number> = {};
  let total = 0;
  for (const r of rows) {
    counts[r.status] = parseInt(r.cnt);
    total += counts[r.status];
  }

  const success = counts['success'] ?? 0;
  const failed = counts['failed'] ?? 0;
  const skipped = counts['skipped'] ?? 0;
  const cancelled = counts['cancelled'] ?? 0;
  const running = counts['running'] ?? 0;
  const ready = counts['ready'] ?? 0;
  const pending = counts['pending'] ?? 0;
  const valid = counts['valid'] ?? 0;
  const invalid = counts['invalid'] ?? 0;

  const nonTerminal = running + ready + pending + valid;
  const allDone = nonTerminal === 0 && total > 0;
  const nextStatus = allDone ? (failed > 0 ? 'failed' : 'done') : null;
  const validCount = total - invalid - pending;

  if (nextStatus) {
    await query(
      `UPDATE deploy_batches SET
         valid_count = $2, invalid_count = $3, success_count = $4, failed_count = $5, skipped_count = $6,
         status = $7::deploy_batch_status, finished_at = NOW(), updated_at = NOW()
       WHERE batch_id = $1`,
      [batchId, validCount, invalid, success, failed, skipped, nextStatus],
    );
  } else {
    await query(
      `UPDATE deploy_batches SET
         valid_count = $2, invalid_count = $3, success_count = $4, failed_count = $5, skipped_count = $6,
         updated_at = NOW()
       WHERE batch_id = $1`,
      [batchId, validCount, invalid, success, failed, skipped],
    );
  }
}

// ═══════════════════════════════════════════
// WATCHDOG
// ═══════════════════════════════════════════

/**
 * Find stuck running items (lock_until expired) and mark them failed.
 * Called periodically by the worker.
 */
export async function watchdogSweep(): Promise<number> {
  const { rowCount } = await query(
    `UPDATE deploy_items SET
       status = 'failed', last_error = 'STUCK_TIMEOUT: Lock expired without callback',
       error_category = 'retryable', lock_owner = NULL, lock_until = NULL,
       finished_at = NOW(), updated_at = NOW()
     WHERE status = 'running' AND lock_until IS NOT NULL AND lock_until < NOW()`,
  );

  if ((rowCount ?? 0) > 0) {
    console.warn(`[deploy-watchdog] Swept ${rowCount} stuck items`);
    // Update batch counters for affected batches
    const { rows: batches } = await query<{ batch_id: string }>(
      `SELECT DISTINCT batch_id FROM deploy_items
       WHERE status = 'failed' AND last_error LIKE 'STUCK_TIMEOUT%'
         AND updated_at > NOW() - INTERVAL '1 minute'`,
    );
    for (const b of batches) {
      await updateBatchCounters(b.batch_id);
    }
  }

  return rowCount ?? 0;
}

// ─────────────────────────────────────────────
// MASSVISION Reap3r — Deploy Service
// Orchestrates batch CSV/XLSX → Zabbix deployment
// ─────────────────────────────────────────────
import { query, transaction } from '../db/pool.js';
import { ZabbixClient, ZabbixApiError, ZabbixCircuitOpenError } from './zabbix-client.js';
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
  const hostCol = headers.findIndex(h => ['zabbix_host', 'host', 'hostname', 'server'].includes(h));
  const datCol = headers.findIndex(h => ['dat', 'token', 'key', 'code'].includes(h));

  if (hostCol === -1 || datCol === -1) {
    return { rows: [], errors: [{ row: 1, error: `Missing required columns. Need: zabbix_host (or host/hostname), dat (or token/key). Found: ${headers.join(', ')}` }] };
  }

  const rows: ParsedRow[] = [];
  const errors: DeployImportError[] = [];
  const seen = new Set<string>();

  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(sep).map(c => c.trim().replace(/^["']|["']$/g, ''));
    const zabbix_host = (cols[hostCol] ?? '').trim();
    const dat = (cols[datCol] ?? '').trim();
    const rowNum = i + 1;

    if (!zabbix_host) {
      errors.push({ row: rowNum, zabbix_host, dat, error: 'Missing zabbix_host' });
      continue;
    }
    if (!dat || !/^[A-Za-z0-9._-]+$/.test(dat)) {
      errors.push({ row: rowNum, zabbix_host, dat, error: 'Invalid or missing DAT format' });
      continue;
    }

    const key = `${zabbix_host.toLowerCase()}`;
    if (seen.has(key)) {
      errors.push({ row: rowNum, zabbix_host, dat, error: 'Duplicate host in file' });
      continue;
    }
    seen.add(key);

    rows.push({ row: rowNum, zabbix_host, dat });
  }

  return { rows, errors };
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

    return { batch, item_count: input.items.length };
  });
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
export async function validateBatch(batchId: string, tenantId: string, zabbixPassword: string): Promise<{
  valid: number; invalid: number; errors: DeployImportError[];
}> {
  const batch = await getBatch(batchId, tenantId);
  if (!batch) throw new Error('Batch not found');
  if (!['created', 'ready'].includes(batch.status)) throw new Error(`Cannot validate batch in status: ${batch.status}`);

  // Update status to validating
  await query(`UPDATE deploy_batches SET status = 'validating', updated_at = NOW() WHERE batch_id = $1`, [batchId]);

  const zbx = new ZabbixClient({
    url: batch.zabbix_url!,
    user: batch.zabbix_user!,
    password: zabbixPassword,
  });

  try {
    await zbx.login();

    // Resolve script
    const script = await zbx.scriptGet(batch.zabbix_script!);
    if (!script) {
      await query(
        `UPDATE deploy_batches SET status = 'failed', error = $2, updated_at = NOW() WHERE batch_id = $1`,
        [batchId, `Zabbix global script "${batch.zabbix_script}" not found`],
      );
      return { valid: 0, invalid: 0, errors: [{ row: 0, error: `Script "${batch.zabbix_script}" not found in Zabbix` }] };
    }

    // Fetch all items
    const items = await getBatchItems(batchId, tenantId);

    // Batch resolve hosts
    const hostnames = items.map(i => i.zabbix_host);
    const hostMap = await zbx.hostGetBatch(hostnames);

    const errors: DeployImportError[] = [];
    let valid = 0;
    let invalid = 0;

    for (const item of items) {
      const host = hostMap.get(item.zabbix_host);
      if (host) {
        await query(
          `UPDATE deploy_items SET status = 'valid', zabbix_hostid = $2, zabbix_scriptid = $3, updated_at = NOW()
           WHERE id = $1`,
          [item.id, host.hostid, script.scriptid],
        );
        valid++;
      } else {
        await query(
          `UPDATE deploy_items SET status = 'invalid', validation_error = $2, updated_at = NOW()
           WHERE id = $1`,
          [item.id, `Host "${item.zabbix_host}" not found in Zabbix`],
        );
        errors.push({ row: item.row_number, zabbix_host: item.zabbix_host, error: 'Host not found in Zabbix' });
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
    });

    // Update item: script was sent
    await query(
      `UPDATE deploy_items SET
         zabbix_exec_id = $2, updated_at = NOW(),
         lock_until = $3
       WHERE id = $1`,
      [item.id, `exec-${Date.now()}`, new Date(Date.now() + DEPLOY_LOCK_TTL_MINUTES * 60 * 1000).toISOString()],
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
  zabbix_host: string;
  exit_code: number;
  status: string;
  message?: string;
  agent_id?: string;
  hostname?: string;
  version?: string;
}

/**
 * Process a callback from the PowerShell enrollment script.
 */
export async function processCallback(data: CallbackData): Promise<void> {
  const exitInfo = DEPLOY_EXIT_CODES[data.exit_code] ?? { label: 'UNKNOWN', retryable: false };
  const isSuccess = data.exit_code === 0 || data.exit_code === 10;

  const proof = {
    exit_code: data.exit_code,
    status: data.status,
    message: data.message,
    agent_id: data.agent_id,
    hostname: data.hostname,
    version: data.version,
    received_at: new Date().toISOString(),
  };

  if (isSuccess) {
    await query(
      `UPDATE deploy_items SET
         status = 'success', callback_received = TRUE, callback_at = NOW(),
         callback_exit = $3, callback_status = $4, callback_message = $5,
         proof = $6, finished_at = NOW(), lock_owner = NULL, lock_until = NULL, updated_at = NOW()
       WHERE batch_id = $1 AND zabbix_host = $2 AND status = 'running'`,
      [data.batch_id, data.zabbix_host, data.exit_code, data.status, data.message ?? '', JSON.stringify(proof)],
    );
  } else if (exitInfo.retryable) {
    // Check attempt count and decide retry vs final fail
    const { rows } = await query<DeployItem>(
      `SELECT * FROM deploy_items WHERE batch_id = $1 AND zabbix_host = $2 AND status = 'running' LIMIT 1`,
      [data.batch_id, data.zabbix_host],
    );
    const item = rows[0];
    if (item && item.attempt_count < item.max_attempts) {
      const backoff = DEPLOY_RETRY_BACKOFF_MINUTES[Math.min(item.attempt_count - 1, DEPLOY_RETRY_BACKOFF_MINUTES.length - 1)];
      const nextRetry = new Date(Date.now() + backoff * 60 * 1000).toISOString();
      await query(
        `UPDATE deploy_items SET
           status = 'ready', callback_received = TRUE, callback_at = NOW(),
           callback_exit = $3, callback_status = $4, callback_message = $5,
           last_error = $6, error_category = 'retryable', next_retry_at = $7,
           lock_owner = NULL, lock_until = NULL, updated_at = NOW()
         WHERE id = $8`,
        [data.batch_id, data.zabbix_host, data.exit_code, data.status, data.message ?? '',
         `${exitInfo.label}: ${data.message ?? ''}`, nextRetry, item.id],
      );
    } else {
      await query(
        `UPDATE deploy_items SET
           status = 'failed', callback_received = TRUE, callback_at = NOW(),
           callback_exit = $3, callback_status = $4, callback_message = $5,
           last_error = $6, error_category = 'non_retryable', proof = $7,
           finished_at = NOW(), lock_owner = NULL, lock_until = NULL, updated_at = NOW()
         WHERE batch_id = $1 AND zabbix_host = $2 AND status = 'running'`,
        [data.batch_id, data.zabbix_host, data.exit_code, data.status, data.message ?? '',
         `${exitInfo.label}: ${data.message ?? ''}`, JSON.stringify(proof)],
      );
    }
  } else {
    // Non-retryable failure
    await query(
      `UPDATE deploy_items SET
         status = 'failed', callback_received = TRUE, callback_at = NOW(),
         callback_exit = $3, callback_status = $4, callback_message = $5,
         last_error = $6, error_category = 'non_retryable', proof = $7,
         finished_at = NOW(), lock_owner = NULL, lock_until = NULL, updated_at = NOW()
       WHERE batch_id = $1 AND zabbix_host = $2 AND status = 'running'`,
      [data.batch_id, data.zabbix_host, data.exit_code, data.status, data.message ?? '',
       `${exitInfo.label}: ${data.message ?? ''}`, JSON.stringify(proof)],
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
  const valid = counts['valid'] ?? 0;
  const invalid = counts['invalid'] ?? 0;

  const terminal = success + failed + skipped + cancelled + invalid;
  const allDone = terminal >= total && total > 0;

  await query(
    `UPDATE deploy_batches SET
       valid_count = $2, invalid_count = $3, success_count = $4, failed_count = $5, skipped_count = $6,
       ${allDone ? "status = CASE WHEN failed_count > 0 THEN 'failed'::deploy_batch_status ELSE 'done'::deploy_batch_status END, finished_at = NOW()," : ''}
       updated_at = NOW()
     WHERE batch_id = $1`,
    [batchId, valid + success + failed + skipped, invalid, success, failed, skipped],
  );
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
       status = 'failed', last_error = 'TIMEOUT_STUCK: Lock expired without callback',
       error_category = 'retryable', lock_owner = NULL, lock_until = NULL,
       finished_at = NOW(), updated_at = NOW()
     WHERE status = 'running' AND lock_until IS NOT NULL AND lock_until < NOW()`,
  );

  if ((rowCount ?? 0) > 0) {
    console.warn(`[deploy-watchdog] Swept ${rowCount} stuck items`);
    // Update batch counters for affected batches
    const { rows: batches } = await query<{ batch_id: string }>(
      `SELECT DISTINCT batch_id FROM deploy_items
       WHERE status = 'failed' AND last_error LIKE 'TIMEOUT_STUCK%'
         AND updated_at > NOW() - INTERVAL '1 minute'`,
    );
    for (const b of batches) {
      await updateBatchCounters(b.batch_id);
    }
  }

  return rowCount ?? 0;
}

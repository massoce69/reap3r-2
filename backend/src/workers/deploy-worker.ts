// ─────────────────────────────────────────────
// MASSVISION Reap3r — Deploy Worker
// Background worker that processes deploy batches
// via Zabbix script.execute, with retry + watchdog
// ─────────────────────────────────────────────
import { query } from '../db/pool.js';
import { ZabbixClient } from '../services/zabbix-client.js';
import * as deploySvc from '../services/deploy.service.js';
import { config } from '../config.js';

let workerTimer: ReturnType<typeof setInterval> | null = null;
let watchdogTimer: ReturnType<typeof setInterval> | null = null;

// Active Zabbix client connections per batch
const zabbixClients = new Map<string, ZabbixClient>();

// ════════════════════════════════════════
// MAIN TICK
// ════════════════════════════════════════

async function processTick(): Promise<void> {
  try {
    // Check if there are any running batches
    const { rows: batches } = await query<{
      batch_id: string; zabbix_url: string; zabbix_user: string;
      server_url: string; zabbix_script: string;
    }>(
      `SELECT batch_id, zabbix_url, zabbix_user, server_url, zabbix_script
       FROM deploy_batches WHERE status = 'running' LIMIT 5`,
    );

    if (batches.length === 0) {
      // Clean up cached clients
      for (const [k, c] of zabbixClients) {
        await c.logout().catch(() => {});
        zabbixClients.delete(k);
      }
      return;
    }

    // Acquire ready items (across all batches)
    const items = await deploySvc.acquireItems(10);
    if (items.length === 0) return;

    // Group items by batch for efficient processing
    const groups = new Map<string, typeof items>();
    for (const item of items) {
      const list = groups.get(item.batch_id) ?? [];
      list.push(item);
      groups.set(item.batch_id, list);
    }

    // Process each group
    for (const [batchId, batchItems] of groups) {
      const batchInfo = batches.find(b => b.batch_id === batchId);
      if (!batchInfo) continue;

      // Get or create Zabbix client for this batch
      let zbx = zabbixClients.get(batchId);
      if (!zbx) {
        zbx = new ZabbixClient({
          url: batchInfo.zabbix_url,
          user: batchInfo.zabbix_user,
          // Note: password is not stored in DB for security — use env var
          password: process.env.ZABBIX_PASSWORD ?? '',
        });
        try {
          await zbx.login();
          zabbixClients.set(batchId, zbx);
        } catch (err: any) {
          console.error(`[deploy-worker] Failed to connect to Zabbix for batch ${batchId}: ${err.message}`);
          // Mark items back to ready
          for (const item of batchItems) {
            await query(
              `UPDATE deploy_items SET status = 'ready', lock_owner = NULL, lock_until = NULL,
                 attempt_count = GREATEST(attempt_count - 1, 0), updated_at = NOW()
               WHERE id = $1`,
              [item.id],
            );
          }
          continue;
        }
      }

      // Check circuit breaker
      if (zbx.isCircuitOpen) {
        console.warn(`[deploy-worker] Zabbix circuit breaker OPEN for batch ${batchId}, skipping`);
        // Release items
        for (const item of batchItems) {
          await query(
            `UPDATE deploy_items SET status = 'ready', lock_owner = NULL, lock_until = NULL,
               attempt_count = GREATEST(attempt_count - 1, 0), updated_at = NOW()
             WHERE id = $1`,
            [item.id],
          );
        }
        continue;
      }

      const callbackKey = process.env.DEPLOY_CALLBACK_KEY ?? 'dev-callback-key';

      // Execute items sequentially (to respect Zabbix rate limits)
      for (const item of batchItems) {
        await deploySvc.executeItem(item, zbx, batchInfo.server_url, callbackKey);
        // Small delay between script executions to avoid Zabbix throttling
        await sleep(500);
      }
    }
  } catch (err: any) {
    console.error('[deploy-worker] Tick error:', err.message);
  }
}

// ════════════════════════════════════════
// WATCHDOG TICK
// ════════════════════════════════════════

async function watchdogTick(): Promise<void> {
  try {
    await deploySvc.watchdogSweep();
  } catch (err: any) {
    console.error('[deploy-watchdog] Error:', err.message);
  }
}

// ════════════════════════════════════════
// START / STOP
// ════════════════════════════════════════

export function startDeployWorker(): void {
  if (workerTimer) return;

  console.log('[deploy-worker] Starting deploy worker (interval: 10s)');
  workerTimer = setInterval(processTick, 10_000);

  console.log('[deploy-watchdog] Starting watchdog (interval: 2min)');
  watchdogTimer = setInterval(watchdogTick, 2 * 60 * 1000);

  // Run first tick after short delay
  setTimeout(processTick, 5_000);
}

export function stopDeployWorker(): void {
  if (workerTimer) {
    clearInterval(workerTimer);
    workerTimer = null;
    console.log('[deploy-worker] Stopped');
  }
  if (watchdogTimer) {
    clearInterval(watchdogTimer);
    watchdogTimer = null;
    console.log('[deploy-watchdog] Stopped');
  }

  // Logout all clients
  for (const [k, c] of zabbixClients) {
    c.logout().catch(() => {});
    zabbixClients.delete(k);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

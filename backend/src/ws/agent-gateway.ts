// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent WebSocket Gateway
// ─────────────────────────────────────────────
import { WebSocketServer, WebSocket as WS, RawData } from 'ws';
import crypto from 'crypto';
import { config } from '../config.js';
import { FastifyInstance } from 'fastify';
import { MessageType, ANTI_REPLAY_WINDOW_MS } from '@massvision/shared';
import * as agentService from '../services/agent.service.js';
import * as jobService from '../services/job.service.js';
import { ingestSecurityEvent } from '../services/edr.service.js';

declare module 'fastify' {
  interface FastifyInstance {
    agentSockets: Map<string, WS>;
    uiSockets: Set<WS>;
    broadcastToUI: (event: string, data: unknown) => void;
  }
}

// Nonce replay cache
const recentNonces = new Set<string>();
const NONCE_CLEANUP_INTERVAL = 60_000;

const agentSecretCache = new Map<string, { secret: string; expiresAt: number }>();
const AGENT_SECRET_CACHE_TTL_MS = 10 * 60_000;

function safeTimingEqualHex(aHex: string, bHex: string): boolean {
  try {
    const a = Buffer.from(aHex, 'hex');
    const b = Buffer.from(bHex, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function canonicalizeJson(value: any): any {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map(canonicalizeJson);
  if (typeof value !== 'object') return value;

  const out: Record<string, any> = {};
  for (const k of Object.keys(value).sort()) {
    out[k] = canonicalizeJson(value[k]);
  }
  return out;
}

function hmacPayloadForMessage(msg: any): string {
  const clone = { ...msg };
  delete clone.hmac;
  // The Rust agent uses serde_json::to_string on a map which sorts keys by default.
  // Use a stable canonical JSON encoding here so HMAC verification matches cross-language.
  return JSON.stringify(canonicalizeJson(clone));
}

function hmacPayloadCandidates(msg: any): string[] {
  // Different agent builds / JSON implementations may preserve insertion order or sort keys.
  // Accept both encodings for compatibility.
  const clone = { ...msg };
  delete clone.hmac;
  return [
    JSON.stringify(clone),
    JSON.stringify(canonicalizeJson(clone)),
  ];
}

function parseJsonString(raw: string, start: number): { value: string; end: number } | null {
  // Minimal JSON string parser (enough for top-level keys).
  if (raw[start] !== '"') return null;
  let i = start + 1;
  let out = '';
  while (i < raw.length) {
    const ch = raw[i];
    if (ch === '"') return { value: out, end: i + 1 };
    if (ch === '\\') {
      i++;
      if (i >= raw.length) return null;
      const esc = raw[i];
      switch (esc) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          const hex = raw.slice(i + 1, i + 5);
          if (hex.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(hex)) return null;
          out += String.fromCharCode(parseInt(hex, 16));
          i += 4;
          break;
        }
        default:
          return null;
      }
      i++;
      continue;
    }
    out += ch;
    i++;
  }
  return null;
}

function skipWs(raw: string, i: number): number {
  while (i < raw.length) {
    const c = raw[i];
    if (c !== ' ' && c !== '\t' && c !== '\n' && c !== '\r') return i;
    i++;
  }
  return i;
}

function scanJsonValueEnd(raw: string, start: number): number | null {
  // Returns index (exclusive) for the end of a JSON value starting at `start`.
  let i = skipWs(raw, start);
  if (i >= raw.length) return null;

  const first = raw[i];
  if (first === '"') {
    const s = parseJsonString(raw, i);
    return s ? s.end : null;
  }

  if (first === '{' || first === '[') {
    const open = first;
    const close = first === '{' ? '}' : ']';
    let depth = 0;
    while (i < raw.length) {
      const ch = raw[i];
      if (ch === '"') {
        const s = parseJsonString(raw, i);
        if (!s) return null;
        i = s.end;
        continue;
      }
      if (ch === open) depth++;
      if (ch === close) {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
    return null;
  }

  // number | true | false | null
  while (i < raw.length) {
    const ch = raw[i];
    if (ch === ',' || ch === '}' || ch === ']' || ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      return i;
    }
    i++;
  }
  return i;
}

function stripTopLevelHmac(raw: string): string | null {
  // Build a raw JSON object string without the top-level "hmac" property, preserving the original
  // raw value substrings (important for float formatting like 0.0 vs 0).
  let i = skipWs(raw, 0);
  if (raw[i] !== '{') return null;
  i++;

  const keptPairs: string[] = [];
  let removed = false;

  while (true) {
    i = skipWs(raw, i);
    if (i >= raw.length) return null;
    if (raw[i] === '}') break;

    const keyStart = i;
    const key = parseJsonString(raw, i);
    if (!key) return null;
    i = skipWs(raw, key.end);
    if (raw[i] !== ':') return null;
    i++;

    const valueEnd = scanJsonValueEnd(raw, i);
    if (valueEnd === null) return null;

    const pairRaw = raw.slice(keyStart, valueEnd);
    if (key.value === 'hmac') removed = true;
    else keptPairs.push(pairRaw);

    i = skipWs(raw, valueEnd);
    if (raw[i] === ',') {
      i++;
      continue;
    }
    if (raw[i] === '}') break;
    return null;
  }

  if (!removed) return null;
  return `{${keptPairs.join(',')}}`;
}

function verifyHMAC(payload: string, receivedHmac: string, secret: string): boolean {
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return safeTimingEqualHex(expected, receivedHmac);
}

async function getAgentSecret(fastify: FastifyInstance, agentId: string): Promise<string | null> {
  const cached = agentSecretCache.get(agentId);
  if (cached && cached.expiresAt > Date.now()) return cached.secret;

  const { rows } = await fastify.pg.query(`SELECT agent_secret FROM agents WHERE id = $1`, [agentId]);
  const secret = rows[0]?.agent_secret ? String(rows[0].agent_secret) : null;
  if (secret) agentSecretCache.set(agentId, { secret, expiresAt: Date.now() + AGENT_SECRET_CACHE_TTL_MS });
  return secret;
}

function remoteIp(ws: WS): string | undefined {
  try {
    const s = (ws as any)?._socket;
    const ip = s?.remoteAddress ? String(s.remoteAddress) : undefined;
    return ip;
  } catch {
    return undefined;
  }
}

export function setupAgentGateway(fastify: FastifyInstance) {
  const agentSockets = new Map<string, WS>();
  const uiSockets = new Set<WS>();

  // Decorate Fastify instance
  fastify.decorate('agentSockets', agentSockets);
  fastify.decorate('uiSockets', uiSockets);
  fastify.decorate('broadcastToUI', (event: string, data: unknown) => {
    const msg = JSON.stringify({ type: event, payload: data });
    for (const ws of uiSockets) {
      if (ws.readyState === WS.OPEN) ws.send(msg);
    }
  });

  // ── Agent WS (port wsPort) ──
  const wss = new WebSocketServer({ port: config.wsPort, path: '/ws/agent' });
  fastify.log.info(`Agent WS gateway listening on port ${config.wsPort}`);

  wss.on('connection', (ws: WS) => {
    let agentId: string | null = null;
    fastify.log.info({ ip: remoteIp(ws) }, 'Agent WS connected');

    ws.on('message', async (raw: RawData) => {
      try {
        const text = raw.toString();
        const msg = JSON.parse(text);

        // Validate HMAC (skip for enroll_request which uses token auth)
        if (msg.type !== MessageType.EnrollRequest) {
          const idForHmac = typeof msg.agent_id === 'string' ? msg.agent_id : '';
          if (!idForHmac) {
            ws.send(JSON.stringify({ type: 'error', message: 'Missing agent_id' }));
            return;
          }
          const secret = await getAgentSecret(fastify, idForHmac);
          if (!secret) {
            fastify.log.warn({ agent_id: idForHmac, ip: remoteIp(ws) }, 'Agent WS message for unknown agent_id');
            ws.send(JSON.stringify({ type: 'error', message: 'Unknown agent_id' }));
            ws.close();
            return;
          }

          const rawWithoutHmac = stripTopLevelHmac(text);
          const candidates = [
            ...(rawWithoutHmac ? [rawWithoutHmac] : []),
            ...hmacPayloadCandidates(msg),
          ];
          const ok = Boolean(msg.hmac) && candidates.some((payload) =>
            verifyHMAC(payload, msg.hmac, secret) || verifyHMAC(payload, msg.hmac, config.hmac.secret),
          );

          if (!ok) {
            fastify.log.warn({ agent_id: idForHmac, ip: remoteIp(ws), msg_type: msg.type }, 'Agent WS HMAC verification failed');
            ws.send(JSON.stringify({ type: 'error', message: 'HMAC verification failed' }));
            return;
          }
          // Anti-replay
          if (recentNonces.has(msg.nonce)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Nonce replay detected' }));
            return;
          }
          if (msg.ts && Date.now() - msg.ts > ANTI_REPLAY_WINDOW_MS) {
            ws.send(JSON.stringify({ type: 'error', message: 'Message expired' }));
            return;
          }
          recentNonces.add(msg.nonce);
        }

        switch (msg.type) {
          case MessageType.EnrollRequest: {
            const p = msg.payload;
            // Validate enrollment token
            const token = await agentService.validateEnrollmentToken(fastify, p.enrollment_token);
            if (!token) {
              fastify.log.warn({ ip: remoteIp(ws) }, 'Agent enrollment failed: invalid token');
              ws.send(JSON.stringify({
                type: MessageType.EnrollResponse,
                payload: { success: false, error: 'Invalid enrollment token' },
              }));
              ws.close();
              return;
            }
            const agent = await agentService.enrollAgent(fastify, {
              hostname: p.hostname,
              os: p.os,
              os_version: p.os_version ?? null,
              arch: p.arch,
              agent_version: p.agent_version,
              token_id: token.id,
              org_id: token.org_id,
              site_id: token.site_id ?? null,
              company_id: p.company_id ?? token.company_id ?? null,
              folder_id: p.folder_id ?? token.folder_id ?? null,
              last_ip: remoteIp(ws) ?? null,
            });
            agentId = agent.id;
            agentSockets.set(agentId!, ws);
            fastify.log.info({ agent_id: agent.id, hostname: p.hostname, ip: remoteIp(ws) }, 'Agent enrolled');
            ws.send(JSON.stringify({
              type: MessageType.EnrollResponse,
              payload: {
                success: true,
                agent_id: agent.id,
                org_id: agent.org_id,
                agent_secret: agent.agent_secret,
                hmac_key: agent.agent_secret, // backward compatible for older agents
                server_url: config.apiBaseUrl,
                heartbeat_interval_sec: config.agentOfflineThresholdSecs / 2,
              },
            }));
            agentSecretCache.set(agent.id, { secret: String(agent.agent_secret), expiresAt: Date.now() + AGENT_SECRET_CACHE_TTL_MS });
            fastify.broadcastToUI('agent:enrolled', { agent_id: agent.id, hostname: p.hostname });
            break;
          }

          case MessageType.Heartbeat: {
            agentId = msg.agent_id;
            agentSockets.set(agentId!, ws);
            const p = msg.payload;
            const usedMb = Number(p.memory_used_mb ?? NaN);
            const totalMb = Number(p.memory_total_mb ?? NaN);
            const memPercent = Number.isFinite(usedMb) && Number.isFinite(totalMb) && totalMb > 0 ? (usedMb / totalMb) * 100 : undefined;
            await agentService.heartbeat(fastify, agentId!, {
              last_ip: remoteIp(ws),
              agent_version: p.agent_version,
              cpu_percent: p.cpu_percent,
              mem_percent: memPercent,
              disk_percent: p.disk_percent,
            });
            // Send pending jobs
            const pending = await jobService.getPendingJobs(fastify, agentId!);
            for (const job of pending) {
              // Send both "payload" and "job" shapes to stay compatible with older agents.
              ws.send(JSON.stringify({ type: MessageType.JobAssign, payload: job, job }));
              await jobService.updateJobStatus(fastify, job.id, 'dispatched');
            }
            break;
          }

          case MessageType.Capabilities: {
            if (msg.agent_id) {
              await agentService.updateCapabilities(fastify, msg.agent_id, msg.payload);
            }
            break;
          }

          case MessageType.MetricsPush: {
            // Store latest metrics (update agent row)
            if (msg.agent_id) {
              const p = msg.payload;
              const memUsedBytes: number | undefined =
                typeof p.memory_used_bytes === 'number' ? p.memory_used_bytes
                  : (typeof p.memory_used_mb === 'number' ? p.memory_used_mb * 1048576 : undefined);
              const memTotalBytes: number | undefined =
                typeof p.memory_total_bytes === 'number' ? p.memory_total_bytes
                  : (typeof p.memory_total_mb === 'number' ? p.memory_total_mb * 1048576 : undefined);
              const diskUsedBytes: number | undefined =
                typeof p.disk_used_bytes === 'number' ? p.disk_used_bytes
                  : (typeof p.disk_used_gb === 'number' ? p.disk_used_gb * 1073741824 : undefined);
              const diskTotalBytes: number | undefined =
                typeof p.disk_total_bytes === 'number' ? p.disk_total_bytes
                  : (typeof p.disk_total_gb === 'number' ? p.disk_total_gb * 1073741824 : undefined);

              const memPercent =
                memUsedBytes !== undefined && memTotalBytes !== undefined && memTotalBytes > 0
                  ? (memUsedBytes / memTotalBytes) * 100
                  : undefined;
              const diskPercent =
                diskUsedBytes !== undefined && diskTotalBytes !== undefined && diskTotalBytes > 0
                  ? (diskUsedBytes / diskTotalBytes) * 100
                  : undefined;
              await agentService.heartbeat(fastify, msg.agent_id, {
                cpu_percent: p.cpu_percent,
                mem_percent: memPercent,
                disk_percent: diskPercent,
              });

              // Store time-series data
              try {
                const agent = await agentService.getAgentById(fastify, msg.agent_id);
                if (agent) {
                  await fastify.pg.query(
                    `INSERT INTO metrics_timeseries (agent_id, org_id, collected_at, cpu_percent, memory_used_mb, memory_total_mb,
                       disk_used_gb, disk_total_gb, network_rx_bytes, network_tx_bytes, processes_count)
                     VALUES ($1, $2, now(), $3, $4, $5, $6, $7, $8, $9, $10)`,
                    [
                      msg.agent_id, agent.org_id,
                      p.cpu_percent ?? 0,
                      memUsedBytes !== undefined ? memUsedBytes / 1048576 : (p.memory_used_mb ?? 0),
                      memTotalBytes !== undefined ? memTotalBytes / 1048576 : (p.memory_total_mb ?? 0),
                      diskUsedBytes !== undefined ? diskUsedBytes / 1073741824 : (p.disk_used_gb ?? 0),
                      diskTotalBytes !== undefined ? diskTotalBytes / 1073741824 : (p.disk_total_gb ?? 0),
                      p.net_rx_bytes ?? 0,
                      p.net_tx_bytes ?? 0,
                      (p.process_count ?? p.processes_count ?? 0),
                    ],
                  );
                }
              } catch (err) {
                fastify.log.warn({ err }, 'Failed to store time-series metric');
              }

              fastify.broadcastToUI('agent:metrics', { agent_id: msg.agent_id, metrics: p });
            }
            break;
          }

          case MessageType.InventoryPush: {
            // Update agent record with inventory data
            if (msg.agent_id) {
              const p = msg.payload;
              await fastify.pg.query(
                `UPDATE agents SET hostname = COALESCE($2, hostname), os = COALESCE($3, os),
                 arch = COALESCE($4, arch), inventory = $5, last_seen_at = now()
                 WHERE id = $1`,
                [msg.agent_id, p.hostname, p.os, p.arch, JSON.stringify(p)],
              );
              fastify.broadcastToUI('agent:inventory', { agent_id: msg.agent_id });
            }
            break;
          }

          case MessageType.SecurityEventPush: {
            // Ingest into EDR pipeline
            if (msg.agent_id) {
              const agent = await agentService.getAgentById(fastify, msg.agent_id);
              if (agent) {
                await ingestSecurityEvent(agent.org_id, msg.agent_id, msg.payload);
              }
              fastify.broadcastToUI('edr:event', { agent_id: msg.agent_id, event: msg.payload });
            }
            break;
          }

          case MessageType.JobAck: {
            const p = msg.payload;
            const newStatus = p.status === 'running' ? 'running' : 'failed';
            await jobService.updateJobStatus(fastify, p.job_id, newStatus, p.reason ? { reason: p.reason } : undefined);
            fastify.broadcastToUI('job:status', { job_id: p.job_id, status: newStatus });
            break;
          }

          case MessageType.JobResult: {
            const p = msg.payload;
            const status = p.status === 'success' ? 'completed' : 'failed';
            await jobService.updateJobStatus(fastify, p.job_id, status, {
              exit_code: p.exit_code,
              stdout: p.stdout,
              stderr: p.stderr,
              error: p.error,
              artifacts: p.artifacts,
              duration_ms: p.duration_ms,
            });
            fastify.broadcastToUI('job:result', { job_id: p.job_id, status, exit_code: p.exit_code });
            break;
          }

          case MessageType.StreamOutput: {
            // Forward stream to UI sockets
            fastify.broadcastToUI('stream:output', { agent_id: msg.agent_id, ...msg.payload });
            break;
          }

          default:
            fastify.log.warn({ type: msg.type }, 'Unknown agent message type');
        }
      } catch (err) {
        fastify.log.error({ err }, 'Error processing agent WS message');
      }
    });

    ws.on('close', () => {
      if (agentId) {
        agentSockets.delete(agentId);
        agentService.updateAgentStatus(fastify, agentId, 'offline').catch(() => {});
        fastify.broadcastToUI('agent:offline', { agent_id: agentId });
      }
    });

    ws.on('error', (err: Error) => {
      fastify.log.error({ err, agentId }, 'Agent WS error');
    });
  });

  // ── UI WS (same HTTP server, path /ws/ui) ──
  const uiWss = new WebSocketServer({ noServer: true });
  const httpServer = fastify.server;

  httpServer.on('upgrade', (request: any, socket: any, head: any) => {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (url.pathname === '/ws/ui') {
      // Simple token check from query
      const token = url.searchParams.get('token');
      if (!token) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      try {
        (fastify as any).jwt.verify(token);
      } catch {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      uiWss.handleUpgrade(request, socket, head, (ws: WS) => {
        uiSockets.add(ws);
        ws.on('close', () => uiSockets.delete(ws));
        ws.on('error', () => uiSockets.delete(ws));
      });
    }
  });

  // ── Periodic cleanup ──
  const cleanupInterval = setInterval(() => {
    recentNonces.clear();
  }, NONCE_CLEANUP_INTERVAL);

  // Periodic stale-agent check
  const staleInterval = setInterval(async () => {
    try {
      await agentService.markStaleAgentsOffline(fastify, config.agentOfflineThresholdSecs);
    } catch (err) {
      fastify.log.error({ err }, 'Error marking stale agents offline');
    }
  }, 30_000);

  // Periodic job timeout check
  const jobTimeoutInterval = setInterval(async () => {
    try {
      await jobService.timeoutExpiredJobs(fastify);
    } catch (err) {
      fastify.log.error({ err }, 'Error timing out expired jobs');
    }
  }, 60_000);

  // Cleanup on close
  fastify.addHook('onClose', async () => {
    clearInterval(cleanupInterval);
    clearInterval(staleInterval);
    clearInterval(jobTimeoutInterval);
    wss.close();
    uiWss.close();
  });
}

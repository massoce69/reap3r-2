// ------------------------------------------------------------
// MASSVISION Reap3r — Agent WebSocket Gateway (Protocol v1)
// ------------------------------------------------------------
//
// P0 requirements:
// - Single protocol source of truth: @massvision/shared (shared/src/protocol.ts)
// - Enrollment is the only unsigned message.
// - All other agent messages must be signed:
//   sig = HMAC_SHA256(HMAC_SECRET, canonical_json(envelope_without_sig))
// - Close WS on invalid signature (fail-closed).
//
import { WebSocketServer, WebSocket as WS, RawData } from 'ws';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { FastifyInstance } from 'fastify';
import { config } from '../config.js';
import {
  MessageType,
  ANTI_REPLAY_WINDOW_MS,
  MessageEnvelopeSchema,
  canonicalJsonStringify,
  EnrollRequestPayload,
  HeartbeatPayload,
  MetricsPushPayload,
  InventoryPushPayload,
  CapabilitiesPayload,
  JobAckPayload,
  JobResultPayload,
  StreamOutputPayload,
} from '@massvision/shared';

import * as agentService from '../services/agent.service.js';
import * as jobService from '../services/job.service.js';
import { ingestSecurityEvent } from '../services/edr.service.js';

declare module 'fastify' {
  interface FastifyInstance {
    agentSockets: Map<string, WS>;
    uiSockets: Set<WS>;
    broadcastToUI: (event: string, data: unknown) => void;
    agentWsPort?: number;
  }
}

// Nonce replay cache (best-effort).
const recentNonces = new Set<string>();
const NONCE_CLEANUP_INTERVAL_MS = 60_000;

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

function computeSig(envelopeWithoutSig: any, secret: string): string {
  const canonical = canonicalJsonStringify(envelopeWithoutSig);
  return crypto.createHmac('sha256', secret).update(canonical).digest('hex');
}

function verifySig(msg: any, secret: string): boolean {
  const received = typeof msg?.sig === 'string' ? msg.sig : '';
  if (!received) return false;
  const clone = { ...msg };
  delete (clone as any).sig;
  const expected = computeSig(clone, secret);
  return safeTimingEqualHex(expected, received);
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

function sendSigned(ws: WS, secret: string, data: Omit<any, 'sig'>) {
  const sig = computeSig(data, secret);
  ws.send(JSON.stringify({ ...data, sig }));
}

function nowEnvelopeBase(agentId: string, type: string, payload: any, extra?: Partial<any>) {
  return {
    type,
    ts: Date.now(),
    nonce: uuidv4(),
    traceId: uuidv4(),
    agentId,
    payload,
    ...(extra ?? {}),
  };
}

export function setupAgentGateway(fastify: FastifyInstance) {
  const agentSockets = new Map<string, WS>();
  const uiSockets = new Set<WS>();

  fastify.decorate('agentSockets', agentSockets);
  fastify.decorate('uiSockets', uiSockets);
  fastify.decorate('broadcastToUI', (event: string, data: unknown) => {
    const msg = JSON.stringify({ type: event, payload: data });
    for (const ws of uiSockets) {
      if (ws.readyState === WS.OPEN) ws.send(msg);
    }
  });

  // Agent WS server is on a dedicated port (proxies should forward /ws/agent to it).
  const wss = new WebSocketServer({ port: config.wsPort, path: '/ws/agent' });
  const addr: any = wss.address();
  const actualPort = typeof addr === 'object' && addr ? Number(addr.port) : config.wsPort;
  fastify.decorate('agentWsPort', actualPort);
  fastify.log.info(`Agent WS gateway listening on port ${actualPort}`);

  // Ping/pong keepalive.
  const pingInterval = setInterval(() => {
    for (const ws of wss.clients) {
      const anyWs: any = ws as any;
      if (anyWs.isAlive === false) {
        try { ws.terminate(); } catch {}
        continue;
      }
      anyWs.isAlive = false;
      try { ws.ping(); } catch {}
    }
  }, 30_000);

  wss.on('connection', (ws: WS) => {
    let agentId: string | null = null;
    (ws as any).isAlive = true;
    ws.on('pong', () => { (ws as any).isAlive = true; });

    fastify.log.info({ ip: remoteIp(ws) }, 'Agent WS connected');
    if ((fastify as any).metrics?.wsConnections) (fastify as any).metrics.wsConnections.inc();

    ws.on('message', async (raw: RawData) => {
      const text = raw.toString();

      try {
        const msg = JSON.parse(text);
        const parsed = MessageEnvelopeSchema.safeParse(msg);
        if (!parsed.success) {
          ws.send(JSON.stringify({ type: 'error', payload: { message: 'Invalid message envelope' } }));
          ws.close();
          return;
        }

        // Fail-closed signature verification (except enroll_request).
        if (msg.type !== MessageType.EnrollRequest) {
          if (!verifySig(msg, config.hmac.secret)) {
            fastify.log.warn({ agentId: msg.agentId, ip: remoteIp(ws), msg_type: msg.type }, 'Agent WS signature verification failed');
            if ((fastify as any).metrics?.wsAuthFailed) (fastify as any).metrics.wsAuthFailed.inc();
            ws.send(JSON.stringify({ type: 'error', payload: { message: 'Signature verification failed' } }));
            ws.close();
            return;
          }

          // Anti-replay.
          if (recentNonces.has(msg.nonce)) {
            ws.send(JSON.stringify({ type: 'error', payload: { message: 'Nonce replay detected' } }));
            ws.close();
            return;
          }
          if (Date.now() - msg.ts > ANTI_REPLAY_WINDOW_MS) {
            ws.send(JSON.stringify({ type: 'error', payload: { message: 'Message expired' } }));
            ws.close();
            return;
          }
          recentNonces.add(msg.nonce);
        }

        switch (msg.type) {
          case MessageType.EnrollRequest: {
            const pParsed = EnrollRequestPayload.safeParse(msg.payload);
            if (!pParsed.success) {
              ws.send(JSON.stringify(nowEnvelopeBase(
                '00000000-0000-0000-0000-000000000000',
                MessageType.EnrollResponse,
                { success: false, error: 'Invalid enroll payload', hmac_key: config.hmac.secret, server_url: config.apiBaseUrl, heartbeat_interval_sec: 10 },
              )));
              ws.close();
              return;
            }
            const p = pParsed.data;

            const token = await agentService.validateEnrollmentToken(fastify, p.enrollment_token);
            if (!token) {
              fastify.log.warn({ ip: remoteIp(ws) }, 'Agent enrollment failed: invalid token');
              ws.send(JSON.stringify(nowEnvelopeBase(
                '00000000-0000-0000-0000-000000000000',
                MessageType.EnrollResponse,
                { success: false, error: 'Invalid enrollment token', hmac_key: config.hmac.secret, server_url: config.apiBaseUrl, heartbeat_interval_sec: 10 },
              )));
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

            const aid = String(agent.id);
            agentId = aid;
            agentSockets.set(aid, ws);
            fastify.log.info({ agent_id: agent.id, hostname: p.hostname, ip: remoteIp(ws) }, 'Agent enrolled');

            // v1: hmac_key is the backend HMAC secret (global). Enroll response is unsigned (agent learns hmac_key here).
            ws.send(JSON.stringify(nowEnvelopeBase(aid, MessageType.EnrollResponse, {
              success: true,
              agent_id: aid,
              org_id: agent.org_id,
              hmac_key: config.hmac.secret,
              server_url: config.apiBaseUrl,
              heartbeat_interval_sec: 10,
            }, { orgId: agent.org_id })));

            fastify.broadcastToUI('agent:enrolled', { agent_id: agent.id, hostname: p.hostname });
            break;
          }

          case MessageType.Capabilities: {
            const pParsed = CapabilitiesPayload.safeParse(msg.payload);
            if (!pParsed.success) break;
            const aid = String(msg.agentId);
            agentId = aid;
            agentSockets.set(aid, ws);
            await agentService.updateCapabilities(fastify, aid, msg.payload as any);
            break;
          }

          case MessageType.Heartbeat: {
            const pParsed = HeartbeatPayload.safeParse(msg.payload);
            if (!pParsed.success) break;
            const aid = String(msg.agentId);
            agentId = aid;
            agentSockets.set(aid, ws);

            const p = pParsed.data;
            await agentService.heartbeat(fastify, aid, {
              last_ip: remoteIp(ws),
              mem_percent: p.memory_percent,
              disk_percent: p.disk_percent,
            });

            // Dispatch pending jobs.
            const pending = await jobService.getPendingJobs(fastify, aid);
            for (const job of pending) {
              const payload = {
                job_id: job.id,
                name: job.type,
                args: job.payload ?? {},
                timeout_sec: job.timeout_secs ?? 300,
                created_at: new Date(job.created_at).toISOString(),
              };
              const env = nowEnvelopeBase(aid, MessageType.JobAssign, payload);
              sendSigned(ws, config.hmac.secret, env);
              await jobService.updateJobStatus(fastify, job.id, 'dispatched');
            }
            break;
          }

          case MessageType.MetricsPush: {
            const pParsed = MetricsPushPayload.safeParse(msg.payload);
            if (!pParsed.success) break;
            const aid = String(msg.agentId);
            agentId = aid;
            agentSockets.set(aid, ws);

            const p = pParsed.data;
            const memPercent = p.memory_total_bytes > 0 ? (p.memory_used_bytes / p.memory_total_bytes) * 100 : undefined;
            const diskPercent = p.disk_total_bytes > 0 ? (p.disk_used_bytes / p.disk_total_bytes) * 100 : undefined;
            await agentService.heartbeat(fastify, aid, {
              cpu_percent: p.cpu_percent,
              mem_percent: memPercent,
              disk_percent: diskPercent,
            });

            // Store time-series in existing schema (MB/GB floats).
            try {
              const agent = await agentService.getAgentById(fastify, aid);
              if (agent) {
                await fastify.pg.query(
                  `INSERT INTO metrics_timeseries (
                     agent_id, org_id, collected_at, cpu_percent,
                     memory_used_mb, memory_total_mb, disk_used_gb, disk_total_gb,
                     network_rx_bytes, network_tx_bytes, processes_count
                   ) VALUES ($1, $2, now(), $3, $4, $5, $6, $7, $8, $9, $10)`,
                  [
                    aid,
                    agent.org_id,
                    p.cpu_percent,
                    p.memory_used_bytes / 1048576,
                    p.memory_total_bytes / 1048576,
                    p.disk_used_bytes / 1073741824,
                    p.disk_total_bytes / 1073741824,
                    p.net_rx_bytes ?? 0,
                    p.net_tx_bytes ?? 0,
                    p.process_count ?? 0,
                  ],
                );
              }
            } catch (err) {
              fastify.log.warn({ err }, 'Failed to store time-series metric');
            }

            fastify.broadcastToUI('agent:metrics', { agent_id: aid, metrics: p });
            break;
          }

          case MessageType.InventoryPush: {
            const pParsed = InventoryPushPayload.safeParse(msg.payload);
            if (!pParsed.success) break;
            const aid = String(msg.agentId);
            agentId = aid;
            agentSockets.set(aid, ws);
            const p = pParsed.data;

            await fastify.pg.query(
              `UPDATE agents
               SET hostname = COALESCE($2, hostname),
                   os = COALESCE($3, os),
                   arch = COALESCE($4, arch),
                   inventory = $5,
                   last_seen_at = now(),
                   status = 'online'
               WHERE id = $1`,
              [aid, p.hostname, p.os, p.arch, JSON.stringify(p)],
            );

            // Snapshot (immutable)
            await fastify.pg.query(
              `INSERT INTO inventory_snapshots (agent_id, collected_at, data)
               VALUES ($1, now(), $2)`,
              [aid, JSON.stringify(p)],
            );

            fastify.broadcastToUI('agent:inventory', { agent_id: aid });
            break;
          }

          case MessageType.SecurityEventPush: {
            const aid = String(msg.agentId);
            agentId = aid;
            agentSockets.set(aid, ws);
            const agent = await agentService.getAgentById(fastify, aid);
            if (agent) {
              await ingestSecurityEvent(agent.org_id, aid, msg.payload);
            }
            fastify.broadcastToUI('edr:event', { agent_id: aid, event: msg.payload });
            break;
          }

          case MessageType.JobAck: {
            const pParsed = JobAckPayload.safeParse(msg.payload);
            if (!pParsed.success) break;
            const p = pParsed.data;
            if (p.status === 'running') {
              await jobService.updateJobStatus(fastify, p.job_id, 'running');
            } else {
              await jobService.updateJobStatus(fastify, p.job_id, 'failed', { error: p.reason ?? 'rejected' });
            }
            fastify.broadcastToUI('job:status', { job_id: p.job_id, status: p.status });
            break;
          }

          case MessageType.JobResult: {
            const pParsed = JobResultPayload.safeParse(msg.payload);
            if (!pParsed.success) break;
            const p = pParsed.data;
            const status = p.status === 'success' ? 'completed' : (p.status === 'timeout' ? 'failed' : 'failed');

            await jobService.updateJobStatus(fastify, p.job_id, status, {
              exit_code: p.exit_code,
              stdout: p.stdout,
              stderr: p.stderr,
              duration_ms: p.duration_ms,
              error: p.error,
            });

            // Immutable job_results row.
            try {
              await fastify.pg.query(
                `INSERT INTO job_results (job_id, agent_id, exit_code, stdout, stderr, data, duration_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
                [
                  p.job_id,
                  msg.agentId,
                  p.exit_code ?? null,
                  p.stdout ?? null,
                  p.stderr ?? null,
                  JSON.stringify({ status: p.status, error: p.error ?? null }),
                  p.duration_ms ?? null,
                ],
              );
            } catch (err) {
              fastify.log.warn({ err }, 'Failed to store job_results');
            }

            fastify.broadcastToUI('job:result', { job_id: p.job_id, status: p.status, exit_code: p.exit_code });
            break;
          }

          case MessageType.StreamOutput: {
            const soParsed = StreamOutputPayload.safeParse(msg.payload);
            if (!soParsed.success) {
              fastify.log.warn({ err: soParsed.error?.message }, 'StreamOutput parse failed');
              break;
            }
            const so = soParsed.data;
            // Relay frames to UI WebSocket subscribers
            if (so.stream_type === 'frame') {
              const uiCount = Array.from(uiSockets).filter(s => s.readyState === WS.OPEN).length;
              if (so.sequence % 10 === 0) {
                fastify.log.info({ seq: so.sequence, uiClients: uiCount, dataLen: so.data.length }, 'RD frame relay');
              }
              fastify.broadcastToUI('rd:frame', {
                agent_id: msg.agentId,
                session_id: so.session_id,
                data: so.data,
                sequence: so.sequence,
              });
            } else {
              // stdout/stderr stream → broadcast as generic stream event
              fastify.broadcastToUI('stream:output', {
                agent_id: msg.agentId,
                session_id: so.session_id,
                stream_type: so.stream_type,
                data: so.data,
                sequence: so.sequence,
              });
            }
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
      if ((fastify as any).metrics?.wsConnections) (fastify as any).metrics.wsConnections.dec();
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

  // UI WS — dedicated port so it works regardless of PM2 mode (cluster/fork)
  const uiWss = new WebSocketServer({ port: config.uiWsPort, path: '/ws/ui' });
  const uiAddr: any = uiWss.address();
  const uiActualPort = typeof uiAddr === 'object' && uiAddr ? Number(uiAddr.port) : config.uiWsPort;
  fastify.log.info(`UI WS gateway listening on port ${uiActualPort}`);

  uiWss.on('connection', (ws: WS, request: any) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    const token = url.searchParams.get('token');
    if (!token) {
      ws.close(4001, 'No token');
      return;
    }
    try {
      (fastify as any).jwt.verify(token);
    } catch {
      ws.close(4001, 'Invalid token');
      return;
    }
    uiSockets.add(ws);
    fastify.log.info({ uiClients: uiSockets.size }, 'UI WS client connected');
    ws.on('close', () => {
      uiSockets.delete(ws);
      fastify.log.info({ uiClients: uiSockets.size }, 'UI WS client disconnected');
    });
    ws.on('error', () => uiSockets.delete(ws));
  });

  // Cleanup.
  const nonceCleanup = setInterval(() => recentNonces.clear(), NONCE_CLEANUP_INTERVAL_MS);
  const staleInterval = setInterval(async () => {
    try {
      await agentService.markStaleAgentsOffline(fastify, config.agentOfflineThresholdSecs);
    } catch (err) {
      fastify.log.error({ err }, 'Error marking stale agents offline');
    }
  }, 30_000);
  const jobTimeoutInterval = setInterval(async () => {
    try {
      await jobService.timeoutExpiredJobs(fastify);
    } catch (err) {
      fastify.log.error({ err }, 'Error timing out expired jobs');
    }
  }, 60_000);

  fastify.addHook('onClose', async () => {
    clearInterval(pingInterval);
    clearInterval(nonceCleanup);
    clearInterval(staleInterval);
    clearInterval(jobTimeoutInterval);
    wss.close();
    uiWss.close();
  });

  return wss;
}

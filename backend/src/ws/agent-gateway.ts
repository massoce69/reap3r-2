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
import { IncomingMessage } from 'node:http';
import { config } from '../config.js';
import {
  Permission,
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
import { hydrateJobPayloadForDispatch } from '../services/job-dispatch.service.js';
import { toV2RunScriptPayload } from '../lib/v2-run-script.js';
import { ingestSecurityEvent, ingestEventBatch } from '../services/edr.service.js';
import * as chatService from '../services/chat.service.js';
import { authenticateAccessToken, hasPermission, isSessionActive } from '../services/auth-session.service.js';

declare module 'fastify' {
  interface FastifyInstance {
    agentSockets: Map<string, WS>;
    agentSocketsV2: Map<string, WS>;
    uiSockets: Set<WS>;
    messagingSockets: Set<WS>;
    broadcastToUI: (event: string, data: unknown) => void;
    broadcastToMessaging: (event: string, data: unknown, orgId?: string) => void;
    agentWsPort?: number;
  }
}

// Nonce replay cache with TTL eviction (no global clear).
const recentNonces = new Map<string, number>();
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

// ── Agent Protocol v2 (Rust) — minimal WS auth ─────────────────────────────
// SignedEnvelope: { payload: string, timestamp: number, nonce: string, hmac: string }
function computeV2HmacHex(agentToken: string, payload: string, timestamp: number, nonce: string): string {
  const mac = crypto.createHmac('sha256', Buffer.from(agentToken, 'utf8'));
  mac.update(Buffer.from(payload, 'utf8'));
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigInt64LE(BigInt(timestamp));
  mac.update(tsBuf);
  mac.update(Buffer.from(nonce, 'utf8'));
  return mac.digest('hex');
}

function safeParseJson(text: string): any | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
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

function normalizeMetricsPayload(input: unknown) {
  const parsed = MetricsPushPayload.safeParse(input);
  if (!parsed.success) return null;
  const p = parsed.data;
  const memPercent = p.memory_total_bytes > 0 ? (p.memory_used_bytes / p.memory_total_bytes) * 100 : undefined;
  const diskPercent = p.disk_total_bytes > 0 ? (p.disk_used_bytes / p.disk_total_bytes) * 100 : undefined;
  return { payload: p, memPercent, diskPercent };
}

function tokenFromRequest(request: IncomingMessage): string | null {
  const url = new URL(request.url ?? '/', `http://${request.headers.host || 'localhost'}`);
  const queryToken = url.searchParams.get('token');
  if (queryToken) return queryToken;

  const auth = request.headers.authorization;
  if (auth?.startsWith('Bearer ')) return auth.slice(7);
  return null;
}

function orgIdFromPayload(data: unknown): string | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const o = data as Record<string, unknown>;
  const v = o.org_id ?? o.orgId;
  return typeof v === 'string' ? v : undefined;
}

function uiEventPermission(event: string): Permission | null {
  if (event === 'chat:message') return Permission.MessageRead;
  if (event === 'edr:event') return Permission.EdrEventsView;
  if (event.startsWith('rd:')) return Permission.RemoteDesktop;
  if (event === 'stream:output') return Permission.JobView;
  if (event.startsWith('agent:')) return Permission.AgentView;
  if (event.startsWith('job:')) return Permission.JobView;
  return null;
}

export function setupAgentGateway(fastify: FastifyInstance) {
  const agentSockets = new Map<string, WS>();
  const agentSocketsV2 = new Map<string, WS>();
  const uiSockets = new Set<WS>();
  const messagingSockets = new Set<WS>();
  const uiSocketOrg = new Map<WS, string>();
  const messagingSocketOrg = new Map<WS, string>();
  const uiSocketSession = new Map<WS, string>();
  const messagingSocketSession = new Map<WS, string>();
  const uiSocketPerms = new Map<WS, Set<Permission>>();
  const messagingSocketPerms = new Map<WS, Set<Permission>>();

  fastify.decorate('agentSockets', agentSockets);
  fastify.decorate('agentSocketsV2', agentSocketsV2);
  fastify.decorate('uiSockets', uiSockets);
  fastify.decorate('messagingSockets', messagingSockets);
  fastify.decorate('broadcastToUI', (event: string, data: unknown) => {
    const targetOrg = orgIdFromPayload(data);
    const requiredPermission = uiEventPermission(event);
    const msg = JSON.stringify({ type: event, payload: data });
    for (const ws of uiSockets) {
      if (ws.readyState !== WS.OPEN) continue;
      if (targetOrg && uiSocketOrg.get(ws) !== targetOrg) continue;
      if (requiredPermission) {
        const perms = uiSocketPerms.get(ws);
        if (!perms?.has(requiredPermission)) continue;
      }
      ws.send(msg);
    }
  });
  fastify.decorate('broadcastToMessaging', (event: string, data: unknown, orgId?: string) => {
    const targetOrg = orgId ?? orgIdFromPayload(data);
    const msg = JSON.stringify({ type: event, payload: data });
    for (const ws of messagingSockets) {
      if (ws.readyState !== WS.OPEN) continue;
      if (targetOrg && messagingSocketOrg.get(ws) !== targetOrg) continue;
      ws.send(msg);
    }
  });

  // Unified WS on the main Fastify HTTP server.
  const wss = new WebSocketServer({ noServer: true });
  const wssV2 = new WebSocketServer({ noServer: true });
  const uiWss = new WebSocketServer({ noServer: true });
  const messagingWss = new WebSocketServer({ noServer: true });

  fastify.decorate('agentWsPort', 0);
  fastify.addHook('onListen', async () => {
    const addr = fastify.server.address();
    const port = typeof addr === 'object' && addr ? Number(addr.port) : config.port;
    fastify.agentWsPort = port;
    fastify.log.info(`Unified WS gateway listening on port ${port} (/ws/agent, /ws/agents, /ws/ui, /ws/messaging)`);
  });

  const upgradeHandler = (request: IncomingMessage, socket: any, head: Buffer) => {
    let pathname = '/';
    try {
      pathname = new URL(request.url ?? '/', `http://${request.headers.host || 'localhost'}`).pathname;
    } catch {
      socket.destroy();
      return;
    }

    const handle = (server: WebSocketServer) => {
      server.handleUpgrade(request, socket, head, (ws) => {
        server.emit('connection', ws, request);
      });
    };

    if (pathname === '/ws/agent') return handle(wss);
    if (pathname === '/ws/agents') return handle(wssV2);
    if (pathname === '/ws/ui') return handle(uiWss);
    if (pathname === '/ws/messaging') return handle(messagingWss);
    socket.destroy();
  };
  fastify.server.on('upgrade', upgradeHandler);

  // ── v2 agent WS: accept auth envelope, then keep socket open ─────────────
  const v2Authed = new Map<WS, { agentId: string }>();

  const handleV2AgentMessage = (agentId: string, raw: RawData) => {
    try {
      const text = raw.toString('utf8');
      const msg = safeParseJson(text);
      if (!msg || typeof msg !== 'object') return;

      // Agent v2 sends: { type: 'stream_output', session_id, stream_type, data, sequence }
      if ((msg as any).type === 'stream_output') {
        const payload = {
          session_id: String((msg as any).session_id ?? ''),
          stream_type: (msg as any).stream_type,
          data: (msg as any).data,
          sequence: Number((msg as any).sequence ?? 0),
        };
        const soParsed = StreamOutputPayload.safeParse(payload);
        if (!soParsed.success) return;
        const so = soParsed.data;

        if (so.stream_type === 'frame') {
          fastify.broadcastToUI('rd:frame', {
            agent_id: agentId,
            session_id: so.session_id,
            data: so.data,
            sequence: so.sequence,
          });
        } else if (so.stream_type === 'error') {
          fastify.broadcastToUI('rd:error', {
            agent_id: agentId,
            session_id: so.session_id,
            error: so.data,
          });
        } else {
          fastify.broadcastToUI('stream:output', {
            agent_id: agentId,
            session_id: so.session_id,
            stream_type: so.stream_type,
            data: so.data,
            sequence: so.sequence,
          });
        }
      }
    } catch {
      // ignore
    }
  };

  const dispatchV2Backlog = async (agentId: string, ws: WS) => {
    try {
      if (ws.readyState !== WS.OPEN) return;
      const { rows } = await fastify.pg.query(
        `SELECT id, type, payload, timeout_secs, priority, created_at
         FROM jobs
         WHERE agent_id = $1
           AND status IN ('pending', 'queued')
           AND type IN ('run_script', 'list_monitors', 'remote_desktop_start', 'remote_desktop_stop')
         ORDER BY created_at ASC
         LIMIT 25`,
        [agentId],
      );

      if (!rows?.length) return;

      let dispatched = 0;
      for (const r of rows) {
        if (ws.readyState !== WS.OPEN) break;
        const jt = String((r as any).type ?? '').toLowerCase();
        const payloadInput = (r as any).payload ?? {};
        const v2Payload = jt === 'run_script' ? toV2RunScriptPayload(payloadInput) : payloadInput;
        const msg = {
          type: 'job',
          job_id: String(r.id),
          job_type: jt,
          payload: v2Payload,
          timeout_secs: Number((r as any).timeout_secs ?? 300) || 300,
          priority: Number(r.priority ?? 0) || 0,
          created_at: new Date(r.created_at).toISOString(),
        };
        ws.send(JSON.stringify(msg));
        await jobService.updateJobStatus(fastify, String(r.id), 'dispatched');
        dispatched++;
      }

      if (dispatched > 0) {
        fastify.log.info({ agentId, dispatched }, '[agents-v2] dispatched backlog run_script jobs');
      }
    } catch (err) {
      fastify.log.warn({ err, agentId }, '[agents-v2] backlog dispatch failed');
    }
  };

  wssV2.on('connection', async (ws, request) => {
    const url = new URL(request.url ?? '/', `http://${request.headers.host || 'localhost'}`);
    const agentId = url.searchParams.get('agent_id') || '';
    const machineId = url.searchParams.get('machine_id') || '';
    const ip = remoteIp(ws);

    if (!agentId) {
      try { ws.close(1008, 'missing agent_id'); } catch {}
      return;
    }

    // Lookup secret
    let agentSecret = '';
    try {
      const { rows } = await fastify.pg.query(`SELECT agent_secret FROM agents WHERE id = $1`, [agentId]);
      agentSecret = rows?.[0]?.agent_secret ? String(rows[0].agent_secret) : '';
    } catch {
      agentSecret = '';
    }
    if (!agentSecret) {
      try { ws.close(1008, 'unknown agent'); } catch {}
      return;
    }

    // First message must be auth envelope
    const onMessage = async (data: RawData) => {
      try {
        const text = data.toString('utf8');
        const env = safeParseJson(text);
        if (!env || typeof env !== 'object') return ws.close(1008, 'invalid envelope');
        const payload = typeof (env as any).payload === 'string' ? (env as any).payload : '';
        const timestamp = typeof (env as any).timestamp === 'number' ? (env as any).timestamp : NaN;
        const nonce = typeof (env as any).nonce === 'string' ? (env as any).nonce : '';
        const hmac = typeof (env as any).hmac === 'string' ? (env as any).hmac : '';
        if (!payload || !Number.isFinite(timestamp) || !nonce || !hmac) return ws.close(1008, 'invalid envelope');

        const ageMs = Math.abs(Date.now() - timestamp);
        if (ageMs > 300_000) return ws.close(1008, 'stale');

        const expected = computeV2HmacHex(agentSecret, payload, timestamp, nonce);
        if (!safeTimingEqualHex(expected, hmac)) return ws.close(1008, 'bad signature');

        const p = safeParseJson(payload);
        if (!p || p.type !== 'auth' || String(p.agent_id || '') !== agentId) return ws.close(1008, 'bad auth');

        v2Authed.set(ws, { agentId });
        agentSocketsV2.set(agentId, ws);
        ws.off('message', onMessage);
        fastify.log.info({ agentId, machineId, ip }, '[agents-v2] WS authenticated');

        ws.on('message', (raw2: RawData) => handleV2AgentMessage(agentId, raw2));

        // Ensure jobs created before WS connect don't stay pending forever.
        await dispatchV2Backlog(agentId, ws);
      } catch {
        try { ws.close(1008, 'error'); } catch {}
      }
    };

    ws.on('message', onMessage);
    ws.on('close', () => {
      v2Authed.delete(ws);
      // Remove socket mapping if it still points to this ws
      for (const [aid, s] of agentSocketsV2) {
        if (s === ws) agentSocketsV2.delete(aid);
      }
    });
  });

  // Ping/pong keepalive.
  const pingInterval = setInterval(() => {
    for (const server of [wss, wssV2, uiWss, messagingWss]) {
      for (const ws of server.clients) {
        const anyWs: any = ws as any;
        if (anyWs.isAlive === false) {
          try { ws.terminate(); } catch {}
          continue;
        }
        anyWs.isAlive = false;
        try { ws.ping(); } catch {}
      }
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
          const now = Date.now();
          const seenAt = recentNonces.get(msg.nonce);
          if (seenAt && now - seenAt <= ANTI_REPLAY_WINDOW_MS) {
            ws.send(JSON.stringify({ type: 'error', payload: { message: 'Nonce replay detected' } }));
            ws.close();
            return;
          }
          if (now - msg.ts > ANTI_REPLAY_WINDOW_MS) {
            ws.send(JSON.stringify({ type: 'error', payload: { message: 'Message expired' } }));
            ws.close();
            return;
          }
          recentNonces.set(msg.nonce, now);
        }

        switch (msg.type) {
          case MessageType.EnrollRequest: {
            const pParsed = EnrollRequestPayload.safeParse(msg.payload);
            if (!pParsed.success) {
              ws.send(JSON.stringify(nowEnvelopeBase(
                '00000000-0000-0000-0000-000000000000',
                MessageType.EnrollResponse,
                { success: false, error: 'Invalid enroll payload' },
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
                { success: false, error: 'Invalid enrollment token' },
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
            // Update agent_version from capabilities modules_version
            const modVer = (msg.payload as any)?.modules_version?.core;
            if (modVer && typeof modVer === 'string') {
              await agentService.heartbeat(fastify, aid, { agent_version: modVer });
            }
            break;
          }

          case MessageType.Heartbeat: {
            const pParsed = HeartbeatPayload.safeParse(msg.payload);
            if (!pParsed.success) break;
            const aid = String(msg.agentId);
            agentId = aid;
            agentSockets.set(aid, ws);

            const p = pParsed.data;
            const heartbeatCpu = typeof (msg.payload as any)?.cpu_percent === 'number'
              ? Number((msg.payload as any).cpu_percent)
              : undefined;
            await agentService.heartbeat(fastify, aid, {
              last_ip: remoteIp(ws),
              cpu_percent: heartbeatCpu,
              mem_percent: p.memory_percent,
              disk_percent: p.disk_percent,
            });

            // Agent v5 embeds full metrics in heartbeat.metrics.
            // Accept either embedded metrics object or full metrics heartbeat payload.
            const embeddedMetrics = (msg.payload as any)?.metrics ?? msg.payload;
            const normalized = normalizeMetricsPayload(embeddedMetrics);
            if (normalized) {
              const m = normalized.payload;
              await agentService.heartbeat(fastify, aid, {
                cpu_percent: m.cpu_percent,
                mem_percent: normalized.memPercent,
                disk_percent: normalized.diskPercent,
              });

              // Persist time-series (same behavior as metrics_push).
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
                      m.cpu_percent,
                      m.memory_used_bytes / 1048576,
                      m.memory_total_bytes / 1048576,
                      m.disk_used_bytes / 1073741824,
                      m.disk_total_bytes / 1073741824,
                      m.net_rx_bytes ?? 0,
                      m.net_tx_bytes ?? 0,
                      m.process_count ?? 0,
                    ],
                  );
                }
              } catch (err) {
                fastify.log.warn({ err }, 'Failed to store heartbeat-embedded time-series metric');
              }

              fastify.broadcastToUI('agent:metrics', { agent_id: aid, metrics: m });
            }

            // Dispatch pending jobs.
            const pending = await jobService.getPendingJobs(fastify, aid);
            for (const job of pending) {
              let args: Record<string, unknown>;
              try {
                args = await hydrateJobPayloadForDispatch(fastify, String(job.org_id), job.payload ?? {});
              } catch (err: any) {
                await jobService.updateJobStatus(fastify, job.id, 'failed', { error: String(err?.message || err) });
                fastify.log.error({ err, job_id: job.id }, 'Failed to hydrate job payload for dispatch');
                continue;
              }
              const payload = {
                job_id: job.id,
                name: job.type,
                args,
                timeout_sec: job.timeout_secs ?? 300,
                created_at: new Date(job.created_at).toISOString(),
              };
              const env = nowEnvelopeBase(aid, MessageType.JobAssign, payload);
              sendSigned(ws, config.hmac.secret, env);
              const isRedispatch = job.status === 'dispatched';
              await jobService.updateJobStatus(fastify, job.id, 'dispatched');
              if (isRedispatch) {
                fastify.log.info({ job_id: job.id, agent_id: aid, dispatch_count: (job.dispatch_count ?? 0) + 1 }, 'Re-dispatching stale update_agent job');
              }
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
            const normalized = normalizeMetricsPayload(p)!;
            await agentService.heartbeat(fastify, aid, {
              cpu_percent: normalized.payload.cpu_percent,
              mem_percent: normalized.memPercent,
              disk_percent: normalized.diskPercent,
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
                    normalized.payload.cpu_percent,
                    normalized.payload.memory_used_bytes / 1048576,
                    normalized.payload.memory_total_bytes / 1048576,
                    normalized.payload.disk_used_bytes / 1073741824,
                    normalized.payload.disk_total_bytes / 1073741824,
                    normalized.payload.net_rx_bytes ?? 0,
                    normalized.payload.net_tx_bytes ?? 0,
                    normalized.payload.process_count ?? 0,
                  ],
                );
              }
            } catch (err) {
              fastify.log.warn({ err }, 'Failed to store time-series metric');
            }

            fastify.broadcastToUI('agent:metrics', { agent_id: aid, metrics: normalized.payload });
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
                   agent_version = COALESCE($6, agent_version),
                   last_seen_at = now(),
                   status = 'online'
               WHERE id = $1`,
              [aid, p.hostname, p.os, p.arch, JSON.stringify(p), (p as any).agent_version ?? null],
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

          case MessageType.SecurityEventBatchPush: {
            const aid = String(msg.agentId);
            agentId = aid;
            agentSockets.set(aid, ws);
            const agent = await agentService.getAgentById(fastify, aid);
            if (agent && Array.isArray(msg.payload?.events)) {
              await ingestEventBatch(agent.org_id, aid, msg.payload.events);
              fastify.broadcastToUI('edr:event', { agent_id: aid, batch: true, count: msg.payload.events.length });
            }
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
            } else if (so.stream_type === 'error') {
              // RD capture error → relay to UI as rd:error
              fastify.log.warn({ agent: msg.agentId, error: so.data }, 'RD capture error');
              fastify.broadcastToUI('rd:error', {
                agent_id: msg.agentId,
                session_id: so.session_id,
                error: so.data,
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
  uiWss.on('connection', async (ws: WS, request: IncomingMessage) => {
    const token = tokenFromRequest(request);
    if (!token) {
      ws.close(4001, 'No token');
      return;
    }

    const auth = await authenticateAccessToken(fastify, token);
    if (!auth) {
      ws.close(4001, 'Invalid or revoked session');
      return;
    }
    if (!hasPermission(auth, Permission.DashboardView)) {
      ws.close(4003, 'Missing dashboard:view');
      return;
    }

    const orgId = auth.org_id;
    uiSockets.add(ws);
    uiSocketOrg.set(ws, orgId);
    uiSocketSession.set(ws, auth.session_id);
    uiSocketPerms.set(ws, new Set(auth.permissions));
    (ws as any).isAlive = true;
    ws.on('pong', () => { (ws as any).isAlive = true; });
    fastify.log.info({ uiClients: uiSockets.size, orgId }, 'UI WS client connected');

    // Handle UI -> Agent messages (rd:input relay)
    ws.on('message', (raw: RawData) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'rd:input') {
          const perms = uiSocketPerms.get(ws);
          if (!perms?.has(Permission.RemoteDesktop)) {
            ws.send(JSON.stringify({ type: 'error', payload: { message: 'Missing permission: remote:desktop' } }));
            return;
          }
          const p = msg.payload;
          if (!p?.agent_id) return;
          const agentWs = agentSockets.get(String(p.agent_id));
          if (agentWs && agentWs.readyState === WS.OPEN) {
            const env = nowEnvelopeBase(String(p.agent_id), MessageType.RdInput, {
              input_type: p.input_type,
              session_id: p.session_id,
              x: p.x,
              y: p.y,
              button: p.button,
              delta: p.delta,
              key: p.key,
              vk: p.vk,
              monitor: p.monitor ?? -1,
            });
            sendSigned(agentWs, config.hmac.secret, env);
            return;
          }

          // Fallback to v2 agents WS
          const ws2 = agentSocketsV2.get(String(p.agent_id));
          if (!ws2 || ws2.readyState !== WS.OPEN) return;
          ws2.send(JSON.stringify({
            type: 'rd_input',
            agent_id: String(p.agent_id),
            session_id: p.session_id ?? null,
            input_type: p.input_type,
            x: p.x,
            y: p.y,
            button: p.button,
            delta: p.delta,
            key: p.key,
            vk: p.vk,
            monitor: p.monitor ?? -1,
          }));
        }
      } catch {
        // Ignore malformed UI messages
      }
    });

    ws.on('close', () => {
      uiSockets.delete(ws);
      uiSocketOrg.delete(ws);
      uiSocketSession.delete(ws);
      uiSocketPerms.delete(ws);
      fastify.log.info({ uiClients: uiSockets.size }, 'UI WS client disconnected');
    });
    ws.on('error', () => {
      uiSockets.delete(ws);
      uiSocketOrg.delete(ws);
      uiSocketSession.delete(ws);
      uiSocketPerms.delete(ws);
    });
  });

  messagingWss.on('connection', async (ws: WS, request: IncomingMessage) => {
    const token = tokenFromRequest(request);
    if (!token) {
      ws.close(4001, 'No token');
      return;
    }

    const auth = await authenticateAccessToken(fastify, token);
    if (!auth) {
      ws.close(4001, 'Invalid or revoked session');
      return;
    }
    if (!hasPermission(auth, Permission.MessageRead)) {
      ws.close(4003, 'Missing message:read');
      return;
    }

    const orgId = auth.org_id;
    const userId = auth.id;
    const userName = auth.name || 'Unknown';

    messagingSockets.add(ws);
    messagingSocketOrg.set(ws, orgId);
    messagingSocketSession.set(ws, auth.session_id);
    messagingSocketPerms.set(ws, new Set(auth.permissions));
    (ws as any).isAlive = true;
    ws.on('pong', () => { (ws as any).isAlive = true; });
    fastify.log.info({ messagingClients: messagingSockets.size, orgId }, 'Messaging WS client connected');

    ws.on('message', async (raw: RawData) => {
      // Optional client -> server messaging path (REST remains primary).
      try {
        const msg = JSON.parse(raw.toString());
        if (msg?.type !== 'chat:send') return;
        const perms = messagingSocketPerms.get(ws);
        if (!perms?.has(Permission.MessageWrite)) {
          ws.send(JSON.stringify({ type: 'error', payload: { message: 'Missing permission: message:write' } }));
          return;
        }

        const p = msg.payload || {};
        const channelId = String(p.channel_id || '');
        const body = String(p.body || '').trim();
        if (!channelId || !body) return;

        const created = await chatService.createMessage(channelId, userId, body);
        const payload = {
          channel_id: channelId,
          message: { ...created, user_name: userName, body },
          org_id: orgId,
        };
        fastify.broadcastToMessaging('chat:message', payload, orgId);
        fastify.broadcastToUI('chat:message', payload);
      } catch {
        // Ignore malformed ws message
      }
    });

    ws.on('close', () => {
      messagingSockets.delete(ws);
      messagingSocketOrg.delete(ws);
      messagingSocketSession.delete(ws);
      messagingSocketPerms.delete(ws);
      fastify.log.info({ messagingClients: messagingSockets.size }, 'Messaging WS client disconnected');
    });
    ws.on('error', () => {
      messagingSockets.delete(ws);
      messagingSocketOrg.delete(ws);
      messagingSocketSession.delete(ws);
      messagingSocketPerms.delete(ws);
    });
  });

  // Cleanup.
  const nonceCleanup = setInterval(() => {
    const cutoff = Date.now() - ANTI_REPLAY_WINDOW_MS;
    for (const [nonce, ts] of recentNonces.entries()) {
      if (ts < cutoff) recentNonces.delete(nonce);
    }
  }, NONCE_CLEANUP_INTERVAL_MS);
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
  const wsSessionRevalidateInterval = setInterval(async () => {
    try {
      for (const [ws, sessionId] of uiSocketSession.entries()) {
        if (ws.readyState !== WS.OPEN) continue;
        if (!(await isSessionActive(fastify, sessionId))) {
          ws.close(4001, 'Session revoked');
        }
      }
      for (const [ws, sessionId] of messagingSocketSession.entries()) {
        if (ws.readyState !== WS.OPEN) continue;
        if (!(await isSessionActive(fastify, sessionId))) {
          ws.close(4001, 'Session revoked');
        }
      }
    } catch (err) {
      fastify.log.warn({ err }, 'WS session revalidation failed');
    }
  }, 60_000);

  fastify.addHook('onClose', async () => {
    clearInterval(pingInterval);
    clearInterval(nonceCleanup);
    clearInterval(staleInterval);
    clearInterval(jobTimeoutInterval);
    clearInterval(wsSessionRevalidateInterval);
    fastify.server.off('upgrade', upgradeHandler);
    wss.close();
    uiWss.close();
    messagingWss.close();
  });

  return wss;
}

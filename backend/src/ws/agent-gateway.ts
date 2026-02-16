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

function verifyHMAC(payload: string, receivedHmac: string): boolean {
  const expected = crypto.createHmac('sha256', config.hmac.secret).update(payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(receivedHmac));
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

    ws.on('message', async (raw: RawData) => {
      try {
        const text = raw.toString();
        const msg = JSON.parse(text);

        // Validate HMAC (skip for enroll_request which uses token auth)
        if (msg.type !== MessageType.EnrollRequest) {
          if (!msg.hmac || !verifyHMAC(JSON.stringify({ ...msg, hmac: undefined }), msg.hmac)) {
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
              ws.send(JSON.stringify({ type: MessageType.EnrollResponse, payload: { error: 'Invalid enrollment token' } }));
              ws.close();
              return;
            }
            const agent = await agentService.enrollAgent(fastify, {
              hostname: p.hostname,
              os: p.os,
              arch: p.arch,
              agent_version: p.agent_version,
              token_id: token.id,
              org_id: token.org_id,
              company_id: p.company_id ?? token.company_id ?? null,
              folder_id: p.folder_id ?? token.folder_id ?? null,
              ip_address: null,
            });
            agentId = agent.id;
            agentSockets.set(agentId!, ws);
            ws.send(JSON.stringify({
              type: MessageType.EnrollResponse,
              payload: {
                agent_id: agent.id,
                org_id: agent.org_id,
                hmac_key: config.hmac.secret,
                server_url: config.apiBaseUrl,
                heartbeat_interval_sec: config.agentOfflineThresholdSecs / 2,
              },
            }));
            fastify.broadcastToUI('agent:enrolled', { agent_id: agent.id, hostname: p.hostname });
            break;
          }

          case MessageType.Heartbeat: {
            agentId = msg.agent_id;
            agentSockets.set(agentId!, ws);
            const p = msg.payload;
            await agentService.heartbeat(fastify, agentId!, {
              ip_address: p.ip_addresses?.[0],
              agent_version: p.agent_version,
              cpu_percent: p.cpu_percent,
              mem_percent: p.memory_percent,
              disk_percent: p.disk_percent,
            });
            // Send pending jobs
            const pending = await jobService.getPendingJobs(fastify, agentId!);
            for (const job of pending) {
              ws.send(JSON.stringify({ type: MessageType.JobAssign, payload: job }));
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
              await agentService.heartbeat(fastify, msg.agent_id, {
                cpu_percent: p.cpu_percent,
                mem_percent: (p.memory_used_bytes / p.memory_total_bytes) * 100,
                disk_percent: (p.disk_used_bytes / p.disk_total_bytes) * 100,
              });
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

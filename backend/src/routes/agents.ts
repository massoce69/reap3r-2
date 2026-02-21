// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission, RolePermissions, Role, JobTypePermission, JobType, canonicalJsonStringify } from '@massvision/shared';
import fs from 'node:fs';
import * as agentService from '../services/agent.service.js';
import { createAuditLog } from '../services/audit.service.js';
import * as jobService from '../services/job.service.js';
import { createHmac, randomUUID } from 'crypto';
import { config } from '../config.js';
import { AgentArch, AgentOs, loadAgentUpdateManifest, normalizeArch, publicBaseUrl, resolveBinaryPath } from '../services/agent-update-manifest.service.js';

function toBoundedInt(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === 'number' ? value : (typeof value === 'string' ? Number(value) : NaN);
  if (!Number.isFinite(n)) return fallback;
  const i = Math.trunc(n);
  if (!Number.isFinite(i)) return fallback;
  return Math.min(max, Math.max(min, i));
}

function toOptionalNonEmptyString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeHttpsUrls(values: unknown[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (!trimmed) continue;
    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'https:') continue;
      const href = parsed.toString();
      if (!seen.has(href)) {
        seen.add(href);
        out.push(href);
      }
    } catch {
      continue;
    }
  }
  return out;
}

export default async function agentRoutes(fastify: FastifyInstance) {
  // ── List agents ──
  fastify.get('/api/agents', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.AgentList)] }, async (request) => {
    const query = request.query as any;
    return agentService.listAgents(fastify, {
      org_id: request.currentUser.org_id,
      company_id: query.company_id,
      folder_id: query.folder_id,
      status: query.status,
      search: query.search,
      os: query.os,
      isolated: query.isolated === 'true' ? true : query.isolated === 'false' ? false : undefined,
      page: query.page ? Number(query.page) : undefined,
      limit: query.limit ? Number(query.limit) : undefined,
      sort_by: query.sort_by,
      sort_dir: query.sort_dir,
    });
  });

  // ── Agent stats (dashboard) — MUST be before /:id to avoid route shadowing ──
  fastify.get('/api/agents/stats', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DashboardView)] }, async (request) => {
    const orgId = request.currentUser.org_id;
    const totalRes = await fastify.pg.query(`SELECT count(*)::int FROM agents WHERE org_id = $1`, [orgId]);
    const onlineRes = await fastify.pg.query(`SELECT count(*)::int FROM agents WHERE org_id = $1 AND status = 'online'`, [orgId]);
    const offlineRes = await fastify.pg.query(`SELECT count(*)::int FROM agents WHERE org_id = $1 AND status = 'offline'`, [orgId]);
    const isolatedRes = await fastify.pg.query(`SELECT count(*)::int FROM agents WHERE org_id = $1 AND isolated = true`, [orgId]);
    const osRes = await fastify.pg.query(
      `SELECT CASE WHEN os ILIKE '%windows%' THEN 'windows' WHEN os ILIKE '%linux%' THEN 'linux' WHEN os ILIKE '%mac%' OR os ILIKE '%darwin%' THEN 'macos' ELSE 'other' END as os_family, count(*)::int
       FROM agents WHERE org_id = $1 GROUP BY os_family`,
      [orgId],
    );
    return {
      total: totalRes.rows[0].count,
      online: onlineRes.rows[0].count,
      offline: offlineRes.rows[0].count,
      isolated: isolatedRes.rows[0].count,
      by_os: Object.fromEntries(osRes.rows.map((r: any) => [r.os_family, r.count])),
    };
  });

  // ── Get available update manifest (latest version info) — MUST be before /:id ──
  fastify.get('/api/agents/update/manifest', { preHandler: [fastify.authenticate] }, async (request, reply) => {
    try {
      const manifest = await loadAgentUpdateManifest({
        os: 'windows',
        arch: 'x86_64',
        request,
      });
      return {
        version: manifest.version,
        available: true,
        signed: Boolean(manifest.sig_ed25519),
        manifest_source: manifest.manifest_source,
      };
    } catch (error: any) {
      const resolved = resolveBinaryPath('windows', 'x86_64');
      const available = Boolean(resolved && fs.existsSync(resolved.filePath));
      if (!available) return { version: process.env.AGENT_VERSION || '1.0.0', available: false };
      return reply.status(503).send({
        statusCode: 503,
        error: 'Service Unavailable',
        message: String(error?.message || 'Update manifest unavailable'),
      });
    }
  });

  // ── Get agent ──
  fastify.get('/api/agents/:id', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.AgentView)] }, async (request, reply) => {
    const { id } = request.params as any;
    const agent = await agentService.getAgentById(fastify, id);
    if (!agent) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    return agent;
  });

  // ── Delete agent ──
  fastify.delete('/api/agents/:id', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.AgentDelete)] }, async (request, reply) => {
    const { id } = request.params as any;
    const agent = await agentService.getAgentById(fastify, id);
    if (!agent) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    await agentService.deleteAgent(fastify, id);
    await createAuditLog(fastify, {
      user_id: request.currentUser.id, org_id: request.currentUser.org_id,
      action: 'agent.delete', entity_type: 'agent', entity_id: id,
      details: { hostname: agent.hostname }, ip_address: request.ip,
    });
    return { message: 'Agent deleted' };
  });

  // ── Agent inventory ──
  fastify.get('/api/agents/:id/inventory', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.AgentView)] }, async (request, reply) => {
    const { id } = request.params as any;
    
    // Get agent
    const { rows: agentRows } = await fastify.pg.query(
      `SELECT id, hostname, os, arch, last_seen_at FROM agents WHERE id = $1 AND org_id = $2`,
      [id, request.currentUser.org_id],
    );
    if (!agentRows[0]) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    const agent = agentRows[0];
    
    // Get latest capabilities
    const { rows: capRows } = await fastify.pg.query(
      `SELECT jsonb_agg(capability) as capabilities FROM agent_capabilities WHERE agent_id = $1`,
      [id],
    );
    const capabilities = capRows[0]?.capabilities || [];
    
    // Get latest inventory snapshot
    const { rows: invRows } = await fastify.pg.query(
      `SELECT data FROM inventory_snapshots WHERE agent_id = $1 ORDER BY collected_at DESC LIMIT 1`,
      [id],
    );
    const inventory = invRows[0]?.data || {};
    
    return {
      ...agent,
      capabilities,
      inventory,
    };
  });

  // ── Agent metrics history (time-series) ──
  fastify.get('/api/agents/:id/metrics', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.AgentView)] }, async (request, reply) => {
    const { id } = request.params as any;
    const query = request.query as any;
    const hours = Math.min(Number(query.hours) || 24, 168); // max 7 days
    const { rows } = await fastify.pg.query(
      `SELECT collected_at as ts, cpu_percent, memory_used_mb, memory_total_mb,
        disk_used_gb, disk_total_gb, network_rx_bytes, network_tx_bytes, processes_count
       FROM metrics_timeseries
       WHERE agent_id = $1 AND collected_at > now() - interval '1 hour' * $2
       ORDER BY collected_at ASC`,
      [id, hours],
    );
    return { data: rows, agent_id: id, period_hours: hours };
  });

  // ── Collect inventory (trigger job) ──
  fastify.post('/api/agents/:id/collect-inventory', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.AgentView)] }, async (request, reply) => {
    const { id } = request.params as any;
    const agent = await agentService.getAgentById(fastify, id);
    if (!agent) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });

    // Create collect_inventory job
    const { createJob } = await import('../services/job.service.js');
    const job = await createJob(fastify, {
      agent_id: id,
      job_type: 'collect_inventory',
      payload: {},
      created_by: request.currentUser.id,
      org_id: request.currentUser.org_id,
      reason: 'Inventory collection from UI',
    });

    return reply.status(201).send(job);
  });

  // ── Bulk update agents ──
  // Creates update_agent jobs for one or more agents. Resolves the binary manifest automatically.
  fastify.post('/api/agents/update', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.AgentUpdate)] }, async (request, reply) => {
    const body = request.body as any;
    const agentIds: string[] = body.agent_ids;
    const force: boolean = body.force ?? false;
    const requestDownloadUrls: unknown[] = Array.isArray(body.download_urls) ? body.download_urls : [];
    const retryCount = toBoundedInt(body.retry_count ?? process.env.AGENT_UPDATE_RETRY_COUNT, 2, 0, 10);
    const retryBackoffMs = toBoundedInt(body.retry_backoff_ms ?? process.env.AGENT_UPDATE_RETRY_BACKOFF_MS, 1500, 0, 60000);
    const deferSeconds = toBoundedInt(body.defer_seconds ?? process.env.AGENT_UPDATE_DEFER_SECONDS, 0, 0, 86400);
    const jitterMaxSeconds = toBoundedInt(body.jitter_max_seconds ?? process.env.AGENT_UPDATE_JITTER_MAX_SECONDS, 0, 0, 86400);
    const serviceName = toOptionalNonEmptyString(body.service_name ?? process.env.AGENT_UPDATE_SERVICE_NAME);
    const launchdLabel = toOptionalNonEmptyString(body.launchd_label ?? process.env.AGENT_UPDATE_LAUNCHD_LABEL);
    const selfRestartDelayInput = body.self_restart_delay_seconds ?? process.env.AGENT_UPDATE_SELF_RESTART_DELAY_SECONDS;
    const selfRestartDelaySeconds = (selfRestartDelayInput !== undefined && selfRestartDelayInput !== null && String(selfRestartDelayInput).trim() !== '')
      ? toBoundedInt(selfRestartDelayInput, 6, 1, 120)
      : undefined;

    if (!Array.isArray(agentIds) || agentIds.length === 0) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'agent_ids is required (non-empty array)' });
    }

    // Permission check for update_agent job type
    const requiredPerm = JobTypePermission[JobType.UpdateAgent];
    if (requiredPerm) {
      const userPerms = RolePermissions[request.currentUser.role as Role] ?? [];
      if (!userPerms.includes(requiredPerm as any)) {
        return reply.status(403).send({ statusCode: 403, error: 'Forbidden', message: `Missing permission: ${requiredPerm}` });
      }
    }

    // Fetch agents to get their OS/arch
    const { rows: agents } = await fastify.pg.query(
      `SELECT id, hostname, os, arch, agent_version, status FROM agents WHERE id = ANY($1) AND org_id = $2`,
      [agentIds, request.currentUser.org_id],
    );

    if (agents.length === 0) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'No matching agents found' });
    }

    const version = process.env.AGENT_VERSION || '1.0.0';
    const results: any[] = [];

    const manifestCache = new Map<string, Awaited<ReturnType<typeof loadAgentUpdateManifest>>>();
    async function resolveManifest(osFamily: AgentOs, archRaw: string) {
      const arch = normalizeArch(archRaw) as AgentArch;
      const cacheKey = `${osFamily}/${arch}`;
      if (manifestCache.has(cacheKey)) return manifestCache.get(cacheKey)!;
      const manifest = await loadAgentUpdateManifest({
        os: osFamily,
        arch,
        request,
        strictSignature: false,
      });
      manifestCache.set(cacheKey, manifest);
      return manifest;
    }

    for (const agent of agents) {
      try {
        // Determine binary OS family
        const osLower = (agent.os || '').toLowerCase();
        let osFamily: AgentOs = 'windows';
        if (osLower.includes('linux')) osFamily = 'linux';
        else if (osLower.includes('darwin') || osLower.includes('mac')) osFamily = 'darwin';
        const arch = normalizeArch(agent.arch || 'x86_64') as AgentArch;
        const manifest = await resolveManifest(osFamily, arch);
        const localFallbackUrl = `${publicBaseUrl(request)}/api/agent-binary/download?os=${encodeURIComponent(osFamily)}&arch=${encodeURIComponent(arch)}`;
        const downloadUrls = normalizeHttpsUrls([
          manifest.download_url,
          ...requestDownloadUrls,
          localFallbackUrl,
        ]);
        if (downloadUrls.length === 0) {
          throw new Error(`No valid HTTPS update URL for ${osFamily}/${arch}`);
        }

        const payload = {
          version: manifest.version || version,
          download_url: downloadUrls[0],
          download_urls: downloadUrls,
          sha256: manifest.sha256,
          ...(manifest.sig_ed25519 ? { sig_ed25519: manifest.sig_ed25519 } : {}),
          ...(manifest.signer_thumbprint ? { signer_thumbprint: manifest.signer_thumbprint } : {}),
          ...(manifest.require_authenticode ? { require_authenticode: true } : {}),
          retry_count: retryCount,
          retry_backoff_ms: retryBackoffMs,
          defer_seconds: deferSeconds,
          jitter_max_seconds: jitterMaxSeconds,
          ...(serviceName ? { service_name: serviceName } : {}),
          ...(launchdLabel ? { launchd_label: launchdLabel } : {}),
          ...(selfRestartDelaySeconds !== undefined ? { self_restart_delay_seconds: selfRestartDelaySeconds } : {}),
          force,
        };

        // Create job
        const job = await jobService.createJob(fastify, {
          agent_id: agent.id,
          job_type: 'update_agent',
          payload,
          created_by: request.currentUser.id,
          org_id: request.currentUser.org_id,
          reason: `Remote update to v${payload.version}`,
        });

        // Proactive push if agent online
        try {
          const agentWs = fastify.agentSockets?.get(agent.id);
          if (agentWs && agentWs.readyState === 1) {
            const jobPayload = {
              job_id: job.id,
              name: 'update_agent',
              args: payload,
              timeout_sec: 300,
              created_at: new Date(job.created_at).toISOString(),
            };
            const envelope = {
              type: 'job_assign' as const,
              ts: Date.now(),
              nonce: randomUUID(),
              traceId: randomUUID(),
              agentId: agent.id,
              payload: jobPayload,
            };
            const sig = createHmac('sha256', config.hmac.secret)
              .update(canonicalJsonStringify(envelope)).digest('hex');
            agentWs.send(JSON.stringify({ ...envelope, sig }));
            await jobService.updateJobStatus(fastify, job.id, 'dispatched');
          }
        } catch (pushErr) {
          fastify.log.warn({ err: pushErr }, 'Proactive push failed for agent update');
        }

        results.push({ agent_id: agent.id, hostname: agent.hostname, status: 'queued', job_id: job.id });

        await createAuditLog(fastify, {
          user_id: request.currentUser.id, org_id: request.currentUser.org_id,
          action: 'agent.update', entity_type: 'agent', entity_id: agent.id,
          details: {
            version,
            force,
            retry_count: retryCount,
            retry_backoff_ms: retryBackoffMs,
            defer_seconds: deferSeconds,
            jitter_max_seconds: jitterMaxSeconds,
          },
          ip_address: request.ip,
        });
      } catch (err: any) {
        results.push({ agent_id: agent.id, hostname: agent.hostname, status: 'error', error: err.message });
      }
    }

    return { version, total: agents.length, results };
  });
}

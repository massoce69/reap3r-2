// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission } from '@massvision/shared';
import * as agentService from '../services/agent.service.js';
import { createAuditLog } from '../services/audit.service.js';

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
}

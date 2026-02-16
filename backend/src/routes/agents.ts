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

  // ── Agent stats (dashboard) ──
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
}

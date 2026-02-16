// ─────────────────────────────────────────────
// MASSVISION Reap3r — Audit Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission } from '@massvision/shared';
import { listAuditLogs } from '../services/audit.service.js';

export default async function auditRoutes(fastify: FastifyInstance) {
  fastify.get('/api/audit', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.AuditView)] }, async (request) => {
    const query = request.query as any;
    return listAuditLogs(fastify, {
      org_id: request.currentUser.org_id,
      user_id: query.user_id,
      entity_type: query.entity_type,
      entity_id: query.entity_id,
      action: query.action,
      page: query.page ? Number(query.page) : undefined,
      limit: query.limit ? Number(query.limit) : undefined,
    });
  });
}

// ─────────────────────────────────────────────
// MASSVISION Reap3r — Audit Middleware Plugin
// ─────────────────────────────────────────────
import { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { createAuditLog, AuditEntry } from '../services/audit.service.js';

declare module 'fastify' {
  interface FastifyRequest {
    audit: (entry: {
      action: string;
      entity_type: string;
      entity_id?: string | null;
      details?: Record<string, unknown> | null;
      org_id?: string | null;
      user_id?: string | null;
    }) => Promise<string>;
  }
}

async function auditPlugin(fastify: FastifyInstance) {
  fastify.decorateRequest('audit', undefined as any);

  fastify.addHook('onRequest', async (request: FastifyRequest) => {
    request.audit = async (entry) => {
      const orgId = entry.org_id ?? (request as any).currentUser?.org_id ?? null;
      const userId = entry.user_id ?? (request as any).currentUser?.id ?? null;
      const ip = request.ip;

      const row = await createAuditLog(fastify, {
        action: entry.action,
        entity_type: entry.entity_type,
        entity_id: entry.entity_id ?? null,
        details: entry.details ?? null,
        org_id: orgId,
        user_id: userId,
        ip_address: ip,
      });
      return row?.id ?? '';
    };
  });
}

export default fp(auditPlugin, { name: 'audit' });

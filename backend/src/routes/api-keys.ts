// ─────────────────────────────────────────────
// MASSVISION Reap3r — API Key Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { Permission } from '@massvision/shared';
import * as apiKeySvc from '../services/apikey.service.js';
import { createAuditLog } from '../services/audit.service.js';
import { parseUUID, parseBody } from '../lib/validate.js';

const CreateApiKeySchema = z.object({
  name: z.string().min(1).max(100),
  scopes: z.array(z.string()).min(1).default(['read']),
  rate_limit: z.number().int().min(1).max(10000).default(100),
  expires_at: z.string().datetime().optional(),
});

export default async function apiKeyRoutes(fastify: FastifyInstance) {
  // ── List API Keys ──
  fastify.get('/api/api-keys', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.SettingsView)],
  }, async (request) => {
    const keys = await apiKeySvc.listApiKeys(request.currentUser.org_id);
    return { data: keys };
  });

  // ── Create API Key ──
  fastify.post('/api/api-keys', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.SettingsUpdate)],
  }, async (request, reply) => {
    const body = parseBody(CreateApiKeySchema, request.body, reply);
    if (!body) return;
    const { name, scopes, expires_at, rate_limit } = body;

    const result = await apiKeySvc.createApiKey(request.currentUser.org_id, request.currentUser.id, {
      name,
      scopes: scopes ?? ['read'],
      rate_limit: rate_limit ?? 100,
      expires_at,
    });

    await createAuditLog(fastify, {
      user_id: request.currentUser.id,
      org_id: request.currentUser.org_id,
      action: 'api_key.create',
      entity_type: 'api_key',
      entity_id: result.id,
      details: { name, scopes: scopes ?? ['read'] },
      ip_address: request.ip,
    });

    return reply.status(201).send(result);
  });

  // ── Revoke API Key ──
  fastify.patch('/api/api-keys/:id/revoke', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.SettingsUpdate)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const ok = await apiKeySvc.revokeApiKey(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'API key not found' });

    await createAuditLog(fastify, {
      user_id: request.currentUser.id,
      org_id: request.currentUser.org_id,
      action: 'api_key.revoke',
      entity_type: 'api_key',
      entity_id: id,
      details: {},
      ip_address: request.ip,
    });

    return { message: 'API key revoked' };
  });

  // ── Delete API Key ──
  fastify.delete('/api/api-keys/:id', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.SettingsUpdate)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const ok = await apiKeySvc.deleteApiKey(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'API key not found' });

    await createAuditLog(fastify, {
      user_id: request.currentUser.id,
      org_id: request.currentUser.org_id,
      action: 'api_key.delete',
      entity_type: 'api_key',
      entity_id: id,
      details: {},
      ip_address: request.ip,
    });

    return { message: 'API key deleted' };
  });
}

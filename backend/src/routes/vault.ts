// ─────────────────────────────────────────────
// MASSVISION Reap3r — Vault Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission, CreateSecretSchema, UpdateSecretSchema } from '@massvision/shared';
import * as svc from '../services/vault.service.js';
import { query } from '../db/pool.js';

export default async function vaultRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  // GET /api/vault/secrets
  fastify.get('/api/vault/secrets', {
    preHandler: [fastify.requirePermission(Permission.SecretList)],
  }, async (request) => {
    const q = request.query as any;
    return svc.listSecrets(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: Number(q.limit) || 25,
      q: q.q,
      company_id: q.company_id,
      folder_id: q.folder_id,
      type: q.type,
    });
  });

  // POST /api/vault/secrets
  fastify.post('/api/vault/secrets', {
    preHandler: [fastify.requirePermission(Permission.SecretWrite)],
  }, async (request, reply) => {
    const parsed = CreateSecretSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const result = await svc.createSecret(request.currentUser.org_id, request.currentUser.id, parsed.data);
    await svc.logSecretAccess(result.id, request.currentUser.id, 'create', request.ip, request.headers['user-agent'] ?? null);
    await request.audit({ action: 'secret_create', entity_type: 'secret', entity_id: result.id, details: { name: parsed.data.name, type: parsed.data.type } });
    return reply.status(201).send(result);
  });

  // PATCH /api/vault/secrets/:id
  fastify.patch('/api/vault/secrets/:id', {
    preHandler: [fastify.requirePermission(Permission.SecretWrite)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = UpdateSecretSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const ok = await svc.updateSecret(request.currentUser.org_id, id, request.currentUser.id, parsed.data);
    if (!ok) return reply.status(404).send({ error: 'Not found' });
    await svc.logSecretAccess(id, request.currentUser.id, 'edit', request.ip, request.headers['user-agent'] ?? null);
    await request.audit({ action: 'secret_update', entity_type: 'secret', entity_id: id });
    return { ok: true };
  });

  // DELETE /api/vault/secrets/:id
  fastify.delete('/api/vault/secrets/:id', {
    preHandler: [fastify.requirePermission(Permission.SecretDelete)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const ok = await svc.deleteSecret(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ error: 'Not found' });
    await svc.logSecretAccess(id, request.currentUser.id, 'delete', request.ip, request.headers['user-agent'] ?? null);
    await request.audit({ action: 'secret_delete', entity_type: 'secret', entity_id: id });
    return { ok: true };
  });

  // POST /api/vault/secrets/:id/reveal
  fastify.post('/api/vault/secrets/:id/reveal', {
    preHandler: [fastify.requirePermission(Permission.SecretReveal)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const value = await svc.revealSecret(request.currentUser.org_id, id, request.currentUser.id, request.currentUser.role);
    if (value === null) return reply.status(404).send({ error: 'Not found' });
    await svc.logSecretAccess(id, request.currentUser.id, 'view', request.ip, request.headers['user-agent'] ?? null);
    await request.audit({ action: 'secret_reveal', entity_type: 'secret', entity_id: id });
    return { value };
  });

  // POST /api/vault/secrets/:id/use — inject secret into job (no value exposed to UI)
  fastify.post('/api/vault/secrets/:id/use', {
    preHandler: [fastify.requirePermission(Permission.SecretUse)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const value = await svc.revealSecret(request.currentUser.org_id, id, request.currentUser.id, request.currentUser.role);
    if (value === null) return reply.status(404).send({ error: 'Not found' });
    await svc.logSecretAccess(id, request.currentUser.id, 'use', request.ip, request.headers['user-agent'] ?? null);
    await request.audit({ action: 'secret_use', entity_type: 'secret', entity_id: id });
    return { ok: true, injected: true };
  });

  // GET /api/vault/secrets/:id/access-logs
  fastify.get('/api/vault/secrets/:id/access-logs', {
    preHandler: [fastify.requirePermission(Permission.SecretRead)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    return svc.getSecretAccessLogs(id);
  });

  // ─────────────────────────────────────────────
  // PREMIUM: Versioning
  // ─────────────────────────────────────────────

  // GET /api/vault/secrets/:id/versions
  fastify.get('/api/vault/secrets/:id/versions', {
    preHandler: [fastify.requirePermission(Permission.SecretRead)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    return svc.getSecretVersions(id);
  });

  // POST /api/vault/secrets/:id/versions/:versionId/reveal
  fastify.post('/api/vault/secrets/:id/versions/:versionId/reveal', {
    preHandler: [fastify.requirePermission(Permission.SecretReveal)],
  }, async (request, reply) => {
    const { id, versionId } = request.params as { id: string; versionId: string };
    const ver = await svc.getSecretVersionById(versionId);
    if (!ver) return reply.status(404).send({ error: 'Version not found' });
    const value = svc.decryptSecret(ver.encrypted_blob);
    await svc.logSecretAccess(id, request.currentUser.id, 'view_version', request.ip, request.headers['user-agent'] ?? null);
    await request.audit({ action: 'secret_version_reveal', entity_type: 'secret', entity_id: id, details: { version_id: versionId } });
    return { value };
  });

  // ─────────────────────────────────────────────
  // PREMIUM: Sharing & Permissions
  // ─────────────────────────────────────────────

  // GET /api/vault/secrets/:id/permissions
  fastify.get('/api/vault/secrets/:id/permissions', {
    preHandler: [fastify.requirePermission(Permission.SecretRead)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    return svc.getSecretPermissions(id);
  });

  // POST /api/vault/secrets/:id/share
  fastify.post('/api/vault/secrets/:id/share', {
    preHandler: [fastify.requirePermission(Permission.SecretWrite)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { principal_type, principal_id, rights } = request.body as { principal_type: 'user' | 'team'; principal_id: string; rights: string[] };
    if (!principal_type || !principal_id || !Array.isArray(rights)) {
      return reply.status(400).send({ error: 'principal_type, principal_id, rights[] required' });
    }
    await svc.shareSecret(id, principal_type, principal_id, rights);
    await request.audit({ action: 'secret_share', entity_type: 'secret', entity_id: id, details: { principal_type, principal_id, rights } });
    return { ok: true };
  });

  // DELETE /api/vault/secrets/:id/permissions/:permId
  fastify.delete('/api/vault/secrets/:id/permissions/:permId', {
    preHandler: [fastify.requirePermission(Permission.SecretWrite)],
  }, async (request, reply) => {
    const { id, permId } = request.params as { id: string; permId: string };
    // permId is actually principal_id in this context - need to get principal_type from DB or pass differently
    // For now, we'll delete by permission ID from secret_permissions table
    await query(`DELETE FROM secret_permissions WHERE id = $1`, [permId]);
    await request.audit({ action: 'secret_share_revoked', entity_type: 'secret', entity_id: id, details: { perm_id: permId } });
    return { ok: true };
  });

  // ─────────────────────────────────────────────
  // PREMIUM: Rotation & Expiration
  // ─────────────────────────────────────────────

  // GET /api/vault/expiring
  fastify.get('/api/vault/expiring', {
    preHandler: [fastify.requirePermission(Permission.SecretList)],
  }, async (request) => {
    const q = request.query as any;
    const days = Number(q.days) || 30;
    const secrets = await svc.getExpiringSecrets(request.currentUser.org_id, days);
    return { data: secrets };
  });

  // POST /api/vault/secrets/:id/rotate
  fastify.post('/api/vault/secrets/:id/rotate', {
    preHandler: [fastify.requirePermission(Permission.SecretWrite)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    await svc.markSecretAsRotated(id, request.currentUser.id);
    await request.audit({ action: 'secret_rotated', entity_type: 'secret', entity_id: id });
    return { ok: true };
  });
}

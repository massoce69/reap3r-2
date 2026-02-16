// ─────────────────────────────────────────────
// MASSVISION Reap3r — Folders Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission } from '@massvision/shared';
import * as svc from '../services/folder.service.js';
import { CreateFolderSchema, UpdateFolderSchema, MoveAgentSchema } from '@massvision/shared';
import { query } from '../db/pool.js';

export default async function folderRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  // GET /api/folders
  fastify.get('/api/folders', {
    preHandler: [fastify.requirePermission(Permission.FolderList)],
  }, async (request) => {
    const q = request.query as any;
    return svc.listFolders(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: Number(q.limit) || 100,
      company_id: q.company_id,
      q: q.q,
    });
  });

  // GET /api/folders/:id
  fastify.get('/api/folders/:id', {
    preHandler: [fastify.requirePermission(Permission.FolderView)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const folder = await svc.getFolderById(request.currentUser.org_id, id);
    if (!folder) return reply.status(404).send({ error: 'Not found' });
    return folder;
  });

  // POST /api/folders
  fastify.post('/api/folders', {
    preHandler: [fastify.requirePermission(Permission.FolderCreate)],
  }, async (request, reply) => {
    const parsed = CreateFolderSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const result = await svc.createFolder(request.currentUser.org_id, parsed.data);
    await request.audit({ action: 'folder_create', entity_type: 'folder', entity_id: result.id, details: { name: parsed.data.name } });
    return reply.status(201).send(result);
  });

  // PATCH /api/folders/:id
  fastify.patch('/api/folders/:id', {
    preHandler: [fastify.requirePermission(Permission.FolderUpdate)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = UpdateFolderSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const ok = await svc.updateFolder(request.currentUser.org_id, id, parsed.data);
    if (!ok) return reply.status(404).send({ error: 'Not found' });
    await request.audit({ action: 'folder_update', entity_type: 'folder', entity_id: id });
    return { ok: true };
  });

  // DELETE /api/folders/:id
  fastify.delete('/api/folders/:id', {
    preHandler: [fastify.requirePermission(Permission.FolderDelete)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const ok = await svc.deleteFolder(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ error: 'Not found' });
    await request.audit({ action: 'folder_delete', entity_type: 'folder', entity_id: id });
    return { ok: true };
  });

  // POST /api/agents/:id/move — move agent to company/folders
  fastify.post('/api/agents/:id/move', {
    preHandler: [fastify.requirePermission(Permission.AgentMove)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = MoveAgentSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const orgId = request.currentUser.org_id;

    // Check agent belongs to org
    const { rows } = await query('SELECT id FROM agents WHERE id = $1 AND org_id = $2', [id, orgId]);
    if (!rows.length) return reply.status(404).send({ error: 'Agent not found' });

    // Update company
    if (parsed.data.company_id !== undefined) {
      await query('UPDATE agents SET company_id = $1 WHERE id = $2', [parsed.data.company_id, id]);
    }

    // Update folders
    if (parsed.data.folder_ids !== undefined) {
      await query('DELETE FROM agent_folder_membership WHERE agent_id = $1', [id]);
      for (const fid of parsed.data.folder_ids) {
        await svc.addAgentToFolder(id, fid);
      }
    }

    await request.audit({
      action: 'agent_move', entity_type: 'agent', entity_id: id,
      details: { company_id: parsed.data.company_id, folder_ids: parsed.data.folder_ids },
    });
    return { ok: true };
  });
}

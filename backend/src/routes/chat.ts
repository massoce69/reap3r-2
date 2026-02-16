// ─────────────────────────────────────────────
// MASSVISION Reap3r — Chat / Messaging Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission, CreateChannelSchema, CreateMessageSchema } from '@massvision/shared';
import * as svc from '../services/chat.service.js';

export default async function chatRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  // GET /api/chat/channels
  fastify.get('/api/chat/channels', {
    preHandler: [fastify.requirePermission(Permission.MessageRead)],
  }, async (request) => {
    return svc.listChannels(request.currentUser.org_id, request.currentUser.id);
  });

  // POST /api/chat/channels
  fastify.post('/api/chat/channels', {
    preHandler: [fastify.requirePermission(Permission.ChannelManage)],
  }, async (request, reply) => {
    const parsed = CreateChannelSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const result = await svc.createChannel(request.currentUser.org_id, parsed.data);
    // Add creator as admin
    await svc.addChannelMember(result.id, request.currentUser.id, 'admin');
    await request.audit({ action: 'channel_create', entity_type: 'channel', entity_id: result.id, details: { name: parsed.data.name } });
    return reply.status(201).send(result);
  });

  // GET /api/chat/channels/:id
  fastify.get('/api/chat/channels/:id', {
    preHandler: [fastify.requirePermission(Permission.MessageRead)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const channel = await svc.getChannelById(request.currentUser.org_id, id);
    if (!channel) return reply.status(404).send({ error: 'Not found' });
    return channel;
  });

  // GET /api/chat/channels/:id/messages
  fastify.get('/api/chat/channels/:id/messages', {
    preHandler: [fastify.requirePermission(Permission.MessageRead)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    const q = request.query as any;
    return svc.listMessages(id, { page: Number(q.page) || 1, limit: Number(q.limit) || 50 });
  });

  // POST /api/chat/channels/:id/messages
  fastify.post('/api/chat/channels/:id/messages', {
    preHandler: [fastify.requirePermission(Permission.MessageWrite)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = CreateMessageSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const msg = await svc.createMessage(id, request.currentUser.id, parsed.data.body);

    // Broadcast via WS to channel members
    try {
      fastify.websocketServer?.clients?.forEach((client: any) => {
        if (client.readyState === 1 && client.orgId === request.currentUser.org_id) {
          client.send(JSON.stringify({ type: 'chat_message', payload: { channel_id: id, message: { ...msg, user_name: request.currentUser.name, body: parsed.data.body } } }));
        }
      });
    } catch { /* noop */ }

    return reply.status(201).send(msg);
  });

  // GET /api/chat/channels/:id/members
  fastify.get('/api/chat/channels/:id/members', {
    preHandler: [fastify.requirePermission(Permission.MessageRead)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    return svc.getChannelMembers(id);
  });

  // POST /api/chat/channels/:id/members
  fastify.post('/api/chat/channels/:id/members', {
    preHandler: [fastify.requirePermission(Permission.ChannelManage)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { user_id } = request.body as { user_id: string };
    await svc.addChannelMember(id, user_id);
    await request.audit({ action: 'channel_member_add', entity_type: 'channel', entity_id: id, details: { user_id } });
    return reply.status(201).send({ ok: true });
  });

  // DELETE /api/chat/channels/:id/members/:userId
  fastify.delete('/api/chat/channels/:id/members/:userId', {
    preHandler: [fastify.requirePermission(Permission.ChannelManage)],
  }, async (request) => {
    const { id, userId } = request.params as { id: string; userId: string };
    await svc.removeChannelMember(id, userId);
    await request.audit({ action: 'channel_member_remove', entity_type: 'channel', entity_id: id, details: { user_id: userId } });
    return { ok: true };
  });
}

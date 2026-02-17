// ─────────────────────────────────────────────
// MASSVISION Reap3r — Alerting Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission, CreateAlertRuleSchema, UpdateAlertRuleSchema, AlertAckSchema, AlertSnoozeSchema, CreateAlertIntegrationSchema } from '@massvision/shared';
import * as alertSvc from '../services/alerting.service.js';
import * as notifier from '../services/notification.service.js';
import { parseUUID, parseBody, clampLimit } from '../lib/validate.js';

export default async function alertingRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  // ════════════════════════════════════════════
  // ALERT RULES
  // ════════════════════════════════════════════

  // GET /api/alerts/rules
  fastify.get('/api/alerts/rules', {
    preHandler: [fastify.requirePermission(Permission.AlertRuleList)],
  }, async (request) => {
    const q = request.query as any;
    return alertSvc.listAlertRules(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: clampLimit(q.limit),
      rule_type: q.rule_type,
      is_enabled: q.is_enabled === 'true' ? true : q.is_enabled === 'false' ? false : undefined,
    });
  });

  // GET /api/alerts/rules/:id
  fastify.get('/api/alerts/rules/:id', {
    preHandler: [fastify.requirePermission(Permission.AlertRuleList)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const rule = await alertSvc.getRuleById(request.currentUser.org_id, id);
    if (!rule) return reply.status(404).send({ error: 'Rule not found' });
    return rule;
  });

  // POST /api/alerts/rules
  fastify.post('/api/alerts/rules', {
    preHandler: [fastify.requirePermission(Permission.AlertRuleCreate)],
  }, async (request, reply) => {
    const body = parseBody(CreateAlertRuleSchema, request.body, reply);
    if (!body) return;
    const rule = await alertSvc.createAlertRule(request.currentUser.org_id, request.currentUser.id, body);
    await request.audit({
      action: 'alert_rule_create',
      entity_type: 'alert_rule',
      entity_id: rule.id,
      details: { name: body.name, rule_type: body.rule_type },
    });
    return reply.status(201).send(rule);
  });

  // PATCH /api/alerts/rules/:id
  fastify.patch('/api/alerts/rules/:id', {
    preHandler: [fastify.requirePermission(Permission.AlertRuleUpdate)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const body = parseBody(UpdateAlertRuleSchema, request.body, reply);
    if (!body) return;
    const rule = await alertSvc.updateAlertRule(request.currentUser.org_id, id, body);
    if (!rule) return reply.status(404).send({ error: 'Rule not found' });
    await request.audit({
      action: 'alert_rule_update',
      entity_type: 'alert_rule',
      entity_id: id,
      details: body,
    });
    return rule;
  });

  // DELETE /api/alerts/rules/:id
  fastify.delete('/api/alerts/rules/:id', {
    preHandler: [fastify.requirePermission(Permission.AlertRuleDelete)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const ok = await alertSvc.deleteAlertRule(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ error: 'Rule not found' });
    await request.audit({
      action: 'alert_rule_delete',
      entity_type: 'alert_rule',
      entity_id: id,
    });
    return { ok: true };
  });

  // ════════════════════════════════════════════
  // ALERT EVENTS
  // ════════════════════════════════════════════

  // GET /api/alerts/events
  fastify.get('/api/alerts/events', {
    preHandler: [fastify.requirePermission(Permission.AlertEventList)],
  }, async (request) => {
    const q = request.query as any;
    return alertSvc.listAlertEvents(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: clampLimit(q.limit),
      status: q.status,
      severity: q.severity,
      entity_type: q.entity_type,
      company_id: q.company_id,
      folder_id: q.folder_id,
    });
  });

  // GET /api/alerts/events/:id
  fastify.get('/api/alerts/events/:id', {
    preHandler: [fastify.requirePermission(Permission.AlertEventList)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const event = await alertSvc.getAlertEventById(request.currentUser.org_id, id);
    if (!event) return reply.status(404).send({ error: 'Alert event not found' });
    return event;
  });

  // POST /api/alerts/events/:id/ack
  fastify.post('/api/alerts/events/:id/ack', {
    preHandler: [fastify.requirePermission(Permission.AlertEventAck)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { note } = (request.body as any) ?? {};
    const ok = await alertSvc.ackAlertEvent(request.currentUser.org_id, id, request.currentUser.id, note);
    if (!ok) return reply.status(404).send({ error: 'Event not found or already acknowledged' });
    await request.audit({
      action: 'alert_event_ack',
      entity_type: 'alert_event',
      entity_id: id,
      details: { note },
    });
    return { ok: true };
  });

  // POST /api/alerts/events/:id/resolve
  fastify.post('/api/alerts/events/:id/resolve', {
    preHandler: [fastify.requirePermission(Permission.AlertEventResolve)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { note } = (request.body as any) ?? {};
    const ok = await alertSvc.resolveAlertEvent(request.currentUser.org_id, id, request.currentUser.id, note);
    if (!ok) return reply.status(404).send({ error: 'Event not found or already resolved' });
    await request.audit({
      action: 'alert_event_resolve',
      entity_type: 'alert_event',
      entity_id: id,
      details: { note },
    });
    return { ok: true };
  });

  // POST /api/alerts/events/:id/snooze
  fastify.post('/api/alerts/events/:id/snooze', {
    preHandler: [fastify.requirePermission(Permission.AlertEventSnooze)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = AlertSnoozeSchema.safeParse({ event_id: id, ...(request.body as any) });
    if (!body.success) return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: body.error.message });
    const ok = await alertSvc.snoozeAlertEvent(
      request.currentUser.org_id, id, request.currentUser.id, body.data.duration_min, body.data.note
    );
    if (!ok) return reply.status(404).send({ error: 'Event not found or cannot be snoozed' });
    await request.audit({
      action: 'alert_event_snooze',
      entity_type: 'alert_event',
      entity_id: id,
      details: { duration_min: body.duration_min, note: body.note },
    });
    return { ok: true };
  });

  // GET /api/alerts/stats
  fastify.get('/api/alerts/stats', {
    preHandler: [fastify.requirePermission(Permission.AlertEventList)],
  }, async (request) => {
    return alertSvc.getAlertStats(request.currentUser.org_id);
  });

  // ════════════════════════════════════════════
  // INTEGRATIONS
  // ════════════════════════════════════════════

  // GET /api/alerts/integrations
  fastify.get('/api/alerts/integrations', {
    preHandler: [fastify.requirePermission(Permission.AlertIntegrationManage)],
  }, async (request) => {
    return alertSvc.listIntegrations(request.currentUser.org_id);
  });

  // POST /api/alerts/integrations
  fastify.post('/api/alerts/integrations', {
    preHandler: [fastify.requirePermission(Permission.AlertIntegrationManage)],
  }, async (request, reply) => {
    const body = parseBody(CreateAlertIntegrationSchema, request.body, reply);
    if (!body) return;
    const integ = await alertSvc.createIntegration(request.currentUser.org_id, body);
    await request.audit({
      action: 'alert_integration_create',
      entity_type: 'alert_integration',
      entity_id: integ.id,
      details: { type: body.type, name: body.name },
    });
    return reply.status(201).send(integ);
  });

  // PATCH /api/alerts/integrations/:id
  fastify.patch('/api/alerts/integrations/:id', {
    preHandler: [fastify.requirePermission(Permission.AlertIntegrationManage)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;
    const ok = await alertSvc.updateIntegration(request.currentUser.org_id, id, body);
    if (!ok) return reply.status(404).send({ error: 'Integration not found' });
    await request.audit({
      action: 'alert_integration_update',
      entity_type: 'alert_integration',
      entity_id: id,
      details: body,
    });
    return { ok: true };
  });

  // DELETE /api/alerts/integrations/:id
  fastify.delete('/api/alerts/integrations/:id', {
    preHandler: [fastify.requirePermission(Permission.AlertIntegrationManage)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const ok = await alertSvc.deleteIntegration(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ error: 'Integration not found' });
    await request.audit({
      action: 'alert_integration_delete',
      entity_type: 'alert_integration',
      entity_id: id,
    });
    return { ok: true };
  });

  // POST /api/alerts/test
  fastify.post('/api/alerts/test', {
    preHandler: [fastify.requirePermission(Permission.AlertTest)],
  }, async (request) => {
    const { channel } = request.body as { channel: string };
    const result = await notifier.sendTestNotification(request.currentUser.org_id, channel);
    await request.audit({
      action: 'alert_test_notification',
      entity_type: 'alert_integration',
      details: { channel, result },
    });
    return result;
  });
}

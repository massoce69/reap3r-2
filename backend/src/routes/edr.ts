// ─────────────────────────────────────────────
// MASSVISION Reap3r — EDR Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { Permission, CreateIncidentSchema, EdrRespondSchema, JobType, canonicalJsonStringify } from '@massvision/shared';
import * as edr from '../services/edr.service.js';
import * as jobSvc from '../services/job.service.js';
import { parseUUID, clampLimit } from '../lib/validate.js';

const SENSITIVE_EDR_ACTIONS = new Set<string>([
  'edr_kill_process',
  'edr_quarantine_file',
  'edr_isolate_machine',
]);
const APPROVAL_TTL_MS = 15 * 60 * 1000;
const EdrRespondWithApprovalSchema = EdrRespondSchema.extend({
  approval_id: z.string().uuid().optional(),
});

function payloadHash(payload: unknown): string {
  return createHash('sha256').update(canonicalJsonStringify(payload ?? {})).digest('hex');
}

function parseJsonObject(input: unknown): Record<string, unknown> {
  if (!input) return {};
  if (typeof input === 'string') {
    try {
      const parsed = JSON.parse(input);
      return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {};
    } catch {
      return {};
    }
  }
  return input && typeof input === 'object' ? input as Record<string, unknown> : {};
}

async function isEdrKillSwitchEnabled(fastify: FastifyInstance, orgId: string): Promise<boolean> {
  if (String(process.env.EDR_KILL_SWITCH || '').toLowerCase() === 'true') return true;
  const { rows } = await fastify.pg.query<{ rules: unknown }>(
    `SELECT rules
     FROM policies
     WHERE org_id = $1
       AND is_active = TRUE
       AND name IN ('edr_global_kill_switch', 'edr-kill-switch')
     ORDER BY updated_at DESC
     LIMIT 1`,
    [orgId],
  );
  if (!rows[0]) return false;
  const rules = parseJsonObject(rows[0].rules);
  return rules.enabled === true || rules.kill_switch === true;
}

export default async function edrRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  // GET /api/edr/events
  fastify.get('/api/edr/events', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request) => {
    const q = request.query as any;
    return edr.listSecurityEvents(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: clampLimit(q.limit, 50),
      agent_id: q.agent_id,
      event_type: q.event_type,
      severity: q.severity,
    });
  });

  // GET /api/edr/detections
  fastify.get('/api/edr/detections', {
    preHandler: [fastify.requirePermission(Permission.EdrDetectionsView)],
  }, async (request) => {
    const q = request.query as any;
    return edr.listDetections(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: clampLimit(q.limit, 50),
      status: q.status,
      severity: q.severity,
      agent_id: q.agent_id,
    });
  });

  // PATCH /api/edr/detections/:id/status
  fastify.patch('/api/edr/detections/:id/status', {
    preHandler: [fastify.requirePermission(Permission.EdrRespond)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const statusSchema = z.object({ status: z.enum(['open', 'acknowledged', 'resolved', 'false_positive']) });
    const parsed = statusSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: parsed.error.message });
    const { status } = parsed.data;
    const ok = await edr.updateDetectionStatus(request.currentUser.org_id, id, status, request.currentUser.id);
    if (!ok) return reply.status(404).send({ error: 'Not found' });
    await request.audit({ action: 'detection_status_update', entity_type: 'detection', entity_id: id, details: { status } });
    return { ok: true };
  });

  // GET /api/edr/incidents
  fastify.get('/api/edr/incidents', {
    preHandler: [fastify.requirePermission(Permission.EdrIncidentManage)],
  }, async (request) => {
    const q = request.query as any;
    return edr.listIncidents(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: clampLimit(q.limit),
      status: q.status,
      severity: q.severity,
    });
  });

  // POST /api/edr/incidents
  fastify.post('/api/edr/incidents', {
    preHandler: [fastify.requirePermission(Permission.EdrIncidentManage)],
  }, async (request, reply) => {
    const parsed = CreateIncidentSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const result = await edr.createIncident(request.currentUser.org_id, request.currentUser.id, parsed.data);
    await request.audit({ action: 'incident_create', entity_type: 'incident', entity_id: result.id, details: { title: parsed.data.title } });
    return reply.status(201).send(result);
  });

  // PATCH /api/edr/incidents/:id/status
  fastify.patch('/api/edr/incidents/:id/status', {
    preHandler: [fastify.requirePermission(Permission.EdrIncidentManage)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const statusSchema = z.object({ status: z.enum(['open', 'investigating', 'contained', 'resolved', 'closed']) });
    const parsed = statusSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: parsed.error.message });
    const { status } = parsed.data;
    const ok = await edr.updateIncidentStatus(request.currentUser.org_id, id, status);
    if (!ok) return reply.status(404).send({ error: 'Not found' });
    await request.audit({ action: 'incident_status_update', entity_type: 'incident', entity_id: id, details: { status } });
    return { ok: true };
  });

  // POST /api/edr/respond — create response action (creates a job)
  fastify.post('/api/edr/respond', {
    preHandler: [fastify.requirePermission(Permission.EdrRespond)],
  }, async (request, reply) => {
    const parsed = EdrRespondWithApprovalSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const { agent_id, action, payload, reason, approval_id } = parsed.data;
    const orgId = request.currentUser.org_id;
    const callerId = request.currentUser.id;

    if (await isEdrKillSwitchEnabled(fastify, orgId)) {
      await request.audit({
        action: 'edr_respond_blocked_kill_switch',
        entity_type: 'agent',
        entity_id: agent_id,
        details: { action, reason },
      });
      return reply.status(423).send({ error: 'EDR global kill-switch enabled' });
    }

    const actionPayloadHash = payloadHash(payload);
    const isSensitive = SENSITIVE_EDR_ACTIONS.has(action);

    if (isSensitive && !approval_id) {
      const pending = await edr.createResponseAction(orgId, {
        agent_id,
        action,
        initiated_by: callerId,
        reason,
        status: 'awaiting_second_approval',
        result: {
          payload_hash: actionPayloadHash,
          requested_by: callerId,
          requested_at: new Date().toISOString(),
        },
      });

      await request.audit({
        action: 'edr_respond_pending_approval',
        entity_type: 'agent',
        entity_id: agent_id,
        details: { action, approval_id: pending.id, reason },
      });

      return reply.status(202).send({
        pending_approval: true,
        approval_id: pending.id,
        message: 'Second approval required for sensitive EDR action',
      });
    }

    if (isSensitive && approval_id) {
      const pending = await edr.getResponseActionById(orgId, approval_id);
      if (!pending) return reply.status(404).send({ error: 'Approval request not found' });
      if (String(pending.status) !== 'awaiting_second_approval') {
        return reply.status(409).send({ error: 'Approval request is no longer pending' });
      }
      if (String(pending.action) !== action || String(pending.agent_id) !== agent_id) {
        return reply.status(409).send({ error: 'Approval request does not match action or target agent' });
      }
      if (String(pending.initiated_by) === callerId) {
        return reply.status(409).send({ error: 'Second approval must be from another user' });
      }
      const createdAtMs = new Date(String(pending.created_at)).getTime();
      if (!Number.isFinite(createdAtMs) || Date.now() - createdAtMs > APPROVAL_TTL_MS) {
        return reply.status(410).send({ error: 'Approval request expired' });
      }
      if (await edr.isResponseApprovalConsumed(orgId, approval_id)) {
        return reply.status(409).send({ error: 'Approval request already consumed' });
      }
      const pendingResult = parseJsonObject(pending.result);
      if (typeof pendingResult.payload_hash === 'string' && pendingResult.payload_hash !== actionPayloadHash) {
        return reply.status(409).send({ error: 'Payload mismatch with pending approval' });
      }

      const job = await jobSvc.createJob(fastify, {
        org_id: orgId,
        agent_id,
        job_type: action as JobType,
        payload,
        created_by: callerId,
        reason,
      });

      await edr.createResponseAction(orgId, {
        agent_id,
        action,
        job_id: job.id,
        initiated_by: callerId,
        reason,
        status: 'approved_dispatched',
        result: {
          approval_id,
          requested_by: pending.initiated_by,
          approved_by: callerId,
          payload_hash: actionPayloadHash,
        },
      });

      await request.audit({
        action: 'edr_respond_approved',
        entity_type: 'agent',
        entity_id: agent_id,
        details: { action, approval_id, job_id: job.id, reason },
      });

      return reply.status(201).send({ job_id: job.id, approval_id, approved: true });
    }

    // Create the job
    const job = await jobSvc.createJob(fastify, {
      org_id: orgId,
      agent_id,
      job_type: action as JobType,
      payload,
      created_by: callerId,
      reason,
    });

    // Log response action
    await edr.createResponseAction(orgId, {
      agent_id,
      action,
      job_id: job.id,
      initiated_by: callerId,
      reason,
      status: 'dispatched',
      result: { mode: 'single_approval', payload_hash: actionPayloadHash },
    });

    await request.audit({
      action: 'edr_respond', entity_type: 'agent', entity_id: agent_id,
      details: { action, job_id: job.id, reason },
    });

    return reply.status(201).send({ job_id: job.id });
  });

  // ══════════════════════════════════════════════
  // EDR Overview Stats
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/overview', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request) => {
    return edr.getEdrOverview(request.currentUser.org_id);
  });

  // ══════════════════════════════════════════════
  // Incident Detail + Timeline
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/incidents/:id', {
    preHandler: [fastify.requirePermission(Permission.EdrIncidentManage)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const incident = await edr.getIncidentById(request.currentUser.org_id, id);
    if (!incident) return reply.status(404).send({ error: 'Incident not found' });
    return incident;
  });

  fastify.get('/api/edr/incidents/:id/timeline', {
    preHandler: [fastify.requirePermission(Permission.EdrIncidentManage)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    return edr.getIncidentTimeline(request.currentUser.org_id, id);
  });

  fastify.post('/api/edr/incidents/:id/timeline', {
    preHandler: [fastify.requirePermission(Permission.EdrIncidentManage)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const schema = z.object({ entry_type: z.enum(['note', 'evidence']), summary: z.string().min(1).max(2000) });
    const parsed = schema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });
    await edr.addIncidentTimelineEntry(id, parsed.data.entry_type, parsed.data.summary, request.currentUser.id);
    await request.audit({ action: 'incident_note_add', entity_type: 'incident', entity_id: id, details: { entry_type: parsed.data.entry_type } });
    return { ok: true };
  });

  // ══════════════════════════════════════════════
  // Detection Detail
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/detections/:id', {
    preHandler: [fastify.requirePermission(Permission.EdrDetectionsView)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const detection = await edr.getDetectionById(request.currentUser.org_id, id);
    if (!detection) return reply.status(404).send({ error: 'Detection not found' });
    return detection;
  });

  // ══════════════════════════════════════════════
  // EDR Rules CRUD
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/rules', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request) => {
    return edr.listRules(request.currentUser.org_id);
  });

  fastify.get('/api/edr/rules/:id', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request, reply) => {
    const { id } = request.params as any;
    const rule = await edr.getRuleById(request.currentUser.org_id, id);
    if (!rule) return reply.status(404).send({ error: 'Rule not found' });
    return rule;
  });

  const CreateRuleSchema = z.object({
    rule_id: z.string().min(3).max(100).regex(/^[A-Z0-9_]+$/),
    name: z.string().min(1).max(200),
    description: z.string().max(2000).optional(),
    severity: z.enum(['low', 'medium', 'high', 'critical']),
    logic: z.record(z.any()),
    event_types: z.array(z.string()).optional(),
    mitre_tactic: z.string().max(60).optional(),
    mitre_technique: z.string().max(20).optional(),
    tags: z.array(z.string()).optional(),
    dedup_window_sec: z.number().int().min(0).max(86400).optional(),
    threshold_count: z.number().int().min(1).max(10000).optional(),
    threshold_window_sec: z.number().int().min(0).max(86400).optional(),
    monitor_only: z.boolean().optional(),
  });

  fastify.post('/api/edr/rules', {
    preHandler: [fastify.requirePermission(Permission.EdrPolicyManage)],
  }, async (request, reply) => {
    const parsed = CreateRuleSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });
    const result = await edr.createRule(request.currentUser.org_id, parsed.data);
    await request.audit({ action: 'edr_rule_create', entity_type: 'edr_rule', entity_id: result.id, details: { rule_id: parsed.data.rule_id, name: parsed.data.name } });
    return reply.status(201).send(result);
  });

  fastify.patch('/api/edr/rules/:id', {
    preHandler: [fastify.requirePermission(Permission.EdrPolicyManage)],
  }, async (request, reply) => {
    const { id } = request.params as any;
    const UpdateRuleSchema = z.object({
      name: z.string().min(1).max(200).optional(),
      description: z.string().max(2000).optional(),
      severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
      logic: z.record(z.any()).optional(),
      is_active: z.boolean().optional(),
      event_types: z.array(z.string()).optional(),
      mitre_tactic: z.string().max(60).optional(),
      mitre_technique: z.string().max(20).optional(),
      tags: z.array(z.string()).optional(),
      dedup_window_sec: z.number().int().min(0).max(86400).optional(),
      threshold_count: z.number().int().min(1).max(10000).optional(),
      threshold_window_sec: z.number().int().min(0).max(86400).optional(),
      monitor_only: z.boolean().optional(),
    });
    const parsed = UpdateRuleSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });
    const ok = await edr.updateRule(request.currentUser.org_id, id, parsed.data);
    if (!ok) return reply.status(404).send({ error: 'Rule not found or is built-in' });
    await request.audit({ action: 'edr_rule_update', entity_type: 'edr_rule', entity_id: id, details: parsed.data });
    return { ok: true };
  });

  fastify.delete('/api/edr/rules/:id', {
    preHandler: [fastify.requirePermission(Permission.EdrPolicyManage)],
  }, async (request, reply) => {
    const { id } = request.params as any;
    const ok = await edr.deleteRule(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ error: 'Rule not found or is built-in (cannot delete)' });
    await request.audit({ action: 'edr_rule_delete', entity_type: 'edr_rule', entity_id: id });
    return { ok: true };
  });

  // ══════════════════════════════════════════════
  // Rule Exceptions / Allowlists
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/exceptions', {
    preHandler: [fastify.requirePermission(Permission.EdrPolicyManage)],
  }, async (request) => {
    const q = request.query as any;
    return edr.listExceptions(request.currentUser.org_id, q.rule_id);
  });

  const CreateExceptionSchema = z.object({
    rule_id: z.string().min(1).max(100),
    scope: z.enum(['org', 'site', 'device']),
    scope_id: z.string().uuid().optional(),
    field: z.string().min(1).max(50),
    pattern: z.string().min(1).max(2000),
    is_regex: z.boolean().optional(),
    reason: z.string().max(1000).optional(),
    expires_at: z.string().optional(),
  });

  fastify.post('/api/edr/exceptions', {
    preHandler: [fastify.requirePermission(Permission.EdrPolicyManage)],
  }, async (request, reply) => {
    const parsed = CreateExceptionSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });
    const result = await edr.createException(request.currentUser.org_id, {
      ...parsed.data,
      created_by: request.currentUser.id,
    });
    await request.audit({ action: 'edr_exception_create', entity_type: 'edr_exception', entity_id: result.id, details: parsed.data });
    return reply.status(201).send(result);
  });

  fastify.delete('/api/edr/exceptions/:id', {
    preHandler: [fastify.requirePermission(Permission.EdrPolicyManage)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const ok = await edr.deleteException(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ error: 'Exception not found' });
    await request.audit({ action: 'edr_exception_delete', entity_type: 'edr_exception', entity_id: id });
    return { ok: true };
  });

  // ══════════════════════════════════════════════
  // Threat Hunting
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/hunt', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request) => {
    const q = request.query as any;
    return edr.hunt(request.currentUser.org_id, {
      q: q.q,
      event_type: q.event_type,
      agent_id: q.agent_id,
      sha256: q.sha256,
      dst_ip: q.dst_ip,
      image: q.image,
      cmdline: q.cmdline,
      from: q.from,
      to: q.to,
      page: Number(q.page) || 1,
      limit: clampLimit(q.limit, 50),
    });
  });

  fastify.get('/api/edr/hunt/saved', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request) => {
    return edr.listHuntQueries(request.currentUser.org_id, request.currentUser.id);
  });

  fastify.post('/api/edr/hunt/saved', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request, reply) => {
    const schema = z.object({
      name: z.string().min(1).max(200),
      description: z.string().max(2000).optional(),
      query: z.record(z.any()),
      is_shared: z.boolean().optional(),
    });
    const parsed = schema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });
    const result = await edr.saveHuntQuery(request.currentUser.org_id, request.currentUser.id, parsed.data);
    return reply.status(201).send(result);
  });

  fastify.delete('/api/edr/hunt/saved/:id', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const ok = await edr.deleteHuntQuery(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ error: 'Query not found' });
    return { ok: true };
  });

  // ══════════════════════════════════════════════
  // Device Isolation State
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/isolation', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request) => {
    return edr.listIsolatedDevices(request.currentUser.org_id);
  });

  fastify.get('/api/edr/isolation/:agentId', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request, reply) => {
    const agentId = parseUUID((request.params as any).agentId, reply);
    if (!agentId) return;
    const state = await edr.getIsolationState(request.currentUser.org_id, agentId);
    return state ?? { is_isolated: false };
  });

  // ══════════════════════════════════════════════
  // Quarantine Registry
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/quarantine', {
    preHandler: [fastify.requirePermission(Permission.EdrEventsView)],
  }, async (request) => {
    const q = request.query as any;
    return edr.listQuarantine(request.currentUser.org_id, q.agent_id);
  });

  // ══════════════════════════════════════════════
  // Response Actions Log
  // ══════════════════════════════════════════════
  fastify.get('/api/edr/actions', {
    preHandler: [fastify.requirePermission(Permission.EdrRespond)],
  }, async (request) => {
    const q = request.query as any;
    return edr.listResponseActions(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: clampLimit(q.limit, 50),
      agent_id: q.agent_id,
      action: q.action,
    });
  });
}

// ─────────────────────────────────────────────
// MASSVISION Reap3r — EDR Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { Permission, CreateIncidentSchema, EdrRespondSchema, JobType } from '@massvision/shared';
import * as edr from '../services/edr.service.js';
import * as jobSvc from '../services/job.service.js';
import { parseUUID, clampLimit } from '../lib/validate.js';

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
    preHandler: [fastify.requirePermission(Permission.EdrDetectionsView)],
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
    const parsed = EdrRespondSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const { agent_id, action, payload, reason } = parsed.data;

    // Create the job
    const job = await jobSvc.createJob(fastify, {
      org_id: request.currentUser.org_id,
      agent_id,
      job_type: action as JobType,
      payload,
      created_by: request.currentUser.id,
      reason,
    });

    // Log response action
    await edr.createResponseAction(request.currentUser.org_id, {
      agent_id,
      action,
      job_id: job.id,
      initiated_by: request.currentUser.id,
      reason,
    });

    await request.audit({
      action: 'edr_respond', entity_type: 'agent', entity_id: agent_id,
      details: { action, job_id: job.id, reason },
    });

    return reply.status(201).send({ job_id: job.id });
  });
}

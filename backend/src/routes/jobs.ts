// ─────────────────────────────────────────────
// MASSVISION Reap3r — Job Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission, JobTypePermission, JobType, CreateJobSchema } from '@massvision/shared';
import { RolePermissions, Role } from '@massvision/shared';
import * as jobService from '../services/job.service.js';
import { createAuditLog } from '../services/audit.service.js';
import { parseUUID, parseBody, clampLimit } from '../lib/validate.js';

export default async function jobRoutes(fastify: FastifyInstance) {
  // ── List jobs ──
  fastify.get('/api/jobs', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.JobList)] }, async (request) => {
    const query = request.query as any;
    return jobService.listJobs(fastify, {
      org_id: request.currentUser.org_id,
      agent_id: query.agent_id,
      status: query.status,
      type: query.type,
      page: query.page ? Number(query.page) : undefined,
      limit: clampLimit(query.limit),
    });
  });

  // ── Get job ──
  fastify.get('/api/jobs/:id', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.JobView)] }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const job = await jobService.getJobById(fastify, id);
    if (!job) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    return job;
  });

  // ── Create job ──
  fastify.post('/api/jobs', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.JobCreate)] }, async (request, reply) => {
    const body = parseBody(CreateJobSchema, request.body, reply);
    if (!body) return;
    const { agent_id, job_type, payload, reason, priority, timeout_sec } = body;

    // Check job-type specific permission
    const requiredPerm = JobTypePermission[job_type as JobType];
    if (requiredPerm) {
      const userPerms = RolePermissions[request.currentUser.role as Role] ?? [];
      if (!userPerms.includes(requiredPerm as any)) {
        return reply.status(403).send({
          statusCode: 403, error: 'Forbidden',
          message: `Missing permission for job type ${job_type}: ${requiredPerm}`,
        });
      }
    }

    const job = await jobService.createJob(fastify, {
      agent_id,
      job_type,
      payload: payload ?? {},
      created_by: request.currentUser.id,
      org_id: request.currentUser.org_id,
      reason,
      priority,
      timeout_sec,
    });

    await createAuditLog(fastify, {
      user_id: request.currentUser.id, org_id: request.currentUser.org_id,
      action: 'job.create', entity_type: 'job', entity_id: job.id,
      details: { agent_id, job_type, reason }, ip_address: request.ip,
    });

    // Agent gateway dispatches on the next heartbeat to keep the wire protocol strictly v1 (no ad-hoc messages).

    return reply.status(201).send(job);
  });

  // ── Cancel job ──
  fastify.post('/api/jobs/:id/cancel', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.JobCancel)] }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const job = await jobService.getJobById(fastify, id);
    if (!job) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    if (!['pending', 'queued', 'dispatched', 'running'].includes(job.status)) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Job is not cancellable' });
    }
    await jobService.cancelJob(fastify, id);
    await createAuditLog(fastify, {
      user_id: request.currentUser.id, org_id: request.currentUser.org_id,
      action: 'job.cancel', entity_type: 'job', entity_id: id,
      details: null, ip_address: request.ip,
    });
    return { message: 'Job cancelled' };
  });

  // ── Job stats ──
  fastify.get('/api/jobs/stats', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DashboardView)] }, async (request) => {
    const orgId = request.currentUser.org_id;
    const res = await fastify.pg.query(
      `SELECT status, count(*)::int FROM jobs WHERE org_id = $1 GROUP BY status`,
      [orgId],
    );
    const stats: Record<string, number> = { pending: 0, queued: 0, dispatched: 0, running: 0, completed: 0, failed: 0, cancelled: 0 };
    for (const r of res.rows) {
      stats[r.status] = r.count;
    }
    return stats;
  });
}

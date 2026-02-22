// ─────────────────────────────────────────────
// MASSVISION Reap3r — Job Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission, JobPayloadSchemas, JobTypePermission, JobType, CreateJobSchema, canonicalJsonStringify } from '@massvision/shared';
import { RolePermissions, Role } from '@massvision/shared';
import * as jobService from '../services/job.service.js';
import { createAuditLog } from '../services/audit.service.js';
import { parseUUID, parseBody, clampLimit } from '../lib/validate.js';
import { createHmac, randomUUID } from 'crypto';
import { config } from '../config.js';
import { hydrateJobPayloadForDispatch } from '../services/job-dispatch.service.js';
import { toV2RunScriptPayload } from '../lib/v2-run-script.js';

function toV2JobType(type: string): string {
  return String(type || '').toLowerCase();
}

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

  // ── Job stats — MUST be before /:id to avoid route shadowing ──
  fastify.get('/api/jobs/stats', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DashboardView)] }, async (request) => {
    const orgId = request.currentUser.org_id;
    const res = await fastify.pg.query(
      `SELECT status, count(*)::int FROM jobs WHERE org_id = $1 GROUP BY status`,
      [orgId],
    );
    const stats: Record<string, number> = { total: 0, pending: 0, queued: 0, dispatched: 0, running: 0, completed: 0, failed: 0, cancelled: 0 };
    for (const r of res.rows) {
      stats[r.status] = r.count;
      stats.total += r.count;
    }
    return stats;
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
    const { agent_id, job_type, reason, priority, timeout_sec } = body;
    let payloadInput = body.payload ?? {};

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

    const payloadSchema = JobPayloadSchemas[job_type as JobType];
    if (payloadSchema) {
      const payloadParsed = payloadSchema.safeParse(payloadInput);
      if (!payloadParsed.success) {
        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: payloadParsed.error.message,
        });
      }
      payloadInput = payloadParsed.data;
    }

    const job = await jobService.createJob(fastify, {
      agent_id,
      job_type,
      payload: payloadInput,
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

    // Proactive push: if the agent is online, dispatch the job immediately instead of
    // waiting for the next heartbeat (up to 30s). This is critical for time-sensitive
    // operations like remote_desktop_start.
    try {
      const agentWs = fastify.agentSockets?.get(agent_id);
      if (agentWs && agentWs.readyState === 1) {
        const hydratedArgs = await hydrateJobPayloadForDispatch(fastify, request.currentUser.org_id, payloadInput);
        const jobPayload = {
          job_id: job.id,
          name: job_type,
          args: hydratedArgs,
          timeout_sec: timeout_sec ?? 300,
          created_at: new Date(job.created_at).toISOString(),
        };
        const envelope = {
          type: 'job_assign' as const,
          ts: Date.now(),
          nonce: randomUUID(),
          traceId: randomUUID(),
          agentId: agent_id,
          payload: jobPayload,
        };
        const sig = createHmac('sha256', config.hmac.secret)
          .update(canonicalJsonStringify(envelope)).digest('hex');
        agentWs.send(JSON.stringify({ ...envelope, sig }));
        await jobService.updateJobStatus(fastify, job.id, 'dispatched');
        fastify.log.info({ job_id: job.id, job_type }, 'Job pushed immediately to agent');
      }

      // v2 agents (Rust): run_script + remote desktop jobs.
      if ((!agentWs || agentWs.readyState !== 1) && fastify.agentSocketsV2) {
        const ws2 = fastify.agentSocketsV2.get(agent_id);
        if (ws2 && ws2.readyState === 1) {
          const jt = toV2JobType(job_type);
          if (jt === 'run_script' || jt === 'list_monitors' || jt === 'remote_desktop_start' || jt === 'remote_desktop_stop') {
            const v2Payload = jt === 'run_script' ? toV2RunScriptPayload(payloadInput) : payloadInput;
            const msg = {
              type: 'job',
              job_id: job.id,
              job_type: jt,
              payload: v2Payload,
              timeout_secs: (timeout_sec ?? 300),
              priority: Number(priority ?? 0) || 0,
              created_at: new Date(job.created_at).toISOString(),
            };
            ws2.send(JSON.stringify(msg));
            await jobService.updateJobStatus(fastify, job.id, 'dispatched');
            fastify.log.info({ job_id: job.id, job_type }, 'Job pushed immediately to agent (v2)');
          } else {
            fastify.log.warn({ job_id: job.id, job_type }, 'Job type not supported on agent v2 WS (will remain pending)');
          }
        }
      }
    } catch (err) {
      fastify.log.warn({ err }, 'Proactive job push failed (will fall back to heartbeat)');
    }

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
}

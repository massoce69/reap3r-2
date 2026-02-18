// ─────────────────────────────────────────────
// MASSVISION Reap3r — Job Service
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';

/* ── Create ── */
export async function createJob(
  fastify: FastifyInstance,
  data: {
    agent_id: string;
    job_type: string;
    payload: Record<string, unknown>;
    created_by: string;
    org_id: string;
    reason?: string;
    priority?: number;
    timeout_sec?: number;
  },
) {
  const { rows } = await fastify.pg.query(
    `INSERT INTO jobs (agent_id, type, payload, created_by, org_id, reason, priority, status, timeout_secs)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8)
     RETURNING *`,
    [
      data.agent_id,
      data.job_type,
      JSON.stringify(data.payload),
      data.created_by,
      data.org_id,
      data.reason ?? null,
      data.priority ?? 0,
      data.timeout_sec ?? 300,
    ],
  );
  return rows[0];
}

/* ── List ── */
export async function listJobs(
  fastify: FastifyInstance,
  opts: {
    org_id: string;
    agent_id?: string;
    status?: string;
    type?: string;
    page?: number;
    limit?: number;
  },
) {
  const page = opts.page ?? 1;
  const limit = Math.min(opts.limit ?? 50, 200);
  const offset = (page - 1) * limit;

  const conditions: string[] = ['j.org_id = $1'];
  const params: unknown[] = [opts.org_id];
  let idx = 2;

  if (opts.agent_id) { conditions.push(`j.agent_id = $${idx++}`); params.push(opts.agent_id); }
  if (opts.status) { conditions.push(`j.status = $${idx++}`); params.push(opts.status); }
  if (opts.type) { conditions.push(`j.type = $${idx++}`); params.push(opts.type); }

  const where = `WHERE ${conditions.join(' AND ')}`;

  const countRes = await fastify.pg.query(`SELECT count(*)::int FROM jobs j ${where}`, params);
  const total = countRes.rows[0].count;

  const dataRes = await fastify.pg.query(
    `SELECT j.*, a.hostname as agent_hostname, u.name as created_by_name
     FROM jobs j
     LEFT JOIN agents a ON a.id = j.agent_id
     LEFT JOIN users u ON u.id = j.created_by
     ${where}
     ORDER BY j.created_at DESC
     LIMIT $${idx++} OFFSET $${idx++}`,
    [...params, limit, offset],
  );

  return { data: dataRes.rows, total, page, limit };
}

/* ── Get ── */
export async function getJobById(fastify: FastifyInstance, id: string) {
  const { rows } = await fastify.pg.query(
    `SELECT j.*, a.hostname as agent_hostname, u.name as created_by_name
     FROM jobs j
     LEFT JOIN agents a ON a.id = j.agent_id
     LEFT JOIN users u ON u.id = j.created_by
     WHERE j.id = $1`,
    [id],
  );
  return rows[0] ?? null;
}

/* ── Pending jobs for agent ── */
export async function getPendingJobs(fastify: FastifyInstance, agentId: string) {
  const { rows } = await fastify.pg.query(
    // Backward compatible: older DBs used 'queued' default.
    `SELECT * FROM jobs WHERE agent_id = $1 AND status IN ('pending', 'queued') ORDER BY priority DESC, created_at ASC`,
    [agentId],
  );
  return rows;
}

/* ── Status update ── */
export async function updateJobStatus(
  fastify: FastifyInstance,
  jobId: string,
  status: string,
  result?: Record<string, unknown>,
) {
  const fields = ['status = $2'];
  const params: unknown[] = [jobId, status];
  let idx = 3;

  if (status === 'dispatched') {
    fields.push('assigned_at = now()');
  } else if (status === 'running') {
    fields.push('started_at = now()');
  } else if (status === 'completed' || status === 'failed' || status === 'cancelled') {
    fields.push('completed_at = now()');
  }

  if (result !== undefined) {
    fields.push(`result = $${idx++}`);
    params.push(JSON.stringify(result));
  }

  await fastify.pg.query(`UPDATE jobs SET ${fields.join(', ')} WHERE id = $1`, params);
}

/* ── Save result ── */
export async function saveJobResult(
  fastify: FastifyInstance,
  jobId: string,
  exitCode: number,
  stdout: string,
  stderr: string,
) {
  await fastify.pg.query(
    `UPDATE jobs SET status = CASE WHEN $2 = 0 THEN 'completed' ELSE 'failed' END,
       result = jsonb_build_object('exit_code', $2, 'stdout', $3, 'stderr', $4),
       completed_at = now()
     WHERE id = $1`,
    [jobId, exitCode, stdout, stderr],
  );
}

/* ── Timeout expired ── */
export async function timeoutExpiredJobs(fastify: FastifyInstance, timeoutMinutes: number = 30) {
  await fastify.pg.query(
    `UPDATE jobs SET status = 'failed',
       result = jsonb_build_object('error', 'Job timed out'),
       completed_at = now()
     WHERE status IN ('pending', 'queued', 'dispatched', 'running')
       AND created_at < now() - interval '1 minute' * $1`,
    [timeoutMinutes],
  );
}

/* ── Cancel ── */
export async function cancelJob(fastify: FastifyInstance, jobId: string) {
  await fastify.pg.query(
    `UPDATE jobs SET status = 'cancelled', completed_at = now() WHERE id = $1 AND status IN ('pending', 'queued', 'dispatched', 'running')`,
    [jobId],
  );
}

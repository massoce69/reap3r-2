// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent Service
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import crypto from 'crypto';

/* ── Enroll ── */
export async function validateEnrollmentToken(fastify: FastifyInstance, token: string) {
  const { rows } = await fastify.pg.query(
    `SELECT * FROM enrollment_tokens
     WHERE token = $1 AND revoked = false AND (expires_at IS NULL OR expires_at > now())
       AND (COALESCE(max_uses, 0) = 0 OR use_count < COALESCE(max_uses, 0))`,
    [token],
  );
  return rows[0] ?? null;
}

export async function enrollAgent(
  fastify: FastifyInstance,
  data: {
    hostname: string;
    os: string;
    os_version?: string | null;
    arch: string;
    agent_version: string;
    token_id: string;
    org_id: string;
    site_id: string | null;
    company_id: string | null;
    folder_id: string | null;
    last_ip: string | null;
  },
) {
  const client = await fastify.pg.connect();
  try {
    await client.query('BEGIN');

    const agentSecret = crypto.randomBytes(32).toString('hex');
    const { rows } = await client.query(
      `INSERT INTO agents (hostname, os, os_version, arch, agent_version, org_id, site_id, company_id, status, agent_secret, enrolled_at, last_seen_at, last_ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'online', $9, now(), now(), $10)
       RETURNING *`,
      [
        data.hostname,
        data.os,
        data.os_version ?? '',
        data.arch,
        data.agent_version,
        data.org_id,
        data.site_id,
        data.company_id,
        agentSecret,
        data.last_ip,
      ],
    );
    const agent = rows[0];

    // Increment token usage
    await client.query(`UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE id = $1`, [data.token_id]);

    // Add to folder if specified
    if (data.folder_id) {
      await client.query(
        `INSERT INTO agent_folder_membership (agent_id, folder_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
        [agent.id, data.folder_id],
      );
    }

    await client.query('COMMIT');
    return agent;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

/* ── List ── */
export async function listAgents(
  fastify: FastifyInstance,
  opts: {
    org_id: string;
    company_id?: string;
    folder_id?: string;
    status?: string;
    search?: string;
    os?: string;
    isolated?: boolean;
    page?: number;
    limit?: number;
    sort_by?: string;
    sort_dir?: string;
  },
) {
  const page = opts.page ?? 1;
  const limit = Math.min(opts.limit ?? 50, 200);
  const offset = (page - 1) * limit;
  const sortBy = ['hostname', 'os', 'status', 'last_seen_at', 'created_at'].includes(opts.sort_by ?? '')
    ? opts.sort_by!
    : 'last_seen_at';
  const sortDir = opts.sort_dir === 'asc' ? 'ASC' : 'DESC';

  const conditions: string[] = ['a.org_id = $1'];
  const params: unknown[] = [opts.org_id];
  let idx = 2;

  if (opts.company_id) { conditions.push(`a.company_id = $${idx++}`); params.push(opts.company_id); }
  if (opts.status) { conditions.push(`a.status = $${idx++}`); params.push(opts.status); }
  if (opts.os) { conditions.push(`a.os ILIKE $${idx++}`); params.push(`%${opts.os}%`); }
  if (opts.search) { conditions.push(`a.hostname ILIKE $${idx++}`); params.push(`%${opts.search}%`); }
  if (opts.isolated !== undefined) { conditions.push(`a.isolated = $${idx++}`); params.push(opts.isolated); }
  if (opts.folder_id) {
    conditions.push(`EXISTS (SELECT 1 FROM agent_folder_membership afm WHERE afm.agent_id = a.id AND afm.folder_id = $${idx++})`);
    params.push(opts.folder_id);
  }

  const where = `WHERE ${conditions.join(' AND ')}`;

  const countRes = await fastify.pg.query(`SELECT count(*)::int FROM agents a ${where}`, params);
  const total = countRes.rows[0].count;

  const dataRes = await fastify.pg.query(
    `SELECT a.*, c.name as company_name,
       (SELECT json_agg(json_build_object('id', f.id, 'name', f.name))
        FROM agent_folder_membership afm JOIN folders f ON f.id = afm.folder_id WHERE afm.agent_id = a.id) as folders
     FROM agents a
     LEFT JOIN companies c ON c.id = a.company_id
     ${where}
     ORDER BY a.${sortBy} ${sortDir}
     LIMIT $${idx++} OFFSET $${idx++}`,
    [...params, limit, offset],
  );

  return { data: dataRes.rows, total, page, limit };
}

/* ── Get / Update / Delete ── */
export async function getAgentById(fastify: FastifyInstance, id: string) {
  const { rows } = await fastify.pg.query(
    `SELECT a.*, c.name as company_name,
       (SELECT json_agg(json_build_object('id', f.id, 'name', f.name))
        FROM agent_folder_membership afm JOIN folders f ON f.id = afm.folder_id WHERE afm.agent_id = a.id) as folders
     FROM agents a LEFT JOIN companies c ON c.id = a.company_id
     WHERE a.id = $1`,
    [id],
  );
  return rows[0] ?? null;
}

export async function deleteAgent(fastify: FastifyInstance, id: string) {
  await fastify.pg.query(`DELETE FROM agents WHERE id = $1`, [id]);
}

export async function updateAgentStatus(fastify: FastifyInstance, id: string, status: string) {
  await fastify.pg.query(
    `UPDATE agents SET status = $2, last_seen_at = now() WHERE id = $1`,
    [id, status],
  );
}

/* ── Heartbeat ── */
export async function heartbeat(
  fastify: FastifyInstance,
  agentId: string,
  data: { last_ip?: string; agent_version?: string; cpu_percent?: number; mem_percent?: number; disk_percent?: number },
) {
  const fields = ['last_seen_at = now()', "status = 'online'"];
  const params: unknown[] = [];
  let idx = 1;

  if (data.last_ip) { fields.push(`last_ip = $${idx++}`); params.push(data.last_ip); }
  if (data.agent_version) { fields.push(`agent_version = $${idx++}`); params.push(data.agent_version); }
  if (data.cpu_percent !== undefined) { fields.push(`cpu_percent = $${idx++}`); params.push(data.cpu_percent); }
  if (data.mem_percent !== undefined) { fields.push(`mem_percent = $${idx++}`); params.push(data.mem_percent); }
  if (data.disk_percent !== undefined) { fields.push(`disk_percent = $${idx++}`); params.push(data.disk_percent); }

  params.push(agentId);
  await fastify.pg.query(`UPDATE agents SET ${fields.join(', ')} WHERE id = $${idx}`, params);
}

/* ── Capabilities ── */
export async function updateCapabilities(fastify: FastifyInstance, agentId: string, payload: Record<string, unknown>) {
  const raw = (payload as any)?.capabilities;
  const caps: string[] = Array.isArray(raw) ? raw.map((c) => String(c)).filter(Boolean) : [];

  const client = await fastify.pg.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM agent_capabilities WHERE agent_id = $1`, [agentId]);
    for (const cap of caps) {
      await client.query(
        `INSERT INTO agent_capabilities (agent_id, capability) VALUES ($1, $2)
         ON CONFLICT (agent_id, capability) DO UPDATE SET updated_at = now()`,
        [agentId, cap],
      );
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

/* ── Mark offline ── */
export async function markStaleAgentsOffline(fastify: FastifyInstance, thresholdSeconds: number = 120) {
  await fastify.pg.query(
    `UPDATE agents SET status = 'offline'
     WHERE status = 'online' AND last_seen_at < now() - interval '1 second' * $1`,
    [thresholdSeconds],
  );
}

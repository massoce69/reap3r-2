// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent API v2 (Rust agent)
// ─────────────────────────────────────────────
// This API is consumed by `massvision-agent` (Rust) which enrolls via HTTP
// and then uses signed envelopes for subsequent HTTP calls.

import { FastifyInstance } from 'fastify';
import crypto from 'node:crypto';
import { z } from 'zod';

type SignedEnvelope = {
  payload: string;
  timestamp: number;
  nonce: string;
  hmac: string;
};

const EnrollmentPayloadSchema = z.object({
  enrollment_token: z.string().min(1),
  machine_id: z.string().min(1),
  hostname: z.string().min(1),
  os_info: z.string().min(1),
  agent_version: z.string().min(1),
});

const SignedEnvelopeSchema = z.object({
  payload: z.string().min(1),
  timestamp: z.number().int(),
  nonce: z.string().min(1),
  hmac: z.string().regex(/^[0-9a-fA-F]{64}$/),
});

function safeTimingEqualHex(aHex: string, bHex: string): boolean {
  try {
    const a = Buffer.from(String(aHex || '').toLowerCase(), 'hex');
    const b = Buffer.from(String(bHex || '').toLowerCase(), 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function computeV2HmacHex(agentToken: string, payload: string, timestamp: number, nonce: string): string {
  const mac = crypto.createHmac('sha256', Buffer.from(agentToken, 'utf8'));
  mac.update(Buffer.from(payload, 'utf8'));

  // Rust: i64::to_le_bytes (8 bytes)
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigInt64LE(BigInt(timestamp));
  mac.update(tsBuf);
  mac.update(Buffer.from(nonce, 'utf8'));

  return mac.digest('hex');
}

async function getAgentSecret(fastify: FastifyInstance, agentId: string): Promise<string | null> {
  const { rows } = await fastify.pg.query(`SELECT agent_secret FROM agents WHERE id = $1`, [agentId]);
  const secret = rows?.[0]?.agent_secret ? String(rows[0].agent_secret) : '';
  return secret.trim() ? secret : null;
}

async function verifySignedEnvelope(
  fastify: FastifyInstance,
  agentId: string,
  envelope: SignedEnvelope,
): Promise<{ ok: true; payload: any } | { ok: false; statusCode: number; message: string }> {
  const secret = await getAgentSecret(fastify, agentId);
  if (!secret) return { ok: false, statusCode: 401, message: 'Unknown agent' };

  // 5 minute replay window (same as agent)
  const ageMs = Math.abs(Date.now() - envelope.timestamp);
  if (ageMs > 300_000) return { ok: false, statusCode: 401, message: 'Signed message too old' };

  const expected = computeV2HmacHex(secret, envelope.payload, envelope.timestamp, envelope.nonce);
  if (!safeTimingEqualHex(expected, envelope.hmac)) return { ok: false, statusCode: 401, message: 'Invalid signature' };

  try {
    return { ok: true, payload: JSON.parse(envelope.payload) };
  } catch {
    return { ok: false, statusCode: 400, message: 'Invalid payload JSON' };
  }
}

function envServerPublicKey(): string {
  const v = String(process.env.REAP3R_SERVER_PUBLIC_KEY || process.env.AGENT_SERVER_PUBLIC_KEY || '').trim();
  return v;
}

export default async function agentV2Routes(fastify: FastifyInstance) {
  // Enrollment (unsigned)
  fastify.post('/api/agents-v2/enroll', async (request, reply) => {
    const parsed = EnrollmentPayloadSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: parsed.error.issues.map(i => i.message).join('; ') });
    }

    const body = parsed.data;
    const enrollmentToken = body.enrollment_token;

    const client = await fastify.pg.connect();
    try {
      await client.query('BEGIN');

      const tokRes = await client.query(
        `SELECT * FROM enrollment_tokens WHERE token = $1 FOR UPDATE`,
        [enrollmentToken],
      );
      const tokenRow = tokRes.rows[0];
      if (!tokenRow) {
        await client.query('ROLLBACK');
        return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid enrollment token' });
      }
      if (tokenRow.revoked) {
        await client.query('ROLLBACK');
        return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Enrollment token revoked' });
      }
      if (tokenRow.expires_at && new Date(tokenRow.expires_at).getTime() < Date.now()) {
        await client.query('ROLLBACK');
        return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Enrollment token expired' });
      }
      const maxUses = Number(tokenRow.max_uses || 0);
      const useCount = Number(tokenRow.use_count || 0);
      if (maxUses > 0 && useCount >= maxUses) {
        await client.query('ROLLBACK');
        return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Enrollment token max uses reached' });
      }

      // Reuse existing agent if machine_id was seen before (stored in tags)
      const orgId = String(tokenRow.org_id);
      const siteId = tokenRow.site_id ? String(tokenRow.site_id) : null;
      const companyId = tokenRow.company_id ? String(tokenRow.company_id) : null;
      const folderId = tokenRow.folder_id ? String(tokenRow.folder_id) : null;

      const machineTag = `machine:${body.machine_id}`;
      const existingRes = await client.query(
        `SELECT id FROM agents WHERE org_id = $1 AND tags @> ARRAY[$2]::text[] LIMIT 1`,
        [orgId, machineTag],
      );

      const agentToken = crypto.randomBytes(32).toString('hex');
      let agentId: string;

      if (existingRes.rows.length > 0) {
        agentId = String(existingRes.rows[0].id);
        await client.query(
          `UPDATE agents
           SET hostname = $1,
               os = $2,
               agent_version = $3,
               site_id = COALESCE($4, site_id),
               company_id = COALESCE($5, company_id),
               agent_secret = $6,
               status = 'online',
               last_seen_at = NOW(),
               last_ip = $7,
               enrolled_at = COALESCE(enrolled_at, NOW()),
               updated_at = NOW()
           WHERE id = $8`,
          [
            body.hostname,
            body.os_info,
            body.agent_version,
            siteId,
            companyId,
            agentToken,
            request.ip,
            agentId,
          ],
        );
      } else {
        const tags = [machineTag, 'agent:v2'];
        const agentRes = await client.query(
          `INSERT INTO agents (org_id, site_id, company_id, hostname, os, os_version, arch, agent_version, status, agent_secret, last_seen_at, last_ip, tags, enrolled_at)
           VALUES ($1, $2, $3, $4, $5, '', 'x86_64', $6, 'online', $7, NOW(), $8, $9, NOW())
           RETURNING id`,
          [orgId, siteId, companyId, body.hostname, body.os_info, body.agent_version, agentToken, request.ip, tags],
        );
        agentId = String(agentRes.rows[0].id);
      }

      // Folder membership (optional)
      if (folderId) {
        await client.query(
          `INSERT INTO agent_folder_membership (agent_id, folder_id)
           VALUES ($1, $2)
           ON CONFLICT (agent_id, folder_id) DO NOTHING`,
          [agentId, folderId],
        );
      }

      await client.query(`UPDATE enrollment_tokens SET use_count = use_count + 1 WHERE id = $1`, [tokenRow.id]);
      await client.query('COMMIT');

      return reply.send({
        agent_id: agentId,
        agent_token: agentToken,
        server_public_key: envServerPublicKey(),
        policies: [],
      });
    } catch (e: any) {
      try { await client.query('ROLLBACK'); } catch {}
      request.log.error(e);
      return reply.status(500).send({ statusCode: 500, error: 'Internal Server Error', message: 'Enrollment failed' });
    } finally {
      client.release();
    }
  });

  // Signed endpoints (minimal set for agent stability)
  async function handleSigned(request: any, reply: any, onPayload: (payload: any, agentId: string) => Promise<any>) {
    const agentId = String(request.headers['x-agent-id'] || request.headers['X-Agent-Id'] || '').trim();
    if (!agentId) return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Missing X-Agent-Id' });

    const envParsed = SignedEnvelopeSchema.safeParse(request.body);
    if (!envParsed.success) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Invalid signed envelope' });
    }
    const envelope = envParsed.data;
    const verified = await verifySignedEnvelope(fastify, agentId, envelope);
    if (!verified.ok) return reply.status(verified.statusCode).send({ statusCode: verified.statusCode, error: 'Unauthorized', message: verified.message });

    // Update liveness (cheap)
    try {
      await fastify.pg.query(`UPDATE agents SET last_seen_at = NOW(), status = 'online', last_ip = $1, updated_at = NOW() WHERE id = $2`, [request.ip, agentId]);
    } catch {}

    return onPayload(verified.payload, agentId);
  }

  fastify.post('/api/agents-v2/heartbeat', async (request, reply) => {
    return handleSigned(request, reply, async (payload, agentId) => {
      // Best-effort: update some agent fields from heartbeat
      try {
        const hostname = typeof payload?.hostname === 'string' ? payload.hostname : undefined;
        const osInfo = typeof payload?.os_info === 'string' ? payload.os_info : undefined;
        const agentVersion = typeof payload?.agent_version === 'string' ? payload.agent_version : undefined;
        if (hostname || osInfo || agentVersion) {
          await fastify.pg.query(
            `UPDATE agents SET hostname = COALESCE($1, hostname), os = COALESCE($2, os), agent_version = COALESCE($3, agent_version), updated_at = NOW() WHERE id = $4`,
            [hostname ?? null, osInfo ?? null, agentVersion ?? null, agentId],
          );
        }
      } catch {}
      return reply.send({ ok: true });
    });
  });

  fastify.post('/api/agents-v2/metrics', async (request, reply) => {
    return handleSigned(request, reply, async (payload, agentId) => {
      try {
        const collectedAt = payload?.timestamp ? new Date(payload.timestamp) : new Date();
        const cpu = typeof payload?.cpu_usage_percent === 'number' ? payload.cpu_usage_percent : null;
        const memUsed = typeof payload?.memory_used_mb === 'number' ? payload.memory_used_mb : null;
        const memTotal = typeof payload?.memory_total_mb === 'number' ? payload.memory_total_mb : null;

        const disks = Array.isArray(payload?.disks) ? payload.disks : [];
        const diskTotals = disks.reduce(
          (acc: any, d: any) => {
            const total = typeof d?.total_gb === 'number' ? d.total_gb : 0;
            const used = typeof d?.used_gb === 'number' ? d.used_gb : 0;
            acc.total += total;
            acc.used += used;
            return acc;
          },
          { total: 0, used: 0 },
        );

        const nets = Array.isArray(payload?.network_interfaces) ? payload.network_interfaces : [];
        const netTotals = nets.reduce(
          (acc: any, n: any) => {
            const tx = typeof n?.bytes_sent === 'number' ? n.bytes_sent : 0;
            const rx = typeof n?.bytes_received === 'number' ? n.bytes_received : 0;
            acc.tx += tx;
            acc.rx += rx;
            return acc;
          },
          { tx: 0, rx: 0 },
        );

        await fastify.pg.query(
          `INSERT INTO metrics_timeseries (agent_id, collected_at, cpu_percent, memory_used_mb, memory_total_mb, disk_used_gb, disk_total_gb, network_rx_bytes, network_tx_bytes, processes_count)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [
            agentId,
            collectedAt,
            cpu,
            memUsed,
            memTotal,
            diskTotals.used || null,
            diskTotals.total || null,
            netTotals.rx || null,
            netTotals.tx || null,
            null,
          ],
        );
      } catch {}
      return reply.send({ ok: true });
    });
  });

  fastify.post('/api/agents-v2/inventory', async (request, reply) => {
    return handleSigned(request, reply, async (payload, agentId) => {
      try {
        const collectedAt = payload?.timestamp ? new Date(payload.timestamp) : new Date();
        await fastify.pg.query(
          `INSERT INTO inventory_snapshots (agent_id, collected_at, data) VALUES ($1, $2, $3)`,
          [agentId, collectedAt, payload ?? {}],
        );
      } catch {}
      return reply.send({ ok: true });
    });
  });

  fastify.post('/api/agents-v2/jobs/result', async (request, reply) => {
    return handleSigned(request, reply, async (payload, agentId) => {
      try {
        const jobId = typeof payload?.job_id === 'string' ? payload.job_id : null;
        if (jobId) {
          await fastify.pg.query(
            `INSERT INTO job_results (job_id, agent_id, exit_code, stdout, stderr, data, duration_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
              jobId,
              agentId,
              typeof payload?.exit_code === 'number' ? payload.exit_code : null,
              typeof payload?.stdout === 'string' ? payload.stdout : null,
              typeof payload?.stderr === 'string' ? payload.stderr : null,
              payload ?? {},
              typeof payload?.duration_ms === 'number' ? payload.duration_ms : null,
            ],
          );
          await fastify.pg.query(
            `UPDATE jobs SET status = $1, completed_at = NOW(), result = $2, error = $3 WHERE id = $4 AND agent_id = $5`,
            [
              String(payload?.status || '').toLowerCase() === 'success' ? 'completed' : 'failed',
              payload ?? {},
              typeof payload?.stderr === 'string' ? payload.stderr : null,
              jobId,
              agentId,
            ],
          );
        }
      } catch {}
      return reply.send({ ok: true });
    });
  });

  fastify.post('/api/agents-v2/webcam/capture', async (request, reply) => {
    return handleSigned(request, reply, async (_payload, _agentId) => {
      // Not implemented yet (artifact storage). Ack to avoid breaking agent.
      return reply.send({ ok: true });
    });
  });
}

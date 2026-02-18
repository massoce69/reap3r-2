// ─────────────────────────────────────────────
// MASSVISION Reap3r — Audit Service
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';

export interface AuditEntry {
  user_id: string | null;
  org_id: string | null;
  action: string;
  entity_type: string;
  entity_id: string | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
}

export async function createAuditLog(fastify: FastifyInstance, entry: AuditEntry) {
  const { rows } = await fastify.pg.query(
    `INSERT INTO audit_logs (user_id, org_id, action, resource_type, resource_id, details, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     RETURNING *`,
    [entry.user_id, entry.org_id, entry.action, entry.entity_type, entry.entity_id, JSON.stringify(entry.details), entry.ip_address],
  );
  return rows[0];
}

export async function listAuditLogs(
  fastify: FastifyInstance,
  opts: { org_id?: string; user_id?: string; entity_type?: string; entity_id?: string; action?: string; page?: number; limit?: number },
) {
  const page = opts.page ?? 1;
  const limit = Math.min(opts.limit ?? 50, 200);
  const offset = (page - 1) * limit;

  const conditions: string[] = [];
  const params: unknown[] = [];
  let idx = 1;

  if (opts.org_id) {
    conditions.push(`al.org_id = $${idx++}`);
    params.push(opts.org_id);
  }
  if (opts.user_id) {
    conditions.push(`al.user_id = $${idx++}`);
    params.push(opts.user_id);
  }
  if (opts.entity_type) {
    conditions.push(`al.resource_type = $${idx++}`);
    params.push(opts.entity_type);
  }
  if (opts.entity_id) {
    conditions.push(`al.resource_id = $${idx++}`);
    params.push(opts.entity_id);
  }
  if (opts.action) {
    conditions.push(`al.action ILIKE $${idx++}`);
    params.push(`%${opts.action}%`);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const countRes = await fastify.pg.query(`SELECT count(*)::int FROM audit_logs al ${where}`, params);
  const total = countRes.rows[0].count;

  const dataRes = await fastify.pg.query(
    `SELECT al.*, u.name as user_name
     FROM audit_logs al
     LEFT JOIN users u ON u.id = al.user_id
     ${where}
     ORDER BY al.created_at DESC
     LIMIT $${idx++} OFFSET $${idx++}`,
    [...params, limit, offset],
  );

  return { data: dataRes.rows, total, page, limit };
}

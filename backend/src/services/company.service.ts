// ─────────────────────────────────────────────
// MASSVISION Reap3r — Company Service
// ─────────────────────────────────────────────
import { query } from '../db/pool.js';

export async function createCompany(orgId: string, data: { name: string; notes?: string; contact_email?: string; contact_phone?: string }) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO companies (org_id, name, notes, contact_email, contact_phone) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
    [orgId, data.name, data.notes ?? null, data.contact_email ?? null, data.contact_phone ?? null]
  );
  return rows[0];
}

export async function updateCompany(orgId: string, id: string, data: Partial<{ name: string; notes: string; contact_email: string; contact_phone: string }>) {
  const sets: string[] = ['updated_at = NOW()'];
  const vals: unknown[] = [];
  let idx = 1;

  if (data.name !== undefined) { sets.push(`name = $${idx}`); vals.push(data.name); idx++; }
  if (data.notes !== undefined) { sets.push(`notes = $${idx}`); vals.push(data.notes); idx++; }
  if (data.contact_email !== undefined) { sets.push(`contact_email = $${idx}`); vals.push(data.contact_email); idx++; }
  if (data.contact_phone !== undefined) { sets.push(`contact_phone = $${idx}`); vals.push(data.contact_phone); idx++; }

  vals.push(orgId, id);
  const { rowCount } = await query(
    `UPDATE companies SET ${sets.join(', ')} WHERE org_id = $${idx} AND id = $${idx + 1}`, vals
  );
  return (rowCount ?? 0) > 0;
}

export async function deleteCompany(orgId: string, id: string) {
  const { rowCount } = await query(`DELETE FROM companies WHERE org_id = $1 AND id = $2`, [orgId, id]);
  return (rowCount ?? 0) > 0;
}

export async function getCompanyById(orgId: string, id: string) {
  const { rows } = await query(
    `SELECT c.*,
       (SELECT COUNT(*) FROM agents a WHERE a.company_id = c.id)::int AS agent_count,
       (SELECT COUNT(*) FROM agents a WHERE a.company_id = c.id AND a.status = 'online')::int AS online_count
     FROM companies c WHERE c.org_id = $1 AND c.id = $2`,
    [orgId, id]
  );
  return rows[0] ?? null;
}

export async function listCompanies(orgId: string, params: { page: number; limit: number; q?: string }) {
  const conditions = ['c.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.q) {
    conditions.push(`c.name ILIKE $${idx}`);
    vals.push(`%${params.q}%`);
    idx++;
  }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT c.*,
         (SELECT COUNT(*) FROM agents a WHERE a.company_id = c.id)::int AS agent_count,
         (SELECT COUNT(*) FROM agents a WHERE a.company_id = c.id AND a.status = 'online')::int AS online_count
       FROM companies c WHERE ${where} ORDER BY c.name ASC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM companies c WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

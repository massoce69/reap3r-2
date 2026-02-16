// ─────────────────────────────────────────────
// MASSVISION Reap3r — Folder Service
// ─────────────────────────────────────────────
import { query } from '../db/pool.js';

export async function createFolder(orgId: string, data: { name: string; company_id?: string | null; parent_folder_id?: string | null }) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO folders (org_id, name, company_id, parent_folder_id) VALUES ($1,$2,$3,$4) RETURNING id`,
    [orgId, data.name, data.company_id ?? null, data.parent_folder_id ?? null]
  );
  return rows[0];
}

export async function updateFolder(orgId: string, id: string, data: Partial<{ name: string; company_id: string | null; parent_folder_id: string | null }>) {
  const sets: string[] = ['updated_at = NOW()'];
  const vals: unknown[] = [];
  let idx = 1;

  if (data.name !== undefined) { sets.push(`name = $${idx}`); vals.push(data.name); idx++; }
  if (data.company_id !== undefined) { sets.push(`company_id = $${idx}`); vals.push(data.company_id); idx++; }
  if (data.parent_folder_id !== undefined) { sets.push(`parent_folder_id = $${idx}`); vals.push(data.parent_folder_id); idx++; }

  vals.push(orgId, id);
  const { rowCount } = await query(
    `UPDATE folders SET ${sets.join(', ')} WHERE org_id = $${idx} AND id = $${idx + 1}`, vals
  );
  return (rowCount ?? 0) > 0;
}

export async function deleteFolder(orgId: string, id: string) {
  const { rowCount } = await query(`DELETE FROM folders WHERE org_id = $1 AND id = $2`, [orgId, id]);
  return (rowCount ?? 0) > 0;
}

export async function getFolderById(orgId: string, id: string) {
  const { rows } = await query(
    `SELECT f.*,
       (SELECT COUNT(*) FROM agent_folder_membership afm WHERE afm.folder_id = f.id)::int AS agent_count
     FROM folders f WHERE f.org_id = $1 AND f.id = $2`,
    [orgId, id]
  );
  return rows[0] ?? null;
}

export async function listFolders(orgId: string, params: { page: number; limit: number; company_id?: string; q?: string }) {
  const conditions = ['f.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.company_id) { conditions.push(`f.company_id = $${idx}`); vals.push(params.company_id); idx++; }
  if (params.q) { conditions.push(`f.name ILIKE $${idx}`); vals.push(`%${params.q}%`); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT f.*,
         (SELECT COUNT(*) FROM agent_folder_membership afm WHERE afm.folder_id = f.id)::int AS agent_count
       FROM folders f WHERE ${where} ORDER BY f.name ASC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM folders f WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

export async function addAgentToFolder(agentId: string, folderId: string) {
  await query(
    `INSERT INTO agent_folder_membership (agent_id, folder_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [agentId, folderId]
  );
}

export async function removeAgentFromFolder(agentId: string, folderId: string) {
  await query(`DELETE FROM agent_folder_membership WHERE agent_id = $1 AND folder_id = $2`, [agentId, folderId]);
}

export async function getAgentFolders(agentId: string) {
  const { rows } = await query(
    `SELECT f.* FROM folders f JOIN agent_folder_membership afm ON afm.folder_id = f.id WHERE afm.agent_id = $1 ORDER BY f.name`,
    [agentId]
  );
  return rows;
}

// ─────────────────────────────────────────────
// MASSVISION Reap3r — Admin Service (Users, Teams)
// ─────────────────────────────────────────────
import { query } from '../db/pool.js';

// ── Teams ──
export async function createTeam(orgId: string, data: { name: string; description?: string }) {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO teams (org_id, name, description) VALUES ($1,$2,$3) RETURNING id`,
    [orgId, data.name, data.description ?? null]
  );
  return rows[0];
}

export async function listTeams(orgId: string) {
  const { rows } = await query(
    `SELECT t.*, (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = t.id)::int AS member_count
     FROM teams t WHERE t.org_id = $1 ORDER BY t.name`,
    [orgId]
  );
  return rows;
}

export async function getTeamById(orgId: string, id: string) {
  const { rows } = await query(
    `SELECT t.*, (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = t.id)::int AS member_count
     FROM teams t WHERE t.org_id = $1 AND t.id = $2`,
    [orgId, id]
  );
  return rows[0] ?? null;
}

export async function updateTeam(orgId: string, id: string, data: Partial<{ name: string; description: string }>) {
  const sets: string[] = ['updated_at = NOW()'];
  const vals: unknown[] = [];
  let idx = 1;
  if (data.name) { sets.push(`name = $${idx}`); vals.push(data.name); idx++; }
  if (data.description !== undefined) { sets.push(`description = $${idx}`); vals.push(data.description); idx++; }
  vals.push(orgId, id);
  await query(`UPDATE teams SET ${sets.join(', ')} WHERE org_id = $${idx} AND id = $${idx + 1}`, vals);
}

export async function deleteTeam(orgId: string, id: string) {
  await query(`DELETE FROM teams WHERE org_id = $1 AND id = $2`, [orgId, id]);
}

export async function addTeamMember(teamId: string, userId: string, role = 'member') {
  await query(
    `INSERT INTO team_members (team_id, user_id, role) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
    [teamId, userId, role]
  );
}

export async function removeTeamMember(teamId: string, userId: string) {
  await query(`DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`, [teamId, userId]);
}

export async function getTeamMembers(teamId: string) {
  const { rows } = await query(
    `SELECT tm.role, u.id, u.email, u.name, u.role AS user_role FROM team_members tm JOIN users u ON u.id = tm.user_id WHERE tm.team_id = $1 ORDER BY u.name`,
    [teamId]
  );
  return rows;
}

// ── Login events ──
export async function logLoginEvent(orgId: string, data: {
  user_id?: string; email: string; success: boolean; ip_address?: string; user_agent?: string; failure_reason?: string;
}) {
  await query(
    `INSERT INTO login_events (org_id, user_id, email, success, ip_address, user_agent, failure_reason)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [orgId, data.user_id ?? null, data.email, data.success, data.ip_address ?? null, data.user_agent ?? null, data.failure_reason ?? null]
  );
}

export async function listLoginEvents(orgId: string, params: { page: number; limit: number; user_id?: string; success?: boolean }) {
  const conditions = ['org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.user_id) { conditions.push(`user_id = $${idx}`); vals.push(params.user_id); idx++; }
  if (params.success !== undefined) { conditions.push(`success = $${idx}`); vals.push(params.success); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT le.*, u.name AS user_name FROM login_events le LEFT JOIN users u ON u.id = le.user_id
       WHERE ${where} ORDER BY le.created_at DESC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM login_events WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

// ── Policies ──
export async function listPolicies(orgId: string) {
  const { rows } = await query(`SELECT * FROM policies WHERE org_id = $1 ORDER BY category, name`, [orgId]);
  return rows;
}

export async function updatePolicy(orgId: string, id: string, data: { settings?: any; is_active?: boolean }) {
  const sets: string[] = ['updated_at = NOW()'];
  const vals: unknown[] = [];
  let idx = 1;
  if (data.settings !== undefined) { sets.push(`settings = $${idx}`); vals.push(JSON.stringify(data.settings)); idx++; }
  if (data.is_active !== undefined) { sets.push(`is_active = $${idx}`); vals.push(data.is_active); idx++; }
  vals.push(orgId, id);
  await query(`UPDATE policies SET ${sets.join(', ')} WHERE org_id = $${idx} AND id = $${idx + 1}`, vals);
}

// ── Users extended ──
export async function suspendUser(orgId: string, userId: string, active: boolean) {
  await query(`UPDATE users SET is_active = $1, updated_at = NOW() WHERE org_id = $2 AND id = $3`, [active, orgId, userId]);
}

export async function listUsersAdvanced(orgId: string, params: { page: number; limit: number; q?: string; role?: string; is_active?: boolean }) {
  const conditions = ['u.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.q) { conditions.push(`(u.name ILIKE $${idx} OR u.email ILIKE $${idx})`); vals.push(`%${params.q}%`); idx++; }
  if (params.role) { conditions.push(`u.role = $${idx}`); vals.push(params.role); idx++; }
  if (params.is_active !== undefined) { conditions.push(`u.is_active = $${idx}`); vals.push(params.is_active); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT u.id, u.org_id, u.email, u.name, u.role, u.is_active, u.mfa_enabled, u.last_login_at, u.created_at, u.updated_at
       FROM users u WHERE ${where} ORDER BY u.name ASC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM users u WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

// ── Sessions Management ──
export async function getUserSessions(userId: string) {
  const { rows } = await query(
    `SELECT id, user_id, ip_address, user_agent, is_active, last_used_at, expires_at, created_at
     FROM sessions WHERE user_id = $1 ORDER BY last_used_at DESC`,
    [userId]
  );
  return rows;
}

export async function revokeSession(sessionId: string) {
  await query(`UPDATE sessions SET is_active = false WHERE id = $1`, [sessionId]);
}

export async function revokeAllUserSessions(userId: string) {
  await query(`UPDATE sessions SET is_active = false WHERE user_id = $1`, [userId]);
}

// ── MFA Management ──
export async function setupMFA(userId: string, secret: string) {
  await query(
    `UPDATE users SET mfa_secret = $1, mfa_enabled = false, updated_at = NOW() WHERE id = $2`,
    [secret, userId]
  );
}

export async function enableMFA(userId: string) {
  await query(
    `UPDATE users SET mfa_enabled = true, updated_at = NOW() WHERE id = $1`,
    [userId]
  );
}

export async function disableMFA(userId: string) {
  await query(
    `UPDATE users SET mfa_enabled = false, mfa_secret = NULL, updated_at = NOW() WHERE id = $1`,
    [userId]
  );
}

export async function getMFASecret(userId: string): Promise<string | null> {
  const { rows } = await query<{ mfa_secret: string | null }>(
    `SELECT mfa_secret FROM users WHERE id = $1`,
    [userId]
  );
  return rows[0]?.mfa_secret ?? null;
}

// ── Roles & Permissions ──
export async function getAllRoles() {
  // Return roles with proper enum keys matching the Role enum in shared/rbac.ts
  return [
    { key: 'super_admin', name: 'Super Admin', description: 'Full system access' },
    { key: 'org_admin', name: 'Org Admin', description: 'Organization administrator' },
    { key: 'operator', name: 'Operator', description: 'Standard operator' },
    { key: 'soc_analyst', name: 'SOC Analyst', description: 'Security analyst' },
    { key: 'viewer', name: 'Viewer', description: 'View-only access' },
  ];
}

export async function updateUserRole(orgId: string, userId: string, role: string) {
  await query(
    `UPDATE users SET role = $1, updated_at = NOW() WHERE org_id = $2 AND id = $3`,
    [role, orgId, userId]
  );
}

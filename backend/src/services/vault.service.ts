// ─────────────────────────────────────────────
// MASSVISION Reap3r — Vault (Secrets) Service
// ─────────────────────────────────────────────
import crypto from 'crypto';
import { query } from '../db/pool.js';
import { config } from '../config.js';

// ── Envelope encryption (simple AES-256-GCM + master key from env) ──
const ALGO = 'aes-256-gcm';

function getMasterKey(): Buffer {
  const key = process.env.VAULT_MASTER_KEY || config.hmac.secret;
  return crypto.createHash('sha256').update(key).digest();
}

export function encryptSecret(plaintext: string): Buffer {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, getMasterKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Format: [iv(16) | tag(16) | encrypted]
  return Buffer.concat([iv, tag, encrypted]);
}

export function decryptSecret(blob: Buffer): string {
  const iv = blob.subarray(0, 16);
  const tag = blob.subarray(16, 32);
  const data = blob.subarray(32);
  const decipher = crypto.createDecipheriv(ALGO, getMasterKey(), iv);
  decipher.setAuthTag(tag);
  return decipher.update(data) + decipher.final('utf8');
}

export async function createSecret(orgId: string, userId: string, data: {
  name: string; type: string; value: string;
  company_id?: string | null; folder_id?: string | null;
  tags?: string[]; notes?: string; expires_at?: string; metadata?: Record<string, string>;
}) {
  const blob = encryptSecret(data.value);
  const { rows } = await query<{ id: string }>(
    `INSERT INTO secrets (org_id, name, type, encrypted_blob, company_id, folder_id, tags, notes, expires_at, metadata_json, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
    [orgId, data.name, data.type, blob, data.company_id ?? null, data.folder_id ?? null,
     data.tags ?? [], data.notes ?? null, data.expires_at ?? null,
     data.metadata ? JSON.stringify(data.metadata) : '{}', userId]
  );
  return rows[0];
}

export async function updateSecret(orgId: string, id: string, userId: string, data: Partial<{
  name: string; value: string; tags: string[]; notes: string; expires_at: string | null; metadata: Record<string, string>;
}>) {
  // Archive current version if value changes
  if (data.value !== undefined) {
    const { rows } = await query<{ encrypted_blob: Buffer }>(
      `SELECT encrypted_blob FROM secrets WHERE org_id = $1 AND id = $2`, [orgId, id]
    );
    if (rows[0]) {
      await createSecretVersion(id, userId, rows[0].encrypted_blob, 'Auto-snapshot before update');
    }
  }

  const sets: string[] = ['updated_at = NOW()'];
  const vals: unknown[] = [];
  let idx = 1;

  if (data.name !== undefined) { sets.push(`name = $${idx}`); vals.push(data.name); idx++; }
  if (data.value !== undefined) { sets.push(`encrypted_blob = $${idx}`); vals.push(encryptSecret(data.value)); idx++; }
  if (data.tags !== undefined) { sets.push(`tags = $${idx}`); vals.push(data.tags); idx++; }
  if (data.notes !== undefined) { sets.push(`notes = $${idx}`); vals.push(data.notes); idx++; }
  if (data.expires_at !== undefined) { sets.push(`expires_at = $${idx}`); vals.push(data.expires_at); idx++; }
  if (data.metadata !== undefined) { sets.push(`metadata_json = $${idx}`); vals.push(JSON.stringify(data.metadata)); idx++; }

  vals.push(orgId, id);
  const { rowCount } = await query(
    `UPDATE secrets SET ${sets.join(', ')} WHERE org_id = $${idx} AND id = $${idx + 1}`, vals
  );
  return (rowCount ?? 0) > 0;
}

export async function deleteSecret(orgId: string, id: string) {
  const { rowCount } = await query(`DELETE FROM secrets WHERE org_id = $1 AND id = $2`, [orgId, id]);
  return (rowCount ?? 0) > 0;
}

export async function revealSecret(
  orgId: string,
  id: string,
  userId?: string,
  role?: string,
): Promise<string | null> {
  const { rows } = await query<{ encrypted_blob: Buffer; created_by: string | null }>(
    `SELECT encrypted_blob, created_by FROM secrets WHERE org_id = $1 AND id = $2`, [orgId, id]
  );
  if (!rows[0]) return null;

  // ACL: admin/super_admin bypass, creator bypass; otherwise check secret_permissions
  if (userId && role && role !== 'super_admin' && role !== 'org_admin') {
    const isCreator = rows[0].created_by === userId;
    if (!isCreator) {
      const perm = await query<{ id: string }>(
        `SELECT id FROM secret_permissions
         WHERE secret_id = $1 AND principal_type = 'user' AND principal_id = $2 AND 'reveal' = ANY(rights)
         UNION ALL
         SELECT sp.id FROM secret_permissions sp
           JOIN team_members tm ON sp.principal_type = 'team' AND sp.principal_id = tm.team_id::text
         WHERE sp.secret_id = $1 AND tm.user_id = $3 AND 'reveal' = ANY(sp.rights)
         LIMIT 1`,
        [id, userId, userId]
      );
      if ((perm.rowCount ?? 0) === 0) return null; // no permission → act as not found
    }
  }

  return decryptSecret(rows[0].encrypted_blob);
}

export async function listSecrets(orgId: string, params: {
  page: number; limit: number; q?: string; company_id?: string; folder_id?: string; type?: string;
}) {
  const conditions = ['s.org_id = $1'];
  const vals: unknown[] = [orgId];
  let idx = 2;

  if (params.q) { conditions.push(`s.name ILIKE $${idx}`); vals.push(`%${params.q}%`); idx++; }
  if (params.company_id) { conditions.push(`s.company_id = $${idx}`); vals.push(params.company_id); idx++; }
  if (params.folder_id) { conditions.push(`s.folder_id = $${idx}`); vals.push(params.folder_id); idx++; }
  if (params.type) { conditions.push(`s.type = $${idx}`); vals.push(params.type); idx++; }

  const where = conditions.join(' AND ');
  const offset = (params.page - 1) * params.limit;

  const [dataRes, countRes] = await Promise.all([
    query(
      `SELECT s.id, s.org_id, s.name, s.type, s.company_id, s.folder_id, s.tags, s.notes,
              s.expires_at, s.metadata_json AS metadata, s.created_by, s.created_at, s.updated_at
       FROM secrets s WHERE ${where} ORDER BY s.name ASC LIMIT $${idx} OFFSET $${idx + 1}`,
      [...vals, params.limit, offset]
    ),
    query(`SELECT COUNT(*)::int AS total FROM secrets s WHERE ${where}`, vals),
  ]);

  return { data: dataRes.rows, total: countRes.rows[0].total, page: params.page, limit: params.limit };
}

export async function logSecretAccess(secretId: string, userId: string, action: string, ip: string | null, userAgent: string | null) {
  await query(
    `INSERT INTO secret_access_logs (secret_id, user_id, action, ip_address, user_agent) VALUES ($1,$2,$3,$4,$5)`,
    [secretId, userId, action, ip, userAgent]
  );
}

export async function getSecretAccessLogs(secretId: string, limit = 50) {
  const { rows } = await query(
    `SELECT sal.*, u.name AS user_name, u.email AS user_email
     FROM secret_access_logs sal LEFT JOIN users u ON u.id = sal.user_id
     WHERE sal.secret_id = $1 ORDER BY sal.created_at DESC LIMIT $2`,
    [secretId, limit]
  );
  return rows;
}

// ── Secret Versioning ──
export async function createSecretVersion(secretId: string, userId: string, encrypted_blob: Buffer, change_note?: string) {
  await query(
    `INSERT INTO secret_versions (secret_id, encrypted_blob, changed_by, change_note)
     VALUES ($1, $2, $3, $4)`,
    [secretId, encrypted_blob, userId, change_note ?? null]
  );
}

export async function getSecretVersions(secretId: string, limit = 20) {
  const { rows } = await query(
    `SELECT sv.*, u.name AS changed_by_name, u.email AS changed_by_email
     FROM secret_versions sv LEFT JOIN users u ON u.id = sv.changed_by
     WHERE sv.secret_id = $1 ORDER BY sv.created_at DESC LIMIT $2`,
    [secretId, limit]
  );
  return rows;
}

export async function getSecretVersionById(versionId: string): Promise<{ encrypted_blob: Buffer } | null> {
  const { rows } = await query<{ encrypted_blob: Buffer }>(
    `SELECT encrypted_blob FROM secret_versions WHERE id = $1`,
    [versionId]
  );
  return rows[0] ?? null;
}

// ── Secret Sharing (Permissions) ──
export async function shareSecret(secretId: string, principal_type: 'user' | 'team', principal_id: string, rights: string[]) {
  await query(
    `INSERT INTO secret_permissions (secret_id, principal_type, principal_id, rights)
     VALUES ($1, $2, $3, $4) ON CONFLICT (secret_id, principal_type, principal_id) DO UPDATE SET rights = EXCLUDED.rights`,
    [secretId, principal_type, principal_id, rights]
  );
}

export async function revokeSecretShare(secretId: string, principal_type: string, principal_id: string) {
  await query(
    `DELETE FROM secret_permissions WHERE secret_id = $1 AND principal_type = $2 AND principal_id = $3`,
    [secretId, principal_type, principal_id]
  );
}

export async function getSecretPermissions(secretId: string) {
  const { rows } = await query(
    `SELECT sp.*, 
      CASE WHEN sp.principal_type = 'user' THEN u.name ELSE t.name END AS principal_name
     FROM secret_permissions sp
     LEFT JOIN users u ON sp.principal_type = 'user' AND sp.principal_id = u.id::text
     LEFT JOIN teams t ON sp.principal_type = 'team' AND sp.principal_id = t.id::text
     WHERE sp.secret_id = $1 ORDER BY sp.created_at DESC`,
    [secretId]
  );
  return rows;
}

// ── Secret Expiration & Rotation ──
export async function getExpiringSecrets(orgId: string, days: number = 30) {
  const { rows } = await query(
    `SELECT id, name, type, expires_at FROM secrets
     WHERE org_id = $1 AND expires_at IS NOT NULL 
     AND expires_at <= NOW() + INTERVAL '${days} days' 
     AND expires_at > NOW()
     ORDER BY expires_at ASC`,
    [orgId]
  );
  return rows;
}

export async function markSecretAsRotated(secretId: string, userId: string) {
  await query(
    `UPDATE secrets SET 
      metadata_json = jsonb_set(COALESCE(metadata_json, '{}'::jsonb), '{last_rotation}', to_jsonb(NOW()::text)),
      metadata_json = jsonb_set(metadata_json, '{rotated_by}', to_jsonb($2::text)),
      updated_at = NOW()
     WHERE id = $1`,
    [secretId, userId]
  );
}

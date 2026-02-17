// ─────────────────────────────────────────────
// MASSVISION Reap3r — API Key Service
// CRUD for scoped, expirable API keys with hashing
// ─────────────────────────────────────────────
import crypto from 'node:crypto';
import { query } from '../db/pool.js';

const API_KEY_PREFIX = 'rp3r_';

// Generate a cryptographically secure API key
function generateKey(): { raw: string; hash: string; prefix: string } {
  const bytes = crypto.randomBytes(32);
  const raw = API_KEY_PREFIX + bytes.toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const prefix = raw.substring(0, 12);
  return { raw, hash, prefix };
}

// Hash an API key for lookup
export function hashKey(rawKey: string): string {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

// ── Create API Key ──
export async function createApiKey(orgId: string, userId: string, params: {
  name: string;
  scopes?: string[];
  rate_limit?: number;
  expires_at?: string;
}): Promise<{ id: string; key: string; name: string; key_prefix: string; scopes: string[]; expires_at: string | null; created_at: string }> {
  const { raw, hash, prefix } = generateKey();
  const scopes = params.scopes ?? ['read'];
  const rateLimit = params.rate_limit ?? 100;

  const { rows } = await query(
    `INSERT INTO api_keys (org_id, user_id, name, key_hash, key_prefix, scopes, rate_limit, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id, name, key_prefix, scopes, rate_limit, expires_at, created_at`,
    [orgId, userId, params.name, hash, prefix, scopes, rateLimit, params.expires_at ?? null],
  );

  return { ...rows[0], key: raw };
}

// ── List API Keys (never expose hash) ──
export async function listApiKeys(orgId: string): Promise<any[]> {
  const { rows } = await query(
    `SELECT id, name, key_prefix, scopes, rate_limit, is_active, last_used_at, expires_at, created_at, updated_at
     FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`,
    [orgId],
  );
  return rows;
}

// ── Validate API Key (returns user context if valid) ──
export async function validateApiKey(rawKey: string): Promise<{
  id: string; org_id: string; user_id: string; scopes: string[];
  user_email: string; user_name: string; user_role: string;
} | null> {
  const hash = hashKey(rawKey);
  const { rows } = await query(
    `SELECT ak.id, ak.org_id, ak.user_id, ak.scopes, ak.expires_at,
            u.email AS user_email, u.name AS user_name, u.role AS user_role
     FROM api_keys ak
     JOIN users u ON u.id = ak.user_id
     WHERE ak.key_hash = $1 AND ak.is_active = TRUE AND u.is_active = TRUE`,
    [hash],
  );
  if (!rows.length) return null;

  const key = rows[0];
  // Check expiration
  if (key.expires_at && new Date(key.expires_at) < new Date()) return null;

  // Update last_used_at
  await query(`UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, [key.id]);

  return {
    id: key.id,
    org_id: key.org_id,
    user_id: key.user_id,
    scopes: key.scopes,
    user_email: key.user_email,
    user_name: key.user_name,
    user_role: key.user_role,
  };
}

// ── Revoke API Key ──
export async function revokeApiKey(orgId: string, keyId: string): Promise<boolean> {
  const { rowCount } = await query(
    `UPDATE api_keys SET is_active = FALSE, updated_at = NOW() WHERE id = $1 AND org_id = $2`,
    [keyId, orgId],
  );
  return (rowCount ?? 0) > 0;
}

// ── Delete API Key ──
export async function deleteApiKey(orgId: string, keyId: string): Promise<boolean> {
  const { rowCount } = await query(
    `DELETE FROM api_keys WHERE id = $1 AND org_id = $2`,
    [keyId, orgId],
  );
  return (rowCount ?? 0) > 0;
}

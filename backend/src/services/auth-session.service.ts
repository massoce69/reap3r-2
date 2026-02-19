import crypto from 'node:crypto';
import { FastifyInstance } from 'fastify';
import { Permission, Role, RolePermissions } from '@massvision/shared';
import { config } from '../config.js';

const LAST_USED_TOUCH_INTERVAL_SECONDS = 30;
const DEFAULT_REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

type JwtPayload = {
  id: string;
  email: string;
  name: string;
  role: Role;
  org_id: string;
  sid?: string;
  typ?: 'access' | 'refresh';
};

function parseDurationToMs(value: string, fallbackMs: number): number {
  const raw = (value || '').trim().toLowerCase();
  const m = raw.match(/^(\d+)([smhd])?$/);
  if (!m) return fallbackMs;
  const amount = Number(m[1]);
  const unit = m[2] ?? 's';
  if (!Number.isFinite(amount) || amount <= 0) return fallbackMs;
  switch (unit) {
    case 's': return amount * 1000;
    case 'm': return amount * 60 * 1000;
    case 'h': return amount * 60 * 60 * 1000;
    case 'd': return amount * 24 * 60 * 60 * 1000;
    default: return fallbackMs;
  }
}

function refreshTokenLifetimeMs(): number {
  return parseDurationToMs(config.jwt.refreshExpiresIn, DEFAULT_REFRESH_TTL_MS);
}

function accessTokenLifetimeSeconds(): number {
  return Math.floor(parseDurationToMs(config.jwt.expiresIn, 24 * 60 * 60 * 1000) / 1000);
}

function refreshTokenLifetimeSeconds(): number {
  return Math.floor(refreshTokenLifetimeMs() / 1000);
}

function issueAccessToken(fastify: FastifyInstance, user: {
  id: string;
  email: string;
  name: string;
  role: Role;
  org_id: string;
}, sessionId: string): string {
  return fastify.jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      org_id: user.org_id,
      sid: sessionId,
      typ: 'access',
    },
    { expiresIn: config.jwt.expiresIn },
  );
}

function refreshExpiryDate(): Date {
  return new Date(Date.now() + refreshTokenLifetimeMs());
}

export function generateOpaqueRefreshToken(): string {
  return crypto.randomBytes(48).toString('hex');
}

export function hashRefreshToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export interface SessionAuthResult {
  id: string;
  email: string;
  name: string;
  role: Role;
  org_id: string;
  session_id: string;
  permissions: Permission[];
}

export interface TokenPair {
  token: string;
  refresh_token: string;
  access_expires_in_sec: number;
  refresh_expires_in_sec: number;
  session_id: string;
}

export async function createSessionAndIssueTokens(
  fastify: FastifyInstance,
  user: {
    id: string;
    email: string;
    name: string;
    role: Role;
    org_id: string;
  },
  meta: {
    ip?: string | null;
    userAgent?: string | null;
  },
): Promise<TokenPair> {
  const refreshToken = generateOpaqueRefreshToken();
  const refreshHash = hashRefreshToken(refreshToken);
  const expiresAt = refreshExpiryDate();

  const { rows } = await fastify.pg.query<{ id: string }>(
    `INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at, last_used_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     RETURNING id`,
    [user.id, refreshHash, meta.ip ?? null, meta.userAgent ?? null, expiresAt.toISOString()],
  );
  const sessionId = rows[0].id;
  const token = issueAccessToken(fastify, user, sessionId);

  return {
    token,
    refresh_token: refreshToken,
    access_expires_in_sec: accessTokenLifetimeSeconds(),
    refresh_expires_in_sec: refreshTokenLifetimeSeconds(),
    session_id: sessionId,
  };
}

export async function rotateSessionAndIssueTokens(
  fastify: FastifyInstance,
  refreshToken: string,
  meta: {
    ip?: string | null;
    userAgent?: string | null;
  },
): Promise<(TokenPair & { user: Omit<SessionAuthResult, 'permissions' | 'session_id'> }) | null> {
  const tokenHash = hashRefreshToken(refreshToken);

  const { rows } = await fastify.pg.query<{
    session_id: string;
    id: string;
    email: string;
    name: string;
    role: Role;
    org_id: string;
  }>(
    `SELECT
       s.id AS session_id,
       u.id,
       u.email,
       u.name,
       u.role,
       u.org_id
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1
       AND s.is_active = TRUE
       AND s.expires_at > NOW()
       AND u.is_active = TRUE
       AND COALESCE(u.is_suspended, FALSE) = FALSE
     LIMIT 1`,
    [tokenHash],
  );

  const row = rows[0];
  if (!row) return null;

  const nextRefresh = generateOpaqueRefreshToken();
  const nextHash = hashRefreshToken(nextRefresh);
  const nextExpiresAt = refreshExpiryDate();

  await fastify.pg.query(
    `UPDATE sessions
     SET token_hash = $1,
         expires_at = $2,
         last_used_at = NOW(),
         ip_address = COALESCE($3, ip_address),
         user_agent = COALESCE($4, user_agent)
     WHERE id = $5`,
    [nextHash, nextExpiresAt.toISOString(), meta.ip ?? null, meta.userAgent ?? null, row.session_id],
  );

  const token = issueAccessToken(fastify, row, row.session_id);
  return {
    token,
    refresh_token: nextRefresh,
    access_expires_in_sec: accessTokenLifetimeSeconds(),
    refresh_expires_in_sec: refreshTokenLifetimeSeconds(),
    session_id: row.session_id,
    user: {
      id: row.id,
      email: row.email,
      name: row.name,
      role: row.role,
      org_id: row.org_id,
    },
  };
}

export async function authenticateAccessToken(
  fastify: FastifyInstance,
  token: string,
): Promise<SessionAuthResult | null> {
  let payload: JwtPayload;
  try {
    payload = fastify.jwt.verify(token) as JwtPayload;
  } catch {
    return null;
  }

  if (!payload?.id || !payload?.sid) return null;
  if (payload.typ && payload.typ !== 'access') return null;

  const { rows } = await fastify.pg.query<{
    session_id: string;
    id: string;
    email: string;
    name: string;
    role: Role;
    org_id: string;
  }>(
    `SELECT
       s.id AS session_id,
       u.id,
       u.email,
       u.name,
       u.role,
       u.org_id
     FROM sessions s
     JOIN users u ON u.id = s.user_id
     WHERE s.id = $1
       AND s.user_id = $2
       AND s.is_active = TRUE
       AND s.expires_at > NOW()
       AND u.is_active = TRUE
       AND COALESCE(u.is_suspended, FALSE) = FALSE
     LIMIT 1`,
    [payload.sid, payload.id],
  );

  const row = rows[0];
  if (!row) return null;
  if (payload.org_id && payload.org_id !== row.org_id) return null;

  await fastify.pg.query(
    `UPDATE sessions
     SET last_used_at = NOW()
     WHERE id = $1
       AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '${LAST_USED_TOUCH_INTERVAL_SECONDS} seconds')`,
    [row.session_id],
  );

  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    org_id: row.org_id,
    session_id: row.session_id,
    permissions: RolePermissions[row.role] ?? [],
  };
}

export async function isSessionActive(fastify: FastifyInstance, sessionId: string): Promise<boolean> {
  const { rowCount } = await fastify.pg.query(
    `SELECT 1 FROM sessions WHERE id = $1 AND is_active = TRUE AND expires_at > NOW() LIMIT 1`,
    [sessionId],
  );
  return (rowCount ?? 0) > 0;
}

export function hasPermission(user: Pick<SessionAuthResult, 'permissions'>, permission: Permission): boolean {
  return user.permissions.includes(permission);
}

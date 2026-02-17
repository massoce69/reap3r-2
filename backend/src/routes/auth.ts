// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import bcrypt from 'bcrypt';
import crypto from 'node:crypto';
import { Permission, Role, LoginRequestSchema, CreateUserSchema, UpdateUserSchema } from '@massvision/shared';
import { config } from '../config.js';
import { createAuditLog } from '../services/audit.service.js';
import { logLoginEvent } from '../services/admin.service.js';
import { parseUUID, parseBody, clampLimit, clampOffset } from '../lib/validate.js';

// TOTP implementation (RFC 6238)
function generateTOTP(secret: string, window = 0): string {
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30) + window;
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter & 0xffffffff, 4);
  const hmac = crypto.createHmac('sha1', Buffer.from(secret, 'base32'));
  hmac.update(buf);
  const hash = hmac.digest();
  const offset = hash[hash.length - 1] & 0xf;
  const code = ((hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 | (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff)) % 1000000;
  return code.toString().padStart(6, '0');
}

function verifyTOTP(secret: string, code: string): boolean {
  // Check current window and ±1 for clock drift tolerance
  for (let w = -1; w <= 1; w++) {
    if (generateTOTP(secret, w) === code) return true;
  }
  return false;
}

export default async function authRoutes(fastify: FastifyInstance) {
  // ── Login ──
  fastify.post('/api/auth/login', async (request, reply) => {
    const parsed = LoginRequestSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ') });
    const { email, password } = parsed.data;
    const mfa_code = (request.body as any)?.mfa_code as string | undefined;

    const { rows } = await fastify.pg.query(
      `SELECT id, email, name, role, org_id, password_hash, is_active, is_suspended,
              mfa_enabled, mfa_secret, failed_login_count, locked_until
       FROM users WHERE email = $1`,
      [email],
    );
    const user = rows[0];
    const ip = request.ip;

    // User not found or inactive
    if (!user || !user.is_active) {
      if (user) await logLoginEvent(user.org_id, { user_id: user.id, email, success: false, ip_address: ip, failure_reason: 'account_inactive' });
      return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid credentials' });
    }

    // Account suspended
    if (user.is_suspended) {
      await logLoginEvent(user.org_id, { user_id: user.id, email, success: false, ip_address: ip, failure_reason: 'account_suspended' });
      return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Account suspended. Contact your administrator.' });
    }

    // Brute force lockout (5 failed attempts = 15 min lockout)
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await logLoginEvent(user.org_id, { user_id: user.id, email, success: false, ip_address: ip, failure_reason: 'account_locked' });
      const remaining = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 60000);
      return reply.status(429).send({ statusCode: 429, error: 'Too Many Requests', message: `Account locked. Try again in ${remaining} minutes.` });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      // Increment failed login count
      const newCount = (user.failed_login_count ?? 0) + 1;
      const lockUntil = newCount >= 5 ? new Date(Date.now() + 15 * 60 * 1000).toISOString() : null;
      await fastify.pg.query(
        `UPDATE users SET failed_login_count = $1, locked_until = $2 WHERE id = $3`,
        [newCount, lockUntil, user.id],
      );
      await logLoginEvent(user.org_id, { user_id: user.id, email, success: false, ip_address: ip, failure_reason: 'bad_password' });
      return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid credentials' });
    }

    // MFA challenge
    if (user.mfa_enabled && user.mfa_secret) {
      if (!mfa_code) {
        // Return MFA challenge — don't issue token yet
        return reply.status(200).send({
          mfa_required: true,
          message: 'MFA code required. Submit with mfa_code parameter.',
        });
      }

      // Verify TOTP code
      if (!verifyTOTP(user.mfa_secret, mfa_code)) {
        await logLoginEvent(user.org_id, { user_id: user.id, email, success: false, ip_address: ip, failure_reason: 'bad_mfa_code' });
        return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid MFA code' });
      }
    }

    // Reset failed login count on success
    await fastify.pg.query(
      `UPDATE users SET failed_login_count = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1`,
      [user.id],
    );

    await logLoginEvent(user.org_id, { user_id: user.id, email, success: true, ip_address: ip });

    // Create session record
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const sessionHash = crypto.createHash('sha256').update(sessionToken).digest('hex');
    await fastify.pg.query(
      `INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, expires_at, last_used_at)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '24 hours', NOW())`,
      [user.id, sessionHash, ip, request.headers['user-agent'] ?? ''],
    );

    const token = fastify.jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role, org_id: user.org_id },
      { expiresIn: config.jwt.expiresIn },
    );

    await createAuditLog(fastify, {
      user_id: user.id, org_id: user.org_id,
      action: 'auth.login', entity_type: 'user', entity_id: user.id,
      details: { mfa_used: !!user.mfa_enabled }, ip_address: ip,
    });

    return { token, user: { id: user.id, email: user.email, name: user.name, role: user.role, org_id: user.org_id } };
  });

  // ── Refresh Token ──
  fastify.post('/api/auth/refresh', { preHandler: [fastify.authenticate] }, async (request) => {
    const user = request.currentUser;
    const token = fastify.jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role, org_id: user.org_id },
      { expiresIn: config.jwt.expiresIn },
    );
    return { token };
  });

  // ── Me ──
  fastify.get('/api/auth/me', { preHandler: [fastify.authenticate] }, async (request) => {
    const { rows } = await fastify.pg.query(
      `SELECT id, email, name, role, org_id, avatar_url, mfa_enabled, created_at FROM users WHERE id = $1`,
      [request.currentUser.id],
    );
    return rows[0] ?? null;
  });

  // ── List users ──
  fastify.get('/api/users', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.UserList)] }, async (request) => {
    const q = request.query as any;
    const limit = clampLimit(q.limit, 50);
    const page = Math.max(Number(q.page) || 1, 1);
    const offset = (page - 1) * limit;
    const countRes = await fastify.pg.query(`SELECT count(*)::int FROM users WHERE org_id = $1`, [request.currentUser.org_id]);
    const dataRes = await fastify.pg.query(
      `SELECT id, email, name, role, org_id, is_active, avatar_url, mfa_enabled, created_at
       FROM users WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [request.currentUser.org_id, Number(limit), offset],
    );
    return { data: dataRes.rows, total: countRes.rows[0].count, page: Number(page), limit: Number(limit) };
  });

  // ── Create user ──
  fastify.post('/api/users', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.UserCreate)] }, async (request, reply) => {
    const body = parseBody(CreateUserSchema, request.body, reply);
    if (!body) return;
    const { email, name, password, role } = body;
    const hash = await bcrypt.hash(password, config.bcryptRounds);
    try {
      const { rows } = await fastify.pg.query(
        `INSERT INTO users (email, name, password_hash, role, org_id) VALUES ($1, $2, $3, $4, $5)
         RETURNING id, email, name, role, org_id, created_at`,
        [email, name, hash, role, request.currentUser.org_id],
      );
      await createAuditLog(fastify, {
        user_id: request.currentUser.id, org_id: request.currentUser.org_id,
        action: 'user.create', entity_type: 'user', entity_id: rows[0].id,
        details: { email, role }, ip_address: request.ip,
      });
      return reply.status(201).send(rows[0]);
    } catch (e: any) {
      if (e.code === '23505') return reply.status(409).send({ statusCode: 409, error: 'Conflict', message: 'Email already exists' });
      throw e;
    }
  });

  // ── Update user ──
  fastify.patch('/api/users/:id', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.UserUpdate)] }, async (request) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const body = parseBody(UpdateUserSchema, request.body, reply);
    if (!body) return;
    const fields: string[] = [];
    const params: unknown[] = [];
    let idx = 1;
    if (body.name) { fields.push(`name = $${idx++}`); params.push(body.name); }
    if (body.role) { fields.push(`role = $${idx++}`); params.push(body.role); }
    if (body.is_active !== undefined) { fields.push(`is_active = $${idx++}`); params.push(body.is_active); }
    if (body.password) {
      const hash = await bcrypt.hash(body.password, config.bcryptRounds);
      fields.push(`password_hash = $${idx++}`);
      params.push(hash);
    }
    if (fields.length === 0) return { message: 'No fields to update' };
    params.push(id);
    const { rows } = await fastify.pg.query(
      `UPDATE users SET ${fields.join(', ')}, updated_at = now() WHERE id = $${idx}
       RETURNING id, email, name, role, org_id, is_active, created_at`,
      params,
    );
    await createAuditLog(fastify, {
      user_id: request.currentUser.id, org_id: request.currentUser.org_id,
      action: 'user.update', entity_type: 'user', entity_id: id,
      details: body, ip_address: request.ip,
    });
    return rows[0];
  });
}

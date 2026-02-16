// ─────────────────────────────────────────────
// MASSVISION Reap3r — Auth Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import bcrypt from 'bcrypt';
import { Permission, Role } from '@massvision/shared';
import { config } from '../config.js';
import { createAuditLog } from '../services/audit.service.js';
import { logLoginEvent } from '../services/admin.service.js';

export default async function authRoutes(fastify: FastifyInstance) {
  // ── Login ──
  fastify.post('/api/auth/login', async (request, reply) => {
    const { email, password } = request.body as { email: string; password: string };

    const { rows } = await fastify.pg.query(
      `SELECT id, email, name, role, org_id, password_hash, is_active FROM users WHERE email = $1`,
      [email],
    );
    const user = rows[0];
    const ip = request.ip;

    if (!user || !user.is_active) {
      if (user) await logLoginEvent(user.org_id, { user_id: user.id, email, success: false, ip_address: ip, failure_reason: 'account_suspended' });
      return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await logLoginEvent(user.org_id, { user_id: user.id, email, success: false, ip_address: ip, failure_reason: 'bad_password' });
      return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Invalid credentials' });
    }

    await logLoginEvent(user.org_id, { user_id: user.id, email, success: true, ip_address: ip });

    const token = fastify.jwt.sign(
      { id: user.id, email: user.email, name: user.name, role: user.role, org_id: user.org_id },
      { expiresIn: config.jwt.expiresIn },
    );

    return { token, user: { id: user.id, email: user.email, name: user.name, role: user.role, org_id: user.org_id } };
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
    const { page = 1, limit = 50 } = request.query as any;
    const offset = (Number(page) - 1) * Number(limit);
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
    const { email, name, password, role } = request.body as any;
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
    const { id } = request.params as any;
    const body = request.body as any;
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

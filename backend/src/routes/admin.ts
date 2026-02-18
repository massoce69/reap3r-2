// ─────────────────────────────────────────────
// MASSVISION Reap3r — Admin Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import bcrypt from 'bcrypt';
import { Permission, CreateUserSchema, UpdateUserSchema, CreateTeamSchema } from '@massvision/shared';
import { query } from '../db/pool.js';
import { config } from '../config.js';
import * as admin from '../services/admin.service.js';

export default async function adminRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  // ═══════════════════════════════════════════
  // USERS
  // ═══════════════════════════════════════════

  // GET /api/admin/users
  fastify.get('/api/admin/users', {
    preHandler: [fastify.requirePermission(Permission.UserList)],
  }, async (request) => {
    const q = request.query as any;
    return admin.listUsersAdvanced(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: Number(q.limit) || 25,
      q: q.q,
      role: q.role,
      is_active: q.is_active !== undefined ? q.is_active === 'true' : undefined,
    });
  });

  // POST /api/admin/users
  fastify.post('/api/admin/users', {
    preHandler: [fastify.requirePermission(Permission.UserCreate)],
  }, async (request, reply) => {
    const parsed = CreateUserSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const { email, name, password, role } = parsed.data;
    const hash = await bcrypt.hash(password, config.bcryptRounds);

    try {
      const { rows } = await query<{ id: string }>(
        `INSERT INTO users (org_id, email, name, password_hash, role) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
        [request.currentUser.org_id, email, name, hash, role]
      );
      await request.audit({ action: 'user_create', entity_type: 'user', entity_id: rows[0].id, details: { email, role } });
      return reply.status(201).send({ id: rows[0].id, email, name, role });
    } catch (err: any) {
      if (err.code === '23505') return reply.status(409).send({ error: 'Email already exists' });
      throw err;
    }
  });

  // PATCH /api/admin/users/:id
  fastify.patch('/api/admin/users/:id', {
    preHandler: [fastify.requirePermission(Permission.UserUpdate)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = UpdateUserSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const sets: string[] = ['updated_at = NOW()'];
    const vals: unknown[] = [];
    let idx = 1;
    if (parsed.data.name) { sets.push(`name = $${idx}`); vals.push(parsed.data.name); idx++; }
    if (parsed.data.role) { sets.push(`role = $${idx}`); vals.push(parsed.data.role); idx++; }
    if (parsed.data.is_active !== undefined) { sets.push(`is_active = $${idx}`); vals.push(parsed.data.is_active); idx++; }
    vals.push(request.currentUser.org_id, id);

    await query(`UPDATE users SET ${sets.join(', ')} WHERE org_id = $${idx} AND id = $${idx + 1}`, vals);
    await request.audit({ action: 'user_update', entity_type: 'user', entity_id: id, details: parsed.data });
    return { ok: true };
  });

  // POST /api/admin/users/:id/suspend
  fastify.post('/api/admin/users/:id/suspend', {
    preHandler: [fastify.requirePermission(Permission.UserSuspend)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    const { active } = request.body as { active: boolean };
    await admin.suspendUser(request.currentUser.org_id, id, active);
    await request.audit({ action: active ? 'user_activate' : 'user_suspend', entity_type: 'user', entity_id: id });
    return { ok: true };
  });

  // ═══════════════════════════════════════════
  // TEAMS
  // ═══════════════════════════════════════════

  // GET /api/admin/teams
  fastify.get('/api/admin/teams', {
    preHandler: [fastify.requirePermission(Permission.TeamList)],
  }, async (request) => {
    return admin.listTeams(request.currentUser.org_id);
  });

  // POST /api/admin/teams
  fastify.post('/api/admin/teams', {
    preHandler: [fastify.requirePermission(Permission.TeamCreate)],
  }, async (request, reply) => {
    const parsed = CreateTeamSchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const result = await admin.createTeam(request.currentUser.org_id, parsed.data);
    await request.audit({ action: 'team_create', entity_type: 'team', entity_id: result.id, details: { name: parsed.data.name } });
    return reply.status(201).send(result);
  });

  // GET /api/admin/teams/:id
  fastify.get('/api/admin/teams/:id', {
    preHandler: [fastify.requirePermission(Permission.TeamList)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const team = await admin.getTeamById(request.currentUser.org_id, id);
    if (!team) return reply.status(404).send({ error: 'Not found' });
    return team;
  });

  // PATCH /api/admin/teams/:id
  fastify.patch('/api/admin/teams/:id', {
    preHandler: [fastify.requirePermission(Permission.TeamUpdate)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;
    await admin.updateTeam(request.currentUser.org_id, id, body);
    await request.audit({ action: 'team_update', entity_type: 'team', entity_id: id });
    return { ok: true };
  });

  // DELETE /api/admin/teams/:id
  fastify.delete('/api/admin/teams/:id', {
    preHandler: [fastify.requirePermission(Permission.TeamDelete)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    await admin.deleteTeam(request.currentUser.org_id, id);
    await request.audit({ action: 'team_delete', entity_type: 'team', entity_id: id });
    return { ok: true };
  });

  // GET /api/admin/teams/:id/members
  fastify.get('/api/admin/teams/:id/members', {
    preHandler: [fastify.requirePermission(Permission.TeamList)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    return admin.getTeamMembers(id);
  });

  // POST /api/admin/teams/:id/members
  fastify.post('/api/admin/teams/:id/members', {
    preHandler: [fastify.requirePermission(Permission.TeamUpdate)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { user_id } = request.body as { user_id: string };
    await admin.addTeamMember(id, user_id);
    await request.audit({ action: 'team_member_add', entity_type: 'team', entity_id: id, details: { user_id } });
    return reply.status(201).send({ ok: true });
  });

  // DELETE /api/admin/teams/:id/members/:userId
  fastify.delete('/api/admin/teams/:id/members/:userId', {
    preHandler: [fastify.requirePermission(Permission.TeamUpdate)],
  }, async (request) => {
    const { id, userId } = request.params as { id: string; userId: string };
    await admin.removeTeamMember(id, userId);
    await request.audit({ action: 'team_member_remove', entity_type: 'team', entity_id: id, details: { user_id: userId } });
    return { ok: true };
  });

  // ═══════════════════════════════════════════
  // POLICIES
  // ═══════════════════════════════════════════

  // GET /api/admin/policies
  fastify.get('/api/admin/policies', {
    preHandler: [fastify.requirePermission(Permission.PolicyView)],
  }, async (request) => {
    return admin.listPolicies(request.currentUser.org_id);
  });

  // PATCH /api/admin/policies/:id
  fastify.patch('/api/admin/policies/:id', {
    preHandler: [fastify.requirePermission(Permission.PolicyUpdate)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;
    await admin.updatePolicy(request.currentUser.org_id, id, body);
    await request.audit({ action: 'policy_update', entity_type: 'policy', entity_id: id });
    return { ok: true };
  });

  // ═══════════════════════════════════════════
  // LOGS
  // ═══════════════════════════════════════════

  // GET /api/admin/login-events
  fastify.get('/api/admin/login-events', {
    preHandler: [fastify.requirePermission(Permission.AuditView)],
  }, async (request) => {
    const q = request.query as any;
    return admin.listLoginEvents(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: Number(q.limit) || 50,
      user_id: q.user_id,
      success: q.success !== undefined ? q.success === 'true' : undefined,
    });
  });

  // ═══════════════════════════════════════════
  // SESSIONS MANAGEMENT
  // ═══════════════════════════════════════════

  // GET /api/admin/users/:id/sessions
  fastify.get('/api/admin/users/:id/sessions', {
    preHandler: [fastify.requirePermission(Permission.UserList)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    return admin.getUserSessions(id);
  });

  // DELETE /api/admin/sessions/:id
  fastify.delete('/api/admin/sessions/:id', {
    preHandler: [fastify.requirePermission(Permission.UserUpdate)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    await admin.revokeSession(id);
    await request.audit({ action: 'session_revoke', entity_type: 'session', entity_id: id });
    return { ok: true };
  });

  // POST /api/admin/users/:id/sessions/revoke-all
  fastify.post('/api/admin/users/:id/sessions/revoke-all', {
    preHandler: [fastify.requirePermission(Permission.UserUpdate)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    await admin.revokeAllUserSessions(id);
    await request.audit({ action: 'sessions_revoke_all', entity_type: 'user', entity_id: id });
    return { ok: true };
  });

  // ═══════════════════════════════════════════
  // MFA MANAGEMENT
  // ═══════════════════════════════════════════

  // POST /api/admin/users/:id/mfa/setup
  fastify.post('/api/admin/users/:id/mfa/setup', {
    preHandler: [fastify.requirePermission(Permission.UserUpdate)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };

    // Generate a cryptographically strong TOTP secret server-side (160-bit / 20 bytes)
    const { randomBytes } = await import('crypto');
    const secretBytes = randomBytes(20);

    // Base32-encode for TOTP (RFC 4226)
    const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let base32 = '';
    let bits = 0;
    let value = 0;
    for (const byte of secretBytes) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        base32 += BASE32_CHARS[(value >> bits) & 31];
      }
    }
    if (bits > 0) base32 += BASE32_CHARS[(value << (5 - bits)) & 31];

    // Fetch the user's email for the TOTP URI label
    const { rows } = await fastify.pg.query(`SELECT email FROM users WHERE id = $1`, [id]);
    const email = rows[0]?.email ?? id;

    const issuer = encodeURIComponent('Reap3r');
    const account = encodeURIComponent(email);
    const totpUri = `otpauth://totp/${issuer}:${account}?secret=${base32}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;

    await admin.setupMFA(id, base32);
    await request.audit({ action: 'mfa_setup', entity_type: 'user', entity_id: id });
    return { ok: true, secret: base32, totp_uri: totpUri };
  });

  // POST /api/admin/users/:id/mfa/enable
  fastify.post('/api/admin/users/:id/mfa/enable', {
    preHandler: [fastify.requirePermission(Permission.UserUpdate)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    await admin.enableMFA(id);
    await request.audit({ action: 'mfa_enable', entity_type: 'user', entity_id: id });
    return { ok: true };
  });

  // POST /api/admin/users/:id/mfa/disable
  fastify.post('/api/admin/users/:id/mfa/disable', {
    preHandler: [fastify.requirePermission(Permission.UserUpdate)],
  }, async (request) => {
    const { id } = request.params as { id: string };
    await admin.disableMFA(id);
    await request.audit({ action: 'mfa_disable', entity_type: 'user', entity_id: id });
    return { ok: true };
  });

  // ═══════════════════════════════════════════
  // ROLES & PERMISSIONS
  // ═══════════════════════════════════════════

  // GET /api/admin/roles
  fastify.get('/api/admin/roles', {
    preHandler: [fastify.requirePermission(Permission.UserList)],
  }, async () => {
    return admin.getAllRoles();
  });

  // PATCH /api/admin/users/:id/role
  fastify.patch('/api/admin/users/:id/role', {
    preHandler: [fastify.requirePermission(Permission.UserUpdate)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { role } = request.body as { role: string };
    if (!role) return reply.status(400).send({ error: 'Role required' });
    
    await admin.updateUserRole(request.currentUser.org_id, id, role);
    await request.audit({ action: 'user_role_change', entity_type: 'user', entity_id: id, details: { role } });
    return { ok: true };
  });
}

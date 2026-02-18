// ─────────────────────────────────────────────
// MASSVISION Reap3r — Enrollment Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import crypto from 'crypto';
import { Permission, CreateEnrollmentTokenSchema } from '@massvision/shared';
import { createAuditLog } from '../services/audit.service.js';
import { parseUUID, parseBody } from '../lib/validate.js';

function firstHeader(v: unknown): string | undefined {
  if (!v) return undefined;
  if (Array.isArray(v)) return String(v[0] ?? '');
  return String(v);
}

function publicBaseUrl(request: any): string {
  const fromEnv = process.env.API_BASE_URL;
  if (fromEnv && fromEnv.trim()) return fromEnv.replace(/\/+$/, '');

  const proto = (firstHeader(request.headers['x-forwarded-proto']) || request.protocol || 'http')
    .split(',')[0]
    .trim();
  const host = (firstHeader(request.headers['x-forwarded-host']) || firstHeader(request.headers.host) || '')
    .split(',')[0]
    .trim();
  const base = host ? `${proto}://${host}` : 'http://localhost:4000';
  return base.replace(/\/+$/, '');
}

export default async function enrollmentRoutes(fastify: FastifyInstance) {
  // ── List tokens ──
  fastify.get('/api/enrollment/tokens', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.TokenList)] }, async (request) => {
    const query = request.query as any;
    const page = Number(query.page ?? 1);
    const limit = Math.min(Number(query.limit ?? 50), 200);
    const offset = (page - 1) * limit;

    const orgId = request.currentUser.org_id;
    const countRes = await fastify.pg.query(`SELECT count(*)::int FROM enrollment_tokens WHERE org_id = $1`, [orgId]);
    const dataRes = await fastify.pg.query(
      `SELECT et.*, c.name as company_name, f.name as folder_name
       FROM enrollment_tokens et
       LEFT JOIN companies c ON c.id = et.company_id
       LEFT JOIN folders f ON f.id = et.folder_id
       WHERE et.org_id = $1
       ORDER BY et.created_at DESC LIMIT $2 OFFSET $3`,
      [orgId, limit, offset],
    );
    return { data: dataRes.rows, total: countRes.rows[0].count, page, limit };
  });

  // ── Create token ──
  fastify.post('/api/enrollment/tokens', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.TokenCreate)] }, async (request, reply) => {
    const body = parseBody(CreateEnrollmentTokenSchema, request.body, reply);
    if (!body) return;
    const token = crypto.randomBytes(32).toString('hex');
    const { rows } = await fastify.pg.query(
      `INSERT INTO enrollment_tokens (token, name, org_id, site_id, company_id, folder_id, max_uses, expires_at, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        token, body.name, request.currentUser.org_id,
        body.site_id ?? null, body.company_id ?? null, body.folder_id ?? null,
        body.max_uses ?? 0, body.expires_at ?? null, request.currentUser.id,
      ],
    );
    await createAuditLog(fastify, {
      user_id: request.currentUser.id, org_id: request.currentUser.org_id,
      action: 'token.create', entity_type: 'enrollment_token', entity_id: rows[0].id,
      details: { name: body.name }, ip_address: request.ip,
    });
    return reply.status(201).send(rows[0]);
  });

  // ── Revoke token ──
  fastify.post('/api/enrollment/tokens/:id/revoke', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.TokenRevoke)] }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const { rows } = await fastify.pg.query(
      `UPDATE enrollment_tokens SET revoked = true WHERE id = $1 AND org_id = $2 RETURNING *`,
      [id, request.currentUser.org_id],
    );
    if (rows.length === 0) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    await createAuditLog(fastify, {
      user_id: request.currentUser.id, org_id: request.currentUser.org_id,
      action: 'token.revoke', entity_type: 'enrollment_token', entity_id: id,
      details: null, ip_address: request.ip,
    });
    return { message: 'Token revoked' };
  });

  // ── Delete token ──
  fastify.delete('/api/enrollment/tokens/:id', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.TokenRevoke)] }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const { rowCount } = await fastify.pg.query(
      `DELETE FROM enrollment_tokens WHERE id = $1 AND org_id = $2`,
      [id, request.currentUser.org_id],
    );
    if (rowCount === 0) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    return { message: 'Token deleted' };
  });

  // ── Deployment commands (for copy/paste) ──
  fastify.get('/api/enrollment/tokens/:id/commands', { preHandler: [fastify.authenticate, fastify.requirePermission(Permission.TokenList)] }, async (request, reply) => {
    const id = parseUUID((request.params as any).id, reply);
    if (!id) return;
    const { rows } = await fastify.pg.query(
      `SELECT token FROM enrollment_tokens WHERE id = $1 AND org_id = $2`,
      [id, request.currentUser.org_id],
    );
    if (rows.length === 0) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    const t = rows[0].token;
    const apiBase = publicBaseUrl(request);
    const wsBase = apiBase.replace(/^http(s?):\/\//i, 'ws$1://');
    return {
      windows_powershell: `$token="${t}"; $server="${apiBase}"; Invoke-WebRequest -Uri "$server/api/install/windows?token=$token" -OutFile reap3r-install.ps1; powershell -ExecutionPolicy Bypass -File .\\reap3r-install.ps1 -Token $token -Server $server`,
      linux_oneliner: `curl -fsSL "${apiBase}/api/install/linux?token=${t}" | sudo bash -s -- --token "${t}" --server "${apiBase}"`,
      macos_oneliner: `curl -fsSL "${apiBase}/api/install/macos?token=${t}" | sudo bash -s -- --token "${t}" --server "${apiBase}"`,

      // Backward-compatible keys for older UIs.
      linux_bash: `curl -fsSL "${apiBase}/api/install/linux?token=${t}" | sudo bash -s -- --token "${t}" --server "${apiBase}"`,
      macos_bash: `curl -fsSL "${apiBase}/api/install/macos?token=${t}" | sudo bash -s -- --token "${t}" --server "${apiBase}"`,
    };
  });
}

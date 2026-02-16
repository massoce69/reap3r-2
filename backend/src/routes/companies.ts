// ─────────────────────────────────────────────
// MASSVISION Reap3r — Companies Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission } from '@massvision/shared';
import * as svc from '../services/company.service.js';
import { CreateCompanySchema, UpdateCompanySchema } from '@massvision/shared';

export default async function companyRoutes(fastify: FastifyInstance) {
  fastify.addHook('preHandler', fastify.authenticate);

  // GET /api/companies
  fastify.get('/api/companies', {
    preHandler: [fastify.requirePermission(Permission.CompanyList)],
  }, async (request) => {
    const q = request.query as any;
    return svc.listCompanies(request.currentUser.org_id, {
      page: Number(q.page) || 1,
      limit: Number(q.limit) || 25,
      q: q.q,
    });
  });

  // GET /api/companies/:id
  fastify.get('/api/companies/:id', {
    preHandler: [fastify.requirePermission(Permission.CompanyView)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const company = await svc.getCompanyById(request.currentUser.org_id, id);
    if (!company) return reply.status(404).send({ error: 'Not found' });
    return company;
  });

  // POST /api/companies
  fastify.post('/api/companies', {
    preHandler: [fastify.requirePermission(Permission.CompanyCreate)],
  }, async (request, reply) => {
    const parsed = CreateCompanySchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const result = await svc.createCompany(request.currentUser.org_id, parsed.data);
    await request.audit({ action: 'company_create', entity_type: 'company', entity_id: result.id, details: { name: parsed.data.name } });
    return reply.status(201).send(result);
  });

  // PATCH /api/companies/:id
  fastify.patch('/api/companies/:id', {
    preHandler: [fastify.requirePermission(Permission.CompanyUpdate)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = UpdateCompanySchema.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: parsed.error.message });

    const ok = await svc.updateCompany(request.currentUser.org_id, id, parsed.data);
    if (!ok) return reply.status(404).send({ error: 'Not found' });
    await request.audit({ action: 'company_update', entity_type: 'company', entity_id: id });
    return { ok: true };
  });

  // DELETE /api/companies/:id
  fastify.delete('/api/companies/:id', {
    preHandler: [fastify.requirePermission(Permission.CompanyDelete)],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const ok = await svc.deleteCompany(request.currentUser.org_id, id);
    if (!ok) return reply.status(404).send({ error: 'Not found' });
    await request.audit({ action: 'company_delete', entity_type: 'company', entity_id: id });
    return { ok: true };
  });
}

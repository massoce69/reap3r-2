// ─────────────────────────────────────────────
// MASSVISION Reap3r — Deploy Routes
// Zabbix DAT batch deployment endpoints
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { Permission, CreateDeployBatchSchema, DeployCallbackSchema, DeployBatchMode } from '@massvision/shared';
import * as deploySvc from '../services/deploy.service.js';
import { createAuditLog } from '../services/audit.service.js';
import { parseUUID, parseBody } from '../lib/validate.js';

export default async function deployRoutes(fastify: FastifyInstance) {

  // ════════════════════════════════════════
  // POST /api/deploy/zabbix/import
  // Upload CSV file + Zabbix config → create batch
  // ════════════════════════════════════════
  fastify.post('/api/deploy/zabbix/import', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DeploymentCreate)],
  }, async (request, reply) => {
    const body = request.body as any;

    // Accept JSON body with CSV content inline
    const csvContent = body?.csv_content;
    const filename = body?.filename ?? 'import.csv';

    if (!csvContent || typeof csvContent !== 'string') {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'csv_content is required (string)' });
    }

    // Validate Zabbix config
    const config = parseBody(CreateDeployBatchSchema, body, reply);
    if (!config) return;

    // Parse CSV
    const { rows, errors: parseErrors } = deploySvc.parseCsv(csvContent);

    if (rows.length === 0) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'No valid rows found in CSV',
        errors: parseErrors,
      });
    }

    // Create batch with items
    const { batch, item_count } = await deploySvc.createBatch({
      tenant_id: request.currentUser.org_id,
      created_by: request.currentUser.id,
      filename,
      mode: config.mode,
      server_url: config.server_url,
      zabbix_url: config.zabbix_url,
      zabbix_user: config.zabbix_user,
      zabbix_script: config.zabbix_script ?? 'Reap3r Enrollment',
      items: rows,
    });

    await createAuditLog(fastify, {
      user_id: request.currentUser.id,
      org_id: request.currentUser.org_id,
      action: 'deploy.import',
      entity_type: 'deploy_batch',
      entity_id: batch.batch_id,
      details: { filename, mode: config.mode, total: item_count, parse_errors: parseErrors.length },
      ip_address: request.ip,
    });

    return {
      batch_id: batch.batch_id,
      filename,
      mode: batch.mode,
      total: item_count,
      valid: item_count - parseErrors.length,
      invalid: parseErrors.length,
      duplicates: 0,
      errors: parseErrors,
    };
  });

  // ════════════════════════════════════════
  // POST /api/deploy/zabbix/validate/:batchId
  // Dry-run: resolve hosts in Zabbix, check script
  // ════════════════════════════════════════
  fastify.post('/api/deploy/zabbix/validate/:batchId', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DeploymentCreate)],
  }, async (request, reply) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;

    const body = request.body as any;
    const zabbixPassword = body?.zabbix_password;
    if (!zabbixPassword) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'zabbix_password is required' });
    }

    try {
      const result = await deploySvc.validateBatch(batchId, request.currentUser.org_id, zabbixPassword);

      await createAuditLog(fastify, {
        user_id: request.currentUser.id,
        org_id: request.currentUser.org_id,
        action: 'deploy.validate',
        entity_type: 'deploy_batch',
        entity_id: batchId,
        details: { valid: result.valid, invalid: result.invalid },
        ip_address: request.ip,
      });

      return result;
    } catch (err: any) {
      return reply.status(502).send({
        statusCode: 502,
        error: 'Zabbix Error',
        message: err.message,
      });
    }
  });

  // ════════════════════════════════════════
  // POST /api/deploy/zabbix/start/:batchId
  // Start live execution
  // ════════════════════════════════════════
  fastify.post('/api/deploy/zabbix/start/:batchId', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DeploymentExecute)],
  }, async (request, reply) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;

    try {
      await deploySvc.startBatch(batchId, request.currentUser.org_id);

      await createAuditLog(fastify, {
        user_id: request.currentUser.id,
        org_id: request.currentUser.org_id,
        action: 'deploy.start',
        entity_type: 'deploy_batch',
        entity_id: batchId,
        details: {},
        ip_address: request.ip,
      });

      return { ok: true, message: 'Batch started' };
    } catch (err: any) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: err.message });
    }
  });

  // ════════════════════════════════════════
  // POST /api/deploy/zabbix/retry/:batchId
  // Retry failed items
  // ════════════════════════════════════════
  fastify.post('/api/deploy/zabbix/retry/:batchId', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DeploymentExecute)],
  }, async (request, reply) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;

    try {
      const retried = await deploySvc.retryFailed(batchId, request.currentUser.org_id);

      await createAuditLog(fastify, {
        user_id: request.currentUser.id,
        org_id: request.currentUser.org_id,
        action: 'deploy.retry',
        entity_type: 'deploy_batch',
        entity_id: batchId,
        details: { retried_count: retried },
        ip_address: request.ip,
      });

      return { ok: true, retried };
    } catch (err: any) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: err.message });
    }
  });

  // ════════════════════════════════════════
  // POST /api/deploy/zabbix/cancel/:batchId
  // Cancel a batch
  // ════════════════════════════════════════
  fastify.post('/api/deploy/zabbix/cancel/:batchId', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DeploymentCancel)],
  }, async (request, reply) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;

    try {
      await deploySvc.cancelBatch(batchId, request.currentUser.org_id);

      await createAuditLog(fastify, {
        user_id: request.currentUser.id,
        org_id: request.currentUser.org_id,
        action: 'deploy.cancel',
        entity_type: 'deploy_batch',
        entity_id: batchId,
        details: {},
        ip_address: request.ip,
      });

      return { ok: true, message: 'Batch cancelled' };
    } catch (err: any) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: err.message });
    }
  });

  // ════════════════════════════════════════
  // GET /api/deploy/zabbix/batches
  // List batches
  // ════════════════════════════════════════
  fastify.get('/api/deploy/zabbix/batches', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DeploymentView)],
  }, async (request) => {
    const q = request.query as any;
    return deploySvc.listBatches(
      request.currentUser.org_id,
      q.page ? Number(q.page) : 1,
      q.limit ? Math.min(Number(q.limit), 100) : 25,
    );
  });

  // ════════════════════════════════════════
  // GET /api/deploy/zabbix/batches/:batchId
  // Get single batch
  // ════════════════════════════════════════
  fastify.get('/api/deploy/zabbix/batches/:batchId', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DeploymentView)],
  }, async (request, reply) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;

    const batch = await deploySvc.getBatch(batchId, request.currentUser.org_id);
    if (!batch) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    return batch;
  });

  // ════════════════════════════════════════
  // GET /api/deploy/zabbix/batches/:batchId/items
  // Get batch items
  // ════════════════════════════════════════
  fastify.get('/api/deploy/zabbix/batches/:batchId/items', {
    preHandler: [fastify.authenticate, fastify.requirePermission(Permission.DeploymentView)],
  }, async (request, reply) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;

    const q = request.query as any;
    const items = await deploySvc.getBatchItems(batchId, request.currentUser.org_id, q.status);
    return { data: items };
  });

  // ════════════════════════════════════════
  // POST /api/deploy/zabbix/callback
  // PUBLIC endpoint — called by PowerShell script
  // Verified by X-Deploy-Callback-Key header
  // ════════════════════════════════════════
  fastify.post('/api/deploy/zabbix/callback', async (request, reply) => {
    const callbackKey = request.headers['x-deploy-callback-key'] as string;
    const expectedKey = process.env.DEPLOY_CALLBACK_KEY ?? 'dev-callback-key';

    if (!callbackKey || callbackKey !== expectedKey) {
      return reply.status(403).send({ statusCode: 403, error: 'Forbidden', message: 'Invalid callback key' });
    }

    const data = parseBody(DeployCallbackSchema, request.body, reply);
    if (!data) return;

    try {
      await deploySvc.processCallback(data);
      return { ok: true };
    } catch (err: any) {
      request.log.error(`[deploy-callback] Error processing callback: ${err.message}`);
      return reply.status(500).send({ statusCode: 500, error: 'Internal Server Error', message: err.message });
    }
  });
}

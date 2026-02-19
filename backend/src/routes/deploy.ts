// ------------------------------------------------------------
// MASSVISION Reap3r - Deploy Routes
// Zabbix DAT batch deployment endpoints
// ------------------------------------------------------------
import { FastifyInstance } from 'fastify';
import { Permission, DeployBatchMode, DeployCallbackSchema } from '@massvision/shared';
import * as deploySvc from '../services/deploy.service.js';
import { createAuditLog } from '../services/audit.service.js';
import { parseUUID, parseBody } from '../lib/validate.js';

export default async function deployRoutes(fastify: FastifyInstance) {
  const createAuth = [fastify.authenticate, fastify.requirePermission(Permission.DeploymentCreate)];
  const execAuth = [fastify.authenticate, fastify.requirePermission(Permission.DeploymentExecute)];
  const cancelAuth = [fastify.authenticate, fastify.requirePermission(Permission.DeploymentCancel)];
  const viewAuth = [fastify.authenticate, fastify.requirePermission(Permission.DeploymentView)];

  const importHandler = async (request: any, reply: any) => {
    const body = request.body as any;
    const filename = String(body?.filename ?? 'import.csv');

    const mode = body?.mode === DeployBatchMode.Live ? DeployBatchMode.Live : DeployBatchMode.DryRun;
    const serverUrl = typeof body?.server_url === 'string' ? body.server_url : '';
    const zabbixUrl = typeof body?.zabbix_url === 'string' ? body.zabbix_url : (process.env.ZABBIX_URL || '');
    const zabbixUser = typeof body?.zabbix_user === 'string' ? body.zabbix_user : (process.env.ZABBIX_USER || '');
    const zabbixScript = typeof body?.zabbix_script === 'string' && body.zabbix_script.trim()
      ? body.zabbix_script.trim()
      : (process.env.ZABBIX_SCRIPT || 'Reap3rEnroll');
    const zabbixPassword = typeof body?.zabbix_password === 'string' && body.zabbix_password.trim()
      ? body.zabbix_password.trim()
      : undefined;

    if (!serverUrl || !/^https?:\/\//i.test(serverUrl)) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'server_url is required and must be a valid http(s) URL' });
    }
    if (!zabbixUrl || !/^https?:\/\//i.test(zabbixUrl)) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'zabbix_url is required (body or ZABBIX_URL env)' });
    }
    if (!zabbixUser) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'zabbix_user is required (body or ZABBIX_USER env)' });
    }

    let parsed: ReturnType<typeof deploySvc.parseCsv>;
    if (typeof body?.file_base64 === 'string' && body.file_base64.trim()) {
      const raw = Buffer.from(body.file_base64, 'base64');
      parsed = deploySvc.parseImportFile(filename, raw);
    } else if (typeof body?.csv_content === 'string' && body.csv_content.trim()) {
      parsed = deploySvc.parseCsv(body.csv_content);
    } else {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Provide either file_base64 (xlsx/csv) or csv_content',
      });
    }

    const { rows, errors: parseErrors } = parsed;
    if (rows.length === 0) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'No valid rows found in import file',
        errors: parseErrors,
      });
    }

    const { batch } = await deploySvc.createBatch({
      tenant_id: request.currentUser.org_id,
      created_by: request.currentUser.id,
      filename,
      mode,
      server_url: serverUrl,
      zabbix_url: zabbixUrl,
      zabbix_user: zabbixUser,
      zabbix_script: zabbixScript,
      zabbix_password: zabbixPassword,
      items: rows,
    });

    await createAuditLog(fastify, {
      user_id: request.currentUser.id,
      org_id: request.currentUser.org_id,
      action: 'deploy.import',
      entity_type: 'deploy_batch',
      entity_id: batch.batch_id,
      details: { filename, mode, total: rows.length + parseErrors.length, parse_errors: parseErrors.length },
      ip_address: request.ip,
    });

    return {
      batch_id: batch.batch_id,
      filename,
      mode: batch.mode,
      total: rows.length + parseErrors.length,
      valid: rows.length,
      invalid: parseErrors.length,
      duplicates: parseErrors.filter((e) => /duplicate/i.test(e.error)).length,
      errors: parseErrors,
    };
  };

  const validateHandler = async (request: any, reply: any) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;

    const body = request.body as any;
    const zabbixPassword = body?.zabbix_password || process.env.ZABBIX_PASSWORD;
    if (!zabbixPassword) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'zabbix_password is required (or set ZABBIX_PASSWORD)',
      });
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
  };

  const startHandler = async (request: any, reply: any) => {
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
  };

  const retryHandler = async (request: any, reply: any) => {
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
  };

  const cancelHandler = async (request: any, reply: any) => {
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
  };

  // POST /api/deploy/zabbix/import
  fastify.post('/api/deploy/zabbix/import', { preHandler: createAuth }, importHandler);

  // Batch-centric endpoints (new contract)
  fastify.post('/api/deploy/zabbix/batches/:batchId/validate', { preHandler: createAuth }, validateHandler);
  fastify.post('/api/deploy/zabbix/batches/:batchId/start', { preHandler: execAuth }, startHandler);
  fastify.post('/api/deploy/zabbix/batches/:batchId/retry', { preHandler: execAuth }, retryHandler);
  fastify.post('/api/deploy/zabbix/batches/:batchId/cancel', { preHandler: cancelAuth }, cancelHandler);

  // Backward-compatible endpoints
  fastify.post('/api/deploy/zabbix/validate/:batchId', { preHandler: createAuth }, validateHandler);
  fastify.post('/api/deploy/zabbix/start/:batchId', { preHandler: execAuth }, startHandler);
  fastify.post('/api/deploy/zabbix/retry/:batchId', { preHandler: execAuth }, retryHandler);
  fastify.post('/api/deploy/zabbix/cancel/:batchId', { preHandler: cancelAuth }, cancelHandler);

  // GET /api/deploy/zabbix/batches
  fastify.get('/api/deploy/zabbix/batches', {
    preHandler: viewAuth,
  }, async (request) => {
    const q = request.query as any;
    return deploySvc.listBatches(
      request.currentUser.org_id,
      q.page ? Number(q.page) : 1,
      q.limit ? Math.min(Number(q.limit), 100) : 25,
    );
  });

  // GET /api/deploy/zabbix/batches/:batchId
  fastify.get('/api/deploy/zabbix/batches/:batchId', {
    preHandler: viewAuth,
  }, async (request, reply) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;
    const batch = await deploySvc.getBatch(batchId, request.currentUser.org_id);
    if (!batch) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    return batch;
  });

  // GET /api/deploy/zabbix/batches/:batchId/items
  fastify.get('/api/deploy/zabbix/batches/:batchId/items', {
    preHandler: viewAuth,
  }, async (request, reply) => {
    const batchId = parseUUID((request.params as any).batchId, reply, 'batchId');
    if (!batchId) return;
    const q = request.query as any;
    const items = await deploySvc.getBatchItems(batchId, request.currentUser.org_id, q.status);
    return { data: items };
  });

  // POST /api/deploy/zabbix/callback
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

// ─────────────────────────────────────────────
// MASSVISION Reap3r — Fastify Server Entry Point
// ─────────────────────────────────────────────
import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import websocket from '@fastify/websocket';
import { config } from './config.js';

// Plugins
import dbPlugin from './plugins/db.js';
import authPlugin from './plugins/auth.js';
import auditPlugin from './plugins/audit.js';
import metricsPlugin from './plugins/metrics.js';

// Routes
import healthRoutes from './routes/health.js';
import authRoutes from './routes/auth.js';
import agentRoutes from './routes/agents.js';
import jobRoutes from './routes/jobs.js';
import auditRoutes from './routes/audit.js';
import enrollmentRoutes from './routes/enrollment.js';
import companyRoutes from './routes/companies.js';
import folderRoutes from './routes/folders.js';
import vaultRoutes from './routes/vault.js';
import chatRoutes from './routes/chat.js';
import edrRoutes from './routes/edr.js';
import adminRoutes from './routes/admin.js';
import alertingRoutes from './routes/alerting.js';
import apiKeyRoutes from './routes/api-keys.js';
import agentBinaryRoutes from './routes/agent-binary.js';
import installRoutes from './routes/install.js';

// WebSocket
import { setupAgentGateway } from './ws/agent-gateway.js';

// Workers
import { startAlertEngine, stopAlertEngine } from './workers/alert-engine.js';

async function main() {
  const fastify = Fastify({
    logger: {
      level: config.logLevel,
      transport:
        config.nodeEnv === 'development'
          ? { target: 'pino-pretty', options: { colorize: true } }
          : undefined,
    },
    trustProxy: true,
  });

  // ── Security ──
  await fastify.register(helmet, { contentSecurityPolicy: false });
  await fastify.register(cors, {
    origin: config.nodeEnv === 'development' ? true : [config.apiBaseUrl],
    credentials: true,
  });
  await fastify.register(rateLimit, {
    max: 200,
    timeWindow: '1 minute',
  });

  // ── WebSocket ──
  await fastify.register(websocket);

  // ── Database ──
  await fastify.register(dbPlugin);

  // ── Plugins ──
  await fastify.register(authPlugin);
  await fastify.register(auditPlugin);
  if (config.prometheusEnabled) {
    await fastify.register(metricsPlugin);
  }

  // ── Routes ──
  // Route modules already mount under '/api/*' (except health, which also exposes '/health').
  // Do not double-prefix them with '/api', otherwise endpoints become '/api/api/*'.
  await fastify.register(healthRoutes);
  await fastify.register(authRoutes);
  await fastify.register(agentRoutes);
  await fastify.register(jobRoutes);
  await fastify.register(auditRoutes);
  await fastify.register(enrollmentRoutes);
  await fastify.register(companyRoutes);
  await fastify.register(folderRoutes);
  await fastify.register(vaultRoutes);
  await fastify.register(chatRoutes);
  await fastify.register(edrRoutes);
  await fastify.register(adminRoutes);
  await fastify.register(alertingRoutes);
  await fastify.register(apiKeyRoutes);
  await fastify.register(agentBinaryRoutes);
  await fastify.register(installRoutes);

  // ── Agent Gateway (WS) ──
  setupAgentGateway(fastify);

  // ── Global error handler ──
  fastify.setErrorHandler((error: any, request, reply) => {
    request.log.error(error);
    const status = error.statusCode ?? 500;
    reply.status(status).send({
      statusCode: status,
      error: error.name ?? 'Internal Server Error',
      message: config.nodeEnv === 'production' && status === 500 ? 'Internal Server Error' : error.message,
    });
  });

  // ── Start ──
  try {
    await fastify.listen({ port: config.port, host: '0.0.0.0' });
    fastify.log.info(`MASSVISION Reap3r API running on port ${config.port}`);

    // Start the Alert Engine worker
    startAlertEngine();

    // Graceful shutdown
    const shutdown = async () => {
      stopAlertEngine();
      await fastify.close();
      process.exit(0);
    };
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

main();

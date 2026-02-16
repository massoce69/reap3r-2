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
  await fastify.register(healthRoutes, { prefix: '/api' });
  await fastify.register(authRoutes, { prefix: '/api' });
  await fastify.register(agentRoutes, { prefix: '/api' });
  await fastify.register(jobRoutes, { prefix: '/api' });
  await fastify.register(auditRoutes, { prefix: '/api' });
  await fastify.register(enrollmentRoutes, { prefix: '/api' });
  await fastify.register(companyRoutes, { prefix: '/api' });
  await fastify.register(folderRoutes, { prefix: '/api' });
  await fastify.register(vaultRoutes, { prefix: '/api' });
  await fastify.register(chatRoutes, { prefix: '/api' });
  await fastify.register(edrRoutes, { prefix: '/api' });
  await fastify.register(adminRoutes, { prefix: '/api' });
  await fastify.register(alertingRoutes, { prefix: '/api' });

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

// ------------------------------------------------------------
// MASSVISION Reap3r — Fastify app factory (testable)
// ------------------------------------------------------------
import Fastify, { FastifyBaseLogger, FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
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
import deployRoutes from './routes/deploy.js';
import agentV2Routes from './routes/agents-v2.js';

// WebSocket
import { setupAgentGateway } from './ws/agent-gateway.js';

export async function buildApp(opts?: { logger?: boolean | FastifyBaseLogger }) {
  const fastify: FastifyInstance = Fastify({
    logger: opts?.logger ?? {
      level: config.logLevel,
      transport:
        config.nodeEnv === 'development'
          ? { target: 'pino-pretty', options: { colorize: true } }
          : undefined,
    },
    trustProxy: true,
  });

  if (process.env.WS_PORT || process.env.UI_WS_PORT) {
    fastify.log.warn('WS_PORT/UI_WS_PORT are deprecated. WS now uses unified PORT + /ws/* paths. Remove legacy vars after migration.');
  }

  // Security
  await fastify.register(helmet, { contentSecurityPolicy: false });
  await fastify.register(cors, {
    origin: config.nodeEnv === 'development' ? true : [config.apiBaseUrl],
    credentials: true,
  });
  await fastify.register(rateLimit, { max: 200, timeWindow: '1 minute' });

  // Database
  await fastify.register(dbPlugin);

  // Plugins
  await fastify.register(authPlugin);
  await fastify.register(auditPlugin);
  if (config.prometheusEnabled) {
    await fastify.register(metricsPlugin);
  }

  // Routes
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
  await fastify.register(deployRoutes);
  await fastify.register(agentV2Routes);

  // Agent gateway (WS)
  setupAgentGateway(fastify);

  // Global error handler
  fastify.setErrorHandler((error: any, request, reply) => {
    request.log.error(error);
    const status = error.statusCode ?? 500;
    reply.status(status).send({
      statusCode: status,
      error: error.name ?? 'Internal Server Error',
      message: config.nodeEnv === 'production' && status === 500 ? 'Internal Server Error' : error.message,
    });
  });

  return fastify;
}

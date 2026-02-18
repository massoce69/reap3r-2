// ─────────────────────────────────────────────
// MASSVISION Reap3r — Health Routes
// ─────────────────────────────────────────────
import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { healthCheck } from '../db/pool.js';

export default async function healthRoutes(fastify: FastifyInstance) {
  const healthHandler = async () => ({ status: 'ok', timestamp: new Date().toISOString() });
  fastify.get('/health', healthHandler);
  fastify.get('/api/health', healthHandler);

  const readyHandler = async (_: FastifyRequest, reply: FastifyReply) => {
    const dbOk = await healthCheck();
    if (!dbOk) {
      return reply.status(503).send({ status: 'not_ready', db: false });
    }
    return { status: 'ready', db: true };
  };
  fastify.get('/ready', readyHandler);
  fastify.get('/api/ready', readyHandler);
}

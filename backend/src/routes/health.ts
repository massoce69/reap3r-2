// ─────────────────────────────────────────────
// MASSVISION Reap3r — Health Routes
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import { healthCheck } from '../db/pool.js';

export default async function healthRoutes(fastify: FastifyInstance) {
  fastify.get('/health', async () => {
    return { status: 'ok', timestamp: new Date().toISOString() };
  });

  fastify.get('/ready', async (_, reply) => {
    const dbOk = await healthCheck();
    if (!dbOk) {
      return reply.status(503).send({ status: 'not_ready', db: false });
    }
    return { status: 'ready', db: true };
  });
}

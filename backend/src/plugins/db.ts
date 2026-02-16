// ─────────────────────────────────────────────
// MASSVISION Reap3r — Database Plugin
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { pool } from '../db/pool.js';

declare module 'fastify' {
  interface FastifyInstance {
    pg: {
      query: typeof pool.query;
      connect: typeof pool.connect;
    };
  }
}

async function dbPlugin(fastify: FastifyInstance) {
  fastify.decorate('pg', {
    query: pool.query.bind(pool),
    connect: pool.connect.bind(pool),
  });

  fastify.addHook('onClose', async () => {
    await pool.end();
  });
}

export default fp(dbPlugin, { name: 'db' });

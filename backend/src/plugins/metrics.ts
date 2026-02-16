// ─────────────────────────────────────────────
// MASSVISION Reap3r — Prometheus Metrics Plugin
// ─────────────────────────────────────────────
import { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import client from 'prom-client';

async function metricsPlugin(fastify: FastifyInstance) {
  const register = new client.Registry();
  client.collectDefaultMetrics({ register });

  const httpRequestDuration = new client.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status'],
    buckets: [0.01, 0.05, 0.1, 0.5, 1, 5],
    registers: [register],
  });

  const wsConnections = new client.Gauge({
    name: 'ws_connections_active',
    help: 'Number of active WebSocket connections',
    registers: [register],
  });

  const agentsOnline = new client.Gauge({
    name: 'agents_online_total',
    help: 'Number of agents currently online',
    registers: [register],
  });

  const jobsTotal = new client.Counter({
    name: 'jobs_created_total',
    help: 'Total number of jobs created',
    labelNames: ['type', 'status'],
    registers: [register],
  });

  // Track request duration
  fastify.addHook('onResponse', async (request, reply) => {
    const route = request.routeOptions?.url ?? request.url;
    httpRequestDuration.observe(
      { method: request.method, route, status: reply.statusCode },
      reply.elapsedTime / 1000
    );
  });

  // Expose /metrics
  fastify.get('/metrics', async (_, reply) => {
    reply.header('Content-Type', register.contentType);
    return register.metrics();
  });

  // Make counters accessible
  fastify.decorate('metrics', { wsConnections, agentsOnline, jobsTotal, register });
}

export default fp(metricsPlugin, { name: 'metrics' });

declare module 'fastify' {
  interface FastifyInstance {
    metrics: {
      wsConnections: import('prom-client').Gauge;
      agentsOnline: import('prom-client').Gauge;
      jobsTotal: import('prom-client').Counter;
      register: import('prom-client').Registry;
    };
  }
}

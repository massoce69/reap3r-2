// ------------------------------------------------------------
// MASSVISION Reap3r — Server Entry Point
// ------------------------------------------------------------
import { config } from './config.js';
import { buildApp } from './app.js';
import { startAlertEngine, stopAlertEngine } from './workers/alert-engine.js';
import { startDeployWorker, stopDeployWorker } from './workers/deploy-worker.js';

async function main() {
  const fastify = await buildApp();

  try {
    await fastify.listen({ port: config.port, host: '0.0.0.0' });
    fastify.log.info(`MASSVISION Reap3r API running on port ${config.port}`);

    startAlertEngine();
    startDeployWorker();

    const shutdown = async () => {
      stopAlertEngine();
      stopDeployWorker();
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


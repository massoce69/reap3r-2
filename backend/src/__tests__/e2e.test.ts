// ------------------------------------------------------------
// MASSVISION Reap3r — Backend E2E (self-hosted)
// Requires: TEST_DATABASE_URL
// ------------------------------------------------------------
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { runMigrations } from '../db/run-migrations.js';

const RUN = Boolean(process.env.TEST_DATABASE_URL);

describe.runIf(RUN)('Backend E2E', () => {
  let fastify: any;
  let apiUrl = '';
  let token = '';

  async function api(path: string, options: RequestInit = {}) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`${apiUrl}${path}`, { ...options, headers });
    const body = res.headers.get('content-type')?.includes('json')
      ? await res.json()
      : await res.text();
    return { status: res.status, body };
  }

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    process.env.DATABASE_URL = process.env.TEST_DATABASE_URL!;
    process.env.PORT = '0';
    process.env.WS_PORT = '0';
    process.env.PROMETHEUS_ENABLED = 'false';
    process.env.HMAC_SECRET = 'test_hmac_secret_change_me_00000000';
    process.env.JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_00000000';

    await runMigrations(process.env.DATABASE_URL);

    const { buildApp } = await import('../app.js');
    fastify = await buildApp({ logger: false });
    await fastify.listen({ port: 0, host: '127.0.0.1' });
    const addr = fastify.server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    apiUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    if (fastify) await fastify.close();
  });

  it('GET /health returns ok', async () => {
    const { status, body } = await api('/health');
    expect(status).toBe(200);
    expect(body.status).toBe('ok');
  });

  it('GET /ready returns db connected', async () => {
    const { status, body } = await api('/ready');
    expect(status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.database).toBe('connected');
  });

  it('POST /api/auth/login returns JWT', async () => {
    const { status, body } = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email: 'admin@massvision.local',
        password: 'Admin123!@#',
      }),
    });
    expect(status).toBe(200);
    expect(body.token).toBeDefined();
    token = body.token;
  });

  it('POST /api/enrollment/tokens creates a token', async () => {
    const { status, body } = await api('/api/enrollment/tokens', {
      method: 'POST',
      body: JSON.stringify({
        name: `Test Token ${Date.now()}`,
        max_uses: 10,
      }),
    });
    expect(status).toBe(201);
    expect(body.token).toBeDefined();
    expect(body.name).toContain('Test Token');

    const cmdRes = await api(`/api/enrollment/tokens/${body.id}/commands`);
    expect(cmdRes.status).toBe(200);
    expect(cmdRes.body.windows_powershell).toContain('api/install/windows');
    expect(cmdRes.body.linux_oneliner).toContain('api/install/linux');
  });
});


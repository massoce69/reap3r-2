// ------------------------------------------------------------
// MASSVISION Reap3r — Agent E2E Proof (Protocol v1)
// Requires: TEST_DATABASE_URL
//
// Scenario:
// - start backend HTTP + agent WS (ephemeral ports)
// - spawn tools/agent-sim (enroll + heartbeat loop)
// - create a job in backend (DB/API)
// - verify: agent exists, last_seen updated, job completed
// ------------------------------------------------------------
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { runMigrations } from '../db/run-migrations.js';

const RUN = Boolean(process.env.TEST_DATABASE_URL);

function waitFor(cond: () => boolean, timeoutMs = 10_000, tickMs = 50) {
  const start = Date.now();
  return new Promise<void>((resolve, reject) => {
    const t = setInterval(() => {
      if (cond()) {
        clearInterval(t);
        resolve();
        return;
      }
      if (Date.now() - start > timeoutMs) {
        clearInterval(t);
        reject(new Error('timeout'));
      }
    }, tickMs);
  });
}

describe.runIf(RUN)('Agent E2E (spawn agent-sim)', () => {
  let fastify: any;
  let apiUrl = '';
  let httpToken = '';

  async function api(pathname: string, options: RequestInit = {}) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };
    if (httpToken) headers.Authorization = `Bearer ${httpToken}`;
    const res = await fetch(`${apiUrl}${pathname}`, { ...options, headers });
    const body = res.headers.get('content-type')?.includes('json') ? await res.json() : await res.text();
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

    const login = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'admin@massvision.local', password: 'Admin123!@#' }),
    });
    expect(login.status).toBe(200);
    httpToken = login.body.token;
  });

  afterAll(async () => {
    if (fastify) await fastify.close();
  });

  it('Enroll -> Heartbeat -> JobAssign -> Ack/Result -> DB persisted', async () => {
    // 1) Create enrollment token.
    const tokRes = await api('/api/enrollment/tokens', {
      method: 'POST',
      body: JSON.stringify({ name: `E2E Token ${Date.now()}`, max_uses: 1 }),
    });
    expect(tokRes.status).toBe(201);
    const enrollToken = tokRes.body.token as string;

    // 2) Spawn agent-sim.
    const wsPort = fastify.agentWsPort;
    expect(typeof wsPort).toBe('number');
    const server = `ws://127.0.0.1:${wsPort}/ws/agent`;

    // Prefer running via Node's module loader/import so we don't depend on workspace-local .bin layout.
    const nodeBin = process.execPath;
    const nodeMajor = Number(process.versions.node.split('.')[0] || '0');
    const tsxArgs = nodeMajor >= 20 ? ['--import', 'tsx'] : ['--loader', 'tsx'];
    const simPath = path.join(process.cwd(), '..', 'tools', 'agent-sim', 'index.ts');

    let out = '';
    let agentId = '';
    let childExit: { code: number | null; signal: string | null } | null = null;

    const child = spawn(nodeBin, [...tsxArgs, simPath, `--server=${server}`, '--heartbeat_ms=1000'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        REAP3R_ENROLLMENT_TOKEN: enrollToken,
      },
    });

    child.on('exit', (code, signal) => {
      childExit = { code, signal };
    });

    child.stdout.on('data', (d) => {
      out += d.toString();
      const m = out.match(/enrolled:\s*([0-9a-f-]{36})/i);
      if (m && !agentId) agentId = m[1];
    });
    child.stderr.on('data', (d) => {
      out += d.toString();
    });

    // Wait until we have the agentId (enrolled).
    try {
      await waitFor(() => Boolean(agentId) || Boolean(childExit), 15_000, 50);
    } catch {
      // Include simulator output for diagnosis. It must not include secrets.
      throw new Error(`agent-sim did not enroll in time. Output:\n${out}`);
    }
    if (!agentId) {
      const exitInfo = childExit ? JSON.stringify(childExit) : 'null';
      throw new Error(`agent-sim exited before enrollment (${exitInfo}). Output:\n${out}`);
    }

    // 3) Create job for the enrolled agent.
    const jobRes = await api('/api/jobs', {
      method: 'POST',
      body: JSON.stringify({
        agent_id: agentId,
        job_type: 'run_script',
        payload: { interpreter: 'bash', script: 'echo hello', timeout_sec: 5 },
        reason: 'e2e',
        priority: 5,
        timeout_sec: 10,
      }),
    });
    expect(jobRes.status).toBe(201);
    const jobId = jobRes.body.id as string;

    // 4) Wait for sim to complete the job and exit.
    const exitCode = await new Promise<number | null>((resolve) => {
      const to = setTimeout(() => resolve(null), 30_000);
      child.on('exit', (code) => {
        clearTimeout(to);
        resolve(code);
      });
    });

    if (exitCode !== 0) {
      throw new Error(`agent-sim exited with code=${exitCode}. Output:\n${out}`);
    }
    expect(out).toMatch(/E2E OK/);

    // 5) DB proof: agent exists, last_seen updated, job completed.
    const agentRow = await fastify.pg.query(
      'SELECT id, last_seen_at FROM agents WHERE id = $1',
      [agentId],
    );
    expect(agentRow.rowCount).toBe(1);
    expect(agentRow.rows[0].last_seen_at).toBeTruthy();
    const lastSeenMs = new Date(agentRow.rows[0].last_seen_at).getTime();
    expect(Date.now() - lastSeenMs).toBeLessThan(60_000);

    const jobRow = await fastify.pg.query(
      'SELECT id, status, result FROM jobs WHERE id = $1',
      [jobId],
    );
    expect(jobRow.rowCount).toBe(1);
    expect(jobRow.rows[0].status).toBe('completed');
    expect(jobRow.rows[0].result).toBeTruthy();
  }, 30_000);
});

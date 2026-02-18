// ------------------------------------------------------------
// MASSVISION Reap3r — Agent WS E2E (Protocol v1)
// Requires: TEST_DATABASE_URL
// ------------------------------------------------------------
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import WebSocket from 'ws';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { runMigrations } from '../db/run-migrations.js';
import {
  MessageType,
  canonicalJsonStringify,
} from '@massvision/shared';

const RUN = Boolean(process.env.TEST_DATABASE_URL);

function computeSig(envelopeWithoutSig: any, secret: string): string {
  const canonical = canonicalJsonStringify(envelopeWithoutSig);
  return crypto.createHmac('sha256', secret).update(canonical).digest('hex');
}

function sign(env: any, secret: string) {
  const clone = { ...env };
  delete clone.sig;
  return { ...clone, sig: computeSig(clone, secret) };
}

function buildEnvelope(agentId: string, type: string, payload: any) {
  return {
    type,
    ts: Date.now(),
    nonce: uuidv4(),
    traceId: uuidv4(),
    agentId,
    payload,
  };
}

async function waitForMessage(ws: WebSocket, predicate: (msg: any) => boolean, timeoutMs = 10_000): Promise<any> {
  return new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('timeout')), timeoutMs);
    const onMsg = (data: WebSocket.RawData) => {
      try {
        const msg = JSON.parse(data.toString());
        if (predicate(msg)) {
          cleanup();
          resolve(msg);
        }
      } catch {}
    };
    const onErr = (e: any) => {
      cleanup();
      reject(e);
    };
    const cleanup = () => {
      clearTimeout(to);
      ws.off('message', onMsg);
      ws.off('error', onErr);
    };
    ws.on('message', onMsg);
    ws.on('error', onErr);
  });
}

describe.runIf(RUN)('Agent WS E2E', () => {
  let fastify: any;
  let apiUrl = '';
  let httpToken = '';

  async function api(path: string, options: RequestInit = {}) {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };
    if (httpToken) headers.Authorization = `Bearer ${httpToken}`;
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

  it('enroll -> heartbeat -> job -> ack/result (E2E OK)', async () => {
    // 1) Create enrollment token
    const tokRes = await api('/api/enrollment/tokens', {
      method: 'POST',
      body: JSON.stringify({ name: `WS Token ${Date.now()}`, max_uses: 10 }),
    });
    expect(tokRes.status).toBe(201);
    const enrollToken = tokRes.body.token as string;

    const wsPort = fastify.agentWsPort;
    expect(typeof wsPort).toBe('number');

    // 2) Connect WS and enroll (unsigned)
    const ws = new WebSocket(`ws://127.0.0.1:${wsPort}/ws/agent`);
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', (e) => reject(e));
    });

    const zeroId = '00000000-0000-0000-0000-000000000000';
    ws.send(JSON.stringify(buildEnvelope(zeroId, MessageType.EnrollRequest, {
      hostname: 'ws-e2e-agent',
      os: 'linux',
      os_version: 'e2e',
      arch: 'x86_64',
      agent_version: '1.0.0',
      enrollment_token: enrollToken,
    })));

    const enrollResp = await waitForMessage(ws, (m) => m.type === MessageType.EnrollResponse, 10_000);
    expect(enrollResp.payload.success).toBe(true);
    const agentId = enrollResp.payload.agent_id as string;
    const hmacKey = enrollResp.payload.hmac_key as string;
    expect(agentId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(hmacKey).toBe(process.env.HMAC_SECRET);

    // 3) Capabilities + heartbeat
    ws.send(JSON.stringify(sign(buildEnvelope(agentId, MessageType.Capabilities, {
      capabilities: ['run_script', 'metrics', 'inventory'],
      modules_version: { core: 'e2e' },
    }), hmacKey)));

    ws.send(JSON.stringify(sign(buildEnvelope(agentId, MessageType.Heartbeat, {
      uptime_sec: 10,
      memory_percent: 10,
      disk_percent: 5,
    }), hmacKey)));

    // 4) Create job
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

    // 5) Trigger dispatch
    ws.send(JSON.stringify(sign(buildEnvelope(agentId, MessageType.Heartbeat, {
      uptime_sec: 11,
      memory_percent: 10,
      disk_percent: 5,
    }), hmacKey)));

    // 6) Receive signed job_assign
    const jobAssign = await waitForMessage(ws, (m) => m.type === MessageType.JobAssign, 10_000);
    const receivedSig = jobAssign.sig as string;
    const expectedSig = computeSig({ ...jobAssign, sig: undefined }, hmacKey);
    expect(receivedSig).toBeDefined();
    // Accept case-insensitive
    expect(receivedSig.toLowerCase()).toBe(expectedSig.toLowerCase());
    expect(jobAssign.payload.job_id).toBe(jobId);

    // 7) ack + result
    ws.send(JSON.stringify(sign(buildEnvelope(agentId, MessageType.JobAck, {
      job_id: jobId,
      status: 'running',
    }), hmacKey)));

    ws.send(JSON.stringify(sign(buildEnvelope(agentId, MessageType.JobResult, {
      job_id: jobId,
      status: 'success',
      exit_code: 0,
      stdout: 'ok',
      stderr: '',
      duration_ms: 1,
    }), hmacKey)));

    // 8) Verify job completed (poll)
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      const j = await api(`/api/jobs/${jobId}`);
      if (j.status === 200 && j.body.status === 'completed') break;
      await new Promise((r) => setTimeout(r, 200));
    }
    const j2 = await api(`/api/jobs/${jobId}`);
    expect(j2.status).toBe(200);
    expect(j2.body.status).toBe('completed');
    expect(j2.body.result).toBeDefined();

    ws.close();
  });

  it('invalid sig => WS close (auth failed)', async () => {
    const tokRes = await api('/api/enrollment/tokens', {
      method: 'POST',
      body: JSON.stringify({ name: `BadSig Token ${Date.now()}`, max_uses: 10 }),
    });
    const enrollToken = tokRes.body.token as string;
    const wsPort = fastify.agentWsPort;
    const ws = new WebSocket(`ws://127.0.0.1:${wsPort}/ws/agent`);
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', (e) => reject(e));
    });

    const zeroId = '00000000-0000-0000-0000-000000000000';
    ws.send(JSON.stringify(buildEnvelope(zeroId, MessageType.EnrollRequest, {
      hostname: 'ws-e2e-agent-2',
      os: 'linux',
      os_version: 'e2e',
      arch: 'x86_64',
      agent_version: '1.0.0',
      enrollment_token: enrollToken,
    })));

    const enrollResp = await waitForMessage(ws, (m) => m.type === MessageType.EnrollResponse, 10_000);
    const agentId = enrollResp.payload.agent_id as string;

    // Send heartbeat with wrong signature.
    const bad = sign(buildEnvelope(agentId, MessageType.Heartbeat, {
      uptime_sec: 1,
      memory_percent: 1,
      disk_percent: 1,
    }), 'wrong_secret');
    ws.send(JSON.stringify(bad));

    const closed = await new Promise<boolean>((resolve) => {
      ws.once('close', () => resolve(true));
      setTimeout(() => resolve(false), 3000);
    });
    expect(closed).toBe(true);
  });
});


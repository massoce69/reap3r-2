#!/usr/bin/env node
// ------------------------------------------------------------
// MASSVISION Reap3r — Agent Simulator (Protocol v1)
// Usage:
//   npm -w backend run test:agent-sim -- --server=ws://localhost:4001/ws/agent --token=... --secret=...
// ------------------------------------------------------------
import WebSocket from 'ws';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import {
  MessageType,
  canonicalJsonStringify,
  MessageEnvelopeSchema,
  JobAssignPayload,
} from '@massvision/shared';

const argv = process.argv.slice(2).reduce((acc, arg) => {
  const [k, v] = arg.split('=');
  acc[k.replace(/^--/, '')] = v;
  return acc;
}, {} as Record<string, string>);

const SERVER = argv.server || process.env.REAP3R_AGENT_SIM_SERVER || 'ws://localhost:4001/ws/agent';
const TOKEN = argv.token || process.env.REAP3R_ENROLLMENT_TOKEN || '';
const FALLBACK_SECRET = argv.secret || 'dev_hmac_secret_change_in_production_00000000';
const HEARTBEAT_EVERY_MS = parseInt(argv.heartbeat_ms || '5000', 10);

if (!TOKEN) {
  console.error('[agent-sim] Missing --token=... (or set REAP3R_ENROLLMENT_TOKEN)');
  process.exit(2);
}

function computeSig(envelopeWithoutSig: any, secret: string): string {
  const canonical = canonicalJsonStringify(envelopeWithoutSig);
  return crypto.createHmac('sha256', secret).update(canonical).digest('hex');
}

function signEnvelope(env: any, secret: string): any {
  const clone = { ...env };
  delete clone.sig;
  return { ...clone, sig: computeSig(clone, secret) };
}

function buildEnvelope(agentId: string, type: string, payload: any, extra?: Partial<any>) {
  return {
    type,
    ts: Date.now(),
    nonce: uuidv4(),
    traceId: uuidv4(),
    agentId,
    payload,
    ...(extra ?? {}),
  };
}

console.log('[agent-sim] Starting...');
console.log(`  Server: ${SERVER}`);

let agentId = '00000000-0000-0000-0000-000000000000';
let hmacKey = '';
let hbTimer: NodeJS.Timeout | null = null;
function startHeartbeatLoop() {
  if (hbTimer) return;
  hbTimer = setInterval(() => {
    if (!hmacKey) return;
    ws.send(JSON.stringify(signEnvelope(
      buildEnvelope(agentId, MessageType.Heartbeat, {
        uptime_sec: 123,
        memory_percent: 10,
        disk_percent: 5,
      }),
      hmacKey,
    )));
  }, HEARTBEAT_EVERY_MS);
}

const ws = new WebSocket(SERVER);

ws.on('open', () => {
  console.log('[agent-sim] WS connected');
  const enroll = buildEnvelope(agentId, MessageType.EnrollRequest, {
    hostname: 'agent-sim',
    os: 'linux',
    os_version: 'sim',
    arch: 'x86_64',
    agent_version: '1.0.0',
    enrollment_token: TOKEN,
  });
  // Enrollment is unsigned.
  ws.send(JSON.stringify(enroll));
});

ws.on('message', async (data: WebSocket.Data) => {
  const text = data.toString();
  let msg: any;
  try {
    msg = JSON.parse(text);
  } catch {
    console.error('[agent-sim] Invalid JSON from server');
    process.exit(1);
  }

  if (msg.type === MessageType.EnrollResponse) {
    const p = msg.payload || {};
    if (!p.success) {
      console.error(`[agent-sim] Enroll failed: ${p.error || 'unknown'}`);
      process.exit(1);
    }
    agentId = p.agent_id;
    hmacKey = p.hmac_key || FALLBACK_SECRET;
    console.log(`[agent-sim] Enrolled OK agentId=${agentId}`);

    // Capabilities (signed)
    ws.send(JSON.stringify(signEnvelope(
      buildEnvelope(agentId, MessageType.Capabilities, {
        capabilities: ['run_script', 'metrics', 'inventory'],
        modules_version: { core: 'sim' },
      }),
      hmacKey,
    )));

    // Heartbeat (signed)
    ws.send(JSON.stringify(signEnvelope(
      buildEnvelope(agentId, MessageType.Heartbeat, {
        uptime_sec: 123,
        memory_percent: 10,
        disk_percent: 5,
      }),
      hmacKey,
    )));
    startHeartbeatLoop();

    // Metrics (signed)
    ws.send(JSON.stringify(signEnvelope(
      buildEnvelope(agentId, MessageType.MetricsPush, {
        ts: Date.now(),
        cpu_percent: 7,
        memory_total_bytes: 8_000_000_000,
        memory_used_bytes: 900_000_000,
        disk_total_bytes: 200_000_000_000,
        disk_used_bytes: 20_000_000_000,
        process_count: 42,
      }),
      hmacKey,
    )));

    console.log('[agent-sim] Waiting for job_assign...');
    return;
  }

  // For all non-enroll_response server messages, validate the envelope shape.
  const parsed = MessageEnvelopeSchema.safeParse(msg);
  if (!parsed.success) {
    console.error('[agent-sim] Invalid envelope from server');
    console.error('[agent-sim] raw:', JSON.stringify(msg));
    process.exit(1);
  }

  if (msg.type === MessageType.JobAssign) {
    const jobParsed = JobAssignPayload.safeParse(msg.payload);
    if (!jobParsed.success) {
      console.error('[agent-sim] Invalid job_assign payload');
      process.exit(1);
    }

    const job = jobParsed.data;
    console.log(`[agent-sim] Got job_assign job_id=${job.job_id} name=${job.name}`);

    ws.send(JSON.stringify(signEnvelope(
      buildEnvelope(agentId, MessageType.JobAck, { job_id: job.job_id, status: 'running' }),
      hmacKey,
    )));

    // Simulate execution and return result.
    await new Promise((r) => setTimeout(r, 200));
    ws.send(JSON.stringify(signEnvelope(
      buildEnvelope(agentId, MessageType.JobResult, {
        job_id: job.job_id,
        status: 'success',
        exit_code: 0,
        stdout: 'ok',
        stderr: '',
        duration_ms: 200,
      }),
      hmacKey,
    )));

    console.log('[agent-sim] E2E OK');
    if (hbTimer) clearInterval(hbTimer);
    ws.close();
    process.exit(0);
  }
});

ws.on('error', (err: Error) => {
  console.error('[agent-sim] WS error:', err.message);
  process.exit(1);
});

setTimeout(() => {
  console.error('[agent-sim] Timeout (30s)');
  process.exit(1);
}, 30_000);

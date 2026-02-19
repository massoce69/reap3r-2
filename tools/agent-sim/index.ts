// Reap3r Agent Simulator (Protocol v1)
//
// Example:
//   npx tsx tools/agent-sim/index.ts --server=ws://localhost:4000/ws/agent --token=... 
//
import WebSocket from 'ws';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { MessageType, canonicalJsonStringify, MessageEnvelopeSchema } from '@massvision/shared';

const argv = process.argv.slice(2).reduce((acc, arg) => {
  const [k, v] = arg.split('=');
  acc[k.replace(/^--/, '')] = v;
  return acc;
}, {} as Record<string, string>);

const server = argv.server || process.env.REAP3R_AGENT_SIM_SERVER || 'ws://localhost:4000/ws/agent';
const token = argv.token || process.env.REAP3R_ENROLLMENT_TOKEN || '';
const heartbeatMs = parseInt(argv.heartbeat_ms || '5000', 10);

if (!token) {
  console.error('[agent-sim] Missing --token=... (or set REAP3R_ENROLLMENT_TOKEN)');
  process.exit(2);
}

function computeSig(envelopeWithoutSig: any, secret: string): string {
  const canonical = canonicalJsonStringify(envelopeWithoutSig);
  return crypto.createHmac('sha256', secret).update(canonical).digest('hex');
}

function sign(env: any, secret: string) {
  const clone = { ...env };
  delete clone.sig;
  return { ...clone, sig: computeSig(clone, secret) };
}

function env(agentId: string, type: string, payload: any) {
  return { type, ts: Date.now(), nonce: uuidv4(), traceId: uuidv4(), agentId, payload };
}

console.log('[agent-sim] connecting:', server);
const ws = new WebSocket(server);

let agentId = '00000000-0000-0000-0000-000000000000';
let hmacKey = '';
let hbTimer: NodeJS.Timeout | null = null;
function startHeartbeatLoop() {
  if (hbTimer) return;
  hbTimer = setInterval(() => {
    if (!hmacKey) return;
    ws.send(JSON.stringify(sign(env(agentId, MessageType.Heartbeat, {
      uptime_sec: 1,
      memory_percent: 10,
      disk_percent: 10,
    }), hmacKey)));
  }, heartbeatMs);
}

ws.on('open', () => {
  ws.send(JSON.stringify(env(agentId, MessageType.EnrollRequest, {
    hostname: 'tools-agent-sim',
    os: 'linux',
    os_version: 'sim',
    arch: 'x86_64',
    agent_version: '1.0.0',
    enrollment_token: token,
  })));
});

ws.on('message', async (data) => {
  const msg = JSON.parse(data.toString());

  if (msg.type === MessageType.EnrollResponse) {
    if (!msg.payload?.success) {
      console.error('[agent-sim] enroll failed:', msg.payload?.error || 'unknown');
      process.exit(1);
    }
    agentId = msg.payload.agent_id;
    hmacKey = msg.payload.hmac_key;
    console.log('[agent-sim] enrolled:', agentId);

    ws.send(JSON.stringify(sign(env(agentId, MessageType.Capabilities, {
      capabilities: ['run_script', 'metrics', 'inventory'],
      modules_version: { core: 'tools-sim' },
    }), hmacKey)));

    ws.send(JSON.stringify(sign(env(agentId, MessageType.Heartbeat, {
      uptime_sec: 1,
      memory_percent: 10,
      disk_percent: 10,
    }), hmacKey)));
    startHeartbeatLoop();

    console.log('[agent-sim] waiting for job_assign...');
    return;
  }

  const parsed = MessageEnvelopeSchema.safeParse(msg);
  if (!parsed.success) {
    console.error('[agent-sim] invalid envelope from server');
    console.error('[agent-sim] raw:', JSON.stringify(msg));
    process.exit(1);
  }

  if (msg.type === MessageType.JobAssign) {
    console.log('[agent-sim] job_assign:', msg.payload?.job_id, msg.payload?.name);
    ws.send(JSON.stringify(sign(env(agentId, MessageType.JobAck, {
      job_id: msg.payload.job_id,
      status: 'running',
    }), hmacKey)));

    ws.send(JSON.stringify(sign(env(agentId, MessageType.JobResult, {
      job_id: msg.payload.job_id,
      status: 'success',
      exit_code: 0,
      stdout: 'ok',
      stderr: '',
      duration_ms: 1,
    }), hmacKey)));

    console.log('[agent-sim] E2E OK');
    if (hbTimer) clearInterval(hbTimer);
    ws.close();
    process.exit(0);
  }
});

ws.on('error', (err) => {
  console.error('[agent-sim] ws error:', (err as any)?.message || String(err));
  process.exit(1);
});

setTimeout(() => {
  console.error('[agent-sim] timeout');
  process.exit(1);
}, 30_000);

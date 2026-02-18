#!/usr/bin/env -S npx ts-node
// ─────────────────────────────────────────────
// MASSVISION Reap3r — Agent Simulator (E2E Test)
// Usage: npx ts-node agent-sim.ts --server ws://localhost:4001 --token <token>
// ─────────────────────────────────────────────

import WebSocket from 'ws';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

interface AgentMessage {
  agent_id: string;
  ts: number;
  nonce: string;
  type: string;
  payload: any;
  hmac: string;
}

const args = process.argv.slice(2).reduce((acc, arg) => {
  const [k, v] = arg.split('=');
  acc[k.replace('--', '')] = v;
  return acc;
}, {} as Record<string, string>);

const SERVER = args.server || 'ws://localhost:4001';
const TOKEN = args.token || 'test-token-12345';
const HMAC_SECRET = args.secret || 'dev_hmac_secret_change_in_production_00000000';

console.log(`[agent-sim] Starting...`);
console.log(`  Server: ${SERVER}`);
console.log(`  Token:  ${TOKEN}`);

// State
let agentId = '';
let agentSecret = '';
const ws = new WebSocket(SERVER);

function computeHmac(msg: Partial<AgentMessage>): string {
  const { hmac, ...toSign } = msg;
  const canonical = JSON.stringify(toSign, Object.keys(toSign).sort());
  return crypto
    .createHmac('sha256', agentSecret || HMAC_SECRET)
    .update(canonical)
    .digest('hex');
}

function buildMessage(type: string, payload: any): string {
  const msg: Partial<AgentMessage> = {
    agent_id: agentId || '00000000-0000-0000-0000-000000000000',
    ts: Date.now(),
    nonce: uuidv4(),
    type,
    payload,
  };
  const hmac = computeHmac(msg);
  return JSON.stringify({ ...msg, hmac });
}

function log(stage: string, msg: string) {
  console.log(`[agent-sim:${stage}] ${msg}`);
}

ws.on('open', () => {
  log('ws', 'Connected to server');

  // 1. Send enrollment request
  const enrollMsg = buildMessage('enroll_request', {
    hostname: 'test-agent-001',
    os: 'linux',
    os_version: '5.10',
    arch: 'x86_64',
    agent_version: '1.0.0',
    enrollment_token: TOKEN,
  });
  log('enroll', `Sending enrollment request (token: ${TOKEN.substring(0, 8)}...)`);
  ws.send(enrollMsg);
});

ws.on('message', async (data: WebSocket.Data) => {
  const text = data.toString();
  try {
    const msg: any = JSON.parse(text);
    const type = msg.type;

    if (type === 'enroll_response') {
      const { payload } = msg;
      if (payload.error) {
        log('enroll', `❌ Error: ${payload.error}`);
        process.exit(1);
      }

      agentId = payload.agent_id;
      agentSecret = payload.agent_secret || payload.hmac_key;
      log('enroll', `✅ Enrolled as ${agentId}`);
      log('enroll', `   Secret (first 16): ${agentSecret.substring(0, 16)}...`);

      // 2. Send capabilities
      const capsMsg = buildMessage('capabilities', {
        capabilities: ['run_script', 'metrics', 'inventory', 'remote_shell'],
        modules_version: { core: '1.0.0' },
      });
      log('caps', 'Sending capabilities...');
      ws.send(capsMsg);

      // 3. Send heartbeat
      setTimeout(() => {
        const hbMsg = buildMessage('heartbeat', {
          uptime_secs: 3600,
          cpu_percent: 15.2,
          memory_used_mb: 512,
          memory_total_mb: 8192,
        });
        log('heartbeat', 'Sending heartbeat...');
        ws.send(hbMsg);
      }, 500);

      // 4. Wait for job_assign
      log('job', 'Waiting for job assignment...');
    } else if (type === 'job_assign') {
      const { payload } = msg;
      const job = payload;
      const jobId = job.id;
      const jobType = job.type;

      log('job', `✅ Received job: ${jobId} (type: ${jobType})`);

      // Send ACK
      const ackMsg = buildMessage('job_ack', {
        job_id: jobId,
        status: 'running',
      });
      log('job_ack', `Sending ACK for ${jobId}...`);
      ws.send(ackMsg);

      // Simulate execution delay
      await new Promise((r) => setTimeout(r, 500));

      // Send result
      const resultMsg = buildMessage('job_result', {
        job_id: jobId,
        status: 'success',
        exit_code: 0,
        stdout: 'Job executed successfully',
        stderr: '',
        duration_ms: 523,
      });
      log('job_result', `Sending result for ${jobId}...`);
      ws.send(resultMsg);

      // Keep connection alive for a bit then close
      await new Promise((r) => setTimeout(r, 2000));
      log('done', '✅ All tests passed! Closing connection.');
      ws.close();
      process.exit(0);
    } else if (type === 'error') {
      const payload = msg.payload;
      log('error', `Server error: ${payload?.message || text}`);
      process.exit(1);
    } else {
      log('msg', `Received: ${type}`);
    }
  } catch (err) {
    log('error', `Failed to parse message: ${err}`);
  }
});

ws.on('error', (err: Error) => {
  log('error', `WebSocket error: ${err.message}`);
  process.exit(1);
});

ws.on('close', () => {
  log('ws', 'Connection closed');
  // If we haven't exited yet, something went wrong
  if (!agentId) {
    log('error', '❌ Did not complete enrollment');
    process.exit(1);
  }
});

// Timeout after 30s
setTimeout(() => {
  log('timeout', '❌ Test timed out after 30s');
  process.exit(1);
}, 30000);

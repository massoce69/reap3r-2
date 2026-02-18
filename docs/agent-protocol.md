# Reap3r Agent Protocol v1

Source of truth: `shared/src/protocol.ts`.

This protocol is used over WebSocket at `/ws/agent` for all agent-to-backend and backend-to-agent messages.

## 1. Transport

- WebSocket endpoint: `ws(s)://<host>/ws/agent`
- Encoding: UTF-8 JSON text messages
- Time: all timestamps are milliseconds since Unix epoch

## 2. Envelope (All Signed Messages)

All messages use the same envelope:

```json
{
  "type": "heartbeat",
  "ts": 1710000000000,
  "nonce": "b7f8c0e6-7c2a-4d43-9c07-8aaf1c1a2b3c",
  "traceId": "2e1f9a9a-1c29-4f7f-8d8e-6f7b1a0c1234",
  "agentId": "46082012-79dc-4549-bdb7-de96386500e6",
  "orgId": "00000000-0000-0000-0000-000000000001",
  "payload": { },
  "sig": "64_hex_chars..."
}
```

Fields:

- `type`: one of `MessageType` (exact strings)
- `ts`: milliseconds since epoch
- `nonce`: anti-replay nonce (UUIDv4 recommended)
- `traceId`: correlation id (UUIDv4 recommended)
- `agentId`: agent UUID (all-zero UUID during enrollment)
- `orgId`: optional (backend can include it)
- `payload`: message payload (type-specific)
- `sig`: optional for enrollment only; required for all other messages

## 3. Signature (HMAC)

For every message except `enroll_request`:

- `sig = HMAC_SHA256(hmac_key, canonical_json(envelope_without_sig))`
- `canonical_json` means:
  - recursively sort object keys
  - stringify with standard JSON (no whitespace)

Important P0 rule:

- Signed payloads must avoid floats that can serialize differently across languages (`0.0` vs `0`).
  - Use integers for percentages and counters.

If signature verification fails:

- backend must `close()` the WebSocket
- backend logs the failure and increments `ws_auth_failed_total`

## 4. Enrollment

### 4.1 `enroll_request` (unsigned)

Envelope:

- `type = "enroll_request"`
- `agentId = "00000000-0000-0000-0000-000000000000"`
- no `sig`

Payload (`EnrollRequestPayload`):

```json
{
  "hostname": "pc-001",
  "os": "windows",
  "os_version": "10.0.19045",
  "arch": "x86_64",
  "agent_version": "1.0.0",
  "enrollment_token": "..."
}
```

### 4.2 `enroll_response` (unsigned envelope)

The backend replies with an **envelope** but without `sig`:

```json
{
  "type": "enroll_response",
  "ts": 1710000000000,
  "nonce": "uuid",
  "traceId": "uuid",
  "agentId": "uuid",
  "payload": {
    "success": true,
    "agent_id": "uuid",
    "org_id": "uuid",
    "hmac_key": "shared_hmac_secret",
    "server_url": "https://...",
    "heartbeat_interval_sec": 10
  }
}
```

Protocol v1 decision:

- `hmac_key` is the backend `HMAC_SECRET` (global key) for P0 reliability.

The agent must persist:

- `agent_id`
- `hmac_key`
- `server`

## 5. Heartbeat / Metrics / Inventory

### 5.1 `heartbeat` (signed)

Payload (`HeartbeatPayload`):

```json
{
  "uptime_sec": 12345,
  "memory_percent": 37,
  "disk_percent": 81
}
```

### 5.2 `metrics_push` (signed)

Payload (`MetricsPushPayload`):

```json
{
  "ts": 1710000000000,
  "cpu_percent": 12,
  "memory_total_bytes": 17179869184,
  "memory_used_bytes": 4294967296,
  "disk_total_bytes": 1000000000000,
  "disk_used_bytes": 500000000000,
  "process_count": 210
}
```

### 5.3 `inventory_push` (signed)

Payload (`InventoryPushPayload`): a snapshot of host inventory. Extra fields are allowed; the backend stores the full JSON.

## 6. Jobs

### 6.1 `job_assign` (backend -> agent, signed)

Payload (`JobAssignPayload`):

```json
{
  "job_id": "uuid",
  "name": "run_script",
  "args": { "interpreter": "bash", "script": "echo hi" },
  "timeout_sec": 300,
  "created_at": "2026-02-18T12:00:00.000Z"
}
```

### 6.2 `job_ack` (agent -> backend, signed)

Payload (`JobAckPayload`):

```json
{ "job_id": "uuid", "status": "running" }
```

or

```json
{ "job_id": "uuid", "status": "rejected", "reason": "duplicate" }
```

### 6.3 `job_result` (agent -> backend, signed)

Payload (`JobResultPayload`):

```json
{
  "job_id": "uuid",
  "status": "success",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "duration_ms": 523
}
```

Job lifecycle target (backend DB):

- `pending` -> `dispatched` -> `running` -> `completed|failed`

## 7. Failure Semantics (P0)

- Invalid envelope: backend responds `error` and closes WS.
- Invalid signature: backend closes WS (fail-closed).
- Network loss: agent reconnects with exponential backoff + jitter (agent-side).
- Idempotence: agent must reject duplicate `job_id` executions.

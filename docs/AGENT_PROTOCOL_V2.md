# MASSVISION Reap3r — Agent Protocol V2 Specification

## Overview

The Agent Protocol V2 defines the communication between Reap3r agents and the backend server over persistent WebSocket connections. All messages are cryptographically signed with HMAC-SHA256 and protected against replay attacks.

## Transport

- **Protocol**: WebSocket (RFC 6455)
- **Endpoint**: `wss://<server>/ws/agent`
- **Encoding**: JSON (UTF-8)
- **Compression**: Per-message deflate (optional)
- **TLS**: Required in production (TLS 1.2+)

## Message Envelope

Every message follows this structure:

```json
{
  "agent_id": "uuid",       // Agent UUID (00000000-... for enrollment)
  "ts": 1700000000000,      // Unix timestamp in milliseconds
  "nonce": "uuid",          // Unique nonce per message
  "type": "message_type",   // Message type identifier
  "payload": { ... },       // Type-specific payload
  "hmac": "hex-string"      // HMAC-SHA256 signature (64 hex chars)
}
```

## HMAC Signing

### Computation

1. Construct the message object **without** the `hmac` field
2. Serialize to JSON string (canonical)
3. Compute HMAC-SHA256 using the agent's secret key
4. Encode result as lowercase hex string

```
HMAC = hex(HMAC-SHA256(key=agent_secret, data=json_without_hmac))
```

### Verification

Server verifies every message:
1. Extract and remove `hmac` from message
2. Serialize remaining fields to JSON
3. Compute expected HMAC using stored agent secret
4. Compare using constant-time comparison

### Anti-Replay Protection

- **Nonce**: Must be unique per agent per session. Server tracks recent nonces.
- **Timestamp Window**: `|server_time - message_ts| <= 300000ms` (5 minutes)
- Messages outside the window are rejected with `REPLAY_DETECTED`

## Connection Lifecycle

```
Agent                                    Server
  │                                        │
  │──── [Connect WebSocket] ──────────────│
  │                                        │
  │──── enroll_request ───────────────────│  (new agent)
  │◄─── enroll_response ─────────────────│
  │                                        │
  │──── capabilities ─────────────────────│  (after enroll/reconnect)
  │                                        │
  │──── heartbeat ── (every 30s) ────────│
  │◄─── job_assign ──────────────────────│  (if pending jobs)
  │──── job_ack ──────────────────────────│
  │──── stream_output ── (optional) ─────│
  │──── job_result ───────────────────────│
  │                                        │
  │──── metrics_push ── (every 30s) ─────│
  │──── inventory_push ── (every 5min) ──│
  │                                        │
```

## Message Types

### Agent → Server

#### `enroll_request`

Sent by a new agent to register with the server.

```json
{
  "type": "enroll_request",
  "agent_id": "00000000-0000-0000-0000-000000000000",
  "hmac": "0000...0000",
  "payload": {
    "hostname": "workstation-01",
    "os": "linux",
    "os_version": "Ubuntu 24.04",
    "arch": "x86_64",
    "agent_version": "0.1.0",
    "enrollment_token": "uuid-token"
  }
}
```

Note: Enrollment messages use a zeroed agent_id and hmac since the agent doesn't have a secret yet.

#### `heartbeat`

Sent periodically to indicate liveness and report basic metrics.

```json
{
  "type": "heartbeat",
  "payload": {
    "uptime_secs": 86400,
    "cpu_percent": 23.5,
    "memory_used_mb": 4096,
    "memory_total_mb": 16384
  }
}
```

Server responds with pending jobs (if any) via `job_assign`.

#### `capabilities`

Declares what the agent can do. Sent after enrollment or reconnection.

```json
{
  "type": "capabilities",
  "payload": {
    "capabilities": [
      "run_script",
      "metrics",
      "inventory",
      "service_management",
      "process_management",
      "reboot",
      "shutdown",
      "remote_shell",
      "remote_desktop",
      "privacy_mode",
      "input_lock",
      "wake_on_lan",
      "self_update",
      "file_transfer"
    ],
    "modules_version": {
      "core": "0.1.0"
    }
  }
}
```

#### `metrics_push`

Detailed system metrics snapshot.

```json
{
  "type": "metrics_push",
  "payload": {
    "collected_at": 1700000000000,
    "cpu_percent": 23.5,
    "memory_used_mb": 4096,
    "memory_total_mb": 16384,
    "disk_used_gb": 120.5,
    "disk_total_gb": 500,
    "network_rx_bytes": 1048576,
    "network_tx_bytes": 524288,
    "processes_count": 142,
    "gpu_percent": 45.0,
    "gpu_memory_mb": 2048
  }
}
```

#### `inventory_push`

Full system inventory (hardware, software, network).

```json
{
  "type": "inventory_push",
  "payload": {
    "collected_at": 1700000000000,
    "hardware": {
      "cpu_model": "Intel Core i9-13900K",
      "cpu_cores": 24,
      "ram_gb": 64,
      "gpu": "NVIDIA RTX 4090",
      "disk_model": "Samsung 990 Pro",
      "disk_gb": 1000
    },
    "software": {
      "os": "Ubuntu 24.04.1 LTS",
      "kernel": "6.5.0-44-generic",
      "installed_packages": 1842
    },
    "network": {
      "interfaces": [
        {
          "name": "eth0",
          "mac": "00:11:22:33:44:55",
          "ipv4": "192.168.1.100",
          "ipv6": "fe80::1"
        }
      ]
    }
  }
}
```

#### `job_ack`

Acknowledges receipt of a job assignment.

```json
{
  "type": "job_ack",
  "payload": {
    "job_id": "uuid"
  }
}
```

#### `job_result`

Reports the final result of a job execution.

```json
{
  "type": "job_result",
  "payload": {
    "job_id": "uuid",
    "success": true,
    "data": {
      "exit_code": 0,
      "stdout": "...",
      "stderr": "",
      "duration_ms": 1234
    }
  }
}
```

#### `stream_output`

Real-time output streaming during long-running jobs.

```json
{
  "type": "stream_output",
  "payload": {
    "job_id": "uuid",
    "channel": "stdout",
    "data": "line of output\n",
    "seq": 42
  }
}
```

### Server → Agent

#### `enroll_response`

Response to enrollment request.

```json
{
  "type": "enroll_response",
  "payload": {
    "success": true,
    "agent_id": "uuid",
    "agent_secret": "hex-string-64-chars",
    "server_ts": 1700000000000
  }
}
```

Error response:

```json
{
  "type": "enroll_response",
  "payload": {
    "success": false,
    "error": "Invalid or expired enrollment token"
  }
}
```

#### `job_assign`

Assigns a job to the agent (sent after heartbeat or on-demand).

```json
{
  "type": "job_assign",
  "job": {
    "id": "uuid",
    "type": "run_script",
    "payload": {
      "interpreter": "bash",
      "script": "echo Hello World",
      "timeout_secs": 300,
      "run_as": "root",
      "env": { "MY_VAR": "value" }
    },
    "timeout_secs": 300
  }
}
```

## Job Types

| Type | Capability Required | Phase | Description |
|------|-------------------|-------|-------------|
| `run_script` | `run_script` | 1 | Execute script (bash/powershell/python/cmd) |
| `collect_metrics` | `metrics` | 1 | Collect system metrics |
| `collect_inventory` | `inventory` | 1 | Collect system inventory |
| `service_action` | `service_management` | 1 | Start/stop/restart services |
| `process_action` | `process_management` | 1 | Kill/list processes |
| `reboot` | `reboot` | 1 | Reboot machine |
| `shutdown` | `shutdown` | 1 | Shutdown machine |
| `remote_shell` | `remote_shell` | 2 | Interactive remote shell session |
| `remote_desktop` | `remote_desktop` | 3 | Remote desktop session |
| `privacy_mode` | `privacy_mode` | 3 | Screen blanking during remote |
| `input_lock` | `input_lock` | 3 | Lock keyboard/mouse during remote |
| `wake_on_lan` | `wake_on_lan` | 4 | Wake machine via WoL packet |
| `update_agent` | `self_update` | 4 | Self-update agent binary |
| `file_transfer_upload` | `file_transfer` | 5 | Upload file to agent |
| `file_transfer_download` | `file_transfer` | 5 | Download file from agent |

## Error Handling

### Connection Errors

| Code | Reason | Action |
|------|--------|--------|
| 1000 | Normal close | Reconnect after delay |
| 1001 | Going away | Reconnect after delay |
| 1008 | Policy violation | Check credentials |
| 4001 | Authentication failed | Re-enroll |
| 4002 | Replay detected | Sync clock, retry |
| 4003 | Rate limited | Back off exponentially |

### Reconnection Strategy

- Initial delay: 5 seconds
- Max delay: 5 minutes
- Backoff: Exponential (5s, 10s, 20s, 40s, 80s, 160s, 300s)
- Jitter: ±20% randomization
- Reset delay on successful heartbeat

## Security Considerations

1. **Secret Storage**: Agent secrets must be stored with OS-level protection (600 permissions, Windows DPAPI)
2. **Clock Sync**: Agents should use NTP to prevent replay window issues
3. **Binary Integrity**: Bootstrap verifies agent binary SHA256 before execution
4. **Minimal Permissions**: Agent runs as dedicated service user (not root) where possible
5. **Audit Trail**: All job executions are logged server-side with full context

# MASSVISION Reap3r

**Enterprise Agent-Driven Remote Management Platform**

A commercial-grade, multi-tenant remote management platform with real-time agent communication, RBAC, and comprehensive audit logging. Optimized for Ubuntu 24.04 LTS deployment.

---

## Architecture

```
┌──────────────┐    WSS/HTTPS    ┌───────────┐    ┌───────────┐    ┌──────────┐
│   Agents     │ ──────────────► │   Nginx   │ ──►│  Backend  │ ──►│PostgreSQL│
│ (Rust binary)│                 │ (TLS/RP)  │    │ (Fastify) │    │   16     │
└──────────────┘                 └─────┬─────┘    └─────┬─────┘    └──────────┘
                                       │                │
┌──────────────┐                 ┌─────┴─────┐    ┌─────┴─────┐
│  Browser UI  │ ──── HTTPS ───►│ Frontend  │    │Prometheus │
│              │                 │ (Next.js) │    │ + Grafana │
└──────────────┘                 └───────────┘    └───────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Node.js 22 / Fastify 5 / TypeScript |
| **Frontend** | Next.js 15 / React 19 / TailwindCSS |
| **Agent** | Rust (tokio, tungstenite, sysinfo) |
| **Database** | PostgreSQL 16 |
| **Protocol** | WebSocket + HMAC-SHA256 + Anti-Replay |
| **Observability** | Prometheus + Grafana |
| **Deployment** | Docker Compose / Ubuntu 24.04 LTS |

## Features (Phase 1)

- **Authentication & RBAC** — JWT auth with 4 roles (super_admin, org_admin, technician, viewer) and 31 granular permissions
- **Agent Management** — Enrollment via tokens, real-time status tracking, capability discovery
- **Job Engine** — Script execution (bash/powershell/python/cmd), service management, process control, reboot/shutdown
- **Real-time Communication** — WebSocket protocol with HMAC-SHA256 signing and anti-replay protection
- **Audit Logging** — Complete trail of all user and agent actions
- **Dark UI** — Modern futuristic interface with real-time updates
- **Monitoring** — Prometheus metrics + Grafana dashboards
- **Production-Ready** — Docker Compose, TLS, UFW, Fail2Ban, systemd service

## Quick Start (Development)

```bash
# Clone
git clone https://github.com/massvision/reap3r.git
cd massvision-reap3r

# Install dependencies
npm install

# Start infrastructure
docker compose up -d postgres

# Run backend
npm run dev -w @massvision/backend

# Run frontend (in another terminal)
npm run dev -w @massvision/frontend
```

### Default Credentials

| Service | Email | Password |
|---------|-------|----------|
| Reap3r UI | admin@massvision.local | Admin123!@# |

## Production Deployment (Ubuntu 24.04 LTS)

```bash
# One-command installation
sudo bash infra/scripts/install_ubuntu_24_04.sh \
  --domain reap3r.example.com \
  --email admin@example.com

# Build & start
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```

See [RUNBOOK_UBUNTU_24_04.md](docs/RUNBOOK_UBUNTU_24_04.md) for complete operations guide.

## Project Structure

```
massvision-reap3r/
├── shared/              # Shared types, schemas, protocol
│   └── src/
│       ├── protocol.ts  # Agent Protocol V2 (HMAC, anti-replay)
│       ├── job-types.ts # Job types & payload schemas
│       ├── rbac.ts      # Roles & permissions
│       └── schemas.ts   # API DTOs (Zod)
├── backend/             # Fastify API + WebSocket gateway
│   └── src/
│       ├── routes/      # REST endpoints
│       ├── ws/          # Agent & UI WebSocket gateway
│       ├── services/    # Business logic
│       ├── plugins/     # Auth, audit, metrics
│       └── db/          # Pool, migrations
├── frontend/            # Next.js 15 dark UI
│   └── src/
│       ├── app/         # Pages (App Router)
│       ├── components/  # UI + layout components
│       └── lib/         # API client, auth store, WebSocket
├── agent/               # Rust agent binary
│   └── src/main.rs      # WS connection, HMAC, job execution
├── bootstrap/           # Rust watchdog (self-healing)
│   └── src/main.rs      # Binary verification, auto-restart
├── infra/               # Infrastructure configs
│   ├── nginx/           # Reverse proxy + TLS
│   ├── prometheus/      # Metrics scraping
│   ├── grafana/         # Dashboards
│   └── scripts/         # Install, upgrade, backup, restore
├── docs/                # Documentation
│   ├── AGENT_PROTOCOL_V2.md
│   ├── RUNBOOK_UBUNTU_24_04.md
│   └── openapi.yaml
├── docker-compose.yml        # Development
└── docker-compose.prod.yml   # Production
```

## Agent Protocol V2

All agent↔server communication uses HMAC-SHA256 signed WebSocket messages:

```json
{
  "agent_id": "uuid",
  "ts": 1700000000000,
  "nonce": "uuid",
  "type": "heartbeat",
  "payload": { "uptime_secs": 86400, "cpu_percent": 23.5 },
  "hmac": "sha256-hex-signature"
}
```

See [AGENT_PROTOCOL_V2.md](docs/AGENT_PROTOCOL_V2.md) for full specification.

## API Documentation

OpenAPI 3.1 spec at [docs/openapi.yaml](docs/openapi.yaml).

Key endpoints:
- `POST /api/auth/login` — Authenticate
- `GET /api/agents` — List agents (paginated, filterable)
- `POST /api/jobs` — Create job (validates RBAC + capabilities)
- `GET /api/audit-logs` — Audit trail
- `POST /api/enrollment-tokens` — Generate enrollment token
- `ws://.../ws/agent` — Agent WebSocket
- `ws://.../ws/ui` — UI real-time updates

## Testing

```bash
# Shared types & protocol tests
npm test -w @massvision/shared

# Backend E2E tests (requires running backend + DB)
npm test -w @massvision/backend
```

## Roadmap

| Phase | Features | Status |
|-------|----------|--------|
| **1** | Auth/RBAC, Agents, Enrollment, Heartbeat, RunScript, Audit, UI | ✅ Done |
| **2** | Remote Shell (WebSocket terminal), File Transfer | 🔲 Planned |
| **3** | Remote Desktop (WebRTC), Privacy Mode, Input Lock | 🔲 Planned |
| **4** | Wake-on-LAN, Agent Self-Update, Policies Engine | 🔲 Planned |
| **5** | Multi-Org, SSO/SAML, Advanced Reporting | 🔲 Planned |
| **6** | Mobile App, Plugin System, Marketplace | 🔲 Planned |

## License

Proprietary — MASSVISION. All rights reserved.

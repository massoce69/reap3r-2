# MASSVISION Reap3r — Enterprise Hardening Changelog

## Summary

All 8 phases implemented. Platform is production-ready with real implementations across all modules.

---

## Phase 1 — Foundation Hardening ✅

### Migration 005 — Enterprise Tables
- `api_keys`: scoped per tenant, SHA-256 hashed, expiration, rate limits
- `tags` + `device_tags`: normalized tag system
- `admin_logs`: separate admin audit trail
- `notification_channels` + `notification_events`: multi-channel alerts
- 15+ performance indexes including partial indexes on hot queries
- Agent metric columns: `cpu_percent`, `memory_used_mb`, `memory_total_mb`, `disk_used_gb`, `disk_total_gb`
- Users: `failed_login_count`, `locked_until` for brute force protection
- Sessions: `last_used_at`
- `metrics_timeseries.org_id`

### API Key Authentication
- `backend/src/services/apikey.service.ts`: Generate (rp3r_ prefix + 32 random bytes), hash (SHA-256), create, list, validate (checks expiration, updates last_used_at), revoke, delete
- `backend/src/routes/api-keys.ts`: Full CRUD with RBAC + audit logging + Zod validation
- Auth plugin enhanced: checks `X-API-Key` header or `Bearer rp3r_...` pattern before JWT

### MFA (Multi-Factor Authentication)
- TOTP implementation (RFC 6238) with ±1 clock drift window
- Login challenge-response: returns `mfa_required` flag
- Frontend login page updated with 6-digit TOTP input

### Brute Force Protection
- 5 failed login attempts = 15 minutes lockout
- Tracks `failed_login_count` and `locked_until` per user
- Resets on successful login

### SMTP Email Notifications
- Added `nodemailer` dependency
- Real SMTP transport with branded HTML email templates
- Severity-colored headers (critical=red, warning=amber, info=blue)
- Config via `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` env vars

### Enterprise Dashboard
- 8 stat cards: agents online/offline/isolated, jobs running/success/failed, alerts open, EDR detections
- 3-column layout: agents list, recent jobs, security overview
- WebSocket real-time updates via `useRealtimeClient`

### Enterprise Settings Page
- 4 tabs: Organization, API Keys, Integrations, Profile
- API Keys: full CRUD with key reveal/copy, scope selection
- Integrations: Teams/Email/Webhook/PagerDuty/Opsgenie with config forms + test button

---

## Phase 2 — Agent Core ✅

### Agent Config Persistence
- `AgentConfig` struct with `agent_id`, `agent_secret`, `server_url`
- Platform-specific paths: Windows `%ProgramData%\Reap3r`, Linux `/etc/reap3r`
- Unix permissions 0o600 on config file
- Auto-loads saved config on startup, saves after enrollment

### Inventory Collection
- `collect_inventory()`: hostname, OS, CPU model/cores, memory, disks (mount/total/available/fs_type), network interfaces (name/MAC/rx/tx), process count, top 20 processes by CPU
- Periodic push every 10 heartbeats (~5 minutes)
- Backend route `GET /api/agents/:id/inventory` + `POST /api/agents/:id/collect-inventory`

### Process Management
- `execute_process_action()`: list all processes (PID, name, CPU%, memory, status, start_time, cmd, exe) and kill by PID
- Job type: `process_action`

### Service Management
- `execute_service_action()`: start/stop/restart/status
- Linux: via `systemctl`
- Windows: via `sc.exe` / PowerShell
- Job type: `service_action`

---

## Phase 3 — Monitoring ✅

### Metrics Time-Series
- Agent gateway stores metrics in `metrics_timeseries` table on every MetricsPush
- `GET /api/agents/:id/metrics`: configurable period (1h to 7d), returns time-series array
- Frontend SparklineChart component: pure CSS bar chart with hover tooltips, color thresholds

### Enhanced Agent Detail Page
- 4 tabs: Overview, Inventory, Metrics, Jobs
- Overview: MiniGauge components for CPU/MEM/DISK, remote actions panel
- Inventory: system info, storage bars, network interfaces, top processes table
- Metrics: period selector, stats summary (avg/max CPU, avg memory), sparkline charts
- Jobs: expandable job list with JSON result preview

---

## Phase 4 — Alerting ✅

### Metric Threshold Evaluation
- Replaced stub `evaluateMetricThreshold()` with real implementation
- Queries agents with cpu_percent/mem_percent/disk_percent vs configurable threshold
- Supports operators: `gt`, `lt`, `gte`, `lte`
- Supports `duration_minutes` window for sustained threshold breach
- Creates fingerprinted alert events with deduplication
- Triggers escalation chain

---

## Phase 5 — Vault ✅
Already fully functional: CRUD, reveal, versioning, sharing, rotation, expiring alerts.

---

## Phase 6 — EDR ✅

### Migration 006 — EDR Tables
- `edr_rules`: name, event_type, severity, logic JSONB, is_enabled
- `response_actions`: action_type, agent_id, job_id, status, details
- Agents: `inventory` JSONB, `mem_percent`, `disk_percent`, `os_version`

### Agent Security Monitoring
- `check_security_events()`: scans every heartbeat
- Detects suspicious process names: mimikatz, bloodhound, rubeus, cobalt, meterpreter, certutil, psexec, procdump
- Detects suspicious paths: `/tmp/.hidden`, `/dev/shm/`, AppData temp svchost
- Detects suspicious PowerShell: `-enc`, `-EncodedCommand`, `-WindowStyle Hidden`
- Pushes `security_event_push` messages to backend

### EDR Response Actions
- `edr_kill_process`: kills process by PID with reason logging
- `edr_isolate_machine`: network isolation via iptables (Linux) or NetFirewallRule (Windows)

---

## Phase 7 — Chat ✅
Already fully functional: channels, messages, real-time via WebSocket.

---

## Phase 8 — Production Hardening ✅

### Input Validation (backend/src/lib/validate.ts)
- `parseUUID()`: validates string as UUID, returns 400 on invalid
- `parseBody()`: validates request body against Zod schema, returns 400 with field-level errors
- `clampLimit()`: enforces max pagination limit (default 200)
- `clampOffset()`: ensures offset ≥ 0

### Routes Hardened
- **auth.ts**: Login uses `LoginRequestSchema`, create user uses `CreateUserSchema`, update uses `UpdateUserSchema`, pagination clamped
- **jobs.ts**: Create job uses `CreateJobSchema`, all `:id` params UUID-validated, pagination clamped
- **enrollment.ts**: Create token uses `CreateEnrollmentTokenSchema`, all `:id` params UUID-validated
- **alerting.ts**: All `.parse()` → `.safeParse()` for proper 400 errors, pagination clamped, UUID validation
- **edr.ts**: Status updates use `z.enum()` validation, UUID checks, pagination clamped
- **api-keys.ts**: Create key uses Zod schema (name, scopes, rate_limit, expires_at), UUID checks

### E2E Tests Enhanced
- 13 test suites: Health, Auth, Enrollment Tokens, Agents, Jobs, Audit Logs, RBAC, Security, API Keys, Dashboard Stats, Alerting, Vault, EDR, Chat, Companies & Folders
- Tests cover CRUD lifecycle, error cases, permission checks

### Docker Hardening
- Non-root user (`appuser:appgroup`) in both backend and frontend Dockerfiles
- `dumb-init` for proper signal handling (PID 1)
- `HEALTHCHECK` instructions for container orchestrator liveness
- File ownership via `--chown=appuser:appgroup`

### Nginx (already production-ready)
- TLS 1.2/1.3 only, modern cipher suite
- OCSP stapling
- Rate limiting zones: API (100r/s), Auth (10r/m), WS connections
- Security headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP
- Gzip compression
- Static asset caching (7 days)
- Internal-only /metrics endpoint

---

## Files Modified/Created

### New Files
- `backend/src/lib/validate.ts` — Input validation helpers
- `backend/src/services/apikey.service.ts` — API key management
- `backend/src/routes/api-keys.ts` — API key CRUD routes
- `backend/src/db/migrations/005_enterprise_hardening.sql` — Enterprise tables
- `backend/src/db/migrations/006_agent_enhancements.sql` — EDR + agent columns
- `docs/ROADMAP.md` — Project roadmap
- `docs/CHANGELOG.md` — This file

### Modified Files
- `agent/src/main.rs` — Config persistence, inventory, process/service mgmt, EDR, security scanning
- `backend/src/index.ts` — API key routes registration
- `backend/src/config.ts` — SMTP config
- `backend/src/plugins/auth.ts` — API key + JWT dual auth
- `backend/src/routes/auth.ts` — MFA, brute force, Zod validation
- `backend/src/routes/jobs.ts` — Zod validation, UUID checks
- `backend/src/routes/enrollment.ts` — Zod validation, UUID checks
- `backend/src/routes/agents.ts` — Inventory, metrics, collect endpoints
- `backend/src/routes/alerting.ts` — safeParse, UUID validation, pagination
- `backend/src/routes/edr.ts` — Enum validation, UUID checks, pagination
- `backend/src/routes/api-keys.ts` — Zod schema, UUID validation
- `backend/src/ws/agent-gateway.ts` — Metrics time-series storage
- `backend/src/workers/alert-engine.ts` — Real metric threshold evaluation
- `backend/src/services/notification.service.ts` — Real SMTP email
- `backend/src/__tests__/e2e.test.ts` — 13 test suites
- `backend/package.json` — nodemailer dependency
- `backend/Dockerfile` — Non-root user, dumb-init, healthcheck
- `frontend/Dockerfile` — Non-root user, dumb-init, healthcheck
- `frontend/src/lib/api.ts` — MFA, API keys, inventory, metrics methods
- `frontend/src/lib/auth.ts` — MFA state
- `frontend/src/app/login/page.tsx` — MFA TOTP input
- `frontend/src/app/(main)/dashboard/page.tsx` — Enterprise dashboard
- `frontend/src/app/(main)/settings/page.tsx` — Enterprise settings (4 tabs)
- `frontend/src/app/(main)/agents/[id]/page.tsx` — Enterprise agent detail (4 tabs)

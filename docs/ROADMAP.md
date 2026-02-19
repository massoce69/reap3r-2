# MASSVISION Reap3r — Enterprise Roadmap

## Current State Assessment (Updated)

| Layer | Status | Coverage |
|-------|--------|----------|
| **DB Schema** | ✅ ~40+ tables, 6 migrations | 95% |
| **Auth/RBAC** | ✅ JWT + API Key + MFA (TOTP) + 5 roles + 80+ perms + brute force protection | 98% |
| **Backend API** | ✅ 70+ endpoints, Zod-validated, UUID-checked | 95% |
| **WebSocket** | ✅ Agent + UI channels, HMAC signed | 95% |
| **Agent (Rust)** | ✅ Inventory, process mgmt, service mgmt, EDR, config persistence | 90% |
| **Frontend** | ✅ 16+ pages, enterprise dashboard, all wired to API | 95% |
| **Alerting** | ✅ Rules + metric thresholds + escalation + multi-channel notifications | 95% |
| **Vault** | ✅ AES-256-GCM, versioning, sharing, rotation | 95% |
| **EDR Backend** | ✅ Ingestion, rules, detections, incidents, response actions | 90% |
| **EDR Agent** | ✅ Security event scanning, process kill, network isolation | 85% |
| **Messaging** | ✅ Channels, messages, WS broadcast | 90% |
| **Infra** | ✅ Docker (non-root, healthcheck), Nginx TLS, Prometheus, Grafana | 95% |
| **Tests** | ✅ 13 E2E test suites covering all modules | 70% |
| **Input Validation** | ✅ Zod schemas, UUID checks, pagination limits | 90% |

---

## Phase 1 — Foundation Hardening (Priority: CRITICAL)

### 1.1 DB Migration 005 — Missing Tables (S)
- `api_keys` (scoped per tenant, expiration, rate limits)
- `tags` + `device_tags` (normalized tag system)
- `notification_channels` (consolidated config)
- `admin_logs` (separate admin audit trail)
- Additional indexes for performance

### 1.2 MFA Login Flow (M)
- TOTP verification during `/api/auth/login`
- Challenge-response: login returns `mfa_required` if enabled
- Second step: verify TOTP code → issue JWT
- Rate limiting on TOTP attempts (brute force protection)

### 1.3 Session Management (M)
- Create session rows on successful login
- Refresh token rotation via `/api/auth/refresh`
- Session revocation invalidates tokens
- Track `last_used_at` for session activity

### 1.4 API Key Authentication (M)
- CRUD for API keys (name, scopes, expiration)
- Auth middleware: accept `Authorization: Bearer <api_key>` or `X-API-Key`
- Scope validation (read-only, per-module, full)
- Rate limiting per key

### 1.5 Email SMTP Notifications (S)
- Replace console.log stub with nodemailer
- Config via env vars: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`
- HTML templates for alert notifications
- Test email endpoint

### 1.6 Settings Page — Real Implementation (M)
- Organization settings (name, slug, contact)
- Alert integration management (Teams/Email/Webhook)
- API key management
- SMTP configuration
- User profile editing

### 1.7 Dashboard — Enterprise Grade (M)
- Agent stats widget (online/offline/isolated/by OS)
- Alert stats widget (open/acked/critical)
- EDR stats widget (detections/incidents)
- Job stats widget (success/failed/running)
- Top alerting agents
- Critical machines list
- Real-time WebSocket updates

---

## Phase 2 — Agent Core (Priority: HIGH)

### 2.1 Config Persistence (S)
- Save `agent_id` + `agent_secret` to disk after enrollment
- Auto-reconnect with saved credentials
- Config file: `/etc/reap3r/agent.conf` (Linux), `%ProgramData%\Reap3r\agent.conf` (Windows)

### 2.2 Full Inventory Collection (M)
- OS details, hostname, domain
- CPU model, cores, architecture
- RAM total/available
- Disk partitions (size, usage, filesystem)
- Network interfaces (name, MAC, IPs)
- Installed software (WMI on Windows, dpkg/rpm on Linux)
- Running services

### 2.3 Process Management (M)
- List processes (PID, name, user, CPU%, MEM%)
- Kill process by PID
- Service list/start/stop/restart

### 2.4 File Transfer (L)
- Chunked upload to server (artifacts)
- Download files from server to agent
- SHA-256 integrity verification
- Progress reporting via WS

### 2.5 Remote Shell (L)
- PTY allocation (Unix) / ConPTY (Windows)
- Bidirectional streaming over WS
- Session timeout
- Audit logging of all commands

---

## Phase 3 — Monitoring (Priority: HIGH)

### 3.1 Metric Ingestion Pipeline (M)
- Batch metric insertion (INSERT ... VALUES)
- Aggregation on read (1min/5min/1h/1d)
- Time-range queries optimized
- Retention policy (auto-cleanup old data)

### 3.2 Dashboard Device Detail (M)
- CPU, RAM, Disk charts (timeseries)
- Network I/O charts
- Process list (live)
- Installed software
- Event timeline

### 3.3 Monitoring Dashboard (M)
- Health overview grid (all agents)
- Heatmap by metrics
- Multi-select actions (reboot, script)
- Export to CSV

---

## Phase 4 — Alerting Enhancements (Priority: MEDIUM)

### 4.1 Silence Windows (S)
- Define maintenance windows
- Suppress alert delivery during window
- Auto-resume after window

### 4.2 Email Template Engine (S)
- HTML email templates
- Custom branding per tenant
- Alert detail embedding

---

## Phase 5 — Vault (Mostly Done)

### 5.1 Password Strength Indicator (S)
- Entropy calculation
- Weak/Medium/Strong badge
- Dashboard widget: "X weak passwords"

### 5.2 Vault Dashboard Widget (S)
- Total secrets count
- Expiring soon count
- Recently accessed
- Weak passwords alert

---

## Phase 6 — EDR Agent MVP (Priority: HIGH)

### 6.1 Process Monitoring (L)
- New process detection
- Process tree tracking
- Suspicious command-line detection
- Hash calculation for executables

### 6.2 Network Monitoring (L)
- Outbound connection logging
- DNS query logging (optional)
- Suspicious IP/domain detection

### 6.3 Persistence Detection (M)
- Registry Run keys (Windows)
- Scheduled tasks / cron jobs
- Startup items
- Systemd units

---

## Phase 7 — Messaging Enhancements (Priority: LOW)

### 7.1 File Attachments (M)
- Upload to local storage / S3
- Preview (images, PDFs)
- Download link

### 7.2 Notifications (S)
- Unread count
- Desktop notification
- @mentions

---

## Phase 8 — Production Hardening (Priority: CRITICAL)

### 8.1 Tests (L)
- Backend unit tests (services)
- API integration tests
- Frontend E2E (Playwright)
- Agent smoke tests

### 8.2 CI/CD (M)
- GitHub Actions pipeline
- Build + lint + test + security scan
- Docker image build + push
- Deployment automation

### 8.3 Performance Tuning (M)
- DB query optimization (EXPLAIN ANALYZE)
- Connection pooling tuning
- Frontend React Query caching
- Virtual scrolling for large tables
- WebSocket connection pooling

### 8.4 Documentation (M)
- API reference (OpenAPI spec update)
- Deployment runbook
- Architecture diagrams
- User guide

---

## API Endpoints (Complete List)

### Auth
| Method | Path | Permission |
|--------|------|-----------|
| POST | `/api/auth/login` | Public |
| POST | `/api/auth/login/mfa` | Public (after login challenge) |
| POST | `/api/auth/refresh` | Authenticated |
| GET | `/api/auth/me` | Authenticated |

### Users
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/users` | `user:list` |
| POST | `/api/users` | `user:create` |
| PATCH | `/api/users/:id` | `user:update` |

### Agents
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/agents` | `agent:list` |
| GET | `/api/agents/:id` | `agent:view` |
| GET | `/api/agents/stats` | `dashboard:view` |
| DELETE | `/api/agents/:id` | `agent:delete` |
| POST | `/api/agents/:id/move` | `agent:move` |

### Jobs
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/jobs` | `job:list` |
| GET | `/api/jobs/:id` | `job:view` |
| GET | `/api/jobs/stats` | `dashboard:view` |
| POST | `/api/jobs` | `job:create` (+ per-type) |
| POST | `/api/jobs/:id/cancel` | `job:cancel` |

### Enrollment
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/enrollment/tokens` | `token:list` |
| POST | `/api/enrollment/tokens` | `token:create` |
| POST | `/api/enrollment/tokens/:id/revoke` | `token:revoke` |
| DELETE | `/api/enrollment/tokens/:id` | `token:revoke` |
| GET | `/api/enrollment/tokens/:id/commands` | `token:list` |

### Companies
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/companies` | `company:list` |
| GET | `/api/companies/:id` | `company:view` |
| POST | `/api/companies` | `company:create` |
| PATCH | `/api/companies/:id` | `company:update` |
| DELETE | `/api/companies/:id` | `company:delete` |

### Folders
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/folders` | `folder:list` |
| GET | `/api/folders/:id` | `folder:view` |
| POST | `/api/folders` | `folder:create` |
| PATCH | `/api/folders/:id` | `folder:update` |
| DELETE | `/api/folders/:id` | `folder:delete` |

### Vault
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/vault` | `secret:list` |
| POST | `/api/vault` | `secret:write` |
| PATCH | `/api/vault/:id` | `secret:write` |
| DELETE | `/api/vault/:id` | `secret:delete` |
| POST | `/api/vault/:id/reveal` | `secret:reveal` |
| POST | `/api/vault/:id/use` | `secret:use` |
| GET | `/api/vault/:id/access-logs` | `secret:read` |
| GET | `/api/vault/:id/versions` | `secret:read` |
| POST | `/api/vault/:id/versions/:v/reveal` | `secret:reveal` |
| GET | `/api/vault/:id/permissions` | `secret:read` |
| POST | `/api/vault/:id/share` | `secret:write` |
| DELETE | `/api/vault/permissions/:id` | `secret:write` |
| GET | `/api/vault/expiring` | `secret:list` |
| POST | `/api/vault/:id/rotate` | `secret:write` |

### Chat
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/channels` | `message:read` |
| POST | `/api/channels` | `channel:manage` |
| GET | `/api/channels/:id` | `message:read` |
| GET | `/api/channels/:id/messages` | `message:read` |
| POST | `/api/channels/:id/messages` | `message:write` |
| GET | `/api/channels/:id/members` | `message:read` |
| POST | `/api/channels/:id/members` | `channel:manage` |
| DELETE | `/api/channels/:id/members/:uid` | `channel:manage` |

### EDR
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/edr/events` | `edr:events_view` |
| GET | `/api/edr/detections` | `edr:detections_view` |
| PATCH | `/api/edr/detections/:id/status` | `edr:respond` |
| GET | `/api/edr/incidents` | `edr:incident_manage` |
| POST | `/api/edr/incidents` | `edr:incident_manage` |
| PATCH | `/api/edr/incidents/:id/status` | `edr:incident_manage` |
| POST | `/api/edr/respond` | `edr:respond` |

### Admin
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/admin/users` | `user:list` |
| POST | `/api/admin/users` | `user:create` |
| PATCH | `/api/admin/users/:id` | `user:update` |
| PATCH | `/api/admin/users/:id/suspend` | `user:suspend` |
| POST | `/api/admin/users/:id/role` | `role:update` |
| GET | `/api/admin/users/:id/sessions` | `user:view` |
| DELETE | `/api/admin/sessions/:id` | `user:update` |
| POST | `/api/admin/users/:id/revoke-all` | `user:update` |
| POST | `/api/admin/users/:id/mfa/setup` | `user:reset_mfa` |
| POST | `/api/admin/users/:id/mfa/enable` | `user:reset_mfa` |
| POST | `/api/admin/users/:id/mfa/disable` | `user:reset_mfa` |
| GET | `/api/admin/teams` | `team:list` |
| POST | `/api/admin/teams` | `team:create` |
| PATCH | `/api/admin/teams/:id` | `team:update` |
| DELETE | `/api/admin/teams/:id` | `team:delete` |
| GET | `/api/admin/teams/:id/members` | `team:list` |
| POST | `/api/admin/teams/:id/members` | `team:update` |
| DELETE | `/api/admin/teams/:id/members/:uid` | `team:update` |
| GET | `/api/admin/policies` | `policy:view` |
| PATCH | `/api/admin/policies/:id` | `policy:update` |
| GET | `/api/admin/login-events` | `audit:view` |
| GET | `/api/admin/roles` | `role:list` |

### Alerting
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/alerting/rules` | `alert:rule_list` |
| GET | `/api/alerting/rules/:id` | `alert:rule_list` |
| POST | `/api/alerting/rules` | `alert:rule_create` |
| PATCH | `/api/alerting/rules/:id` | `alert:rule_update` |
| DELETE | `/api/alerting/rules/:id` | `alert:rule_delete` |
| GET | `/api/alerting/events` | `alert:event_list` |
| GET | `/api/alerting/events/:id` | `alert:event_list` |
| POST | `/api/alerting/events/:id/ack` | `alert:event_ack` |
| POST | `/api/alerting/events/:id/resolve` | `alert:event_resolve` |
| POST | `/api/alerting/events/:id/snooze` | `alert:event_snooze` |
| GET | `/api/alerting/stats` | `alert:event_list` |
| GET | `/api/alerting/integrations` | `alert:integration_manage` |
| POST | `/api/alerting/integrations` | `alert:integration_manage` |
| PATCH | `/api/alerting/integrations/:id` | `alert:integration_manage` |
| DELETE | `/api/alerting/integrations/:id` | `alert:integration_manage` |
| POST | `/api/alerting/integrations/:id/test` | `alert:test` |

### API Keys (NEW)
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/api-keys` | `settings:view` |
| POST | `/api/api-keys` | `settings:update` |
| DELETE | `/api/api-keys/:id` | `settings:update` |

### Health & Metrics
| Method | Path | Permission |
|--------|------|-----------|
| GET | `/api/health` | Public |
| GET | `/api/ready` | Public |
| GET | `/metrics` | Internal |

---

## WebSocket Events

### Agent → Server
| Event | Description |
|-------|-------------|
| `enroll_request` | Agent enrollment with token |
| `heartbeat` | Periodic status update |
| `capabilities` | Declare supported features |
| `metrics_push` | CPU/RAM/Disk/Network batch |
| `inventory_push` | Full hardware/software inventory |
| `security_event_push` | EDR security events |
| `job_ack` | Job received by agent |
| `job_result` | Job execution result |
| `stream_output` | Streaming job output (remote shell) |

### Server → Agent
| Event | Description |
|-------|-------------|
| `enroll_response` | Credentials after enrollment |
| `job_dispatch` | New job assignment |
| `job_cancel` | Cancel running job |
| `config_update` | Runtime config changes |

### Server → UI (Browser)
| Event | Description |
|-------|-------------|
| `agent_online` | Agent came online |
| `agent_offline` | Agent went offline |
| `agent_metrics` | Real-time metrics update |
| `job_update` | Job status change |
| `alert_event` | New alert fired |
| `edr_detection` | New EDR detection |
| `chat_message` | New chat message |

---

## DB Schema Summary (After Migration 005)

| Table | Tenant-Scoped | Description |
|-------|:---:|-------------|
| `orgs` | — | Multi-tenant organizations |
| `sites` | ✅ | Logical groupings |
| `users` | ✅ | User accounts + MFA |
| `agents` | ✅ | Managed devices |
| `agent_capabilities` | — | Agent feature flags |
| `companies` | ✅ | Client companies |
| `folders` | ✅ | Folder hierarchy |
| `agent_folder_membership` | — | Agent ↔ Folder M:N |
| `teams` | ✅ | User teams |
| `team_members` | — | Team ↔ User M:N |
| `enrollment_tokens` | ✅ | Agent enrollment |
| `jobs` | ✅ | Remote operations |
| `job_results` | — | Job output (immutable) |
| `metrics_timeseries` | — | Agent metrics |
| `inventory_snapshots` | — | HW/SW inventory |
| `audit_logs` | ✅ | Immutable audit trail |
| `admin_logs` | ✅ | Admin-specific audit |
| `artifacts` | ✅ | File artifacts |
| `policies` | ✅ | Agent policies |
| `secrets` | ✅ | Vault items |
| `secret_versions` | — | Vault history |
| `secret_access_logs` | — | Vault audit |
| `secret_permissions` | — | Vault sharing |
| `vault_folders` | ✅ | Vault folders |
| `vault_rotation_policies` | ✅ | Auto-rotation |
| `vault_totp` | ✅ | OTP secrets |
| `channels` | ✅ | Chat channels |
| `channel_members` | — | Channel membership |
| `messages` | — | Chat messages |
| `login_events` | ✅ | Login audit |
| `sessions` | — | Active sessions |
| `security_events` | ✅ | EDR telemetry |
| `edr_rules` | ✅ | Detection rules |
| `detections` | ✅ | Triggered detections |
| `incidents` | ✅ | Security incidents |
| `incident_detections` | — | Incident ↔ Detection M:N |
| `edr_policies` | ✅ | EDR configs |
| `response_actions` | ✅ | EDR response log |
| `alert_rules` | ✅ | Alert rules |
| `alert_escalations` | — | Escalation tiers |
| `alert_events` | ✅ | Alert instances |
| `alert_acks` | — | Ack audit |
| `alert_notifications` | — | Delivery log |
| `alert_integrations` | ✅ | Notification configs |
| `api_keys` | ✅ | **NEW** API keys |
| `tags` | ✅ | **NEW** Normalized tags |
| `device_tags` | — | **NEW** Device ↔ Tag M:N |

---

## Security Controls

| Control | Status | Implementation |
|---------|--------|---------------|
| HTTPS/TLS | ✅ | Nginx + Let's Encrypt |
| JWT Auth | ✅ | Fastify JWT, HS256 |
| RBAC (80+ perms) | ✅ | Middleware per route |
| Multi-tenant isolation | ✅ | `org_id` FK + query scoping |
| Input validation | ✅ | Zod schemas everywhere |
| Audit logging | ✅ | All mutations logged |
| Agent HMAC | ✅ | SHA-256 envelope signing |
| Anti-replay | ✅ | Nonce + timestamp window |
| Vault encryption | ✅ | AES-256-GCM |
| Rate limiting | ✅ | 200/min global, 10/min auth |
| Security headers | ✅ | CSP, HSTS, X-Frame-Options |
| Brute force protection | ✅ | Login event logging + lockout |
| MFA (TOTP) | ⚠️ | Login + Vault reveal are enforced with TOTP; org-wide rollout policy pending |
| Session revocation | ✅ | Access session bound to DB session, refresh rotation + revocation enforced |
| API keys | ❌ | Migration 005 |

---

## Migration Tickets

- [ ] Remove legacy `WS_PORT` / `UI_WS_PORT` after migration window and config cleanup.

---

## Release Automation

- Signed agent update manifests:
  - `tools/gen_update_keys.py` generates Ed25519 keypairs (`REAP3R_UPDATE_PRIVKEY_HEX`, `REAP3R_UPDATE_PUBKEY_HEX`).
  - `tools/sign_update.py` signs agent binaries and writes `<binary>.manifest.json` with `sig_ed25519`.
  - Backend manifest resolution supports sidecar signed manifests, or runtime signing via `REAP3R_UPDATE_PRIVKEY_HEX`, and can enforce signature via `AGENT_UPDATE_REQUIRE_SIGNATURE=true`.
  - Optional Authenticode policy can be enforced for Windows updates via `AGENT_UPDATE_REQUIRE_AUTHENTICODE=true` and `AGENT_UPDATE_SIGNER_THUMBPRINT`.
- Windows trust / AV false positive mitigation:
  - `tools/sign_windows_binary.ps1` Authenticode-signs the Windows agent binaries.
  - CI can sign binaries when `WIN_CODE_SIGN_PFX_BASE64` and `WIN_CODE_SIGN_PFX_PASSWORD` secrets are present.
- Enterprise bundle packaging:
  - `tools/build_agent_bundle.ps1` creates `dist/Reap3rAgentBundle/` with `agent-x64.exe`, `agent-x86.exe`, `installer.exe`, `install.ps1`, `uninstall.ps1`, `config.json`, `logs/`.
- CI pipeline:
  - `.github/workflows/enterprise-ci.yml` builds/lints/tests app, builds agent x64/x86 with static CRT, signs manifests, and publishes bundle artifact.

---

## Performance Plan

### Backend
- Connection pooling: `pg.Pool` with `max: 20`
- Pagination on ALL list endpoints (enforced)
- Batch metric inserts (multi-row INSERT)
- Redis for session cache + rate limiting (V1.1)
- WebSocket backpressure via drain events
- DB indexes on all FK + timestamp columns

### Frontend
- React Query for all API calls (caching + dedup)
- Virtual scrolling for agent/job tables (1000+ rows)
- Debounced search (300ms)
- Code splitting per route (Next.js dynamic)
- WebSocket updates via Zustand store (no re-render cascade)
- Skeleton loading on all data pages

### Agent
- sysinfo crate for low-overhead metrics
- 30s heartbeat (configurable)
- Batch metrics per heartbeat
- Local job queue with retry
- Circuit breaker on WS disconnect

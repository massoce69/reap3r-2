# MASSVISION Reap3r — Ubuntu 24.04 LTS Runbook

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Server Requirements](#server-requirements)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Operations](#operations)
7. [Monitoring](#monitoring)
8. [Backup & Restore](#backup--restore)
9. [Security](#security)
10. [Troubleshooting](#troubleshooting)
11. [Agent Deployment](#agent-deployment)

---

## Overview

MASSVISION Reap3r is an enterprise agent-driven remote management platform. This runbook covers deploying and operating the platform on Ubuntu 24.04 LTS.

### Components

| Component | Technology | Port (internal) | Description |
|-----------|-----------|-----------------|-------------|
| Backend | Node.js/Fastify | 4000 | REST API + WebSocket Gateway |
| Frontend | Next.js | 3000 | Web UI (dark theme) |
| Database | PostgreSQL 16 | 5432 | Persistent storage |
| Nginx | Nginx 1.25 | 80/443 | Reverse proxy + TLS |
| Prometheus | Prometheus | 9090 | Metrics collection |
| Grafana | Grafana | 3000 | Metrics visualization |

---

## Architecture

```
┌─────────────┐     HTTPS/WSS     ┌──────────┐     ┌──────────┐
│   Agents    │ ───────────────── │  Nginx   │ ──── │ Backend  │
│(Win/Lin/Mac)│                   │ (TLS)    │      │ Fastify  │
└─────────────┘                   └──────────┘      └────┬─────┘
                                       │                  │
┌─────────────┐                   ┌──────────┐      ┌────┴─────┐
│  Browser UI │ ───── HTTPS ───── │ Frontend │      │PostgreSQL│
└─────────────┘                   │ Next.js  │      └──────────┘
                                  └──────────┘
```

All components run in Docker containers.  
Only ports **80** (HTTP→HTTPS redirect) and **443** (HTTPS) are exposed externally.

---

## Server Requirements

### Minimum (up to 100 agents)
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Disk**: 40 GB SSD
- **OS**: Ubuntu 24.04 LTS
- **Network**: Static IP, ports 80/443 open

### Recommended (100–1000 agents)
- **CPU**: 4 cores
- **RAM**: 8 GB
- **Disk**: 100 GB SSD
- **OS**: Ubuntu 24.04 LTS
- **Network**: 1 Gbps

### Enterprise (1000+ agents)
- **CPU**: 8+ cores
- **RAM**: 16+ GB
- **Disk**: 500 GB NVMe SSD
- **Database**: External managed PostgreSQL (RDS, Cloud SQL)

---

## Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/massvision/reap3r.git /opt/massvision/reap3r
cd /opt/massvision/reap3r

# Run installation script
sudo bash infra/scripts/install_ubuntu_24_04.sh \
  --domain reap3r.example.com \
  --email admin@example.com
```

The script will:
1. Update system packages
2. Install Docker Engine + Compose
3. Create `massvision` service user
4. Configure UFW firewall (SSH, HTTP, HTTPS only)
5. Configure Fail2Ban
6. Generate cryptographic secrets
7. Create self-signed TLS certificate
8. Create systemd service

### Post-Install

```bash
# Build Docker images
cd /opt/massvision/reap3r
docker compose -f docker-compose.prod.yml build

# Start all services
sudo systemctl start massvision-reap3r

# Verify
curl -s https://localhost/health -k | jq .
```

### TLS Certificate (Let's Encrypt)

After DNS A record is configured:

```bash
# Stop nginx temporarily
docker compose -f docker-compose.prod.yml stop nginx

# Get certificate
certbot certonly --standalone \
  -d reap3r.example.com \
  --email admin@example.com \
  --agree-tos --no-eff-email

# Copy certificates
cp /etc/letsencrypt/live/reap3r.example.com/fullchain.pem /opt/massvision/reap3r/infra/certs/
cp /etc/letsencrypt/live/reap3r.example.com/privkey.pem /opt/massvision/reap3r/infra/certs/

# Restart
docker compose -f docker-compose.prod.yml up -d
```

Auto-renewal is configured via cron (runs daily at 03:00).

---

## Configuration

### Environment Variables

All configuration is in `/opt/massvision/reap3r/.env`:

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_NAME` | Database name | `reap3r` |
| `DB_USER` | Database user | `reap3r` |
| `DB_PASSWORD` | Database password | (auto-generated) |
| `JWT_SECRET` | JWT signing key (64 hex chars) | (auto-generated) |
| `HMAC_SECRET` | Agent protocol signing key | (auto-generated) |
| `CORS_ORIGIN` | Allowed CORS origin | `https://reap3r.example.com` |
| `API_URL` | Public API URL | `https://reap3r.example.com` |
| `WS_URL` | Public WebSocket URL | `wss://reap3r.example.com` |
| `GRAFANA_USER` | Grafana admin user | `admin` |
| `GRAFANA_PASSWORD` | Grafana admin password | (auto-generated) |

### Default Credentials

| Service | Username | Password |
|---------|----------|----------|
| Reap3r UI | `admin@massvision.local` | `Admin123!@#` |
| Grafana | `admin` | (see `.env`) |
| PostgreSQL | `reap3r` | (see `.env`) |

> **⚠️ Change default passwords immediately after first login!**

---

## Operations

### Service Management

```bash
# Start
sudo systemctl start massvision-reap3r

# Stop
sudo systemctl stop massvision-reap3r

# Restart
sudo systemctl restart massvision-reap3r

# Status
sudo systemctl status massvision-reap3r

# View logs
docker compose -f docker-compose.prod.yml logs -f backend
docker compose -f docker-compose.prod.yml logs -f frontend
docker compose -f docker-compose.prod.yml logs -f postgres
```

### Upgrading

```bash
cd /opt/massvision/reap3r
sudo bash infra/scripts/upgrade.sh
```

The upgrade script:
1. Creates a pre-upgrade backup
2. Pulls latest code
3. Rebuilds Docker images
4. Restarts services (migrations auto-apply)
5. Runs health checks

### Database Management

```bash
# Connect to PostgreSQL
docker compose -f docker-compose.prod.yml exec postgres psql -U reap3r -d reap3r

# Check database size
docker compose -f docker-compose.prod.yml exec postgres psql -U reap3r -d reap3r \
  -c "SELECT pg_size_pretty(pg_database_size('reap3r'));"

# List tables and row counts
docker compose -f docker-compose.prod.yml exec postgres psql -U reap3r -d reap3r \
  -c "SELECT schemaname, tablename, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;"
```

---

## Monitoring

### Prometheus Metrics

Available at `/metrics` (internal only). Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `http_request_duration_seconds` | Histogram | API latency by route |
| `ws_connections` | Gauge | Active WebSocket connections |
| `agents_online` | Gauge | Number of online agents |
| `jobs_total` | Counter | Jobs by status |

### Grafana Dashboards

Access at `https://reap3r.example.com/grafana/`

Pre-configured dashboard: **MASSVISION Reap3r — Overview**
- HTTP request rate and latency
- Agents online
- Job status distribution
- Error rates

### Health Checks

```bash
# Liveness
curl -s https://reap3r.example.com/health | jq .

# Readiness (includes DB check)
curl -s https://reap3r.example.com/ready | jq .
```

### Log Aggregation

Backend logs are structured JSON (pino):

```bash
# Follow backend logs with jq
docker compose -f docker-compose.prod.yml logs -f backend | jq .

# Filter errors
docker compose -f docker-compose.prod.yml logs backend | jq 'select(.level >= 50)'

# Filter by request ID
docker compose -f docker-compose.prod.yml logs backend | jq 'select(.reqId == "abc123")'
```

---

## Backup & Restore

### Manual Backup

```bash
sudo bash infra/scripts/backup.sh --label "manual"
```

### Automated Backups

Add to crontab:

```bash
# Daily backup at 02:00
echo "0 2 * * * root bash /opt/massvision/reap3r/infra/scripts/backup.sh --label daily" \
  > /etc/cron.d/massvision-backup
```

### Restore

```bash
# List available backups
ls -lh /opt/massvision/reap3r/backups/

# Restore
sudo bash infra/scripts/restore.sh /opt/massvision/reap3r/backups/daily_20240101_020000.tar.gz
```

### Backup Retention

Default: 30 days. Change with `REAP3R_BACKUP_RETENTION` environment variable.

---

## Security

### Network Security

- **UFW Firewall**: Only SSH (22), HTTP (80), HTTPS (443) exposed
- **Fail2Ban**: Protects against brute-force (SSH, Nginx auth)
- **Docker Network**: Internal services (DB, Prometheus, Grafana) not exposed
- **TLS 1.2/1.3**: Modern TLS configuration with HSTS

### Application Security

- **JWT Authentication**: Short-lived tokens for API access
- **RBAC**: 4 roles (super_admin, org_admin, technician, viewer) with 31 granular permissions
- **HMAC-SHA256**: All agent messages cryptographically signed
- **Anti-Replay**: Nonce + 5-minute time window on agent protocol
- **Rate Limiting**: API (100 req/s), Auth (10 req/min)
- **Audit Logging**: All actions logged with user, IP, timestamp
- **bcrypt**: Password hashing (cost factor 12)

### Hardening Checklist

- [ ] Change default admin password
- [ ] Replace self-signed cert with Let's Encrypt
- [ ] Restrict SSH access (key-only, no root login)
- [ ] Enable unattended security updates (configured by install script)
- [ ] Review UFW rules
- [ ] Set strong HMAC_SECRET and JWT_SECRET
- [ ] Enable PostgreSQL SSL (for external DB)
- [ ] Configure log rotation
- [ ] Set up external backup storage (S3, GCS)

---

## Troubleshooting

### Backend won't start

```bash
# Check logs
docker compose -f docker-compose.prod.yml logs backend

# Common issues:
# - DATABASE_URL incorrect → verify .env
# - Port 4000 in use → check "lsof -i :4000"
# - Migration failed → check SQL syntax in migrations/
```

### Database connection failed

```bash
# Check PostgreSQL is running
docker compose -f docker-compose.prod.yml ps postgres

# Test connection
docker compose -f docker-compose.prod.yml exec postgres pg_isready -U reap3r

# Check disk space
df -h
```

### Agents not connecting

```bash
# Verify WebSocket endpoint
wscat -c wss://reap3r.example.com/ws/agent

# Check agent logs on the endpoint
journalctl -u reap3r-agent -f

# Verify HMAC secret matches
# Agent: REAP3R_AGENT_SECRET
# Server: HMAC_SECRET
```

### High memory usage

```bash
# Check container resource usage
docker stats

# Restart specific service
docker compose -f docker-compose.prod.yml restart backend

# Adjust resource limits in docker-compose.prod.yml
```

### SSL Certificate Issues

```bash
# Check certificate expiration
openssl x509 -in /opt/massvision/reap3r/infra/certs/fullchain.pem -text -noout | grep "Not After"

# Force renewal
certbot renew --force-renewal

# Copy new certs
cp /etc/letsencrypt/live/reap3r.example.com/*.pem /opt/massvision/reap3r/infra/certs/
docker compose -f docker-compose.prod.yml restart nginx
```

---

## Agent Deployment

### Enrollment Token

1. Log in to Reap3r UI → **Deployment**
2. Create new enrollment token with expiration
3. Copy the generated deployment command

### Linux Agent (Ubuntu/Debian)

```bash
curl -fsSL https://reap3r.example.com/api/deployment/install.sh | \
  sudo bash -s -- --token <ENROLLMENT_TOKEN>
```

### Windows Agent (PowerShell)

```powershell
irm https://reap3r.example.com/api/deployment/install.ps1 | iex
# Then: Install-Reap3rAgent -Token "<ENROLLMENT_TOKEN>"
```

### Agent as systemd Service

The agent installs as a systemd service:

```bash
# Status
sudo systemctl status reap3r-agent

# Logs
sudo journalctl -u reap3r-agent -f

# Restart
sudo systemctl restart reap3r-agent

# Config
cat /etc/massvision/reap3r/config.json
```

### Agent Binary Locations

| OS | Binary | Config | Logs |
|----|--------|--------|------|
| Linux | `/opt/massvision/reap3r/reap3r-agent` | `/etc/massvision/reap3r/config.json` | `journalctl -u reap3r-agent` |
| Windows | `C:\Program Files\MASSVISION\Reap3r\reap3r-agent.exe` | `C:\ProgramData\MASSVISION\Reap3r\config.json` | Event Viewer |
| macOS | `/usr/local/massvision/reap3r/reap3r-agent` | `/etc/massvision/reap3r/config.json` | `log show --predicate 'subsystem == "com.massvision.reap3r"'` |

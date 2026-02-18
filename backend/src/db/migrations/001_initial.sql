-- ─────────────────────────────────────────────
-- MASSVISION Reap3r — Initial DB Schema
-- Migration 001
-- ─────────────────────────────────────────────

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Organizations ──
CREATE TABLE orgs (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name        VARCHAR(255) NOT NULL,
  slug        VARCHAR(128) NOT NULL UNIQUE,
  settings    JSONB NOT NULL DEFAULT '{}',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Sites (logical grouping within org) ──
CREATE TABLE sites (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name        VARCHAR(255) NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_sites_org ON sites(org_id);

-- ── Users ──
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email         VARCHAR(320) NOT NULL,
  name          VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(50)  NOT NULL DEFAULT 'viewer',
  is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
  last_login_at TIMESTAMPTZ,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  UNIQUE(org_id, email)
);
CREATE INDEX idx_users_org ON users(org_id);
CREATE INDEX idx_users_email ON users(email);

-- ── Agents ──
CREATE TABLE agents (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  site_id         UUID REFERENCES sites(id) ON DELETE SET NULL,
  hostname        VARCHAR(255) NOT NULL,
  os              VARCHAR(50)  NOT NULL,
  os_version      VARCHAR(128) NOT NULL DEFAULT '',
  arch            VARCHAR(20)  NOT NULL DEFAULT 'x86_64',
  agent_version   VARCHAR(50)  NOT NULL DEFAULT '0.0.0',
  status          VARCHAR(20)  NOT NULL DEFAULT 'pending',
  agent_secret    VARCHAR(255) NOT NULL,
  last_seen_at    TIMESTAMPTZ,
  last_ip         VARCHAR(45),
  tags            TEXT[]       NOT NULL DEFAULT '{}',
  enrolled_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_agents_org ON agents(org_id);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_site ON agents(site_id);

-- ── Agent Capabilities ──
CREATE TABLE agent_capabilities (
  id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id   UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  capability VARCHAR(100) NOT NULL,
  updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  UNIQUE(agent_id, capability)
);
CREATE INDEX idx_agent_caps_agent ON agent_capabilities(agent_id);

-- ── Policies ──
CREATE TABLE policies (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  site_id       UUID REFERENCES sites(id) ON DELETE CASCADE,
  name          VARCHAR(255) NOT NULL,
  description   TEXT,
  rules         JSONB NOT NULL DEFAULT '{}',
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  priority      INT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_policies_org ON policies(org_id);

-- ── Enrollment Tokens ──
CREATE TABLE enrollment_tokens (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  site_id     UUID REFERENCES sites(id) ON DELETE SET NULL,
  token       VARCHAR(128) NOT NULL UNIQUE,
  name        VARCHAR(255) NOT NULL,
  max_uses    INT NOT NULL DEFAULT 0,
  use_count   INT NOT NULL DEFAULT 0,
  expires_at  TIMESTAMPTZ,
  revoked     BOOLEAN NOT NULL DEFAULT FALSE,
  created_by  UUID NOT NULL REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_enroll_token ON enrollment_tokens(token);

-- ── Jobs ──
CREATE TABLE jobs (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  type          VARCHAR(50)  NOT NULL,
  status        VARCHAR(20)  NOT NULL DEFAULT 'queued',
  payload       JSONB        NOT NULL DEFAULT '{}',
  result        JSONB,
  error         TEXT,
  reason        TEXT,
  created_by    UUID NOT NULL REFERENCES users(id),
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  assigned_at   TIMESTAMPTZ,
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ,
  timeout_secs  INT NOT NULL DEFAULT 300
);
CREATE INDEX idx_jobs_agent ON jobs(agent_id);
CREATE INDEX idx_jobs_org ON jobs(org_id);
CREATE INDEX idx_jobs_status ON jobs(status);
CREATE INDEX idx_jobs_type ON jobs(type);
CREATE INDEX idx_jobs_created ON jobs(created_at DESC);

-- ── Job Results (detailed, immutable) ──
CREATE TABLE job_results (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_id      UUID NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  exit_code   INT,
  stdout      TEXT,
  stderr      TEXT,
  data        JSONB,
  duration_ms INT,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_job_results_job ON job_results(job_id);

-- ── Metrics Timeseries ──
CREATE TABLE metrics_timeseries (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  collected_at    TIMESTAMPTZ NOT NULL,
  cpu_percent     REAL,
  memory_used_mb  REAL,
  memory_total_mb REAL,
  disk_used_gb    REAL,
  disk_total_gb   REAL,
  network_rx_bytes BIGINT,
  network_tx_bytes BIGINT,
  processes_count INT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_metrics_agent_time ON metrics_timeseries(agent_id, collected_at DESC);

-- ── Inventory Snapshots ──
CREATE TABLE inventory_snapshots (
  id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id     UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  collected_at TIMESTAMPTZ NOT NULL,
  data         JSONB NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_inventory_agent ON inventory_snapshots(agent_id, collected_at DESC);

-- ── Audit Logs (immutable) ──
CREATE TABLE audit_logs (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
  agent_id      UUID REFERENCES agents(id) ON DELETE SET NULL,
  action        VARCHAR(100) NOT NULL,
  resource_type VARCHAR(100) NOT NULL,
  resource_id   VARCHAR(255),
  details       JSONB,
  ip_address    VARCHAR(45),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_org ON audit_logs(org_id, created_at DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_agent ON audit_logs(agent_id);
CREATE INDEX idx_audit_action ON audit_logs(action);

-- ── Artifacts ──
CREATE TABLE artifacts (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  agent_id    UUID REFERENCES agents(id) ON DELETE SET NULL,
  job_id      UUID REFERENCES jobs(id) ON DELETE SET NULL,
  filename    VARCHAR(512) NOT NULL,
  size_bytes  BIGINT NOT NULL,
  sha256      VARCHAR(64) NOT NULL,
  storage_path VARCHAR(1024) NOT NULL,
  uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_artifacts_org ON artifacts(org_id);

-- ── Seed default org + admin user ──
-- Password: Admin123!@# (bcrypt hash, 12 rounds)
-- To regenerate: node -e "require('bcrypt').hash('Admin123!@#',12).then(h=>console.log(h))"
INSERT INTO orgs (id, name, slug) VALUES
  ('00000000-0000-0000-0000-000000000001', 'Default Organization', 'default');

INSERT INTO users (id, org_id, email, name, password_hash, role) VALUES
  ('00000000-0000-0000-0000-000000000002',
   '00000000-0000-0000-0000-000000000001',
   'admin@massvision.local',
   'System Admin',
   '$2b$12$YqpGyxi19jKt4g1lBwS/Ye3.LGFhQQH7K4coScJqU1F5cEVhtqXxK',
   'super_admin');

INSERT INTO sites (id, org_id, name) VALUES
  ('00000000-0000-0000-0000-000000000003',
   '00000000-0000-0000-0000-000000000001',
   'Default Site');

-- ── Updated_at triggers ──
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_orgs_updated  BEFORE UPDATE ON orgs  FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_agents_updated BEFORE UPDATE ON agents FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_sites_updated BEFORE UPDATE ON sites FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_policies_updated BEFORE UPDATE ON policies FOR EACH ROW EXECUTE FUNCTION update_updated_at();

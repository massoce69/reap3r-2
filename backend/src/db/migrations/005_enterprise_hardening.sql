-- ─────────────────────────────────────────────
-- MASSVISION Reap3r — Migration 005: Enterprise Hardening
-- API Keys, Tags, Admin Logs, Notifications, Performance Indexes
-- ─────────────────────────────────────────────

-- ══════════════════════════════════════════════
-- 1) API KEYS (scoped, expirable, rate-limited)
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS api_keys (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name          VARCHAR(200) NOT NULL,
  key_hash      VARCHAR(128) NOT NULL UNIQUE,
  key_prefix    VARCHAR(12) NOT NULL,             -- first 8 chars for identification
  scopes        TEXT[] NOT NULL DEFAULT '{read}',  -- read, write, admin, agents, jobs, vault, edr, alerting
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  rate_limit    INTEGER NOT NULL DEFAULT 100,      -- requests per minute
  last_used_at  TIMESTAMPTZ,
  expires_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);

-- ══════════════════════════════════════════════
-- 2) NORMALIZED TAGS + DEVICE_TAGS
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS tags (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name        VARCHAR(100) NOT NULL,
  color       VARCHAR(7) DEFAULT '#6366f1',       -- hex color for UI
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(org_id, name)
);
CREATE INDEX IF NOT EXISTS idx_tags_org ON tags(org_id);

CREATE TABLE IF NOT EXISTS device_tags (
  agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  tag_id      UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (agent_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_device_tags_agent ON device_tags(agent_id);
CREATE INDEX IF NOT EXISTS idx_device_tags_tag ON device_tags(tag_id);

-- ══════════════════════════════════════════════
-- 3) ADMIN LOGS (separate high-security audit trail)
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS admin_logs (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id       UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  action        VARCHAR(100) NOT NULL,
  target_type   VARCHAR(100) NOT NULL,
  target_id     VARCHAR(255),
  details       JSONB DEFAULT '{}',
  ip_address    VARCHAR(45),
  user_agent    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_admin_logs_org ON admin_logs(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_logs_user ON admin_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_logs_action ON admin_logs(action);

-- ══════════════════════════════════════════════
-- 4) NOTIFICATION CHANNELS (consolidated config)
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS notification_channels (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  type          VARCHAR(30) NOT NULL CHECK (type IN ('email','teams','slack','pagerduty','opsgenie','webhook','sms')),
  name          VARCHAR(200) NOT NULL,
  config        JSONB NOT NULL DEFAULT '{}',
  is_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  is_default    BOOLEAN NOT NULL DEFAULT FALSE,
  last_test_at  TIMESTAMPTZ,
  last_test_ok  BOOLEAN,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notification_channels_org ON notification_channels(org_id);

-- ══════════════════════════════════════════════
-- 5) NOTIFICATION EVENTS (delivery log)
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS notification_events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  channel_id    UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
  event_type    VARCHAR(50) NOT NULL,             -- alert, edr, system, test
  subject       VARCHAR(500) NOT NULL,
  body          TEXT,
  status        VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed','skipped')),
  error         TEXT,
  attempts      INTEGER NOT NULL DEFAULT 0,
  sent_at       TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notification_events_org ON notification_events(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_events_status ON notification_events(status);

-- ══════════════════════════════════════════════
-- 6) AGENTS: add cpu/mem/disk columns for fast queries
-- ══════════════════════════════════════════════
ALTER TABLE agents ADD COLUMN IF NOT EXISTS cpu_percent REAL DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS memory_used_mb REAL DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS memory_total_mb REAL DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS disk_used_gb REAL DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS disk_total_gb REAL DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS processes_count INTEGER DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS network_rx_bytes BIGINT DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS network_tx_bytes BIGINT DEFAULT 0;

-- ══════════════════════════════════════════════
-- 7) PERFORMANCE INDEXES
-- ══════════════════════════════════════════════

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_agents_org_status ON agents(org_id, status);
CREATE INDEX IF NOT EXISTS idx_agents_org_company ON agents(org_id, company_id);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen_at DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_jobs_org_status_created ON jobs(org_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_agent_status ON jobs(agent_id, status);
CREATE INDEX IF NOT EXISTS idx_metrics_agent_collected ON metrics_timeseries(agent_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_org_status_sev ON detections(org_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_sec_events_org_agent_time ON security_events(org_id, agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_org_resource ON audit_logs(org_id, resource_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secrets_org_type ON secrets(org_id, type);
CREATE INDEX IF NOT EXISTS idx_messages_channel_time ON messages(channel_id, created_at DESC);

-- Partial indexes for active-only queries
CREATE INDEX IF NOT EXISTS idx_agents_online ON agents(org_id) WHERE status = 'online';
CREATE INDEX IF NOT EXISTS idx_agents_isolated ON agents(org_id) WHERE isolated = TRUE;
CREATE INDEX IF NOT EXISTS idx_jobs_pending ON jobs(agent_id) WHERE status IN ('queued', 'assigned');
CREATE INDEX IF NOT EXISTS idx_alert_events_open ON alert_events(org_id) WHERE status IN ('open', 'acknowledged');

-- ══════════════════════════════════════════════
-- 8) SESSIONS: add last_used_at for tracking
-- ══════════════════════════════════════════════
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ DEFAULT NOW();

-- ══════════════════════════════════════════════
-- 9) USERS: add fields for brute force protection
-- ══════════════════════════════════════════════
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_suspended BOOLEAN DEFAULT FALSE;

-- ══════════════════════════════════════════════
-- 10) METRICS TIMESERIES: add org_id for tenant scoping
-- ══════════════════════════════════════════════
ALTER TABLE metrics_timeseries ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES orgs(id) ON DELETE CASCADE;

-- Backfill org_id from agent
UPDATE metrics_timeseries SET org_id = (SELECT org_id FROM agents WHERE agents.id = metrics_timeseries.agent_id)
WHERE org_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_metrics_org_time ON metrics_timeseries(org_id, collected_at DESC);

-- ══════════════════════════════════════════════
-- 11) TRIGGERS for updated_at on new tables
-- ══════════════════════════════════════════════
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_api_keys_updated') THEN
    CREATE TRIGGER trg_api_keys_updated BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION update_updated_at();
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_notification_channels_updated') THEN
    CREATE TRIGGER trg_notification_channels_updated BEFORE UPDATE ON notification_channels FOR EACH ROW EXECUTE FUNCTION update_updated_at();
  END IF;
END $$;

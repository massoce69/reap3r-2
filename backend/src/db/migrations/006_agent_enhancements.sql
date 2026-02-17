-- ─────────────────────────────────────────────
-- MASSVISION Reap3r — Migration 006: Agent Enhancements
-- Inventory JSONB, mem_percent, disk_percent, metrics improvements
-- ─────────────────────────────────────────────

-- ══════════════════════════════════════════════
-- 1) AGENTS: add inventory JSONB + percent columns
-- ══════════════════════════════════════════════
ALTER TABLE agents ADD COLUMN IF NOT EXISTS inventory JSONB DEFAULT '{}';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS mem_percent REAL DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS disk_percent REAL DEFAULT 0;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS os_version VARCHAR(200);

-- ══════════════════════════════════════════════
-- 2) METRICS TIMESERIES: ensure org_id + proper indexes
-- ══════════════════════════════════════════════
-- Ensure org_id exists (may already exist from 005)
ALTER TABLE metrics_timeseries ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES orgs(id) ON DELETE CASCADE;

-- Time-partitioning-friendly index
CREATE INDEX IF NOT EXISTS idx_metrics_org_agent_time ON metrics_timeseries(org_id, agent_id, collected_at DESC);

-- ══════════════════════════════════════════════
-- 3) METRICS CLEANUP: auto-delete metrics older than 30 days
-- ══════════════════════════════════════════════
-- Note: In production, schedule this via pg_cron or a cron job
-- DELETE FROM metrics_timeseries WHERE collected_at < NOW() - INTERVAL '30 days';

-- ══════════════════════════════════════════════
-- 4) EDR RULES: ensure columns exist (table may already exist from earlier migration)
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS edr_rules (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name          VARCHAR(200) NOT NULL,
  description   TEXT,
  event_type    VARCHAR(50) NOT NULL DEFAULT 'generic',
  severity      VARCHAR(20) NOT NULL DEFAULT 'medium',
  logic         JSONB NOT NULL DEFAULT '{}',
  is_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Add missing columns to pre-existing table
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS event_type VARCHAR(50) NOT NULL DEFAULT 'generic';
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS is_enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
CREATE INDEX IF NOT EXISTS idx_edr_rules_org ON edr_rules(org_id);
CREATE INDEX IF NOT EXISTS idx_edr_rules_event ON edr_rules(event_type);

-- ══════════════════════════════════════════════
-- 5) RESPONSE ACTIONS: track EDR response actions
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS response_actions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  action_type   VARCHAR(50) NOT NULL,              -- kill_process, quarantine_file, isolate_machine, collect_bundle
  job_id        UUID REFERENCES jobs(id) ON DELETE SET NULL,
  status        VARCHAR(20) NOT NULL DEFAULT 'pending',
  initiated_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  details       JSONB DEFAULT '{}',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_response_actions_org ON response_actions(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_response_actions_agent ON response_actions(agent_id);

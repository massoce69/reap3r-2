-- ─────────────────────────────────────────────
-- MASSVISION Reap3r — Migration 003: Notifications & Alerting
-- ─────────────────────────────────────────────

-- Alert rules (user-defined rules for triggering alerts)
CREATE TABLE IF NOT EXISTS alert_rules (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id),
  name          VARCHAR(200) NOT NULL,
  description   TEXT,
  rule_type     VARCHAR(50) NOT NULL
    CHECK (rule_type IN ('agent_offline','job_failed','edr_critical','metric_threshold','tamper_detected','custom')),
  scope_type    VARCHAR(20) NOT NULL DEFAULT 'all'
    CHECK (scope_type IN ('all','company','folder','tag')),
  scope_value   TEXT,  -- company_id, folder_id, or tag value depending on scope_type
  params        JSONB NOT NULL DEFAULT '{}',
  severity      VARCHAR(20) NOT NULL DEFAULT 'high'
    CHECK (severity IN ('info','low','medium','high','critical')),
  is_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  cooldown_sec  INTEGER NOT NULL DEFAULT 300,  -- dedup window
  created_by    UUID REFERENCES users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_org ON alert_rules(org_id);
CREATE INDEX IF NOT EXISTS idx_alert_rules_type ON alert_rules(rule_type);

-- Escalation tiers (per rule)
CREATE TABLE IF NOT EXISTS alert_escalations (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id       UUID NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
  step          INTEGER NOT NULL DEFAULT 1,
  delay_sec     INTEGER NOT NULL DEFAULT 0,  -- delay after event before this step fires
  target_type   VARCHAR(20) NOT NULL CHECK (target_type IN ('user','team','role')),
  target_id     UUID,  -- user or team id
  target_role   VARCHAR(50),  -- role name if target_type=role
  channels      JSONB NOT NULL DEFAULT '["email"]',  -- ["email","teams","pagerduty","opsgenie"]
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_escalations_rule ON alert_escalations(rule_id);

-- Alert events (fired instances)
CREATE TABLE IF NOT EXISTS alert_events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id),
  rule_id       UUID REFERENCES alert_rules(id) ON DELETE SET NULL,
  rule_name     VARCHAR(200),
  entity_type   VARCHAR(30) NOT NULL,  -- 'agent','job','detection','security_event'
  entity_id     UUID,
  fingerprint   VARCHAR(255) NOT NULL,  -- dedup key
  severity      VARCHAR(20) NOT NULL DEFAULT 'high',
  status        VARCHAR(20) NOT NULL DEFAULT 'open'
    CHECK (status IN ('open','acknowledged','resolved','snoozed')),
  title         VARCHAR(500) NOT NULL,
  details       JSONB DEFAULT '{}',
  snoozed_until TIMESTAMPTZ,
  escalation_step INTEGER NOT NULL DEFAULT 0,
  last_escalated_at TIMESTAMPTZ,
  resolved_at   TIMESTAMPTZ,
  resolved_by   UUID REFERENCES users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_events_org ON alert_events(org_id);
CREATE INDEX IF NOT EXISTS idx_alert_events_status ON alert_events(status);
CREATE INDEX IF NOT EXISTS idx_alert_events_severity ON alert_events(severity);
CREATE INDEX IF NOT EXISTS idx_alert_events_fingerprint ON alert_events(fingerprint);
CREATE INDEX IF NOT EXISTS idx_alert_events_rule ON alert_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_events_created ON alert_events(created_at DESC);

-- Alert acknowledgment logs (immutable audit)
CREATE TABLE IF NOT EXISTS alert_acks (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      UUID NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
  user_id       UUID NOT NULL REFERENCES users(id),
  action        VARCHAR(20) NOT NULL CHECK (action IN ('ack','resolve','snooze','reopen')),
  note          TEXT,
  snooze_min    INTEGER,  -- for snooze actions
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_acks_event ON alert_acks(event_id);

-- Alert notification delivery log
CREATE TABLE IF NOT EXISTS alert_notifications (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id      UUID NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
  escalation_id UUID REFERENCES alert_escalations(id) ON DELETE SET NULL,
  channel       VARCHAR(30) NOT NULL CHECK (channel IN ('email','teams','pagerduty','opsgenie','webhook')),
  recipient     VARCHAR(500),
  status        VARCHAR(20) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','sent','failed','skipped')),
  attempt       INTEGER NOT NULL DEFAULT 1,
  last_error    TEXT,
  sent_at       TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_notifications_event ON alert_notifications(event_id);
CREATE INDEX IF NOT EXISTS idx_alert_notifications_status ON alert_notifications(status);

-- Integration configs (for Teams webhooks, PagerDuty keys, etc.)
CREATE TABLE IF NOT EXISTS alert_integrations (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id),
  type          VARCHAR(30) NOT NULL CHECK (type IN ('email','teams','pagerduty','opsgenie','webhook')),
  name          VARCHAR(200) NOT NULL,
  config        JSONB NOT NULL DEFAULT '{}',  -- webhook_url, api_key (encrypted in app layer)
  is_enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_integrations_org ON alert_integrations(org_id);

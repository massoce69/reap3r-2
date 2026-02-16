-- ─────────────────────────────────────────────
-- MASSVISION Reap3r — Migration 002: Full Platform Schema
-- Companies, Folders, Teams, Vault, Messaging, EDR, Admin
-- ─────────────────────────────────────────────

-- ══════════════════════════════════════════════
-- 1) COMPANIES
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS companies (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name          VARCHAR(200) NOT NULL,
  notes         TEXT,
  contact_email VARCHAR(200),
  contact_phone VARCHAR(50),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_companies_org ON companies(org_id);

-- ══════════════════════════════════════════════
-- 2) FOLDERS
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS folders (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id            UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  company_id        UUID REFERENCES companies(id) ON DELETE SET NULL,
  parent_folder_id  UUID REFERENCES folders(id) ON DELETE SET NULL,
  name              VARCHAR(200) NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_folders_org ON folders(org_id);
CREATE INDEX IF NOT EXISTS idx_folders_company ON folders(company_id);
CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_folder_id);

-- ══════════════════════════════════════════════
-- 3) AGENT ↔ FOLDER / COMPANY
-- ══════════════════════════════════════════════
ALTER TABLE agents ADD COLUMN IF NOT EXISTS company_id UUID REFERENCES companies(id) ON DELETE SET NULL;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS isolated BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS agent_folder_membership (
  agent_id   UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  folder_id  UUID NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
  added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (agent_id, folder_id)
);

CREATE INDEX IF NOT EXISTS idx_agents_company ON agents(company_id);
CREATE INDEX IF NOT EXISTS idx_agent_folder_agent ON agent_folder_membership(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_folder_folder ON agent_folder_membership(folder_id);

-- ══════════════════════════════════════════════
-- 4) TEAMS
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS teams (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name        VARCHAR(100) NOT NULL,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_teams_org ON teams(org_id);

CREATE TABLE IF NOT EXISTS team_members (
  team_id    UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role       VARCHAR(50) DEFAULT 'member',
  added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (team_id, user_id)
);

-- ══════════════════════════════════════════════
-- 5) USERS ENHANCEMENTS
-- ══════════════════════════════════════════════
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret  VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url  VARCHAR(500);

-- Login events
CREATE TABLE IF NOT EXISTS login_events (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  email       VARCHAR(200) NOT NULL,
  success     BOOLEAN NOT NULL,
  ip_address  VARCHAR(45),
  user_agent  TEXT,
  failure_reason VARCHAR(100),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_login_events_user ON login_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_events_org  ON login_events(org_id, created_at DESC);

-- Sessions (refresh tokens / revocation)
CREATE TABLE IF NOT EXISTS sessions (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  VARCHAR(128) NOT NULL UNIQUE,
  ip_address  VARCHAR(45),
  user_agent  TEXT,
  is_active   BOOLEAN DEFAULT TRUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- ══════════════════════════════════════════════
-- 6) VAULT / SECRETS
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS secrets (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  company_id      UUID REFERENCES companies(id) ON DELETE SET NULL,
  folder_id       UUID REFERENCES folders(id) ON DELETE SET NULL,
  name            VARCHAR(200) NOT NULL,
  type            VARCHAR(50) NOT NULL DEFAULT 'password',
  encrypted_blob  BYTEA NOT NULL,
  tags            TEXT[] DEFAULT '{}',
  notes           TEXT,
  metadata_json   JSONB DEFAULT '{}',
  expires_at      TIMESTAMPTZ,
  created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_secrets_org     ON secrets(org_id);
CREATE INDEX IF NOT EXISTS idx_secrets_company ON secrets(company_id);
CREATE INDEX IF NOT EXISTS idx_secrets_folder  ON secrets(folder_id);

CREATE TABLE IF NOT EXISTS secret_access_logs (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  secret_id   UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  action      VARCHAR(50) NOT NULL, -- view, copy, edit, delete, use
  ip_address  VARCHAR(45),
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_secret_access_secret ON secret_access_logs(secret_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secret_access_user   ON secret_access_logs(user_id);

CREATE TABLE IF NOT EXISTS secret_permissions (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  secret_id       UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  principal_type  VARCHAR(20) NOT NULL, -- user, role, team
  principal_id    UUID NOT NULL,
  rights          TEXT[] NOT NULL DEFAULT '{read}', -- read, write, use, delete
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_secret_perms ON secret_permissions(secret_id);

-- ══════════════════════════════════════════════
-- 7) MESSAGING
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS channels (
  id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name            VARCHAR(100) NOT NULL,
  type            VARCHAR(20) NOT NULL DEFAULT 'general', -- dm, team, company, folder, general
  company_id      UUID REFERENCES companies(id) ON DELETE SET NULL,
  description     TEXT,
  is_archived     BOOLEAN DEFAULT FALSE,
  last_message_at TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_channels_org ON channels(org_id);

CREATE TABLE IF NOT EXISTS channel_members (
  channel_id  UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        VARCHAR(20) DEFAULT 'member', -- admin, member
  joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (channel_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  channel_id  UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body        TEXT NOT NULL,
  is_pinned   BOOLEAN DEFAULT FALSE,
  edited_at   TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_user    ON messages(user_id);

-- ══════════════════════════════════════════════
-- 8) EDR (Security Events, Detections, Incidents)
-- ══════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS security_events (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  event_type    VARCHAR(60) NOT NULL,
  severity      VARCHAR(20) NOT NULL DEFAULT 'low',
  details       JSONB NOT NULL DEFAULT '{}',
  process_name  VARCHAR(500),
  process_path  TEXT,
  pid           INTEGER,
  parent_pid    INTEGER,
  cmdline       TEXT,
  username      VARCHAR(200),
  sha256        VARCHAR(64),
  dest_ip       VARCHAR(45),
  dest_port     INTEGER,
  dest_domain   VARCHAR(500),
  raw_event     JSONB,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sec_events_org   ON security_events(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_agent ON security_events(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_type  ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_sec_events_sev   ON security_events(severity);

-- Detection rules
CREATE TABLE IF NOT EXISTS edr_rules (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID REFERENCES orgs(id) ON DELETE CASCADE,
  rule_id     VARCHAR(100) NOT NULL UNIQUE,
  name        VARCHAR(200) NOT NULL,
  description TEXT,
  severity    VARCHAR(20) NOT NULL DEFAULT 'medium',
  logic       JSONB NOT NULL DEFAULT '{}',
  is_active   BOOLEAN DEFAULT TRUE,
  is_builtin  BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Detections (matched events)
CREATE TABLE IF NOT EXISTS detections (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  event_id    UUID NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
  rule_id     VARCHAR(100) NOT NULL,
  rule_name   VARCHAR(200) NOT NULL,
  severity    VARCHAR(20) NOT NULL DEFAULT 'medium',
  score       REAL NOT NULL DEFAULT 0.0,
  status      VARCHAR(30) NOT NULL DEFAULT 'open', -- open, acknowledged, resolved, false_positive
  details     JSONB DEFAULT '{}',
  resolved_by UUID REFERENCES users(id),
  resolved_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_detections_org    ON detections(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_agent  ON detections(agent_id);
CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status);

-- Incidents / Cases
CREATE TABLE IF NOT EXISTS incidents (
  id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  title          VARCHAR(200) NOT NULL,
  severity       VARCHAR(20) NOT NULL DEFAULT 'medium',
  status         VARCHAR(30) NOT NULL DEFAULT 'open', -- open, investigating, contained, resolved, closed
  assigned_to    UUID REFERENCES users(id) ON DELETE SET NULL,
  notes          TEXT,
  created_by     UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incidents_org    ON incidents(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS incident_detections (
  incident_id  UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  detection_id UUID NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
  PRIMARY KEY (incident_id, detection_id)
);

-- EDR Policies
CREATE TABLE IF NOT EXISTS edr_policies (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name        VARCHAR(200) NOT NULL,
  category    VARCHAR(50) NOT NULL,
  settings    JSONB NOT NULL DEFAULT '{}',
  is_active   BOOLEAN DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Response actions log
CREATE TABLE IF NOT EXISTS response_actions (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  action      VARCHAR(100) NOT NULL,
  job_id      UUID REFERENCES jobs(id) ON DELETE SET NULL,
  initiated_by UUID REFERENCES users(id) ON DELETE SET NULL,
  reason      TEXT,
  status      VARCHAR(30) DEFAULT 'pending',
  result      JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_response_actions_org ON response_actions(org_id, created_at DESC);

-- ══════════════════════════════════════════════
-- 9) ENROLLMENT TOKENS — add company/folder
-- ══════════════════════════════════════════════
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS company_id UUID REFERENCES companies(id) ON DELETE SET NULL;
ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS folder_id  UUID REFERENCES folders(id) ON DELETE SET NULL;

-- ══════════════════════════════════════════════
-- 10) JOBS — add reason + priority
-- ══════════════════════════════════════════════
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS reason   TEXT;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 5;

-- ══════════════════════════════════════════════
-- 11) SEED: Built-in EDR rules
-- ══════════════════════════════════════════════
INSERT INTO edr_rules (rule_id, name, description, severity, logic, is_builtin)
VALUES
  ('RULE_TEMP_EXEC', 'Process from Temp/AppData', 'Process executed from temporary directory', 'high',
   '{"match": {"process_path": ["\\\\Temp\\\\", "\\\\AppData\\\\"]}}', true),
  ('RULE_PS_ENCODED', 'PowerShell Encoded Command', 'PowerShell launched with -EncodedCommand', 'high',
   '{"match": {"cmdline": ["-EncodedCommand", "-enc ", "-e "]}}', true),
  ('RULE_SVC_CREATED', 'Unknown Service Created', 'New service installed on the system', 'medium',
   '{"match": {"event_type": "service_created"}}', true),
  ('RULE_OUTBOUND_ANOMALY', 'Anomalous Outbound Connection', 'Suspicious outbound network connection', 'medium',
   '{"match": {"event_type": "outbound_connection"}}', true),
  ('RULE_TAMPER', 'Agent Tamper Detected', 'Agent binary or service was tampered with', 'critical',
   '{"match": {"event_type": "tamper_detected"}}', true),
  ('RULE_PERSISTENCE', 'Persistence Indicator', 'Autorun or systemd unit modification detected', 'high',
   '{"match": {"event_type": "persistence_indicator"}}', true)
ON CONFLICT (rule_id) DO NOTHING;

-- ══════════════════════════════════════════════
-- 12) SEED: Default channel "General"
-- ══════════════════════════════════════════════
INSERT INTO channels (id, org_id, name, type)
SELECT '00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000001', 'General', 'general'
WHERE NOT EXISTS (SELECT 1 FROM channels WHERE id = '00000000-0000-0000-0000-000000000010');

-- Add admin to General channel
INSERT INTO channel_members (channel_id, user_id)
SELECT '00000000-0000-0000-0000-000000000010', '00000000-0000-0000-0000-000000000002'
WHERE NOT EXISTS (SELECT 1 FROM channel_members WHERE channel_id = '00000000-0000-0000-0000-000000000010' AND user_id = '00000000-0000-0000-0000-000000000002');

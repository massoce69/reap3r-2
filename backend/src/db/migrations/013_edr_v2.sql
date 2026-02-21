-- ══════════════════════════════════════════════════════════════
-- MASSVISION Reap3r — EDR v2: Market-grade detection & response
-- Migration 013 — Full EDR schema for 2000-tenant scale
-- ══════════════════════════════════════════════════════════════

-- ──────────────────────────────────────────────
-- 1) Normalized EDR events (high-volume, partitionable)
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS edr_events (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL,
  agent_id      UUID NOT NULL,
  event_type    VARCHAR(60) NOT NULL,         -- process_start, process_stop, net_conn, file_write, file_create, file_delete, file_rename, persistence_add, persistence_remove, module_load, dns_query, registry_write, sensor_health
  ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Process context (always present)
  pid           INTEGER,
  ppid          INTEGER,
  image         TEXT,                          -- full path of process image
  cmdline       TEXT,
  username      VARCHAR(200),
  integrity     VARCHAR(20),                   -- system, high, medium, low, untrusted
  signer        VARCHAR(300),                  -- Authenticode / code-signing subject
  sha256        VARCHAR(64),
  -- Parent process context
  parent_image  TEXT,
  parent_cmdline TEXT,
  -- Network context
  src_ip        VARCHAR(45),
  src_port      INTEGER,
  dst_ip        VARCHAR(45),
  dst_port      INTEGER,
  protocol      VARCHAR(10),                   -- tcp, udp, icmp
  dns_query     VARCHAR(500),
  -- File context
  file_path     TEXT,
  file_op       VARCHAR(20),                   -- create, modify, delete, rename
  file_hash     VARCHAR(64),
  file_size     BIGINT,
  -- Persistence context
  persist_type  VARCHAR(30),                   -- run_key, service, scheduled_task, systemd_unit, cron, login_item
  persist_key   TEXT,                          -- registry key / unit name / cron path
  persist_value TEXT,                          -- value written
  -- Tags
  mitre_tactics TEXT[],                        -- e.g. {'execution','persistence'}
  mitre_techniques TEXT[],                     -- e.g. {'T1059.001','T1547.001'}
  tags          TEXT[],                        -- free-form tags
  severity      VARCHAR(10) NOT NULL DEFAULT 'info',  -- info, low, medium, high, critical
  -- Raw payload (agent-sent blob)
  raw           JSONB,
  -- Sensor health
  sensor_queue_depth INTEGER,
  sensor_dropped     INTEGER,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for high-volume queries (tenant-scoped, time-ordered)
CREATE INDEX IF NOT EXISTS idx_edr_events_org_ts      ON edr_events(org_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_edr_events_agent_ts    ON edr_events(agent_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_edr_events_type        ON edr_events(event_type);
CREATE INDEX IF NOT EXISTS idx_edr_events_sha256      ON edr_events(sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_edr_events_dst_ip      ON edr_events(dst_ip) WHERE dst_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_edr_events_file_path   ON edr_events USING gin (to_tsvector('simple', COALESCE(file_path,'')));
CREATE INDEX IF NOT EXISTS idx_edr_events_cmdline     ON edr_events USING gin (to_tsvector('simple', COALESCE(cmdline,'')));
CREATE INDEX IF NOT EXISTS idx_edr_events_image       ON edr_events USING gin (to_tsvector('simple', COALESCE(image,'')));
CREATE INDEX IF NOT EXISTS idx_edr_events_mitre       ON edr_events USING gin (mitre_techniques) WHERE mitre_techniques IS NOT NULL;

-- ──────────────────────────────────────────────
-- 2) Detection rules v2 (MITRE-mapped, versioned)
-- ──────────────────────────────────────────────
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS version      INTEGER NOT NULL DEFAULT 1;
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(60);
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(20);
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS event_types  TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS tags         TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS author       VARCHAR(200);
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS false_positive_hints TEXT;
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS dedup_window_sec INTEGER NOT NULL DEFAULT 300;
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS threshold_count  INTEGER NOT NULL DEFAULT 1;
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS threshold_window_sec INTEGER NOT NULL DEFAULT 0;
ALTER TABLE edr_rules ADD COLUMN IF NOT EXISTS monitor_only BOOLEAN NOT NULL DEFAULT FALSE;

-- ──────────────────────────────────────────────
-- 3) Rule exceptions / allowlists
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS edr_rule_exceptions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  rule_id     VARCHAR(100) NOT NULL,           -- FK to edr_rules.rule_id
  scope       VARCHAR(20) NOT NULL DEFAULT 'org',  -- org, site, device
  scope_id    UUID,                            -- company_id / folder_id / agent_id depending on scope
  field       VARCHAR(50) NOT NULL,            -- which event field to exception: image, cmdline, sha256, dst_ip, etc
  pattern     TEXT NOT NULL,                   -- exact match or regex
  is_regex    BOOLEAN NOT NULL DEFAULT FALSE,
  reason      TEXT,
  created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ                      -- optional auto-expiry
);
CREATE INDEX IF NOT EXISTS idx_edr_exceptions_org  ON edr_rule_exceptions(org_id, rule_id);

-- ──────────────────────────────────────────────
-- 4) Incidents v2 (with timeline & scoring)
-- ──────────────────────────────────────────────
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS risk_score    REAL NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS agent_id      UUID REFERENCES agents(id) ON DELETE SET NULL;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS closed_at     TIMESTAMPTZ;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS auto_created  BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_tactics TEXT[];
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS mitre_techniques TEXT[];

-- Incident timeline (stores ordered entries — detections, actions, notes)
CREATE TABLE IF NOT EXISTS edr_incident_timeline (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  entry_type  VARCHAR(30) NOT NULL,            -- detection, action, note, status_change, evidence
  ref_id      UUID,                            -- detection_id / response_action_id / edr_event_id
  summary     TEXT NOT NULL,
  actor       UUID REFERENCES users(id) ON DELETE SET NULL,
  metadata    JSONB DEFAULT '{}',
  ts          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incident_timeline ON edr_incident_timeline(incident_id, ts);

-- ──────────────────────────────────────────────
-- 5) Device isolation state tracking
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS device_isolation_state (
  agent_id     UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
  org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  is_isolated  BOOLEAN NOT NULL DEFAULT FALSE,
  isolated_at  TIMESTAMPTZ,
  isolated_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  reason       TEXT,
  job_id       UUID REFERENCES jobs(id) ON DELETE SET NULL,
  released_at  TIMESTAMPTZ,
  released_by  UUID REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_isolation_org ON device_isolation_state(org_id) WHERE is_isolated = TRUE;

-- ──────────────────────────────────────────────
-- 6) Quarantined files registry
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS edr_quarantine (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  agent_id      UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  original_path TEXT NOT NULL,
  sha256        VARCHAR(64) NOT NULL,
  file_size     BIGINT,
  quarantine_path TEXT,                        -- agent-local quarantine dir
  reason        TEXT,
  quarantined_by UUID REFERENCES users(id) ON DELETE SET NULL,
  quarantined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  restored_at   TIMESTAMPTZ,
  restored_by   UUID REFERENCES users(id) ON DELETE SET NULL,
  job_id        UUID REFERENCES jobs(id) ON DELETE SET NULL,
  status        VARCHAR(20) NOT NULL DEFAULT 'quarantined'  -- quarantined, restored, deleted
);
CREATE INDEX IF NOT EXISTS idx_quarantine_org   ON edr_quarantine(org_id, quarantined_at DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_hash  ON edr_quarantine(sha256);

-- ──────────────────────────────────────────────
-- 7) Threat hunting saved queries
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS edr_hunt_queries (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name        VARCHAR(200) NOT NULL,
  description TEXT,
  query       JSONB NOT NULL,                  -- structured hunt query
  created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  is_shared   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_hunt_queries_org ON edr_hunt_queries(org_id);

-- ──────────────────────────────────────────────
-- 8) EDR metrics / observability counters
-- ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS edr_ingestion_stats (
  id          BIGSERIAL PRIMARY KEY,
  org_id      UUID NOT NULL,
  agent_id    UUID NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  window_end   TIMESTAMPTZ NOT NULL,
  events_received   INTEGER NOT NULL DEFAULT 0,
  events_dropped    INTEGER NOT NULL DEFAULT 0,
  detections_fired  INTEGER NOT NULL DEFAULT 0,
  avg_latency_ms    REAL,
  p95_latency_ms    REAL
);
CREATE INDEX IF NOT EXISTS idx_edr_stats_org ON edr_ingestion_stats(org_id, window_start DESC);

-- ──────────────────────────────────────────────
-- 9) Seed: Market-grade built-in rules (MITRE-mapped)
-- ──────────────────────────────────────────────
INSERT INTO edr_rules (rule_id, name, description, severity, logic, is_builtin, mitre_tactic, mitre_technique, event_types, tags, author)
VALUES
  -- Execution
  ('RULE_PS_DOWNLOAD_CRADLE', 'PowerShell Download Cradle', 'PowerShell downloading and executing remote content (IEX, Invoke-Expression, DownloadString, DownloadFile)', 'high',
   '{"match": {"cmdline": ["Invoke-Expression", "IEX", "DownloadString", "DownloadFile", "Invoke-WebRequest", "wget ", "curl ", "Net.WebClient", "Start-BitsTransfer"]}, "conditions": {"event_type": "process_start"}}',
   true, 'Execution', 'T1059.001', '{process_start}', '{powershell,download}', 'Reap3r Built-in'),

  ('RULE_PS_ENCODED_V2', 'Encoded PowerShell Execution', 'PowerShell launched with encoded/obfuscated command line', 'high',
   '{"match": {"cmdline": ["-EncodedCommand", "-enc ", "-e ", "-ec ", "FromBase64String", "[Convert]::", "hidden -"]}, "conditions": {"image": ["powershell.exe", "pwsh.exe"]}}',
   true, 'Defense Evasion', 'T1027', '{process_start}', '{powershell,obfuscation}', 'Reap3r Built-in'),

  -- LOLBins
  ('RULE_LOLBIN_RUNDLL32', 'Suspicious rundll32 Execution', 'rundll32.exe executing unusual DLL or JavaScript', 'high',
   '{"match": {"cmdline": ["javascript:", "vbscript:", "shell32.dll,Control_RunDLL", "url.dll,FileProtocolHandler", "advpack.dll,LaunchINFSection", "pcwutl.dll,LaunchApplication"]}, "conditions": {"image": ["rundll32.exe"]}}',
   true, 'Defense Evasion', 'T1218.011', '{process_start}', '{lolbin,rundll32}', 'Reap3r Built-in'),

  ('RULE_LOLBIN_REGSVR32', 'Suspicious regsvr32 Execution', 'regsvr32.exe used for proxy execution (squiblydoo)', 'high',
   '{"match": {"cmdline": ["/s /n /u /i:", "scrobj.dll", "/i:http", "/i:ftp"]}, "conditions": {"image": ["regsvr32.exe"]}}',
   true, 'Defense Evasion', 'T1218.010', '{process_start}', '{lolbin,regsvr32}', 'Reap3r Built-in'),

  ('RULE_LOLBIN_MSHTA', 'Suspicious mshta Execution', 'mshta.exe executing remote or inline script', 'high',
   '{"match": {"cmdline": ["http://", "https://", "javascript:", "vbscript:", "about:"]}, "conditions": {"image": ["mshta.exe"]}}',
   true, 'Defense Evasion', 'T1218.005', '{process_start}', '{lolbin,mshta}', 'Reap3r Built-in'),

  ('RULE_LOLBIN_WMIC', 'Suspicious WMIC Process Call', 'wmic.exe used to create processes or execute commands', 'medium',
   '{"match": {"cmdline": ["process call create", "os get", "/node:", "shadowcopy delete"]}, "conditions": {"image": ["wmic.exe"]}}',
   true, 'Execution', 'T1047', '{process_start}', '{lolbin,wmic}', 'Reap3r Built-in'),

  ('RULE_LOLBIN_CERTUTIL', 'Certutil Used for Download', 'certutil.exe downloading or decoding files', 'high',
   '{"match": {"cmdline": ["-urlcache", "-decode", "-encode", "-decodehex", "split"]}, "conditions": {"image": ["certutil.exe"]}}',
   true, 'Defense Evasion', 'T1140', '{process_start}', '{lolbin,certutil}', 'Reap3r Built-in'),

  ('RULE_LOLBIN_BITSADMIN', 'BITSAdmin Job Transfer', 'bitsadmin.exe creating download jobs', 'medium',
   '{"match": {"cmdline": ["/transfer", "/addfile", "/resume", "/complete"]}, "conditions": {"image": ["bitsadmin.exe"]}}',
   true, 'Defense Evasion', 'T1197', '{process_start}', '{lolbin,bitsadmin}', 'Reap3r Built-in'),

  -- Credential Access
  ('RULE_LSASS_ACCESS', 'LSASS Memory Access Indicator', 'Process accessing LSASS or tool associated with credential dumping', 'critical',
   '{"match": {"cmdline": ["lsass", "mimikatz", "sekurlsa", "logonpasswords", "hashdump", "lsadump", "procdump", "comsvcs.dll,MiniDump", "createdump"]}, "ANY_match": {"image": ["procdump.exe", "procdump64.exe", "mimikatz.exe"]}}',
   true, 'Credential Access', 'T1003.001', '{process_start}', '{credential,lsass}', 'Reap3r Built-in'),

  -- Persistence
  ('RULE_SCHEDULED_TASK', 'Scheduled Task Created', 'New scheduled task created via schtasks.exe', 'medium',
   '{"match": {"cmdline": ["/create", "/sc ", "/tn "]}, "conditions": {"image": ["schtasks.exe"]}}',
   true, 'Persistence', 'T1053.005', '{process_start}', '{persistence,scheduled_task}', 'Reap3r Built-in'),

  ('RULE_RUN_KEY_MOD', 'Run Key Registry Modification', 'Modification of Windows auto-start registry keys', 'high',
   '{"match": {"persist_key": ["CurrentVersion\\\\Run", "CurrentVersion\\\\RunOnce", "Winlogon\\\\Shell", "Winlogon\\\\Userinit"]}, "conditions": {"event_type": "persistence_add"}}',
   true, 'Persistence', 'T1547.001', '{persistence_add}', '{persistence,registry}', 'Reap3r Built-in'),

  ('RULE_NEW_SERVICE', 'Service Installed', 'New Windows service or systemd unit installed', 'medium',
   '{"match": {"event_type": ["persistence_add"]}, "conditions": {"persist_type": ["service","systemd_unit"]}}',
   true, 'Persistence', 'T1543.003', '{persistence_add}', '{persistence,service}', 'Reap3r Built-in'),

  -- Rare parent-child
  ('RULE_OFFICE_SPAWN_CMD', 'Office Application Spawning Shell', 'Microsoft Office process spawning command interpreter', 'critical',
   '{"match": {"image": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"]}, "conditions": {"parent_image": ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"]}}',
   true, 'Execution', 'T1204.002', '{process_start}', '{office,macro}', 'Reap3r Built-in'),

  -- Lateral Movement
  ('RULE_PSEXEC', 'PsExec or Similar Remote Execution', 'PsExec-style remote process execution detected', 'high',
   '{"match": {"image": ["psexec.exe", "psexesvc.exe", "paexec.exe"], "cmdline": ["psexec", "\\\\\\\\", "-s cmd", "-accepteula"]}}',
   true, 'Lateral Movement', 'T1570', '{process_start}', '{lateral,psexec}', 'Reap3r Built-in'),

  -- Defense Evasion
  ('RULE_PROCESS_TEMP_EXEC', 'Process from Temporary Directory', 'Executable launched from Temp or AppData directory', 'high',
   '{"match": {"image": ["\\\\Temp\\\\", "\\\\AppData\\\\Local\\\\Temp\\\\", "\\\\tmp\\\\", "/tmp/", "/var/tmp/", "/dev/shm/"]}}',
   true, 'Defense Evasion', 'T1036', '{process_start}', '{temp_exec}', 'Reap3r Built-in'),

  -- Discovery
  ('RULE_BLOODHOUND', 'BloodHound / SharpHound Collection', 'BloodHound Active Directory enumeration tool detected', 'critical',
   '{"match": {"image": ["sharphound.exe", "bloodhound.exe", "azurehound.exe"], "cmdline": ["sharphound", "bloodhound", "-CollectionMethod", "Invoke-BloodHound"]}}',
   true, 'Discovery', 'T1087.002', '{process_start}', '{recon,bloodhound}', 'Reap3r Built-in'),

  -- Impact
  ('RULE_SHADOW_COPY_DELETE', 'Volume Shadow Copy Deletion', 'Attempt to delete Volume Shadow Copies (ransomware indicator)', 'critical',
   '{"match": {"cmdline": ["shadowcopy delete", "vssadmin delete shadows", "wmic shadowcopy", "bcdedit /set", "recoveryenabled No"]}}',
   true, 'Impact', 'T1490', '{process_start}', '{ransomware,vss}', 'Reap3r Built-in')

ON CONFLICT (rule_id) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  severity = EXCLUDED.severity,
  logic = EXCLUDED.logic,
  mitre_tactic = EXCLUDED.mitre_tactic,
  mitre_technique = EXCLUDED.mitre_technique,
  event_types = EXCLUDED.event_types,
  tags = EXCLUDED.tags,
  author = EXCLUDED.author;

-- ──────────────────────────────────────────────
-- 10) Additional indexes for detection engine perf
-- ──────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_detections_rule    ON detections(rule_id);
CREATE INDEX IF NOT EXISTS idx_detections_event   ON detections(event_id);
CREATE INDEX IF NOT EXISTS idx_detections_created ON detections(created_at DESC);

-- Partial index for dedup check
CREATE INDEX IF NOT EXISTS idx_detections_dedup   ON detections(org_id, agent_id, rule_id, created_at DESC)
  WHERE status NOT IN ('resolved', 'false_positive');

-- ─────────────────────────────────────────────
-- 009 — Zabbix DAT Deployment System
-- Tables for batch-based deploy via Zabbix API
-- ─────────────────────────────────────────────

-- Enum: batch mode
DO $$ BEGIN
  CREATE TYPE deploy_batch_mode AS ENUM ('dry_run', 'live');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Enum: batch status
DO $$ BEGIN
  CREATE TYPE deploy_batch_status AS ENUM (
    'created', 'validating', 'ready', 'running', 'done', 'failed', 'cancelled'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Enum: item status
DO $$ BEGIN
  CREATE TYPE deploy_item_status AS ENUM (
    'pending', 'valid', 'invalid', 'ready', 'running',
    'success', 'failed', 'skipped', 'cancelled'
  );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── deploy_batches ──
CREATE TABLE IF NOT EXISTS deploy_batches (
  batch_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  filename       TEXT NOT NULL,
  server_url     TEXT NOT NULL,
  mode           deploy_batch_mode NOT NULL DEFAULT 'dry_run',
  status         deploy_batch_status NOT NULL DEFAULT 'created',
  created_by     UUID NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at     TIMESTAMPTZ,
  finished_at    TIMESTAMPTZ,
  -- Stats counters (denormalized for fast reads)
  total_items    INT NOT NULL DEFAULT 0,
  valid_count    INT NOT NULL DEFAULT 0,
  invalid_count  INT NOT NULL DEFAULT 0,
  success_count  INT NOT NULL DEFAULT 0,
  failed_count   INT NOT NULL DEFAULT 0,
  skipped_count  INT NOT NULL DEFAULT 0,
  -- Zabbix connection info
  zabbix_url     TEXT,
  zabbix_user    TEXT,
  zabbix_script  TEXT,
  -- Error / notes
  error          TEXT,
  notes          TEXT
);

-- ── deploy_items ──
CREATE TABLE IF NOT EXISTS deploy_items (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  batch_id          UUID NOT NULL REFERENCES deploy_batches(batch_id) ON DELETE CASCADE,
  row_number        INT NOT NULL,
  zabbix_host       TEXT NOT NULL,
  dat               TEXT NOT NULL,
  status            deploy_item_status NOT NULL DEFAULT 'pending',
  -- Validation
  validation_error  TEXT,
  -- Zabbix resolved
  zabbix_hostid     TEXT,
  zabbix_scriptid   TEXT,
  zabbix_exec_id    TEXT,
  -- Execution
  attempt_count     INT NOT NULL DEFAULT 0,
  max_attempts      INT NOT NULL DEFAULT 3,
  last_attempt_at   TIMESTAMPTZ,
  next_retry_at     TIMESTAMPTZ,
  last_error        TEXT,
  error_category    TEXT,  -- 'retryable' | 'non_retryable'
  -- Lock (anti-double-run)
  lock_owner        TEXT,
  lock_until        TIMESTAMPTZ,
  -- Callback
  callback_received BOOLEAN NOT NULL DEFAULT FALSE,
  callback_at       TIMESTAMPTZ,
  callback_exit     INT,
  callback_status   TEXT,    -- 'INSTALLED', 'ALREADY_INSTALLED', 'DOWNLOAD_FAILED', etc.
  callback_message  TEXT,
  -- Proof
  proof             JSONB,
  -- Timestamps
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  started_at        TIMESTAMPTZ,
  finished_at       TIMESTAMPTZ,

  -- Anti-duplicate: one host per batch per tenant
  CONSTRAINT uq_deploy_item_host UNIQUE (tenant_id, batch_id, zabbix_host)
);

-- ── Indexes ──
CREATE INDEX IF NOT EXISTS idx_deploy_batches_tenant_status ON deploy_batches(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_deploy_items_batch_status ON deploy_items(batch_id, status);
CREATE INDEX IF NOT EXISTS idx_deploy_items_tenant_status ON deploy_items(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_deploy_items_lock_until ON deploy_items(lock_until) WHERE lock_until IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_deploy_items_next_retry ON deploy_items(next_retry_at) WHERE next_retry_at IS NOT NULL;

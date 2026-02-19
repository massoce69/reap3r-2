-- ------------------------------------------------------------
-- 010 - Deploy batch secrets (Zabbix password per batch)
-- ------------------------------------------------------------

CREATE TABLE IF NOT EXISTS deploy_batch_secrets (
  batch_id        UUID PRIMARY KEY REFERENCES deploy_batches(batch_id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL,
  zabbix_password TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_deploy_batch_secrets_tenant ON deploy_batch_secrets(tenant_id);

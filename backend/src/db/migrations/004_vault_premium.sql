-- ─────────────────────────────────────────────
-- MASSVISION Reap3r — Migration 004: Vault Premium
-- ─────────────────────────────────────────────

-- Secret versions (history)
CREATE TABLE IF NOT EXISTS secret_versions (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  secret_id     UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  encrypted_blob BYTEA NOT NULL,
  change_note   TEXT,
  changed_by    UUID REFERENCES users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_secret_versions_secret ON secret_versions(secret_id, created_at DESC);

-- Vault folders (optional hierarchy)
CREATE TABLE IF NOT EXISTS vault_folders (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id),
  parent_id     UUID REFERENCES vault_folders(id) ON DELETE CASCADE,
  name          VARCHAR(200) NOT NULL,
  description   TEXT,
  created_by    UUID REFERENCES users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vault_folders_org ON vault_folders(org_id);
CREATE INDEX IF NOT EXISTS idx_vault_folders_parent ON vault_folders(parent_id);

-- Vault rotation policies
CREATE TABLE IF NOT EXISTS vault_rotation_policies (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id),
  secret_type   VARCHAR(50) NOT NULL,  -- 'password', 'api_key', etc.
  rotation_days INTEGER NOT NULL DEFAULT 90,
  is_active     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vault_rotation_policies_org ON vault_rotation_policies(org_id);

-- Vault TOTP (for OTP secrets)
CREATE TABLE IF NOT EXISTS vault_totp (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        UUID NOT NULL REFERENCES orgs(id),
  secret_id     UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  issuer        VARCHAR(200),
  account_name  VARCHAR(200),
  algorithm     VARCHAR(20) NOT NULL DEFAULT 'SHA1',
  digits        INTEGER NOT NULL DEFAULT 6,
  period        INTEGER NOT NULL DEFAULT 30,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vault_totp_secret ON vault_totp(secret_id);

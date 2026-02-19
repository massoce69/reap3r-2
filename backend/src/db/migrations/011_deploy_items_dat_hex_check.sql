-- ------------------------------------------------------------
-- 011 - Enforce DAT format for deploy items (64 hex)
-- ------------------------------------------------------------

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'ck_deploy_items_dat_hex64'
  ) THEN
    ALTER TABLE deploy_items
      ADD CONSTRAINT ck_deploy_items_dat_hex64
      CHECK (dat ~ '^[A-Fa-f0-9]{64}$') NOT VALID;
  END IF;
END $$;

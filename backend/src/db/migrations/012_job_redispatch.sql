-- ------------------------------------------------------------
-- MASSVISION Reap3r — Job re-dispatch improvements
-- ------------------------------------------------------------

-- Track how many times a job has been dispatched (for max-retry cap).
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS dispatch_count INT NOT NULL DEFAULT 0;

-- Partial index for the re-dispatch query on stale update_agent jobs.
CREATE INDEX IF NOT EXISTS idx_jobs_dispatched_update
  ON jobs(agent_id, type)
  WHERE status = 'dispatched';

-- Update the legacy partial index to cover 'pending' (the actual runtime value)
-- alongside the older 'queued' rows that may still exist.
DROP INDEX IF EXISTS idx_jobs_pending;
CREATE INDEX IF NOT EXISTS idx_jobs_pending
  ON jobs(agent_id)
  WHERE status IN ('pending', 'queued');

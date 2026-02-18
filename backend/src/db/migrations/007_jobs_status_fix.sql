-- ------------------------------------------------------------
-- MASSVISION Reap3r — Jobs status normalization (P0)
-- ------------------------------------------------------------

-- Older schemas defaulted to 'queued' while the backend expects 'pending'.
ALTER TABLE jobs ALTER COLUMN status SET DEFAULT 'pending';

UPDATE jobs SET status = 'pending' WHERE status = 'queued';


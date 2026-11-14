-- Persist congestion requeue telemetry directly on remember_jobs so operators
-- and status checks can inspect how many times a job was parked for upload
-- congestion and when its next attempt is scheduled without decoding the
-- Apalis payload or scraping logs.
--
-- Both columns use metadata-only fast defaults in PostgreSQL 11+ and do not
-- rewrite existing rows.
ALTER TABLE remember_jobs
    ADD COLUMN IF NOT EXISTS congestion_requeues INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ;

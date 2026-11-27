-- Scope column for security-delete tracking and batches
ALTER TABLE delete_blobs_tracking
    ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE deletion_batches
    ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'legacy';
CREATE INDEX IF NOT EXISTS idx_tracking_owner_scope_state_created
    ON delete_blobs_tracking (owner, scope, state, created_at, blob_id);
CREATE INDEX IF NOT EXISTS idx_batches_owner_scope
    ON deletion_batches (owner, scope, state);

-- Migration 002 has already seeded pre-migration vector_entries rows with the
-- 'legacy' default. Any subsequent INSERT into vector_entries (including in
-- shared LEGACY_DB_URL == DATABASE_URL deployments) is a post-migration write
-- and must be captured under scope = 'current' so legacy delete-all cannot
-- claim post-migration memories.
CREATE OR REPLACE FUNCTION track_deletable() RETURNS trigger AS $$
DECLARE
    canonical_owner TEXT;
BEGIN
    canonical_owner := canonical_sui_address(NEW.owner);
    PERFORM pg_advisory_xact_lock_shared(
        21316,
        hashtext(TG_TABLE_SCHEMA || ':' || canonical_owner)
    );
    INSERT INTO delete_blobs_tracking (owner, blob_id, created_at, state, scope)
    VALUES (canonical_owner, NEW.blob_id, NEW.created_at, 'deletable', 'current')
    ON CONFLICT (owner, blob_id) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

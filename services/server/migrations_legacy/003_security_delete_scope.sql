-- Scope column for security-delete tracking and batches
ALTER TABLE delete_blobs_tracking
    ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE deletion_batches
    ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'legacy';
CREATE INDEX IF NOT EXISTS idx_tracking_owner_scope_state_created
    ON delete_blobs_tracking (owner, scope, state, created_at, blob_id);
CREATE INDEX IF NOT EXISTS idx_batches_owner_scope
    ON deletion_batches (owner, scope, state);

-- services/server/migrations/029_memory_updated_xid_not_null.sql
-- Enforce NOT NULL on vector_entries.updated_xid after online batched backfill completes (#1018).

ALTER TABLE vector_entries
ALTER COLUMN updated_xid SET NOT NULL;

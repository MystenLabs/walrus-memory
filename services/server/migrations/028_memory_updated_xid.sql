-- services/server/migrations/028_memory_updated_xid.sql
--
-- Production Rollout Plan: Migration 028 and updated_xid trigger
--
-- Purpose:
-- Track the transaction ID (xid8) of the last API visible content or expiry write
-- on vector_entries so background housekeeping tasks (such as mark_expiry_scheduled
-- and metadata backfills) never mask a late committing write from MVCC cursor gap detection.
--
-- Phased Rollout Plan:
--
-- Phase 1: Nullable column addition, column default, and trigger installation
-- 1. ALTER TABLE vector_entries ADD COLUMN IF NOT EXISTS updated_xid xid8:
--    In PostgreSQL 11+, adding a nullable column without a default takes an ACCESS EXCLUSIVE
--    lock on vector_entries for metadata update only. It does not rewrite table tuples or
--    block concurrent operations beyond milliseconds. In production, execute under a strict
--    lock_timeout (such as 5s) to guarantee fast abort if long queries are active.
-- 2. ALTER TABLE vector_entries ALTER COLUMN updated_xid SET DEFAULT pg_current_xact_id():
--    Setting a volatile default applies to new inserts immediately without updating
--    existing rows, taking a brief metadata lock.
-- 3. Trigger installation (CREATE FUNCTION trg_vector_entries_content_xid and CREATE TRIGGER
--    trg_vector_entries_update_xid):
--    Takes a brief ACCESS EXCLUSIVE lock to register the BEFORE UPDATE trigger. All subsequent
--    content updates (where updated_at changes) stamp NEW.updated_xid with the current xid8.
--
-- Phase 2: Online batched backfill
-- 1. Existing rows with NULL updated_xid are backfilled using:
--    UPDATE vector_entries SET updated_xid = xmin::text::xid8 WHERE updated_xid IS NULL;
-- 2. On large production tables, execute in bounded chunks (for example 5000 rows per batch)
--    to avoid long row locks, replication lag, and transaction log pressure.
-- 3. On development and CI databases, the backfill completes in a single statement.
--
-- Phase 3: SET NOT NULL validation
-- 1. ALTER TABLE vector_entries ALTER COLUMN updated_xid SET NOT NULL:
--    Once Phase 2 backfills all rows, NOT NULL is enforced. In PostgreSQL 12+, verifying
--    that no NULLs remain completes quickly.
--
-- Zero Downtime and Mixed Replica Compatibility:
-- 1. Rolling deployment safety:
--    Application queries in memory_read.rs check COALESCE(updated_xid, xmin::text::xid8).
--    Replicas running older or newer code tolerate pre backfill rows safely because any row
--    lacking updated_xid falls back to tuple xmin for MVCC gap detection.
-- 2. Housekeeping stability:
--    Housekeeping jobs (such as mark_expiry_scheduled or sync timestamps) update rows without
--    bumping updated_at. The trigger executes the ELSE branch, setting NEW.updated_xid to
--    OLD.updated_xid. This prevents housekeeping updates from advancing updated_xid and avoids
--    spurious must_resync signals to polling clients.

ALTER TABLE vector_entries ADD COLUMN IF NOT EXISTS updated_xid xid8;

ALTER TABLE vector_entries
ALTER COLUMN updated_xid SET DEFAULT pg_current_xact_id();

CREATE OR REPLACE FUNCTION trg_vector_entries_content_xid()
RETURNS trigger AS $$
BEGIN
    IF NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
        NEW.updated_xid := pg_current_xact_id();
    ELSE
        NEW.updated_xid := OLD.updated_xid;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_vector_entries_update_xid ON vector_entries;

CREATE TRIGGER trg_vector_entries_update_xid
BEFORE UPDATE ON vector_entries
FOR EACH ROW
EXECUTE FUNCTION trg_vector_entries_content_xid();

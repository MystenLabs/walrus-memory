-- services/server/migrations/028_memory_updated_xid.sql
--
-- Track the transaction ID (xid8) of the last API-visible content or expiry write
-- on vector_entries so background housekeeping tasks (such as mark_expiry_scheduled
-- and metadata backfills) never mask a late-committing write from MVCC cursor gap detection.

ALTER TABLE vector_entries ADD COLUMN IF NOT EXISTS updated_xid xid8;

UPDATE vector_entries
SET updated_xid = xmin::text::xid8
WHERE updated_xid IS NULL;

ALTER TABLE vector_entries
ALTER COLUMN updated_xid SET DEFAULT pg_current_xact_id();

ALTER TABLE vector_entries
ALTER COLUMN updated_xid SET NOT NULL;

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

-- Retain original memory indexing timestamps across /api/forget cycles (#1060).
-- Populated atomically inside delete_by_namespace using MAX(created_at) for
-- duplicate blob rows, and preserved across memory_tombstones sweeping so
-- subsequent /api/restore calls restore the exact original vector_entries.created_at
-- instead of substituting job enqueue time or NOW().
CREATE TABLE IF NOT EXISTS forgotten_blob_timestamps (
    owner TEXT NOT NULL,
    namespace TEXT NOT NULL,
    blob_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (owner, namespace, blob_id)
);

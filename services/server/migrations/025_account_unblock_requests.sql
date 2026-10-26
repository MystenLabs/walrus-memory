-- One open unblock request per quarantined owner.
--
-- The owner signs a personal message; this row is what operators read
-- before they call admin_clear_quarantine. Re-runs on every boot, so the
-- statement has to be idempotent. A second request from the same owner
-- refreshes requested_at instead of inserting another row.
CREATE TABLE IF NOT EXISTS account_unblock_requests (
    owner TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

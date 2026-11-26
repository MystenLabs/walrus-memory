CREATE TABLE IF NOT EXISTS account_owner_deactivations (
    package_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    account_version BIGINT NOT NULL,
    checkpoint_timestamp_ms BIGINT NOT NULL,
    PRIMARY KEY (package_id, account_id)
);
CREATE INDEX IF NOT EXISTS account_owner_deactivations_owner_idx
    ON account_owner_deactivations (package_id, owner);

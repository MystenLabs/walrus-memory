-- One consent record per Memory owner. Addresses are encrypted by the relayer.
-- Withdrawn records retain the lookup hash and consent history.
CREATE TABLE IF NOT EXISTS marketing_consent (
    owner               TEXT PRIMARY KEY CHECK (owner ~ '^0x[0-9a-f]{64}$'),
    status              TEXT NOT NULL DEFAULT 'none'
                        CHECK (status IN ('none','pending_verification','opted_in','withdrawn')),
    address_ciphertext  TEXT,
    address_hash        TEXT CHECK (address_hash ~ '^[0-9a-f]{64}$'),
    verified_at         TIMESTAMPTZ,
    consented_at        TIMESTAMPTZ,
    policy_version      TEXT CHECK (length(policy_version) <= 64),
    source_surface      TEXT CHECK (source_surface IN ('prompt','settings')),
    withdrawn_at        TIMESTAMPTZ,
    withdrawal_reason   TEXT CHECK (withdrawal_reason IN ('user','unsubscribe','bounce','complaint')),
    prompt_dismissed_at TIMESTAMPTZ,
    sendgrid_synced_at  TIMESTAMPTZ,
    sendgrid_contact_id TEXT,
    account_id          TEXT CHECK (account_id ~ '^0x[0-9a-f]{64}$'),
    account_version     BIGINT CHECK (account_version >= 0),
    CONSTRAINT mc_account_snapshot_shape CHECK ((account_id IS NULL) = (account_version IS NULL)),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT mc_none_has_no_address CHECK (
        status <> 'none' OR (address_ciphertext IS NULL AND address_hash IS NULL)),
    CONSTRAINT mc_pending_shape CHECK (
        status <> 'pending_verification'
        OR (address_ciphertext IS NOT NULL AND address_hash IS NOT NULL AND verified_at IS NULL
            AND consented_at IS NOT NULL AND policy_version IS NOT NULL)),
    CONSTRAINT mc_opted_in_is_verified CHECK (
        status <> 'opted_in'
        OR (address_ciphertext IS NOT NULL AND address_hash IS NOT NULL AND verified_at IS NOT NULL
            AND consented_at IS NOT NULL AND policy_version IS NOT NULL)),
    CONSTRAINT mc_withdrawn_drops_ciphertext CHECK (
        status <> 'withdrawn'
        OR (address_ciphertext IS NULL AND withdrawn_at IS NOT NULL AND withdrawal_reason IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS marketing_consent_address_hash_idx
    ON marketing_consent (address_hash) WHERE address_hash IS NOT NULL;

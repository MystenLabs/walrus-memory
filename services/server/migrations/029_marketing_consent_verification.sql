-- One single-use verification code per consent owner. Erasure removes it.
CREATE TABLE IF NOT EXISTS marketing_consent_verification (
    owner        TEXT PRIMARY KEY REFERENCES marketing_consent(owner) ON DELETE CASCADE,
    address_hash TEXT NOT NULL CHECK (address_hash ~ '^[0-9a-f]{64}$'),
    code_hash    TEXT NOT NULL CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    expires_at   TIMESTAMPTZ NOT NULL,
    attempts     SMALLINT NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    consumed_at  TIMESTAMPTZ,
    sent_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

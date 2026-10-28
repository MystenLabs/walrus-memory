-- Runtime operator policy only. No deployment-specific identities or seeded overrides.
CREATE TABLE IF NOT EXISTS owner_rate_limits (
    owner TEXT PRIMARY KEY CHECK (owner ~ '^0x[0-9a-f]{64}$'),
    requests_per_minute BIGINT NOT NULL CHECK (requests_per_minute BETWEEN 1 AND 1000000),
    requests_per_hour BIGINT NOT NULL CHECK (requests_per_hour BETWEEN 1 AND 100000000),
    delegate_key_per_minute BIGINT NOT NULL CHECK (delegate_key_per_minute BETWEEN 1 AND 1000000),
    expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Retain changes, including resets, without recording credentials or free-form labels.
CREATE TABLE IF NOT EXISTS owner_rate_limit_audit (
    id BIGSERIAL PRIMARY KEY,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    operation TEXT NOT NULL,
    previous_value JSONB,
    new_value JSONB
);
CREATE OR REPLACE FUNCTION audit_owner_rate_limits() RETURNS trigger AS $$
BEGIN
    INSERT INTO owner_rate_limit_audit(operation, previous_value, new_value)
    VALUES (TG_OP, CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
                   CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS owner_rate_limits_audit ON owner_rate_limits;
CREATE TRIGGER owner_rate_limits_audit AFTER INSERT OR UPDATE OR DELETE ON owner_rate_limits
FOR EACH ROW EXECUTE FUNCTION audit_owner_rate_limits();

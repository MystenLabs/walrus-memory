-- Cross-process rate limit refunds for in-memory fallback when workers run in separate processes (#655).
CREATE TABLE IF NOT EXISTS rate_limit_fallback_refunds (
    rate_key TEXT NOT NULL,
    request_id TEXT NOT NULL,
    member_offset BIGINT NOT NULL,
    weight BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (rate_key, request_id, member_offset)
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_fallback_refunds_created_at
    ON rate_limit_fallback_refunds(created_at);

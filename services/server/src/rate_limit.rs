use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    storage::db::{StorageAdmission, StorageReservationRequest},
    types::{AppError, AppState, AuthInfo, McpRateLimitConfig},
};

// ============================================================
// Sponsor Rate Limit Result
// ============================================================

/// Result of a per-sender (or per-IP) sponsor rate limit check.
#[derive(Debug, PartialEq)]
pub enum SponsorRlResult {
    /// Request is within limits — proceed.
    Allowed,
    /// Per-minute bucket exhausted.
    MinuteLimitExceeded,
    /// Per-hour bucket exhausted.
    HourLimitExceeded,
}

// ============================================================
// Rate Limit Configuration
// ============================================================

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    // --- Per-account burst window ---
    /// Maximum weighted requests per minute per user (default: 60)
    pub max_requests_per_minute: i64,

    // --- Per-account sustained window ---
    /// Maximum weighted requests per hour per user (default: 500)
    pub max_requests_per_hour: i64,

    // --- Per-delegate-key window ---
    /// Maximum weighted requests per minute per delegate key (default: 30)
    pub max_requests_per_delegate_key: i64,

    // --- Storage quota ---
    /// Maximum storage per user in bytes (default: 1 GB)
    pub max_storage_bytes: i64,

    /// Redis URL (default: redis://localhost:6379)
    pub redis_url: String,

    /// Bypass all request-rate buckets (per-key, per-account burst/sustained,
    /// sponsor IP+sender) when set. Storage quota and auth still apply.
    /// Off unless `RATE_LIMIT_DISABLED=1` (or `true`) is set; intended only
    /// for localhost benchmarks. Logs a loud warning at startup when on.
    pub bench_bypass_enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests_per_minute: 60,
            max_requests_per_hour: 500,
            max_requests_per_delegate_key: 30,
            max_storage_bytes: 1_073_741_824, // 1 GB
            redis_url: "redis://127.0.0.1:6379".to_string(),
            bench_bypass_enabled: false,
        }
    }
}

impl RateLimitConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("RATE_LIMIT_REQUESTS_PER_MINUTE") {
            if let Ok(n) = val.parse::<i64>() {
                config.max_requests_per_minute = n;
            }
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_REQUESTS_PER_HOUR") {
            if let Ok(n) = val.parse::<i64>() {
                config.max_requests_per_hour = n;
            }
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_DELEGATE_KEY_PER_MINUTE") {
            if let Ok(n) = val.parse::<i64>() {
                config.max_requests_per_delegate_key = n;
            }
        }

        if let Ok(val) = std::env::var("RATE_LIMIT_STORAGE_BYTES") {
            if let Ok(n) = val.parse::<i64>() {
                config.max_storage_bytes = n;
            }
        }

        if let Ok(val) = std::env::var("REDIS_URL") {
            config.redis_url = val;
        }

        // Accepted: "1" or "true" (case-insensitive). Anything else,
        // including unset, leaves the limiter active.
        if let Ok(val) = std::env::var("RATE_LIMIT_DISABLED") {
            config.bench_bypass_enabled = val == "1" || val.eq_ignore_ascii_case("true");
        }

        config
    }
}

/// Sliding-window lower bounds shared by the live limiter and post-hoc
/// `charge_explicit_weight`. Passing `now` as `window_start` would prune
/// every in-window Redis member before inserting the extra charge.
fn sliding_window_starts(now: f64) -> (f64, f64, f64) {
    (now - 60_000.0, now - 60_000.0, now - 3_600_000.0)
}

// ============================================================
// Cost Weights — per endpoint
// ============================================================

/// Get the cost weight for a given API path.
///
/// Expensive endpoints (embedding + encrypt + Walrus upload + LLM)
/// consume more of the rate limit budget than cheap read endpoints.
///
/// Endpoint weight normalization:
///   1. Percent-decode the path to neutralise URL-encoded variants
///      (e.g. `/api/anal%79ze` → `/api/analyze`).
///   2. Strip any trailing slash so `/api/analyze/` == `/api/analyze`.
///      Both transforms are applied before the match, so no variant can
///      slip through with a cost of 1 instead of its true weight.
fn endpoint_weight(path: &str) -> i64 {
    // Step 1 — percent-decode (e.g. "%2F" → "/", "%79" → "y")
    // Use lossy decoding: malformed sequences are replaced with U+FFFD
    // and will not match any known route, falling through to weight 1.
    let decoded = percent_decode_str(path).decode_utf8_lossy();

    // Step 2 — strip trailing slash
    let path = decoded.trim_end_matches('/');

    match path {
        "/api/analyze" => 5,         // LLM extract + N × (1 pt per fact)
        "/api/remember" => 5,        // embed + SEAL encrypt + Walrus upload
        "/api/remember/bulk" => 10,  // N × embed/encrypt/upload in one request
        "/api/remember/manual" => 3, // Walrus upload only (client did embed/encrypt)
        "/api/restore" => 3,         // download + decrypt + re-embed
        "/api/ask" => 2,             // recall + LLM
        "/api/embed" => 2,           // embedding API only
        // Owner-scoped read API — {owner} is a variable path segment, so
        // match by prefix/suffix like the observability route_label()
        // normalization does for the same three routes.
        _ if path.starts_with("/v1/owners/") && path.ends_with("/agents") => 2, // live sui_getObject RPC call, weighted like /api/ask's recall+LLM call
        _ if path.starts_with("/v1/owners/") && path.ends_with("/namespaces") => 1, // DB read only
        _ if path.starts_with("/v1/owners/") && path.ends_with("/memories") => 1, // DB read only
        _ => 1, // recall, recall/manual, etc.
    }
}

// ============================================================
// Redis Client
// ============================================================

/// Reconnect so a dropped Redis connection does not fail-close
/// unauthenticated limiters for the process lifetime.
pub async fn create_redis_client(redis_url: &str) -> Result<redis::aio::ConnectionManager, String> {
    let client = redis::Client::open(redis_url)
        .map_err(|e| format!("Failed to create Redis client: {}", e))?;

    // Bound reconnect so a dead Redis still 503s promptly instead of
    // stalling fail-closed routes.
    let config = redis::aio::ConnectionManagerConfig::new()
        .set_connection_timeout(Duration::from_secs(2))
        .set_response_timeout(Duration::from_secs(2))
        .set_max_delay(2_000)
        .set_number_of_retries(3);
    redis::aio::ConnectionManager::new_with_config(client, config)
        .await
        .map_err(|e| format!("Failed to connect to Redis: {}", e))
}

// ============================================================
// Sliding Window Helpers — Atomic Lua Script
// ============================================================

/// Lua script that atomically:
///   1. Removes stale entries older than `window_start`.
///   2. Counts current entries in the window.
///   3. If count < limit: adds `weight` new timestamped entries and refreshes TTL.
///   4. Returns 1 (allowed) or 0 (denied).
///
/// This replaces the previous two-step check_window + record_in_window
/// pattern which had a TOCTOU race where concurrent requests could both pass the
/// check then both record, collectively exceeding the limit.
/// A Lua script runs atomically on the Redis server — no other command can execute
/// between steps, eliminating the race window entirely.
const SLIDING_WINDOW_LUA: &str = r#"
local key          = KEYS[1]
local window_start = tonumber(ARGV[1])
local now          = tonumber(ARGV[2])
local limit        = tonumber(ARGV[3])
local weight       = tonumber(ARGV[4])
local ttl          = tonumber(ARGV[5])
local request_id   = ARGV[6]

-- 1. Prune entries outside the window
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- 2. Count remaining entries
local count = redis.call('ZCARD', key)

-- 3. Check and conditionally record
if count + weight > limit then
    return 0  -- denied
end

for i = 0, weight - 1 do
    -- ZSET members, unlike scores, must be unique. A timestamp-only member
    -- collapses concurrent requests that arrive in the same millisecond.
    local member = request_id .. ':' .. tostring(i)
    redis.call('ZADD', key, now, member)
end
redis.call('EXPIRE', key, ttl)

return 1  -- allowed
"#;

/// Result of an atomic sliding-window check-and-record.
#[derive(Debug, PartialEq)]
enum WindowCheckResult {
    /// Request is within limit — entries have been recorded.
    Allowed,
    /// Limit exceeded — no entries were recorded.
    Denied,
}

/// Atomically check the sliding window and record entries if within limit.
///
/// Replaces the separate check_window + record_in_window calls.
/// The Lua script executes as a single atomic Redis operation, preventing the
/// TOCTOU race where two concurrent requests could both pass the check before
/// either records, then both record and collectively exceed the limit.
async fn check_and_record_window<C>(
    redis: &mut C,
    key: &str,
    window_start: f64,
    now: f64,
    limit: i64,
    weight: i64,
    ttl_seconds: i64,
) -> Result<WindowCheckResult, redis::RedisError>
where
    C: redis::aio::ConnectionLike,
{
    // The UUID keeps members distinct across concurrent requests, processes,
    // and replicas even when they share an identical millisecond timestamp.
    let request_id = Uuid::new_v4().to_string();
    let result: i64 = redis::Script::new(SLIDING_WINDOW_LUA)
        .key(key)
        .arg(window_start)
        .arg(now)
        .arg(limit)
        .arg(weight)
        .arg(ttl_seconds)
        .arg(request_id)
        .invoke_async(redis)
        .await?;

    if result == 1 {
        Ok(WindowCheckResult::Allowed)
    } else {
        Ok(WindowCheckResult::Denied)
    }
}

// ============================================================
// In-Memory Token Bucket Fallback
// ============================================================

#[derive(Default)]
pub struct InMemoryFallback {
    pub buckets: std::collections::HashMap<String, TokenBucket>,
    pub cleanup_counter: usize,
}

impl InMemoryFallback {
    pub fn can_consume(
        &mut self,
        key: &str,
        weight: f64,
        capacity: f64,
        refill_duration_secs: f64,
    ) -> bool {
        let refill_rate = capacity / refill_duration_secs;
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(capacity));
        bucket.peek(weight, capacity, refill_rate)
    }

    pub fn consume(&mut self, key: &str, weight: f64, capacity: f64, refill_duration_secs: f64) {
        let refill_rate = capacity / refill_duration_secs;
        if let Some(bucket) = self.buckets.get_mut(key) {
            bucket.consume(weight, capacity, refill_rate);
        }

        self.cleanup_counter += 1;
        if self.cleanup_counter >= 1000 {
            self.cleanup_counter = 0;
            let now = std::time::Instant::now();
            self.buckets
                .retain(|_, b| now.duration_since(b.last_update).as_secs_f64() < 7200.0);
        }
    }
}

pub struct TokenBucket {
    pub tokens: f64,
    pub last_update: std::time::Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: std::time::Instant::now(),
        }
    }

    pub fn peek(&self, weight: f64, capacity: f64, refill_rate_per_sec: f64) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let projected = (self.tokens + elapsed * refill_rate_per_sec).min(capacity);
        projected >= weight
    }

    pub fn consume(&mut self, weight: f64, capacity: f64, refill_rate_per_sec: f64) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let projected = (self.tokens + elapsed * refill_rate_per_sec).min(capacity);
        self.tokens = projected - weight;
        self.last_update = now;
    }
}

// ============================================================
// Rate Limit Response
// ============================================================

/// Build a 429 response with JSON body and Retry-After header.
fn rate_limit_response(layer: &str, limit: i64, window: &str, retry_after: u64) -> Response {
    crate::observability::record_rate_limit_denial(layer);
    let body = serde_json::json!({
        "error": "Rate limit exceeded",
        "layer": layer,
        "limit": format!("{} weighted-requests/{}", limit, window),
        "retry_after_seconds": retry_after,
    });

    axum::response::Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Content-Type", "application/json")
        .header("Retry-After", retry_after.to_string())
        .body(axum::body::Body::from(
            serde_json::to_string(&body).unwrap(),
        ))
        .unwrap()
}

/// Build a 503 response when Redis is completely unreachable and the
/// in-memory fallback also cannot be used (e.g., lock poisoned).
/// previously Redis errors silently allowed requests through.
fn rate_limiter_unavailable_response() -> Response {
    crate::observability::record_app_error("rate_limiter_unavailable");
    let body = serde_json::json!({
        "error": "Rate limiter temporarily unavailable",
        "retry_after_seconds": 30,
    });

    axum::response::Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Content-Type", "application/json")
        .header("Retry-After", "30")
        .body(axum::body::Body::from(
            serde_json::to_string(&body).unwrap(),
        ))
        .unwrap()
}

// ============================================================
// Rate Limit Middleware
// ============================================================

/// Multi-layer rate limiting middleware for the write-path authenticated
/// routes (`/api/*`, mounted on `protected_routes` in `main.rs`).
///
/// The owner-scoped read API (`/v1/owners/{owner}/{namespaces,memories,agents}`)
/// does NOT run through this middleware — it has its own
/// dedicated single-layer budget (`read_api_rate_limit_middleware`, below)
/// so routine read pagination can never spend the write path's budget or
/// vice versa.
///
/// Checks 3 layers (all must pass):
/// 1. Per-delegate-key: 30 weighted-req/min (prevents compromised key abuse)
/// 2. Per-account burst: 60 weighted-req/min (prevents spam)
/// 3. Per-account sustained: 500 weighted-req/hour (prevents slow-burn)
///
/// Endpoints are cost-weighted:
///   analyze=10, remember=5, remember/manual=3, restore=3, ask=2, recall=1
///
/// Returns 429 Too Many Requests with JSON body if any layer exceeds its limit.
///
/// Returns 503 Service Unavailable (fail-closed) if Redis
/// is unreachable — previously was fail-open (silently allowed all requests).
///
/// Normalizes trailing slash in path before cost weight lookup.
pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // RATE_LIMIT_DISABLED=1 — see RateLimitConfig::bench_bypass_enabled.
    if state.config.rate_limit.bench_bypass_enabled {
        return next.run(request).await;
    }

    // Extract auth info (set by auth middleware)
    let auth_info = request
        .extensions()
        .get::<crate::types::AuthInfo>()
        .cloned();

    let auth = match auth_info {
        Some(a) => a,
        None => {
            // No auth info = not an authenticated route, skip rate limiting
            return next.run(request).await;
        }
    };

    let config = &state.config.rate_limit;
    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;

    // Determine cost weight based on endpoint; path is normalized inside endpoint_weight.
    let weight = endpoint_weight(request.uri().path());

    // --- Key definitions for all three rate-limit buckets ---
    let dk_key = format!("rate:dk:{}", auth.public_key);
    let burst_key = format!("rate:{}", auth.owner);
    let hourly_key = format!("rate:hr:{}", auth.owner);

    let (dk_window_start, burst_window_start, hourly_window_start) = sliding_window_starts(now);

    // --- Atomic check-and-record via Lua script for all 3 layers ---
    // Each layer is checked+recorded atomically. If Redis is unavailable,
    // we fall through to the in-memory token-bucket fallback.

    let mut redis_down = false;

    // Layer 1: Per-delegate-key (burst) — atomic check + record
    match check_and_record_window(
        &mut redis,
        &dk_key,
        dk_window_start,
        now,
        config.max_requests_per_delegate_key,
        weight,
        120, // TTL 2 min
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "rate limit [delegate-key]: key={}... denied (limit={})",
                &auth.public_key[..16.min(auth.public_key.len())],
                config.max_requests_per_delegate_key
            );
            return rate_limit_response(
                "delegate_key",
                config.max_requests_per_delegate_key,
                "min",
                60,
            );
        }
        Err(e) => {
            tracing::warn!("rate limit [delegate-key] Redis error: {}", e);
            redis_down = true;
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    // Layer 2: Per-account burst — atomic check + record
    if !redis_down {
        match check_and_record_window(
            &mut redis,
            &burst_key,
            burst_window_start,
            now + 0.1, // slight timestamp offset to avoid member collision
            config.max_requests_per_minute,
            weight,
            120, // TTL 2 min
        )
        .await
        {
            Ok(WindowCheckResult::Denied) => {
                tracing::warn!(
                    "rate limit [burst]: owner={} denied (limit={})",
                    auth.owner,
                    config.max_requests_per_minute
                );
                // Roll back the delegate-key window entry just recorded above
                // (best-effort; a Lua multi-key script would be fully atomic across keys)
                return rate_limit_response(
                    "account_burst",
                    config.max_requests_per_minute,
                    "min",
                    60,
                );
            }
            Err(e) => {
                tracing::warn!("rate limit [burst] Redis error: {}", e);
                redis_down = true;
            }
            Ok(WindowCheckResult::Allowed) => {}
        }
    }

    // Layer 3: Per-account sustained — atomic check + record
    if !redis_down {
        match check_and_record_window(
            &mut redis,
            &hourly_key,
            hourly_window_start,
            now + 0.2, // slight timestamp offset to avoid member collision
            config.max_requests_per_hour,
            weight,
            3700, // TTL ~1hr + buffer
        )
        .await
        {
            Ok(WindowCheckResult::Denied) => {
                tracing::warn!(
                    "rate limit [sustained]: owner={} denied (limit={})",
                    auth.owner,
                    config.max_requests_per_hour
                );
                return rate_limit_response(
                    "account_sustained",
                    config.max_requests_per_hour,
                    "hour",
                    300,
                );
            }
            Err(e) => {
                tracing::warn!("rate limit [sustained] Redis error: {}", e);
                redis_down = true;
            }
            Ok(WindowCheckResult::Allowed) => {}
        }
    }

    // --- Fallback path: Redis unreachable — use in-memory token buckets ---
    if redis_down {
        tracing::warn!("rate limit: Redis is unreachable, using in-memory fallback");
        crate::observability::record_rate_limit_fallback("authenticated");
        let mut fallback = state.fallback_rate_limit.lock().await;

        if !fallback.can_consume(
            &dk_key,
            weight as f64,
            config.max_requests_per_delegate_key as f64,
            60.0,
        ) {
            return rate_limit_response(
                "delegate_key",
                config.max_requests_per_delegate_key,
                "min",
                60,
            );
        }
        if !fallback.can_consume(
            &burst_key,
            weight as f64,
            config.max_requests_per_minute as f64,
            60.0,
        ) {
            return rate_limit_response("account_burst", config.max_requests_per_minute, "min", 60);
        }
        if !fallback.can_consume(
            &hourly_key,
            weight as f64,
            config.max_requests_per_hour as f64,
            3600.0,
        ) {
            return rate_limit_response(
                "account_sustained",
                config.max_requests_per_hour,
                "hour",
                300,
            );
        }

        fallback.consume(
            &dk_key,
            weight as f64,
            config.max_requests_per_delegate_key as f64,
            60.0,
        );
        fallback.consume(
            &burst_key,
            weight as f64,
            config.max_requests_per_minute as f64,
            60.0,
        );
        fallback.consume(
            &hourly_key,
            weight as f64,
            config.max_requests_per_hour as f64,
            3600.0,
        );

        return next.run(request).await;
    }

    next.run(request).await
}

// ============================================================
// Read API Rate Limit Middleware
// ============================================================

/// Rate limiting middleware for the owner-scoped read API
/// (`GET /v1/owners/{owner}/{namespaces,memories,agents}`).
///
/// These routes used to sit in the same `protected_routes` router as every
/// write endpoint, behind `rate_limit_middleware`, so they
/// spent the same 30/min per-delegate-key budget that exists to bound the
/// write path's spend-risk (Walrus upload, LLM calls, gas). A single
/// dedicated budget is enough here — reads don't carry that risk, so there's
/// no need for the write path's extra account-level burst/sustained layers.
///
/// Checks ONE dedicated sliding-window layer, keyed by delegate key under
/// its own Redis prefix (`rate:read:dk:{public_key}`) so it cannot share or
/// contend with the write path's `rate:dk:{public_key}` bucket. Endpoint
/// weight is looked up via the same `endpoint_weight()` table the write path
/// uses (namespaces=1, memories=1, agents=2).
///
/// Returns 429 with the same JSON shape as `rate_limit_middleware`
/// (`layer: "read_delegate_key"`) on exceed, and fails closed to 503 if
/// Redis is unreachable — no in-memory fallback, matching every other
/// rate limiter in this file except the deliberately-fallback-enabled
/// authenticated write path.
pub async fn read_api_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // RATE_LIMIT_DISABLED=1 — see RateLimitConfig::bench_bypass_enabled.
    if state.config.rate_limit.bench_bypass_enabled {
        return next.run(request).await;
    }

    let auth_info = request
        .extensions()
        .get::<crate::types::AuthInfo>()
        .cloned();

    let auth = match auth_info {
        Some(a) => a,
        None => {
            // No auth info = auth middleware didn't run ahead of this one;
            // nothing to key the bucket on, so skip rather than 500.
            return next.run(request).await;
        }
    };

    let config = &state.config.read_api_rate_limit;
    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;

    let weight = endpoint_weight(request.uri().path());
    let dk_key = format!("rate:read:dk:{}", auth.public_key);
    let window_start = now - 60_000.0; // 1-min window (ms)

    match check_and_record_window(
        &mut redis,
        &dk_key,
        window_start,
        now,
        config.per_delegate_key_per_minute,
        weight,
        120, // TTL 2 min
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "rate limit [read-delegate-key]: key={}... denied (limit={})",
                &auth.public_key[..16.min(auth.public_key.len())],
                config.per_delegate_key_per_minute
            );
            rate_limit_response(
                "read_delegate_key",
                config.per_delegate_key_per_minute,
                "min",
                60,
            )
        }
        Err(e) => {
            tracing::warn!("rate limit [read-delegate-key] Redis error: {}", e);
            rate_limiter_unavailable_response()
        }
        Ok(WindowCheckResult::Allowed) => next.run(request).await,
    }
}

// ============================================================
// Storage Quota Check (called from routes, not middleware)
// ============================================================

/// Check if a user has enough storage quota for a new blob.
///
/// Storage tracking still uses PostgreSQL (it's per-row in vector_entries).
/// Returns `Ok(())` if within quota, `Err(AppError::QuotaExceeded)` if not.
///
/// How long an unreleased storage reservation keeps counting against quota.
///
/// This is the backstop for a release that never happens: process killed
/// between admission and insert, task cancelled, job lost. It must be longer
/// than any window in which the write could still legitimately land, or a slow
/// upload would have its reservation expire while the row is still coming and
/// a concurrent burst could slip past the quota.
///
/// The longest such window is bounded by `main::STALE_REMEMBER_JOB_AFTER`
/// (10 minutes), after which the sweeper marks the job failed and releases the
/// reservation anyway. 15 minutes leaves margin over that without letting a
/// leak sit around long. Over-counting for at most this long is the intended
/// failure mode; an account is never permanently stranded.
pub const STORAGE_RESERVATION_TTL: Duration = Duration::from_secs(15 * 60);

/// Atomically admit pending writes against the owner's storage quota.
///
/// Replaces the old `check_storage_quota`, which was not atomic: it read usage
/// under a `pg_advisory_xact_lock`, committed (releasing the lock, because xact
/// locks are transaction scoped), compared outside any lock, and left the
/// caller to insert later still. Concurrent requests from one owner all read
/// the same pre-insert total, all passed, and all inserted (GH #532 /
/// WALM-359).
///
/// Admission now records the intent to write inside the locked transaction, so
/// a later request in the same burst sees the earlier one's bytes even though
/// no row exists yet. Callers must release once the row lands or the write is
/// known to be dead — see `release_storage_quota`.
///
/// Admission is all-or-nothing across `reservations`, preserving the existing
/// behaviour where a bulk request lands whole or is rejected whole, and the
/// `402` / "Storage quota exceeded" response shape is unchanged.
pub async fn reserve_storage_quota(
    state: &AppState,
    owner: &str,
    reservations: &[StorageReservationRequest],
) -> Result<(), AppError> {
    let max_bytes = state.config.rate_limit.max_storage_bytes;

    // 0 or negative means unlimited
    if max_bytes <= 0 {
        return Ok(());
    }

    if reservations.is_empty() {
        return Ok(());
    }

    // Stable hash of the owner string as the per-owner advisory lock key.
    let lock_key = stable_hash_i64(owner);
    let requested: i64 = reservations.iter().map(|r| r.bytes).sum();

    let admission = state
        .db
        .admit_storage_reservations(
            owner,
            lock_key,
            max_bytes,
            reservations,
            STORAGE_RESERVATION_TTL,
        )
        .await?;

    match admission {
        StorageAdmission::Admitted => Ok(()),
        StorageAdmission::Rejected { used } => {
            let used_mb = used as f64 / 1_048_576.0;
            let max_mb = max_bytes as f64 / 1_048_576.0;
            tracing::warn!(
                "storage quota exceeded: owner={} used={:.1}MB + {:.1}MB > max={:.1}MB",
                owner,
                used_mb,
                requested as f64 / 1_048_576.0,
                max_mb
            );
            Err(AppError::QuotaExceeded(format!(
                "Storage quota exceeded: {:.1}MB used of {:.1}MB allowed",
                used_mb, max_mb
            )))
        }
    }
}

/// Convenience wrapper for the single-write call sites.
pub async fn reserve_storage_quota_one(
    state: &AppState,
    owner: &str,
    id: String,
    bytes: i64,
) -> Result<(), AppError> {
    reserve_storage_quota(state, owner, &[StorageReservationRequest { id, bytes }]).await
}

/// Release reservations after the bytes are committed as rows, or after the
/// write that reserved them is known to be dead.
///
/// Deliberately infallible: a failed release is recovered by
/// `STORAGE_RESERVATION_TTL`, and must never turn a successful write into a
/// failed request.
pub async fn release_storage_quota(state: &AppState, ids: &[String]) {
    if state.config.rate_limit.max_storage_bytes <= 0 {
        return;
    }
    state.db.release_storage_reservations(ids).await;
}

/// Release a single reservation. See `release_storage_quota`.
pub async fn release_storage_quota_one(state: &AppState, id: &str) {
    let ids = [id.to_string()];
    release_storage_quota(state, &ids).await;
}

/// Compute a stable i64 hash of a string for use as PG advisory lock key.
/// Uses FNV-1a (no external dependency needed).
fn stable_hash_i64(s: &str) -> i64 {
    const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
    const FNV_PRIME: u64 = 1_099_511_628_211;

    let hash = s
        .bytes()
        .fold(FNV_OFFSET, |acc, b| acc.wrapping_mul(FNV_PRIME) ^ b as u64);

    // Fold into i64 range (XOR high and low 32 bits)
    ((hash >> 32) ^ (hash & 0xFFFF_FFFF)) as i64
}

// ============================================================
// Restore — owner-scoped call-frequency guard (GH #501 / WALM-299)
// ============================================================

/// Bound how often a single owner can call `/api/restore`.
///
/// `/api/restore` already rides the generic weighted account limiter
/// (`rate_limit_middleware`, weight 3), but that budget is shared across
/// every endpoint and flat regardless of per-call blob volume — it does not
/// specifically bound "attacker keeps transferring a fresh junk blob_id,
/// costing one new first-time-discovery download+decrypt per call". This is
/// a dedicated, owner-keyed guard on top, reusing the same atomic
/// sliding-window primitive the account limiter already uses.
///
/// Deliberately keyed only by `owner` + call frequency — this guard itself
/// does not inspect, record, or reason about who created/uploaded/relayed
/// any blob (see GH #501: Henry explicitly rejected an uploader/relayer
/// allowlist as *this* guard's fix direction). A separate mechanism,
/// `findBlobCreationSender` in the sidecar's `walrus-query.ts`, checks
/// immutable creation provenance upstream of this — see that function's
/// doc-comment for why it exists independently of the decision made here.
///
/// Fails OPEN (logs a warning and allows the call) on a Redis error,
/// consistent with `rate_limit_middleware`'s graceful-degrade philosophy for
/// authenticated routes — `restore()` runs after auth, so an unreachable
/// Redis should not lock a legitimate user out of their own memories.
/// (Contrast with `sponsor_rate_limit_middleware`, which fails closed
/// because it guards the unauthenticated, deployment-wide sponsor budget.)
///
/// Shared "single-window, per-key" wrapper around `check_and_record_window`:
/// classifies the result, records the denial metric, logs, and fails open on
/// a Redis error. Factored out so a caller like
/// `check_restore_call_rate_limit` doesn't hand-copy the
/// check/log/fail-open boilerplate that already exists inline in
/// `rate_limit_middleware`'s per-account layer and in the global
/// sponsor/account limiters below.
async fn check_owner_window_limit<C>(
    redis: &mut C,
    scope: &str,
    key: &str,
    window_start: f64,
    now: f64,
    limit: i64,
    weight: i64,
    ttl_seconds: i64,
    owner: &str,
    deny_message: impl FnOnce() -> String,
) -> Result<(), AppError>
where
    C: redis::aio::ConnectionLike,
{
    match check_and_record_window(redis, key, window_start, now, limit, weight, ttl_seconds).await {
        Ok(WindowCheckResult::Denied) => {
            crate::observability::record_rate_limit_denial(scope);
            tracing::warn!(
                "rate limit [{}]: owner={} denied (limit={}/min)",
                scope,
                owner,
                limit
            );
            Err(AppError::RateLimited(deny_message()))
        }
        Ok(WindowCheckResult::Allowed) => Ok(()),
        Err(e) => {
            tracing::warn!("rate limit [{}] Redis error, failing open: {}", scope, e);
            Ok(())
        }
    }
}

/// `restore_requests_per_owner_per_minute == 0` disables the guard.
pub(crate) async fn check_restore_call_rate_limit(
    state: &crate::types::AppState,
    owner: &str,
) -> Result<(), AppError> {
    let limit = state.config.restore_requests_per_owner_per_minute;
    if limit == 0 {
        return Ok(());
    }

    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;
    let key = format!("rate:restore-call:{owner}");
    let window_start = now - 60_000.0; // 1-min window (ms)

    check_owner_window_limit(
        &mut redis,
        "restore_call",
        &key,
        window_start,
        now,
        limit as i64,
        1,   // weight = 1 per restore() call
        120, // TTL 2 min
        owner,
        || {
            format!(
                "restore called too frequently; limit is {} calls/min",
                limit
            )
        },
    )
    .await
}

// ============================================================
// Sponsor — deployment-wide budget limit
// ============================================================

/// Check whether the deployment has exceeded its sponsor budget limits.
///
/// Uses a sliding-window counter in Redis just like the authenticated route
/// middleware, but keyed by fixed server-controlled identifiers. Unlike a
/// caller-supplied sender address, these keys cannot be rotated by an attacker.
///
/// Returns `SponsorRlResult::Allowed` when the request can proceed, or the
/// appropriate `MinuteLimitExceeded` / `HourLimitExceeded` variant otherwise.
///
/// Returns `Err(())` on Redis failure so callers can fail closed. A per-process
/// fallback would not enforce a deployment-wide cap across replicas.
pub async fn check_global_sponsor_rate_limit(
    state: &crate::types::AppState,
    per_minute: i64,
    per_hour: i64,
) -> Result<SponsorRlResult, ()> {
    let now = chrono::Utc::now().timestamp_millis() as f64;
    let mut redis = state.redis.clone();

    let min_key = "rate:sponsor:global:min";
    let hr_key = "rate:sponsor:global:hr";
    let min_window_start = now - 60_000.0;
    let hr_window_start = now - 3_600_000.0;

    // --- Atomic check-and-record for minute bucket ---
    match check_and_record_window(
        &mut redis,
        &min_key,
        min_window_start,
        now,
        per_minute,
        1, // weight = 1 per sponsor request
        120,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            crate::observability::record_rate_limit_denial("sponsor_global_burst");
            return Ok(SponsorRlResult::MinuteLimitExceeded);
        }
        Err(e) => {
            tracing::error!(
                "check_global_sponsor_rate_limit: Redis error (minute): {}",
                e
            );
            return Err(());
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    // --- Atomic check-and-record for hour bucket ---
    match check_and_record_window(
        &mut redis,
        &hr_key,
        hr_window_start,
        now + 0.1,
        per_hour,
        1, // weight = 1 per sponsor request
        3700,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            crate::observability::record_rate_limit_denial("sponsor_global_sustained");
            return Ok(SponsorRlResult::HourLimitExceeded);
        }
        Err(e) => {
            tracing::error!("check_global_sponsor_rate_limit: Redis error (hour): {}", e);
            return Err(());
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    Ok(SponsorRlResult::Allowed)
}

// ============================================================
// Analyze — explicit weight helpers (called from routes)
// ============================================================

/// Cost of the /api/analyze endpoint already reserved by the middleware
/// for the first (LLM extraction) step. The weight value must match
/// `endpoint_weight("/api/analyze")` = 5.
#[allow(dead_code)]
const ANALYZE_BASE_WEIGHT: i64 = 5;

/// Additional weight to charge after fact-count is known.
///
/// Each stored fact costs 1 point. The formula is:
///
///   additional = fact_count
///
/// This ensures the total cost of an analyze call is proportional to the
/// number of facts produced, and caps at 5 + 20 = 25 points.
pub fn analyze_additional_weight(fact_count: usize) -> i64 {
    fact_count as i64
}

/// Total effective weight of an `/api/analyze` call given `fact_count`.
#[allow(dead_code)]
pub fn analyze_total_weight(fact_count: usize) -> i64 {
    ANALYZE_BASE_WEIGHT + analyze_additional_weight(fact_count)
}

/// Charge an explicit extra weight against all rate-limit buckets for an
/// authenticated user. Called by `/api/analyze` after fact-count is known.
///
/// If `weight` is zero, this is a no-op. Returns `Ok(())` on success or
/// when Redis is unavailable (we prefer not to block the request for a
/// bookkeeping failure after the expensive work is already done).
pub async fn charge_explicit_weight(
    state: &AppState,
    auth: &AuthInfo,
    weight: i64,
    _path: &str,
) -> Result<(), AppError> {
    if weight <= 0 {
        return Ok(());
    }

    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;
    let (dk_window_start, burst_window_start, hourly_window_start) = sliding_window_starts(now);

    let dk_key = format!("rate:dk:{}", auth.public_key);
    let burst_key = format!("rate:{}", auth.owner);
    let hr_key = format!("rate:hr:{}", auth.owner);

    // Same sliding windows as the live limiter so this post-hoc charge
    // cannot prune in-window history. Limit is i64::MAX — we never deny
    // after the work is already done.
    let _ = check_and_record_window(
        &mut redis,
        &dk_key,
        dk_window_start,
        now,
        i64::MAX,
        weight,
        120,
    )
    .await;
    let _ = check_and_record_window(
        &mut redis,
        &burst_key,
        burst_window_start,
        now,
        i64::MAX,
        weight,
        120,
    )
    .await;
    let _ = check_and_record_window(
        &mut redis,
        &hr_key,
        hourly_window_start,
        now,
        i64::MAX,
        weight,
        3700,
    )
    .await;

    Ok(())
}

// ============================================================
// Client IP for unauthenticated IP limiters
// ============================================================

/// Resolve the rate-limit client IP. Missing `ConnectInfo` uses `0.0.0.0`
/// so hops=0 still shares one unknown bucket and hops>0 still read XFF.
fn rate_limit_peer_addr(request: &Request, trusted_proxy_hops: usize) -> std::net::IpAddr {
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
    crate::client_ip::canonical_client_ip(request.headers(), peer, trusted_proxy_hops)
}

// ============================================================
// Sponsor Rate Limit Middleware (IP-based, unauthenticated)
// ============================================================

/// Pre-authentication rate limiting middleware for the public `/sponsor` routes.
///
/// Enforces a per-IP sliding-window limit using the same Redis counters as
/// the authenticated middleware. Defaults: 10 req/min, 30 req/hr per IP.
///
/// Redis errors return 503. A local fallback cannot provide consistent abuse
/// protection across replicas, so the sponsor path intentionally fails closed.
pub async fn sponsor_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // RATE_LIMIT_DISABLED=1 — see RateLimitConfig::bench_bypass_enabled.
    // Covers the IP+sender sponsor bucket too so benches can hit /sponsor.
    if state.config.rate_limit.bench_bypass_enabled {
        return next.run(request).await;
    }

    // XFF is ignored by default. Only walk back through the explicitly
    // configured number of trusted proxy hops, using the same resolver as
    // the MCP proxy path.
    let ip = rate_limit_peer_addr(&request, state.config.trusted_proxy_hops).to_string();

    let config = &state.config.sponsor_rate_limit;
    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;

    let min_key = format!("rate:sponsor:ip:min:{}", ip);
    let hr_key = format!("rate:sponsor:ip:hr:{}", ip);
    let min_window_start = now - 60_000.0;
    let hr_window_start = now - 3_600_000.0;

    // --- Atomic check-and-record for minute bucket (IP-based) ---
    match check_and_record_window(
        &mut redis,
        &min_key,
        min_window_start,
        now,
        config.per_minute,
        1,
        120,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "sponsor rate limit [IP/min]: ip={} denied (limit={})",
                ip,
                config.per_minute
            );
            return rate_limit_response("sponsor_ip_burst", config.per_minute, "min", 60);
        }
        Err(e) => {
            tracing::error!(
                "sponsor_rate_limit_middleware: Redis error (minute bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    // --- Atomic check-and-record for hour bucket (IP-based) ---
    match check_and_record_window(
        &mut redis,
        &hr_key,
        hr_window_start,
        now + 0.1,
        config.per_hour,
        1,
        3700,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "sponsor rate limit [IP/hr]: ip={} denied (limit={})",
                ip,
                config.per_hour
            );
            return rate_limit_response("sponsor_ip_sustained", config.per_hour, "hour", 300);
        }
        Err(e) => {
            tracing::error!(
                "sponsor_rate_limit_middleware: Redis error (hour bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    match check_global_sponsor_rate_limit(&state, config.global_per_minute, config.global_per_hour)
        .await
    {
        Ok(SponsorRlResult::MinuteLimitExceeded) => {
            return rate_limit_response(
                "sponsor_global_burst",
                config.global_per_minute,
                "min",
                60,
            );
        }
        Ok(SponsorRlResult::HourLimitExceeded) => {
            return rate_limit_response(
                "sponsor_global_sustained",
                config.global_per_hour,
                "hour",
                300,
            );
        }
        Ok(SponsorRlResult::Allowed) => {}
        Err(()) => return rate_limiter_unavailable_response(),
    }

    next.run(request).await
}

// ============================================================
// Accounts — deployment-wide budget limit
// ============================================================

/// Check whether the deployment has exceeded its accounts-exists budget
/// limits.
///
/// Uses a sliding-window counter in Redis just like
/// `check_global_sponsor_rate_limit`, but keyed by fixed server-controlled
/// identifiers so IP rotation cannot bypass an aggregate ceiling on this
/// anonymous, enumeration-risk endpoint.
///
/// Returns `Err(())` on Redis failure so callers can fail closed. A
/// per-process fallback would not enforce a deployment-wide cap across
/// replicas.
pub async fn check_global_accounts_rate_limit(
    state: &crate::types::AppState,
    per_minute: i64,
    per_hour: i64,
) -> Result<SponsorRlResult, ()> {
    let now = chrono::Utc::now().timestamp_millis() as f64;
    let mut redis = state.redis.clone();

    let min_key = "rate:accounts:global:min";
    let hr_key = "rate:accounts:global:hr";
    let min_window_start = now - 60_000.0;
    let hr_window_start = now - 3_600_000.0;

    // --- Atomic check-and-record for minute bucket ---
    match check_and_record_window(
        &mut redis,
        min_key,
        min_window_start,
        now,
        per_minute,
        1, // weight = 1 per accounts-exists request
        120,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            crate::observability::record_rate_limit_denial("accounts_global_burst");
            return Ok(SponsorRlResult::MinuteLimitExceeded);
        }
        Err(e) => {
            tracing::error!(
                "check_global_accounts_rate_limit: Redis error (minute): {}",
                e
            );
            return Err(());
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    // --- Atomic check-and-record for hour bucket ---
    match check_and_record_window(
        &mut redis,
        hr_key,
        hr_window_start,
        now + 0.1,
        per_hour,
        1, // weight = 1 per accounts-exists request
        3700,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            crate::observability::record_rate_limit_denial("accounts_global_sustained");
            return Ok(SponsorRlResult::HourLimitExceeded);
        }
        Err(e) => {
            tracing::error!(
                "check_global_accounts_rate_limit: Redis error (hour): {}",
                e
            );
            return Err(());
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    Ok(SponsorRlResult::Allowed)
}

// ============================================================
// Accounts Rate Limit Middleware (IP-based, unauthenticated)
// ============================================================

/// Pre-authentication rate limiting middleware for the public
/// `GET /api/accounts/{owner}/exists` route.
///
/// Hosted MCP used to share this budget. It must not be mounted here again:
/// `/api/mcp*` is on `mcp_rate_limit_middleware`, whose Redis keys are
/// `rate:mcp:*`. This budget stays small because the route is an anonymous
/// address-existence oracle.
///
/// This is the only route in `public_routes` that reaches the DB pool
/// (`max_connections(10)`) — `/health`, `/version`, `/config`, `/metrics`
/// are all static/no-DB. Modeled directly on `sponsor_rate_limit_middleware`:
/// enforces a per-IP sliding-window limit via `AccountsRateLimitConfig`
/// (a dedicated, stricter budget than the general authenticated
/// `RateLimitConfig` this middleware used to reuse — see that config's doc
/// comment for the reasoning behind its numbers), plus a deployment-wide
/// global cap via `check_global_accounts_rate_limit` so IP rotation alone
/// cannot exceed an aggregate ceiling.
///
/// Redis errors return 503. A local fallback cannot provide consistent abuse
/// protection across replicas, so — like `sponsor_rate_limit_middleware` —
/// this path intentionally fails closed.
pub async fn accounts_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // RATE_LIMIT_DISABLED=1 — see RateLimitConfig::bench_bypass_enabled.
    if state.config.rate_limit.bench_bypass_enabled {
        return next.run(request).await;
    }

    // XFF is ignored by default. Only walk back through the explicitly
    // configured number of trusted proxy hops, using the same resolver as
    // the sponsor and MCP proxy paths.
    let ip = rate_limit_peer_addr(&request, state.config.trusted_proxy_hops).to_string();

    let config = &state.config.accounts_rate_limit;
    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;

    let min_key = format!("rate:accounts:ip:min:{}", ip);
    let hr_key = format!("rate:accounts:ip:hr:{}", ip);
    let min_window_start = now - 60_000.0;
    let hr_window_start = now - 3_600_000.0;

    // --- Atomic check-and-record for minute bucket (IP-based) ---
    match check_and_record_window(
        &mut redis,
        &min_key,
        min_window_start,
        now,
        config.per_minute,
        1,
        120,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "accounts rate limit [IP/min]: ip={} denied (limit={})",
                ip,
                config.per_minute
            );
            return rate_limit_response("accounts_ip_burst", config.per_minute, "min", 60);
        }
        Err(e) => {
            tracing::error!(
                "accounts_rate_limit_middleware: Redis error (minute bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    // --- Atomic check-and-record for hour bucket (IP-based) ---
    match check_and_record_window(
        &mut redis,
        &hr_key,
        hr_window_start,
        now + 0.1,
        config.per_hour,
        1,
        3700,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "accounts rate limit [IP/hr]: ip={} denied (limit={})",
                ip,
                config.per_hour
            );
            return rate_limit_response("accounts_ip_sustained", config.per_hour, "hour", 300);
        }
        Err(e) => {
            tracing::error!(
                "accounts_rate_limit_middleware: Redis error (hour bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    match check_global_accounts_rate_limit(&state, config.global_per_minute, config.global_per_hour)
        .await
    {
        Ok(SponsorRlResult::MinuteLimitExceeded) => {
            return rate_limit_response(
                "accounts_global_burst",
                config.global_per_minute,
                "min",
                60,
            );
        }
        Ok(SponsorRlResult::HourLimitExceeded) => {
            return rate_limit_response(
                "accounts_global_sustained",
                config.global_per_hour,
                "hour",
                300,
            );
        }
        Ok(SponsorRlResult::Allowed) => {}
        Err(()) => return rate_limiter_unavailable_response(),
    }

    next.run(request).await
}

// ============================================================
// Hosted MCP rate limit (own budget, one ceiling for every IP)
// ============================================================

fn mcp_ip_rate_keys(ip: std::net::IpAddr) -> (String, String) {
    let ip = McpRateLimitConfig::normalize_ip(ip);
    (
        format!("rate:mcp:ip:min:{ip}"),
        format!("rate:mcp:ip:hr:{ip}"),
    )
}

const MCP_GLOBAL_MIN_KEY: &str = "rate:mcp:global:min";
const MCP_GLOBAL_HR_KEY: &str = "rate:mcp:global:hr";

/// Redis keys for one MCP tenant's own bucket. `tenant` comes from
/// `mcp_proxy::mcp_tenant_id` (account id + delegate public key), so two
/// tenants never share a window whatever IPs they connect from (GH #1050).
fn mcp_tenant_rate_keys(tenant: &str) -> (String, String) {
    (
        format!("rate:mcp:tenant:min:{tenant}"),
        format!("rate:mcp:tenant:hr:{tenant}"),
    )
}

/// Which MCP window denied a request, mapped to the 429 `layer`.
#[derive(Debug, PartialEq)]
enum McpTenantDenial {
    TenantBurst,
    TenantSustained,
    GlobalBurst,
    GlobalSustained,
}

/// Post-authentication MCP budget: the caller's own tenant windows first,
/// then the deployment-wide ceiling.
///
/// The global ceiling is checked only after the tenant windows admit the
/// request, so a tenant that is already over its own budget is turned away
/// without recording anything in `rate:mcp:global:*`. One tenant therefore
/// cannot fill the shared ceiling as long as `tenant_per_minute` and
/// `tenant_per_hour` stay below the global caps.
async fn check_mcp_tenant_windows<C>(
    redis: &mut C,
    config: &McpRateLimitConfig,
    tenant: &str,
    global_keys: (&str, &str),
) -> Result<Option<McpTenantDenial>, redis::RedisError>
where
    C: redis::aio::ConnectionLike,
{
    let now = chrono::Utc::now().timestamp_millis() as f64;
    let min_start = now - 60_000.0;
    let hr_start = now - 3_600_000.0;
    let (tenant_min, tenant_hr) = mcp_tenant_rate_keys(tenant);

    let windows: [(&str, f64, f64, i64, i64, McpTenantDenial); 4] = [
        (
            &tenant_min,
            min_start,
            now,
            config.tenant_per_minute,
            120,
            McpTenantDenial::TenantBurst,
        ),
        (
            &tenant_hr,
            hr_start,
            now + 0.1,
            config.tenant_per_hour,
            3700,
            McpTenantDenial::TenantSustained,
        ),
        (
            global_keys.0,
            min_start,
            now + 0.2,
            config.global_per_minute,
            120,
            McpTenantDenial::GlobalBurst,
        ),
        (
            global_keys.1,
            hr_start,
            now + 0.3,
            config.global_per_hour,
            3700,
            McpTenantDenial::GlobalSustained,
        ),
    ];
    for (key, start, at, limit, ttl, denial) in windows {
        if check_and_record_window(redis, key, start, at, limit, 1, ttl).await?
            == WindowCheckResult::Denied
        {
            return Ok(Some(denial));
        }
    }
    Ok(None)
}

/// Per-tenant MCP rate limit, called by the MCP proxy handlers once the
/// bearer has been resolved to a tenant. Returns the 429 (or 503 when Redis
/// is down) to send instead of proxying, or `None` to proceed. `RATE_LIMIT_DISABLED=1` skips it.
pub async fn check_mcp_tenant_rate_limit(state: &AppState, tenant: &str) -> Option<Response> {
    if state.config.rate_limit.bench_bypass_enabled {
        return None;
    }
    let config = &state.config.mcp_rate_limit;
    let mut redis = state.redis.clone();
    match check_mcp_tenant_windows(
        &mut redis,
        config,
        tenant,
        (MCP_GLOBAL_MIN_KEY, MCP_GLOBAL_HR_KEY),
    )
    .await
    {
        Ok(None) => None,
        Ok(Some(denial)) => {
            tracing::warn!(
                "mcp rate limit [{:?}]: tenant={}... denied",
                denial,
                &tenant[..24.min(tenant.len())]
            );
            Some(mcp_denial_response(config, denial))
        }
        Err(e) => {
            tracing::error!("check_mcp_tenant_rate_limit: Redis error: {}", e);
            Some(rate_limiter_unavailable_response())
        }
    }
}

fn mcp_denial_response(config: &McpRateLimitConfig, denial: McpTenantDenial) -> Response {
    match denial {
        McpTenantDenial::TenantBurst => {
            rate_limit_response("mcp_tenant_burst", config.tenant_per_minute, "min", 60)
        }
        McpTenantDenial::TenantSustained => {
            rate_limit_response("mcp_tenant_sustained", config.tenant_per_hour, "hour", 300)
        }
        McpTenantDenial::GlobalBurst => {
            rate_limit_response("mcp_global_burst", config.global_per_minute, "min", 60)
        }
        McpTenantDenial::GlobalSustained => {
            rate_limit_response("mcp_global_sustained", config.global_per_hour, "hour", 300)
        }
    }
}

/// Pre-authentication rate limit for `/api/mcp`, `/api/mcp/sse`, and
/// `/api/mcp/messages`.
///
/// Every client IP uses the same `per_minute` / `per_hour` pair. There is
/// no venue allowlist. Each request counts as 1, not a tool weight. Bearer
/// tokens are not exempt. The per-tenant and deployment-wide windows run
/// after authentication, in `check_mcp_tenant_rate_limit`, so they never
/// count an unauthenticated request or one a tenant's own bucket refused. Redis
/// errors return 503, same as the accounts-exists limiter.
/// `RATE_LIMIT_DISABLED=1` skips this, same as every other request-rate
/// middleware.
pub async fn mcp_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if state.config.rate_limit.bench_bypass_enabled {
        return next.run(request).await;
    }

    let ip = McpRateLimitConfig::normalize_ip(rate_limit_peer_addr(
        &request,
        state.config.trusted_proxy_hops,
    ));
    let config = &state.config.mcp_rate_limit;

    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;
    let (min_key, hr_key) = mcp_ip_rate_keys(ip);
    let min_window_start = now - 60_000.0;
    let hr_window_start = now - 3_600_000.0;

    match check_and_record_window(
        &mut redis,
        &min_key,
        min_window_start,
        now,
        config.per_minute,
        1,
        120,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "mcp rate limit [IP/min]: ip={} denied (limit={})",
                ip,
                config.per_minute
            );
            return rate_limit_response("mcp_ip_burst", config.per_minute, "min", 60);
        }
        Err(e) => {
            tracing::error!(
                "mcp_rate_limit_middleware: Redis error (minute bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    match check_and_record_window(
        &mut redis,
        &hr_key,
        hr_window_start,
        now + 0.1,
        config.per_hour,
        1,
        3700,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "mcp rate limit [IP/hr]: ip={} denied (limit={})",
                ip,
                config.per_hour
            );
            return rate_limit_response("mcp_ip_sustained", config.per_hour, "hour", 300);
        }
        Err(e) => {
            tracing::error!(
                "mcp_rate_limit_middleware: Redis error (hour bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    next.run(request).await
}

// ============================================================
// Owner Token — issuance rate limiting
// ============================================================

/// Pre-handler rate limiting for `POST /v1/owner-tokens`, keyed by a
/// SHA-256 hash of the caller's `x-service-credential` header value (the
/// raw credential itself is never used as a Redis key or logged).
///
/// Phase 1 has exactly one shared service credential (see
/// `routes::owner_token` module doc), so today this is effectively one
/// deployment-wide bucket — same mechanism as
/// `check_global_sponsor_rate_limit`'s fixed-key global cap — but hashing
/// the credential rather than hardcoding one key means a future
/// multi-credential Console rollout (e.g. per-integration credentials)
/// gets independent buckets for free, with no changes needed here.
///
/// This is the "per-service-credential" layer only. The additional
/// per-owner cap (`check_owner_token_owner_rate_limit`) is applied inside
/// the `issue_token` handler itself, after the owner address has been
/// canonicalized — not here — because this middleware runs before the
/// request body is parsed by the handler's `Json` extractor, and
/// buffering + re-parsing the body a second time here (mirroring
/// `auth::verify_signature`'s body-consumption pattern) would duplicate
/// validation the handler already has to do, for no benefit: an
/// unauthenticated or malformed-body request is rejected by the
/// credential gate or the handler's own `Json` extractor either way.
///
/// Per-IP budget on `POST /v1/owner-tokens`, independent of whether the
/// supplied `x-service-credential` is valid. Wired as the TRUE outermost
/// layer on this route (outside `service_credential_gate` itself) — see
/// `main.rs`'s `owner_token_routes` wiring for why this is load-bearing:
/// `service_credential_gate` rejects a bad credential in-process with no
/// I/O, so `owner_token_credential_rate_limit_middleware` below (keyed by
/// the *value* of the supplied credential, hashed) is structurally never
/// reached by a failing-credential request, and an attacker who varies
/// their guess every request gets a fresh Redis bucket key each time and
/// is never throttled by it either. Without a limiter keyed by something
/// an attacker can't freely vary (their source IP), guessing the single
/// shared service credential has no throttling at all — this closes that
/// gap the same way `accounts_rate_limit_middleware`/
/// `sponsor_rate_limit_middleware` already do for their own routes (IP
/// budget applied unconditionally, before any auth/validity check).
/// Fails closed to 503 on Redis error, matching every other limiter here.
pub async fn owner_token_ip_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if state.config.rate_limit.bench_bypass_enabled {
        return next.run(request).await;
    }

    let ip = rate_limit_peer_addr(&request, state.config.trusted_proxy_hops).to_string();

    let config = &state.config.owner_token_rate_limit;
    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;

    let min_key = format!("rate:ownertoken:ip:min:{}", ip);
    let hr_key = format!("rate:ownertoken:ip:hr:{}", ip);
    let min_window_start = now - 60_000.0;
    let hr_window_start = now - 3_600_000.0;

    match check_and_record_window(
        &mut redis,
        &min_key,
        min_window_start,
        now,
        config.ip_per_minute,
        1,
        120,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "owner-token rate limit [IP/min]: ip={} denied (limit={})",
                ip,
                config.ip_per_minute
            );
            return rate_limit_response("owner_token_ip_burst", config.ip_per_minute, "min", 60);
        }
        Err(e) => {
            tracing::error!(
                "owner_token_ip_rate_limit_middleware: Redis error (minute bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    match check_and_record_window(
        &mut redis,
        &hr_key,
        hr_window_start,
        now + 0.1,
        config.ip_per_hour,
        1,
        3700,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "owner-token rate limit [IP/hr]: ip={} denied (limit={})",
                ip,
                config.ip_per_hour
            );
            return rate_limit_response(
                "owner_token_ip_sustained",
                config.ip_per_hour,
                "hour",
                300,
            );
        }
        Err(e) => {
            tracing::error!(
                "owner_token_ip_rate_limit_middleware: Redis error (hour bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    next.run(request).await
}

pub async fn owner_token_credential_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // RATE_LIMIT_DISABLED=1 — see RateLimitConfig::bench_bypass_enabled.
    if state.config.rate_limit.bench_bypass_enabled {
        return next.run(request).await;
    }

    // Header name duplicated from `routes::owner_token::SERVICE_CREDENTIAL_HEADER`
    // rather than imported: `rate_limit.rs` is compiled into BOTH the
    // `main.rs` binary crate tree and the separate `lib.rs` library crate
    // tree (see that file's module doc — it deliberately does not declare
    // `mod routes`, only what `sui`'s dependency closure needs), so a
    // `crate::routes::...` reference here would fail to resolve under
    // `cargo test --lib`. Keep this literal in sync with
    // `SERVICE_CREDENTIAL_HEADER` if that constant's value ever changes.
    const SERVICE_CREDENTIAL_HEADER: &str = "x-service-credential";
    let credential = request
        .headers()
        .get(SERVICE_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let credential_hash = hex::encode(Sha256::digest(credential.as_bytes()));

    let config = &state.config.owner_token_rate_limit;
    let mut redis = state.redis.clone();
    let now = chrono::Utc::now().timestamp_millis() as f64;

    let min_key = format!("rate:ownertoken:cred:min:{credential_hash}");
    let hr_key = format!("rate:ownertoken:cred:hr:{credential_hash}");
    let min_window_start = now - 60_000.0;
    let hr_window_start = now - 3_600_000.0;

    match check_and_record_window(
        &mut redis,
        &min_key,
        min_window_start,
        now,
        config.per_minute,
        1,
        120,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "owner-token rate limit [credential/min]: denied (limit={})",
                config.per_minute
            );
            return rate_limit_response(
                "owner_token_credential_burst",
                config.per_minute,
                "min",
                60,
            );
        }
        Err(e) => {
            tracing::error!(
                "owner_token_credential_rate_limit_middleware: Redis error (minute bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    match check_and_record_window(
        &mut redis,
        &hr_key,
        hr_window_start,
        now + 0.1,
        config.per_hour,
        1,
        3700,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            tracing::warn!(
                "owner-token rate limit [credential/hr]: denied (limit={})",
                config.per_hour
            );
            return rate_limit_response(
                "owner_token_credential_sustained",
                config.per_hour,
                "hour",
                300,
            );
        }
        Err(e) => {
            tracing::error!(
                "owner_token_credential_rate_limit_middleware: Redis error (hour bucket): {}",
                e
            );
            return rate_limiter_unavailable_response();
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    next.run(request).await
}

/// Per-owner cap on `POST /v1/owner-tokens` issuance. Keyed by
/// the canonical (lowercased) owner address, independent of the
/// per-service-credential budget enforced by
/// `owner_token_credential_rate_limit_middleware` — a compromised or buggy
/// Console instance that still holds a valid service credential must not
/// be able to mint unbounded tokens for one owner. Called directly from
/// the `issue_token` handler (see that function's doc comment for why this
/// isn't middleware).
///
/// Reuses `SponsorRlResult` (`Allowed` / `MinuteLimitExceeded` /
/// `HourLimitExceeded`) rather than defining a fourth near-identical
/// two-tier rate-limit result enum — this crate already has
/// `check_global_sponsor_rate_limit` and `check_global_accounts_rate_limit`
/// returning the same shape for the same reason.
///
/// Returns `Err(())` on Redis failure so the caller can fail closed —
/// consistent with every other limiter in this module.
pub async fn check_owner_token_owner_rate_limit(
    state: &crate::types::AppState,
    owner: &str,
    per_minute: i64,
    per_hour: i64,
) -> Result<SponsorRlResult, ()> {
    let now = chrono::Utc::now().timestamp_millis() as f64;
    let mut redis = state.redis.clone();

    let min_key = format!("rate:ownertoken:owner:min:{owner}");
    let hr_key = format!("rate:ownertoken:owner:hr:{owner}");
    let min_window_start = now - 60_000.0;
    let hr_window_start = now - 3_600_000.0;

    match check_and_record_window(
        &mut redis,
        &min_key,
        min_window_start,
        now,
        per_minute,
        1,
        120,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            crate::observability::record_rate_limit_denial("owner_token_owner_burst");
            return Ok(SponsorRlResult::MinuteLimitExceeded);
        }
        Err(e) => {
            tracing::error!(
                "check_owner_token_owner_rate_limit: Redis error (minute): {}",
                e
            );
            return Err(());
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    match check_and_record_window(
        &mut redis,
        &hr_key,
        hr_window_start,
        now + 0.1,
        per_hour,
        1,
        3700,
    )
    .await
    {
        Ok(WindowCheckResult::Denied) => {
            crate::observability::record_rate_limit_denial("owner_token_owner_sustained");
            return Ok(SponsorRlResult::HourLimitExceeded);
        }
        Err(e) => {
            tracing::error!(
                "check_owner_token_owner_rate_limit: Redis error (hour): {}",
                e
            );
            return Err(());
        }
        Ok(WindowCheckResult::Allowed) => {}
    }

    Ok(SponsorRlResult::Allowed)
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_rate_limit_keys_do_not_share_the_accounts_budget() {
        let v4: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let mapped: std::net::IpAddr = "::ffff:203.0.113.5".parse().unwrap();
        let (min_a, hr_a) = mcp_ip_rate_keys(v4);
        let (min_b, hr_b) = mcp_ip_rate_keys(mapped);
        assert_eq!(min_a, min_b);
        assert_eq!(hr_a, hr_b);
        assert_eq!(min_a, "rate:mcp:ip:min:203.0.113.5");
        assert_eq!(hr_a, "rate:mcp:ip:hr:203.0.113.5");
        for key in [&min_a, &hr_a, MCP_GLOBAL_MIN_KEY, MCP_GLOBAL_HR_KEY] {
            assert!(key.starts_with("rate:mcp:"), "{key}");
            assert!(!key.contains("accounts"), "{key}");
        }
    }

    #[test]
    fn test_endpoint_weight_trailing_slash_normalized() {
        // Without trailing slash
        assert_eq!(endpoint_weight("/api/analyze"), 5);
        assert_eq!(endpoint_weight("/api/remember"), 5);
        assert_eq!(endpoint_weight("/api/remember/manual"), 3);
        assert_eq!(endpoint_weight("/api/restore"), 3);
        assert_eq!(endpoint_weight("/api/ask"), 2);
        assert_eq!(endpoint_weight("/api/embed"), 2);

        // With trailing slash — must return SAME weight.
        assert_eq!(
            endpoint_weight("/api/analyze/"),
            5,
            "trailing slash bypass!"
        );
        assert_eq!(
            endpoint_weight("/api/remember/"),
            5,
            "trailing slash bypass!"
        );
        assert_eq!(endpoint_weight("/api/ask/"), 2, "trailing slash bypass!");

        // Unknown path → weight 1
        assert_eq!(endpoint_weight("/api/recall"), 1);
        assert_eq!(endpoint_weight("/health"), 1);
        assert_eq!(endpoint_weight("/unknown/path/"), 1);
    }

    #[test]
    fn test_endpoint_weight_no_regression() {
        // Double trailing slash should also normalize
        assert_eq!(endpoint_weight("/api/analyze//"), 5);
    }

    #[test]
    fn charge_windows_match_live_limiter_not_now() {
        let now = 1_700_000_000_000.0;
        let (dk, burst, hourly) = sliding_window_starts(now);
        assert_eq!(dk, now - 60_000.0);
        assert_eq!(burst, now - 60_000.0);
        assert_eq!(hourly, now - 3_600_000.0);
        assert!(dk < now && burst < now && hourly < now);
    }

    #[test]
    fn test_endpoint_weight_owner_scoped_read_api_routes() {
        // Previously these three fell through to the default `1`
        // implicitly (no explicit entry) — now explicit, and /agents is
        // weighted higher since it makes a live on-chain RPC call per request.
        assert_eq!(endpoint_weight("/v1/owners/0xabc123/namespaces"), 1);
        assert_eq!(endpoint_weight("/v1/owners/0xabc123/memories"), 1);
        assert_eq!(
            endpoint_weight("/v1/owners/0xabc123/agents"),
            2,
            "agents does a live on-chain RPC call and must outweigh plain DB reads"
        );
        // Trailing slash must not bypass the explicit weight.
        assert_eq!(endpoint_weight("/v1/owners/0xabc123/agents/"), 2);
    }

    // ---- stable_hash_i64 ----

    #[test]
    fn test_stable_hash_i64_deterministic() {
        let owner = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let h1 = stable_hash_i64(owner);
        let h2 = stable_hash_i64(owner);
        assert_eq!(h1, h2, "hash must be deterministic");
    }

    #[test]
    fn test_stable_hash_i64_different_owners() {
        let h1 = stable_hash_i64("owner_a");
        let h2 = stable_hash_i64("owner_b");
        assert_ne!(h1, h2, "different owners must produce different lock keys");
    }

    #[test]
    fn test_stable_hash_i64_empty() {
        // Should not panic on empty string
        let h = stable_hash_i64("");
        let _ = h; // just verify no panic
    }

    // ---- fail-closed response ----

    #[test]
    fn test_rate_limiter_unavailable_response_is_503() {
        let resp = rate_limiter_unavailable_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // Verify Retry-After header is present
        assert!(resp.headers().contains_key("retry-after"));
    }

    // ---- Missing ConnectInfo must still be rate-limited (WALM-626) ----

    fn rate_limit_request(peer: Option<std::net::SocketAddr>, xff: Option<&str>) -> Request {
        let mut builder = axum::http::Request::builder().uri("/");
        if let Some(xff) = xff {
            builder = builder.header("x-forwarded-for", xff);
        }
        let mut request = builder.body(axum::body::Body::empty()).unwrap();
        if let Some(peer) = peer {
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
        }
        request
    }

    #[test]
    fn missing_connect_info_with_zero_hops_uses_unspecified_peer() {
        let request = rate_limit_request(None, Some("198.51.100.7"));
        assert_eq!(
            rate_limit_peer_addr(&request, 0),
            "0.0.0.0".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn connect_info_present_with_zero_hops_ignores_xff() {
        let peer = "203.0.113.9:443".parse().unwrap();
        let request = rate_limit_request(Some(peer), Some("198.51.100.7"));
        assert_eq!(
            rate_limit_peer_addr(&request, 0),
            "203.0.113.9".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn missing_connect_info_with_trusted_hop_uses_xff() {
        let request = rate_limit_request(None, Some("198.51.100.7"));
        assert_eq!(
            rate_limit_peer_addr(&request, 1),
            "198.51.100.7".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn missing_connect_info_with_trusted_hop_falls_back_without_xff() {
        let no_xff = rate_limit_request(None, None);
        let malformed = rate_limit_request(None, Some("not-an-ip"));
        assert_eq!(
            rate_limit_peer_addr(&no_xff, 1),
            "0.0.0.0".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            rate_limit_peer_addr(&malformed, 1),
            "0.0.0.0".parse::<std::net::IpAddr>().unwrap()
        );
    }

    // ---- Read API rate limit config + response shape ----

    #[test]
    fn test_read_api_rate_limit_config_defaults() {
        let config = crate::types::ReadApiRateLimitConfig::default();
        assert_eq!(config.per_delegate_key_per_minute, 200);
    }

    #[test]
    fn test_read_api_rate_limit_response_uses_dedicated_layer_name() {
        // Guards against re-drifting into the shared "delegate_key" /
        // "account_burst" layer names the write path uses — the whole point
        // of this budget is that it is a *separate* bucket clients (and
        // dashboards keying off `layer`) can distinguish from write-path 429s.
        let resp = rate_limit_response("read_delegate_key", 200, "min", 60);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers().get("retry-after").unwrap(),
            "60",
            "Retry-After header must be present with the same value as retry_after_seconds"
        );
    }

    #[test]
    fn test_rate_limit_response_is_429() {
        let resp = rate_limit_response("account_burst", 60, "min", 60);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key("retry-after"));
    }

    // ---- Atomic Lua script structure ----

    /// Verify the Lua script constant is non-empty and contains the critical
    /// idempotency guard (`count + weight > limit`). If the guard disappears,
    /// the TOCTOU race is reintroduced.
    #[test]
    fn test_lua_script_contains_atomic_guard() {
        assert!(
            !SLIDING_WINDOW_LUA.is_empty(),
            "Lua script must not be empty"
        );
        assert!(
            SLIDING_WINDOW_LUA.contains("count + weight > limit"),
            "Lua script must contain atomic count+weight guard"
        );
        assert!(
            SLIDING_WINDOW_LUA.contains("ZREMRANGEBYSCORE"),
            "Lua script must prune stale entries"
        );
        assert!(
            SLIDING_WINDOW_LUA.contains("ZADD"),
            "Lua script must add new entries"
        );
        assert!(
            SLIDING_WINDOW_LUA.contains("EXPIRE"),
            "Lua script must refresh TTL"
        );
        assert!(
            SLIDING_WINDOW_LUA.contains("request_id .. ':' .. tostring(i)"),
            "Lua script must use a unique request ID for every ZSET member"
        );
    }

    /// Regression test for same-millisecond concurrent requests. This talks to
    /// a real Redis instance because Redis ZSET member de-duplication and Lua
    /// atomicity cannot be faithfully covered by a mock.
    ///
    /// Run with:
    /// TEST_REDIS_URL=redis://127.0.0.1:6379 \
    ///   cargo test concurrent_same_millisecond_requests_respect_limit -- --ignored
    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL pointing to a real Redis instance"]
    async fn concurrent_same_millisecond_requests_respect_limit() {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("TEST_REDIS_URL must be set when running Redis integration tests");
        let client = redis::Client::open(redis_url).expect("valid TEST_REDIS_URL");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("connect to test Redis");
        let key = format!("test:rate-limit:concurrent:{}", Uuid::new_v4());
        let _: i64 = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .expect("clear test key");

        const REQUESTS: usize = 32;
        const LIMIT: i64 = 10;
        let now = chrono::Utc::now().timestamp_millis() as f64;
        let barrier = Arc::new(tokio::sync::Barrier::new(REQUESTS + 1));
        let mut tasks = Vec::with_capacity(REQUESTS);

        for _ in 0..REQUESTS {
            let mut task_connection = connection.clone();
            let task_key = key.clone();
            let task_barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                task_barrier.wait().await;
                check_and_record_window(
                    &mut task_connection,
                    &task_key,
                    now - 60_000.0,
                    now,
                    LIMIT,
                    1,
                    120,
                )
                .await
            }));
        }

        barrier.wait().await;
        let mut allowed = 0;
        for task in tasks {
            if task
                .await
                .expect("rate-limit task panicked")
                .expect("Redis script failed")
                == WindowCheckResult::Allowed
            {
                allowed += 1;
            }
        }

        let cardinality: i64 = redis::cmd("ZCARD")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .expect("read test bucket cardinality");
        let _: i64 = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .expect("clean test key");

        assert_eq!(allowed, LIMIT);
        assert_eq!(cardinality, LIMIT);
    }

    /// Regression test for `check_restore_call_rate_limit`'s underlying
    /// window (GH #501 / WALM-299 owner-scoped restore-call guard). Talks to
    /// a real Redis instance for the same reason as
    /// `concurrent_same_millisecond_requests_respect_limit`.
    ///
    /// `check_restore_call_rate_limit` itself takes `&AppState`, which
    /// nothing in this crate constructs outside of `main.rs` (it wires a DB
    /// pool, Sui clients, the memory engine, embedder, extractor, ranker,
    /// etc.). Standing one up here would test plumbing this fix didn't
    /// touch, so this test drives the exact `rate:restore-call:{owner}` key
    /// + 1-minute-window + weight-1 shape through `check_and_record_window`
    /// directly — the same primitive `check_restore_call_rate_limit` calls,
    /// with no logic of its own in between.
    ///
    /// Run with:
    /// TEST_REDIS_URL=redis://127.0.0.1:6379 \
    ///   cargo test restore_call_rate_limit_denies_past_the_owner_window -- --ignored
    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL pointing to a real Redis instance"]
    async fn restore_call_rate_limit_denies_past_the_owner_window() {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("TEST_REDIS_URL must be set when running Redis integration tests");
        let client = redis::Client::open(redis_url).expect("valid TEST_REDIS_URL");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("connect to test Redis");

        const LIMIT: i64 = 10;
        let owner = format!("0xrestore-rl-owner-{}", Uuid::new_v4());
        let other_owner = format!("0xrestore-rl-other-{}", Uuid::new_v4());
        let key = format!("rate:restore-call:{owner}");
        let other_key = format!("rate:restore-call:{other_owner}");
        let now = chrono::Utc::now().timestamp_millis() as f64;
        let window_start = now - 60_000.0;

        // First LIMIT calls for `owner` are allowed, the LIMIT+1'th is denied.
        for i in 0..LIMIT {
            let result = check_and_record_window(
                &mut connection,
                &key,
                window_start,
                now + i as f64,
                LIMIT,
                1,
                120,
            )
            .await
            .expect("Redis script failed");
            assert_eq!(
                result,
                WindowCheckResult::Allowed,
                "call {} of {} should be allowed",
                i + 1,
                LIMIT
            );
        }
        let denied = check_and_record_window(
            &mut connection,
            &key,
            window_start,
            now + LIMIT as f64,
            LIMIT,
            1,
            120,
        )
        .await
        .expect("Redis script failed");
        assert_eq!(
            denied,
            WindowCheckResult::Denied,
            "call {} should be denied for a limit of {}",
            LIMIT + 1,
            LIMIT
        );

        // Key isolation: a distinct owner's window is unaffected by the
        // first owner having exhausted theirs.
        let other_allowed = check_and_record_window(
            &mut connection,
            &other_key,
            window_start,
            now,
            LIMIT,
            1,
            120,
        )
        .await
        .expect("Redis script failed");
        assert_eq!(
            other_allowed,
            WindowCheckResult::Allowed,
            "a distinct owner must not be affected by another owner's exhausted window"
        );

        let _: i64 = redis::cmd("DEL")
            .arg(&key)
            .arg(&other_key)
            .query_async(&mut connection)
            .await
            .expect("clean test keys");
    }

    /// Verify that WindowCheckResult variants are correctly defined.
    #[test]
    fn test_window_check_result_variants() {
        let allowed = WindowCheckResult::Allowed;
        let denied = WindowCheckResult::Denied;
        assert_eq!(allowed, WindowCheckResult::Allowed);
        assert_eq!(denied, WindowCheckResult::Denied);
        assert_ne!(allowed, denied, "Allowed and Denied must be distinct");
    }

    // ---- Percent-encoded path normalization ----

    #[test]
    fn test_endpoint_weight_percent_encoded_analyze() {
        // "%79" = 'y', so "/api/anal%79ze" = "/api/analyze"
        assert_eq!(
            endpoint_weight("/api/anal%79ze"),
            5,
            "percent-encoded 'y' bypass"
        );
    }

    #[test]
    fn test_endpoint_weight_percent_encoded_remember() {
        // "%72" = 'r', so "/api/%72emember" = "/api/remember"
        assert_eq!(
            endpoint_weight("/api/%72emember"),
            5,
            "percent-encoded 'r' bypass"
        );
    }

    #[test]
    fn test_endpoint_weight_percent_encoded_slash_and_trailing() {
        // "%2F" = '/', combined with trailing slash
        // "/api/remember/manual%2F" → "/api/remember/manual/"
        // After slash stripping → "/api/remember/manual"
        assert_eq!(endpoint_weight("/api/remember/manual%2F"), 3);
    }

    #[test]
    fn test_endpoint_weight_full_percent_encoded_path() {
        // Full path encoded: /api/ask → /%61%70%69/%61%73%6b
        assert_eq!(endpoint_weight("/%61%70%69/%61%73%6b"), 2);
    }

    #[test]
    fn test_endpoint_weight_mixed_case_percent_encoding() {
        // Mixed case encoding: %41 = 'A' — not matching lowercase paths
        // "/api/%41nalyze" → "/api/Analyze" → weight 1 (no match, different case)
        assert_eq!(endpoint_weight("/api/%41nalyze"), 1);
    }

    #[test]
    fn test_endpoint_weight_malformed_percent_encoding() {
        // Invalid percent encoding → lossy decode → U+FFFD → no match → weight 1
        assert_eq!(endpoint_weight("/api/%ZZ/bad"), 1);
    }

    // ---- In-memory token bucket fallback ----

    #[test]
    fn test_fallback_token_bucket_new_starts_full() {
        let bucket = TokenBucket::new(10.0);
        assert_eq!(bucket.tokens, 10.0);
    }

    #[test]
    fn test_fallback_token_bucket_consume_reduces_tokens() {
        let mut bucket = TokenBucket::new(10.0);
        bucket.consume(3.0, 10.0, 1.0); // consume 3 of 10
                                        // tokens should be ~7.0 (with tiny time delta adding a fraction)
        assert!(
            bucket.tokens < 8.0,
            "tokens should be around 7, got {}",
            bucket.tokens
        );
        assert!(
            bucket.tokens > 6.0,
            "tokens should be around 7, got {}",
            bucket.tokens
        );
    }

    #[test]
    fn test_fallback_token_bucket_peek_does_not_modify() {
        let bucket = TokenBucket::new(10.0);
        let can1 = bucket.peek(5.0, 10.0, 1.0);
        let can2 = bucket.peek(5.0, 10.0, 1.0);
        assert!(can1);
        assert!(can2);
        // Peeking twice must not reduce tokens
        assert_eq!(bucket.tokens, 10.0);
    }

    #[test]
    fn test_fallback_token_bucket_rejects_when_empty() {
        let mut bucket = TokenBucket::new(5.0);
        bucket.consume(5.0, 5.0, 0.0); // consume all, no refill
                                       // With 0 refill rate and ~0 elapsed time, no tokens available
        assert!(!bucket.peek(1.0, 5.0, 0.0));
    }

    #[test]
    fn test_fallback_inmemory_cleanup() {
        let mut fb = InMemoryFallback {
            cleanup_counter: 999,
            ..Default::default()
        };

        // Add a bucket and consume to trigger cleanup
        fb.consume("test_key", 1.0, 10.0, 60.0);

        // After cleanup_counter >= 1000, it resets to 0
        assert_eq!(
            fb.cleanup_counter, 0,
            "cleanup counter should reset after reaching 1000"
        );
    }

    #[test]
    fn test_fallback_inmemory_can_consume_and_consume() {
        let mut fb = InMemoryFallback::default();

        // First request should be allowed
        assert!(fb.can_consume("k1", 1.0, 10.0, 60.0));
        fb.consume("k1", 1.0, 10.0, 60.0);

        // Should still have capacity
        assert!(fb.can_consume("k1", 1.0, 10.0, 60.0));
    }

    #[test]
    fn test_fallback_inmemory_independent_keys() {
        let mut fb = InMemoryFallback::default();

        // Exhaust key k1
        for _ in 0..10 {
            fb.consume("k1", 1.0, 10.0, 60.0);
        }

        // k2 should still be available
        assert!(fb.can_consume("k2", 1.0, 10.0, 60.0));
    }

    // ---- Analyze weight calculations ----

    #[test]
    fn test_analyze_additional_weight() {
        assert_eq!(analyze_additional_weight(0), 0);
        assert_eq!(analyze_additional_weight(1), 1);
        assert_eq!(analyze_additional_weight(5), 5);
        assert_eq!(analyze_additional_weight(20), 20);
    }

    #[test]
    fn test_analyze_total_weight() {
        // base weight (5) + fact_count
        assert_eq!(analyze_total_weight(0), 5);
        assert_eq!(analyze_total_weight(1), 6);
        assert_eq!(analyze_total_weight(10), 15);
        assert_eq!(analyze_total_weight(20), 25); // max: 5 + 20
    }

    // ---- RateLimitConfig defaults ----

    #[test]
    fn test_rate_limit_config_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests_per_minute, 60);
        assert_eq!(config.max_requests_per_hour, 500);
        assert_eq!(config.max_requests_per_delegate_key, 30);
        assert_eq!(config.max_storage_bytes, 1_073_741_824); // 1 GB
        assert_eq!(config.redis_url, "redis://127.0.0.1:6379");
        // Bench bypass MUST default to false — production safety net.
        assert!(!config.bench_bypass_enabled);
    }

    // ---- SponsorRlResult variants ----

    #[test]
    fn test_sponsor_rl_result_variants() {
        assert_eq!(SponsorRlResult::Allowed, SponsorRlResult::Allowed);
        assert_eq!(
            SponsorRlResult::MinuteLimitExceeded,
            SponsorRlResult::MinuteLimitExceeded
        );
        assert_eq!(
            SponsorRlResult::HourLimitExceeded,
            SponsorRlResult::HourLimitExceeded
        );
        assert_ne!(
            SponsorRlResult::Allowed,
            SponsorRlResult::MinuteLimitExceeded
        );
        assert_ne!(
            SponsorRlResult::MinuteLimitExceeded,
            SponsorRlResult::HourLimitExceeded
        );
    }

    // ---- GH #1050: per-tenant MCP bucket ----

    #[test]
    fn mcp_tenant_keys_are_per_tenant_and_mcp_scoped() {
        let (min_a, hr_a) = mcp_tenant_rate_keys("0xaa:11");
        let (min_b, hr_b) = mcp_tenant_rate_keys("0xbb:22");
        assert_eq!(min_a, "rate:mcp:tenant:min:0xaa:11");
        assert_eq!(hr_a, "rate:mcp:tenant:hr:0xaa:11");
        assert_ne!(min_a, min_b);
        assert_ne!(hr_a, hr_b);
        assert_ne!(min_a, MCP_GLOBAL_MIN_KEY);
    }

    #[tokio::test]
    async fn mcp_tenant_denial_is_429_with_retry_after() {
        let config = McpRateLimitConfig::default();
        let resp = mcp_denial_response(&config, McpTenantDenial::TenantBurst);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()["retry-after"], "60");
        let body = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["layer"], "mcp_tenant_burst");
        assert_eq!(json["limit"], "1000 weighted-requests/min");
        assert_eq!(json["retry_after_seconds"], 60);

        let resp = mcp_denial_response(&config, McpTenantDenial::TenantSustained);
        assert_eq!(resp.headers()["retry-after"], "300");
    }

    #[test]
    fn mcp_tenant_defaults_stay_below_global_caps() {
        let c = McpRateLimitConfig::default();
        assert!(c.tenant_per_minute < c.global_per_minute);
        assert!(c.tenant_per_hour < c.global_per_hour);
    }

    /// GH #1050 regression. Tenant A and tenant B send concurrently. A sends
    /// far more than its bucket; B stays inside its own. A must get
    /// `mcp_tenant_burst` denials, B must get none, and A's refused requests
    /// must not be recorded in the shared global window.
    ///
    /// Run with:
    /// TEST_REDIS_URL=redis://127.0.0.1:6379 \
    ///   cargo test mcp_tenant_a_exhausting_bucket_does_not_throttle_tenant_b -- --ignored
    #[tokio::test]
    #[ignore = "requires TEST_REDIS_URL pointing to a real Redis instance"]
    async fn mcp_tenant_a_exhausting_bucket_does_not_throttle_tenant_b() {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .expect("TEST_REDIS_URL must be set when running Redis integration tests");
        let client = redis::Client::open(redis_url).expect("valid TEST_REDIS_URL");
        let connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("connect to test Redis");

        let run = Uuid::new_v4();
        let tenant_a = format!("test-1050-{run}:a");
        let tenant_b = format!("test-1050-{run}:b");
        let global_min = format!("test:rate:mcp:global:min:{run}");
        let global_hr = format!("test:rate:mcp:global:hr:{run}");

        const TENANT_LIMIT: i64 = 10;
        const A_REQUESTS: usize = 200;
        const B_REQUESTS: usize = 10;
        let config = Arc::new(McpRateLimitConfig {
            per_minute: 2000,
            per_hour: 8000,
            tenant_per_minute: TENANT_LIMIT,
            tenant_per_hour: 1000,
            // Lower than A's request count: under the old shared bucket A
            // alone would fill it and B would be refused.
            global_per_minute: 50,
            global_per_hour: 5000,
        });

        let barrier = Arc::new(tokio::sync::Barrier::new(A_REQUESTS + B_REQUESTS + 1));
        let mut tasks = Vec::new();
        for i in 0..(A_REQUESTS + B_REQUESTS) {
            let mut conn = connection.clone();
            let tenant = if i % 21 == 20 && i / 21 < B_REQUESTS {
                tenant_b.clone()
            } else {
                tenant_a.clone()
            };
            let (gm, gh, cfg, bar) = (
                global_min.clone(),
                global_hr.clone(),
                config.clone(),
                barrier.clone(),
            );
            tasks.push(tokio::spawn(async move {
                bar.wait().await;
                let r = check_mcp_tenant_windows(&mut conn, &cfg, &tenant, (&gm, &gh))
                    .await
                    .expect("Redis script failed");
                (tenant, r)
            }));
        }
        barrier.wait().await;

        let (mut a_ok, mut a_denied, mut b_ok, mut b_denied) = (0, 0, 0, 0);
        for task in tasks {
            let (tenant, result) = task.await.expect("task panicked");
            match (tenant == tenant_b, result) {
                (false, None) => a_ok += 1,
                (false, Some(McpTenantDenial::TenantBurst)) => a_denied += 1,
                (false, Some(other)) => panic!("tenant A denied by {other:?}"),
                (true, None) => b_ok += 1,
                (true, Some(d)) => {
                    b_denied += 1;
                    eprintln!("tenant B denied by {d:?}");
                }
            }
        }
        eprintln!("#1050: A ok={a_ok} denied={a_denied}; B ok={b_ok} denied={b_denied}");
        assert_eq!(a_ok + a_denied, A_REQUESTS);
        assert_eq!(b_ok + b_denied, B_REQUESTS);
        assert_eq!(a_ok, TENANT_LIMIT as usize, "A gets exactly its own bucket");
        assert_eq!(b_denied, 0, "A exhausting its bucket must not throttle B");
        assert_eq!(b_ok, B_REQUESTS);

        let mut conn = connection.clone();
        let global_count: i64 = redis::cmd("ZCARD")
            .arg(&global_min)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            global_count,
            TENANT_LIMIT + B_REQUESTS as i64,
            "A's refused requests must not spend the global window"
        );

        // A is still refused afterwards, with the 429 + Retry-After shape.
        let denial =
            check_mcp_tenant_windows(&mut conn, &config, &tenant_a, (&global_min, &global_hr))
                .await
                .unwrap()
                .expect("A stays over its bucket");
        let resp = mcp_denial_response(&config, denial);
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers()["retry-after"], "60");

        let (a_min, a_hr) = mcp_tenant_rate_keys(&tenant_a);
        let (b_min, b_hr) = mcp_tenant_rate_keys(&tenant_b);
        let _: i64 = redis::cmd("DEL")
            .arg(&[a_min, a_hr, b_min, b_hr, global_min, global_hr])
            .query_async(&mut conn)
            .await
            .unwrap();
    }
}

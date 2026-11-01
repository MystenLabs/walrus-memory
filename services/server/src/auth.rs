use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::owner_token_auth;
use crate::storage::sui::{verify_delegate_key_cached, OnchainVerifyError};
use crate::types::{AppState, AuthInfo};

/// Maximum signed-JSON body the auth middleware will buffer before computing
/// the SHA-256 digest. Must be ≥ the largest per-route body limit so the auth
/// layer never rejects requests the routes themselves would accept.
/// Today the bulk-remember route is the largest at 2 MiB.
pub(crate) const PROTECTED_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// Ed25519 signature verification + onchain delegate key verification middleware
///
/// Expects these headers:
/// - `x-public-key`: hex-encoded Ed25519 public key (32 bytes)
/// - `x-signature`: hex-encoded Ed25519 signature (64 bytes)
/// - `x-timestamp`: Unix timestamp (seconds)
/// - `x-nonce`: UUID v4 replay-protection nonce
/// - `x-account-id`: account object ID hint included in the canonical signature
///
/// Flow:
/// 1. Verify Ed25519 signature:
///    `{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}`
/// 2. Resolve account: cache → signed `x-account-id` or `MEMWAL_ACCOUNT_ID`.
///    A cold key with neither is rejected. The relayer does not scan
///    AccountRegistry.
/// 3. Verify onchain: public_key ∈ MemWalAccount.delegate_keys
/// 4. Cache the mapping for future requests
/// 5. Store AuthInfo { public_key, owner } in request extensions
///
/// Normalize response timing across all auth failure paths.
/// Returns UNAUTHORIZED after a constant 100 ms delay so that an attacker
/// cannot distinguish "account does not exist" (fast RPC fail) from
/// "account exists but key not found" (slow delegate_keys array scan)
/// by measuring response latency.
async fn constant_time_reject() -> StatusCode {
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    StatusCode::UNAUTHORIZED
}

/// Machine-readable reason for a stale/future-dated timestamp, surfaced on the
/// `x-auth-error` header so a client can distinguish clock drift from a bad
/// signature. Identity 401s (signature, nonce, account-resolution) keep the
/// bare uniform 401 so they cannot be used to enumerate accounts. 503 auth
/// unavailability uses the same header with `AUTH_UPSTREAM_UNAVAILABLE` — that
/// path does not leak whether the key exists.
const ERR_TIMESTAMP_OUT_OF_BOUNDS: &str = "ERR_TIMESTAMP_OUT_OF_BOUNDS";

/// 401 carrying `x-auth-error: <code>`, after the same constant delay as
/// `constant_time_reject` so timing stays uniform across auth-failure paths.
async fn constant_time_reject_with_reason(code: &'static str) -> Response {
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    (
        StatusCode::UNAUTHORIZED,
        [("x-auth-error", code)],
        String::new(),
    )
        .into_response()
}

fn unsupported_legacy_sdk() -> StatusCode {
    StatusCode::UPGRADE_REQUIRED
}

/// Machine-readable 503 from signed HTTP auth / MCP when Sui cannot be
/// consulted. Distinct from other relayer 503s (Redis, rate limiter, LLM)
/// so SDKs only print the credential-verification copy when this header is
/// present (WALM-429).
pub(crate) const AUTH_UPSTREAM_UNAVAILABLE: &str = "AUTH_UPSTREAM_UNAVAILABLE";

/// Short Retry-After for auth 503. Callers must backoff rather than
/// immediately re-hitting a 429ing Sui fullnode. Not a substitute for the
/// 100 ms 401 timing pad — that path stays 401-only.
pub(crate) const AUTH_UPSTREAM_RETRY_AFTER_SECS: u64 = 5;

/// Matches the MCP proxy: Sui could not be consulted, so this is not a login
/// failure. Empty 401 here is what made the SDK print memwal_login (WALM-429).
///
/// Fail-closed: do not authenticate from a cached mapping while the chain
/// is unreachable. Keep the cache row (do not evict), return 503 with
/// `x-auth-error: AUTH_UPSTREAM_UNAVAILABLE` and `Retry-After`.
pub(crate) fn upstream_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            ("retry-after", AUTH_UPSTREAM_RETRY_AFTER_SECS.to_string()),
            ("x-auth-error", AUTH_UPSTREAM_UNAVAILABLE.to_string()),
        ],
        "upstream unavailable",
    )
        .into_response()
}

/// WALM-429: an RPC failure must not evict the cache row *and* must not
/// authenticate from it.
#[derive(Debug)]
enum CacheReverifyAction {
    Authenticate { owner: String },
    UnavailableKeepCache { reason: String },
    Evict { reason: String },
}

fn cache_reverify_action(result: Result<String, OnchainVerifyError>) -> CacheReverifyAction {
    match result {
        Ok(owner) => CacheReverifyAction::Authenticate { owner },
        Err(e) if e.is_unavailable() => CacheReverifyAction::UnavailableKeepCache {
            reason: e.to_string(),
        },
        Err(e) => CacheReverifyAction::Evict {
            reason: e.to_string(),
        },
    }
}

/// Outcome of resolving a signed delegate key to a MemWal account.
enum AccountResolveError {
    /// Identity could not be established. Maps to a timing-normalized 401.
    Unauthorized(String),
    /// On-chain lookup could not be completed. Maps to 503 — retryable.
    Unavailable(String),
}

impl std::fmt::Display for AccountResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized(msg) | Self::Unavailable(msg) => write!(f, "{msg}"),
        }
    }
}

/// Whether a request whose signed timestamp is `age` seconds old (negative =
/// future-dated) is fresh, given the accepted drift window. The window is
/// inclusive and symmetric: `|age| <= drift`. `drift == 0` requires an exact
/// second match. This is the sole freshness predicate — the middleware and its
/// tests both call it, so a boundary regression can't hide behind a duplicated
/// expression.
fn is_timestamp_fresh(age: i64, drift: i64) -> bool {
    (-drift..=drift).contains(&age)
}

/// Redis TTL (seconds) for a request's replay nonce.
///
/// Freshness is symmetric: a request signed for time `T` is accepted for any
/// `now` in `[T - drift, T + drift]`. Its nonce record is written on first
/// acceptance, which can happen as early as `now = T - drift` (a future-dated
/// request), yet the request stays fresh until `now = T + drift`. So the record
/// must survive the *full* `2 * drift` lifetime, not just one drift — otherwise
/// a request first seen at `T - drift` has its nonce expire at
/// `(T - drift) + ttl` while still being fresh, and the same signature replays
/// in the gap. TTL = `2 * drift + NONCE_TTL_BUFFER_SECS` covers the worst case
/// with margin for every window value. `drift` is bounded to
/// `0..=MAX_AUTH_CLOCK_DRIFT_SECS`, so `2 * drift + buffer` (≤ 2100) never
/// overflows and the `as u64` is lossless.
fn nonce_ttl_secs(drift: i64) -> u64 {
    (2 * drift + crate::types::NONCE_TTL_BUFFER_SECS).max(0) as u64
}

#[tracing::instrument(name = "auth.verify_signature", skip_all)]
pub async fn verify_signature(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = request.headers();

    // Extract auth headers as owned Strings
    let public_key_hex = headers
        .get("x-public-key")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let signature_hex = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let timestamp_str = headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Optional account ID hint from header
    let account_id_hint = headers
        .get("x-account-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Optional delegate private key (hex) for SEAL decrypt — legacy path.
    // Modern clients send `x-seal-session` instead.
    let delegate_key_hex = headers
        .get("x-delegate-key")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Optional SEAL SessionKey (base64 JSON) — replaces `x-delegate-key` on
    // the wire. When present, it is preferred over `delegate_key_hex` for
    // any SEAL decrypt operation. Phase 1 of the migration: both headers
    // are accepted so existing SDKs continue to work unchanged.
    let seal_session = headers
        .get("x-seal-session")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if seal_session.is_some() && delegate_key_hex.is_some() {
        tracing::debug!(
            "both x-seal-session and x-delegate-key present; preferring x-seal-session"
        );
    }
    if seal_session.is_none() && delegate_key_hex.is_some() {
        // Deprecation telemetry: log (without value) so we can count legacy
        // header usage per SDK version during the deprecation window.
        tracing::warn!(
            target: "memwal::deprecation",
            "request using legacy x-delegate-key header — client should upgrade to SDK v0.4+ (x-seal-session)"
        );
    }

    // Extract nonce for replay protection.
    // Nonce must be a UUID, checked against Redis to prevent replay attacks.
    // Its TTL is kept strictly greater than the timestamp window (see the SET
    // below) so no replay is possible once the fresh window closes.
    let nonce = headers
        .get("x-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!(
                target: "memwal::deprecation",
                "request missing x-nonce; rejecting unsupported legacy SDK"
            );
            unsupported_legacy_sdk()
        })?
        .to_string();

    // Validate nonce is UUID format (prevents injection attacks)
    if uuid::Uuid::parse_str(&nonce).is_err() {
        tracing::warn!(
            "Invalid nonce format (not UUID): {}",
            &nonce[..nonce.len().min(36)]
        );
        return Err(constant_time_reject().await);
    }

    // Validate timestamp freshness against the configured drift window.
    // Use checked_sub to avoid potential overflow with user-supplied timestamps
    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let now = chrono::Utc::now().timestamp();
    let age = now.checked_sub(timestamp).unwrap_or(i64::MAX);
    let drift = state.config.auth_max_clock_drift_secs;
    if !is_timestamp_fresh(age, drift) {
        tracing::warn!(
            "Request timestamp outside ±{}s window: {} (now: {}, age: {})",
            drift,
            timestamp,
            now,
            age,
        );
        // Timestamp failures are timing-normalized like every other auth reject,
        // but carry a machine-readable reason so a drifted client clock is
        // distinguishable from a bad signature (safe: the check is independent
        // of any server-side identity state).
        return Ok(constant_time_reject_with_reason(ERR_TIMESTAMP_OUT_OF_BOUNDS).await);
    }

    // Decode public key
    let pk_bytes = hex::decode(&public_key_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let pk_array: [u8; 32] = pk_bytes.try_into().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Canonicalize to lowercase hex derived from the decoded bytes, not the
    // caller-supplied header string: `hex::decode` above accepts mixed-case
    // input, so without this the same delegate key could vary casing across
    // requests to obtain independent identities for account-resolution
    // caching and — most importantly — the read-API rate limiter's per-key
    // Redis bucket (`rate:read:dk:{public_key}` in rate_limit.rs), trivially
    // defeating that abuse-prevention control. Every downstream use of
    // `public_key_hex` (cache keys, `AuthInfo.public_key`, logging) must see
    // this canonical form, not the raw header value.
    let public_key_hex = hex::encode(pk_array);

    // Decode signature
    let sig_bytes = hex::decode(&signature_hex).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let signature = Signature::from_bytes(&sig_array);

    // Build the signed message: "{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}"
    // Include query parameters in signed message to prevent query-param tampering
    let method = request.method().as_str().to_string();
    let path = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());

    // Split request to consume body
    let (mut parts, body) = request.into_parts();

    let body_bytes = axum::body::to_bytes(body, PROTECTED_BODY_LIMIT_BYTES)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let body_hash = hex::encode(Sha256::digest(&body_bytes));
    // Include nonce in signed message to prevent replay attacks.
    // Include x-account-id in the signed canonical message so an
    //         intermediary cannot swap the account hint. The header MUST be
    //         present — the SDK now always sends it. If absent we use an
    //         empty string so the signature will mismatch and the request
    //         is rejected below.
    //
    // The canonical message below is the single source of truth for this
    // format: any change to it must land in lockstep with the SDK signing
    // code in packages/sdk/src/{memwal,manual}.ts, or every signed request
    // from an unmatched SDK will fail verification.
    //
    // Canonical format:
    //   "{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}"
    let account_id_for_sig = account_id_hint.clone().unwrap_or_default();
    let message = format!(
        "{}.{}.{}.{}.{}.{}",
        timestamp_str, method, path, body_hash, nonce, account_id_for_sig
    );

    // Step 1: Verify Ed25519 signature
    // Use constant_time_reject so signature failures take the same wall-clock
    // time as account-resolution failures, preventing differential timing attacks.
    if verifying_key
        .verify(message.as_bytes(), &signature)
        .is_err()
    {
        tracing::warn!("Signature verification failed for key: {}", public_key_hex);
        return Err(constant_time_reject().await);
    }

    tracing::debug!("signature verified for key: {}", public_key_hex);

    // Check and record nonce in Redis to block replays.
    // Done AFTER signature verify so we don't waste Redis writes on bad requests.
    {
        let nonce_key = format!("nonce:{}", nonce);
        let mut redis = state.redis.clone();

        // Nonce record must outlive the timestamp window so a signature can't be
        // replayed after its nonce entry expires while still inside the fresh
        // window. `nonce_ttl_secs` derives TTL from the window so the invariant
        // holds no matter how the drift window is tuned.
        let ttl = nonce_ttl_secs(drift);

        // SET nonce_key "1" EX <ttl> NX — only set if Not eXists
        let set_result: Option<String> = redis
            .set_options(
                &nonce_key,
                "1",
                redis::SetOptions::default()
                    .conditional_set(redis::ExistenceCheck::NX)
                    .with_expiration(redis::SetExpiry::EX(ttl)),
            )
            .await
            .unwrap_or(None); // A Redis error maps to None here, which is
                              // indistinguishable from "nonce already seen" below —
                              // i.e. the request is REJECTED (fail-CLOSED). That is
                              // deliberate: replay protection holds even when Redis
                              // is down, at the availability cost that a Redis
                              // outage 401s all signed traffic through this
                              // middleware until Redis recovers.

        if set_result.is_none() {
            // NX failed = nonce already exists = replay attempt
            tracing::warn!(
                "Replay attack detected: nonce {} already seen (key={}...)",
                nonce,
                &public_key_hex[..16.min(public_key_hex.len())]
            );
            // uniform timing even for replay rejections
            return Err(constant_time_reject().await);
        }
    }

    // Step 2: Resolve account — cache, then the signed account id or
    // MEMWAL_ACCOUNT_ID. No registry scan.
    // Identity failures stay on constant_time_reject (bare 401) so "account not
    // found" vs "key not in account" cannot be timed. RPC/scan unavailability
    // is 503: a Sui 429 is not a revoke (WALM-429).
    let (account_id, owner) =
        match resolve_account(&state, &public_key_hex, &pk_array, account_id_hint).await {
            Ok(pair) => pair,
            Err(AccountResolveError::Unavailable(e)) => {
                tracing::warn!("Account resolution unavailable: {}", e);
                return Ok(upstream_unavailable());
            }
            Err(AccountResolveError::Unauthorized(e)) => {
                tracing::warn!("Account resolution failed: {}", e);
                return Err(constant_time_reject().await);
            }
        };

    tracing::debug!("account resolved: {} (owner: {})", account_id, owner);

    // Store auth info in request extensions
    parts.extensions.insert(AuthInfo {
        public_key: public_key_hex,
        owner,
        account_id,
        delegate_key: delegate_key_hex,
        seal_session,
    });

    // Rebuild request with the body re-injected
    let request = Request::from_parts(parts, axum::body::Body::from(body_bytes));

    Ok(next.run(request).await)
}

/// Whether the cached row for a delegate key may answer *this* request.
///
/// `delegate_key_cache.public_key` is the primary key, so the cache holds one
/// account per delegate key: whichever resolved last. A key can be registered
/// on several accounts, so that row is not necessarily the account the caller
/// asked for.
///
/// `x-account-id` is covered by the signed canonical message, so when it is
/// present it is the caller's unforgeable statement of which account this
/// request is for — it selects the account, it does not merely hint at one. A
/// row naming a different account must not answer, or the request runs against
/// an account the caller never asked for (WALM-681).
///
/// With no signed account id there is nothing to contradict: legacy discovery
/// keeps its existing behaviour.
fn cached_row_answers_request(cached_account_id: &str, requested_account_id: Option<&str>) -> bool {
    match requested_account_id {
        Some(requested) => requested == cached_account_id,
        None => true,
    }
}

/// Resolve a delegate key to its account.
///
/// 1. PostgreSQL cache.
/// 2. Signed `x-account-id`, or `MEMWAL_ACCOUNT_ID` when the header is absent.
///    Either way this is one object read, not a registry walk.
///
/// A cold key with no account id is rejected. A successful resolution is
/// cached for later requests.
#[tracing::instrument(name = "auth.resolve_account", skip_all)]
async fn resolve_account(
    state: &AppState,
    public_key_hex: &str,
    pk_bytes: &[u8; 32],
    account_id_hint: Option<String>,
) -> Result<(String, String), AccountResolveError> {
    // Strategy 1: Check PostgreSQL cache.
    //
    // The cache is keyed by delegate key alone (`delegate_key_cache.public_key`
    // is the primary key), so it holds exactly one account per key: whichever
    // one resolved last. A key may be registered on several accounts, and
    // `x-account-id` is part of the signed canonical message, so the caller has
    // told us — unforgeably — which of those accounts this request is for.
    // Answering from a row that names a *different* account would run the
    // request against an account the caller did not ask for, and the write
    // routes take their owner and account id from this result: B's data would
    // land in A (WALM-681).
    //
    // So a mismatched row is not a hit. Fall through to Strategy 2, which
    // verifies the requested account directly and then overwrites this row.
    // The extra work is one delegate verify, which the in-memory verify cache
    // absorbs within its TTL. Requests with no signed hint keep the old
    // behaviour: legacy account discovery is a separate path, unchanged here.
    let cached_mapping = match state.db.get_cached_account(public_key_hex).await {
        Ok(Some((cached_account_id, cached_owner))) => {
            if cached_row_answers_request(&cached_account_id, account_id_hint.as_deref()) {
                Some((cached_account_id, cached_owner))
            } else {
                tracing::debug!(
                    "cached account {} does not match the signed x-account-id; \
                     verifying the requested account instead of answering from cache",
                    cached_account_id
                );
                None
            }
        }
        _ => None,
    };

    if let Some((cached_account_id, _cached_owner)) = cached_mapping {
        // Re-verify the cached mapping, through the in-memory verify cache.
        // A hit inside `DELEGATE_VERIFY_CACHE_TTL` answers without touching
        // Sui at all — including during an outage — so the fail-closed rule
        // below now applies to a live read, not to every request. That 30s
        // window is the stated revocation bound.
        //
        // On a live miss: a transient RPC failure is *not* a revoke, so keep
        // the Postgres row and fail closed with 503 rather than let a revoked
        // key ride the 24h cache through an outage. A definitive miss evicts
        // both caches.
        match cache_reverify_action(
            verify_delegate_key_cached(
                &state.delegate_verify_cache,
                &state.delegate_reject_cache,
                &state.http_client,
                &state.config.sui_rpc_url,
                state.sui_grpc_client.as_ref(),
                &cached_account_id,
                pk_bytes,
                &state.config.package_id,
            )
            .await,
        ) {
            CacheReverifyAction::Authenticate { owner } => {
                tracing::debug!("account resolved from cache: {}", cached_account_id);
                return Ok((cached_account_id, owner));
            }
            CacheReverifyAction::UnavailableKeepCache { reason } => {
                tracing::warn!(
                    "on-chain re-verify unavailable for key {} on account {} ({}); keeping cached mapping, not authenticating from it",
                    public_key_hex,
                    cached_account_id,
                    reason
                );
                return Err(AccountResolveError::Unavailable(format!(
                    "on-chain re-verify unavailable for cached account {}: {}",
                    cached_account_id, reason
                )));
            }
            CacheReverifyAction::Evict { reason } => {
                tracing::warn!(
                    "cached delegate key {} is stale for account {} ({}); evicting from cache",
                    public_key_hex,
                    cached_account_id,
                    reason
                );
                let _ = state.db.delete_cached_key(public_key_hex).await;
            }
        }
    }

    // Strategy 2: signed x-account-id, or MEMWAL_ACCOUNT_ID when the header
    // is absent. The id is part of the canonical signature, so an
    // intermediary cannot swap it. This reads that one account object.
    if let Some(exact_account_id) = account_id_hint
        .as_deref()
        .or(state.config.memwal_account_id.as_deref())
    {
        match verify_delegate_key_cached(
            &state.delegate_verify_cache,
            &state.delegate_reject_cache,
            &state.http_client,
            &state.config.sui_rpc_url,
            state.sui_grpc_client.as_ref(),
            exact_account_id,
            pk_bytes,
            &state.config.package_id,
        )
        .await
        {
            Ok(owner) => {
                let _ = state
                    .db
                    .cache_delegate_key(public_key_hex, exact_account_id, &owner)
                    .await;

                tracing::debug!(
                    "account resolved from exact account id: {}",
                    exact_account_id
                );
                return Ok((exact_account_id.to_string(), owner));
            }
            Err(e) if e.is_unavailable() => {
                return Err(AccountResolveError::Unavailable(format!(
                    "exact account {} verification unavailable: {}",
                    exact_account_id, e
                )));
            }
            Err(e) => {
                return Err(AccountResolveError::Unauthorized(format!(
                    "exact account {} verification failed: {}",
                    exact_account_id, e
                )));
            }
        }
    }

    // No signed account id and no MEMWAL_ACCOUNT_ID. Do not scan
    // AccountRegistry. A cached key already returned above. Every network
    // takes this path: testnet has no JSON-RPC, and mainnet's registry is
    // too long for a sequential scan to finish inside a client timeout.
    Err(AccountResolveError::Unauthorized(
        "x-account-id is required for delegate-key authentication".to_string(),
    ))
}

/// Combined auth dispatcher for `read_api_routes`: tries the owner-scoped
/// bearer token (Console) when `Authorization: Bearer` is present, otherwise falls
/// back to the unmodified Ed25519 signed-request scheme (SDK/dashboard delegate-key
/// callers). The two calling populations are disjoint by construction — Console never
/// holds a delegate key, the SDK never sends `Authorization` — so presence of that
/// header alone is a safe, unambiguous dispatch key.
///
/// NOTE: if a request ever carried both a full Ed25519 header set AND an
/// `Authorization: Bearer` header, the bearer branch wins unconditionally; the
/// Ed25519 headers are never consulted. This is fine while the two populations stay
/// disjoint — flagging here so a future proxy/gateway that auto-attaches
/// `Authorization` doesn't silently break signed requests on this router only.
#[tracing::instrument(name = "auth.verify_read_api_auth", skip_all)]
pub async fn verify_read_api_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);

    let Some(token) = bearer else {
        return verify_signature(State(state), request, next).await;
    };

    if state.config.owner_token_secret.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let claims = owner_token_auth::verify_token(
        state.config.owner_token_secret.as_bytes(),
        &token,
        chrono::Utc::now().timestamp(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !owner_token_has_scope(&claims, owner_token_auth::PERMISSION_MEMORIES_READ) {
        tracing::warn!(owner = %claims.owner_address, "owner token missing memories.read");
        return Err(StatusCode::FORBIDDEN);
    }

    // claims.owner_address is already canonical lowercase (issue_token validated +
    // lowercased before minting) — do not re-lowercase.
    let account_id = match state.db.find_account_by_owner(&claims.owner_address).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            // Valid token, but the backing account no longer resolves (e.g. deleted
            // between mint and use). Mirrors verify_signature's own "account not
            // found" resolution failure: bare 401, not 403 — this codebase reserves
            // 403 (AppError::Forbidden) strictly for "identity resolved but doesn't
            // own this path", never for "doesn't exist".
            tracing::warn!(owner = %claims.owner_address, "owner token account no longer resolves");
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            tracing::warn!("owner token account lookup failed: {}", e);
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Enforce live on-chain `active == true` (cached via `DelegateVerifyCache` /
    // `DelegateRejectCache`) so a deactivated account cannot keep serving metadata
    // over `/v1/owners/{owner}/{namespaces,memories,agents}` using an unexpired
    // owner token (#1051).
    match crate::storage::sui::verify_account_active_cached(
        &state.delegate_verify_cache,
        &state.delegate_reject_cache,
        &state.http_client,
        &state.config.sui_rpc_url,
        state.sui_grpc_client.as_ref(),
        &account_id,
        &state.config.package_id,
    )
    .await
    {
        Ok(onchain_owner) => {
            if !crate::security_delete_auth::same_owner(Some(&onchain_owner), &claims.owner_address)
            {
                tracing::warn!(
                    account_id = %account_id,
                    token_owner = %claims.owner_address,
                    onchain_owner = %onchain_owner,
                    "owner token account owner mismatch on-chain"
                );
                state.delegate_keys_cache.write().await.remove(&account_id);
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Err(e) if e.is_unavailable() => {
            tracing::warn!(
                account_id = %account_id,
                owner = %claims.owner_address,
                error = %e,
                "owner token account active verification unavailable"
            );
            return Ok(upstream_unavailable());
        }
        Err(e) => {
            tracing::warn!(
                account_id = %account_id,
                owner = %claims.owner_address,
                error = %e,
                "owner token account active verification rejected"
            );
            state.delegate_keys_cache.write().await.remove(&account_id);
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let mut request = request;
    request
        .extensions_mut()
        .insert(owner_token_to_auth_info(claims, account_id));
    Ok(next.run(request).await)
}

fn owner_token_has_scope(claims: &owner_token_auth::OwnerTokenClaims, required: &str) -> bool {
    claims.permissions.iter().any(|p| p == required)
}

fn owner_token_to_auth_info(
    claims: owner_token_auth::OwnerTokenClaims,
    account_id: String,
) -> AuthInfo {
    AuthInfo {
        // Not a real hex Ed25519 key. read_api_rate_limit_middleware keys its Redis
        // bucket solely on `public_key` (`rate:read:dk:{public_key}`) — an
        // empty/constant value here would collapse every Console-proxied owner into
        // one shared bucket. The `ownertoken:` prefix keeps buckets isolated per
        // owner and can never collide with a real 64-hex-char key (hex has no `:`).
        public_key: format!("ownertoken:{}", claims.owner_address),
        owner: claims.owner_address,
        account_id,
        delegate_key: None,
        seal_session: None,
    }
}

#[tracing::instrument(name = "auth.verify_admin_key", skip_all)]
pub async fn verify_admin_key(request: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = request.headers();

    let api_key = headers
        .get("x-admin-api-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let expected_key = std::env::var("ADMIN_API_KEY").map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !admin_api_key_is_configured(&expected_key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !constant_time_compare(api_key.as_bytes(), expected_key.as_bytes()) {
        return Err(constant_time_reject().await);
    }

    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(response)
}

pub(crate) fn admin_api_key_is_configured(key: &str) -> bool {
    !key.trim().is_empty()
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    let mut result = (a.len() ^ b.len()) as usize;
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        result |= (x ^ y) as usize;
    }
    result == 0
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_body_limit_allows_one_mb_remember_json() {
        let body = serde_json::json!({
            "text": "a".repeat(1024 * 1024),
            "namespace": "default",
        })
        .to_string();

        assert!(body.len() > 1024 * 1024);
        assert!(body.len() <= PROTECTED_BODY_LIMIT_BYTES);
    }

    // ── Nonce must be valid UUID v4 ──────────────────────────────

    #[test]
    fn nonce_valid_uuid_accepted() {
        let nonce = "550e8400-e29b-41d4-a716-446655440000";
        assert!(uuid::Uuid::parse_str(nonce).is_ok());
    }

    #[test]
    fn nonce_invalid_format_rejected() {
        let bad_nonces = [
            "",
            "not-a-uuid",
            "12345",
            "550e8400-e29b-41d4-a716",              // truncated
            "ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ", // non-hex
            "../../../etc/passwd",                  // injection attempt
        ];
        for nonce in bad_nonces {
            assert!(
                uuid::Uuid::parse_str(nonce).is_err(),
                "should reject nonce: {:?}",
                nonce,
            );
        }
    }

    // ── checked_sub prevents overflow ───────────────────────────

    #[test]
    fn checked_sub_handles_underflow() {
        // Attacker sends timestamp = i64::MAX, now is a small positive number
        // 1700000000 - i64::MAX is a large negative number (no overflow),
        // but it's far outside the ±300s window → request rejected.
        let now: i64 = 1700000000;
        let timestamp: i64 = i64::MAX;
        let age = now.checked_sub(timestamp).unwrap_or(i64::MAX);
        // age is a huge negative value, well below -300
        assert!(age < -300, "age {} should be less than -300", age);
    }

    #[test]
    fn checked_sub_handles_negative_overflow() {
        // Attacker sends timestamp = i64::MIN
        let now: i64 = 1700000000;
        let timestamp: i64 = i64::MIN;
        let age = now.checked_sub(timestamp).unwrap_or(i64::MAX);
        // i64::MIN wraps — checked_sub returns None → i64::MAX
        assert_eq!(age, i64::MAX);
    }

    #[test]
    fn checked_sub_normal_case_passes() {
        let now: i64 = 1700000100;
        let timestamp: i64 = 1700000000;
        let age = now.checked_sub(timestamp).unwrap_or(i64::MAX);
        assert_eq!(age, 100);
        assert!(age <= 300); // within window
    }

    #[test]
    fn checked_sub_future_timestamp_within_window() {
        let now: i64 = 1700000000;
        let timestamp: i64 = 1700000200; // 200s in the future
        let age = now.checked_sub(timestamp).unwrap_or(i64::MAX);
        assert_eq!(age, -200);
        assert!(age >= -300); // within ±300s window
    }

    #[test]
    fn checked_sub_exactly_at_boundary() {
        let now: i64 = 1700000000;

        // Exactly at +300s boundary — should be accepted (age == 300, not > 300)
        let timestamp_past = now - 300;
        let age_past = now.checked_sub(timestamp_past).unwrap_or(i64::MAX);
        assert_eq!(age_past, 300);
        // The check is `!(-300..=300).contains(&age)`, so exactly 300 passes
        assert!((-300..=300).contains(&age_past));

        // At +301s — should be rejected
        let timestamp_expired = now - 301;
        let age_expired = now.checked_sub(timestamp_expired).unwrap_or(i64::MAX);
        assert_eq!(age_expired, 301);
        assert!(age_expired > 300);
    }

    // ── Configurable drift window (exercises the real predicate) ─

    #[test]
    fn drift_window_boundaries_are_inclusive_and_symmetric() {
        let drift = 120;
        assert!(is_timestamp_fresh(drift, drift)); // exactly +window accepted
        assert!(is_timestamp_fresh(-drift, drift)); // exactly -window accepted
        assert!(!is_timestamp_fresh(drift + 1, drift)); // just past → rejected
        assert!(!is_timestamp_fresh(-(drift + 1), drift)); // just past (future) → rejected
    }

    #[test]
    fn drift_window_zero_requires_exact_second() {
        assert!(is_timestamp_fresh(0, 0));
        assert!(!is_timestamp_fresh(1, 0));
        assert!(!is_timestamp_fresh(-1, 0));
    }

    #[test]
    fn reported_repro_45s_offset_is_within_default_window() {
        // The issue's repro used a +45s client offset; it is comfortably inside
        // the default 300s window and is accepted (i.e. does not reproduce).
        assert!(is_timestamp_fresh(
            45,
            crate::types::DEFAULT_AUTH_CLOCK_DRIFT_SECS
        ));
        assert!(is_timestamp_fresh(
            -45,
            crate::types::DEFAULT_AUTH_CLOCK_DRIFT_SECS
        ));
    }

    #[test]
    fn nonce_ttl_covers_full_future_dated_freshness_lifetime() {
        // Exercises the real `nonce_ttl_secs` used at the Redis call site, so a
        // regression is caught here, not hidden behind a duplicated formula.
        //
        // Worst case (the one a naive `drift + buffer` TTL misses): a request
        // signed for `T` is first accepted as early as `now = T - drift`
        // (future-dated), and stays fresh until `now = T + drift`. The nonce
        // record, written at first acceptance, must still exist at the end of
        // that window, i.e. its TTL must cover the full `2 * drift` span so no
        // replay slips through after it expires.
        for drift in [0i64, 45, 300, 600, crate::types::MAX_AUTH_CLOCK_DRIFT_SECS] {
            let first_seen_at = -drift; // now = T - drift, relative to T
            let fresh_until = drift; //    now = T + drift, relative to T
            let nonce_expires_at = first_seen_at + nonce_ttl_secs(drift) as i64;
            assert!(
                nonce_expires_at > fresh_until,
                "drift {drift}: nonce expires at {nonce_expires_at} but request is \
                 fresh through {fresh_until} — replay gap"
            );
        }
        // Pin the exact derivation at default and ceiling so it cannot regress:
        //   default: 2*300 + 300 = 900
        //   ceiling: 2*900 + 300 = 2100
        assert_eq!(
            nonce_ttl_secs(crate::types::DEFAULT_AUTH_CLOCK_DRIFT_SECS),
            900
        );
        assert_eq!(
            nonce_ttl_secs(crate::types::MAX_AUTH_CLOCK_DRIFT_SECS),
            2100
        );
    }

    // ── Timestamp-drift reason header (safe to distinguish) ──────

    #[tokio::test]
    async fn timestamp_reject_carries_reason_header_and_401() {
        let resp = constant_time_reject_with_reason(ERR_TIMESTAMP_OUT_OF_BOUNDS).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("x-auth-error")
                .and_then(|v| v.to_str().ok()),
            Some("ERR_TIMESTAMP_OUT_OF_BOUNDS"),
        );
    }

    #[tokio::test]
    async fn identity_reject_carries_no_reason_header() {
        // Signature/nonce/account failures must stay indistinguishable: the bare
        // 401 from constant_time_reject exposes no x-auth-error, so it can't be
        // used to tell "bad signature" from "account not found".
        let status = constant_time_reject().await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ── Query parameters included in signed message ──────────────

    #[test]
    fn signed_message_includes_query_params() {
        // Simulate what the middleware does: use path_and_query
        let uri: axum::http::Uri = "/api/recall?limit=999".parse().unwrap();
        let path = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string());

        assert_eq!(path, "/api/recall?limit=999");
        // The full query string is part of the message → signature covers it
    }

    #[test]
    fn signed_message_without_query_uses_path_only() {
        let uri: axum::http::Uri = "/api/remember".parse().unwrap();
        let path = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| uri.path().to_string());

        assert_eq!(path, "/api/remember");
    }

    // ── constant_time_reject returns 401 ─────────────────────────

    #[tokio::test]
    async fn constant_time_reject_returns_unauthorized() {
        let status = constant_time_reject().await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn upstream_unavailable_is_503_not_401() {
        let resp = upstream_unavailable();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get("x-auth-error")
                .and_then(|v| v.to_str().ok()),
            Some(AUTH_UPSTREAM_UNAVAILABLE),
        );
        let retry_after = AUTH_UPSTREAM_RETRY_AFTER_SECS.to_string();
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some(retry_after.as_str()),
        );
        assert_eq!(AUTH_UPSTREAM_RETRY_AFTER_SECS, 5);
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(&body[..], b"upstream unavailable");
    }

    #[test]
    fn resolve_account_cache_hit_rpc_error_keeps_row_without_authenticating() {
        // WALM-429: a Sui 429 used to evict the cache and 401 a live key.
        // Keep the row (so a later verify can succeed) but do not treat the
        // cached mapping as authorization while the chain is unreachable.
        let action = cache_reverify_action(Err(OnchainVerifyError::RpcError(
            "gRPC GetObject failed: 429 Too Many Requests".into(),
        )));
        assert!(matches!(
            action,
            CacheReverifyAction::UnavailableKeepCache { .. }
        ));
    }

    // ── signed x-account-id selects the account, cache cannot override ──

    #[test]
    fn cached_row_answers_request_when_signed_account_matches() {
        assert!(cached_row_answers_request(
            "0xaccount_a",
            Some("0xaccount_a")
        ));
    }

    #[test]
    fn cached_row_is_ignored_when_signed_account_differs() {
        // WALM-681: one delegate key may be registered on several accounts, but
        // the cache holds only the one that resolved last. Answering from it
        // would run a request signed for B against A, and the write routes take
        // their owner/account id from this result — B's memory would be stored
        // under A. A mismatched row is not a hit; Strategy 2 verifies the
        // account that was actually requested.
        assert!(!cached_row_answers_request(
            "0xaccount_a",
            Some("0xaccount_b")
        ));
    }

    #[test]
    fn cached_row_answers_request_when_no_account_was_signed() {
        // Legacy clients that send no x-account-id keep the old behaviour:
        // there is no signed statement to contradict the cached row.
        assert!(cached_row_answers_request("0xaccount_a", None));
    }

    #[test]
    fn cached_row_match_is_exact_not_prefix() {
        // Account ids are compared whole. A longer id that merely starts with a
        // cached one is a different object.
        assert!(!cached_row_answers_request(
            "0xaccount",
            Some("0xaccount_b")
        ));
        assert!(!cached_row_answers_request(
            "0xaccount_b",
            Some("0xaccount")
        ));
    }

    #[test]
    fn alternating_accounts_each_resolve_to_the_requested_one() {
        // The account switch the ticket asks to cover: with the cache warm on A,
        // a request for B must not be answered from it, and once the row has
        // been overwritten with B, a request for A must not be answered either.
        // Neither direction may inherit the other's account.
        let warm_on_a = "0xaccount_a";
        assert!(cached_row_answers_request(warm_on_a, Some("0xaccount_a")));
        assert!(!cached_row_answers_request(warm_on_a, Some("0xaccount_b")));

        let warm_on_b = "0xaccount_b";
        assert!(cached_row_answers_request(warm_on_b, Some("0xaccount_b")));
        assert!(!cached_row_answers_request(warm_on_b, Some("0xaccount_a")));
    }

    #[test]
    fn resolve_account_cache_hit_key_not_found_evicts() {
        let action = cache_reverify_action(Err(OnchainVerifyError::KeyNotFound("gone".into())));
        assert!(matches!(action, CacheReverifyAction::Evict { .. }));
    }

    #[test]
    fn resolve_account_cache_hit_object_not_found_evicts() {
        // Typo'd x-account-id / gRPC NOT_FOUND is a sign-in failure, not a 503.
        let action = cache_reverify_action(Err(OnchainVerifyError::NotFound(
            "gRPC GetObject failed: not found".into(),
        )));
        assert!(matches!(action, CacheReverifyAction::Evict { .. }));
    }

    #[test]
    fn resolve_account_cache_hit_ok_authenticates() {
        match cache_reverify_action(Ok("0xowner".into())) {
            CacheReverifyAction::Authenticate { owner } => assert_eq!(owner, "0xowner"),
            other => panic!("expected authenticate, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_legacy_sdk_returns_upgrade_required() {
        assert_eq!(unsupported_legacy_sdk(), StatusCode::UPGRADE_REQUIRED);
    }

    // ── account_id included in signed canonical message ─────────

    #[test]
    fn canonical_message_format_with_account_id() {
        let timestamp = "1700000000";
        let method = "POST";
        let path = "/api/remember";
        let body_hash = "abc123";
        let nonce = "550e8400-e29b-41d4-a716-446655440000";
        let account_id = "0xdeadbeef";

        let message = format!(
            "{}.{}.{}.{}.{}.{}",
            timestamp, method, path, body_hash, nonce, account_id
        );

        assert_eq!(
            message,
            "1700000000.POST./api/remember.abc123.550e8400-e29b-41d4-a716-446655440000.0xdeadbeef"
        );
        // Verify all 6 fields are present
        assert_eq!(message.matches('.').count(), 5);
    }

    #[test]
    fn canonical_message_without_account_id_uses_empty_string() {
        let account_id_for_sig = String::new();

        let message = format!(
            "{}.{}.{}.{}.{}.{}",
            "1700000000", "POST", "/api/recall", "hash", "nonce", account_id_for_sig
        );

        // Ends with a dot and empty string — will mismatch if client sends an actual account_id
        assert!(message.ends_with('.'));
    }

    // ── Full signature + nonce verification flow ─────────────────

    #[test]
    fn signed_message_all_fields_present() {
        // Verify the canonical format: "{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}"
        let parts = [
            "1700000000",
            "POST",
            "/api/analyze?ns=work",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        ];
        let message = parts.join(".");
        // Must have exactly 6 fields separated by 5 dots
        assert_eq!(message.split('.').count(), 6);
        // Nonce field (5th) must be a valid UUID
        let nonce_field = message.split('.').nth(4).unwrap();
        assert!(uuid::Uuid::parse_str(nonce_field).is_ok());
    }

    // ── Ed25519 signature verification integration ──────────────────────

    /// Helper: create a deterministic Ed25519 signing key for tests.
    /// Uses a fixed 32-byte secret key — NOT for production use.
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        let secret: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        ed25519_dalek::SigningKey::from_bytes(&secret)
    }

    // ── Public-key casing must canonicalize ─────────────────────────────
    //
    // `hex::decode` accepts mixed-case input, but `AuthInfo.public_key` (and
    // everything keyed by it downstream: account-resolution cache lookups,
    // and — the actual security-relevant one — read_api_rate_limit_middleware's
    // per-key Redis bucket `rate:read:dk:{public_key}`) must see one
    // canonical string per key, or the same delegate key could vary casing
    // to get a fresh rate-limit bucket on every request. The fix re-encodes
    // from the decoded bytes (`hex::encode(pk_array)`) rather than trusting
    // the caller-supplied header string — this pins that invariant directly,
    // independent of the full request pipeline.
    #[test]
    fn public_key_hex_canonicalizes_regardless_of_input_casing() {
        let lower = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(lower.len(), 64, "fixture must be exactly 32 bytes of hex");
        let upper = lower.to_ascii_uppercase();
        let mixed = "0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef";

        let canon_from = |s: &str| {
            let bytes = hex::decode(s).unwrap();
            let array: [u8; 32] = bytes.try_into().unwrap();
            hex::encode(array)
        };

        let canonical = canon_from(lower);
        assert_eq!(
            canonical, lower,
            "lowercase input should already be canonical"
        );
        assert_eq!(
            canon_from(&upper),
            canonical,
            "uppercase input must canonicalize to the same string as lowercase"
        );
        assert_eq!(
            canon_from(mixed),
            canonical,
            "mixed-case input must canonicalize to the same string as lowercase"
        );
    }

    #[test]
    fn ed25519_roundtrip_signature_verification() {
        use ed25519_dalek::Signer;

        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();

        let message =
            "1700000000.POST./api/remember.abc123.f47ac10b-58cc-4372-a567-0e02b2c3d479.0xdead";
        let signature = signing_key.sign(message.as_bytes());

        // Valid signature passes
        assert!(verifying_key.verify(message.as_bytes(), &signature).is_ok());

        // Tampered message fails
        let tampered =
            "1700000001.POST./api/remember.abc123.f47ac10b-58cc-4372-a567-0e02b2c3d479.0xdead";
        assert!(verifying_key
            .verify(tampered.as_bytes(), &signature)
            .is_err());
    }

    #[test]
    fn ed25519_wrong_nonce_fails_verification() {
        use ed25519_dalek::Signer;

        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();

        let nonce1 = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        let nonce2 = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

        let msg1 = format!("1700000000.POST./api/remember.hash.{}.0xdead", nonce1);
        let signature = signing_key.sign(msg1.as_bytes());

        // Replacing nonce = replay with different nonce → signature fails
        let msg2 = format!("1700000000.POST./api/remember.hash.{}.0xdead", nonce2);
        assert!(verifying_key.verify(msg2.as_bytes(), &signature).is_err());
    }

    #[test]
    fn ed25519_wrong_account_id_fails_verification() {
        use ed25519_dalek::Signer;

        let signing_key = test_signing_key();
        let verifying_key = signing_key.verifying_key();

        let msg = "1700000000.POST./api/recall.hash.nonce.0xaccount_a";
        let signature = signing_key.sign(msg.as_bytes());

        // Swapping account_id makes signature verification fail.
        let swapped = "1700000000.POST./api/recall.hash.nonce.0xaccount_b";
        assert!(verifying_key
            .verify(swapped.as_bytes(), &signature)
            .is_err());
    }

    // ── Manual-mode trust boundary ────────────────────────────
    //
    // Manual-mode routes (/api/remember/manual, /api/recall/manual) must
    // succeed without the `x-delegate-key` header. The SDK no longer emits
    // this header on those routes (packages/sdk/src/memwal.ts), and Manual-
    // mode route handlers (services/server/src/routes.rs) never read
    // `AuthInfo.delegate_key`. This test locks in the invariant that
    // `AuthInfo` is valid with `delegate_key: None` so a future refactor
    // cannot silently re-introduce a requirement on the header.

    #[test]
    fn auth_info_valid_without_delegate_key_for_manual_routes() {
        let auth = AuthInfo {
            public_key: "abcd".to_string(),
            owner: "0xowner".to_string(),
            account_id: "0xaccount".to_string(),
            delegate_key: None,
            seal_session: None,
        };
        assert!(auth.delegate_key.is_none());
        assert!(auth.seal_session.is_none());
        // Verify Debug impl still redacts — even in
        // Manual mode we must never leak any credential material in logs.
        let debug_str = format!("{:?}", auth);
        assert!(debug_str.contains("None"));
        assert!(!debug_str.contains("<redacted>"));
    }

    // ── Owner-token → AuthInfo bridge for read_api_routes ────────────────

    fn owner_token_claims(permissions: &[&str]) -> owner_token_auth::OwnerTokenClaims {
        owner_token_auth::OwnerTokenClaims {
            subject: "console".to_string(),
            owner_address: "0xabc".to_string(),
            audience: owner_token_auth::OWNER_TOKEN_AUDIENCE.to_string(),
            issued_at: 0,
            expires_at: i64::MAX,
            nonce: "00000000-0000-0000-0000-000000000000".to_string(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
        }
    }

    #[test]
    fn owner_token_to_auth_info_sets_ownertoken_prefixed_public_key() {
        let claims = owner_token_claims(&[owner_token_auth::PERMISSION_MEMORIES_READ]);
        let auth = owner_token_to_auth_info(claims, "0xaccount".to_string());
        assert_eq!(auth.public_key, "ownertoken:0xabc");
    }

    #[test]
    fn owner_token_to_auth_info_preserves_owner_and_account_id() {
        let claims = owner_token_claims(&[owner_token_auth::PERMISSION_MEMORIES_READ]);
        let auth = owner_token_to_auth_info(claims, "0xaccount".to_string());
        assert_eq!(auth.owner, "0xabc");
        assert_eq!(auth.account_id, "0xaccount");
    }

    #[test]
    fn owner_token_to_auth_info_never_sets_delegate_key_or_seal_session() {
        let claims = owner_token_claims(&[owner_token_auth::PERMISSION_MEMORIES_READ]);
        let auth = owner_token_to_auth_info(claims, "0xaccount".to_string());
        assert!(auth.delegate_key.is_none());
        assert!(auth.seal_session.is_none());
    }

    #[test]
    fn owner_token_has_scope_true_when_present() {
        let claims = owner_token_claims(&[owner_token_auth::PERMISSION_MEMORIES_READ]);
        assert!(owner_token_has_scope(
            &claims,
            owner_token_auth::PERMISSION_MEMORIES_READ
        ));
    }

    #[test]
    fn owner_token_has_scope_false_when_missing() {
        let claims = owner_token_claims(&["some.other.scope"]);
        assert!(!owner_token_has_scope(
            &claims,
            owner_token_auth::PERMISSION_MEMORIES_READ
        ));
    }

    #[test]
    fn owner_token_has_scope_false_when_empty() {
        let claims = owner_token_claims(&[]);
        assert!(!owner_token_has_scope(
            &claims,
            owner_token_auth::PERMISSION_MEMORIES_READ
        ));
    }

    #[test]
    fn ownertoken_prefix_cannot_collide_with_hex_ed25519_pubkey() {
        // Ed25519 public keys on the wire are 64 lowercase hex chars
        // (`x-public-key`, decoded via `hex::decode` above) — `[0-9a-f]` only,
        // no `:`. The synthetic sentinel this module mints always contains a
        // `:`, so it can never be mistaken for (or collide with) a real key.
        let synthetic = format!("ownertoken:{}", "0".repeat(64));
        assert!(synthetic.contains(':'));
        assert!(!synthetic.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn admin_key_configuration_rejects_empty_values() {
        assert!(!admin_api_key_is_configured(""));
        assert!(!admin_api_key_is_configured("   \t\n"));
        assert!(admin_api_key_is_configured("a-strong-secret"));
    }

    #[test]
    fn admin_key_comparison_requires_identical_bytes_and_length() {
        assert!(constant_time_compare(
            b"secret-key-12345",
            b"secret-key-12345"
        ));
        assert!(!constant_time_compare(
            b"secret-key-aaaaa",
            b"secret-key-bbbbb"
        ));
        assert!(!constant_time_compare(b"short", b"much-longer-key"));
    }
}

//! `POST /v1/owner-tokens` issuance (phase 1) + a minimal token-gated probe
//! route.
//!
//! Console has already proven (entirely on its own side; WM is never
//! involved) that a user controls a WM owner address `Y`.
//! It then calls `POST /v1/owner-tokens`, authenticating itself as a
//! legitimate client via the **service credential** (a single
//! static shared secret WM generates and hands to Console out of band;
//! mTLS and signed-client-assertion were explicitly considered and NOT
//! chosen), to mint a short-lived bearer
//! token scoped to `Y`. Console then presents that token as `Authorization:
//! Bearer <token>` to WM's owner-scoped read routes.
//!
//! `token_probe` was originally added as a minimal token-gated route so this
//! feature could be tested end-to-end before the real
//! `GET /v1/owners/{owner}/{namespaces,memories,agents}` handlers existed on
//! this branch. That wiring is now done: those handlers accept this same
//! bearer token via `auth::verify_read_api_auth` (`services/server/src/auth.rs`),
//! which dispatches between it and the existing Ed25519 signed-request
//! scheme based on whether the request carries an `Authorization` header.
//! `token_probe` itself is now redundant and left in place only as a
//! smoke-test artifact — a candidate for removal in a follow-up.

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::owner_token_auth::{self, OwnerToken, PERMISSION_MEMORIES_READ};
use crate::rate_limit::{self, SponsorRlResult};
use crate::routes::sponsor::validate_sui_address;
use crate::security_delete_auth::same_owner;
use crate::types::{AppError, AppState};

/// Header Console sends the shared WM↔Console service credential on.
/// Chosen to read clearly on the wire and
/// to follow this crate's existing lowercase-`x-*` convention for
/// auth-adjacent headers (`x-public-key`, `x-signature`, `x-account-id`,
/// ... — see `auth.rs`), same family as the sidecar's own shared-secret
/// header (`X-Sidecar-Secret`, `Config::sidecar_secret`).
pub const SERVICE_CREDENTIAL_HEADER: &str = "x-service-credential";

// ============================================================
// Constant-time secret comparison
// ============================================================

/// Constant-time equality for the service-credential comparison below. This
/// workspace has no `subtle` crate dependency (checked `Cargo.toml` — the
/// only crypto deps are `ed25519-dalek`, `sha2`, `hmac`, `hex`), and none of
/// the existing secret comparisons in this crate (`deletion_token_secret`
/// verification goes through HMAC `verify_slice`, which is already
/// constant-time; there is no existing *plain-secret* comparison to
/// mirror) provide one either. Rather than pull in a new dependency for a
/// single byte comparison, this hand-rolls the standard
/// equal-length-then-XOR-accumulate technique: unlike `==`, it does not
/// short-circuit on the first differing byte, so response timing cannot be
/// used to learn how many leading bytes of the guess were correct.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Axum middleware gating the whole `POST /v1/owner-tokens` router group.
/// Reads [`SERVICE_CREDENTIAL_HEADER`] and compares it against
/// `Config::owner_token_service_credential`. Missing header, wrong value,
/// or an unconfigured (empty) secret all collapse to a bare 401 with no
/// body — matching this crate's existing convention for auth failures (see
/// `auth::verify_signature`'s bare `StatusCode` rejections): no detail is
/// leaked about *why* the request was rejected.
pub async fn service_credential_gate(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let provided = request
        .headers()
        .get(SERVICE_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let configured = state.config.owner_token_service_credential.as_str();
    if configured.is_empty() || !constant_time_eq(provided.as_bytes(), configured.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

// The per-service-credential rate-limit middleware
// (`rate_limit::owner_token_credential_rate_limit_middleware`) lives in
// `rate_limit.rs` alongside every other limiter in this crate
// (`sponsor_rate_limit_middleware`, `accounts_rate_limit_middleware`) —
// wired directly from `main.rs`, not re-exported through this module.

// ============================================================
// POST /v1/owner-tokens
// ============================================================

#[derive(Debug, Deserialize)]
pub struct IssueOwnerTokenRequest {
    pub owner: String,
    /// Optional. Phase 1 only mints `memories.read`. Unknown values are 400
    /// so a caller cannot think they received a broader grant.
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
    /// Alias some clients send instead of `permissions`.
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IssueOwnerTokenResponse {
    pub token: String,
    /// RFC 3339 / ISO 8601 UTC timestamp, e.g. `"2026-08-04T12:15:00Z"`.
    pub expires_at: String,
    pub permissions: Vec<String>,
}

/// `POST /v1/owner-tokens` — mint a short-lived, owner-scoped bearer token.
///
/// Request: `{ "owner": "<sui address>" }`
/// Response (200): `{ "token": "...", "expires_at": "<ISO8601>",
/// "permissions": ["memories.read"] }`
///
/// Ordering: address format validation → configuration check → per-owner
/// rate limit → MemWalAccount existence check → mint. Format validation
/// runs first (cheapest, and avoids charging the rate-limit budget or
/// touching the DB for garbage input); the existence check runs last
/// (most expensive, a DB round trip) so it only runs for requests that
/// already cleared every cheaper gate.
pub async fn issue_token(
    State(state): State<Arc<AppState>>,
    Json(request): Json<IssueOwnerTokenRequest>,
) -> Result<Json<IssueOwnerTokenResponse>, AppError> {
    if !validate_sui_address(&request.owner) {
        return Err(AppError::BadRequest(
            "owner must be a 0x-prefixed 32-byte Sui address (66 characters)".into(),
        ));
    }
    if let Some(ref permissions) = request.permissions {
        if permissions != &[PERMISSION_MEMORIES_READ.to_string()] {
            return Err(AppError::BadRequest(
                "Phase 1 only grants memories.read".into(),
            ));
        }
    }
    if let Some(ref scope) = request.scope {
        if scope != PERMISSION_MEMORIES_READ {
            return Err(AppError::BadRequest(
                "Phase 1 only grants memories.read".into(),
            ));
        }
    }
    // Same case-normalization rationale as `routes::accounts::account_exists`:
    // the indexed `accounts.owner` column is always lowercase hex (populated
    // via `hex::encode` in the v2-indexer), and lowercasing here (rather than
    // `LOWER(owner) = LOWER($1)` in SQL) keeps the plain btree index usable.
    let owner = request.owner.to_ascii_lowercase();

    if state.config.owner_token_secret.is_empty() {
        // Feature not configured for this deployment (`OWNER_TOKEN_SECRET`
        // unset). Distinct from an auth failure — this is a deployment
        // configuration gap, not a bad caller — so it gets a 503 rather
        // than folding into the bare-401 auth-failure convention used
        // elsewhere in this file.
        return Err(AppError::UpstreamUnavailable(
            "owner-token issuance is not configured".into(),
        ));
    }

    match rate_limit::check_owner_token_owner_rate_limit(
        &state,
        &owner,
        state.config.owner_token_rate_limit.owner_per_minute,
        state.config.owner_token_rate_limit.owner_per_hour,
    )
    .await
    {
        Ok(SponsorRlResult::Allowed) => {}
        Ok(SponsorRlResult::MinuteLimitExceeded)
        | Ok(SponsorRlResult::HourLimitExceeded)
        | Ok(SponsorRlResult::DayLimitExceeded) => {
            return Err(AppError::RateLimited(
                "too many owner-token requests for this owner; retry later".into(),
            ));
        }
        Err(()) => {
            return Err(AppError::UpstreamUnavailable(
                "rate limiter temporarily unavailable".into(),
            ));
        }
    }

    // Reject up front, with 400, when the owner has no MemWalAccount at
    // all, rather than minting a token for a nonexistent account. A token
    // scoped to an address with no account is nonsensical — every real read
    // route it would be used against is itself scoped to an existing
    // account's data — and this mirrors the `GET
    // /api/accounts/{owner}/exists` design (an explicit existence-check
    // primitive Console is expected to use before this call anyway). Reuses
    // the exact same DB helper accounts.rs calls
    // (`db.find_account_by_owner`), not a second implementation.
    let Some(account_id) = state.db.find_account_by_owner(&owner).await? else {
        return Err(AppError::BadRequest("owner has no MemWalAccount".into()));
    };

    // Verify on-chain that the resolved MemWalAccount is still active before
    // minting an owner token (#1051). Also warms `DelegateVerifyCache` so the
    // immediate follow-up `/v1/owners/{owner}/*` reads hit the cache.
    match crate::storage::sui::verify_account_active_for_issuance(
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
            if !same_owner(Some(&onchain_owner), &owner) {
                state.delegate_keys_cache.write().await.remove(&account_id);
                return Err(AppError::BadRequest("owner has no MemWalAccount".into()));
            }
        }
        Err(crate::storage::sui::OnchainVerifyError::AccountDeactivated(_)) => {
            state.delegate_keys_cache.write().await.remove(&account_id);
            return Err(AppError::Forbidden(
                "MemWalAccount has been deactivated".into(),
            ));
        }
        Err(
            crate::storage::sui::OnchainVerifyError::NotFound(_)
            | crate::storage::sui::OnchainVerifyError::WrongObjectType(_),
        ) => {
            state.delegate_keys_cache.write().await.remove(&account_id);
            return Err(AppError::BadRequest("owner has no MemWalAccount".into()));
        }
        Err(e) => {
            tracing::warn!(
                account_id = %account_id,
                owner = %owner,
                error = %e,
                "owner token issuance on-chain account verification failed"
            );
            return Err(AppError::UpstreamUnavailable(
                "on-chain account verification temporarily unavailable".into(),
            ));
        }
    }

    let now = chrono::Utc::now().timestamp();
    let ttl = state.config.owner_token_ttl_secs;
    let token =
        owner_token_auth::mint_token(state.config.owner_token_secret.as_bytes(), &owner, ttl, now);
    // `to_rfc3339_opts(_, use_z=true)`, not the plain `to_rfc3339()` used
    // previously: chrono's `to_rfc3339()` always renders the UTC offset as
    // `+00:00`, never as the `Z` this response's own doc comment and
    // internal/api/owner-token-auth.md's example both promise.
    //
    // `OWNER_TOKEN_TTL_SECS` is clamped to `MAX_OWNER_TOKEN_TTL_SECS` at
    // config-load time (types.rs), so `now + ttl` cannot exceed chrono's
    // representable range in practice — but this still fails loudly with a
    // real error rather than silently substituting "now" (which would have
    // told the caller their brand-new token was already expired) if that
    // invariant is ever violated.
    let expires_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp(now.saturating_add(ttl as i64), 0)
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "owner-token expiry timestamp out of range (now={now}, ttl={ttl})"
                ))
            })?
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    Ok(Json(IssueOwnerTokenResponse {
        token,
        expires_at,
        permissions: vec![PERMISSION_MEMORIES_READ.to_string()],
    }))
}

// ============================================================
// GET /v1/owners/{owner}/_token_probe
// ============================================================

#[derive(Debug, Serialize)]
pub struct TokenProbeResponse {
    pub ok: bool,
    pub owner: String,
    pub permissions: Vec<String>,
}

/// `GET /v1/owners/{owner}/_token_probe` — minimal token-gated route.
///
/// This route was originally added so owner-token auth was testable
/// end-to-end before the real
/// `GET /v1/owners/{owner}/{namespaces,memories,agents}` handlers existed on
/// this branch. It is not itself one of those read endpoints. Its authorization
/// logic — extract `OwnerToken`, compare the `{owner}` path segment against
/// `claims.owner_address` via `same_owner` (403 on mismatch), check the
/// required permission string is present in `claims.permissions` (403 if
/// not) — has since been carried over into `auth::verify_read_api_auth`,
/// which the real handlers now use. This route is redundant and left in
/// place only as a smoke-test artifact.
///
/// No separate rate-limit / auth middleware needed here — `OwnerToken` is a
/// pure `FromRequestParts` extractor, so axum resolves it (and rejects
/// unauthenticated calls) before this handler body ever runs.
pub async fn token_probe(
    OwnerToken(claims): OwnerToken,
    Path(owner): Path<String>,
) -> Result<Json<TokenProbeResponse>, StatusCode> {
    // Reuse `security_delete_auth::same_owner`, which already implements
    // the canonical-address comparison, rather than writing a second
    // implementation.
    if !same_owner(Some(owner.as_str()), &claims.owner_address) {
        return Err(StatusCode::FORBIDDEN);
    }
    // Trivially always true in Phase 1 (only `memories.read` is ever
    // minted — see `owner_token_auth::mint_token`), but wired as a real
    // check against `claims.permissions` rather than hardcoded so it's not
    // dead code once a future phase mints additional scopes.
    if !claims
        .permissions
        .iter()
        .any(|permission| permission == PERMISSION_MEMORIES_READ)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(TokenProbeResponse {
        ok: true,
        owner: claims.owner_address.clone(),
        permissions: claims.permissions.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_std_eq_semantics() {
        assert!(constant_time_eq(b"same-secret", b"same-secret"));
        assert!(!constant_time_eq(b"same-secret", b"different"));
        assert!(!constant_time_eq(b"short", b"a-much-longer-value"));
        assert!(!constant_time_eq(b"", b"nonempty"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn service_credential_header_name_is_lowercase_x_prefixed() {
        // Header name comparisons in `HeaderMap::get` are already
        // case-insensitive, but keep the constant itself lowercase to match
        // every other custom header in this crate (`x-public-key`,
        // `x-signature`, ...).
        assert_eq!(SERVICE_CREDENTIAL_HEADER, "x-service-credential");
        assert!(SERVICE_CREDENTIAL_HEADER.starts_with("x-"));
        assert_eq!(
            SERVICE_CREDENTIAL_HEADER,
            SERVICE_CREDENTIAL_HEADER.to_ascii_lowercase()
        );
    }

    // `token_probe`'s two checks (owner-match, permission-scope) are the
    // actual authorization decision this whole feature exists to make, and
    // are the template the real owner-scoped read handlers follow — so
    // they're tested directly here even though
    // `token_probe` is itself a dev-only stand-in route. `OwnerToken` and
    // `Path` are both directly constructible (no AppState/DB/Redis needed),
    // matching how `routes::accounts` unit-tests its pure logic.
    fn claims_for(owner: &str, permissions: &[&str]) -> owner_token_auth::OwnerTokenClaims {
        owner_token_auth::OwnerTokenClaims {
            subject: "console".to_string(),
            owner_address: owner.to_string(),
            audience: owner_token_auth::OWNER_TOKEN_AUDIENCE.to_string(),
            issued_at: 0,
            expires_at: i64::MAX,
            nonce: uuid::Uuid::new_v4().to_string(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
        }
    }

    // Realistic 66-char Sui addresses — `same_owner`/`canonical_sui_address`
    // reject anything shorter, so a placeholder like "0xabc" fails for the
    // wrong reason (invalid address) rather than exercising the actual
    // owner-comparison logic these tests target.
    const TEST_OWNER: &str = "0x0000000000000000000000000000000000000000000000000000000000000abc";
    const OTHER_OWNER: &str = "0x0000000000000000000000000000000000000000000000000000000000000def";

    #[tokio::test]
    async fn token_probe_allows_matching_owner_with_memories_read() {
        let result = token_probe(
            OwnerToken(claims_for(TEST_OWNER, &[PERMISSION_MEMORIES_READ])),
            Path(TEST_OWNER.to_string()),
        )
        .await;
        let Json(body) = result.expect("matching owner + correct scope must succeed");
        assert!(body.ok);
        assert_eq!(body.owner, TEST_OWNER);
        assert_eq!(body.permissions, vec![PERMISSION_MEMORIES_READ.to_string()]);
    }

    #[tokio::test]
    async fn token_probe_rejects_owner_mismatch() {
        let result = token_probe(
            OwnerToken(claims_for(TEST_OWNER, &[PERMISSION_MEMORIES_READ])),
            Path(OTHER_OWNER.to_string()),
        )
        .await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn token_probe_matches_owner_case_insensitively_via_same_owner() {
        // `same_owner` canonicalizes the *path* side before comparing, so
        // this must still succeed even though the path segment's case
        // differs from the (already-canonical) claim — pins that
        // token_probe reuses the real canonical comparison rather than a
        // raw string `==`.
        let upper_path = TEST_OWNER.to_ascii_uppercase().replacen("0X", "0x", 1);
        let result = token_probe(
            OwnerToken(claims_for(TEST_OWNER, &[PERMISSION_MEMORIES_READ])),
            Path(upper_path),
        )
        .await;
        assert!(result.is_ok(), "canonical-equal owners must match");
    }

    #[tokio::test]
    async fn token_probe_rejects_missing_required_permission() {
        let result = token_probe(
            OwnerToken(claims_for(TEST_OWNER, &["some.other.scope"])),
            Path(TEST_OWNER.to_string()),
        )
        .await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn token_probe_rejects_empty_permissions() {
        let result = token_probe(
            OwnerToken(claims_for(TEST_OWNER, &[])),
            Path(TEST_OWNER.to_string()),
        )
        .await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}

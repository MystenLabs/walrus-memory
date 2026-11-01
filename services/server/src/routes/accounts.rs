//! `GET /api/accounts/{owner}/exists` — MemWalAccount existence check.
//!
//! Backs WALM-298's "MemWalAccount existence-check primitive" acceptance
//! criterion for the Console team's backend: given a Sui address, tells the
//! caller whether that address owns a MemWalAccount, without requiring
//! Console to hold a delegate key or run its own onchain scan.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use std::sync::Arc;

use crate::routes::sponsor::validate_sui_address;
use crate::types::*;

/// GET /api/accounts/{owner}/exists
///
/// Public, unauthenticated by design: the underlying `AccountRegistry` is
/// itself a public onchain Sui object, so anyone can already determine
/// whether an address owns a MemWalAccount via a direct RPC scan (see
/// docs/indexer/purpose.md's "onchain registry scan" fallback). This
/// endpoint is a convenience/performance wrapper around the indexer's
/// already-public data (populated from onchain `AccountCreated` events),
/// not a new information disclosure — so it deliberately does not require
/// Console-specific auth. Do not add auth here without re-checking that
/// reasoning first.
///
/// Response is intentionally minimal (`{ "exists": bool }`): the internal
/// `account_id` is not returned, since Console doesn't need it per
/// WALM-298's acceptance criteria and leaking it would needlessly widen
/// the API's surface for future churn.
///
/// This checks registry presence only, not onchain `active` status — an
/// address that once created a MemWalAccount and was later deactivated
/// still resolves to `exists: true`. The primary reason is mechanical, not
/// by-design elsewhere: `services/indexer/src/handler.rs`'s `AccountPipeline`
/// only decodes the `AccountCreated` event type — there is no deactivation
/// event handler in the indexer at all — so a row inserted into the
/// off-chain `accounts` table this endpoint queries is never removed or
/// updated afterwards, regardless of what happens to the account onchain.
/// That happens to line up with the onchain `AccountRegistry` design
/// described in docs/architecture/permanent-registry-design.md (a
/// deactivated account is intentionally kept permanently in the registry
/// too), which is supporting context for why this is an acceptable
/// property to leave as-is rather than an oversight to fix — but it is not
/// itself why the off-chain table behaves this way. Live on-chain `active`
/// gating is enforced both at owner-token issuance
/// (`routes::owner_token::issue_token`) and on owner-token reads in
/// `auth::verify_read_api_auth`, not in this existence check.
pub async fn account_exists(
    State(state): State<Arc<AppState>>,
    Path(owner): Path<String>,
) -> Result<Json<AccountExistsResponse>, AppError> {
    // Reject malformed input before the DB call rather than silently
    // returning `exists: false` for garbage — matches `validate_sui_address`
    // usage in `routes::sponsor`, the codebase's existing Sui-address check.
    // `validate_sui_address` accepts mixed/upper-case hex (see
    // `test_sui_address_uppercase_hex_accepted` in `routes::sponsor`), so
    // validation alone doesn't normalize case.
    if !validate_sui_address(&owner) {
        return Err(AppError::BadRequest(
            "owner must be a 0x-prefixed 32-byte Sui address (66 characters)".into(),
        ));
    }

    // `accounts.owner` is populated by the v2-indexer from onchain event
    // bytes via `hex::encode` (see `services/indexer/src/handler.rs`),
    // which always produces lowercase hex. Lowercase the input here — not
    // in the SQL (`LOWER(owner) = LOWER($1)` would defeat the plain btree
    // index on `accounts.owner` from migration 001, forcing a sequential
    // scan) — so a caller-supplied uppercase/mixed-case address still hits
    // the index and doesn't false-negative against an existing account.
    let owner = owner.to_ascii_lowercase();

    let exists = state.db.find_account_by_owner(&owner).await?.is_some();
    Ok(Json(AccountExistsResponse { exists }))
}

/// GET /api/whoami
///
/// Returns the account identity the caller's delegate key resolves to.
///
/// Authenticated, and that is what makes returning `account_id` here
/// acceptable where `account_exists` deliberately withholds it: the auth
/// middleware has already proven the caller holds a delegate key registered
/// against this account, so this only ever tells a caller about itself. Do
/// not move this into the unauthenticated router group.
///
/// Motivating case (WALM-332): a login interrupted between the browser's
/// on-chain `add_delegate_key` and the localhost callback leaves the client
/// holding a valid delegate key but none of the surrounding metadata, so it
/// cannot write a usable `credentials.json`. Everything needed to rebuild one
/// is already resolved during authentication — `account_id` and `owner` from
/// the signed account id (or the delegate-key cache), `package_id` from
/// config — so this endpoint hands back what the middleware already computed
/// rather than doing new work.
pub async fn whoami(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
) -> Result<Json<WhoamiResponse>, AppError> {
    Ok(Json(whoami_response(auth, state.config.package_id.clone())))
}

/// The field mapping, factored out of the handler so it is testable without a
/// live `AppState`/DB (same reason as `account_exists` above — this codebase
/// has no axum-handler test harness).
///
/// Worth isolating rather than inlining: `account_id` and `owner` are both
/// 0x-prefixed 32-byte hex, so transposing them is invisible to the type
/// checker and would produce credentials that authenticate as the wrong
/// identity. The test below pins the mapping.
fn whoami_response(auth: AuthInfo, package_id: String) -> WhoamiResponse {
    WhoamiResponse {
        account_id: auth.account_id,
        owner: auth.owner,
        package_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure unit test for the case-normalization step, factored out of the
    /// handler body above (`owner.to_ascii_lowercase()`) so it's covered
    /// without needing a live `AppState`/DB (see module doc for why this
    /// codebase has no axum-handler test harness to reuse).
    #[test]
    fn owner_lowercasing_normalizes_mixed_case_before_lookup() {
        // 0x + 64 hex chars (32 bytes) — must match `validate_sui_address`'s
        // length requirement (66 chars total) exactly.
        let mixed_case = "0xABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890";
        assert_eq!(
            mixed_case.len(),
            66,
            "fixture must be a 66-char Sui address"
        );
        assert!(validate_sui_address(mixed_case));

        let normalized = mixed_case.to_ascii_lowercase();
        assert_eq!(
            normalized,
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );

        // Already-lowercase input must be unaffected (idempotent).
        assert_eq!(normalized.to_ascii_lowercase(), normalized);
    }

    // ── GET /api/whoami (WALM-332 recovery) ──────────────────────

    fn auth_fixture() -> AuthInfo {
        AuthInfo {
            public_key: "aa".repeat(32),
            owner: format!("0x{}", "b".repeat(64)),
            account_id: format!("0x{}", "a".repeat(64)),
            delegate_key: None,
            seal_session: None,
        }
    }

    /// `account_id` and `owner` are indistinguishable by type — both
    /// 0x-prefixed 32-byte hex — so a transposition here would compile, pass
    /// every other test, and hand a recovering client credentials that
    /// authenticate as the wrong identity. Pin the mapping explicitly.
    #[test]
    fn whoami_maps_account_and_owner_without_transposing_them() {
        let auth = auth_fixture();
        let package_id = format!("0x{}", "c".repeat(64));

        let resp = whoami_response(auth, package_id.clone());

        assert_eq!(
            resp.account_id,
            format!("0x{}", "a".repeat(64)),
            "account_id must come from AuthInfo::account_id, not owner"
        );
        assert_eq!(
            resp.owner,
            format!("0x{}", "b".repeat(64)),
            "owner must come from AuthInfo::owner, not account_id"
        );
        assert_eq!(resp.package_id, package_id, "package_id comes from config");
        assert_ne!(resp.account_id, resp.owner, "fixture must distinguish them");
    }

    /// The recovering MCP client cannot send `x-account-id` — not knowing it
    /// is the whole reason it is calling this endpoint — so it signs the
    /// canonical message with an empty account field and omits the header.
    /// The server defaults the hint to `""` for exactly this case.
    ///
    /// This pins the literal string both sides must build. It is duplicated
    /// verbatim in `packages/mcp/test/login-recovery-signing.test.mjs`; if the
    /// canonical format in `auth.rs` ever changes, both fail together rather
    /// than recovery silently breaking in production.
    #[test]
    fn whoami_recovery_request_canonical_message_is_stable() {
        let timestamp = "1700000000";
        let method = "GET";
        let path = "/api/whoami";
        // sha256 of an empty body — a GET carries none, but the server hashes
        // the empty body all the same.
        let body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let nonce = "550e8400-e29b-41d4-a716-446655440000";
        let account_id_for_sig = String::new();

        let message = format!(
            "{}.{}.{}.{}.{}.{}",
            timestamp, method, path, body_hash, nonce, account_id_for_sig
        );

        let expected = concat!(
            "1700000000.GET./api/whoami.",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.",
            "550e8400-e29b-41d4-a716-446655440000."
        );
        assert_eq!(message, expected);
        // Six fields → five separators. Nothing else in the message contains a
        // dot: the nonce is hyphen-separated and the body hash is bare hex.
        assert_eq!(message.matches('.').count(), 5);
        assert!(
            message.ends_with('.'),
            "the empty account id leaves a trailing separator — the client must \
             reproduce this exactly, not trim it"
        );
    }
}

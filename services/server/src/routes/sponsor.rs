//! `/sponsor` + `/sponsor/execute` proxy handlers.
//!
//! Thin authenticated proxies that forward Enoki-sponsor requests to the
//! internal sidecar, with input validation (Sui address / tx digest /
//! signature size / base64) and per-sender rate limiting. Upstream error
//! bodies are never echoed to the client — they're logged server-side and
//! masked to a generic message (`mask_upstream`).
//!
//! Masked upstream responses also carry a stable machine-readable `code` and
//! the request's `traceId`. Masking has to keep the upstream body out of the
//! response, but a caller still needs to tell "the sponsor refused this
//! transaction" apart from "your request was malformed" — the code draws that
//! line without leaking anything, and the traceId points at the one server log
//! line that does hold the upstream detail.
//!
//! `validate_sponsor_transaction_kind` is the sponsorship allowlist: a
//! sponsored transaction may only call `account::create_account`,
//! `account::add_delegate_key`, `account::remove_delegate_key`, or
//! `account::reactivate_account` on the configured MemWal package. Batching is allowed for delegate-key **removal**
//! only, up to `MAX_SPONSORED_DELEGATE_REMOVALS` — the dashboard removes a
//! multi-key selection in one transaction, so a one-command-only rule would
//! reject every bulk revoke. Every other shape stays single-command.

use axum::body::Body;
use axum::extract::State;
use axum::response::Response;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use sui_sdk_types::{Command, TransactionKind};
use uuid::Uuid;

use crate::security_delete_error::SdCode;
use crate::types::*;

/// Sui transaction signatures are serialized as base64 bytes — native
/// schemes are 65/97 bytes, zkLogin signatures are variable-size payloads.
/// Upper bound to reject obviously oversized inputs before any work.
const MAX_SPONSORED_SIGNATURE_BYTES: usize = 2048;
/// A sponsored transaction may batch this many `account::remove_delegate_key`
/// calls. An account holds at most 20 delegate keys, so this is exactly enough
/// to revoke every key at once and no more. It bounds how much sponsored gas a
/// single rate-limited request can spend.
const MAX_SPONSORED_DELEGATE_REMOVALS: usize = 20;
const MAX_WALLET_AUTH_SIGNATURE_BYTES: usize = 8192;
const SPONSOR_AUTH_WINDOW_SECONDS: i64 = 300;
const SPONSOR_AUTH_NONCE_TTL_SECONDS: i64 = 600;
const PENDING_SPONSOR_TTL_SECONDS: i64 = 600;

const CONSUME_PENDING_SPONSOR_LUA: &str = r#"
local value = redis.call('GET', KEYS[1])
if not value then return 0 end
if value ~= ARGV[1] then return -1 end
redis.call('DEL', KEYS[1])
return 1
"#;

/// Map an upstream sponsor status onto what the client is allowed to see: the
/// status to return, a stable machine-readable code, and a generic message.
/// The upstream body itself is never part of the result.
fn mask_upstream(status: u16) -> (axum::http::StatusCode, &'static str, &'static str) {
    match status {
        429 => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "sponsor_overloaded",
            "Sponsor service temporarily overloaded",
        ),
        401 | 403 => (
            axum::http::StatusCode::BAD_GATEWAY,
            "sponsor_misconfigured",
            "Sponsor service misconfigured",
        ),
        500..=599 => (
            axum::http::StatusCode::BAD_GATEWAY,
            "sponsor_upstream_error",
            "Sponsor service error",
        ),
        _ => (
            axum::http::StatusCode::BAD_REQUEST,
            "sponsor_rejected",
            "Sponsor request rejected",
        ),
    }
}

/// A known `reactivate_account` abort. The sidecar names it with a stable
/// code; the raw upstream body stays in the log and never reaches the client.
fn reactivate_rejection(
    body: &[u8],
) -> Option<(axum::http::StatusCode, &'static str, &'static str)> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    match value.get("code").and_then(serde_json::Value::as_str)? {
        "account_already_active" => Some((
            axum::http::StatusCode::CONFLICT,
            "account_already_active",
            "This account is already active, so it cannot be reactivated.",
        )),
        "account_quarantined" => Some((
            axum::http::StatusCode::CONFLICT,
            "account_quarantined",
            "This account is still locked, so it cannot be reactivated yet.",
        )),
        _ => None,
    }
}

fn sponsor_error_response(status: reqwest::StatusCode, body: &[u8]) -> Response<Body> {
    let (masked_status, masked_code, masked_msg) =
        reactivate_rejection(body).unwrap_or_else(|| mask_upstream(status.as_u16()));
    json_error_response(masked_status, masked_code, masked_msg)
}

/// Error body for the sponsor proxies: a generic message, a stable `code`, and
/// the `traceId` that ties the response to the server log line holding the
/// upstream detail. Without the traceId a masked failure is undiagnosable from
/// the browser alone.
fn json_error_response(
    status: axum::http::StatusCode,
    code: &'static str,
    msg: &'static str,
) -> Response<Body> {
    let trace_id =
        crate::observability::current_request_id().unwrap_or_else(|| Uuid::new_v4().to_string());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::json!({ "error": msg, "code": code, "traceId": trace_id }).to_string(),
        ))
        .unwrap()
}

/// Validate a Sui address: `0x` followed by exactly 64 hex characters.
pub(super) fn validate_sui_address(s: &str) -> bool {
    s.starts_with("0x") && s.len() == 66 && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate base64 and return decoded bytes, or None on failure.
pub(super) fn decode_base64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Validate a Sui transaction digest: base58 alphabet, 43 or 44 characters.
pub(super) fn validate_digest(s: &str) -> bool {
    // Base58 of 32 bytes is normally 43-44 chars, but digests with leading
    // zero bytes encode shorter (~0.1% of real digests are 42) — accept the
    // full range a 32-byte value can produce.
    let len = s.len();
    if !(32..=44).contains(&len) {
        return false;
    }
    // Base58 alphabet excludes: 0, O, I, l
    s.chars().all(|c| {
        matches!(c,
            '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'
        )
    })
}

/// Sui transaction signatures are serialized as base64 bytes. Native schemes are
/// 65/97 bytes, while zkLogin signatures are variable-size serialized payloads.
pub(super) fn validate_sponsored_signature_len(len: usize) -> bool {
    (65..=MAX_SPONSORED_SIGNATURE_BYTES).contains(&len)
}

/// Forward a signed sponsored transaction to the sidecar's
/// `/sponsor/execute` and return the upstream status + body. Shared by the
/// `/sponsor/execute` proxy.
async fn call_sidecar_sponsor_execute(
    state: &AppState,
    digest: &str,
    signature: &str,
    verify_effects: bool,
) -> Result<(reqwest::StatusCode, axum::body::Bytes), AppError> {
    if crate::storage::walrus_native::is_in_process_sidecar_enabled(&state.config.sidecar_url) {
        let started = std::time::Instant::now();
        match crate::sui::enoki::enoki_execute_and_verify_sponsored_transaction(
            &state.http_client,
            digest,
            signature,
            verify_effects,
            state.config.sui_grpc_url.as_deref(),
        )
        .await
        {
            Ok(executed) => {
                crate::observability::observe_external(
                    "sidecar",
                    "sponsor_execute",
                    "200",
                    started.elapsed(),
                );
                let body = serde_json::to_vec(&executed).map_err(|e| {
                    AppError::Internal(format!("Sponsor execute encode failed: {e}"))
                })?;
                return Ok((reqwest::StatusCode::OK, axum::body::Bytes::from(body)));
            }
            Err(err) => {
                let err_msg = err.error_message();
                if let Some((code, msg)) = crate::sui::enoki::reactivate_rejection_code(&err_msg) {
                    crate::observability::observe_external(
                        "sidecar",
                        "sponsor_execute",
                        "409",
                        started.elapsed(),
                    );
                    let body = serde_json::json!({ "error": msg, "code": code }).to_string();
                    return Ok((
                        reqwest::StatusCode::CONFLICT,
                        axum::body::Bytes::from(body.into_bytes()),
                    ));
                }
                let status_u16 = err.upstream_status_u16();
                let status = reqwest::StatusCode::from_u16(status_u16)
                    .unwrap_or(reqwest::StatusCode::BAD_GATEWAY);
                crate::observability::observe_external(
                    "sidecar",
                    "sponsor_execute",
                    &status.as_u16().to_string(),
                    started.elapsed(),
                );
                let sanitized =
                    crate::sui::enoki::sanitize_upstream_error_for_logging(&err_msg);
                let body = serde_json::json!({ "error": sanitized }).to_string();
                return Ok((status, axum::body::Bytes::from(body.into_bytes())));
            }
        }
    }

    let forwarded = serde_json::json!({
        "digest": digest,
        "signature": signature,
        "verifyEffects": verify_effects,
    });

    let url = format!("{}/sponsor/execute", state.config.sidecar_url);
    let mut upstream_request = state
        .http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&forwarded);
    if let Some(secret) = state.config.sidecar_secret.as_deref() {
        upstream_request = upstream_request.header("authorization", format!("Bearer {}", secret));
    }
    let upstream_request = crate::observability::apply_request_id_header(upstream_request);
    let started = std::time::Instant::now();
    let resp = upstream_request.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sidecar",
            "sponsor_execute",
            "transport_error",
            started.elapsed(),
        );
        crate::observability::record_sidecar_failure("sponsor_execute", "transport_error");
        AppError::Internal(format!("Sponsor execute proxy failed: {}", e))
    })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external(
        "sidecar",
        "sponsor_execute",
        &status_label,
        started.elapsed(),
    );

    let upstream_status = resp.status();
    let resp_body = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(format!("Sponsor execute proxy read failed: {}", e)))?;
    Ok((upstream_status, resp_body))
}

/// Parse and validate a /sponsor-shaped body — never echo back
/// client-supplied values in errors.
fn parse_sponsor_request(body: &[u8]) -> Result<(SponsorRequest, Vec<u8>), AppError> {
    let req: SponsorRequest = serde_json::from_slice(body)
        .map_err(|_| AppError::BadRequest("Invalid request body".into()))?;

    if !validate_sui_address(&req.sender) {
        return Err(AppError::BadRequest("Invalid sender address".into()));
    }

    let tx_bytes = decode_base64(&req.transaction_block_kind_bytes).ok_or_else(|| {
        AppError::BadRequest("transactionBlockKindBytes must be valid base64".into())
    })?;
    if tx_bytes.len() < 10 || tx_bytes.len() > 7000 {
        return Err(AppError::BadRequest(
            "transactionBlockKindBytes out of range".into(),
        ));
    }

    Ok((req, tx_bytes))
}

fn sponsor_authorization_message(
    sender: &str,
    transaction_kind_bytes: &[u8],
    timestamp: i64,
    nonce: &str,
) -> String {
    let transaction_kind_hash = hex::encode(Sha256::digest(transaction_kind_bytes));
    format!(
        "MemWal sponsor authorization\nsender: {sender}\ntransaction-kind-sha256: {transaction_kind_hash}\ntimestamp: {timestamp}\nnonce: {nonce}"
    )
}

fn validate_sponsor_transaction_kind(
    transaction_kind_bytes: &[u8],
    package_id: &str,
) -> Result<&'static str, AppError> {
    let kind: TransactionKind = bcs::from_bytes(transaction_kind_bytes)
        .map_err(|_| AppError::BadRequest("Invalid transaction kind".into()))?;
    let TransactionKind::ProgrammableTransaction(programmable) = kind else {
        return Err(AppError::BadRequest(
            "Transaction kind is not permitted for sponsorship".into(),
        ));
    };
    let package = package_id
        .parse::<sui_sdk_types::Address>()
        .map_err(|_| AppError::Internal("Invalid configured MemWal package ID".into()))?;

    // Every command must be an allowlisted MemWal account call with no type
    // arguments. Anything else collapses the whole collect() to None, so one
    // foreign command rejects the entire transaction.
    let functions: Option<Vec<&str>> = programmable
        .commands
        .iter()
        .map(|command| match command {
            Command::MoveCall(call)
                if call.package == package
                    && call.module.as_str() == "account"
                    && call.type_arguments.is_empty()
                    && matches!(
                        call.function.as_str(),
                        "create_account"
                            | "add_delegate_key"
                            | "remove_delegate_key"
                            | "reactivate_account"
                    ) =>
            {
                Some(call.function.as_str())
            }
            _ => None,
        })
        .collect();

    let Some(functions) = functions else {
        return Err(AppError::BadRequest(
            "Transaction kind is not permitted for sponsorship".into(),
        ));
    };

    match functions.as_slice() {
        // An empty programmable transaction has no effects but still burns
        // sponsored gas — never worth paying for.
        [] => Err(AppError::BadRequest(
            "Transaction kind is not permitted for sponsorship".into(),
        )),
        // One allowlisted call: create, add, or remove.
        [function] => match *function {
            "create_account" => Ok("create_account"),
            "add_delegate_key" => Ok("add_delegate_key"),
            "remove_delegate_key" => Ok("remove_delegate_key"),
            "reactivate_account" => Ok("reactivate_account"),
            _ => Err(AppError::BadRequest(
                "Transaction kind is not permitted for sponsorship".into(),
            )),
        },
        // Batching exists for bulk revoke only. Every command has to be a
        // removal, and the batch stays inside the sponsored-gas bound.
        calls
            if calls
                .iter()
                .all(|function| *function == "remove_delegate_key") =>
        {
            if calls.len() > MAX_SPONSORED_DELEGATE_REMOVALS {
                return Err(AppError::BadRequest(format!(
                    "Too many delegate key removals in one transaction (max {MAX_SPONSORED_DELEGATE_REMOVALS})"
                )));
            }
            Ok("remove_delegate_key")
        }
        _ => Err(AppError::BadRequest(
            "Transaction kind is not permitted for sponsorship".into(),
        )),
    }
}

async fn authenticate_sponsor_request(
    state: &AppState,
    request: &SponsorRequest,
    transaction_kind_bytes: &[u8],
) -> Result<(), AppError> {
    let signature = request
        .auth_signature
        .as_deref()
        .ok_or_else(|| AppError::Unauthorized("Sponsor authorization required".into()))?;
    let timestamp = request
        .auth_timestamp
        .ok_or_else(|| AppError::Unauthorized("Sponsor authorization required".into()))?;
    let nonce = request
        .auth_nonce
        .as_deref()
        .ok_or_else(|| AppError::Unauthorized("Sponsor authorization required".into()))?;

    let now = chrono::Utc::now().timestamp();
    let age = now.checked_sub(timestamp).unwrap_or(i64::MAX);
    let valid_nonce = Uuid::parse_str(nonce)
        .ok()
        .is_some_and(|parsed| parsed.get_version_num() == 4);
    let signature_len = decode_base64(signature).map(|bytes| bytes.len());
    if !(-SPONSOR_AUTH_WINDOW_SECONDS..=SPONSOR_AUTH_WINDOW_SECONDS).contains(&age)
        || !valid_nonce
        || !signature_len.is_some_and(|len| (65..=MAX_WALLET_AUTH_SIGNATURE_BYTES).contains(&len))
    {
        return Err(AppError::Unauthorized(
            "Invalid sponsor authorization".into(),
        ));
    }

    // Reserve the nonce before remote signature verification. Invalid or
    // replayed attempts are burned, and Redis failure denies the request.
    let mut redis = state.redis.clone();
    let reserved: Option<String> = redis::cmd("SET")
        .arg(format!("sponsor:auth:nonce:{nonce}"))
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(SPONSOR_AUTH_NONCE_TTL_SECONDS)
        .query_async(&mut redis)
        .await
        .map_err(|error| {
            AppError::UpstreamUnavailable(format!("Sponsor auth Redis unavailable: {error}"))
        })?;
    if reserved.is_none() {
        return Err(AppError::Unauthorized(
            "Invalid sponsor authorization".into(),
        ));
    }

    let message =
        sponsor_authorization_message(&request.sender, transaction_kind_bytes, timestamp, nonce);
    state
        .security_delete_wallet_verifier
        .verify_personal(&request.sender, message.as_bytes(), signature)
        .await
        .map_err(|error| match error.code {
            SdCode::RpcUnavailable | SdCode::InternalError => AppError::UpstreamUnavailable(
                format!("Sponsor wallet verification unavailable: {}", error.message),
            ),
            _ => AppError::Unauthorized("Invalid sponsor authorization".into()),
        })
}

async fn record_pending_sponsor(
    state: &AppState,
    digest: &str,
    sender: &str,
) -> Result<(), AppError> {
    let mut redis = state.redis.clone();
    let recorded: Option<String> = redis::cmd("SET")
        .arg(format!("sponsor:pending:{digest}"))
        .arg(sender)
        .arg("NX")
        .arg("EX")
        .arg(PENDING_SPONSOR_TTL_SECONDS)
        .query_async(&mut redis)
        .await
        .map_err(|error| {
            AppError::UpstreamUnavailable(format!("Sponsor binding Redis unavailable: {error}"))
        })?;
    if recorded.is_none() {
        return Err(AppError::UpstreamUnavailable(
            "Sponsor digest binding collision".into(),
        ));
    }
    Ok(())
}

async fn consume_pending_sponsor(
    state: &AppState,
    digest: &str,
    sender: &str,
) -> Result<(), AppError> {
    let mut redis = state.redis.clone();
    let consumed: i64 = redis::Script::new(CONSUME_PENDING_SPONSOR_LUA)
        .key(format!("sponsor:pending:{digest}"))
        .arg(sender)
        .invoke_async(&mut redis)
        .await
        .map_err(|error| {
            AppError::UpstreamUnavailable(format!("Sponsor binding Redis unavailable: {error}"))
        })?;
    if consumed != 1 {
        return Err(AppError::Unauthorized(
            "Invalid or expired sponsor authorization".into(),
        ));
    }
    Ok(())
}

async fn record_sponsor_kind(state: &AppState, digest: &str, kind: &str) -> Result<(), AppError> {
    let mut redis = state.redis.clone();
    let _: String = redis::cmd("SET")
        .arg(format!("sponsor:kind:{digest}"))
        .arg(kind)
        .arg("EX")
        .arg(PENDING_SPONSOR_TTL_SECONDS)
        .query_async(&mut redis)
        .await
        .map_err(|error| {
            AppError::UpstreamUnavailable(format!("Sponsor kind Redis unavailable: {error}"))
        })?;
    Ok(())
}

async fn take_sponsor_kind(state: &AppState, digest: &str) -> Option<String> {
    let mut redis = state.redis.clone();
    let key = format!("sponsor:kind:{digest}");
    let value: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut redis)
        .await
        .ok()
        .flatten();
    if value.is_some() {
        let _: Result<i64, _> = redis::cmd("DEL").arg(&key).query_async(&mut redis).await;
    }
    value
}

/// Forward a validated sponsor request to the sidecar's POST /sponsor.
async fn forward_sponsor(
    state: &AppState,
    req: &SponsorRequest,
    kind: &str,
) -> Result<Response<Body>, AppError> {
    if crate::storage::walrus_native::is_in_process_sidecar_enabled(&state.config.sidecar_url) {
        let started = std::time::Instant::now();
        let allowed_targets = crate::sui::enoki::default_sponsor_allowed_move_call_targets(
            &state.config.package_id,
            &state.config.seal_policy_package_id,
        );
        match crate::sui::enoki::enoki_sponsor_transaction_kind(
            &state.http_client,
            &state.config.sui_network,
            &req.sender,
            &req.transaction_block_kind_bytes,
            allowed_targets,
        )
        .await
        {
            Ok(sponsored) => {
                crate::observability::observe_external(
                    "sidecar",
                    "sponsor",
                    "200",
                    started.elapsed(),
                );
                if !validate_digest(&sponsored.digest) {
                    return Err(AppError::Internal("Invalid sponsor upstream digest".into()));
                }
                record_pending_sponsor(state, &sponsored.digest, &req.sender).await?;
                if let Err(err) = record_sponsor_kind(state, &sponsored.digest, kind).await {
                    tracing::warn!(
                        digest = %sponsored.digest,
                        error = %err,
                        "failed to remember sponsored transaction kind"
                    );
                }
                let body = serde_json::to_vec(&sponsored)
                    .map_err(|_| AppError::Internal("Invalid sponsor upstream response".into()))?;
                return Response::builder()
                    .status(axum::http::StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .map_err(|e| AppError::Internal(format!("Sponsor response build failed: {e}")));
            }
            Err(err) => {
                let err_msg = err.error_message();
                let sanitized_err =
                    crate::sui::enoki::sanitize_upstream_error_for_logging(&err_msg);
                let status_u16 = err.upstream_status_u16();
                crate::observability::observe_external(
                    "sidecar",
                    "sponsor",
                    &status_u16.to_string(),
                    started.elapsed(),
                );
                crate::observability::record_sidecar_failure("sponsor", "http_error");
                tracing::error!(
                    request_id = %crate::observability::current_request_id().unwrap_or_default(),
                    "sponsor in-process error {}: {}",
                    status_u16,
                    sanitized_err
                );
                if let Some((code, msg)) = crate::sui::enoki::reactivate_rejection_code(&err_msg) {
                    return Ok(json_error_response(
                        axum::http::StatusCode::CONFLICT,
                        code,
                        msg,
                    ));
                }
                let status = reqwest::StatusCode::from_u16(status_u16)
                    .unwrap_or(reqwest::StatusCode::BAD_GATEWAY);
                let body = serde_json::json!({ "error": sanitized_err }).to_string();
                return Ok(sponsor_error_response(status, body.as_bytes()));
            }
        }
    }

    // Re-serialise only validated fields before forwarding.
    let forwarded = serde_json::json!({
        "sender": req.sender,
        "transactionBlockKindBytes": req.transaction_block_kind_bytes,
    });

    let url = format!("{}/sponsor", state.config.sidecar_url);
    let mut upstream_request = state
        .http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&forwarded);
    if let Some(secret) = state.config.sidecar_secret.as_deref() {
        upstream_request = upstream_request.header("authorization", format!("Bearer {}", secret));
    }
    let upstream_request = crate::observability::apply_request_id_header(upstream_request);
    let started = std::time::Instant::now();
    let resp = upstream_request.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sidecar",
            "sponsor",
            "transport_error",
            started.elapsed(),
        );
        crate::observability::record_sidecar_failure("sponsor", "transport_error");
        AppError::Internal(format!("Sponsor proxy failed: {}", e))
    })?;
    let status_label = resp.status().as_u16().to_string();
    crate::observability::observe_external("sidecar", "sponsor", &status_label, started.elapsed());

    let upstream_status = resp.status();
    let resp_body = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(format!("Sponsor proxy read failed: {}", e)))?;

    if upstream_status.is_success() {
        let sponsored: serde_json::Value = serde_json::from_slice(&resp_body)
            .map_err(|_| AppError::Internal("Invalid sponsor upstream response".into()))?;
        let digest = sponsored
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .filter(|digest| validate_digest(digest))
            .ok_or_else(|| AppError::Internal("Invalid sponsor upstream digest".into()))?;
        record_pending_sponsor(state, digest, &req.sender).await?;
        if let Err(err) = record_sponsor_kind(state, digest, kind).await {
            tracing::warn!(
                digest,
                error = %err,
                "failed to remember sponsored transaction kind"
            );
        }
        Ok(Response::builder()
            .status(axum::http::StatusCode::from_u16(upstream_status.as_u16()).unwrap())
            .header("Content-Type", "application/json")
            .body(Body::from(resp_body))
            .unwrap())
    } else {
        crate::observability::record_sidecar_failure("sponsor", "http_error");
        tracing::error!(
            request_id = %crate::observability::current_request_id().unwrap_or_default(),
            "sponsor upstream error {}: {}",
            upstream_status,
            String::from_utf8_lossy(&resp_body)
        );
        Ok(sponsor_error_response(upstream_status, &resp_body))
    }
}

/// POST /sponsor — proxy to sidecar POST /sponsor
pub async fn sponsor_proxy(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Response<Body>, AppError> {
    let (req, transaction_kind_bytes) = parse_sponsor_request(&body)?;
    let kind =
        validate_sponsor_transaction_kind(&transaction_kind_bytes, &state.config.package_id)?;
    authenticate_sponsor_request(&state, &req, &transaction_kind_bytes).await?;

    forward_sponsor(&state, &req, kind).await
}

/// POST /sponsor/execute — proxy to sidecar POST /sponsor/execute
pub async fn sponsor_execute_proxy(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Response<Body>, AppError> {
    let req: SponsorExecuteRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("Invalid request body".into()))?;

    if !validate_digest(&req.digest) {
        return Err(AppError::BadRequest("Invalid digest".into()));
    }

    let sender = req
        .sender
        .as_deref()
        .filter(|sender| validate_sui_address(sender))
        .ok_or_else(|| AppError::Unauthorized("Sponsor authorization required".into()))?;

    let sig_bytes = decode_base64(&req.signature)
        .ok_or_else(|| AppError::BadRequest("signature must be valid base64".into()))?;
    if !validate_sponsored_signature_len(sig_bytes.len()) {
        return Err(AppError::BadRequest(
            "signature has unexpected length".into(),
        ));
    }

    consume_pending_sponsor(&state, &req.digest, sender).await?;

    let execute_result =
        call_sidecar_sponsor_execute(&state, &req.digest, &req.signature, false).await;

    let (upstream_status, resp_body) = match execute_result {
        Ok(pair) => pair,
        Err(err) => {
            // Transport / parse failure: the sidecar never confirmed
            // execution. Put the binding back so the client can retry
            // without re-running /sponsor (GH #617).
            if let Err(restore_err) = record_pending_sponsor(&state, &req.digest, sender).await {
                tracing::error!(
                    digest = %req.digest,
                    error = %restore_err,
                    "failed to restore sponsor pending record after sidecar transport error"
                );
            }
            return Err(err);
        }
    };

    if upstream_status.is_success() {
        let kind = take_sponsor_kind(&state, &req.digest)
            .await
            .unwrap_or_else(|| "unknown".to_string());
        let pool = state.db.pool().clone();
        let sender_owned = sender.to_string();
        let digest = req.digest.clone();
        tokio::spawn(async move {
            if let Err(err) =
                crate::routes::admin_activity::record_sponsored_tx(&pool, &sender_owned, &kind)
                    .await
            {
                tracing::warn!(
                    digest = %digest,
                    error = %err,
                    "failed to record sponsored transaction"
                );
            }
        });
        Ok(Response::builder()
            .status(axum::http::StatusCode::from_u16(upstream_status.as_u16()).unwrap())
            .header("Content-Type", "application/json")
            .body(Body::from(resp_body))
            .unwrap())
    } else {
        if should_restore_pending_sponsor(upstream_status) {
            if let Err(restore_err) = record_pending_sponsor(&state, &req.digest, sender).await {
                tracing::error!(
                    digest = %req.digest,
                    status = %upstream_status,
                    error = %restore_err,
                    "failed to restore sponsor pending record after sidecar error"
                );
            }
        }
        crate::observability::record_sidecar_failure("sponsor_execute", "http_error");
        tracing::error!(
            request_id = %crate::observability::current_request_id().unwrap_or_default(),
            "sponsor/execute upstream error {}: {}",
            upstream_status,
            String::from_utf8_lossy(&resp_body)
        );
        Ok(sponsor_error_response(upstream_status, &resp_body))
    }
}

/// Restore the pending binding after a sidecar failure that did not
/// confirm execution. 4xx means the signed tx was rejected; leave it
/// consumed so the client must re-sponsor. 5xx / 429 are transient.
fn should_restore_pending_sponsor(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod more_tests {
    use super::*;

    #[test]
    fn restore_pending_on_transient_sidecar_status() {
        assert!(should_restore_pending_sponsor(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        ));
        assert!(should_restore_pending_sponsor(
            reqwest::StatusCode::BAD_GATEWAY
        ));
        assert!(should_restore_pending_sponsor(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(should_restore_pending_sponsor(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(!should_restore_pending_sponsor(
            reqwest::StatusCode::BAD_REQUEST
        ));
        assert!(!should_restore_pending_sponsor(
            reqwest::StatusCode::UNAUTHORIZED
        ));
        assert!(!should_restore_pending_sponsor(reqwest::StatusCode::OK));
    }

    fn move_call_kind(package: &str, module: &str, function: &str) -> Vec<u8> {
        let kind =
            TransactionKind::ProgrammableTransaction(sui_sdk_types::ProgrammableTransaction {
                inputs: vec![],
                commands: vec![Command::MoveCall(sui_sdk_types::MoveCall {
                    package: package.parse().unwrap(),
                    module: module.parse().unwrap(),
                    function: function.parse().unwrap(),
                    type_arguments: vec![],
                    arguments: vec![],
                })],
            });
        bcs::to_bytes(&kind).unwrap()
    }

    /// Build a programmable transaction kind with one MoveCall per
    /// `(module, function)` pair, so batches of any shape can be asserted on.
    fn move_calls_kind(package: &str, calls: &[(&str, &str)]) -> Vec<u8> {
        let kind =
            TransactionKind::ProgrammableTransaction(sui_sdk_types::ProgrammableTransaction {
                inputs: vec![],
                commands: calls
                    .iter()
                    .map(|(module, function)| {
                        Command::MoveCall(sui_sdk_types::MoveCall {
                            package: package.parse().unwrap(),
                            module: module.parse().unwrap(),
                            function: function.parse().unwrap(),
                            type_arguments: vec![],
                            arguments: vec![],
                        })
                    })
                    .collect(),
            });
        bcs::to_bytes(&kind).unwrap()
    }

    #[test]
    fn sponsor_authorization_message_matches_sdk_contract() {
        assert_eq!(
            sponsor_authorization_message(
                "0xabc",
                &[1, 2, 3],
                1_700_000_000,
                "00000000-0000-4000-8000-000000000000",
            ),
            "MemWal sponsor authorization\n\
sender: 0xabc\n\
transaction-kind-sha256: 039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81\n\
timestamp: 1700000000\n\
nonce: 00000000-0000-4000-8000-000000000000"
        );
    }

    #[test]
    fn sponsor_allowlist_accepts_a_single_memwal_account_call() {
        let package = format!("0x{}", "a".repeat(64));
        for function in [
            "create_account",
            "add_delegate_key",
            "remove_delegate_key",
            "reactivate_account",
        ] {
            let bytes = move_call_kind(&package, "account", function);
            assert_eq!(
                validate_sponsor_transaction_kind(&bytes, &package).unwrap(),
                function
            );
        }

        let foreign_package = format!("0x{}", "b".repeat(64));
        let foreign = move_call_kind(&foreign_package, "account", "create_account");
        assert!(validate_sponsor_transaction_kind(&foreign, &package).is_err());

        let wrong_function = move_call_kind(&package, "account", "arbitrary_call");
        assert!(validate_sponsor_transaction_kind(&wrong_function, &package).is_err());

        let wrong_module = move_call_kind(&package, "coin", "transfer");
        assert!(validate_sponsor_transaction_kind(&wrong_module, &package).is_err());
    }

    /// Regression: the dashboard removes a multi-key selection in ONE
    /// transaction, so a one-command-only rule rejected every bulk revoke with
    /// a 400 while single-key removal and add both worked.
    #[test]
    fn sponsor_allowlist_accepts_batched_delegate_key_removals() {
        let package = format!("0x{}", "a".repeat(64));
        for count in [2usize, 3, MAX_SPONSORED_DELEGATE_REMOVALS] {
            let calls = vec![("account", "remove_delegate_key"); count];
            let bytes = move_calls_kind(&package, &calls);
            validate_sponsor_transaction_kind(&bytes, &package)
                .unwrap_or_else(|e| panic!("{count} removals must be permitted, got {e}"));
        }
    }

    #[test]
    fn sponsor_allowlist_rejects_removal_batch_over_the_cap() {
        let package = format!("0x{}", "a".repeat(64));
        let calls = vec![("account", "remove_delegate_key"); MAX_SPONSORED_DELEGATE_REMOVALS + 1];
        let bytes = move_calls_kind(&package, &calls);
        assert!(validate_sponsor_transaction_kind(&bytes, &package).is_err());
    }

    /// Batching is a bulk-revoke affordance only — it must not become a general
    /// "many sponsored calls per transaction" hole.
    #[test]
    fn sponsor_allowlist_rejects_batches_that_are_not_pure_removals() {
        let package = format!("0x{}", "a".repeat(64));
        for calls in [
            vec![
                ("account", "add_delegate_key"),
                ("account", "add_delegate_key"),
            ],
            vec![
                ("account", "remove_delegate_key"),
                ("account", "add_delegate_key"),
            ],
            vec![("account", "create_account"), ("account", "create_account")],
            vec![("account", "remove_delegate_key"), ("coin", "transfer")],
        ] {
            let bytes = move_calls_kind(&package, &calls);
            assert!(
                validate_sponsor_transaction_kind(&bytes, &package).is_err(),
                "batch {calls:?} must be rejected"
            );
        }
    }

    #[test]
    fn sponsor_allowlist_rejects_an_empty_command_list() {
        let package = format!("0x{}", "a".repeat(64));
        let bytes = move_calls_kind(&package, &[]);
        assert!(validate_sponsor_transaction_kind(&bytes, &package).is_err());
    }

    // ---- fixtures from the browser's own encoder ----
    //
    // The fixtures above are built with the Rust BCS types, which cannot catch a
    // shape mismatch between the two encoders. These were produced by
    // @mysten/sui 2.8.0 — the exact encoder `apps/app` ships — for the
    // transactions `Dashboard.tsx` builds: object-ref inputs for the account and
    // registry, a `vector<u8>` pure arg per key, and one MoveCall per selected
    // key.

    const FE_PACKAGE: &str = "0xcee7a6fd8de52ce645c38332bde23d4a30fd9426bc4681409733dd50958a24c6";
    const FE_REMOVE_1: &str = "AAMBAKGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABALKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKyAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAISAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwEAzuem/Y3lLOZFw4MyveI9SjD9lCa8RoFAlzPdUJWKJMYHYWNjb3VudBNyZW1vdmVfZGVsZWdhdGVfa2V5AAMBAAABAQABAgA=";
    const FE_REMOVE_2: &str = "AAQBAKGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABALKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKyAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAISAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwAhIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHAgDO56b9jeUs5kXDgzK94j1KMP2UJrxGgUCXM91QlYokxgdhY2NvdW50E3JlbW92ZV9kZWxlZ2F0ZV9rZXkAAwEAAAEBAAECAADO56b9jeUs5kXDgzK94j1KMP2UJrxGgUCXM91QlYokxgdhY2NvdW50E3JlbW92ZV9kZWxlZ2F0ZV9rZXkAAwEAAAEBAAEDAA==";
    const FE_REMOVE_3: &str = "AAUBAKGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABALKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKyAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAISAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwAhIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHACEgBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcDAM7npv2N5SzmRcODMr3iPUow/ZQmvEaBQJcz3VCViiTGB2FjY291bnQTcmVtb3ZlX2RlbGVnYXRlX2tleQADAQAAAQEAAQIAAM7npv2N5SzmRcODMr3iPUow/ZQmvEaBQJcz3VCViiTGB2FjY291bnQTcmVtb3ZlX2RlbGVnYXRlX2tleQADAQAAAQEAAQMAAM7npv2N5SzmRcODMr3iPUow/ZQmvEaBQJcz3VCViiTGB2FjY291bnQTcmVtb3ZlX2RlbGVnYXRlX2tleQADAQAAAQEAAQQA";
    const FE_ADD_1: &str = "AAMBAKGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABALKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKyAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAISAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwEAzuem/Y3lLOZFw4MyveI9SjD9lCa8RoFAlzPdUJWKJMYHYWNjb3VudBBhZGRfZGVsZWdhdGVfa2V5AAMBAAABAQABAgA=";
    const FE_MIXED_REMOVE_ADD: &str = "AAQBAKGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABALKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKyAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAISAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwAhIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHAgDO56b9jeUs5kXDgzK94j1KMP2UJrxGgUCXM91QlYokxgdhY2NvdW50E3JlbW92ZV9kZWxlZ2F0ZV9rZXkAAwEAAAEBAAECAADO56b9jeUs5kXDgzK94j1KMP2UJrxGgUCXM91QlYokxgdhY2NvdW50EGFkZF9kZWxlZ2F0ZV9rZXkAAwEAAAEBAAEDAA==";
    const FE_ADD_TWICE: &str = "AAQBAKGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABALKysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKyAQAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAISAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwAhIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHAgDO56b9jeUs5kXDgzK94j1KMP2UJrxGgUCXM91QlYokxgdhY2NvdW50EGFkZF9kZWxlZ2F0ZV9rZXkAAwEAAAEBAAECAADO56b9jeUs5kXDgzK94j1KMP2UJrxGgUCXM91QlYokxgdhY2NvdW50EGFkZF9kZWxlZ2F0ZV9rZXkAAwEAAAEBAAEDAA==";

    /// The regression, reproduced from browser-encoded bytes: 2 and 3 keys were
    /// rejected before this fix, 1 key always passed.
    #[test]
    fn validator_accepts_browser_encoded_delegate_key_removals() {
        for (label, fixture) in [
            ("1 key", FE_REMOVE_1),
            ("2 keys", FE_REMOVE_2),
            ("3 keys", FE_REMOVE_3),
        ] {
            let bytes = decode_base64(fixture).expect("fixture must be valid base64");
            validate_sponsor_transaction_kind(&bytes, FE_PACKAGE)
                .unwrap_or_else(|e| panic!("{label} from the browser encoder must pass, got {e}"));
        }
    }

    #[test]
    fn validator_accepts_browser_encoded_add_but_rejects_impure_batches() {
        let add = decode_base64(FE_ADD_1).expect("fixture must be valid base64");
        validate_sponsor_transaction_kind(&add, FE_PACKAGE).expect("a lone add must pass");

        for (label, fixture) in [
            ("remove + add", FE_MIXED_REMOVE_ADD),
            ("add twice", FE_ADD_TWICE),
        ] {
            let bytes = decode_base64(fixture).expect("fixture must be valid base64");
            assert!(
                validate_sponsor_transaction_kind(&bytes, FE_PACKAGE).is_err(),
                "{label} must be rejected"
            );
        }
    }

    /// Same real bytes, a different configured package — the package check still
    /// holds against browser-encoded input.
    #[test]
    fn validator_rejects_browser_encoded_removals_for_a_foreign_package() {
        let bytes = decode_base64(FE_REMOVE_3).expect("fixture must be valid base64");
        let foreign = format!("0x{}", "c".repeat(64));
        assert!(validate_sponsor_transaction_kind(&bytes, &foreign).is_err());
    }

    // ---- validate_sui_address ----

    #[test]
    fn test_sui_address_valid() {
        assert!(validate_sui_address(
            "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        ));
    }

    #[test]
    fn test_sui_address_all_zeros() {
        assert!(validate_sui_address(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_sui_address_uppercase_hex_accepted() {
        assert!(validate_sui_address(&format!("0x{}", "A".repeat(64))));
    }

    #[test]
    fn test_sui_address_missing_0x_prefix() {
        assert!(!validate_sui_address(&"a".repeat(64)));
    }

    #[test]
    fn test_sui_address_too_short() {
        assert!(!validate_sui_address("0xBAD"));
    }

    #[test]
    fn test_sui_address_too_long() {
        assert!(!validate_sui_address(&format!("0x{}", "a".repeat(65))));
    }

    #[test]
    fn test_sui_address_non_hex_char() {
        // 'z' is not a hex digit
        let bad = format!("0x{}z{}", "a".repeat(32), "b".repeat(31));
        assert!(!validate_sui_address(&bad));
    }

    #[test]
    fn test_sui_address_empty() {
        assert!(!validate_sui_address(""));
    }

    // ---- validate_digest ----

    #[test]
    fn test_digest_valid_43_chars() {
        assert!(validate_digest(&"1".repeat(43)));
    }

    #[test]
    fn test_digest_valid_44_chars() {
        assert!(validate_digest(&"1".repeat(44)));
    }

    #[test]
    fn test_digest_valid_42_chars_leading_zero_encoding() {
        // 32-byte digests with leading zero bytes encode shorter than 43.
        assert!(validate_digest(&"1".repeat(42)));
    }

    #[test]
    fn test_digest_too_short_31() {
        assert!(!validate_digest(&"1".repeat(31)));
    }

    #[test]
    fn test_digest_too_long_45() {
        assert!(!validate_digest(&"1".repeat(45)));
    }

    #[test]
    fn test_digest_invalid_char_zero() {
        // '0' is excluded from base58
        let mut d: Vec<char> = "1".repeat(43).chars().collect();
        d[10] = '0';
        assert!(!validate_digest(&d.into_iter().collect::<String>()));
    }

    #[test]
    fn test_digest_invalid_char_capital_o() {
        let mut d: Vec<char> = "1".repeat(43).chars().collect();
        d[5] = 'O';
        assert!(!validate_digest(&d.into_iter().collect::<String>()));
    }

    #[test]
    fn test_digest_invalid_char_capital_i() {
        let mut d: Vec<char> = "1".repeat(43).chars().collect();
        d[0] = 'I';
        assert!(!validate_digest(&d.into_iter().collect::<String>()));
    }

    #[test]
    fn test_digest_invalid_char_lowercase_l() {
        let mut d: Vec<char> = "1".repeat(43).chars().collect();
        d[20] = 'l';
        assert!(!validate_digest(&d.into_iter().collect::<String>()));
    }

    #[test]
    fn test_digest_empty() {
        assert!(!validate_digest(""));
    }

    // ---- validate_sponsored_signature_len ----

    #[test]
    fn test_sponsored_signature_len_accepts_native_and_zklogin_sizes() {
        assert!(validate_sponsored_signature_len(65));
        assert!(validate_sponsored_signature_len(97));
        assert!(validate_sponsored_signature_len(512));
        assert!(validate_sponsored_signature_len(
            MAX_SPONSORED_SIGNATURE_BYTES
        ));
    }

    #[test]
    fn test_sponsored_signature_len_rejects_out_of_bounds() {
        assert!(!validate_sponsored_signature_len(64));
        assert!(!validate_sponsored_signature_len(
            MAX_SPONSORED_SIGNATURE_BYTES + 1
        ));
    }

    // ---- decode_base64 ----

    #[test]
    fn test_base64_valid_decodes() {
        let result = decode_base64("AAAAAAAAAAAAAAAA"); // 12 zero bytes
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 12);
    }

    #[test]
    fn test_base64_invalid_returns_none() {
        assert!(decode_base64("not!!valid##base64").is_none());
    }

    #[test]
    fn test_base64_empty_decodes_to_empty() {
        let result = decode_base64("").unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_base64_exactly_10_bytes() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 10]);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded.len(), 10);
    }

    #[test]
    fn test_base64_7000_bytes_passes_size_check() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 7000]);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded.len(), 7000);
        assert!(decoded.len() >= 10 && decoded.len() <= 7000);
    }

    #[test]
    fn test_base64_7001_bytes_fails_size_check() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 7001]);
        let decoded = decode_base64(&encoded).unwrap();
        assert!(decoded.len() > 7000); // caller must reject this
    }

    // ---- mask_upstream — must never leak internal details ----

    #[test]
    fn test_mask_upstream_429_to_503() {
        let (status, code, msg) = mask_upstream(429);
        assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "sponsor_overloaded");
        assert_eq!(msg, "Sponsor service temporarily overloaded");
    }

    #[test]
    fn test_mask_upstream_401_to_502() {
        let (status, code, msg) = mask_upstream(401);
        assert_eq!(status, axum::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, "sponsor_misconfigured");
        assert_eq!(msg, "Sponsor service misconfigured");
    }

    #[test]
    fn test_mask_upstream_403_to_502() {
        let (status, code, msg) = mask_upstream(403);
        assert_eq!(status, axum::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, "sponsor_misconfigured");
        assert_eq!(msg, "Sponsor service misconfigured");
    }

    #[test]
    fn test_mask_upstream_500_to_502() {
        let (status, code, msg) = mask_upstream(500);
        assert_eq!(status, axum::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, "sponsor_upstream_error");
        assert_eq!(msg, "Sponsor service error");
    }

    #[test]
    fn test_mask_upstream_503_to_502() {
        let (status, code, msg) = mask_upstream(503);
        assert_eq!(status, axum::http::StatusCode::BAD_GATEWAY);
        assert_eq!(code, "sponsor_upstream_error");
        assert_eq!(msg, "Sponsor service error");
    }

    #[test]
    fn test_mask_upstream_404_to_400() {
        let (status, code, msg) = mask_upstream(404);
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(code, "sponsor_rejected");
        assert_eq!(msg, "Sponsor request rejected");
    }

    #[test]
    fn test_reactivate_already_active_is_its_own_message() {
        let raw = br#"{"error":"MoveAbort in 1st command, abort code: 11, in '0xabc::account::reactivate_account'","code":"account_already_active"}"#;
        let (status, code, msg) = reactivate_rejection(raw).unwrap();
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert_eq!(code, "account_already_active");
        assert_eq!(
            msg,
            "This account is already active, so it cannot be reactivated."
        );
        assert!(!msg.contains("MoveAbort"));
        assert!(!msg.contains("0xabc"));
    }

    #[test]
    fn test_reactivate_quarantine_is_its_own_message() {
        let raw = br#"{"code":"account_quarantined","error":"upstream text"}"#;
        let (status, code, msg) = reactivate_rejection(raw).unwrap();
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert_eq!(code, "account_quarantined");
        assert_eq!(
            msg,
            "This account is still locked, so it cannot be reactivated yet."
        );
        assert!(!msg.contains("upstream"));
    }

    #[test]
    fn test_reactivate_rejection_ignores_unclassified_bodies() {
        assert!(reactivate_rejection(br#"{"error":"MoveAbort abort code: 11"}"#).is_none());
        assert!(reactivate_rejection(br#"{"code":"sponsor_rejected"}"#).is_none());
        assert!(reactivate_rejection(b"not json").is_none());
    }

    #[test]
    fn test_mask_upstream_returns_static_strings_only() {
        // Verify no dynamic content leaks through for any common error status
        for status_code in [400u16, 401, 403, 404, 422, 429, 500, 502, 503] {
            let (_, code, msg) = mask_upstream(status_code);
            assert!(!msg.is_empty(), "mask must always return a message");
            // Message must not look like it came from serde_json / reqwest
            assert!(!msg.contains("Error"), "raw error strings must not leak");
            // Codes are the client's only signal, so they must be stable,
            // lowercase snake_case identifiers rather than free text.
            assert!(!code.is_empty(), "mask must always return a code");
            assert!(
                code.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "code {code} must be a stable snake_case identifier"
            );
        }
    }
}

//! In-process Enoki HTTP sponsorship client, Sui Ed25519 private-key parser,
//! and direct Address-Balance transaction builder/executor.
//!
//! Replaces `services/server/scripts/sidecar/enoki.ts`, `wallet.ts`,
//! `address-balance.ts`, and `routes/sponsor.ts`.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock as StdRwLock};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sui_crypto::{ed25519::Ed25519PrivateKey, SuiSigner, SuiVerifier};
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{
    changed_object, ExecuteTransactionRequest, ExecutedTransaction, GetEpochRequest,
    GetServiceInfoRequest, GetTransactionRequest,
};
use sui_sdk_types::{
    Address, Digest, ExecutionStatus, GasPayment, PersonalMessage, ProgrammableTransaction,
    Transaction, TransactionEffects, TransactionExpiration, TransactionKind, UserSignature,
};
use uuid::Uuid;

const DEFAULT_ENOKI_API_URL: &str = "https://api.enoki.mystenlabs.com";
const DEFAULT_GAS_BUDGET: u64 = 50_000_000; // 0.05 SUI

static SUI_GRPC_CLIENT_POOL: OnceLock<StdRwLock<HashMap<String, sui_rpc::Client>>> =
    OnceLock::new();

/// Returns a cloned `sui_rpc::Client` backed by a shared HTTP/2 `tonic::transport::Channel`
/// for `grpc_url`, avoiding a fresh TCP + TLS 1.3 handshake on every RPC call.
pub fn shared_sui_grpc_client(grpc_url: &str) -> Result<sui_rpc::Client, String> {
    let key = grpc_url.trim();
    let pool = SUI_GRPC_CLIENT_POOL.get_or_init(|| StdRwLock::new(HashMap::new()));
    if let Ok(guard) = pool.read() {
        if let Some(client) = guard.get(key) {
            return Ok(client.clone());
        }
    }
    let client = sui_rpc::Client::new(key)
        .map_err(|e| format!("invalid Sui gRPC URL '{grpc_url}': {e}"))?;
    if let Ok(mut guard) = pool.write() {
        guard.insert(key.to_owned(), client.clone());
    }
    Ok(client)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnokiSponsorOutput {
    pub bytes: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnokiExecuteOutput {
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CreatedObjectInfo {
    pub object_id: String,
    pub version: u64,
    pub digest: String,
    pub object_type: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WalletTxOutcome {
    pub digest: String,
    pub created_objects: Vec<CreatedObjectInfo>,
    pub used_enoki: bool,
}

#[derive(Debug, Clone)]
pub enum EnokiError {
    NotConfigured,
    BadRequest(String),
    FallbackEligible { status: u16, message: String },
    Rejected { status: u16, message: String },
    Transport(String),
}

impl std::fmt::Display for EnokiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("ENOKI_API_KEY is not configured"),
            Self::BadRequest(msg) => write!(f, "Enoki bad request: {msg}"),
            Self::FallbackEligible { status, message } => {
                write!(f, "Enoki transient/rate-limit error ({status}): {message}")
            }
            Self::Rejected { status, message } => {
                write!(f, "Enoki rejected request ({status}): {message}")
            }
            Self::Transport(msg) => write!(f, "Enoki transport error: {msg}"),
        }
    }
}

impl std::error::Error for EnokiError {}

impl EnokiError {
    #[must_use]
    pub fn is_fallback_eligible(&self) -> bool {
        matches!(
            self,
            Self::NotConfigured | Self::FallbackEligible { .. } | Self::Transport(_)
        )
    }

    #[must_use]
    pub fn upstream_status_u16(&self) -> u16 {
        match self {
            Self::NotConfigured => 503,
            Self::BadRequest(_) => 400,
            Self::FallbackEligible { status, .. } | Self::Rejected { status, .. } => *status,
            Self::Transport(_) => 502,
        }
    }

    #[must_use]
    pub fn error_message(&self) -> String {
        match self {
            Self::NotConfigured => "Enoki sponsorship is not configured".to_owned(),
            Self::BadRequest(msg)
            | Self::FallbackEligible { message: msg, .. }
            | Self::Rejected { message: msg, .. }
            | Self::Transport(msg) => msg.clone(),
        }
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn http_status_code(&self) -> axum::http::StatusCode {
        match self {
            Self::NotConfigured => axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Self::BadRequest(_) => axum::http::StatusCode::BAD_REQUEST,
            Self::FallbackEligible { status: 429, .. } => axum::http::StatusCode::TOO_MANY_REQUESTS,
            Self::FallbackEligible { .. } | Self::Transport(_) => {
                axum::http::StatusCode::BAD_GATEWAY
            }
            Self::Rejected { status, .. } => {
                axum::http::StatusCode::from_u16(*status)
                    .unwrap_or(axum::http::StatusCode::BAD_REQUEST)
            }
        }
    }
}

/// Sanitizes an upstream HTTP/RPC error body before logging or embedding in diagnostic strings:
/// strips ASCII control characters, redacts `Bearer <token>` credentials, and caps length at 512 chars.
#[must_use]
pub fn sanitize_upstream_error_for_logging(raw: &str) -> String {
    const MAX_CHARS: usize = 512;
    let mut cleaned = String::with_capacity(raw.len().min(MAX_CHARS + 32));
    for ch in raw.trim().chars() {
        if ch.is_control() {
            if !cleaned.ends_with(' ') {
                cleaned.push(' ');
            }
        } else {
            cleaned.push(ch);
        }
    }
    // Redact any accidental Bearer token reflection in upstream proxy/gateway errors.
    let redacted = if let Some(idx) = cleaned.to_ascii_lowercase().find("bearer ") {
        let prefix = &cleaned[..idx];
        let after_bearer = &cleaned[idx + 7..];
        let token_end = after_bearer
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')'))
            .unwrap_or(after_bearer.len());
        format!("{prefix}Bearer [REDACTED]{}", &after_bearer[token_end..])
    } else {
        cleaned
    };
    if redacted.chars().count() > MAX_CHARS {
        let truncated: String = redacted.chars().take(MAX_CHARS).collect();
        format!("{truncated}...(truncated)")
    } else {
        redacted
    }
}

/// Returns true if `ENOKI_API_KEY` or `ENOKI_SECRET_KEY` is configured in the environment.
#[must_use]
pub fn enoki_is_enabled() -> bool {
    enoki_api_key().is_some()
}

fn enoki_api_key() -> Option<String> {
    std::env::var("ENOKI_API_KEY")
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("ENOKI_SECRET_KEY")
                .ok()
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
}

fn enoki_api_url() -> String {
    std::env::var("ENOKI_API_URL")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_ENOKI_API_URL.to_owned())
}

/// Default `allowedMoveCallTargets` when `ENOKI_RESTRICT_MOVE_CALLS=true`,
/// matching `services/server/scripts/sidecar/routes/sponsor.ts`.
#[must_use]
pub fn default_sponsor_allowed_move_call_targets(
    package_id: &str,
    seal_policy_package_id: &str,
) -> Option<Vec<String>> {
    let restrict = std::env::var("ENOKI_RESTRICT_MOVE_CALLS")
        .ok()
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    if !restrict {
        return None;
    }
    let mut pkgs = vec![package_id.trim()];
    let policy_pkg = seal_policy_package_id.trim();
    if !policy_pkg.is_empty() && policy_pkg != package_id.trim() {
        pkgs.push(policy_pkg);
    }
    let mut targets = Vec::new();
    for pkg in pkgs {
        if pkg.is_empty() {
            continue;
        }
        for func in [
            "create_account",
            "add_delegate_key",
            "remove_delegate_key",
            "reactivate_account",
            "revoke_all_delegate_keys",
            "bump_access_counter",
            "seal_approve",
            "delete_account",
        ] {
            targets.push(format!("{pkg}::account::{func}"));
        }
    }
    if targets.is_empty() {
        None
    } else {
        Some(targets)
    }
}

/// Detects `account::reactivate_account` MoveAbort codes 11 (`account_already_active`)
/// and 20 (`account_quarantined`), matching `reactivateRejectionCode` in `enoki.ts`.
#[must_use]
pub fn reactivate_rejection_code(message: &str) -> Option<(&'static str, &'static str)> {
    let lower = message.to_ascii_lowercase();
    if !lower.contains("moveabort") {
        return None;
    }
    let names_reactivate = message.contains("::account::reactivate_account")
        || message.contains("\"functionName\":\"reactivate_account\"")
        || message.contains("\"functionName\": \"reactivate_account\"");
    if !names_reactivate {
        return None;
    }
    if lower.contains("abort code: 11")
        || message.contains("\"abortCode\":\"11\"")
        || message.contains("\"abortCode\": \"11\"")
    {
        return Some((
            "account_already_active",
            "This account is already active, so it cannot be reactivated.",
        ));
    }
    if lower.contains("abort code: 20")
        || message.contains("\"abortCode\":\"20\"")
        || message.contains("\"abortCode\": \"20\"")
    {
        return Some((
            "account_quarantined",
            "This account is still locked, so it cannot be reactivated yet.",
        ));
    }
    None
}

#[derive(Deserialize)]
struct EnokiEnvelope<T> {
    data: T,
}

fn classify_enoki_http_error(status: u16, body: &str) -> EnokiError {
    let sanitized = sanitize_upstream_error_for_logging(body);
    let lower = sanitized.to_ascii_lowercase();
    if status == 429
        || status >= 500
        || lower.contains("insufficient gas")
        || lower.contains("gas pool")
        || lower.contains("rate limit")
        || lower.contains("too many requests")
    {
        EnokiError::FallbackEligible {
            status,
            message: sanitized,
        }
    } else if status == 400 {
        EnokiError::BadRequest(sanitized)
    } else {
        EnokiError::Rejected {
            status,
            message: sanitized,
        }
    }
}

/// Sponsor a `transactionBlockKindBytes` (base64) via Enoki HTTP API (`POST /v1/transaction-blocks/sponsor`).
pub async fn enoki_sponsor_transaction_kind(
    http: &reqwest::Client,
    network: &str,
    sender: &str,
    tx_kind_bytes_b64: &str,
    allowed_move_call_targets: Option<Vec<String>>,
) -> Result<EnokiSponsorOutput, EnokiError> {
    enoki_sponsor_transaction_kind_with_addresses(
        http,
        network,
        sender,
        tx_kind_bytes_b64,
        allowed_move_call_targets,
        None,
    )
    .await
}

/// Sponsor a `transactionBlockKindBytes` (base64) via Enoki HTTP API (`POST /v1/transaction-blocks/sponsor`)
/// with optional `allowedMoveCallTargets` and `allowedAddresses`.
pub async fn enoki_sponsor_transaction_kind_with_addresses(
    http: &reqwest::Client,
    network: &str,
    sender: &str,
    tx_kind_bytes_b64: &str,
    allowed_move_call_targets: Option<Vec<String>>,
    allowed_addresses: Option<Vec<String>>,
) -> Result<EnokiSponsorOutput, EnokiError> {
    let api_key = enoki_api_key().ok_or(EnokiError::NotConfigured)?;
    let api_url = enoki_api_url();
    let url = format!("{api_url}/v1/transaction-blocks/sponsor");

    let mut payload = serde_json::json!({
        "network": network,
        "transactionBlockKindBytes": tx_kind_bytes_b64,
        "sender": sender,
    });
    if let Some(targets) = allowed_move_call_targets {
        if !targets.is_empty() {
            payload["allowedMoveCallTargets"] = serde_json::json!(targets);
        }
    }
    if let Some(addrs) = allowed_addresses {
        if !addrs.is_empty() {
            payload["allowedAddresses"] = serde_json::json!(addrs);
        }
    }

    let resp = http
        .post(&url)
        .bearer_auth(&api_key)
        .json(&payload)
        .send()
        .await
        .map_err(|e| EnokiError::Transport(e.to_string()))?;

    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(classify_enoki_http_error(status, &body));
    }

    let parsed: EnokiEnvelope<EnokiSponsorOutput> = resp
        .json()
        .await
        .map_err(|e| EnokiError::Transport(format!("invalid Enoki sponsor JSON: {e}")))?;
    Ok(parsed.data)
}

/// Execute a sponsored transaction via Enoki HTTP API (`POST /v1/transaction-blocks/sponsor/:digest`).
pub async fn enoki_execute_sponsored_transaction(
    http: &reqwest::Client,
    digest: &str,
    signature: &str,
) -> Result<EnokiExecuteOutput, EnokiError> {
    let api_key = enoki_api_key().ok_or(EnokiError::NotConfigured)?;
    let api_url = enoki_api_url();
    let encoded_digest = percent_encoding::utf8_percent_encode(
        digest,
        percent_encoding::NON_ALPHANUMERIC,
    );
    let url = format!("{api_url}/v1/transaction-blocks/sponsor/{encoded_digest}");

    let payload = serde_json::json!({
        "digest": digest,
        "signature": signature,
    });

    let resp = http
        .post(&url)
        .bearer_auth(&api_key)
        .json(&payload)
        .send()
        .await
        .map_err(|e| EnokiError::Transport(e.to_string()))?;

    let status = resp.status().as_u16();
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(classify_enoki_http_error(status, &body));
    }

    let parsed: EnokiEnvelope<EnokiExecuteOutput> = resp
        .json()
        .await
        .map_err(|e| EnokiError::Transport(format!("invalid Enoki execute JSON: {e}")))?;
    Ok(parsed.data)
}

/// Executes a sponsored transaction via Enoki and optionally verifies on-chain effects
/// (`verifyExecutedTransaction` in `services/server/scripts/sidecar/routes/sponsor.ts`).
pub async fn enoki_execute_and_verify_sponsored_transaction(
    http: &reqwest::Client,
    digest: &str,
    signature: &str,
    verify_effects: bool,
    grpc_url: Option<&str>,
) -> Result<EnokiExecuteOutput, EnokiError> {
    let mut executed = enoki_execute_sponsored_transaction(http, digest, signature).await?;
    if !verify_effects {
        return Ok(executed);
    }

    let Some(grpc) = grpc_url.filter(|s| !s.trim().is_empty()) else {
        return Err(EnokiError::Transport(
            "missing Sui gRPC URL for verifyEffects".to_owned(),
        ));
    };
    let mut client = shared_sui_grpc_client(grpc).map_err(EnokiError::Transport)?;
    let tx_digest = if executed.digest.is_empty() {
        digest
    } else {
        &executed.digest
    };
    let parsed_digest: Digest = tx_digest
        .parse()
        .map_err(|e| EnokiError::BadRequest(format!("invalid executed digest '{tx_digest}': {e}")))?;

    let mut last_err = String::new();
    for attempt in 0..10u64 {
        let req = GetTransactionRequest::new(&parsed_digest).with_read_mask(FieldMask::from_paths([
            "digest",
            "transaction.sender",
            "effects.status",
            "effects.bcs",
        ]));
        match client.ledger_client().get_transaction(req).await {
            Ok(resp) => {
                if let Some(tx) = resp.into_inner().transaction {
                    let sender = tx.transaction.as_ref().and_then(|t| t.sender.clone());
                    let succeeded = tx
                        .effects
                        .as_ref()
                        .and_then(|e| e.bcs.as_ref())
                        .and_then(|b| b.deserialize::<TransactionEffects>().ok())
                        .map(|eff| matches!(eff.status(), ExecutionStatus::Success))
                        .unwrap_or_else(|| {
                            tx.effects
                                .as_ref()
                                .and_then(|e| e.status.as_ref())
                                .and_then(|s| s.success)
                                .unwrap_or(false)
                        });
                    if !succeeded {
                        return Err(EnokiError::Rejected {
                            status: 422,
                            message: serde_json::json!({
                                "error": "sponsored transaction did not succeed on-chain"
                            })
                            .to_string(),
                        });
                    }
                    executed.sender = sender;
                    return Ok(executed);
                }
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(1000 + attempt * 500)).await;
    }

    Err(EnokiError::Transport(format!(
        "executed transaction not found on-chain after retries: {last_err}"
    )))
}

// ---------------------------------------------------------------------------
// Sui Ed25519 Private Key Parsing (`suiprivkey1...` Bech32, hex, base64)
// ---------------------------------------------------------------------------

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ u32::from(v);
        for (i, &g) in GEN.iter().enumerate() {
            if ((top >> i) & 1) != 0 {
                chk ^= g;
            }
        }
    }
    chk
}

fn decode_bech32_suiprivkey(input: &str) -> Result<Vec<u8>, String> {
    let lower = input.trim().to_ascii_lowercase();
    let sep = lower
        .rfind('1')
        .ok_or_else(|| "invalid Bech32 key: missing separator '1'".to_owned())?;
    let (hrp, data_with_sep) = lower.split_at(sep);
    if hrp != "suiprivkey" {
        return Err(format!("unexpected Bech32 HRP '{hrp}', expected 'suiprivkey'"));
    }
    let data_str = &data_with_sep[1..];
    if data_str.len() < 6 {
        return Err("Bech32 data too short".to_owned());
    }
    let mut data = Vec::with_capacity(data_str.len());
    for ch in data_str.bytes() {
        let idx = BECH32_CHARSET
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| format!("invalid Bech32 character '{}'", ch as char))?;
        data.push(idx as u8);
    }

    let mut expand = Vec::with_capacity(hrp.len() * 2 + 1 + data.len());
    for b in hrp.bytes() {
        expand.push(b >> 5);
    }
    expand.push(0);
    for b in hrp.bytes() {
        expand.push(b & 0x1f);
    }
    expand.extend_from_slice(&data);
    // Accept both BIP-173 Bech32 (1) and BIP-350 Bech32m (0x2bc830a3).
    let polymod = bech32_polymod(&expand);
    if polymod != 1 && polymod != 0x2bc830a3 {
        return Err("Bech32 checksum verification failed".to_owned());
    }

    let payload_5bit = &data[..data.len() - 6];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity((payload_5bit.len() * 5) / 8);
    for &val in payload_5bit {
        acc = (acc << 5) | u32::from(val);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || ((acc << (8 - bits)) & 0xff) != 0 {
        return Err("invalid Bech32 5-to-8 bit padding".to_owned());
    }
    Ok(out)
}

/// Parses an Ed25519 32-byte private key seed from any format supported by MemWal / Sui CLI:
/// - `suiprivkey1...` (SIP-15 Bech32 with `0x00` Ed25519 scheme byte + 32-byte seed)
/// - `0x`-prefixed or raw 64-character hex (32-byte seed)
/// - Standard or URL-safe base64 (either 32-byte raw seed or 33-byte `[0x00, ..32]` Sui keystore)
pub fn parse_sui_private_key_bytes(raw: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty Sui private key".to_owned());
    }

    let secret_bytes: [u8; 32] = if trimmed
        .get(..11)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("suiprivkey1"))
    {
        let decoded = decode_bech32_suiprivkey(trimmed)?;
        if decoded.len() != 33 {
            return Err(format!(
                "suiprivkey payload must be 33 bytes (1 scheme + 32 seed), got {}",
                decoded.len()
            ));
        }
        if decoded[0] != 0x00 {
            return Err(format!(
                "unsupported Sui key scheme flag 0x{:02x} (only Ed25519 0x00 is supported)",
                decoded[0]
            ));
        }
        decoded[1..33]
            .try_into()
            .map_err(|_| "suiprivkey seed slice must be 32 bytes".to_owned())?
    } else {
        let hex_candidate = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        if hex_candidate.len() == 64 && hex_candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
            let bytes = hex::decode(hex_candidate)
                .map_err(|e| format!("invalid hex private key: {e}"))?;
            bytes
                .try_into()
                .map_err(|_| "hex private key must be 32 bytes".to_owned())?
        } else {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(trimmed)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
                .map_err(|e| format!("invalid Sui private key encoding: {e}"))?;
            match decoded.len() {
                32 => decoded
                    .try_into()
                    .map_err(|_| "decoded base64 key must be 32 bytes".to_owned())?,
                33 if decoded[0] == 0x00 => decoded[1..33]
                    .try_into()
                    .map_err(|_| "decoded keystore key seed must be 32 bytes".to_owned())?,
                33 => {
                    return Err(format!(
                        "unsupported Sui keystore scheme byte 0x{:02x} (expected 0x00 for Ed25519)",
                        decoded[0]
                    ));
                }
                other => {
                    return Err(format!(
                        "decoded base64 key must be 32 or 33 bytes, got {other}"
                    ));
                }
            }
        }
    };

    Ok(secret_bytes)
}

pub fn parse_sui_private_key(raw: &str) -> Result<Ed25519PrivateKey, String> {
    parse_sui_private_key_bytes(raw).map(Ed25519PrivateKey::new)
}

/// Derives the canonical `0x`-prefixed 32-byte Sui address from a private key string.
pub fn derive_sui_address(raw_key: &str) -> Result<String, String> {
    let key = parse_sui_private_key(raw_key)?;
    Ok(key.public_key().derive_address().to_string())
}

/// Signs BCS-encoded `Transaction` (`TransactionData`) bytes with `raw_key` and returns
/// `(base64_signature, transaction_digest)`.
pub fn sign_transaction_bytes(raw_key: &str, tx_bytes: &[u8]) -> Result<(String, String), String> {
    let key = parse_sui_private_key(raw_key)?;
    let tx: Transaction =
        bcs::from_bytes(tx_bytes).map_err(|e| format!("invalid Transaction BCS: {e}"))?;
    let sig = key
        .sign_transaction(&tx)
        .map_err(|e| format!("failed to sign transaction: {e}"))?;
    key.verifying_key()
        .verify_transaction(&tx, &sig)
        .map_err(|e| format!("signature self-verification failed: {e}"))?;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    Ok((sig_b64, tx.digest().to_string()))
}

/// Signs a Sui personal message and returns the base64-encoded `UserSignature`.
pub fn sign_personal_message_bytes(
    raw_key: &str,
    message: &[u8],
) -> Result<String, String> {
    let key = parse_sui_private_key(raw_key)?;
    let personal = PersonalMessage(message.into());
    let sig: UserSignature = key
        .sign_personal_message(&personal)
        .map_err(|e| format!("failed to sign personal message: {e}"))?;
    Ok(sig.to_base64())
}

// ---------------------------------------------------------------------------
// Direct Address-Balance Execution + Enoki-First Submission
// ---------------------------------------------------------------------------

fn extract_created_objects(tx: &ExecutedTransaction) -> Vec<CreatedObjectInfo> {
    let mut type_map = std::collections::HashMap::new();
    if let Some(obj_set) = &tx.objects {
        for obj in &obj_set.objects {
            if let (Some(id), Some(ty)) = (&obj.object_id, &obj.object_type) {
                type_map.insert(id.clone(), ty.clone());
            }
        }
    }

    let mut created = Vec::new();
    if let Some(effects) = &tx.effects {
        for changed in &effects.changed_objects {
            if changed.id_operation == Some(changed_object::IdOperation::Created as i32) {
                if let Some(id) = &changed.object_id {
                    let object_type = changed
                        .object_type
                        .clone()
                        .or_else(|| type_map.get(id).cloned());
                    created.push(CreatedObjectInfo {
                        object_id: id.clone(),
                        version: changed.output_version.unwrap_or(1),
                        digest: changed.output_digest.clone().unwrap_or_default(),
                        object_type,
                    });
                }
            }
        }
    }
    created
}

fn verify_executed_tx_success(tx: &ExecutedTransaction) -> Result<String, String> {
    let digest = tx
        .digest
        .clone()
        .ok_or_else(|| "executed transaction omitted digest".to_owned())?;
    if let Some(effects_proto) = &tx.effects {
        if let Ok(effects) = TransactionEffects::try_from(effects_proto) {
            if let ExecutionStatus::Failure { error, command } = effects.status() {
                return Err(format!(
                    "transaction {digest} failed at command {command:?}: {error:?}"
                ));
            }
        }
    }
    Ok(digest)
}

/// Fetches a transaction by digest from Sui gRPC (retrying briefly if Enoki just executed it)
/// to extract created objects and verify execution status.
pub async fn fetch_executed_transaction_outcome(
    grpc_url: &str,
    digest: &str,
    used_enoki: bool,
) -> Result<WalletTxOutcome, String> {
    let mut client = shared_sui_grpc_client(grpc_url)?;
    let parsed_digest: Digest = digest
        .parse()
        .map_err(|e| format!("invalid transaction digest '{digest}': {e}"))?;

    for attempt in 0..8 {
        let req = GetTransactionRequest::new(&parsed_digest)
            .with_read_mask(FieldMask::from_paths(["digest", "effects", "objects"]));
        match client.ledger_client().get_transaction(req).await {
            Ok(resp) => {
                if let Some(tx) = resp.into_inner().transaction {
                    verify_executed_tx_success(&tx)?;
                    let created_objects = extract_created_objects(&tx);
                    return Ok(WalletTxOutcome {
                        digest: digest.to_owned(),
                        created_objects,
                        used_enoki,
                    });
                }
            }
            Err(status) if status.code() == tonic::Code::NotFound && attempt < 7 => {}
            Err(status) if attempt < 4 => {
                tracing::debug!(
                    attempt,
                    digest,
                    error = %status,
                    "transient gRPC error fetching executed transaction; retrying"
                );
            }
            Err(status) => {
                return Err(format!(
                    "failed to fetch executed transaction {digest} via gRPC: {status}"
                ));
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(250 * (attempt + 1) as u64)).await;
    }

    // Even if the fullnode hasn't indexed the transaction yet, return the digest if Enoki succeeded.
    Ok(WalletTxOutcome {
        digest: digest.to_owned(),
        created_objects: Vec::new(),
        used_enoki,
    })
}

/// Builds a gasless (`GasPayment.objects = []`) `ValidDuring` address-balance transaction
/// from `ptb`, signs it with `raw_private_key`, and executes it directly via Sui gRPC.
///
/// Mirrors `signAndExecuteWithAddressBalance` in `services/server/scripts/sidecar/address-balance.ts`.
pub async fn execute_ptb_with_address_balance(
    grpc_url: &str,
    raw_private_key: &str,
    ptb: ProgrammableTransaction,
    gas_budget_override: Option<u64>,
) -> Result<WalletTxOutcome, String> {
    let key = parse_sui_private_key(raw_private_key)?;
    let sender: Address = key.public_key().derive_address();

    let mut client = shared_sui_grpc_client(grpc_url)?;
    let mut epoch_client = client.clone();
    let mut info_client = client.clone();
    let mut epoch_ledger = epoch_client.ledger_client();
    let mut info_ledger = info_client.ledger_client();

    // Fetch current epoch + reference gas price from GetEpoch and chain identifier from GetServiceInfo concurrently.
    let (epoch_res, info_res) = tokio::join!(
        epoch_ledger.get_epoch(
            GetEpochRequest::latest()
                .with_read_mask(FieldMask::from_paths(["epoch", "reference_gas_price"])),
        ),
        info_ledger.get_service_info(GetServiceInfoRequest::default()),
    );

    let epoch_resp = epoch_res
        .map_err(|e| format!("GetEpoch gRPC failed: {e}"))?
        .into_inner();
    let epoch_info = epoch_resp
        .epoch
        .ok_or_else(|| "GetEpoch response omitted epoch".to_owned())?;
    let current_epoch = epoch_info.epoch.unwrap_or(0);
    let gas_price = epoch_info.reference_gas_price.unwrap_or(1_000).max(1);

    let service_info = info_res
        .map_err(|e| format!("GetServiceInfo gRPC failed: {e}"))?
        .into_inner();
    let chain_id_str = service_info
        .chain_id
        .ok_or_else(|| "GetServiceInfo omitted chain_id".to_owned())?;
    let chain_digest: Digest = chain_id_str
        .parse()
        .map_err(|e| format!("invalid chain_id digest '{chain_id_str}': {e}"))?;

    let uuid = Uuid::new_v4();
    let b = uuid.as_bytes();
    let nonce = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);

    let transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(ptb),
        sender,
        gas_payment: GasPayment {
            objects: Vec::new(),
            owner: sender,
            price: gas_price,
            budget: gas_budget_override.unwrap_or(DEFAULT_GAS_BUDGET),
        },
        expiration: TransactionExpiration::ValidDuring {
            min_epoch: Some(current_epoch),
            max_epoch: Some(current_epoch + 1),
            min_timestamp: None,
            max_timestamp: None,
            chain: chain_digest,
            nonce,
        },
    };

    let sig: UserSignature = key
        .sign_transaction(&transaction)
        .map_err(|e| format!("failed to sign address-balance transaction: {e}"))?;

    let mut exec_req = ExecuteTransactionRequest::default();
    exec_req.transaction = Some(transaction.into());
    exec_req.signatures = vec![sig.into()];
    exec_req.read_mask = Some(FieldMask::from_paths(["digest", "effects", "objects"]));

    let exec_resp = client
        .execution_client()
        .execute_transaction(exec_req)
        .await
        .map_err(|e| format!("ExecuteTransaction gRPC failed: {e}"))?
        .into_inner();

    let executed = exec_resp
        .transaction
        .ok_or_else(|| "ExecuteTransaction response omitted transaction".to_owned())?;
    let digest = verify_executed_tx_success(&executed)?;
    let created_objects = extract_created_objects(&executed);

    Ok(WalletTxOutcome {
        digest,
        created_objects,
        used_enoki: false,
    })
}

/// Verifies that the BCS `Transaction` returned by Enoki `sponsor` matches our expected
/// `sender` and `ProgrammableTransaction` kind (`assertSponsoredRegisterTransaction` /
/// `assertSponsoredRegisterTransactionKind` in `walrus-upload-journal.ts`).
pub fn verify_sponsored_transaction_matches_ptb(
    sponsored_tx_bytes: &[u8],
    expected_sender: Address,
    expected_ptb: &ProgrammableTransaction,
) -> Result<(), String> {
    let tx: Transaction = bcs::from_bytes(sponsored_tx_bytes)
        .map_err(|e| format!("invalid sponsored Transaction BCS: {e}"))?;
    if tx.sender != expected_sender {
        return Err(format!(
            "Enoki sponsored transaction sender mismatch: expected {expected_sender}, got {}",
            tx.sender
        ));
    }
    match &tx.kind {
        TransactionKind::ProgrammableTransaction(ptb) if ptb == expected_ptb => Ok(()),
        _ => Err(
            "Enoki sponsored transaction kind does not match the requested ProgrammableTransaction"
                .to_owned(),
        ),
    }
}

/// Executes a `ProgrammableTransaction` using Enoki sponsorship first (when `ENOKI_API_KEY`
/// is set and `force_direct` is false), automatically falling back to direct address-balance
/// signing on Enoki rate limits (429), 5xx, transport errors, or gas-pool exhaustion.
///
/// Mirrors `submitSidecarTransaction` in `services/server/scripts/sidecar/enoki.ts`.
pub async fn submit_wallet_ptb(
    http: &reqwest::Client,
    grpc_url: &str,
    network: &str,
    raw_private_key: &str,
    ptb: ProgrammableTransaction,
    force_direct: bool,
    need_created_objects: bool,
) -> Result<WalletTxOutcome, String> {
    submit_wallet_ptb_with_allowed_addresses(
        http,
        grpc_url,
        network,
        raw_private_key,
        ptb,
        None,
        force_direct,
        need_created_objects,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn submit_wallet_ptb_with_allowed_addresses(
    http: &reqwest::Client,
    grpc_url: &str,
    network: &str,
    raw_private_key: &str,
    ptb: ProgrammableTransaction,
    allowed_addresses: Option<Vec<String>>,
    force_direct: bool,
    need_created_objects: bool,
) -> Result<WalletTxOutcome, String> {
    let key = parse_sui_private_key(raw_private_key)?;
    let sender_addr: Address = key.public_key().derive_address();
    let sender = sender_addr.to_string();

    if !force_direct && enoki_is_enabled() {
        let tx_kind = TransactionKind::ProgrammableTransaction(ptb.clone());
        let tx_kind_bytes =
            bcs::to_bytes(&tx_kind).map_err(|e| format!("failed to BCS-encode PTB kind: {e}"))?;
        let tx_kind_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_kind_bytes);

        match enoki_sponsor_transaction_kind_with_addresses(
            http,
            network,
            &sender,
            &tx_kind_b64,
            None,
            allowed_addresses,
        )
        .await
        {
            Ok(sponsored) => {
                let sponsored_bytes = base64::engine::general_purpose::STANDARD
                    .decode(&sponsored.bytes)
                    .map_err(|e| format!("invalid base64 from Enoki sponsor: {e}"))?;
                verify_sponsored_transaction_matches_ptb(&sponsored_bytes, sender_addr, &ptb)?;
                let (sig_b64, _) = sign_transaction_bytes(raw_private_key, &sponsored_bytes)?;
                match enoki_execute_sponsored_transaction(http, &sponsored.digest, &sig_b64).await {
                    Ok(executed) => {
                        if need_created_objects {
                            return fetch_executed_transaction_outcome(
                                grpc_url,
                                &executed.digest,
                                true,
                            )
                            .await;
                        }
                        return Ok(WalletTxOutcome {
                            digest: executed.digest,
                            created_objects: Vec::new(),
                            used_enoki: true,
                        });
                    }
                    Err(err) if err.is_fallback_eligible() => {
                        tracing::warn!(
                            sender = %sender,
                            error = %err,
                            "Enoki execute failed with fallback-eligible error; falling back to direct address-balance execution"
                        );
                    }
                    Err(err) => return Err(err.to_string()),
                }
            }
            Err(err) if err.is_fallback_eligible() => {
                tracing::warn!(
                    sender = %sender,
                    error = %err,
                    "Enoki sponsor failed with fallback-eligible error; falling back to direct address-balance execution"
                );
            }
            Err(err) => return Err(err.to_string()),
        }
    }

    execute_ptb_with_address_balance(grpc_url, raw_private_key, ptb, None).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a 33-byte `[0x00, ..32]` payload as BIP-173 Bech32 `suiprivkey1...` for testing.
    fn encode_test_suiprivkey(seed: &[u8; 32]) -> String {
        let mut payload = [0u8; 33];
        payload[0] = 0x00;
        payload[1..].copy_from_slice(seed);

        let mut data_5bit = Vec::new();
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &b in &payload {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                data_5bit.push(((acc >> bits) & 0x1f) as u8);
            }
        }
        if bits > 0 {
            data_5bit.push(((acc << (5 - bits)) & 0x1f) as u8);
        }

        let hrp = "suiprivkey";
        let mut expand = Vec::new();
        for b in hrp.bytes() {
            expand.push(b >> 5);
        }
        expand.push(0);
        for b in hrp.bytes() {
            expand.push(b & 0x1f);
        }
        expand.extend_from_slice(&data_5bit);
        expand.extend_from_slice(&[0u8; 6]);
        let polymod = bech32_polymod(&expand) ^ 1;
        for i in 0..6 {
            data_5bit.push(((polymod >> (5 * (5 - i))) & 0x1f) as u8);
        }

        let mut out = String::from("suiprivkey1");
        for idx in data_5bit {
            out.push(BECH32_CHARSET[idx as usize] as char);
        }
        out
    }

    #[test]
    fn parses_suiprivkey_bech32_hex_and_base64_identically() {
        let seed = [0x42u8; 32];
        let bech32_key = encode_test_suiprivkey(&seed);
        let hex_key = format!("0x{}", hex::encode(seed));
        let b64_raw = base64::engine::general_purpose::STANDARD.encode(seed);
        let mut keystore_bytes = vec![0x00];
        keystore_bytes.extend_from_slice(&seed);
        let b64_keystore = base64::engine::general_purpose::STANDARD.encode(&keystore_bytes);

        let addr_bech32 = derive_sui_address(&bech32_key).expect("bech32 key should parse");
        let addr_hex = derive_sui_address(&hex_key).expect("hex key should parse");
        let addr_b64_raw = derive_sui_address(&b64_raw).expect("32-byte base64 key should parse");
        let addr_b64_ks =
            derive_sui_address(&b64_keystore).expect("33-byte keystore base64 key should parse");

        assert_eq!(addr_bech32, addr_hex);
        assert_eq!(addr_bech32, addr_b64_raw);
        assert_eq!(addr_bech32, addr_b64_ks);
        assert!(addr_bech32.starts_with("0x"));
    }

    #[test]
    fn rejects_corrupted_bech32_checksum() {
        let seed = [0x11u8; 32];
        let mut bech32_key = encode_test_suiprivkey(&seed);
        bech32_key.pop();
        bech32_key.push('q');
        assert!(parse_sui_private_key(&bech32_key).is_err());
    }

    #[test]
    fn verify_sponsored_transaction_matches_ptb_rejects_sender_or_kind_tampering() {
        let sender: Address =
            "0x0000000000000000000000000000000000000000000000000000000000000011"
                .parse()
                .unwrap();
        let attacker: Address =
            "0x0000000000000000000000000000000000000000000000000000000000000099"
                .parse()
                .unwrap();
        let ptb = ProgrammableTransaction {
            inputs: vec![sui_sdk_types::Input::Pure(vec![1, 2, 3])],
            commands: Vec::new(),
        };
        let valid_tx = Transaction {
            kind: TransactionKind::ProgrammableTransaction(ptb.clone()),
            sender,
            gas_payment: GasPayment {
                objects: Vec::new(),
                owner: attacker, // sponsor owns gas
                price: 1000,
                budget: 50_000_000,
            },
            expiration: TransactionExpiration::None,
        };
        let valid_bytes = bcs::to_bytes(&valid_tx).unwrap();
        assert!(verify_sponsored_transaction_matches_ptb(&valid_bytes, sender, &ptb).is_ok());

        // Wrong sender
        assert!(verify_sponsored_transaction_matches_ptb(&valid_bytes, attacker, &ptb).is_err());

        // Tampered PTB inputs
        let tampered_ptb = ProgrammableTransaction {
            inputs: vec![sui_sdk_types::Input::Pure(vec![9, 9, 9])],
            commands: Vec::new(),
        };
        assert!(
            verify_sponsored_transaction_matches_ptb(&valid_bytes, sender, &tampered_ptb).is_err()
        );
    }

    #[test]
    fn classify_enoki_http_error_distinguishes_fallback_eligible_and_permanent_errors() {
        let rate_limited = classify_enoki_http_error(
            429,
            r#"{"errors":[{"message":"Rate limit exceeded"}]}"#,
        );
        assert!(rate_limited.is_fallback_eligible());
        assert_eq!(rate_limited.http_status_code(), 429);

        let gas_pool_exhausted = classify_enoki_http_error(
            400,
            r#"{"errors":[{"message":"Sponsor has insufficient gas balance"}]}"#,
        );
        assert!(gas_pool_exhausted.is_fallback_eligible());
        assert_eq!(gas_pool_exhausted.http_status_code(), 502);

        let server_err = classify_enoki_http_error(503, "upstream unavailable");
        assert!(server_err.is_fallback_eligible());
        assert_eq!(server_err.http_status_code(), 502);

        let rejected = classify_enoki_http_error(
            403,
            r#"{"message":"Move call target not allowed"}"#,
        );
        assert!(!rejected.is_fallback_eligible());
        assert_eq!(rejected.http_status_code(), 403);

        let bad_req = classify_enoki_http_error(
            400,
            r#"{"errors":[{"message":"Invalid transactionKindBytes"}]}"#,
        );
        assert!(!bad_req.is_fallback_eligible());
        assert_eq!(bad_req.http_status_code(), 400);
    }

    #[test]
    fn sanitize_upstream_error_redacts_bearer_tokens_and_strips_control_chars() {
        let raw = "upstream failed:\n\r\tAuthorization: Bearer secret_enoki_token_12345 with \x07bell";
        let sanitized = sanitize_upstream_error_for_logging(raw);
        assert!(!sanitized.contains("secret_enoki_token_12345"));
        assert!(sanitized.contains("Bearer [REDACTED]"));
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\x07'));

        let oversized = "x".repeat(800);
        let truncated = sanitize_upstream_error_for_logging(&oversized);
        assert!(truncated.ends_with("...(truncated)"));
        assert!(truncated.len() < 550);
    }

    #[test]
    fn reactivate_rejection_code_detects_move_abort_11_and_20() {
        assert_eq!(
            reactivate_rejection_code(
                "MoveAbort in 0x1::account::reactivate_account, abort code: 11"
            ),
            Some((
                "account_already_active",
                "This account is already active, so it cannot be reactivated.",
            ))
        );
        assert_eq!(
            reactivate_rejection_code(
                r#"MoveAbort({"functionName":"reactivate_account","abortCode":"20"})"#
            ),
            Some((
                "account_quarantined",
                "This account is still locked, so it cannot be reactivated yet.",
            ))
        );
        assert_eq!(
            reactivate_rejection_code(
                "MoveAbort in 0x1::account::reactivate_account, abort code: 99"
            ),
            None
        );
    }

    #[test]
    fn sign_personal_message_bytes_produces_97_byte_ed25519_serialized_signature() {
        let seed = [0x24u8; 32];
        let hex_key = format!("0x{}", hex::encode(seed));
        let sig_b64 =
            sign_personal_message_bytes(&hex_key, b"MemWal session certificate").unwrap();
        let raw_sig = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .unwrap();
        assert_eq!(raw_sig.len(), 97);
        assert_eq!(raw_sig[0], 0x00); // Ed25519 scheme flag
    }
}

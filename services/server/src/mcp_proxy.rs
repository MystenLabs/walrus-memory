//! MCP reverse-proxy to the Node sidecar.
//!
//! The MCP server (Model Context Protocol) lives in the sidecar at
//! `<sidecar_url>/mcp/*` because the official `@modelcontextprotocol/sdk` is
//! TypeScript. This module exposes two public axum routes that forward
//! external client traffic to the sidecar:
//!
//!   GET  /api/mcp/sse        SSE stream open + endpoint event
//!   POST /api/mcp/messages   JSON-RPC envelopes from the client
//!
//! These routes intentionally bypass the relayer's Ed25519 signed-request
//! auth + per-key rate limiting because:
//!
//!   * MCP clients (Claude Code, Codex, etc.) cannot ship a per-request
//!     timestamp+nonce+signature — they send a single `Authorization: Bearer`
//!     at SSE open and reuse the session for the lifetime of the connection.
//!   * The sidecar's MCP layer does its own auth — parses the Bearer as the
//!     Ed25519 delegate key and the `X-MemWal-Account-Id` header — and the
//!     SDK signs every downstream relayer API call from inside the MCP tools.
//!
//! Trust model: the sidecar's blanket shared-secret middleware does not run on
//! `/mcp/*` (mounted before it in `scripts/sidecar/app.ts`), because
//! `Authorization` already carries the end user's delegate key. Instead this
//! module presents the same secret in `x-memwal-internal-sidecar-token`, and
//! the sidecar refuses to honour any `x-memwal-internal-*` header without it —
//! so reaching the sidecar directly is not enough to forge one (GH #685).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{client_ip::canonical_client_ip, types::AppState};

/// Header names that we forward verbatim from the inbound client request to
/// the sidecar. Anything else is dropped — we never proxy cookies, host, or
/// any infra header that would confuse the sidecar.
///
/// Internal headers (starting with `x-memwal-internal-`) are strictly reserved
/// for trusted relayer-to-sidecar communication and must NEVER be forwarded
/// from untrusted client requests.
const FORWARD_HEADER_PREFIXES: &[&str] = &["x-memwal-"];
const INTERNAL_HEADER_PREFIXES: &[&str] = &["x-memwal-internal-"];
const FORWARD_HEADER_EXACT: &[&str] = &[
    "authorization",
    "content-type",
    "accept",
    "x-request-id",
    "x-correlation-id",
    // MCP 2025-06 streamable HTTP transport headers — the SDK on both
    // sides reads these to route requests to the right session.
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
];

fn should_forward(name: &HeaderName) -> bool {
    let s = name.as_str().to_ascii_lowercase();
    if INTERNAL_HEADER_PREFIXES.iter().any(|p| s.starts_with(p)) {
        return false;
    }
    FORWARD_HEADER_EXACT.iter().any(|h| *h == s)
        || FORWARD_HEADER_PREFIXES.iter().any(|p| s.starts_with(p))
}

fn build_forwarded_headers(inbound: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::new();
    for (name, value) in inbound.iter() {
        if should_forward(name) {
            if let (Ok(n), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                out.insert(n, v);
            }
        }
    }
    out
}

/// Forward exactly one canonical, validated client IP to the loopback
/// sidecar. Never pass the inbound XFF chain through: its left side may be
/// attacker-controlled and the sidecar must not reinterpret proxy trust.
fn set_forwarded_client_ip(
    headers: &mut reqwest::header::HeaderMap,
    inbound: &HeaderMap,
    peer: SocketAddr,
    trusted_proxy_hops: usize,
) {
    let client_ip = canonical_client_ip(inbound, peer, trusted_proxy_hops);
    if let Ok(v) = reqwest::header::HeaderValue::from_str(&client_ip.to_string()) {
        out_set(headers, "x-forwarded-for", v);
    }
}

fn out_set(
    headers: &mut reqwest::header::HeaderMap,
    name: &'static str,
    value: reqwest::header::HeaderValue,
) {
    if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) {
        headers.insert(n, value);
    }
}

// ---------------------------------------------------------------------
// MCP OAuth bearer resolution (Claude custom connectors). Runs before the
// sidecar ever sees the request: classifies the inbound bearer, and when
// it's an OAuth access token, translates it into the legacy
// `Authorization: Bearer <delegate-key-hex>` + `X-MemWal-Account-Id` shape
// the sidecar's `resolveAuth()` already accepts — so the sidecar itself
// needs zero changes. See `oauth.rs` for the crypto/DB side.
// ---------------------------------------------------------------------

/// Client-supplied handshake identity. None of it is trusted for any
/// decision — it exists so a refused handshake can be attributed to a person
/// and a client build instead of appearing as an anonymous status code.
const CONNECT_ID_HEADER: &str = "x-memwal-connect-id";
const CLIENT_NAME_HEADER: &str = "x-memwal-client";
const CLIENT_VERSION_HEADER: &str = "x-memwal-client-version";
const BRIDGE_VERSION_HEADER: &str = "x-memwal-bridge-version";

/// Which `/api/mcp/*` entry point a handshake outcome came from.
///
/// A label rather than three metrics, so the SSE refusal ratio can be
/// queried on its own. `classify_and_resolve` runs on every JSON-RPC
/// envelope as well as on the handshake, so without this the `ok` bucket
/// counts a live session's POSTs and the ratio WALM-618 was diagnosed from
/// reads far healthier than it is.
const ROUTE_SSE: &str = "sse";
const ROUTE_MESSAGES: &str = "messages";
const ROUTE_STREAMABLE: &str = "streamable";

/// Why a handshake was refused. Stable, low-cardinality strings: they are a
/// Prometheus label and a log field, and they never carry a token, a key, or
/// anything else caller-supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeRejection {
    /// No `Authorization: Bearer`, or an empty one.
    NoBearer,
    /// A delegate-shaped bearer with no `X-MemWal-Account-Id` to check it against.
    NoAccountHeader,
    /// 64 hex characters that are not a usable ed25519 secret.
    MalformedDelegateKey,
    /// Well-formed key, real account, but the key is not registered on it.
    NotRegistered,
    /// Not a delegate key, and this deployment has no OAuth configured.
    OauthNotConfigured,
    /// Not a delegate key and not an OAuth token either.
    NotOauthToken,
    /// An OAuth token that is expired, revoked, or otherwise refused.
    OauthRejected,
}

impl HandshakeRejection {
    fn code(self) -> &'static str {
        match self {
            Self::NoBearer => "no_bearer",
            Self::NoAccountHeader => "no_account_header",
            Self::MalformedDelegateKey => "malformed_delegate_key",
            Self::NotRegistered => "not_registered",
            Self::OauthNotConfigured => "oauth_not_configured",
            Self::NotOauthToken => "not_oauth_token",
            Self::OauthRejected => "oauth_rejected",
        }
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Client identity is logged, so cap it and keep it printable — it is
/// caller-supplied and must not be able to inject newlines into the log or
/// blow up a line.
fn sanitized_client(headers: &HeaderMap, name: &str) -> String {
    header_str(headers, name)
        .map(|v| {
            v.chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(64)
                .collect::<String>()
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "-".to_string())
}

/// Log and count one refused handshake, then produce the outcome.
///
/// Every refusal goes through here. Before this, four of the five ways to be
/// refused logged nothing at all and none of them touched a metric, so 401 —
/// 70% of this route's traffic — was invisible in both logs and dashboards.
fn refuse(
    reason: HandshakeRejection,
    route: &str,
    headers: &HeaderMap,
    oauth_err: Option<crate::oauth::OAuthBearerError>,
) -> McpAuthOutcome {
    // Counter first and unconditionally — it is the signal a dashboard reads,
    // and it must not depend on whether this particular refusal was sampled.
    crate::observability::record_mcp_handshake(route, "unauthorized", reason.code());
    crate::observability::record_app_error("mcp_unauthorized");
    // The line carries what the counter cannot, but this route has no rate
    // limit in front of it and a stuck client retries forever, so it is
    // sampled per account rather than written per request.
    let account_id = account_id_header(headers).unwrap_or("-");
    if crate::observability::should_log_refusal(account_id) {
        tracing::warn!(
            reason = reason.code(),
            account_id = %account_id,
            connect_id = header_str(headers, CONNECT_ID_HEADER).unwrap_or("-"),
            client = %sanitized_client(headers, CLIENT_NAME_HEADER),
            client_version = %sanitized_client(headers, CLIENT_VERSION_HEADER),
            bridge_version = %sanitized_client(headers, BRIDGE_VERSION_HEADER),
            "mcp handshake refused (sampled; see memwal_mcp_handshake_total for the rate)"
        );
    }
    McpAuthOutcome::Unauthorized(oauth_err)
}

/// Start timing this client's connect episode, if it named one.
///
/// Called on every attempt; only the first one for an id records anything, so
/// the measured span runs from the client's first try to the one that works —
/// which is the interval a user perceives, and the one no per-request metric
/// can see, because each individual request here is fast.
async fn note_connect_attempt(state: &AppState, headers: &HeaderMap) {
    let Some(id) = header_str(headers, CONNECT_ID_HEADER) else {
        return;
    };
    let mut episodes = state.mcp_connect_episodes.write().await;
    if episodes.contains_key(id) {
        return;
    }
    // Expire before consulting the cap, as the rejection cache and the log
    // samplers do. This runs before authentication on a route with no rate
    // limit, keyed on a header the caller chooses, so without it a few
    // thousand made-up connect ids hold every slot until the 300s sweep —
    // and while they do, no legitimate client is timed at all, which blinds
    // `time_to_session` during exactly the incident it exists to measure.
    //
    // It self-heals once the spam stops; it does not stop a caller who keeps
    // it up. Bounding that needs an authenticated key, or the measurement
    // moved to the bridge, which already knows its own elapsed time.
    if episodes.len() >= crate::observability::MCP_CONNECT_EPISODE_MAX {
        episodes.retain(|_, started| crate::observability::connect_episode_is_fresh(*started));
    }
    if episodes.len() >= crate::observability::MCP_CONNECT_EPISODE_MAX {
        return;
    }
    episodes.insert(id.to_string(), std::time::Instant::now());
}

/// Close the episode and record how long the client waited in total.
async fn finish_connect_episode(state: &AppState, headers: &HeaderMap) {
    let Some(id) = header_str(headers, CONNECT_ID_HEADER) else {
        return;
    };
    let started = state.mcp_connect_episodes.write().await.remove(id);
    let Some(started) = started.filter(|s| crate::observability::connect_episode_is_fresh(*s))
    else {
        return;
    };
    let waited = started.elapsed();
    // Anything past a couple of seconds means the client was retrying, which
    // is the WALM-618 shape. Say so at `info` with the id, so one grep gives
    // the whole episode including the refusals that led here.
    if waited > std::time::Duration::from_secs(2) {
        tracing::info!(
            connect_id = %id,
            account_id = account_id_header(headers).unwrap_or("-"),
            waited_ms = waited.as_millis(),
            client = %sanitized_client(headers, CLIENT_NAME_HEADER),
            "mcp session opened after retries"
        );
    }
    crate::observability::record_mcp_time_to_session(waited);
}

enum McpAuthOutcome {
    /// The bearer is the legacy 64-hex delegate key — forward exactly as
    /// today, byte for byte (OAuth tokens are never valid here).
    Passthrough,
    Oauth(Box<crate::oauth::ResolvedOAuthIdentity>),
    /// Bearer missing/malformed/expired/revoked, or the hex key is not a
    /// registered delegate. RFC 9728 challenge when OAuth is configured.
    Unauthorized(Option<crate::oauth::OAuthBearerError>),
    /// On-chain lookup failed transiently; do not 401 a registered key.
    Unavailable,
}

fn is_legacy_delegate_bearer(token: &str) -> bool {
    let hex_part = token.strip_prefix("0x").unwrap_or(token);
    hex_part.len() == 64 && hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let auth_value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    auth_value
        .strip_prefix("Bearer ")
        .or_else(|| auth_value.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn account_id_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-memwal-account-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|id| !id.is_empty())
}

fn public_key_from_delegate_hex(token: &str) -> Option<[u8; 32]> {
    let hex_part = token.strip_prefix("0x").unwrap_or(token);
    let secret: [u8; 32] = hex::decode(hex_part).ok()?.try_into().ok()?;
    Some(
        ed25519_dalek::SigningKey::from_bytes(&secret)
            .verifying_key()
            .to_bytes(),
    )
}

async fn legacy_delegate_registered(
    state: &AppState,
    headers: &HeaderMap,
    token: &str,
    route: &str,
) -> McpAuthOutcome {
    let Some(account_id) = account_id_header(headers) else {
        return refuse(HandshakeRejection::NoAccountHeader, route, headers, None);
    };
    let Some(pk) = public_key_from_delegate_hex(token) else {
        return refuse(
            HandshakeRejection::MalformedDelegateKey,
            route,
            headers,
            None,
        );
    };
    // Cached: this runs on the SSE handshake and on every JSON-RPC envelope,
    // so an uncached read here is one fullnode call per envelope.
    match crate::storage::sui::verify_delegate_key_cached(
        &state.delegate_verify_cache,
        &state.delegate_reject_cache,
        &state.http_client,
        &state.config.sui_rpc_url,
        state.sui_grpc_client.as_ref(),
        account_id,
        &pk,
        &state.config.package_id,
    )
    .await
    {
        Ok(_) => {
            crate::observability::record_mcp_handshake(route, "ok", "none");
            McpAuthOutcome::Passthrough
        }
        Err(err) if err.is_unavailable() => {
            tracing::warn!(
                account_id = %account_id,
                connect_id = header_str(headers, CONNECT_ID_HEADER).unwrap_or("-"),
                client = %sanitized_client(headers, CLIENT_NAME_HEADER),
                error = %err,
                "mcp delegate on-chain verify unavailable"
            );
            crate::observability::record_mcp_handshake(route, "unavailable", "sui_unavailable");
            crate::observability::record_app_error("mcp_upstream_unavailable");
            McpAuthOutcome::Unavailable
        }
        Err(err) => {
            tracing::debug!(error = %err, "mcp delegate rejected on chain");
            refuse(HandshakeRejection::NotRegistered, route, headers, None)
        }
    }
}

async fn classify_and_resolve(
    state: &AppState,
    headers: &HeaderMap,
    route: &str,
) -> McpAuthOutcome {
    let Some(token) = bearer_token(headers) else {
        return refuse(HandshakeRejection::NoBearer, route, headers, None);
    };

    if is_legacy_delegate_bearer(token) {
        return legacy_delegate_registered(state, headers, token, route).await;
    }

    if state.config.mcp_oauth.is_none() {
        return refuse(HandshakeRejection::OauthNotConfigured, route, headers, None);
    }

    match crate::oauth::resolve_oauth_bearer(state, token).await {
        Ok(identity) => {
            crate::observability::record_mcp_handshake(route, "ok", "none");
            McpAuthOutcome::Oauth(Box::new(identity))
        }
        Err(crate::oauth::OAuthBearerError::NotOAuthToken) => {
            refuse(HandshakeRejection::NotOauthToken, route, headers, None)
        }
        Err(err) => {
            tracing::debug!("mcp_proxy oauth bearer detail: {:?}", err);
            refuse(HandshakeRejection::OauthRejected, route, headers, Some(err))
        }
    }
}

/// Internal headers the relayer states on every forwarded `/mcp/*` request.
///
/// Both values are written with `insert` (overwrite, never append), so a
/// client-supplied `x-memwal-internal-*` copied through by
/// `build_forwarded_headers` is always replaced and can never survive. GH #665
/// additionally drops that prefix on the way in; this function does not depend
/// on it.
///
/// - **sidecar token** proves to the sidecar that the request really came from
///   the relayer. `/mcp/*` is mounted before the sidecar's shared-secret
///   middleware because `authorization` already carries the end user's
///   delegate key, so the secret rides in its own header instead.
/// - **oauth scope** is stated explicitly on BOTH auth paths — the resolved
///   grant for OAuth callers, and full read+write for legacy delegate-key
///   callers. The sidecar registers no tools when it is absent, so silence
///   means "no access" rather than "unrestricted" (GH #685).
///
/// For the OAuth path this MUST overwrite `authorization` and
/// `x-memwal-account-id`: `build_forwarded_headers` copies any client-supplied
/// `x-memwal-*` header verbatim (that's how the legacy explicit-header flow
/// works), so a caller presenting a valid OAuth token alongside a forged
/// `X-MemWal-Account-Id` must have the forged value discarded, not merged.
///
/// Returns `Err` rather than skipping a header it cannot build: a partially
/// applied set would hand the sidecar an authenticated request with no scope,
/// and the whole point of #685 is that such a request must fail, not proceed.
fn apply_internal_headers(
    forwarded: &mut reqwest::header::HeaderMap,
    sidecar_secret: Option<&str>,
    identity: Option<&crate::oauth::ResolvedOAuthIdentity>,
) -> Result<(), StatusCode> {
    fn internal_error(what: &str) -> StatusCode {
        tracing::error!("mcp_proxy: cannot build internal header {what}");
        StatusCode::INTERNAL_SERVER_ERROR
    }

    let Some(secret) = sidecar_secret else {
        return Err(internal_error(
            "x-memwal-internal-sidecar-token (SIDECAR_AUTH_TOKEN unset)",
        ));
    };
    let token = reqwest::header::HeaderValue::from_str(secret)
        .map_err(|_| internal_error("x-memwal-internal-sidecar-token"))?;

    let scope = match identity {
        Some(identity) => identity.scope.clone(),
        // Legacy delegate-key callers have no OAuth grant, so the relayer says
        // outright that they hold every tool scope.
        None => format!("{} {}", crate::oauth::SCOPE_READ, crate::oauth::SCOPE_WRITE),
    };
    let scope = reqwest::header::HeaderValue::from_str(&scope)
        .map_err(|_| internal_error("x-memwal-internal-oauth-scope"))?;

    if let Some(identity) = identity {
        let auth = reqwest::header::HeaderValue::from_str(&format!(
            "Bearer {}",
            identity.delegate_private_key.as_str()
        ))
        .map_err(|_| internal_error("authorization"))?;
        let account = reqwest::header::HeaderValue::from_str(&identity.account_id)
            .map_err(|_| internal_error("x-memwal-account-id"))?;
        forwarded.insert(reqwest::header::AUTHORIZATION, auth);
        forwarded.insert(
            reqwest::header::HeaderName::from_static("x-memwal-account-id"),
            account,
        );
    }

    forwarded.insert(
        reqwest::header::HeaderName::from_static("x-memwal-internal-sidecar-token"),
        token,
    );
    forwarded.insert(
        reqwest::header::HeaderName::from_static("x-memwal-internal-oauth-scope"),
        scope,
    );
    Ok(())
}

/// Stable per-tenant id for the MCP rate limit: `{account_id}:{delegate
/// public key hex}`. Legacy callers are already verified on chain by
/// `legacy_delegate_registered`; OAuth callers use the grant's resolved
/// account and delegate, never client headers. `None` only when the key
/// cannot be parsed, which `classify_and_resolve` already refused.
fn mcp_tenant_id(
    headers: &HeaderMap,
    identity: Option<&crate::oauth::ResolvedOAuthIdentity>,
) -> Option<String> {
    let (account, secret) = match identity {
        Some(identity) => (
            identity.account_id.as_str(),
            identity.delegate_private_key.as_str(),
        ),
        None => (account_id_header(headers)?, bearer_token(headers)?),
    };
    let pk = public_key_from_delegate_hex(secret)?;
    Some(format!(
        "{}:{}",
        account.to_ascii_lowercase(),
        hex::encode(pk)
    ))
}

/// GH #1050: meter authenticated MCP traffic per tenant, not per IP or
/// one shared bucket. `Some` is the response to send instead of proxying.
async fn enforce_tenant_rate_limit(
    state: &AppState,
    headers: &HeaderMap,
    identity: Option<&crate::oauth::ResolvedOAuthIdentity>,
) -> Option<Response> {
    let Some(tenant) = mcp_tenant_id(headers, identity) else {
        return Some(oauth_unauthorized_response(state, None));
    };
    crate::rate_limit::check_mcp_tenant_rate_limit(state, &tenant).await
}

/// RFC 9728 401 challenge when OAuth is configured; plain 401 otherwise.
fn oauth_unauthorized_response(
    state: &AppState,
    err: Option<&crate::oauth::OAuthBearerError>,
) -> Response {
    let Some(cfg) = state.config.mcp_oauth.as_ref() else {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    };
    let mut challenge = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
        cfg.issuer
    );
    if let Some(err) = err {
        challenge.push_str(&format!(", error=\"{}\"", err.error_code()));
    }
    let mut resp = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    if let Ok(v) = HeaderValue::from_str(&challenge) {
        resp.headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, v);
    }
    resp
}

/// `GET /api/mcp/sse` — open the SSE stream to the sidecar and stream the
/// response body back to the client without buffering. The sidecar emits an
/// `event: endpoint` line carrying `/api/mcp/messages?sessionId=…`; the
/// client posts subsequent JSON-RPC envelopes to that URL.
pub async fn sse_proxy(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let url = format!("{}/mcp/sse", state.config.sidecar_url);
    // SSE streams are long-lived (idle between tool calls + 27-35s walrus
    // writes leave the body silent). The shared `http_client` carries a 30s
    // request timeout intended for finite LLM/Walrus calls; if we let it
    // apply here reqwest kills the streaming response at 30s and the bridge
    // sees `terminated`. Override with a 24h ceiling so the stream stays
    // open until the client itself closes it. `read_timeout` keeps a
    // per-chunk watchdog (heartbeats fire every 3s, so 60s is plenty).
    let mut forwarded = build_forwarded_headers(&headers);
    set_forwarded_client_ip(
        &mut forwarded,
        &headers,
        peer,
        state.config.trusted_proxy_hops,
    );
    note_connect_attempt(&state, &headers).await;
    let identity = match classify_and_resolve(&state, &headers, ROUTE_SSE).await {
        McpAuthOutcome::Passthrough => {
            finish_connect_episode(&state, &headers).await;
            None
        }
        McpAuthOutcome::Oauth(identity) => {
            finish_connect_episode(&state, &headers).await;
            Some(identity)
        }
        McpAuthOutcome::Unauthorized(err) => {
            return oauth_unauthorized_response(&state, err.as_ref())
        }
        McpAuthOutcome::Unavailable => return crate::auth::upstream_unavailable(),
    };
    if let Some(resp) = enforce_tenant_rate_limit(&state, &headers, identity.as_deref()).await {
        return resp;
    }
    if let Err(code) = apply_internal_headers(
        &mut forwarded,
        state.config.sidecar_secret.as_deref(),
        identity.as_deref(),
    ) {
        return (code, "internal error").into_response();
    }
    if crate::storage::walrus_native::is_in_process_sidecar_enabled(&state.config.sidecar_url) {
        return crate::mcp_native::handle_sse_in_process(state, forwarded).await;
    }
    let req = state
        .http_client
        .get(&url)
        .timeout(std::time::Duration::from_secs(86_400))
        .headers(forwarded);

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!("mcp_proxy.sse upstream connect failed: {}", err);
            return (
                StatusCode::BAD_GATEWAY,
                format!("MCP sidecar unreachable: {}", err),
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // Build response with streaming body. Forward only the headers SSE
    // clients actually depend on; copy custom `www-authenticate` on auth
    // failures so the user agent knows what's wrong.
    let mut resp = Response::builder().status(status);
    for (name, value) in upstream.headers().iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if matches!(
            lname.as_str(),
            // `retry-after` is load-bearing: the sidecar sets it on an
            // `ip_burst_cap` 429 and the bridge honours it (WALM-386).
            // Dropping it here left the client with no ETA and the wrong
            // remediation, since it could not tell a timed cap from a
            // concurrency one.
            "content-type" | "cache-control" | "www-authenticate" | "connection" | "retry-after"
        ) {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_str().as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                resp = resp.header(n, v);
            }
        }
    }
    // Belt-and-braces: ensure no intermediary buffers the stream. nginx /
    // Cloudflare honor `X-Accel-Buffering: no`; explicit `no-transform`
    // tells caches not to compress. These are no-ops on loopback but cheap
    // insurance once the relayer sits behind a real proxy.
    resp = resp
        .header("x-accel-buffering", "no")
        .header("cache-control", "no-cache, no-transform")
        .header("connection", "keep-alive");

    let body = Body::from_stream(upstream.bytes_stream());
    match resp.body(body) {
        Ok(r) => r,
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to build proxied response: {}", err),
        )
            .into_response(),
    }
}

/// `POST /api/mcp/messages?sessionId=<uuid>` — forward the JSON-RPC envelope
/// to the sidecar's matching session.
pub async fn messages_proxy(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let session_id = match params.get("sessionId") {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            return (StatusCode::BAD_REQUEST, "Missing sessionId query parameter").into_response();
        }
    };

    // session_id comes from the sidecar (it is a UUID v4, no special chars)
    // so no percent-encoding needed. Sanitize the assumption by rejecting any
    // value that contains characters outside the UUID alphabet.
    if !session_id
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == '-')
    {
        return (StatusCode::BAD_REQUEST, "Invalid sessionId").into_response();
    }
    let url = format!(
        "{}/mcp/messages?sessionId={}",
        state.config.sidecar_url, session_id
    );

    let mut forwarded = build_forwarded_headers(&headers);
    set_forwarded_client_ip(
        &mut forwarded,
        &headers,
        peer,
        state.config.trusted_proxy_hops,
    );
    note_connect_attempt(&state, &headers).await;
    let identity = match classify_and_resolve(&state, &headers, ROUTE_MESSAGES).await {
        McpAuthOutcome::Passthrough => {
            finish_connect_episode(&state, &headers).await;
            None
        }
        McpAuthOutcome::Oauth(identity) => {
            finish_connect_episode(&state, &headers).await;
            Some(identity)
        }
        McpAuthOutcome::Unauthorized(err) => {
            return oauth_unauthorized_response(&state, err.as_ref())
        }
        McpAuthOutcome::Unavailable => return crate::auth::upstream_unavailable(),
    };
    if let Some(resp) = enforce_tenant_rate_limit(&state, &headers, identity.as_deref()).await {
        return resp;
    }
    if let Err(code) = apply_internal_headers(
        &mut forwarded,
        state.config.sidecar_secret.as_deref(),
        identity.as_deref(),
    ) {
        return (code, "internal error").into_response();
    }
    if crate::storage::walrus_native::is_in_process_sidecar_enabled(&state.config.sidecar_url) {
        return crate::mcp_native::handle_messages_in_process(state, session_id, forwarded, body)
            .await;
    }
    let upstream = state
        .http_client
        .post(&url)
        .headers(forwarded)
        .body(body.to_vec())
        .send()
        .await;

    let upstream = match upstream {
        Ok(r) => r,
        Err(err) => {
            tracing::error!("mcp_proxy.messages upstream connect failed: {}", err);
            return (
                StatusCode::BAD_GATEWAY,
                format!("MCP sidecar unreachable: {}", err),
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    // Same reason as the SSE and streamable allowlists: the sidecar rate
    // limits this route too, and dropping `retry-after` leaves the client
    // unable to tell a cap that clears on a timer from one that clears when
    // somebody else disconnects (WALM-386). Captured before `bytes()`
    // consumes the response.
    let retry_after = upstream
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| HeaderValue::from_str(v).ok());

    match upstream.bytes().await {
        Ok(bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_str(&content_type)
                    .unwrap_or_else(|_| HeaderValue::from_static("application/json")),
            );
            if let Some(value) = retry_after {
                headers.insert(axum::http::header::RETRY_AFTER, value);
            }
            (status, headers, bytes).into_response()
        }
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            format!("MCP sidecar read failed: {}", err),
        )
            .into_response(),
    }
}

/// `ANY /api/mcp` — Streamable HTTP transport (MCP 2025-06 spec).
///
/// Single endpoint that supersedes the SSE+POST split: one URL handles
/// GET (open server→client SSE), POST (JSON-RPC with optional SSE upgrade),
/// and DELETE (close session). The MailGate / Linear / Figma MCP servers
/// all use this newer transport — clients just configure a single URL:
///
///     claude mcp add --transport http memwal https://relayer.memory.walrus.xyz/api/mcp
///
/// We proxy verbatim to the sidecar's `/mcp` endpoint (whose SDK
/// `StreamableHTTPServerTransport` does all the protocol heavy-lifting).
/// `mcp-session-id` round-trips between client and sidecar; the
/// authorization scheme stays Bearer-on-every-request (same ed25519 seed
/// scheme as the stdio bridge — no OAuth dance required).
pub async fn streamable_proxy(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: axum::http::Method,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let url = format!("{}/mcp", state.config.sidecar_url);

    // Build the upstream request matching the inbound method. reqwest
    // doesn't expose a generic builder that takes a Method directly, so
    // we branch — only GET/POST/DELETE are meaningful for the transport.
    let mut req = match method {
        axum::http::Method::GET => state.http_client.get(&url),
        axum::http::Method::POST => state.http_client.post(&url),
        axum::http::Method::DELETE => state.http_client.delete(&url),
        axum::http::Method::OPTIONS => {
            // CORS preflight — answer here without hitting the sidecar.
            return (StatusCode::NO_CONTENT, ()).into_response();
        }
        _ => {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                "MCP HTTP transport only supports GET, POST, DELETE",
            )
                .into_response();
        }
    };

    // GET/DELETE may carry an empty body; only POST will have JSON-RPC
    // envelopes. Streaming both ways is the simplest correct choice.
    if !body.is_empty() {
        req = req.body(body.to_vec());
    }
    let mut forwarded = build_forwarded_headers(&headers);
    set_forwarded_client_ip(
        &mut forwarded,
        &headers,
        peer,
        state.config.trusted_proxy_hops,
    );
    note_connect_attempt(&state, &headers).await;
    let identity = match classify_and_resolve(&state, &headers, ROUTE_STREAMABLE).await {
        McpAuthOutcome::Passthrough => {
            finish_connect_episode(&state, &headers).await;
            None
        }
        McpAuthOutcome::Oauth(identity) => {
            finish_connect_episode(&state, &headers).await;
            Some(identity)
        }
        McpAuthOutcome::Unauthorized(err) => {
            return oauth_unauthorized_response(&state, err.as_ref())
        }
        McpAuthOutcome::Unavailable => return crate::auth::upstream_unavailable(),
    };
    if let Some(resp) = enforce_tenant_rate_limit(&state, &headers, identity.as_deref()).await {
        return resp;
    }
    if let Err(code) = apply_internal_headers(
        &mut forwarded,
        state.config.sidecar_secret.as_deref(),
        identity.as_deref(),
    ) {
        return (code, "internal error").into_response();
    }
    if crate::storage::walrus_native::is_in_process_sidecar_enabled(&state.config.sidecar_url) {
        return crate::mcp_native::handle_streamable_in_process(state, method, forwarded, body)
            .await;
    }
    req = req.headers(forwarded);

    // Same 24h request timeout as the SSE proxy — a streamable response
    // can stay open well past the shared `http_client`'s default 30s
    // (tool calls take 25-35s for walrus blob writes). See mcp_proxy.rs
    // commit 8990a88 for the original SSE fix.
    req = req.timeout(std::time::Duration::from_secs(86_400));

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            tracing::error!("mcp_proxy.streamable upstream connect failed: {}", err);
            return (
                StatusCode::BAD_GATEWAY,
                format!("MCP sidecar unreachable: {}", err),
            )
                .into_response();
        }
    };

    let status = StatusCode::from_u16(upstream.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // Forward the headers the streamable transport relies on. Critically
    // `mcp-session-id` — the SDK sets it on the response to first POST and
    // expects subsequent requests to carry it back.
    let mut resp = Response::builder().status(status);
    for (name, value) in upstream.headers().iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if matches!(
            lname.as_str(),
            "content-type"
                | "cache-control"
                | "www-authenticate"
                | "connection"
                | "mcp-session-id"
                | "mcp-protocol-version"
                | "retry-after"
        ) {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_str().as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                resp = resp.header(n, v);
            }
        }
    }
    resp = resp
        .header("x-accel-buffering", "no")
        .header("cache-control", "no-cache, no-transform");

    // Stream both ways — the SDK may upgrade a POST response to SSE
    // (`Content-Type: text/event-stream`) for long-running tool calls.
    // `Body::from_stream` handles small JSON bodies and infinite SSE
    // alike without buffering.
    let body = Body::from_stream(upstream.bytes_stream());
    match resp.body(body) {
        Ok(r) => r,
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to build proxied response: {}", err),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn mcp_tenant_id_separates_delegate_keys() {
        let key_a = "11".repeat(32);
        let key_b = "22".repeat(32);
        let mut h = HeaderMap::new();
        h.insert("x-memwal-account-id", HeaderValue::from_static("0xABC"));
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {key_a}")).unwrap(),
        );
        let a = mcp_tenant_id(&h, None).unwrap();
        assert!(a.starts_with("0xabc:"), "{a}");
        assert!(!a.contains(&key_a), "tenant id must not carry the secret");

        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {key_b}")).unwrap(),
        );
        assert_ne!(mcp_tenant_id(&h, None).unwrap(), a);
        assert!(mcp_tenant_id(&HeaderMap::new(), None).is_none());
    }

    use super::*;
    use axum::http::HeaderName as AxumHeaderName;

    fn axum_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                AxumHeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    fn xff(headers: &reqwest::header::HeaderMap) -> Option<String> {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    #[test]
    fn every_rejection_reason_has_a_distinct_stable_code() {
        // These are Prometheus label values and log fields. A duplicate would
        // silently merge two causes into one series; a rename breaks every
        // saved query. Both are worth a test.
        use HandshakeRejection::*;
        let all = [
            NoBearer,
            NoAccountHeader,
            MalformedDelegateKey,
            NotRegistered,
            OauthNotConfigured,
            NotOauthToken,
            OauthRejected,
        ];
        let codes: Vec<&str> = all.iter().map(|r| r.code()).collect();
        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len(), "reason codes must be distinct");
        assert_eq!(
            codes,
            vec![
                "no_bearer",
                "no_account_header",
                "malformed_delegate_key",
                "not_registered",
                "oauth_not_configured",
                "not_oauth_token",
                "oauth_rejected",
            ]
        );
        assert!(
            codes
                .iter()
                .all(|c| c.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_')),
            "low-cardinality snake_case only — never a token or an account"
        );
    }

    #[test]
    fn client_identity_is_sanitized_before_it_reaches_a_log_line() {
        // Caller-supplied and logged, so it must not be able to forge a second
        // log line or run away with the line length.
        let h = axum_headers(&[("x-memwal-client", "claude-code")]);
        assert_eq!(sanitized_client(&h, "x-memwal-client"), "claude-code");

        let missing = axum_headers(&[]);
        assert_eq!(
            sanitized_client(&missing, "x-memwal-client"),
            "-",
            "absent must read as absent, not as an empty field"
        );

        let long = "a".repeat(500);
        let h = axum_headers(&[("x-memwal-client", &long)]);
        assert_eq!(sanitized_client(&h, "x-memwal-client").len(), 64);
    }

    #[test]
    fn expired_episodes_do_not_hold_the_cap_against_a_real_client() {
        // `note_connect_attempt` runs BEFORE authentication, on a route with
        // no rate limit, keyed on a header the caller picks. Without expiring
        // at the cap, a few thousand made-up connect ids hold every slot for
        // the full 300s sweep interval — and while they do, no legitimate
        // client is ever recorded, so `time_to_session` observes nothing
        // during exactly the incident it was added to measure.
        //
        // This pins the policy; the retain itself is inline in
        // `note_connect_attempt`, which needs an `AppState`. Keep them in step.
        let mut episodes: std::collections::HashMap<String, std::time::Instant> =
            std::collections::HashMap::new();
        let abandoned = std::time::Instant::now()
            - (crate::observability::MCP_CONNECT_EPISODE_TTL + std::time::Duration::from_secs(1));
        for i in 0..crate::observability::MCP_CONNECT_EPISODE_MAX {
            episodes.insert(format!("spam-{i}"), abandoned);
        }
        assert!(
            episodes.len() >= crate::observability::MCP_CONNECT_EPISODE_MAX,
            "precondition: the cap is full, so a real client would be turned away"
        );

        episodes.retain(|_, started| crate::observability::connect_episode_is_fresh(*started));

        assert!(
            episodes.is_empty(),
            "every seeded episode is past the TTL, so none may be kept"
        );
        assert!(
            episodes.len() < crate::observability::MCP_CONNECT_EPISODE_MAX,
            "after expiring, a real client can be timed again"
        );
    }

    #[test]
    fn a_connect_episode_expires_so_an_abandoned_one_cannot_hold_a_slot() {
        let fresh = std::time::Instant::now();
        assert!(crate::observability::connect_episode_is_fresh(fresh));

        let abandoned = std::time::Instant::now()
            - (crate::observability::MCP_CONNECT_EPISODE_TTL + std::time::Duration::from_secs(1));
        assert!(
            !crate::observability::connect_episode_is_fresh(abandoned),
            "past the TTL it is swept, and never reported as a time_to_session"
        );
    }

    #[test]
    fn should_forward_allows_authorization_and_mcp_headers() {
        for h in [
            "authorization",
            "content-type",
            "accept",
            "mcp-session-id",
            "mcp-protocol-version",
            "last-event-id",
            "x-memwal-account-id",
            "x-memwal-namespace",
            "x-memwal-client",
            "x-memwal-client-version",
        ] {
            let name = AxumHeaderName::from_bytes(h.as_bytes()).unwrap();
            assert!(should_forward(&name), "should forward {h}");
        }
    }

    #[test]
    fn should_forward_blocks_cookies_and_host_and_arbitrary_headers() {
        for h in ["cookie", "host", "x-real-ip", "user-agent", "referer"] {
            let name = AxumHeaderName::from_bytes(h.as_bytes()).unwrap();
            assert!(!should_forward(&name), "must not forward {h}");
        }
    }

    #[test]
    fn should_forward_blocks_internal_headers() {
        for h in [
            "x-memwal-internal-oauth-scope",
            "x-memwal-internal-auth",
            "x-memwal-internal-test",
            "X-MemWal-Internal-Oauth-Scope",
        ] {
            let name = AxumHeaderName::from_bytes(h.as_bytes()).unwrap();
            assert!(
                !should_forward(&name),
                "must not forward internal header {h}"
            );
        }
    }

    #[test]
    fn forwarded_client_ip_sets_peer_when_inbound_missing() {
        let mut out = reqwest::header::HeaderMap::new();
        let inbound = axum_headers(&[]);
        let peer: SocketAddr = "203.0.113.7:54321".parse().unwrap();

        set_forwarded_client_ip(&mut out, &inbound, peer, 0);

        assert_eq!(xff(&out).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn forwarded_client_ip_default_ignores_inbound_chain() {
        let mut out = reqwest::header::HeaderMap::new();
        let inbound = axum_headers(&[("x-forwarded-for", "198.51.100.4, 10.0.0.1")]);
        let peer: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        set_forwarded_client_ip(&mut out, &inbound, peer, 0);

        assert_eq!(xff(&out).as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn forwarded_client_ip_uses_configured_trusted_hop() {
        let mut out = reqwest::header::HeaderMap::new();
        let inbound = axum_headers(&[("x-forwarded-for", "192.0.2.66, 203.0.113.7")]);
        let peer: SocketAddr = "10.0.0.2:1".parse().unwrap();

        set_forwarded_client_ip(&mut out, &inbound, peer, 1);

        assert_eq!(xff(&out).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn forwarded_client_ip_handles_ipv6_peer() {
        let mut out = reqwest::header::HeaderMap::new();
        let inbound = axum_headers(&[]);
        let peer: SocketAddr = "[2001:db8::1]:443".parse().unwrap();

        set_forwarded_client_ip(&mut out, &inbound, peer, 0);

        assert_eq!(xff(&out).as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn build_forwarded_headers_drops_cookies_keeps_authorization() {
        let inbound = axum_headers(&[
            ("authorization", "Bearer abc"),
            ("cookie", "session=evil"),
            ("x-memwal-account-id", "0xdeadbeef"),
            ("x-memwal-internal-oauth-scope", "memwal:write"),
            ("host", "evil.example"),
        ]);

        let out = build_forwarded_headers(&inbound);

        assert_eq!(
            out.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer abc")
        );
        assert_eq!(
            out.get("x-memwal-account-id").and_then(|v| v.to_str().ok()),
            Some("0xdeadbeef")
        );
        assert!(out.get("cookie").is_none(), "cookie must not be forwarded");
        assert!(out.get("host").is_none(), "host must not be forwarded");
        assert!(
            out.get("x-memwal-internal-oauth-scope").is_none(),
            "inbound internal oauth scope header must be dropped"
        );
    }

    // -- MCP OAuth bearer classification ---------------------------------

    #[test]
    fn legacy_bearer_classification_accepts_64_hex_with_or_without_0x() {
        let hex64 = "a".repeat(64);
        assert!(is_legacy_delegate_bearer(&hex64));
        assert!(is_legacy_delegate_bearer(&format!("0x{hex64}")));
    }

    #[test]
    fn legacy_bearer_classification_rejects_oauth_and_garbage_tokens() {
        assert!(!is_legacy_delegate_bearer("mwo_abcdefgh"));
        assert!(!is_legacy_delegate_bearer("not-hex-at-all"));
        assert!(!is_legacy_delegate_bearer(&"a".repeat(63))); // one short
        assert!(!is_legacy_delegate_bearer(&"a".repeat(65))); // one long
    }

    #[test]
    fn bearer_token_requires_authorization_header() {
        assert!(bearer_token(&axum_headers(&[])).is_none());
        assert_eq!(
            bearer_token(&axum_headers(&[("authorization", "Bearer abc")])),
            Some("abc")
        );
        assert!(bearer_token(&axum_headers(&[("authorization", "Basic abc")])).is_none());
    }

    // -- internal relayer->sidecar headers (GH #685) ----------------------

    fn test_identity(scope: &str) -> crate::oauth::ResolvedOAuthIdentity {
        let key = [3u8; 32];
        let envelope = crate::oauth::encrypt_delegate_private_key(&key, &"b".repeat(64)).unwrap();
        let secret = crate::oauth::decrypt_delegate_private_key(&key, &envelope).unwrap();
        crate::oauth::ResolvedOAuthIdentity {
            account_id: "0xrealaccount".to_string(),
            delegate_private_key: secret,
            grant_id: "mwg_test".to_string(),
            scope: scope.to_string(),
        }
    }

    #[test]
    fn internal_headers_grant_full_scope_to_legacy_passthrough() {
        let mut out = reqwest::header::HeaderMap::new();

        apply_internal_headers(&mut out, Some("shhh"), None).expect("passthrough must succeed");

        assert_eq!(
            out.get("x-memwal-internal-oauth-scope")
                .and_then(|v| v.to_str().ok()),
            Some("memwal:read memwal:write"),
            "legacy callers must be granted read+write explicitly, not by omission"
        );
        assert_eq!(
            out.get("x-memwal-internal-sidecar-token")
                .and_then(|v| v.to_str().ok()),
            Some("shhh")
        );
    }

    #[test]
    fn internal_headers_forward_the_resolved_oauth_scope() {
        let mut out = reqwest::header::HeaderMap::new();
        let identity = test_identity("memwal:read");

        apply_internal_headers(&mut out, Some("shhh"), Some(&identity))
            .expect("oauth must succeed");

        assert_eq!(
            out.get("x-memwal-internal-oauth-scope")
                .and_then(|v| v.to_str().ok()),
            Some("memwal:read"),
            "the sidecar relies on this header being set; nothing else asserts it"
        );
        assert_eq!(
            out.get("x-memwal-internal-sidecar-token")
                .and_then(|v| v.to_str().ok()),
            Some("shhh")
        );
    }

    #[test]
    fn internal_headers_overwrite_client_supplied_values() {
        let mut out = build_forwarded_headers(&axum_headers(&[
            ("x-memwal-internal-oauth-scope", "memwal:write"),
            ("x-memwal-internal-sidecar-token", "guessed"),
        ]));

        apply_internal_headers(&mut out, Some("shhh"), None).unwrap();

        assert_eq!(
            out.get("x-memwal-internal-oauth-scope")
                .and_then(|v| v.to_str().ok()),
            Some("memwal:read memwal:write")
        );
        assert_eq!(
            out.get("x-memwal-internal-sidecar-token")
                .and_then(|v| v.to_str().ok()),
            Some("shhh")
        );
    }

    #[test]
    fn internal_headers_fail_closed_without_a_sidecar_secret() {
        let mut out = reqwest::header::HeaderMap::new();

        assert!(
            apply_internal_headers(&mut out, None, None).is_err(),
            "no shared secret must fail the request, not forward unauthenticated"
        );
        assert!(
            out.get("x-memwal-internal-oauth-scope").is_none(),
            "must not leave partial headers behind on failure"
        );
    }

    #[test]
    fn apply_internal_headers_overwrites_forwarded_authorization_and_account_id() {
        // Simulates the case build_forwarded_headers already copied a
        // client-supplied (potentially forged) x-memwal-account-id — the
        // OAuth resolution must win, not merge.
        let mut forwarded = reqwest::header::HeaderMap::new();
        forwarded.insert(
            reqwest::header::AUTHORIZATION,
            "Bearer mwo_whatever".parse().unwrap(),
        );
        forwarded.insert(
            reqwest::header::HeaderName::from_bytes(b"x-memwal-account-id").unwrap(),
            "0xforged".parse().unwrap(),
        );

        let key = [3u8; 32];
        let envelope = crate::oauth::encrypt_delegate_private_key(&key, &"b".repeat(64)).unwrap();
        let secret = crate::oauth::decrypt_delegate_private_key(&key, &envelope).unwrap();
        let identity = crate::oauth::ResolvedOAuthIdentity {
            account_id: "0xrealaccount".to_string(),
            delegate_private_key: secret,
            grant_id: "mwg_test".to_string(),
            scope: "memwal:read".to_string(),
        };

        apply_internal_headers(&mut forwarded, Some("shhh"), Some(&identity)).unwrap();

        assert_eq!(
            forwarded.get("authorization").and_then(|v| v.to_str().ok()),
            Some(format!("Bearer {}", "b".repeat(64)).as_str())
        );
        assert_eq!(
            forwarded
                .get("x-memwal-account-id")
                .and_then(|v| v.to_str().ok()),
            Some("0xrealaccount")
        );
    }
}

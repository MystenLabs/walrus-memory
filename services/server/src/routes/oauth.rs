//! HTTP handlers for MCP OAuth 2.1 (Claude custom connectors).
//!
//! Structurally mirrors the reviewed-but-unmerged WALM-30/ENG-1783
//! `app_auth.rs` (PR #193) — same start/complete/cancel/token shape — but
//! implements RFC 7591 dynamic client registration, RFC 8414/9728
//! discovery, and PKCE instead of that ticket's simpler client_id/secret
//! model. All pure logic (crypto, PKCE, validation, sanitization) lives in
//! `crate::oauth`; this file is HTTP plumbing + the on-chain verification
//! call at `/api/oauth/session/{id}/complete`.
//!
//! Routes are always mounted when configured; OAuth tokens simply won't resolve
//! if clients haven't registered yet.

use axum::extract::{ConnectInfo, FromRequest, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::oauth::{self, OAuthError};
use crate::storage::db::oauth_rows::{
    OAuthClientRow, OAuthCodeRow, OAuthDelegateRow, OAuthGrantRow, OAuthSessionRow, OAuthTokenRow,
};
use crate::storage::sui::{
    verify_delegate_key_cached_for_refresh, verify_delegate_key_onchain, OnchainVerifyError,
    GET_OBJECT_ATTEMPTS,
};
use crate::types::{AppError, AppState};

/// Read the configured `McpOAuthConfig`, or fail with 404 if not configured.
fn require_oauth(state: &AppState) -> Result<&oauth::McpOAuthConfig, OAuthError> {
    state.config.mcp_oauth.as_ref().ok_or_else(|| {
        OAuthError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "MCP OAuth is not configured",
        )
    })
}

// ---------------------------------------------------------------------
// Discovery — RFC 9728 protected-resource metadata, RFC 8414
// authorization-server metadata
// ---------------------------------------------------------------------

pub async fn protected_resource_metadata(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, OAuthError> {
    let cfg = require_oauth(&state)?;
    Ok(Json(serde_json::json!({
        "resource": cfg.resource,
        "authorization_servers": [cfg.issuer],
        "scopes_supported": ["memwal:read", "memwal:write", "offline_access"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Walrus Memory",
    })))
}

pub async fn authorization_server_metadata(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, OAuthError> {
    let cfg = require_oauth(&state)?;
    Ok(Json(serde_json::json!({
        "issuer": cfg.issuer,
        "authorization_endpoint": format!("{}/oauth/authorize", cfg.issuer),
        "token_endpoint": format!("{}/oauth/token", cfg.issuer),
        "registration_endpoint": format!("{}/oauth/register", cfg.issuer),
        "revocation_endpoint": format!("{}/oauth/revoke", cfg.issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "scopes_supported": ["memwal:read", "memwal:write", "offline_access"],
    })))
}

// ---------------------------------------------------------------------
// RFC 7591 — Dynamic Client Registration
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    #[serde(default)]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub client_id_issued_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub scope: String,
}

pub async fn register_client(
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(req): Json<ClientRegistrationRequest>,
) -> Result<(StatusCode, Json<ClientRegistrationResponse>), OAuthError> {
    let cfg = require_oauth(&state)?;

    // Decision D5: Anthropic's documented connector egress is a single
    // shared CIDR — every Claude user's DCR request would otherwise land in
    // one per-IP bucket. Exempt it; throttle everything else per-IP via the
    // existing Redis rate limiter, backed by the global unconsumed-client
    // cap below regardless of source.
    let ip = crate::client_ip::canonical_client_ip(
        &headers,
        connect_addr,
        state.config.trusted_proxy_hops,
    );
    let is_trusted = oauth::ip_is_trusted(ip, &cfg.registration_trusted_cidrs);
    if !is_trusted {
        let mut redis = state.redis.clone();
        let key = format!("mcp_oauth:register_rl:{}", ip);
        let count: i64 = redis::cmd("INCR")
            .arg(&key)
            .query_async(&mut redis)
            .await
            .unwrap_or(1);
        if count == 1 {
            let _: Result<(), redis::RedisError> = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(3600)
                .query_async(&mut redis)
                .await;
        }
        if count > cfg.registration_per_hour_per_ip as i64 {
            return Err(OAuthError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "invalid_request",
                "registration rate limit exceeded, try again later",
            ));
        }
    }

    // Global backstop regardless of source IP — bounds the worst case even
    // if the trusted-CIDR check is ever misconfigured.
    if state
        .db
        .count_unconsumed_oauth_clients(std::time::Duration::from_secs(3600))
        .await
        .unwrap_or(0)
        > 5000
    {
        return Err(OAuthError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "invalid_request",
            "registration is temporarily unavailable, try again later",
        ));
    }

    if req.redirect_uris.is_empty() || req.redirect_uris.len() > 10 {
        return Err(OAuthError::invalid_client_metadata(
            "redirect_uris must contain 1-10 URIs",
        ));
    }
    for uri in &req.redirect_uris {
        if !oauth::is_allowed_registration_redirect(uri, &cfg.allowed_registration_redirect_hosts) {
            return Err(OAuthError::invalid_client_metadata(format!(
                "redirect_uri is not on the allowed registration list: {uri}"
            )));
        }
    }

    let client_name =
        oauth::sanitize_client_name(req.client_name.as_deref().unwrap_or("Unnamed client"))
            .map_err(|_| OAuthError::invalid_client_metadata("client_name is invalid"))?;

    let auth_method = req
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| "none".to_string());
    if !matches!(
        auth_method.as_str(),
        "none" | "client_secret_basic" | "client_secret_post"
    ) {
        return Err(OAuthError::invalid_client_metadata(
            "unsupported token_endpoint_auth_method",
        ));
    }

    let grant_types = req.grant_types.clone().unwrap_or_else(|| {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    });
    for gt in &grant_types {
        if !matches!(gt.as_str(), "authorization_code" | "refresh_token") {
            return Err(OAuthError::invalid_client_metadata(format!(
                "unsupported grant_type: {gt}"
            )));
        }
    }
    let response_types = req
        .response_types
        .clone()
        .unwrap_or_else(|| vec!["code".to_string()]);
    if response_types != ["code"] {
        return Err(OAuthError::invalid_client_metadata(
            "only response_type=code is supported",
        ));
    }
    let scope = oauth::normalize_scopes(req.scope.as_deref().unwrap_or(oauth::DEFAULT_SCOPES))
        .map_err(OAuthError::invalid_client_metadata)?;

    let client_id = oauth::random_token(oauth::CLIENT_ID_PREFIX);
    let (client_secret, client_secret_sha256) = if auth_method == "none" {
        (None, None)
    } else {
        let secret = oauth::random_token("mws_secret_");
        let hash = oauth::hash_token(&secret);
        (Some(secret), Some(hash))
    };

    let row = OAuthClientRow {
        client_id: client_id.clone(),
        client_secret_sha256,
        client_name: client_name.clone(),
        redirect_uris: req.redirect_uris.clone(),
        grant_types: grant_types.clone(),
        response_types: response_types.clone(),
        token_endpoint_auth_method: auth_method.clone(),
        scope: scope.clone(),
        status: "active".to_string(),
        registered_ip: Some(ip.to_string()),
    };
    state.db.insert_oauth_client(&row).await?;

    Ok((
        StatusCode::CREATED,
        Json(ClientRegistrationResponse {
            client_id,
            client_id_issued_at: Utc::now().timestamp(),
            client_secret,
            client_secret_expires_at: if auth_method == "none" { None } else { Some(0) },
            client_name,
            redirect_uris: req.redirect_uris,
            grant_types,
            response_types,
            token_endpoint_auth_method: auth_method,
            scope,
        }),
    ))
}

// ---------------------------------------------------------------------
// GET /oauth/authorize
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

fn error_page(status: StatusCode, title: &str, detail: &str) -> Response {
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head>\
         <body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem\">\
         <h1>{title}</h1><p>{detail}</p></body></html>"
    );
    (status, Html(body)).into_response()
}

pub async fn authorize(
    ConnectInfo(connect_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<AuthorizeQuery>,
) -> Response {
    let cfg = match require_oauth(&state) {
        Ok(cfg) => cfg,
        Err(err) => return err.into_response(),
    };

    let ip = crate::client_ip::canonical_client_ip(
        &headers,
        connect_addr,
        state.config.trusted_proxy_hops,
    );
    let is_trusted = oauth::ip_is_trusted(ip, &cfg.registration_trusted_cidrs);
    if !is_trusted {
        let mut redis = state.redis.clone();
        let key = format!("mcp_oauth:authorize_rl:{}", ip);
        let count: i64 = redis::cmd("INCR")
            .arg(&key)
            .query_async(&mut redis)
            .await
            .unwrap_or(1);
        let _: Result<(), redis::RedisError> = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(3600)
            .query_async(&mut redis)
            .await;
        if count > 60 {
            return error_page(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many requests",
                "Authorization rate limit exceeded, try again later.",
            );
        }
    }

    // Client and redirect_uri must both check out before we're willing to
    // redirect anywhere — an invalid client or redirect target is an error
    // PAGE, never a redirect, so a bad `client_id` can't be used to bounce
    // a victim through our domain to an attacker's URL.
    let client = match state.db.fetch_oauth_client(&query.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Unknown application",
                "This connector is not registered with Walrus Memory.",
            )
        }
        Err(_) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "Please try again.",
            )
        }
    };
    // Match against the registered list (port-agnostic for loopback), but
    // persist the client-presented URI. Cloning the registered URI here
    // sent Claude Code's auth code to port 80 and made token exchange
    // reject the real `http://localhost:<ephemeral>/callback` (#619).
    let Some(redirect_uri) = oauth::authorize_redirect_uri(
        &query.redirect_uri,
        client.redirect_uris.iter().map(String::as_str),
    )
    .map(str::to_owned) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Redirect not recognized",
            "The redirect_uri does not match what this connector registered.",
        );
    };

    // Every failure below this point is safe to report via redirect, per
    // RFC 6749 §4.1.2.1 — the caller already proved it controls
    // `redirect_uri`.
    let bounce_error = |error: &'static str, description: &str| -> Response {
        let mut target = url::Url::parse(&redirect_uri).expect("validated above");
        target.query_pairs_mut().append_pair("error", error);
        if !description.is_empty() {
            target
                .query_pairs_mut()
                .append_pair("error_description", description);
        }
        if let Some(state) = &query.state {
            target.query_pairs_mut().append_pair("state", state);
        }
        Redirect::to(target.as_str()).into_response()
    };

    if query.response_type != "code" {
        return bounce_error(
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    if query.code_challenge_method.as_deref() != Some("S256") {
        return bounce_error("invalid_request", "code_challenge_method must be S256");
    }
    if query.code_challenge.is_empty() {
        return bounce_error("invalid_request", "code_challenge is required");
    }
    let Some(resource) = query
        .resource
        .as_deref()
        .and_then(oauth::normalize_resource_uri)
    else {
        return bounce_error(
            "invalid_target",
            "resource is required and must be a valid https URL",
        );
    };
    if resource != oauth::normalize_resource_uri(&cfg.resource).unwrap_or_default() {
        return bounce_error("invalid_target", "resource does not match this server");
    }

    // Reuse an already-activated delegate for this account+client pair if
    // the account is known from a prior grant tied to the SAME client, so a
    // reconnect doesn't mint a fresh on-chain delegate key every time. We
    // don't know the account yet at this point (no wallet connected), so
    // this is re-checked in `session_account` once the user picks a
    // wallet — here we always mint a placeholder pending delegate; the
    // consent step may swap it for a reused one.
    let (private_key_hex, public_key_hex, delegate_address) = oauth::generate_delegate_key();
    let encrypted = match oauth::encrypt_delegate_private_key(&cfg.encryption_key, &private_key_hex)
    {
        Ok(env) => env,
        Err(_) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "Please try again.",
            )
        }
    };
    let delegate_ref = oauth::random_token(oauth::DELEGATE_REF_PREFIX);
    let delegate_row = OAuthDelegateRow {
        delegate_ref: delegate_ref.clone(),
        account_id: None,
        owner_address: None,
        delegate_public_key: public_key_hex,
        delegate_address,
        encrypted_private_key: encrypted,
        label: oauth::sanitize_label(query.state.as_deref().unwrap_or(""), &client.client_name),
        status: "pending".to_string(),
        tx_digest: None,
    };
    if state.db.insert_oauth_delegate(&delegate_row).await.is_err() {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "Please try again.",
        );
    }

    let scope = match oauth::normalize_scopes(query.scope.as_deref().unwrap_or(&client.scope)) {
        Ok(scope) if oauth::scopes_are_subset(&scope, &client.scope) => scope,
        Ok(_) => {
            return bounce_error(
                "invalid_scope",
                "requested scope exceeds the registered client scope",
            )
        }
        Err(_) => return bounce_error("invalid_scope", "requested scope is unsupported"),
    };
    let session_id = oauth::random_token(oauth::SESSION_ID_PREFIX);
    let session_row = OAuthSessionRow {
        session_id: session_id.clone(),
        client_id: client.client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        state: query.state.clone(),
        scope,
        resource: resource.clone(),
        code_challenge: query.code_challenge.clone(),
        code_challenge_method: "S256".to_string(),
        delegate_ref,
        status: "pending".to_string(),
        expires_at: Utc::now() + Duration::seconds(cfg.session_ttl_secs),
    };
    if state.db.insert_oauth_session(&session_row).await.is_err() {
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong",
            "Please try again.",
        );
    }
    let _ = state
        .db
        .touch_oauth_client_last_used(&client.client_id)
        .await;

    Redirect::to(&format!("{}?session={session_id}", cfg.consent_url)).into_response()
}

// ---------------------------------------------------------------------
// Consent SPA JSON API
// ---------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SessionViewResponse {
    pub client_name: String,
    pub redirect_host: String,
    pub scopes: Vec<String>,
    pub delegate_public_key: String,
    pub delegate_sui_address: String,
    pub expires_at: chrono::DateTime<Utc>,
}

pub async fn session_view(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<Json<SessionViewResponse>, OAuthError> {
    require_oauth(&state)?;
    let session = state
        .db
        .fetch_oauth_session(&session_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_request("unknown or expired session"))?;
    let client = state
        .db
        .fetch_oauth_client(&session.client_id)
        .await?
        .ok_or_else(|| OAuthError::server_error("session references an unknown client"))?;
    let delegate = state
        .db
        .fetch_oauth_delegate(&session.delegate_ref)
        .await?
        .ok_or_else(|| OAuthError::server_error("session references an unknown delegate"))?;

    let redirect_host = url::Url::parse(&session.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());

    Ok(Json(SessionViewResponse {
        client_name: client.client_name,
        redirect_host,
        scopes: session
            .scope
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        delegate_public_key: delegate.delegate_public_key,
        delegate_sui_address: delegate.delegate_address,
        expires_at: session.expires_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SessionAccountRequest {
    pub account_id: String,
    /// Accepted for API-shape symmetry with `SessionCompleteRequest`;
    /// the reuse-preflight only needs `account_id`. Owner is verified
    /// on-chain in `session_complete`, not here.
    #[allow(dead_code)]
    pub owner_address: String,
}

#[derive(Debug, Serialize)]
pub struct SessionAccountResponse {
    pub needs_onchain_registration: bool,
    pub delegate_public_key: String,
    pub delegate_sui_address: String,
    /// True when this session's own pending key is already on the account, so
    /// an earlier attempt landed `add_delegate_key` and only `/complete` is
    /// left. Distinguishes that resume from the reuse case, which also sets
    /// `needs_onchain_registration: false` but points at a delegate from an
    /// earlier grant.
    pub resume_pending_registration: bool,
}

pub async fn session_account(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<SessionAccountRequest>,
) -> Result<Json<SessionAccountResponse>, OAuthError> {
    require_oauth(&state)?;
    let account_id = sanitize_sui_object_id(&req.account_id)?;
    let session = state
        .db
        .fetch_oauth_session(&session_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_request("unknown or expired session"))?;

    // Preflight: does this account already have an active OAuth delegate
    // (from a prior grant, any client)? If so, the consent UI can skip the
    // on-chain `add_delegate_key` tx entirely — this is what keeps a
    // reconnect from burning another slot toward the on-chain 20-key cap.
    if let Some(existing) = state.db.find_reusable_oauth_delegate(&account_id).await? {
        return Ok(Json(SessionAccountResponse {
            needs_onchain_registration: false,
            delegate_public_key: existing.delegate_public_key,
            delegate_sui_address: existing.delegate_address,
            resume_pending_registration: false,
        }));
    }

    let delegate = state
        .db
        .fetch_oauth_delegate(&session.delegate_ref)
        .await?
        .ok_or_else(|| OAuthError::server_error("session references an unknown delegate"))?;

    // This session's own key can already be on the account: an earlier attempt
    // landed `add_delegate_key` and then failed further along, which is exactly
    // what a Sui 429 during `/complete` verify used to cause (WALM-605).
    // Re-submitting aborts with `EDelegateKeyAlreadyExists`, and the consent UI
    // cannot recognise that abort — it signs through the sponsor proxy, and
    // `sponsor::mask_upstream` turns any upstream 5xx into a bare 502
    // `sponsor_upstream_error` that never echoes the Move abort. So the skip has
    // to be decided here, against the chain, rather than by string-matching a
    // transaction error that does not survive the proxy.
    let public_key_bytes = hex::decode(&delegate.delegate_public_key)
        .map_err(|_| OAuthError::server_error("stored delegate public key is invalid"))?;
    let resume = match classify_pending_key_preflight(
        verify_delegate_key_onchain(
            &state.http_client,
            &state.config.sui_rpc_url,
            state.sui_grpc_client.as_ref(),
            &account_id,
            &public_key_bytes,
            &state.config.package_id,
            GET_OBJECT_ATTEMPTS,
        )
        .await,
    ) {
        PendingKeyPreflight::Resume => true,
        PendingKeyPreflight::Register => false,
        PendingKeyPreflight::Unknown { reason } => {
            tracing::warn!(
                %reason,
                "oauth session_account: Sui unavailable, cannot tell whether this session's delegate key is already registered"
            );
            return Err(OAuthError::temporarily_unavailable(format!(
                "could not check the delegate key on-chain right now, please retry: {reason}"
            )));
        }
    };

    Ok(Json(SessionAccountResponse {
        needs_onchain_registration: !resume,
        delegate_public_key: delegate.delegate_public_key,
        delegate_sui_address: delegate.delegate_address,
        resume_pending_registration: resume,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SessionCompleteRequest {
    pub account_id: String,
    pub owner_address: String,
    pub owner_signature: String,
    pub tx_digest: String,
}

#[derive(Debug, Serialize)]
pub struct RedirectResponse {
    pub redirect_url: String,
}

fn oauth_owner_proof_message(session_id: &str, account_id: &str, owner_address: &str) -> String {
    format!(
        "Walrus Memory OAuth authorization\nsession:{session_id}\naccount:{account_id}\nowner:{owner_address}"
    )
}

fn sanitize_sui_object_id(raw: &str) -> Result<String, OAuthError> {
    let value = raw.trim();
    if value.starts_with("0x")
        && value.len() == 66
        && value[2..].chars().all(|c| c.is_ascii_hexdigit())
    {
        Ok(value.to_ascii_lowercase())
    } else {
        Err(OAuthError::invalid_request(
            "account_id/owner_address is invalid",
        ))
    }
}

/// What the chain told us about a delegate key, split by whether the answer
/// was definitive. WALM-605: a Sui `GetObject` 429 is not evidence that the
/// key is unregistered, and must not burn the one-time authorization session.
#[derive(Debug)]
enum DelegateVerifyOutcome {
    /// The chain answered: the key is registered under `owner`.
    Verified { owner: String },
    /// The chain answered definitively "no" — key absent, account deactivated,
    /// object missing or of the wrong type. Terminal for this session.
    Unregistered { reason: String },
    /// The chain could not be consulted (RPC 429/503/timeout, registry scan
    /// cap). No answer yet, so the caller may re-submit the same request.
    Retryable { reason: String },
}

impl DelegateVerifyOutcome {
    /// Only a definitive answer spends the one-time authorization session. A
    /// retryable upstream failure must leave it `pending` so the consent UI can
    /// re-POST `/complete` instead of restarting `/oauth/authorize` (WALM-605).
    ///
    /// `session_complete` encodes this in its match arms; the tests below pin
    /// the rule itself.
    fn consumes_session(&self) -> bool {
        !matches!(self, Self::Retryable { .. })
    }
}

/// Classify a `verify_delegate_key_onchain` result. Deliberately delegates to
/// `OnchainVerifyError::is_unavailable()` — the same primitive signed HTTP
/// auth uses in `auth::cache_reverify_action` — so the OAuth callback and
/// signed recall can never drift apart on what a Sui 429 means (WALM-429).
fn classify_delegate_verify(result: Result<String, OnchainVerifyError>) -> DelegateVerifyOutcome {
    match result {
        Ok(owner) => DelegateVerifyOutcome::Verified { owner },
        Err(e) if e.is_unavailable() => DelegateVerifyOutcome::Retryable {
            reason: e.to_string(),
        },
        Err(e) => DelegateVerifyOutcome::Unregistered {
            reason: e.to_string(),
        },
    }
}

/// What `/account` should tell the consent UI about this session's own pending
/// delegate key, given what the chain said about it.
#[derive(Debug)]
enum PendingKeyPreflight {
    /// Already on the account: an earlier attempt landed `add_delegate_key` and
    /// only `/complete` is left. Re-submitting would abort with
    /// `EDelegateKeyAlreadyExists`, which the consent UI cannot see.
    Resume,
    /// Definitively absent — the ordinary first-time path.
    Register,
    /// The chain could not be consulted, so there is no safe guess: telling the
    /// UI to register walks into a sponsor 502 it cannot classify, and telling
    /// it to skip sends `/complete` at a key that is not on the account, which
    /// is definitive Unregistered and burns the one-time session.
    Unknown { reason: String },
}

/// Reuse `classify_delegate_verify` rather than re-reading `is_unavailable()`,
/// so the preflight and `session_complete` cannot drift apart on what a Sui 429
/// means (WALM-429 / WALM-605).
fn classify_pending_key_preflight(
    result: Result<String, OnchainVerifyError>,
) -> PendingKeyPreflight {
    match classify_delegate_verify(result) {
        DelegateVerifyOutcome::Verified { .. } => PendingKeyPreflight::Resume,
        DelegateVerifyOutcome::Unregistered { .. } => PendingKeyPreflight::Register,
        DelegateVerifyOutcome::Retryable { reason } => PendingKeyPreflight::Unknown { reason },
    }
}

/// What an OAuth refresh may do after the custodied delegate key is re-checked.
///
/// The token handler acts only on this value, so the unit tests lock the
/// policy without a database or a live chain. A positive inside
/// `DELEGATE_VERIFY_CACHE_TTL` (30s) may still mint. Refresh does not use
/// the 600s stale grace. A cached rejection (10s) revokes (GH #1141).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshDelegateDecision {
    /// Key is still registered to the grant's owner. Rotate and mint.
    Rotate,
    /// Definitive miss, or the on-chain owner is not the grant owner.
    /// Revoke the grant and do not mint.
    RejectAndRevoke,
    /// Chain could not be consulted. Do not revoke and do not mint.
    Unavailable,
}

impl RefreshDelegateDecision {
    fn revokes_grant(self) -> bool {
        matches!(self, Self::RejectAndRevoke)
    }

    /// `None` only when the refresh may mint. A miss is `invalid_grant`;
    /// an RPC blip is `temporarily_unavailable` (503 + Retry-After) so the
    /// grant stays usable and the client retries later.
    fn failure(self) -> Option<OAuthError> {
        match self {
            Self::Rotate => None,
            Self::RejectAndRevoke => Some(OAuthError::invalid_grant(
                "delegate key is no longer registered on-chain",
            )),
            Self::Unavailable => Some(OAuthError::temporarily_unavailable(
                "delegate key could not be verified on-chain",
            )),
        }
    }
}

/// Classify a cached delegate verify for refresh.
///
/// Revoke only when [`OnchainVerifyError::revokes_oauth_refresh`] is set, or
/// the verified owner is not the grant owner. A partial read and any
/// unavailable RPC, including a Sui 429, are `temporarily_unavailable`.
fn refresh_delegate_decision(
    verified: Result<String, OnchainVerifyError>,
    grant_owner: &str,
) -> RefreshDelegateDecision {
    match verified {
        Ok(owner) if owner.eq_ignore_ascii_case(grant_owner) => RefreshDelegateDecision::Rotate,
        Ok(_) => RefreshDelegateDecision::RejectAndRevoke,
        Err(err) if err.revokes_oauth_refresh() => RefreshDelegateDecision::RejectAndRevoke,
        Err(_) => RefreshDelegateDecision::Unavailable,
    }
}

/// The single database capability refresh needs to apply a decision, kept
/// narrow so the wiring is unit-testable without a Postgres pool.
#[async_trait::async_trait]
trait RefreshGrantRevoker: Send + Sync {
    async fn revoke_grant_and_delegate(
        &self,
        grant_id: &str,
        delegate_ref: &str,
    ) -> Result<(), AppError>;
}

#[async_trait::async_trait]
impl RefreshGrantRevoker for crate::storage::db::VectorDb {
    async fn revoke_grant_and_delegate(
        &self,
        grant_id: &str,
        delegate_ref: &str,
    ) -> Result<(), AppError> {
        self.revoke_oauth_grant_and_delegate(grant_id, delegate_ref)
            .await
    }
}

/// Apply a refresh decision before any minting: a revoke lands first, and a
/// failure is returned so the caller cannot rotate without it.
async fn apply_refresh_decision<D: RefreshGrantRevoker>(
    db: &D,
    grant_id: &str,
    delegate_ref: &str,
    decision: RefreshDelegateDecision,
) -> Result<(), OAuthError> {
    if decision.revokes_grant() {
        db.revoke_grant_and_delegate(grant_id, delegate_ref).await?;
    }
    match decision.failure() {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Stored delegate public keys are raw 32-byte hex (`generate_delegate_key`).
/// Anything else is a corrupt row, not evidence the key was removed.
fn decode_refresh_delegate_public_key(hex_key: &str) -> Option<Vec<u8>> {
    let bytes = hex::decode(hex_key).ok()?;
    if bytes.len() == 32 {
        Some(bytes)
    } else {
        None
    }
}

/// Atomically claim a pending session so it can only ever be completed once —
/// Postgres analog of the WALM-30 prior art's Redis GETDEL guarantee. This is
/// the single gate on issuing an authorization code, so it stays the last step
/// before minting one even though the on-chain read now happens earlier.
async fn claim_oauth_session(
    state: &AppState,
    session_id: &str,
) -> Result<OAuthSessionRow, OAuthError> {
    state
        .db
        .consume_oauth_session(session_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_request("session already used, expired, or unknown"))
}

pub async fn session_complete(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<SessionCompleteRequest>,
) -> Result<Json<RedirectResponse>, OAuthError> {
    require_oauth(&state)?;
    let account_id = sanitize_sui_object_id(&req.account_id)?;
    let owner_address = sanitize_sui_object_id(&req.owner_address)?;
    if req.tx_digest.trim().is_empty() || req.tx_digest.len() > 160 {
        return Err(OAuthError::invalid_request("tx_digest is invalid"));
    }
    if req.owner_signature.trim().is_empty() || req.owner_signature.len() > 4096 {
        return Err(OAuthError::invalid_request("owner_signature is invalid"));
    }

    // Verify a fresh, session-bound wallet signature before consuming the
    // session or consulting reusable delegates. This prevents an attacker
    // with a session ID from naming a victim account that connected before.
    let proof = oauth_owner_proof_message(&session_id, &account_id, &owner_address);
    state
        .security_delete_wallet_verifier
        .verify_personal(&owner_address, proof.as_bytes(), &req.owner_signature)
        .await
        .map_err(|_| OAuthError::invalid_request("wallet ownership proof is invalid"))?;

    // Read WITHOUT claiming: the claim is irreversible and belongs below the
    // on-chain read (WALM-605). Single-use is unaffected — no code is minted
    // until `claim_oauth_session` wins the `WHERE status = 'pending'` update.
    let pending = state
        .db
        .fetch_oauth_session(&session_id)
        .await?
        .filter(|s| s.status == "pending")
        .ok_or_else(|| OAuthError::invalid_request("session already used, expired, or unknown"))?;

    // Both new and reused delegates require fresh on-chain verification.
    // Possession of an authorization session ID is not wallet proof and must
    // never be sufficient to select another account's custodied delegate.
    let (delegate, is_reused) = match state.db.find_reusable_oauth_delegate(&account_id).await? {
        Some(existing) => (existing, true),
        None => (
            state
                .db
                .fetch_oauth_delegate(&pending.delegate_ref)
                .await?
                .ok_or_else(|| OAuthError::server_error("session delegate is missing"))?,
            false,
        ),
    };
    let public_key_bytes = hex::decode(&delegate.delegate_public_key)
        .map_err(|_| OAuthError::server_error("stored delegate public key is invalid"))?;
    let outcome = classify_delegate_verify(
        verify_delegate_key_onchain(
            &state.http_client,
            &state.config.sui_rpc_url,
            state.sui_grpc_client.as_ref(),
            &account_id,
            &public_key_bytes,
            &state.config.package_id,
            GET_OBJECT_ATTEMPTS,
        )
        .await,
    );
    // Claim only after a definitive on-chain answer; Retryable must leave
    // status='pending'. Claiming per-arm rather than behind a boolean keeps the
    // compiler, not a convention, responsible for that.
    let (session, verified_owner) = match outcome {
        DelegateVerifyOutcome::Retryable { reason } => {
            // Deliberately no session_id: possession of one plus a wallet
            // signature mints a code, so it does not belong in logs.
            tracing::warn!(
                %reason,
                "oauth session_complete: Sui unavailable, leaving session pending for retry"
            );
            return Err(OAuthError::temporarily_unavailable(format!(
                "could not verify the delegate key on-chain right now, please retry: {reason}"
            )));
        }
        DelegateVerifyOutcome::Unregistered { reason } => {
            claim_oauth_session(&state, &session_id).await?;
            return Err(OAuthError::invalid_request(format!(
                "delegate key is not registered on-chain: {reason}"
            )));
        }
        DelegateVerifyOutcome::Verified { owner } => {
            (claim_oauth_session(&state, &session_id).await?, owner)
        }
    };
    if !verified_owner.eq_ignore_ascii_case(&owner_address) {
        return Err(OAuthError::invalid_request(
            "verified owner does not match connected account",
        ));
    }
    if !is_reused {
        state
            .db
            .activate_oauth_delegate(
                &delegate.delegate_ref,
                &account_id,
                &verified_owner,
                &req.tx_digest,
            )
            .await?;
    }
    let delegate_ref = delegate.delegate_ref;
    let delegate_public_key = delegate.delegate_public_key;

    let code = oauth::random_token("mwac_");
    let code_row = OAuthCodeRow {
        code_sha256: oauth::hash_token(&code),
        client_id: session.client_id.clone(),
        redirect_uri: session.redirect_uri.clone(),
        scope: session.scope.clone(),
        resource: session.resource.clone(),
        code_challenge: session.code_challenge.clone(),
        code_challenge_method: session.code_challenge_method.clone(),
        delegate_ref,
        account_id,
        owner_address,
        expires_at: Utc::now()
            + Duration::seconds(
                state
                    .config
                    .mcp_oauth
                    .as_ref()
                    .map(|c| c.code_ttl_secs)
                    .unwrap_or(300),
            ),
    };
    state.db.insert_oauth_code(&code_row).await?;
    let _ = delegate_public_key; // reserved for future consent-page echo; not needed in the redirect

    let mut target = url::Url::parse(&session.redirect_uri).expect("validated at authorize time");
    target.query_pairs_mut().append_pair("code", &code);
    if let Some(state_param) = &session.state {
        target.query_pairs_mut().append_pair("state", state_param);
    }
    Ok(Json(RedirectResponse {
        redirect_url: target.to_string(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct SessionCancelRequest {
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn session_cancel(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(req): Json<SessionCancelRequest>,
) -> Result<Json<RedirectResponse>, OAuthError> {
    require_oauth(&state)?;
    // Cancelling consults nothing off-box, so there is no retryable failure:
    // the denial is definitive and burning the session is the point.
    let session = claim_oauth_session(&state, &session_id).await?;

    let error = req
        .error
        .as_deref()
        .filter(|e| e.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
        .unwrap_or("access_denied");

    let mut target = url::Url::parse(&session.redirect_uri).expect("validated at authorize time");
    target.query_pairs_mut().append_pair("error", error);
    if let Some(state_param) = &session.state {
        target.query_pairs_mut().append_pair("state", state_param);
    }
    Ok(Json(RedirectResponse {
        redirect_url: target.to_string(),
    }))
}

// ---------------------------------------------------------------------
// POST /oauth/token — accepts BOTH application/x-www-form-urlencoded (the
// spec-required content type) and application/json (Anthropic's docs
// explicitly warn that a JSON-only parser here breaks the flow with a 415,
// implying some client code paths send JSON).
// ---------------------------------------------------------------------

pub struct FormOrJson<T>(pub T);

impl<S, T> FromRequest<S> for FormOrJson<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = OAuthError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let is_json = req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.starts_with("application/json"))
            .unwrap_or(false);
        if is_json {
            let Json(value) = Json::<T>::from_request(req, state)
                .await
                .map_err(|e| OAuthError::invalid_request(format!("invalid JSON body: {e}")))?;
            Ok(FormOrJson(value))
        } else {
            let Form(value) = Form::<T>::from_request(req, state)
                .await
                .map_err(|e| OAuthError::invalid_request(format!("invalid form body: {e}")))?;
            Ok(FormOrJson(value))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
}

/// Authenticate the client for `/oauth/token`: Basic-auth header wins if
/// present (confidential clients), otherwise `client_id`/`client_secret`
/// from the body (RFC 6749 allows either; Claude's public clients send
/// neither and rely on `token_endpoint_auth_method: "none"`).
fn client_credentials_from_request(
    headers: &HeaderMap,
    body: &TokenRequest,
) -> Option<(String, Option<String>)> {
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(encoded) = auth.strip_prefix("Basic ") {
            if let Ok(decoded) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            {
                if let Ok(text) = String::from_utf8(decoded) {
                    if let Some((id, secret)) = text.split_once(':') {
                        return Some((id.to_string(), Some(secret.to_string())));
                    }
                }
            }
        }
    }
    body.client_id
        .clone()
        .map(|id| (id, body.client_secret.clone()))
}

async fn authenticate_client(
    state: &AppState,
    headers: &HeaderMap,
    body: &TokenRequest,
) -> Result<OAuthClientRow, OAuthError> {
    let (client_id, secret) = client_credentials_from_request(headers, body)
        .ok_or_else(|| OAuthError::invalid_client("missing client authentication"))?;
    let client = state
        .db
        .fetch_oauth_client(&client_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_client("unknown client"))?;

    match client.token_endpoint_auth_method.as_str() {
        "none" => Ok(client),
        _ => {
            let secret =
                secret.ok_or_else(|| OAuthError::invalid_client("missing client_secret"))?;
            let expected = client
                .client_secret_sha256
                .as_deref()
                .ok_or_else(|| OAuthError::invalid_client("client has no secret configured"))?;
            if oauth::constant_time_eq(oauth::hash_token(&secret).as_bytes(), expected.as_bytes()) {
                Ok(client)
            } else {
                Err(OAuthError::invalid_client("invalid client_secret"))
            }
        }
    }
}

fn mint_token_pair(
    cfg: &oauth::McpOAuthConfig,
    grant_id: &str,
    scope: &str,
) -> (String, OAuthTokenRow, String, OAuthTokenRow) {
    let access_token = oauth::random_token(oauth::ACCESS_TOKEN_PREFIX);
    let access_row = OAuthTokenRow {
        token_sha256: oauth::hash_token(&access_token),
        grant_id: grant_id.to_string(),
        token_type: "access".to_string(),
        expires_at: Utc::now() + Duration::seconds(cfg.access_ttl_secs),
    };
    let refresh_token = oauth::random_token(oauth::REFRESH_TOKEN_PREFIX);
    let refresh_row = OAuthTokenRow {
        token_sha256: oauth::hash_token(&refresh_token),
        grant_id: grant_id.to_string(),
        token_type: "refresh".to_string(),
        expires_at: Utc::now() + Duration::seconds(cfg.refresh_ttl_secs),
    };
    let _ = scope;
    (access_token, access_row, refresh_token, refresh_row)
}

pub async fn token(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    FormOrJson(req): FormOrJson<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    let cfg = require_oauth(&state)?;

    match req.grant_type.as_str() {
        "authorization_code" => {
            let client = authenticate_client(&state, &headers, &req).await?;
            let code = req
                .code
                .as_deref()
                .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
            let redirect_uri = req
                .redirect_uri
                .as_deref()
                .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;
            let code_verifier = req
                .code_verifier
                .as_deref()
                .ok_or_else(|| OAuthError::invalid_request("code_verifier is required"))?;

            let code_sha256 = oauth::hash_token(code);
            let code_row = state
                .db
                .fetch_oauth_code(&client.client_id, &code_sha256)
                .await?
                .ok_or_else(|| {
                    OAuthError::invalid_grant(
                        "authorization code is invalid, expired, or already used",
                    )
                })?;

            if code_row.redirect_uri != redirect_uri {
                return Err(OAuthError::invalid_grant(
                    "redirect_uri does not match the authorization request",
                ));
            }
            if !oauth::verify_pkce_s256(code_verifier, &code_row.code_challenge) {
                return Err(OAuthError::invalid_grant(
                    "code_verifier does not match code_challenge",
                ));
            }
            if let Some(requested_resource) = req.resource.as_deref() {
                let normalized = oauth::normalize_resource_uri(requested_resource);
                if normalized.as_deref() != Some(code_row.resource.as_str()) {
                    return Err(OAuthError::invalid_target(
                        "resource does not match the authorization request",
                    ));
                }
            }

            let code_row = state
                .db
                .consume_oauth_code(&client.client_id, &code_sha256)
                .await?
                .ok_or_else(|| {
                    OAuthError::invalid_grant(
                        "authorization code is invalid, expired, or already used",
                    )
                })?;

            let grant_id = oauth::random_token(oauth::GRANT_ID_PREFIX);
            state
                .db
                .insert_oauth_grant(&OAuthGrantRow {
                    grant_id: grant_id.clone(),
                    client_id: client.client_id.clone(),
                    delegate_ref: code_row.delegate_ref.clone(),
                    account_id: code_row.account_id.clone(),
                    owner_address: code_row.owner_address.clone(),
                    scope: code_row.scope.clone(),
                    resource: code_row.resource.clone(),
                })
                .await?;

            let (access_token, access_row, refresh_token, refresh_row) =
                mint_token_pair(cfg, &grant_id, &code_row.scope);
            state.db.insert_oauth_token(&access_row).await?;
            state.db.insert_oauth_token(&refresh_row).await?;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: cfg.access_ttl_secs,
                refresh_token: Some(refresh_token),
                scope: code_row.scope,
            }))
        }
        "refresh_token" => {
            let client = authenticate_client(&state, &headers, &req).await?;
            let presented = req
                .refresh_token
                .as_deref()
                .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
            let presented_hash = oauth::hash_token(presented);

            let preview = state
                .db
                .fetch_oauth_token_with_delegate(&presented_hash)
                .await?
                .ok_or_else(|| OAuthError::invalid_grant("refresh_token is invalid"))?;
            if preview.token_type != "refresh" {
                return Err(OAuthError::invalid_grant("token is not a refresh token"));
            }
            if preview.client_id != client.client_id {
                return Err(OAuthError::invalid_grant(
                    "refresh_token belongs to another client",
                ));
            }
            if preview.revoked_at.is_some() || preview.grant_revoked_at.is_some() {
                state.db.revoke_oauth_grant(&preview.grant_id).await?;
                return Err(OAuthError::invalid_grant(
                    "refresh_token was already used or revoked; the connection has been revoked",
                ));
            }
            if preview.expires_at <= Utc::now() {
                return Err(OAuthError::invalid_grant("refresh_token has expired"));
            }

            // GH #1141: refresh must not outlive `remove_delegate_key`.
            // Revoke when the key is gone, the account is deactivated, the
            // owner does not match, gRPC NotFound or JSON-RPC notExists/
            // deleted hits the object, or the object is a present foreign
            // type. A partial RPC read is `temporarily_unavailable` and does
            // not revoke. A definitive miss retires the grant *and* the
            // delegate atomically, so reconnect cannot reuse the dead key.
            // Do not log `encrypted_private_key` or the key bytes.
            //
            // Window on this path: a positive inside `DELEGATE_VERIFY_CACHE_TTL`
            // (30s) may still mint. `DELEGATE_VERIFY_STALE_GRACE` (600s) is
            // not used — past 30s an unreachable chain is
            // `temporarily_unavailable`, not a mint and not a revoke. A
            // rejection cached for `DELEGATE_REJECT_CACHE_TTL` (10s) is a
            // miss and revokes.
            let Some(public_key_bytes) =
                decode_refresh_delegate_public_key(&preview.delegate_public_key)
            else {
                return Err(OAuthError::server_error(
                    "stored delegate public key is invalid",
                ));
            };
            let verified = verify_delegate_key_cached_for_refresh(
                &state.delegate_verify_cache,
                &state.delegate_reject_cache,
                &state.http_client,
                &state.config.sui_rpc_url,
                state.sui_grpc_client.as_ref(),
                &preview.account_id,
                &public_key_bytes,
                &state.config.package_id,
            )
            .await;
            if let Err(err) = &verified {
                tracing::warn!(
                    account_id = %preview.account_id,
                    error = %err,
                    "oauth refresh delegate verify failed"
                );
            }
            let decision = refresh_delegate_decision(verified, &preview.owner_address);
            // Revoke (grant + delegate) and fail before any token is minted;
            // the helper returns the decision's error, if any.
            apply_refresh_decision(
                state.db.as_ref(),
                &preview.grant_id,
                &preview.delegate_ref,
                decision,
            )
            .await?;

            // Consume and replace the refresh token in one database
            // transaction. Exactly one concurrent presenter can succeed.
            let (access_token, access_row, refresh_token, refresh_row) =
                mint_token_pair(cfg, &preview.grant_id, &preview.scope);
            let row = state
                .db
                .rotate_oauth_refresh_token(
                    &presented_hash,
                    &client.client_id,
                    &access_row,
                    &refresh_row,
                )
                .await?
                .ok_or_else(|| {
                    OAuthError::invalid_grant("refresh_token was concurrently used or revoked")
                })?;

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer",
                expires_in: cfg.access_ttl_secs,
                refresh_token: Some(refresh_token),
                scope: row.scope,
            }))
        }
        other => Err(OAuthError::unsupported_grant_type(format!(
            "unsupported grant_type: {other}"
        ))),
    }
}

// ---------------------------------------------------------------------
// POST /oauth/revoke (RFC 7009)
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

pub async fn revoke(
    State(state): State<Arc<AppState>>,
    FormOrJson(req): FormOrJson<RevokeRequest>,
) -> Result<StatusCode, OAuthError> {
    require_oauth(&state)?;
    let hash = oauth::hash_token(&req.token);
    let _ = req.token_type_hint;

    // RFC 7009 §2.2: revoking a refresh token invalidates its whole grant;
    // revoking an access token invalidates only that token. Always 200
    // regardless of whether the token existed, to avoid leaking token
    // validity to an unauthenticated caller.
    if let Ok(Some(row)) = state.db.fetch_oauth_token_with_delegate(&hash).await {
        if row.token_type == "refresh" {
            let _ = state.db.revoke_oauth_grant(&row.grant_id).await;
        } else {
            let _ = state.db.revoke_oauth_token(&hash).await;
        }
    }
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::Mutex;

    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use sui_crypto::ed25519::Ed25519PrivateKey;
    use sui_crypto::SuiSigner;
    use sui_sdk_types::{PersonalMessage, UserSignature};

    use crate::oauth::{OAuthError, OAUTH_UPSTREAM_RETRY_AFTER_SECS};
    use crate::security_delete_auth::{NativeWalletSignatureVerifier, WalletSignatureVerifier};
    use crate::storage::sui::{
        ensure_memwal_account_type, map_get_object_status, partial_get_object, OnchainVerifyError,
        PARTIAL_GRPC_OBJECT_ABSENT, PARTIAL_RPC_NO_CONTENT, PARTIAL_RPC_NO_RESULT,
    };
    use crate::types::AppError;

    use super::{
        apply_refresh_decision, classify_delegate_verify, classify_pending_key_preflight,
        decode_refresh_delegate_public_key, oauth_owner_proof_message, refresh_delegate_decision,
        DelegateVerifyOutcome, PendingKeyPreflight, RefreshDelegateDecision, RefreshGrantRevoker,
    };

    fn assert_refresh_policy(
        decision: RefreshDelegateDecision,
        rotates: bool,
        revokes: bool,
        error: Option<&str>,
    ) {
        assert_eq!(
            matches!(decision, RefreshDelegateDecision::Rotate),
            rotates,
            "{decision:?}"
        );
        assert_eq!(decision.revokes_grant(), revokes, "{decision:?}");
        assert_eq!(
            decision.revokes_grant(),
            matches!(decision, RefreshDelegateDecision::RejectAndRevoke),
            "{decision:?}"
        );
        assert!(
            !(rotates && revokes),
            "a refresh must not both mint and revoke"
        );
        match decision.failure() {
            None => {
                assert!(rotates, "{decision:?} with no error must mint");
                assert!(error.is_none(), "{decision:?} must not mint an error");
            }
            Some(err) => {
                assert!(!rotates, "{decision:?} must not mint");
                assert_eq!(err.error, error.expect("expected an oauth error code"));
            }
        }
    }

    #[test]
    fn refresh_rotates_only_when_the_verified_owner_matches() {
        assert_refresh_policy(
            refresh_delegate_decision(Ok("0xAbC".into()), "0xabc"),
            true,
            false,
            None,
        );
        assert_refresh_policy(
            refresh_delegate_decision(Ok("0xowner".into()), "0xowner"),
            true,
            false,
            None,
        );
    }

    #[test]
    fn refresh_revokes_on_definitive_miss_and_owner_mismatch() {
        for err in [
            OnchainVerifyError::KeyNotFound("gone".into()),
            OnchainVerifyError::AccountDeactivated("dead".into()),
            map_get_object_status(tonic::Status::not_found("no such object")),
            OnchainVerifyError::WrongObjectType("foreign".into()),
            OnchainVerifyError::NotFound("sui_getObject notExists".into()),
            OnchainVerifyError::NotFound("sui_getObject deleted".into()),
        ] {
            let label = err.to_string();
            assert!(err.revokes_oauth_refresh(), "{label}");
            let decision = refresh_delegate_decision(Err(err), "0xowner");
            assert_refresh_policy(decision, false, true, Some("invalid_grant"));
            let err = decision
                .failure()
                .expect("definitive miss is invalid_grant");
            assert!(
                err.description.contains("no longer registered on-chain"),
                "{label}"
            );
        }
        let mismatch = refresh_delegate_decision(Ok("0xOther".into()), "0xowner");
        assert_refresh_policy(mismatch, false, true, Some("invalid_grant"));
        assert!(mismatch
            .failure()
            .expect("owner mismatch is invalid_grant")
            .description
            .contains("no longer registered on-chain"));
    }

    #[test]
    fn refresh_does_not_revoke_on_a_partial_rpc_read() {
        let missing_type =
            ensure_memwal_account_type(None, "0xpkg", "0xobj").expect_err("missing object_type");
        let cases = [
            partial_get_object(PARTIAL_RPC_NO_RESULT),
            partial_get_object(PARTIAL_RPC_NO_CONTENT),
            partial_get_object(PARTIAL_GRPC_OBJECT_ABSENT),
            map_get_object_status(tonic::Status::invalid_argument("bad object id")),
            missing_type,
        ];
        for err in cases {
            let label = err.to_string();
            assert!(
                err.is_unavailable(),
                "{label} is a partial read, not a missing key"
            );
            assert!(!err.revokes_oauth_refresh(), "{label}");
            let decision = refresh_delegate_decision(Err(err), "0xowner");
            assert_refresh_policy(decision, false, false, Some("temporarily_unavailable"));
            assert!(
                !decision.revokes_grant(),
                "{label} must not revoke the grant"
            );
        }

        // Historical partial strings, if they still arrive as NotFound, and an
        // unparseable object id, are not a real removal and must not revoke.
        let stale_shapes = [
            OnchainVerifyError::NotFound(PARTIAL_RPC_NO_RESULT.into()),
            OnchainVerifyError::NotFound(PARTIAL_RPC_NO_CONTENT.into()),
            OnchainVerifyError::NotFound(PARTIAL_GRPC_OBJECT_ABSENT.into()),
            OnchainVerifyError::NotFound(format!(
                "gRPC GetObject failed: {}",
                tonic::Status::invalid_argument("bad object id")
            )),
            OnchainVerifyError::NotFound("invalid object id: bad".into()),
        ];
        for err in stale_shapes {
            let label = err.to_string();
            assert!(!err.revokes_oauth_refresh(), "{label}");
            assert_refresh_policy(
                refresh_delegate_decision(Err(err), "0xowner"),
                false,
                false,
                Some("temporarily_unavailable"),
            );
        }
    }

    #[test]
    fn refresh_holds_when_the_chain_is_unavailable() {
        for err in [
            OnchainVerifyError::RpcError("gRPC GetObject failed: 429 Too Many Requests".into()),
            OnchainVerifyError::ScanCapExceeded("registry scan cap".into()),
        ] {
            let decision = refresh_delegate_decision(Err(err), "0xowner");
            assert_refresh_policy(decision, false, false, Some("temporarily_unavailable"));
            assert!(
                !decision.revokes_grant(),
                "an RPC blip must not revoke the grant"
            );
            assert!(
                matches!(decision, RefreshDelegateDecision::Unavailable),
                "an RPC blip must not mint"
            );
            assert_eq!(
                decision.failure().expect("an RPC blip is retryable").status,
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }

    /// Records the revokes the refresh helper performs. A `Mutex` rather than
    /// a `RefCell` because the trait is `Send + Sync`; still no DB, no I/O.
    #[derive(Default)]
    struct RecordingRevoker {
        calls: Mutex<Vec<String>>,
        fail: bool,
    }

    impl RecordingRevoker {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    #[async_trait::async_trait]
    impl RefreshGrantRevoker for RecordingRevoker {
        async fn revoke_grant_and_delegate(
            &self,
            grant_id: &str,
            delegate_ref: &str,
        ) -> Result<(), AppError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(format!("{grant_id}:{delegate_ref}"));
            if self.fail {
                return Err(AppError::Internal("revoke failed".into()));
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn refresh_reject_and_revoke_retires_grant_and_delegate_before_failing() {
        let db = RecordingRevoker::default();
        let err = apply_refresh_decision(
            &db,
            "grant-1",
            "delegate-1",
            RefreshDelegateDecision::RejectAndRevoke,
        )
        .await
        .expect_err("a definitive miss must fail the refresh");
        assert_eq!(db.calls(), vec!["grant-1:delegate-1".to_string()]);
        assert_eq!(err.error, "invalid_grant");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn refresh_unavailable_holds_without_revoking_and_returns_503() {
        let db = RecordingRevoker::default();
        let err = apply_refresh_decision(
            &db,
            "grant-1",
            "delegate-1",
            RefreshDelegateDecision::Unavailable,
        )
        .await
        .expect_err("an RPC blip must not mint");
        assert!(db.calls().is_empty(), "an RPC blip must not revoke");
        assert_eq!(err.error, "temporarily_unavailable");
        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn refresh_rotate_reaches_the_mint_without_revoking() {
        let db = RecordingRevoker::default();
        assert!(apply_refresh_decision(
            &db,
            "grant-1",
            "delegate-1",
            RefreshDelegateDecision::Rotate,
        )
        .await
        .is_ok());
        assert!(db.calls().is_empty(), "a rotate must not revoke");
    }

    #[tokio::test]
    async fn refresh_revoke_failure_blocks_the_mint() {
        let db = RecordingRevoker {
            fail: true,
            ..Default::default()
        };
        let err = apply_refresh_decision(
            &db,
            "grant-1",
            "delegate-1",
            RefreshDelegateDecision::RejectAndRevoke,
        )
        .await
        .expect_err("a failed revoke must fail the refresh");
        assert_eq!(db.calls(), vec!["grant-1:delegate-1".to_string()]);
        // `From<AppError>` maps a DB failure to server_error; the point is
        // that no token is minted when the revoke did not land.
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn refresh_delegate_public_key_must_be_32_byte_hex() {
        assert!(decode_refresh_delegate_public_key("zz").is_none());
        assert!(decode_refresh_delegate_public_key("").is_none());
        assert!(decode_refresh_delegate_public_key(&"ab".repeat(31)).is_none());
        assert!(decode_refresh_delegate_public_key(&"ab".repeat(33)).is_none());
        let key = decode_refresh_delegate_public_key(&"ab".repeat(32)).expect("32 bytes");
        assert_eq!(key.len(), 32);
        assert_eq!(
            decode_refresh_delegate_public_key(&"AB".repeat(32)).expect("uppercase hex"),
            key
        );
    }

    // ── WALM-605: a Sui 429 must not read as "unregistered" ──────────
    //
    // These cover the decision, not the handler: `session_complete` needs a
    // Postgres pool, a Sui client and a wallet verifier, and this crate has no
    // mock harness for them.

    #[test]
    fn rpc_error_during_verify_is_retryable_and_spares_the_session() {
        // The exact WALM-605 report: Sui GetObject answers 429, which
        // `map_get_object_status` classifies as RpcError.
        let outcome = classify_delegate_verify(Err(OnchainVerifyError::RpcError(
            "gRPC GetObject failed: 429 Too Many Requests".into(),
        )));
        assert!(matches!(outcome, DelegateVerifyOutcome::Retryable { .. }));
        assert!(
            !outcome.consumes_session(),
            "a 429 must leave the one-time session pending so the user can retry"
        );
    }

    // ── WALM-605: `/account` decides the duplicate-key skip, not the SPA ──
    //
    // The consent UI signs through the sponsor proxy, and `sponsor::mask_upstream`
    // replaces any upstream 5xx with a bare 502 that never echoes the Move
    // abort. So `EDelegateKeyAlreadyExists` is invisible to the client, and the
    // "is a second add_delegate_key needed" question has to be answered here.

    #[test]
    fn a_key_already_on_the_account_tells_the_ui_to_resume_at_complete() {
        // The WALM-605 journey: the transaction landed, then verify hit a 429.
        let outcome = classify_pending_key_preflight(Ok("0xowner".into()));
        assert!(matches!(outcome, PendingKeyPreflight::Resume));
    }

    #[test]
    fn a_key_definitively_absent_tells_the_ui_to_register() {
        for err in [
            OnchainVerifyError::KeyNotFound("not in delegate_keys".into()),
            OnchainVerifyError::NotFound("no such object".into()),
            OnchainVerifyError::WrongObjectType("not a MemWalAccount".into()),
        ] {
            let label = err.to_string();
            assert!(
                matches!(
                    classify_pending_key_preflight(Err(err)),
                    PendingKeyPreflight::Register
                ),
                "{label} is a definitive no, so the first-time path is correct"
            );
        }
    }

    #[test]
    fn an_unreachable_chain_refuses_to_guess_the_preflight() {
        // Guessing "register" dead-ends on a sponsor 502 the SPA cannot read;
        // guessing "skip" burns the session as Unregistered. The preflight
        // claims nothing, so refusing costs the user only a retry.
        for err in [
            OnchainVerifyError::RpcError("gRPC GetObject failed: 429 Too Many Requests".into()),
            OnchainVerifyError::ScanCapExceeded("registry scan cap".into()),
        ] {
            let label = err.to_string();
            assert!(
                matches!(
                    classify_pending_key_preflight(Err(err)),
                    PendingKeyPreflight::Unknown { .. }
                ),
                "{label} is not evidence either way"
            );
        }
    }

    #[test]
    fn the_preflight_and_complete_agree_on_what_is_definitive() {
        // Both read `OnchainVerifyError::is_unavailable()`. If one ever stops,
        // a 429 becomes "unregistered" on that path again (WALM-429).
        // Built twice rather than cloned: `OnchainVerifyError` is not `Clone`,
        // and both classifiers take the value.
        let cases: [fn() -> OnchainVerifyError; 6] = [
            || OnchainVerifyError::RpcError("429".into()),
            || OnchainVerifyError::ScanCapExceeded("cap".into()),
            || OnchainVerifyError::KeyNotFound("absent".into()),
            || OnchainVerifyError::NotFound("missing".into()),
            || OnchainVerifyError::AccountDeactivated("dead".into()),
            || OnchainVerifyError::WrongObjectType("foreign".into()),
        ];
        for build in cases {
            let label = build().to_string();
            let complete_is_definitive = classify_delegate_verify(Err(build())).consumes_session();
            let preflight_is_definitive = !matches!(
                classify_pending_key_preflight(Err(build())),
                PendingKeyPreflight::Unknown { .. }
            );
            assert_eq!(
                complete_is_definitive, preflight_is_definitive,
                "{label} must be definitive on both paths or neither"
            );
        }
    }

    #[test]
    fn scan_cap_exceeded_during_verify_is_retryable() {
        let outcome = classify_delegate_verify(Err(OnchainVerifyError::ScanCapExceeded(
            "registry scan cap".into(),
        )));
        assert!(matches!(outcome, DelegateVerifyOutcome::Retryable { .. }));
        assert!(!outcome.consumes_session());
    }

    #[test]
    fn key_not_found_during_verify_is_unregistered_and_consumes_the_session() {
        let outcome = classify_delegate_verify(Err(OnchainVerifyError::KeyNotFound(
            "not in registry".into(),
        )));
        assert!(matches!(
            outcome,
            DelegateVerifyOutcome::Unregistered { .. }
        ));
        assert!(
            outcome.consumes_session(),
            "a genuine unregistered key is definitive and still burns the session"
        );
    }

    #[test]
    fn definitive_verify_failures_are_unregistered_and_consume_the_session() {
        for err in [
            OnchainVerifyError::NotFound("no such object".into()),
            OnchainVerifyError::AccountDeactivated("deactivated".into()),
            OnchainVerifyError::WrongObjectType("not a MemWalAccount".into()),
        ] {
            let outcome = classify_delegate_verify(Err(err));
            assert!(
                matches!(outcome, DelegateVerifyOutcome::Unregistered { .. }),
                "{outcome:?}"
            );
            assert!(outcome.consumes_session(), "{outcome:?}");
        }
    }

    #[test]
    fn verified_key_consumes_the_session() {
        let outcome = classify_delegate_verify(Ok("0xowner".into()));
        match &outcome {
            DelegateVerifyOutcome::Verified { owner } => assert_eq!(owner, "0xowner"),
            other => panic!("expected Verified, got {other:?}"),
        }
        assert!(outcome.consumes_session());
    }

    #[test]
    fn classification_tracks_is_unavailable_exactly() {
        // Guard against the OAuth callback and signed HTTP auth drifting apart
        // again: `Retryable` must be exactly `OnchainVerifyError::is_unavailable`.
        for err in [
            OnchainVerifyError::RpcError("429".into()),
            OnchainVerifyError::ScanCapExceeded("cap".into()),
            OnchainVerifyError::NotFound("missing".into()),
            OnchainVerifyError::KeyNotFound("gone".into()),
            OnchainVerifyError::AccountDeactivated("dead".into()),
            OnchainVerifyError::WrongObjectType("type".into()),
        ] {
            let unavailable = err.is_unavailable();
            let outcome = classify_delegate_verify(Err(err));
            assert_eq!(
                matches!(outcome, DelegateVerifyOutcome::Retryable { .. }),
                unavailable,
                "{outcome:?}"
            );
            assert_eq!(outcome.consumes_session(), !unavailable, "{outcome:?}");
        }
    }

    #[tokio::test]
    async fn retryable_verify_maps_to_a_503_the_client_can_retry() {
        // The pre-fix behaviour was a 400 invalid_request, which the consent UI
        // renders as a dead end. It must now be a retryable 503 with backoff.
        let response = OAuthError::temporarily_unavailable("sui is throttling").into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some(OAUTH_UPSTREAM_RETRY_AFTER_SECS.to_string().as_str())
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "temporarily_unavailable");
    }

    #[test]
    fn unregistered_verify_stays_a_definitive_400() {
        let response = OAuthError::invalid_request("delegate key is not registered on-chain: x")
            .into_response();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        assert!(response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none());
    }

    #[tokio::test]
    async fn delegate_reuse_rejects_proof_from_another_authorization_session() {
        let key = Ed25519PrivateKey::new([19; 32]);
        let account_id = format!("0x{}", "11".repeat(32));
        let owner = key.public_key().derive_address().to_string();
        let victim_session = "mws_victim-session";
        let attacker_session = "mws_attacker-session";
        let signed_message = oauth_owner_proof_message(victim_session, &account_id, &owner);
        let signature: UserSignature = key
            .sign_personal_message(&PersonalMessage(Cow::Borrowed(signed_message.as_bytes())))
            .unwrap();

        let attacker_message = oauth_owner_proof_message(attacker_session, &account_id, &owner);
        assert!(NativeWalletSignatureVerifier
            .verify_personal(&owner, attacker_message.as_bytes(), &signature.to_base64())
            .await
            .is_err());
        NativeWalletSignatureVerifier
            .verify_personal(&owner, signed_message.as_bytes(), &signature.to_base64())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fetch_oauth_code_reads_without_consuming() {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://memwal:memwal_secret@localhost:5432/memwal".into());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../../migrations/011_mcp_oauth.sql"))
            .execute(&pool)
            .await
            .unwrap();
        let db = crate::storage::db::VectorDb::from_pool(pool);

        let client_id = format!("mcpc_{}", uuid::Uuid::new_v4().simple());
        let code_sha256 = format!("{:064x}", uuid::Uuid::new_v4().as_u128());
        db.insert_oauth_code(&super::OAuthCodeRow {
            code_sha256: code_sha256.clone(),
            client_id: client_id.clone(),
            redirect_uri: "https://claude.ai/api/mcp/auth_callback".into(),
            scope: "memwal".into(),
            resource: "https://relayer.example/mcp".into(),
            code_challenge: "challenge".into(),
            code_challenge_method: "S256".into(),
            delegate_ref: "mwd_ref".into(),
            account_id: format!("0x{}", "11".repeat(32)),
            owner_address: format!("0x{}", "22".repeat(32)),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        })
        .await
        .unwrap();

        let read = db
            .fetch_oauth_code(&client_id, &code_sha256)
            .await
            .unwrap()
            .expect("fetch returns the code");
        assert_eq!(read.code_sha256, code_sha256);
        let again = db.fetch_oauth_code(&client_id, &code_sha256).await.unwrap();
        assert!(again.is_some(), "fetch must leave the code redeemable");

        let consumed = db
            .consume_oauth_code(&client_id, &code_sha256)
            .await
            .unwrap()
            .expect("consume returns the code");
        assert_eq!(consumed.code_sha256, code_sha256);
        assert!(
            db.consume_oauth_code(&client_id, &code_sha256)
                .await
                .unwrap()
                .is_none(),
            "the code must stay single-use"
        );
    }
}

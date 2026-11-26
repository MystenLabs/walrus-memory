use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use super::{
    crypto,
    email::EmailAddress,
    owner_session::{self, MarketingConsentOwner},
    store,
    verification::{self, ConfirmOutcome, ConfirmRequest},
    SourceSurface,
};
use crate::{
    rate_limit,
    security_delete_auth::same_owner,
    services::email::OutboundEmail,
    types::{AppError, AppState},
};

pub(crate) const OWNER_PATH: &str = "/v1/owners/{owner}/marketing-consent/verification";
pub(crate) const CONFIRM_PATH: &str = "/v1/owners/{owner}/marketing-consent/verification/confirm";

#[derive(Deserialize)]
struct RequestVerification {
    email: String,
    policy_version: String,
    source_surface: SourceSurface,
}

pub(crate) fn owner_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    if state.config.marketing_consent.is_none() {
        return Router::new();
    }
    let auth = Router::new()
        .route(
            owner_session::CHALLENGE_PATH,
            post(owner_session::challenge).layer(DefaultBodyLimit::max(1024)),
        )
        .route(
            owner_session::VERIFY_PATH,
            post(owner_session::verify).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .layer(middleware::from_fn_with_state(state.clone(), limit_auth));
    let verification = Router::new()
        .route(OWNER_PATH, post(request))
        .route(CONFIRM_PATH, post(confirm))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn_with_state(state, require_delivery));
    auth.merge(verification)
        .layer(middleware::from_fn(no_store))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn require_delivery(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if state.email_sender.is_none() {
        return unavailable("email_delivery_disabled");
    }
    next.run(request).await
}

async fn limit_auth(State(state): State<Arc<AppState>>, request: Request, next: Next) -> Response {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|peer| {
            crate::client_ip::canonical_client_ip(
                request.headers(),
                peer.0,
                state.config.trusted_proxy_hops,
            )
            .to_string()
        })
        .unwrap_or_else(|| "unknown".into());
    match rate_limit::check_owner_session_rate_limit(&state.redis, &ip).await {
        Ok(0) => next.run(request).await,
        Ok(retry_after) => limited(retry_after),
        Err(_) => unavailable("owner_session_unavailable"),
    }
}

pub(super) fn unavailable(error: &'static str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": error})),
    )
        .into_response()
}

fn limited(seconds: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, seconds.to_string())],
        Json(json!({"error": "rate_limited"})),
    )
        .into_response()
}

fn owned_path(raw: &str, authenticated: &str) -> Result<String, AppError> {
    let owner = store::owner_address(raw)?;
    if !same_owner(Some(&owner), authenticated) {
        return Err(AppError::Forbidden("owner_mismatch".into()));
    }
    Ok(owner)
}

async fn request(
    State(state): State<Arc<AppState>>,
    MarketingConsentOwner(authenticated): MarketingConsentOwner,
    Path(owner): Path<String>,
    body: Result<Json<RequestVerification>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, AppError> {
    let owner = owned_path(&owner, &authenticated)?;
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => return Ok(invalid_body(error)),
    };
    let email = EmailAddress::parse(&body.email)
        .ok_or_else(|| AppError::BadRequest("invalid_email".into()))?;
    if !store::policy_version_valid(&body.policy_version) {
        return Err(AppError::BadRequest("invalid_policy_version".into()));
    }
    let (Some(config), Some(sender)) = (&state.config.marketing_consent, &state.email_sender)
    else {
        return Ok(unavailable("email_delivery_disabled"));
    };
    let account = crate::storage::sui::load_owner_account_onchain(
        &state.http_client,
        &state.config.sui_rpc_url,
        state.sui_grpc_client.as_ref(),
        &state.config.registry_id,
        &state.config.package_id,
        &owner,
    )
    .await;
    let account = match account {
        Ok(Some(account)) if account.active && !account.admin_quarantined => account,
        Ok(_) => return Err(AppError::Forbidden("inactive_owner_account".into())),
        Err(_) => return Ok(unavailable("account_state_unavailable")),
    };
    let Some(version) = account
        .object_version
        .and_then(|version| i64::try_from(version).ok())
    else {
        return Ok(unavailable("account_state_unavailable"));
    };
    let revision = store::AccountRevision {
        id: account.account_id,
        version,
    };
    let address_hash = crypto::address_hash(&config.hash_key, &email);
    match rate_limit::check_verification_send_limits(
        &state.redis,
        &config.send_limits,
        &owner,
        &address_hash,
    )
    .await
    {
        Ok(0) => {}
        Ok(retry_after) => return Ok(limited(retry_after)),
        Err(_) => return Ok(unavailable("rate_limiter_unavailable")),
    }
    let (pending, code) = verification::issue(
        state.db.pool(),
        config,
        &owner,
        &email,
        &body.policy_version,
        body.source_surface,
        &revision,
    )
    .await?;
    let message = OutboundEmail::verification(owner, email, &code);
    if sender.send(message).await.is_err() {
        return Ok(unavailable("email_delivery_failed"));
    }
    Ok((StatusCode::ACCEPTED, Json(pending)).into_response())
}

async fn confirm(
    State(state): State<Arc<AppState>>,
    MarketingConsentOwner(authenticated): MarketingConsentOwner,
    Path(owner): Path<String>,
    body: Result<Json<ConfirmRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Response, AppError> {
    let owner = owned_path(&owner, &authenticated)?;
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => return Ok(invalid_body(error)),
    };
    let Some(config) = state.config.marketing_consent.as_ref() else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    match verification::confirm(state.db.pool(), config, &owner, &body.code).await? {
        ConfirmOutcome::Verified => Ok(Json(json!({"status": "opted_in"})).into_response()),
        ConfirmOutcome::InvalidCode { attempts_left } => Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_code", "attempts_left": attempts_left})),
        )
            .into_response()),
    }
}

fn invalid_body(error: axum::extract::rejection::JsonRejection) -> Response {
    let status = match error.status() {
        StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
        status => status,
    };
    (status, Json(json!({"error": "invalid_request"}))).into_response()
}

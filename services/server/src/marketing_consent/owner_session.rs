use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{crypto, store};
use crate::{
    security_delete_auth::{mint_token, verify_token, NonceStore, RedisNonceStore},
    types::{AppError, AppState},
};

pub(crate) const CHALLENGE_PATH: &str = "/v1/owner-sessions/marketing-consent/challenge";
pub(crate) const VERIFY_PATH: &str = "/v1/owner-sessions/marketing-consent/verify";
const CHALLENGE_TTL_SECS: u64 = 300;
const TOKEN_TTL_SECS: u64 = 900;
const NONCE_NAMESPACE: &str = "owner_session:marketing_consent";

#[derive(Deserialize)]
pub(super) struct ChallengeRequest {
    address: String,
}

#[derive(Serialize)]
pub(super) struct ChallengeResponse {
    challenge_id: String,
    challenge: String,
    expires_in_secs: u64,
}

#[derive(Deserialize)]
pub(super) struct VerifyRequest {
    challenge_id: Uuid,
    address: String,
    signature: String,
}

#[derive(Serialize)]
pub(super) struct VerifyResponse {
    token: String,
    expires_in_secs: u64,
}

#[derive(Serialize, Deserialize)]
struct ChallengeRecord {
    owner: String,
    expires: i64,
}

fn challenge_message(network: &str, record: &ChallengeRecord, id: Uuid) -> String {
    format!(
        "Walrus Memory owner session\nscope: marketing_consent\nnetwork: {network}\naddress: {}\nnonce: {id}\nexpires: {}",
        record.owner, record.expires,
    )
}

fn session_key(state: &AppState) -> Option<Zeroizing<String>> {
    let config = state.config.marketing_consent.as_ref()?;
    // Scope and network are part of the key derivation, so another bearer
    // extractor cannot verify this token even if it uses the same token format.
    Some(Zeroizing::new(crypto::keyed_hash(
        &config.hash_key,
        b"memwal/owner_session/marketing_consent/v1:",
        &[state.config.sui_network.as_bytes()],
    )))
}

fn unavailable() -> Response {
    super::routes::unavailable("owner_session_unavailable")
}

pub(super) async fn challenge(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, Response> {
    let owner = store::owner_address(&body.address).map_err(IntoResponse::into_response)?;
    let id = Uuid::new_v4();
    let record = ChallengeRecord {
        owner,
        expires: Utc::now().timestamp() + CHALLENGE_TTL_SECS as i64,
    };
    let store = RedisNonceStore::namespaced(state.redis.clone(), NONCE_NAMESPACE);
    store
        .issue(
            &id.to_string(),
            &serde_json::to_string(&record).expect("fixed owner challenge record serializes"),
            CHALLENGE_TTL_SECS,
        )
        .await
        .map_err(|_| unavailable())?;
    Ok(Json(ChallengeResponse {
        challenge_id: id.to_string(),
        challenge: challenge_message(&state.config.sui_network, &record, id),
        expires_in_secs: CHALLENGE_TTL_SECS,
    }))
}

pub(super) async fn verify(
    State(state): State<Arc<AppState>>,
    Json(body): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, Response> {
    let owner = store::owner_address(&body.address).map_err(IntoResponse::into_response)?;
    let store = RedisNonceStore::namespaced(state.redis.clone(), NONCE_NAMESPACE);
    let raw = store
        .take(&body.challenge_id.to_string())
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(|| AppError::Unauthorized("invalid_challenge".into()).into_response())?;
    let record: ChallengeRecord = serde_json::from_str(&raw).map_err(|_| unavailable())?;
    if record.owner != owner || record.expires <= Utc::now().timestamp() {
        return Err(AppError::Unauthorized("invalid_challenge".into()).into_response());
    }
    let message = challenge_message(&state.config.sui_network, &record, body.challenge_id);
    state
        .security_delete_wallet_verifier
        .verify_personal(&owner, message.as_bytes(), &body.signature)
        .await
        .map_err(|_| AppError::Unauthorized("invalid_signature".into()).into_response())?;
    let key = session_key(&state).ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;
    Ok(Json(VerifyResponse {
        token: mint_token(
            key.as_bytes(),
            &owner,
            TOKEN_TTL_SECS,
            Utc::now().timestamp(),
        ),
        expires_in_secs: TOKEN_TTL_SECS,
    }))
}

/// Owner credential for WALM-901 and the email verification routes.
pub(crate) struct MarketingConsentOwner(pub String);

impl<S> FromRequestParts<S> for MarketingConsentOwner
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = Arc::<AppState>::from_ref(state);
        let invalid = || AppError::Unauthorized("invalid_owner_session".into());
        let key = session_key(&state).ok_or_else(invalid)?;
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(invalid)?;
        verify_token(key.as_bytes(), token, Utc::now().timestamp())
            .map(Self)
            .map_err(|_| invalid())
    }
}

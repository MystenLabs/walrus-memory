use std::borrow::Cow;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::{header, request::Parts};
use axum::Json;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sui_crypto::{simple::SimpleVerifier, SuiVerifier};
use sui_sdk_types::{Address, PersonalMessage, Transaction, UserSignature};
use uuid::Uuid;

use crate::security_delete_error::{SdCode, SdError, SdJson};
use crate::types::{AppError, AppState};

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
struct TokenClaims {
    a: String,
    e: i64,
}

pub fn mint_token(secret: &[u8], address: &str, ttl_secs: u64, now_unix: i64) -> String {
    let payload = serde_json::to_vec(&TokenClaims {
        a: address.to_owned(),
        e: now_unix.saturating_add(ttl_secs as i64),
    })
    .expect("fixed token claims serialize");
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{payload}.{signature}")
}

pub fn verify_token(secret: &[u8], token: &str, now_unix: i64) -> Result<String, SdError> {
    let (payload, signature) = token.split_once('.').ok_or_else(token_error)?;
    if signature.contains('.') {
        return Err(token_error());
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| token_error())?;
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| token_error())?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature).map_err(|_| token_error())?;
    let claims: TokenClaims =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).map_err(|_| token_error())?)
            .map_err(|_| token_error())?;
    if claims.e <= now_unix {
        return Err(token_error());
    }
    canonical_sui_address(&claims.a).map_err(|_| token_error())
}

fn token_error() -> SdError {
    SdError::new(
        SdCode::AuthTokenExpired,
        "Authentication token is invalid or expired",
    )
}

pub fn canonical_sui_address(raw: &str) -> Result<String, SdError> {
    raw.parse::<Address>()
        .map(|address| address.to_string())
        .map_err(|_| SdError::new(SdCode::InvalidRequest, "Invalid request"))
}

/// Compare an owner as returned by an RPC against an owner we already hold in canonical
/// form (a token subject, or a `delete_blobs_tracking` row — the insert trigger canonicalizes).
/// The RPC side is canonicalized here: the two sides are independently sourced, and the same
/// address has many valid text forms (short-hand, mixed case). A raw string compare on a
/// non-canonical RPC form reads as "not the owner", which on the eviction paths is an
/// irreversible terminal state. An unparseable owner is never a match.
pub fn same_owner(raw: Option<&str>, canonical_owner: &str) -> bool {
    raw.and_then(|value| canonical_sui_address(value).ok())
        .is_some_and(|value| value == canonical_owner)
}

pub fn challenge_message(address: &str, nonce: &str, expires_unix: i64) -> String {
    format!(
        "MemWal security deletion auth\naddress: {address}\nnonce: {nonce}\nexpires: {expires_unix}"
    )
}

#[async_trait]
pub trait WalletSignatureVerifier: Send + Sync {
    async fn verify_personal(
        &self,
        address: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> Result<(), SdError>;
    async fn verify_transaction(
        &self,
        address: &str,
        tx_bytes: &[u8],
        signature_b64: &str,
    ) -> Result<Vec<u8>, SdError>;
}

/// Native verifier for the three simple Sui signature schemes. Task 6 swaps
/// this for the composite verifier that also owns the live zkLogin JWK cache.
pub struct NativeWalletSignatureVerifier;

impl NativeWalletSignatureVerifier {
    fn signature(address: &str, signature_b64: &str) -> Result<UserSignature, SdError> {
        let signature = UserSignature::from_base64(signature_b64)
            .map_err(|_| SdError::new(SdCode::AuthInvalidSignature, "Invalid signature"))?;
        let expected = canonical_sui_address(address)
            .map_err(|_| SdError::new(SdCode::AuthInvalidSignature, "Invalid signature"))?;
        if !signature
            .derive_addresses()
            .any(|derived| derived.to_string() == expected)
        {
            return Err(SdError::new(
                SdCode::AuthInvalidSignature,
                "Invalid signature",
            ));
        }
        Ok(signature)
    }
}

#[async_trait]
impl WalletSignatureVerifier for NativeWalletSignatureVerifier {
    async fn verify_personal(
        &self,
        address: &str,
        message: &[u8],
        signature_b64: &str,
    ) -> Result<(), SdError> {
        let signature = Self::signature(address, signature_b64)?;
        SimpleVerifier
            .verify_personal_message(&PersonalMessage(Cow::Borrowed(message)), &signature)
            .map_err(|_| SdError::new(SdCode::AuthInvalidSignature, "Invalid signature"))
    }

    async fn verify_transaction(
        &self,
        address: &str,
        tx_bytes: &[u8],
        signature_b64: &str,
    ) -> Result<Vec<u8>, SdError> {
        let signature = Self::signature(address, signature_b64)
            .map_err(|_| SdError::new(SdCode::InvalidSignature, "Invalid signature"))?;
        let transaction: Transaction = bcs::from_bytes(tx_bytes)
            .map_err(|_| SdError::new(SdCode::InvalidSignature, "Invalid signature"))?;
        SimpleVerifier
            .verify_transaction(&transaction, &signature)
            .map_err(|_| SdError::new(SdCode::InvalidSignature, "Invalid signature"))?;
        STANDARD
            .decode(signature_b64)
            .map_err(|_| SdError::new(SdCode::InvalidSignature, "Invalid signature"))
    }
}

#[async_trait]
pub trait NonceStore: Send + Sync {
    async fn issue(&self, id: &str, record_json: &str, ttl_secs: u64) -> Result<(), SdError>;
    async fn take(&self, id: &str) -> Result<Option<String>, SdError>;
}

pub struct RedisNonceStore {
    connection: ConnectionManager,
    prefix: &'static str,
}

impl RedisNonceStore {
    pub fn new(connection: ConnectionManager) -> Self {
        Self {
            connection,
            prefix: "sd_nonce",
        }
    }

    pub fn namespaced(connection: ConnectionManager, prefix: &'static str) -> Self {
        Self { connection, prefix }
    }
}

#[async_trait]
impl NonceStore for RedisNonceStore {
    async fn issue(&self, id: &str, record_json: &str, ttl_secs: u64) -> Result<(), SdError> {
        let mut connection = self.connection.clone();
        let result: Option<String> = redis::cmd("SET")
            .arg(format!("{}:{id}", self.prefix))
            .arg(record_json)
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut connection)
            .await
            .map_err(|error| {
                SdError::internal(AppError::Internal(format!("nonce issue: {error}")))
            })?;
        if result.is_some() {
            Ok(())
        } else {
            Err(SdError::internal(AppError::Internal(
                "nonce identifier collision".into(),
            )))
        }
    }

    async fn take(&self, id: &str) -> Result<Option<String>, SdError> {
        let mut connection = self.connection.clone();
        redis::cmd("GETDEL")
            .arg(format!("{}:{id}", self.prefix))
            .query_async(&mut connection)
            .await
            .map_err(|error| SdError::internal(AppError::Internal(format!("nonce take: {error}"))))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeRequest {
    pub address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub challenge: String,
    pub expires_in_secs: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub challenge_id: String,
    pub address: String,
    pub signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub token: String,
    pub expires_in_secs: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeRecord {
    canonical_address: String,
    message: String,
    expires: i64,
}

pub async fn challenge(
    State(state): State<Arc<AppState>>,
    SdJson(request): SdJson<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, SdError> {
    let address = canonical_sui_address(&request.address)?;
    let challenge_id = Uuid::new_v4().to_string();
    let expires_in_secs = 300;
    let expires = chrono::Utc::now().timestamp() + expires_in_secs as i64;
    let message = challenge_message(&address, &challenge_id, expires);
    let record = serde_json::to_string(&ChallengeRecord {
        canonical_address: address,
        message: message.clone(),
        expires,
    })
    .map_err(|error| SdError::internal(AppError::Internal(error.to_string())))?;
    state
        .security_delete_nonce_store
        .issue(&challenge_id, &record, expires_in_secs)
        .await?;
    Ok(Json(ChallengeResponse {
        challenge_id,
        challenge: message,
        expires_in_secs,
    }))
}

pub async fn verify(
    State(state): State<Arc<AppState>>,
    SdJson(request): SdJson<VerifyRequest>,
) -> Result<Json<VerifyResponse>, SdError> {
    Uuid::parse_str(&request.challenge_id)
        .map_err(|_| SdError::new(SdCode::InvalidRequest, "Invalid request"))?;
    let address = canonical_sui_address(&request.address)?;
    let raw = state
        .security_delete_nonce_store
        .take(&request.challenge_id)
        .await?
        .ok_or_else(|| {
            SdError::new(
                SdCode::AuthChallengeExpired,
                "Authentication challenge is expired",
            )
        })?;
    let record: ChallengeRecord = serde_json::from_str(&raw)
        .map_err(|error| SdError::internal(AppError::Internal(error.to_string())))?;
    if record.expires < chrono::Utc::now().timestamp() || record.canonical_address != address {
        return Err(SdError::new(
            SdCode::AuthChallengeExpired,
            "Authentication challenge is expired",
        ));
    }
    state
        .security_delete_wallet_verifier
        .verify_personal(&address, record.message.as_bytes(), &request.signature)
        .await?;
    let ttl = state.config.deletion_token_ttl_secs;
    let secret = state
        .config
        .deletion_token_secret
        .as_deref()
        .ok_or_else(|| SdError::new(SdCode::FeatureDisabled, "Feature disabled"))?;
    Ok(Json(VerifyResponse {
        token: mint_token(
            secret.as_bytes(),
            &address,
            ttl,
            chrono::Utc::now().timestamp(),
        ),
        expires_in_secs: ttl,
    }))
}

pub struct SdOwner(pub String);

impl<S> FromRequestParts<S> for SdOwner
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = SdError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = Arc::<AppState>::from_ref(state);
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(token_error)?;
        let secret = state
            .config
            .deletion_token_secret
            .as_deref()
            .ok_or_else(token_error)?;
        verify_token(secret.as_bytes(), token, chrono::Utc::now().timestamp()).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sui_crypto::SuiSigner;

    #[test]
    fn security_delete_auth_token_roundtrip_and_expiry() {
        let address = canonical_sui_address("0xabc").unwrap();
        let token = mint_token(b"test-secret", &address, 2700, 1_000_000);
        assert_eq!(
            verify_token(b"test-secret", &token, 1_000_100).unwrap(),
            address
        );
        assert!(verify_token(b"test-secret", &token, 1_002_701).is_err());
        assert!(verify_token(b"other", &token, 1_000_000).is_err());
        assert!(verify_token(b"test-secret", &(token + "x"), 1_000_000).is_err());
    }

    #[test]
    fn security_delete_auth_challenge_message_format_is_exact() {
        assert_eq!(
            challenge_message("0xabc", "9f8e...", 1_000_000),
            "MemWal security deletion auth\naddress: 0xabc\nnonce: 9f8e...\nexpires: 1000000"
        );
    }

    #[test]
    fn security_delete_auth_address_is_canonical() {
        assert_eq!(
            canonical_sui_address("0xAbC").unwrap(),
            format!("0x{}abc", "0".repeat(61))
        );
    }

    #[tokio::test]
    async fn security_delete_auth_native_ed25519_personal_message_verifies() {
        let key = sui_crypto::ed25519::Ed25519PrivateKey::new([7; 32]);
        let message = b"security deletion challenge";
        let signature = key
            .sign_personal_message(&PersonalMessage(Cow::Borrowed(message)))
            .unwrap();
        let address = signature.derive_address().to_string();
        NativeWalletSignatureVerifier
            .verify_personal(&address, message, &signature.to_base64())
            .await
            .unwrap();
        assert!(NativeWalletSignatureVerifier
            .verify_personal(&address, b"tampered", &signature.to_base64())
            .await
            .is_err());
    }

    #[tokio::test]
    #[ignore]
    async fn security_delete_auth_redis_nonce_is_single_use() {
        let Ok(url) = std::env::var("TEST_REDIS_URL") else {
            return;
        };
        let client = redis::Client::open(url).unwrap();
        let connection = redis::aio::ConnectionManager::new(client).await.unwrap();
        let store = RedisNonceStore::new(connection);
        let id = Uuid::new_v4().to_string();
        store.issue(&id, r#"{"ok":true}"#, 30).await.unwrap();
        assert_eq!(
            store.take(&id).await.unwrap().as_deref(),
            Some(r#"{"ok":true}"#)
        );
        assert_eq!(store.take(&id).await.unwrap(), None);
    }
}

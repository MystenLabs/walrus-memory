use std::time::Instant;

use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use super::{crypto, email::EmailAddress, store, MarketingConsentConfig};
use crate::{oauth::constant_time_eq, types::AppError};

#[derive(FromRow)]
struct CodeRow {
    address_hash: String,
    code_hash: String,
    expires_at: DateTime<Utc>,
    attempts: i16,
    consumed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct PendingVerification {
    pub status: &'static str,
    pub masked_address: String,
    pub expires_in_secs: u64,
    pub resend_after_secs: u64,
}

#[derive(Deserialize)]
pub(super) struct ConfirmRequest {
    pub code: String,
}

pub(super) fn new_code() -> String {
    format!("{:06}", OsRng.gen_range(0..1_000_000u32))
}

pub(super) fn code_hash(
    key: &crypto::SecretKey32,
    owner: &str,
    address_hash: &str,
    code: &str,
) -> String {
    crypto::keyed_hash(
        key,
        b"memwal/marketing_consent/code/v1:",
        &[
            owner.as_bytes(),
            b":",
            address_hash.as_bytes(),
            b":",
            code.as_bytes(),
        ],
    )
}

pub(super) async fn issue(
    pool: &PgPool,
    config: &MarketingConsentConfig,
    owner: &str,
    email: &EmailAddress,
    policy_version: &str,
    surface: super::SourceSurface,
    account: &store::AccountRevision,
) -> Result<(PendingVerification, String), AppError> {
    let owner = store::owner_address(owner)?;
    let mut tx = store::observe(
        "marketing_consent.begin_issue",
        Instant::now(),
        pool.begin().await,
    )?;
    let address_hash = store::set_pending(
        &mut *tx,
        config,
        &owner,
        email,
        policy_version,
        surface,
        Some(account),
    )
    .await?;
    let code = new_code();
    let hash = code_hash(&config.hash_key, &owner, &address_hash, &code);
    let start = Instant::now();
    let result = sqlx::query(
        "INSERT INTO marketing_consent_verification (owner, address_hash, code_hash, expires_at, attempts, consumed_at)
         VALUES ($1, $2, $3, now() + interval '15 minutes', 0, NULL)
         ON CONFLICT (owner) DO UPDATE SET address_hash = EXCLUDED.address_hash,
             code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at,
             attempts = 0, consumed_at = NULL, sent_at = now()")
        .bind(&owner).bind(&address_hash).bind(&hash)
        .execute(&mut *tx).await;
    store::observe("marketing_consent.issue_code", start, result)?;
    store::observe(
        "marketing_consent.commit_issue",
        Instant::now(),
        tx.commit().await,
    )?;
    Ok((
        PendingVerification {
            status: "pending_verification",
            masked_address: email.masked(),
            expires_in_secs: 900,
            resend_after_secs: config.send_limits.resend_secs,
        },
        code,
    ))
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ConfirmOutcome {
    Verified,
    InvalidCode { attempts_left: i16 },
}

pub(super) async fn confirm(
    pool: &PgPool,
    config: &MarketingConsentConfig,
    owner: &str,
    code: &str,
) -> Result<ConfirmOutcome, AppError> {
    if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AppError::BadRequest("invalid_code".into()));
    }
    let owner = store::owner_address(owner)?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|_| AppError::Internal("Marketing consent verification unavailable".into()))?;
    if !store::lock_owner(&mut tx, &owner).await? {
        return Err(AppError::BadRequest("no_pending_code".into()));
    }
    let row = sqlx::query_as::<_, CodeRow>("SELECT address_hash, code_hash, expires_at, attempts, consumed_at FROM marketing_consent_verification WHERE owner = $1 FOR UPDATE")
        .bind(&owner).fetch_optional(&mut *tx).await.map_err(|_| AppError::Internal("Marketing consent verification unavailable".into()))?
        .ok_or(AppError::BadRequest("no_pending_code".into()))?;
    if row.consumed_at.is_some() {
        return Err(AppError::BadRequest("code_used".into()));
    }
    if row.expires_at <= Utc::now() {
        return Err(AppError::BadRequest("code_expired".into()));
    }
    if row.attempts >= 3 {
        return Err(AppError::BadRequest("code_locked".into()));
    }
    let computed = code_hash(&config.hash_key, &owner, &row.address_hash, code);
    if !constant_time_eq(computed.as_bytes(), row.code_hash.as_bytes()) {
        sqlx::query(
            "UPDATE marketing_consent_verification SET attempts = attempts + 1 WHERE owner = $1",
        )
        .bind(&owner)
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::Internal("Marketing consent verification unavailable".into()))?;
        tx.commit()
            .await
            .map_err(|_| AppError::Internal("Marketing consent verification unavailable".into()))?;
        return Ok(ConfirmOutcome::InvalidCode {
            attempts_left: 2 - row.attempts,
        });
    }
    sqlx::query("UPDATE marketing_consent_verification SET consumed_at = now() WHERE owner = $1")
        .bind(&owner)
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::Internal("Marketing consent verification unavailable".into()))?;
    if !store::mark_verified(&mut tx, &owner, &row.address_hash).await? {
        return Err(AppError::BadRequest("no_pending_code".into()));
    }
    tx.commit()
        .await
        .map_err(|_| AppError::Internal("Marketing consent verification unavailable".into()))?;
    Ok(ConfirmOutcome::Verified)
}

#[cfg(test)]
mod tests;

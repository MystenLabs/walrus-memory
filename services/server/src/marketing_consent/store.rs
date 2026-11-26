use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{Executor, FromRow, PgPool, Postgres, Transaction};
use std::time::Instant;

use super::{
    crypto, email::EmailAddress, ConsentStatus, MarketingConsentConfig, SourceSurface,
    WithdrawalReason,
};
use crate::{
    observability::observe_db, security_delete_auth::canonical_sui_address, types::AppError,
};

type Result<T> = std::result::Result<T, AppError>;

#[derive(FromRow, Serialize)]
struct ConsentRow {
    owner: String,
    status: ConsentStatus,
    address_ciphertext: Option<String>,
    address_hash: Option<String>,
    verified_at: Option<DateTime<Utc>>,
    consented_at: Option<DateTime<Utc>>,
    policy_version: Option<String>,
    source_surface: Option<SourceSurface>,
    withdrawn_at: Option<DateTime<Utc>>,
    withdrawal_reason: Option<WithdrawalReason>,
    prompt_dismissed_at: Option<DateTime<Utc>>,
    sendgrid_synced_at: Option<DateTime<Utc>>,
    sendgrid_contact_id: Option<String>,
    account_id: Option<String>,
    account_version: Option<i64>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub(super) struct ConsentExport {
    #[serde(flatten)]
    row: ConsentRow,
    address: Option<EmailAddress>,
}

// The dashboard consumes this masked view when its routes are mounted.
#[allow(dead_code)]
#[derive(Serialize)]
pub(super) struct ConsentView {
    pub status: ConsentStatus,
    pub masked_address: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub consented_at: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub prompt_dismissed_at: Option<DateTime<Utc>>,
}

pub(super) fn owner_address(raw: &str) -> Result<String> {
    canonical_sui_address(raw).map_err(|_| AppError::BadRequest("Invalid owner address".into()))
}

pub(super) fn observe<T>(op: &'static str, start: Instant, result: sqlx::Result<T>) -> Result<T> {
    observe_db(
        op,
        if result.is_ok() { "ok" } else { "error" },
        start.elapsed(),
    );
    result.map_err(|error| {
        // Keep Postgres messages and DETAIL fields out of the application logs.
        let kind = match &error {
            sqlx::Error::Database(error) => error.code().unwrap_or("database".into()).into_owned(),
            sqlx::Error::PoolTimedOut => "pool_timeout".into(),
            sqlx::Error::PoolClosed => "pool_closed".into(),
            sqlx::Error::Io(_) => "io".into(),
            _ => "query".into(),
        };
        AppError::Internal(format!("{op} failed ({kind})"))
    })
}

async fn load(pool: &PgPool, owner: &str, operation: &'static str) -> Result<Option<ConsentRow>> {
    let start = Instant::now();
    observe(
        operation,
        start,
        sqlx::query_as("SELECT * FROM marketing_consent WHERE owner = $1")
            .bind(owner)
            .fetch_optional(pool)
            .await,
    )
}

#[allow(dead_code)]
pub(super) async fn get_state(
    pool: &PgPool,
    config: &MarketingConsentConfig,
    owner: &str,
) -> Result<Option<ConsentView>> {
    let owner = owner_address(owner)?;
    load(pool, &owner, "marketing_consent.get_state")
        .await?
        .map(|row| {
            let masked_address = row
                .address_ciphertext
                .as_deref()
                .map(|ciphertext| {
                    crypto::decrypt(&config.encryption_key, &owner, ciphertext)
                        .map(|address| address.masked())
                })
                .transpose()
                .map_err(|_| AppError::Internal("Marketing consent decryption failed".into()))?;
            Ok(ConsentView {
                status: row.status,
                masked_address,
                verified_at: row.verified_at,
                consented_at: row.consented_at,
                withdrawn_at: row.withdrawn_at,
                prompt_dismissed_at: row.prompt_dismissed_at,
            })
        })
        .transpose()
}

pub(super) async fn export(
    pool: &PgPool,
    config: &MarketingConsentConfig,
    owner: &str,
) -> Result<Option<ConsentExport>> {
    let owner = owner_address(owner)?;
    load(pool, &owner, "marketing_consent.export")
        .await?
        .map(|row| {
            let address = row
                .address_ciphertext
                .as_deref()
                .map(|ciphertext| crypto::decrypt(&config.encryption_key, &owner, ciphertext))
                .transpose()
                .map_err(|_| AppError::Internal("Marketing consent decryption failed".into()))?;
            Ok(ConsentExport { row, address })
        })
        .transpose()
}

pub(super) struct AccountRevision {
    pub id: String,
    pub version: i64,
}

pub(super) fn policy_version_valid(policy_version: &str) -> bool {
    !policy_version.trim().is_empty()
        && policy_version.chars().count() <= 64
        && !policy_version.chars().any(char::is_control)
}

pub(super) async fn set_pending<'e>(
    db: impl Executor<'e, Database = Postgres>,
    config: &MarketingConsentConfig,
    owner: &str,
    email: &EmailAddress,
    policy_version: &str,
    surface: SourceSurface,
    account: Option<&AccountRevision>,
) -> Result<String> {
    let owner = owner_address(owner)?;
    if !policy_version_valid(policy_version) {
        return Err(AppError::BadRequest("Invalid policy version".into()));
    }
    let ciphertext = crypto::encrypt(&config.encryption_key, &owner, email)
        .map_err(|_| AppError::Internal("Marketing consent encryption failed".into()))?;
    let hash = crypto::address_hash(&config.hash_key, email);
    let start = Instant::now();
    let result = observe("marketing_consent.set_pending", start, sqlx::query(
        "INSERT INTO marketing_consent
            (owner, status, address_ciphertext, address_hash, consented_at, policy_version, source_surface,
             account_id, account_version)
         VALUES ($1, 'pending_verification', $2, $3, now(), $4, $5, $6, $7)
         ON CONFLICT (owner) DO UPDATE SET
            status = EXCLUDED.status, address_ciphertext = EXCLUDED.address_ciphertext,
            address_hash = EXCLUDED.address_hash, consented_at = EXCLUDED.consented_at,
            policy_version = EXCLUDED.policy_version, source_surface = EXCLUDED.source_surface,
            account_id = EXCLUDED.account_id, account_version = EXCLUDED.account_version,
            verified_at = NULL, withdrawn_at = NULL, withdrawal_reason = NULL,
            sendgrid_synced_at = NULL, sendgrid_contact_id = NULL, updated_at = now()
         WHERE marketing_consent.account_id IS DISTINCT FROM EXCLUDED.account_id
            OR marketing_consent.account_version <= EXCLUDED.account_version
            OR EXCLUDED.account_version IS NULL")
        .bind(owner).bind(ciphertext).bind(&hash).bind(policy_version).bind(surface)
        .bind(account.map(|account| account.id.as_str())).bind(account.map(|account| account.version))
        .execute(db).await)?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict("stale_account_revision".into()));
    }
    Ok(hash)
}

#[allow(dead_code)]
pub(super) async fn mark_verified(
    tx: &mut Transaction<'_, Postgres>,
    owner: &str,
    expected_address_hash: &str,
) -> Result<bool> {
    let owner = owner_address(owner)?;
    let start = Instant::now();
    let result = sqlx::query(
        "UPDATE marketing_consent SET status = 'opted_in', verified_at = now(), updated_at = now()
         WHERE owner = $1 AND status = 'pending_verification' AND address_hash = $2",
    )
    .bind(owner)
    .bind(expected_address_hash)
    .execute(&mut **tx)
    .await;
    Ok(observe("marketing_consent.mark_verified", start, result)?.rows_affected() > 0)
}

#[allow(dead_code)]
pub(super) async fn withdraw(pool: &PgPool, owner: &str, reason: WithdrawalReason) -> Result<()> {
    let owner = owner_address(owner)?;
    let start = Instant::now();
    observe(
        "marketing_consent.withdraw",
        start,
        sqlx::query(
            "UPDATE marketing_consent SET status = 'withdrawn', address_ciphertext = NULL,
            withdrawn_at = now(), withdrawal_reason = $2, updated_at = now()
         WHERE owner = $1 AND status IN ('pending_verification', 'opted_in')",
        )
        .bind(owner)
        .bind(reason)
        .execute(pool)
        .await,
    )?;
    Ok(())
}

#[allow(dead_code)]
pub(super) async fn mark_prompt_dismissed(pool: &PgPool, owner: &str) -> Result<()> {
    let owner = owner_address(owner)?;
    let start = Instant::now();
    observe("marketing_consent.mark_prompt_dismissed", start, sqlx::query(
        "INSERT INTO marketing_consent (owner, prompt_dismissed_at) VALUES ($1, now())
         ON CONFLICT (owner) DO UPDATE SET prompt_dismissed_at = EXCLUDED.prompt_dismissed_at, updated_at = now()")
        .bind(owner).execute(pool).await)?;
    Ok(())
}

pub(super) async fn erase(pool: &PgPool, owner: &str) -> Result<bool> {
    let owner = owner_address(owner)?;
    let start = Instant::now();
    let result = sqlx::query("DELETE FROM marketing_consent WHERE owner = $1")
        .bind(owner)
        .execute(pool)
        .await;
    Ok(observe("marketing_consent.erase", start, result)?.rows_affected() > 0)
}

pub(super) async fn lock_owner(tx: &mut Transaction<'_, Postgres>, owner: &str) -> Result<bool> {
    let owner = owner_address(owner)?;
    let start = Instant::now();
    let row = sqlx::query_scalar::<_, String>(
        "SELECT owner FROM marketing_consent WHERE owner = $1 FOR UPDATE",
    )
    .bind(owner)
    .fetch_optional(&mut **tx)
    .await;
    Ok(observe("marketing_consent.lock_owner", start, row)?.is_some())
}

pub(super) async fn erase_deactivated(pool: &PgPool, package: &str) -> Result<Vec<String>> {
    let package = owner_address(package)?;
    let start = Instant::now();
    // Account object versions fence opt-ins, including requests concurrent
    // with deactivation. Address-less dismissals have only a database time.
    let result = sqlx::query_scalar(
        "DELETE FROM marketing_consent AS consent
         WHERE EXISTS (
             SELECT 1 FROM account_owner_deactivations AS event
             WHERE event.package_id = $1 AND event.owner = consent.owner
               AND CASE WHEN consent.account_id IS NOT NULL THEN
                   event.account_id = consent.account_id AND event.account_version > consent.account_version
               ELSE
                   COALESCE(consent.consented_at, consent.created_at) <=
                       to_timestamp(event.checkpoint_timestamp_ms / 1000.0)
               END
         ) RETURNING consent.owner")
        .bind(package).fetch_all(pool).await;
    observe("marketing_consent.erase_deactivated", start, result)
}

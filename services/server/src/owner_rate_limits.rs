//! Private operator policy. Identity comes from authenticated owner resolution;
//! overrides never change authentication, endpoint weights, or storage quotas.
use crate::rate_limit::RateLimitConfig;
use crate::security_delete_auth::canonical_sui_address;
use crate::types::{AppError, AppState};
use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct OwnerRateLimit {
    pub requests_per_minute: i64,
    pub requests_per_hour: i64,
    pub delegate_key_per_minute: i64,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct PolicyResponse {
    pub owner: String,
    pub defaults: OwnerRateLimit,
    pub override_policy: Option<OwnerRateLimit>,
    pub effective: OwnerRateLimit,
}

impl OwnerRateLimit {
    pub fn defaults(config: &RateLimitConfig) -> Self {
        Self {
            requests_per_minute: config.max_requests_per_minute,
            requests_per_hour: config.max_requests_per_hour,
            delegate_key_per_minute: config.max_requests_per_delegate_key,
            expires_at: None,
        }
    }

    fn validate(&self, now: DateTime<Utc>) -> Result<(), AppError> {
        if !(1..=1_000_000).contains(&self.requests_per_minute)
            || !(1..=100_000_000).contains(&self.requests_per_hour)
            || !(1..=1_000_000).contains(&self.delegate_key_per_minute)
        {
            return Err(AppError::BadRequest(
                "Limits must be positive integers within the supported range".into(),
            ));
        }
        if self.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(AppError::BadRequest("Expiry must be in the future".into()));
        }
        Ok(())
    }

    pub fn active_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|expiry| expiry > now)
    }
}

fn policy_store_error(_: sqlx::Error) -> AppError {
    AppError::UpstreamUnavailable("Rate limit policy store is unavailable".into())
}

fn owner_address(raw: &str) -> Result<String, AppError> {
    canonical_sui_address(raw).map_err(|_| AppError::BadRequest("Invalid owner address".into()))
}

pub async fn load_policy(
    pool: &sqlx::PgPool,
    owner: &str,
) -> Result<Option<OwnerRateLimit>, sqlx::Error> {
    sqlx::query_as::<_, OwnerRateLimit>("SELECT requests_per_minute, requests_per_hour, delegate_key_per_minute, expires_at FROM owner_rate_limits WHERE owner = $1")
        .bind(owner).fetch_optional(pool).await
}

pub async fn get_policy(
    State(state): State<Arc<AppState>>,
    Path(raw): Path<String>,
) -> Result<Json<PolicyResponse>, AppError> {
    let owner = owner_address(&raw)?;
    let policy = load_policy(state.db.pool(), &owner)
        .await
        .map_err(policy_store_error)?;
    let defaults = OwnerRateLimit::defaults(&state.config.rate_limit);
    let effective = policy
        .as_ref()
        .filter(|p| p.active_at(Utc::now()))
        .unwrap_or(&defaults)
        .clone();
    Ok(Json(PolicyResponse {
        owner,
        defaults,
        override_policy: policy,
        effective,
    }))
}

async fn store_policy(
    pool: &sqlx::PgPool,
    owner: &str,
    policy: &OwnerRateLimit,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO owner_rate_limits(owner, requests_per_minute, requests_per_hour, delegate_key_per_minute, expires_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(owner) DO UPDATE SET requests_per_minute=EXCLUDED.requests_per_minute, requests_per_hour=EXCLUDED.requests_per_hour, delegate_key_per_minute=EXCLUDED.delegate_key_per_minute, expires_at=EXCLUDED.expires_at, updated_at=now()")
        .bind(owner).bind(policy.requests_per_minute).bind(policy.requests_per_hour)
        .bind(policy.delegate_key_per_minute).bind(policy.expires_at).execute(pool).await?;
    Ok(())
}
async fn remove_policy(pool: &sqlx::PgPool, owner: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM owner_rate_limits WHERE owner=$1")
        .bind(owner)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn put_policy(
    State(state): State<Arc<AppState>>,
    Path(raw): Path<String>,
    Json(policy): Json<OwnerRateLimit>,
) -> Result<Json<PolicyResponse>, AppError> {
    let owner = owner_address(&raw)?;
    policy.validate(Utc::now())?;
    store_policy(state.db.pool(), &owner, &policy)
        .await
        .map_err(policy_store_error)?;
    // Return exactly the saved policy, without a second read racing another operator.
    let defaults = OwnerRateLimit::defaults(&state.config.rate_limit);
    Ok(Json(PolicyResponse {
        owner,
        defaults,
        override_policy: Some(policy.clone()),
        effective: policy,
    }))
}

pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    Path(raw): Path<String>,
) -> Result<Json<PolicyResponse>, AppError> {
    let owner = owner_address(&raw)?;
    remove_policy(state.db.pool(), &owner)
        .await
        .map_err(policy_store_error)?;
    let defaults = OwnerRateLimit::defaults(&state.config.rate_limit);
    Ok(Json(PolicyResponse {
        owner,
        defaults: defaults.clone(),
        override_policy: None,
        effective: defaults,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policy_validation_and_expiry() {
        let now = Utc::now();
        let mut policy = OwnerRateLimit::defaults(&RateLimitConfig::default());
        assert!(policy.validate(now).is_ok());
        policy.requests_per_minute = 0;
        assert!(policy.validate(now).is_err());
        policy.requests_per_minute = 1_000_001;
        assert!(policy.validate(now).is_err());
        policy.requests_per_minute = 60;
        policy.requests_per_hour = -1;
        assert!(policy.validate(now).is_err());
        policy.requests_per_hour = 500;
        policy.delegate_key_per_minute = 0;
        assert!(policy.validate(now).is_err());
        policy.delegate_key_per_minute = 30;
        policy.expires_at = Some(now);
        assert!(!policy.active_at(now));
        assert!(policy.validate(now).is_err());
        policy.expires_at = Some(now + chrono::Duration::hours(1));
        assert!(policy.active_at(now));
        assert!(policy.validate(now).is_ok());
    }
    #[test]
    fn address_normalization_and_strict_payload() {
        assert_eq!(
            owner_address("0xA").unwrap(),
            owner_address("0x000a").unwrap()
        );
        assert!(owner_address("invalid").is_err());
        assert!(serde_json::from_str::<OwnerRateLimit>(r#"{"requests_per_minute":60,"requests_per_hour":500,"delegate_key_per_minute":30,"expires_at":null,"label":"example"}"#).is_err());
    }
    #[tokio::test]
    async fn owner_policy_database_lifecycle() {
        let Ok(database_url) = std::env::var("OWNER_RATE_LIMIT_TEST_DATABASE_URL") else {
            eprintln!("skipping: OWNER_RATE_LIMIT_TEST_DATABASE_URL is not configured");
            return;
        };
        let parsed = url::Url::parse(&database_url).unwrap();
        assert!(
            matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1")),
            "policy test requires a local database"
        );
        let setup = sqlx::PgPool::connect(&database_url).await.unwrap();
        let schema = format!("policy_test_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&setup)
            .await
            .unwrap();
        let search_path = format!("SET search_path TO {schema}");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .after_connect(move |connection, _| {
                let statement = search_path.clone();
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .unwrap();
        let migration = include_str!("../migrations/027_owner_rate_limits.sql");
        // Startup can replay migrations; audit trigger must remain single.
        sqlx::raw_sql(migration).execute(&pool).await.unwrap();
        sqlx::raw_sql(migration).execute(&pool).await.unwrap();
        let owner = owner_address("0x1").unwrap();
        let other = owner_address("0x2").unwrap();
        let mut policy = OwnerRateLimit::defaults(&RateLimitConfig::default());
        policy.requests_per_minute = 180;
        store_policy(&pool, &owner, &policy).await.unwrap();
        assert_eq!(
            load_policy(&pool, &owner)
                .await
                .unwrap()
                .unwrap()
                .requests_per_minute,
            180
        );
        assert!(load_policy(&pool, &other).await.unwrap().is_none());
        policy.requests_per_minute = 240;
        policy.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        store_policy(&pool, &owner, &policy).await.unwrap();
        assert!(!load_policy(&pool, &owner)
            .await
            .unwrap()
            .unwrap()
            .active_at(Utc::now()));
        // Database constraints also reject bypasses of HTTP validation.
        policy.requests_per_minute = 0;
        assert!(store_policy(&pool, &owner, &policy).await.is_err());
        remove_policy(&pool, &owner).await.unwrap();
        remove_policy(&pool, &owner).await.unwrap();
        assert!(load_policy(&pool, &owner).await.unwrap().is_none());
        let operations: Vec<String> =
            sqlx::query_scalar("SELECT operation FROM owner_rate_limit_audit ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(operations, ["INSERT", "UPDATE", "DELETE"]);
        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&setup)
            .await
            .unwrap();
        setup.close().await;
    }
}

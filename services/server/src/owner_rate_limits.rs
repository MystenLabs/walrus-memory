//! Private operator policy. Identity comes from authenticated owner resolution;
//! overrides never change authentication, endpoint weights, or storage quotas.
use crate::rate_limit::RateLimitConfig;
use crate::security_delete_auth::canonical_sui_address;
use crate::types::{AppError, AppState};
use axum::extract::{Path, Query, State};
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

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct OwnerPolicyRecord {
    owner: String,
    requests_per_minute: i64,
    requests_per_hour: i64,
    delegate_key_per_minute: i64,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyListQuery {
    after: Option<String>,
}

#[derive(Serialize)]
pub struct PolicyListResponse {
    defaults: OwnerRateLimit,
    policies: Vec<OwnerPolicyRecord>,
    next_cursor: Option<String>,
}

async fn list_records(
    pool: &sqlx::PgPool,
    after: Option<&str>,
) -> Result<Vec<OwnerPolicyRecord>, sqlx::Error> {
    sqlx::query_as::<_, OwnerPolicyRecord>("SELECT owner, requests_per_minute, requests_per_hour, delegate_key_per_minute, expires_at FROM owner_rate_limits WHERE ($1::text IS NULL OR owner > $1) ORDER BY owner LIMIT 101")
        .bind(after).fetch_all(pool).await
}

pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PolicyListQuery>,
) -> Result<Json<PolicyListResponse>, AppError> {
    let after = query.after.as_deref().map(owner_address).transpose()?;
    let mut policies = list_records(state.db.pool(), after.as_deref())
        .await
        .map_err(policy_store_error)?;
    let more = policies.len() > 100;
    policies.truncate(100);
    let next_cursor = if more {
        policies.last().map(|p| p.owner.clone())
    } else {
        None
    };
    Ok(Json(PolicyListResponse {
        defaults: OwnerRateLimit::defaults(&state.config.rate_limit),
        policies,
        next_cursor,
    }))
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
    let _policy_guard =
        tokio::time::timeout(REFRESH_INTERVAL, state.owner_policies.mutation_guard())
            .await
            .map_err(|_| policy_store_error(sqlx::Error::PoolTimedOut))?;
    tokio::time::timeout(
        REFRESH_INTERVAL,
        store_policy(state.db.pool(), &owner, &policy),
    )
    .await
    .map_err(|_| policy_store_error(sqlx::Error::PoolTimedOut))?
    .map_err(policy_store_error)?;
    state
        .owner_policies
        .apply_committed(owner.clone(), Some(policy.clone()));
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
    let _policy_guard =
        tokio::time::timeout(REFRESH_INTERVAL, state.owner_policies.mutation_guard())
            .await
            .map_err(|_| policy_store_error(sqlx::Error::PoolTimedOut))?;
    tokio::time::timeout(REFRESH_INTERVAL, remove_policy(state.db.pool(), &owner))
        .await
        .map_err(|_| policy_store_error(sqlx::Error::PoolTimedOut))?
        .map_err(policy_store_error)?;
    state.owner_policies.apply_committed(owner.clone(), None);
    let defaults = OwnerRateLimit::defaults(&state.config.rate_limit);
    Ok(Json(PolicyResponse {
        owner,
        defaults: defaults.clone(),
        override_policy: None,
        effective: defaults,
    }))
}

// Requests read a small immutable-in-practice snapshot, never PostgreSQL.
// Replicas check a shared generation once per second on a dedicated connection.
// Policy edits can take up to one refresh interval to reach other replicas.
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_SNAPSHOT_AGE: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Default)]
struct PolicySnapshot {
    revision: Option<i64>,
    checked_at: Option<std::time::Instant>,
    policies: std::collections::HashMap<String, OwnerRateLimit>,
}

#[derive(Default)]
pub struct OwnerPolicyStore {
    snapshot: std::sync::RwLock<PolicySnapshot>,
    // Serializes refreshes with local committed mutations, preventing an older
    // refresh from overwriting a just-saved policy on this replica.
    refresh_lock: tokio::sync::Mutex<()>,
}

#[derive(Debug)]
pub struct PolicySnapshotUnavailable;

impl OwnerPolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn policy_for(
        &self,
        owner: &str,
    ) -> Result<Option<OwnerRateLimit>, PolicySnapshotUnavailable> {
        self.policy_at(owner, std::time::Instant::now())
    }

    fn policy_at(
        &self,
        owner: &str,
        now: std::time::Instant,
    ) -> Result<Option<OwnerRateLimit>, PolicySnapshotUnavailable> {
        let snapshot = self
            .snapshot
            .read()
            .map_err(|_| PolicySnapshotUnavailable)?;
        if snapshot
            .checked_at
            .is_none_or(|checked| now.saturating_duration_since(checked) >= MAX_SNAPSHOT_AGE)
        {
            return Err(PolicySnapshotUnavailable);
        }
        Ok(snapshot.policies.get(owner).cloned())
    }

    pub async fn mutation_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.refresh_lock.lock().await
    }

    // Called only after durable commit, while holding mutation_guard.
    fn apply_committed(&self, owner: String, policy: Option<OwnerRateLimit>) {
        if let Ok(mut snapshot) = self.snapshot.write() {
            match policy {
                Some(policy) => {
                    snapshot.policies.insert(owner, policy);
                }
                None => {
                    snapshot.policies.remove(&owner);
                }
            }
            snapshot.revision = None;
            // A single edit cannot certify freshness of all other owners.
        }
    }

    pub async fn refresh(&self, pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
        let _guard = self.refresh_lock.lock().await;
        let current = self
            .snapshot
            .read()
            .map_err(|_| sqlx::Error::Protocol("policy snapshot lock unavailable".into()))?
            .revision;
        let checked_at = std::time::Instant::now();
        let (revision, policies) = tokio::time::timeout(REFRESH_INTERVAL, async {
            let observed: i64 = sqlx::query_scalar("SELECT revision FROM owner_rate_limit_revision WHERE singleton").fetch_one(pool).await?;
            if current == Some(observed) {
                return Ok::<_, sqlx::Error>((observed, None));
            }
            let mut transaction = pool.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY").execute(&mut *transaction).await?;
            // Re-read inside the transaction so generation and rows refer to
            // one MVCC snapshot even if another replica commits meanwhile.
            let revision: i64 = sqlx::query_scalar("SELECT revision FROM owner_rate_limit_revision WHERE singleton").fetch_one(&mut *transaction).await?;
            let records = sqlx::query_as::<_, OwnerPolicyRecord>("SELECT owner, requests_per_minute, requests_per_hour, delegate_key_per_minute, expires_at FROM owner_rate_limits WHERE expires_at IS NULL OR expires_at > now()")
                .fetch_all(&mut *transaction).await?;
            let policies = records.into_iter().map(|row| (row.owner, OwnerRateLimit { requests_per_minute: row.requests_per_minute, requests_per_hour: row.requests_per_hour, delegate_key_per_minute: row.delegate_key_per_minute, expires_at: row.expires_at })).collect();
            transaction.commit().await?;
            Ok::<_, sqlx::Error>((revision, Some(policies)))
        }).await.map_err(|_| sqlx::Error::PoolTimedOut)??;
        let mut snapshot = self
            .snapshot
            .write()
            .map_err(|_| sqlx::Error::Protocol("policy snapshot lock unavailable".into()))?;
        if let Some(policies) = policies {
            snapshot.policies = policies;
        }
        snapshot.revision = Some(revision);
        snapshot.checked_at = Some(checked_at);
        Ok(())
    }

    pub fn spawn_refresher(self: &Arc<Self>, pool: sqlx::PgPool) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(REFRESH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(store) = weak.upgrade() else { break };
                if let Err(error) = store.refresh(&pool).await {
                    crate::observability::record_app_error("owner_policy_refresh_failed");
                    tracing::warn!(%error, "owner policy refresh failed; stale snapshots fail closed");
                }
            }
        });
    }

    #[cfg(test)]
    pub fn expire_for_test(&self) {
        self.snapshot.write().unwrap().checked_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_unknown_owner_and_freshness_bound() {
        let store = OwnerPolicyStore::new();
        assert!(store.policy_for("0x1").is_err());
        let now = std::time::Instant::now();
        store.snapshot.write().unwrap().checked_at = Some(now);
        assert!(store.policy_at("0x1", now).unwrap().is_none());
        assert!(store.policy_at("0x1", now + MAX_SNAPSHOT_AGE).is_err());
        assert!(store
            .policy_at(
                "0x1",
                now + MAX_SNAPSHOT_AGE - std::time::Duration::from_millis(1)
            )
            .is_ok());
    }

    #[test]
    fn local_commit_does_not_certify_unrelated_stale_owners() {
        let store = OwnerPolicyStore::new();
        store.apply_committed(
            "0x1".into(),
            Some(OwnerRateLimit::defaults(&RateLimitConfig::default())),
        );
        assert!(store.policy_for("0x1").is_err());
        assert!(store.snapshot.read().unwrap().revision.is_none());
        store.snapshot.write().unwrap().checked_at = Some(std::time::Instant::now());
        assert!(store.policy_for("0x1").unwrap().is_some());
        store.apply_committed("0x1".into(), None);
        assert!(store.policy_for("0x1").unwrap().is_none());
    }

    #[test]
    #[ignore = "explicit local policy hot-path microbenchmark"]
    fn policy_snapshot_lookup_benchmark() {
        let store = OwnerPolicyStore::new();
        let policy = OwnerRateLimit::defaults(&RateLimitConfig::default());
        {
            let mut snapshot = store.snapshot.write().unwrap();
            snapshot.policies = (0..10_000)
                .map(|i| (format!("0x{i:064x}"), policy.clone()))
                .collect();
            snapshot.checked_at = Some(std::time::Instant::now());
        }
        let owners: Vec<String> = (0..12_000).map(|i| format!("0x{i:064x}")).collect();
        let mut times = Vec::with_capacity(100_000);
        for i in 0..100_000 {
            let start = std::time::Instant::now();
            std::hint::black_box(store.policy_for(std::hint::black_box(&owners[i % owners.len()])))
                .unwrap();
            times.push(start.elapsed().as_nanos());
        }
        times.sort_unstable();
        eprintln!(
            "snapshot entries=10000 lookups=100000 p50={}ns p95={}ns max={}ns",
            times[50_000], times[95_000], times[99_999]
        );
        assert_eq!(store.snapshot.read().unwrap().policies.len(), 10_000);
    }

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
        assert_eq!(list_records(&pool, None).await.unwrap().len(), 1);
        assert!(list_records(&pool, Some(&owner)).await.unwrap().is_empty());
        let first = OwnerPolicyStore::new();
        let second = OwnerPolicyStore::new();
        first.refresh(&pool).await.unwrap();
        second.refresh(&pool).await.unwrap();
        assert_eq!(
            first
                .policy_for(&owner)
                .unwrap()
                .unwrap()
                .requests_per_minute,
            180
        );
        assert!(first.policy_for(&other).unwrap().is_none());
        // Refresh with an unchanged generation must not reload policy rows.
        let mut lock = pool.begin().await.unwrap();
        sqlx::query("LOCK TABLE owner_rate_limits IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();
        second.refresh(&pool).await.unwrap();
        lock.rollback().await.unwrap();
        policy.requests_per_minute = 240;
        {
            let _guard = first.mutation_guard().await;
            store_policy(&pool, &owner, &policy).await.unwrap();
            first.apply_committed(owner.clone(), Some(policy.clone()));
        }
        assert_eq!(
            first
                .policy_for(&owner)
                .unwrap()
                .unwrap()
                .requests_per_minute,
            240
        );
        assert_eq!(
            second
                .policy_for(&owner)
                .unwrap()
                .unwrap()
                .requests_per_minute,
            180
        );
        second.refresh(&pool).await.unwrap();
        assert_eq!(
            second
                .policy_for(&owner)
                .unwrap()
                .unwrap()
                .requests_per_minute,
            240
        );
        // A local refresh cannot overwrite a mutation while its commit guard is held.
        {
            let guard = first.mutation_guard().await;
            assert!(first.refresh_lock.try_lock().is_err());
            drop(guard);
        }
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
        first.refresh(&pool).await.unwrap();
        second.refresh(&pool).await.unwrap();
        assert!(first.policy_for(&owner).unwrap().is_none());
        assert!(second.policy_for(&owner).unwrap().is_none());
        let operations: Vec<String> =
            sqlx::query_scalar("SELECT operation FROM owner_rate_limit_audit ORDER BY id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(operations, ["INSERT", "UPDATE", "UPDATE", "DELETE"]);
        let revision: i64 =
            sqlx::query_scalar("SELECT revision FROM owner_rate_limit_revision WHERE singleton")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(revision, 4);
        pool.close().await;
        // Fresh snapshots continue without any available database connections.
        assert!(second.policy_for(&owner).unwrap().is_none());
        second.expire_for_test();
        assert!(second.refresh(&pool).await.is_err());
        assert!(second.policy_for(&owner).is_err());
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&setup)
            .await
            .unwrap();
        setup.close().await;
    }
}

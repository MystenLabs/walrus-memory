//! Private operator policy. Identity comes from authenticated owner resolution;
//! overrides never change authentication, endpoint weights, or storage quotas.
use crate::rate_limit::RateLimitConfig;
use crate::security_delete_auth::canonical_sui_address;
use crate::types::{AppError, AppState};
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use sui_sdk_types::Address;

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
    tokio::time::timeout(
        POLICY_STORE_TIMEOUT,
        store_policy(state.db.pool(), &owner, &policy),
    )
    .await
    .map_err(|_| policy_store_error(sqlx::Error::PoolTimedOut))?
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
    tokio::time::timeout(POLICY_STORE_TIMEOUT, remove_policy(state.db.pool(), &owner))
        .await
        .map_err(|_| policy_store_error(sqlx::Error::PoolTimedOut))?
        .map_err(policy_store_error)?;
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
const POLICY_STORE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_SNAPSHOT_AGE: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Clone, Default)]
struct PolicySnapshot {
    revision: Option<i64>,
    checked_at: Option<std::time::Instant>,
    policies: Arc<HashMap<Address, OwnerRateLimit>>,
}

impl PolicySnapshot {
    fn is_fresh(&self, now: std::time::Instant) -> bool {
        self.checked_at
            .is_some_and(|checked| now.saturating_duration_since(checked) < MAX_SNAPSHOT_AGE)
    }
}

#[derive(Default)]
pub struct OwnerPolicyStore {
    snapshot: arc_swap::ArcSwap<PolicySnapshot>,
}

#[derive(Debug)]
pub struct PolicySnapshotUnavailable;

impl OwnerPolicyStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    // Initialize before serving requests, then start exactly one snapshot writer.
    pub async fn start(pool: sqlx::PgPool) -> Result<Arc<Self>, sqlx::Error> {
        let store = Arc::new(Self::new());
        store.refresh(&pool).await?;
        store.spawn_refresher(pool);
        Ok(store)
    }

    pub fn is_ready(&self) -> bool {
        self.snapshot.load().is_fresh(std::time::Instant::now())
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
        let owner: Address = owner.parse().map_err(|_| PolicySnapshotUnavailable)?;
        let snapshot = self.snapshot.load();
        if !snapshot.is_fresh(now) {
            return Err(PolicySnapshotUnavailable);
        }
        Ok(snapshot.policies.get(&owner).cloned())
    }

    // Test fixtures may publish artificial timestamps; production has only the
    // background refresh task writing snapshots.
    #[cfg(test)]
    fn update_snapshot(&self, update: impl FnOnce(&mut PolicySnapshot)) {
        let mut next = self.snapshot.load_full().as_ref().clone();
        update(&mut next);
        self.snapshot.store(Arc::new(next));
    }

    async fn refresh(&self, pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
        let current = self.snapshot.load().revision;
        let checked_at = std::time::Instant::now();
        let (revision, policies) = tokio::time::timeout(POLICY_STORE_TIMEOUT, async {
            const REVISION_QUERY: &str =
                "SELECT revision FROM owner_rate_limit_revision WHERE singleton";
            let observed: i64 = sqlx::query_scalar(REVISION_QUERY).fetch_one(pool).await?;
            if current == Some(observed) {
                return Ok::<_, sqlx::Error>((observed, None));
            }
            let mut transaction = pool.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                .execute(&mut *transaction)
                .await?;
            // Re-read inside the transaction so generation and rows refer to
            // one MVCC snapshot even if another replica commits meanwhile.
            let revision: i64 = sqlx::query_scalar(REVISION_QUERY)
                .fetch_one(&mut *transaction)
                .await?;
            let records = sqlx::query_as::<_, OwnerPolicyRecord>(
                "SELECT owner, requests_per_minute, requests_per_hour,
                        delegate_key_per_minute, expires_at
                 FROM owner_rate_limits
                 WHERE expires_at IS NULL OR expires_at > now()",
            )
            .fetch_all(&mut *transaction)
            .await?;
            let policies = records
                .into_iter()
                .map(|row| {
                    let owner: Address = row.owner.parse().map_err(|_| {
                        sqlx::Error::Protocol("invalid policy owner address".into())
                    })?;
                    Ok((
                        owner,
                        OwnerRateLimit {
                            requests_per_minute: row.requests_per_minute,
                            requests_per_hour: row.requests_per_hour,
                            delegate_key_per_minute: row.delegate_key_per_minute,
                            expires_at: row.expires_at,
                        },
                    ))
                })
                .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
            transaction.commit().await?;
            Ok::<_, sqlx::Error>((revision, Some(policies)))
        })
        .await
        .map_err(|_| sqlx::Error::PoolTimedOut)??;
        let policies = match policies {
            Some(policies) => Arc::new(policies),
            None => Arc::clone(&self.snapshot.load().policies),
        };
        self.snapshot.store(Arc::new(PolicySnapshot {
            revision: Some(revision),
            checked_at: Some(checked_at),
            policies,
        }));
        Ok(())
    }

    fn spawn_refresher(self: &Arc<Self>, pool: sqlx::PgPool) {
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
    pub async fn refresh_for_test(&self, pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
        self.refresh(pool).await
    }

    #[cfg(test)]
    pub fn expire_for_test(&self) {
        self.update_snapshot(|snapshot| snapshot.checked_at = None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_unknown_owner_and_freshness_bound() {
        let store = OwnerPolicyStore::new();
        assert!(store.policy_for("0x1").is_err());
        assert!(!store.is_ready());
        let now = std::time::Instant::now();
        store.update_snapshot(|snapshot| snapshot.checked_at = Some(now));
        assert!(store.policy_at("0x1", now).unwrap().is_none());
        assert!(store.is_ready());
        assert!(store.policy_at("0x1", now + MAX_SNAPSHOT_AGE).is_err());
        assert!(store
            .policy_at(
                "0x1",
                now + MAX_SNAPSHOT_AGE - std::time::Duration::from_millis(1)
            )
            .is_ok());
    }

    #[test]
    fn published_snapshot_readers_remain_consistent_during_updates() {
        let store = OwnerPolicyStore::new();
        let owner: Address = "0xabc".parse().unwrap();
        let mut policy = OwnerRateLimit::defaults(&RateLimitConfig::default());
        policy.requests_per_minute = 180;
        store.update_snapshot(|snapshot| {
            snapshot.policies = Arc::new(HashMap::from([(owner, policy.clone())]));
            snapshot.checked_at = Some(std::time::Instant::now());
        });
        let previous = store.snapshot.load();
        // A retained reader must not block publication, or observe a half edit.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    policy.requests_per_minute = 240;
                    store.update_snapshot(|snapshot| {
                        snapshot.policies = Arc::new(HashMap::from([(owner, policy)]));
                    });
                })
                .join()
                .unwrap();
        });
        assert_eq!(previous.policies[&owner].requests_per_minute, 180);
        assert_eq!(
            store
                .policy_for("0x000AbC")
                .unwrap()
                .unwrap()
                .requests_per_minute,
            240
        );
        assert!(store.policy_for("invalid").is_err());
        let current = store.snapshot.load();
        store.update_snapshot(|snapshot| snapshot.checked_at = Some(std::time::Instant::now()));
        assert!(
            Arc::ptr_eq(&current.policies, &store.snapshot.load().policies),
            "freshness updates must share the policy map without copying it"
        );
    }

    #[test]
    #[ignore = "explicit local policy hot-path microbenchmark"]
    fn policy_snapshot_lookup_benchmark() {
        let store = OwnerPolicyStore::new();
        let policy = OwnerRateLimit::defaults(&RateLimitConfig::default());
        store.update_snapshot(|snapshot| {
            snapshot.policies = Arc::new(
                (0..10_000)
                    .map(|i| (format!("0x{i:064x}").parse().unwrap(), policy.clone()))
                    .collect(),
            );
            snapshot.checked_at = Some(std::time::Instant::now());
        });
        let owners: Vec<String> = (0..12_000).map(|i| format!("0x{i:064x}")).collect();
        // Compare complete address normalization + policy lookup with the
        // previous canonical-string/RwLock design, at 1 and 8 reader threads.
        let baseline = std::sync::RwLock::new((
            std::time::Instant::now(),
            (0..10_000)
                .map(|i| (format!("0x{i:064x}"), policy.clone()))
                .collect::<std::collections::HashMap<_, _>>(),
        ));
        fn measure(
            resolve: impl Fn(&str) -> Option<OwnerRateLimit> + Sync,
            owners: &[String],
            threads: usize,
        ) -> (u128, u128) {
            let mut times = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..threads)
                    .map(|thread| {
                        let resolve = &resolve;
                        scope.spawn(move || {
                            (0..(100_000 / threads))
                                .map(|i| {
                                    let start = std::time::Instant::now();
                                    std::hint::black_box(resolve(std::hint::black_box(
                                        &owners[(i + thread) % owners.len()],
                                    )));
                                    start.elapsed().as_nanos()
                                })
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|handle| handle.join().unwrap())
                    .collect::<Vec<_>>()
            });
            times.sort_unstable();
            (times[times.len() / 2], times[times.len() * 95 / 100])
        }
        for threads in [1, 8] {
            baseline.write().unwrap().0 = std::time::Instant::now();
            let old = measure(
                |owner| {
                    let owner = crate::security_delete_auth::canonical_sui_address(owner).unwrap();
                    let now = std::time::Instant::now();
                    let snapshot = baseline.read().unwrap();
                    assert!(now.duration_since(snapshot.0) < MAX_SNAPSHOT_AGE);
                    snapshot.1.get(&owner).cloned()
                },
                &owners,
                threads,
            );
            store.update_snapshot(|snapshot| snapshot.checked_at = Some(std::time::Instant::now()));
            let new = measure(|owner| store.policy_for(owner).unwrap(), &owners, threads);
            eprintln!("entries=10000 lookups=100000 threads={threads} canonical_string_rwlock_p50={}ns p95={}ns binary_snapshot_p50={}ns p95={}ns", old.0, old.1, new.0, new.1);
        }
        assert_eq!(store.snapshot.load().policies.len(), 10_000);
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
        let background = OwnerPolicyStore::start(pool.clone()).await.unwrap();
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
        store_policy(&pool, &owner, &policy).await.unwrap();
        // Admin commits do not modify RAM. Only refresh publishes new state.
        assert_eq!(
            first
                .policy_for(&owner)
                .unwrap()
                .unwrap()
                .requests_per_minute,
            180
        );
        first.refresh(&pool).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if background
                    .policy_for(&owner)
                    .unwrap()
                    .unwrap()
                    .requests_per_minute
                    == 240
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("background refresh must propagate a committed edit");
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
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while background.policy_for(&owner).unwrap().is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("background refresh must propagate a committed reset");
        drop(background);
        pool.close().await;
        // Fresh snapshots continue without any available database connections.
        assert!(second.policy_for(&owner).unwrap().is_none());
        assert!(second.is_ready());
        second.expire_for_test();
        assert!(!second.is_ready());
        assert!(second.refresh(&pool).await.is_err());
        assert!(second.policy_for(&owner).is_err());
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&setup)
            .await
            .unwrap();
        setup.close().await;
    }
}

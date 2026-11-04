use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions};
use sqlx::{Connection, PgPool};
use std::str::FromStr;
use std::time::Duration;

use super::postgres_url::{direct_postgres_url, is_transaction_pooler_url, postgres_host};
use crate::types::AppError;

/// Bound how long a single migrate attempt waits on sqlx's session advisory
/// lock. Combined with retries so a leaked pooler lock is a transient boot
/// delay, not a hard crash.
const LEGACY_MIGRATION_LOCK_TIMEOUT: &str = "5s";
const LEGACY_MIGRATION_MAX_ATTEMPTS: u32 = 6;

#[derive(Debug)]
pub struct LegacyDb {
    pool: PgPool,
}

impl LegacyDb {
    #[allow(dead_code)]
    pub async fn new(database_url: &str) -> Result<Self, AppError> {
        Self::new_with_search_path(database_url, None).await
    }

    pub async fn new_checked(database_url: &str, primary_pool: &PgPool) -> Result<Self, AppError> {
        Self::new_checked_with_search_path(database_url, None, primary_pool).await
    }

    pub(crate) async fn new_checked_with_search_path(
        database_url: &str,
        search_path: Option<&str>,
        primary_pool: &PgPool,
    ) -> Result<Self, AppError> {
        Self::ensure_distinct_from_primary(primary_pool, database_url, search_path).await?;
        Self::new_with_search_path(database_url, search_path).await
    }

    pub async fn ensure_distinct_from_primary(
        primary_pool: &PgPool,
        legacy_database_url: &str,
        legacy_search_path: Option<&str>,
    ) -> Result<(), AppError> {
        let mut primary_tx = primary_pool.begin().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to begin primary db transaction for identity check: {error}"
            ))
        })?;
        let primary_schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&mut *primary_tx)
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to query primary schema: {error}"))
            })?;

        let uuid_val = uuid::Uuid::new_v4().as_u128();
        let k1 = (uuid_val as u32) as i32;
        let k2 = ((uuid_val >> 32) as u32) as i32;

        sqlx::query("SELECT pg_advisory_xact_lock(21318, $1), pg_advisory_xact_lock(21318, $2)")
            .bind(k1)
            .bind(k2)
            .execute(&mut *primary_tx)
            .await
            .map_err(|error| {
                AppError::Internal(format!(
                    "failed to acquire advisory lock on primary db for identity check: {error}"
                ))
            })?;

        let migrate_url = direct_postgres_url(legacy_database_url);
        let mut options = PgConnectOptions::from_str(migrate_url.as_ref())
            .map_err(|error| AppError::Internal(format!("legacy db URL invalid: {error}")))?;
        if let Some(search_path) = legacy_search_path {
            options = options.options([("search_path", search_path)]);
        }

        let mut legacy_conn = PgConnection::connect_with(&options)
            .await
            .map_err(|error| {
                AppError::Internal(format!("legacy db identity probe connect failed: {error}"))
            })?;

        let legacy_schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&mut legacy_conn)
            .await
            .map_err(|error| {
                AppError::Internal(format!("failed to query legacy schema: {error}"))
            })?;

        let mut legacy_tx = legacy_conn.begin().await.map_err(|error| {
            AppError::Internal(format!(
                "failed to begin legacy db transaction for identity check: {error}"
            ))
        })?;

        let probe_result: Result<(bool, bool), sqlx::Error> = sqlx::query_as(
            "SELECT pg_try_advisory_xact_lock(21318, $1), pg_try_advisory_xact_lock(21318, $2)",
        )
        .bind(k1)
        .bind(k2)
        .fetch_one(&mut *legacy_tx)
        .await;

        let _ = legacy_tx.rollback().await;
        let _ = legacy_conn.close().await;
        let _ = primary_tx.rollback().await;

        let (locked_a, locked_b) = probe_result.map_err(|error| {
            AppError::Internal(format!("legacy db advisory lock probe failed: {error}"))
        })?;

        if !locked_a && !locked_b && primary_schema == legacy_schema {
            return Err(AppError::Internal(
                "LEGACY_DB_URL points to the same PostgreSQL database and schema as DATABASE_URL; refusing to run legacy security-delete migrations on the primary database".into(),
            ));
        }

        Ok(())
    }

    pub(crate) async fn new_with_search_path(
        database_url: &str,
        search_path: Option<&str>,
    ) -> Result<Self, AppError> {
        apply_legacy_migrations(database_url, search_path).await?;

        let mut options = PgConnectOptions::from_str(database_url)
            .map_err(|error| AppError::Internal(format!("legacy db URL invalid: {error}")))?;
        if let Some(search_path) = search_path {
            options = options.options([("search_path", search_path)]);
        }
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await
            .map_err(|error| AppError::Internal(format!("legacy db connect failed: {error}")))?;
        tracing::info!("legacy db connected, security-delete migrations applied");
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

async fn apply_legacy_migrations(
    database_url: &str,
    search_path: Option<&str>,
) -> Result<(), AppError> {
    let migrate_url = direct_postgres_url(database_url);
    if is_transaction_pooler_url(database_url) {
        let original_host = url::Url::parse(database_url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned));
        let direct_host = url::Url::parse(migrate_url.as_ref())
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_owned));
        tracing::info!(
            original_host,
            direct_host,
            "legacy db: running sqlx migrations on the direct Postgres endpoint"
        );
    }

    let mut last_error: Option<AppError> = None;
    for attempt in 1..=LEGACY_MIGRATION_MAX_ATTEMPTS {
        match apply_legacy_migrations_once(migrate_url.as_ref(), search_path).await {
            Ok(()) => return Ok(()),
            Err(failure) if failure.lock_contention && attempt < LEGACY_MIGRATION_MAX_ATTEMPTS => {
                let delay = Duration::from_millis(500 * (1u64 << (attempt - 1).min(4)));
                tracing::warn!(
                    attempt,
                    max_attempts = LEGACY_MIGRATION_MAX_ATTEMPTS,
                    retry_in_ms = delay.as_millis() as u64,
                    error = %failure.error,
                    "legacy migration lock contention; retrying. \
                     If this persists, an orphaned sqlx advisory lock is held on a pooled backend. \
                     Release it with pg_terminate_backend on the pg_locks pid."
                );
                tokio::time::sleep(delay).await;
                last_error = Some(failure.error);
            }
            Err(failure) => return Err(failure.error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        AppError::Internal("legacy migration failed: lock contention retries exhausted".into())
    }))
}

struct LegacyMigrationAttemptError {
    error: AppError,
    lock_contention: bool,
}

impl From<AppError> for LegacyMigrationAttemptError {
    fn from(error: AppError) -> Self {
        Self {
            error,
            lock_contention: false,
        }
    }
}

async fn apply_legacy_migrations_once(
    migrate_url: &str,
    search_path: Option<&str>,
) -> Result<(), LegacyMigrationAttemptError> {
    let mut options = PgConnectOptions::from_str(migrate_url)
        .map_err(|error| AppError::Internal(format!("legacy db URL invalid: {error}")))?;
    let mut gucs: Vec<(&str, &str)> = vec![("lock_timeout", LEGACY_MIGRATION_LOCK_TIMEOUT)];
    if let Some(search_path) = search_path {
        gucs.push(("search_path", search_path));
    }
    options = options.options(gucs);

    let host = postgres_host(migrate_url).unwrap_or_else(|| "unknown".into());
    let mut conn = PgConnection::connect_with(&options)
        .await
        .map_err(|error| {
            AppError::Internal(format!(
                "legacy db migrate connect failed (host={host}): {error}"
            ))
        })?;

    let mut migrator = sqlx::migrate!("./migrations_legacy");
    // The old V1 database already contains migration history from Apalis.
    // Only validate and apply migrations owned by the security-delete subsystem.
    migrator.set_ignore_missing(true);
    let result = match migrator.run(&mut conn).await {
        Ok(()) => Ok(()),
        Err(error) => {
            let lock_contention = migrate_error_is_lock_contention(&error);
            if lock_contention {
                // lock_timeout aborts the statement; if sqlx had a transaction
                // open the connection is now unusable until ROLLBACK.
                let _ = sqlx::query("ROLLBACK").execute(&mut conn).await;
                release_orphaned_sqlx_migration_lock(&mut conn).await;
            }
            Err(LegacyMigrationAttemptError {
                error: AppError::Internal(format!("legacy migration failed: {error}")),
                lock_contention,
            })
        }
    };

    // Direct connections drop session locks on close. Still unlock explicitly
    // so a cancelled run cannot leave the lock if the backend is reused.
    let _ = sqlx::query("ROLLBACK").execute(&mut conn).await;
    let _ = sqlx::query("SELECT pg_advisory_unlock_all()")
        .execute(&mut conn)
        .await;
    let _ = conn.close().await;
    result
}

/// sqlx's Postgres migrator lock: `0x3d32ad9e * crc32(database_name)`.
/// Must match sqlx 0.8 so we can find (and drop) a leaked session lock.
fn sqlx_migration_lock_id(database_name: &str) -> i64 {
    0x3d32ad9e * (crc32_iso_hdlc(database_name.as_bytes()) as i64)
}

fn crc32_iso_hdlc(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Advisory locks are database-wide. A pooled backend that leaked sqlx's
/// session lock will block even a direct migrator. If that holder is idle
/// (idle pgbouncer backend now serving unrelated traffic),
/// terminate it so the next attempt can proceed. Never kill a non-idle
/// backend — that could be a live upload holding a different advisory lock.
async fn release_orphaned_sqlx_migration_lock(conn: &mut PgConnection) {
    let database_name: String = match sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *conn)
        .await
    {
        Ok(name) => name,
        Err(error) => {
            tracing::warn!(%error, "legacy migration: could not read current_database() after lock timeout");
            return;
        }
    };
    let lock_id = sqlx_migration_lock_id(&database_name);
    let holders: Vec<(i32, Option<String>, Option<String>, Option<String>)> = match sqlx::query_as(
        "SELECT a.pid, a.application_name, a.state, left(a.query, 120)
         FROM pg_locks l
         JOIN pg_stat_activity a ON a.pid = l.pid
         WHERE l.locktype = 'advisory'
           AND l.granted
           AND l.objsubid = 1
           AND l.pid <> pg_backend_pid()
           AND ((l.classid::bigint << 32) | l.objid::bigint) = $1",
    )
    .bind(lock_id)
    .fetch_all(&mut *conn)
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(%error, "legacy migration: could not inspect pg_locks after lock timeout");
            return;
        }
    };
    for (pid, application_name, state, query) in holders {
        tracing::warn!(
            pid,
            application_name = application_name.as_deref().unwrap_or(""),
            state = state.as_deref().unwrap_or(""),
            query = query.as_deref().unwrap_or(""),
            "legacy migration: sqlx advisory lock is held by another backend"
        );
        // Live migrators are `active`. A leaked pooler backend is `idle`
        // (or `idle in transaction` if SET left a txn).
        if !matches!(state.as_deref(), Some("idle") | Some("idle in transaction")) {
            continue;
        }
        match sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&mut *conn)
            .await
        {
            Ok(true) => tracing::warn!(
                pid,
                "legacy migration: terminated idle backend holding the leaked sqlx lock"
            ),
            Ok(false) => {
                tracing::warn!(pid, "legacy migration: pg_terminate_backend returned false")
            }
            Err(error) => {
                tracing::warn!(pid, %error, "legacy migration: pg_terminate_backend failed")
            }
        }
    }
}

/// Postgres SQLSTATE for lock-wait failures.
///
/// `55P03` = lock_not_available (`canceling statement due to lock timeout`)
/// `40P01` = deadlock_detected
fn sqlstate_is_lock_contention(code: &str) -> bool {
    code.eq_ignore_ascii_case("55P03") || code.eq_ignore_ascii_case("40P01")
}

fn sqlx_error_is_lock_contention(error: &sqlx::Error) -> bool {
    let Some(db) = error.as_database_error() else {
        return false;
    };
    match db.code() {
        Some(code) => sqlstate_is_lock_contention(code.as_ref()),
        // Driver dropped SQLSTATE: don't let a Display reword disable retries,
        // but don't treat generic statement-timeout text as lock contention.
        None => {
            let msg = db.message().to_ascii_lowercase();
            msg.contains("lock timeout") || msg.contains("deadlock detected")
        }
    }
}

fn migrate_error_sqlx_source(error: &sqlx::migrate::MigrateError) -> Option<&sqlx::Error> {
    match error {
        sqlx::migrate::MigrateError::Execute(source)
        | sqlx::migrate::MigrateError::ExecuteMigration(source, _) => Some(source),
        _ => None,
    }
}

fn migrate_error_is_lock_contention(error: &sqlx::migrate::MigrateError) -> bool {
    migrate_error_sqlx_source(error).is_some_and(sqlx_error_is_lock_contention)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use uuid::Uuid;

    pub async fn fixture() -> Option<(LegacyDb, PgPool, String)> {
        fixture_with_rows(&[]).await
    }

    async fn fixture_with_rows(rows: &[(&str, &str, &str)]) -> Option<(LegacyDb, PgPool, String)> {
        let url = std::env::var("TEST_LEGACY_DATABASE_URL").ok()?;
        let admin = PgPool::connect(&url).await.expect("connect test Postgres");
        let schema = format!("sd_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create scratch schema");
        let options = PgConnectOptions::from_str(&url)
            .unwrap()
            .options([("search_path", schema.as_str())]);
        let setup = PgPoolOptions::new().connect_with(options).await.unwrap();
        sqlx::raw_sql(
            "CREATE TABLE vector_entries (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, blob_id TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&setup)
        .await
        .unwrap();
        for (id, owner, blob_id) in rows {
            sqlx::query("INSERT INTO vector_entries(id,owner,blob_id) VALUES($1,$2,$3)")
                .bind(id)
                .bind(owner)
                .bind(blob_id)
                .execute(&setup)
                .await
                .unwrap();
        }
        let legacy = LegacyDb::new_with_search_path(&url, Some(&schema))
            .await
            .unwrap();
        Some((legacy, admin, schema))
    }

    #[test]
    fn sqlx_lock_id_matches_known_neondb_dump() {
        // Values taken from a live Neon/sqlx lock-id dump.
        assert_eq!(crc32_iso_hdlc(b"neondb"), 1_372_559_388);
        assert_eq!(sqlx_migration_lock_id("neondb"), 1_409_249_852_220_689_736);
    }

    #[test]
    fn lock_timeout_sqlstates_are_retryable() {
        assert!(sqlstate_is_lock_contention("55P03"));
        assert!(sqlstate_is_lock_contention("40P01"));
        assert!(sqlstate_is_lock_contention("55p03"));
        assert!(!sqlstate_is_lock_contention("57014")); // statement_timeout
        assert!(!sqlstate_is_lock_contention("42P01")); // undefined_table
    }

    #[test]
    fn migrate_errors_classify_on_sqlstate_not_display_text() {
        let lock_timeout = sqlx::Error::Database(Box::new(FakeDbError {
            message: "the wording changed in a future postgres",
            code: Some("55P03"),
        }));
        assert!(sqlx_error_is_lock_contention(&lock_timeout));
        assert!(migrate_error_is_lock_contention(
            &sqlx::migrate::MigrateError::Execute(lock_timeout)
        ));

        let statement_timeout = sqlx::Error::Database(Box::new(FakeDbError {
            message: "canceling statement due to lock timeout",
            code: Some("57014"),
        }));
        assert!(!sqlx_error_is_lock_contention(&statement_timeout));
        assert!(!migrate_error_is_lock_contention(
            &sqlx::migrate::MigrateError::Execute(statement_timeout)
        ));

        let missing_code_lock = sqlx::Error::Database(Box::new(FakeDbError {
            message: "canceling statement due to lock timeout",
            code: None,
        }));
        assert!(sqlx_error_is_lock_contention(&missing_code_lock));

        let missing_code_other = sqlx::Error::Database(Box::new(FakeDbError {
            message: "relation \"vector_entries\" does not exist",
            code: None,
        }));
        assert!(!sqlx_error_is_lock_contention(&missing_code_other));
    }

    #[derive(Debug)]
    struct FakeDbError {
        message: &'static str,
        code: Option<&'static str>,
    }

    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.message)
        }
    }

    impl std::error::Error for FakeDbError {}

    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            self.message
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            self.code.map(std::borrow::Cow::Borrowed)
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
    }

    #[tokio::test]
    #[ignore]
    async fn legacy_migration_trigger_captures_new_inserts_and_seed_is_idempotent() {
        let Some((legacy, admin, schema)) = fixture_with_rows(&[("1", "0xa", "pre")]).await else {
            return;
        };
        sqlx::query("INSERT INTO vector_entries (id, owner, blob_id) VALUES ('2','0xa','post')")
            .execute(legacy.pool())
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM delete_blobs_tracking")
            .fetch_one(legacy.pool())
            .await
            .unwrap();
        assert_eq!(count, 2);
        let pre_scope: String =
            sqlx::query_scalar("SELECT scope FROM delete_blobs_tracking WHERE blob_id = 'pre'")
                .fetch_one(legacy.pool())
                .await
                .unwrap();
        assert_eq!(pre_scope, "legacy");
        let post_scope: String =
            sqlx::query_scalar("SELECT scope FROM delete_blobs_tracking WHERE blob_id = 'post'")
                .fetch_one(legacy.pool())
                .await
                .unwrap();
        assert_eq!(post_scope, "current");
        let url = std::env::var("TEST_LEGACY_DATABASE_URL").unwrap();
        let reopened = LegacyDb::new_with_search_path(&url, Some(&schema))
            .await
            .unwrap();
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                .fetch_all(reopened.pool())
                .await
                .unwrap();
        assert_eq!(versions, vec![1, 2, 3]);
        drop(reopened);
        drop(legacy);
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn ensure_distinct_from_primary_rejects_same_schema_and_accepts_different() {
        let Some(url) = std::env::var("TEST_LEGACY_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()
        else {
            return;
        };
        let Ok(admin) = sqlx::PgPool::connect(&url).await else {
            return;
        };
        let schema_a = format!("sd_test_a_{}", Uuid::new_v4().simple());
        let schema_b = format!("sd_test_b_{}", Uuid::new_v4().simple());
        for s in [&schema_a, &schema_b] {
            sqlx::query(&format!("CREATE SCHEMA {s}"))
                .execute(&admin)
                .await
                .unwrap();
        }

        let pool_a = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(
                PgConnectOptions::from_str(&url)
                    .unwrap()
                    .options([("search_path", schema_a.as_str())]),
            )
            .await
            .unwrap();

        // 1. Same database and same schema must be rejected
        let same_res = LegacyDb::ensure_distinct_from_primary(&pool_a, &url, Some(&schema_a)).await;
        assert!(same_res.is_err());
        assert!(same_res.unwrap_err().to_string().contains(
            "LEGACY_DB_URL points to the same PostgreSQL database and schema as DATABASE_URL"
        ));

        // 2. Same database but different schemas must be accepted
        let diff_res = LegacyDb::ensure_distinct_from_primary(&pool_a, &url, Some(&schema_b)).await;
        assert!(diff_res.is_ok());

        drop(pool_a);
        for s in [&schema_a, &schema_b] {
            sqlx::query(&format!("DROP SCHEMA {s} CASCADE"))
                .execute(&admin)
                .await
                .unwrap();
        }
    }
}

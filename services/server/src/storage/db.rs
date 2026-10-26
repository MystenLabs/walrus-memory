use std::sync::Arc;

use pgvector::Vector;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use std::collections::HashSet;
use std::sync::atomic::AtomicBool;

use crate::alerts::AlertManager;
use crate::types::{AppError, SearchHit};

/// Keep the first hit for each `blob_id` (closest: callers already order by
/// cosine distance). `vector_entries` has no UNIQUE on blob_id, so a
/// remember retry or restore can insert a second row for the same Walrus
/// blob; returning both spends `limit` on one memory (WALM-594 / GH #694).
pub(crate) fn unique_hits_by_blob_id(hits: Vec<SearchHit>) -> Vec<SearchHit> {
    let mut seen = HashSet::with_capacity(hits.len());
    hits.into_iter()
        .filter(|hit| seen.insert(hit.blob_id.clone()))
        .collect()
}

/// ANN over-fetch ceiling: `fetch_limit <= limit * this`. Stops a
/// single heavily duplicated nearest blob from walking the whole
/// namespace one unique-shortfall at a time.
const SEARCH_SIMILAR_OVERFETCH_FACTOR: usize = 4;

/// Next ANN `LIMIT` after collapsing `dropped` duplicate rows from a
/// full page. Grows by the observed duplicate count in the current
/// window (not `limit + dropped`, which only adds the unique shortfall).
/// `None` means stop: no dups, no growth, or the cap is hit.
pub(crate) fn next_search_fetch_limit(
    limit: usize,
    fetch_limit: usize,
    dropped: usize,
) -> Option<usize> {
    if dropped == 0 {
        return None;
    }
    let cap = limit.saturating_mul(SEARCH_SIMILAR_OVERFETCH_FACTOR).max(limit);
    if fetch_limit >= cap {
        return None;
    }
    let next = fetch_limit.saturating_add(dropped).min(cap);
    (next > fetch_limit).then_some(next)
}

/// Tombstone retention for both the read-API `must_resync` clock and the
/// background sweep. Keep a single constant so the two cannot drift.
pub const TOMBSTONE_RETENTION: chrono::Duration = chrono::Duration::days(30);

/// One migration file, paired with the name the pipeline reports it by.
type Migration = (&'static str, &'static str);

/// Pairs a migration's file name with its embedded contents so the two
/// cannot drift apart.
macro_rules! migration {
    ($file:literal) => {
        ($file, include_str!(concat!("../../migrations/", $file)))
    };
}

/// The migration pipeline, split at the two points where `VectorDb::new`
/// has to run Rust in between files.
///
/// This stays an explicit, hand-ordered list rather than a
/// `sqlx::migrate!` directory scan, for three reasons that all still
/// hold:
///
/// 1. `014_storage_reservations.sql` must run *before*
///    `014_memory_read_api_columns.sql` — the reverse of their
///    alphabetical order.
/// 2. Two files share the version number `014`, which `sqlx::migrate!`
///    rejects outright.
/// 3. `backfill_updated_at` and `recover_invalid_concurrent_indexes` are
///    Rust steps that have to land between specific files.
///
/// What is no longer manual is *completeness*: every `.sql` file in
/// `services/server/migrations` must appear in one of these three
/// slices, and `every_migration_file_is_wired_into_the_pipeline` fails
/// the test suite if one does not. The original 021 ADD reached
/// origin/dev as a file but never entered this list, which is why the
/// check exists. This 021 is the DROP of that column, for environments
/// that ran a PR-branch build that did wire the ADD.
const MIGRATIONS_BEFORE_BACKFILL: &[Migration] = &[
    migration!("001_init.sql"),
    migration!("002_add_namespace.sql"),
    migration!("003_rate_limiter.sql"),
    migration!("004_delegate_key_cache_expires.sql"),
    migration!("005_remember_jobs.sql"),
    // composite index on (owner, status, updated_at DESC) for bulk poll
    migration!("006_bulk_remember.sql"),
    // collapse per-wallet Apalis queues to a single `wallet_jobs` queue.
    // Equivocation locks are no longer a practical concern on Sui (per
    // Will Bradley, Mysten, 2026-05-12); concurrent workers on one wallet
    // + retry handling is sufficient.
    migration!("007_collapse_wallet_queues.sql"),
    // nullable `plaintext` column for benchmark-mode storage
    // (PlaintextEngine). NULL for all production rows — additive.
    // Renumbered from 007 -> 008 during rebase onto dev to avoid collision
    // with the wallet-queue collapse migration.
    migration!("008_benchmark_plaintext.sql"),
    // importance signal column on vector_entries.
    migration!("009_importance_signal.sql"),
    // Permanent restore-failure negative cache (GH #501 / WALM-299).
    migration!("010_restore_failed_blobs.sql"),
    // MCP OAuth 2.1 (Claude custom connectors): client registry,
    // server-custodied delegate keys, and authorization state.
    migration!("011_mcp_oauth.sql"),
    // Durable idempotency, preparation, and paid-upload recovery state.
    migration!("012_remember_write_idempotency.sql"),
    // Build the owner/key uniqueness constraint without blocking writes.
    migration!("013_remember_write_idempotency_index.sql"),
    // per-owner storage quota reservations. Makes quota admission atomic
    // with the eventual insert (GH #532 / WALM-359).
    migration!("014_storage_reservations.sql"),
    // owner-scoped read API: updated_at cursor column + agent_id/package_id.
    // Split across 014-019 (see each file's header, and
    // backfill_updated_at's / recover_invalid_concurrent_indexes's doc
    // comments below) to avoid holding ACCESS EXCLUSIVE across the
    // full-table backfill or the index build.
    migration!("014_memory_read_api_columns.sql"),
];

/// Applied after `backfill_updated_at`: 015 validates NOT NULL and will
/// error if any `updated_at` row is still NULL.
const MIGRATIONS_AFTER_BACKFILL: &[Migration] =
    &[migration!("015_memory_read_api_updated_at_not_null.sql")];

/// Applied after `recover_invalid_concurrent_indexes`, which must precede
/// every `CREATE INDEX CONCURRENTLY IF NOT EXISTS` in this slice — 016,
/// 018 and 022. Each of those would otherwise silently no-op forever
/// against a permanently INVALID index left behind by an interrupted
/// build. Every such index is registered in
/// `CONCURRENTLY_BUILT_INDEXES`; a new one added to this slice without
/// being registered fails
/// `every_concurrently_built_index_is_registered_for_recovery`.
const MIGRATIONS_AFTER_INDEX_RECOVERY: &[Migration] = &[
    // keyset-pagination index for the memories listing endpoint.
    // Must stay in its own file/transaction — see 016's header comment.
    migration!("016_memory_read_api_index.sql"),
    // per-memory expiry columns.
    migration!("017_memory_expiry_columns.sql"),
    // index on expiry_synced_at so the periodic expiry refresh sweep
    // doesn't full-scan vector_entries every tick. Must stay in its own
    // file/transaction — see 018's header comment.
    migration!("018_memory_expiry_synced_at_index.sql"),
    // Finalizes updated_at NOT NULL cheaply using the validated CHECK
    // constraint 015 set up — see 019's header.
    migration!("019_memory_read_api_updated_at_set_not_null.sql"),
    migration!("020_read_api_followups.sql"),
    // Drops failure_reported_at if a preview deploy created it. IF EXISTS,
    // so a database that never had the column (CI, origin/dev-only) is fine.
    migration!("021_drop_failed_write_report_ack.sql"),
    // Partial index for /health recent_write_outcomes. CONCURRENTLY, own
    // file — see 022's header.
    migration!("022_remember_jobs_recent_outcomes.sql"),
    // Balance samples and sponsored-transaction log for the admin spend view.
    migration!("023_admin_activity.sql"),
    // deleted_at range index for the admin activity delete counts.
    // CONCURRENTLY, own file -- see 024's header.
    migration!("024_memory_tombstones_deleted_at_index.sql"),
];

/// Every migration the pipeline applies, in the order it applies them.
#[cfg(test)]
fn all_migrations() -> impl Iterator<Item = &'static Migration> {
    MIGRATIONS_BEFORE_BACKFILL
        .iter()
        .chain(MIGRATIONS_AFTER_BACKFILL)
        .chain(MIGRATIONS_AFTER_INDEX_RECOVERY)
}

/// Applies one slice of the pipeline, naming the file that failed.
async fn run_migrations(pool: &PgPool, migrations: &[Migration]) -> Result<(), AppError> {
    for (name, sql) in migrations {
        sqlx::raw_sql(sql)
            .execute(pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to run migration {}: {}", name, e)))?;
    }
    Ok(())
}

/// Same as `run_migrations`, but on a held session — used so recover +
/// `CREATE INDEX CONCURRENTLY` share the advisory lock that serializes
/// replica boots.
async fn run_migrations_on(
    conn: &mut PgConnection,
    migrations: &[Migration],
) -> Result<(), AppError> {
    for (name, sql) in migrations {
        sqlx::raw_sql(sql)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to run migration {}: {}", name, e)))?;
    }
    Ok(())
}
/// The recall query. `search_similar` is the hottest read in the service and
/// the `ORDER BY embedding <=> $1 LIMIT $4` shape is what lets the planner
/// drive off the HNSW index (`idx_vector_entries_embedding`, migration 001).
const SEARCH_SIMILAR_SQL: &str =
    "SELECT blob_id, (embedding <=> $1)::float8 AS distance, created_at, importance
             FROM vector_entries
             WHERE owner = $2 AND namespace = $3
             ORDER BY embedding <=> $1
             LIMIT $4";

/// `SEARCH_SIMILAR_SQL` with the memories the security-delete subsystem has
/// already claimed hidden (WALM-592).
///
/// Anti-join rather than a soft-delete column: migration 020 keeps deletion
/// state out of `vector_entries` on purpose. `delete_blobs_tracking`'s primary
/// key is `(owner, blob_id)` — the anti-join key — so the HNSW scan still
/// drives the plan and no new index is needed.
///
/// Only the three states where the Walrus Blob object is gone or going are
/// filtered. `expired` in particular must stay visible: `terminal_state`
/// applies `EXPIRY_MARGIN_EPOCHS` ahead of the real lapse, so filtering it
/// would retire live memories early. The state list is pinned against the
/// store's own constants by
/// `pending_delete_filter_matches_the_security_delete_store`.
const SEARCH_SIMILAR_EXCLUDING_PENDING_DELETES_SQL: &str =
    "SELECT v.blob_id, (v.embedding <=> $1)::float8 AS distance, v.created_at, v.importance
             FROM vector_entries v
             WHERE v.owner = $2 AND v.namespace = $3
               AND NOT EXISTS (
                     SELECT 1 FROM delete_blobs_tracking t
                     WHERE t.owner = v.owner
                       AND t.blob_id = v.blob_id
                       AND t.state IN ('deleting', 'deleted', 'deleted_external')
                   )
             ORDER BY v.embedding <=> $1
             LIMIT $4";

/// One `vector_entries` row queued for an all-or-nothing batch insert.
///
/// Mirrors the argument list of [`VectorDb::insert_vector`]; see that method
/// for the meaning of each field. Used by [`VectorDb::insert_vectors_atomic`]
/// so callers that persist a whole batch (namespace restore) can hand over
/// every row up front instead of issuing one autocommitted INSERT per row.
pub struct VectorInsert<'a> {
    pub id: &'a str,
    pub owner: &'a str,
    pub namespace: &'a str,
    pub blob_id: &'a str,
    pub vector: &'a [f32],
    pub blob_size_bytes: i64,
    pub importance: f32,
    pub agent_id: Option<&'a str>,
    pub package_id: Option<&'a str>,
    pub end_epoch: Option<i32>,
}

pub struct VectorDb {
    pool: PgPool,
    storage_alerts: Option<(Arc<AlertManager>, String)>,
    /// Whether this database carries the security-delete subsystem's
    /// `delete_blobs_tracking` table, and recall therefore has to hide the
    /// memories it has claimed for deletion (WALM-592). Interior mutability
    /// because that table is created by `migrations_legacy` — applied by
    /// `LegacyDb` *after* `VectorDb::new()` has already run — so the answer
    /// can change once, from `false` to `true`, during boot. See
    /// `refresh_pending_delete_filter`.
    pending_delete_filter: AtomicBool,
}

/// Serialises `VectorDb::new()` across the test binary.
///
/// The migration chain is idempotent per statement but NOT safe to run
/// concurrently: `CREATE TABLE IF NOT EXISTS` is not atomic in Postgres, so two
/// tests that build a db at the same moment race inside migration 011 and one
/// loses with `duplicate key value violates unique constraint
/// "pg_type_typname_nsp_index"` on `mcp_oauth_clients`. Tests then fail on an
/// unreachable database rather than on anything they assert. `jobs::tests`
/// already guards its pool this way; these modules did not, which left the race
/// latent until a test was added.
#[cfg(test)]
static DB_SETUP_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

/// Builds a test `VectorDb`, retrying when Postgres aborts the migration
/// replay with a deadlock (40P01).
///
/// `DB_SETUP_LOCK` only orders setups against each other. Migration 020 locks
/// `memory_tombstones` then `vector_entries`, while `insert_vector` from a test
/// that is already running locks them in the opposite order, so CI sometimes
/// aborts the setup (`stale_sweep_tests::orphaned_preparation_is_failed`).
/// Every migration is idempotent, so replaying the setup is safe.
#[cfg(test)]
pub(crate) async fn test_vector_db(database_url: &str) -> VectorDb {
    let _guard = DB_SETUP_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let mut attempt = 0u64;
    loop {
        match VectorDb::new(database_url).await {
            Ok(db) => return db,
            Err(err) if attempt < 5 && err.to_string().contains("deadlock detected") => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_millis(50 * attempt)).await;
            }
            Err(err) => panic!("test database must be reachable with pgvector installed: {err:?}"),
        }
    }
}

impl VectorDb {
    pub fn with_storage_alerts(self, alerts: Arc<AlertManager>, sui_network: String) -> Self {
        Self {
            storage_alerts: Some((alerts, sui_network)),
            ..self
        }
    }

    async fn maybe_alert_storage_exhausted(&self, err: &sqlx::Error) {
        let Some((alerts, network)) = &self.storage_alerts else {
            return;
        };
        crate::alerts::maybe_alert_sqlx_postgres_storage_exhausted(alerts, network, err).await;
    }
}

#[cfg(test)]
impl VectorDb {
    pub(crate) fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            storage_alerts: None,
            pending_delete_filter: AtomicBool::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;
    use std::time::Duration;

    use sqlx::postgres::PgPoolOptions;

    use super::{oauth_rows, VectorDb, VectorInsert};

    static VECTOR_SCHEMA_SETUP_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

    /// Looks a migration up in the pipeline by file name.
    ///
    /// Test helpers below build deliberately partial schemas — only the
    /// tables a given module touches — so they cannot just replay the
    /// whole pipeline. Going through this lookup still keeps them from
    /// drifting: a renamed or deleted migration panics here by name
    /// instead of failing later as a missing column.
    fn migration_sql(name: &str) -> &'static str {
        super::all_migrations()
            .find(|(n, _)| *n == name)
            .map(|(_, sql)| *sql)
            .unwrap_or_else(|| panic!("migration {name} is not wired into the pipeline"))
    }

    fn is_pg_deadlock(error: &sqlx::Error) -> bool {
        error
            .as_database_error()
            .and_then(|db| db.code())
            .is_some_and(|code| code.as_ref() == "40P01")
    }

    /// Replays an idempotent migration while other tests are writing.
    ///
    /// A multi-statement file holds every lock until it commits. Migration
    /// 020 locks `memory_tombstones` and then `vector_entries`.
    /// `insert_vector` locks those tables in the opposite order, so Postgres
    /// aborts one side with `40P01`. Each statement is idempotent, so the
    /// aborted setup is safe to run again.
    async fn execute_idempotent_migration(pool: &sqlx::PgPool, sql: &str) {
        let mut conn = pool.acquire().await.expect("test database connection");
        let mut last_err = None;
        for attempt in 0..5 {
            match sqlx::raw_sql(sql).execute(&mut *conn).await {
                Ok(_) => return,
                Err(err) if is_pg_deadlock(&err) => {
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    last_err = Some(err);
                    tokio::time::sleep(Duration::from_millis(25 * (attempt as u64 + 1))).await;
                }
                Err(err) => panic!("test migration failed: {err}"),
            }
        }
        panic!(
            "test migration deadlocked after retries: {}",
            last_err.expect("deadlock error")
        );
    }

    /// Every `.sql` file in `services/server/migrations` must be wired
    /// into the pipeline.
    #[test]
    fn every_migration_file_is_wired_into_the_pipeline() {
        use std::collections::BTreeSet;

        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
        let on_disk: BTreeSet<String> = std::fs::read_dir(dir)
            .expect("migrations directory should be readable")
            .map(|entry| {
                entry
                    .expect("migrations directory entry should be readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.ends_with(".sql"))
            .collect();

        let wired: BTreeSet<String> = super::all_migrations()
            .map(|(name, _)| (*name).to_owned())
            .collect();

        let unwired: Vec<&String> = on_disk.difference(&wired).collect();
        assert!(
            unwired.is_empty(),
            "migration file(s) exist on disk but are not applied by VectorDb::new: {unwired:?}. \
             Add them to MIGRATIONS_BEFORE_BACKFILL / _AFTER_BACKFILL / \
             _AFTER_INDEX_RECOVERY in the position the pipeline needs."
        );

        let missing: Vec<&String> = wired.difference(&on_disk).collect();
        assert!(
            missing.is_empty(),
            "pipeline references migration file(s) that no longer exist: {missing:?}"
        );
    }

    /// Every index a migration in `MIGRATIONS_AFTER_INDEX_RECOVERY` builds
    /// CONCURRENTLY must be registered in `CONCURRENTLY_BUILT_INDEXES`.
    ///
    /// Forgetting one fails silently, which is why it needs a test rather
    /// than a convention: an interrupted build leaves the index INVALID,
    /// `IF NOT EXISTS` then no-ops its migration on every later boot, and
    /// the query it served quietly falls back to a scan. 022 is the case
    /// that motivates the check -- it keeps `/health`'s write-outcome
    /// probe cheap, so losing it disables a silent-failure detector,
    /// silently.
    #[test]
    fn every_concurrently_built_index_is_registered_for_recovery() {
        use std::collections::BTreeSet;

        // `CREATE [UNIQUE] INDEX CONCURRENTLY [IF NOT EXISTS] <name>`,
        // whether the name sits with the keywords or the `ON` clause wraps
        // to the next line.
        fn index_name(statement: &str) -> Option<String> {
            let tokens: Vec<&str> = statement.split_whitespace().collect();
            let at = tokens.iter().position(|t| *t == "concurrently")?;
            let mut rest = &tokens[at + 1..];
            for keyword in ["if", "not", "exists"] {
                if rest.first() == Some(&keyword) {
                    rest = &rest[1..];
                }
            }
            rest.first()
                .map(|name| {
                    name.trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                        .to_owned()
                })
                .filter(|name| !name.is_empty())
        }

        let mut built: BTreeSet<String> = BTreeSet::new();
        for (file, sql) in super::MIGRATIONS_AFTER_INDEX_RECOVERY {
            for statement in sql.split(';') {
                // Drop comment lines so a file header that merely mentions
                // CREATE INDEX CONCURRENTLY is not read as one.
                let code = statement
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("--"))
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_lowercase();
                if !(code.contains("create")
                    && code.contains("index")
                    && code.contains("concurrently"))
                {
                    continue;
                }
                built.insert(
                    index_name(&code)
                        .unwrap_or_else(|| panic!("could not read an index name out of {file}")),
                );
            }
        }

        let registered: BTreeSet<String> = super::CONCURRENTLY_BUILT_INDEXES
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();

        let unregistered: Vec<&String> = built.difference(&registered).collect();
        assert!(
            unregistered.is_empty(),
            "index(es) built CONCURRENTLY but not registered for invalid-index \
             recovery: {unregistered:?}. Add them to CONCURRENTLY_BUILT_INDEXES, or an \
             interrupted build leaves them INVALID and their migration no-ops forever."
        );

        let stale: Vec<&String> = registered.difference(&built).collect();
        assert!(
            stale.is_empty(),
            "CONCURRENTLY_BUILT_INDEXES names index(es) that no migration in \
             MIGRATIONS_AFTER_INDEX_RECOVERY builds: {stale:?}"
        );
    }

    #[test]
    fn drop_invalid_concurrent_index_uses_if_exists() {
        let sql = super::drop_invalid_concurrent_index_sql("remember_jobs_recent_outcomes_idx");
        assert!(sql.to_ascii_uppercase().contains("CONCURRENTLY"), "{sql}");
        assert!(sql.to_ascii_uppercase().contains("IF EXISTS"), "{sql}");
        assert!(sql.contains("remember_jobs_recent_outcomes_idx"), "{sql}");
    }

    #[test]
    fn invalid_index_is_not_dropped_while_a_build_is_in_progress() {
        assert!(!super::should_drop_invalid_concurrent_index(true));
        assert!(super::should_drop_invalid_concurrent_index(false));
    }

    fn test_database_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }

    async fn test_db() -> Option<VectorDb> {
        let database_url = test_database_url()?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&database_url)
            .await
            .expect("test database should be available");

        // This test needs only the vector-entry schema. Avoid migrations for
        // unrelated job tables, whose test setup runs concurrently in this
        // binary and has a separate lock.
        let _guard = VECTOR_SCHEMA_SETUP_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        for migration in [
            migration_sql("001_init.sql"),
            migration_sql("002_add_namespace.sql"),
            migration_sql("003_rate_limiter.sql"),
            migration_sql("008_benchmark_plaintext.sql"),
            migration_sql("009_importance_signal.sql"),
            migration_sql("010_restore_failed_blobs.sql"),
            migration_sql("014_memory_read_api_columns.sql"),
        ] {
            execute_idempotent_migration(&pool, migration).await;
        }

        // Mirrors the ordering in VectorDb::new(): batched Rust backfill
        // must complete before 015 validates NOT NULL, and the invalid-
        // index recovery check must run before 016's CREATE INDEX
        // CONCURRENTLY IF NOT EXISTS.
        super::backfill_updated_at(&pool).await.unwrap();

        execute_idempotent_migration(
            &pool,
            migration_sql("015_memory_read_api_updated_at_not_null.sql"),
        )
        .await;

        super::recover_invalid_concurrent_indexes(&pool)
            .await
            .unwrap();

        for migration in [
            migration_sql("016_memory_read_api_index.sql"),
            migration_sql("017_memory_expiry_columns.sql"),
            migration_sql("018_memory_expiry_synced_at_index.sql"),
            migration_sql("019_memory_read_api_updated_at_set_not_null.sql"),
            migration_sql("020_read_api_followups.sql"),
        ] {
            execute_idempotent_migration(&pool, migration).await;
        }

        let db = VectorDb {
            pool,
            storage_alerts: None,
            pending_delete_filter: std::sync::atomic::AtomicBool::new(false),
        };
        // Mirror `VectorDb::new()`: whether recall filters pending security
        // deletes is decided by probing the database, not by the constructor.
        db.refresh_pending_delete_filter().await;
        Some(db)
    }

    /// Regression test for the migration-order fixes: batched Rust
    /// backfill, the CHECK/VALIDATE NOT NULL fast path split across
    /// migrations 015/019, and invalid-index recovery ahead of
    /// migration 016.
    ///
    /// Gated on a dedicated env var (rather than `DATABASE_URL`, which
    /// `test_db()` above already uses for the lighter-weight vector-only
    /// schema) so it never runs as part of the normal suite by accident —
    /// it exercises the FULL `VectorDb::new()` migration pipeline
    /// (001-019) end to end, which is disruptive to run against a
    /// database other tests share concurrently. Point
    /// `MIGRATION_PIPELINE_TEST_DATABASE_URL` at a throwaway local
    /// database to run it, e.g.:
    /// `createdb -h localhost -U memwal memwal_migration_test`.
    #[tokio::test]
    async fn full_migration_pipeline_runs_end_to_end() {
        let Ok(database_url) = std::env::var("MIGRATION_PIPELINE_TEST_DATABASE_URL") else {
            eprintln!("skipping: MIGRATION_PIPELINE_TEST_DATABASE_URL is not configured");
            return;
        };

        let db = VectorDb::new(&database_url)
            .await
            .expect("full migration pipeline should complete cleanly");

        let remaining_nulls: i64 =
            sqlx::query_scalar("SELECT count(*) FROM vector_entries WHERE updated_at IS NULL")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(
            remaining_nulls, 0,
            "backfill should have cleared every NULL updated_at row"
        );

        let index_valid: Option<bool> = sqlx::query_scalar(
            "SELECT indisvalid FROM pg_index JOIN pg_class ON pg_class.oid = pg_index.indexrelid \
             WHERE relname = 'idx_vector_entries_owner_updated_id'",
        )
        .fetch_optional(&db.pool)
        .await
        .unwrap();
        assert_eq!(
            index_valid,
            Some(true),
            "pagination index should exist and be valid"
        );

        let constraint_dropped: Option<String> = sqlx::query_scalar(
            "SELECT conname FROM pg_constraint WHERE conname = 'vector_entries_updated_at_not_null'",
        )
        .fetch_optional(&db.pool)
        .await
        .unwrap();
        assert_eq!(
            constraint_dropped, None,
            "the temporary CHECK constraint should have been dropped by migration 019"
        );

        // Running the whole pipeline a second time (simulating a restart)
        // must still be clean and idempotent.
        VectorDb::new(&database_url)
            .await
            .expect("second run of the full migration pipeline should also complete cleanly");
    }

    async fn oauth_test_db() -> Option<VectorDb> {
        let db = test_db().await?;
        sqlx::raw_sql(migration_sql("011_mcp_oauth.sql"))
            .execute(db.pool())
            .await
            .expect("OAuth migration must create tables on a fresh test database");
        Some(db)
    }

    #[tokio::test]
    async fn oauth_migration_011_creates_required_tables() {
        let Some(db) = oauth_test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let tables: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM information_schema.tables
             WHERE table_schema = current_schema()
               AND table_name IN ('mcp_oauth_clients', 'mcp_oauth_delegates',
                                  'mcp_oauth_authorize_sessions', 'mcp_oauth_codes',
                                  'mcp_oauth_grants', 'mcp_oauth_tokens')",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(tables.0, 6);
    }

    #[tokio::test]
    async fn concurrent_refresh_rotation_has_exactly_one_winner() {
        let Some(db) = oauth_test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let client_id = format!("mwc_{suffix}");
        let delegate_ref = format!("mwd_{suffix}");
        let grant_id = format!("mwg_{suffix}");
        let presented = crate::oauth::hash_token(&format!("mwr_{suffix}"));
        let now = chrono::Utc::now();

        sqlx::query(
            "INSERT INTO mcp_oauth_clients
             (client_id, client_name, redirect_uris, grant_types, response_types,
              token_endpoint_auth_method, scope, status)
             VALUES ($1, 'refresh concurrency test', ARRAY['http://localhost/callback'],
                     ARRAY['authorization_code','refresh_token'], ARRAY['code'],
                     'none', 'memwal:read offline_access', 'active')",
        )
        .bind(&client_id)
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO mcp_oauth_delegates
             (delegate_ref, account_id, owner_address, delegate_public_key,
              delegate_address, encrypted_private_key, label, status)
             VALUES ($1, $2, $3, $4, $5, 'v1.test.test', 'test', 'active')",
        )
        .bind(&delegate_ref)
        .bind(format!("account-{suffix}"))
        .bind(format!("owner-{suffix}"))
        .bind(hex::encode(uuid::Uuid::new_v4().as_bytes()).repeat(2))
        .bind(format!("address-{suffix}"))
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO mcp_oauth_grants
             (grant_id, client_id, delegate_ref, account_id, owner_address, scope, resource)
             VALUES ($1, $2, $3, $4, $5, 'memwal:read offline_access', 'https://example.test/api/mcp')",
        )
        .bind(&grant_id)
        .bind(&client_id)
        .bind(&delegate_ref)
        .bind(format!("account-{suffix}"))
        .bind(format!("owner-{suffix}"))
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO mcp_oauth_tokens (token_sha256, grant_id, token_type, expires_at)
             VALUES ($1, $2, 'refresh', $3)",
        )
        .bind(&presented)
        .bind(&grant_id)
        .bind(now + chrono::Duration::minutes(5))
        .execute(db.pool())
        .await
        .unwrap();

        let pair = |label: &str| {
            let access = oauth_rows::OAuthTokenRow {
                token_sha256: crate::oauth::hash_token(&format!("access-{label}-{suffix}")),
                grant_id: grant_id.clone(),
                token_type: "access".to_string(),
                expires_at: now + chrono::Duration::minutes(5),
            };
            let refresh = oauth_rows::OAuthTokenRow {
                token_sha256: crate::oauth::hash_token(&format!("refresh-{label}-{suffix}")),
                grant_id: grant_id.clone(),
                token_type: "refresh".to_string(),
                expires_at: now + chrono::Duration::minutes(10),
            };
            (access, refresh)
        };
        let (access_a, refresh_a) = pair("a");
        let (access_b, refresh_b) = pair("b");
        let first = db.rotate_oauth_refresh_token(&presented, &client_id, &access_a, &refresh_a);
        let second = db.rotate_oauth_refresh_token(&presented, &client_id, &access_b, &refresh_b);
        let (first, second) = tokio::join!(first, second);
        let winners =
            usize::from(first.unwrap().is_some()) + usize::from(second.unwrap().is_some());
        assert_eq!(
            winners, 1,
            "a refresh token must have exactly one concurrent consumer"
        );

        sqlx::query("DELETE FROM mcp_oauth_clients WHERE client_id = $1")
            .bind(&client_id)
            .execute(db.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn expired_blob_cleanup_is_namespace_scoped() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xexpired-cleanup-owner-{suffix}");
        let blob_id = format!("expired-cleanup-blob-{suffix}");
        let queried_namespace = format!("queried-{suffix}");
        let other_namespace = format!("other-{suffix}");
        let vector = vec![0.0; 1536];

        db.insert_vector(
            &format!("queried-row-{suffix}"),
            &owner,
            &queried_namespace,
            &blob_id,
            &vector,
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        db.insert_vector(
            &format!("other-row-{suffix}"),
            &owner,
            &other_namespace,
            &blob_id,
            &vector,
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // Models the reactive Walrus-404 cleanup triggered while reading
        // `queried_namespace`. A reused ciphertext in another namespace must
        // remain indexed.
        assert_eq!(
            db.delete_by_blob_id(&blob_id, &owner, &queried_namespace)
                .await
                .unwrap(),
            1
        );

        let remaining: Vec<(String, String)> = sqlx::query_as(
            "SELECT namespace, blob_id FROM vector_entries
             WHERE owner = $1 ORDER BY namespace",
        )
        .bind(&owner)
        .fetch_all(db.pool())
        .await
        .unwrap();
        sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();

        assert_eq!(
            remaining,
            vec![(other_namespace, blob_id)],
            "the cleanup must not delete an identical blob_id in another namespace"
        );
    }

    fn hit(blob_id: &str, distance: f64) -> crate::types::SearchHit {
        crate::types::SearchHit {
            blob_id: blob_id.to_string(),
            distance,
            created_at: chrono::Utc::now(),
            importance: 0.5,
        }
    }

    #[test]
    fn unique_hits_by_blob_id_keeps_first_and_distinct() {
        let unique = super::unique_hits_by_blob_id(vec![
            hit("dup", 0.10),
            hit("dup", 0.10),
            hit("other", 0.20),
            hit("dup", 0.30),
        ]);
        let ids: Vec<&str> = unique.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(ids, vec!["dup", "other"]);
        assert_eq!(unique[0].distance, 0.10);
    }

    #[test]
    fn unique_hits_by_blob_id_empty() {
        assert!(super::unique_hits_by_blob_id(vec![]).is_empty());
    }

    #[test]
    fn next_search_fetch_limit_grows_by_dropped_not_unique_shortfall() {
        // limit=2, two copies of A: first page unique=1, dropped=1 → LIMIT 3.
        assert_eq!(super::next_search_fetch_limit(2, 2, 1), Some(3));
        // Three copies of A: LIMIT 3 is still all A (dropped=2) → LIMIT 5,
        // not stop after the first widen.
        assert_eq!(super::next_search_fetch_limit(2, 3, 2), Some(5));
        // Cap at limit * 4.
        assert_eq!(super::next_search_fetch_limit(2, 5, 4), Some(8));
        assert_eq!(super::next_search_fetch_limit(2, 8, 7), None);
    }

    #[test]
    fn next_search_fetch_limit_uniform_2x_at_http_cap() {
        // limit=100, half the page duplicate: grow by dropped (50), not
        // by unique shortfall alone. 100 → 150, then 150 → 225.
        assert_eq!(super::next_search_fetch_limit(100, 100, 50), Some(150));
        assert_eq!(super::next_search_fetch_limit(100, 150, 75), Some(225));
        assert_eq!(super::next_search_fetch_limit(100, 400, 50), None);
    }

    #[tokio::test]
    async fn search_similar_returns_each_blob_id_once() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xrecall-dedupe-owner-{suffix}");
        let namespace = format!("ns-{suffix}");
        let blob_id = format!("dup-blob-{suffix}");
        let other_blob = format!("other-blob-{suffix}");
        let query = vec![1.0_f32; 1536];
        let near = vec![1.0_f32; 1536];
        let far = {
            let mut v = vec![0.0_f32; 1536];
            v[0] = 1.0;
            v
        };

        db.insert_vector(
            &format!("row-a-{suffix}"),
            &owner,
            &namespace,
            &blob_id,
            &near,
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        db.insert_vector(
            &format!("row-b-{suffix}"),
            &owner,
            &namespace,
            &blob_id,
            &near,
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        db.insert_vector(
            &format!("row-c-{suffix}"),
            &owner,
            &namespace,
            &other_blob,
            &far,
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let hits = db
            .search_similar(&query, &owner, &namespace, 10)
            .await
            .unwrap();
        sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();

        let ids: Vec<&str> = hits.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(
            ids.iter().filter(|id| **id == blob_id).count(),
            1,
            "the remembered blob must appear once, not once per index row"
        );
        assert!(ids.contains(&blob_id.as_str()));
        assert!(ids.contains(&other_blob.as_str()));
        assert_eq!(ids.len(), 2);
    }

    #[tokio::test]
    async fn search_similar_fills_limit_when_duplicate_rows_crowd_the_window() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xrecall-dedupe-limit-{suffix}");
        let namespace = format!("ns-{suffix}");
        let blob_a = format!("blob-a-{suffix}");
        let blob_b = format!("blob-b-{suffix}");
        let query = vec![1.0_f32; 1536];
        let near = vec![1.0_f32; 1536];
        let far = {
            let mut v = vec![0.0_f32; 1536];
            v[0] = 1.0;
            v
        };

        db.insert_vector(
            &format!("row-a1-{suffix}"),
            &owner,
            &namespace,
            &blob_a,
            &near,
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        db.insert_vector(
            &format!("row-a2-{suffix}"),
            &owner,
            &namespace,
            &blob_a,
            &near,
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        db.insert_vector(
            &format!("row-b-{suffix}"),
            &owner,
            &namespace,
            &blob_b,
            &far,
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let hits = db
            .search_similar(&query, &owner, &namespace, 2)
            .await
            .unwrap();
        sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();

        let ids: Vec<&str> = hits.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(ids.len(), 2, "limit=2 must refill after collapsing blob A");
        assert!(ids.contains(&blob_a.as_str()));
        assert!(ids.contains(&blob_b.as_str()));
    }

    #[tokio::test]
    async fn search_similar_widens_again_when_three_copies_crowd_limit_two() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xrecall-dedupe-triple-{suffix}");
        let namespace = format!("ns-{suffix}");
        let blob_a = format!("blob-a-{suffix}");
        let blob_b = format!("blob-b-{suffix}");
        let query = vec![1.0_f32; 1536];
        let near = vec![1.0_f32; 1536];
        let far = {
            let mut v = vec![0.0_f32; 1536];
            v[0] = 1.0;
            v
        };

        for (row, blob, embedding) in [
            ("a1", blob_a.as_str(), &near),
            ("a2", blob_a.as_str(), &near),
            ("a3", blob_a.as_str(), &near),
            ("b", blob_b.as_str(), &far),
        ] {
            db.insert_vector(
                &format!("row-{row}-{suffix}"),
                &owner,
                &namespace,
                blob,
                embedding,
                1,
                0.5,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }

        let hits = db
            .search_similar(&query, &owner, &namespace, 2)
            .await
            .unwrap();
        sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();

        let ids: Vec<&str> = hits.iter().map(|h| h.blob_id.as_str()).collect();
        assert_eq!(
            ids.len(),
            2,
            "first widen (LIMIT 3) is still all A; second widen must include B"
        );
        assert!(ids.contains(&blob_a.as_str()));
        assert!(ids.contains(&blob_b.as_str()));
    }

    #[tokio::test]
    async fn insert_vector_persists_agent_and_package_id() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let id = format!("test-{}", uuid::Uuid::new_v4());

        db.insert_vector(
            &id,
            "0xtest-owner",
            "test-ns",
            "blob-1",
            &[0.1_f32; 1536],
            42,
            0.5,
            Some("agent-abc"),
            Some("0xpkg-123"),
            None,
        )
        .await
        .unwrap();

        let row: (Option<String>, Option<String>) =
            sqlx::query_as("SELECT agent_id, package_id FROM vector_entries WHERE id = $1")
                .bind(&id)
                .fetch_one(db.pool())
                .await
                .unwrap();

        assert_eq!(row.0.as_deref(), Some("agent-abc"));
        assert_eq!(row.1.as_deref(), Some("0xpkg-123"));

        let _ = sqlx::query("DELETE FROM vector_entries WHERE id = $1")
            .bind(&id)
            .execute(db.pool())
            .await;
    }

    #[tokio::test]
    async fn insert_vector_persists_end_epoch() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let id = format!("test-{}", uuid::Uuid::new_v4());

        db.insert_vector(
            &id,
            "0xtest-owner",
            "test-ns",
            "blob-1",
            &[0.1_f32; 1536],
            42,
            0.5,
            None,
            None,
            Some(457),
        )
        .await
        .unwrap();

        let row: (Option<i32>,) =
            sqlx::query_as("SELECT end_epoch FROM vector_entries WHERE id = $1")
                .bind(&id)
                .fetch_one(db.pool())
                .await
                .unwrap();

        assert_eq!(row.0, Some(457));

        let _ = sqlx::query("DELETE FROM vector_entries WHERE id = $1")
            .bind(&id)
            .execute(db.pool())
            .await;
    }

    /// Reproduces an Apalis retry re-entering `insert_vector` with the same
    /// primary key (`jobs.rs` sets `vector_id = remember_job_id`): the second
    /// call takes the `ON CONFLICT (id) DO UPDATE` branch. Console's
    /// `updated_after` incremental sync depends on `updated_at` actually
    /// advancing on that branch, not just the insert succeeding.
    #[tokio::test]
    async fn insert_vector_bumps_updated_at_on_conflict() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let id = format!("test-conflict-{}", uuid::Uuid::new_v4());

        db.insert_vector(
            &id,
            "0xtest-owner-conflict",
            "test-ns",
            "blob-1",
            &[0.1_f32; 1536],
            42,
            0.5,
            Some("agent-abc"),
            Some("0xpkg-123"),
            None,
        )
        .await
        .unwrap();

        let first_updated_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_as("SELECT updated_at FROM vector_entries WHERE id = $1")
                .bind(&id)
                .fetch_one(db.pool())
                .await
                .map(|(v,): (chrono::DateTime<chrono::Utc>,)| v)
                .unwrap();

        // Force a measurable time gap so a naive "insert succeeded" assertion
        // couldn't accidentally pass — the row must actually move forward.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Simulate the Apalis retry: same id, same conflict branch.
        db.insert_vector(
            &id,
            "0xtest-owner-conflict",
            "test-ns",
            "blob-1-retried",
            &[0.2_f32; 1536],
            43,
            0.5,
            Some("agent-abc"),
            Some("0xpkg-123"),
            None,
        )
        .await
        .unwrap();

        let second_updated_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_as("SELECT updated_at FROM vector_entries WHERE id = $1")
                .bind(&id)
                .fetch_one(db.pool())
                .await
                .map(|(v,): (chrono::DateTime<chrono::Utc>,)| v)
                .unwrap();

        assert!(
            second_updated_at > first_updated_at,
            "updated_at must advance on ON CONFLICT DO UPDATE (first={:?}, second={:?})",
            first_updated_at,
            second_updated_at
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE id = $1")
            .bind(&id)
            .execute(db.pool())
            .await;
    }

    #[tokio::test]
    async fn rows_needing_expiry_refresh_returns_null_and_stale_rows_only() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        // never synced (NULL expiry_synced_at) — should be selected
        db.insert_vector(
            &format!("{}-a", owner),
            &owner,
            "ns",
            "blob-a",
            &[0.0_f32; 1536],
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        // synced recently — should NOT be selected
        sqlx::query("INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes, expiry_synced_at) VALUES ($1, $2, 'ns', 'blob-b', $3, 1, NOW())")
            .bind(format!("{}-b", owner)).bind(&owner).bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .execute(db.pool()).await.unwrap();

        // synced 25 hours ago (stale, past a 24h threshold) — should be selected
        sqlx::query("INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes, expiry_synced_at) VALUES ($1, $2, 'ns', 'blob-c', $3, 1, NOW() - INTERVAL '25 hours')")
            .bind(format!("{}-c", owner)).bind(&owner).bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .execute(db.pool()).await.unwrap();

        // This shared local test database accumulates NULL/stale
        // expiry_synced_at rows across many prior test runs (thousands, in
        // practice), and ties among NULL values are unordered in Postgres.
        // A small limit (e.g. 10, as in the original design sketch) would
        // make this test flaky/order-dependent against that cruft — request
        // a limit generous enough to comfortably outrun it instead.
        let rows = db.rows_needing_expiry_refresh(50_000).await.unwrap();
        let blob_ids: std::collections::HashSet<_> = rows
            .iter()
            .filter(|r| r.0 == owner)
            .map(|r| r.2.clone())
            .collect();

        assert!(blob_ids.contains("blob-a"));
        assert!(blob_ids.contains("blob-c"));
        assert!(!blob_ids.contains("blob-b"));

        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await;
    }

    /// "Never touch updated_at" is a load-bearing plan constraint for the
    /// expiry sweep (Console's `updated_after` incremental sync depends on
    /// it not moving for reasons unrelated to the row's own content — see
    /// `insert_vector_bumps_updated_at_on_conflict` above for the positive
    /// case). Regression-protects the negative case for both new
    /// write-paths the sweep uses.
    #[tokio::test]
    async fn mark_expiry_scheduled_never_touches_updated_at() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let id = format!("test-expiry-scheduled-updated-at-{}", uuid::Uuid::new_v4());

        db.insert_vector(
            &id,
            "0xtest-owner-expiry-scheduled-updated-at",
            "test-ns",
            "blob-1",
            &[0.1_f32; 1536],
            42,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let original_updated_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_as("SELECT updated_at FROM vector_entries WHERE id = $1")
                .bind(&id)
                .fetch_one(db.pool())
                .await
                .map(|(v,): (chrono::DateTime<chrono::Utc>,)| v)
                .unwrap();

        // Force a measurable time gap so a naive "call succeeded" assertion
        // couldn't accidentally pass — updated_at must genuinely not move.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Pure bookkeeping (no API-visible field changes) — must never bump
        // updated_at, or every read that schedules a staleness check would
        // spuriously reappear in Console's incremental sync.
        db.mark_expiry_scheduled(&[id.clone()]).await.unwrap();

        let after_updated_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_as("SELECT updated_at FROM vector_entries WHERE id = $1")
                .bind(&id)
                .fetch_one(db.pool())
                .await
                .map(|(v,): (chrono::DateTime<chrono::Utc>,)| v)
                .unwrap();

        assert_eq!(
            original_updated_at, after_updated_at,
            "mark_expiry_scheduled must never touch updated_at"
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE id = $1")
            .bind(&id)
            .execute(db.pool())
            .await;
    }

    /// `set_memory_expiry` previously never bumped `updated_at` at all —
    /// deliberately, to avoid the ~24h re-verification sweep making every
    /// synced row reappear in Console's incremental sync — but that also
    /// meant the *first* real write (a row's expiry resolving from unknown
    /// to known) was invisible to a client that had already synced that
    /// row, silently breaking per-memory expiry tracking for exactly the
    /// rows synced before their expiry was known. The fix conditions the
    /// bump on the value actually changing (`IS DISTINCT FROM`, null-safe).
    /// This test pins all three cases: first real write bumps, an unchanged
    /// re-verification does not, and a genuine later change bumps again.
    #[tokio::test]
    async fn set_memory_expiry_bumps_updated_at_only_when_value_changes() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let id = format!("test-expiry-set-updated-at-{}", uuid::Uuid::new_v4());

        db.insert_vector(
            &id,
            "0xtest-owner-expiry-set-updated-at",
            "test-ns",
            "blob-1",
            &[0.1_f32; 1536],
            42,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let fetch_updated_at = |id: String, pool: sqlx::PgPool| async move {
            sqlx::query_as("SELECT updated_at FROM vector_entries WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .map(|(v,): (chrono::DateTime<chrono::Utc>,)| v)
                .unwrap()
        };

        let before_first_write = fetch_updated_at(id.clone(), db.pool().clone()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // First real write: NULL -> a real value. Must bump updated_at so a
        // client that already synced this row's still-unknown expiry sees
        // the populated value on its next incremental poll.
        let first_expires_at = chrono::Utc::now();
        db.set_memory_expiry(&id, 500, first_expires_at)
            .await
            .unwrap();
        let after_first_write = fetch_updated_at(id.clone(), db.pool().clone()).await;
        assert!(
            after_first_write > before_first_write,
            "the first real expiry write must bump updated_at (unsynced -> synced is a real \
             API-visible change), got before={:?} after={:?}",
            before_first_write,
            after_first_write
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Routine re-verification with the SAME end_epoch but a DIFFERENT
        // expires_at (the real caller recomputes expires_at from a fresh
        // `now()` on every sweep tick — see `expires_at_from_epoch` — so it
        // never matches the previous write byte-for-byte even when nothing
        // actually changed) must NOT bump updated_at, or every synced row
        // would spam Console's incremental sync roughly once a day
        // regardless of whether anything actually changed.
        let reverify_expires_at = first_expires_at + chrono::Duration::seconds(7);
        db.set_memory_expiry(&id, 500, reverify_expires_at)
            .await
            .unwrap();
        let after_reverify = fetch_updated_at(id.clone(), db.pool().clone()).await;
        assert_eq!(
            after_first_write, after_reverify,
            "re-verifying with an unchanged end_epoch (even with a recomputed expires_at) \
             must not bump updated_at"
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // A genuine later change (e.g. the on-chain lease was extended,
        // moving end_epoch) must bump updated_at again — this is a real
        // content change, not routine housekeeping.
        let second_expires_at = first_expires_at + chrono::Duration::hours(1);
        db.set_memory_expiry(&id, 501, second_expires_at)
            .await
            .unwrap();
        let after_real_change = fetch_updated_at(id.clone(), db.pool().clone()).await;
        assert!(
            after_real_change > after_reverify,
            "a genuine end_epoch/expires_at change must bump updated_at, got prior={:?} \
             after={:?}",
            after_reverify,
            after_real_change
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE id = $1")
            .bind(&id)
            .execute(db.pool())
            .await;
    }

    /// The mainline write path, which the test above does not reach.
    ///
    /// `insert_vector` writes `end_epoch` but never `expires_at`. So when the
    /// sweep first resolves that row, `end_epoch` is already equal and only
    /// `expires_at` changes. Guarding the bump on `end_epoch` alone made that
    /// write invisible to incremental sync: a client that synced the row in
    /// the up-to-5-minute window before the sweep kept `expires_at: null`
    /// forever, which is the whole of WALM-296 silently not working.
    #[tokio::test]
    async fn set_memory_expiry_bumps_updated_at_when_only_expires_at_appears() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let id = format!("test-expiry-inserted-end-epoch-{}", uuid::Uuid::new_v4());

        // end_epoch supplied at INSERT, exactly as the wallet-job path does.
        db.insert_vector(
            &id,
            "0xtest-owner-expiry-inserted-end-epoch",
            "test-ns",
            "blob-1",
            &[0.1_f32; 1536],
            42,
            0.5,
            None,
            None,
            Some(500),
        )
        .await
        .unwrap();

        let fetch_updated_at = |id: String, pool: sqlx::PgPool| async move {
            sqlx::query_as("SELECT updated_at FROM vector_entries WHERE id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .map(|(v,): (chrono::DateTime<chrono::Utc>,)| v)
                .unwrap()
        };

        let before = fetch_updated_at(id.clone(), db.pool().clone()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Same end_epoch the row already carries; only expires_at changes.
        db.set_memory_expiry(&id, 500, chrono::Utc::now())
            .await
            .unwrap();
        let after = fetch_updated_at(id.clone(), db.pool().clone()).await;
        assert!(
            after > before,
            "populating expires_at on a row that already had end_epoch must bump updated_at, \
             otherwise the row never re-enters incremental sync and the client keeps null \
             forever; got before={:?} after={:?}",
            before,
            after
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE id = $1")
            .bind(&id)
            .execute(db.pool())
            .await;
    }

    // ── find_account_by_owner (backs GET /api/accounts/{owner}/exists) ──
    //
    // `accounts` is populated by the v2-indexer from onchain
    // `AccountCreated` events, not by this server. This test simulates
    // that indexer write directly (a raw INSERT) rather than driving it
    // through any server code path, since the indexer itself is a
    // separate service/binary outside this crate.

    #[tokio::test]
    async fn find_account_by_owner_reflects_indexed_accounts_table() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xaccount-exists-owner-{suffix}");
        let account_id = format!("account-{suffix}");

        // No indexed row yet — an address that has never created a
        // MemWalAccount (or whose AccountCreated event hasn't been
        // indexed yet) must resolve to `None`.
        assert_eq!(db.find_account_by_owner(&owner).await.unwrap(), None);

        // Simulate the v2-indexer inserting a row after observing
        // `AccountCreated` onchain.
        sqlx::query("INSERT INTO accounts (account_id, owner) VALUES ($1, $2)")
            .bind(&account_id)
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();

        assert_eq!(
            db.find_account_by_owner(&owner).await.unwrap(),
            Some(account_id.clone())
        );

        sqlx::query("DELETE FROM accounts WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();
    }

    /// `find_account_by_owner` is an exact, case-sensitive match — it does
    /// not itself lowercase the input. `accounts.owner` is always indexed
    /// in lowercase hex by the v2-indexer (`hex::encode` in
    /// `services/indexer/src/handler.rs`), so callers (the
    /// `account_exists` route handler) are responsible for lowercasing the
    /// caller-supplied address before calling this function. This test
    /// pins down both halves of that contract: an uppercase/mixed-case
    /// lookup against a lowercase-indexed row misses without
    /// normalization, and hits once the same normalization the handler
    /// applies (`to_ascii_lowercase`) is applied here too.
    #[tokio::test]
    async fn find_account_by_owner_is_case_sensitive_requiring_caller_normalization() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        // Indexed rows are always lowercase, mirroring the indexer's
        // `hex::encode` output.
        let owner_lower = format!("0xcase-owner-{suffix}").to_ascii_lowercase();
        let owner_upper = owner_lower.to_ascii_uppercase();
        let account_id = format!("account-case-{suffix}");

        sqlx::query("INSERT INTO accounts (account_id, owner) VALUES ($1, $2)")
            .bind(&account_id)
            .bind(&owner_lower)
            .execute(db.pool())
            .await
            .unwrap();

        // Without normalization, an uppercase/mixed-case address for an
        // account that DOES exist would false-negative — this is the bug
        // the route handler's `to_ascii_lowercase()` fixes.
        assert_eq!(
            db.find_account_by_owner(&owner_upper).await.unwrap(),
            None,
            "find_account_by_owner must not silently case-fold internally \
             (that would defeat the btree index via a query-side LOWER())"
        );

        // The handler's normalization step, applied here, must resolve to
        // the same account as the canonical lowercase lookup.
        assert_eq!(
            db.find_account_by_owner(&owner_upper.to_ascii_lowercase())
                .await
                .unwrap(),
            Some(account_id.clone())
        );

        sqlx::query("DELETE FROM accounts WHERE owner = $1")
            .bind(&owner_lower)
            .execute(db.pool())
            .await
            .unwrap();
    }

    // ── Restore persists its batch atomically (GH #566 / WALM-591) ──

    /// Build one restore-shaped batch row. Passing a `vector` of the wrong
    /// length plants a row the `vector(1536)` column will reject, which is how
    /// the rollback test forces a failure partway through the batch.
    fn restore_row<'a>(
        id: &'a str,
        owner: &'a str,
        namespace: &'a str,
        blob_id: &'a str,
        vector: &'a [f32],
    ) -> VectorInsert<'a> {
        VectorInsert {
            id,
            owner,
            namespace,
            blob_id,
            vector,
            blob_size_bytes: 1,
            importance: 0.5,
            agent_id: None,
            package_id: None,
            end_epoch: None,
        }
    }

    async fn rows_for_owner(db: &VectorDb, owner: &str, namespace: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM vector_entries WHERE owner = $1 AND namespace = $2",
        )
        .bind(owner)
        .bind(namespace)
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    async fn delete_rows_for_owner(db: &VectorDb, owner: &str) {
        sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(owner)
            .execute(db.pool())
            .await
            .unwrap();
    }

    /// A row that fails partway through must not leave earlier rows committed.
    #[tokio::test]
    async fn restore_batch_insert_rolls_back_every_row_when_one_fails() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xrestore-rollback-{suffix}");
        let namespace = format!("ns-{suffix}");
        let ids: Vec<String> = (0..3)
            .map(|i| format!("restore-rollback-{i}-{suffix}"))
            .collect();
        let blob_ids: Vec<String> = (0..3)
            .map(|i| format!("blob-rollback-{i}-{suffix}"))
            .collect();
        let good = vec![0.1_f32; 1536];
        // The middle row's embedding has the wrong dimension, so Postgres
        // rejects it *after* the first row has already been written inside the
        // transaction. Before the fix that first row stayed committed.
        let bad = vec![0.1_f32; 8];

        let batch = vec![
            restore_row(&ids[0], &owner, &namespace, &blob_ids[0], &good),
            restore_row(&ids[1], &owner, &namespace, &blob_ids[1], &bad),
            restore_row(&ids[2], &owner, &namespace, &blob_ids[2], &good),
        ];

        let result = db.insert_vectors_atomic(&batch).await;
        assert!(
            result.is_err(),
            "a batch containing an invalid row must report an explicit error"
        );

        let landed = rows_for_owner(&db, &owner, &namespace).await;
        delete_rows_for_owner(&db, &owner).await;
        assert_eq!(
            landed, 0,
            "a failed restore batch must leave zero rows, not a partial index"
        );
    }

    /// The success path still has to commit the whole batch — the rollback fix
    /// must not turn restore into a no-op.
    #[tokio::test]
    async fn restore_batch_insert_commits_every_row_on_success() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xrestore-commit-{suffix}");
        let namespace = format!("ns-{suffix}");
        let ids: Vec<String> = (0..3)
            .map(|i| format!("restore-commit-{i}-{suffix}"))
            .collect();
        let blob_ids: Vec<String> = (0..3)
            .map(|i| format!("blob-commit-{i}-{suffix}"))
            .collect();
        let vector = vec![0.1_f32; 1536];

        let batch: Vec<VectorInsert<'_>> = ids
            .iter()
            .zip(blob_ids.iter())
            .map(|(id, blob_id)| restore_row(id, &owner, &namespace, blob_id, &vector))
            .collect();

        db.insert_vectors_atomic(&batch)
            .await
            .expect("a valid restore batch must commit");

        let landed = rows_for_owner(&db, &owner, &namespace).await;
        delete_rows_for_owner(&db, &owner).await;
        assert_eq!(landed, 3, "every row in a successful batch must be visible");
    }

    /// The original bug's actual trigger: `POST /api/restore` wraps the restore
    /// future in `tokio::time::timeout(55s, ..)`, so a slow batch had its future
    /// DROPPED mid-loop and left every already-inserted row committed.
    ///
    /// With one transaction, dropping the future rolls it back — SQLx queues a
    /// ROLLBACK when the dropped transaction hands its connection back to the
    /// pool. To make sure the cancellation really lands *mid-batch* (a 1ms
    /// deadline would just abort before the first row and pass trivially), the
    /// test first times an uncancelled batch of the same shape and then cancels
    /// the second one at half that duration.
    ///
    /// The assertion is "none or all", not "always none": if the batch wins the
    /// race and commits before the deadline that is a correct outcome too. What
    /// must never happen — and did before the fix — is a partial count.
    #[tokio::test]
    async fn restore_batch_insert_is_all_or_nothing_when_the_future_is_cancelled() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let namespace = format!("ns-{suffix}");
        let batch_size: i64 = 40;
        let vector = vec![0.1_f32; 1536];

        let build = |owner: &str, tag: &str| {
            let ids: Vec<String> = (0..batch_size)
                .map(|i| format!("restore-{tag}-{i}-{suffix}"))
                .collect();
            let blob_ids: Vec<String> = (0..batch_size)
                .map(|i| format!("blob-{tag}-{i}-{suffix}"))
                .collect();
            (owner.to_string(), ids, blob_ids)
        };

        // Warm-up run: how long does a full batch of this shape take?
        let (timed_owner, timed_ids, timed_blob_ids) = build(&format!("0xtimed-{suffix}"), "timed");
        let timed_batch: Vec<VectorInsert<'_>> = timed_ids
            .iter()
            .zip(timed_blob_ids.iter())
            .map(|(id, blob_id)| restore_row(id, &timed_owner, &namespace, blob_id, &vector))
            .collect();
        let started = std::time::Instant::now();
        db.insert_vectors_atomic(&timed_batch)
            .await
            .expect("warm-up batch must commit");
        let full_batch_time = started.elapsed();
        delete_rows_for_owner(&db, &timed_owner).await;

        // Cancel the real run halfway through that measured duration, so the
        // drop lands while rows are still being written.
        let (owner, ids, blob_ids) = build(&format!("0xcancel-{suffix}"), "cancel");
        let batch: Vec<VectorInsert<'_>> = ids
            .iter()
            .zip(blob_ids.iter())
            .map(|(id, blob_id)| restore_row(id, &owner, &namespace, blob_id, &vector))
            .collect();
        // Floored at 5ms: on a fast pool half a sub-millisecond warm-up
        // cancels before `BEGIN` is even sent, and `landed == 0` would then
        // pass without the rollback ever being exercised. If the floor lets the
        // batch finish instead, the `Ok(Ok(()))` arm asserts a full commit — a
        // real check either way.
        let deadline = (full_batch_time / 2).max(Duration::from_millis(5));
        let cancelled = tokio::time::timeout(deadline, db.insert_vectors_atomic(&batch)).await;

        let landed = rows_for_owner(&db, &owner, &namespace).await;
        delete_rows_for_owner(&db, &owner).await;

        match cancelled {
            // Timed out: the future was dropped. Postgres may still have
            // committed if the drop landed after COMMIT was flushed, so accept
            // the full batch — but never a partial one.
            Err(_) => assert!(
                landed == 0 || landed == batch_size,
                "a cancelled restore batch must be all-or-nothing, saw {landed} of {batch_size} rows"
            ),
            Ok(Ok(())) => assert_eq!(
                landed, batch_size,
                "a batch that finished before the deadline must be fully committed"
            ),
            Ok(Err(error)) => panic!("restore batch failed unexpectedly: {error:?}"),
        }
    }

    async fn remember_jobs_test_db() -> Option<VectorDb> {
        let db = test_db().await?;
        for migration in [
            migration_sql("005_remember_jobs.sql"),
            migration_sql("012_remember_write_idempotency.sql"),
            migration_sql("013_remember_write_idempotency_index.sql"),
        ] {
            execute_idempotent_migration(db.pool(), migration).await;
        }
        Some(db)
    }

    #[tokio::test]
    async fn update_vector_importance_is_owner_and_namespace_scoped() {
        let Some(db) = test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0ximp-owner-{suffix}");
        let other_owner = format!("0ximp-other-{suffix}");
        let id = format!("imp-row-{suffix}");
        let other_id = format!("imp-other-{suffix}");

        db.insert_vector(
            &id,
            &owner,
            "notes",
            "blob-imp",
            &[0.1_f32; 1536],
            1,
            0.2,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        db.insert_vector(
            &other_id,
            &other_owner,
            "notes",
            "blob-imp-other",
            &[0.1_f32; 1536],
            1,
            0.2,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        assert!(db
            .update_vector_importance(&id, &owner, "notes", 0.9)
            .await
            .unwrap());
        assert!(
            !db.update_vector_importance(&id, &other_owner, "notes", 0.5)
                .await
                .unwrap(),
            "must not update another owner's row"
        );
        assert!(
            !db.update_vector_importance(&id, &owner, "other-ns", 0.5)
                .await
                .unwrap(),
            "must not update another namespace"
        );

        let scores: Vec<(String, f32)> = sqlx::query_as(
            "SELECT id, importance FROM vector_entries WHERE id = ANY($1) ORDER BY id",
        )
        .bind(vec![id.clone(), other_id.clone()])
        .fetch_all(db.pool())
        .await
        .unwrap();

        sqlx::query("DELETE FROM vector_entries WHERE id = ANY($1)")
            .bind(vec![id.clone(), other_id.clone()])
            .execute(db.pool())
            .await
            .unwrap();

        assert_eq!(scores, vec![(other_id, 0.2), (id, 0.9)]);
    }

    #[tokio::test]
    async fn forget_clears_idempotency_keys_so_the_same_text_can_be_rewritten() {
        let Some(db) = remember_jobs_test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xforget-idem-{suffix}");
        let other_ns_owner_job = format!("other-ns-job-{suffix}");
        let job_id = format!("forget-job-{suffix}");
        let vector_id = job_id.clone();
        let key = format!("analyze:{suffix}");

        db.insert_vector(
            &vector_id,
            &owner,
            "notes",
            "blob-forget",
            &[0.1_f32; 1536],
            1,
            0.5,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status, idempotency_key, blob_id)
             VALUES ($1, $2, 'notes', 'done', $3, 'blob-forget')",
        )
        .bind(&job_id)
        .bind(&owner)
        .bind(&key)
        .execute(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status, idempotency_key)
             VALUES ($1, $2, 'keep', 'done', $3)",
        )
        .bind(&other_ns_owner_job)
        .bind(&owner)
        .bind(format!("analyze-keep:{suffix}"))
        .execute(db.pool())
        .await
        .unwrap();

        assert_eq!(db.delete_by_namespace(&owner, "notes").await.unwrap(), 1);

        let remaining_key: Option<String> =
            sqlx::query_scalar("SELECT idempotency_key FROM remember_jobs WHERE id = $1")
                .bind(&job_id)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(remaining_key, None);

        let kept_key: Option<String> =
            sqlx::query_scalar("SELECT idempotency_key FROM remember_jobs WHERE id = $1")
                .bind(&other_ns_owner_job)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            kept_key.as_deref(),
            Some(format!("analyze-keep:{suffix}").as_str())
        );

        let rewritten = sqlx::query(
            "INSERT INTO remember_jobs (id, owner, namespace, status, idempotency_key)
             VALUES ($1, $2, 'notes', 'pending', $3)
             ON CONFLICT (owner, namespace, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING",
        )
        .bind(format!("rewrite-job-{suffix}"))
        .bind(&owner)
        .bind(&key)
        .execute(db.pool())
        .await
        .unwrap();
        assert_eq!(
            rewritten.rows_affected(),
            1,
            "the same analyze key must insert after forget"
        );

        sqlx::query("DELETE FROM remember_jobs WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM memory_tombstones WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();
    }

    /// The pending-delete filter names `delete_blobs_tracking` states as SQL
    /// literals (the planner needs them inline). This is the tripwire that
    /// keeps those literals honest against the store's own constants — and,
    /// just as importantly, that keeps the *live* states out of the list: a
    /// stray `'deletable'` there would make every tracked memory in a
    /// security-delete deployment silently unrecallable.
    #[test]
    fn pending_delete_filter_matches_the_security_delete_store() {
        use crate::storage::security_delete_store as store;

        for state in [
            store::BLOB_DELETING,
            store::BLOB_DELETED,
            store::BLOB_DELETED_EXTERNAL,
        ] {
            assert!(
                super::SEARCH_SIMILAR_EXCLUDING_PENDING_DELETES_SQL.contains(&format!("'{state}'")),
                "recall must hide memories in the '{state}' tracking state"
            );
        }
        for state in [
            store::BLOB_DELETABLE,
            store::BLOB_NOT_OWNER,
            store::BLOB_EXPIRED,
        ] {
            assert!(
                !super::SEARCH_SIMILAR_EXCLUDING_PENDING_DELETES_SQL
                    .contains(&format!("'{state}'")),
                "'{state}' is a live, readable blob — recall must still return it"
            );
        }
    }

    /// `test_db()` plus the security-delete subsystem's
    /// `delete_blobs_tracking` table.
    ///
    /// That table is defined in `migrations_legacy`, which `LegacyDb` applies
    /// to `LEGACY_DB_URL` only when security deletion is enabled — so it is
    /// absent from the schema `test_db()` builds, exactly as it is absent
    /// from a default deployment. The columns the filter reads are recreated
    /// here rather than `include_str!`-ed because that file is a sqlx
    /// migration: it is not idempotent (bare `CREATE TABLE`), it hard-fails
    /// unless `vector_entries` predates it, and it installs an `AFTER INSERT`
    /// trigger that rejects any owner which is not a canonical 32-byte Sui
    /// address — which every synthetic `0x…-{uuid}` test owner is not.
    async fn security_delete_test_db() -> Option<VectorDb> {
        let db = test_db().await?;
        {
            let _guard = VECTOR_SCHEMA_SETUP_LOCK
                .get_or_init(|| tokio::sync::Mutex::new(()))
                .lock()
                .await;
            sqlx::raw_sql(
                "CREATE TABLE IF NOT EXISTS delete_blobs_tracking (
                    owner TEXT NOT NULL,
                    blob_id TEXT NOT NULL,
                    object_id TEXT,
                    state TEXT NOT NULL DEFAULT 'deletable' CHECK (state IN
                        ('deletable','deleting','deleted','deleted_external',
                         'not_owner','expired')),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (owner, blob_id)
                )",
            )
            .execute(db.pool())
            .await
            .expect("security-delete tracking table must be creatable on the test database");
        }
        assert!(
            db.refresh_pending_delete_filter().await,
            "the filter must switch on once delete_blobs_tracking exists"
        );
        Some(db)
    }

    /// A probe that errors must not turn off a filter a previous probe
    /// enabled. `main` re-probes after `LegacyDb::new()`; a transient failure
    /// there used to disable the filter for the life of the process.
    #[tokio::test]
    async fn a_failed_probe_keeps_the_pending_delete_filter_it_already_had() {
        let Some(db) = security_delete_test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        assert!(
            db.pending_delete_filter_enabled(),
            "security_delete_test_db must hand back a db with the filter on"
        );

        // Closing the pool makes the next probe fail the way a transient
        // connection error would.
        db.pool().close().await;

        assert!(
            db.refresh_pending_delete_filter().await,
            "a failed probe must keep the filter that was already enabled"
        );
        assert!(db.pending_delete_filter_enabled());
    }

    /// WALM-592 / GH #591. The dashboard delete claims a memory by flipping
    /// its tracking row to `deleting`; the `vector_entries` row then survives
    /// until the Sui transaction confirms and `finalize_batch_deleted` runs
    /// (inline on submit, or up to a 30s reconciler tick later). Recall must
    /// not serve the memory during that window.
    #[tokio::test]
    async fn search_similar_hides_memories_claimed_by_a_pending_security_delete() {
        let Some(db) = security_delete_test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xpending-delete-{suffix}");
        let live_blob = format!("blob-live-{suffix}");
        let tracked_blob = format!("blob-tracked-{suffix}");

        // Identical embeddings: whichever row recall drops, it drops because
        // of the filter and not because it lost on cosine distance.
        for (id, blob_id) in [
            (format!("live-{suffix}"), &live_blob),
            (format!("tracked-{suffix}"), &tracked_blob),
        ] {
            db.insert_vector(
                &id,
                &owner,
                "notes",
                blob_id,
                &[0.1_f32; 1536],
                1,
                0.5,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO delete_blobs_tracking (owner, blob_id, state) VALUES ($1, $2, $3)",
        )
        .bind(&owner)
        .bind(&tracked_blob)
        .bind("deletable")
        .execute(db.pool())
        .await
        .unwrap();

        let mut both = vec![live_blob.clone(), tracked_blob.clone()];
        both.sort();

        let mut outcomes = Vec::new();
        for state in [
            "deletable",
            "not_owner",
            "expired",
            "deleting",
            "deleted",
            "deleted_external",
        ] {
            sqlx::query(
                "UPDATE delete_blobs_tracking SET state = $3 WHERE owner = $1 AND blob_id = $2",
            )
            .bind(&owner)
            .bind(&tracked_blob)
            .bind(state)
            .execute(db.pool())
            .await
            .unwrap();
            let mut recalled: Vec<String> = db
                .search_similar(&[0.1_f32; 1536], &owner, "notes", 10)
                .await
                .unwrap()
                .into_iter()
                .map(|hit| hit.blob_id)
                .collect();
            recalled.sort();
            outcomes.push((state, recalled));
        }

        sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM delete_blobs_tracking WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();

        assert_eq!(
            outcomes,
            vec![
                // ── Blob object still on chain: recall must keep serving it.
                // Ordinary live memory that merely *could* be deleted.
                ("deletable", both.clone()),
                // The relayer cannot delete it on chain; still readable.
                ("not_owner", both.clone()),
                // A look-ahead by EXPIRY_MARGIN_EPOCHS, not an actual lapse.
                ("expired", both),
                // ── Blob object gone or going: recall must hide it.
                // Claimed by an in-flight batch — the reported stale window.
                ("deleting", vec![live_blob.clone()]),
                ("deleted", vec![live_blob.clone()]),
                ("deleted_external", vec![live_blob]),
            ]
        );
    }

    /// The acceptance criterion straight from the ticket: forget, then recall
    /// in the same turn, must not return the forgotten fact. `/api/forget`
    /// already deletes and tombstones in one transaction, so this pins that
    /// there is no read-your-writes gap on this path — and that forget stays
    /// scoped to the namespace it was asked for.
    #[tokio::test]
    async fn forget_then_immediate_recall_returns_nothing() {
        let Some(db) = remember_jobs_test_db().await else {
            eprintln!("skipping DB integration test: DATABASE_URL is not configured");
            return;
        };
        let suffix = uuid::Uuid::new_v4();
        let owner = format!("0xforget-recall-{suffix}");

        for (id, namespace, blob_id) in [
            (format!("forget-a-{suffix}"), "notes", "blob-forget-a"),
            (format!("forget-b-{suffix}"), "notes", "blob-forget-b"),
            (format!("keep-{suffix}"), "keep", "blob-keep"),
        ] {
            db.insert_vector(
                &id,
                &owner,
                namespace,
                blob_id,
                &[0.1_f32; 1536],
                1,
                0.5,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        }

        assert_eq!(db.delete_by_namespace(&owner, "notes").await.unwrap(), 2);

        // No sleep, no retry: the very next read after forget returns.
        let forgotten = db
            .search_similar(&[0.1_f32; 1536], &owner, "notes", 10)
            .await
            .unwrap();
        let kept: Vec<String> = db
            .search_similar(&[0.1_f32; 1536], &owner, "keep", 10)
            .await
            .unwrap()
            .into_iter()
            .map(|hit| hit.blob_id)
            .collect();

        sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM memory_tombstones WHERE owner = $1")
            .bind(&owner)
            .execute(db.pool())
            .await
            .unwrap();

        assert!(
            forgotten.is_empty(),
            "forget must be visible to the next recall in the same turn, got {:?}",
            forgotten.iter().map(|hit| &hit.blob_id).collect::<Vec<_>>()
        );
        assert_eq!(kept, vec!["blob-keep".to_string()]);
    }
}

fn db_status<T>(result: &Result<T, AppError>) -> &'static str {
    if result.is_ok() {
        "ok"
    } else {
        "error"
    }
}

/// Indexes built with `CREATE INDEX CONCURRENTLY IF NOT EXISTS`, paired
/// with the migration that builds each one.
///
/// `IF NOT EXISTS` matches by index NAME only -- it cannot tell whether
/// an index already carrying that name is usable. So any entry here can
/// be left permanently INVALID by an interrupted build, after which its
/// migration no-ops forever while the planner refuses to use what was
/// left behind. Nothing errors; the query just silently degrades.
///
/// The interruption that used to matter was the server
/// `statement_timeout` cancelling a large `CREATE INDEX CONCURRENTLY`.
/// The locked rebuild now sets `statement_timeout = 0` for that
/// session so a large `remember_jobs` cannot leave 022 INVALID by
/// hitting the GUC. Recovery still exists for a crash or kill mid-build.
///
/// Only indexes whose loss is SILENT belong here. Migration 013's
/// `uq_remember_jobs_owner_namespace_idempotency_key` is deliberately absent: it is
/// a unique index backing `ON CONFLICT (owner, namespace, idempotency_key)`, and an
/// invalid one makes that upsert ERROR outright rather than quietly
/// degrade, so it reports itself. It also runs in
/// `MIGRATIONS_BEFORE_BACKFILL`, ahead of the single recovery pass below.
///
/// Add an entry whenever a migration in `MIGRATIONS_AFTER_INDEX_RECOVERY`
/// builds an index CONCURRENTLY --
/// `every_concurrently_built_index_is_registered_for_recovery` fails the
/// suite if one is missed.
const CONCURRENTLY_BUILT_INDEXES: &[(&str, &str)] = &[
    // Keyset pagination for the memories listing endpoint.
    ("idx_vector_entries_owner_updated_id", "016"),
    // Expiry-refresh sweep ordering (ASC NULLS FIRST).
    ("idx_vector_entries_expiry_synced_at", "018"),
    // `/health` recent_write_outcomes window scan -- the probe that keeps
    // `writes=degraded` alive, so losing it silently disables a
    // silent-failure detector.
    ("remember_jobs_recent_outcomes_idx", "022"),
    // Admin activity memory-delete counts over a deleted_at window.
    ("idx_memory_tombstones_deleted_at", "024"),
];

/// Session advisory lock for recover + `CREATE INDEX CONCURRENTLY`.
/// Two replicas booting together (first 022 deploy, restart-all, scale-up)
/// must not interleave recover and build: `indisvalid` is false for the
/// entire live CONCURRENTLY build, so a follower that dropped "the
/// leftover" would drop the leader's in-progress (or just-finished)
/// index. Stable across deploys so rolling replicas share the key.
const CONCURRENT_INDEX_LOCK_KEYS: (i32, i32) = (872_122, 22);
const CONCURRENT_INDEX_LOCK_POLL: std::time::Duration = std::time::Duration::from_secs(2);
const CONCURRENT_INDEX_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(20 * 60);

fn should_drop_invalid_concurrent_index(build_in_progress: bool) -> bool {
    !build_in_progress
}

fn drop_invalid_concurrent_index_sql(name: &str) -> String {
    format!("DROP INDEX CONCURRENTLY IF EXISTS {}", name)
}

/// Backfill `vector_entries.updated_at` from `created_at` in bounded
/// batches.
///
/// This cannot be a plain migration file's `UPDATE ... WHERE
/// updated_at IS NULL` (the naive version this replaced) on a
/// real-sized table: a single unbatched full-table UPDATE can run long
/// enough to hit a statement/idle timeout. Postgres rolls back the
/// ENTIRE update atomically on timeout -- there is no partial-UPDATE
/// commit -- which propagates as an error/panic out of
/// `VectorDb::new()`. Under Railway's restart policy that becomes a
/// crash-loop with zero net progress between attempts: restart ->
/// reconnect -> same unbatched UPDATE -> same timeout, forever.
/// LIVE-CONFIRMED against the dev DB (113k rows): the single-statement
/// version could not complete under a short timeout, while this batched
/// version (5000 rows/iteration) completed in ~281s.
///
/// It also cannot be pushed into a `DO $$ ... $$` block inside a
/// migration file: Postgres does not allow `COMMIT` inside a
/// procedural block executed as a single statement, which is exactly
/// what batching needs (each batch must commit on its own so a crash
/// or restart mid-backfill doesn't lose progress already made). So the
/// loop has to live in application code, where each iteration below is
/// its own bare statement against the pool -- not wrapped in an
/// explicit transaction -- and therefore commits independently. A
/// later restart resumes near where the last successful batch left
/// off, because already-backfilled rows no longer match `WHERE
/// updated_at IS NULL`.
///
/// Called from `VectorDb::new()` after migration 014 (which adds the
/// nullable `updated_at` column) and before migration 015 (which
/// requires no NULL rows remain before it can validate its NOT NULL
/// constraint).
async fn backfill_updated_at(pool: &PgPool) -> Result<(), AppError> {
    const BATCH_SIZE: i64 = 5000;
    let mut total_rows: u64 = 0;

    loop {
        let result = sqlx::query(
            "UPDATE vector_entries SET updated_at = created_at \
             WHERE id IN (SELECT id FROM vector_entries WHERE updated_at IS NULL LIMIT $1)",
        )
        .bind(BATCH_SIZE)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to backfill updated_at: {}", e)))?;

        let rows_affected = result.rows_affected();
        total_rows += rows_affected;
        if rows_affected == 0 {
            break;
        }
    }

    if total_rows > 0 {
        tracing::info!(
            rows = total_rows,
            "backfilled vector_entries.updated_at from created_at"
        );
    }

    Ok(())
}

/// Drop any INVALID index left behind by an interrupted
/// `CREATE INDEX CONCURRENTLY` build, so the migration that owns it can
/// rebuild it on this same boot.
///
/// See `CONCURRENTLY_BUILT_INDEXES` for why `IF NOT EXISTS` cannot
/// recover on its own and which indexes are in scope.
///
/// `indisvalid = false` is also true for the entire duration of a *live*
/// `CREATE INDEX CONCURRENTLY`. Dropping that catalog row races two
/// replicas on first deploy of 022: the follower waits out the leader's
/// build, then drops the now-valid index (or errors if the sibling
/// already dropped it, which fails `VectorDb::new`). Skip the drop when
/// `pg_stat_progress_create_index` shows a live build for that name.
/// `DROP INDEX CONCURRENTLY IF EXISTS` so a sibling that already cleaned
/// up does not abort boot.
///
/// Called immediately before `MIGRATIONS_AFTER_INDEX_RECOVERY` on the
/// same session that holds `CONCURRENT_INDEX_LOCK_KEYS`.
async fn recover_invalid_concurrent_indexes(pool: &PgPool) -> Result<(), AppError> {
    let mut conn = pool.acquire().await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to acquire a connection for concurrent-index recovery: {}",
            e
        ))
    })?;
    recover_invalid_concurrent_indexes_on(&mut conn).await
}

async fn recover_invalid_concurrent_indexes_on(conn: &mut PgConnection) -> Result<(), AppError> {
    for (index, migration) in CONCURRENTLY_BUILT_INDEXES {
        let index_is_invalid: Option<bool> = sqlx::query_scalar(
            "SELECT pg_index.indisvalid FROM pg_index \
             JOIN pg_class ON pg_class.oid = pg_index.indexrelid \
             WHERE pg_class.relname = $1",
        )
        .bind(index)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to check validity of {}: {}", index, e)))?;

        // None means no index by that name -- nothing built it yet, which
        // its own migration handles. Some(true) is a healthy index.
        if index_is_invalid != Some(false) {
            continue;
        }

        if !should_drop_invalid_concurrent_index(
            concurrent_index_build_in_progress(conn, index).await?,
        ) {
            tracing::info!(
                index = %index,
                migration = %migration,
                "INVALID concurrent index is a live CREATE INDEX CONCURRENTLY; \
                 not dropping it"
            );
            continue;
        }

        tracing::warn!(
            index = %index,
            migration = %migration,
            "found INVALID index, likely left behind by an interrupted CREATE INDEX \
             CONCURRENTLY build -- dropping it so its migration can rebuild it"
        );

        let drop_stmt = drop_invalid_concurrent_index_sql(index);
        sqlx::query(&drop_stmt)
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to drop invalid index {}: {}", index, e))
            })?;
    }

    Ok(())
}

async fn concurrent_index_build_in_progress(
    conn: &mut PgConnection,
    index: &str,
) -> Result<bool, AppError> {
    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
            SELECT 1
            FROM pg_stat_progress_create_index p
            JOIN pg_class c ON c.oid = p.index_relid
            WHERE c.relname = $1
        )",
    )
    .bind(index)
    .fetch_one(&mut *conn)
    .await
    {
        Ok(in_progress) => Ok(in_progress),
        Err(e) => {
            // Regular roles may not see other backends' progress rows.
            // The session advisory lock is the fence between replica boots;
            // treat an unreadable view as "no live build we can see".
            tracing::warn!(
                error = %e,
                index,
                "could not read pg_stat_progress_create_index; \
                 not treating the INVALID index as a live build"
            );
            Ok(false)
        }
    }
}

/// Recover leftover INVALID indexes, then run 016/018/022, on one session.
///
/// The lock serializes replica boots so a follower cannot mistake the
/// leader's in-progress CONCURRENTLY build for a crashed leftover. It is
/// polled with `pg_try_advisory_lock` rather than waited on: a blocking
/// `pg_advisory_lock` waiter holds a snapshot for the whole wait, and
/// `CREATE INDEX CONCURRENTLY` waits for exactly such snapshots to finish,
/// so the two deadlock. `statement_timeout = 0` for this session so a large
/// `remember_jobs` cannot leave 022 INVALID by hitting the server GUC.
async fn recover_and_rebuild_concurrent_indexes(pool: &PgPool) -> Result<(), AppError> {
    let mut conn = pool.acquire().await.map_err(|e| {
        AppError::Internal(format!(
            "Failed to acquire a connection for concurrent-index rebuild: {}",
            e
        ))
    })?;

    let previous: String = sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read statement_timeout: {}", e)))?;

    sqlx::query("SET statement_timeout = 0")
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "Failed to disable statement_timeout for concurrent index builds: {}",
                e
            ))
        })?;

    let (result, lock_released) = lock_and_rebuild_concurrent_indexes(&mut conn).await;

    let timeout_restored = sqlx::query("SELECT set_config('statement_timeout', $1, false)")
        .bind(&previous)
        .execute(&mut *conn)
        .await
        .is_ok();

    if !timeout_restored || !lock_released {
        // Either a leaked `statement_timeout = 0` or a still-held session
        // advisory lock. Both ride on the connection, so close it instead of
        // returning it to the pool.
        tracing::warn!(
            timeout_restored,
            lock_released,
            "concurrent-index rebuild left the session dirty; discarding it \
             rather than returning it to the pool"
        );
        let _ = conn.close().await;
    }

    result
}

async fn lock_and_rebuild_concurrent_indexes(
    conn: &mut PgConnection,
) -> (Result<(), AppError>, bool) {
    let mut waited = std::time::Duration::ZERO;
    loop {
        let acquired = sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1, $2)")
            .bind(CONCURRENT_INDEX_LOCK_KEYS.0)
            .bind(CONCURRENT_INDEX_LOCK_KEYS.1)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to lock concurrent-index rebuild: {}", e))
            });
        match acquired {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => return (Err(e), true),
        }
        if waited >= CONCURRENT_INDEX_LOCK_WAIT {
            return (
                Err(AppError::Internal(format!(
                    "Timed out after {}s waiting for the concurrent-index rebuild lock",
                    CONCURRENT_INDEX_LOCK_WAIT.as_secs()
                ))),
                true,
            );
        }
        tokio::time::sleep(CONCURRENT_INDEX_LOCK_POLL).await;
        waited += CONCURRENT_INDEX_LOCK_POLL;
    }

    let result = async {
        recover_invalid_concurrent_indexes_on(conn).await?;
        run_migrations_on(conn, MIGRATIONS_AFTER_INDEX_RECOVERY).await?;
        Ok(())
    }
    .await;

    let unlocked = sqlx::query("SELECT pg_advisory_unlock($1, $2)")
        .bind(CONCURRENT_INDEX_LOCK_KEYS.0)
        .bind(CONCURRENT_INDEX_LOCK_KEYS.1)
        .execute(&mut *conn)
        .await
        .is_ok();

    (result, unlocked)
}

/// Release storage reservations given only a pool handle.
///
/// Several wallet-job error paths hold a `&PgPool` rather than an `AppState`
/// (`update_remember_job_after_wallet_error` and friends), and threading state
/// through all of them just to release quota would be a much larger change than
/// this fix warrants. Releasing does not need config: when quota is unlimited
/// no reservation was ever written, so the delete simply matches nothing.
///
/// Infallible for the same reason as the method: a failed release is recovered
/// by the TTL and the terminal-job reconcile, and must never turn a successful
/// write into a failed request.
pub async fn release_storage_reservations_with_pool(pool: &PgPool, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let started = std::time::Instant::now();
    let result = sqlx::query("DELETE FROM storage_reservations WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await;

    match result {
        Ok(_) => {
            crate::observability::observe_db("quota.release_reservations", "ok", started.elapsed());
        }
        Err(e) => {
            crate::observability::observe_db(
                "quota.release_reservations",
                "error",
                started.elapsed(),
            );
            // TTL and the terminal-job reconcile are the backstops. Log
            // loudly but do not propagate.
            tracing::warn!(
                "failed to release {} storage reservation(s), falling back to TTL: {}",
                ids.len(),
                e
            );
        }
    }
}

/// One pending write awaiting admission against an owner's storage quota.
///
/// `id` is supplied by the caller rather than generated here, because the
/// release site must be able to name the reservation without extra plumbing:
///   * enqueued paths pass the `remember_jobs.id` the vector row will use, so
///     `jobs.rs` can release from the job id it already carries. Nothing new
///     has to be threaded through the serialized `WalletOperation` payloads.
///   * inline paths pass a fresh UUID and release it themselves a few lines
///     later.
#[derive(Debug, Clone)]
pub struct StorageReservationRequest {
    pub id: String,
    pub bytes: i64,
}

/// Outcome of an atomic quota admission.
///
/// `Rejected` is a normal outcome, not an error, so the caller owns the
/// response shape. `used` is the total observed under the lock (committed
/// rows plus live reservations) and feeds the existing 402 message verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageAdmission {
    Admitted,
    Rejected { used: i64 },
}

impl VectorDb {
    /// Initialize database connection pool and run migrations
    pub async fn new(database_url: &str) -> Result<Self, AppError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to connect to database: {}", e)))?;

        // Run migrations. The ordering, and the two Rust steps woven
        // between these slices, are load-bearing — see
        // MIGRATIONS_BEFORE_BACKFILL's comment.
        run_migrations(&pool, MIGRATIONS_BEFORE_BACKFILL).await?;

        // Backfill runs as batched Rust code, not a migration file, since
        // Postgres can't COMMIT mid-loop inside a plain migration
        // statement — see backfill_updated_at()'s doc comment.
        backfill_updated_at(&pool).await?;

        run_migrations(&pool, MIGRATIONS_AFTER_BACKFILL).await?;

        recover_and_rebuild_concurrent_indexes(&pool).await?;

        tracing::info!("database connected and migrations applied");

        let db = Self {
            pool,
            storage_alerts: None,
            pending_delete_filter: AtomicBool::new(false),
        };
        db.refresh_pending_delete_filter().await;

        Ok(db)
    }

    /// Re-probe for the security-delete subsystem's `delete_blobs_tracking`
    /// table and cache the answer for `search_similar`. Returns whether the
    /// pending-delete filter is now active.
    ///
    /// Called once at the end of `new()`, and again from `main` right after
    /// `LegacyDb::new()` — the legacy migrations *create* that table, and
    /// they run after `VectorDb::new()`, so without the second probe the
    /// first boot that turns security deletion on would keep serving
    /// pending-delete rows until the next restart.
    ///
    /// The flag starts `false`, so a table that is genuinely absent can never
    /// turn recall into an `undefined_table` 500. A probe that *errors* is not
    /// evidence of absence, though: it leaves the current setting alone, or a
    /// transient failure on the `main` re-probe would disable a working filter
    /// for the life of the process.
    pub async fn refresh_pending_delete_filter(&self) -> bool {
        let present: bool =
            match sqlx::query_scalar("SELECT to_regclass('delete_blobs_tracking') IS NOT NULL")
                .fetch_one(&self.pool)
                .await
            {
                Ok(present) => present,
                Err(e) => {
                    let current = self.pending_delete_filter_enabled();
                    tracing::warn!(
                        enabled = current,
                        "could not probe for delete_blobs_tracking; keeping the current \
                         recall pending-security-delete filter setting: {}",
                        e
                    );
                    return current;
                }
            };
        let previous = self
            .pending_delete_filter
            .swap(present, std::sync::atomic::Ordering::Relaxed);
        if previous != present {
            tracing::info!(
                enabled = present,
                "recall pending-security-delete filter toggled"
            );
        }
        present
    }

    fn pending_delete_filter_enabled(&self) -> bool {
        self.pending_delete_filter
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Expose a reference to the underlying `PgPool` so job handlers
    /// can run ad-hoc queries (e.g. `remember_jobs` status updates).
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Insert a vector entry (with blob size tracking for storage quota).
    ///
    /// `importance` is the per-fact score set at extraction time
    /// (0.0–1.0, mapped from the extractor LLM's vital/standard/trivial
    /// bucket via `services::extractor::importance_for_bucket`). Stored
    /// on the new `importance` column (migration 009) so the recall
    /// `CompositeRanker` can weight it into the composite score when
    /// `scoring_weights.importance` is non-zero.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_vector(
        &self,
        id: &str,
        owner: &str,
        namespace: &str,
        blob_id: &str,
        vector: &[f32],
        blob_size_bytes: i64,
        importance: f32,
        agent_id: Option<&str>,
        package_id: Option<&str>,
        end_epoch: Option<i32>,
    ) -> Result<(), AppError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to begin insert tx: {}", e)))?;
        self.insert_vector_in_tx(
            &mut tx,
            &VectorInsert {
                id,
                owner,
                namespace,
                blob_id,
                vector,
                blob_size_bytes,
                importance,
                agent_id,
                package_id,
                end_epoch,
            },
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to commit insert tx: {}", e)))?;
        Ok(())
    }

    /// Persist a whole batch of vector rows in ONE transaction: either every
    /// row lands or none of them do.
    ///
    /// One transaction, so neither a mid-batch `?` nor a dropped future can
    /// commit a prefix: restore runs under `tokio::time::timeout(55s, ..)`, and
    /// a prefix is a half-written index (GH #566 / WALM-591). SQLx queues a
    /// `ROLLBACK` when a dropped `Transaction` returns its connection to the
    /// pool — the property `jobs::JobUploadLock` also relies on — so a drop
    /// before Postgres has processed `COMMIT` leaves zero rows. A drop after
    /// that lands the whole batch; either way it is never partial.
    ///
    /// Callers must keep the batch bounded. Restore clamps its page to 100 rows
    /// (`clamp_restore_limit`), so this stays short-lived.
    pub async fn insert_vectors_atomic(&self, rows: &[VectorInsert<'_>]) -> Result<(), AppError> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut tx =
            self.pool.begin().await.map_err(|e| {
                AppError::Internal(format!("Failed to begin batch insert tx: {}", e))
            })?;
        for row in rows {
            // Deliberately no explicit `tx.rollback()` here: `?` drops `tx`,
            // and SQLx's Drop impl rolls the transaction back before the
            // connection is reused. That is also what makes a dropped future
            // (the restore timeout) safe.
            self.insert_vector_in_tx(&mut tx, row).await?;
        }
        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to commit batch insert tx: {}", e)))?;

        tracing::debug!("inserted {} vector rows atomically", rows.len());
        Ok(())
    }

    /// Shared statement pair behind [`Self::insert_vector`] and
    /// [`Self::insert_vectors_atomic`]: upsert the row, then clear any
    /// tombstone for the same memory id. Runs on the caller's transaction so a
    /// batch can span many rows without an intermediate commit.
    async fn insert_vector_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        row: &VectorInsert<'_>,
    ) -> Result<(), AppError> {
        let embedding = Vector::from(row.vector.to_vec());

        let started = std::time::Instant::now();
        let result = sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes, importance, agent_id, package_id, end_epoch)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (id) DO UPDATE SET
                owner = EXCLUDED.owner,
                namespace = EXCLUDED.namespace,
                blob_id = EXCLUDED.blob_id,
                embedding = EXCLUDED.embedding,
                blob_size_bytes = EXCLUDED.blob_size_bytes,
                importance = EXCLUDED.importance,
                agent_id = EXCLUDED.agent_id,
                package_id = EXCLUDED.package_id,
                end_epoch = EXCLUDED.end_epoch,
                updated_at = NOW()",
        )
        .bind(row.id)
        .bind(row.owner)
        .bind(row.namespace)
        .bind(row.blob_id)
        .bind(embedding)
        .bind(row.blob_size_bytes)
        .bind(row.importance)
        .bind(row.agent_id)
        .bind(row.package_id)
        .bind(row.end_epoch)
        .execute(&mut **tx)
        .await;
        // A Postgres storage-exhaustion failure is a write outage, not a user
        // error, so it pages before it is mapped to a generic 500 (WALM-612).
        // Reached from the batch path too, unlike the pre-batch code.
        if let Err(e) = &result {
            self.maybe_alert_storage_exhausted(e).await;
        }
        let result =
            result.map_err(|e| AppError::Internal(format!("Failed to insert vector: {}", e)));
        crate::observability::observe_db("vector.insert", db_status(&result), started.elapsed());
        result?;
        sqlx::query("DELETE FROM memory_tombstones WHERE memory_id = $1")
            .bind(row.id)
            .execute(&mut **tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to clear tombstone: {}", e)))?;

        tracing::debug!(
            "inserted vector: id={}, blob_id={}, owner={}, ns={}, size={}B",
            row.id,
            row.blob_id,
            row.owner,
            row.namespace,
            row.blob_size_bytes
        );
        Ok(())
    }

    /// Insert a vector entry with its plaintext (benchmark mode only —
    /// PlaintextEngine). Production rows never use this; they go through
    /// `insert_vector` and leave the `plaintext` column NULL.
    ///
    /// BENCHMARK MODE IS NOT FOR PRODUCTION USE — storing plaintext
    /// memories defeats SEAL's confidentiality guarantee.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_vector_plaintext(
        &self,
        id: &str,
        owner: &str,
        namespace: &str,
        blob_id: &str,
        vector: &[f32],
        plaintext: &str,
        blob_size_bytes: i64,
        importance: f32,
    ) -> Result<(), AppError> {
        let embedding = Vector::from(vector.to_vec());

        let started = std::time::Instant::now();
        let mut tx = self.pool.begin().await.map_err(|e| {
            AppError::Internal(format!("Failed to begin plaintext insert tx: {}", e))
        })?;
        let result = sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes, plaintext, importance)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (id) DO UPDATE SET
                owner = EXCLUDED.owner,
                namespace = EXCLUDED.namespace,
                blob_id = EXCLUDED.blob_id,
                embedding = EXCLUDED.embedding,
                blob_size_bytes = EXCLUDED.blob_size_bytes,
                plaintext = EXCLUDED.plaintext,
                importance = EXCLUDED.importance,
                updated_at = NOW()",
        )
        .bind(id)
        .bind(owner)
        .bind(namespace)
        .bind(blob_id)
        .bind(embedding)
        .bind(blob_size_bytes)
        .bind(plaintext)
        .bind(importance)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert plaintext vector: {}", e)));
        crate::observability::observe_db(
            "vector.insert_plaintext",
            db_status(&result),
            started.elapsed(),
        );
        result?;
        sqlx::query("DELETE FROM memory_tombstones WHERE memory_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to clear tombstone: {}", e)))?;
        tx.commit().await.map_err(|e| {
            AppError::Internal(format!("Failed to commit plaintext insert tx: {}", e))
        })?;

        tracing::debug!(
            "inserted plaintext vector: id={}, blob_id={}, owner={}, ns={}, size={}B",
            id,
            blob_id,
            owner,
            namespace,
            blob_size_bytes
        );
        Ok(())
    }

    /// Fetch the plaintext for a benchmark-mode row by its synthetic
    /// blob_id. Returns `Ok(None)` if the row doesn't exist; `Ok(Some(""))`
    /// vs `Ok(None)` distinguishes "empty plaintext" from "no row".
    /// Returns `Ok(None)` when the row exists but `plaintext` is NULL (a
    /// production row in a benchmark DB — shouldn't happen, handled gracefully).
    ///
    /// Scoped to `owner` + `namespace` so a recall hit cannot surface a
    /// different tenant's plaintext even when the same blob_id is reused.
    /// The upstream `search_similar` already applies both filters; this is
    /// defence-in-depth against a bug there.
    pub async fn fetch_plaintext_by_blob_id(
        &self,
        blob_id: &str,
        owner: &str,
        namespace: &str,
    ) -> Result<Option<String>, AppError> {
        let started = std::time::Instant::now();
        let result: Result<Option<(Option<String>,)>, AppError> = sqlx::query_as(
            "SELECT plaintext FROM vector_entries
             WHERE blob_id = $1 AND owner = $2 AND namespace = $3
             LIMIT 1",
        )
        .bind(blob_id)
        .bind(owner)
        .bind(namespace)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch plaintext: {}", e)));
        crate::observability::observe_db(
            "vector.fetch_plaintext",
            db_status(&result),
            started.elapsed(),
        );
        let row = result?;

        Ok(row.and_then(|(plaintext,)| plaintext))
    }

    /// Search for similar vectors using pgvector cosine distance (<=>).
    /// Each `blob_id` appears at most once (closest row wins). Duplicate
    /// index rows are over-fetched so `limit` still fills with distinct blobs.
    pub async fn search_similar(
        &self,
        query_vector: &[f32],
        owner: &str,
        namespace: &str,
        limit: usize,
    ) -> Result<Vec<SearchHit>, AppError> {
        if limit == 0 {
            return Ok(vec![]);
        }

        // First-wins unique after ANN `LIMIT` is HNSW-friendly, but duplicate
        // index rows consume that window. Widen by the dropped count in the
        // current window (duplicate factor), capped at `limit * 4`.
        let mut fetch_limit = limit;
        loop {
            let rows = self
                .search_similar_rows(query_vector, owner, namespace, fetch_limit)
                .await?;
            let fetched = rows.len();
            let mut unique = unique_hits_by_blob_id(rows);
            if unique.len() >= limit {
                unique.truncate(limit);
                return Ok(unique);
            }
            if fetched < fetch_limit {
                return Ok(unique);
            }
            let dropped = fetched - unique.len();
            let Some(next) = next_search_fetch_limit(limit, fetch_limit, dropped) else {
                return Ok(unique);
            };
            fetch_limit = next;
        }
    }

    async fn search_similar_rows(
        &self,
        query_vector: &[f32],
        owner: &str,
        namespace: &str,
        fetch_limit: usize,
    ) -> Result<Vec<SearchHit>, AppError> {
        let embedding = Vector::from(query_vector.to_vec());

        // `created_at` + `importance` are selected alongside the cosine
        // distance so the recall pipeline can rank by recency / importance
        // without a second round-trip. Both NOT NULL (migration 001 for
        // created_at, 009 for importance) so the row tuple types are
        // non-Option.
        //
        // The pending-delete variant is chosen here, not stitched together
        // per call, so the hot path costs one branch rather than a `format!`.
        let sql = if self.pending_delete_filter_enabled() {
            SEARCH_SIMILAR_EXCLUDING_PENDING_DELETES_SQL
        } else {
            SEARCH_SIMILAR_SQL
        };
        let started = std::time::Instant::now();
        #[allow(clippy::type_complexity)]
        let result: Result<
            Vec<(String, f64, chrono::DateTime<chrono::Utc>, f32)>,
            AppError,
        > = sqlx::query_as(sql)
            .bind(embedding)
            .bind(owner)
            .bind(namespace)
            .bind(fetch_limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to search vectors: {}", e)));
        crate::observability::observe_db(
            "vector.search_similar",
            db_status(&result),
            started.elapsed(),
        );
        let rows = result?;

        Ok(rows
            .into_iter()
            .map(|(blob_id, distance, created_at, importance)| SearchHit {
                blob_id,
                distance,
                created_at,
                importance,
            })
            .collect())
    }

    /// Get all blob_ids for a given owner + namespace (used by restore flow)
    pub async fn get_blobs_by_namespace(
        &self,
        owner: &str,
        namespace: &str,
    ) -> Result<Vec<String>, AppError> {
        let started = std::time::Instant::now();
        let result: Result<Vec<(String,)>, AppError> = sqlx::query_as(
            "SELECT DISTINCT blob_id FROM vector_entries
             WHERE owner = $1 AND namespace = $2",
        )
        .bind(owner)
        .bind(namespace)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get blobs by namespace: {}", e)));
        crate::observability::observe_db(
            "vector.get_blobs_by_namespace",
            db_status(&result),
            started.elapsed(),
        );
        let rows = result?;

        Ok(rows.into_iter().map(|(blob_id,)| blob_id).collect())
    }

    /// Count + total stored bytes for a given owner + namespace.
    /// Used by `POST /api/stats` for harness verification. Returns
    /// `(memory_count, storage_bytes)`; both 0 if the namespace is empty.
    pub async fn namespace_stats(
        &self,
        owner: &str,
        namespace: &str,
    ) -> Result<(i64, i64), AppError> {
        let started = std::time::Instant::now();
        let result: Result<(i64, i64), AppError> = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT, COALESCE(SUM(blob_size_bytes)::BIGINT, 0)
             FROM vector_entries WHERE owner = $1 AND namespace = $2",
        )
        .bind(owner)
        .bind(namespace)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get namespace stats: {}", e)));
        crate::observability::observe_db(
            "vector.namespace_stats",
            db_status(&result),
            started.elapsed(),
        );
        let row = result?;

        Ok(row)
    }

    /// How durable writes that finished inside `window` turned out,
    /// across every owner: `(failed, succeeded)`.
    ///
    /// `write_ready` is a sidecar probe AND a Postgres size check. Neither
    /// can see Walrus refusing every upload, so a total Walrus outage left
    /// `/health` reporting a healthy write path while every remember
    /// failed minutes after being accepted. This is the missing term.
    ///
    /// Counted rather than listed, and read behind a cache measured in
    /// tens of seconds. Served by `remember_jobs_recent_outcomes_idx`
    /// (022). The statement is also cancelled at 1s (`SET LOCAL`) so a
    /// sequential scan cannot stall the public `/health` handler; the
    /// probe fails open on timeout.
    pub async fn recent_write_outcomes(
        &self,
        window: std::time::Duration,
    ) -> Result<(i64, i64), AppError> {
        let started = std::time::Instant::now();
        let since = chrono::Utc::now() - chrono::Duration::from_std(window).unwrap_or_default();
        // SET LOCAL needs a transaction; the pool's statement_timeout is
        // the startup bound (up to 300s) and would let this scan run that
        // long. 1000ms matches WRITE_READY_PROBE_TIMEOUT on /health.
        let mut tx = self.pool.begin().await.map_err(|e| {
            AppError::Internal(format!("Failed to count recent remember outcomes: {}", e))
        })?;
        sqlx::query("SELECT set_config('statement_timeout', '1000ms', true)")
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to count recent remember outcomes: {}", e))
            })?;
        let outcome = sqlx::query_as::<_, (i64, i64)>(
            "SELECT
               count(*) FILTER (WHERE status = 'failed'),
               count(*) FILTER (WHERE status IN ('done', 'uploaded'))
             FROM remember_jobs
             WHERE status IN ('failed', 'done', 'uploaded')
               AND updated_at >= $1",
        )
        .bind(since)
        .fetch_one(&mut *tx)
        .await;
        let _ = tx.rollback().await;

        match outcome {
            Ok(counts) => {
                crate::observability::observe_db(
                    "remember_jobs.recent_outcomes",
                    "ok",
                    started.elapsed(),
                );
                Ok(counts)
            }
            Err(e) => {
                crate::observability::observe_db(
                    "remember_jobs.recent_outcomes",
                    "error",
                    started.elapsed(),
                );
                Err(AppError::Internal(format!(
                    "Failed to count recent remember outcomes: {}",
                    e
                )))
            }
        }
    }

    /// Hard-delete all vector index rows for a given owner + namespace.
    /// (Walrus blobs themselves persist — Walrus has no delete; this only
    /// removes the local `vector_entries` rows, so the memories stop being
    /// retrievable and stop counting toward storage quota.) Reachable via
    /// `POST /api/forget` — authed, owner-scoped.
    ///
    /// Also NULLs `remember_jobs.idempotency_key` for the same owner +
    /// namespace. Analyze (and client-keyed remember) collapse retries on
    /// that unique key; leaving it set after forget makes a later write of
    /// the same text return success without storing anything.
    pub async fn delete_by_namespace(&self, owner: &str, namespace: &str) -> Result<u64, AppError> {
        let started = std::time::Instant::now();
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to begin forget tx: {}", e)))?;
        let result = sqlx::query(
            "WITH removed AS (
                DELETE FROM vector_entries
                WHERE owner = $1 AND namespace = $2
                RETURNING id, owner, namespace, blob_id
             )
             INSERT INTO memory_tombstones (memory_id, owner, namespace, blob_id)
             SELECT id, owner, namespace, blob_id FROM removed
             ON CONFLICT (memory_id) DO UPDATE SET deleted_at = NOW()",
        )
        .bind(owner)
        .bind(namespace)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to delete by namespace: {}", e)));
        let result = match result {
            Ok(result) => result,
            Err(e) => {
                crate::observability::observe_db(
                    "vector.delete_by_namespace",
                    "error",
                    started.elapsed(),
                );
                return Err(e);
            }
        };
        let clear = sqlx::query(
            "UPDATE remember_jobs
             SET idempotency_key = NULL, updated_at = NOW()
             WHERE owner = $1 AND namespace = $2 AND idempotency_key IS NOT NULL",
        )
        .bind(owner)
        .bind(namespace)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            AppError::Internal(format!("Failed to clear remember idempotency keys: {}", e))
        });
        if let Err(e) = clear {
            crate::observability::observe_db(
                "vector.delete_by_namespace",
                "error",
                started.elapsed(),
            );
            return Err(e);
        }
        if let Err(e) = tx.commit().await {
            crate::observability::observe_db(
                "vector.delete_by_namespace",
                "error",
                started.elapsed(),
            );
            return Err(AppError::Internal(format!(
                "Failed to commit forget tx: {}",
                e
            )));
        }
        crate::observability::observe_db("vector.delete_by_namespace", "ok", started.elapsed());
        let rows = result.rows_affected();
        tracing::info!(
            "deleted {} entries for owner={}, ns={}",
            rows,
            owner,
            namespace
        );
        Ok(rows)
    }

    /// Change importance on one live memory without rewriting the blob.
    /// Returns whether a matching owner-scoped row existed.
    pub async fn update_vector_importance(
        &self,
        id: &str,
        owner: &str,
        namespace: &str,
        importance: f32,
    ) -> Result<bool, AppError> {
        let started = std::time::Instant::now();
        let result = sqlx::query(
            "UPDATE vector_entries
             SET importance = $4, updated_at = NOW()
             WHERE id = $1 AND owner = $2 AND namespace = $3",
        )
        .bind(id)
        .bind(owner)
        .bind(namespace)
        .bind(importance)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to update vector importance: {}", e)));
        crate::observability::observe_db(
            "vector.update_importance",
            db_status(&result),
            started.elapsed(),
        );
        Ok(result?.rows_affected() > 0)
    }

    /// Delete vector entries for one expired blob within an owner + namespace.
    /// Called reactively when Walrus returns 404 during blob download.
    /// Both owner and namespace are required so cleanup cannot cross either
    /// isolation boundary when ciphertext is reused in multiple rows.
    pub async fn delete_by_blob_id(
        &self,
        blob_id: &str,
        owner: &str,
        namespace: &str,
    ) -> Result<u64, AppError> {
        let started = std::time::Instant::now();
        let result = sqlx::query(
            "WITH removed AS (
                DELETE FROM vector_entries
                WHERE blob_id = $1 AND owner = $2 AND namespace = $3
                RETURNING id, owner, namespace, blob_id
             )
             INSERT INTO memory_tombstones (memory_id, owner, namespace, blob_id)
             SELECT id, owner, namespace, blob_id FROM removed
             ON CONFLICT (memory_id) DO UPDATE SET deleted_at = NOW()",
        )
        .bind(blob_id)
        .bind(owner)
        .bind(namespace)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to delete vector by blob_id: {}", e)));
        crate::observability::observe_db(
            "vector.delete_by_blob_id",
            db_status(&result),
            started.elapsed(),
        );
        let result = result?;
        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!(
                "deleted expired blob from DB: blob_id={}, owner={}, namespace={}, rows={}",
                blob_id,
                owner,
                namespace,
                rows
            );
        }
        Ok(rows)
    }

    /// Drop tombstones older than `TOMBSTONE_RETENTION`. Batched so a large
    /// backlog cannot lock the table for one giant delete.
    pub async fn sweep_expired_tombstones(&self) -> Result<u64, AppError> {
        let secs = TOMBSTONE_RETENTION.num_seconds();
        let mut total = 0u64;
        loop {
            let result = sqlx::query(
                "DELETE FROM memory_tombstones
                 WHERE memory_id IN (
                    SELECT memory_id FROM memory_tombstones
                    WHERE deleted_at < NOW() - make_interval(secs => $1)
                    LIMIT 1000
                 )",
            )
            .bind(secs)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to sweep tombstones: {}", e)))?;
            let n = result.rows_affected();
            total += n;
            if n < 1000 {
                break;
            }
        }
        Ok(total)
    }

    // ============================================================
    // Delegate Key Cache
    // ============================================================

    /// Look up cached account info for a delegate public key.
    /// Returns `Some((account_id, owner))` if found.
    pub async fn get_cached_account(
        &self,
        public_key_hex: &str,
    ) -> Result<Option<(String, String)>, AppError> {
        let started = std::time::Instant::now();
        let result: Result<Option<(String, String)>, AppError> = sqlx::query_as(
            "SELECT account_id, owner FROM delegate_key_cache WHERE public_key = $1 AND expires_at > NOW()",
        )
        .bind(public_key_hex)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to query cache: {}", e)));
        crate::observability::observe_db(
            "delegate_cache.get",
            db_status(&result),
            started.elapsed(),
        );

        result
    }

    /// Cache a verified delegate key → account mapping.
    pub async fn cache_delegate_key(
        &self,
        public_key_hex: &str,
        account_id: &str,
        owner: &str,
    ) -> Result<(), AppError> {
        let started = std::time::Instant::now();
        let result = sqlx::query(
            "INSERT INTO delegate_key_cache (public_key, account_id, owner, expires_at)
             VALUES ($1, $2, $3, NOW() + INTERVAL '24 hours')
             ON CONFLICT (public_key)
             DO UPDATE SET account_id = $2, owner = $3, cached_at = NOW(), expires_at = NOW() + INTERVAL '24 hours'",
        )
        .bind(public_key_hex)
        .bind(account_id)
        .bind(owner)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to cache delegate key: {}", e)));
        crate::observability::observe_db(
            "delegate_cache.set",
            db_status(&result),
            started.elapsed(),
        );
        result?;

        tracing::debug!(
            "cached delegate key: {} -> account {}",
            public_key_hex,
            account_id
        );
        Ok(())
    }

    /// Periodically called to evict expired keys
    pub async fn evict_expired_delegate_keys(&self) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM delegate_key_cache WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to evict expired delegate keys: {}", e))
            })?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!("Evicted {} expired delegate keys from cache", rows);
        }
        Ok(rows)
    }

    /// Mark remember jobs as failed once nothing can still move them:
    /// `running`/`uploaded` whose worker stopped updating them, and `pending`
    /// rows whose preparation never finished.
    ///
    /// `prepare_claimed_at IS NOT NULL` is load-bearing — only the single
    /// `remember` path claims a preparation slot, so without it the sweep also
    /// matches healthy `/api/remember/bulk` and `/api/analyze` rows, which
    /// never set `preparation_encrypted_b64` at all.
    ///
    /// Clearing `prepare_claim_token` fences a slow preparation: its own
    /// UPDATE is keyed on that token, so it can no longer reach
    /// `enqueue_wallet_job`. Failing is the only option — the row stores
    /// ciphertext, never plaintext, so nothing can be retried from.
    ///
    /// Quota is reclaimed by `release_reservations_for_terminal_jobs`, which
    /// `main` runs immediately after this on the same tick.
    pub async fn fail_stale_remember_jobs(
        &self,
        stale_after: std::time::Duration,
    ) -> Result<u64, AppError> {
        let stale_after_secs = stale_after.as_secs().min(i64::MAX as u64) as i64;
        // A congestion requeue parks the row on `running` for minutes while
        // the next attempt is already scheduled. The normal 10-minute sweep
        // would mark that wait failed and the client would send the fact
        // again. Only a prefix that has not been refreshed for 45 minutes is
        // a lost job.
        let congestion_wait_stale_secs: i64 = 45 * 60;
        let result = sqlx::query(
            "UPDATE remember_jobs
             SET status = 'failed',
                 error_msg = COALESCE(error_msg, 'stale/orphaned remember job'),
                 updated_at = NOW()
             WHERE status IN ('running', 'uploaded')
               AND updated_at < NOW() - ($1 * INTERVAL '1 second')
               AND (
                    error_msg IS NULL
                    OR error_msg NOT LIKE ($2 || '%')
                    OR updated_at < NOW() - ($3 * INTERVAL '1 second')
               )",
        )
        .bind(stale_after_secs)
        .bind(crate::jobs::CONGESTION_WAIT_ERROR_PREFIX)
        .bind(congestion_wait_stale_secs)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fail stale remember jobs: {}", e)))?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::warn!("Marked {} stale remember jobs as failed", rows);
        }

        // Second pass rather than one OR'd predicate: this branch clears the
        // preparation claim and carries its own error text, and the two are
        // different enough that folding them together would hide which case
        // actually fired in the logs.
        let orphaned = sqlx::query(
            "UPDATE remember_jobs
             SET status = 'failed',
                 error_msg = COALESCE(
                     error_msg,
                     'preparation never completed — the relayer stopped before this write was encrypted, so the fact was never stored and must be sent again'
                 ),
                 prepare_claim_token = NULL,
                 prepare_claimed_at = NULL,
                 updated_at = NOW()
             WHERE status = 'pending'
               AND prepare_claimed_at IS NOT NULL
               AND preparation_encrypted_b64 IS NULL
               AND updated_at < NOW() - ($1 * INTERVAL '1 second')",
        )
        .bind(stale_after_secs)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AppError::Internal(format!("Failed to fail orphaned remember preparations: {}", e))
        })?;

        let orphaned_rows = orphaned.rows_affected();
        if orphaned_rows > 0 {
            // Distinct wording from the sweep above: this one means writes were
            // accepted and silently lost, which is an availability signal about
            // the relayer, not a Walrus or wallet problem.
            tracing::warn!(
                "Marked {} remember jobs as failed whose preparation never completed",
                orphaned_rows
            );
        }

        Ok(rows + orphaned_rows)
    }

    /// Rows whose expiry data has never been synced, or was synced more
    /// than 24h ago. Returns (owner, id, blob_id) tuples — the minimum a
    /// caller needs to look up on-chain data and write it back. Stamps
    /// nothing itself; the caller must call `mark_expiry_scheduled` before
    /// doing the (potentially slow) on-chain lookup, so a second sweep
    /// tick doesn't re-select the same rows while the first is in flight.
    pub async fn rows_needing_expiry_refresh(
        &self,
        limit: i64,
    ) -> Result<Vec<(String, String, String)>, AppError> {
        sqlx::query_as(
            "SELECT owner, id, blob_id FROM vector_entries
             WHERE expiry_synced_at IS NULL OR expiry_synced_at < NOW() - INTERVAL '24 hours'
             ORDER BY expiry_synced_at ASC NULLS FIRST
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "Failed to select rows needing expiry refresh: {}",
                e
            ))
        })
    }

    /// Stamp expiry_synced_at = NOW() at SCHEDULE time (not completion) so
    /// a row already picked up by the current sweep tick isn't re-selected
    /// by the next tick while its on-chain lookup is still in flight. A
    /// failed lookup is retried on the next sweep after the 24h window —
    /// acceptable degradation, avoids duplicate-enqueue storms. Never
    /// touches updated_at.
    pub async fn mark_expiry_scheduled(&self, ids: &[String]) -> Result<(), AppError> {
        sqlx::query("UPDATE vector_entries SET expiry_synced_at = NOW() WHERE id = ANY($1)")
            .bind(ids)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to mark expiry scheduled: {}", e)))?;
        Ok(())
    }

    /// Write back a resolved end_epoch/expires_at for one row.
    ///
    /// `updated_at` advances when `end_epoch` changes, and also whenever
    /// `expires_at` is still NULL. The second half matters because
    /// `insert_vector` writes `end_epoch` but not `expires_at`, so on the
    /// mainline write path the sweep's first call finds `end_epoch` already
    /// equal and would otherwise populate `expires_at` invisibly, leaving a
    /// client that synced the row pre-sweep on `null` forever. This was
    /// originally
    /// unconditional-never: the sweep that calls this re-verifies every
    /// row on a ~24h cadence even after it already has a value, and an
    /// unconditional `updated_at = NOW()` on every one of those routine
    /// re-checks would make effectively every memory reappear in Console's
    /// `updated_after` incremental sync roughly once a day regardless of
    /// whether anything actually changed. But that guard was too broad: it
    /// also suppressed the *one* write that must be cursor-visible — the
    /// first time a row's expiry resolves from `NULL` to a real value. A
    /// client that already synced that row before the sweep ran would then
    /// never see the populated `end_epoch`/`expires_at` on any later poll,
    /// silently breaking expiry tracking for exactly the rows synced
    /// before their expiry was known. Conditioning on an actual value
    /// change satisfies both: the first real write bumps `updated_at`
    /// (visible to sync); unchanged re-verifications don't (no spam).
    ///
    /// The change-check deliberately compares `end_epoch` only, not
    /// `expires_at`. `expires_at` is derived from `end_epoch` plus
    /// wall-clock `now` at sweep time (see `expires_at_from_epoch`), so it
    /// recomputes to a slightly different instant on every routine
    /// re-verification even when `end_epoch` hasn't moved at all — an
    /// `expires_at IS DISTINCT FROM $2` condition would be true on
    /// essentially every sweep tick and defeat the anti-spam guard this
    /// comment describes. `expires_at` is still refreshed on every write
    /// (it's deliberately approximate; keeping it current is harmless),
    /// it just doesn't drive whether `updated_at` bumps.
    pub async fn set_memory_expiry(
        &self,
        id: &str,
        end_epoch: i32,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE vector_entries
             SET end_epoch = $1,
                 expires_at = $2,
                 updated_at = CASE
                     WHEN end_epoch IS DISTINCT FROM $1 OR expires_at IS NULL
                     THEN NOW()
                     ELSE updated_at
                 END
             WHERE id = $3",
        )
        .bind(end_epoch)
        .bind(expires_at)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to set memory expiry: {}", e)))?;
        Ok(())
    }

    /// Immediately remove a single stale/revoked delegate key from the cache.
    ///
    /// Called when a cached entry's on-chain re-verify returns a *definitive*
    /// miss (`KeyNotFound` / `AccountDeactivated` / `WrongObjectType`). Do
    /// **not** call this for `RpcError` / `ScanCapExceeded` — those mean Sui
    /// could not be consulted (WALM-429). Evicting on a 429 made every later
    /// request miss the cache, burn a second GetObject, and 401 a still-valid
    /// key.
    pub async fn delete_cached_key(&self, public_key_hex: &str) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM delegate_key_cache WHERE public_key = $1")
            .bind(public_key_hex)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to delete stale cached key: {}", e)))?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!(
                "evicted stale/revoked delegate key from cache: {}",
                public_key_hex
            );
        }
        Ok(rows)
    }

    // ============================================================
    // Storage Quota (still PostgreSQL — tracks per-row blob sizes)
    // ============================================================

    /// Atomically admit a batch of writes against the owner's storage quota.
    ///
    /// This is the whole fix for GH #532 / WALM-359. The previous
    /// `get_storage_used_with_lock` took a `pg_advisory_xact_lock`, read the
    /// total, and then committed — which released the lock, because xact locks
    /// are transaction scoped. The comparison and the caller's INSERT both
    /// happened outside it, so concurrent requests from one owner all observed
    /// the same pre-insert total and all passed.
    ///
    /// Here the lock, the usage read, the comparison, and the reservation
    /// INSERT all live in one transaction. Nothing else for this owner can
    /// interleave, so a burst is serialized and only what actually fits is
    /// admitted.
    ///
    /// Usage counts committed rows plus live reservations:
    ///   `SUM(vector_entries.blob_size_bytes) + SUM(storage_reservations.bytes)`
    /// Expired reservations are excluded by predicate and opportunistically
    /// deleted for this owner, so a missed release self-heals at `ttl`.
    ///
    /// Admission is all-or-nothing across `reservations`, which preserves the
    /// existing behaviour where a bulk request either lands whole or is
    /// rejected whole.
    ///
    /// `pg_advisory_xact_lock` (not the session-level `pg_advisory_lock`) is
    /// still the right primitive here: with a connection pool the session
    /// variant leaks locks onto pooled connections and deadlocks. Inside an
    /// explicit transaction the lock is released on commit or rollback.
    pub async fn admit_storage_reservations(
        &self,
        owner: &str,
        lock_key: i64,
        max_bytes: i64,
        reservations: &[StorageReservationRequest],
        ttl: std::time::Duration,
    ) -> Result<StorageAdmission, AppError> {
        if reservations.is_empty() {
            return Ok(StorageAdmission::Admitted);
        }

        let started = std::time::Instant::now();
        let ttl_secs = ttl.as_secs().min(i64::MAX as u64) as i64;
        let requested: i64 = reservations.iter().map(|r| r.bytes).sum();

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to begin tx: {}", e)))?;

        // Serializes every admission for this owner. Held until commit or
        // rollback below, which is what makes check-then-reserve atomic.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to acquire advisory lock: {}", e)))?;

        // Opportunistic cleanup, scoped to this owner so the write stays
        // small and cannot contend with other owners' admissions. The global
        // sweeper handles owners who never come back.
        sqlx::query("DELETE FROM storage_reservations WHERE owner = $1 AND expires_at <= NOW()")
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to prune expired reservations: {}", e))
            })?;

        let committed: (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(blob_size_bytes)::BIGINT, 0) FROM vector_entries WHERE owner = $1",
        )
        .bind(owner)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get storage used: {}", e)))?;

        let reserved: (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(bytes)::BIGINT, 0) FROM storage_reservations
             WHERE owner = $1 AND expires_at > NOW()",
        )
        .bind(owner)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get reserved storage: {}", e)))?;

        let used = committed.0.saturating_add(reserved.0);

        if used.saturating_add(requested) > max_bytes {
            // Rollback releases the advisory lock and writes nothing.
            if let Err(e) = tx.rollback().await {
                tracing::warn!("failed to roll back rejected quota admission: {}", e);
            }
            crate::observability::observe_db(
                "quota.admit_reservations",
                "rejected",
                started.elapsed(),
            );
            return Ok(StorageAdmission::Rejected { used });
        }

        // ON CONFLICT makes admission idempotent. A retried enqueued job
        // re-admitting under the same `remember_jobs.id` refreshes its own
        // reservation instead of double counting itself.
        for reservation in reservations {
            sqlx::query(
                "INSERT INTO storage_reservations (id, owner, bytes, expires_at)
                 VALUES ($1, $2, $3, NOW() + ($4 * INTERVAL '1 second'))
                 ON CONFLICT (id) DO UPDATE SET
                    owner = EXCLUDED.owner,
                    bytes = EXCLUDED.bytes,
                    expires_at = EXCLUDED.expires_at",
            )
            .bind(&reservation.id)
            .bind(owner)
            .bind(reservation.bytes)
            .bind(ttl_secs)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to insert reservation: {}", e)))?;
        }

        tx.commit()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to commit tx: {}", e)))?;

        crate::observability::observe_db("quota.admit_reservations", "ok", started.elapsed());
        Ok(StorageAdmission::Admitted)
    }

    /// Release reservations once their bytes are accounted for elsewhere, or
    /// once the write that reserved them is known to be dead.
    ///
    /// Callers release *after* the vector row is committed. That ordering
    /// briefly double counts the same bytes (row + reservation), which is the
    /// safe direction: releasing first would open a window where neither
    /// counts and a concurrent burst could slip through.
    ///
    /// Idempotent by construction — deleting an already released id is a
    /// no-op, so retried jobs and overlapping failure handlers are harmless.
    /// Never returns an error to the caller: a failed release is recovered by
    /// the TTL, and must not turn a successful write into a failed one.
    pub async fn release_storage_reservations(&self, ids: &[String]) {
        release_storage_reservations_with_pool(&self.pool, ids).await
    }

    /// Drop reservations whose `remember_jobs` row is already terminal.
    ///
    /// The explicit release calls in `jobs.rs` handle the common paths
    /// promptly, but a terminal row with a live reservation can still arise:
    /// the stale-job sweeper fails a row directly, a recovery handoff marks a
    /// job failed from a code path that only has a pool handle, or a future
    /// terminal path forgets to release. Reconciling against job status turns
    /// every one of those from a full-TTL overcount into a bounded one, and
    /// keeps the guarantee from depending on nobody ever missing a call site.
    ///
    /// Only reservations keyed by a `remember_jobs.id` are affected. Inline
    /// reservations use local UUIDs with no job row, so they never match here
    /// and are covered by their own release plus the TTL.
    pub async fn release_reservations_for_terminal_jobs(&self) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE FROM storage_reservations r
             USING remember_jobs j
             WHERE r.id = j.id AND j.status IN ('done', 'failed')",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AppError::Internal(format!(
                "Failed to reconcile reservations against terminal jobs: {}",
                e
            ))
        })?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!(
                "released {} storage reservation(s) held by terminal remember jobs",
                rows
            );
        }
        Ok(rows)
    }

    /// Delete reservations whose TTL has passed, across all owners.
    ///
    /// The admission path already prunes the owner it touches, so this only
    /// matters for owners who reserved, leaked, and never returned. Without it
    /// their rows would sit in the table forever even though the predicate
    /// already stops counting them.
    pub async fn sweep_expired_storage_reservations(&self) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM storage_reservations WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to sweep expired reservations: {}", e))
            })?;

        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!("swept {} expired storage reservation(s)", rows);
        }
        Ok(rows)
    }

    // ============================================================
    // Accounts (populated by v2-indexer)
    // ============================================================

    /// Find an account by owner address (from indexed accounts table).
    /// Returns `Some(account_id)` if the owner has a registered account.
    pub async fn find_account_by_owner(&self, owner: &str) -> Result<Option<String>, AppError> {
        let result: Option<(String,)> =
            sqlx::query_as("SELECT account_id FROM accounts WHERE owner = $1")
                .bind(owner)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AppError::Internal(format!("Failed to query accounts: {}", e)))?;

        Ok(result.map(|(id,)| id))
    }

    // ============================================================
    // MCP OAuth (Claude custom connectors) — see `../oauth.rs` and
    // `../../migrations/010_mcp_oauth.sql`. Methods are only called from
    // `routes/oauth.rs` and `mcp_proxy.rs`'s bearer resolution.
    // ============================================================

    pub async fn insert_oauth_client(
        &self,
        client: &oauth_rows::OAuthClientRow,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO mcp_oauth_clients
                (client_id, client_secret_sha256, client_name, redirect_uris, grant_types,
                 response_types, token_endpoint_auth_method, scope, status, registered_ip)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&client.client_id)
        .bind(&client.client_secret_sha256)
        .bind(&client.client_name)
        .bind(&client.redirect_uris)
        .bind(&client.grant_types)
        .bind(&client.response_types)
        .bind(&client.token_endpoint_auth_method)
        .bind(&client.scope)
        .bind(&client.status)
        .bind(&client.registered_ip)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert oauth client: {}", e)))?;
        Ok(())
    }

    pub async fn fetch_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<oauth_rows::OAuthClientRow>, AppError> {
        sqlx::query_as::<_, oauth_rows::OAuthClientRow>(
            "SELECT client_id, client_secret_sha256, client_name, redirect_uris, grant_types,
                    response_types, token_endpoint_auth_method, scope, status, registered_ip
             FROM mcp_oauth_clients WHERE client_id = $1 AND status = 'active'",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch oauth client: {}", e)))
    }

    pub async fn touch_oauth_client_last_used(&self, client_id: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE mcp_oauth_clients SET last_used_at = NOW() WHERE client_id = $1")
            .bind(client_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to touch oauth client: {}", e)))?;
        Ok(())
    }

    /// Total DCR-registered clients that never completed a grant, created in
    /// the given window. Backstop for decision D5 (Anthropic's shared egress
    /// CIDR is exempted from per-IP throttling, so this global cap is the
    /// remaining defense against a registration flood).
    pub async fn count_unconsumed_oauth_clients(
        &self,
        within: std::time::Duration,
    ) -> Result<i64, AppError> {
        let secs = within.as_secs().min(i64::MAX as u64) as i64;
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mcp_oauth_clients c
             WHERE c.created_at > NOW() - ($1 * INTERVAL '1 second')
               AND NOT EXISTS (SELECT 1 FROM mcp_oauth_grants g WHERE g.client_id = c.client_id)",
        )
        .bind(secs)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            AppError::Internal(format!("Failed to count unconsumed oauth clients: {}", e))
        })?;
        Ok(row.0)
    }

    pub async fn insert_oauth_delegate(
        &self,
        delegate: &oauth_rows::OAuthDelegateRow,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO mcp_oauth_delegates
                (delegate_ref, account_id, owner_address, delegate_public_key, delegate_address,
                 encrypted_private_key, label, status, tx_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&delegate.delegate_ref)
        .bind(&delegate.account_id)
        .bind(&delegate.owner_address)
        .bind(&delegate.delegate_public_key)
        .bind(&delegate.delegate_address)
        .bind(&delegate.encrypted_private_key)
        .bind(&delegate.label)
        .bind(&delegate.status)
        .bind(&delegate.tx_digest)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert oauth delegate: {}", e)))?;
        Ok(())
    }

    pub async fn fetch_oauth_delegate(
        &self,
        delegate_ref: &str,
    ) -> Result<Option<oauth_rows::OAuthDelegateRow>, AppError> {
        sqlx::query_as::<_, oauth_rows::OAuthDelegateRow>(
            "SELECT delegate_ref, account_id, owner_address, delegate_public_key, delegate_address,
                    encrypted_private_key, label, status, tx_digest
             FROM mcp_oauth_delegates WHERE delegate_ref = $1",
        )
        .bind(delegate_ref)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch oauth delegate: {}", e)))
    }

    /// A delegate this account already activated for a *previous* OAuth
    /// grant, if any. Checked before minting a brand-new delegate keypair at
    /// `/oauth/authorize` time so a user reconnecting the same account
    /// doesn't have to sign another on-chain `add_delegate_key` tx and burn
    /// another slot toward the on-chain 20-key cap.
    pub async fn find_reusable_oauth_delegate(
        &self,
        account_id: &str,
    ) -> Result<Option<oauth_rows::OAuthDelegateRow>, AppError> {
        sqlx::query_as::<_, oauth_rows::OAuthDelegateRow>(
            "SELECT delegate_ref, account_id, owner_address, delegate_public_key, delegate_address,
                    encrypted_private_key, label, status, tx_digest
             FROM mcp_oauth_delegates
             WHERE account_id = $1 AND status = 'active'
             ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to query reusable oauth delegate: {}", e)))
    }

    pub async fn activate_oauth_delegate(
        &self,
        delegate_ref: &str,
        account_id: &str,
        owner_address: &str,
        tx_digest: &str,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE mcp_oauth_delegates
             SET account_id = $2, owner_address = $3, tx_digest = $4, status = 'active', updated_at = NOW()
             WHERE delegate_ref = $1",
        )
        .bind(delegate_ref)
        .bind(account_id)
        .bind(owner_address)
        .bind(tx_digest)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to activate oauth delegate: {}", e)))?;
        Ok(())
    }

    /// Retire a reusable delegate that can no longer authenticate, so
    /// `session_account` stops offering it. The refresh path uses
    /// `revoke_oauth_grant_and_delegate` instead, which retires the delegate
    /// in the same transaction that revokes its grant.
    pub async fn revoke_oauth_delegate(&self, delegate_ref: &str) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE mcp_oauth_delegates SET status = 'revoked', updated_at = NOW() WHERE delegate_ref = $1",
        )
        .bind(delegate_ref)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to revoke oauth delegate: {}", e)))?;
        Ok(())
    }

    pub async fn insert_oauth_session(
        &self,
        session: &oauth_rows::OAuthSessionRow,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO mcp_oauth_authorize_sessions
                (session_id, client_id, redirect_uri, state, scope, resource, code_challenge,
                 code_challenge_method, delegate_ref, status, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&session.session_id)
        .bind(&session.client_id)
        .bind(&session.redirect_uri)
        .bind(&session.state)
        .bind(&session.scope)
        .bind(&session.resource)
        .bind(&session.code_challenge)
        .bind(&session.code_challenge_method)
        .bind(&session.delegate_ref)
        .bind(&session.status)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert oauth session: {}", e)))?;
        Ok(())
    }

    pub async fn fetch_oauth_session(
        &self,
        session_id: &str,
    ) -> Result<Option<oauth_rows::OAuthSessionRow>, AppError> {
        sqlx::query_as::<_, oauth_rows::OAuthSessionRow>(
            "SELECT session_id, client_id, redirect_uri, state, scope, resource, code_challenge,
                    code_challenge_method, delegate_ref, status, expires_at
             FROM mcp_oauth_authorize_sessions
             WHERE session_id = $1 AND expires_at > NOW()",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch oauth session: {}", e)))
    }

    /// Atomically claim a pending session so it can't be completed twice —
    /// `UPDATE ... WHERE status = 'pending' RETURNING *` is the Postgres
    /// equivalent of the WALM-30 prior art's Redis `GETDEL` single-use
    /// guarantee (decision D3).
    pub async fn consume_oauth_session(
        &self,
        session_id: &str,
    ) -> Result<Option<oauth_rows::OAuthSessionRow>, AppError> {
        sqlx::query_as::<_, oauth_rows::OAuthSessionRow>(
            "UPDATE mcp_oauth_authorize_sessions
             SET status = 'consumed'
             WHERE session_id = $1 AND status = 'pending' AND expires_at > NOW()
             RETURNING session_id, client_id, redirect_uri, state, scope, resource, code_challenge,
                       code_challenge_method, delegate_ref, status, expires_at",
        )
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to consume oauth session: {}", e)))
    }

    pub async fn insert_oauth_code(&self, code: &oauth_rows::OAuthCodeRow) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO mcp_oauth_codes
                (code_sha256, client_id, redirect_uri, scope, resource, code_challenge,
                 code_challenge_method, delegate_ref, account_id, owner_address, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&code.code_sha256)
        .bind(&code.client_id)
        .bind(&code.redirect_uri)
        .bind(&code.scope)
        .bind(&code.resource)
        .bind(&code.code_challenge)
        .bind(&code.code_challenge_method)
        .bind(&code.delegate_ref)
        .bind(&code.account_id)
        .bind(&code.owner_address)
        .bind(code.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert oauth code: {}", e)))?;
        Ok(())
    }

    pub async fn fetch_oauth_code(
        &self,
        client_id: &str,
        code_sha256: &str,
    ) -> Result<Option<oauth_rows::OAuthCodeRow>, AppError> {
        sqlx::query_as::<_, oauth_rows::OAuthCodeRow>(
            "SELECT code_sha256, client_id, redirect_uri, scope, resource, code_challenge,
                    code_challenge_method, delegate_ref, account_id, owner_address, expires_at
             FROM mcp_oauth_codes
             WHERE code_sha256 = $1 AND client_id = $2 AND expires_at > NOW()",
        )
        .bind(code_sha256)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to read oauth code: {}", e)))
    }

    /// Single-use consume via `DELETE ... RETURNING` — the first successful
    /// exchange deletes the row; any replay finds nothing. Also filters on
    /// `client_id` so a code minted for one client can never be redeemed by
    /// another, even under a future refactor bug (defense in depth, same
    /// reasoning as the WALM-30 prior art's `app_auth_token` doc comment).
    pub async fn consume_oauth_code(
        &self,
        client_id: &str,
        code_sha256: &str,
    ) -> Result<Option<oauth_rows::OAuthCodeRow>, AppError> {
        sqlx::query_as::<_, oauth_rows::OAuthCodeRow>(
            "DELETE FROM mcp_oauth_codes
             WHERE code_sha256 = $1 AND client_id = $2 AND expires_at > NOW()
             RETURNING code_sha256, client_id, redirect_uri, scope, resource, code_challenge,
                       code_challenge_method, delegate_ref, account_id, owner_address, expires_at",
        )
        .bind(code_sha256)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to consume oauth code: {}", e)))
    }

    pub async fn insert_oauth_grant(
        &self,
        grant: &oauth_rows::OAuthGrantRow,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO mcp_oauth_grants
                (grant_id, client_id, delegate_ref, account_id, owner_address, scope, resource)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&grant.grant_id)
        .bind(&grant.client_id)
        .bind(&grant.delegate_ref)
        .bind(&grant.account_id)
        .bind(&grant.owner_address)
        .bind(&grant.scope)
        .bind(&grant.resource)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert oauth grant: {}", e)))?;
        Ok(())
    }

    /// Revokes a grant and every token derived from it in one statement —
    /// this is the entire "disconnect this connector" operation (and the
    /// refresh-token-reuse-detection response, see `resolve_oauth_bearer`).
    pub async fn revoke_oauth_grant(&self, grant_id: &str) -> Result<(), AppError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to start tx: {}", e)))?;
        sqlx::query("UPDATE mcp_oauth_grants SET revoked_at = NOW() WHERE grant_id = $1 AND revoked_at IS NULL")
            .bind(grant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to revoke oauth grant: {}", e)))?;
        sqlx::query(
            "UPDATE mcp_oauth_tokens SET revoked_at = NOW() WHERE grant_id = $1 AND revoked_at IS NULL",
        )
        .bind(grant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to revoke oauth grant tokens: {}", e)))?;
        tx.commit().await.map_err(|e| {
            AppError::Internal(format!("Failed to commit oauth grant revocation: {}", e))
        })?;
        Ok(())
    }

    /// Revoke a grant (and its tokens) and retire the delegate it custodies,
    /// in one transaction.
    ///
    /// Used only when the delegate key is definitively gone from the chain
    /// (GH #1141): leaving the row `active` would let
    /// `find_reusable_oauth_delegate` hand the dead key to the next
    /// authorize, whose `/complete` rejects it after burning the session, so
    /// every reconnect retries the same failure. `revoke_oauth_grant` stays
    /// delegate-agnostic because ordinary disconnect (RFC 7009) must keep
    /// the delegate reusable across grants.
    pub async fn revoke_oauth_grant_and_delegate(
        &self,
        grant_id: &str,
        delegate_ref: &str,
    ) -> Result<(), AppError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to start tx: {}", e)))?;
        sqlx::query("UPDATE mcp_oauth_grants SET revoked_at = NOW() WHERE grant_id = $1 AND revoked_at IS NULL")
            .bind(grant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to revoke oauth grant: {}", e)))?;
        sqlx::query(
            "UPDATE mcp_oauth_tokens SET revoked_at = NOW() WHERE grant_id = $1 AND revoked_at IS NULL",
        )
        .bind(grant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to revoke oauth grant tokens: {}", e)))?;
        sqlx::query(
            "UPDATE mcp_oauth_delegates SET status = 'revoked', updated_at = NOW()
             WHERE delegate_ref = $1 AND status <> 'revoked'",
        )
        .bind(delegate_ref)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to revoke oauth delegate: {}", e)))?;
        tx.commit().await.map_err(|e| {
            AppError::Internal(format!(
                "Failed to commit oauth grant and delegate revocation: {}",
                e
            ))
        })?;
        Ok(())
    }

    pub async fn insert_oauth_token(
        &self,
        token: &oauth_rows::OAuthTokenRow,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO mcp_oauth_tokens (token_sha256, grant_id, token_type, expires_at)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&token.token_sha256)
        .bind(&token.grant_id)
        .bind(&token.token_type)
        .bind(token.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to insert oauth token: {}", e)))?;
        Ok(())
    }

    /// Resolve a hashed bearer token all the way to the delegate it
    /// authorizes, joining through the grant. This is the query the proxy's
    /// `resolve_oauth_bearer` (PR3) runs on every MCP request, so it's a
    /// single round trip rather than N+1.
    pub async fn fetch_oauth_token_with_delegate(
        &self,
        token_sha256: &str,
    ) -> Result<Option<oauth_rows::OAuthTokenWithDelegateRow>, AppError> {
        sqlx::query_as::<_, oauth_rows::OAuthTokenWithDelegateRow>(
            "SELECT t.token_sha256, t.grant_id, t.token_type, t.expires_at, t.revoked_at,
                    g.client_id, g.account_id, g.owner_address, g.scope, g.revoked_at AS grant_revoked_at,
                    d.delegate_ref, d.encrypted_private_key, d.delegate_public_key, d.status AS delegate_status
             FROM mcp_oauth_tokens t
             JOIN mcp_oauth_grants g ON g.grant_id = t.grant_id
             JOIN mcp_oauth_delegates d ON d.delegate_ref = g.delegate_ref
             WHERE t.token_sha256 = $1",
        )
        .bind(token_sha256)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to fetch oauth token: {}", e)))
    }

    pub async fn revoke_oauth_token(&self, token_sha256: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE mcp_oauth_tokens SET revoked_at = NOW() WHERE token_sha256 = $1")
            .bind(token_sha256)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to revoke oauth token: {}", e)))?;
        Ok(())
    }

    /// Atomically consume one active refresh token and insert its replacement
    /// pair. The grant's client id is checked inside the same transaction.
    pub async fn rotate_oauth_refresh_token(
        &self,
        presented_sha256: &str,
        client_id: &str,
        access: &oauth_rows::OAuthTokenRow,
        refresh: &oauth_rows::OAuthTokenRow,
    ) -> Result<Option<oauth_rows::OAuthTokenWithDelegateRow>, AppError> {
        let mut tx = self.pool.begin().await.map_err(|e| {
            AppError::Internal(format!("Failed to start oauth refresh rotation: {}", e))
        })?;
        let consumed = sqlx::query_as::<_, oauth_rows::OAuthTokenWithDelegateRow>(
            "UPDATE mcp_oauth_tokens t
             SET revoked_at = NOW()
             FROM mcp_oauth_grants g, mcp_oauth_delegates d
             WHERE t.token_sha256 = $1
               AND t.grant_id = g.grant_id
               AND g.delegate_ref = d.delegate_ref
               AND t.token_type = 'refresh'
               AND t.revoked_at IS NULL
               AND t.expires_at > NOW()
               AND g.revoked_at IS NULL
               AND g.client_id = $2
             RETURNING t.token_sha256, t.grant_id, t.token_type, t.expires_at, t.revoked_at,
                       g.client_id, g.account_id, g.owner_address, g.scope,
                       g.revoked_at AS grant_revoked_at, d.delegate_ref,
                       d.encrypted_private_key, d.delegate_public_key,
                       d.status AS delegate_status",
        )
        .bind(presented_sha256)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to consume oauth refresh token: {}", e)))?;
        if consumed.is_none() {
            tx.rollback().await.map_err(|e| {
                AppError::Internal(format!("Failed to roll back oauth refresh rotation: {}", e))
            })?;
            return Ok(None);
        }
        for token in [access, refresh] {
            sqlx::query(
                "INSERT INTO mcp_oauth_tokens (token_sha256, grant_id, token_type, expires_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&token.token_sha256)
            .bind(&token.grant_id)
            .bind(&token.token_type)
            .bind(token.expires_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to insert rotated oauth token: {}", e))
            })?;
        }
        tx.commit().await.map_err(|e| {
            AppError::Internal(format!("Failed to commit oauth refresh rotation: {}", e))
        })?;
        Ok(consumed)
    }

    /// Periodic sweep for the hourly eviction task (mirrors
    /// `evict_expired_delegate_keys`): clears expired authorize sessions and
    /// authorization codes. Grants/tokens/clients/delegates are durable and
    /// are NOT touched here — only ever revoked explicitly.
    pub async fn evict_expired_oauth_state(&self) -> Result<u64, AppError> {
        let mut total = 0u64;
        let sessions =
            sqlx::query("DELETE FROM mcp_oauth_authorize_sessions WHERE expires_at <= NOW()")
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    AppError::Internal(format!("Failed to evict expired oauth sessions: {}", e))
                })?;
        total += sessions.rows_affected();
        let codes = sqlx::query("DELETE FROM mcp_oauth_codes WHERE expires_at <= NOW()")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                AppError::Internal(format!("Failed to evict expired oauth codes: {}", e))
            })?;
        total += codes.rows_affected();
        let pending = sqlx::query(
            "DELETE FROM mcp_oauth_delegates d
             WHERE d.status = 'pending'
               AND d.created_at <= NOW() - INTERVAL '1 hour'
               AND NOT EXISTS (
                   SELECT 1 FROM mcp_oauth_authorize_sessions s
                   WHERE s.delegate_ref = d.delegate_ref
               )
               AND NOT EXISTS (
                   SELECT 1 FROM mcp_oauth_codes c
                   WHERE c.delegate_ref = d.delegate_ref
               )
               AND NOT EXISTS (
                   SELECT 1 FROM mcp_oauth_grants g
                   WHERE g.delegate_ref = d.delegate_ref
               )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AppError::Internal(format!("Failed to prune abandoned oauth delegates: {}", e))
        })?;
        total += pending.rows_affected();
        if total > 0 {
            tracing::info!(
                "Evicted {} expired MCP OAuth session/code/pending-delegate rows",
                total
            );
        }
        Ok(total)
    }

    /// DCR clients registered more than 24h ago that never completed a
    /// grant. Claude registers a fresh client on every new connection
    /// (expected, per Anthropic's docs), so this table grows without bound
    /// unless swept — see the plan's "DCR client-table growth" risk note.
    pub async fn prune_unconsumed_oauth_clients(&self) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE FROM mcp_oauth_clients c
             WHERE c.created_at <= NOW() - INTERVAL '24 hours'
               AND NOT EXISTS (SELECT 1 FROM mcp_oauth_grants g WHERE g.client_id = c.client_id)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            AppError::Internal(format!("Failed to prune unconsumed oauth clients: {}", e))
        })?;
        let rows = result.rows_affected();
        if rows > 0 {
            tracing::info!("Pruned {} unconsumed MCP OAuth DCR clients", rows);
        }
        Ok(rows)
    }

    /// Return blob_ids that have permanently failed to restore for `owner` +
    /// `namespace` (GH #501 / WALM-299). Used by restore() to exclude blobs
    /// that already failed decrypt/validation once and should never be
    /// re-downloaded and re-decrypt-attempted on every subsequent restore() call.
    pub async fn get_failed_blob_ids(
        &self,
        owner: &str,
        namespace: &str,
    ) -> Result<Vec<String>, AppError> {
        let started = std::time::Instant::now();
        let result: Result<Vec<(String,)>, AppError> = sqlx::query_as(
            "SELECT blob_id FROM restore_failed_blobs
             WHERE owner = $1 AND namespace = $2",
        )
        .bind(owner)
        .bind(namespace)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get failed blobs: {}", e)));
        crate::observability::observe_db(
            "vector.get_failed_blob_ids",
            db_status(&result),
            started.elapsed(),
        );
        let rows = result?;

        Ok(rows.into_iter().map(|(blob_id,)| blob_id).collect())
    }

    /// Record that `blob_id` permanently failed to restore for `owner` +
    /// `namespace` (GH #501 / WALM-299). `reason` is `"decrypt_permanent"`
    /// (SEAL rejected it deterministically) or `"invalid_utf8"`
    /// (decrypt succeeded but the plaintext wasn't valid UTF-8). Repeated
    /// calls for the same (owner, namespace, blob_id) bump `attempts`
    /// instead of erroring or duplicating the row.
    pub async fn record_restore_failure(
        &self,
        owner: &str,
        namespace: &str,
        blob_id: &str,
        reason: &str,
    ) -> Result<(), AppError> {
        let started = std::time::Instant::now();
        let result = sqlx::query(
            "INSERT INTO restore_failed_blobs (owner, namespace, blob_id, reason)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (owner, namespace, blob_id) DO UPDATE SET
                attempts = restore_failed_blobs.attempts + 1,
                last_attempt_at = now(),
                reason = EXCLUDED.reason",
        )
        .bind(owner)
        .bind(namespace)
        .bind(blob_id)
        .bind(reason)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to record restore failure: {}", e)));
        crate::observability::observe_db(
            "vector.record_restore_failure",
            db_status(&result),
            started.elapsed(),
        );
        result?;

        Ok(())
    }
}

/// Row types for the MCP OAuth tables (`sqlx::FromRow`) — kept in their own
/// submodule so `db.rs`'s existing tuple-based queries elsewhere aren't
/// disturbed by this file's naming.
pub mod oauth_rows {
    use chrono::{DateTime, Utc};

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct OAuthClientRow {
        pub client_id: String,
        pub client_secret_sha256: Option<String>,
        pub client_name: String,
        pub redirect_uris: Vec<String>,
        pub grant_types: Vec<String>,
        pub response_types: Vec<String>,
        pub token_endpoint_auth_method: String,
        pub scope: String,
        pub status: String,
        pub registered_ip: Option<String>,
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct OAuthDelegateRow {
        pub delegate_ref: String,
        pub account_id: Option<String>,
        pub owner_address: Option<String>,
        pub delegate_public_key: String,
        pub delegate_address: String,
        pub encrypted_private_key: String,
        pub label: String,
        pub status: String,
        pub tx_digest: Option<String>,
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct OAuthSessionRow {
        pub session_id: String,
        pub client_id: String,
        pub redirect_uri: String,
        pub state: Option<String>,
        pub scope: String,
        pub resource: String,
        pub code_challenge: String,
        pub code_challenge_method: String,
        pub delegate_ref: String,
        pub status: String,
        pub expires_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct OAuthCodeRow {
        pub code_sha256: String,
        pub client_id: String,
        pub redirect_uri: String,
        pub scope: String,
        pub resource: String,
        pub code_challenge: String,
        pub code_challenge_method: String,
        pub delegate_ref: String,
        pub account_id: String,
        pub owner_address: String,
        pub expires_at: DateTime<Utc>,
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct OAuthGrantRow {
        pub grant_id: String,
        pub client_id: String,
        pub delegate_ref: String,
        pub account_id: String,
        pub owner_address: String,
        pub scope: String,
        pub resource: String,
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct OAuthTokenRow {
        pub token_sha256: String,
        pub grant_id: String,
        pub token_type: String,
        pub expires_at: DateTime<Utc>,
    }

    /// Denormalized join result for resolving a bearer token straight
    /// through to signable delegate material — what `resolve_oauth_bearer`
    /// (PR3) needs in one round trip. Most fields are unread until PR3
    /// wires up the proxy-side consumer.
    #[allow(dead_code)]
    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct OAuthTokenWithDelegateRow {
        pub token_sha256: String,
        pub grant_id: String,
        pub token_type: String,
        pub expires_at: DateTime<Utc>,
        pub revoked_at: Option<DateTime<Utc>>,
        pub client_id: String,
        pub account_id: String,
        pub owner_address: String,
        pub scope: String,
        pub grant_revoked_at: Option<DateTime<Utc>>,
        pub delegate_ref: String,
        pub encrypted_private_key: String,
        pub delegate_public_key: String,
        pub delegate_status: String,
    }
}

// ============================================================
// Storage quota admission — concurrency regression tests
// ============================================================
//
// These pin the fix for GH #532 / WALM-359 against a real PostgreSQL, because
// the defect only exists in the interleaving of concurrent transactions. An
// in-process fake would serialize the very thing under test and pass against
// the broken code.
//
// Shape mirrors the reproduction on the issue: seed an owner just under quota
// so exactly one more write fits, fire a 20-way burst, and assert exactly one
// admission. Against the old read-then-commit-then-insert code the same
// harness admitted 13 to 20 of 20.
//
// Requires DATABASE_URL (or the local default) to point at a Postgres with
// pgvector. Marked #[ignore] to match the existing convention for tests with
// external dependencies — run with `cargo test -- --ignored`.
#[cfg(test)]
mod quota_admission_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    /// Matches the real default in `rate_limit::RateLimitConfig` (1 GiB).
    const MAX_BYTES: i64 = 1_073_741_824;
    /// Per-request size for the burst. Arbitrary but fixed, so the seed below
    /// can leave room for exactly one.
    const ITEM_BYTES: i64 = 1_048_576;
    const BURST: usize = 20;
    const TTL: Duration = Duration::from_secs(900);

    fn test_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://memwal:memwal_secret@localhost:5432/memwal".into())
    }

    async fn test_db() -> VectorDb {
        super::test_vector_db(&test_database_url()).await
    }

    /// Unique per test so concurrent runs cannot see each other's rows, and so
    /// a failed run leaves no state that poisons the next one.
    fn unique_owner(tag: &str) -> String {
        format!("0xtest-{}-{}", tag, uuid::Uuid::new_v4())
    }

    fn lock_key(owner: &str) -> i64 {
        // Same FNV-1a folding as `rate_limit::stable_hash_i64`. Duplicated
        // rather than imported so this test pins the DB layer's contract on
        // its own, independent of the caller.
        const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
        const FNV_PRIME: u64 = 1_099_511_628_211;
        let hash = owner
            .bytes()
            .fold(FNV_OFFSET, |acc, b| acc.wrapping_mul(FNV_PRIME) ^ b as u64);
        ((hash >> 32) ^ (hash & 0xFFFF_FFFF)) as i64
    }

    fn zero_vector() -> Vec<f32> {
        vec![0.0; 1536]
    }

    /// Seed committed usage so exactly one `ITEM_BYTES` write still fits.
    async fn seed_to_one_slot_remaining(db: &VectorDb, owner: &str) {
        let seeded = MAX_BYTES - ITEM_BYTES;
        db.insert_vector(
            &format!("seed-{}", uuid::Uuid::new_v4()),
            owner,
            "default",
            "seed-blob",
            &zero_vector(),
            seeded,
            0.5,
            None,
            None,
            None,
        )
        .await
        .expect("seed insert");
    }

    async fn committed_bytes(db: &VectorDb, owner: &str) -> i64 {
        let row: (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(blob_size_bytes)::BIGINT, 0) FROM vector_entries WHERE owner = $1",
        )
        .bind(owner)
        .fetch_one(db.pool())
        .await
        .unwrap();
        row.0
    }

    async fn cleanup(db: &VectorDb, owner: &str) {
        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(owner)
            .execute(db.pool())
            .await;
        let _ = sqlx::query("DELETE FROM storage_reservations WHERE owner = $1")
            .bind(owner)
            .execute(db.pool())
            .await;
    }

    /// Inline path: admission immediately followed by the insert.
    ///
    /// This is the cheap case (microseconds between check and write) and it
    /// still overshot before the fix.
    #[tokio::test]
    #[ignore]
    async fn burst_admits_exactly_one_inline() {
        let db = Arc::new(test_db().await);
        let owner = unique_owner("inline");
        seed_to_one_slot_remaining(&db, &owner).await;

        let mut handles = Vec::with_capacity(BURST);
        for _ in 0..BURST {
            let db = Arc::clone(&db);
            let owner = owner.clone();
            handles.push(tokio::spawn(async move {
                let id = uuid::Uuid::new_v4().to_string();
                let admission = db
                    .admit_storage_reservations(
                        &owner,
                        lock_key(&owner),
                        MAX_BYTES,
                        &[StorageReservationRequest {
                            id: id.clone(),
                            bytes: ITEM_BYTES,
                        }],
                        TTL,
                    )
                    .await
                    .expect("admission must not error");

                if admission != StorageAdmission::Admitted {
                    return false;
                }

                db.insert_vector(
                    &id,
                    &owner,
                    "default",
                    "blob",
                    &zero_vector(),
                    ITEM_BYTES,
                    0.5,
                    None,
                    None,
                    None,
                )
                .await
                .expect("insert");
                db.release_storage_reservations(&[id]).await;
                true
            }));
        }

        let mut admitted = 0usize;
        for h in handles {
            if h.await.unwrap() {
                admitted += 1;
            }
        }

        let total = committed_bytes(&db, &owner).await;
        cleanup(&db, &owner).await;

        assert_eq!(
            admitted, 1,
            "exactly one of {} concurrent requests should be admitted, got {}",
            BURST, admitted
        );
        assert!(
            total <= MAX_BYTES,
            "committed bytes {} must never exceed quota {}",
            total,
            MAX_BYTES
        );
    }

    /// Enqueued path: admission, then a delay standing in for the Walrus
    /// upload, then the insert.
    ///
    /// This is the severe case. The gap is real (documented as up to five
    /// minutes) and before the fix a 150 ms gap was enough to admit the entire
    /// burst. The delay here is what makes the test meaningful, so it must not
    /// be optimised away.
    #[tokio::test]
    #[ignore]
    async fn burst_admits_exactly_one_with_delayed_insert() {
        let db = Arc::new(test_db().await);
        let owner = unique_owner("enqueued");
        seed_to_one_slot_remaining(&db, &owner).await;

        let mut handles = Vec::with_capacity(BURST);
        for _ in 0..BURST {
            let db = Arc::clone(&db);
            let owner = owner.clone();
            handles.push(tokio::spawn(async move {
                let id = uuid::Uuid::new_v4().to_string();
                let admission = db
                    .admit_storage_reservations(
                        &owner,
                        lock_key(&owner),
                        MAX_BYTES,
                        &[StorageReservationRequest {
                            id: id.clone(),
                            bytes: ITEM_BYTES,
                        }],
                        TTL,
                    )
                    .await
                    .expect("admission must not error");

                if admission != StorageAdmission::Admitted {
                    return false;
                }

                // Stands in for embed → encrypt → Walrus upload.
                tokio::time::sleep(Duration::from_millis(150)).await;

                db.insert_vector(
                    &id,
                    &owner,
                    "default",
                    "blob",
                    &zero_vector(),
                    ITEM_BYTES,
                    0.5,
                    None,
                    None,
                    None,
                )
                .await
                .expect("insert");
                db.release_storage_reservations(&[id]).await;
                true
            }));
        }

        let mut admitted = 0usize;
        for h in handles {
            if h.await.unwrap() {
                admitted += 1;
            }
        }

        let total = committed_bytes(&db, &owner).await;
        cleanup(&db, &owner).await;

        assert_eq!(
            admitted, 1,
            "the upload gap must not let extra requests through: got {} of {}",
            admitted, BURST
        );
        assert!(
            total <= MAX_BYTES,
            "committed bytes {} must never exceed quota {}",
            total,
            MAX_BYTES
        );
    }

    /// A reservation must count against quota before any row exists. This is
    /// the single assertion that fails against the pre-fix code.
    #[tokio::test]
    #[ignore]
    async fn reservation_counts_before_the_row_lands() {
        let db = test_db().await;
        let owner = unique_owner("counts");
        seed_to_one_slot_remaining(&db, &owner).await;

        let first = db
            .admit_storage_reservations(
                &owner,
                lock_key(&owner),
                MAX_BYTES,
                &[StorageReservationRequest {
                    id: "res-first".into(),
                    bytes: ITEM_BYTES,
                }],
                TTL,
            )
            .await
            .unwrap();
        assert_eq!(first, StorageAdmission::Admitted);

        // No insert yet — the reservation alone must fill the slot.
        let second = db
            .admit_storage_reservations(
                &owner,
                lock_key(&owner),
                MAX_BYTES,
                &[StorageReservationRequest {
                    id: "res-second".into(),
                    bytes: ITEM_BYTES,
                }],
                TTL,
            )
            .await
            .unwrap();
        assert!(
            matches!(second, StorageAdmission::Rejected { .. }),
            "an outstanding reservation must block the next admission, got {:?}",
            second
        );

        cleanup(&db, &owner).await;
    }

    /// Releasing must hand the quota straight back, so a failed or completed
    /// write does not cost the owner capacity until TTL.
    #[tokio::test]
    #[ignore]
    async fn release_frees_quota_immediately() {
        let db = test_db().await;
        let owner = unique_owner("release");
        seed_to_one_slot_remaining(&db, &owner).await;

        let req = [StorageReservationRequest {
            id: "res-release".into(),
            bytes: ITEM_BYTES,
        }];
        assert_eq!(
            db.admit_storage_reservations(&owner, lock_key(&owner), MAX_BYTES, &req, TTL)
                .await
                .unwrap(),
            StorageAdmission::Admitted
        );

        db.release_storage_reservations(&["res-release".to_string()])
            .await;

        assert_eq!(
            db.admit_storage_reservations(&owner, lock_key(&owner), MAX_BYTES, &req, TTL)
                .await
                .unwrap(),
            StorageAdmission::Admitted,
            "released bytes must be immediately reusable"
        );

        cleanup(&db, &owner).await;
    }

    /// The TTL backstop: a reservation nobody ever released must stop counting,
    /// so a missed release can never make an account permanently unusable.
    #[tokio::test]
    #[ignore]
    async fn expired_reservation_stops_counting() {
        let db = test_db().await;
        let owner = unique_owner("ttl");
        seed_to_one_slot_remaining(&db, &owner).await;

        // Zero TTL: expired the moment it is written, standing in for a
        // reservation whose release never came.
        assert_eq!(
            db.admit_storage_reservations(
                &owner,
                lock_key(&owner),
                MAX_BYTES,
                &[StorageReservationRequest {
                    id: "res-stale".into(),
                    bytes: ITEM_BYTES,
                }],
                Duration::from_secs(0),
            )
            .await
            .unwrap(),
            StorageAdmission::Admitted
        );

        assert_eq!(
            db.admit_storage_reservations(
                &owner,
                lock_key(&owner),
                MAX_BYTES,
                &[StorageReservationRequest {
                    id: "res-after-stale".into(),
                    bytes: ITEM_BYTES,
                }],
                TTL,
            )
            .await
            .unwrap(),
            StorageAdmission::Admitted,
            "an expired reservation must not hold quota"
        );

        db.sweep_expired_storage_reservations().await.unwrap();

        cleanup(&db, &owner).await;
    }

    /// Bulk admission is all-or-nothing, which is what keeps the existing
    /// "reject the whole request" behaviour and the 402 shape intact.
    #[tokio::test]
    #[ignore]
    async fn batch_admission_is_all_or_nothing() {
        let db = test_db().await;
        let owner = unique_owner("batch");
        seed_to_one_slot_remaining(&db, &owner).await;

        // Two items, only one slot.
        let outcome = db
            .admit_storage_reservations(
                &owner,
                lock_key(&owner),
                MAX_BYTES,
                &[
                    StorageReservationRequest {
                        id: "batch-a".into(),
                        bytes: ITEM_BYTES,
                    },
                    StorageReservationRequest {
                        id: "batch-b".into(),
                        bytes: ITEM_BYTES,
                    },
                ],
                TTL,
            )
            .await
            .unwrap();
        assert!(
            matches!(outcome, StorageAdmission::Rejected { .. }),
            "an over-quota batch must be rejected whole, got {:?}",
            outcome
        );

        let leaked: (i64,) =
            sqlx::query_as("SELECT COUNT(*)::BIGINT FROM storage_reservations WHERE owner = $1")
                .bind(&owner)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            leaked.0, 0,
            "a rejected batch must not leave partial reservations behind"
        );

        cleanup(&db, &owner).await;
    }
}

#[cfg(test)]
mod stale_sweep_tests {
    use super::*;
    use std::time::Duration;

    fn test_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://memwal:memwal_secret@localhost:5432/memwal".into())
    }

    async fn test_db() -> VectorDb {
        super::test_vector_db(&test_database_url()).await
    }

    /// Unique per test so concurrent runs cannot see each other's rows.
    fn unique_owner(tag: &str) -> String {
        format!("0xtest-{}-{}", tag, uuid::Uuid::new_v4())
    }

    /// Insert one remember job, aged by `age_secs`, optionally already prepared.
    ///
    /// `prepare_claimed_at` is stamped only alongside a claim token, because
    /// that is the only way a row can reach the database: the single-write
    /// path claims and stamps together, while `/api/remember/bulk` and
    /// `/api/analyze` insert neither. Stamping it unconditionally would hand
    /// every seeded row the one column the orphan sweep keys on, so a helper
    /// detail — not the sweep — would decide what the tests below prove.
    async fn seed_job(
        db: &VectorDb,
        owner: &str,
        status: &str,
        prepared: bool,
        claim_token: Option<&str>,
        age_secs: i64,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO remember_jobs
                 (id, owner, namespace, status, preparation_encrypted_b64,
                  prepare_claim_token, prepare_claimed_at, created_at, updated_at)
             VALUES ($1, $2, 'default', $3, $4, $5,
                     CASE WHEN $5::text IS NULL THEN NULL
                          ELSE NOW() - ($6 * INTERVAL '1 second') END,
                     NOW() - ($6 * INTERVAL '1 second'),
                     NOW() - ($6 * INTERVAL '1 second'))",
        )
        .bind(&id)
        .bind(owner)
        .bind(status)
        .bind(if prepared { Some("ZW5jcnlwdGVk") } else { None })
        .bind(claim_token)
        .bind(age_secs)
        .execute(&db.pool)
        .await
        .expect("seed remember job");
        id
    }

    async fn status_of(db: &VectorDb, id: &str) -> String {
        sqlx::query_scalar("SELECT status FROM remember_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .expect("read status")
    }

    /// A row committed by the route whose preparation never ran has no task
    /// left to resume it: preparation lives in a `tokio::spawn` inside the
    /// relayer, so a restart in that window strands it. Before this it sat at
    /// `pending` forever and `memwal_remember_status` reported it as still
    /// uploading — a write silently lost while the user was told it was coming.
    #[tokio::test]
    async fn orphaned_preparation_is_failed() {
        let db = test_db().await;
        let owner = unique_owner("orphan");
        let id = seed_job(&db, &owner, "pending", false, Some("claim-1"), 900).await;

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        assert_eq!(status_of(&db, &id).await, "failed");
        let msg: Option<String> =
            sqlx::query_scalar("SELECT error_msg FROM remember_jobs WHERE id = $1")
                .bind(&id)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert!(
            msg.unwrap_or_default().contains("never stored"),
            "the message has to say the fact is gone, not merely that a job died",
        );
    }

    /// The reason `pending` cannot be swept wholesale. A prepared job waits at
    /// `pending` until a wallet worker takes it, and with
    /// `WALRUS_UPLOAD_PER_WALLET_CONCURRENCY` defaulting to 1 that queue is
    /// legitimately minutes deep. Failing these would abandon paid work that
    /// was about to run.
    #[tokio::test]
    async fn prepared_job_waiting_on_the_upload_queue_is_left_alone() {
        let db = test_db().await;
        let owner = unique_owner("queued");
        let id = seed_job(&db, &owner, "pending", true, Some("claim-1"), 900).await;

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        assert_eq!(status_of(&db, &id).await, "pending");
    }

    /// Preparation itself takes a moment (summarize, embed, SEAL encrypt), so
    /// a young unprepared row is in-flight, not orphaned.
    #[tokio::test]
    async fn a_preparation_still_in_flight_is_left_alone() {
        let db = test_db().await;
        let owner = unique_owner("young");
        let id = seed_job(&db, &owner, "pending", false, Some("claim-1"), 5).await;

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        assert_eq!(status_of(&db, &id).await, "pending");
    }

    /// What makes the sweep safe against a preparation that was merely very
    /// slow rather than dead. Its own UPDATE is fenced on the claim token, so
    /// once the sweeper clears it that statement matches zero rows and the task
    /// returns before `enqueue_wallet_job` — it cannot mint a paid blob for a
    /// job just declared dead.
    #[tokio::test]
    async fn clearing_the_claim_fences_a_late_preparation() {
        let db = test_db().await;
        let owner = unique_owner("fence");
        let id = seed_job(&db, &owner, "pending", false, Some("claim-1"), 900).await;

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        // Exactly the statement `spawn_prepare_remember_job` runs when it
        // finishes, token and all.
        let late = sqlx::query(
            "UPDATE remember_jobs SET preparation_encrypted_b64 = $1, updated_at = NOW()
             WHERE id = $2 AND ($3::TEXT IS NULL OR prepare_claim_token = $3)",
        )
        .bind("ZW5jcnlwdGVk")
        .bind(&id)
        .bind("claim-1")
        .execute(&db.pool)
        .await
        .expect("late preparation");

        assert_eq!(
            late.rows_affected(),
            0,
            "a late preparation must be fenced out, or it would queue a paid write for a dead job",
        );
    }

    /// A congestion requeue leaves the row `running` with a prefixed
    /// error while the next attempt is already scheduled. The 10-minute
    /// sweep must not fail that wait. 45 minutes without a refresh is the
    /// lost-job backstop.
    #[tokio::test]
    async fn a_congestion_wait_survives_the_normal_sweep_and_dies_when_abandoned() {
        let db = test_db().await;
        let owner = unique_owner("congestion-wait");
        let waiting = seed_job(&db, &owner, "running", true, Some("claim-1"), 20 * 60).await;
        let abandoned = seed_job(&db, &owner, "running", true, Some("claim-2"), 50 * 60).await;
        let plain = seed_job(&db, &owner, "running", true, None, 20 * 60).await;
        let prefix = crate::jobs::CONGESTION_WAIT_ERROR_PREFIX;
        for id in [&waiting, &abandoned] {
            sqlx::query("UPDATE remember_jobs SET error_msg = $2 WHERE id = $1")
                .bind(id)
                .bind(format!(
                    "{prefix}timed out waiting for wallet 1 upload slot"
                ))
                .execute(&db.pool)
                .await
                .expect("stamp congestion wait");
        }

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        assert_eq!(status_of(&db, &waiting).await, "running");
        assert_eq!(status_of(&db, &abandoned).await, "failed");
        assert_eq!(status_of(&db, &plain).await, "failed");
    }

    /// A metadata retry writes the Enoki text while the row stays `uploaded`.
    /// If that retry then goes quiet, the sweep may fail the row, but it must
    /// keep the Enoki sentence. `COALESCE` only fills an empty `error_msg`.
    #[tokio::test]
    async fn an_uploaded_metadata_error_survives_the_stale_sweep() {
        let db = test_db().await;
        let owner = unique_owner("metadata-enoki");
        let id = seed_job(&db, &owner, "uploaded", true, None, 900).await;
        let enoki = "wallet job error (transient): Enoki API error (400): dry_run_failed Could not find the referenced object at version Some(SequenceNumber(1025755045))";
        sqlx::query("UPDATE remember_jobs SET error_msg = $2 WHERE id = $1")
            .bind(&id)
            .bind(enoki)
            .execute(&db.pool)
            .await
            .expect("stamp enoki error");

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        let row: (String, Option<String>) =
            sqlx::query_as("SELECT status, error_msg FROM remember_jobs WHERE id = $1")
                .bind(&id)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(row.0, "failed");
        let msg = row.1.unwrap_or_default();
        assert!(msg.contains("dry_run_failed"), "{msg}");
        assert!(
            msg.contains("Could not find the referenced object"),
            "{msg}"
        );
        assert!(!msg.contains("stale/orphaned"), "{msg}");
    }

    /// The pre-existing sweep is unchanged.
    #[tokio::test]
    async fn a_stalled_worker_claim_still_fails() {
        let db = test_db().await;
        let owner = unique_owner("running");
        let id = seed_job(&db, &owner, "running", true, None, 900).await;

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        assert_eq!(status_of(&db, &id).await, "failed");
    }

    /// `/api/remember/bulk` inserts its rows directly and never claims a
    /// preparation slot, so `preparation_encrypted_b64` is ALWAYS NULL for a
    /// bulk job — healthy or not. Keying the sweep on that column alone would
    /// fail every bulk write that waits out the TTL behind a normal upload
    /// backlog, destroying paid work that was about to run.
    #[tokio::test]
    async fn a_queued_bulk_job_is_never_swept() {
        let db = test_db().await;
        let owner = unique_owner("bulk");
        // Exactly what remember_bulk writes: pending, no claim, no preparation.
        let id = seed_job(&db, &owner, "pending", false, None, 900).await;

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        assert_eq!(
            status_of(&db, &id).await,
            "pending",
            "a bulk job waiting on the upload queue must survive the sweep",
        );
    }

    /// `/api/analyze` inserts the same shape (`prepare_claim_token: None`), so
    /// it needs the same protection.
    #[tokio::test]
    async fn a_queued_analyze_job_is_never_swept() {
        let db = test_db().await;
        let owner = unique_owner("analyze");
        let id = seed_job(&db, &owner, "pending", false, None, 3600).await;

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        assert_eq!(status_of(&db, &id).await, "pending");
    }

    /// A finished write is terminal and the sweeper must never touch it.
    #[tokio::test]
    async fn a_done_job_is_never_swept() {
        let db = test_db().await;
        let owner = unique_owner("done");
        let id = seed_job(&db, &owner, "done", true, None, 900).await;

        db.fail_stale_remember_jobs(Duration::from_secs(600))
            .await
            .expect("sweep");

        assert_eq!(status_of(&db, &id).await, "done");
    }
}

/// Sanitized by `sanitize_job_error_for_client`, as on every other
/// client-facing job-status path: an infrastructure-funding failure is
/// replaced wholesale (its raw text names the relayer's own wallet and
/// balance), and long hex runs are redacted.
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::alerts::AlertManager;
use crate::engine::MemoryEngine;
use crate::jobs::{BulkRememberJobStorage, RememberJobStorage, WalletJobStorage};
use crate::rate_limit::RateLimitConfig;
use crate::services::{Embedder, Extractor, Ranker};
use crate::storage::db::VectorDb;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Max items in a single POST /api/remember/bulk request.
pub const MAX_BULK_ITEMS: usize = 20;
/// Namespace values participate in a composite PostgreSQL B-tree index.
/// Keep them small enough that caller input can never exceed an index tuple.
pub const MAX_NAMESPACE_BYTES: usize = 255;

/// Bounded concurrency for concurrent embed+encrypt in bulk route handler.
pub const BULK_EMBED_CONCURRENCY: usize = 5;

/// Redis key prefix for Walrus ciphertext cache entries.
pub const BLOB_CACHE_KEY_PREFIX: &str = "memwal:blob:v1:";

/// Default max age for Redis-cached Walrus ciphertext before revalidating via Walrus.
pub const DEFAULT_BLOB_CACHE_TTL_SECS: u64 = 14 * 24 * 60 * 60;

/// Default maximum ciphertext size stored in Redis.
pub const DEFAULT_BLOB_CACHE_MAX_BYTES: usize = 512 * 1024;

/// Default max age for Redis-cached recall query embeddings.
pub const DEFAULT_EMBEDDING_CACHE_TTL_SECS: u64 = 10 * 60;

/// Prevent an accidental low interval from continuously polling Sui and the sidecar.
const MIN_BALANCE_MONITOR_INTERVAL_SECS: u64 = 30;

/// Upper bound for explicit Walrus storage purchases.
pub const MAX_WALRUS_STORAGE_EPOCHS: u32 = 15;
/// Hard ceiling for `OWNER_TOKEN_TTL_SECS` — 24 hours. Without a
/// bound, `env_positive_u64` accepts any positive u64, and a very large TTL
/// both defeats the "short-lived" security property the token scheme's
/// whole threat model rests on (see internal/api/owner-token-auth.md's
/// trust-boundary note) and can push `now + ttl` outside chrono's
/// representable range in `routes::owner_token::issue_token`'s `expires_at`
/// computation.
pub const MAX_OWNER_TOKEN_TTL_SECS: u64 = 24 * 60 * 60;
/// Minimum `OWNER_TOKEN_SECRET` length in bytes when the env var is set.
/// Unset or empty still disables the feature.
pub const MIN_OWNER_TOKEN_SECRET_LEN: usize = 32;
pub const DEFAULT_TESTNET_WALRUS_STORAGE_EPOCHS: u32 = 5;

pub(crate) fn default_walrus_storage_epochs_for_network(network: &str) -> u32 {
    match network {
        "mainnet" => 3,
        _ => DEFAULT_TESTNET_WALRUS_STORAGE_EPOCHS,
    }
}

pub(crate) fn configured_walrus_storage_epochs(network: &str) -> u32 {
    let default = default_walrus_storage_epochs_for_network(network);
    match std::env::var("WALRUS_STORAGE_EPOCHS")
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
    {
        Some(epochs) if epochs > 0 && epochs <= MAX_WALRUS_STORAGE_EPOCHS => epochs,
        Some(epochs) if epochs > MAX_WALRUS_STORAGE_EPOCHS => {
            tracing::warn!(
                "WALRUS_STORAGE_EPOCHS={} exceeds max {}; using default {} for {}",
                epochs,
                MAX_WALRUS_STORAGE_EPOCHS,
                default,
                network,
            );
            default
        }
        _ => default,
    }
}

/// Delay before racing a cold Walrus read against the next configured aggregator.
pub const DEFAULT_WALRUS_AGGREGATOR_RACE_AFTER_MS: u64 = 150;

pub const MAX_SECURITY_DELETE_EXECUTE_IN_FLIGHT: usize = 64;

/// Process-local admission gate for deletion transactions that all mutate
/// the Walrus System shared object. API submits and reconciler replays share
/// one instance; prepare/read RPCs and every other subsystem bypass it.
#[derive(Clone)]
pub struct SecurityDeleteExecutionGate {
    permits: Arc<Semaphore>,
}

impl SecurityDeleteExecutionGate {
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(max_in_flight)),
        }
    }

    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .expect("security-delete execution gate is never closed")
    }
}

/// Default accepted clock drift (seconds, each direction) between a client's
/// signed timestamp and the relayer's clock. A request is fresh when
/// `|now - timestamp| <= this`.
pub const DEFAULT_AUTH_CLOCK_DRIFT_SECS: i64 = 300;

/// Hard upper bound on the configurable clock-drift window. A wide window
/// lengthens the interval in which a captured (signature, nonce) pair could be
/// replayed if the nonce store were unavailable, so operators may tune the
/// window down but never past this ceiling. Values above it fall back to the
/// default.
pub const MAX_AUTH_CLOCK_DRIFT_SECS: i64 = 900;

/// Safety margin added on top of a request's full freshness lifetime when
/// computing the replay-nonce TTL. Freshness is symmetric, so a request can be
/// first accepted as early as `drift` seconds before its timestamp and remains
/// fresh until `drift` seconds after — a `2 * drift` span. The nonce TTL is
/// `2 * drift + NONCE_TTL_BUFFER_SECS` (see `auth::nonce_ttl_secs`), so the
/// record always outlives the window in which the same signature could be
/// replayed, whatever the window is tuned to.
pub const NONCE_TTL_BUFFER_SECS: i64 = 300;

/// Accepted timestamp drift window, from `AUTH_MAX_CLOCK_DRIFT_SECS`.
/// Bounded to `0..=MAX_AUTH_CLOCK_DRIFT_SECS`; 0 requires an exact-second match.
/// Out-of-range or unparseable values warn and fall back to the default.
pub(crate) fn configured_auth_clock_drift_secs() -> i64 {
    match std::env::var("AUTH_MAX_CLOCK_DRIFT_SECS")
        .ok()
        .and_then(|raw| raw.trim().parse::<i64>().ok())
    {
        Some(secs) if (0..=MAX_AUTH_CLOCK_DRIFT_SECS).contains(&secs) => secs,
        Some(secs) => {
            tracing::warn!(
                "AUTH_MAX_CLOCK_DRIFT_SECS={} out of range 0..={}; using default {}",
                secs,
                MAX_AUTH_CLOCK_DRIFT_SECS,
                DEFAULT_AUTH_CLOCK_DRIFT_SECS,
            );
            DEFAULT_AUTH_CLOCK_DRIFT_SECS
        }
        None => DEFAULT_AUTH_CLOCK_DRIFT_SECS,
    }
}

// ============================================================
// App State (shared across routes + middleware)
// ============================================================

/// Shared application state passed to all routes and middleware
pub struct AppState {
    /// `Arc` so the `MemoryEngine` impl can share the same handle rather
    /// than duplicating the pool.
    pub db: Arc<VectorDb>,
    /// Small dedicated pool used ONLY to hold a per-job advisory lock across an
    /// upload's guard-read → mint → persist section, so two attempts of the same
    /// job cannot both mint. The connection is checked out only after that
    /// wallet's upload permit is held; jobs waiting for a busy key do not take
    /// one. Kept separate from `db` so an in-flight upload never starves request
    /// handlers.
    pub wallet_lock_pool: sqlx::PgPool,
    /// Isolated old-V1 database. Present only when at least one tracked
    /// security-delete component is enabled.
    pub legacy_db: Option<Arc<crate::storage::legacy_db::LegacyDb>>,
    pub security_delete_nonce_store: Arc<dyn crate::security_delete_auth::NonceStore>,
    pub security_delete_wallet_verifier:
        Arc<dyn crate::security_delete_auth::WalletSignatureVerifier>,
    pub security_delete_sui: Option<Arc<dyn crate::sui::SuiApi>>,
    /// The same security-delete client and quota controls, tagged as
    /// background so resolver/reconciler traffic cannot consume reservations
    /// held for auth, prepare, and submit.
    pub security_delete_background_sui: Option<Arc<dyn crate::sui::SuiApi>>,
    /// General-purpose Sui client for on-chain reads unrelated to security
    /// deletion (currently: the per-memory expiry sweep's
    /// `walrus_epoch_schedule()` lookup). Unlike
    /// `security_delete_sui`, this is populated whenever `SUI_GRPC_URL` is
    /// configured, regardless of whether the security-delete component is
    /// enabled — the expiry sweep must work in deployments that don't run
    /// security deletion at all. `None` only when `SUI_GRPC_URL` itself is
    /// unset, in which case dependent background tasks log and skip rather
    /// than panic.
    pub walrus_sui_client: Option<Arc<dyn crate::sui::SuiApi>>,
    /// Shared only by security-delete API execution and reconciler replay.
    pub security_delete_execution_gate: Arc<SecurityDeleteExecutionGate>,
    /// `Arc` so the engine + handlers share one immutable config.
    pub config: Arc<Config>,
    pub http_client: reqwest::Client,
    /// Shared Sui gRPC client for onchain delegate-key verification, built
    /// once at startup. This client is intentionally independent of security
    /// deletion's quota gate.
    pub sui_grpc_client: Option<sui_rpc::Client>,
    /// Short-TTL (`storage::sui::DELEGATE_KEYS_CACHE_TTL`, mirrors
    /// `sui/client.rs`'s `Timed<WalrusEpoch>` window) in-memory cache of
    /// each account's on-chain delegate-key list, keyed by account object
    /// id. Backs `GET /v1/owners/{owner}/agents` so repeated calls within
    /// the TTL window don't re-hit the chain.
    pub delegate_keys_cache: crate::storage::sui::DelegateKeysCache,
    /// Short-TTL (`storage::sui::DELEGATE_VERIFY_CACHE_TTL`) in-memory
    /// cache of successful delegate-key verifications, keyed by
    /// `(account object id, public key)`. Shared by the signed-request
    /// auth middleware and the MCP proxy so a burst of requests carrying
    /// the same credentials costs one `GetObject` instead of one each
    /// (WALM-618).
    pub delegate_verify_cache: crate::storage::sui::DelegateVerifyCache,
    pub delegate_reject_cache: crate::storage::sui::DelegateRejectCache,
    /// In-flight MCP connect episodes, for `time_to_session`.
    pub mcp_connect_episodes: crate::observability::McpConnectEpisodes,
    /// Alert dispatchers for operational notifications. Individual alert
    /// paths decide when failures are terminal enough to notify.
    pub alerts: Arc<AlertManager>,
    /// Round-robin pool of Sui private keys for parallel Walrus uploads.
    /// `Arc` so the engine's `store_blob` can draw from the same pool.
    pub key_pool: Arc<KeyPool>,
    /// Persistence abstraction — `WalrusSealEngine` in production,
    /// `PlaintextEngine` in benchmark mode. Selected once at startup
    /// from `Config::benchmark_mode`. Handlers / job workers are mode-blind.
    pub engine: Arc<dyn MemoryEngine>,
    /// Embedding service — `OpenAiEmbedder` (text-embedding-3-small, with
    /// a deterministic mock fallback when no API key). Used by `analyze`,
    /// `remember` (per fact / summary), and `recall` (the query embedding).
    pub embedder: Arc<dyn Embedder>,
    /// LLM fact-extraction service — `LlmExtractor` (gpt-4o-mini). Used by
    /// `analyze`.
    pub extractor: Arc<dyn Extractor>,
    /// Recall re-ranker — `CompositeRanker` blends semantic similarity
    /// with optional recency decay. Used by `/api/recall` and `/api/ask`
    /// when the request body sets `scoring_weights`; default weights
    /// preserve the pgvector cosine order exactly.
    pub ranker: Arc<dyn Ranker>,
    /// Redis connection manager for rate limiting (reconnects after a drop)
    pub redis: redis::aio::ConnectionManager,
    /// In-memory token bucket fallback for when Redis is unavailable
    pub fallback_rate_limit: tokio::sync::Mutex<crate::rate_limit::InMemoryFallback>,
    /// Apalis storage for legacy RememberJob payloads. Kept so the worker can
    /// fail unfenced rows closed and surface them for reconciliation.
    #[allow(dead_code)]
    pub remember_job_storage: RememberJobStorage,
    /// Apalis storage for upload WalletJobs. Workers prefetch a batch from
    /// this queue. Routing dimension was previously a Vec<WalletJobStorage>
    /// keyed by wallet_index; that existed to side-step Sui coin-object
    /// equivocation locks. Per Will Bradley (Mysten, 2026-05-12 Slack
    /// callout): Sui no longer permanently locks coin objects on equivocation,
    /// so one upload queue + concurrent workers + retry handler is sufficient.
    /// See `plans/simplify-walrus-wallet-queues/reports/` for context.
    pub wallet_storage: WalletJobStorage,
    /// Metadata and finalize. Separate from `wallet_storage` so a certified
    /// blob is not stuck behind uploads a worker already prefetched.
    pub wallet_followup_storage: WalletJobStorage,
    /// Apalis storage for BulkRememberJob.
    pub bulk_job_storage: BulkRememberJobStorage,
    /// Redis TTL for Walrus blob ciphertext cache entries.
    /// Expiry forces Walrus revalidation so BlobNotFound still triggers cleanup.
    /// (Also cloned into `WalrusSealEngine` at construction so the engine
    /// shares the same TTL when serving recall.)
    pub blob_cache_ttl: std::time::Duration,
    /// Maximum SEAL ciphertext bytes to cache in Redis.
    /// Zero disables blob ciphertext reads and writes in Redis.
    /// (Also cloned into `WalrusSealEngine` for size-capped cache writes.)
    pub blob_cache_max_bytes: usize,
    /// Redis TTL for recall query embedding cache entries.
    pub embedding_cache_ttl: std::time::Duration,
}

// ============================================================
// Key Pool — round-robin wallet selection
// ============================================================

/// Wallet key holder for distributing Walrus uploads across configured server
/// keys. Routes and other non-retry callers use `next_index()` for round-robin
/// starting assignments; wallet-job retries derive their next index from the
/// job's starting index and attempt number.
pub struct KeyPool {
    keys: Vec<String>,
    cursor: AtomicUsize,
    /// Wallet transactions currently executing, per key.
    ///
    /// The sidecar enforces one upload at a time per wallet (concurrent
    /// transactions from one signer can equivocate its owned objects, which
    /// then stay locked until the epoch boundary). Blind round-robin does not
    /// know that, so it hands a job to a wallet that is mid-upload while other
    /// wallets sit idle — observed in production as a job waiting 6.2s for its
    /// assigned wallet while the global limiter still had two free slots and
    /// an empty queue.
    ///
    /// Counted per *executing attempt*, incremented and decremented inside one
    /// scope by `WalletAttemptGuard`. Nothing crosses the job-queue boundary,
    /// so a counter cannot drift: a restart zeroes it, which is accurate, and
    /// every early return still releases because `Drop` runs.
    inflight: Vec<AtomicUsize>,
}

impl KeyPool {
    pub fn new(keys: Vec<String>) -> Self {
        let inflight = keys.iter().map(|_| AtomicUsize::new(0)).collect();
        Self {
            keys,
            cursor: AtomicUsize::new(0),
            inflight,
        }
    }

    /// Returns the next configured key in round-robin order.
    #[allow(dead_code)]
    pub fn next(&self) -> Option<&str> {
        let idx = self.next_index()?;
        self.keys.get(idx).map(|s| s.as_str())
    }

    /// Returns the next key index in round-robin order, or `None` if no keys
    /// are configured.
    pub fn next_index(&self) -> Option<usize> {
        let len = self.keys.len();
        if len == 0 {
            None
        } else {
            Some(self.cursor.fetch_add(1, Ordering::Relaxed) % len)
        }
    }

    /// Returns the least-loaded key index, breaking ties in round-robin order.
    ///
    /// Join-shortest-queue rather than `next_index()`'s blind modulo: a wallet
    /// that is mid-upload is skipped in favour of an idle one, which is the
    /// whole point — the per-wallet limit is 1, so landing on a busy wallet
    /// means queueing behind it even when the pool has capacity.
    ///
    /// The tie-break matters as much as the minimum. On an idle pool every
    /// counter is 0, and a plain `argmin` would return index 0 every time,
    /// funnelling all traffic onto one wallet — strictly worse than the
    /// round-robin this replaces. Starting the scan at the rotating cursor
    /// keeps equally-loaded keys spreading exactly as before.
    pub fn least_loaded_index(&self) -> Option<usize> {
        let len = self.keys.len();
        if len == 0 {
            return None;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % len;
        let mut best = start;
        let mut best_load = self.inflight[start].load(Ordering::Relaxed);
        for step in 1..len {
            let idx = (start + step) % len;
            let load = self.inflight[idx].load(Ordering::Relaxed);
            // Strictly less, so the first key scanned — the cursor's own —
            // wins any tie and the rotation is preserved.
            if load < best_load {
                best = idx;
                best_load = load;
            }
        }
        Some(best)
    }

    /// Marks `index` busy for as long as the returned guard lives.
    ///
    /// Call this around the wallet transaction itself, not around enqueueing
    /// one: the counter is meant to answer "is this wallet signing right now",
    /// which is what the per-wallet limit actually serialises on.
    pub fn begin_attempt(self: &Arc<Self>, index: usize) -> WalletAttemptGuard {
        if let Some(slot) = self.inflight.get(index) {
            slot.fetch_add(1, Ordering::Relaxed);
        }
        WalletAttemptGuard {
            pool: Arc::clone(self),
            index,
        }
    }

    /// Picks the least-loaded key and marks it busy in one step.
    ///
    /// `least_loaded_index` followed later by `begin_attempt` leaves a gap.
    /// Every worker choosing inside that gap sees the same idle wallet, steers
    /// its job there, and pins it. On staging one wallet took 27 of a
    /// 100-job burst while most others got 3, and the run lasted as long as
    /// that one queue (bench-w9-merged-9e9a10c-r1). The compare-exchange makes
    /// the loser of a tie re-scan and see the wallet as taken.
    pub fn claim_least_loaded(self: &Arc<Self>) -> Option<WalletAttemptGuard> {
        loop {
            let index = self.least_loaded_index()?;
            let slot = &self.inflight[index];
            let seen = slot.load(Ordering::Relaxed);
            if slot
                .compare_exchange(seen, seen + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(WalletAttemptGuard {
                    pool: Arc::clone(self),
                    index,
                });
            }
        }
    }

    /// In-flight count per key. Observability only.
    pub fn inflight_snapshot(&self) -> Vec<usize> {
        self.inflight
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .collect()
    }

    fn end_attempt(&self, index: usize) {
        if let Some(slot) = self.inflight.get(index) {
            // Saturating: an extra release must not wrap to usize::MAX and
            // leave this key looking permanently busiest, which would exclude
            // it from selection for the life of the process.
            let _ = slot.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
        }
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// Releases a wallet's in-flight count when dropped.
///
/// A guard rather than paired calls because `execute_wallet_job` returns from
/// many points; every one of them has to decrement, and `Drop` is the only way
/// to get that for free — including while unwinding from a panic.
pub struct WalletAttemptGuard {
    pool: Arc<KeyPool>,
    index: usize,
}

impl WalletAttemptGuard {
    pub fn index(&self) -> usize {
        self.index
    }
}

impl Drop for WalletAttemptGuard {
    fn drop(&mut self) {
        self.pool.end_attempt(self.index);
    }
}

// ============================================================
// Config
// ============================================================

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub sui_rpc_url: String,
    /// Required gRPC endpoint for boot-time SEAL policy validation and onchain
    /// account/delegate-key verification.
    pub sui_grpc_url: Option<String>,
    /// network name (mainnet/testnet/devnet). Surfaced via
    /// `GET /config` so the SDK can select the matching Sui fullnode
    /// without the user having to configure it.
    pub sui_network: String,
    pub memwal_account_id: Option<String>,
    pub openai_api_key: Option<String>,
    pub openai_api_base: String,
    pub walrus_publisher_url: String,
    pub walrus_aggregator_url: String,
    /// Number of Walrus storage epochs requested for new uploads.
    pub walrus_storage_epochs: u32,
    /// Ordered aggregator candidates used for cold Walrus reads. The primary
    /// `walrus_aggregator_url` is always first; `WALRUS_AGGREGATOR_URLS`
    /// appends additional low-latency/proxy endpoints for tail-race reads.
    pub walrus_aggregator_urls: Vec<String>,
    /// Opt-in Walrus read optimization for blobs written by this relayer.
    /// When true, cold reads append `skip_consistency_check=true`.
    pub walrus_skip_consistency_check: bool,
    /// Delay before launching the next aggregator candidate on a cold read.
    /// Zero launches all configured candidates immediately.
    pub walrus_aggregator_race_after_ms: u64,
    /// Primary key (used for SEAL decrypt / recall). Unchanged.
    pub sui_private_key: Option<String>,
    /// Pool of keys for parallel Walrus uploads (parsed from SERVER_SUI_PRIVATE_KEYS,
    /// falls back to SERVER_SUI_PRIVATE_KEY as a single-element list).
    pub sui_private_keys: Vec<String>,
    /// Immutable original-publish package ID. This is the Move type origin and
    /// the SEAL ciphertext namespace; it must not change across upgrades.
    pub package_id: String,
    /// Package version whose `account::seal_approve` policy is executed for
    /// decrypts. Defaults to `package_id`, but moves to the latest published
    /// package after an upgrade without changing the ciphertext namespace.
    pub seal_policy_package_id: String,
    pub registry_id: String,
    /// URL of the Walrus upload sidecar. Upload work stays here.
    pub sidecar_url: String,
    /// Seal encrypt/decrypt. A different port from `sidecar_url` so recall
    /// does not wait on the upload process event loop.
    pub seal_sidecar_url: String,
    /// Shared secret for authenticating Rust→sidecar calls (X-Sidecar-Secret header)
    pub sidecar_secret: Option<String>,
    /// Reviewed SEAL committee identity pinned on every encryption request.
    /// The sidecar compares this JSON object to its effective key-server config.
    pub seal_expected_committee_identity: Option<serde_json::Value>,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Sponsor-specific rate limiting and concurrency config
    pub sponsor_rate_limit: SponsorRateLimitConfig,
    /// Dedicated rate-limit budget for the owner-scoped read API
    /// (`/v1/owners/{owner}/{namespaces,memories,agents}`), separate from
    /// the write path's `rate_limit` budget.
    pub read_api_rate_limit: ReadApiRateLimitConfig,
    /// Rate limiting for the public, unauthenticated `GET
    /// /api/accounts/{owner}/exists` endpoint
    pub accounts_rate_limit: AccountsRateLimitConfig,
    /// Hosted MCP (`/api/mcp`, `/api/mcp/sse`, `/api/mcp/messages`).
    /// Separate Redis keys from `accounts_rate_limit`.
    pub mcp_rate_limit: McpRateLimitConfig,
    /// Reverse-proxy hops trusted to append/sanitize X-Forwarded-For. Zero
    /// ignores caller-supplied XFF and uses the direct peer address.
    pub trusted_proxy_hops: usize,
    /// Allowed CORS origins (comma-separated, e.g. "http://localhost:3000,https://memwal.ai")
    pub allowed_origins: String,
    /// when true, select `PlaintextEngine` instead of
    /// `WalrusSealEngine` — memories are stored as plaintext in Postgres,
    /// bypassing SEAL + Walrus. **Not for production.** Off by default;
    /// set `BENCHMARK_MODE=true` to enable. Surfaced via `GET /health`.
    pub benchmark_mode: bool,
    /// Operator write-pause flag from `WRITES_PAUSED`. When true, write
    /// routes reject with HTTP 503 and `/health` reports `writes: "paused"`
    /// while staying HTTP 200. Distinct from sidecar liveness (`write_ready`).
    pub writes_paused: bool,
    /// Master visibility flag for the memory-deletion feature family.
    pub enable_memory_deletion: bool,
    /// Selects the tracked, backend-built security-delete flow. The master
    /// deletion flag must also be enabled. When false, the legacy
    /// handlers remain the only destructive API.
    pub enable_security_delete: bool,
    pub legacy_db_url: Option<String>,
    pub deletion_reconciler_enabled: bool,
    pub deletion_object_resolver_enabled: bool,
    pub delete_batch_max: usize,
    pub max_active_batches_per_owner: usize,
    pub security_delete_auth_requests_per_minute: u64,
    pub security_delete_prepare_requests_per_minute: u64,
    /// Process-local concurrency for deletion PTBs mutating the shared
    /// Walrus System object. Keep at one unless the target network is proven
    /// to tolerate a higher aggregate across all replicas.
    pub security_delete_execute_max_in_flight: usize,
    /// Secret-gated localnet crash failpoint. Unset by default.
    pub security_delete_crash_test_secret: Option<String>,
    /// Per-process rolling quota for the security-deletion Sui client.
    pub sui_rpc_requests_per_window: u32,
    pub sui_rpc_window: std::time::Duration,
    pub sui_rpc_attempt_timeout: std::time::Duration,
    pub sui_rpc_max_in_flight: usize,
    pub sponsor_private_key: Option<String>,
    pub sponsor_min_balance_alert: u64,
    pub claim_ttl_secs: u64,
    pub exec_grace_secs: u64,
    pub deletion_token_secret: Option<String>,
    pub deletion_token_ttl_secs: u64,
    pub expiry_margin_epochs: u64,
    pub walrus_package_id: String,
    pub walrus_system_object_id: String,
    /// Walrus staking pool object id — a SEPARATE shared object from
    /// walrus_system_object_id. The system state object (read by
    /// sui::client::walrus_epoch()) carries committee.epoch; this object's
    /// state carries epoch_duration/first_epoch_start, needed to convert a
    /// Walrus epoch into a wall-clock timestamp. Do not
    /// conflate the two ids.
    pub walrus_staking_pool_id: String,
    /// HMAC signing secret for owner-scoped bearer tokens
    /// (`OWNER_TOKEN_SECRET`). Typed `String` rather than `Option<String>`
    /// (unlike `deletion_token_secret`, whose env-loading idiom this
    /// otherwise mirrors — `nonempty_env`, trimmed): owner-token issuance
    /// isn't behind a separate feature flag the way security-delete is, so
    /// there's no natural "component disabled" state to model with `None`.
    /// An empty string means "not configured" — both `POST
    /// /v1/owner-tokens` and the `OwnerToken` extractor treat that as an
    /// unconditional rejection rather than letting an empty HMAC key
    /// validate (see `owner_token_auth::OwnerToken`'s doc comment).
    /// When set, the value must be at least [`MIN_OWNER_TOKEN_SECRET_LEN`]
    /// bytes or config load panics.
    pub owner_token_secret: String,
    /// The **service credential**: one static
    /// shared secret WM generates and hands to Console, which Console
    /// includes on every `POST /v1/owner-tokens` call
    /// (`OWNER_TOKEN_SERVICE_CREDENTIAL`, header
    /// `routes::owner_token::SERVICE_CREDENTIAL_HEADER`). Distinct from
    /// `owner_token_secret`, which only signs the minted tokens: this one
    /// authenticates the *client* calling the mint endpoint, and there is
    /// nothing else for that check to compare against. Same
    /// empty-string-means-unconfigured contract as `owner_token_secret`
    /// above.
    pub owner_token_service_credential: String,
    /// TTL for owner-scoped bearer tokens
    /// (`OWNER_TOKEN_TTL_SECS`). Default 900s (15 min): short enough to keep
    /// the "short-lived" security property, long enough that Console doesn't
    /// need to re-mint on every single read during one user session.
    pub owner_token_ttl_secs: u64,
    /// Rate limiting for `POST /v1/owner-tokens`.
    pub owner_token_rate_limit: OwnerTokenRateLimitConfig,
    /// Max `/api/restore` calls per owner per minute (GH #501 / WALM-299).
    /// Dedicated on top of the generic weighted account rate limiter —
    /// bounds how often an attacker can force a fresh first-time-discovery
    /// cost by repeatedly transferring junk blob_ids into a victim's wallet.
    /// `0` disables the guard.
    pub restore_requests_per_owner_per_minute: u64,
    /// Balance monitoring (proactive alerts)
    pub balance_monitor_interval_secs: u64,
    pub wallet_balance_low_threshold_wal: u64,
    pub wallet_balance_low_threshold_sui: u64,
    pub sponsor_balance_low_threshold_sui: u64,
    /// MCP OAuth 2.1 support for Claude (and future) native custom
    /// connectors. `None` when required env vars are unset — routes still
    /// mount but OAuth tokens won't resolve. When configured, OAuth is
    /// always available alongside the legacy delegate-key bearer.
    #[allow(dead_code)]
    pub mcp_oauth: Option<crate::oauth::McpOAuthConfig>,
    /// Accepted clock drift (seconds, each direction) for signed-request
    /// timestamps. Signatures older/newer than this are rejected as stale.
    /// Default 300; tunable via `AUTH_MAX_CLOCK_DRIFT_SECS`, capped at
    /// `MAX_AUTH_CLOCK_DRIFT_SECS`. Independent of nonce replay protection.
    pub auth_max_clock_drift_secs: i64,
}

/// Where recall dials seal, and whether this process should fork a listener.
/// `bind` is a literal address. The name `localhost` is never used: on some
/// hosts it resolves only to `::1`, so a dialer using `127.0.0.1` is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealDeployment {
    pub dial_url: String,
    pub bind: Option<(String, u16)>,
}

pub fn plan_seal_deployment(
    sidecar_url: &str,
    explicit: Option<&str>,
    bind_host_env: Option<&str>,
    listener_disabled: bool,
    writer_only: bool,
) -> SealDeployment {
    let mut planned = plan_seal_deployment_raw(
        sidecar_url,
        explicit,
        bind_host_env,
        listener_disabled,
        writer_only,
    );
    if let Some(url) = normalize_parsed_url(&planned.dial_url) {
        planned.dial_url = canonical_dial_url(&url);
    }
    planned
}

fn plan_seal_deployment_raw(
    sidecar_url: &str,
    explicit: Option<&str>,
    bind_host_env: Option<&str>,
    listener_disabled: bool,
    writer_only: bool,
) -> SealDeployment {
    if let Some(raw) = explicit.map(str::trim).filter(|value| !value.is_empty()) {
        if normalize_parsed_url(raw).is_none() {
            panic!("SIDECAR_SEAL_URL is not a valid absolute URL: {raw}");
        }
    }
    let fallback = SealDeployment {
        dial_url: canonical_dial(sidecar_url),
        bind: None,
    };
    if writer_only || listener_disabled {
        if let Some(raw) = explicit.map(str::trim).filter(|value| !value.is_empty()) {
            if let Some(url) = normalize_parsed_url(raw) {
                return SealDeployment {
                    dial_url: canonical_dial_url(&url),
                    bind: None,
                };
            }
        }
        return fallback;
    }
    if let Some(raw) = explicit.map(str::trim).filter(|value| !value.is_empty()) {
        let url = normalize_parsed_url(raw).expect("SIDECAR_SEAL_URL checked above");
        return deployment_for_url(&url, bind_host_env, sidecar_url);
    }
    let Some(url) = normalize_parsed_url(sidecar_url) else {
        return fallback;
    };
    if !is_loopback_host(url.host_str().unwrap_or("")) {
        return SealDeployment {
            dial_url: base_url_string(&url),
            bind: None,
        };
    }
    let Some(port) = url.port() else {
        return SealDeployment {
            dial_url: base_url_string(&url),
            bind: None,
        };
    };
    let next = port.saturating_add(1);
    if next == port {
        return SealDeployment {
            dial_url: base_url_string(&url),
            bind: None,
        };
    }
    let host = canonical_bind_host(url.host_str().unwrap_or(""), bind_host_env);
    let dial_host = dial_host_for(&host);
    SealDeployment {
        dial_url: origin(url.scheme(), &dial_host, next),
        bind: Some((host, next)),
    }
}

pub fn plan_seal_deployment_from_env(sidecar_url: &str) -> SealDeployment {
    let explicit = std::env::var("SIDECAR_SEAL_URL").ok();
    let bind_host = std::env::var("SIDECAR_HOST").ok();
    let listener_disabled = std::env::var("SIDECAR_SEAL_LISTENER")
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        });
    let writer_only = std::env::var("SIDECAR_ROUTE_MODE")
        .ok()
        .is_some_and(|mode| mode.trim().eq_ignore_ascii_case("writer"));
    plan_seal_deployment(
        sidecar_url,
        explicit.as_deref(),
        bind_host.as_deref(),
        listener_disabled,
        writer_only,
    )
}

fn deployment_for_url(
    url: &url::Url,
    bind_host_env: Option<&str>,
    sidecar_url: &str,
) -> SealDeployment {
    let dial_fallback = base_url_string(url);
    let Some(host) = url.host_str() else {
        return SealDeployment {
            dial_url: dial_fallback,
            bind: None,
        };
    };
    if !is_loopback_host(host) {
        return SealDeployment {
            dial_url: dial_fallback,
            bind: None,
        };
    }
    let Some(port) = url.port() else {
        return SealDeployment {
            dial_url: dial_fallback,
            bind: None,
        };
    };
    if let Some(sidecar) = normalize_parsed_url(sidecar_url) {
        if sidecar.port() == Some(port)
            && sidecar
                .host_str()
                .is_some_and(|item| is_loopback_host(item))
        {
            return SealDeployment {
                dial_url: dial_fallback,
                bind: None,
            };
        }
    }
    let bind_host = canonical_bind_host(host, bind_host_env);
    let dial_host = dial_host_for(&bind_host);
    SealDeployment {
        dial_url: origin(url.scheme(), &dial_host, port),
        bind: Some((bind_host, port)),
    }
}

fn dial_host_for(bind_host: &str) -> String {
    // Unspecified addresses accept a local dial but are not dial targets.
    // `localhost` is only ::1 on some hosts, so a 127.0.0.1 dial is refused.
    match bind_host {
        "localhost" | "0.0.0.0" => "127.0.0.1".to_string(),
        "::" | "[::]" => "::1".to_string(),
        other => other.to_string(),
    }
}

fn canonical_dial(raw: &str) -> String {
    match normalize_parsed_url(raw) {
        Some(url) => canonical_dial_url(&url),
        None => raw.trim().trim_end_matches('/').to_string(),
    }
}

fn canonical_dial_url(url: &url::Url) -> String {
    let Some(host) = url.host_str() else {
        return base_url_string(url);
    };
    let dial_host = dial_host_for(host);
    match url.port_or_known_default() {
        Some(port) if url.port().is_some() => origin(url.scheme(), &dial_host, port),
        _ => {
            let mut copy = url.clone();
            if copy.set_host(Some(&dial_host)).is_err() {
                return base_url_string(url);
            }
            base_url_string(&copy)
        }
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn canonical_bind_host(url_host: &str, env_host: Option<&str>) -> String {
    if let Some(env_host) = env_host.map(str::trim).filter(|value| !value.is_empty()) {
        if env_host != "localhost" {
            return env_host.to_string();
        }
    }
    if url_host == "::1" || url_host == "[::1]" {
        return "::1".to_string();
    }
    "127.0.0.1".to_string()
}

fn origin(scheme: &str, host: &str, port: u16) -> String {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.contains(':') {
        format!("{scheme}://[{host}]:{port}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

fn normalize_parsed_url(raw: &str) -> Option<url::Url> {
    url::Url::parse(raw.trim()).ok()
}

fn normalize_base_url(raw: &str) -> Option<String> {
    normalize_parsed_url(raw).map(|url| base_url_string(&url))
}

fn base_url_string(url: &url::Url) -> String {
    let mut copy = url.clone();
    copy.set_path("");
    copy.set_query(None);
    copy.set_fragment(None);
    copy.to_string().trim_end_matches('/').to_string()
}

#[cfg(test)]
mod seal_sidecar_url_tests {
    use super::{plan_seal_deployment, SealDeployment};

    fn plan(
        sidecar: &str,
        explicit: Option<&str>,
        bind_host: Option<&str>,
        listener_disabled: bool,
        writer_only: bool,
    ) -> SealDeployment {
        plan_seal_deployment(sidecar, explicit, bind_host, listener_disabled, writer_only)
    }

    #[test]
    fn localhost_upload_url_binds_ipv4_loopback_on_the_next_port() {
        assert_eq!(
            plan("http://localhost:9000", None, None, false, false),
            SealDeployment {
                dial_url: "http://127.0.0.1:9001".into(),
                bind: Some(("127.0.0.1".into(), 9001)),
            }
        );
        assert_eq!(
            plan("http://127.0.0.1:9000/", None, None, false, false).dial_url,
            "http://127.0.0.1:9001"
        );
    }

    #[test]
    fn an_explicit_remote_url_is_dialed_and_not_bound() {
        assert_eq!(
            plan(
                "http://127.0.0.1:9000",
                Some("http://seal.internal:9100/"),
                None,
                false,
                false,
            ),
            SealDeployment {
                dial_url: "http://seal.internal:9100".into(),
                bind: None,
            }
        );
    }

    #[test]
    fn disabling_the_listener_or_writer_mode_does_not_fork() {
        assert_eq!(
            plan("http://localhost:9000", None, None, true, false),
            SealDeployment {
                dial_url: "http://127.0.0.1:9000".into(),
                bind: None,
            }
        );
        assert_eq!(
            plan(
                "http://127.0.0.1:9000",
                Some("http://localhost:9100"),
                None,
                true,
                false,
            ),
            SealDeployment {
                dial_url: "http://127.0.0.1:9100".into(),
                bind: None,
            }
        );
        assert_eq!(
            plan(
                "http://127.0.0.1:9000",
                Some("http://0.0.0.0:9100"),
                None,
                false,
                true,
            )
            .dial_url,
            "http://127.0.0.1:9100"
        );
        assert_eq!(
            plan(
                "http://127.0.0.1:9000",
                Some("http://127.0.0.1:9100"),
                None,
                false,
                true,
            ),
            SealDeployment {
                dial_url: "http://127.0.0.1:9100".into(),
                bind: None,
            }
        );
    }

    #[test]
    fn ipv6_upload_url_moves_the_seal_port() {
        assert_eq!(
            plan("http://[::1]:9000", None, None, false, false),
            SealDeployment {
                dial_url: "http://[::1]:9001".into(),
                bind: Some(("::1".into(), 9001)),
            }
        );
    }

    #[test]
    #[should_panic(expected = "SIDECAR_SEAL_URL is not a valid absolute URL")]
    fn an_unparseable_seal_url_refuses_to_boot() {
        plan(
            "http://127.0.0.1:9000",
            Some("not a url"),
            None,
            false,
            false,
        );
    }

    #[test]
    fn a_portless_origin_stays_put() {
        assert_eq!(
            plan("http://sidecar.internal", None, None, false, false).dial_url,
            "http://sidecar.internal"
        );
        assert!(plan("http://sidecar.internal", None, None, false, false)
            .bind
            .is_none());
    }
}

impl Config {
    pub fn from_env() -> Self {
        let network = std::env::var("SUI_NETWORK")
            .unwrap_or_else(|_| "mainnet".to_string())
            .trim()
            .to_ascii_lowercase();
        let default_rpc = match network.as_str() {
            "testnet" => "https://fullnode.testnet.sui.io:443",
            "devnet" => "https://fullnode.devnet.sui.io:443",
            _ => "https://fullnode.mainnet.sui.io:443",
        };
        let default_walrus_staking_pool_id = default_walrus_staking_pool_id(&network);
        let walrus_publisher_url = std::env::var("WALRUS_PUBLISHER_URL")
            .unwrap_or_else(|_| "https://publisher.walrus-mainnet.walrus.space".to_string());
        let walrus_aggregator_url = std::env::var("WALRUS_AGGREGATOR_URL")
            .unwrap_or_else(|_| "https://aggregator.walrus-mainnet.walrus.space".to_string());
        let walrus_aggregator_urls = parse_walrus_aggregator_urls(
            &walrus_aggregator_url,
            std::env::var("WALRUS_AGGREGATOR_URLS").ok().as_deref(),
        );
        let (sui_rpc_requests_per_window, sui_rpc_window) = sui_rpc_quota_from_env();
        let package_id = std::env::var("MEMWAL_PACKAGE_ID").expect("MEMWAL_PACKAGE_ID must be set");
        let seal_policy_package_id =
            nonempty_env("MEMWAL_SEAL_POLICY_PACKAGE_ID").unwrap_or_else(|| package_id.clone());
        let seal_expected_committee_identity = nonempty_env("SEAL_EXPECTED_COMMITTEE_IDENTITY")
            .map(|raw| {
                serde_json::from_str(&raw).unwrap_or_else(|error| {
                    panic!(
                        "SEAL_EXPECTED_COMMITTEE_IDENTITY must be valid JSON: {}",
                        error
                    )
                })
            });
        if env_bool("SEAL_REQUIRE_COMMITTEE_IDENTITY") && seal_expected_committee_identity.is_none()
        {
            panic!(
                "SEAL_EXPECTED_COMMITTEE_IDENTITY must be set when SEAL_REQUIRE_COMMITTEE_IDENTITY=true"
            );
        }

        let sidecar_url =
            std::env::var("SIDECAR_URL").unwrap_or_else(|_| "http://localhost:9000".to_string());
        let seal_sidecar_url = plan_seal_deployment_from_env(&sidecar_url).dial_url;

        Self {
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8000".to_string())
                .parse()
                .expect("PORT must be a number"),
            database_url: std::env::var("DATABASE_URL")
                .expect("DATABASE_URL must be set (e.g. postgresql://memwal:memwal_secret@localhost:5432/memwal)"),
            sui_rpc_url: std::env::var("SUI_RPC_URL")
                .unwrap_or_else(|_| default_rpc.to_string()),
            sui_grpc_url: std::env::var("SUI_GRPC_URL")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            sui_network: network.clone(),
            memwal_account_id: std::env::var("MEMWAL_ACCOUNT_ID").ok(),
            openai_api_key: std::env::var("OPENAI_API_KEY").ok(),
            openai_api_base: std::env::var("OPENAI_API_BASE")
                .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
            walrus_publisher_url,
            walrus_aggregator_url,
            walrus_storage_epochs: configured_walrus_storage_epochs(&network),
            walrus_aggregator_urls,
            walrus_skip_consistency_check: env_bool("WALRUS_SKIP_CONSISTENCY_CHECK"),
            walrus_aggregator_race_after_ms: std::env::var("WALRUS_AGGREGATOR_RACE_AFTER_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_WALRUS_AGGREGATOR_RACE_AFTER_MS),
            sui_private_key: std::env::var("SERVER_SUI_PRIVATE_KEY").ok(),
            sui_private_keys: {
                // SERVER_SUI_PRIVATE_KEYS takes priority (comma-separated list).
                // Falls back to SERVER_SUI_PRIVATE_KEY as a single-element list.
                let multi = std::env::var("SERVER_SUI_PRIVATE_KEYS").ok().map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect::<Vec<_>>()
                });
                let single = std::env::var("SERVER_SUI_PRIVATE_KEY").ok().map(|k| vec![k]);
                multi.or(single).unwrap_or_default()
            },
            package_id,
            seal_policy_package_id,
            registry_id: normalize_object_id_env("MEMWAL_REGISTRY_ID"),
            sidecar_url,
            seal_sidecar_url,
            sidecar_secret: std::env::var("SIDECAR_AUTH_TOKEN").ok(),
            seal_expected_committee_identity,
            rate_limit: RateLimitConfig::from_env(),
            sponsor_rate_limit: SponsorRateLimitConfig::from_env(),
            read_api_rate_limit: ReadApiRateLimitConfig::from_env(),
            accounts_rate_limit: AccountsRateLimitConfig::from_env(),
            mcp_rate_limit: McpRateLimitConfig::from_env(),
            trusted_proxy_hops: std::env::var("TRUSTED_PROXY_HOPS")
                .ok()
                .and_then(|value| value.trim().parse::<usize>().ok())
                .filter(|hops| *hops <= 32)
                .unwrap_or(0),
            allowed_origins: std::env::var("ALLOWED_ORIGINS")
                .unwrap_or_default(),
            benchmark_mode: std::env::var("BENCHMARK_MODE")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false),
            writes_paused: env_bool("WRITES_PAUSED"),
            enable_memory_deletion: env_bool("ENABLE_MEMORY_DELETION"),
            enable_security_delete: env_bool("ENABLE_SECURITY_DELETE"),
            legacy_db_url: nonempty_env("LEGACY_DB_URL"),
            deletion_reconciler_enabled: env_bool("DELETION_RECONCILER_ENABLED"),
            deletion_object_resolver_enabled: env_bool("DELETION_OBJECT_RESOLVER_ENABLED"),
            delete_batch_max: env_number("DELETE_BATCH_MAX", 900),
            max_active_batches_per_owner: env_number("MAX_ACTIVE_BATCHES_PER_OWNER", 16),
            security_delete_auth_requests_per_minute: env_positive_u64(
                "SECURITY_DELETE_AUTH_REQUESTS_PER_MINUTE",
                20,
            ),
            security_delete_prepare_requests_per_minute: env_positive_u64(
                "SECURITY_DELETE_PREPARE_REQUESTS_PER_MINUTE",
                10,
            ),
            security_delete_execute_max_in_flight: env_number(
                "SECURITY_DELETE_EXECUTE_MAX_IN_FLIGHT",
                1,
            ),
            security_delete_crash_test_secret: nonempty_env(
                "SECURITY_DELETE_CRASH_TEST_SECRET",
            ),
            sui_rpc_requests_per_window,
            sui_rpc_window,
            sui_rpc_attempt_timeout: std::time::Duration::from_millis(env_number(
                "SUI_RPC_ATTEMPT_TIMEOUT_MS",
                5_000,
            )),
            sui_rpc_max_in_flight: env_number("SUI_RPC_MAX_IN_FLIGHT", 64),
            sponsor_private_key: nonempty_env("SPONSOR_PRIVATE_KEY"),
            sponsor_min_balance_alert: env_number("SPONSOR_MIN_BALANCE_ALERT", 0),
            claim_ttl_secs: env_number("CLAIM_TTL_SECS", 600),
            exec_grace_secs: env_number("EXEC_GRACE_SECS", 120),
            deletion_token_secret: nonempty_env("DELETION_TOKEN_SECRET"),
            deletion_token_ttl_secs: env_number("DELETION_TOKEN_TTL_SECS", 2700),
            expiry_margin_epochs: env_number("EXPIRY_MARGIN_EPOCHS", 1),
            walrus_package_id: nonempty_env("WALRUS_PACKAGE_ID").unwrap_or_default(),
            walrus_system_object_id: nonempty_env("WALRUS_SYSTEM_OBJECT_ID")
                .unwrap_or_default(),
            walrus_staking_pool_id: nonempty_env("WALRUS_STAKING_POOL_ID")
                .unwrap_or_else(|| default_walrus_staking_pool_id.to_string()),
            owner_token_secret: require_owner_token_secret_len(
                nonempty_env("OWNER_TOKEN_SECRET").unwrap_or_default(),
            ),
            owner_token_service_credential: nonempty_env("OWNER_TOKEN_SERVICE_CREDENTIAL")
                .unwrap_or_default(),
            owner_token_ttl_secs: env_positive_u64("OWNER_TOKEN_TTL_SECS", 900)
                .min(MAX_OWNER_TOKEN_TTL_SECS),
            owner_token_rate_limit: OwnerTokenRateLimitConfig::from_env(),
            // `env_number`, not `env_positive_u64`: `0` is a meaningful,
            // documented value here (disables `check_restore_call_rate_limit`
            // entirely) — `env_positive_u64` would silently coerce it back
            // to the default, making that escape hatch unreachable.
            restore_requests_per_owner_per_minute: env_number(
                "RESTORE_REQUESTS_PER_OWNER_PER_MINUTE",
                10,
            ),
            balance_monitor_interval_secs: normalized_balance_monitor_interval(env_positive_u64(
                "BALANCE_MONITOR_INTERVAL_SECS",
                900,
            )),
            // Both WAL and SUI use 9 decimal places (FROST/MIST).
            wallet_balance_low_threshold_wal: env_number(
                "WALLET_BALANCE_LOW_THRESHOLD_WAL",
                50_000_000_000,
            ),
            wallet_balance_low_threshold_sui: env_number(
                "WALLET_BALANCE_LOW_THRESHOLD_SUI",
                5_000_000_000,
            ),
            sponsor_balance_low_threshold_sui: env_number(
                "SPONSOR_BALANCE_LOW_THRESHOLD_SUI",
                5_000_000_000,
            ),
            mcp_oauth: crate::oauth::McpOAuthConfig::from_env(),
            auth_max_clock_drift_secs: configured_auth_clock_drift_secs(),
        }
    }
}

/// Per-network default for the Walrus staking pool shared object id (see
/// `Config::walrus_staking_pool_id`'s doc comment). Matches @mysten/walrus's
/// constants.mjs per-network defaults (see also scripts/sidecar/config.ts's
/// WALRUS_PACKAGE_ID handling, which follows the same pattern for the TS
/// sidecar). Only `testnet` has a distinct default — every other network
/// value, including `devnet`/`localnet`, silently falls back to the
/// MAINNET object id. Callers on a non-testnet, non-mainnet network should
/// set `WALRUS_STAKING_POOL_ID` explicitly rather than relying on this.
/// Expects `network` already trimmed/lowercased (see `Config::from_env`).
pub fn default_walrus_staking_pool_id(network: &str) -> &'static str {
    match network {
        "testnet" => "0xbe46180321c30aab2f8b3501e24048377287fa708018a5b7c2792b35fe339ee3",
        _ => "0x10b9d30c28448939ce6c4d6c6e0ffce4a7f8a4ada8248bdad09ef8b70e4a3904",
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn require_owner_token_secret_len(secret: String) -> String {
    if secret.is_empty() {
        return secret;
    }
    if secret.len() < MIN_OWNER_TOKEN_SECRET_LEN {
        panic!(
            "OWNER_TOKEN_SECRET must be at least {MIN_OWNER_TOKEN_SECRET_LEN} bytes; got {}",
            secret.len()
        );
    }
    secret
}

fn env_number<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr + Copy,
{
    nonempty_env(name)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_positive_u64(name: &str, default: u64) -> u64 {
    nonempty_env(name)
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn normalized_balance_monitor_interval(interval_secs: u64) -> u64 {
    interval_secs.max(MIN_BALANCE_MONITOR_INTERVAL_SECS)
}

fn sui_rpc_quota_from_env() -> (u32, std::time::Duration) {
    resolve_sui_rpc_quota(
        nonempty_env("SUI_RPC_REQUESTS_PER_WINDOW").as_deref(),
        nonempty_env("SUI_RPC_WINDOW_SECS").as_deref(),
        nonempty_env("SUI_RPC_MAX_RPS").as_deref(),
        nonempty_env("SUI_RPC_QUOTA_UTILIZATION").as_deref(),
    )
}

fn resolve_sui_rpc_quota(
    requests: Option<&str>,
    window: Option<&str>,
    legacy_max_rps: Option<&str>,
    utilization: Option<&str>,
) -> (u32, std::time::Duration) {
    match (requests, window) {
        (None, None) => match legacy_max_rps {
            None => (
                apply_sui_rpc_quota_utilization(3_000, utilization),
                std::time::Duration::from_secs(10),
            ),
            Some(value) => match value.parse::<u32>() {
                Ok(0) => (0, std::time::Duration::ZERO),
                Ok(max_rps) => (
                    1,
                    std::time::Duration::from_secs_f64(1.0 / f64::from(max_rps)),
                ),
                Err(_) => (1, std::time::Duration::from_millis(250)),
            },
        },
        (Some(requests), Some(window)) => {
            let requests = requests.parse().unwrap_or_default();
            let window = window.parse().unwrap_or_default();
            (
                apply_sui_rpc_quota_utilization(requests, utilization),
                std::time::Duration::from_secs(window),
            )
        }
        _ => (0, std::time::Duration::ZERO),
    }
}

fn apply_sui_rpc_quota_utilization(requests: u32, utilization: Option<&str>) -> u32 {
    if requests == 0 {
        return 0;
    }
    let utilization = match utilization.unwrap_or("0.95").parse::<f64>() {
        Ok(value) if value.is_finite() && value > 0.0 && value <= 1.0 => value,
        _ => return 0,
    };
    ((f64::from(requests) * utilization).floor() as u32).max(1)
}

/// Validate the mutually-exclusive legacy/new delete selectors and the
/// dependencies required by each independently deployable component.
pub fn validate_security_delete_config(config: &Config) -> Result<(), String> {
    if !matches!(
        config.sui_network.as_str(),
        "mainnet" | "testnet" | "devnet" | "localnet"
    ) {
        return Err(format!(
            "unsupported SUI_NETWORK={}; expected mainnet, testnet, devnet, or localnet",
            config.sui_network
        ));
    }
    if config.sui_network == "testnet" && config.sui_grpc_url.is_none() {
        return Err(
            "SUI_GRPC_URL is required when SUI_NETWORK=testnet; JSON-RPC is not supported".into(),
        );
    }

    if config.enable_security_delete && !config.enable_memory_deletion {
        return Err("ENABLE_SECURITY_DELETE requires ENABLE_MEMORY_DELETION".into());
    }
    if config.security_delete_crash_test_secret.is_some() && config.sui_network != "localnet" {
        return Err("security-delete crash failpoint is allowed only on localnet".into());
    }

    let any_component = config.enable_security_delete
        || config.deletion_reconciler_enabled
        || config.deletion_object_resolver_enabled;
    if !any_component {
        return Ok(());
    }

    if config.delete_batch_max == 0
        || config.delete_batch_max > 900
        || config.max_active_batches_per_owner == 0
        || config.security_delete_execute_max_in_flight == 0
        || config.security_delete_execute_max_in_flight > MAX_SECURITY_DELETE_EXECUTE_IN_FLIGHT
        || config.sui_rpc_requests_per_window == 0
        || config.sui_rpc_requests_per_window > 1_000_000
        || config.sui_rpc_window.is_zero()
        || config.sui_rpc_window > std::time::Duration::from_secs(60 * 60)
        || config.sui_rpc_attempt_timeout.is_zero()
        || config.sui_rpc_attempt_timeout > std::time::Duration::from_secs(60)
        || !(2..=10_000).contains(&config.sui_rpc_max_in_flight)
        || config.claim_ttl_secs == 0
        || config.deletion_token_ttl_secs == 0
    {
        return Err("security-delete numeric limits are invalid; DELETE_BATCH_MAX must be at most 900, SUI_RPC_REQUESTS_PER_WINDOW at most 1000000, SUI_RPC_WINDOW_SECS at most 3600, SUI_RPC_ATTEMPT_TIMEOUT_MS at most 60000, and SUI_RPC_MAX_IN_FLIGHT between 2 and 10000".into());
    }

    let mut missing = Vec::new();
    if config.legacy_db_url.is_none() {
        missing.push("LEGACY_DB_URL");
    }
    if config.sui_grpc_url.is_none() {
        missing.push("SUI_GRPC_URL");
    }
    if config.walrus_package_id.trim().is_empty() {
        missing.push("WALRUS_PACKAGE_ID");
    }
    if config.walrus_system_object_id.trim().is_empty() {
        missing.push("WALRUS_SYSTEM_OBJECT_ID");
    }
    if config.enable_security_delete && config.deletion_token_secret.is_none() {
        missing.push("DELETION_TOKEN_SECRET");
    }
    if (config.enable_security_delete || config.deletion_reconciler_enabled)
        && config.sponsor_private_key.is_none()
    {
        missing.push("SPONSOR_PRIVATE_KEY");
    }

    if !missing.is_empty() {
        Err(format!(
            "security-delete configuration requires: {}",
            missing.join(", ")
        ))
    } else {
        config
            .walrus_package_id
            .parse::<sui_sdk_types::Address>()
            .map_err(|_| "WALRUS_PACKAGE_ID must be a valid Sui address".to_string())?;
        config
            .walrus_system_object_id
            .parse::<sui_sdk_types::Address>()
            .map_err(|_| "WALRUS_SYSTEM_OBJECT_ID must be a valid Sui address".to_string())?;
        if let Some(key) = config.sponsor_private_key.as_deref() {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(key)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key))
                .map_err(|_| "SPONSOR_PRIVATE_KEY must be base64".to_string())?;
            if decoded.len() != 32 {
                return Err("SPONSOR_PRIVATE_KEY must decode to 32 bytes".into());
            }
        }
        Ok(())
    }
}

pub fn security_delete_routes_enabled(config: &Config) -> bool {
    config.enable_memory_deletion && config.enable_security_delete
}

fn normalize_object_id_env(name: &str) -> String {
    let raw = std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
    raw.trim()
        .parse::<sui_sdk_types::Address>()
        .unwrap_or_else(|error| panic!("{name} must be a valid Sui object ID: {error}"))
        .to_string()
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// `/health` `writes` wire value: `"paused"`, `"degraded"`, or `"ok"`.
/// Paused wins if both flags are set — write routes already 503.
pub(crate) fn writes_health_status(paused: bool, degraded: bool) -> String {
    if paused {
        "paused".to_string()
    } else if degraded {
        "degraded".to_string()
    } else {
        "ok".to_string()
    }
}

/// Stable client-facing body for write-path 503 when `WRITES_PAUSED` is set.
const WRITES_PAUSED_ERROR: &str = "writes are paused";

/// Reject write-path admission when `WRITES_PAUSED` is set.
///
/// Shared by `remember`, `remember_bulk`, `remember_manual`, and `analyze`
/// so `/health` `writes: "paused"` and write rejection stay one flag.
pub(crate) fn reject_if_writes_paused(paused: bool) -> Result<(), AppError> {
    if paused {
        Err(AppError::WritesPaused(WRITES_PAUSED_ERROR.to_string()))
    } else {
        Ok(())
    }
}

fn parse_walrus_aggregator_urls(primary: &str, extra_csv: Option<&str>) -> Vec<String> {
    let mut urls = Vec::new();
    let mut push_unique = |raw: &str| {
        let value = raw.trim();
        if !value.is_empty() && !urls.iter().any(|existing| existing == value) {
            urls.push(value.to_string());
        }
    };

    push_unique(primary);
    if let Some(extra_csv) = extra_csv {
        for value in extra_csv.split(',') {
            push_unique(value);
        }
    }

    urls
}

// ============================================================
// Sponsor Rate Limit Config
// ============================================================

#[derive(Debug, Clone)]
pub struct SponsorRateLimitConfig {
    /// Max sponsor requests per minute per IP (default: 10)
    pub per_minute: i64,
    /// Max sponsor requests per hour per IP (default: 30)
    pub per_hour: i64,
    /// Deployment-wide cap that cannot be bypassed by changing client input.
    pub global_per_minute: i64,
    /// Deployment-wide sustained cap that protects the sponsor budget.
    pub global_per_hour: i64,
}

impl Default for SponsorRateLimitConfig {
    fn default() -> Self {
        Self {
            per_minute: 10,
            per_hour: 30,
            global_per_minute: 100,
            global_per_hour: 1000,
        }
    }
}

impl SponsorRateLimitConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(v) = std::env::var("SPONSOR_RATE_LIMIT_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                c.per_minute = n;
            }
        }
        if let Ok(v) = std::env::var("SPONSOR_RATE_LIMIT_PER_HOUR") {
            if let Ok(n) = v.parse() {
                c.per_hour = n;
            }
        }
        if let Ok(v) = std::env::var("SPONSOR_GLOBAL_RATE_LIMIT_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                c.global_per_minute = n;
            }
        }
        if let Ok(v) = std::env::var("SPONSOR_GLOBAL_RATE_LIMIT_PER_HOUR") {
            if let Ok(n) = v.parse() {
                c.global_per_hour = n;
            }
        }
        c
    }
}

// ============================================================
// Read API Rate Limit Config
// ============================================================
//
// The 3 owner-scoped read endpoints (`namespaces`,
// `memories`, `agents`) originally shared the write path's 30/min
// per-delegate-key budget (`RateLimitConfig::max_requests_per_delegate_key`).
// That budget exists to bound spend-risk on endpoints that write, upload to
// Walrus, or call an LLM; a 31-request pagination loop over
// `GET /v1/owners/{owner}/memories` — completely ordinary client behavior —
// could trip it. Reads carry no equivalent spend risk, so they get their own,
// more generous, single-layer budget instead of being folded into the
// account-level burst/sustained layers that exist specifically to protect
// the write path's spend surface.
#[derive(Debug, Clone)]
pub struct ReadApiRateLimitConfig {
    /// Max weighted read-API requests per minute per delegate key.
    /// Default 200: headroom for paginating a ~10k-memory account at
    /// `limit=100` (100+ requests per full sync) plus margin for retries
    /// and concurrent `namespaces`/`agents` calls in the same window.
    pub per_delegate_key_per_minute: i64,
}

impl Default for ReadApiRateLimitConfig {
    fn default() -> Self {
        Self {
            per_delegate_key_per_minute: 200,
        }
    }
}

// ============================================================
// Accounts Rate Limit Config
// ============================================================

/// Per-IP rate limits for the public, unauthenticated `GET
/// /api/accounts/{owner}/exists` endpoint.
///
/// This is a cheap read (one indexed Postgres lookup) rather than a
/// state-changing, cost-incurring operation like `/sponsor`, so its per-IP
/// limits are set a bit more generously than `SponsorRateLimitConfig`'s
/// 10/min · 30/hour. But the endpoint is still an anonymous
/// address-existence oracle, so it must stay well below the general
/// authenticated per-account budget (`RateLimitConfig`'s 60/min · 500/hour)
/// — reusing that budget as a per-IP limit (the bug this config replaces)
/// left effectively no defense against enumeration. 20/min and 120/hour
/// per IP is the same order of magnitude as sponsor's proportions while
/// staying generous enough not to bother a legitimate integrator retrying
/// a handful of lookups.
#[derive(Debug, Clone)]
pub struct AccountsRateLimitConfig {
    /// Max accounts-exists requests per minute per IP (default: 20)
    pub per_minute: i64,
    /// Max accounts-exists requests per hour per IP (default: 120)
    pub per_hour: i64,
    /// Deployment-wide cap that cannot be bypassed by IP rotation.
    pub global_per_minute: i64,
    /// Deployment-wide sustained cap that protects the DB pool this
    /// endpoint shares with every other public route.
    pub global_per_hour: i64,
}

impl Default for AccountsRateLimitConfig {
    fn default() -> Self {
        Self {
            per_minute: 20,
            per_hour: 120,
            global_per_minute: 200,
            global_per_hour: 1500,
        }
    }
}

impl ReadApiRateLimitConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(v) = std::env::var("READ_API_RATE_LIMIT_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                c.per_delegate_key_per_minute = n;
            }
        }
        c
    }
}

impl AccountsRateLimitConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(v) = std::env::var("ACCOUNTS_RATE_LIMIT_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                c.per_minute = n;
            }
        }
        if let Ok(v) = std::env::var("ACCOUNTS_RATE_LIMIT_PER_HOUR") {
            if let Ok(n) = v.parse() {
                c.per_hour = n;
            }
        }
        if let Ok(v) = std::env::var("ACCOUNTS_GLOBAL_RATE_LIMIT_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                c.global_per_minute = n;
            }
        }
        if let Ok(v) = std::env::var("ACCOUNTS_GLOBAL_RATE_LIMIT_PER_HOUR") {
            if let Ok(n) = v.parse() {
                c.global_per_hour = n;
            }
        }
        c
    }
}

// ============================================================
// Hosted MCP rate limit
// ============================================================

/// Rate limits for `/api/mcp`, `/api/mcp/sse`, and `/api/mcp/messages`.
///
/// Redis keys are `rate:mcp:*`, not `rate:accounts:*`. The accounts-exists
/// route is an anonymous address oracle and stays on its own small budget.
/// Every client IP shares this one ceiling. There is no venue allowlist.
/// Bearer tokens are not exempt.
///
/// The deployment-wide caps must stay above the per-IP caps. If they were
/// equal, one IP could spend the whole deployment's budget and every other
/// IP would receive 429.
#[derive(Debug, Clone)]
pub struct McpRateLimitConfig {
    /// Requests per minute for every client IP (default: 2000).
    pub per_minute: i64,
    /// Requests per hour for every client IP (default: 8000).
    pub per_hour: i64,
    /// Requests per minute for one tenant, keyed by account id + delegate
    /// public key after authentication (default: 1000). Must stay below
    /// `global_per_minute` so one tenant cannot fill the shared ceiling.
    pub tenant_per_minute: i64,
    /// Requests per hour for one tenant (default: 6000). Must stay below
    /// `global_per_hour`.
    pub tenant_per_hour: i64,
    /// Deployment-wide cap (default: 2500). Must stay above `per_minute`.
    pub global_per_minute: i64,
    /// Deployment-wide sustained cap (default: 15000). Must stay above `per_hour`.
    pub global_per_hour: i64,
}

impl Default for McpRateLimitConfig {
    fn default() -> Self {
        Self {
            per_minute: 2000,
            per_hour: 8000,
            tenant_per_minute: 1000,
            tenant_per_hour: 6000,
            global_per_minute: 2500,
            global_per_hour: 15000,
        }
    }
}

impl McpRateLimitConfig {
    /// Collapse an IPv4-mapped IPv6 address to IPv4 so the Redis key agrees
    /// whether the peer socket was v4 or `::ffff:`.
    pub fn normalize_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
        match ip {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(std::net::IpAddr::V4)
                .unwrap_or(std::net::IpAddr::V6(v6)),
            other => other,
        }
    }

    pub fn from_env() -> Self {
        let defaults = Self::default();
        let config = Self {
            per_minute: env_positive_i64("MCP_RATE_LIMIT_PER_MINUTE", defaults.per_minute),
            per_hour: env_positive_i64("MCP_RATE_LIMIT_PER_HOUR", defaults.per_hour),
            tenant_per_minute: env_positive_i64(
                "MCP_TENANT_RATE_LIMIT_PER_MINUTE",
                defaults.tenant_per_minute,
            ),
            tenant_per_hour: env_positive_i64(
                "MCP_TENANT_RATE_LIMIT_PER_HOUR",
                defaults.tenant_per_hour,
            ),
            global_per_minute: env_positive_i64(
                "MCP_GLOBAL_RATE_LIMIT_PER_MINUTE",
                defaults.global_per_minute,
            ),
            global_per_hour: env_positive_i64(
                "MCP_GLOBAL_RATE_LIMIT_PER_HOUR",
                defaults.global_per_hour,
            ),
        };
        if config.global_per_minute <= config.per_minute {
            tracing::warn!(
                "MCP global per-minute cap {} is not above the per-IP cap {}; one IP can exhaust the deployment",
                config.global_per_minute,
                config.per_minute
            );
        }
        if config.global_per_minute <= config.tenant_per_minute {
            tracing::warn!(
                "MCP global per-minute cap {} is not above the per-tenant cap {}; one tenant can exhaust the deployment",
                config.global_per_minute,
                config.tenant_per_minute
            );
        }
        if config.global_per_hour <= config.tenant_per_hour {
            tracing::warn!(
                "MCP global per-hour cap {} is not above the per-tenant cap {}; one tenant can exhaust the deployment",
                config.global_per_hour,
                config.tenant_per_hour
            );
        }
        if config.global_per_hour <= config.per_hour {
            tracing::warn!(
                "MCP global per-hour cap {} is not above the per-IP cap {}; one IP can exhaust the deployment",
                config.global_per_hour,
                config.per_hour
            );
        }
        config
    }
}

fn env_positive_i64(name: &str, default: i64) -> i64 {
    let Ok(raw) = std::env::var(name) else {
        return default;
    };
    match raw.trim().parse::<i64>() {
        Ok(n) if n > 0 => n,
        Ok(_) => {
            tracing::warn!("ignoring non-positive {name}={raw:?}; using {default}");
            default
        }
        Err(_) => {
            tracing::warn!("ignoring invalid {name}={raw:?}; using {default}");
            default
        }
    }
}

// ============================================================
// Owner Token Rate Limit Config
// ============================================================

/// Rate limits for `POST /v1/owner-tokens`.
///
/// Two independent layers, both enforced (see
/// `rate_limit::owner_token_credential_rate_limit_middleware` and
/// `rate_limit::check_owner_token_owner_rate_limit`):
///
/// - `per_minute` / `per_hour` — keyed by the caller's service credential.
///   Phase 1 has exactly one shared credential (Console's), so in practice
///   this is one deployment-wide budget, same idea as
///   `SponsorRateLimitConfig::global_per_minute`. Defaults (120/min,
///   3000/hr) are generous relative to a 15-minute token TTL — Console
///   minting a token per active user session, even across many concurrent
///   sessions, stays well under this.
/// - `owner_per_minute` / `owner_per_hour` — keyed by the (canonical)
///   owner address, independent of which credential presented it. A
///   compromised or buggy Console instance that still holds a valid
///   service credential must not be able to mint unbounded tokens for one
///   owner. Defaults (5/min, 30/hr) are tight: with a 900s default TTL, a
///   legitimate caller has no reason to re-mint for the same owner more
///   than a handful of times per minute.
#[derive(Debug, Clone)]
pub struct OwnerTokenRateLimitConfig {
    pub per_minute: i64,
    pub per_hour: i64,
    pub owner_per_minute: i64,
    pub owner_per_hour: i64,
    /// Per-source-IP budget, independent of `x-service-credential` validity
    /// (see `rate_limit::owner_token_ip_rate_limit_middleware`'s doc
    /// comment — this is what actually throttles someone guessing the
    /// shared credential, since the per-credential budget below is keyed
    /// by the guessed value itself and never sees repeated failed guesses).
    pub ip_per_minute: i64,
    pub ip_per_hour: i64,
}

impl Default for OwnerTokenRateLimitConfig {
    fn default() -> Self {
        Self {
            per_minute: 120,
            per_hour: 3000,
            owner_per_minute: 5,
            owner_per_hour: 30,
            ip_per_minute: 30,
            ip_per_hour: 300,
        }
    }
}

impl OwnerTokenRateLimitConfig {
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(v) = std::env::var("OWNER_TOKEN_RATE_LIMIT_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                c.per_minute = n;
            }
        }
        if let Ok(v) = std::env::var("OWNER_TOKEN_RATE_LIMIT_PER_HOUR") {
            if let Ok(n) = v.parse() {
                c.per_hour = n;
            }
        }
        if let Ok(v) = std::env::var("OWNER_TOKEN_RATE_LIMIT_OWNER_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                c.owner_per_minute = n;
            }
        }
        if let Ok(v) = std::env::var("OWNER_TOKEN_RATE_LIMIT_OWNER_PER_HOUR") {
            if let Ok(n) = v.parse() {
                c.owner_per_hour = n;
            }
        }
        if let Ok(v) = std::env::var("OWNER_TOKEN_RATE_LIMIT_IP_PER_MINUTE") {
            if let Ok(n) = v.parse() {
                c.ip_per_minute = n;
            }
        }
        if let Ok(v) = std::env::var("OWNER_TOKEN_RATE_LIMIT_IP_PER_HOUR") {
            if let Ok(n) = v.parse() {
                c.ip_per_hour = n;
            }
        }
        c
    }
}

// ============================================================
// API Types
// ============================================================

/// POST /api/remember
/// Phase 2: Server handles everything — encrypt, upload Walrus, embed, store
/// Owner is derived from delegate key via onchain verification (auth middleware)
#[derive(Debug, Deserialize)]
pub struct RememberRequest {
    pub text: String,
    /// Namespace for memory isolation (default: "default")
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Optional client-supplied idempotency key. When set, a retry with the
    /// same key (for the same owner) collapses onto the original job instead of
    /// minting a new one — so an ambiguous timeout can't produce a duplicate
    /// paid on-chain blob. Omit for the default (each request is independent).
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

// ============================================================
// Bulk Remember types
// ============================================================

/// One item in a POST /api/remember/bulk request.
#[derive(Debug, Deserialize)]
pub struct RememberBulkItem {
    pub text: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

/// POST /api/remember/bulk request body.
#[derive(Debug, Deserialize)]
pub struct RememberBulkRequest {
    /// 1–MAX_BULK_ITEMS items to remember in one batched operation.
    pub items: Vec<RememberBulkItem>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// POST /api/remember/bulk — 202 Accepted response.
/// `job_ids[i]` corresponds to `items[i]`; poll each via GET /api/remember/:job_id.
#[derive(Debug, Serialize)]
pub struct RememberBulkAcceptedResponse {
    pub job_ids: Vec<String>,
    pub total: usize,
    pub status: String, // "running" on accepted background work
}

/// POST /api/remember/bulk/status request body.
#[derive(Debug, Deserialize)]
pub struct RememberBulkStatusRequest {
    /// 1–MAX_BULK_ITEMS job IDs from a prior POST /api/remember/bulk call.
    pub job_ids: Vec<String>,
}

/// One item in a POST /api/remember/bulk/status response.
#[derive(Debug, Serialize, Clone)]
pub struct RememberBulkStatusItem {
    pub job_id: String,
    pub status: String,
    /// Set when the job row exists. Omitted for `not_found`, which has no row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST /api/remember/bulk/status response.
#[derive(Debug, Serialize)]
pub struct RememberBulkStatusResponse {
    pub results: Vec<RememberBulkStatusItem>,
}

/// POST /api/remember (async, v3)
/// Returns 202 Accepted immediately with a job_id for polling.
#[derive(Debug, Serialize)]
pub struct RememberAcceptedResponse {
    pub job_id: String,
    pub status: String, // "running" on accepted background work
}

/// GET /api/remember/:job_id — job status polling response
#[derive(Debug, Serialize)]
pub struct RememberJobStatusResponse {
    pub job_id: String,
    pub status: String, // "pending" | "running" | "uploaded" | "done" | "failed"
    /// Owner address of the memory (from auth at enqueue time).
    pub owner: String,
    /// Namespace the memory was stored under.
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// POST /api/remember (legacy sync response, kept for remember_manual)
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct RememberResponse {
    pub blob_id: String,
    pub owner: String,
    pub namespace: String,
}

/// POST /api/recall
/// Phase 2: Server does search → download → decrypt → return plaintext
/// Owner is derived from delegate key via onchain verification (auth middleware)
fn default_limit() -> usize {
    10
}

fn default_namespace() -> String {
    "default".to_string()
}

/// Empty or whitespace-only text. Callers reject it before creating a job.
///
/// `str::is_empty` lets `" "`, `"\t"`, and `"\n"` through. Those used to be
/// accepted and then sit until the client timed out (GH #1129). A non-blank
/// fact is not trimmed: surrounding spaces stay part of the stored text.
pub fn text_is_blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// Shared namespace validation for every request that carries a namespace.
///
/// API-compatibility note: this rejects the empty string, and the read paths
/// (`recall`, `recall_manual`, `ask`) call it, so an explicit
/// `"namespace": ""` returns HTTP 400 where it previously returned HTTP 200
/// with an empty result set. That matches the write paths, but it is
/// client-visible: a caller that sends `""` to mean "unset" must omit the
/// field instead and let `default_namespace` apply.
pub fn validate_namespace(namespace: &str) -> Result<(), AppError> {
    if namespace.is_empty() {
        return Err(AppError::BadRequest("namespace cannot be empty".into()));
    }
    if namespace.len() > MAX_NAMESPACE_BYTES {
        return Err(AppError::BadRequest(format!(
            "namespace exceeds maximum length of {} bytes",
            MAX_NAMESPACE_BYTES
        )));
    }
    // NUL must not reach PostgreSQL: a `\0` in a text bind makes libpq/pg
    // reject the query as an opaque 500. Reject here so recall/ask match
    // remember and return HTTP 400 (WALM-439 / GH #787).
    //
    // Deliberately NUL-only, not every Unicode Cc character: `\t`, `\n`, `\r`,
    // DEL and C1 are all valid Postgres `text` and stored fine before this
    // check existed. Because this validator also guards the read and delete
    // paths, rejecting them here would strand any namespace already written
    // with one — unreadable via recall/ask/stats and undeletable via forget.
    if namespace.contains('\0') {
        return Err(AppError::BadRequest("namespace contains a NUL byte".into()));
    }
    Ok(())
}

/// Validate a client-supplied embedding vector against what the fact store can
/// accept. Shared by the manual write and read paths, where the vector comes
/// from the caller rather than the server-side embedder. Rejects, with an
/// actionable `BadRequest` (and, on the write path, before any paid upload):
///   - a width other than the fixed pgvector column (`EMBEDDING_DIMS`), and
///   - any non-finite component (NaN / ±Inf), which pgvector refuses to index
///     and which is meaningless for cosine similarity.
///
/// Both would otherwise only fail deep in pgvector as an opaque 500.
pub fn validate_embedding_vector(vector: &[f32]) -> Result<(), AppError> {
    use crate::services::embedder::EMBEDDING_DIMS;
    if vector.len() != EMBEDDING_DIMS {
        return Err(AppError::BadRequest(format!(
            "vector must have exactly {EMBEDDING_DIMS} dimensions, got {}",
            vector.len()
        )));
    }
    if let Some(index) = vector.iter().position(|component| !component.is_finite()) {
        return Err(AppError::BadRequest(format!(
            "vector must contain only finite values; component at index {index} is not finite"
        )));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct RecallRequest {
    pub query: String,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Optional composite-scoring weights. Omitted → response order is
    /// byte-identical to a pgvector cosine-distance sort. See
    /// [`ScoringWeights`].
    #[serde(default)]
    pub scoring_weights: Option<ScoringWeights>,
    /// How to order results. Omitted → [`RecallSort::Relevance`], today's
    /// behaviour. See [`RecallSort`].
    ///
    /// `Option` because an explicit `sort`, `relevance` included, suppresses
    /// `scoring_weights`, so omitted and explicit must stay distinct.
    #[serde(default)]
    pub sort: Option<RecallSort>,
    /// How long the caller waits, in ms. When set, the recall stops just
    /// short of it and answers [`AppError::RecallTimeout`] naming the stage
    /// it was in; omitted, it runs to completion.
    #[serde(default)]
    pub deadline_ms: Option<u64>,
}

/// Result ordering mode for `/api/recall`.
///
/// Distinct from [`ScoringWeights`], which only re-ranks the rows the vector
/// search already returned. `sort` decides how many rows are fetched in the
/// first place — which is the half that matters, because the candidate set is
/// the cosine top-N and no amount of re-weighting can surface a row pgvector
/// never returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecallSort {
    /// Pure semantic relevance — the cosine order, unchanged. Default, so an
    /// omitted field leaves every existing caller byte-identical.
    #[default]
    Relevance,
    /// Newest-among-matches: over-fetch semantic candidates, order them by
    /// write-time descending, then truncate to `limit`.
    ///
    /// Semantic similarity is the candidate *generator* and write-time decides
    /// the order, so a newest record worded less literally than an older one
    /// still wins. A recency *weight* cannot guarantee that — it has to
    /// out-score the semantic gap before it reorders anything, and at a
    /// 30-day half-life two records days apart barely differ.
    Recent,
}

impl RecallSort {
    /// How many rows to pull from `search_similar` to serve `limit` results.
    ///
    /// `Recent` needs a wider net than it returns: the newest row is often a
    /// mediocre semantic match, so it sits deep in the cosine ordering. 5x
    /// covers the reported failures without turning recall into a table scan,
    /// and the 50-row ceiling bounds the cost.
    ///
    /// Never returns less than `limit`. A naive `min(limit * 5, 50)`
    /// under-fetches once `limit` passes 50 and hands the caller a short page.
    pub fn candidate_limit(self, limit: usize) -> usize {
        match self {
            RecallSort::Relevance => limit,
            RecallSort::Recent => limit.saturating_mul(5).min(50).max(limit),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RecallResponse {
    pub results: Vec<RecallResult>,
    pub total: usize,
    /// Count of matches whose blob download / SEAL decrypt / UTF-8 decode
    /// failed and were silently omitted from `results`. Zero on the happy path.
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub dropped_count: usize,
}

fn is_zero_usize(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Serialize)]
pub struct RecallResult {
    pub blob_id: String,
    pub text: String,
    pub distance: f64,
    /// Composite score used for ranking. Present only when the ranker
    /// actually ran (i.e. when `scoring_weights` was supplied with
    /// `recency > 0` so the ranker didn't short-circuit). `None` when
    /// the response is in default pgvector-cosine order — in that case
    /// the score is just `1.0 - distance` and we don't bother surfacing
    /// a derived field. `#[serde(skip_serializing_if)]` keeps the wire
    /// shape byte-identical to today for default-weights requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Write-time of the memory, from `vector_entries.created_at` — threaded
    /// `SearchHit` → `HydratedMemory` → here by the recall handler's
    /// `zip_search_hit_fields_onto_hydrated`.
    ///
    /// Present so a caller can order and verify the returned set by
    /// write-time rather than re-ranking on a date it has to parse back out
    /// of the memory text (WALM-383). Note this is the *write* time, not any
    /// event time the text itself may describe.
    ///
    /// This alone does not make "newest wins" correct: the candidate set is
    /// the cosine top-`limit` from `search_similar`, so the newest row can be
    /// missing from `results` entirely and no client-side sort recovers it.
    /// The server-side recency mode that over-fetches is still open.
    ///
    /// `None` only when the hydrated record had no matching `SearchHit`,
    /// which shouldn't happen on the recall path. `skip_serializing_if`
    /// then omits the field rather than sending a fabricated date — for a
    /// newest-wins caller a wrong timestamp is worse than a missing one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub blob_id: String,
    pub distance: f64,
    /// Insertion timestamp from `vector_entries.created_at`. Used by the
    /// composite ranker for recency scoring; threaded through unchanged
    /// in the engine `fetch_*` calls. Always present (column is NOT NULL
    /// in migration 001).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// per-fact importance score from `vector_entries.importance`
    /// (column added by migration 009). Set at extraction time by the
    /// LLM-emitted vital/standard/trivial bucket (mapped to 0.9/0.5/0.2
    /// via `services::extractor::importance_for_bucket`). Consumed by
    /// `CompositeRanker` at recall time when `scoring_weights.importance`
    /// is non-zero. NOT NULL with default 0.5 so legacy rows degrade
    /// gracefully to the "standard" bucket.
    pub importance: f32,
}

/// Composite-scoring weights for `/api/recall` and `/api/ask`. Optional on
/// the wire — when omitted, the response order is byte-identical to a
/// pure pgvector cosine-distance sort (today's behaviour).
///
/// The score formula is:
///
/// ```text
/// score = semantic    * (1.0 - distance)
///       + recency     * 2^(-age_days / recency_half_life_days)
///       + importance  * vector_entries.importance   (already in [0,1])
/// ```
///
/// Sorted descending (higher score = better). `default()` returns
/// `semantic=1.0, recency=0.0, importance=0.0` so deserialising an empty
/// body yields the "today" ordering exactly.
#[derive(Debug, Clone, Deserialize)]
pub struct ScoringWeights {
    /// Weight applied to `1.0 - cosine_distance`. Default 1.0.
    #[serde(default = "default_semantic_weight")]
    pub semantic: f64,
    /// Weight applied to `2^(-age_days / half_life)`. Default 0.0.
    /// When all non-semantic weights are effectively zero, the ranker
    /// short-circuits and preserves the input order (which is already
    /// cosine-sorted by pgvector).
    #[serde(default)]
    pub recency: f64,
    /// Half-life for the recency decay term, in days. Default 30.
    /// A memory aged exactly `half_life` days has recency score 0.5;
    /// twice that, 0.25; etc.
    #[serde(default = "default_recency_half_life_days")]
    pub recency_half_life_days: f64,
    /// weight applied to the per-fact importance score from
    /// `vector_entries.importance` (set by the extractor's vital /
    /// standard / trivial bucket → 0.9 / 0.5 / 0.2). Default 0.0 so the
    /// existing default-weights path is byte-identical to previous
    /// behaviour. Opt in by passing a positive value via
    /// `scoring_weights.importance` in the request body.
    #[serde(default)]
    pub importance: f64,
}

fn default_semantic_weight() -> f64 {
    1.0
}

fn default_recency_half_life_days() -> f64 {
    30.0
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            semantic: 1.0,
            recency: 0.0,
            recency_half_life_days: 30.0,
            importance: 0.0,
        }
    }
}

impl ScoringWeights {
    /// Minimum allowed half-life. Anything smaller (incl. subnormals like
    /// `f64::MIN_POSITIVE`) makes the `exp(-age * ln2 / half_life)` term
    /// collapse to `0.0` for any non-zero `age`, silently turning the
    /// recency signal into a constant. ~86 milliseconds is well below any
    /// real-world recall use case and still survives float arithmetic.
    const MIN_HALF_LIFE_DAYS: f64 = 1e-6;

    /// True when the ranker actually computes scores (rather than
    /// short-circuiting to the input order). Mirrors the
    /// `recency / importance < f64::EPSILON` predicate inside
    /// `CompositeRanker` so handler-side gating (validation logs, tracing
    /// breadcrumbs) stays in lockstep with what the ranker actually does.
    /// Keep this in sync with [`crate::services::ranker::CompositeRanker::rank`].
    ///
    /// a non-zero `importance` weight is enough on its own to
    /// activate the ranker — the importance signal alone can reorder hits
    /// even when recency is off.
    pub fn is_ranker_active(&self) -> bool {
        self.recency.abs() >= f64::EPSILON || self.importance.abs() >= f64::EPSILON
    }

    /// Return an error if the weights are outside reasonable bounds. The
    /// `CompositeRanker` already has internal guards (NaN sorts as Equal,
    /// non-positive half-life zeros out the recency term) so we wouldn't
    /// crash — but it's friendlier to return a 400 up-front than to
    /// silently degrade to the default ordering.
    ///
    /// Constraints:
    /// - no NaN or infinite weights
    /// - signal weights (`semantic`, `recency`) must be in `[0.0, 100.0]`
    ///   — negative weights would invert the signal (older = better, less
    ///   semantic match = better), which is almost certainly a bug, not a
    ///   feature. The 100.0 ceiling is generous; a real client doesn't
    ///   need values that large.
    /// - `recency_half_life_days` must be at least `MIN_HALF_LIFE_DAYS`
    ///   (≈86 ms) when `recency > 0`. A zero / negative / subnormal
    ///   half-life with non-zero recency silently degrades the recency
    ///   term to zero — surface it as a 400 so the client notices.
    pub fn validate(&self) -> Result<(), AppError> {
        for (name, value) in [
            ("semantic", self.semantic),
            ("recency", self.recency),
            ("recency_half_life_days", self.recency_half_life_days),
            ("importance", self.importance),
        ] {
            if !value.is_finite() {
                return Err(AppError::BadRequest(format!(
                    "scoring_weights.{} must be a finite number (got {})",
                    name, value
                )));
            }
        }
        for (name, value) in [
            ("semantic", self.semantic),
            ("recency", self.recency),
            ("importance", self.importance),
        ] {
            if !(0.0..=100.0).contains(&value) {
                return Err(AppError::BadRequest(format!(
                    "scoring_weights.{} must be in [0.0, 100.0] (got {})",
                    name, value
                )));
            }
        }
        if self.recency > 0.0 && self.recency_half_life_days < Self::MIN_HALF_LIFE_DAYS {
            return Err(AppError::BadRequest(format!(
                "scoring_weights.recency_half_life_days must be >= {} when \
                 recency > 0 (got {})",
                Self::MIN_HALF_LIFE_DAYS,
                self.recency_half_life_days
            )));
        }
        Ok(())
    }
}

/// POST /api/analyze
/// Extract facts from conversation text using LLM, then remember each fact
/// Owner is derived from delegate key via onchain verification (auth middleware)
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    /// Conversation text to analyze for memorable facts
    pub text: String,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// optional absolute timestamp of when this conversation turn
    /// took place (RFC 3339, UTC). When present, the extractor uses it as
    /// the temporal anchor to resolve relative-time references ("last
    /// Friday", "yesterday") into absolute dates *inside the extracted
    /// fact text* — so the date enters both the SEAL-encrypted fact on
    /// Walrus and the embedding vector, making time-anchored facts
    /// retrievable.
    ///
    /// Caller-trusted: same trust level as the conversation text itself
    /// (we never validate the text either). Optional. No default-to-`now()`
    /// fallback — silence is honest. Falling back to `now()` would stamp
    /// present-time onto past-event facts and pollute retrieval.
    ///
    /// Architecture A (locked 2026-05-27): the date lives ONLY inside the
    /// encrypted fact text + the embedding. There is no metadata column on
    /// `vector_entries`. The server can never filter or rank by event time
    /// — that's the privacy-floor-preserving trade we accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// POST /api/analyze (async, returns 202 immediately)
/// Returns job_ids for each extracted fact; poll via GET /api/remember/:job_id
#[derive(Debug, Serialize)]
pub struct AnalyzeAcceptedResponse {
    /// One job_id per extracted fact — poll GET /api/remember/:job_id for each
    pub job_ids: Vec<String>,
    /// Extracted facts accepted for background storage. `id` equals `job_id`.
    pub facts: Vec<AnalyzeAcceptedFact>,
    /// Number of facts extracted from the text
    pub fact_count: usize,
    /// "pending" on accepted analyze jobs
    pub status: String,
    pub owner: String,
}

#[derive(Debug, Serialize)]
pub struct AnalyzeAcceptedFact {
    pub text: String,
    pub id: String,
    pub job_id: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct AnalyzedFact {
    pub text: String,
    pub id: String,
    pub blob_id: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct AnalyzeResponse {
    pub facts: Vec<AnalyzedFact>,
    pub total: usize,
    pub owner: String,
}

/// POST /api/remember/manual
/// Client sends SEAL-encrypted data (base64) + pre-computed embedding vector.
/// Server uploads to Walrus via sidecar, then stores the vector ↔ blobId mapping.
#[derive(Debug, Deserialize)]
pub struct RememberManualRequest {
    pub encrypted_data: String, // base64-encoded SEAL-encrypted bytes
    pub vector: Vec<f32>,
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct RememberManualResponse {
    pub id: String,
    pub blob_id: String,
    pub owner: String,
    pub namespace: String,
}

/// POST /api/embed
/// Embed text into a vector without storing anything.
#[derive(Debug, Deserialize)]
pub struct EmbedRequest {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct EmbedResponse {
    pub vector: Vec<f32>,
}

/// POST /api/recall/manual
/// User provides pre-computed query vector.
/// Server returns matching blobIds + distances (no download/decrypt).
#[derive(Debug, Deserialize)]
pub struct RecallManualRequest {
    pub vector: Vec<f32>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Optional composite-scoring weights. Omitted → results are ordered by
    /// raw pgvector cosine distance, byte-identical to the pre-ranker
    /// behaviour. When set, the manual path applies the **same**
    /// `CompositeRanker` as `/api/recall` and `/api/ask` so all three return
    /// the same ordering for the same query + weights. The ranker
    /// scores the `SearchHit` fields directly (`distance` / `created_at` /
    /// `importance`) — no Walrus fetch or SEAL decrypt — preserving manual
    /// recall's "server returns blob ids + distances, client hydrates" contract.
    #[serde(default)]
    pub scoring_weights: Option<ScoringWeights>,
}

#[derive(Debug, Serialize)]
pub struct RecallManualResponse {
    pub results: Vec<SearchHit>,
    pub total: usize,
}

/// POST /api/ask
/// Recall memories + LLM chat — full AI-with-memory demo
#[derive(Debug, Deserialize)]
pub struct AskRequest {
    /// User's question
    pub question: String,
    /// Max memories to inject (default: 5)
    pub limit: Option<usize>,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Optional composite-scoring weights applied to the retrieved
    /// memories before they're injected into the LLM prompt. Omitted →
    /// pgvector cosine order. See [`ScoringWeights`].
    #[serde(default)]
    pub scoring_weights: Option<ScoringWeights>,
}

#[derive(Debug, Serialize)]
pub struct AskResponse {
    pub answer: String,
    pub memories_used: usize,
    pub memories: Vec<RecallResult>,
}

/// POST /api/restore
/// Restore a namespace: download blobs from Walrus, decrypt, re-embed, re-index
fn default_restore_limit() -> usize {
    10
}

#[derive(Debug, Deserialize)]
pub struct RestoreRequest {
    pub namespace: String,
    /// Max blobs to restore (default: 10)
    #[serde(default = "default_restore_limit")]
    pub limit: usize,
}

#[derive(Debug, Serialize)]
pub struct RestoreResponse {
    pub restored: usize,
    pub skipped: usize,
    /// Permanent decrypt/UTF-8 failures on this on-chain page: negative-cache
    /// hits plus any new permanent failures this call. Transient download,
    /// decrypt, or embed errors are not counted here. Additive JSON field
    /// (COMG-719 / WALM-480).
    pub failed: usize,
    pub total: usize,
    pub namespace: String,
    pub owner: String,
    /// True when this restore is known-incomplete: more on-chain blobs were
    /// missing locally than `limit` allowed this call to restore, or the
    /// sidecar's owner-wide candidate fetch hit its cap *and* raising
    /// `limit` can still expand that fetch (`limit < 20`, cap = min(limit*5,
    /// 100)) — including `total == 0` in that window, because other
    /// namespaces can starve this one. Once the sidecar cap is saturated
    /// (`limit >= 20`), truncation follows this call's missing-blob page,
    /// not on-chain `total`, so a fully restored namespace does not loop
    /// (WALM-431 / GH #762). Also true when an inspected page produced only
    /// transients (download/decrypt/embed) so the caller retries (WALM-480).
    pub truncated: bool,
}

/// POST /api/forget — delete the vector index rows for a namespace
/// (hard DELETE on vector_entries; Walrus blobs persist). Used by the
/// benchmark harness for inter-run cleanup. Mode-blind, owner-scoped.
#[derive(Debug, Deserialize)]
pub struct ForgetRequest {
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct ForgetResponse {
    pub deleted: u64,
    pub namespace: String,
    pub owner: String,
}

/// GET /api/accounts/:owner/exists — does `owner` have a registered
/// MemWalAccount? Backs Console's existence-check primitive.
/// Intentionally minimal: no `account_id`, since Console doesn't need the
/// internal identifier and returning it would needlessly widen the API's
/// surface for future churn.
#[derive(Debug, Serialize)]
pub struct AccountExistsResponse {
    pub exists: bool,
}

/// GET /api/whoami — the identity the caller's delegate key resolves to.
///
/// Unlike `AccountExistsResponse` this *does* carry `account_id`, which is
/// safe here precisely because the route is authenticated: the caller proved
/// possession of a delegate key already registered against this account, so
/// it is being told its own identity, not anyone else's.
///
/// Exists so a client that holds a delegate key but lost the surrounding
/// metadata can rebuild `credentials.json` (WALM-332). All three fields are
/// required for that: `account_id` and `owner` come from auth (the signed
/// account id, or the delegate-key cache), `package_id` from server config.
#[derive(Debug, Serialize)]
pub struct WhoamiResponse {
    pub account_id: String,
    pub owner: String,
    pub package_id: String,
}

/// POST /api/stats — count + stored bytes for a namespace.
/// Used by the benchmark harness for verification. Mode-blind.
#[derive(Debug, Deserialize)]
pub struct StatsRequest {
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub memory_count: i64,
    pub storage_bytes: i64,
    pub namespace: String,
    pub owner: String,
}

/// Health check
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    #[serde(flatten)]
    pub compatibility: crate::compatibility::VersionResponse,
    /// "production" or "benchmark" — lets benchmark harness runs verify
    /// at startup that they're hitting a benchmark-mode server before
    /// ingesting plaintext memories. Mirrors `Config::benchmark_mode`.
    pub mode: String,
    /// the prompt version constants the running binary is using.
    /// The benchmark harness reads this at run start and pins the
    /// versions into the result-artifact JSON so a future "score jumped"
    /// delta is attributable to the prompt change rather than guessed
    /// at from git history. Both fields are always populated — there is
    /// no "version unknown" state for a running server.
    pub prompt_versions: PromptVersions,
    /// Whether the encryption sidecar answered `/health` AND Postgres can
    /// accept writes (Neon `neon.max_cluster_size` cap). Prefer
    /// `public.pg_cluster_size()`; if that function is missing, fall back
    /// to `sum(pg_database_size)` against the same GUC. Self-hosted
    /// Postgres without the GUC is sidecar-only. Probe errors and timeouts
    /// fail open so CI `wait-for-relayer` does not hang. `status` stays
    /// `"ok"` while the relayer process is up.
    pub write_ready: bool,
    /// Write-path state: `"ok"`, `"degraded"`, or `"paused"`.
    ///
    /// `"paused"` when `WRITES_PAUSED` is set; write routes then return
    /// HTTP 503. `"degraded"` when recent durable writes have been failing
    /// and none have landed -- the relayer still accepts and durably
    /// queues a write, but Walrus is not storing it, so a caller should
    /// expect the job to fail minutes later rather than queue more.
    ///
    /// Deliberately separate from `write_ready`, which stays true through
    /// a downstream outage: CI's wait-for-relayer gate blocks on
    /// `write_ready is True`, so folding this into it would make a Walrus
    /// outage hang every deploy. `/health` stays HTTP 200 throughout.
    pub writes: String,
}

/// prompt version constants surfaced on `/health`. See the
/// `*_PROMPT_VERSION` consts in `services::extractor` and `routes::admin`.
#[derive(Debug, Serialize)]
pub struct PromptVersions {
    /// `FACT_EXTRACTION_PROMPT_VERSION` from `services::extractor` — the
    /// extractor system prompt used by `/api/analyze` and the
    /// summarise-long-text path in `/api/remember`.
    pub extract: String,
    /// `ASK_SYSTEM_PROMPT_VERSION` from `routes::admin` — the LLM
    /// system prompt that wraps recalled memories on `/api/ask`.
    pub ask: String,
}

/// GET /config response.
///
/// Public deployment parameters the SDK needs to build a SEAL SessionKey
/// client-side. All fields are non-secret (on-chain / public provider URL).
#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub network: String,
    #[serde(rename = "suiRpcUrl", skip_serializing_if = "Option::is_none")]
    pub sui_rpc_url: Option<String>,
    /// Preferred gRPC endpoint. Clients may fall back to `suiRpcUrl` during a
    /// rolling deployment or when the preferred endpoint is unavailable.
    #[serde(rename = "suiGrpcUrl", skip_serializing_if = "Option::is_none")]
    pub sui_grpc_url: Option<String>,
    /// Preferred transport for Sui reads. Clients may use the other advertised
    /// endpoint as a compatibility fallback.
    #[serde(rename = "suiTransport")]
    pub sui_transport: &'static str,
    /// Mirror of `RateLimitConfig::bench_bypass_enabled`. Lets benchmark
    /// scripts pre-flight the server config before running.
    #[serde(rename = "rateLimitDisabled")]
    pub rate_limit_disabled: bool,
    /// Effective deletion-only rolling-window quota after utilization is applied.
    #[serde(rename = "securityDeleteSuiRpcRequestsPerWindow")]
    pub security_delete_sui_rpc_requests_per_window: u32,
    #[serde(rename = "securityDeleteSuiRpcWindowSecs")]
    pub security_delete_sui_rpc_window_secs: u64,
    #[serde(rename = "securityDeleteEnabled")]
    pub security_delete_enabled: bool,
    #[serde(rename = "securityDeleteReconcilerEnabled")]
    pub security_delete_reconciler_enabled: bool,
    #[serde(rename = "securityDeleteObjectResolverEnabled")]
    pub security_delete_object_resolver_enabled: bool,
    #[serde(rename = "securityDeleteBatchMax")]
    pub security_delete_batch_max: usize,
    #[serde(rename = "securityDeleteMaxActiveBatchesPerOwner")]
    pub security_delete_max_active_batches_per_owner: usize,
    #[serde(rename = "securityDeleteAuthRequestsPerMinute")]
    pub security_delete_auth_requests_per_minute: u64,
    #[serde(rename = "securityDeletePrepareRequestsPerMinute")]
    pub security_delete_prepare_requests_per_minute: u64,
    #[serde(rename = "securityDeleteExecuteMaxInFlight")]
    pub security_delete_execute_max_in_flight: usize,
    #[serde(rename = "securityDeleteCrashTestEnabled")]
    pub security_delete_crash_test_enabled: bool,
    #[serde(rename = "securityDeleteClaimTtlSecs")]
    pub security_delete_claim_ttl_secs: u64,
    #[serde(rename = "securityDeleteExecutionGraceSecs")]
    pub security_delete_execution_grace_secs: u64,
    #[serde(rename = "securityDeleteExpiryMarginEpochs")]
    pub security_delete_expiry_margin_epochs: u64,
}

// ============================================================
// Sponsor Types
// ============================================================

/// POST /sponsor — validated request body forwarded to sidecar
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SponsorRequest {
    pub sender: String,
    pub transaction_block_kind_bytes: String,
    #[serde(default)]
    pub auth_signature: Option<String>,
    #[serde(default)]
    pub auth_timestamp: Option<i64>,
    #[serde(default)]
    pub auth_nonce: Option<String>,
}

/// POST /sponsor/execute — validated request body forwarded to sidecar.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SponsorExecuteRequest {
    pub digest: String,
    pub signature: String,
    #[serde(default)]
    pub sender: Option<String>,
}

// ============================================================
// Auth Types
// ============================================================

/// Headers required for authenticated requests
#[derive(Clone)]
pub struct AuthInfo {
    /// Hex-encoded Ed25519 public key for a signed-request caller. For an
    /// owner-token-authenticated read-API request (no delegate key
    /// involved), `auth::verify_read_api_auth` populates this instead with
    /// the synthetic sentinel `"ownertoken:{owner_address}"` — never a real
    /// key — solely so `read_api_rate_limit_middleware`'s per-key budget
    /// stays isolated per owner. Do not assume this is always valid hex.
    #[allow(dead_code)]
    pub public_key: String,
    /// Owner address from the onchain MemWalAccount (set after onchain verification)
    pub owner: String,
    /// Walrus Memory account object ID (set after onchain verification)
    pub account_id: String,
    /// Delegate private key (hex) — legacy path for SEAL decrypt. Optional;
    /// modern SDKs send `seal_session` instead. Retained during the
    /// transition so older clients keep working.
    pub delegate_key: Option<String>,
    /// Exported SEAL SessionKey (base64-encoded JSON) — replaces the raw
    /// delegate private key on the wire. When present it is preferred over
    /// `delegate_key`. TTL-bounded, package-scoped, signed by the delegate
    /// key on the client; the server never handles private-key material.
    pub seal_session: Option<String>,
}

// Manual Debug redacts both credential fields so accidental
// `{:?}` formatting never leaks delegate private key material or session
// tokens into logs.
impl std::fmt::Debug for AuthInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthInfo")
            .field("public_key", &self.public_key)
            .field("owner", &self.owner)
            .field("account_id", &self.account_id)
            .field(
                "delegate_key",
                &self.delegate_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "seal_session",
                &self.seal_session.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

// ============================================================
// Error
// ============================================================

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    #[allow(dead_code)]
    Unauthorized(String),
    Internal(String),
    /// Walrus blob not found (expired or deleted) — triggers cleanup
    BlobNotFound(String),
    /// Caller authenticated successfully but the path's {owner} does not
    /// match the authenticated identity (HTTP 403).
    Forbidden(String),
    /// Rate limit exceeded (HTTP 429)
    #[allow(dead_code)]
    RateLimited(String),
    /// Storage quota exceeded (HTTP 402)
    QuotaExceeded(String),
    /// Request conflicts with existing state (HTTP 409) — e.g. an idempotency
    /// key reused for a request with different content.
    Conflict(String),
    /// upstream LLM/embedding provider returned a transient failure
    /// (gateway timeout / connection reset / "200 OK" wrapping an
    /// `{"error":{"code":504}}` envelope from OpenRouter). Maps to HTTP 503
    /// so the SDK + benchmark harness will retry per their transient-error
    /// policy (`_RETRY_STATUS = (429, 502, 503, 504)`). This converts a
    /// silently-dropped turn into one retried with exponential backoff —
    /// closing the bench-completion gap diagnosed during the LME v2 run.
    UpstreamUnavailable(String),
    /// Operator write pause (`WRITES_PAUSED`). HTTP 503 with a stable
    /// client-visible message, distinct from transient upstream failures.
    WritesPaused(String),
    /// A recall about to miss the caller's `deadline_ms`. HTTP 504 with
    /// `code: "RECALL_TIMEOUT"` and the stage it was stuck in.
    RecallTimeout {
        stage: &'static str,
        elapsed_ms: u64,
    },
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Internal(msg) => write!(f, "Internal Error: {}", msg),
            AppError::BlobNotFound(msg) => write!(f, "Blob Not Found: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::RateLimited(msg) => write!(f, "Rate Limited: {}", msg),
            AppError::RecallTimeout { stage, elapsed_ms } => {
                write!(f, "Recall Timeout: {} after {}ms", stage, elapsed_ms)
            }
            AppError::QuotaExceeded(msg) => write!(f, "Quota Exceeded: {}", msg),
            AppError::UpstreamUnavailable(msg) => write!(f, "Upstream Unavailable: {}", msg),
            AppError::WritesPaused(msg) => write!(f, "Writes Paused: {}", msg),
        }
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        crate::observability::record_app_error(self.kind());
        let (status, message) = match &self {
            AppError::BadRequest(msg) => (axum::http::StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized(msg) => (axum::http::StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::Internal(msg) => {
                // SEC: Never leak internal error details to the client.
                // Log the full message server-side with a request ID so
                // operators can correlate, then return a generic message.
                let trace_id = crate::observability::current_request_id()
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                tracing::error!(
                    request_id = %trace_id,
                    "Internal server error: {}",
                    msg,
                );
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal server error (traceId: {})", trace_id),
                )
            }
            AppError::BlobNotFound(msg) => (axum::http::StatusCode::NOT_FOUND, msg.clone()),
            AppError::Forbidden(msg) => (axum::http::StatusCode::FORBIDDEN, msg.clone()),
            AppError::Conflict(msg) => (axum::http::StatusCode::CONFLICT, msg.clone()),
            AppError::RateLimited(msg) => (axum::http::StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            AppError::QuotaExceeded(msg) => (axum::http::StatusCode::PAYMENT_REQUIRED, msg.clone()),
            AppError::WritesPaused(msg) => {
                (axum::http::StatusCode::SERVICE_UNAVAILABLE, msg.clone())
            }
            AppError::RecallTimeout { stage, elapsed_ms } => {
                // Not `{error}` alone: the SDK reads `code` into
                // `serverCode` and shows `message`, and callers read
                // `stage` to decide what to do next.
                let message = format!("Recall timed out after {elapsed_ms}ms during {stage}");
                let body = serde_json::json!({
                    "error": message,
                    "message": message,
                    "code": "RECALL_TIMEOUT",
                    "stage": stage,
                    "elapsed_ms": elapsed_ms,
                });
                return (axum::http::StatusCode::GATEWAY_TIMEOUT, axum::Json(body)).into_response();
            }
            AppError::UpstreamUnavailable(msg) => {
                // log the upstream details server-side, return
                // 503 so the SDK / harness will retry per their
                // transient-error policy. Body is a generic message —
                // we don't leak internal upstream-provider names to
                // clients.
                let trace_id = crate::observability::current_request_id()
                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                tracing::warn!(
                    request_id = %trace_id,
                    "Upstream unavailable: {}",
                    msg,
                );
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    format!("Upstream temporarily unavailable (traceId: {})", trace_id),
                )
            }
        };

        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}

impl AppError {
    pub fn kind(&self) -> &'static str {
        match self {
            AppError::BadRequest(_) => "bad_request",
            AppError::Unauthorized(_) => "unauthorized",
            AppError::Internal(_) => "internal",
            AppError::BlobNotFound(_) => "blob_not_found",
            AppError::Forbidden(_) => "forbidden",
            AppError::Conflict(_) => "conflict",
            AppError::RateLimited(_) => "rate_limited",
            AppError::QuotaExceeded(_) => "quota_exceeded",
            AppError::UpstreamUnavailable(_) => "upstream_unavailable",
            AppError::WritesPaused(_) => "writes_paused",
            AppError::RecallTimeout { .. } => "recall_timeout",
        }
    }
}

// ============================================================
// Sidecar Types (shared by seal.rs + walrus.rs)
// ============================================================

/// Error response from the TS sidecar HTTP server
#[derive(Debug, Deserialize)]
pub struct SidecarError {
    pub error: String,
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static WALRUS_STORAGE_EPOCHS_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn pool(n: usize) -> Arc<KeyPool> {
        Arc::new(KeyPool::new((0..n).map(|i| format!("key{i}")).collect()))
    }

    #[test]
    fn claiming_a_free_wallet_takes_it_before_the_next_worker_looks() {
        // bench-w9-merged-9e9a10c-r1: one wallet took 27 of 100 jobs because
        // every worker choosing in the same instant saw the same idle wallet.
        let pool = pool(3);
        let _a = pool.begin_attempt(0);
        let _b = pool.begin_attempt(1);
        // Plain lookups herd: both see wallet 2 as the only idle one.
        assert_eq!(pool.least_loaded_index().unwrap(), 2);
        assert_eq!(pool.least_loaded_index().unwrap(), 2);
        // Claims do not: the first takes 2, the second sees 2 as busy.
        let first = pool.claim_least_loaded().unwrap();
        let second = pool.claim_least_loaded().unwrap();
        assert_eq!(first.index(), 2);
        assert_ne!(second.index(), 2);
        assert_eq!(pool.inflight_snapshot().iter().sum::<usize>(), 4);
        drop(first);
        drop(second);
        assert_eq!(pool.inflight_snapshot(), vec![1, 1, 0]);
    }

    #[test]
    fn an_idle_pool_still_spreads_round_robin() {
        // The regression this guards: with every counter at 0 a plain argmin
        // returns index 0 forever, funnelling the whole pool onto one wallet
        // — worse than the round-robin it replaces.
        let pool = pool(4);
        let picked: Vec<_> = (0..8).map(|_| pool.least_loaded_index().unwrap()).collect();
        assert_eq!(picked, vec![0, 1, 2, 3, 0, 1, 2, 3]);
    }

    #[test]
    fn a_busy_wallet_is_skipped_for_an_idle_one() {
        // The production case: a job waited 6.2s for its assigned wallet while
        // other wallets sat idle, because round-robin could not see the load.
        let pool = pool(4);
        let _busy = pool.begin_attempt(1);
        // Cursor lands on 1 next, but 1 is busy and 2 is not.
        let _ = pool.least_loaded_index();
        assert_eq!(pool.least_loaded_index().unwrap(), 2);
    }

    #[test]
    fn selection_avoids_every_busy_wallet_until_only_busy_ones_remain() {
        let pool = pool(3);
        let _a = pool.begin_attempt(0);
        let _b = pool.begin_attempt(1);
        // Only wallet 2 is free, so every pick goes there regardless of cursor.
        for _ in 0..6 {
            assert_eq!(pool.least_loaded_index().unwrap(), 2);
        }
    }

    #[test]
    fn a_fully_busy_pool_falls_back_to_spreading_evenly() {
        // Saturated is not a special case: equal load means the tie-break
        // decides, so behaviour degrades exactly to round-robin.
        let pool = pool(3);
        let _a = pool.begin_attempt(0);
        let _b = pool.begin_attempt(1);
        let _c = pool.begin_attempt(2);
        let picked: Vec<_> = (0..6).map(|_| pool.least_loaded_index().unwrap()).collect();
        assert_eq!(picked, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn dropping_the_guard_frees_the_wallet() {
        let pool = pool(2);
        {
            let _busy = pool.begin_attempt(0);
            assert_eq!(pool.inflight_snapshot(), vec![1, 0]);
        }
        assert_eq!(pool.inflight_snapshot(), vec![0, 0]);
    }

    #[test]
    fn the_guard_releases_on_an_early_return() {
        // `execute_wallet_job` returns from many points; the guard exists so
        // none of them has to remember to decrement.
        let pool = pool(2);
        fn bail(pool: &Arc<KeyPool>) -> Result<(), ()> {
            let _slot = pool.begin_attempt(1);
            Err(())
        }
        assert!(bail(&pool).is_err());
        assert_eq!(pool.inflight_snapshot(), vec![0, 0]);
    }

    #[test]
    fn nested_attempts_on_one_wallet_count_and_release_independently() {
        let pool = pool(2);
        let first = pool.begin_attempt(0);
        let second = pool.begin_attempt(0);
        assert_eq!(pool.inflight_snapshot(), vec![2, 0]);
        drop(first);
        assert_eq!(pool.inflight_snapshot(), vec![1, 0]);
        drop(second);
        assert_eq!(pool.inflight_snapshot(), vec![0, 0]);
    }

    #[test]
    fn releasing_below_zero_saturates_instead_of_wrapping() {
        // A wrapped counter would read as usize::MAX and exclude the wallet
        // from selection for the life of the process.
        let pool = pool(2);
        pool.end_attempt(0);
        pool.end_attempt(0);
        assert_eq!(pool.inflight_snapshot(), vec![0, 0]);
        let _busy = pool.begin_attempt(1);
        assert_eq!(pool.least_loaded_index().unwrap(), 0);
    }

    #[test]
    fn an_out_of_range_index_is_ignored_rather_than_panicking() {
        let pool = pool(2);
        let guard = pool.begin_attempt(99);
        assert_eq!(pool.inflight_snapshot(), vec![0, 0]);
        drop(guard);
        assert_eq!(pool.inflight_snapshot(), vec![0, 0]);
    }

    #[test]
    fn an_empty_pool_selects_nothing() {
        let pool = Arc::new(KeyPool::new(vec![]));
        assert_eq!(pool.least_loaded_index(), None);
        assert_eq!(pool.next_index(), None);
    }

    #[test]
    fn next_index_is_unchanged_for_the_retry_path() {
        // Retries derive their wallet from the job's own start index, not the
        // global cursor, so `next_index` has to keep its old semantics.
        let pool = pool(3);
        let picked: Vec<_> = (0..6).map(|_| pool.next_index().unwrap()).collect();
        assert_eq!(picked, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn balance_monitor_interval_has_a_safe_minimum() {
        assert_eq!(normalized_balance_monitor_interval(1), 30);
        assert_eq!(normalized_balance_monitor_interval(30), 30);
        assert_eq!(normalized_balance_monitor_interval(900), 900);
    }

    // ── Client-supplied embedding vector validation ──────────────

    #[test]
    fn embedding_of_correct_width_is_accepted() {
        use crate::services::embedder::EMBEDDING_DIMS;
        assert!(validate_embedding_vector(&vec![0.1_f32; EMBEDDING_DIMS]).is_ok());
    }

    #[test]
    fn embedding_of_wrong_width_is_rejected_with_actionable_message() {
        use crate::services::embedder::EMBEDDING_DIMS;
        // A width from a different embedding model; kept distinct from the
        // expected width so a transposed format! (expected/actual swapped) still
        // fails the exact-string assert below.
        let wrong = EMBEDDING_DIMS / 2 + 1;
        match validate_embedding_vector(&vec![0.1_f32; wrong]).unwrap_err() {
            // BadRequest maps to HTTP 400, unlike the opaque 500 a downstream
            // pgvector failure would produce (after a paid upload on the write path).
            AppError::BadRequest(msg) => {
                // Build the expected message from the constant (single source of
                // truth — survives a dimension change) while still pinning the
                // exact wording and the expected-then-actual order.
                assert_eq!(
                    msg,
                    format!("vector must have exactly {EMBEDDING_DIMS} dimensions, got {wrong}")
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn embedding_empty_vector_is_rejected() {
        // The width check subsumes a separate non-empty guard.
        assert!(matches!(
            validate_embedding_vector(&[]),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn embedding_with_non_finite_component_is_rejected() {
        use crate::services::embedder::EMBEDDING_DIMS;
        // Correct width, but a NaN/Inf component pgvector would refuse to index —
        // must be caught here, before any paid upload, not as an opaque 500.
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut vector = vec![0.1_f32; EMBEDDING_DIMS];
            vector[7] = bad;
            match validate_embedding_vector(&vector).unwrap_err() {
                AppError::BadRequest(msg) => {
                    assert!(
                        msg.contains("finite"),
                        "message names the finiteness rule: {msg}"
                    );
                    assert!(
                        msg.contains("index 7"),
                        "message names the offending index: {msg}"
                    );
                }
                other => panic!("expected BadRequest, got {other:?}"),
            }
        }
    }

    fn security_delete_test_config() -> Config {
        Config {
            port: 8000,
            database_url: "postgres://test".into(),
            sui_rpc_url: "https://rpc.example".into(),
            sui_grpc_url: Some("https://grpc.example".into()),
            sui_network: "testnet".into(),
            memwal_account_id: None,
            openai_api_key: None,
            openai_api_base: "https://api.example".into(),
            walrus_publisher_url: "https://publisher.example".into(),
            walrus_aggregator_url: "https://aggregator.example".into(),
            walrus_storage_epochs: 3,
            walrus_aggregator_urls: vec!["https://aggregator.example".into()],
            walrus_skip_consistency_check: false,
            walrus_aggregator_race_after_ms: 150,
            sui_private_key: None,
            sui_private_keys: Vec::new(),
            package_id: "0x1".into(),
            seal_policy_package_id: "0x1".into(),
            registry_id: "0x2".into(),
            sidecar_url: "http://localhost:9000".into(),
            seal_sidecar_url: "http://localhost:9001".into(),
            sidecar_secret: None,
            seal_expected_committee_identity: None,
            rate_limit: RateLimitConfig::default(),
            sponsor_rate_limit: SponsorRateLimitConfig::default(),
            read_api_rate_limit: ReadApiRateLimitConfig::default(),
            accounts_rate_limit: AccountsRateLimitConfig::default(),
            mcp_rate_limit: McpRateLimitConfig::default(),
            trusted_proxy_hops: 0,
            allowed_origins: String::new(),
            benchmark_mode: false,
            writes_paused: false,
            enable_memory_deletion: false,
            enable_security_delete: false,
            legacy_db_url: None,
            deletion_reconciler_enabled: false,
            deletion_object_resolver_enabled: false,
            delete_batch_max: 900,
            max_active_batches_per_owner: 16,
            security_delete_auth_requests_per_minute: 20,
            security_delete_prepare_requests_per_minute: 10,
            sui_rpc_requests_per_window: 3_000,
            sui_rpc_window: std::time::Duration::from_secs(10),
            sui_rpc_attempt_timeout: std::time::Duration::from_secs(5),
            sui_rpc_max_in_flight: 64,
            security_delete_execute_max_in_flight: 1,
            security_delete_crash_test_secret: None,
            sponsor_private_key: None,
            sponsor_min_balance_alert: 0,
            claim_ttl_secs: 600,
            exec_grace_secs: 60,
            deletion_token_secret: None,
            deletion_token_ttl_secs: 2700,
            expiry_margin_epochs: 1,
            walrus_package_id: "0x3".into(),
            walrus_system_object_id: "0x4".into(),
            walrus_staking_pool_id: "0x5".into(),
            owner_token_secret: "owner-token-test-secret".into(),
            owner_token_service_credential: "owner-token-test-credential".into(),
            owner_token_ttl_secs: 900,
            owner_token_rate_limit: OwnerTokenRateLimitConfig::default(),
            restore_requests_per_owner_per_minute: 10,
            balance_monitor_interval_secs: 900,
            wallet_balance_low_threshold_wal: 50_000_000_000,
            wallet_balance_low_threshold_sui: 5_000_000_000,
            sponsor_balance_low_threshold_sui: 5_000_000_000,
            mcp_oauth: None,
            auth_max_clock_drift_secs: DEFAULT_AUTH_CLOCK_DRIFT_SECS,
        }
    }

    #[tokio::test]
    async fn security_delete_execution_gate_serializes_callers() {
        let gate = SecurityDeleteExecutionGate::new(1);
        let first = gate.acquire().await;
        let waiting_gate = gate.clone();
        let waiter = tokio::spawn(async move { waiting_gate.acquire().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        drop(first);
        let second = waiter.await.unwrap();
        drop(second);
    }

    #[test]
    fn security_delete_execution_concurrency_is_bounded() {
        let mut config = security_delete_test_config();
        config.enable_memory_deletion = true;
        config.enable_security_delete = true;
        config.legacy_db_url = Some("postgres://legacy".into());
        config.deletion_token_secret = Some("secret".into());
        config.sponsor_private_key =
            Some(base64::engine::general_purpose::STANDARD.encode([0_u8; 32]));

        config.security_delete_execute_max_in_flight = 0;
        assert!(validate_security_delete_config(&config).is_err());
        config.security_delete_execute_max_in_flight = MAX_SECURITY_DELETE_EXECUTE_IN_FLIGHT + 1;
        assert!(validate_security_delete_config(&config).is_err());
        config.security_delete_execute_max_in_flight = 1;
        assert!(validate_security_delete_config(&config).is_ok());
    }

    #[test]
    fn security_delete_boot_guard_rejects_selector_without_master() {
        let mut config = security_delete_test_config();
        config.enable_security_delete = true;
        assert!(validate_security_delete_config(&config).is_err());
    }

    #[test]
    fn security_delete_boot_guard_rejects_missing_dependencies() {
        let mut config = security_delete_test_config();
        config.enable_memory_deletion = true;
        config.enable_security_delete = true;
        assert!(validate_security_delete_config(&config).is_err());
        config.legacy_db_url = Some("postgres://legacy".into());
        config.deletion_token_secret = Some("secret".into());
        config.sponsor_private_key =
            Some(base64::engine::general_purpose::STANDARD.encode([7u8; 32]));
        assert!(validate_security_delete_config(&config).is_ok());
    }

    #[test]
    fn security_delete_boot_guard_resolver_only_needs_chain_and_legacy_db() {
        let mut config = security_delete_test_config();
        config.deletion_object_resolver_enabled = true;
        config.legacy_db_url = Some("postgres://legacy".into());
        assert!(validate_security_delete_config(&config).is_ok());
    }

    #[test]
    fn security_delete_boot_guard_reconciler_requires_sponsor() {
        let mut config = security_delete_test_config();
        config.deletion_reconciler_enabled = true;
        config.legacy_db_url = Some("postgres://legacy".into());
        assert!(validate_security_delete_config(&config).is_err());
        config.sponsor_private_key =
            Some(base64::engine::general_purpose::STANDARD.encode([7u8; 32]));
        assert!(validate_security_delete_config(&config).is_ok());
    }

    #[test]
    fn security_delete_boot_guard_all_off_needs_nothing() {
        let config = security_delete_test_config();
        assert!(validate_security_delete_config(&config).is_ok());
    }

    #[test]
    fn testnet_boot_guard_requires_grpc_even_when_security_delete_is_off() {
        let mut config = security_delete_test_config();
        config.sui_grpc_url = None;
        let error = validate_security_delete_config(&config).unwrap_err();
        assert!(error.contains("SUI_GRPC_URL is required"));

        config.sui_network = "localnet".into();
        assert!(validate_security_delete_config(&config).is_ok());
    }

    #[test]
    fn boot_guard_rejects_unknown_sui_network() {
        let mut config = security_delete_test_config();
        config.sui_network = "testnet ".into();
        let error = validate_security_delete_config(&config).unwrap_err();
        assert!(error.contains("unsupported SUI_NETWORK"));
    }

    #[test]
    fn config_response_advertises_grpc_transport_compatibly() {
        let response = ConfigResponse {
            package_id: "0x1".into(),
            network: "testnet".into(),
            sui_rpc_url: Some("https://rpc.example".into()),
            sui_grpc_url: Some("https://grpc.example".into()),
            sui_transport: "grpc",
            rate_limit_disabled: false,
            security_delete_sui_rpc_requests_per_window: 2_850,
            security_delete_sui_rpc_window_secs: 10,
            security_delete_enabled: true,
            security_delete_reconciler_enabled: true,
            security_delete_object_resolver_enabled: true,
            security_delete_batch_max: 900,
            security_delete_max_active_batches_per_owner: 16,
            security_delete_auth_requests_per_minute: 20,
            security_delete_prepare_requests_per_minute: 10,
            security_delete_execute_max_in_flight: 1,
            security_delete_crash_test_enabled: false,
            security_delete_claim_ttl_secs: 600,
            security_delete_execution_grace_secs: 60,
            security_delete_expiry_margin_epochs: 1,
        };
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["suiGrpcUrl"], "https://grpc.example");
        assert_eq!(json["suiTransport"], "grpc");
        assert_eq!(json["suiRpcUrl"], "https://rpc.example");
    }

    #[test]
    fn security_delete_boot_guard_rejects_unsafe_rpc_controls() {
        let mut config = security_delete_test_config();
        config.deletion_object_resolver_enabled = true;
        config.legacy_db_url = Some("postgres://legacy".into());

        config.sui_rpc_attempt_timeout = std::time::Duration::ZERO;
        assert!(validate_security_delete_config(&config).is_err());
        config.sui_rpc_attempt_timeout = std::time::Duration::from_secs(5);
        config.sui_rpc_max_in_flight = 1;
        assert!(validate_security_delete_config(&config).is_err());
        config.sui_rpc_max_in_flight = 64;
        assert!(validate_security_delete_config(&config).is_ok());
    }

    #[test]
    fn security_delete_crash_failpoint_is_localnet_only() {
        let mut config = security_delete_test_config();
        config.security_delete_crash_test_secret = Some("test-secret".into());
        config.sui_network = "mainnet".into();
        assert!(validate_security_delete_config(&config).is_err());
        config.sui_network = "localnet".into();
        assert!(validate_security_delete_config(&config).is_ok());
    }

    #[test]
    fn security_delete_routes_require_master_and_selector() {
        for master in [false, true] {
            for selector in [false, true] {
                let mut config = security_delete_test_config();
                config.enable_memory_deletion = master;
                config.enable_security_delete = selector;
                assert_eq!(security_delete_routes_enabled(&config), master && selector);
            }
        }
    }

    #[test]
    fn sui_rpc_quota_defaults_to_provider_window() {
        assert_eq!(
            resolve_sui_rpc_quota(None, None, None, None),
            (2_850, std::time::Duration::from_secs(10))
        );
        assert_eq!(
            resolve_sui_rpc_quota(None, None, None, Some("1")),
            (3_000, std::time::Duration::from_secs(10))
        );
    }

    #[test]
    fn sui_rpc_quota_preserves_legacy_request_spacing() {
        assert_eq!(
            resolve_sui_rpc_quota(None, None, Some("4"), Some("0.5")),
            (1, std::time::Duration::from_millis(250))
        );
        assert_eq!(
            resolve_sui_rpc_quota(None, None, Some("invalid"), None),
            (1, std::time::Duration::from_millis(250))
        );
    }

    #[test]
    fn sui_rpc_quota_requires_a_complete_valid_window() {
        assert_eq!(
            resolve_sui_rpc_quota(Some("3000"), None, None, None),
            (0, std::time::Duration::ZERO)
        );
        assert_eq!(
            resolve_sui_rpc_quota(None, Some("10"), None, None),
            (0, std::time::Duration::ZERO)
        );
        assert_eq!(
            resolve_sui_rpc_quota(Some("invalid"), Some("10"), None, None),
            (0, std::time::Duration::from_secs(10))
        );
        for utilization in ["0", "1.1", "invalid"] {
            assert_eq!(
                resolve_sui_rpc_quota(Some("3000"), Some("10"), None, Some(utilization)),
                (0, std::time::Duration::from_secs(10))
            );
        }
    }

    fn with_walrus_storage_epochs_env<R>(value: Option<&str>, test: impl FnOnce() -> R) -> R {
        let _guard = WALRUS_STORAGE_EPOCHS_ENV_LOCK.lock().unwrap();
        let previous = std::env::var("WALRUS_STORAGE_EPOCHS").ok();

        match value {
            Some(value) => std::env::set_var("WALRUS_STORAGE_EPOCHS", value),
            None => std::env::remove_var("WALRUS_STORAGE_EPOCHS"),
        }

        let result = test();

        match previous {
            Some(value) => std::env::set_var("WALRUS_STORAGE_EPOCHS", value),
            None => std::env::remove_var("WALRUS_STORAGE_EPOCHS"),
        }

        result
    }

    // ── AuthInfo Debug redacts delegate_key ───────────────────────

    #[test]
    fn blob_cache_defaults_match_mem_37_policy() {
        assert_eq!(BLOB_CACHE_KEY_PREFIX, "memwal:blob:v1:");
        assert_eq!(DEFAULT_BLOB_CACHE_TTL_SECS, 14 * 24 * 60 * 60);
        assert_eq!(DEFAULT_BLOB_CACHE_MAX_BYTES, 512 * 1024);
        assert_eq!(DEFAULT_WALRUS_AGGREGATOR_RACE_AFTER_MS, 150);
    }

    #[test]
    fn parse_walrus_aggregator_urls_keeps_primary_first_and_dedupes() {
        let urls = parse_walrus_aggregator_urls(
            "https://primary.example",
            Some(" https://secondary.example,https://primary.example,,https://third.example "),
        );

        assert_eq!(
            urls,
            vec![
                "https://primary.example".to_string(),
                "https://secondary.example".to_string(),
                "https://third.example".to_string(),
            ]
        );
    }

    #[test]
    fn auth_info_debug_redacts_delegate_key() {
        let auth = AuthInfo {
            public_key: "aabbccdd".to_string(),
            owner: "0xowner".to_string(),
            account_id: "0xaccount".to_string(),
            delegate_key: Some("supersecretprivatekeyinhex1234567890abcdef".to_string()),
            seal_session: None,
        };

        let debug_str = format!("{:?}", auth);

        // Must contain the redacted marker
        assert!(
            debug_str.contains("<redacted>"),
            "delegate_key must be redacted in Debug output, got: {}",
            debug_str
        );
        // Must NOT contain the actual key
        assert!(
            !debug_str.contains("supersecretprivatekeyinhex"),
            "actual delegate key leaked in Debug output: {}",
            debug_str
        );
        // Public fields are still visible
        assert!(debug_str.contains("aabbccdd"));
        assert!(debug_str.contains("0xowner"));
        assert!(debug_str.contains("0xaccount"));
    }

    #[test]
    fn auth_info_debug_shows_none_when_no_delegate_key() {
        let auth = AuthInfo {
            public_key: "aabb".to_string(),
            owner: "0xowner".to_string(),
            account_id: "0xaccount".to_string(),
            delegate_key: None,
            seal_session: None,
        };

        let debug_str = format!("{:?}", auth);

        // None variant should render as None
        assert!(
            debug_str.contains("None"),
            "expected None in debug: {}",
            debug_str
        );
        assert!(!debug_str.contains("<redacted>"));
    }

    // seal_session must also be redacted in Debug output. While
    // less catastrophic than the raw private key (bounded TTL, bounded
    // scope), it is still an authorization token and must not surface in
    // structured logs.
    #[test]
    fn auth_info_debug_redacts_seal_session() {
        let auth = AuthInfo {
            public_key: "aabbccdd".to_string(),
            owner: "0xowner".to_string(),
            account_id: "0xaccount".to_string(),
            delegate_key: None,
            seal_session: Some("eyJhZGRyZXNzIjoiMHhhYmMiLCJwYWNrYWdlSWQiOiIweGRlZiJ9".to_string()),
        };

        let debug_str = format!("{:?}", auth);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("eyJhZGRyZXNzIjo"));
    }

    // ── AppError: status code mapping ───────────────────────────────────

    #[test]
    fn app_error_bad_request_status() {
        let err = AppError::BadRequest("test".into());
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[test]
    fn app_error_unauthorized_status() {
        let err = AppError::Unauthorized("test".into());
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn app_error_internal_status() {
        let err = AppError::Internal("secret db connection string".into());
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn app_error_internal_redacts_message() {
        let err = AppError::Internal("secret db connection string".into());
        let resp = axum::response::IntoResponse::into_response(err);
        let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        // Must NOT contain the internal message
        assert!(
            !body_str.contains("secret db connection string"),
            "internal error details leaked to client: {}",
            body_str,
        );
        // Must contain a traceId for correlation
        assert!(
            body_str.contains("traceId"),
            "response should contain traceId: {}",
            body_str,
        );
    }

    #[test]
    fn app_error_blob_not_found_status() {
        let err = AppError::BlobNotFound("test".into());
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[test]
    fn app_error_rate_limited_status() {
        let err = AppError::RateLimited("test".into());
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn app_error_quota_exceeded_status() {
        let err = AppError::QuotaExceeded("test".into());
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::PAYMENT_REQUIRED);
    }

    #[test]
    fn app_error_upstream_unavailable_status_is_503_for_retryability() {
        // HTTP 503 is in the SDK + benchmark harness retry
        // set (429, 502, 503, 504). Pinning this so a future change
        // can't silently re-map UpstreamUnavailable to a non-retryable
        // code — that would re-introduce the bench-completion gap that
        // the LME v2 diagnosis surfaced.
        let err = AppError::UpstreamUnavailable("OpenRouter upstream error (code=504)".into());
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "UpstreamUnavailable MUST map to 503 so clients retry"
        );
    }

    #[test]
    fn app_error_upstream_unavailable_kind_label() {
        let err = AppError::UpstreamUnavailable("test".into());
        assert_eq!(
            err.kind(),
            "upstream_unavailable",
            "observability label must be stable for grafana/loki queries"
        );
    }

    #[tokio::test]
    async fn forbidden_maps_to_403() {
        // `IntoResponse` isn't otherwise imported in this module (other
        // status-mapping tests call it via the fully-qualified
        // `axum::response::IntoResponse::into_response(err)` form instead),
        // so bring it into scope locally for the method-call syntax below.
        use axum::response::IntoResponse;
        let err = AppError::Forbidden("owner mismatch".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn forbidden_display_format() {
        let err = AppError::Forbidden("owner mismatch".to_string());
        assert_eq!(err.to_string(), "Forbidden: owner mismatch");
    }

    #[test]
    fn forbidden_kind() {
        let err = AppError::Forbidden("owner mismatch".to_string());
        assert_eq!(err.kind(), "forbidden");
    }

    // ── KeyPool: round-robin selection ─────────────────────────────────

    #[test]
    fn key_pool_returns_keys_round_robin() {
        let pool = KeyPool::new(vec!["key_a".into(), "key_b".into(), "key_c".into()]);

        assert_eq!(pool.next(), Some("key_a"));
        assert_eq!(pool.next(), Some("key_b"));
        assert_eq!(pool.next(), Some("key_c"));
        assert_eq!(pool.next(), Some("key_a"));
    }

    #[test]
    fn key_pool_empty_returns_none() {
        let pool = KeyPool::new(vec![]);
        assert_eq!(pool.next(), None);
        assert_eq!(pool.next_index(), None);
        assert!(pool.is_empty());
    }

    #[test]
    fn key_pool_single_key() {
        let pool = KeyPool::new(vec!["only_key".into()]);
        assert_eq!(pool.next(), Some("only_key"));
        assert_eq!(pool.next(), Some("only_key"));
        assert!(!pool.is_empty());
    }

    #[test]
    fn key_pool_next_index_round_robin() {
        let pool = KeyPool::new(vec!["a".into(), "b".into()]);
        assert_eq!(pool.next_index(), Some(0));
        assert_eq!(pool.next_index(), Some(1));
        assert_eq!(pool.next_index(), Some(0));
    }

    // ── SponsorRateLimitConfig defaults ─────────────────────────────────

    #[test]
    fn sponsor_rate_limit_default_values() {
        let config = SponsorRateLimitConfig::default();
        assert_eq!(config.per_minute, 10);
        assert_eq!(config.per_hour, 30);
        assert_eq!(config.global_per_minute, 100);
        assert_eq!(config.global_per_hour, 1000);
    }

    // ── ReadApiRateLimitConfig defaults ─────────────────────────────────

    #[test]
    fn read_api_rate_limit_default_values() {
        let config = ReadApiRateLimitConfig::default();
        assert_eq!(config.per_delegate_key_per_minute, 200);
    }

    #[test]
    fn read_api_rate_limit_from_env_override() {
        // No other test touches READ_API_RATE_LIMIT_PER_MINUTE, so unlike
        // WALRUS_STORAGE_EPOCHS above this doesn't need a shared lock to be
        // race-free under `cargo test`'s parallel test threads.
        std::env::set_var("READ_API_RATE_LIMIT_PER_MINUTE", "500");
        let config = ReadApiRateLimitConfig::from_env();
        std::env::remove_var("READ_API_RATE_LIMIT_PER_MINUTE");
        assert_eq!(config.per_delegate_key_per_minute, 500);
    }

    // ── AccountsRateLimitConfig defaults ────────────────────────────────

    #[test]
    fn accounts_rate_limit_default_values() {
        let config = AccountsRateLimitConfig::default();
        assert_eq!(config.per_minute, 20);
        assert_eq!(config.per_hour, 120);
        assert_eq!(config.global_per_minute, 200);
        assert_eq!(config.global_per_hour, 1500);
        // Must stay well below the general authenticated per-account budget
        // this middleware used to (bug-)reuse, or the fix regresses.
        assert!(config.per_minute < RateLimitConfig::default().max_requests_per_minute);
        assert!(config.per_hour < RateLimitConfig::default().max_requests_per_hour);
    }

    #[test]
    fn mcp_rate_limit_default_values() {
        let config = McpRateLimitConfig::default();
        assert_eq!(config.per_minute, 2000);
        assert_eq!(config.per_hour, 8000);
        assert_eq!(config.global_per_minute, 2500);
        assert_eq!(config.global_per_hour, 15000);
        assert!(config.global_per_minute > config.per_minute);
        assert!(config.global_per_hour > config.per_hour);
        let accounts = AccountsRateLimitConfig::default();
        assert_eq!(accounts.per_minute, 20);
        assert_eq!(accounts.per_hour, 120);
        assert_eq!(accounts.global_per_minute, 200);
        assert_eq!(accounts.global_per_hour, 1500);
    }

    static MCP_RATE_LIMIT_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn mcp_rate_limit_from_env_parses_overrides() {
        let _lock = MCP_RATE_LIMIT_ENV_LOCK.lock().unwrap();
        let keys = [
            "MCP_RATE_LIMIT_PER_MINUTE",
            "MCP_RATE_LIMIT_PER_HOUR",
            "MCP_GLOBAL_RATE_LIMIT_PER_MINUTE",
            "MCP_GLOBAL_RATE_LIMIT_PER_HOUR",
        ];
        let saved: Vec<_> = keys
            .iter()
            .map(|key| (*key, std::env::var(key).ok()))
            .collect();
        struct Restore<'a>(&'a [(&'static str, Option<String>)]);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                for (key, previous) in self.0 {
                    match previous {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
        let _restore = Restore(&saved);

        std::env::set_var("MCP_RATE_LIMIT_PER_MINUTE", "0");
        std::env::set_var("MCP_RATE_LIMIT_PER_HOUR", "-5");
        std::env::set_var("MCP_GLOBAL_RATE_LIMIT_PER_MINUTE", "");
        std::env::set_var("MCP_GLOBAL_RATE_LIMIT_PER_HOUR", "15000abc");
        let rejected = McpRateLimitConfig::from_env();
        assert_eq!(rejected.per_minute, 2000);
        assert_eq!(rejected.per_hour, 8000);
        assert_eq!(rejected.global_per_minute, 2500);
        assert_eq!(rejected.global_per_hour, 15000);

        std::env::set_var("MCP_RATE_LIMIT_PER_MINUTE", "90");
        std::env::set_var("MCP_RATE_LIMIT_PER_HOUR", "900");
        std::env::set_var("MCP_GLOBAL_RATE_LIMIT_PER_MINUTE", "4000");
        std::env::set_var("MCP_GLOBAL_RATE_LIMIT_PER_HOUR", "20000");
        let config = McpRateLimitConfig::from_env();
        assert_eq!(config.per_minute, 90);
        assert_eq!(config.per_hour, 900);
        assert_eq!(config.global_per_minute, 4000);
        assert_eq!(config.global_per_hour, 20000);
    }

    #[test]
    fn walrus_storage_epochs_default_by_network() {
        assert_eq!(default_walrus_storage_epochs_for_network("mainnet"), 3);
        assert_eq!(
            default_walrus_storage_epochs_for_network("testnet"),
            DEFAULT_TESTNET_WALRUS_STORAGE_EPOCHS
        );
    }

    #[test]
    fn configured_walrus_storage_epochs_uses_valid_env_value() {
        with_walrus_storage_epochs_env(Some("4"), || {
            assert_eq!(configured_walrus_storage_epochs("mainnet"), 4);
        });
    }

    #[test]
    fn configured_walrus_storage_epochs_honors_explicit_fifteen() {
        with_walrus_storage_epochs_env(Some("15"), || {
            assert_eq!(configured_walrus_storage_epochs("mainnet"), 15);
            assert_eq!(configured_walrus_storage_epochs("testnet"), 15);
        });
    }

    #[test]
    fn configured_walrus_storage_epochs_falls_back_when_env_exceeds_cap() {
        with_walrus_storage_epochs_env(Some("16"), || {
            assert_eq!(configured_walrus_storage_epochs("mainnet"), 3);
            assert_eq!(configured_walrus_storage_epochs("testnet"), 5);
        });
    }

    // ── configured_auth_clock_drift_secs — bounded, defaulted ────────────

    static AUTH_CLOCK_DRIFT_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_auth_clock_drift_env<R>(value: Option<&str>, test: impl FnOnce() -> R) -> R {
        let _guard = AUTH_CLOCK_DRIFT_ENV_LOCK.lock().unwrap();
        let previous = std::env::var("AUTH_MAX_CLOCK_DRIFT_SECS").ok();

        match value {
            Some(value) => std::env::set_var("AUTH_MAX_CLOCK_DRIFT_SECS", value),
            None => std::env::remove_var("AUTH_MAX_CLOCK_DRIFT_SECS"),
        }

        let result = test();

        match previous {
            Some(value) => std::env::set_var("AUTH_MAX_CLOCK_DRIFT_SECS", value),
            None => std::env::remove_var("AUTH_MAX_CLOCK_DRIFT_SECS"),
        }

        result
    }

    #[test]
    fn auth_clock_drift_defaults_to_300_when_unset() {
        with_auth_clock_drift_env(None, || {
            assert_eq!(configured_auth_clock_drift_secs(), 300);
            assert_eq!(DEFAULT_AUTH_CLOCK_DRIFT_SECS, 300);
        });
    }

    #[test]
    fn auth_clock_drift_honors_valid_env() {
        with_auth_clock_drift_env(Some("120"), || {
            assert_eq!(configured_auth_clock_drift_secs(), 120);
        });
    }

    #[test]
    fn auth_clock_drift_zero_means_exact_match() {
        with_auth_clock_drift_env(Some("0"), || {
            assert_eq!(configured_auth_clock_drift_secs(), 0);
        });
    }

    #[test]
    fn auth_clock_drift_accepts_exact_ceiling() {
        with_auth_clock_drift_env(Some("900"), || {
            assert_eq!(
                configured_auth_clock_drift_secs(),
                MAX_AUTH_CLOCK_DRIFT_SECS
            );
        });
    }

    #[test]
    fn auth_clock_drift_rejects_just_over_ceiling() {
        // Pin the exact inclusive boundary: 900 accepted, 901 falls back.
        with_auth_clock_drift_env(Some("901"), || {
            assert_eq!(
                configured_auth_clock_drift_secs(),
                DEFAULT_AUTH_CLOCK_DRIFT_SECS
            );
        });
    }

    #[test]
    fn auth_clock_drift_falls_back_when_env_exceeds_cap() {
        with_auth_clock_drift_env(Some("3600"), || {
            assert_eq!(
                configured_auth_clock_drift_secs(),
                DEFAULT_AUTH_CLOCK_DRIFT_SECS
            );
        });
    }

    #[test]
    fn auth_clock_drift_falls_back_on_negative_or_garbage() {
        with_auth_clock_drift_env(Some("-5"), || {
            assert_eq!(
                configured_auth_clock_drift_secs(),
                DEFAULT_AUTH_CLOCK_DRIFT_SECS
            );
        });
        with_auth_clock_drift_env(Some("not-a-number"), || {
            assert_eq!(
                configured_auth_clock_drift_secs(),
                DEFAULT_AUTH_CLOCK_DRIFT_SECS
            );
        });
    }

    // ── require_owner_token_secret_len — empty disables, short panics ────

    #[test]
    fn owner_token_secret_empty_stays_disabled() {
        assert_eq!(require_owner_token_secret_len(String::new()), "");
    }

    #[test]
    #[should_panic(expected = "OWNER_TOKEN_SECRET must be at least 32 bytes; got 11")]
    fn owner_token_secret_rejects_test_secret() {
        let _ = require_owner_token_secret_len("test-secret".into());
    }

    #[test]
    #[should_panic(expected = "OWNER_TOKEN_SECRET must be at least 32 bytes; got 31")]
    fn owner_token_secret_rejects_31_bytes() {
        let _ = require_owner_token_secret_len("a".repeat(MIN_OWNER_TOKEN_SECRET_LEN - 1));
    }

    #[test]
    fn owner_token_secret_accepts_32_bytes() {
        let secret = "a".repeat(MIN_OWNER_TOKEN_SECRET_LEN);
        assert_eq!(require_owner_token_secret_len(secret.clone()), secret);
    }

    #[test]
    fn nonce_ttl_buffer_is_positive() {
        // The replay invariant (nonce record outlives the full 2*drift
        // freshness lifetime) rests on the buffer being strictly positive; the
        // `2*drift + buffer` derivation itself is tested against the real
        // `nonce_ttl_secs` in the auth module.
        assert!(NONCE_TTL_BUFFER_SECS > 0);
    }

    // ── AppError Display implementations ────────────────────────────────

    #[test]
    fn app_error_display_all_variants() {
        assert!(AppError::BadRequest("x".into())
            .to_string()
            .contains("Bad Request"));
        assert!(AppError::Unauthorized("x".into())
            .to_string()
            .contains("Unauthorized"));
        assert!(AppError::Internal("x".into())
            .to_string()
            .contains("Internal"));
        assert!(AppError::BlobNotFound("x".into())
            .to_string()
            .contains("Blob Not Found"));
        assert!(AppError::RateLimited("x".into())
            .to_string()
            .contains("Rate Limited"));
        assert!(AppError::QuotaExceeded("x".into())
            .to_string()
            .contains("Quota Exceeded"));
    }

    // ── ScoringWeights::validate() — full bounds matrix ──────────────────

    /// Build weights from explicit fields so tests don't depend on
    /// `Default::default()` if someone changes the defaults later.
    fn w(semantic: f64, recency: f64, half_life: f64) -> ScoringWeights {
        ScoringWeights {
            semantic,
            recency,
            recency_half_life_days: half_life,
            importance: 0.0,
        }
    }

    fn assert_bad_request_mentions(w: &ScoringWeights, needle: &str) {
        match w.validate() {
            Err(AppError::BadRequest(msg)) => assert!(
                msg.contains(needle),
                "expected error mentioning {:?}, got: {}",
                needle,
                msg
            ),
            other => panic!(
                "expected BadRequest containing {:?}, got: {:?}",
                needle, other
            ),
        }
    }

    #[test]
    fn validate_default_is_ok() {
        ScoringWeights::default().validate().unwrap();
    }

    #[test]
    fn validate_rejects_nan_on_each_field() {
        assert_bad_request_mentions(&w(f64::NAN, 0.0, 30.0), "semantic");
        assert_bad_request_mentions(&w(1.0, f64::NAN, 30.0), "recency");
        assert_bad_request_mentions(&w(1.0, 0.0, f64::NAN), "recency_half_life_days");
    }

    #[test]
    fn validate_rejects_infinity_on_each_field() {
        for v in [f64::INFINITY, f64::NEG_INFINITY] {
            assert_bad_request_mentions(&w(v, 0.0, 30.0), "semantic");
            assert_bad_request_mentions(&w(1.0, v, 30.0), "recency");
            assert_bad_request_mentions(&w(1.0, 0.0, v), "recency_half_life_days");
        }
    }

    #[test]
    fn validate_rejects_negative_weights() {
        assert_bad_request_mentions(&w(-0.0001, 0.0, 30.0), "semantic");
        assert_bad_request_mentions(&w(1.0, -1.0, 30.0), "recency");
    }

    #[test]
    fn validate_rejects_weights_above_100() {
        assert_bad_request_mentions(&w(100.0001, 0.0, 30.0), "semantic");
        assert_bad_request_mentions(&w(1.0, 200.0, 30.0), "recency");
    }

    #[test]
    fn validate_accepts_exact_boundaries() {
        // 0.0 and 100.0 are inclusive; half-life only matters when recency > 0.
        w(0.0, 0.0, 30.0).validate().unwrap();
        w(100.0, 100.0, 30.0).validate().unwrap();
    }

    #[test]
    fn validate_rejects_zero_half_life_when_recency_positive() {
        assert_bad_request_mentions(&w(1.0, 0.5, 0.0), "recency_half_life_days");
    }

    #[test]
    fn validate_rejects_negative_half_life_when_recency_positive() {
        assert_bad_request_mentions(&w(1.0, 0.5, -1.0), "recency_half_life_days");
    }

    #[test]
    fn validate_rejects_subnormal_half_life_when_recency_positive() {
        // Subnormal would silently collapse `exp(-age * ln(2) / half_life)`
        // to 0 for any non-zero age — surface as 400 instead of degrading
        // the recency signal to a constant.
        assert_bad_request_mentions(&w(1.0, 0.5, f64::MIN_POSITIVE), "recency_half_life_days");
        // Just below the floor — still rejected.
        assert_bad_request_mentions(
            &w(1.0, 0.5, ScoringWeights::MIN_HALF_LIFE_DAYS / 2.0),
            "recency_half_life_days",
        );
    }

    #[test]
    fn validate_allows_negative_half_life_when_recency_zero() {
        // Carve-out: half-life is only constrained when recency > 0, so a
        // client that sets recency=0 can leave half-life at whatever
        // (the ranker short-circuits anyway). Pinning this keeps the
        // no-op default path from getting a spurious 400 if a stale SDK
        // forwards a placeholder half-life.
        w(1.0, 0.0, -1.0).validate().unwrap();
        w(1.0, 0.0, 0.0).validate().unwrap();
    }

    #[test]
    fn validate_accepts_half_life_at_floor() {
        // The minimum is inclusive: exactly MIN_HALF_LIFE_DAYS is allowed.
        w(1.0, 0.5, ScoringWeights::MIN_HALF_LIFE_DAYS)
            .validate()
            .unwrap();
    }

    // ── RecallRequest.sort — omitted vs explicit ─────────────────────────

    #[test]
    fn recall_sort_keeps_omitted_apart_from_explicit_relevance() {
        let parse = |body: &str| serde_json::from_str::<RecallRequest>(body).unwrap().sort;
        assert_eq!(parse(r#"{"query":"q"}"#), None);
        assert_eq!(
            parse(r#"{"query":"q","sort":"relevance"}"#),
            Some(RecallSort::Relevance)
        );
        assert_eq!(
            parse(r#"{"query":"q","sort":"recent"}"#),
            Some(RecallSort::Recent)
        );
    }

    // ── RecallRequest.deadline_ms / RECALL_TIMEOUT ───────────────────────

    #[test]
    fn recall_deadline_is_optional() {
        let parse = |body: &str| {
            serde_json::from_str::<RecallRequest>(body)
                .unwrap()
                .deadline_ms
        };
        assert_eq!(parse(r#"{"query":"q"}"#), None);
        assert_eq!(parse(r#"{"query":"q","deadline_ms":15000}"#), Some(15_000));
    }

    #[tokio::test]
    async fn recall_timeout_is_a_504_that_names_the_stage() {
        let err = AppError::RecallTimeout {
            stage: "walrus_download",
            elapsed_ms: 14_001,
        };
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::GATEWAY_TIMEOUT);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "RECALL_TIMEOUT");
        assert_eq!(body["stage"], "walrus_download");
        assert_eq!(body["elapsed_ms"], 14_001);
        // `message` is what the TypeScript SDK shows; `error` is what every
        // other relayer error carries.
        assert_eq!(body["message"], body["error"]);
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("walrus_download"));
    }

    // ── ScoringWeights::is_ranker_active() — opt-in predicate ────────────

    #[test]
    fn is_ranker_active_false_for_default() {
        assert!(!ScoringWeights::default().is_ranker_active());
    }

    #[test]
    fn is_ranker_active_true_for_non_zero_recency() {
        assert!(w(1.0, 0.2, 30.0).is_ranker_active());
        assert!(w(1.0, 0.0001, 30.0).is_ranker_active());
    }

    #[test]
    fn is_ranker_active_false_for_subepsilon_recency() {
        // Below EPSILON ≈ 2.22e-16 is treated as zero — the ranker would
        // short-circuit, so the handler considers itself inactive too.
        assert!(!w(1.0, f64::EPSILON / 2.0, 30.0).is_ranker_active());
    }

    // ── Refactor-safety: default short-circuits, wire contract pinned ────

    #[test]
    fn default_recency_is_zero_so_short_circuit_engages() {
        // If you change `ScoringWeights::default().recency` away from 0.0,
        // you change the wire contract on every existing client (the new
        // `score` field would suddenly appear on every default-weighted
        // recall response). Failing this test = ack the change.
        assert_eq!(ScoringWeights::default().recency, 0.0);
        assert!(!ScoringWeights::default().is_ranker_active());
    }

    #[test]
    fn namespace_validation_rejects_empty_and_oversized_values() {
        assert!(validate_namespace("default").is_ok());
        assert!(validate_namespace(&"n".repeat(MAX_NAMESPACE_BYTES)).is_ok());
        assert!(validate_namespace("").is_err());
        assert!(validate_namespace(&"n".repeat(MAX_NAMESPACE_BYTES + 1)).is_err());
    }

    #[test]
    fn namespace_validation_rejects_nul_bytes() {
        assert!(validate_namespace("default\0evil").is_err());
        assert!(validate_namespace("normal-ns_01").is_ok());
        // Other control characters stay accepted: Postgres stores them without
        // complaint, and this validator also gates recall/ask/stats/forget, so
        // rejecting them would strand namespaces written before the NUL check.
        assert!(validate_namespace("has\nnewline").is_ok());
        assert!(validate_namespace("has\ttab").is_ok());
    }

    #[test]
    fn blank_text_is_empty_or_whitespace_only() {
        assert!(text_is_blank(""));
        assert!(text_is_blank(" "));
        assert!(text_is_blank("\t"));
        assert!(text_is_blank("\n"));
        assert!(text_is_blank("  \t\n "));
        // Surrounding whitespace on a real fact is kept by the caller.
        assert!(!text_is_blank("  hello  "));
    }

    // ── HealthResponse.prompt_versions wire shape ────────────────

    #[test]
    fn health_response_serializes_prompt_versions_block() {
        // The benchmark harness reads exactly these field names — pin the
        // wire shape so a rename can't silently break the run-artifact
        // pipeline.
        let resp = HealthResponse {
            status: "ok".to_string(),
            version: "0.1.0".to_string(),
            compatibility: crate::compatibility::version_response(),
            mode: "benchmark".to_string(),
            prompt_versions: PromptVersions {
                extract: "extract.v1".to_string(),
                ask: "ask.v1".to_string(),
            },
            write_ready: true,
            writes: "ok".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["prompt_versions"]["extract"], "extract.v1");
        assert_eq!(json["prompt_versions"]["ask"], "ask.v1");
        assert_eq!(json["write_ready"], true);
        assert_eq!(json["writes"], "ok");
        assert_eq!(
            json["apiVersion"],
            crate::compatibility::RELAYER_API_VERSION
        );
        assert_eq!(json["relayerVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            json["minSupportedSdk"]["typescript"],
            crate::compatibility::MIN_TYPESCRIPT_SDK_VERSION
        );
    }

    #[tokio::test]
    async fn writes_paused_maps_to_503_with_stable_message() {
        assert_eq!(writes_health_status(false, false), "ok");
        assert_eq!(writes_health_status(false, true), "degraded");
        assert_eq!(writes_health_status(true, false), "paused");
        // An operator pause is the stronger statement and wins.
        assert_eq!(writes_health_status(true, true), "paused");
        assert!(reject_if_writes_paused(false).is_ok());
        let err = reject_if_writes_paused(true).expect_err("paused writes");
        assert_eq!(err.kind(), "writes_paused");
        let resp = axum::response::IntoResponse::into_response(err);
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], WRITES_PAUSED_ERROR);
    }
}

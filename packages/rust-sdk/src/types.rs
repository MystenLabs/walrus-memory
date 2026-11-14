//! Request options, environment presets, and wire response types for Walrus Memory.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::tokens::{RecallTokenMeta, TruncationStrategy};

/// Default hosted production relayer URL (`Env::Prod`).
pub const DEFAULT_SERVER_URL: &str = "https://relayer.memory.walrus.xyz";

/// Default namespace when none is configured (`"default"`).
pub const DEFAULT_NAMESPACE: &str = "default";

/// Maximum items accepted in a single `POST /api/remember/bulk` call (`20`).
pub const MAX_BULK_ITEMS: usize = 20;

/// Maximum UTF-8 byte length of a namespace string (`255`).
pub const MAX_NAMESPACE_BYTES: usize = 255;

/// Default per-request HTTP deadline (`30s`).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default HTTP deadline for `POST /api/recall` (`15s`).
pub const DEFAULT_RECALL_TIMEOUT: Duration = Duration::from_secs(15);

/// Default HTTP deadline for unauthenticated preflights (`/version`, `/health`, `/config`, `5s`).
pub const DEFAULT_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default HTTP deadline for `POST /api/restore` (`60s`).
pub const DEFAULT_RESTORE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default HTTP deadline for `POST /api/analyze` (`60s`).
pub const DEFAULT_ANALYZE_TIMEOUT: Duration = Duration::from_secs(60);

/// Named Walrus Memory relayer environment presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Env {
    /// Production mainnet relayer (`https://relayer.memory.walrus.xyz`).
    #[default]
    Prod,
    /// Shared development testnet relayer (`https://relayer.dev.memwal.ai`).
    Dev,
    /// Local relayer instance (`http://127.0.0.1:8000`).
    Local,
}

impl Env {
    /// Returns the canonical base URL for this environment preset.
    #[must_use]
    pub const fn server_url(self) -> &'static str {
        match self {
            Self::Prod => DEFAULT_SERVER_URL,
            Self::Dev => "https://relayer.dev.memwal.ai",
            Self::Local => "http://127.0.0.1:8000",
        }
    }
}

impl fmt::Display for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Prod => "prod",
            Self::Dev => "dev",
            Self::Local => "local",
        };
        f.write_str(name)
    }
}

impl FromStr for Env {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "prod" | "production" => Ok(Self::Prod),
            "dev" | "development" => Ok(Self::Dev),
            "local" | "localhost" => Ok(Self::Local),
            other => Err(Error::InvalidArgument(format!(
                "unknown environment preset {other:?}; expected \"prod\", \"dev\", or \"local\""
            ))),
        }
    }
}

/// Deduplication policy for `remember` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum DedupeMode {
    /// Standard 30-minute retry-bucket idempotency window (default).
    #[default]
    RetryWindow,
    /// Content-hash deduplication across `(owner, namespace, text)` without a time limit.
    ContentHash,
}

/// Polling cadence and timeout budget for background `remember` jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitOptions {
    /// Base delay between status polls before exponential backoff and jitter (`1500ms` default).
    pub poll_interval: Duration,
    /// Maximum wall-clock wait duration before returning a timeout (`60s` single, `120s` bulk).
    pub timeout: Duration,
}

impl Default for WaitOptions {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(1_500),
            timeout: Duration::from_secs(60),
        }
    }
}

impl WaitOptions {
    /// Default wait budget for batched `remember_bulk` and `analyze_and_wait` calls (`120s`).
    #[must_use]
    pub const fn default_bulk() -> Self {
        Self {
            poll_interval: Duration::from_millis(1_500),
            timeout: Duration::from_secs(120),
        }
    }

    /// Sets the base polling interval.
    #[must_use]
    pub const fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    /// Sets the total polling timeout budget.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Per-call options for [`crate::MemWal::remember_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RememberOptions {
    /// Optional namespace override (defaults to the client namespace).
    pub namespace: Option<String>,
    /// Optional caller-supplied idempotency key.
    pub idempotency_key: Option<String>,
    /// Deduplication mode (`RetryWindow` by default, or `ContentHash` when opted in).
    pub dedupe: DedupeMode,
}

impl RememberOptions {
    /// Creates default `remember` options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the target namespace for this call.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Sets an explicit idempotency key scoped to `(owner, namespace)`.
    #[must_use]
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Enables bucket-less content-hash deduplication (`dedupe: true` on the wire).
    #[must_use]
    pub const fn with_dedupe(mut self, mode: DedupeMode) -> Self {
        self.dedupe = mode;
        self
    }

    /// Shorthand for `with_dedupe(DedupeMode::ContentHash)`.
    #[must_use]
    pub const fn dedupe_by_content(mut self) -> Self {
        self.dedupe = DedupeMode::ContentHash;
        self
    }
}

/// Combined write and polling options for [`crate::MemWal::remember_and_wait_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RememberWaitOptions {
    /// Write options (`namespace`, `idempotency_key`, `dedupe`).
    pub remember: RememberOptions,
    /// Polling cadence and deadline.
    pub wait: WaitOptions,
}

impl RememberWaitOptions {
    /// Creates default `remember_and_wait` options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the target namespace.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.remember.namespace = Some(namespace.into());
        self
    }

    /// Sets an explicit idempotency key.
    #[must_use]
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.remember.idempotency_key = Some(key.into());
        self
    }

    /// Enables content-hash deduplication.
    #[must_use]
    pub const fn dedupe_by_content(mut self) -> Self {
        self.remember.dedupe = DedupeMode::ContentHash;
        self
    }

    /// Overrides the polling cadence and deadline.
    #[must_use]
    pub const fn with_wait(mut self, wait: WaitOptions) -> Self {
        self.wait = wait;
        self
    }
}

/// Result ordering mode for `/api/recall`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RecallSort {
    /// Pure semantic cosine similarity order (default).
    #[default]
    Relevance,
    /// Over-fetches semantic candidates on the server and orders them by `created_at` descending.
    Recent,
}

impl fmt::Display for RecallSort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relevance => f.write_str("relevance"),
            Self::Recent => f.write_str("recent"),
        }
    }
}

impl FromStr for RecallSort {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "relevance" => Ok(Self::Relevance),
            "recent" => Ok(Self::Recent),
            other => Err(Error::InvalidArgument(format!(
                "unknown recall sort {other:?}; expected \"relevance\" or \"recent\""
            ))),
        }
    }
}

/// Optional composite-scoring weights applied by the relayer ranker on `recall`,
/// `recall_manual`, and `ask`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ScoringWeights {
    /// Weight applied to `1.0 - cosine_distance` (`1.0` default).
    pub semantic: f64,
    /// Weight applied to exponential recency decay (`0.0` default).
    pub recency: f64,
    /// Half-life in days for the recency decay term (`30.0` default).
    pub recency_half_life_days: f64,
    /// Weight applied to extracted fact importance (`0.0` default).
    pub importance: f64,
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
    const MIN_HALF_LIFE_DAYS: f64 = 1e-6;

    /// Validates that every weight is finite and within relayer bounds before signing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any weight is `NaN`/`Infinity`, outside
    /// `[0.0, 100.0]`, or uses a near-zero `recency_half_life_days` when `recency > 0`.
    pub fn validate(&self) -> Result<()> {
        for (name, val) in [
            ("semantic", self.semantic),
            ("recency", self.recency),
            ("recency_half_life_days", self.recency_half_life_days),
            ("importance", self.importance),
        ] {
            if !val.is_finite() {
                return Err(Error::InvalidArgument(format!(
                    "scoring_weights.{name} must be a finite number, got {val}"
                )));
            }
        }
        for (name, val) in [
            ("semantic", self.semantic),
            ("recency", self.recency),
            ("importance", self.importance),
        ] {
            if !(0.0..=100.0).contains(&val) {
                return Err(Error::InvalidArgument(format!(
                    "scoring_weights.{name} must be in [0.0, 100.0], got {val}"
                )));
            }
        }
        if self.recency > 0.0 && self.recency_half_life_days < Self::MIN_HALF_LIFE_DAYS {
            return Err(Error::InvalidArgument(format!(
                "scoring_weights.recency_half_life_days must be >= {} when recency > 0, got {}",
                Self::MIN_HALF_LIFE_DAYS,
                self.recency_half_life_days
            )));
        }
        Ok(())
    }
}

/// Self-describing input parameters for [`crate::MemWal::recall`].
///
/// Accepts plain `&str` or `String` queries via [`From`], or fluent builder
/// overrides via [`RecallParams::new`].
#[derive(Debug, Clone, PartialEq)]
pub struct RecallParams {
    /// Natural-language search query.
    pub query: String,
    /// Maximum results requested from the relayer (`10` default, capped at `100` server-side).
    pub limit: usize,
    /// Optional namespace override.
    pub namespace: Option<String>,
    /// Client-side relevance threshold; drops hits with `distance >= max_distance`.
    pub max_distance: Option<f64>,
    /// Optional composite ranker weights.
    pub scoring_weights: Option<ScoringWeights>,
    /// Optional server-side sort mode (`Relevance` or `Recent`).
    pub sort: Option<RecallSort>,
    /// Optional client-side token budget for the returned `results` payload.
    pub max_tokens: Option<usize>,
    /// Truncation strategy used when `max_tokens` is set.
    pub truncation_strategy: TruncationStrategy,
    /// Optional per-call deadline overriding the client `recall_timeout`.
    pub timeout: Option<Duration>,
}

impl RecallParams {
    /// Creates `RecallParams` for `query` with `limit = 10`.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            limit: 10,
            namespace: None,
            max_distance: None,
            scoring_weights: None,
            sort: None,
            max_tokens: None,
            truncation_strategy: TruncationStrategy::HighRelevanceOnly,
            timeout: None,
        }
    }

    /// Sets the maximum number of memories to recall (`>= 1`).
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Overrides the namespace for this query.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Drops recalled memories whose cosine distance is `>= max_distance`.
    #[must_use]
    pub const fn with_max_distance(mut self, max_distance: f64) -> Self {
        self.max_distance = Some(max_distance);
        self
    }

    /// Applies composite ranker weights on the server.
    #[must_use]
    pub const fn with_scoring_weights(mut self, weights: ScoringWeights) -> Self {
        self.scoring_weights = Some(weights);
        self
    }

    /// Selects server-side result ordering (`Relevance` or `Recent`).
    #[must_use]
    pub const fn with_sort(mut self, sort: RecallSort) -> Self {
        self.sort = Some(sort);
        self
    }

    /// Bounds the returned recall payload to at most `max_tokens` estimated tokens.
    #[must_use]
    pub const fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Sets the client-side truncation strategy used alongside `max_tokens`.
    #[must_use]
    pub const fn with_truncation_strategy(mut self, strategy: TruncationStrategy) -> Self {
        self.truncation_strategy = strategy;
        self
    }

    /// Overrides the HTTP request deadline for this `recall` call.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl From<&str> for RecallParams {
    fn from(query: &str) -> Self {
        Self::new(query)
    }
}

impl From<String> for RecallParams {
    fn from(query: String) -> Self {
        Self::new(query)
    }
}

/// One memory item in a batched [`crate::MemWal::remember_bulk`] request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RememberBulkItem {
    /// Plaintext memory content.
    pub text: String,
    /// Optional per-item namespace override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl RememberBulkItem {
    /// Creates a bulk item using the client's default namespace.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            namespace: None,
        }
    }

    /// Overrides the namespace for this single item.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }
}

impl From<&str> for RememberBulkItem {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

impl From<String> for RememberBulkItem {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

/// Options for [`crate::MemWal::remember_bulk_with`] and [`crate::MemWal::remember_bulk_and_wait`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberBulkOptions {
    /// Optional caller-supplied idempotency key for the batch.
    pub idempotency_key: Option<String>,
    /// Polling cadence and timeout budget (`120s` default).
    pub wait: WaitOptions,
}

impl Default for RememberBulkOptions {
    fn default() -> Self {
        Self {
            idempotency_key: None,
            wait: WaitOptions::default_bulk(),
        }
    }
}

impl RememberBulkOptions {
    /// Creates default bulk options (`1500ms` poll interval, `120s` timeout).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets an explicit idempotency key for the batch.
    #[must_use]
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Overrides the polling cadence and deadline.
    #[must_use]
    pub const fn with_wait(mut self, wait: WaitOptions) -> Self {
        self.wait = wait;
        self
    }
}

/// Options for [`crate::MemWal::analyze`] and [`crate::MemWal::analyze_and_wait`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalyzeOptions {
    /// Optional namespace override.
    pub namespace: Option<String>,
    /// Optional RFC-3339 timestamp with explicit timezone (`Z` or UTC offset)
    /// anchoring when the conversation took place.
    pub occurred_at: Option<String>,
}

impl AnalyzeOptions {
    /// Creates empty `analyze` options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the namespace for extracted facts.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Sets the RFC-3339 conversation timestamp anchor (`e.g. "2026-05-25T17:50:00Z"`).
    #[must_use]
    pub fn with_occurred_at(mut self, occurred_at: impl Into<String>) -> Self {
        self.occurred_at = Some(occurred_at.into());
        self
    }
}

/// Options for [`crate::MemWal::ask`].
#[derive(Debug, Clone, PartialEq)]
pub struct AskOptions {
    /// Maximum recalled memories injected into the LLM prompt (`5` default).
    pub limit: usize,
    /// Optional namespace override.
    pub namespace: Option<String>,
    /// Optional composite ranker weights for context retrieval.
    pub scoring_weights: Option<ScoringWeights>,
}

impl Default for AskOptions {
    fn default() -> Self {
        Self {
            limit: 5,
            namespace: None,
            scoring_weights: None,
        }
    }
}

impl AskOptions {
    /// Creates default `ask` options (`limit = 5`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of recalled memories (`>= 1`).
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Overrides the namespace searched for context.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Applies composite scoring weights to the context search.
    #[must_use]
    pub const fn with_scoring_weights(mut self, weights: ScoringWeights) -> Self {
        self.scoring_weights = Some(weights);
        self
    }
}

/// Input for [`crate::MemWal::remember_manual`], where encryption and embedding
/// happen client-side and no `x-seal-session` header is sent.
#[derive(Debug, Clone, PartialEq)]
pub struct RememberManualOptions {
    /// Base64-encoded SEAL-encrypted ciphertext bytes.
    pub encrypted_data: String,
    /// Pre-computed finite `f32` embedding vector.
    pub vector: Vec<f32>,
    /// Optional namespace override.
    pub namespace: Option<String>,
}

impl RememberManualOptions {
    /// Creates manual remember input from Base64 SEAL ciphertext and an embedding vector.
    #[must_use]
    pub fn new(encrypted_data: impl Into<String>, vector: Vec<f32>) -> Self {
        Self {
            encrypted_data: encrypted_data.into(),
            vector,
            namespace: None,
        }
    }

    /// Overrides the namespace for this manual entry.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }
}

/// Input for [`crate::MemWal::recall_manual`], returning matching `blob_id` and
/// cosine distance hits without transmitting any decrypt credential.
#[derive(Debug, Clone, PartialEq)]
pub struct RecallManualOptions {
    /// Pre-computed finite `f32` query embedding vector.
    pub vector: Vec<f32>,
    /// Maximum hits to return (`10` default).
    pub limit: usize,
    /// Optional namespace override.
    pub namespace: Option<String>,
    /// Optional composite ranker weights.
    pub scoring_weights: Option<ScoringWeights>,
}

impl RecallManualOptions {
    /// Creates manual recall options with `limit = 10`.
    #[must_use]
    pub const fn new(vector: Vec<f32>) -> Self {
        Self {
            vector,
            limit: 10,
            namespace: None,
            scoring_weights: None,
        }
    }

    /// Sets the maximum hit count (`>= 1`).
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }

    /// Overrides the namespace searched.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Applies composite ranker weights on the server.
    #[must_use]
    pub const fn with_scoring_weights(mut self, weights: ScoringWeights) -> Self {
        self.scoring_weights = Some(weights);
        self
    }
}

/// Pagination options for [`crate::MemWal::list_namespaces`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListNamespacesOptions {
    /// Keyset cursor (`next_cursor` from a previous page).
    pub cursor: Option<String>,
    /// Page size (`>= 1`; server defaults to `100` and clamps to `500`).
    pub limit: Option<usize>,
}

impl ListNamespacesOptions {
    /// Creates empty pagination options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resumes pagination after `cursor`.
    #[must_use]
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Sets the requested page size (`>= 1`).
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Pagination and filtering options for [`crate::MemWal::list_memories`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListMemoriesOptions {
    /// Keyset cursor (`next_cursor` from a previous page).
    pub cursor: Option<String>,
    /// Page size before client-side namespace filtering (`>= 1`).
    pub limit: Option<usize>,
    /// Optional exact-match namespace filter applied client-side while preserving `has_more`.
    pub namespace: Option<String>,
}

impl ListMemoriesOptions {
    /// Creates empty pagination options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resumes pagination after `cursor`.
    #[must_use]
    pub fn with_cursor(mut self, cursor: impl Into<String>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Sets the requested page size (`>= 1`).
    #[must_use]
    pub const fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Filters returned `memories` and `deleted` tombstones to a single namespace.
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }
}

// ============================================================
// Response Types
// ============================================================

/// `202 Accepted` response from [`crate::MemWal::remember`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberAccepted {
    /// Background job identifier used with [`crate::MemWal::wait_for_remember_job`].
    pub job_id: String,
    /// Initial job state (`"pending"` or `"running"`).
    pub status: String,
}

/// Snapshot of a background `remember` job from [`crate::MemWal::remember_status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberJobStatus {
    /// Job identifier.
    pub job_id: String,
    /// Lifecycle state: `"pending"`, `"running"`, `"uploaded"`, `"done"`, `"failed"`, or `"not_found"`.
    pub status: String,
    /// Account owner Sui address when the job exists.
    #[serde(default)]
    pub owner: Option<String>,
    /// Target namespace when the job exists.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Assigned Walrus `blob_id` once uploaded.
    #[serde(default)]
    pub blob_id: Option<String>,
    /// Sanitized failure message when `status == "failed"`.
    #[serde(default)]
    pub error: Option<String>,
}

/// Terminal result of [`crate::MemWal::remember_and_wait`] or [`crate::MemWal::wait_for_remember_job`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberResult {
    /// Stable server vector row ID (equal to `job_id`).
    pub id: String,
    /// Async job ID that settled.
    pub job_id: String,
    /// Walrus blob identifier storing the SEAL ciphertext.
    pub blob_id: String,
    /// Sui address of the `MemWalAccount` owner.
    pub owner: String,
    /// Namespace under which the memory was indexed.
    pub namespace: String,
}

/// A single decrypted memory hit returned by [`crate::MemWal::recall`] or [`crate::MemWal::ask`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecallMemory {
    /// Walrus blob identifier.
    pub blob_id: String,
    /// Decrypted plaintext memory content.
    pub text: String,
    /// Cosine distance (`0.0` = identical, lower = closer).
    pub distance: f64,
    /// Composite ranker score when non-default `scoring_weights` ran on the server.
    #[serde(default)]
    pub score: Option<f64>,
    /// RFC-3339 write timestamp recorded when the memory was indexed.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Result returned by [`crate::MemWal::recall`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecallResult {
    /// Decrypted memories ordered by the requested sort or ranker policy.
    pub results: Vec<RecallMemory>,
    /// Total vector hits matched on the relayer before client-side filters.
    pub total: usize,
    /// Count of candidate hits omitted because Walrus download or SEAL decryption failed.
    #[serde(default)]
    pub dropped_count: usize,
    /// Present when client-side `max_tokens` budgeting was applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<RecallTokenMeta>,
}

/// `202 Accepted` response from [`crate::MemWal::remember_bulk`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberBulkAccepted {
    /// Job identifiers aligned positionally with the submitted `items`.
    pub job_ids: Vec<String>,
    /// Number of accepted items.
    pub total: usize,
    /// Initial batch status.
    pub status: String,
}

/// Single job entry inside [`RememberBulkStatusResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberBulkStatusItem {
    /// Job identifier.
    pub job_id: String,
    /// Lifecycle state (`"pending"`, `"running"`, `"uploaded"`, `"done"`, `"failed"`, `"not_found"`).
    pub status: String,
    /// Stored namespace when the job row exists.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Walrus `blob_id` once uploaded.
    #[serde(default)]
    pub blob_id: Option<String>,
    /// Sanitized error when `status == "failed"`.
    #[serde(default)]
    pub error: Option<String>,
}

/// Response from [`crate::MemWal::remember_bulk_status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberBulkStatusResult {
    /// Per-job status snapshots.
    pub results: Vec<RememberBulkStatusItem>,
}

/// Settled per-item outcome inside [`RememberBulkResult`] and [`AnalyzeWaitResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberBulkItemResult {
    /// Job identifier.
    pub id: String,
    /// Walrus `blob_id` (`""` when `status != "done"`).
    pub blob_id: String,
    /// Terminal outcome: `"done"`, `"failed"`, or `"timeout"`.
    pub status: String,
    /// Target namespace for this item.
    pub namespace: String,
    /// Diagnostic message when `status != "done"`.
    #[serde(default)]
    pub error: Option<String>,
}

/// Aggregate result from [`crate::MemWal::remember_bulk_and_wait`] or
/// [`crate::MemWal::wait_for_remember_jobs`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberBulkResult {
    /// Per-item outcomes in input order.
    pub results: Vec<RememberBulkItemResult>,
    /// Total items tracked (`succeeded + failed + timed_out == total`).
    pub total: usize,
    /// Count of items with `status == "done"`.
    pub succeeded: usize,
    /// Count of items with `status == "failed"`.
    pub failed: usize,
    /// Count of items with `status == "timeout"`.
    pub timed_out: usize,
}

/// Response from [`crate::MemWal::forget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ForgetResult {
    /// Number of vector index rows deleted for `namespace`.
    pub deleted: u64,
    /// Forgotten namespace name.
    pub namespace: String,
    /// Authenticated owner Sui address.
    pub owner: String,
}

/// Response from [`crate::MemWal::embed`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct EmbedResult {
    /// Embedding vector produced by the relayer embedding model.
    pub vector: Vec<f32>,
}

/// One extracted fact accepted for background storage by [`crate::MemWal::analyze`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AnalyzedFact {
    /// Extracted atomic fact text.
    pub text: String,
    /// Stable vector row / job identifier.
    #[serde(default)]
    pub id: String,
    /// Background polling identifier when returned separately.
    #[serde(default)]
    pub job_id: Option<String>,
    /// Walrus `blob_id` when already available synchronously (e.g. benchmark mode).
    #[serde(default)]
    pub blob_id: Option<String>,
}

/// Response from [`crate::MemWal::analyze`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AnalyzeResult {
    /// Background job IDs for each extracted fact.
    #[serde(default)]
    pub job_ids: Vec<String>,
    /// Extracted facts accepted for storage.
    #[serde(default)]
    pub facts: Vec<AnalyzedFact>,
    /// Number of extracted facts.
    #[serde(default)]
    pub fact_count: usize,
    /// Initial batch status (`"pending"`).
    #[serde(default)]
    pub status: String,
    /// Authenticated owner Sui address.
    #[serde(default)]
    pub owner: String,
}

/// Combined extraction and persistence result from [`crate::MemWal::analyze_and_wait`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AnalyzeWaitResult {
    /// Settled per-job outcomes in fact order.
    pub results: Vec<RememberBulkItemResult>,
    /// Total background jobs tracked.
    pub total: usize,
    /// Count of jobs that reached `"done"`.
    pub succeeded: usize,
    /// Count of jobs that reached `"failed"`.
    pub failed: usize,
    /// Count of jobs that reached `"timeout"`.
    pub timed_out: usize,
    /// Extracted facts returned by `/api/analyze`.
    pub facts: Vec<AnalyzedFact>,
    /// Authenticated owner Sui address.
    pub owner: String,
}

/// Response from [`crate::MemWal::ask`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AskResult {
    /// LLM-generated answer grounded in recalled memories.
    pub answer: String,
    /// Number of memories injected into the prompt.
    pub memories_used: usize,
    /// Recalled memories used as grounding context.
    #[serde(default)]
    pub memories: Vec<RecallMemory>,
}

/// Response from [`crate::MemWal::restore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RestoreResult {
    /// Blobs downloaded, SEAL-decrypted, re-embedded, and inserted during this call.
    pub restored: usize,
    /// On-chain blobs already present in the local vector index.
    pub skipped: usize,
    /// Permanent decrypt or UTF-8 decode failures encountered on this page.
    #[serde(default)]
    pub failed: usize,
    /// Total on-chain blobs discovered for `(owner, namespace)` before `limit`.
    pub total: usize,
    /// Restored namespace name.
    pub namespace: String,
    /// Authenticated owner Sui address.
    pub owner: String,
    /// `true` when additional blobs remain beyond `limit` or transient errors occurred.
    #[serde(default)]
    pub truncated: bool,
}

/// Summary of one namespace inside [`NamespacesPage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NamespaceSummary {
    /// Namespace identifier.
    pub id: String,
    /// Exact namespace string passed to `remember` / `recall`.
    pub name: String,
    /// Count of indexed memories in this namespace.
    pub memory_count: u64,
    /// Encrypted storage bytes tracked for this namespace.
    pub storage_used: u64,
    /// RFC-3339 `MAX(updated_at)` watermark across memories in this namespace.
    pub updated_at: String,
}

/// Cursor-paginated response from [`crate::MemWal::list_namespaces`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NamespacesPage {
    /// Namespace summaries on this page.
    pub namespaces: Vec<NamespaceSummary>,
    /// Opaque keyset watermark to pass as `cursor` on the next call.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// Authoritative signal indicating more pages exist on the server.
    pub has_more: bool,
    /// Monotonic server snapshot version.
    pub snapshot_version: u64,
}

/// Metadata summary of one indexed memory inside [`MemoriesPage`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemorySummary {
    /// Vector row / memory identifier.
    pub memory_id: String,
    /// Namespace string under which this memory lives.
    pub namespace_id: String,
    /// Walrus blob identifier.
    pub blob_id: String,
    /// RFC-3339 creation timestamp.
    pub created_at: String,
    /// RFC-3339 last-update timestamp used for keyset pagination.
    pub updated_at: String,
    /// Encrypted blob size in bytes.
    pub size: u64,
    /// Optional originating agent identifier.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Optional Sui Move package ID associated with the ciphertext.
    #[serde(default)]
    pub package_id: Option<String>,
    /// Indexing status string.
    pub status: String,
    /// Optional Walrus storage expiration epoch.
    #[serde(default)]
    pub end_epoch: Option<u64>,
    /// Optional RFC-3339 expiration timestamp.
    #[serde(default)]
    pub expires_at: Option<String>,
    /// Optional extracted fact importance in `[0.0, 1.0]`.
    #[serde(default)]
    pub importance: Option<f64>,
}

/// Tombstone entry for a memory deleted since the caller's pagination cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeletedMemorySummary {
    /// Deleted memory identifier.
    pub memory_id: String,
    /// Namespace from which the memory was removed.
    pub namespace_id: String,
    /// RFC-3339 deletion timestamp.
    pub deleted_at: String,
}

/// Cursor-paginated metadata inventory from [`crate::MemWal::list_memories`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MemoriesPage {
    /// Live memory metadata entries on this page.
    pub memories: Vec<MemorySummary>,
    /// Opaque keyset watermark to pass as `cursor` on the next call.
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// Authoritative pagination continuation flag.
    pub has_more: bool,
    /// Monotonic server snapshot version.
    pub snapshot_version: u64,
    /// Tombstones recorded since `cursor`.
    #[serde(default)]
    pub deleted: Vec<DeletedMemorySummary>,
    /// `true` when `cursor` predates tombstone retention and a fresh walk is required.
    #[serde(default)]
    pub must_resync: bool,
}

/// Response from [`crate::MemWal::remember_manual`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RememberManualResult {
    /// Vector index row identifier.
    pub id: String,
    /// Uploaded Walrus `blob_id`.
    pub blob_id: String,
    /// Authenticated owner Sui address.
    pub owner: String,
    /// Target namespace.
    pub namespace: String,
}

/// Raw vector search hit returned by [`crate::MemWal::recall_manual`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecallManualHit {
    /// Walrus `blob_id` to download and SEAL-decrypt client-side.
    pub blob_id: String,
    /// Cosine distance (`0.0` = identical).
    pub distance: f64,
    /// Optional RFC-3339 insertion timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Optional fact importance score.
    #[serde(default)]
    pub importance: Option<f32>,
}

/// Response from [`crate::MemWal::recall_manual`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RecallManualResult {
    /// Matching encrypted blob hits.
    pub results: Vec<RecallManualHit>,
    /// Total hits returned.
    pub total: usize,
}

/// Authenticated identity metadata returned by [`crate::MemWal::whoami`] (`GET /api/whoami`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct WhoamiResult {
    /// On-chain `MemWalAccount` Sui object ID.
    pub account_id: String,
    /// Account owner Sui address.
    pub owner: String,
    /// First-published Move package ID configured on the relayer.
    pub package_id: String,
}

/// Minimum supported first-party client versions advertised by `/version`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MinSupportedSdk {
    /// Minimum TypeScript SDK semver.
    #[serde(default)]
    pub typescript: String,
    /// Minimum Python SDK semver.
    #[serde(default)]
    pub python: String,
    /// Minimum MCP package semver.
    #[serde(default)]
    pub mcp: String,
    /// Optional minimum Rust SDK semver when advertised by newer relayers.
    #[serde(default)]
    pub rust: Option<String>,
}

/// Public API deprecation notice advertised by `/version` and `/health`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DeprecationNotice {
    /// Deprecated surface identifier (for example `"header:x-delegate-key"`).
    pub surface: String,
    /// API version in which deprecation started.
    pub deprecated_since: String,
    /// Planned removal API version.
    pub removal_api_version: String,
    /// Migration instructions.
    pub guidance: String,
}

/// Build provenance metadata advertised by `/version` and `/health`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BuildMetadata {
    /// Optional Git commit SHA of the running relayer binary.
    #[serde(default)]
    pub commit: Option<String>,
    /// Optional build timestamp string.
    #[serde(default)]
    pub build_timestamp: Option<String>,
}

/// Prompt version identifiers surfaced on `/health`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PromptVersions {
    /// Fact-extraction prompt version.
    pub extract: String,
    /// Question-answering prompt version.
    pub ask: String,
}

/// Runtime compatibility contract returned by [`crate::MemWal::compatibility`] (`GET /version`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct VersionInfo {
    /// Relayer binary Cargo package version.
    #[serde(default)]
    pub relayer_version: String,
    /// Semantic relayer HTTP API contract version (`"1.x.y"`).
    #[serde(default)]
    pub api_version: String,
    /// Minimum supported SDK versions.
    #[serde(default)]
    pub min_supported_sdk: MinSupportedSdk,
    /// Enabled capability flags on the relayer.
    #[serde(default)]
    pub feature_flags: BTreeMap<String, bool>,
    /// Active deprecation notices.
    #[serde(default)]
    pub deprecations: Vec<DeprecationNotice>,
    /// Relayer build metadata.
    #[serde(default)]
    pub build: BuildMetadata,
}

/// Response from [`crate::MemWal::health`] (`GET /health`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HealthResult {
    /// Process liveness string (`"ok"`).
    pub status: String,
    /// Relayer package version string.
    pub version: String,
    /// Optional runtime mode (`"production"` or `"benchmark"`).
    #[serde(default)]
    pub mode: Option<String>,
    /// Optional flag indicating whether sidecar and database write probes succeeded.
    #[serde(default)]
    pub write_ready: Option<bool>,
    /// Optional write admission state (`"ok"`, `"degraded"`, or `"paused"`).
    #[serde(default)]
    pub writes: Option<String>,
    /// Optional prompt version pins.
    #[serde(default)]
    pub prompt_versions: Option<PromptVersions>,
    /// Optional compatibility metadata flattened onto `/health` by modern relayers.
    #[serde(rename = "apiVersion", default)]
    pub api_version: Option<String>,
    /// Optional relayer version alias from flattened compatibility metadata.
    #[serde(rename = "relayerVersion", default)]
    pub relayer_version: Option<String>,
}

// ============================================================
// Shared Input Validators
// ============================================================

pub(crate) fn is_blank_or_zero_width(s: &str) -> bool {
    s.chars().all(|ch| {
        ch.is_whitespace()
            || matches!(
                ch,
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
            )
    })
}

pub(crate) fn validate_non_blank(text: &str, field_name: &str) -> Result<()> {
    if is_blank_or_zero_width(text) {
        return Err(Error::InvalidArgument(format!(
            "{field_name} cannot be empty or whitespace-only"
        )));
    }
    Ok(())
}

pub(crate) fn validate_namespace(namespace: &str) -> Result<()> {
    if namespace.is_empty() {
        return Err(Error::InvalidArgument(
            "namespace cannot be empty".to_owned(),
        ));
    }
    if namespace.len() > MAX_NAMESPACE_BYTES {
        return Err(Error::InvalidArgument(format!(
            "namespace exceeds maximum length of {MAX_NAMESPACE_BYTES} bytes"
        )));
    }
    if namespace.contains('\0') {
        return Err(Error::InvalidArgument(
            "namespace must not contain NUL bytes".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_positive_limit(limit: usize, field_name: &str) -> Result<()> {
    if limit == 0 {
        return Err(Error::InvalidArgument(format!(
            "{field_name} must be at least 1, got 0"
        )));
    }
    Ok(())
}

pub(crate) fn validate_max_distance(max_distance: Option<f64>) -> Result<()> {
    if let Some(d) = max_distance
        && (!d.is_finite() || d < 0.0)
    {
        return Err(Error::InvalidArgument(format!(
            "max_distance must be a non-negative finite number, got {d}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_vector(vector: &[f32]) -> Result<()> {
    if vector.is_empty() {
        return Err(Error::InvalidArgument(
            "vector must not be empty".to_owned(),
        ));
    }
    if let Some(idx) = vector.iter().position(|v| !v.is_finite()) {
        return Err(Error::InvalidArgument(format!(
            "vector must contain only finite f32 values; non-finite component at index {idx}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_job_id(job_id: &str) -> bool {
    !job_id.is_empty()
        && job_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub(crate) fn normalize_occurred_at(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidArgument(
            "occurred_at cannot be empty".to_owned(),
        ));
    }
    let parsed: DateTime<Utc> = DateTime::parse_from_rfc3339(trimmed)
        .map_err(|err| {
            Error::InvalidArgument(format!(
                "occurred_at must be an RFC-3339 timestamp with explicit timezone offset or 'Z': {err}"
            ))
        })?
        .with_timezone(&Utc);
    Ok(parsed.to_rfc3339_opts(SecondsFormat::Millis, true))
}

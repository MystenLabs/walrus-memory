//! Deterministic in-memory test double (`MemWalMock`) for offline unit testing.
//!
//! Mirrors the TypeScript and Python `MemWalMock` helpers so Rust AI agents can
//! exercise `remember`, `recall`, `forget`, `list_namespaces`, `list_memories`,
//! and `destroy` flows without live Sui credentials or network sockets.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::Engine as _;
use chrono::Utc;
use sha2::{Digest as _, Sha256};

use crate::client::SDK_VERSION;
use crate::error::{Error, Result};
use crate::tokens::apply_token_budget;
use crate::types::{
    AnalyzeOptions, AnalyzeResult, AnalyzeWaitResult, AnalyzedFact, AskOptions, AskResult,
    BuildMetadata, DEFAULT_NAMESPACE, DedupeMode, DeletedMemorySummary, EmbedResult, ForgetResult,
    HealthResult, ListMemoriesOptions, ListNamespacesOptions, MAX_BULK_ITEMS, MemoriesPage,
    MemorySummary, MinSupportedSdk, NamespaceSummary, NamespacesPage, PromptVersions, RecallMemory,
    RecallParams, RecallResult, RecallSort, RememberAccepted, RememberBulkAccepted,
    RememberBulkItem, RememberBulkItemResult, RememberBulkOptions, RememberBulkResult,
    RememberBulkStatusItem, RememberBulkStatusResult, RememberJobStatus, RememberOptions,
    RememberResult, RememberWaitOptions, RestoreResult, VersionInfo, WaitOptions, WhoamiResult,
    is_blank_or_zero_width, normalize_occurred_at, validate_job_id, validate_max_distance,
    validate_namespace, validate_non_blank, validate_positive_limit,
};

#[derive(Debug, Clone)]
struct StoredEntry {
    id: String,
    blob_id: String,
    namespace: String,
    text: String,
    created_at: String,
    seq: u64,
}

#[derive(Debug, Default)]
struct MockState {
    next_seq: u64,
    entries: Vec<StoredEntry>,
    deleted: Vec<DeletedMemorySummary>,
}

#[derive(Debug)]
struct MockInner {
    owner: String,
    account_id: String,
    namespace: String,
    destroyed: AtomicBool,
    state: Mutex<MockState>,
}

/// Thread-safe, deterministic in-memory test double for [`crate::MemWal`].
///
/// # Examples
///
/// ```
/// # tokio_test_block();
/// # fn tokio_test_block() {
/// # let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
/// # rt.block_on(async {
/// use memwal::{MemWalMock, RecallParams};
///
/// let mock = MemWalMock::new();
/// let stored = mock.remember_and_wait("User prefers dark mode").await?;
/// assert!(!stored.blob_id.is_empty());
///
/// let recalled = mock.recall(RecallParams::new("dark mode").with_limit(3)).await?;
/// assert_eq!(recalled.results.len(), 1);
/// assert_eq!(recalled.results[0].text, "User prefers dark mode");
/// # Ok::<(), memwal::Error>(())
/// # }).unwrap();
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct MemWalMock(Arc<MockInner>);

impl Default for MemWalMock {
    fn default() -> Self {
        Self::new()
    }
}

impl MemWalMock {
    /// Creates an in-memory mock client using deterministic placeholder `owner` and `account_id`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_namespace(DEFAULT_NAMESPACE)
    }

    /// Creates an in-memory mock client scoped to `namespace`.
    #[must_use]
    pub fn with_namespace(namespace: impl Into<String>) -> Self {
        Self(Arc::new(MockInner {
            owner: "0x0000000000000000000000000000000000000000000000000000000000000001".to_owned(),
            account_id: "0x0000000000000000000000000000000000000000000000000000000000000002"
                .to_owned(),
            namespace: namespace.into(),
            destroyed: AtomicBool::new(false),
            state: Mutex::new(MockState::default()),
        }))
    }

    /// Wipes stored mock memories and marks the mock client destroyed.
    pub fn destroy(&self) {
        self.0.destroyed.store(true, Ordering::SeqCst);
        let mut guard = self.lock_state();
        guard.entries.clear();
        guard.deleted.clear();
    }

    /// Returns `true` if [`Self::destroy`] has been called.
    #[must_use]
    pub fn is_destroyed(&self) -> bool {
        self.0.destroyed.load(Ordering::SeqCst)
    }

    /// Returns the mock client's default namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.0.namespace
    }

    /// Returns the mock client's `account_id`.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.0.account_id
    }

    /// Stores `text` immediately in memory and returns an accepted job receipt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `text` is blank or [`Error::Destroyed`] if destroyed.
    pub async fn remember(&self, text: &str) -> Result<RememberAccepted> {
        self.remember_with(text, &RememberOptions::default()).await
    }

    /// Stores `text` with options in memory and returns an accepted job receipt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid input or [`Error::Destroyed`] if destroyed.
    pub async fn remember_with(
        &self,
        text: &str,
        opts: &RememberOptions,
    ) -> Result<RememberAccepted> {
        self.check_alive().await?;
        validate_non_blank(text, "text")?;
        let ns = self.resolve_ns(opts.namespace.as_deref())?;
        let entry = self.insert_entry(text, &ns, opts.dedupe);
        Ok(RememberAccepted {
            job_id: entry.id,
            status: "done".to_owned(),
        })
    }

    /// Stores `text` and returns the completed [`RememberResult`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `text` is blank or [`Error::Destroyed`] if destroyed.
    pub async fn remember_and_wait(&self, text: &str) -> Result<RememberResult> {
        self.remember_and_wait_with(text, &RememberWaitOptions::default())
            .await
    }

    /// Stores `text` with options and returns the completed [`RememberResult`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid input or [`Error::Destroyed`] if destroyed.
    pub async fn remember_and_wait_with(
        &self,
        text: &str,
        opts: &RememberWaitOptions,
    ) -> Result<RememberResult> {
        self.check_alive().await?;
        validate_non_blank(text, "text")?;
        let ns = self.resolve_ns(opts.remember.namespace.as_deref())?;
        let entry = self.insert_entry(text, &ns, opts.remember.dedupe);
        Ok(RememberResult {
            id: entry.id.clone(),
            job_id: entry.id,
            blob_id: entry.blob_id,
            owner: self.0.owner.clone(),
            namespace: entry.namespace,
        })
    }

    /// Looks up a previously stored mock job by `job_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] if destroyed.
    pub async fn remember_status(&self, job_id: &str) -> Result<RememberJobStatus> {
        self.check_alive().await?;
        if !validate_job_id(job_id) {
            return Ok(RememberJobStatus {
                job_id: job_id.to_owned(),
                status: "not_found".to_owned(),
                owner: None,
                namespace: None,
                blob_id: None,
                error: Some(format!("job {job_id} not found")),
            });
        }
        let guard = self.lock_state();
        if let Some(found) = guard.entries.iter().find(|e| e.id == job_id) {
            Ok(RememberJobStatus {
                job_id: found.id.clone(),
                status: "done".to_owned(),
                owner: Some(self.0.owner.clone()),
                namespace: Some(found.namespace.clone()),
                blob_id: Some(found.blob_id.clone()),
                error: None,
            })
        } else {
            Ok(RememberJobStatus {
                job_id: job_id.to_owned(),
                status: "not_found".to_owned(),
                owner: None,
                namespace: None,
                blob_id: None,
                error: Some(format!("job {job_id} not found")),
            })
        }
    }

    /// Resolves a mock job immediately or returns [`Error::JobNotFound`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::JobNotFound`] when `job_id` is unknown or [`Error::Destroyed`] if destroyed.
    pub async fn wait_for_remember_job(
        &self,
        job_id: &str,
        _opts: &WaitOptions,
    ) -> Result<RememberResult> {
        self.check_alive().await?;
        let guard = self.lock_state();
        let found = guard
            .entries
            .iter()
            .find(|e| e.id == job_id)
            .ok_or_else(|| Error::JobNotFound {
                job_id: job_id.to_owned(),
            })?;
        Ok(RememberResult {
            id: found.id.clone(),
            job_id: found.id.clone(),
            blob_id: found.blob_id.clone(),
            owner: self.0.owner.clone(),
            namespace: found.namespace.clone(),
        })
    }

    /// Stores up to [`MAX_BULK_ITEMS`] (`20`) items in memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `items` is empty, exceeds `20`, or has blank text.
    pub async fn remember_bulk(&self, items: &[RememberBulkItem]) -> Result<RememberBulkAccepted> {
        self.check_alive().await?;
        if items.is_empty() || items.len() > MAX_BULK_ITEMS {
            return Err(Error::InvalidArgument(format!(
                "items must contain between 1 and {MAX_BULK_ITEMS} entries"
            )));
        }
        let mut ids = Vec::with_capacity(items.len());
        for (idx, item) in items.iter().enumerate() {
            if is_blank_or_zero_width(&item.text) {
                return Err(Error::InvalidArgument(format!(
                    "items[{idx}].text cannot be empty"
                )));
            }
            let ns = self.resolve_ns(item.namespace.as_deref())?;
            let stored = self.insert_entry(&item.text, &ns, DedupeMode::RetryWindow);
            ids.push(stored.id);
        }
        Ok(RememberBulkAccepted {
            total: ids.len(),
            job_ids: ids,
            status: "done".to_owned(),
        })
    }

    /// Stores a batch of items and returns settled [`RememberBulkResult`] outcomes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid input or [`Error::Destroyed`] if destroyed.
    pub async fn remember_bulk_and_wait(
        &self,
        items: &[RememberBulkItem],
        opts: &RememberBulkOptions,
    ) -> Result<RememberBulkResult> {
        let accepted = self.remember_bulk(items).await?;
        let namespaces: Vec<String> = items
            .iter()
            .map(|i| {
                i.namespace
                    .clone()
                    .unwrap_or_else(|| self.0.namespace.clone())
            })
            .collect();
        self.wait_for_remember_jobs(&accepted.job_ids, &namespaces, &opts.wait)
            .await
    }

    /// Queries bulk status for `job_ids`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] if destroyed.
    pub async fn remember_bulk_status(
        &self,
        job_ids: &[String],
    ) -> Result<RememberBulkStatusResult> {
        self.check_alive().await?;
        let guard = self.lock_state();
        let results = job_ids
            .iter()
            .map(|jid| {
                if let Some(found) = guard.entries.iter().find(|e| &e.id == jid) {
                    RememberBulkStatusItem {
                        job_id: found.id.clone(),
                        status: "done".to_owned(),
                        namespace: Some(found.namespace.clone()),
                        blob_id: Some(found.blob_id.clone()),
                        error: None,
                    }
                } else {
                    RememberBulkStatusItem {
                        job_id: jid.clone(),
                        status: "not_found".to_owned(),
                        namespace: None,
                        blob_id: None,
                        error: None,
                    }
                }
            })
            .collect();
        Ok(RememberBulkStatusResult { results })
    }

    /// Settles `job_ids` in memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] if destroyed.
    pub async fn wait_for_remember_jobs(
        &self,
        job_ids: &[String],
        namespaces: &[String],
        _opts: &WaitOptions,
    ) -> Result<RememberBulkResult> {
        let status = self.remember_bulk_status(job_ids).await?;
        let mut results = Vec::with_capacity(job_ids.len());
        let mut succeeded = 0_usize;
        let mut failed = 0_usize;

        for (idx, item) in status.results.into_iter().enumerate() {
            let ns = namespaces
                .get(idx)
                .cloned()
                .or(item.namespace)
                .unwrap_or_else(|| self.0.namespace.clone());
            if item.status == "done" {
                succeeded += 1;
                results.push(RememberBulkItemResult {
                    id: item.job_id,
                    blob_id: item.blob_id.unwrap_or_default(),
                    status: "done".to_owned(),
                    namespace: ns,
                    error: None,
                });
            } else {
                failed += 1;
                results.push(RememberBulkItemResult {
                    id: item.job_id,
                    blob_id: String::new(),
                    status: "failed".to_owned(),
                    namespace: ns,
                    error: Some("job not found".to_owned()),
                });
            }
        }

        Ok(RememberBulkResult {
            total: results.len(),
            results,
            succeeded,
            failed,
            timed_out: 0,
        })
    }

    /// Searches stored mock memories using deterministic lexical overlap distance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid parameters or [`Error::Destroyed`] if destroyed.
    pub async fn recall(&self, params: impl Into<RecallParams>) -> Result<RecallResult> {
        self.check_alive().await?;
        let params = params.into();
        validate_non_blank(&params.query, "query")?;
        validate_positive_limit(params.limit, "limit")?;
        validate_max_distance(params.max_distance)?;
        if let Some(w) = &params.scoring_weights {
            w.validate()?;
        }
        let ns = self.resolve_ns(params.namespace.as_deref())?;

        let scored = {
            let guard = self.lock_state();
            let mut candidates: Vec<(u64, RecallMemory)> = guard
                .entries
                .iter()
                .filter(|e| e.namespace == ns)
                .map(|e| {
                    let dist = lexical_distance(&params.query, &e.text);
                    (
                        e.seq,
                        RecallMemory {
                            blob_id: e.blob_id.clone(),
                            text: e.text.clone(),
                            distance: dist,
                            score: None,
                            created_at: Some(e.created_at.clone()),
                        },
                    )
                })
                .collect();

            match params.sort.unwrap_or(RecallSort::Relevance) {
                RecallSort::Relevance => {
                    candidates.sort_by(|a, b| {
                        a.1.distance
                            .total_cmp(&b.1.distance)
                            .then_with(|| b.0.cmp(&a.0))
                    });
                }
                RecallSort::Recent => {
                    candidates.sort_by_key(|b| std::cmp::Reverse(b.0));
                }
            }

            candidates
                .into_iter()
                .take(params.limit)
                .map(|(_, m)| m)
                .collect::<Vec<_>>()
        };

        let total = scored.len();
        let mut filtered = scored;
        if let Some(max_dist) = params.max_distance {
            filtered.retain(|m| m.distance < max_dist);
        }

        let meta = if let Some(max_tokens) = params.max_tokens {
            let (budgeted, m) =
                apply_token_budget(filtered, max_tokens, params.truncation_strategy);
            filtered = budgeted;
            Some(m)
        } else {
            None
        };

        Ok(RecallResult {
            results: filtered,
            total,
            dropped_count: 0,
            meta,
        })
    }

    /// Deletes all mock memories in `namespace` (or the default namespace).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `namespace` is invalid or [`Error::Destroyed`] if destroyed.
    pub async fn forget(&self, namespace: Option<&str>) -> Result<ForgetResult> {
        self.check_alive().await?;
        let ns = self.resolve_ns(namespace)?;
        let now = Utc::now().to_rfc3339();
        let mut guard = self.lock_state();
        let before = guard.entries.len();
        let mut tombstones = Vec::new();
        guard.entries.retain(|e| {
            if e.namespace == ns {
                tombstones.push(DeletedMemorySummary {
                    memory_id: e.id.clone(),
                    namespace_id: e.namespace.clone(),
                    deleted_at: now.clone(),
                });
                false
            } else {
                true
            }
        });
        guard.deleted.extend(tombstones);
        let deleted = u64::try_from(before - guard.entries.len()).unwrap_or(0);
        Ok(ForgetResult {
            deleted,
            namespace: ns,
            owner: self.0.owner.clone(),
        })
    }

    /// Generates a deterministic `64`-dimensional unit vector from `text`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `text` is blank or [`Error::Destroyed`] if destroyed.
    pub async fn embed(&self, text: &str) -> Result<EmbedResult> {
        self.check_alive().await?;
        validate_non_blank(text, "text")?;
        let digest = Sha256::digest(text.as_bytes());
        let vector = digest
            .iter()
            .map(|&b| (f32::from(b) / 127.5) - 1.0)
            .collect();
        Ok(EmbedResult { vector })
    }

    /// Splits `text` into non-empty sentence facts and stores them in memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid input or [`Error::Destroyed`] if destroyed.
    pub async fn analyze(&self, text: &str, opts: &AnalyzeOptions) -> Result<AnalyzeResult> {
        self.check_alive().await?;
        validate_non_blank(text, "text")?;
        let ns = self.resolve_ns(opts.namespace.as_deref())?;
        if let Some(ts) = &opts.occurred_at {
            let _ = normalize_occurred_at(ts)?;
        }

        let mut job_ids = Vec::new();
        let mut facts = Vec::new();
        for seg in text
            .split(['.', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let entry = self.insert_entry(seg, &ns, DedupeMode::RetryWindow);
            job_ids.push(entry.id.clone());
            facts.push(AnalyzedFact {
                text: seg.to_owned(),
                id: entry.id.clone(),
                job_id: Some(entry.id),
                blob_id: Some(entry.blob_id),
            });
        }

        Ok(AnalyzeResult {
            fact_count: facts.len(),
            job_ids,
            facts,
            status: "done".to_owned(),
            owner: self.0.owner.clone(),
        })
    }

    /// Extracts facts from `text` and returns settled outcomes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid input or [`Error::Destroyed`] if destroyed.
    pub async fn analyze_and_wait(
        &self,
        text: &str,
        opts: &AnalyzeOptions,
        wait: &WaitOptions,
    ) -> Result<AnalyzeWaitResult> {
        let ns = self.resolve_ns(opts.namespace.as_deref())?;
        let accepted = self.analyze(text, opts).await?;
        let namespaces = vec![ns; accepted.job_ids.len()];
        let settled = self
            .wait_for_remember_jobs(&accepted.job_ids, &namespaces, wait)
            .await?;
        Ok(AnalyzeWaitResult {
            results: settled.results,
            total: settled.total,
            succeeded: settled.succeeded,
            failed: settled.failed,
            timed_out: settled.timed_out,
            facts: accepted.facts,
            owner: accepted.owner,
        })
    }

    /// Synthesizes a deterministic mock answer grounded in recalled memories.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid input or [`Error::Destroyed`] if destroyed.
    pub async fn ask(&self, question: &str, opts: &AskOptions) -> Result<AskResult> {
        validate_non_blank(question, "question")?;
        validate_positive_limit(opts.limit, "limit")?;
        let mut recall_params = RecallParams::new(question).with_limit(opts.limit);
        if let Some(ns) = &opts.namespace {
            recall_params = recall_params.with_namespace(ns.clone());
        }
        if let Some(w) = opts.scoring_weights {
            recall_params = recall_params.with_scoring_weights(w);
        }
        let recalled = self.recall(recall_params).await?;
        let answer = if recalled.results.is_empty() {
            "No matching memories found.".to_owned()
        } else {
            recalled
                .results
                .iter()
                .map(|m| m.text.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        };
        Ok(AskResult {
            memories_used: recalled.results.len(),
            memories: recalled.results,
            answer,
        })
    }

    /// Returns a no-op [`RestoreResult`] counting already-indexed memories in `namespace`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid input or [`Error::Destroyed`] if destroyed.
    pub async fn restore(&self, namespace: &str, limit: usize) -> Result<RestoreResult> {
        self.check_alive().await?;
        validate_namespace(namespace)?;
        validate_positive_limit(limit, "limit")?;
        let guard = self.lock_state();
        let count = guard
            .entries
            .iter()
            .filter(|e| e.namespace == namespace)
            .count();
        Ok(RestoreResult {
            restored: 0,
            skipped: count,
            failed: 0,
            total: count,
            namespace: namespace.to_owned(),
            owner: self.0.owner.clone(),
            truncated: false,
        })
    }

    /// Lists namespaces held in memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `opts.limit == Some(0)` or [`Error::Destroyed`] if destroyed.
    pub async fn list_namespaces(&self, opts: &ListNamespacesOptions) -> Result<NamespacesPage> {
        self.check_alive().await?;
        if let Some(limit) = opts.limit {
            validate_positive_limit(limit, "limit")?;
        }
        let guard = self.lock_state();
        let mut grouped: BTreeMap<String, (u64, u64, String)> = BTreeMap::new();
        for entry in &guard.entries {
            let slot = grouped
                .entry(entry.namespace.clone())
                .or_insert_with(|| (0, 0, entry.created_at.clone()));
            slot.0 += 1;
            slot.1 += u64::try_from(entry.text.len()).unwrap_or(u64::MAX);
            if entry.created_at > slot.2 {
                slot.2.clone_from(&entry.created_at);
            }
        }

        let all_namespaces: Vec<NamespaceSummary> = grouped
            .into_iter()
            .map(|(name, (count, bytes, updated_at))| NamespaceSummary {
                id: name.clone(),
                name,
                memory_count: count,
                storage_used: bytes,
                updated_at,
            })
            .collect();

        let remaining = if let Some(cursor) = &opts.cursor {
            filter_namespaces_by_cursor(&all_namespaces, cursor)
        } else {
            all_namespaces
        };

        let limit = opts.limit.unwrap_or(100);
        let has_more = remaining.len() > limit;
        let namespaces: Vec<NamespaceSummary> = remaining.into_iter().take(limit).collect();
        let next_cursor = namespaces.last().map(encode_mock_namespace_cursor);
        Ok(NamespacesPage {
            namespaces,
            next_cursor,
            has_more,
            snapshot_version: guard.next_seq,
        })
    }

    /// Lists memory metadata entries held in memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid options or [`Error::Destroyed`] if destroyed.
    pub async fn list_memories(&self, opts: &ListMemoriesOptions) -> Result<MemoriesPage> {
        self.check_alive().await?;
        if let Some(limit) = opts.limit {
            validate_positive_limit(limit, "limit")?;
        }
        if let Some(ns) = &opts.namespace {
            validate_namespace(ns)?;
        }
        let guard = self.lock_state();
        let all_memories: Vec<MemorySummary> = guard
            .entries
            .iter()
            .map(|e| MemorySummary {
                memory_id: e.id.clone(),
                namespace_id: e.namespace.clone(),
                blob_id: e.blob_id.clone(),
                created_at: e.created_at.clone(),
                updated_at: e.created_at.clone(),
                size: u64::try_from(e.text.len()).unwrap_or(u64::MAX),
                agent_id: None,
                package_id: None,
                status: "indexed".to_owned(),
                end_epoch: None,
                expires_at: None,
                importance: Some(0.5),
            })
            .collect();

        let remaining = if let Some(cursor) = &opts.cursor {
            filter_memories_by_cursor(&all_memories, cursor)
        } else {
            all_memories
        };

        let limit = opts.limit.unwrap_or(100);
        let has_more = remaining.len() > limit;
        let mut memories: Vec<MemorySummary> = remaining.into_iter().take(limit).collect();
        let next_cursor = memories.last().map(encode_mock_memory_cursor);

        let mut deleted = guard.deleted.clone();
        if let Some(ns) = &opts.namespace {
            memories.retain(|m| &m.namespace_id == ns);
            deleted.retain(|d| &d.namespace_id == ns);
        }

        Ok(MemoriesPage {
            memories,
            next_cursor,
            has_more,
            snapshot_version: guard.next_seq,
            deleted,
            must_resync: false,
        })
    }

    /// Returns mock identity metadata.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] if destroyed.
    pub async fn whoami(&self) -> Result<WhoamiResult> {
        self.check_alive().await?;
        Ok(WhoamiResult {
            account_id: self.0.account_id.clone(),
            owner: self.0.owner.clone(),
            package_id: "0x0000000000000000000000000000000000000000000000000000000000000003"
                .to_owned(),
        })
    }

    /// Returns a healthy mock status response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] if destroyed.
    pub async fn health(&self) -> Result<HealthResult> {
        self.check_alive().await?;
        Ok(HealthResult {
            status: "ok".to_owned(),
            version: SDK_VERSION.to_owned(),
            mode: Some("mock".to_owned()),
            write_ready: Some(true),
            writes: Some("ok".to_owned()),
            prompt_versions: Some(PromptVersions {
                extract: "mock.v1".to_owned(),
                ask: "mock.v1".to_owned(),
            }),
            api_version: Some("1.0.0".to_owned()),
            relayer_version: Some(SDK_VERSION.to_owned()),
        })
    }

    /// Returns a compatible mock [`VersionInfo`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] if destroyed.
    pub async fn compatibility(&self) -> Result<VersionInfo> {
        self.check_alive().await?;
        Ok(VersionInfo {
            relayer_version: SDK_VERSION.to_owned(),
            api_version: "1.0.0".to_owned(),
            min_supported_sdk: MinSupportedSdk::default(),
            feature_flags: BTreeMap::new(),
            deprecations: Vec::new(),
            build: BuildMetadata::default(),
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, MockState> {
        self.0.state.lock().expect("mock state lock poisoned")
    }

    async fn check_alive(&self) -> Result<()> {
        tokio::task::yield_now().await;
        if self.is_destroyed() {
            Err(Error::Destroyed)
        } else {
            Ok(())
        }
    }

    fn resolve_ns(&self, override_ns: Option<&str>) -> Result<String> {
        let ns = override_ns.unwrap_or(&self.0.namespace);
        validate_namespace(ns)?;
        Ok(ns.to_owned())
    }

    fn insert_entry(&self, text: &str, namespace: &str, dedupe: DedupeMode) -> StoredEntry {
        let mut guard = self.lock_state();
        if dedupe == DedupeMode::ContentHash
            && let Some(existing) = guard
                .entries
                .iter()
                .find(|e| e.namespace == namespace && e.text == text)
        {
            return existing.clone();
        }
        guard.next_seq += 1;
        let seq = guard.next_seq;
        let id = format!("mock-job-{seq}");
        let blob_id = format!("mock-blob-{seq}");
        let entry = StoredEntry {
            id,
            blob_id,
            namespace: namespace.to_owned(),
            text: text.to_owned(),
            created_at: Utc::now().to_rfc3339(),
            seq,
        };
        guard.entries.push(entry.clone());
        entry
    }
}

fn lexical_distance(query: &str, candidate: &str) -> f64 {
    let q_tokens = tokenize(query);
    let c_tokens = tokenize(candidate);
    if q_tokens.is_empty() || c_tokens.is_empty() {
        return 1.0;
    }
    let overlap = q_tokens.intersection(&c_tokens).count();
    let overlap_f = u32::try_from(overlap).map_or(f64::MAX, f64::from);
    let total_f = u32::try_from(q_tokens.len()).map_or(f64::MAX, f64::from);
    let ratio = overlap_f / total_f;
    (1.0 - ratio).clamp(0.0, 1.0)
}

fn tokenize(s: &str) -> HashSet<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

#[derive(Debug, serde::Deserialize)]
struct NamespaceCursorPayload {
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

fn decode_namespace_cursor(cursor: &str) -> Option<(Option<String>, Option<String>)> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(cursor))
        .ok()?;
    let payload: NamespaceCursorPayload = serde_json::from_slice(&bytes).ok()?;
    Some((payload.namespace, payload.updated_at))
}

fn encode_mock_namespace_cursor(summary: &NamespaceSummary) -> String {
    let payload = serde_json::json!({
        "namespace": summary.name,
        "updated_at": summary.updated_at,
    });
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
}

fn filter_namespaces_by_cursor(all: &[NamespaceSummary], cursor: &str) -> Vec<NamespaceSummary> {
    let cursor_target = decode_namespace_cursor(cursor);
    let pos = all.iter().position(|ns| {
        if let Some((ref target_ns, ref target_up)) = cursor_target {
            match (target_ns, target_up) {
                (Some(name), Some(up)) if &ns.name == name && &ns.updated_at == up => return true,
                (Some(name), None) if &ns.name == name => return true,
                (None, Some(up)) if &ns.updated_at == up => return true,
                _ => {}
            }
        }
        ns.name == cursor || ns.updated_at == cursor || ns.id == cursor
    });

    match pos {
        Some(idx) => all.get(idx + 1..).unwrap_or(&[]).to_vec(),
        None => all.to_vec(),
    }
}

#[derive(Debug, serde::Deserialize)]
struct MemoryCursorPayload {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

fn decode_memory_cursor(cursor: &str) -> Option<(Option<String>, Option<String>)> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(cursor))
        .ok()?;
    let payload: MemoryCursorPayload = serde_json::from_slice(&bytes).ok()?;
    Some((payload.id, payload.updated_at))
}

fn encode_mock_memory_cursor(summary: &MemorySummary) -> String {
    let payload = serde_json::json!({
        "id": summary.memory_id,
        "updated_at": summary.updated_at,
    });
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
}

fn filter_memories_by_cursor(all: &[MemorySummary], cursor: &str) -> Vec<MemorySummary> {
    let cursor_target = decode_memory_cursor(cursor);
    let pos = all.iter().position(|m| {
        if let Some((ref target_id, ref target_up)) = cursor_target {
            match (target_id, target_up) {
                (Some(id), Some(up)) if &m.memory_id == id && &m.updated_at == up => return true,
                (Some(id), None) if &m.memory_id == id => return true,
                (None, Some(up)) if &m.updated_at == up => return true,
                _ => {}
            }
        }
        m.memory_id == cursor || m.updated_at == cursor
    });

    match pos {
        Some(idx) => all.get(idx + 1..).unwrap_or(&[]).to_vec(),
        None => all.to_vec(),
    }
}

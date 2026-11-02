//! Async Walrus Memory client (`MemWal`) and builder (`MemWalBuilder`).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::SigningKey;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rand::Rng as _;
use rand::rngs::OsRng;
use reqwest::header::HeaderMap;
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::signing::{
    Signer, build_seal_session_personal_message, canonical_message, derived_bulk_idempotency_key,
    derived_content_dedupe_key, derived_idempotency_key, encode_sui_private_key, now_epoch_ms,
    sign_sui_personal_message,
};
use crate::tokens::{apply_token_budget, estimate_tokens};
use crate::types::{
    AnalyzeOptions, AnalyzeResult, AnalyzeWaitResult, AskOptions, AskResult,
    DEFAULT_ANALYZE_TIMEOUT, DEFAULT_NAMESPACE, DEFAULT_PREFLIGHT_TIMEOUT, DEFAULT_RECALL_TIMEOUT,
    DEFAULT_REQUEST_TIMEOUT, DEFAULT_RESTORE_TIMEOUT, DEFAULT_SERVER_URL, DedupeMode, EmbedResult,
    Env, ForgetResult, HealthResult, ListMemoriesOptions, ListNamespacesOptions, MAX_BULK_ITEMS,
    MemoriesPage, NamespacesPage, RecallManualOptions, RecallManualResult, RecallParams,
    RecallResult, RememberAccepted, RememberBulkAccepted, RememberBulkItem, RememberBulkItemResult,
    RememberBulkOptions, RememberBulkResult, RememberBulkStatusItem, RememberBulkStatusResult,
    RememberJobStatus, RememberManualOptions, RememberManualResult, RememberOptions,
    RememberResult, RememberWaitOptions, RestoreResult, VersionInfo, WaitOptions, WhoamiResult,
    normalize_occurred_at, validate_job_id, validate_max_distance, validate_namespace,
    validate_non_blank, validate_positive_limit, validate_vector,
};

/// Crate version reported for SDK compatibility checks.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Relayer HTTP API major version supported by this crate.
pub const SUPPORTED_API_MAJOR: u64 = 1;

const SEAL_SESSION_TTL_MIN: u64 = 5;
const SEAL_SESSION_SAFETY_MARGIN_MS: u128 = 30_000;
const PACKAGE_VERSION_CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const CONFIRM_READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BACKOFF_DELAY_MS: u64 = 10_000;
const RECALL_DEADLINE_MARGIN_MS: u64 = 1_000;

/// RFC-3986 query value encoding set (encodes everything outside unreserved characters).
const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Debug, Clone)]
struct SessionCacheEntry {
    header_value: String,
    expires_at_ms: u128,
}

#[derive(Debug, Clone)]
struct ServerConfig {
    package_id: String,
    network: String,
    sui_rpc_url: Option<String>,
}

#[derive(Debug, Default)]
struct CachedMetadata {
    session: Option<SessionCacheEntry>,
    server_config: Option<ServerConfig>,
    package_verified: bool,
    version_info: Option<VersionInfo>,
    owner_address: Option<String>,
    pending_remember_keys: HashMap<String, String>,
}

struct ClientInner {
    http: reqwest::Client,
    signer: RwLock<Option<Signer>>,
    account_id: String,
    server_url: String,
    namespace: String,
    request_timeout: Duration,
    recall_timeout: Duration,
    preflight_timeout: Duration,
    destroyed: AtomicBool,
    caches: Mutex<CachedMetadata>,
    compat_gate: tokio::sync::Mutex<()>,
    session_gate: tokio::sync::Mutex<()>,
    owner_gate: tokio::sync::Mutex<()>,
}

#[derive(Clone)]
enum KeySource {
    Str(Zeroizing<String>),
    Bytes(Zeroizing<Vec<u8>>),
}

/// Builder for configuring and constructing a [`MemWal`] client.
///
/// Secret key material is zeroized on drop and redacted in [`Debug`] output.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use memwal::{Env, MemWal};
///
/// # fn example() -> memwal::Result<()> {
/// let client = MemWal::builder("0x1111111111111111111111111111111111111111111111111111111111111111", "0xabc")
///     .env(Env::Dev)
///     .namespace("agent-prod")
///     .request_timeout(Duration::from_secs(30))
///     .build()?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct MemWalBuilder {
    key: KeySource,
    account_id: String,
    env: Option<Env>,
    server_url: Option<String>,
    namespace: String,
    request_timeout: Duration,
    recall_timeout: Duration,
    preflight_timeout: Duration,
    http_client: Option<reqwest::Client>,
}

impl fmt::Debug for MemWalBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemWalBuilder")
            .field("key", &"<redacted>")
            .field("account_id", &self.account_id)
            .field("env", &self.env)
            .field("server_url", &self.server_url)
            .field("namespace", &self.namespace)
            .field("request_timeout", &self.request_timeout)
            .field("recall_timeout", &self.recall_timeout)
            .field("preflight_timeout", &self.preflight_timeout)
            .field("has_custom_http_client", &self.http_client.is_some())
            .finish()
    }
}

impl MemWalBuilder {
    pub(crate) fn new_str(key: impl Into<String>, account_id: impl Into<String>) -> Self {
        Self {
            key: KeySource::Str(Zeroizing::new(key.into())),
            account_id: account_id.into(),
            env: None,
            server_url: None,
            namespace: DEFAULT_NAMESPACE.to_owned(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            recall_timeout: DEFAULT_RECALL_TIMEOUT,
            preflight_timeout: DEFAULT_PREFLIGHT_TIMEOUT,
            http_client: None,
        }
    }

    pub(crate) fn new_bytes(seed: &[u8], account_id: impl Into<String>) -> Self {
        Self {
            key: KeySource::Bytes(Zeroizing::new(seed.to_vec())),
            account_id: account_id.into(),
            env: None,
            server_url: None,
            namespace: DEFAULT_NAMESPACE.to_owned(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            recall_timeout: DEFAULT_RECALL_TIMEOUT,
            preflight_timeout: DEFAULT_PREFLIGHT_TIMEOUT,
            http_client: None,
        }
    }

    /// Selects a hosted or local relayer environment preset (`Prod`, `Dev`, or `Local`).
    ///
    /// An explicit [`Self::server_url`] always takes precedence over `env`.
    pub fn env(&mut self, env: Env) -> &mut Self {
        self.env = Some(env);
        self
    }

    /// Sets an explicit relayer base URL (overrides [`Self::env`]).
    pub fn server_url(&mut self, url: impl Into<String>) -> &mut Self {
        self.server_url = Some(url.into());
        self
    }

    /// Sets the default namespace used when per-call options omit one.
    pub fn namespace(&mut self, namespace: impl Into<String>) -> &mut Self {
        self.namespace = namespace.into();
        self
    }

    /// Sets the default deadline for individual authenticated HTTP requests (`30s` default).
    pub fn request_timeout(&mut self, timeout: Duration) -> &mut Self {
        if !timeout.is_zero() {
            self.request_timeout = timeout;
        }
        self
    }

    /// Sets the default deadline for `POST /api/recall` (`15s` default).
    pub fn recall_timeout(&mut self, timeout: Duration) -> &mut Self {
        if !timeout.is_zero() {
            self.recall_timeout = timeout;
        }
        self
    }

    /// Sets the deadline for unauthenticated preflight probes (`/version`, `/health`, `/config`, `5s` default).
    pub fn preflight_timeout(&mut self, timeout: Duration) -> &mut Self {
        if !timeout.is_zero() {
            self.preflight_timeout = timeout;
        }
        self
    }

    /// Supplies a pre-configured [`reqwest::Client`] connection pool instead of building a default one.
    pub fn http_client(&mut self, client: reqwest::Client) -> &mut Self {
        self.http_client = Some(client);
        self
    }

    /// Validates credentials, URLs, and namespace settings and builds a [`MemWal`] client.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`], [`Error::InvalidUrl`], or [`Error::InvalidArgument`]
    /// when configuration inputs are malformed.
    pub fn build(&self) -> Result<MemWal> {
        let signer = match &self.key {
            KeySource::Str(s) => Signer::from_key_str(s)?,
            KeySource::Bytes(b) => Signer::from_seed_bytes(b)?,
        };

        let trimmed_account = self.account_id.trim();
        if trimmed_account.is_empty() {
            return Err(Error::InvalidArgument(
                "account_id is required (Walrus Memory Sui object ID, e.g. 0x...)".to_owned(),
            ));
        }

        validate_namespace(&self.namespace)?;

        let raw_url = self
            .server_url
            .as_deref()
            .unwrap_or_else(|| self.env.map_or(DEFAULT_SERVER_URL, Env::server_url));
        let normalized_url = normalize_server_url(raw_url)?;

        let http = if let Some(custom) = &self.http_client {
            custom.clone()
        } else {
            reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(10))
                .user_agent(format!("memwal-rust-sdk/{SDK_VERSION}"))
                .build()
                .map_err(|err| Error::Transport {
                    context: "initializing HTTP client",
                    source: Box::new(err),
                })?
        };

        Ok(MemWal(Arc::new(ClientInner {
            http,
            signer: RwLock::new(Some(signer)),
            account_id: trimmed_account.to_owned(),
            server_url: normalized_url,
            namespace: self.namespace.clone(),
            request_timeout: self.request_timeout,
            recall_timeout: self.recall_timeout,
            preflight_timeout: self.preflight_timeout,
            destroyed: AtomicBool::new(false),
            caches: Mutex::new(CachedMetadata::default()),
            compat_gate: tokio::sync::Mutex::new(()),
            session_gate: tokio::sync::Mutex::new(()),
            owner_gate: tokio::sync::Mutex::new(()),
        })))
    }
}

/// Async client for the Walrus Memory Relayer API.
///
/// `MemWal` wraps a shared, connection-pooled internal state (`Arc`) so cloning a
/// handle is cheap (`O(1)`) and shares cached compatibility metadata, SEAL sessions,
/// and HTTP connection pools across Tokio tasks. Calling [`MemWal::destroy`] wipes
/// key material across all clones immediately.
#[derive(Clone)]
pub struct MemWal(Arc<ClientInner>);

impl fmt::Debug for MemWal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemWal")
            .field("server_url", &self.0.server_url)
            .field("account_id", &self.0.account_id)
            .field("namespace", &self.0.namespace)
            .field("destroyed", &self.is_destroyed())
            .finish()
    }
}

#[derive(Debug, Clone, Copy)]
struct SignedCallOpts {
    include_seal_session: bool,
    timeout: Duration,
}

impl MemWal {
    /// Creates a [`MemWal`] client targeting the default production relayer (`Env::Prod`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if `key` is malformed or [`Error::InvalidArgument`]
    /// if `account_id` is empty.
    pub fn new(key: impl Into<String>, account_id: impl Into<String>) -> Result<Self> {
        Self::builder(key, account_id).build()
    }

    /// Creates a [`MemWalBuilder`] from a hex (`0x...` or raw 64-char) or `suiprivkey1...` key string.
    #[must_use]
    pub fn builder(key: impl Into<String>, account_id: impl Into<String>) -> MemWalBuilder {
        MemWalBuilder::new_str(key, account_id)
    }

    /// Creates a [`MemWalBuilder`] by copying a raw 32-byte Ed25519 secret seed.
    ///
    /// The caller's byte slice is copied into an internal zeroizing buffer so
    /// [`Self::destroy`] never mutates caller-owned memory.
    #[must_use]
    pub fn builder_from_seed_bytes(seed: &[u8], account_id: impl Into<String>) -> MemWalBuilder {
        MemWalBuilder::new_bytes(seed, account_id)
    }

    /// Securely wipes the Ed25519 delegate key and cached SEAL session credentials
    /// from memory and permanently invalidates this client (including all clones).
    pub fn destroy(&self) {
        self.0.destroyed.store(true, Ordering::SeqCst);
        {
            let mut signer_guard = self
                .0
                .signer
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            *signer_guard = None;
        }
        {
            let mut caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            caches.session = None;
            caches.server_config = None;
            caches.package_verified = false;
            caches.version_info = None;
            caches.owner_address = None;
            caches.pending_remember_keys.clear();
        }
    }

    /// Returns `true` if [`Self::destroy`] has been called on this client.
    #[must_use]
    pub fn is_destroyed(&self) -> bool {
        self.0.destroyed.load(Ordering::SeqCst)
    }

    /// Returns the configured relayer base URL (without trailing slash).
    #[must_use]
    pub fn server_url(&self) -> &str {
        &self.0.server_url
    }

    /// Returns the configured default namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.0.namespace
    }

    /// Returns the on-chain `MemWalAccount` Sui object ID.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.0.account_id
    }

    /// Returns the 64-character lowercase hex Ed25519 public key for the delegate key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] if [`Self::destroy`] has been called.
    pub fn public_key_hex(&self) -> Result<String> {
        self.check_not_destroyed()?;
        let guard = self.0.signer.read().unwrap_or_else(PoisonError::into_inner);
        let signer = guard.as_ref().ok_or(Error::Destroyed)?;
        Ok(signer.public_key_hex().to_owned())
    }

    /// Returns the `0x`-prefixed Sui address derived from the delegate key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] if [`Self::destroy`] has been called.
    pub fn sui_address(&self) -> Result<String> {
        self.check_not_destroyed()?;
        let guard = self.0.signer.read().unwrap_or_else(PoisonError::into_inner);
        let signer = guard.as_ref().ok_or(Error::Destroyed)?;
        Ok(signer.sui_address().to_owned())
    }

    /// Estimates the LLM token count of `text` using the SDK's deterministic
    /// `ceil(chars / 4)` approximation.
    #[must_use]
    pub fn count_tokens(&self, text: &str) -> usize {
        estimate_tokens(text)
    }

    // ============================================================
    // Core Memory Operations
    // ============================================================

    /// Enqueues a memory for SEAL encryption, Walrus upload, and vector indexing,
    /// returning immediately once accepted (`HTTP 202`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `text` is blank, [`Error::Destroyed`] if
    /// destroyed, or transport/relayer errors if the request fails.
    pub async fn remember(&self, text: &str) -> Result<RememberAccepted> {
        self.remember_with(text, &RememberOptions::default()).await
    }

    /// Enqueues a memory with custom namespace, idempotency key, or deduplication options.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `text` or `opts.namespace` is invalid,
    /// or a relayer error if submission fails.
    pub async fn remember_with(
        &self,
        text: &str,
        opts: &RememberOptions,
    ) -> Result<RememberAccepted> {
        validate_non_blank(text, "text")?;
        let resolved_ns = self.resolve_namespace(opts.namespace.as_deref())?;
        let dedupe = opts.dedupe == DedupeMode::ContentHash;
        let request_identity = format!("{resolved_ns}\0{text}");
        let pending_identity = if dedupe {
            format!("dedupe\0{request_identity}")
        } else {
            request_identity.clone()
        };

        let generated_key = opts.idempotency_key.is_none();
        let idempotency_key = if let Some(explicit) = &opts.idempotency_key {
            explicit.clone()
        } else {
            self.get_or_insert_pending_key(&pending_identity, || {
                if dedupe {
                    derived_content_dedupe_key(&request_identity)
                } else {
                    derived_idempotency_key(&request_identity)
                }
            })?
        };

        let res = self
            .signed_request::<RememberAccepted, _>(
                "POST",
                "/api/remember",
                Some(&RememberWireBody {
                    text,
                    namespace: &resolved_ns,
                    idempotency_key: &idempotency_key,
                    dedupe,
                }),
                &[200, 202],
                SignedCallOpts {
                    include_seal_session: true,
                    timeout: self.0.request_timeout,
                },
            )
            .await;

        match &res {
            Ok(_) => {
                if generated_key {
                    self.clear_pending_key(&pending_identity);
                }
            }
            Err(err) if !err.is_transient() => {
                if generated_key {
                    self.clear_pending_key(&pending_identity);
                }
            }
            Err(_) => {}
        }

        res
    }

    /// Queries the current status of a background `remember` job without polling.
    ///
    /// Unknown or malformed job IDs resolve to `status == "not_found"` rather than
    /// returning an error, matching the TypeScript and Python SDK contracts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] or transport/auth errors if the status request fails.
    pub async fn remember_status(&self, job_id: &str) -> Result<RememberJobStatus> {
        self.check_not_destroyed()?;
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

        let path = format!("/api/remember/{job_id}");
        let raw: serde_json::Value = self
            .signed_request::<serde_json::Value, ()>(
                "GET",
                &path,
                None,
                &[200, 404],
                SignedCallOpts {
                    include_seal_session: false,
                    timeout: self.0.request_timeout,
                },
            )
            .await?;

        Ok(parse_job_status_value(job_id, &raw))
    }

    /// Polls an accepted `remember` job until it reaches `"done"` or fails/times out.
    ///
    /// # Errors
    ///
    /// Returns [`Error::JobFailed`], [`Error::JobNotFound`], [`Error::JobTimeout`],
    /// or non-transient relayer/auth errors.
    pub async fn wait_for_remember_job(
        &self,
        job_id: &str,
        opts: &WaitOptions,
    ) -> Result<RememberResult> {
        self.check_not_destroyed()?;
        if !validate_job_id(job_id) {
            return Err(Error::JobNotFound {
                job_id: job_id.to_owned(),
            });
        }

        let path = format!("/api/remember/{job_id}");
        let start = Instant::now();
        let deadline = start + opts.timeout;
        let mut attempt = 0_u32;
        let mut retry_after_delay: Option<Duration> = None;
        let mut saw_rate_limit = false;
        let mut last_status: Option<String> = None;

        loop {
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() && attempt > 0 {
                break;
            }

            let sleep_for =
                next_poll_sleep(opts.poll_interval, &mut attempt, &mut retry_after_delay)
                    .min(remaining);
            if !sleep_for.is_zero() {
                tokio::time::sleep(sleep_for).await;
            }

            let poll_timeout = self.poll_deadline(deadline);
            let poll_res = self
                .signed_request::<serde_json::Value, ()>(
                    "GET",
                    &path,
                    None,
                    &[200, 404],
                    SignedCallOpts {
                        include_seal_session: false,
                        timeout: poll_timeout,
                    },
                )
                .await;

            let value = match poll_res {
                Ok(v) => v,
                Err(err) if err.is_transient() => {
                    if matches!(err, Error::RateLimited { .. }) {
                        saw_rate_limit = true;
                        retry_after_delay = err.retry_after();
                    }
                    if Instant::now() >= deadline {
                        break;
                    }
                    continue;
                }
                Err(err) => return Err(err),
            };

            let status = parse_job_status_value(job_id, &value);
            if status.status == "not_found" {
                return Err(Error::JobNotFound {
                    job_id: job_id.to_owned(),
                });
            }

            last_status = Some(status.status.clone());
            if status.status == "done" {
                return Ok(RememberResult {
                    id: status.job_id.clone(),
                    job_id: status.job_id,
                    blob_id: status.blob_id.unwrap_or_default(),
                    owner: status.owner.unwrap_or_default(),
                    namespace: status.namespace.unwrap_or_else(|| self.0.namespace.clone()),
                });
            }
            if status.status == "failed" {
                return Err(Error::JobFailed {
                    job_id: job_id.to_owned(),
                    message: redact_internal_urls(
                        status.error.as_deref().unwrap_or("unknown error"),
                    ),
                });
            }

            if Instant::now() >= deadline {
                break;
            }
        }

        Err(Error::JobTimeout {
            job_id: job_id.to_owned(),
            elapsed: opts.timeout,
            last_status,
            saw_rate_limit,
        })
    }

    /// Enqueues a memory and waits until the Walrus upload and vector index commit finish.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`], [`Error::JobFailed`], [`Error::JobTimeout`],
    /// or relayer/transport errors.
    pub async fn remember_and_wait(&self, text: &str) -> Result<RememberResult> {
        self.remember_and_wait_with(text, &RememberWaitOptions::default())
            .await
    }

    /// Enqueues a memory with custom options and waits until persistence completes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`], [`Error::JobFailed`], [`Error::JobTimeout`],
    /// or relayer/transport errors.
    pub async fn remember_and_wait_with(
        &self,
        text: &str,
        opts: &RememberWaitOptions,
    ) -> Result<RememberResult> {
        validate_non_blank(text, "text")?;
        let resolved_ns = self.resolve_namespace(opts.remember.namespace.as_deref())?;
        let dedupe = opts.remember.dedupe == DedupeMode::ContentHash;
        let request_identity = format!("{resolved_ns}\0{text}");
        let pending_identity = if dedupe {
            format!("dedupe\0{request_identity}")
        } else {
            request_identity.clone()
        };

        let generated_key = opts.remember.idempotency_key.is_none();
        let idempotency_key = if let Some(explicit) = &opts.remember.idempotency_key {
            explicit.clone()
        } else {
            self.get_or_insert_pending_key(&pending_identity, || {
                if dedupe {
                    derived_content_dedupe_key(&request_identity)
                } else {
                    derived_idempotency_key(&request_identity)
                }
            })?
        };

        let mut call_opts = opts.remember.clone();
        call_opts.namespace = Some(resolved_ns);
        call_opts.idempotency_key = Some(idempotency_key);

        let accepted = match self.remember_with(text, &call_opts).await {
            Ok(acc) => acc,
            Err(err) => {
                if generated_key && !err.is_transient() {
                    self.clear_pending_key(&pending_identity);
                }
                return Err(err);
            }
        };

        let wait_res = self
            .wait_for_remember_job(&accepted.job_id, &opts.wait)
            .await;

        match &wait_res {
            Ok(_) | Err(Error::JobFailed { .. } | Error::JobNotFound { .. }) => {
                if generated_key {
                    self.clear_pending_key(&pending_identity);
                }
            }
            Err(_) => {}
        }

        wait_res
    }

    // ============================================================
    // Bulk Remember Operations
    // ============================================================

    /// Submits up to [`MAX_BULK_ITEMS`] (`20`) memories in a single batched call (`HTTP 202`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `items` is empty, exceeds `20` items, or
    /// contains blank text or invalid namespaces.
    pub async fn remember_bulk(&self, items: &[RememberBulkItem]) -> Result<RememberBulkAccepted> {
        self.remember_bulk_with(items, &RememberBulkOptions::default())
            .await
    }

    /// Submits a batched `remember_bulk` request with an optional custom idempotency key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on invalid input or relayer errors on failure.
    pub async fn remember_bulk_with(
        &self,
        items: &[RememberBulkItem],
        opts: &RememberBulkOptions,
    ) -> Result<RememberBulkAccepted> {
        let normalized = self.normalize_bulk_items(items)?;
        let identity = bulk_request_identity(&normalized);
        let generated_key = opts.idempotency_key.is_none();
        let idempotency_key = if let Some(explicit) = &opts.idempotency_key {
            explicit.clone()
        } else {
            self.get_or_insert_pending_key(&identity, || derived_bulk_idempotency_key(&identity))?
        };

        let wire_items = normalized
            .iter()
            .map(|(text, ns)| BulkWireItem {
                text: text.as_str(),
                namespace: ns.as_str(),
            })
            .collect();

        let res = self
            .signed_request::<RememberBulkAccepted, _>(
                "POST",
                "/api/remember/bulk",
                Some(&BulkRememberWireBody {
                    items: wire_items,
                    idempotency_key: &idempotency_key,
                }),
                &[200, 202],
                SignedCallOpts {
                    include_seal_session: true,
                    timeout: self.0.request_timeout,
                },
            )
            .await;

        match &res {
            Ok(_) => {
                if generated_key {
                    self.clear_pending_key(&identity);
                }
            }
            Err(err) if !err.is_transient() => {
                if generated_key {
                    self.clear_pending_key(&identity);
                }
            }
            Err(_) => {}
        }

        let accepted = res?;
        if accepted.job_ids.len() != normalized.len() {
            return Err(Error::json_msg(
                "POST /api/remember/bulk",
                format!(
                    "expected {} job_ids, relayer returned {}",
                    normalized.len(),
                    accepted.job_ids.len()
                ),
            ));
        }
        Ok(accepted)
    }

    /// Queries current status snapshots for `job_ids` via `POST /api/remember/bulk/status`,
    /// automatically chunking batches larger than [`MAX_BULK_ITEMS`] (`20`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] or relayer/transport errors if any chunk fails.
    pub async fn remember_bulk_status(
        &self,
        job_ids: &[String],
    ) -> Result<RememberBulkStatusResult> {
        self.remember_bulk_status_with_timeout(job_ids, self.0.request_timeout)
            .await
    }

    async fn remember_bulk_status_with_timeout(
        &self,
        job_ids: &[String],
        timeout: Duration,
    ) -> Result<RememberBulkStatusResult> {
        self.check_not_destroyed()?;
        if job_ids.is_empty() {
            return Ok(RememberBulkStatusResult {
                results: Vec::new(),
            });
        }

        let mut all_results = Vec::with_capacity(job_ids.len());
        for chunk in job_ids.chunks(MAX_BULK_ITEMS) {
            let chunk_res: RememberBulkStatusResult = self
                .signed_request(
                    "POST",
                    "/api/remember/bulk/status",
                    Some(&BulkStatusWireBody { job_ids: chunk }),
                    &[200],
                    SignedCallOpts {
                        include_seal_session: false,
                        timeout,
                    },
                )
                .await?;
            all_results.extend(chunk_res.results);
        }

        Ok(RememberBulkStatusResult {
            results: all_results,
        })
    }

    /// Polls multiple background `remember` jobs until every job settles or `opts.timeout` expires.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RateLimited`] if every poll and confirmation probe is rejected with
    /// `HTTP 429`, or non-transient auth/relayer errors.
    pub async fn wait_for_remember_jobs(
        &self,
        job_ids: &[String],
        namespaces: &[String],
        opts: &WaitOptions,
    ) -> Result<RememberBulkResult> {
        self.check_not_destroyed()?;
        if job_ids.is_empty() {
            return Ok(RememberBulkResult {
                results: Vec::new(),
                total: 0,
                succeeded: 0,
                failed: 0,
                timed_out: 0,
            });
        }

        let deadline = Instant::now() + opts.timeout;
        let timeout_ms = opts.timeout.as_millis();
        let mut results =
            init_bulk_timeout_placeholders(job_ids, namespaces, &self.0.namespace, timeout_ms);

        let mut pending: HashSet<String> = job_ids.iter().cloned().collect();
        let mut last_seen: HashMap<String, RememberBulkStatusItem> = HashMap::new();
        let mut attempt = 0_u32;
        let mut retry_after_delay: Option<Duration> = None;
        let mut saw_rate_limit = false;
        let mut last_refusal: Option<u16> = None;
        let mut answered = false;

        while !pending.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() && attempt > 0 {
                break;
            }

            let sleep_for =
                next_poll_sleep(opts.poll_interval, &mut attempt, &mut retry_after_delay)
                    .min(remaining);
            if !sleep_for.is_zero() {
                tokio::time::sleep(sleep_for).await;
            }

            let pending_ids: Vec<String> = job_ids
                .iter()
                .filter(|id| pending.contains(*id))
                .cloned()
                .collect();
            if pending_ids.is_empty() {
                break;
            }

            let poll_timeout = self.poll_deadline(deadline);
            let batch_res = self
                .remember_bulk_status_with_timeout(&pending_ids, poll_timeout)
                .await;

            let batch = match batch_res {
                Ok(b) => b,
                Err(err) if err.is_transient() => {
                    last_refusal = err.status_code();
                    if matches!(err, Error::RateLimited { .. }) {
                        saw_rate_limit = true;
                        retry_after_delay = err.retry_after();
                    }
                    if Instant::now() >= deadline {
                        break;
                    }
                    continue;
                }
                Err(err) => return Err(err),
            };
            answered = true;

            for item in batch.results {
                settle_bulk_item(
                    &item,
                    job_ids,
                    namespaces,
                    &self.0.namespace,
                    &mut results,
                    &mut pending,
                    &mut last_seen,
                );
            }

            if pending.is_empty() || Instant::now() >= deadline {
                break;
            }
        }

        if !opts.timeout.is_zero() && pending.len() == job_ids.len() && last_seen.is_empty() {
            answered |= self
                .confirm_unanswered_bulk_batch(
                    job_ids,
                    namespaces,
                    &mut results,
                    &mut pending,
                    &mut last_seen,
                )
                .await?;
        }

        Ok(finalize_bulk_wait_result(
            job_ids,
            results,
            &pending,
            &last_seen,
            timeout_ms,
            answered,
            last_refusal,
            saw_rate_limit,
        ))
    }

    async fn confirm_unanswered_bulk_batch(
        &self,
        job_ids: &[String],
        namespaces: &[String],
        results: &mut [RememberBulkItemResult],
        pending: &mut HashSet<String>,
        last_seen: &mut HashMap<String, RememberBulkStatusItem>,
    ) -> Result<bool> {
        let probe_timeout = self.0.request_timeout.min(CONFIRM_READ_TIMEOUT);
        match self
            .remember_bulk_status_with_timeout(job_ids, probe_timeout)
            .await
        {
            Ok(probed) => {
                for item in probed.results {
                    if pending.contains(&item.job_id) {
                        settle_bulk_item(
                            &item,
                            job_ids,
                            namespaces,
                            &self.0.namespace,
                            results,
                            pending,
                            last_seen,
                        );
                    }
                }
                Ok(true)
            }
            Err(Error::RateLimited { retry_after, .. }) => Err(Error::RateLimited {
                retry_after,
                job_ids: job_ids.to_vec(),
                message: format!(
                    "rate-limited every status read for this batch of {} writes; verify status later with remember_bulk_status",
                    job_ids.len()
                ),
            }),
            Err(_) => Ok(false),
        }
    }

    /// Submits up to [`MAX_BULK_ITEMS`] (`20`) memories and waits until all items settle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] or relayer/rate-limit errors.
    pub async fn remember_bulk_and_wait(
        &self,
        items: &[RememberBulkItem],
        opts: &RememberBulkOptions,
    ) -> Result<RememberBulkResult> {
        let normalized = self.normalize_bulk_items(items)?;
        let namespaces: Vec<String> = normalized.iter().map(|(_, ns)| ns.clone()).collect();
        let identity = bulk_request_identity(&normalized);
        let generated_key = opts.idempotency_key.is_none();
        let idempotency_key = if let Some(explicit) = &opts.idempotency_key {
            explicit.clone()
        } else {
            self.get_or_insert_pending_key(&identity, || derived_bulk_idempotency_key(&identity))?
        };

        let mut submit_opts = opts.clone();
        submit_opts.idempotency_key = Some(idempotency_key);

        let accepted = self.remember_bulk_with(items, &submit_opts).await?;
        let settled = self
            .wait_for_remember_jobs(&accepted.job_ids, &namespaces, &opts.wait)
            .await?;

        if generated_key {
            self.clear_pending_key(&identity);
        }
        Ok(settled)
    }

    // ============================================================
    // Recall, Forget, Embed, Analyze, Ask, Restore
    // ============================================================

    /// Recalls decrypted memories matching a natural-language query or [`RecallParams`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `query` is blank, `limit == 0`, `max_distance`
    /// is negative/non-finite, or `scoring_weights` are invalid; or relayer/transport errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use memwal::{MemWal, RecallParams, RecallSort};
    ///
    /// # async fn run(client: &MemWal) -> memwal::Result<()> {
    /// let quick = client.recall("food allergies").await?;
    /// let recent = client
    ///     .recall(RecallParams::new("sprint notes").with_limit(5).with_sort(RecallSort::Recent))
    ///     .await?;
    /// # let _ = (quick, recent);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn recall(&self, params: impl Into<RecallParams>) -> Result<RecallResult> {
        let params = params.into();
        validate_non_blank(&params.query, "query")?;
        validate_positive_limit(params.limit, "limit")?;
        validate_max_distance(params.max_distance)?;
        if let Some(weights) = &params.scoring_weights {
            weights.validate()?;
        }
        let resolved_ns = self.resolve_namespace(params.namespace.as_deref())?;
        let timeout = params.timeout.unwrap_or(self.0.recall_timeout);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "clamped to u64::MAX milliseconds"
        )]
        let raw_deadline_ms = timeout.as_millis().min(u128::from(u64::MAX)) as u64;
        let deadline_ms = if raw_deadline_ms > RECALL_DEADLINE_MARGIN_MS {
            raw_deadline_ms - RECALL_DEADLINE_MARGIN_MS
        } else {
            raw_deadline_ms
        };

        let mut response: RecallResult = self
            .signed_request(
                "POST",
                "/api/recall",
                Some(&RecallWireBody {
                    query: &params.query,
                    limit: params.limit,
                    namespace: &resolved_ns,
                    scoring_weights: params.scoring_weights.as_ref(),
                    sort: params.sort,
                    deadline_ms: (deadline_ms > 0).then_some(deadline_ms),
                }),
                &[200],
                SignedCallOpts {
                    include_seal_session: true,
                    timeout,
                },
            )
            .await?;

        if let Some(max_dist) = params.max_distance {
            response
                .results
                .retain(|m| m.distance.is_finite() && m.distance.max(0.0) < max_dist);
        }

        if let Some(max_tokens) = params.max_tokens {
            let (budgeted, meta) =
                apply_token_budget(response.results, max_tokens, params.truncation_strategy);
            response.results = budgeted;
            response.meta = Some(meta);
        }

        Ok(response)
    }

    /// Deletes all vector index entries in `namespace` (or the client's default namespace).
    ///
    /// Encrypted blobs on Walrus remain immutable; use `restore` to re-index them if needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `namespace` is invalid or relayer errors on failure.
    pub async fn forget(&self, namespace: Option<&str>) -> Result<ForgetResult> {
        let resolved_ns = self.resolve_namespace(namespace)?;

        self.signed_request(
            "POST",
            "/api/forget",
            Some(&ForgetWireBody {
                namespace: &resolved_ns,
            }),
            &[200],
            SignedCallOpts {
                include_seal_session: false,
                timeout: self.0.request_timeout,
            },
        )
        .await
    }

    /// Generates an embedding vector for `text` via `POST /api/embed` without storing a memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `text` is blank or relayer errors on failure.
    pub async fn embed(&self, text: &str) -> Result<EmbedResult> {
        validate_non_blank(text, "text")?;

        self.signed_request(
            "POST",
            "/api/embed",
            Some(&EmbedWireBody { text }),
            &[200],
            SignedCallOpts {
                include_seal_session: false,
                timeout: self.0.request_timeout,
            },
        )
        .await
    }

    /// Extracts atomic facts from conversation `text` via `POST /api/analyze` and enqueues
    /// background `remember` jobs for each fact.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `text` is blank or `opts.occurred_at` is not
    /// a valid timezone-aware RFC-3339 timestamp.
    pub async fn analyze(&self, text: &str, opts: &AnalyzeOptions) -> Result<AnalyzeResult> {
        validate_non_blank(text, "text")?;
        let resolved_ns = self.resolve_namespace(opts.namespace.as_deref())?;
        let wire_occurred_at = opts
            .occurred_at
            .as_deref()
            .map(normalize_occurred_at)
            .transpose()?;

        let mut res: AnalyzeResult = self
            .signed_request(
                "POST",
                "/api/analyze",
                Some(&AnalyzeWireBody {
                    text,
                    namespace: &resolved_ns,
                    occurred_at: wire_occurred_at.as_deref(),
                }),
                &[200, 202],
                SignedCallOpts {
                    include_seal_session: true,
                    timeout: DEFAULT_ANALYZE_TIMEOUT,
                },
            )
            .await?;

        if res.fact_count == 0 && !res.facts.is_empty() {
            res.fact_count = res.facts.len();
        }
        Ok(res)
    }

    /// Extracts facts from `text` and waits until every enqueued fact job reaches a terminal state.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] or relayer/polling errors.
    pub async fn analyze_and_wait(
        &self,
        text: &str,
        opts: &AnalyzeOptions,
        wait: &WaitOptions,
    ) -> Result<AnalyzeWaitResult> {
        let resolved_ns = self.resolve_namespace(opts.namespace.as_deref())?;
        let accepted = self.analyze(text, opts).await?;
        let namespaces = vec![resolved_ns; accepted.job_ids.len()];
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

    /// Recalls relevant memories and asks the relayer LLM to answer `question`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `question` is blank, `opts.limit == 0`, or
    /// `opts.scoring_weights` are invalid.
    pub async fn ask(&self, question: &str, opts: &AskOptions) -> Result<AskResult> {
        validate_non_blank(question, "question")?;
        validate_positive_limit(opts.limit, "limit")?;
        if let Some(weights) = &opts.scoring_weights {
            weights.validate()?;
        }
        let resolved_ns = self.resolve_namespace(opts.namespace.as_deref())?;

        self.signed_request(
            "POST",
            "/api/ask",
            Some(&AskWireBody {
                question,
                limit: opts.limit,
                namespace: &resolved_ns,
                scoring_weights: opts.scoring_weights.as_ref(),
            }),
            &[200],
            SignedCallOpts {
                include_seal_session: true,
                timeout: self.0.request_timeout,
            },
        )
        .await
    }

    /// Rebuilds missing vector index entries for `namespace` from on-chain Walrus blobs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `namespace` is invalid or `limit == 0`.
    pub async fn restore(&self, namespace: &str, limit: usize) -> Result<RestoreResult> {
        validate_namespace(namespace)?;
        validate_positive_limit(limit, "limit")?;

        self.signed_request(
            "POST",
            "/api/restore",
            Some(&RestoreWireBody { namespace, limit }),
            &[200],
            SignedCallOpts {
                include_seal_session: true,
                timeout: DEFAULT_RESTORE_TIMEOUT,
            },
        )
        .await
    }

    // ============================================================
    // Owner-Scoped Inventory & Identity Reads
    // ============================================================

    /// Lists namespaces belonging to this account with cursor pagination (`GET /v1/owners/{owner}/namespaces`).
    ///
    /// Always paginate using [`NamespacesPage::has_more`] rather than page length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `opts.limit == Some(0)` or relayer errors.
    pub async fn list_namespaces(&self, opts: &ListNamespacesOptions) -> Result<NamespacesPage> {
        if let Some(limit) = opts.limit {
            validate_positive_limit(limit, "limit")?;
        }
        let owner = self.resolve_owner().await?;
        let query = build_owner_read_query(opts.cursor.as_deref(), opts.limit);
        let path = if query.is_empty() {
            format!("/v1/owners/{owner}/namespaces")
        } else {
            format!("/v1/owners/{owner}/namespaces?{query}")
        };

        self.signed_request::<NamespacesPage, ()>(
            "GET",
            &path,
            None,
            &[200],
            SignedCallOpts {
                include_seal_session: false,
                timeout: self.0.request_timeout,
            },
        )
        .await
    }

    /// Lists indexed memory metadata entries (`GET /v1/owners/{owner}/memories`).
    ///
    /// When `opts.namespace` is set, filtering is applied client-side while preserving
    /// [`MemoriesPage::has_more`] and [`MemoriesPage::next_cursor`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `opts.limit == Some(0)` or `opts.namespace`
    /// is empty/invalid.
    pub async fn list_memories(&self, opts: &ListMemoriesOptions) -> Result<MemoriesPage> {
        if let Some(limit) = opts.limit {
            validate_positive_limit(limit, "limit")?;
        }
        if let Some(ns) = &opts.namespace {
            validate_namespace(ns)?;
        }

        let owner = self.resolve_owner().await?;
        let query = build_owner_read_query(opts.cursor.as_deref(), opts.limit);
        let path = if query.is_empty() {
            format!("/v1/owners/{owner}/memories")
        } else {
            format!("/v1/owners/{owner}/memories?{query}")
        };

        let mut page: MemoriesPage = self
            .signed_request::<MemoriesPage, ()>(
                "GET",
                &path,
                None,
                &[200],
                SignedCallOpts {
                    include_seal_session: false,
                    timeout: self.0.request_timeout,
                },
            )
            .await?;

        if let Some(ns) = &opts.namespace {
            page.memories.retain(|m| &m.namespace_id == ns);
            page.deleted.retain(|d| &d.namespace_id == ns);
        }

        Ok(page)
    }

    /// Resolves the authenticated `account_id`, `owner`, and `package_id` via `GET /api/whoami`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`] or relayer/auth errors.
    pub async fn whoami(&self) -> Result<WhoamiResult> {
        self.signed_request::<WhoamiResult, ()>(
            "GET",
            "/api/whoami",
            None,
            &[200],
            SignedCallOpts {
                include_seal_session: false,
                timeout: self.0.request_timeout,
            },
        )
        .await
    }

    // ============================================================
    // Manual Mode (Client-Side SEAL + Embedding)
    // ============================================================

    /// Uploads pre-encrypted SEAL ciphertext (`encrypted_data` Base64) and a pre-computed
    /// `vector` via `POST /api/remember/manual` without sending `x-seal-session`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `encrypted_data` is blank or `vector` is
    /// empty or contains non-finite values.
    pub async fn remember_manual(
        &self,
        opts: &RememberManualOptions,
    ) -> Result<RememberManualResult> {
        validate_non_blank(&opts.encrypted_data, "encrypted_data")?;
        validate_vector(&opts.vector)?;
        let resolved_ns = self.resolve_namespace(opts.namespace.as_deref())?;

        self.signed_request(
            "POST",
            "/api/remember/manual",
            Some(&RememberManualWireBody {
                encrypted_data: &opts.encrypted_data,
                vector: &opts.vector,
                namespace: &resolved_ns,
            }),
            &[200],
            SignedCallOpts {
                include_seal_session: false,
                timeout: self.0.request_timeout,
            },
        )
        .await
    }

    /// Searches by pre-computed query `vector` via `POST /api/recall/manual` and returns
    /// matching `blob_id` and cosine distance pairs without sending `x-seal-session`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `vector` is empty/non-finite, `limit == 0`,
    /// or `scoring_weights` are invalid.
    pub async fn recall_manual(&self, opts: &RecallManualOptions) -> Result<RecallManualResult> {
        validate_vector(&opts.vector)?;
        validate_positive_limit(opts.limit, "limit")?;
        if let Some(weights) = &opts.scoring_weights {
            weights.validate()?;
        }
        let resolved_ns = self.resolve_namespace(opts.namespace.as_deref())?;

        self.signed_request(
            "POST",
            "/api/recall/manual",
            Some(&RecallManualWireBody {
                vector: &opts.vector,
                limit: opts.limit,
                namespace: &resolved_ns,
                scoring_weights: opts.scoring_weights.as_ref(),
            }),
            &[200],
            SignedCallOpts {
                include_seal_session: false,
                timeout: self.0.request_timeout,
            },
        )
        .await
    }

    // ============================================================
    // Unauthenticated Health & Compatibility Probes
    // ============================================================

    /// Checks relayer liveness and readiness via unauthenticated `GET /health`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Destroyed`], [`Error::Server`], [`Error::Transport`], or [`Error::Json`].
    pub async fn health(&self) -> Result<HealthResult> {
        self.check_not_destroyed()?;
        let url = format!("{}/health", self.0.server_url);
        let resp = self
            .0
            .http
            .get(&url)
            .timeout(self.0.preflight_timeout)
            .send()
            .await
            .map_err(|err| map_reqwest_error(err, "GET", "/health", self.0.preflight_timeout))?;
        self.check_not_destroyed()?;

        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let raw = resp.text().await.map_err(|err| Error::Transport {
            context: "reading GET /health response",
            source: Box::new(err),
        })?;

        if status != 200 {
            return Err(classify_http_error(status, &headers, &raw));
        }
        parse_json_str(&raw, "GET /health")
    }

    /// Fetches and validates the relayer compatibility contract (`GET /version`, falling back
    /// to `GET /health` on `404`/`405`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Incompatible`] when the relayer's `apiVersion` major does not match
    /// [`SUPPORTED_API_MAJOR`] (`1`), or transport/server errors if the probe fails.
    pub async fn compatibility(&self) -> Result<VersionInfo> {
        self.ensure_compatible_relayer().await
    }

    // ============================================================
    // Internal: Preflights, SEAL Session, & Signed HTTP
    // ============================================================

    fn check_not_destroyed(&self) -> Result<()> {
        if self.is_destroyed() {
            Err(Error::Destroyed)
        } else {
            Ok(())
        }
    }

    fn resolve_namespace(&self, override_ns: Option<&str>) -> Result<String> {
        let ns = override_ns.unwrap_or(&self.0.namespace);
        validate_namespace(ns)?;
        Ok(ns.to_owned())
    }

    fn normalize_bulk_items(&self, items: &[RememberBulkItem]) -> Result<Vec<(String, String)>> {
        if items.is_empty() {
            return Err(Error::InvalidArgument("items must not be empty".to_owned()));
        }
        if items.len() > MAX_BULK_ITEMS {
            return Err(Error::InvalidArgument(format!(
                "items length {} exceeds maximum of {MAX_BULK_ITEMS} per bulk request",
                items.len()
            )));
        }
        let mut out = Vec::with_capacity(items.len());
        for (idx, item) in items.iter().enumerate() {
            if crate::types::is_blank_or_zero_width(&item.text) {
                return Err(Error::InvalidArgument(format!(
                    "items[{idx}].text cannot be empty or whitespace-only"
                )));
            }
            let ns = self.resolve_namespace(item.namespace.as_deref())?;
            out.push((item.text.clone(), ns));
        }
        Ok(out)
    }

    fn get_or_insert_pending_key(
        &self,
        identity: &str,
        generate: impl FnOnce() -> String,
    ) -> Result<String> {
        self.check_not_destroyed()?;
        let mut caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = caches.pending_remember_keys.get(identity) {
            return Ok(existing.clone());
        }
        let fresh = generate();
        caches
            .pending_remember_keys
            .insert(identity.to_owned(), fresh.clone());
        Ok(fresh)
    }

    fn clear_pending_key(&self, identity: &str) {
        let mut caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
        caches.pending_remember_keys.remove(identity);
    }

    fn poll_deadline(&self, overall_deadline: Instant) -> Duration {
        let remaining = overall_deadline.saturating_duration_since(Instant::now());
        remaining
            .min(self.0.request_timeout)
            .max(Duration::from_millis(1))
    }

    async fn ensure_compatible_relayer(&self) -> Result<VersionInfo> {
        self.check_not_destroyed()?;
        {
            let caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(cached) = &caches.version_info {
                return Ok(cached.clone());
            }
        }

        let _gate = self.0.compat_gate.lock().await;
        self.check_not_destroyed()?;
        {
            let caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(cached) = &caches.version_info {
                return Ok(cached.clone());
            }
        }

        let version_url = format!("{}/version", self.0.server_url);
        let resp = self
            .0
            .http
            .get(&version_url)
            .timeout(self.0.preflight_timeout)
            .send()
            .await
            .map_err(|err| map_reqwest_error(err, "GET", "/version", self.0.preflight_timeout))?;
        self.check_not_destroyed()?;

        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let raw = resp.text().await.map_err(|err| Error::Transport {
            context: "reading GET /version response",
            source: Box::new(err),
        })?;

        let info: VersionInfo = if status == 200 {
            parse_json_str(&raw, "GET /version")?
        } else if status == 404 || status == 405 {
            let health_url = format!("{}/health", self.0.server_url);
            let h_resp = self
                .0
                .http
                .get(&health_url)
                .timeout(self.0.preflight_timeout)
                .send()
                .await
                .map_err(|err| {
                    map_reqwest_error(err, "GET", "/health", self.0.preflight_timeout)
                })?;
            self.check_not_destroyed()?;
            let h_status = h_resp.status().as_u16();
            let h_headers = h_resp.headers().clone();
            let h_raw = h_resp.text().await.map_err(|err| Error::Transport {
                context: "reading GET /health fallback response",
                source: Box::new(err),
            })?;
            if h_status != 200 {
                return Err(classify_http_error(h_status, &h_headers, &h_raw));
            }
            parse_json_str(&h_raw, "GET /health")?
        } else {
            return Err(classify_http_error(status, &headers, &raw));
        };

        validate_compatibility(&info, &self.0.server_url)?;
        self.check_not_destroyed()?;
        {
            let mut caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            caches.version_info = Some(info.clone());
        }
        Ok(info)
    }

    async fn resolve_owner(&self) -> Result<String> {
        self.check_not_destroyed()?;
        {
            let caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(owner) = &caches.owner_address {
                return Ok(owner.clone());
            }
        }

        let _gate = self.0.owner_gate.lock().await;
        self.check_not_destroyed()?;
        {
            let caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(owner) = &caches.owner_address {
                return Ok(owner.clone());
            }
        }

        let stats: StatsWireResp = self
            .signed_request(
                "POST",
                "/api/stats",
                Some(&StatsWireReq {
                    namespace: &self.0.namespace,
                }),
                &[200],
                SignedCallOpts {
                    include_seal_session: false,
                    timeout: self.0.request_timeout,
                },
            )
            .await?;

        if stats.owner.trim().is_empty() {
            return Err(Error::json_msg(
                "POST /api/stats",
                "relayer returned empty owner address",
            ));
        }

        self.check_not_destroyed()?;
        {
            let mut caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            caches.owner_address = Some(stats.owner.clone());
        }
        Ok(stats.owner)
    }

    async fn build_seal_session(&self) -> Result<String> {
        self.check_not_destroyed()?;
        let now_ms = now_epoch_ms();
        {
            let caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(entry) = &caches.session
                && now_ms < entry.expires_at_ms
            {
                return Ok(entry.header_value.clone());
            }
        }

        let _gate = self.0.session_gate.lock().await;
        self.check_not_destroyed()?;
        let now_ms = now_epoch_ms();
        let (cached_cfg, already_verified) = {
            let caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(entry) = &caches.session
                && now_ms < entry.expires_at_ms
            {
                return Ok(entry.header_value.clone());
            }
            (caches.server_config.clone(), caches.package_verified)
        };

        let cfg = if let Some(c) = cached_cfg {
            c
        } else {
            let fetched = self.fetch_server_config().await?;
            self.check_not_destroyed()?;
            let mut caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            caches.server_config = Some(fetched.clone());
            fetched
        };

        if !already_verified {
            self.verify_package_version_one(&cfg).await?;
            self.check_not_destroyed()?;
            let mut caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            caches.package_verified = true;
        }

        let ephemeral_signing = SigningKey::generate(&mut OsRng);
        let ephemeral_pubkey = ephemeral_signing.verifying_key().to_bytes();
        let ephemeral_seed = Zeroizing::new(ephemeral_signing.to_bytes());
        let session_key_bech32 = encode_sui_private_key(&ephemeral_seed)?;

        #[expect(
            clippy::cast_possible_truncation,
            reason = "Unix epoch milliseconds fit in u64 for millions of years"
        )]
        let creation_time_ms = now_epoch_ms() as u64;
        let personal_msg = build_seal_session_personal_message(
            &cfg.package_id,
            SEAL_SESSION_TTL_MIN,
            creation_time_ms,
            &ephemeral_pubkey,
        )?;

        let (delegate_sui_address, personal_sig) = {
            let guard = self.0.signer.read().unwrap_or_else(PoisonError::into_inner);
            let signer = guard.as_ref().ok_or(Error::Destroyed)?;
            (
                signer.sui_address().to_owned(),
                sign_sui_personal_message(&personal_msg, signer),
            )
        };

        let exported = ExportedSessionKey {
            address: &delegate_sui_address,
            package_id: &cfg.package_id,
            mvr_name: None,
            creation_time_ms,
            ttl_min: SEAL_SESSION_TTL_MIN,
            personal_message_signature: &personal_sig,
            session_key: &session_key_bech32,
        };

        let json_bytes = serde_json::to_vec(&exported).map_err(|err| Error::Json {
            context: "serializing ExportedSessionKey".to_owned(),
            source: Box::new(err),
        })?;
        let header_value = BASE64_STANDARD.encode(json_bytes);
        let expires_at_ms = now_epoch_ms()
            .saturating_add(u128::from(SEAL_SESSION_TTL_MIN) * 60_000)
            .saturating_sub(SEAL_SESSION_SAFETY_MARGIN_MS);

        self.check_not_destroyed()?;
        {
            let mut caches = self.0.caches.lock().unwrap_or_else(PoisonError::into_inner);
            caches.session = Some(SessionCacheEntry {
                header_value: header_value.clone(),
                expires_at_ms,
            });
        }
        Ok(header_value)
    }

    async fn fetch_server_config(&self) -> Result<ServerConfig> {
        let url = format!("{}/config", self.0.server_url);
        let resp = self
            .0
            .http
            .get(&url)
            .timeout(self.0.preflight_timeout)
            .send()
            .await
            .map_err(|err| map_reqwest_error(err, "GET", "/config", self.0.preflight_timeout))?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(Error::SealSession(format!(
                "GET /config returned HTTP {status}"
            )));
        }

        let raw = resp
            .text()
            .await
            .map_err(|err| Error::SealSession(format!("reading GET /config failed: {err}")))?;
        let body: serde_json::Value =
            serde_json::from_str(&raw).map_err(|err| Error::SealSession(err.to_string()))?;

        let package_id = body
            .get("packageId")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| Error::SealSession("GET /config response missing packageId".to_owned()))?
            .to_owned();

        let network = body
            .get("network")
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| Error::SealSession("GET /config response missing network".to_owned()))?
            .to_owned();

        let sui_rpc_url = body
            .get("suiRpcUrl")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        Ok(ServerConfig {
            package_id,
            network,
            sui_rpc_url,
        })
    }

    async fn verify_package_version_one(&self, cfg: &ServerConfig) -> Result<()> {
        let net = cfg.network.trim().to_ascii_lowercase();
        let is_public_graphql = matches!(net.as_str(), "mainnet" | "testnet" | "devnet");

        let version_str = if is_public_graphql {
            match self
                .fetch_package_version_graphql(&net, &cfg.package_id)
                .await
            {
                Ok(v) => v,
                Err(gql_err) => {
                    if let Some(rpc_url) = &cfg.sui_rpc_url {
                        self.fetch_package_version_jsonrpc(rpc_url, &cfg.package_id)
                            .await
                            .map_err(|_| gql_err)?
                    } else {
                        return Err(gql_err);
                    }
                }
            }
        } else if let Some(rpc_url) = &cfg.sui_rpc_url {
            self.fetch_package_version_jsonrpc(rpc_url, &cfg.package_id)
                .await?
        } else {
            return Err(Error::SealSession(format!(
                "no Sui read endpoint available for network {net:?}; GET /config carried no suiRpcUrl"
            )));
        };

        if version_str != "1" {
            return Err(Error::SealSession(format!(
                "SEAL package {} must be at object version 1 to build x-seal-session, got {version_str:?}",
                cfg.package_id
            )));
        }
        Ok(())
    }

    async fn fetch_package_version_graphql(
        &self,
        network: &str,
        package_id: &str,
    ) -> Result<String> {
        let graphql_url = format!("https://graphql.{network}.sui.io/graphql");
        let payload = serde_json::json!({
            "query": "query($a:SuiAddress!){object(address:$a){version}}",
            "variables": { "a": package_id },
        });
        let resp = self
            .0
            .http
            .post(&graphql_url)
            .json(&payload)
            .timeout(PACKAGE_VERSION_CHECK_TIMEOUT)
            .send()
            .await
            .map_err(|err| {
                Error::SealSession(format!(
                    "Sui GraphQL request to {graphql_url} failed: {err}"
                ))
            })?;

        if resp.status().as_u16() != 200 {
            return Err(Error::SealSession(format!(
                "Sui GraphQL returned HTTP {}",
                resp.status().as_u16()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|err| Error::SealSession(format!("invalid Sui GraphQL JSON: {err}")))?;

        let version_val = body.pointer("/data/object/version").ok_or_else(|| {
            Error::SealSession(format!(
                "Sui GraphQL could not resolve package {package_id}"
            ))
        })?;

        json_scalar_to_string(version_val).ok_or_else(|| {
            Error::SealSession(format!(
                "unexpected version value in Sui GraphQL response for {package_id}"
            ))
        })
    }

    async fn fetch_package_version_jsonrpc(
        &self,
        sui_rpc_url: &str,
        package_id: &str,
    ) -> Result<String> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sui_getObject",
            "params": [
                package_id,
                { "showBcs": false, "showContent": false, "showType": false }
            ],
        });

        let resp = self
            .0
            .http
            .post(sui_rpc_url)
            .json(&payload)
            .timeout(PACKAGE_VERSION_CHECK_TIMEOUT)
            .send()
            .await
            .map_err(|err| Error::SealSession(format!("sui_getObject request failed: {err}")))?;

        if resp.status().as_u16() != 200 {
            return Err(Error::SealSession(format!(
                "sui_getObject returned HTTP {}",
                resp.status().as_u16()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|err| Error::SealSession(format!("invalid sui_getObject JSON: {err}")))?;

        let version_val = body
            .pointer("/result/data/version")
            .or_else(|| body.pointer("/result/object/version"))
            .ok_or_else(|| {
                Error::SealSession(format!(
                    "sui_getObject returned no object version for {package_id}"
                ))
            })?;

        json_scalar_to_string(version_val).ok_or_else(|| {
            Error::SealSession(format!(
                "unexpected version type in sui_getObject response for {package_id}"
            ))
        })
    }

    async fn signed_request<R, B>(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&B>,
        accepted_statuses: &[u16],
        opts: SignedCallOpts,
    ) -> Result<R>
    where
        R: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.check_not_destroyed()?;
        self.ensure_compatible_relayer().await?;
        self.check_not_destroyed()?;

        let seal_session = if opts.include_seal_session {
            Some(self.build_seal_session().await?)
        } else {
            None
        };
        self.check_not_destroyed()?;

        let body_bytes: Vec<u8> = if method == "GET" {
            Vec::new()
        } else if let Some(payload) = body {
            serde_json::to_vec(payload).map_err(|err| Error::Json {
                context: format!("serializing {method} {path} body"),
                source: Box::new(err),
            })?
        } else {
            b"{}".to_vec()
        };

        let timestamp = (now_epoch_ms() / 1_000).to_string();
        let nonce = uuid::Uuid::new_v4().to_string();
        let canonical = canonical_message(
            &timestamp,
            method,
            path,
            &body_bytes,
            &nonce,
            &self.0.account_id,
        );

        let (public_key_hex, signature_hex) = {
            let guard = self.0.signer.read().unwrap_or_else(PoisonError::into_inner);
            let signer = guard.as_ref().ok_or(Error::Destroyed)?;
            (
                signer.public_key_hex().to_owned(),
                signer.sign_hex(canonical.as_bytes()),
            )
        };

        let url = format!("{}{path}", self.0.server_url);
        let mut req = match method {
            "GET" => self.0.http.get(&url),
            "POST" => self
                .0
                .http
                .post(&url)
                .header("content-type", "application/json")
                .body(body_bytes),
            _ => {
                return Err(Error::InvalidArgument(format!(
                    "unsupported HTTP method {method}"
                )));
            }
        };

        req = req
            .header("x-public-key", public_key_hex)
            .header("x-signature", signature_hex)
            .header("x-timestamp", timestamp)
            .header("x-nonce", nonce)
            .header("x-account-id", &self.0.account_id)
            .timeout(opts.timeout);

        if let Some(session_hdr) = seal_session {
            req = req.header("x-seal-session", session_hdr);
        }

        let resp = req
            .send()
            .await
            .map_err(|err| map_reqwest_error(err, method, path, opts.timeout))?;
        self.check_not_destroyed()?;

        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let raw_body = resp
            .text()
            .await
            .map_err(|err| map_reqwest_error(err, method, path, opts.timeout))?;

        if !accepted_statuses.contains(&status) {
            return Err(classify_http_error(status, &headers, &raw_body));
        }

        let context = format!("{method} {path} (HTTP {status})");
        parse_json_str(&raw_body, &context)
    }
}

// ============================================================
// Helper Functions
// ============================================================

fn normalize_server_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(Error::InvalidUrl("server_url cannot be empty".to_owned()));
    }
    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|err| Error::InvalidUrl(format!("malformed URL {trimmed:?}: {err}")))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => {
            return Err(Error::InvalidUrl(format!(
                "unsupported URL scheme {other:?}; expected \"https\" or \"http\""
            )));
        }
    }
    if parsed.host_str().is_none() {
        return Err(Error::InvalidUrl(format!(
            "server_url {trimmed:?} is missing a host"
        )));
    }
    Ok(trimmed.to_owned())
}

fn validate_compatibility(info: &VersionInfo, server_url: &str) -> Result<()> {
    let api_ver = info.api_version.trim();
    if api_ver.is_empty() {
        return Ok(());
    }
    let major_str = api_ver.split('.').next().unwrap_or_default();
    let Ok(major) = major_str.parse::<u64>() else {
        return Err(Error::Incompatible {
            message: format!("relayer at {server_url} reported malformed apiVersion {api_ver:?}"),
        });
    };
    if major != SUPPORTED_API_MAJOR {
        return Err(Error::Incompatible {
            message: format!(
                "relayer at {server_url} speaks API v{api_ver}, while memwal Rust SDK {SDK_VERSION} supports API major v{SUPPORTED_API_MAJOR}"
            ),
        });
    }

    if let Some(min_rust) = &info.min_supported_sdk.rust {
        let min_trimmed = min_rust.trim();
        if !min_trimmed.is_empty()
            && let (Some(curr), Some(floor)) =
                (parse_semver(SDK_VERSION), parse_semver(min_trimmed))
            && curr < floor
        {
            return Err(Error::Incompatible {
                message: format!(
                    "relayer at {server_url} requires memwal Rust SDK >= {min_trimmed}, current version is {SDK_VERSION}"
                ),
            });
        }
    }

    Ok(())
}

fn parse_semver(raw: &str) -> Option<(u64, u64, u64)> {
    let core = raw.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

fn json_scalar_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn parse_json_str<T: DeserializeOwned>(raw: &str, context: &str) -> Result<T> {
    if raw.trim().is_empty() {
        return Err(Error::json_msg(
            context,
            "response body was empty; expected JSON",
        ));
    }
    serde_json::from_str(raw).map_err(|err| Error::Json {
        context: context.to_owned(),
        source: Box::new(err),
    })
}

fn map_reqwest_error(err: reqwest::Error, method: &str, path: &str, timeout: Duration) -> Error {
    if err.is_timeout() {
        Error::RequestTimeout {
            method: method.to_owned(),
            path: path.to_owned(),
            elapsed: timeout,
        }
    } else {
        Error::Transport {
            context: "sending HTTP request",
            source: Box::new(err),
        }
    }
}

fn classify_http_error(status: u16, headers: &HeaderMap, raw_body: &str) -> Error {
    let auth_header = headers
        .get("x-auth-error")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);

    let (parsed_msg, parsed_code, body_retry_after) = extract_error_fields(raw_body);
    let sanitized_msg = redact_internal_urls(&parsed_msg);

    if status == 426 {
        return Error::Incompatible {
            message: sanitized_msg,
        };
    }

    if status == 401 {
        let lower_hdr = auth_header.unwrap_or_default().to_ascii_lowercase();
        let lower_msg = sanitized_msg.to_ascii_lowercase();
        if lower_hdr.contains("timestamp")
            || lower_hdr.contains("clock")
            || lower_msg.contains("timestamp out of range")
            || lower_msg.contains("clock drift")
        {
            return Error::ClockDrift {
                message: format!(
                    "{sanitized_msg} (synchronize local system clock via NTP and retry)"
                ),
            };
        }
    }

    if status == 401 || status == 403 {
        let code = parsed_code.or_else(|| auth_header.map(ToOwned::to_owned));
        return Error::AuthRejected {
            status,
            code,
            message: sanitized_msg,
        };
    }

    if status == 429 {
        let header_retry = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v > 0.0)
            .map(Duration::from_secs_f64);
        let retry_after = header_retry.or(body_retry_after);
        return Error::RateLimited {
            retry_after,
            job_ids: Vec::new(),
            message: sanitized_msg,
        };
    }

    Error::Server {
        status,
        code: parsed_code,
        message: sanitized_msg,
    }
}

fn extract_error_fields(raw_body: &str) -> (String, Option<String>, Option<Duration>) {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(raw_body)
    {
        let msg = map
            .get("error")
            .or_else(|| map.get("message"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map_or_else(|| truncate_body(raw_body), ToOwned::to_owned);

        let code = map
            .get("code")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);

        let retry = map
            .get("retry_after_seconds")
            .and_then(serde_json::Value::as_f64)
            .filter(|v| v.is_finite() && *v > 0.0)
            .map(Duration::from_secs_f64);

        return (msg, code, retry);
    }

    (truncate_body(raw_body), None, None)
}

fn truncate_body(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "empty error response".to_owned();
    }
    let max_chars = 512;
    let count = trimmed.chars().count();
    if count <= max_chars {
        trimmed.to_owned()
    } else {
        let prefix: String = trimmed.chars().take(max_chars).collect();
        format!("{prefix}...")
    }
}

fn redact_internal_urls(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for token in input.split_inclusive(char::is_whitespace) {
        let trimmed = token.trim_end();
        let suffix = &token[trimmed.len()..];
        let lower = trimmed.to_ascii_lowercase();
        let is_internal = (lower.starts_with("http://") || lower.starts_with("https://"))
            && (lower.contains("localhost")
                || lower.contains("127.0.0.1")
                || lower.contains(".internal"));
        if is_internal {
            out.push_str("[redacted-url]");
            out.push_str(suffix);
        } else {
            out.push_str(token);
        }
    }
    out
}

fn parse_job_status_value(job_id: &str, value: &serde_json::Value) -> RememberJobStatus {
    let Some(obj) = value.as_object() else {
        return RememberJobStatus {
            job_id: job_id.to_owned(),
            status: "not_found".to_owned(),
            owner: None,
            namespace: None,
            blob_id: None,
            error: Some(format!("remember job not found: {job_id}")),
        };
    };

    let Some(status) = obj.get("status").and_then(serde_json::Value::as_str) else {
        let err_msg = obj
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || format!("remember job not found: {job_id}"),
                ToOwned::to_owned,
            );
        return RememberJobStatus {
            job_id: job_id.to_owned(),
            status: "not_found".to_owned(),
            owner: None,
            namespace: None,
            blob_id: None,
            error: Some(err_msg),
        };
    };

    RememberJobStatus {
        job_id: obj
            .get("job_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(job_id)
            .to_owned(),
        status: status.to_owned(),
        owner: obj
            .get("owner")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        namespace: obj
            .get("namespace")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        blob_id: obj
            .get("blob_id")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
        error: obj
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
    }
}

fn next_poll_sleep(
    poll_interval: Duration,
    attempt: &mut u32,
    retry_after_delay: &mut Option<Duration>,
) -> Duration {
    if let Some(ra) = retry_after_delay.take() {
        ra
    } else {
        let d = polling_delay(poll_interval, *attempt);
        *attempt = attempt.saturating_add(1);
        d
    }
}

fn polling_delay(base: Duration, attempt: u32) -> Duration {
    let max_ms = u128::from(MAX_BACKOFF_DELAY_MS);
    let mut scaled_ms = base.as_millis().clamp(1, max_ms);
    for _ in 0..attempt.min(16) {
        scaled_ms = (scaled_ms.saturating_mul(3) / 2).min(max_ms);
    }
    let jitter_bps = u128::from(OsRng.gen_range(800_u32..=1_200_u32));
    let jittered_ms = ((scaled_ms.saturating_mul(jitter_bps) + 500) / 1_000).clamp(1, max_ms);
    let delay_ms = u64::try_from(jittered_ms).unwrap_or(MAX_BACKOFF_DELAY_MS);
    Duration::from_millis(delay_ms)
}

fn bulk_request_identity(items: &[(String, String)]) -> String {
    let mut buf = String::from("bulk\0");
    for (idx, (text, ns)) in items.iter().enumerate() {
        if idx > 0 {
            buf.push_str("\0\0");
        }
        buf.push_str(ns);
        buf.push('\0');
        buf.push_str(text);
    }
    buf
}

fn settle_bulk_item(
    item: &RememberBulkStatusItem,
    job_ids: &[String],
    namespaces: &[String],
    default_namespace: &str,
    results: &mut [RememberBulkItemResult],
    pending: &mut HashSet<String>,
    last_seen: &mut HashMap<String, RememberBulkStatusItem>,
) {
    last_seen.insert(item.job_id.clone(), item.clone());
    let is_terminal = matches!(item.status.as_str(), "done" | "failed" | "not_found");

    for (idx, jid) in job_ids.iter().enumerate() {
        if jid != &item.job_id {
            continue;
        }
        let resolved_ns = namespaces
            .get(idx)
            .cloned()
            .or_else(|| item.namespace.clone())
            .unwrap_or_else(|| default_namespace.to_owned());

        if !is_terminal {
            results[idx].namespace = resolved_ns;
            continue;
        }

        if item.status == "done" {
            results[idx] = RememberBulkItemResult {
                id: item.job_id.clone(),
                blob_id: item.blob_id.clone().unwrap_or_default(),
                status: "done".to_owned(),
                namespace: resolved_ns,
                error: None,
            };
        } else {
            let err_text = if item.status == "not_found" {
                "job not found".to_owned()
            } else {
                redact_internal_urls(item.error.as_deref().unwrap_or("unknown error"))
            };
            results[idx] = RememberBulkItemResult {
                id: item.job_id.clone(),
                blob_id: String::new(),
                status: "failed".to_owned(),
                namespace: resolved_ns,
                error: Some(err_text),
            };
        }
    }

    if is_terminal {
        pending.remove(&item.job_id);
    }
}

fn build_owner_read_query(cursor: Option<&str>, limit: Option<usize>) -> String {
    let mut parts = Vec::with_capacity(2);
    if let Some(c) = cursor {
        let encoded = utf8_percent_encode(c, QUERY_ENCODE_SET);
        parts.push(format!("updated_after={encoded}"));
    }
    if let Some(l) = limit {
        parts.push(format!("limit={l}"));
    }
    parts.join("&")
}

fn init_bulk_timeout_placeholders(
    job_ids: &[String],
    namespaces: &[String],
    default_namespace: &str,
    timeout_ms: u128,
) -> Vec<RememberBulkItemResult> {
    job_ids
        .iter()
        .enumerate()
        .map(|(idx, id)| RememberBulkItemResult {
            id: id.clone(),
            blob_id: String::new(),
            status: "timeout".to_owned(),
            namespace: namespaces
                .get(idx)
                .cloned()
                .unwrap_or_else(|| default_namespace.to_owned()),
            error: Some(format!("polling timed out after {timeout_ms}ms")),
        })
        .collect()
}

#[expect(
    clippy::too_many_arguments,
    reason = "private bulk-wait finalizer consolidating settled and timed-out outcomes"
)]
fn finalize_bulk_wait_result(
    job_ids: &[String],
    mut results: Vec<RememberBulkItemResult>,
    pending: &HashSet<String>,
    last_seen: &HashMap<String, RememberBulkStatusItem>,
    timeout_ms: u128,
    answered: bool,
    last_refusal: Option<u16>,
    saw_rate_limit: bool,
) -> RememberBulkResult {
    for (idx, job_id) in job_ids.iter().enumerate() {
        if !pending.contains(job_id) {
            continue;
        }
        let base_msg = if let Some(seen) = last_seen.get(job_id) {
            if let Some(err_text) = &seen.error {
                format!(
                    "still {} after {timeout_ms}ms: {}",
                    seen.status,
                    redact_internal_urls(err_text)
                )
            } else {
                format!("still {} after {timeout_ms}ms", seen.status)
            }
        } else if answered {
            "not in relayer status answer; item may not be stored".to_owned()
        } else if let Some(code) = last_refusal {
            format!("no status read succeeded (last HTTP {code}); item may not be stored")
        } else {
            format!("polling timed out after {timeout_ms}ms")
        };

        let names_429 = !answered && !last_seen.contains_key(job_id) && last_refusal == Some(429);
        let final_msg = if saw_rate_limit && !names_429 {
            format!("{base_msg}; wait hit rate limit (429)")
        } else {
            base_msg
        };
        results[idx].error = Some(final_msg);
    }

    let succeeded = results.iter().filter(|r| r.status == "done").count();
    let failed = results.iter().filter(|r| r.status == "failed").count();
    let timed_out = results.iter().filter(|r| r.status == "timeout").count();

    RememberBulkResult {
        total: results.len(),
        results,
        succeeded,
        failed,
        timed_out,
    }
}

// ============================================================
// Private Wire Serialization Payloads
// ============================================================

#[derive(Serialize)]
struct RememberWireBody<'a> {
    text: &'a str,
    namespace: &'a str,
    idempotency_key: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    dedupe: bool,
}

#[derive(Serialize)]
struct BulkWireItem<'a> {
    text: &'a str,
    namespace: &'a str,
}

#[derive(Serialize)]
struct BulkRememberWireBody<'a> {
    items: Vec<BulkWireItem<'a>>,
    idempotency_key: &'a str,
}

#[derive(Serialize)]
struct BulkStatusWireBody<'a> {
    job_ids: &'a [String],
}

#[derive(Serialize)]
struct RecallWireBody<'a> {
    query: &'a str,
    limit: usize,
    namespace: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scoring_weights: Option<&'a crate::types::ScoringWeights>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort: Option<crate::types::RecallSort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline_ms: Option<u64>,
}

#[derive(Serialize)]
struct ForgetWireBody<'a> {
    namespace: &'a str,
}

#[derive(Serialize)]
struct EmbedWireBody<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct AnalyzeWireBody<'a> {
    text: &'a str,
    namespace: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurred_at: Option<&'a str>,
}

#[derive(Serialize)]
struct AskWireBody<'a> {
    question: &'a str,
    limit: usize,
    namespace: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scoring_weights: Option<&'a crate::types::ScoringWeights>,
}

#[derive(Serialize)]
struct RestoreWireBody<'a> {
    namespace: &'a str,
    limit: usize,
}

#[derive(Serialize)]
struct RememberManualWireBody<'a> {
    encrypted_data: &'a str,
    vector: &'a [f32],
    namespace: &'a str,
}

#[derive(Serialize)]
struct RecallManualWireBody<'a> {
    vector: &'a [f32],
    limit: usize,
    namespace: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    scoring_weights: Option<&'a crate::types::ScoringWeights>,
}

#[derive(Serialize)]
struct StatsWireReq<'a> {
    namespace: &'a str,
}

#[derive(serde::Deserialize)]
struct StatsWireResp {
    #[serde(default)]
    owner: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportedSessionKey<'a> {
    address: &'a str,
    package_id: &'a str,
    mvr_name: Option<&'a str>,
    creation_time_ms: u64,
    ttl_min: u64,
    personal_message_signature: &'a str,
    session_key: &'a str,
}

use base64::Engine as _;
use serde::Deserialize;
use sui_rpc::proto::sui::rpc::v2::{
    open_signature::Reference, open_signature_body::Type as SignatureType, FunctionDescriptor,
    GetPackageRequest, OpenSignature, OpenSignatureBody, Package,
};
use sui_sdk_types::Address;

/// Verify that a given public key is registered as a delegate key
/// in the onchain MemWalAccount object.
///
/// Routes through gRPC when `grpc_client` is provided (opt-in via
/// SUI_GRPC_URL, mirrors the sidecar's write-path migration — JSON-RPC
/// sunsets 2026-07-31, and testnet's public JSON-RPC endpoint already
/// returns 404 today), otherwise falls back to the original Sui JSON-RPC
/// `sui_getObject` call below. The gRPC client is built once at startup
/// (AppState) and cloned here — clones share the underlying tonic channel.
///
/// Returns `Ok(owner_address)` if the key is found, `Err` otherwise.
pub async fn verify_delegate_key_onchain(
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    account_object_id: &str,
    public_key_bytes: &[u8],
    expected_type_origin_package_id: &str,
    get_object_attempts: u32,
) -> Result<String, OnchainVerifyError> {
    if let Some(grpc_client) = grpc_client {
        return verify_delegate_key_onchain_grpc(
            grpc_client.clone(),
            account_object_id,
            public_key_bytes,
            expected_type_origin_package_id,
            get_object_attempts,
        )
        .await;
    }

    // Build JSON-RPC request
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_getObject",
        "params": [
            account_object_id,
            { "showContent": true }
        ]
    });

    let request = http_client
        .post(rpc_url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .json(&body);
    let request = crate::observability::apply_request_id_header(request);
    let started = std::time::Instant::now();
    let response = request.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sui_rpc",
            "sui_getObject",
            "transport_error",
            started.elapsed(),
        );
        OnchainVerifyError::RpcError(format!("HTTP request failed: {}", e))
    })?;
    let status_label = response.status().as_u16().to_string();
    crate::observability::observe_external(
        "sui_rpc",
        "sui_getObject",
        &status_label,
        started.elapsed(),
    );

    let rpc_response: RpcResponse = parse_json_rpc_response(response, "sui_getObject").await?;

    if let Some(error) = rpc_response.error {
        return Err(OnchainVerifyError::RpcError(format!(
            "RPC error {}: {}",
            error.code, error.message
        )));
    }

    let result = rpc_response
        .result
        .ok_or_else(|| partial_get_object(PARTIAL_RPC_NO_RESULT))?;
    let content = require_get_object_content(result)?;

    // #398: reject foreign/lookalike objects — verify the Move type against the
    // configured immutable type-origin package id before trusting any field.
    ensure_memwal_account_type(
        content.object_type.as_deref(),
        expected_type_origin_package_id,
        account_object_id,
    )?;

    let fields = content
        .fields
        .ok_or_else(|| OnchainVerifyError::RpcError("Object has no fields".into()))?;

    // Extract owner address
    let owner = fields
        .get("owner")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing 'owner' field".into()))?
        .to_string();

    // Block deactivated accounts.
    // The onchain MemWalAccount has an `active: bool` field.
    // If false, reject immediately — even if the delegate key is valid.
    let active = json_account_active(&fields)?;
    if !active {
        tracing::warn!(
            "account {} is deactivated — rejecting delegate key auth",
            account_object_id
        );
        return Err(OnchainVerifyError::AccountDeactivated(format!(
            "Account {} has been deactivated",
            account_object_id
        )));
    }

    // Extract delegate_keys array
    let delegate_keys = fields
        .get("delegate_keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing 'delegate_keys' field".into()))?;

    // Convert our public key to the same format as stored onchain (Vec<u8> as JSON array)
    let pk_as_numbers: Vec<serde_json::Value> = public_key_bytes
        .iter()
        .map(|&b| serde_json::Value::Number(b.into()))
        .collect();

    // Search for matching delegate key
    for dk in delegate_keys {
        // Each delegate key is a struct with fields: { public_key, label, created_at }
        // The onchain representation has a "fields" wrapper
        let dk_fields = dk.get("fields").or(Some(dk)); // fallback if no "fields" wrapper

        if let Some(stored_key) = dk_fields.and_then(|f| f.get("public_key")) {
            // Compare as arrays of numbers
            if let Some(stored_arr) = stored_key.as_array() {
                if *stored_arr == pk_as_numbers {
                    tracing::info!("delegate key verified onchain, owner: {}", owner);
                    return Ok(owner);
                }
            }
        }
    }

    Err(OnchainVerifyError::KeyNotFound(format!(
        "Public key not found in {} delegate key(s) for account {}",
        delegate_keys.len(),
        account_object_id
    )))
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct DelegateKeyInfo {
    pub sui_address: String,
    pub label: String,
    pub created_at: u64,
}

// ============================================================
// Delegate keys — short-TTL in-memory cache (`/agents`)
// ============================================================
//
// Mirrors `sui/client.rs`'s `Timed<WalrusEpoch>` pattern used by
// `walrus_epoch()` — a value + fetch timestamp, refreshed once stale —
// per the design spec: "Cached with the same short TTL pattern as
// walrus_epoch() ... rather than left uncached". This is deliberately
// NOT the DB-backed `delegate_key_cache` table (`storage/db.rs`): that
// table caches a single verified public-key -> account mapping on the
// hot per-request auth path; this caches the full delegate-key *list*
// per account for a page-load-triggered read (`GET /v1/owners/{owner}/agents`),
// which has no existing cache at all today.

/// Same window `walrus_epoch()` uses (`sui/client.rs::walrus_epoch`, 30s).
pub const DELEGATE_KEYS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Staleness threshold for the periodic `DelegateKeysCache` sweep run from
/// `main.rs`. `DELEGATE_KEYS_CACHE_TTL` above only gates whether a hit is
/// *trusted* on read — nothing ever removed the map slot itself, so every
/// `account_object_id` ever looked up via `list_delegate_keys_cached` stayed
/// resident in memory for the life of the process (unbounded growth).
///
/// 10 minutes = 20x the 30s trust TTL: generous headroom so a sweep never
/// evicts an entry that's still realistically in use, while still bounding
/// the map to "accounts read from in the last 10 minutes" instead of
/// "every account ever queried since boot".
pub const DELEGATE_KEYS_CACHE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Clone)]
pub struct TimedDelegateKeys {
    pub value: Vec<DelegateKeyInfo>,
    pub fetched_at: std::time::Instant,
}

/// Keyed by `account_object_id` so different accounts' delegate lists don't
/// collide. `AppState` owns one `Arc` of this (see `types.rs`), shared across
/// all `/agents` requests the same way `SuiClient`'s `Timed` caches are
/// shared via its own `Arc<RwLock<..>>` fields.
pub type DelegateKeysCache =
    std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, TimedDelegateKeys>>>;

pub fn new_delegate_keys_cache() -> DelegateKeysCache {
    std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Cached wrapper around `list_delegate_keys_onchain`: returns the cached
/// list if it was fetched within `DELEGATE_KEYS_CACHE_TTL`, otherwise fetches
/// live and refreshes the cache. Keeps repeated `/agents` calls for the same
/// account within the TTL window from re-hitting the chain.
pub async fn list_delegate_keys_cached(
    cache: &DelegateKeysCache,
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    account_object_id: &str,
    expected_type_origin_package_id: &str,
) -> Result<Vec<DelegateKeyInfo>, OnchainVerifyError> {
    if let Some(cached) = cache
        .read()
        .await
        .get(account_object_id)
        .filter(|c| c.fetched_at.elapsed() < DELEGATE_KEYS_CACHE_TTL)
    {
        return Ok(cached.value.clone());
    }

    let keys = list_delegate_keys_onchain(
        http_client,
        rpc_url,
        grpc_client,
        account_object_id,
        expected_type_origin_package_id,
    )
    .await?;

    cache.write().await.insert(
        account_object_id.to_string(),
        TimedDelegateKeys {
            value: keys.clone(),
            fetched_at: std::time::Instant::now(),
        },
    );

    Ok(keys)
}

// ============================================================
// Delegate key verification — short-TTL in-memory result cache
// ============================================================
//
// Positive verifications are trusted for `DELEGATE_VERIFY_CACHE_TTL`, so a
// burst of requests carrying the same credentials costs one `GetObject`
// rather than one each. Only `Ok` is stored, keyed by
// `(account_object_id, public_key_bytes)`. An unavailable RPC does not
// evict; see `VerifyCacheMissAction`.

/// How long a successful on-chain verification is trusted without
/// re-reading the account object. Matches `DELEGATE_KEYS_CACHE_TTL`.
///
/// This is the upper bound on delegate-key revocation latency at the
/// relayer: a key revoked on-chain keeps authenticating for at most this
/// long. 30s is the same staleness the `/agents` listing already accepts,
/// and is the deliberate trade for removing the retry amplifier.
pub const DELEGATE_VERIFY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// How far past `DELEGATE_VERIFY_CACHE_TTL` an entry may still be served —
/// but *only* when the chain itself is unreachable.
///
/// The 30s TTL assumes dense traffic: several requests carrying the same
/// credentials inside one window. Real MCP usage is not dense. A user who
/// calls a tool every few minutes misses the cache every single time, so
/// while the public fullnode is throttling they take a 503 on each attempt
/// even though their key verified cleanly minutes ago — measured on
/// production as 155,874 × 503 against 50,958 × 200 on `/api/mcp/sse`, and
/// six consecutive failed handshakes with a valid registered key.
///
/// Serving the stale entry in exactly that case turns a hard 503 into a
/// successful call. The trade is bounded and narrow: revocation latency
/// stays 30s whenever the chain answers, and stretches to 10 minutes only
/// while the chain cannot be read at all — a window in which the relayer
/// could not have observed the revoke anyway.
pub const DELEGATE_VERIFY_STALE_GRACE: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Clone)]
pub struct TimedVerifiedOwner {
    /// Owner address returned by the verification that populated this entry.
    pub owner: String,
    pub verified_at: std::time::Instant,
}

impl TimedVerifiedOwner {
    /// Whether this entry may be served on the ordinary path — the window
    /// in which a verification is trusted without re-reading the chain.
    /// The sweeper uses `is_servable_while_unavailable` instead, because an
    /// entry past this point is still worth keeping for the outage path.
    pub fn is_fresh(&self) -> bool {
        self.verified_at.elapsed() < DELEGATE_VERIFY_CACHE_TTL
    }

    /// Whether this entry may be served *because the chain is unreachable*.
    /// Never consulted on the healthy path: a caller reaches this only after
    /// a live read already failed with an unavailable error.
    pub fn is_servable_while_unavailable(&self) -> bool {
        self.verified_at.elapsed() < DELEGATE_VERIFY_CACHE_TTL + DELEGATE_VERIFY_STALE_GRACE
    }
}

/// Keyed by `(account_object_id, public_key_bytes)` so one account's
/// entry can never authenticate a different delegate key.
///
/// Only *successful* verifications are stored, so an entry always
/// corresponds to a delegate key that is really registered on an account:
/// the map is bounded by real accounts, not by what callers send. A
/// rejection records nothing, which is also why an unregistered key
/// cannot be used to grow this map.
///
/// `expected_type_origin_package_id` is deliberately not part of the key:
/// it comes from `Config::package_id`, which is fixed for the life of the
/// process, so it cannot vary between a cache write and a later hit.
/// Borrowed view of an `(account_object_id, public_key_bytes)` key.
///
/// `HashMap<(String, Vec<u8>), _>` cannot be probed with `(&str, &[u8])`, and
/// this lookup now runs on every signed request *and* every MCP envelope, so
/// both caches below are keyed through this trait object rather than
/// allocating a `String` and a `Vec` per hit. `(String, Vec<u8>)` and
/// `(&str, &[u8])` hash identically — tuples hash element-wise, `String`
/// hashes as its `str`, and `Vec<u8>` as its `[u8]` — so the borrowed probe
/// finds the owned key. Same shape as `DelegatePairKey` in #882; this is the
/// two-map version, since the verify cache and the rejection cache share a
/// key. `Send + Sync` because the probe is held across an `.await`, and a
/// non-`Sync` referent there would make the surrounding futures non-`Send`.
pub trait DelegateAccountKey: Send + Sync {
    fn parts(&self) -> (&str, &[u8]);
}

impl DelegateAccountKey for (String, Vec<u8>) {
    fn parts(&self) -> (&str, &[u8]) {
        (self.0.as_str(), self.1.as_slice())
    }
}

impl DelegateAccountKey for (&str, &[u8]) {
    fn parts(&self) -> (&str, &[u8]) {
        (self.0, self.1)
    }
}

impl std::hash::Hash for dyn DelegateAccountKey + '_ {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.parts().hash(state);
    }
}

impl PartialEq for dyn DelegateAccountKey + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.parts() == other.parts()
    }
}

impl Eq for dyn DelegateAccountKey + '_ {}

impl<'a> std::borrow::Borrow<dyn DelegateAccountKey + 'a> for (String, Vec<u8>) {
    fn borrow(&self) -> &(dyn DelegateAccountKey + 'a) {
        self
    }
}

pub struct DelegateVerifyCacheState {
    pub entries:
        tokio::sync::RwLock<std::collections::HashMap<(String, Vec<u8>), TimedVerifiedOwner>>,
    /// Bumped by every definitive eviction.
    ///
    /// Cold misses are deliberately not single-flighted, so two requests for
    /// the same pair can be in the chain at once. Without this, request A can
    /// start a read, request B can observe a revoke and evict, and A's older
    /// success can then land and re-open a full trust window on a key that is
    /// already gone. An insert refuses when the generation moved under it, so
    /// the revoke wins and the next caller reads the chain again.
    pub evictions: std::sync::atomic::AtomicU64,
}

pub type DelegateVerifyCache = std::sync::Arc<DelegateVerifyCacheState>;

pub fn new_delegate_verify_cache() -> DelegateVerifyCache {
    std::sync::Arc::new(DelegateVerifyCacheState {
        entries: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        evictions: std::sync::atomic::AtomicU64::new(0),
    })
}

// ── Rejections ──────────────────────────────────────────────────────────
//
// Definitive rejections are cached too, briefly. A client holding a key the
// relayer will never accept retries forever, and an uncached rejection makes
// each retry another fullnode read.

/// How long a definitive rejection is remembered.
///
/// Deliberately much shorter than the positive TTL, because the cost of
/// being wrong is asymmetric: a stale positive authenticates a revoked key,
/// while a stale negative only delays a key that just became valid.
///
/// It does not delay an ordinary `memwal_login`: that registers a freshly
/// generated delegate key, so the `(account, pk)` pair has never been
/// rejected and has no entry. What it can delay by up to this long is the
/// narrower case of retrying a key that was tried *before* its registration
/// landed — the interrupted-login path.
pub const DELEGATE_REJECT_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(10);

/// Hard ceiling on remembered rejections.
///
/// Unlike the positive cache, this one is keyed by what *callers send*, not
/// by what exists on chain, so it would otherwise grow one entry per made-up
/// `(account, key)` pair anyone cares to try. At the cap we stop inserting
/// and fall back to the live read — degrading to today's behaviour rather
/// than trading a throttle for unbounded memory.
pub const DELEGATE_REJECT_CACHE_MAX_ENTRIES: usize = 4_096;

pub type DelegateRejectCache = std::sync::Arc<
    tokio::sync::RwLock<std::collections::HashMap<(String, Vec<u8>), std::time::Instant>>,
>;

pub fn new_delegate_reject_cache() -> DelegateRejectCache {
    std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Whether a rejection recorded at `rejected_at` may still be reused.
pub fn reject_entry_is_fresh(rejected_at: std::time::Instant) -> bool {
    rejected_at.elapsed() < DELEGATE_REJECT_CACHE_TTL
}

/// Whether a fresh rejection may be recorded, given the map's current size
/// and whether this pair is already present. Pure so the cap is testable
/// without a chain: refreshing an existing entry is always allowed (it
/// cannot grow the map), a new one only below the cap.
pub fn should_record_rejection(current_len: usize, already_present: bool) -> bool {
    already_present || current_len < DELEGATE_REJECT_CACHE_MAX_ENTRIES
}

/// Cached wrapper around `verify_delegate_key_onchain`.
///
/// A hit within `DELEGATE_VERIFY_CACHE_TTL` returns the recorded owner
/// without touching the chain. Only successes are cached: a rejection is
/// always a live read, so adding a delegate key (the tail of `login`)
/// takes effect immediately rather than after a TTL. A definitive
/// rejection also evicts any entry for that pair, so an observed revoke
/// cannot be overtaken by a positive still inside its window.
///
/// When the live read fails *because the chain is unreachable*, a stale
/// entry within `DELEGATE_VERIFY_STALE_GRACE` is served rather than
/// surfacing the outage to a caller whose key is known good. Only an
/// unavailable error takes this path — a definitive rejection is still
/// returned, and still evicts. Without it the TTL helps only callers who
/// repeat inside 30s, which is not how the MCP clients that hit this
/// actually behave (WALM-618).
///
/// OAuth refresh does not use that grace. It calls
/// [`verify_delegate_key_cached_for_refresh`].
pub async fn verify_delegate_key_cached(
    cache: &DelegateVerifyCache,
    reject_cache: &DelegateRejectCache,
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    account_object_id: &str,
    public_key_bytes: &[u8],
    expected_type_origin_package_id: &str,
) -> Result<String, OnchainVerifyError> {
    verify_delegate_key_cached_inner(
        cache,
        reject_cache,
        http_client,
        rpc_url,
        grpc_client,
        account_object_id,
        public_key_bytes,
        expected_type_origin_package_id,
        false,
    )
    .await
}

/// OAuth refresh. Same cache as [`verify_delegate_key_cached`], but a
/// positive older than [`DELEGATE_VERIFY_CACHE_TTL`] is not served when the
/// chain is down, and only [`OnchainVerifyError::revokes_oauth_refresh`]
/// evicts. Other callers keep the 600s stale grace.
pub async fn verify_delegate_key_cached_for_refresh(
    cache: &DelegateVerifyCache,
    reject_cache: &DelegateRejectCache,
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    account_object_id: &str,
    public_key_bytes: &[u8],
    expected_type_origin_package_id: &str,
) -> Result<String, OnchainVerifyError> {
    verify_delegate_key_cached_inner(
        cache,
        reject_cache,
        http_client,
        rpc_url,
        grpc_client,
        account_object_id,
        public_key_bytes,
        expected_type_origin_package_id,
        true,
    )
    .await
}

async fn verify_delegate_key_cached_inner(
    cache: &DelegateVerifyCache,
    reject_cache: &DelegateRejectCache,
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    account_object_id: &str,
    public_key_bytes: &[u8],
    expected_type_origin_package_id: &str,
    for_refresh: bool,
) -> Result<String, OnchainVerifyError> {
    // Borrowed probe: a hit — the common case on both hot paths — allocates
    // nothing. The owned key is built only where the map is actually written.
    let probe: &dyn DelegateAccountKey = &(account_object_id, public_key_bytes);

    let get_object_attempts = {
        let entries = cache.entries.read().await;
        match entries.get(probe) {
            Some(cached) if cached.is_fresh() => return Ok(cached.owner.clone()),
            // The one-attempt shortcut exists to fall into the stale grace.
            // Refresh does not serve that grace, so it retries in full.
            Some(cached) if !for_refresh && cached.is_servable_while_unavailable() => 1,
            _ => GET_OBJECT_ATTEMPTS,
        }
    };

    // Read before the chain call, compared after it. See `evictions`.
    let generation_before = cache.evictions.load(std::sync::atomic::Ordering::Acquire);
    // Stamped from BEFORE the read, not after: a slow `GetObject` would
    // otherwise extend the stated revocation bound by its own duration.
    let verify_started = std::time::Instant::now();

    // A pair we refused moments ago is refused again without a chain read.
    // Checked after the positive lookup so a key that has since been
    // registered and verified is never held back by an older rejection.
    if reject_cache
        .read()
        .await
        .get(probe)
        .copied()
        .is_some_and(reject_entry_is_fresh)
    {
        return Err(OnchainVerifyError::KeyNotFound(format!(
            "delegate key not registered on account {account_object_id} (cached)"
        )));
    }

    match verify_delegate_key_onchain(
        http_client,
        rpc_url,
        grpc_client,
        account_object_id,
        public_key_bytes,
        expected_type_origin_package_id,
        get_object_attempts,
    )
    .await
    {
        Ok(owner) => {
            let key = (account_object_id.to_string(), public_key_bytes.to_vec());
            // The unconditional `reject_cache.remove` that used to stand here
            // is deleted rather than made conditional. Any entry present for
            // this pair at this point was either stamped before this read —
            // in which case the lookup above already stepped past it, so it
            // was expired and inert — or stamped *during* it, which means a
            // concurrent request saw the chain refuse this pair. Removing the
            // second kind is how a revoke ended up recorded in neither map:
            // no positive entry (correct, the generation check below declines
            // it) and no rejection either (wrong).
            let mut entries = cache.entries.write().await;
            if may_store_verification(
                generation_before,
                cache.evictions.load(std::sync::atomic::Ordering::Acquire),
            ) {
                entries.insert(
                    key,
                    TimedVerifiedOwner {
                        owner: owner.clone(),
                        verified_at: verify_started,
                    },
                );
            }
            // Otherwise a concurrent request saw something definitive while
            // this read was in flight. Answer this caller — the read did
            // succeed — but do not cache a result the chain has since
            // contradicted.
            Ok(owner)
        }
        Err(err) => {
            if delegate_verify_evicts(&err, for_refresh) {
                // One guard across the removal, the bump and the rejection
                // record. A concurrent success takes this same `entries` lock
                // to insert and reads the generation while holding it, so it
                // either runs before this block (and its entry is deleted by
                // the remove) or after it (and sees the bumped generation and
                // declines). Bumping after the guard dropped left a window
                // where it could do neither, which is the race `evictions`
                // exists to close.
                let mut entries = cache.entries.write().await;
                entries.remove(probe);
                cache
                    .evictions
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                // Remember the refusal so a client looping on a key that can
                // never be accepted stops costing one fullnode read per retry.
                let mut rejects = reject_cache.write().await;
                let present = rejects.contains_key(probe);
                // Expire before consulting the cap. The TTL is 10s and the
                // sweeper runs every 300s, so the raw length counts up to
                // thirty generations of entries that can no longer be served
                // by anyone. Without this, a few thousand distinct made-up
                // pairs hold every slot for five minutes, during which no
                // genuine rejection is recorded at all and every looping
                // client is back to one fullnode read per retry — the exact
                // amplifier this cache was added to remove. Same policy as
                // the refusal-log sampler in `observability`.
                if !present && rejects.len() >= DELEGATE_REJECT_CACHE_MAX_ENTRIES {
                    rejects.retain(|_, rejected_at| reject_entry_is_fresh(*rejected_at));
                }
                // At the cap we still simply do not record — the next attempt
                // reads the chain exactly as it does today.
                if should_record_rejection(rejects.len(), present) {
                    rejects.insert(
                        (account_object_id.to_string(), public_key_bytes.to_vec()),
                        std::time::Instant::now(),
                    );
                }
                drop(rejects);
                drop(entries);
                return Err(err);
            }
            // Refresh must not mint from a positive past the 30s TTL.
            if for_refresh {
                return Err(err);
            }
            // Unavailable: the chain proved nothing about this key, so a
            // recent success is still the best evidence we have. Serving it
            // is what keeps a valid caller working through a fullnode
            // throttle instead of collecting a 503 per attempt.
            let stale = cache
                .entries
                .read()
                .await
                .get(probe)
                .filter(|c| c.is_servable_while_unavailable())
                .map(|c| (c.owner.clone(), c.verified_at.elapsed()));
            match stale {
                Some((owner, age)) => {
                    // Sampled per account, like the refusal line. This runs on
                    // every signed request and every MCP envelope, and it fires
                    // hardest exactly when an outage is pushing many requests
                    // past the TTL at once — one line per request there is the
                    // repetition the sampler exists to stop.
                    if crate::observability::should_log_stale_serve(account_object_id) {
                        tracing::warn!(
                            account_id = %account_object_id,
                            age_secs = age.as_secs(),
                            error = %err,
                            "serving stale delegate verification while Sui is unavailable (sampled)"
                        );
                    }
                    Ok(owner)
                }
                None => Err(err),
            }
        }
    }
}

/// What a failed live verification means for any cached entry on the same
/// `(account, key)` pair. Pure so the policy is testable without a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyCacheMissAction {
    /// The rejection is definitive (revoked, deactivated, wrong object) —
    /// drop the pair so a positive still inside its TTL cannot outlive the
    /// revoke we just observed.
    Evict,
    /// An unavailable RPC proves nothing about the key, so leave the entry
    /// alone. Load-bearing in two distinct ways, neither of them obvious:
    ///
    /// - The entry this thread missed on is what
    ///   `DELEGATE_VERIFY_STALE_GRACE` goes on to serve, so evicting here
    ///   would delete exactly what the outage path exists to use.
    /// - A *different* request may have verified successfully in the window
    ///   between this thread's miss and its failed read. Evicting on an
    ///   unavailable error would throw away that fresh, valid entry on the
    ///   strength of an RPC failure that says nothing about the key.
    Keep,
}

/// Whether a completed verification may still be stored.
///
/// False when a definitive eviction landed while the read was in flight: the
/// chain has since contradicted this answer, so caching it would re-open a
/// trust window on a key another request already saw revoked.
pub fn may_store_verification(generation_before: u64, generation_now: u64) -> bool {
    generation_before == generation_now
}

pub fn verify_cache_miss_action(err: &OnchainVerifyError) -> VerifyCacheMissAction {
    if err.is_unavailable() {
        VerifyCacheMissAction::Keep
    } else {
        VerifyCacheMissAction::Evict
    }
}

/// Shared callers evict on every definitive miss. Refresh evicts only on
/// answers that revoke the grant, so a partial read is not remembered as
/// `KeyNotFound` for the next refresh.
fn delegate_verify_evicts(err: &OnchainVerifyError, for_refresh: bool) -> bool {
    if for_refresh {
        err.revokes_oauth_refresh()
    } else {
        verify_cache_miss_action(err) == VerifyCacheMissAction::Evict
    }
}

/// Parse the `delegate_keys` array out of a MemWalAccount's `fields` map.
/// Pure function — no I/O — so it's unit-testable without a live chain.
pub fn parse_delegate_keys(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<DelegateKeyInfo>, OnchainVerifyError> {
    let delegate_keys = fields
        .get("delegate_keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing 'delegate_keys' field".into()))?;

    let mut out = Vec::with_capacity(delegate_keys.len());
    for dk in delegate_keys {
        let dk_fields = dk.get("fields").or(Some(dk));
        let sui_address = dk_fields
            .and_then(|f| f.get("sui_address"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| OnchainVerifyError::RpcError("delegate key missing sui_address".into()))?
            .to_string();
        let label = dk_fields
            .and_then(|f| f.get("label"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let created_at = dk_fields
            .and_then(|f| f.get("created_at"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| {
                dk_fields
                    .and_then(|f| f.get("created_at"))
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(0);
        out.push(DelegateKeyInfo {
            sui_address,
            label,
            created_at,
        });
    }
    Ok(out)
}

/// A delegate key as stored on `MemWalAccount`, including the public key
/// `DelegateKeyInfo` leaves out. Hex is 64 lowercase chars, no `0x`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnchainDelegateKeyPublic {
    pub public_key_hex: String,
    pub sui_address: String,
    pub label: String,
    pub created_at: u64,
}

/// Account object read straight from RPC for the revocation notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAccountOnchain {
    pub account_id: String,
    pub active: bool,
    pub admin_quarantined: bool,
    pub keys: Vec<OnchainDelegateKeyPublic>,
}

/// `0xf0` is `HashingIntentScope::ChildObjectId`. The rest matches
/// `sui_types::dynamic_field::derive_dynamic_field_id` for an `address` key:
/// blake2b-256 of `0xf0 || parent || len(key) || key || TypeTag::Address`.
pub fn derive_address_dynamic_field_id(parent: &Address, key: &Address) -> Address {
    let mut hasher = sui_sdk_types::hash::Hasher::new();
    hasher.update([0xf0]);
    hasher.update(parent.as_bytes());
    hasher.update(32u64.to_le_bytes());
    hasher.update(key.as_bytes());
    hasher.update([0x04]);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(digest.as_ref());
    Address::new(bytes)
}

fn address_hex(address: &Address) -> String {
    format!("0x{}", hex::encode(address.inner()))
}

fn normalize_object_id(value: &str) -> Option<String> {
    let bare = value.trim().trim_start_matches("0x").trim_start_matches("0X");
    if bare.len() != 64 || !bare.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", bare.to_ascii_lowercase()))
}

fn json_object_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => normalize_object_id(text),
        serde_json::Value::Array(items) if items.len() == 32 => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            bytes.map(|bytes| format!("0x{}", hex::encode(bytes)))
        }
        serde_json::Value::Object(map) => map
            .get("id")
            .and_then(json_object_id)
            .or_else(|| map.get("bytes").and_then(json_object_id)),
        _ => None,
    }
}

fn json_at<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for key in path {
        current = current.as_object()?.get(*key)?;
    }
    Some(current)
}

/// Table UID inside `AccountRegistry.accounts`. Accepts the flat gRPC json
/// shape and the JSON-RPC `{fields: ...}` wrapper.
pub fn registry_table_id(fields: &serde_json::Map<String, serde_json::Value>) -> Option<String> {
    let accounts = serde_json::Value::Object(fields.clone());
    let accounts = accounts.get("accounts")?;
    json_at(accounts, &["id"])
        .and_then(json_object_id)
        .or_else(|| json_at(accounts, &["fields", "id"]).and_then(json_object_id))
}

/// `value` of a `dynamic_field::Field<address, ID>`.
pub fn dynamic_field_account_id(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Option<String> {
    let root = serde_json::Value::Object(fields.clone());
    root.get("value")
        .and_then(json_object_id)
        .or_else(|| json_at(&root, &["fields", "value"]).and_then(json_object_id))
}

fn public_key_hex(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|item| item.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            let bytes = bytes?;
            (bytes.len() == 32).then(|| hex::encode(bytes))
        }
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if let Some(id) = normalize_object_id(trimmed) {
                return Some(id.trim_start_matches("0x").to_string());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(trimmed)
                .ok()?;
            (bytes.len() == 32).then(|| hex::encode(bytes))
        }
        _ => None,
    }
}

fn created_at_u64(value: &serde_json::Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .unwrap_or(0)
}

/// `active`, `admin_quarantined`, and delegate keys from one account object.
/// A missing quarantine flag means the object is not quarantined. `active`
/// is required.
pub fn parse_owner_account_fields(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<(bool, bool, Vec<OnchainDelegateKeyPublic>), OnchainVerifyError> {
    let active = json_account_active(fields)?;
    let admin_quarantined = fields
        .get("admin_quarantined")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let delegate_keys = fields
        .get("delegate_keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing 'delegate_keys' field".into()))?;
    let mut keys = Vec::with_capacity(delegate_keys.len());
    for entry in delegate_keys {
        let node = entry.get("fields").unwrap_or(entry);
        let public_key_hex = node
            .get("public_key")
            .and_then(public_key_hex)
            .ok_or_else(|| OnchainVerifyError::RpcError("delegate key missing public_key".into()))?;
        let sui_address = node
            .get("sui_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OnchainVerifyError::RpcError("delegate key missing sui_address".into()))?
            .to_ascii_lowercase();
        let label = node
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let created_at = node
            .get("created_at")
            .map(created_at_u64)
            .unwrap_or(0);
        keys.push(OnchainDelegateKeyPublic {
            public_key_hex,
            sui_address,
            label,
            created_at,
        });
    }
    Ok((active, admin_quarantined, keys))
}

/// List all delegate keys on a MemWalAccount object. JSON-RPC only (mirrors
/// verify_delegate_key_onchain's non-gRPC path) — the initial phase did not
/// need the gRPC variant since this endpoint is not on the hot signature-
/// verification path.
/// Routes through gRPC when `grpc_client` is provided, mirroring
/// `verify_delegate_key_onchain`'s same JSON-RPC-sunset rationale — this
/// was the one remaining `/agents`-only call site still hardcoded to
/// JSON-RPC after that migration.
pub async fn list_delegate_keys_onchain(
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    account_object_id: &str,
    expected_type_origin_package_id: &str,
) -> Result<Vec<DelegateKeyInfo>, OnchainVerifyError> {
    if let Some(grpc_client) = grpc_client {
        return list_delegate_keys_onchain_grpc(
            grpc_client.clone(),
            account_object_id,
            expected_type_origin_package_id,
        )
        .await;
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_getObject",
        "params": [account_object_id, { "showContent": true }]
    });

    let request = http_client
        .post(rpc_url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .json(&body);
    let request = crate::observability::apply_request_id_header(request);
    // Mirror verify_delegate_key_onchain's instrumentation exactly so this
    // call is visible in the same `sui_rpc` external-call metrics instead
    // of being an invisible RPC cost.
    let started = std::time::Instant::now();
    let response = request.send().await.map_err(|e| {
        crate::observability::observe_external(
            "sui_rpc",
            "sui_getObject",
            "transport_error",
            started.elapsed(),
        );
        OnchainVerifyError::RpcError(format!("HTTP request failed: {}", e))
    })?;
    let status_label = response.status().as_u16().to_string();
    crate::observability::observe_external(
        "sui_rpc",
        "sui_getObject",
        &status_label,
        started.elapsed(),
    );

    let rpc_response: RpcResponse = parse_json_rpc_response(response, "sui_getObject").await?;
    if let Some(error) = rpc_response.error {
        return Err(OnchainVerifyError::RpcError(format!(
            "RPC error {}: {}",
            error.code, error.message
        )));
    }

    let result = rpc_response
        .result
        .ok_or_else(|| partial_get_object(PARTIAL_RPC_NO_RESULT))?;
    let content = require_get_object_content(result)?;

    ensure_memwal_account_type(
        content.object_type.as_deref(),
        expected_type_origin_package_id,
        account_object_id,
    )?;

    let fields = content
        .fields
        .ok_or_else(|| OnchainVerifyError::RpcError("Object has no fields".into()))?;

    parse_delegate_keys(&fields)
}

// ── gRPC value helpers ──
// google.protobuf.Value (via prost-types) is a dynamic JSON-like tree, not
// serde_json::Value — these navigate it the same way `fields.get(...)` reads
// the parsed JSON-RPC content above, so the two code paths stay structurally
// parallel and easy to compare.
fn grpc_value_as_struct(v: &prost_types::Value) -> Option<&prost_types::Struct> {
    match &v.kind {
        Some(prost_types::value::Kind::StructValue(s)) => Some(s),
        _ => None,
    }
}

fn grpc_value_as_str(v: &prost_types::Value) -> Option<&str> {
    match &v.kind {
        Some(prost_types::value::Kind::StringValue(s)) => Some(s.as_str()),
        _ => None,
    }
}

fn grpc_value_as_bool(v: &prost_types::Value) -> Option<bool> {
    match &v.kind {
        Some(prost_types::value::Kind::BoolValue(b)) => Some(*b),
        _ => None,
    }
}

fn json_account_active(
    fields: &serde_json::Map<String, serde_json::Value>,
) -> Result<bool, OnchainVerifyError> {
    fields
        .get("active")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing or malformed 'active' field".into()))
}

fn grpc_account_active(fields: &prost_types::Struct) -> Result<bool, OnchainVerifyError> {
    fields
        .fields
        .get("active")
        .and_then(grpc_value_as_bool)
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing or malformed 'active' field".into()))
}

fn grpc_value_as_list(v: &prost_types::Value) -> Option<&[prost_types::Value]> {
    match &v.kind {
        Some(prost_types::value::Kind::ListValue(l)) => Some(&l.values),
        _ => None,
    }
}

/// `created_at` (a Move `u64`) round-trips through gRPC's JSON-like
/// `google.protobuf.Value` the same way it does through JSON-RPC — usually
/// as a string (to avoid f64 precision loss), occasionally as a number —
/// so try both, mirroring `parse_delegate_keys`'s JSON-RPC dual-path.
fn grpc_value_as_u64(v: &prost_types::Value) -> Option<u64> {
    match &v.kind {
        Some(prost_types::value::Kind::StringValue(s)) => s.parse::<u64>().ok(),
        Some(prost_types::value::Kind::NumberValue(n)) => Some(*n as u64),
        _ => None,
    }
}

fn parse_object_id(account_object_id: &str) -> Result<sui_sdk_types::Address, OnchainVerifyError> {
    account_object_id
        .parse()
        .map_err(|error| OnchainVerifyError::NotFound(format!("invalid object id: {error}")))
}

/// JSON-RPC omitted `result`. Not proof the object is missing.
pub(crate) const PARTIAL_RPC_NO_RESULT: &str = "No result in RPC response";
/// JSON-RPC object had no `content`. Not proof the object is missing.
pub(crate) const PARTIAL_RPC_NO_CONTENT: &str = "Object has no content";
/// gRPC status was success but `object` was absent. Not proof it is missing.
pub(crate) const PARTIAL_GRPC_OBJECT_ABSENT: &str = "gRPC response missing object";
/// Prefix on gRPC `Code::NotFound` for the object. Owned by us so refresh
/// does not parse tonic's English `code:` text.
pub(crate) const GRPC_OBJECT_NOT_FOUND_PREFIX: &str = "gRPC object not found: ";

/// A GetObject body that does not say whether the object exists.
///
/// `RpcError` so `is_unavailable` is true. A partial read must not revoke an
/// OAuth grant or be remembered as a delegate-key rejection.
pub(crate) fn partial_get_object(reason: &str) -> OnchainVerifyError {
    OnchainVerifyError::RpcError(reason.to_string())
}

/// Classify LedgerService.GetObject failures by gRPC *code*, never by message
/// text. tonic's Display embeds the code's English name, so matching "not found"
/// in the string would also fire on INTERNAL errors that merely mention a
/// missing object.
///
/// Only `NotFound` means the object is gone. `InvalidArgument` is a malformed
/// request, so it stays unavailable and must not revoke a grant.
pub(crate) fn map_get_object_status(status: tonic::Status) -> OnchainVerifyError {
    match status.code() {
        tonic::Code::NotFound => {
            OnchainVerifyError::NotFound(format!("{GRPC_OBJECT_NOT_FOUND_PREFIX}{status}"))
        }
        _ => OnchainVerifyError::RpcError(format!("gRPC GetObject failed: {status}")),
    }
}

pub const GET_OBJECT_ATTEMPTS: u32 = 3;
const GET_OBJECT_RETRY_BASE_DELAY_MS: u64 = 500;
static GET_OBJECT_RETRY_JITTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn with_get_object_retry<T, F, Fut>(attempts: u32, mut call: F) -> Result<T, tonic::Status>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, tonic::Status>>,
{
    for attempt in 0..attempts {
        let started = std::time::Instant::now();
        let result =
            match tokio::time::timeout(crate::sui::DEFAULT_RPC_ATTEMPT_TIMEOUT, call()).await {
                Ok(result) => result,
                Err(_) => Err(tonic::Status::deadline_exceeded(format!(
                    "GetObject exceeded {}ms",
                    crate::sui::DEFAULT_RPC_ATTEMPT_TIMEOUT.as_millis()
                ))),
            };
        let status_label = match &result {
            Ok(_) => "200".to_string(),
            Err(status) => status.code().to_string(),
        };
        crate::observability::observe_external(
            "sui_grpc",
            "GetObject",
            &status_label,
            started.elapsed(),
        );

        match result {
            Err(status)
                if attempt + 1 < attempts && crate::sui::is_transient_grpc_code(status.code()) => {}
            outcome => return outcome,
        }

        let base = GET_OBJECT_RETRY_BASE_DELAY_MS.saturating_mul(1_u64 << attempt.min(16));
        let sequence = GET_OBJECT_RETRY_JITTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let jitter = base.saturating_mul(((sequence * 37 + u64::from(attempt)) % 21) + 90) / 100;
        tokio::time::sleep(std::time::Duration::from_millis(jitter)).await;
    }
    unreachable!("attempts is non-zero")
}

async fn grpc_get_object(
    client: sui_rpc::Client,
    account_object_id: &str,
    attempts: u32,
) -> Result<sui_rpc::proto::sui::rpc::v2::Object, OnchainVerifyError> {
    let address = parse_object_id(account_object_id)?;
    let mut request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::new(&address);
    request.read_mask = Some(prost_types::FieldMask {
        paths: vec!["json".to_string(), "object_type".to_string()],
    });

    with_get_object_retry(attempts, || {
        let mut client = client.clone();
        let request = request.clone();
        async move { client.ledger_client().get_object(request).await }
    })
    .await
    .map_err(map_get_object_status)?
    .into_inner()
    .object
    .ok_or_else(|| partial_get_object(PARTIAL_GRPC_OBJECT_ABSENT))
}

fn prost_value_to_json(value: &prost_types::Value) -> serde_json::Value {
    match &value.kind {
        Some(prost_types::value::Kind::NullValue(_)) | None => serde_json::Value::Null,
        Some(prost_types::value::Kind::NumberValue(number)) => serde_json::Number::from_f64(*number)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Some(prost_types::value::Kind::StringValue(text)) => serde_json::Value::String(text.clone()),
        Some(prost_types::value::Kind::BoolValue(flag)) => serde_json::Value::Bool(*flag),
        Some(prost_types::value::Kind::StructValue(fields)) => {
            let mut map = serde_json::Map::new();
            for (key, child) in &fields.fields {
                map.insert(key.clone(), prost_value_to_json(child));
            }
            serde_json::Value::Object(map)
        }
        Some(prost_types::value::Kind::ListValue(list)) => {
            serde_json::Value::Array(list.values.iter().map(prost_value_to_json).collect())
        }
    }
}

async fn json_rpc_get_move_fields(
    http_client: &reqwest::Client,
    rpc_url: &str,
    object_id: &str,
) -> Result<Option<(Option<String>, serde_json::Map<String, serde_json::Value>)>, OnchainVerifyError>
{
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sui_getObject",
        "params": [object_id, { "showContent": true }]
    });
    let started = std::time::Instant::now();
    let response = http_client
        .post(rpc_url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .json(&body)
        .send()
        .await
        .map_err(|error| {
            crate::observability::observe_external(
                "sui_rpc",
                "sui_getObject",
                "transport_error",
                started.elapsed(),
            );
            OnchainVerifyError::RpcError(format!("HTTP request failed: {error}"))
        })?;
    let status_label = response.status().as_u16().to_string();
    crate::observability::observe_external(
        "sui_rpc",
        "sui_getObject",
        &status_label,
        started.elapsed(),
    );
    let rpc_response: OwnerObjectRpcResponse =
        parse_json_rpc_response(response, "sui_getObject").await?;
    if let Some(error) = &rpc_response.error {
        let message = error.message.to_ascii_lowercase();
        if message.contains("not exists") || message.contains("not found") {
            return Ok(None);
        }
        return Err(OnchainVerifyError::RpcError(format!(
            "RPC error {}: {}",
            error.code, error.message
        )));
    }
    if rpc_response
        .result
        .as_ref()
        .and_then(|result| result.error.as_ref())
        .is_some_and(|error| error.code.eq_ignore_ascii_case("notExists"))
    {
        return Ok(None);
    }
    let Some(content) = rpc_response
        .result
        .and_then(|result| result.data)
        .and_then(|data| data.content)
    else {
        return Ok(None);
    };
    let fields = content
        .fields
        .ok_or_else(|| OnchainVerifyError::RpcError("Object has no fields".into()))?;
    Ok(Some((content.object_type, fields)))
}

async fn get_move_fields(
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    object_id: &str,
) -> Result<Option<(Option<String>, serde_json::Map<String, serde_json::Value>)>, OnchainVerifyError>
{
    let Some(grpc_client) = grpc_client else {
        return json_rpc_get_move_fields(http_client, rpc_url, object_id).await;
    };
    match grpc_get_object(grpc_client.clone(), object_id, GET_OBJECT_ATTEMPTS).await {
        Ok(object) => {
            let json = object
                .json
                .ok_or_else(|| OnchainVerifyError::RpcError("Object has no json content".into()))?;
            let value = prost_value_to_json(&json);
            let fields = value.as_object().cloned().ok_or_else(|| {
                OnchainVerifyError::RpcError("Object json is not an object".into())
            })?;
            Ok(Some((object.object_type, fields)))
        }
        Err(OnchainVerifyError::NotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

static REGISTRY_TABLE_IDS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, String>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Resolve `owner` through `AccountRegistry`'s `Table<address, ID>` and read
/// that `MemWalAccount` from RPC. `Ok(None)` means the owner has no account.
/// The registry object itself missing is an error, not an empty account.
pub async fn load_owner_account_onchain(
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    registry_id: &str,
    expected_type_origin_package_id: &str,
    owner: &str,
) -> Result<Option<OwnerAccountOnchain>, OnchainVerifyError> {
    let table_id = {
        let cached = REGISTRY_TABLE_IDS
            .lock()
            .ok()
            .and_then(|guard| guard.get(registry_id).cloned());
        if let Some(table_id) = cached {
            table_id
        } else {
            let Some((_, registry_fields)) =
                get_move_fields(http_client, rpc_url, grpc_client, registry_id).await?
            else {
                return Err(OnchainVerifyError::NotFound(
                    "AccountRegistry object not found".into(),
                ));
            };
            let table_id = registry_table_id(&registry_fields).ok_or_else(|| {
                OnchainVerifyError::RpcError("AccountRegistry has no accounts table id".into())
            })?;
            if let Ok(mut guard) = REGISTRY_TABLE_IDS.lock() {
                guard.insert(registry_id.to_string(), table_id.clone());
            }
            table_id
        }
    };

    let parent = parse_object_id(&table_id)?;
    let key = parse_object_id(owner)?;
    let field_id = address_hex(&derive_address_dynamic_field_id(&parent, &key));
    let Some((_, field_fields)) =
        get_move_fields(http_client, rpc_url, grpc_client, &field_id).await?
    else {
        return Ok(None);
    };
    let account_id = dynamic_field_account_id(&field_fields).ok_or_else(|| {
        OnchainVerifyError::RpcError("registry dynamic field has no account id".into())
    })?;

    let Some((object_type, account_fields)) =
        get_move_fields(http_client, rpc_url, grpc_client, &account_id).await?
    else {
        return Err(OnchainVerifyError::NotFound(format!(
            "MemWalAccount {account_id} not found"
        )));
    };
    ensure_memwal_account_type(
        object_type.as_deref(),
        expected_type_origin_package_id,
        &account_id,
    )?;
    let (active, admin_quarantined, keys) = parse_owner_account_fields(&account_fields)?;
    Ok(Some(OwnerAccountOnchain {
        account_id,
        active,
        admin_quarantined,
        keys,
    }))
}

/// gRPC counterpart of `verify_delegate_key_onchain` above — same checks
/// (owner, active, delegate_keys membership), fetched via
/// LedgerService.GetObject instead of JSON-RPC's `sui_getObject`.
///
/// The gRPC `.json` object representation is flatter than JSON-RPC's
/// `.fields` shape and encodes delegate key `public_key` as base64 (not a
/// byte-array) — verified live against real testnet objects while migrating
/// the sidecar and web app to gRPC for this same JSON-RPC sunset.
async fn verify_delegate_key_onchain_grpc(
    client: sui_rpc::Client,
    account_object_id: &str,
    public_key_bytes: &[u8],
    expected_type_origin_package_id: &str,
    attempts: u32,
) -> Result<String, OnchainVerifyError> {
    let object = grpc_get_object(client, account_object_id, attempts).await?;

    // #398: verify the Move type before trusting any field (gRPC path).
    ensure_memwal_account_type(
        object.object_type.as_deref(),
        expected_type_origin_package_id,
        account_object_id,
    )?;

    let json = object
        .json
        .ok_or_else(|| OnchainVerifyError::RpcError("Object has no json content".into()))?;
    let fields = grpc_value_as_struct(&json)
        .ok_or_else(|| OnchainVerifyError::RpcError("Object json is not a struct".into()))?;

    let owner = fields
        .fields
        .get("owner")
        .and_then(grpc_value_as_str)
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing 'owner' field".into()))?
        .to_string();

    let active = grpc_account_active(fields)?;
    if !active {
        tracing::warn!(
            "account {} is deactivated — rejecting delegate key auth (gRPC)",
            account_object_id
        );
        return Err(OnchainVerifyError::AccountDeactivated(format!(
            "Account {} has been deactivated",
            account_object_id
        )));
    }

    let delegate_keys = fields
        .fields
        .get("delegate_keys")
        .and_then(grpc_value_as_list)
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing 'delegate_keys' field".into()))?;

    for dk in delegate_keys {
        let Some(dk_fields) = grpc_value_as_struct(dk) else {
            continue;
        };
        let Some(stored_b64) = dk_fields
            .fields
            .get("public_key")
            .and_then(grpc_value_as_str)
        else {
            continue;
        };
        let Ok(stored_bytes) = base64::engine::general_purpose::STANDARD.decode(stored_b64) else {
            continue;
        };
        if stored_bytes == public_key_bytes {
            tracing::info!("delegate key verified onchain (gRPC), owner: {}", owner);
            return Ok(owner);
        }
    }

    Err(OnchainVerifyError::KeyNotFound(format!(
        "Public key not found in {} delegate key(s) for account {} (gRPC)",
        delegate_keys.len(),
        account_object_id
    )))
}

/// gRPC counterpart of `list_delegate_keys_onchain`'s JSON-RPC body — same
/// shape as `verify_delegate_key_onchain_grpc` above (GetObject, type check,
/// struct navigation), but returns every delegate key rather than searching
/// for one match. Public key bytes are base64-encoded in the gRPC json
/// representation (unlike JSON-RPC's array-of-numbers), but `/agents`
/// doesn't need the key bytes at all — only `sui_address`/`label`/`created_at`.
async fn list_delegate_keys_onchain_grpc(
    client: sui_rpc::Client,
    account_object_id: &str,
    expected_type_origin_package_id: &str,
) -> Result<Vec<DelegateKeyInfo>, OnchainVerifyError> {
    let object = grpc_get_object(client, account_object_id, GET_OBJECT_ATTEMPTS).await?;

    ensure_memwal_account_type(
        object.object_type.as_deref(),
        expected_type_origin_package_id,
        account_object_id,
    )?;

    let json = object
        .json
        .ok_or_else(|| OnchainVerifyError::RpcError("Object has no json content".into()))?;
    let fields = grpc_value_as_struct(&json)
        .ok_or_else(|| OnchainVerifyError::RpcError("Object json is not a struct".into()))?;

    let delegate_keys = fields
        .fields
        .get("delegate_keys")
        .and_then(grpc_value_as_list)
        .ok_or_else(|| OnchainVerifyError::RpcError("Missing 'delegate_keys' field".into()))?;

    let mut out = Vec::with_capacity(delegate_keys.len());
    for dk in delegate_keys {
        let Some(dk_fields) = grpc_value_as_struct(dk) else {
            continue;
        };
        let sui_address = dk_fields
            .fields
            .get("sui_address")
            .and_then(grpc_value_as_str)
            .ok_or_else(|| OnchainVerifyError::RpcError("delegate key missing sui_address".into()))?
            .to_string();
        let label = dk_fields
            .fields
            .get("label")
            .and_then(grpc_value_as_str)
            .unwrap_or("")
            .to_string();
        let created_at = dk_fields
            .fields
            .get("created_at")
            .and_then(grpc_value_as_u64)
            .unwrap_or(0);
        out.push(DelegateKeyInfo {
            sui_address,
            label,
            created_at,
        });
    }

    Ok(out)
}

// ============================================================
// Types for JSON-RPC response parsing
// ============================================================

async fn parse_json_rpc_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T, OnchainVerifyError> {
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<missing>")
        .to_string();
    let bytes = response.bytes().await.map_err(|e| {
        OnchainVerifyError::RpcError(format!(
            "{}: failed to read RPC response body: {} (status={}, content-type={})",
            context, e, status, content_type
        ))
    })?;

    if !status.is_success() {
        return Err(OnchainVerifyError::RpcError(format!(
            "{}: RPC HTTP error status={}, content-type={}, body={}",
            context,
            status,
            content_type,
            body_snippet(&bytes),
        )));
    }

    serde_json::from_slice(&bytes).map_err(|e| {
        OnchainVerifyError::RpcError(format!(
            "{}: failed to parse RPC JSON: {} (status={}, content-type={}, body={})",
            context,
            e,
            status,
            content_type,
            body_snippet(&bytes),
        ))
    })
}

fn body_snippet(bytes: &[u8]) -> String {
    const MAX_CHARS: usize = 512;

    let text = String::from_utf8_lossy(bytes);
    let mut snippet: String = text.chars().take(MAX_CHARS).collect();
    if text.chars().count() > MAX_CHARS {
        snippet.push_str("...");
    }
    snippet.replace('\n', "\\n").replace('\r', "\\r")
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    result: Option<RpcResult>,
    error: Option<RpcError>,
}

/// `sui_getObject` for an owner lookup. A missing object is `result.error.code
/// = notExists` (or no content), which is not the same as a JSON-RPC error.
#[derive(Debug, Deserialize)]
struct OwnerObjectRpcResponse {
    result: Option<OwnerObjectRpcResult>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct OwnerObjectRpcResult {
    data: Option<ObjectData>,
    error: Option<OwnerObjectRpcObjectError>,
}

#[derive(Debug, Deserialize)]
struct OwnerObjectRpcObjectError {
    code: String,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RpcResult {
    data: Option<ObjectData>,
    /// Set when the object is missing or deleted. `data` is absent in that body.
    error: Option<ObjectReadError>,
}

#[derive(Debug, Deserialize)]
struct ObjectReadError {
    code: String,
}

/// `notExists` and `deleted` are a real removal. Any other body with no
/// content is a partial read (`RpcError`), not a miss.
fn require_get_object_content(result: RpcResult) -> Result<ObjectContent, OnchainVerifyError> {
    if let Some(error) = &result.error {
        if error.code == "notExists" || error.code == "deleted" {
            return Err(OnchainVerifyError::NotFound(format!(
                "sui_getObject {}",
                error.code
            )));
        }
    }
    result
        .data
        .and_then(|data| data.content)
        .ok_or_else(|| partial_get_object(PARTIAL_RPC_NO_CONTENT))
}

#[derive(Debug, Deserialize)]
struct ObjectData {
    content: Option<ObjectContent>,
}

#[derive(Debug, Deserialize)]
struct ObjectContent {
    /// Move type string, e.g. `0x…::account::MemWalAccount`. Checked against
    /// the configured package before any field is trusted (#398).
    #[serde(rename = "type")]
    object_type: Option<String>,
    fields: Option<serde_json::Map<String, serde_json::Value>>,
}

// ============================================================
// Error types
// ============================================================

#[derive(Debug)]
pub enum OnchainVerifyError {
    RpcError(String),
    KeyNotFound(String),
    /// The named object does not exist, the id is unparseable, or GetObject
    /// returned no object. Distinct from `KeyNotFound` (the account exists
    /// but this key is not in `delegate_keys`).
    NotFound(String),
    /// Returned when MemWalAccount.active == false.
    /// Prevents deactivated accounts from authenticating.
    AccountDeactivated(String),
    /// The named object is not `{package}::account::MemWalAccount` — a foreign
    /// or lookalike object was supplied. Blocks owner spoofing (#398).
    WrongObjectType(String),
    /// A registry walk stopped at its page cap. Auth no longer scans.
    /// Still "unavailable", not a definitive miss, so a caller must not
    /// treat it as a revoke.
    ScanCapExceeded(String),
}

impl std::fmt::Display for OnchainVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OnchainVerifyError::RpcError(msg) => write!(f, "Sui RPC error: {}", msg),
            OnchainVerifyError::KeyNotFound(msg) => write!(f, "Key not found: {}", msg),
            OnchainVerifyError::NotFound(msg) => write!(f, "Object not found: {}", msg),
            OnchainVerifyError::AccountDeactivated(msg) => {
                write!(f, "Account deactivated: {}", msg)
            }
            OnchainVerifyError::WrongObjectType(msg) => {
                write!(f, "Wrong object type: {}", msg)
            }
            OnchainVerifyError::ScanCapExceeded(msg) => {
                write!(f, "Registry scan cap exceeded: {}", msg)
            }
        }
    }
}

impl std::error::Error for OnchainVerifyError {}

impl OnchainVerifyError {
    /// True when the chain could not be consulted, as opposed to a definitive
    /// "this key is not registered / this account is dead / this object does
    /// not exist" answer.
    ///
    /// HTTP signed auth and the MCP proxy must not treat these as a revoke:
    /// a Sui gRPC 429 is `RpcError`, and logging it as "revoked on-chain"
    /// produced intermittent empty 401s that the SDK mapped to memwal_login
    /// (WALM-429).
    pub fn is_unavailable(&self) -> bool {
        match self {
            Self::RpcError(_) | Self::ScanCapExceeded(_) => true,
            Self::NotFound(_)
            | Self::KeyNotFound(_)
            | Self::AccountDeactivated(_)
            | Self::WrongObjectType(_) => false,
        }
    }

    /// Whether OAuth refresh may revoke the grant on this answer.
    ///
    /// A removed key, a deactivated account, gRPC `NotFound`, JSON-RPC
    /// `notExists` / `deleted`, or a present foreign type. A partial body,
    /// `InvalidArgument`, a missing `object_type`, an unparseable id, and
    /// any unavailable RPC are not a removal.
    pub fn revokes_oauth_refresh(&self) -> bool {
        match self {
            Self::KeyNotFound(_) | Self::AccountDeactivated(_) | Self::WrongObjectType(_) => true,
            // gRPC `Code::NotFound` uses the prefix. JSON-RPC removal uses
            // the two codes. `invalid object id` is neither.
            Self::NotFound(msg) => {
                msg.starts_with(GRPC_OBJECT_NOT_FOUND_PREFIX)
                    || msg == "sui_getObject notExists"
                    || msg == "sui_getObject deleted"
            }
            Self::RpcError(_) | Self::ScanCapExceeded(_) => false,
        }
    }
}

/// Reject any object whose Move type is not
/// `{type-origin-package}::account::MemWalAccount`. Sui preserves the original
/// publish/type-origin id across package upgrades, so this must never be the
/// current upgraded package object's id. The origin id comes from trusted
/// config, never from the object itself, so foreign lookalikes cannot
/// authenticate as an arbitrary owner (#398).
pub(crate) fn ensure_memwal_account_type(
    actual_type: Option<&str>,
    expected_type_origin_package_id: &str,
    account_object_id: &str,
) -> Result<(), OnchainVerifyError> {
    ensure_object_type(
        actual_type,
        expected_type_origin_package_id,
        "account",
        "MemWalAccount",
        account_object_id,
    )
}

fn ensure_object_type(
    actual_type: Option<&str>,
    expected_type_origin_package_id: &str,
    module: &str,
    struct_name: &str,
    object_id: &str,
) -> Result<(), OnchainVerifyError> {
    let expected = format!("{expected_type_origin_package_id}::{module}::{struct_name}");
    match actual_type {
        Some(t) if t == expected => Ok(()),
        Some(other) => Err(OnchainVerifyError::WrongObjectType(format!(
            "object {object_id} has type {other:?}, expected {expected} — foreign object rejected"
        ))),
        // Missing type is an incomplete read, not a foreign object.
        None => Err(OnchainVerifyError::RpcError(format!(
            "object {object_id} response is missing object_type; expected {expected}"
        ))),
    }
}

/// Boot-time invariant check for the package id used by the auth path. The
/// configured registry is a type-origin object: its Move type keeps the
/// original publish id across upgrades. Comparing that type to
/// MEMWAL_PACKAGE_ID makes the server refuse a natural but dangerous
/// misconfiguration where auth is pointed at an upgraded package object id.
pub async fn verify_registry_type_origin(
    http_client: &reqwest::Client,
    rpc_url: &str,
    grpc_client: Option<&sui_rpc::Client>,
    registry_id: &str,
    expected_type_origin_package_id: &str,
) -> Result<(), OnchainVerifyError> {
    let actual_type = if let Some(client) = grpc_client {
        let address: sui_sdk_types::Address = registry_id.parse().map_err(|error| {
            OnchainVerifyError::RpcError(format!("invalid registry id: {error}"))
        })?;
        let mut request = sui_rpc::proto::sui::rpc::v2::GetObjectRequest::new(&address);
        request.read_mask = Some(prost_types::FieldMask {
            paths: vec!["object_type".into()],
        });
        client
            .clone()
            .ledger_client()
            .get_object(request)
            .await
            .map_err(|error| {
                OnchainVerifyError::RpcError(format!(
                    "gRPC GetObject registry type-origin check failed: {error}"
                ))
            })?
            .into_inner()
            .object
            .and_then(|object| object.object_type)
    } else {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sui_getObject",
            "params": [registry_id, { "showType": true }]
        });
        let response = http_client
            .post(rpc_url)
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                OnchainVerifyError::RpcError(format!(
                    "registry type-origin check request failed: {error}"
                ))
            })?;
        let parsed: serde_json::Value =
            parse_json_rpc_response(response, "sui_getObject registry type-origin check").await?;
        parsed
            .pointer("/result/data/type")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
    };

    ensure_object_type(
        actual_type.as_deref(),
        expected_type_origin_package_id,
        "account",
        "AccountRegistry",
        registry_id,
    )
}

/// Fail closed at boot unless the configured executable SEAL policy is the
/// expected ABI from the immutable MemWal package lineage.
pub async fn verify_seal_policy_package(
    client: &sui_rpc::Client,
    immutable_package_id: &str,
    policy_package_id: &str,
) -> Result<(), OnchainVerifyError> {
    let immutable_id = parse_package_id("MEMWAL_PACKAGE_ID", immutable_package_id)?;
    let policy_id = parse_package_id("MEMWAL_SEAL_POLICY_PACKAGE_ID", policy_package_id)?;
    let package = client
        .clone()
        .package_client()
        .get_package(GetPackageRequest::new(&policy_id))
        .await
        .map_err(|error| {
            policy_error(format!(
                "gRPC GetPackage failed for {policy_package_id}: {error}"
            ))
        })?
        .into_inner()
        .package
        .ok_or_else(|| policy_error("gRPC GetPackage response is missing package"))?;

    validate_seal_policy_package(&package, immutable_id, policy_id)
}

fn parse_package_id(name: &str, value: &str) -> Result<Address, OnchainVerifyError> {
    value
        .parse()
        .map_err(|error| policy_error(format!("{name} is not a valid Sui address: {error}")))
}

fn policy_error(message: impl Into<String>) -> OnchainVerifyError {
    OnchainVerifyError::RpcError(format!(
        "SEAL policy package validation failed: {}",
        message.into()
    ))
}

fn validate_seal_policy_package(
    package: &Package,
    immutable_id: Address,
    policy_id: Address,
) -> Result<(), OnchainVerifyError> {
    let storage_id = package
        .storage_id
        .as_deref()
        .ok_or_else(|| policy_error("package is missing storage_id"))
        .and_then(|id| parse_package_id("GetPackage storage_id", id))?;
    if storage_id != policy_id {
        return Err(policy_error(format!(
            "storage_id {storage_id} does not match MEMWAL_SEAL_POLICY_PACKAGE_ID {policy_id}"
        )));
    }

    let original_id = package
        .original_id
        .as_deref()
        .ok_or_else(|| policy_error("package is missing original_id"))
        .and_then(|id| parse_package_id("GetPackage original_id", id))?;
    if original_id != immutable_id {
        return Err(policy_error(format!(
            "original_id {original_id} does not match MEMWAL_PACKAGE_ID {immutable_id}"
        )));
    }

    let seal_approve = package
        .modules
        .iter()
        .find(|module| module.name.as_deref() == Some("account"))
        .and_then(|module| {
            module
                .functions
                .iter()
                .find(|function| function.name.as_deref() == Some("seal_approve"))
        })
        .ok_or_else(|| policy_error("account::seal_approve is missing"))?;

    validate_seal_approve_abi(seal_approve, immutable_id)
}

fn validate_seal_approve_abi(
    function: &FunctionDescriptor,
    immutable_id: Address,
) -> Result<(), OnchainVerifyError> {
    if function.is_entry != Some(true) {
        return Err(policy_error(
            "account::seal_approve is not an entry function",
        ));
    }
    if !function.type_parameters.is_empty() {
        return Err(policy_error(
            "account::seal_approve must not have type parameters",
        ));
    }
    if !function.returns.is_empty() {
        return Err(policy_error("account::seal_approve must not return values"));
    }
    if function.parameters != expected_seal_approve_parameters(immutable_id) {
        return Err(policy_error(
            "account::seal_approve parameters do not match the current v1-new ABI",
        ));
    }
    Ok(())
}

fn expected_seal_approve_parameters(immutable_id: Address) -> Vec<OpenSignature> {
    vec![
        signature(
            None,
            signature_body(
                SignatureType::Vector,
                None,
                vec![signature_body(SignatureType::U8, None, vec![])],
            ),
        ),
        datatype_signature(
            immutable_id,
            "account",
            "AccountRegistry",
            Reference::Immutable,
        ),
        datatype_signature(
            immutable_id,
            "account",
            "MemWalAccount",
            Reference::Immutable,
        ),
        datatype_signature(
            Address::TWO,
            "tx_context",
            "TxContext",
            Reference::Immutable,
        ),
    ]
}

fn datatype_signature(
    package: Address,
    module: &str,
    name: &str,
    reference: Reference,
) -> OpenSignature {
    signature(
        Some(reference as i32),
        signature_body(
            SignatureType::Datatype,
            Some(format!("{package}::{module}::{name}")),
            vec![],
        ),
    )
}

fn signature(reference: Option<i32>, body: OpenSignatureBody) -> OpenSignature {
    let mut signature = OpenSignature::default();
    signature.reference = reference;
    signature.body = Some(body);
    signature
}

fn signature_body(
    signature_type: SignatureType,
    type_name: Option<String>,
    type_parameters: Vec<OpenSignatureBody>,
) -> OpenSignatureBody {
    let mut body = OpenSignatureBody::default();
    body.r#type = Some(signature_type as i32);
    body.type_name = type_name;
    body.type_parameter_instantiation = type_parameters;
    body
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AccountDeactivated error variant ----

    #[test]
    fn test_account_deactivated_display() {
        let err =
            OnchainVerifyError::AccountDeactivated("Account 0xabc has been deactivated".into());
        assert!(err.to_string().contains("deactivated"));
    }

    #[test]
    fn test_key_not_found_display() {
        let err = OnchainVerifyError::KeyNotFound("Key not in 3 delegate key(s)".into());
        assert!(err.to_string().contains("Key not found"));
    }

    #[test]
    fn test_rpc_error_display() {
        let err = OnchainVerifyError::RpcError("HTTP request failed".into());
        assert!(err.to_string().contains("Sui RPC error"));
    }

    #[test]
    fn test_error_variants_are_distinct() {
        let deactivated = OnchainVerifyError::AccountDeactivated("msg".into());
        let not_found = OnchainVerifyError::KeyNotFound("msg".into());
        assert!(matches!(
            deactivated,
            OnchainVerifyError::AccountDeactivated(_)
        ));
        assert!(matches!(not_found, OnchainVerifyError::KeyNotFound(_)));
        assert!(!deactivated.is_unavailable());
        assert!(!not_found.is_unavailable());
        assert!(OnchainVerifyError::RpcError("429".into()).is_unavailable());
        assert!(OnchainVerifyError::ScanCapExceeded("cap".into()).is_unavailable());
        assert!(!OnchainVerifyError::WrongObjectType("type".into()).is_unavailable());
        assert!(!OnchainVerifyError::NotFound("missing object".into()).is_unavailable());
    }

    #[test]
    fn partial_get_object_reads_do_not_revoke_or_evict() {
        let missing_type = ensure_memwal_account_type(None, "0xpkg", "0xobj").unwrap_err();
        for err in [
            partial_get_object(PARTIAL_RPC_NO_RESULT),
            partial_get_object(PARTIAL_RPC_NO_CONTENT),
            partial_get_object(PARTIAL_GRPC_OBJECT_ABSENT),
            map_get_object_status(tonic::Status::invalid_argument("bad object id")),
            missing_type,
        ] {
            assert!(err.is_unavailable(), "{err}");
            assert!(!err.revokes_oauth_refresh(), "{err}");
            assert!(!delegate_verify_evicts(&err, true), "{err}");
            assert!(!delegate_verify_evicts(&err, false), "{err}");
        }

        let real = map_get_object_status(tonic::Status::not_found("no such object"));
        assert!(!real.is_unavailable(), "{real}");
        assert!(real.revokes_oauth_refresh(), "{real}");
        assert!(delegate_verify_evicts(&real, true), "{real}");

        // A present foreign type is a finished read. Refresh revokes it.
        // Missing `object_type` is `RpcError` and is covered above.
        let foreign = OnchainVerifyError::WrongObjectType("foreign".into());
        assert!(foreign.revokes_oauth_refresh());
        assert!(delegate_verify_evicts(&foreign, false));
        assert!(delegate_verify_evicts(&foreign, true));

        let invalid_id = parse_object_id("not-a-sui-object-id").unwrap_err();
        assert!(!invalid_id.revokes_oauth_refresh(), "{invalid_id}");
        assert!(!delegate_verify_evicts(&invalid_id, true));
    }

    #[test]
    fn json_rpc_not_exists_and_deleted_revoke_but_a_bare_body_does_not() {
        for code in ["notExists", "deleted"] {
            let body = format!(r#"{{"result":{{"error":{{"code":"{code}"}}}}}}"#);
            let response: RpcResponse = serde_json::from_str(&body).expect(&body);
            let err =
                require_get_object_content(response.result.expect("result")).expect_err(&body);
            assert!(matches!(err, OnchainVerifyError::NotFound(_)), "{err}");
            assert!(err.to_string().contains(code), "{err}");
            assert!(!err.is_unavailable(), "{err}");
            assert!(err.revokes_oauth_refresh(), "{err}");
            assert!(delegate_verify_evicts(&err, true), "{err}");
            assert!(delegate_verify_evicts(&err, false), "{err}");
        }

        let bare: RpcResponse = serde_json::from_str(r#"{"result":{}}"#).unwrap();
        let err = require_get_object_content(bare.result.unwrap()).unwrap_err();
        assert!(matches!(err, OnchainVerifyError::RpcError(_)), "{err}");
        assert!(err.to_string().contains(PARTIAL_RPC_NO_CONTENT), "{err}");
        assert!(err.is_unavailable(), "{err}");
        assert!(!err.revokes_oauth_refresh(), "{err}");
        assert!(!delegate_verify_evicts(&err, true));
    }

    #[test]
    fn get_object_status_classifies_by_grpc_code() {
        for (status, unavailable) in [
            (tonic::Status::not_found("no such object"), false),
            (tonic::Status::invalid_argument("bad object id"), true),
            (
                tonic::Status::resource_exhausted("429 Too Many Requests"),
                true,
            ),
            (tonic::Status::unavailable("fullnode down"), true),
            (tonic::Status::deadline_exceeded("timeout"), true),
            (
                tonic::Status::internal("internal error: object not found while loading state"),
                true,
            ),
        ] {
            let err = map_get_object_status(status);
            assert_eq!(err.is_unavailable(), unavailable, "{err}");
            if unavailable {
                assert!(matches!(err, OnchainVerifyError::RpcError(_)), "{err}");
            } else {
                assert!(matches!(err, OnchainVerifyError::NotFound(_)), "{err}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn get_object_retries_a_transient_unavailable() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let object = with_get_object_retry(GET_OBJECT_ATTEMPTS, || {
            let attempt = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if attempt == 0 {
                    Err(tonic::Status::unavailable(
                        "The service is currently unavailable",
                    ))
                } else {
                    Ok("object")
                }
            }
        })
        .await
        .expect("second attempt succeeds");

        assert_eq!(object, "object");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn get_object_makes_one_attempt_when_a_stale_entry_can_be_served() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result: Result<&str, tonic::Status> = with_get_object_retry(1, || {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                Err(tonic::Status::unavailable(
                    "The service is currently unavailable",
                ))
            }
        })
        .await;

        assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn invalid_object_id_is_not_unavailable() {
        let err = parse_object_id("not-a-sui-object-id").unwrap_err();
        assert!(matches!(err, OnchainVerifyError::NotFound(_)));
        assert!(!err.is_unavailable());
    }

    // ── Deactivated account field parsing ────────────────────────

    #[test]
    fn json_active_field_fails_closed() {
        let fields = |json| serde_json::from_str(json).unwrap();

        assert!(json_account_active(&fields(r#"{"active":true}"#)).unwrap());
        assert!(!json_account_active(&fields(r#"{"active":false}"#)).unwrap());
        let missing = json_account_active(&fields(r#"{}"#)).unwrap_err();
        assert!(missing.is_unavailable());
        assert!(json_account_active(&fields(r#"{"active":"false"}"#)).is_err());
    }

    #[test]
    fn grpc_active_field_fails_closed() {
        use prost_types::value::Kind;

        let fields = |kind: Option<Kind>| prost_types::Struct {
            fields: kind
                .map(|kind| {
                    (
                        "active".to_string(),
                        prost_types::Value { kind: Some(kind) },
                    )
                })
                .into_iter()
                .collect(),
        };

        assert!(grpc_account_active(&fields(Some(Kind::BoolValue(true)))).unwrap());
        assert!(!grpc_account_active(&fields(Some(Kind::BoolValue(false)))).unwrap());
        let missing = grpc_account_active(&fields(None)).unwrap_err();
        assert!(missing.is_unavailable());
        assert!(grpc_account_active(&fields(Some(Kind::StringValue("false".into())))).is_err());
    }

    // ── Delegate key matching — public key as JSON array ────────────────

    #[test]
    fn test_public_key_to_json_array_conversion() {
        // Test the exact conversion done in verify_delegate_key_onchain
        let pk_bytes: [u8; 32] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let pk_as_numbers: Vec<serde_json::Value> = pk_bytes
            .iter()
            .map(|&b| serde_json::Value::Number(b.into()))
            .collect();

        assert_eq!(pk_as_numbers.len(), 32);
        assert_eq!(pk_as_numbers[0], serde_json::json!(1));
        assert_eq!(pk_as_numbers[31], serde_json::json!(32));
    }

    #[test]
    fn test_delegate_key_matching_in_struct() {
        // Simulate array comparison used in the verification loop
        let pk_bytes: &[u8] = &[10, 20, 30];
        let pk_as_numbers: Vec<serde_json::Value> = pk_bytes
            .iter()
            .map(|&b| serde_json::Value::Number(b.into()))
            .collect();

        // Matching stored key
        let stored_key = serde_json::json!([10, 20, 30]);
        let stored_arr = stored_key.as_array().unwrap();
        assert_eq!(*stored_arr, pk_as_numbers, "matching key should be Equal");

        // Non-matching stored key
        let wrong_key = serde_json::json!([10, 20, 31]);
        let wrong_arr = wrong_key.as_array().unwrap();
        assert_ne!(*wrong_arr, pk_as_numbers, "different key should NOT match");
    }

    // ── parse_delegate_keys (Task 7 — pure JSON parsing, no I/O) ────────

    #[test]
    fn parse_delegate_keys_extracts_all_fields() {
        let fields: serde_json::Map<String, serde_json::Value> = serde_json::json!({
            "owner": "0xowner",
            "active": true,
            "delegate_keys": [
                {
                    "fields": {
                        "public_key": [1, 2, 3],
                        "sui_address": "0xdelegate1",
                        "label": "cli",
                        "created_at": "1700000000000"
                    }
                },
                {
                    "fields": {
                        "public_key": [4, 5, 6],
                        "sui_address": "0xdelegate2",
                        "label": "mobile",
                        "created_at": "1700000001000"
                    }
                }
            ]
        })
        .as_object()
        .unwrap()
        .clone();

        let parsed = parse_delegate_keys(&fields).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].label, "cli");
        assert_eq!(parsed[0].sui_address, "0xdelegate1");
        assert_eq!(parsed[0].created_at, 1700000000000);
        assert_eq!(parsed[1].label, "mobile");
    }

    // ── list_delegate_keys_cached (short-TTL cache) ─────────────────────
    //
    // No mock-HTTP crate exists in this codebase's dependency tree, so these
    // tests prove the cache-hit / TTL-expiry branches without a live chain
    // call: they point at an unreachable RPC URL and rely on the fact that a
    // cache HIT returns before ever attempting the HTTP request (so it
    // succeeds despite the bad URL), while a cache MISS/expiry falls through
    // to the real request path (so it fails against the bad URL). This
    // exercises the exact branch the fix depends on.

    fn unreachable_rpc_url() -> &'static str {
        // Port 1 is a reserved/unassigned TCP port — connection is refused
        // immediately rather than hanging, so the test stays fast.
        "http://127.0.0.1:1/"
    }

    fn sample_delegate_keys() -> Vec<DelegateKeyInfo> {
        vec![DelegateKeyInfo {
            sui_address: "0xdelegate1".to_string(),
            label: "cli".to_string(),
            created_at: 1_700_000_000,
        }]
    }

    #[tokio::test]
    async fn list_delegate_keys_cached_returns_cached_value_within_ttl() {
        let cache = new_delegate_keys_cache();
        let account_id = "0xaccount-fresh";
        cache.write().await.insert(
            account_id.to_string(),
            TimedDelegateKeys {
                value: sample_delegate_keys(),
                fetched_at: std::time::Instant::now(),
            },
        );

        let client = reqwest::Client::new();
        let result = list_delegate_keys_cached(
            &cache,
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            "0xpkg",
        )
        .await;

        assert!(
            result.is_ok(),
            "a fresh cache entry must be served without attempting the RPC call, got {:?}",
            result.err()
        );
        assert_eq!(result.unwrap(), sample_delegate_keys());
    }

    #[tokio::test]
    async fn list_delegate_keys_cached_refetches_after_ttl_expiry() {
        let cache = new_delegate_keys_cache();
        let account_id = "0xaccount-stale";
        cache.write().await.insert(
            account_id.to_string(),
            TimedDelegateKeys {
                value: sample_delegate_keys(),
                fetched_at: std::time::Instant::now()
                    - DELEGATE_KEYS_CACHE_TTL
                    - std::time::Duration::from_secs(1),
            },
        );

        let client = reqwest::Client::new();
        let result = list_delegate_keys_cached(
            &cache,
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            "0xpkg",
        )
        .await;

        assert!(
            result.is_err(),
            "an expired cache entry must trigger a real re-fetch attempt, which should fail \
             against the unreachable RPC URL used in this test — got Ok, meaning the stale \
             entry was served instead"
        );
    }

    #[tokio::test]
    async fn list_delegate_keys_cached_misses_for_unknown_account() {
        let cache = new_delegate_keys_cache();
        let client = reqwest::Client::new();
        let result = list_delegate_keys_cached(
            &cache,
            &client,
            unreachable_rpc_url(),
            None,
            "0xnever-cached",
            "0xpkg",
        )
        .await;

        assert!(
            result.is_err(),
            "no cache entry exists yet, so this must attempt (and fail) the real RPC call"
        );
    }

    // ── verify_delegate_key_cached (WALM-618) ───────────────────────────
    //
    // Same no-mock-HTTP technique as the block above: a cache HIT returns
    // before any network attempt (so it succeeds against an unreachable RPC
    // URL), a MISS falls through to the real request (so it fails). That is
    // exactly the branch the fix turns on — an uncached verify ran on every
    // signed API call and every MCP envelope, ~10 fullnode reads per tool
    // call, which is what the public fullnode was throttling.

    fn sample_pk() -> Vec<u8> {
        vec![7u8; 32]
    }

    async fn seed_verify_cache(
        cache: &DelegateVerifyCache,
        account_id: &str,
        pk: &[u8],
        age: std::time::Duration,
    ) -> String {
        let owner = "0xowner-from-cache".to_string();
        cache.entries.write().await.insert(
            (account_id.to_string(), pk.to_vec()),
            TimedVerifiedOwner {
                owner: owner.clone(),
                verified_at: std::time::Instant::now() - age,
            },
        );
        owner
    }

    #[tokio::test]
    async fn verify_delegate_key_cached_returns_cached_owner_within_ttl() {
        let cache = new_delegate_verify_cache();
        let account_id = "0xaccount-verify-fresh";
        let pk = sample_pk();
        let owner = seed_verify_cache(&cache, account_id, &pk, std::time::Duration::ZERO).await;

        let client = reqwest::Client::new();
        let result = verify_delegate_key_cached(
            &cache,
            &new_delegate_reject_cache(),
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await;

        assert_eq!(
            result.ok(),
            Some(owner),
            "a fresh entry must be served without attempting the on-chain read"
        );
    }

    #[tokio::test]
    async fn verify_delegate_key_cached_reverifies_after_ttl_expiry() {
        // An expired entry must not be served on the ordinary path: the read
        // is attempted for real. Here the RPC is unreachable, so the attempt
        // fails and the stale-grace path below decides what happens next —
        // this test only pins that the live read was actually made.
        let cache = new_delegate_verify_cache();
        let account_id = "0xaccount-verify-stale";
        let pk = sample_pk();
        seed_verify_cache(
            &cache,
            account_id,
            &pk,
            DELEGATE_VERIFY_CACHE_TTL + std::time::Duration::from_secs(1),
        )
        .await;

        let before = cache
            .entries
            .read()
            .await
            .get(&(account_id.to_string(), pk.clone()))
            .map(|c| c.verified_at);

        let client = reqwest::Client::new();
        let _ = verify_delegate_key_cached(
            &cache,
            &new_delegate_reject_cache(),
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await;

        let after = cache
            .entries
            .read()
            .await
            .get(&(account_id.to_string(), pk.clone()))
            .map(|c| c.verified_at);
        assert_eq!(
            before, after,
            "a failed re-verify must not refresh the entry's timestamp — otherwise a key \
             could be renewed indefinitely by an outage and never re-checked"
        );
    }

    #[tokio::test]
    async fn verify_delegate_key_cached_serves_stale_entry_while_chain_unavailable() {
        // The WALM-618 case: a valid key, verified minutes ago, used again
        // while the public fullnode is throttling. Before this, every such
        // call was a 503 even though nothing about the key had changed.
        let cache = new_delegate_verify_cache();
        let account_id = "0xaccount-verify-grace";
        let pk = sample_pk();
        let owner = seed_verify_cache(
            &cache,
            account_id,
            &pk,
            DELEGATE_VERIFY_CACHE_TTL + std::time::Duration::from_secs(60),
        )
        .await;

        let client = reqwest::Client::new();
        let result = verify_delegate_key_cached(
            &cache,
            &new_delegate_reject_cache(),
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await;

        assert_eq!(
            result.ok(),
            Some(owner),
            "an entry inside the stale grace must be served when the chain cannot be read"
        );
    }

    #[tokio::test]
    async fn refresh_verify_does_not_serve_a_stale_positive() {
        // OAuth refresh skips `DELEGATE_VERIFY_STALE_GRACE`. Past the 30s TTL
        // an unreachable chain is an error, not a mint.
        let cache = new_delegate_verify_cache();
        let account_id = "0xaccount-refresh-no-grace";
        let pk = sample_pk();
        seed_verify_cache(
            &cache,
            account_id,
            &pk,
            DELEGATE_VERIFY_CACHE_TTL + std::time::Duration::from_secs(60),
        )
        .await;

        let client = reqwest::Client::new();
        let result = verify_delegate_key_cached_for_refresh(
            &cache,
            &new_delegate_reject_cache(),
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await;

        let err = result.expect_err("refresh must not mint from the stale grace");
        assert!(err.is_unavailable(), "{err}");
        assert!(!err.revokes_oauth_refresh(), "{err}");
        assert!(
            cache
                .entries
                .read()
                .await
                .contains_key(&(account_id.to_string(), pk)),
            "an unavailable read must not evict the positive other callers still serve"
        );
    }

    #[tokio::test]
    async fn refresh_verify_still_serves_a_fresh_positive() {
        // The revocation window on refresh is the 30s TTL, not zero.
        let cache = new_delegate_verify_cache();
        let account_id = "0xaccount-refresh-fresh";
        let pk = sample_pk();
        let owner = seed_verify_cache(&cache, account_id, &pk, std::time::Duration::ZERO).await;

        let client = reqwest::Client::new();
        let result = verify_delegate_key_cached_for_refresh(
            &cache,
            &new_delegate_reject_cache(),
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await;

        assert_eq!(result.ok(), Some(owner));
    }

    #[tokio::test]
    async fn verify_delegate_key_cached_refuses_stale_entry_past_the_grace() {
        // The grace is bounded. Past it the outage is no longer an excuse and
        // the caller gets the unavailable error, so a key revoked during a
        // long outage cannot authenticate forever.
        let cache = new_delegate_verify_cache();
        let account_id = "0xaccount-verify-past-grace";
        let pk = sample_pk();
        seed_verify_cache(
            &cache,
            account_id,
            &pk,
            DELEGATE_VERIFY_CACHE_TTL
                + DELEGATE_VERIFY_STALE_GRACE
                + std::time::Duration::from_secs(1),
        )
        .await;

        let client = reqwest::Client::new();
        let result = verify_delegate_key_cached(
            &cache,
            &new_delegate_reject_cache(),
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await;

        assert!(
            result.is_err(),
            "past TTL + grace the entry must not be served, outage or not"
        );
    }

    #[test]
    fn a_borrowed_probe_finds_the_key_an_owned_insert_wrote() {
        // If `(String, Vec<u8>)` and `(&str, &[u8])` ever hashed differently,
        // every lookup would miss silently: no error, no panic, just a cache
        // that never hits and a `GetObject` per request — the exact thing this
        // PR exists to remove. Worth an explicit assertion rather than trust.
        use std::collections::HashMap;

        let mut map: HashMap<(String, Vec<u8>), &str> = HashMap::new();
        map.insert(("0xaccount".to_string(), vec![7u8; 32]), "owner");

        let probe: &dyn DelegateAccountKey = &("0xaccount", &[7u8; 32][..]);
        assert_eq!(map.get(probe).copied(), Some("owner"));

        let wrong_account: &dyn DelegateAccountKey = &("0xother", &[7u8; 32][..]);
        assert_eq!(map.get(wrong_account), None);

        let wrong_key: &dyn DelegateAccountKey = &("0xaccount", &[9u8; 32][..]);
        assert_eq!(
            map.get(wrong_key),
            None,
            "a different delegate key on the same account must not collide"
        );

        // Removal through the borrowed probe has to reach the owned entry too,
        // or a revoke would be observed and then quietly not applied.
        assert_eq!(map.remove(probe), Some("owner"));
        assert!(map.is_empty());
    }

    #[test]
    fn an_unavailable_error_never_evicts_so_a_concurrent_success_survives() {
        // The race this pins: thread A misses (no entry, or a stale one),
        // thread B verifies successfully and writes a FRESH entry, then A's
        // own read fails with an unavailable RPC. Evicting on that error
        // would delete B's valid entry on the strength of a failure that says
        // nothing about the key. `Keep` is unconditional, so no interleaving
        // is needed to guarantee it — the policy itself is the guarantee.
        assert_eq!(
            verify_cache_miss_action(&OnchainVerifyError::RpcError("throttled".into())),
            VerifyCacheMissAction::Keep,
            "an unavailable read must never remove an entry it did not observe"
        );
        assert_eq!(
            verify_cache_miss_action(&OnchainVerifyError::ScanCapExceeded("cap".into())),
            VerifyCacheMissAction::Keep
        );
    }

    #[test]
    fn stale_grace_is_only_reachable_through_the_unavailable_branch() {
        // Guards the pairing the outage path depends on: the only error class
        // that keeps an entry is the one the stale read is allowed to serve.
        // If a definitive rejection ever became `Keep`, a revoked key would
        // start riding the grace window.
        assert_eq!(
            verify_cache_miss_action(&OnchainVerifyError::KeyNotFound("k".into())),
            VerifyCacheMissAction::Evict
        );
        assert_eq!(
            verify_cache_miss_action(&OnchainVerifyError::AccountDeactivated("a".into())),
            VerifyCacheMissAction::Evict
        );
        assert_eq!(
            verify_cache_miss_action(&OnchainVerifyError::RpcError("throttled".into())),
            VerifyCacheMissAction::Keep
        );
    }

    async fn seed_reject_cache(
        cache: &DelegateRejectCache,
        account_id: &str,
        pk: &[u8],
        age: std::time::Duration,
    ) {
        cache.write().await.insert(
            (account_id.to_string(), pk.to_vec()),
            std::time::Instant::now() - age,
        );
    }

    #[tokio::test]
    async fn a_remembered_rejection_is_reused_without_touching_the_chain() {
        // The 401 loop: ~70% of `/api/mcp/sse` traffic is a bridge retrying a
        // key that will never be accepted, and each retry cost one fullnode
        // read. `KeyNotFound` here (rather than the `RpcError` the
        // unreachable URL would produce) proves no read was attempted.
        let cache = new_delegate_verify_cache();
        let rejects = new_delegate_reject_cache();
        let account_id = "0xaccount-reject-fresh";
        let pk = sample_pk();
        seed_reject_cache(&rejects, account_id, &pk, std::time::Duration::ZERO).await;

        let client = reqwest::Client::new();
        let err = verify_delegate_key_cached(
            &cache,
            &rejects,
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await
        .expect_err("a remembered rejection must still be a rejection");

        assert!(
            !err.is_unavailable(),
            "served from the reject cache, so it must not look like an RPC failure: {err}"
        );
    }

    #[tokio::test]
    async fn an_expired_rejection_goes_back_to_the_chain() {
        let cache = new_delegate_verify_cache();
        let rejects = new_delegate_reject_cache();
        let account_id = "0xaccount-reject-expired";
        let pk = sample_pk();
        seed_reject_cache(
            &rejects,
            account_id,
            &pk,
            DELEGATE_REJECT_CACHE_TTL + std::time::Duration::from_secs(1),
        )
        .await;

        let client = reqwest::Client::new();
        let err = verify_delegate_key_cached(
            &cache,
            &rejects,
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await
        .expect_err("the unreachable RPC still fails");

        assert!(
            err.is_unavailable(),
            "past the TTL the chain must be consulted again, so the error is the RPC's: {err}"
        );
    }

    #[tokio::test]
    async fn a_registered_key_is_never_held_back_by_an_older_rejection() {
        // Ordering guard: the positive lookup runs first, so a key that was
        // refused before its registration landed starts working the moment a
        // verification succeeds, without waiting out the rejection TTL.
        let cache = new_delegate_verify_cache();
        let rejects = new_delegate_reject_cache();
        let account_id = "0xaccount-reject-then-registered";
        let pk = sample_pk();
        let owner = seed_verify_cache(&cache, account_id, &pk, std::time::Duration::ZERO).await;
        seed_reject_cache(&rejects, account_id, &pk, std::time::Duration::ZERO).await;

        let client = reqwest::Client::new();
        let result = verify_delegate_key_cached(
            &cache,
            &rejects,
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await;

        assert_eq!(result.ok(), Some(owner), "the positive entry must win");
    }

    #[test]
    fn the_rejection_cache_cap_bounds_what_callers_can_grow() {
        // Keyed by what callers send, so without a cap anyone could grow it
        // one entry per made-up pair. Refreshing an entry that already exists
        // cannot grow the map and stays allowed at the cap.
        assert!(should_record_rejection(0, false));
        assert!(should_record_rejection(
            DELEGATE_REJECT_CACHE_MAX_ENTRIES - 1,
            false
        ));
        assert!(
            !should_record_rejection(DELEGATE_REJECT_CACHE_MAX_ENTRIES, false),
            "a new pair at the cap must fall back to the live read, not evict something"
        );
        assert!(
            should_record_rejection(DELEGATE_REJECT_CACHE_MAX_ENTRIES, true),
            "refreshing an existing entry does not grow the map"
        );
    }

    #[tokio::test]
    async fn expired_rejections_do_not_hold_the_cap_against_a_genuine_one() {
        // The cap is consulted with the map's raw length, but the TTL is 10s
        // and the sweeper runs every 300s — so without expiring first, up to
        // thirty generations of entries nobody can be served from still hold
        // every slot. A few thousand made-up pairs then block every genuine
        // rejection for five minutes, and each looping client goes back to
        // one fullnode read per retry.
        //
        // This pins the policy, not the call site: the retain is inline in
        // `verify_delegate_key_cached`'s Evict arm, which needs a chain that
        // answers definitively and so cannot run offline. Keep the two in
        // step by hand.
        let rejects = new_delegate_reject_cache();
        {
            let mut map = rejects.write().await;
            let dead = std::time::Instant::now()
                - (DELEGATE_REJECT_CACHE_TTL + std::time::Duration::from_secs(1));
            for i in 0..DELEGATE_REJECT_CACHE_MAX_ENTRIES {
                map.insert((format!("0xspam-{i}"), sample_pk()), dead);
            }
        }

        assert!(
            !should_record_rejection(rejects.read().await.len(), false),
            "precondition: the cap is full, so a new pair would be turned away"
        );

        rejects
            .write()
            .await
            .retain(|_, rejected_at| reject_entry_is_fresh(*rejected_at));

        assert!(
            rejects.read().await.is_empty(),
            "every seeded entry is past the TTL, so none may be kept"
        );
        assert!(
            should_record_rejection(rejects.read().await.len(), false),
            "after expiring, a genuine rejection has room again"
        );
    }

    #[test]
    fn a_verification_overtaken_by_an_eviction_is_not_stored() {
        // Cold misses are not single-flighted, so A can be reading while B
        // observes a revoke and evicts. Without this check A's older success
        // lands afterwards and re-opens a full trust window on a dead key.
        assert!(may_store_verification(7, 7), "nothing moved, safe to store");
        assert!(
            !may_store_verification(7, 8),
            "an eviction landed mid-read; the chain has contradicted this answer"
        );
    }

    #[test]
    fn a_rejection_is_forgotten_sooner_than_a_success_is_trusted() {
        // The asymmetry that makes the negative cache safe: a stale positive
        // authenticates a revoked key, a stale negative only delays one that
        // just became valid.
        assert!(
            DELEGATE_REJECT_CACHE_TTL < DELEGATE_VERIFY_CACHE_TTL,
            "a rejection must never outlive the trust window for a success"
        );
    }

    #[test]
    fn stale_grace_outlives_the_ttl_so_the_sweeper_has_something_to_serve() {
        // `main.rs` sweeps on `is_servable_while_unavailable`. If that ever
        // collapsed back to the TTL the outage path would still compile and
        // still be dead, because the entry would already have been evicted.
        let entry = TimedVerifiedOwner {
            owner: "0xowner".into(),
            verified_at: std::time::Instant::now()
                - (DELEGATE_VERIFY_CACHE_TTL + std::time::Duration::from_secs(1)),
        };
        assert!(!entry.is_fresh(), "past the TTL on the ordinary path");
        assert!(
            entry.is_servable_while_unavailable(),
            "but still held for the outage path"
        );
    }

    #[tokio::test]
    async fn verify_delegate_key_cached_entry_is_scoped_to_account_and_key() {
        let cache = new_delegate_verify_cache();
        let account_id = "0xaccount-verify-scope";
        let pk = sample_pk();
        seed_verify_cache(&cache, account_id, &pk, std::time::Duration::ZERO).await;

        let client = reqwest::Client::new();

        let other_key = vec![9u8; 32];
        assert!(
            verify_delegate_key_cached(
                &cache,
                &new_delegate_reject_cache(),
                &client,
                unreachable_rpc_url(),
                None,
                account_id,
                &other_key,
                "0xpkg",
            )
            .await
            .is_err(),
            "a different delegate key on the same account must not ride this entry"
        );

        assert!(
            verify_delegate_key_cached(
                &cache,
                &new_delegate_reject_cache(),
                &client,
                unreachable_rpc_url(),
                None,
                "0xsome-other-account",
                &pk,
                "0xpkg",
            )
            .await
            .is_err(),
            "the same delegate key on a different account must not ride this entry"
        );
    }

    #[tokio::test]
    async fn verify_delegate_key_cached_keeps_entry_when_rpc_is_unavailable() {
        let cache = new_delegate_verify_cache();
        let account_id = "0xaccount-verify-unavailable";
        let pk = sample_pk();
        seed_verify_cache(
            &cache,
            account_id,
            &pk,
            DELEGATE_VERIFY_CACHE_TTL + std::time::Duration::from_secs(1),
        )
        .await;

        let client = reqwest::Client::new();
        let _ = verify_delegate_key_cached(
            &cache,
            &new_delegate_reject_cache(),
            &client,
            unreachable_rpc_url(),
            None,
            account_id,
            &pk,
            "0xpkg",
        )
        .await;

        assert!(
            cache
                .entries
                .read()
                .await
                .contains_key(&(account_id.to_string(), pk.clone())),
            "a transport failure is not a revoke, so it must not evict the pair"
        );
    }

    #[test]
    fn verify_cache_miss_action_evicts_only_on_a_definitive_rejection() {
        for err in [
            OnchainVerifyError::KeyNotFound("revoked".into()),
            OnchainVerifyError::AccountDeactivated("deactivated".into()),
            OnchainVerifyError::NotFound("missing object".into()),
            OnchainVerifyError::WrongObjectType("lookalike".into()),
        ] {
            assert_eq!(
                verify_cache_miss_action(&err),
                VerifyCacheMissAction::Evict,
                "{err}"
            );
        }
        for err in [
            OnchainVerifyError::RpcError("429 Too Many Requests".into()),
            OnchainVerifyError::ScanCapExceeded("cap".into()),
        ] {
            assert_eq!(
                verify_cache_miss_action(&err),
                VerifyCacheMissAction::Keep,
                "{err}"
            );
        }
    }

    #[tokio::test]
    async fn delegate_verify_cache_sweep_keeps_what_the_outage_path_can_serve() {
        let cache = new_delegate_verify_cache();
        seed_verify_cache(&cache, "0xfresh", &sample_pk(), std::time::Duration::ZERO).await;
        // Past the TTL, so `is_fresh` is already false and the ordinary lookup
        // will not serve it — but inside the grace, which is precisely what
        // the unavailable branch falls back to.
        seed_verify_cache(
            &cache,
            "0xin-grace",
            &sample_pk(),
            DELEGATE_VERIFY_CACHE_TTL + std::time::Duration::from_secs(1),
        )
        .await;
        seed_verify_cache(
            &cache,
            "0xpast-grace",
            &sample_pk(),
            DELEGATE_VERIFY_CACHE_TTL
                + DELEGATE_VERIFY_STALE_GRACE
                + std::time::Duration::from_secs(1),
        )
        .await;

        // The predicate `main.rs`'s sweep task uses. Sweeping on `is_fresh`
        // instead would evict `0xin-grace` 30s after it was verified — the
        // entry the stale-serve path exists to use — so the sweep bound has
        // to be the grace, not the TTL.
        cache
            .entries
            .write()
            .await
            .retain(|_, v| v.is_servable_while_unavailable());

        let remaining = cache.entries.read().await;
        assert!(remaining.contains_key(&("0xfresh".to_string(), sample_pk())));
        assert!(
            remaining.contains_key(&("0xin-grace".to_string(), sample_pk())),
            "sweeping on the TTL would delete exactly what the unavailable branch serves"
        );
        assert!(!remaining.contains_key(&("0xpast-grace".to_string(), sample_pk())));
    }

    #[tokio::test]
    async fn a_rejected_key_records_nothing_so_it_cannot_grow_the_map() {
        // The MCP proxy takes `x-memwal-account-id` from an unauthenticated
        // header and only checks that it is non-empty, and `/api/mcp/*` has no
        // rate limit ahead of the verify. Caching rejections would therefore
        // let an anonymous caller mint one entry per made-up account id. Only
        // successes are stored, so the map stays bounded by real accounts.
        let cache = new_delegate_verify_cache();
        let client = reqwest::Client::new();
        for i in 0..5 {
            let _ = verify_delegate_key_cached(
                &cache,
                &new_delegate_reject_cache(),
                &client,
                unreachable_rpc_url(),
                None,
                &format!("0xmade-up-{i}"),
                &sample_pk(),
                "0xpkg",
            )
            .await;
        }
        assert!(
            cache.entries.read().await.is_empty(),
            "a failed verification must leave no entry behind"
        );
    }

    // ── DelegateKeysCache periodic sweep (nothing else ever removed a map
    //    slot — only the TTL above gated trust-on-hit) ───────────────────
    //
    // The sweep itself is a `tokio::spawn` + `interval` loop in `main.rs`
    // (not unit-testable in isolation without booting the binary), but its
    // core logic is exactly this `retain` predicate. This test locks that
    // predicate down against the two failure modes that would silently
    // reintroduce the leak: evicting entries that are still within
    // `DELEGATE_KEYS_CACHE_MAX_AGE`, or failing to evict ones that aren't.
    #[tokio::test]
    async fn delegate_keys_cache_sweep_predicate_evicts_only_stale_entries() {
        let cache = new_delegate_keys_cache();
        cache.write().await.insert(
            "0xstale".to_string(),
            TimedDelegateKeys {
                value: vec![],
                fetched_at: std::time::Instant::now()
                    - DELEGATE_KEYS_CACHE_MAX_AGE
                    - std::time::Duration::from_secs(1),
            },
        );
        cache.write().await.insert(
            "0xfresh".to_string(),
            TimedDelegateKeys {
                value: vec![],
                fetched_at: std::time::Instant::now(),
            },
        );

        // Mirrors main.rs's `delegate_cache_sweep` task body verbatim.
        cache
            .write()
            .await
            .retain(|_, v| v.fetched_at.elapsed() < DELEGATE_KEYS_CACHE_MAX_AGE);

        let remaining = cache.read().await;
        assert!(
            !remaining.contains_key("0xstale"),
            "entry older than DELEGATE_KEYS_CACHE_MAX_AGE must be evicted"
        );
        assert!(
            remaining.contains_key("0xfresh"),
            "entry younger than DELEGATE_KEYS_CACHE_MAX_AGE must survive the sweep"
        );
    }

    #[test]
    fn test_delegate_key_in_fields_wrapper() {
        // Test the delegate key extraction with the "fields" wrapper pattern
        let dk_json = serde_json::json!({
            "fields": {
                "public_key": [1, 2, 3],
                "label": "test-key",
                "created_at": "123456"
            }
        });

        let dk_fields = dk_json.get("fields").or(Some(&dk_json));
        let stored_key = dk_fields.and_then(|f| f.get("public_key"));
        assert!(stored_key.is_some());
        assert_eq!(
            stored_key.unwrap().as_array().unwrap(),
            &vec![
                serde_json::json!(1),
                serde_json::json!(2),
                serde_json::json!(3),
            ]
        );
    }

    #[test]
    fn test_delegate_key_without_fields_wrapper() {
        // Test the fallback when there's no "fields" wrapper
        let dk_json = serde_json::json!({
            "public_key": [4, 5, 6],
            "label": "test-key"
        });

        let dk_fields = dk_json.get("fields").or(Some(&dk_json));
        let stored_key = dk_fields.and_then(|f| f.get("public_key"));
        assert!(stored_key.is_some());
        assert_eq!(
            stored_key.unwrap().as_array().unwrap(),
            &vec![
                serde_json::json!(4),
                serde_json::json!(5),
                serde_json::json!(6),
            ]
        );
    }

    // ── OnchainVerifyError: Display correctness ─────────────────────────

    #[test]
    fn test_account_deactivated_display_includes_account_id() {
        let err =
            OnchainVerifyError::AccountDeactivated("Account 0xabc has been deactivated".into());
        let display = err.to_string();
        assert!(display.contains("deactivated"));
        assert!(display.contains("0xabc"));
    }

    #[test]
    fn test_error_is_std_error() {
        // Verify OnchainVerifyError implements std::error::Error
        let err: Box<dyn std::error::Error> =
            Box::new(OnchainVerifyError::AccountDeactivated("test".into()));
        assert!(err.to_string().contains("deactivated"));
    }

    // ── #398: object Move-type check ────────────────────────────────────────
    #[test]
    fn test_ensure_memwal_account_type() {
        let original_type_origin_pkg = "0xabc";
        let upgraded_current_pkg = "0xdef";
        // After an upgrade the object still carries the original type-origin
        // package id, so pinning that immutable id keeps auth working.
        assert!(ensure_memwal_account_type(
            Some("0xabc::account::MemWalAccount"),
            original_type_origin_pkg,
            "0xobj"
        )
        .is_ok());
        // A foreign lookalike (same field names, different type) — the #398
        // spoofing object — is rejected.
        assert!(matches!(
            ensure_memwal_account_type(
                Some("0xdef::fake_account::FakeAccount"),
                original_type_origin_pkg,
                "0xobj"
            ),
            Err(OnchainVerifyError::WrongObjectType(_))
        ));
        // Mistakenly configuring the upgraded/current package id rejects the
        // genuine object's original type, making the configuration error clear.
        assert!(matches!(
            ensure_memwal_account_type(
                Some("0xabc::account::MemWalAccount"),
                upgraded_current_pkg,
                "0xobj"
            ),
            Err(OnchainVerifyError::WrongObjectType(_))
        ));
        // Missing type is an incomplete read, not a foreign object.
        let missing = ensure_memwal_account_type(None, original_type_origin_pkg, "0xobj")
            .expect_err("missing type");
        assert!(missing.is_unavailable(), "{missing}");
        assert!(!missing.revokes_oauth_refresh(), "{missing}");
    }

    #[test]
    fn test_registry_type_origin_rejects_upgraded_package_id() {
        let origin = "0xabc";
        let actual = "0xabc::account::AccountRegistry";
        assert!(ensure_object_type(
            Some(actual),
            origin,
            "account",
            "AccountRegistry",
            "0xregistry",
        )
        .is_ok());

        let error = ensure_object_type(
            Some(actual),
            "0xupgraded",
            "account",
            "AccountRegistry",
            "0xregistry",
        )
        .expect_err("upgraded package id must fail closed");
        assert!(error
            .to_string()
            .contains("0xupgraded::account::AccountRegistry"));
    }

    fn seal_policy_package_fixture() -> (Package, Address, Address) {
        let immutable_id: Address = "0xabc".parse().unwrap();
        let policy_id: Address = "0xdef".parse().unwrap();

        let mut seal_approve = FunctionDescriptor::default();
        seal_approve.name = Some("seal_approve".into());
        seal_approve.is_entry = Some(true);
        seal_approve.parameters = expected_seal_approve_parameters(immutable_id);

        let mut account = sui_rpc::proto::sui::rpc::v2::Module::default();
        account.name = Some("account".into());
        account.functions = vec![seal_approve];

        let mut package = Package::default();
        package.storage_id = Some(policy_id.to_string());
        package.original_id = Some(immutable_id.to_string());
        package.modules = vec![account];
        (package, immutable_id, policy_id)
    }

    #[test]
    fn seal_policy_package_accepts_exact_v1_new_abi() {
        let (package, immutable_id, policy_id) = seal_policy_package_fixture();
        validate_seal_policy_package(&package, immutable_id, policy_id).unwrap();
    }

    #[test]
    fn seal_policy_package_rejects_storage_or_lineage_mismatch() {
        let (package, immutable_id, policy_id) = seal_policy_package_fixture();

        let mut wrong_storage = package.clone();
        wrong_storage.storage_id = Some(Address::TWO.to_string());
        assert!(
            validate_seal_policy_package(&wrong_storage, immutable_id, policy_id)
                .unwrap_err()
                .to_string()
                .contains("storage_id")
        );

        let mut wrong_lineage = package;
        wrong_lineage.original_id = Some(Address::THREE.to_string());
        assert!(
            validate_seal_policy_package(&wrong_lineage, immutable_id, policy_id)
                .unwrap_err()
                .to_string()
                .contains("original_id")
        );
    }

    #[test]
    fn seal_policy_package_rejects_entry_or_parameter_drift() {
        let (package, immutable_id, policy_id) = seal_policy_package_fixture();

        let mut not_entry = package.clone();
        not_entry.modules[0].functions[0].is_entry = Some(false);
        assert!(
            validate_seal_policy_package(&not_entry, immutable_id, policy_id)
                .unwrap_err()
                .to_string()
                .contains("not an entry")
        );

        let mut generic = package.clone();
        generic.modules[0].functions[0]
            .type_parameters
            .push(Default::default());
        assert!(validate_seal_policy_package(&generic, immutable_id, policy_id).is_err());

        let mut returns_value = package.clone();
        returns_value.modules[0].functions[0]
            .returns
            .push(Default::default());
        assert!(validate_seal_policy_package(&returns_value, immutable_id, policy_id).is_err());

        let mut wrong_parameters = package;
        wrong_parameters.modules[0].functions[0].parameters[3].reference =
            Some(Reference::Mutable as i32);
        assert!(
            validate_seal_policy_package(&wrong_parameters, immutable_id, policy_id)
                .unwrap_err()
                .to_string()
                .contains("current v1-new ABI")
        );
    }

    #[test]
    fn seal_policy_package_rejects_invalid_configured_ids() {
        assert!(parse_package_id("MEMWAL_PACKAGE_ID", "not-an-address").is_err());
        assert!(parse_package_id("MEMWAL_SEAL_POLICY_PACKAGE_ID", "0xnothex").is_err());
    }

    // ── gRPC path: live network tests (real testnet, no mocking) ─────────
    // `cargo test -- --ignored` to run. Not part of the default suite since
    // it needs real network access — but this is exactly how the equivalent
    // gRPC shape bugs were caught on the TS side during this same migration
    // (guessing from docs got the shape wrong twice; live testing didn't).

    #[tokio::test]
    #[ignore]
    async fn test_verify_delegate_key_onchain_grpc_real_account() {
        // Real MemWalAccount on testnet with a known delegate_keys entry,
        // confirmed live while migrating the sidecar/web app to gRPC for
        // this same JSON-RPC sunset.
        let account_id = "0xfba86e31b07ce36748ffe46de494bd4a2fa0058a5851ec4006141abcc5498fe2";
        let wrong_key = [0u8; 32];
        // The account is defined by the V1 testnet package; pass it so the type
        // check passes and we reach the (wrong) key check.
        let expected_pkg = "0xcf6ad755a1cdff7217865c796778fabe5aa399cb0cf2eba986f4b582047229c6";

        let client = sui_rpc::Client::new("https://fullnode.testnet.sui.io").unwrap();
        let result = verify_delegate_key_onchain_grpc(
            client,
            account_id,
            &wrong_key,
            expected_pkg,
            GET_OBJECT_ATTEMPTS,
        )
        .await;

        // The account genuinely exists and gRPC parses it correctly — a
        // non-matching key must fail with KeyNotFound, not RpcError. Getting
        // RpcError here means the gRPC request/response shape is wrong, not
        // that the key is missing.
        match result {
            Err(OnchainVerifyError::KeyNotFound(_)) => {}
            other => {
                panic!("expected KeyNotFound for a real account with a wrong key, got: {other:?}")
            }
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_verify_delegate_key_onchain_grpc_missing_object() {
        // Object that doesn't exist onchain — must surface as an error, not panic.
        let fake_id = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let client = sui_rpc::Client::new("https://fullnode.testnet.sui.io").unwrap();
        let result = verify_delegate_key_onchain_grpc(
            client,
            fake_id,
            &[0u8; 32],
            "0xcf6ad755a1cdff7217865c796778fabe5aa399cb0cf2eba986f4b582047229c6",
            GET_OBJECT_ATTEMPTS,
        )
        .await;
        assert!(
            matches!(result, Err(OnchainVerifyError::NotFound(_))),
            "missing object must be NotFound, not unavailable RpcError, got: {result:?}"
        );
    }
}

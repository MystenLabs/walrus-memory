//! In-process Rust Walrus upload, durable journal step machine, metadata/transfer PTB builder,
//! on-chain blob query/verification, concurrency limiter, and wallet-balance inspector.
//!
//! Replaces `services/server/scripts/sidecar/routes/walrus*.ts`, `blob-metadata.ts`,
//! `concurrency.ts`, and `routes/balances.ts` using `walrus-core` (`EncodingConfig`,
//! `BlobId`, `BlobMetadataApi`, `ConfirmationCertificate`), `seal-crypto` (`EncryptedObject`),
//! and `sui-rpc` gRPC.

use std::collections::HashMap;
use std::num::NonZeroU16;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock, RwLock as StdRwLock,
};
use std::time::{Duration, Instant};

use base64::Engine as _;
use fastcrypto::hash::{HashFunction as _, Sha256};
use seal_crypto::EncryptedObject;
use serde::{Deserialize, Serialize};
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{
    BatchGetObjectsRequest, GetObjectRequest, ListBalancesRequest, ListDynamicFieldsRequest,
    ListOwnedObjectsRequest,
};
use sui_sdk_types::{
    Address, Digest, Identifier, ObjectData, ProgrammableTransaction, StructTag, TypeTag,
};
use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};
use tokio::sync::{Notify, RwLock};
use walrus_core::{
    encoding::{encoded_blob_length_for_n_shards, EncodingConfig, EncodingFactory as _},
    messages::ConfirmationCertificate,
    metadata::BlobMetadataApi as _,
    BlobId, EncodingType,
};

use crate::storage::walrus::{
    BlobStorageLease, BlobStorageLeases, DurableUploadAdvance, FoundBlobByJob, OnChainBlob,
    SealPersistence, SetMetadataBatchEntry, UploadBlobError, UploadExecutionIdentity,
    UploadJournal, UploadResult,
};
use crate::sui::enoki::{
    derive_sui_address, parse_sui_private_key, shared_sui_grpc_client, submit_wallet_ptb,
    submit_wallet_ptb_with_allowed_addresses, WalletTxOutcome,
};
use crate::types::{AppError, Config};

// ---------------------------------------------------------------------------
// Network Constants (matching `@mysten/walrus` & `scripts/sidecar/config.ts`)
// ---------------------------------------------------------------------------

pub const TESTNET_WALRUS_PACKAGE_ID: &str =
    "0xd84704c17fc870b8764832c535aa6b11f21a95cd6f5bb38a9b07d2cf42220c66";
pub const MAINNET_WALRUS_PACKAGE_ID: &str =
    "0xfdc88f7d7cf30afab2f82e8380d11ee8f70efb90e863d1de8616fae1bb09ea77";

pub const TESTNET_WALRUS_SYSTEM_OBJECT_ID: &str =
    "0x6c2547cbbc38025cf3adac45f63cb0a8d12ecf777cdc75a4971612bf97fdf6af";
pub const MAINNET_WALRUS_SYSTEM_OBJECT_ID: &str =
    "0x2134d52768ea07e8c43570ef975eb3e4c27a39fa6396bef985b5abc58d03ddd2";

pub const TESTNET_WAL_COIN_TYPE: &str =
    "0x8270feb7375eee355e64fdb69c50abb6b5f9393a722883c1cf45f8e26048810a::wal::WAL";
pub const MAINNET_WAL_COIN_TYPE: &str =
    "0x356a26eb9e012a68958082340d4c4116e7f55615cf27affcff209cf0ae544f59::wal::WAL";

const SUI_COIN_TYPE: &str = "0x2::sui::SUI";
const BYTES_PER_UNIT_SIZE: u64 = 1024 * 1024; // 1 MiB
pub const IN_PROCESS_SIDECAR_URL: &str = "in-process://rust";

// ---------------------------------------------------------------------------
// Runtime Config Snapshot (populated from `Config` at server startup or env)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NativeRuntimeConfig {
    pub grpc_url: String,
    pub sui_network: String,
    pub walrus_publisher_url: String,
    pub walrus_package_id: String,
    pub walrus_system_object_id: String,
    pub sui_private_keys: Vec<String>,
    pub package_id: String,
    pub seal_policy_package_id: String,
    pub registry_id: String,
}

impl NativeRuntimeConfig {
    #[allow(dead_code)]
    pub fn from_config(config: &Config) -> Self {
        let grpc_url = config
            .sui_grpc_url
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&config.sui_rpc_url)
            .to_owned();
        Self {
            grpc_url,
            sui_network: config.sui_network.clone(),
            walrus_publisher_url: effective_walrus_upload_relay_url(
                &config.sui_network,
                &config.walrus_publisher_url,
            ),
            walrus_package_id: effective_walrus_package_id(
                &config.sui_network,
                &config.walrus_package_id,
            ),
            walrus_system_object_id: effective_walrus_system_object_id(
                &config.sui_network,
                &config.walrus_system_object_id,
            ),
            sui_private_keys: config.sui_private_keys.clone(),
            package_id: config.package_id.clone(),
            seal_policy_package_id: config.seal_policy_package_id.clone(),
            registry_id: config.registry_id.clone(),
        }
    }

    pub fn from_env_fallback() -> Self {
        let sui_network = std::env::var("SUI_NETWORK")
            .unwrap_or_else(|_| "testnet".to_owned())
            .trim()
            .to_ascii_lowercase();
        let default_rpc = match sui_network.as_str() {
            "testnet" => "https://fullnode.testnet.sui.io:443",
            "devnet" => "https://fullnode.devnet.sui.io:443",
            _ => "https://fullnode.mainnet.sui.io:443",
        };
        let grpc_url = std::env::var("SUI_GRPC_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                std::env::var("SUI_RPC_URL")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            })
            .unwrap_or_else(|| default_rpc.to_owned());
        let configured_publisher = std::env::var("WALRUS_PUBLISHER_URL").unwrap_or_default();
        let walrus_publisher_url =
            effective_walrus_upload_relay_url(&sui_network, &configured_publisher);
        let sui_private_keys = std::env::var("SERVER_SUI_PRIVATE_KEYS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|k| !k.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .or_else(|| {
                std::env::var("SERVER_SUI_PRIVATE_KEY")
                    .ok()
                    .filter(|k| !k.trim().is_empty())
                    .map(|k| vec![k.trim().to_owned()])
            })
            .unwrap_or_default();
        let package_id = std::env::var("MEMWAL_PACKAGE_ID").unwrap_or_default();
        let seal_policy_package_id = std::env::var("MEMWAL_SEAL_POLICY_PACKAGE_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| package_id.clone());
        let registry_id = std::env::var("MEMWAL_REGISTRY_ID").unwrap_or_default();

        Self {
            grpc_url,
            walrus_package_id: effective_walrus_package_id(&sui_network, ""),
            walrus_system_object_id: effective_walrus_system_object_id(&sui_network, ""),
            sui_network,
            walrus_publisher_url,
            sui_private_keys,
            package_id,
            seal_policy_package_id,
            registry_id,
        }
    }

    pub fn key_for_slot(&self, key_index: usize) -> Result<&str, String> {
        if self.sui_private_keys.is_empty() {
            return Err("no SERVER_SUI_PRIVATE_KEYS configured".to_owned());
        }
        let idx = key_index % self.sui_private_keys.len();
        Ok(self.sui_private_keys[idx].as_str())
    }
}

static NATIVE_RUNTIME_CONFIG: OnceLock<StdRwLock<NativeRuntimeConfig>> = OnceLock::new();

pub fn init_native_runtime_config(config: &Config) {
    let runtime = NativeRuntimeConfig::from_config(config);
    match NATIVE_RUNTIME_CONFIG.get() {
        Some(lock) => {
            if let Ok(mut guard) = lock.write() {
                *guard = runtime;
            }
        }
        None => {
            let _ = NATIVE_RUNTIME_CONFIG.set(StdRwLock::new(runtime));
        }
    }
}

pub fn get_native_runtime_config() -> NativeRuntimeConfig {
    NATIVE_RUNTIME_CONFIG
        .get_or_init(|| StdRwLock::new(NativeRuntimeConfig::from_env_fallback()))
        .read()
        .expect("NativeRuntimeConfig lock poisoned")
        .clone()
}

/// Returns true when the server should execute Walrus/SEAL/Sponsor operations in-process in Rust
/// instead of calling the external Node.js sidecar over HTTP.
///
/// Defaults to `true` when `sidecar_url` is the default (`http://localhost:9000` / `in-process`)
/// or when `IN_PROCESS_SIDECAR=true`. Preserves HTTP sidecar execution when unit tests pass an
/// ephemeral mock HTTP server port (`http://127.0.0.1:<random_port>`) unless `IN_PROCESS_SIDECAR=true`.
pub fn is_in_process_sidecar_enabled(sidecar_url: &str) -> bool {
    if let Ok(val) = std::env::var("IN_PROCESS_SIDECAR") {
        let trimmed = val.trim().to_ascii_lowercase();
        if matches!(trimmed.as_str(), "1" | "true" | "yes") {
            return true;
        }
        if matches!(trimmed.as_str(), "0" | "false" | "no") {
            return false;
        }
    }
    let normalized = sidecar_url.trim().trim_end_matches('/');
    normalized.is_empty()
        || normalized == "in-process"
        || normalized == "rust://in-process"
        || normalized == "in-process://rust"
        || normalized == "http://localhost:9000"
        || normalized == "http://127.0.0.1:9000"
        || normalized == "http://localhost:9001"
        || normalized == "http://127.0.0.1:9001"
}

pub fn effective_walrus_upload_relay_url(network: &str, configured_publisher: &str) -> String {
    if let Ok(env_val) = std::env::var("WALRUS_UPLOAD_RELAY_URL") {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    let pub_trimmed = configured_publisher.trim();
    if !pub_trimmed.is_empty() && !pub_trimmed.contains("publisher.walrus") {
        return pub_trimmed.to_owned();
    }
    if network.trim().eq_ignore_ascii_case("testnet") {
        "https://upload-relay.testnet.walrus.space".to_owned()
    } else {
        "https://upload-relay.mainnet.walrus.space".to_owned()
    }
}

pub fn effective_walrus_package_id(network: &str, configured: &str) -> String {
    let trimmed = configured.trim();
    if !trimmed.is_empty() {
        return trimmed.to_owned();
    }
    if let Ok(env_val) = std::env::var("WALRUS_PACKAGE_ID") {
        if !env_val.trim().is_empty() {
            return env_val.trim().to_owned();
        }
    }
    if network.eq_ignore_ascii_case("testnet") {
        TESTNET_WALRUS_PACKAGE_ID.to_owned()
    } else {
        MAINNET_WALRUS_PACKAGE_ID.to_owned()
    }
}

pub fn effective_walrus_system_object_id(network: &str, configured: &str) -> String {
    let trimmed = configured.trim();
    if !trimmed.is_empty() {
        return trimmed.to_owned();
    }
    if let Ok(env_val) = std::env::var("WALRUS_SYSTEM_OBJECT_ID") {
        if !env_val.trim().is_empty() {
            return env_val.trim().to_owned();
        }
    }
    if network.eq_ignore_ascii_case("testnet") {
        TESTNET_WALRUS_SYSTEM_OBJECT_ID.to_owned()
    } else {
        MAINNET_WALRUS_SYSTEM_OBJECT_ID.to_owned()
    }
}

pub fn default_wal_coin_type(network: &str) -> String {
    if let Ok(env_val) = std::env::var("WAL_COIN_TYPE") {
        if !env_val.trim().is_empty() {
            return env_val.trim().to_owned();
        }
    }
    if network.eq_ignore_ascii_case("testnet") {
        TESTNET_WAL_COIN_TYPE.to_owned()
    } else {
        MAINNET_WAL_COIN_TYPE.to_owned()
    }
}

pub fn effective_grpc_url(config: &Config) -> String {
    config
        .sui_grpc_url
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&config.sui_rpc_url)
        .to_owned()
}

// ---------------------------------------------------------------------------
// 1. In-Process Upload Concurrency Limiter (replaces `scripts/sidecar/concurrency.ts`)
// ---------------------------------------------------------------------------

pub struct InProcessUploadLimiter {
    in_flight: AtomicUsize,
    queued: AtomicUsize,
    max_concurrent: usize,
    max_queue_depth: usize,
    queue_timeout_ms: u64,
    notify: Notify,
}

pub struct UploadSlotGuard<'a> {
    limiter: &'a InProcessUploadLimiter,
    slots: usize,
}

impl Drop for UploadSlotGuard<'_> {
    fn drop(&mut self) {
        self.limiter
            .in_flight
            .fetch_sub(self.slots, Ordering::SeqCst);
        self.limiter.notify.notify_waiters();
    }
}

impl InProcessUploadLimiter {
    fn from_env() -> Self {
        let max_concurrent = std::env::var("WALRUS_MAX_CONCURRENT_UPLOADS")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(100);
        let max_queue_depth = std::env::var("WALRUS_MAX_QUEUE_DEPTH")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(300);
        let queue_timeout_ms = std::env::var("WALRUS_QUEUE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(60_000);
        Self {
            in_flight: AtomicUsize::new(0),
            queued: AtomicUsize::new(0),
            max_concurrent,
            max_queue_depth,
            queue_timeout_ms,
            notify: Notify::new(),
        }
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "activeWalrusUploads": self.in_flight.load(Ordering::Relaxed) as u64,
            "queuedWalrusUploads": self.queued.load(Ordering::Relaxed) as u64,
            "walrusUploadLimits": {
                "globalCapacity": self.max_concurrent as u64,
                "perWalletCapacity": 1u64,
                "acquireTimeoutMs": self.queue_timeout_ms,
            }
        })
    }

    pub async fn acquire(&self, requested_slots: usize) -> Result<UploadSlotGuard<'_>, String> {
        let slots = requested_slots.max(1);
        if slots > self.max_concurrent {
            return Err(format!(
                "requested upload slots ({slots}) exceed WALRUS_MAX_CONCURRENT_UPLOADS ({})",
                self.max_concurrent
            ));
        }

        loop {
            let current = self.in_flight.load(Ordering::SeqCst);
            if current + slots <= self.max_concurrent {
                if self
                    .in_flight
                    .compare_exchange(current, current + slots, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return Ok(UploadSlotGuard {
                        limiter: self,
                        slots,
                    });
                }
                continue;
            }
            break;
        }

        let current_queued = self.queued.fetch_add(1, Ordering::SeqCst);
        if current_queued >= self.max_queue_depth {
            self.queued.fetch_sub(1, Ordering::SeqCst);
            return Err(format!(
                "Walrus upload queue full ({}/{} queued)",
                current_queued, self.max_queue_depth
            ));
        }

        let deadline = Instant::now() + Duration::from_millis(self.queue_timeout_ms);
        loop {
            let notified = self.notify.notified();
            let current = self.in_flight.load(Ordering::SeqCst);
            if current + slots <= self.max_concurrent
                && self
                    .in_flight
                    .compare_exchange(current, current + slots, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                self.queued.fetch_sub(1, Ordering::SeqCst);
                return Ok(UploadSlotGuard {
                    limiter: self,
                    slots,
                });
            }

            let now = Instant::now();
            if now >= deadline {
                self.queued.fetch_sub(1, Ordering::SeqCst);
                return Err(format!(
                    "Timed out waiting for Walrus upload slot after {}ms",
                    self.queue_timeout_ms
                ));
            }
            let remaining = deadline - now;
            if tokio::time::timeout(remaining, notified).await.is_err() {
                self.queued.fetch_sub(1, Ordering::SeqCst);
                return Err(format!(
                    "Timed out waiting for Walrus upload slot after {}ms",
                    self.queue_timeout_ms
                ));
            }
        }
    }
}

static UPLOAD_LIMITER: OnceLock<InProcessUploadLimiter> = OnceLock::new();

pub fn global_upload_limiter() -> &'static InProcessUploadLimiter {
    UPLOAD_LIMITER.get_or_init(InProcessUploadLimiter::from_env)
}

pub fn in_process_upload_metrics_snapshot() -> serde_json::Value {
    global_upload_limiter().snapshot()
}

// ---------------------------------------------------------------------------
// 2. In-Process Wallet Balances (replaces `GET /internal/wallet-balances`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeWalletBalanceEntry {
    pub wallet_index: usize,
    pub address: String,
    pub sui_mist: String,
    pub wal_frost: String,
    pub sui_coin_balance_mist: String,
    pub sui_address_balance_mist: String,
    pub wal_coin_balance_frost: String,
    pub wal_address_balance_frost: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn fetch_wallet_balances_in_process() -> serde_json::Value {
    let runtime = get_native_runtime_config();
    let grpc_url = runtime.grpc_url;
    let expected_wal_type = default_wal_coin_type(&runtime.sui_network);
    let shared_client_res = shared_sui_grpc_client(&grpc_url);

    let balance_futures =
        runtime
            .sui_private_keys
            .iter()
            .enumerate()
            .map(|(index, raw_key)| {
                let client_res = shared_client_res.clone();
                let expected_wal = expected_wal_type.clone();
                async move {
                    let address = match derive_sui_address(raw_key) {
                        Ok(addr) => addr,
                        Err(err) => {
                            return NativeWalletBalanceEntry {
                                wallet_index: index,
                                address: "invalid-key".to_owned(),
                                sui_mist: "0".to_owned(),
                                wal_frost: "0".to_owned(),
                                sui_coin_balance_mist: "0".to_owned(),
                                sui_address_balance_mist: "0".to_owned(),
                                wal_coin_balance_frost: "0".to_owned(),
                                wal_address_balance_frost: "0".to_owned(),
                                error: Some(err),
                            };
                        }
                    };

                    let mut client = match client_res {
                        Ok(c) => c,
                        Err(err) => {
                            return NativeWalletBalanceEntry {
                                wallet_index: index,
                                address,
                                sui_mist: "0".to_owned(),
                                wal_frost: "0".to_owned(),
                                sui_coin_balance_mist: "0".to_owned(),
                                sui_address_balance_mist: "0".to_owned(),
                                wal_coin_balance_frost: "0".to_owned(),
                                wal_address_balance_frost: "0".to_owned(),
                                error: Some(err),
                            };
                        }
                    };

                    let mut req = ListBalancesRequest::default();
                    req.owner = Some(address.clone());
                    match client.state_client().list_balances(req).await {
                        Ok(resp) => {
                            let balances = resp.into_inner().balances;
                            let mut sui_total: u64 = 0;
                            let mut sui_coin: u64 = 0;
                            let mut sui_addr: u64 = 0;
                            let mut wal_total: u64 = 0;
                            let mut wal_coin: u64 = 0;
                            let mut wal_addr: u64 = 0;

                            for bal in balances {
                                let ct = bal.coin_type.as_deref().unwrap_or_default();
                                if ct == SUI_COIN_TYPE
                                    || (ct.ends_with("::sui::SUI") && ct.starts_with("0x00000000"))
                                {
                                    sui_total = bal.balance.unwrap_or(0);
                                    sui_coin = bal.coin_balance.unwrap_or(0);
                                    sui_addr = bal.address_balance.unwrap_or(0);
                                } else if ct == expected_wal || ct.ends_with("::wal::WAL") {
                                    wal_total = bal.balance.unwrap_or(0);
                                    wal_coin = bal.coin_balance.unwrap_or(0);
                                    wal_addr = bal.address_balance.unwrap_or(0);
                                }
                            }

                            NativeWalletBalanceEntry {
                                wallet_index: index,
                                address,
                                sui_mist: sui_total.to_string(),
                                wal_frost: wal_total.to_string(),
                                sui_coin_balance_mist: sui_coin.to_string(),
                                sui_address_balance_mist: sui_addr.to_string(),
                                wal_coin_balance_frost: wal_coin.to_string(),
                                wal_address_balance_frost: wal_addr.to_string(),
                                error: None,
                            }
                        }
                        Err(err) => NativeWalletBalanceEntry {
                            wallet_index: index,
                            address,
                            sui_mist: "0".to_owned(),
                            wal_frost: "0".to_owned(),
                            sui_coin_balance_mist: "0".to_owned(),
                            sui_address_balance_mist: "0".to_owned(),
                            wal_coin_balance_frost: "0".to_owned(),
                            wal_address_balance_frost: "0".to_owned(),
                            error: Some(err.to_string()),
                        },
                    }
                }
            });

    let entries = futures::future::join_all(balance_futures).await;

    serde_json::json!({
        "perWallet": entries,
    })
}

// ---------------------------------------------------------------------------
// 3. Walrus System State & Upload Relay Tip Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WalrusSystemSnapshot {
    pub system_object_id: Address,
    pub initial_shared_version: u64,
    pub call_package_id: Address,
    pub origin_package_id: Address,
    pub epoch: u32,
    pub n_shards: u16,
    pub committee_size: u16,
    pub storage_price_per_unit_size: u64,
    pub write_price_per_unit_size: u64,
}

impl WalrusSystemSnapshot {
    pub fn storage_cost(&self, encoded_size: u64, epochs: u32) -> u64 {
        let units = encoded_size.div_ceil(BYTES_PER_UNIT_SIZE);
        units
            .saturating_mul(self.storage_price_per_unit_size)
            .saturating_mul(u64::from(epochs))
    }

    pub fn write_cost(&self, encoded_size: u64) -> u64 {
        let units = encoded_size.div_ceil(BYTES_PER_UNIT_SIZE);
        units.saturating_mul(self.write_price_per_unit_size)
    }
}

struct TimedValue<T> {
    value: T,
    fetched_at: Instant,
}

static SYSTEM_SNAPSHOT_CACHE: OnceLock<RwLock<Option<TimedValue<WalrusSystemSnapshot>>>> =
    OnceLock::new();

fn prost_to_json(value: &prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match &value.kind {
        Some(Kind::NullValue(_)) | None => serde_json::Value::Null,
        Some(Kind::NumberValue(n))
            if n.fract() == 0.0 && n.is_finite() && *n >= 0.0 && *n <= 9007199254740992.0 =>
        {
            serde_json::json!(*n as i64)
        }
        Some(Kind::NumberValue(n)) => serde_json::json!(n),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(s)) => serde_json::Value::Object(
            s.fields
                .iter()
                .map(|(k, v)| (k.clone(), prost_to_json(v)))
                .collect(),
        ),
        Some(Kind::ListValue(l)) => {
            serde_json::Value::Array(l.values.iter().map(prost_to_json).collect())
        }
    }
}

fn json_u64(val: Option<&serde_json::Value>) -> Option<u64> {
    match val? {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

pub async fn invalidate_walrus_system_snapshot_cache() {
    if let Some(cache) = SYSTEM_SNAPSHOT_CACHE.get() {
        *cache.write().await = None;
    }
}

pub async fn resolve_walrus_system_snapshot(
    grpc_url: &str,
    network: &str,
    configured_package_id: &str,
    configured_system_id: &str,
) -> Result<WalrusSystemSnapshot, String> {
    let cache = SYSTEM_SNAPSHOT_CACHE.get_or_init(|| RwLock::new(None));
    if let Some(cached) = cache.read().await.as_ref() {
        if cached.fetched_at.elapsed() < Duration::from_secs(30) {
            return Ok(cached.value.clone());
        }
    }

    let origin_pkg_str = effective_walrus_package_id(network, configured_package_id);
    let system_id_str = effective_walrus_system_object_id(network, configured_system_id);
    let origin_package_id: Address = origin_pkg_str
        .parse()
        .map_err(|e| format!("invalid Walrus package ID '{origin_pkg_str}': {e}"))?;
    let system_object_id: Address = system_id_str
        .parse()
        .map_err(|e| format!("invalid Walrus system object ID '{system_id_str}': {e}"))?;

    let mut client = shared_sui_grpc_client(grpc_url)?;

    let mut sys_req = GetObjectRequest::default();
    sys_req.object_id = Some(system_id_str.clone());
    sys_req.read_mask = Some(FieldMask::from_paths(["object_id", "owner", "json"]));
    let sys_obj = client
        .ledger_client()
        .get_object(sys_req)
        .await
        .map_err(|e| format!("failed to fetch Walrus System object {system_id_str}: {e}"))?
        .into_inner()
        .object
        .ok_or_else(|| format!("Walrus System object {system_id_str} not found"))?;

    let initial_shared_version = sys_obj
        .owner
        .and_then(|o| o.version)
        .ok_or_else(|| "Walrus System object owner is missing initial_shared_version".to_owned())?;

    let sys_json = sys_obj.json.as_deref().map(prost_to_json);
    let call_package_id = sys_json
        .as_ref()
        .and_then(|v| v.get("package_id"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())
        .unwrap_or(origin_package_id);

    let mut fields = Vec::new();
    let mut page_token: Option<Vec<u8>> = None;
    loop {
        let mut df_req = ListDynamicFieldsRequest::default();
        df_req.parent = Some(system_id_str.clone());
        df_req.page_size = Some(50);
        df_req.page_token = page_token.clone().map(Into::into);
        df_req.read_mask = Some(FieldMask::from_paths(["field_id", "name"]));
        let resp = client
            .state_client()
            .list_dynamic_fields(df_req)
            .await
            .map_err(|e| format!("ListDynamicFields on Walrus System failed: {e}"))?
            .into_inner();
        fields.extend(resp.dynamic_fields);
        match resp.next_page_token {
            Some(tok) if !tok.is_empty() => page_token = Some(tok.to_vec()),
            _ => break,
        }
    }

    let state_field_id = fields
        .iter()
        .filter_map(|f| {
            let id = f.field_id.clone()?;
            let name_bytes = f.name.as_ref()?.value.as_ref()?;
            let version: u64 = bcs::from_bytes(name_bytes).ok()?;
            Some((version, id))
        })
        .max_by_key(|(version, _)| *version)
        .map(|(_, id)| id)
        .ok_or_else(|| "Walrus System object has no versioned state dynamic field".to_owned())?;

    let mut state_req = GetObjectRequest::default();
    state_req.object_id = Some(state_field_id.clone());
    state_req.read_mask = Some(FieldMask::from_paths(["json"]));
    let state_json_proto = client
        .ledger_client()
        .get_object(state_req)
        .await
        .map_err(|e| format!("failed to fetch Walrus System state {state_field_id}: {e}"))?
        .into_inner()
        .object
        .and_then(|o| o.json)
        .ok_or_else(|| "Walrus System state object omitted JSON".to_owned())?;

    let state_val = prost_to_json(&state_json_proto);
    let root = state_val.get("value").unwrap_or(&state_val);
    let committee = root
        .get("committee")
        .ok_or_else(|| "Walrus System state JSON omitted committee".to_owned())?;

    let epoch = json_u64(committee.get("epoch")).unwrap_or(1) as u32;
    let n_shards = json_u64(committee.get("n_shards")).unwrap_or(1000) as u16;
    let committee_size = committee
        .get("members")
        .and_then(|m| m.as_array())
        .map(|arr| arr.len() as u16)
        .unwrap_or(100);
    let storage_price_per_unit_size =
        json_u64(root.get("storage_price_per_unit_size")).unwrap_or(1_000);
    let write_price_per_unit_size =
        json_u64(root.get("write_price_per_unit_size")).unwrap_or(2_000);

    let snapshot = WalrusSystemSnapshot {
        system_object_id,
        initial_shared_version,
        call_package_id,
        origin_package_id,
        epoch,
        n_shards,
        committee_size,
        storage_price_per_unit_size,
        write_price_per_unit_size,
    };

    *cache.write().await = Some(TimedValue {
        value: snapshot.clone(),
        fetched_at: Instant::now(),
    });

    Ok(snapshot)
}

// ---------------------------------------------------------------------------
// Upload Relay Tip Config (`GET {relay_url}/v1/tip-config`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayTipKind {
    Const(u64),
    Linear {
        base: u64,
        encoded_size_mul_per_kib: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayTipConfig {
    NoTip,
    SendTip {
        address: String,
        kind: RelayTipKind,
    },
}

impl RelayTipConfig {
    pub fn calculate_tip(&self, n_shards: u16, unencoded_length: u64) -> Option<(Address, u64)> {
        match self {
            Self::NoTip => None,
            Self::SendTip { address, kind } => {
                let recipient: Address = address.parse().ok()?;
                let amount = match kind {
                    RelayTipKind::Const(c) => *c,
                    RelayTipKind::Linear {
                        base,
                        encoded_size_mul_per_kib,
                    } => {
                        let shards = NonZeroU16::new(n_shards.max(1)).unwrap();
                        let encoded_len = encoded_blob_length_for_n_shards(
                            shards,
                            unencoded_length,
                            EncodingType::RS2,
                        )?;
                        base.saturating_add(
                            encoded_len
                                .div_ceil(1024)
                                .saturating_mul(*encoded_size_mul_per_kib),
                        )
                    }
                };
                Some((recipient, amount))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HashedAuthPackage {
    blob_digest: [u8; 32],
    nonce_digest: [u8; 32],
    unencoded_length: u64,
}

static TIP_CONFIG_CACHE: OnceLock<RwLock<HashMap<String, TimedValue<RelayTipConfig>>>> =
    OnceLock::new();

pub async fn fetch_relay_tip_config(
    http: &reqwest::Client,
    relay_url: &str,
) -> Result<RelayTipConfig, String> {
    let base = relay_url.trim().trim_end_matches('/').to_owned();
    let cache = TIP_CONFIG_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Some(cached) = cache.read().await.get(&base) {
        if cached.fetched_at.elapsed() < Duration::from_secs(60) {
            return Ok(cached.value.clone());
        }
    }

    let url = format!("{base}/v1/tip-config");
    let resp = http
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("failed to query Walrus upload relay tip-config at {url}: {e}"))?;
    if !resp.status().is_success() {
        return Ok(RelayTipConfig::NoTip);
    }
    let tip_config: RelayTipConfig = resp.json().await.unwrap_or(RelayTipConfig::NoTip);

    cache.write().await.insert(
        base,
        TimedValue {
            value: tip_config.clone(),
            fetched_at: Instant::now(),
        },
    );
    Ok(tip_config)
}

// ---------------------------------------------------------------------------
// 4. RedStuff RS2 Erasure Coding via `walrus-core`
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EncodedWalrusBlob {
    pub blob_id: BlobId,
    pub blob_id_str: String,
    pub root_hash_bytes: [u8; 32],
    pub unencoded_length: u64,
    pub encoded_size: u64,
    pub nonce: [u8; 32],
    pub blob_digest: [u8; 32],
}

pub async fn encode_walrus_blob_rs2(
    data: Vec<u8>,
    n_shards: u16,
) -> Result<EncodedWalrusBlob, String> {
    tokio::task::spawn_blocking(move || {
        let shards = NonZeroU16::new(n_shards.max(1))
            .ok_or_else(|| "invalid n_shards (0)".to_owned())?;
        let encoding_config = EncodingConfig::new(shards);
        let verified_meta = encoding_config
            .get_for_type(EncodingType::RS2)
            .compute_metadata(&data)
            .map_err(|e| format!("walrus-core RS2 compute_metadata failed: {e}"))?;

        let blob_id = *verified_meta.blob_id();
        let blob_id_str = blob_id.to_string();
        let root_hash_bytes = verified_meta.metadata().compute_root_hash().bytes();
        let unencoded_length = data.len() as u64;
        let encoded_size = verified_meta
            .metadata()
            .encoded_size()
            .or_else(|| {
                encoded_blob_length_for_n_shards(shards, unencoded_length, EncodingType::RS2)
            })
            .ok_or_else(|| "failed to compute RS2 encoded blob length".to_owned())?;

        let blob_digest = Sha256::digest(&data).digest;
        let mut nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        Ok(EncodedWalrusBlob {
            blob_id,
            blob_id_str,
            root_hash_bytes,
            unencoded_length,
            encoded_size,
            nonce,
            blob_digest,
        })
    })
    .await
    .map_err(|e| format!("walrus-core RS2 encoding task panicked: {e}"))?
}

// ---------------------------------------------------------------------------
// 5. Registration, Relay Upload, Certification & Metadata PTBs
// ---------------------------------------------------------------------------

async fn select_owned_wal_coins(
    grpc_url: &str,
    owner: &str,
    wal_coin_type: &str,
) -> Result<(u64, Vec<(Address, u64, Digest)>), String> {
    let mut bal_client = shared_sui_grpc_client(grpc_url)?;
    let mut obj_client = bal_client.clone();
    let mut bal_state = bal_client.state_client();
    let mut obj_state = obj_client.state_client();

    let mut bal_req = ListBalancesRequest::default();
    bal_req.owner = Some(owner.to_owned());

    let mut req = ListOwnedObjectsRequest::default();
    req.owner = Some(owner.to_owned());
    req.page_size = Some(100);
    req.object_type = Some(format!("0x2::coin::Coin<{wal_coin_type}>"));
    req.read_mask = Some(FieldMask::from_paths(["object_id", "version", "digest"]));

    let (bal_res, obj_res) = tokio::join!(
        bal_state.list_balances(bal_req),
        obj_state.list_owned_objects(req),
    );

    let mut address_wal: u64 = 0;
    if let Ok(resp) = bal_res {
        for bal in resp.into_inner().balances {
            let ct = bal.coin_type.as_deref().unwrap_or_default();
            if ct == wal_coin_type || ct.ends_with("::wal::WAL") {
                address_wal = bal.address_balance.unwrap_or(0);
                break;
            }
        }
    }

    let mut coins = Vec::new();
    if let Ok(resp) = obj_res {
        for obj in resp.into_inner().objects {
            if let (Some(id_str), Some(version), Some(digest_str)) =
                (obj.object_id, obj.version, obj.digest)
            {
                if let (Ok(id), Ok(digest)) =
                    (id_str.parse::<Address>(), digest_str.parse::<Digest>())
                {
                    coins.push((id, version, digest));
                }
            }
        }
    }

    Ok((address_wal, coins))
}

fn finalize_offline_ptb(
    mut builder: TransactionBuilder,
    sender: Address,
) -> Result<ProgrammableTransaction, String> {
    builder.set_sender(sender);
    builder.set_gas_price(1_000);
    builder.set_gas_budget(50_000_000);
    builder.add_gas_objects([ObjectInput::owned(Address::ZERO, 1, Digest::ZERO)]);
    let tx = builder
        .try_build()
        .map_err(|e| format!("failed to build PTB: {e}"))?;
    match tx.kind {
        sui_sdk_types::TransactionKind::ProgrammableTransaction(ptb) => Ok(ptb),
        _ => Err("unexpected non-PTB transaction kind".to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn build_register_blob_ptb(
    grpc_url: &str,
    network: &str,
    sender: Address,
    system: &WalrusSystemSnapshot,
    encoded: &EncodedWalrusBlob,
    epochs: u32,
    tip_config: &RelayTipConfig,
    attributes: &[(&str, String)],
) -> Result<ProgrammableTransaction, String> {
    let mut builder = TransactionBuilder::new();

    // CRITICAL: When `SendTip` is active, `ptb.inputs[0]` MUST be `Pure(bcs(HashedAuthPackage))`.
    if let Some((tip_recipient, tip_amount)) =
        tip_config.calculate_tip(system.n_shards, encoded.unencoded_length)
    {
        let auth_pkg = HashedAuthPackage {
            blob_digest: encoded.blob_digest,
            nonce_digest: Sha256::digest(encoded.nonce).digest,
            unencoded_length: encoded.unencoded_length,
        };
        let auth_bytes =
            bcs::to_bytes(&auth_pkg).map_err(|e| format!("BCS HashedAuthPackage: {e}"))?;
        let _auth_input = builder.pure_bytes(auth_bytes);

        if tip_amount > 0 {
            let sui_tag = TypeTag::Struct(Box::new(StructTag::sui()));
            let tip_coin = builder.funds_withdrawal_coin(sui_tag, tip_amount);
            let recipient_arg = builder.pure(&tip_recipient);
            builder.transfer_objects(vec![tip_coin], recipient_arg);
        }
    }

    let storage_cost = system.storage_cost(encoded.encoded_size, epochs);
    let write_cost = system.write_cost(encoded.encoded_size);
    let total_wal_cost = storage_cost.saturating_add(write_cost);

    let wal_coin_type_str = default_wal_coin_type(network);
    let wal_struct_tag: StructTag = wal_coin_type_str
        .parse()
        .map_err(|e| format!("invalid WAL StructTag '{wal_coin_type_str}': {e}"))?;
    let wal_type_tag = TypeTag::Struct(Box::new(wal_struct_tag));

    let (address_wal, owned_wal_coins) =
        select_owned_wal_coins(grpc_url, &sender.to_string(), &wal_coin_type_str).await?;

    let (wal_coin_arg, destroy_zero_after) =
        if address_wal >= total_wal_cost || owned_wal_coins.is_empty() {
            (
                builder.funds_withdrawal_coin(wal_type_tag.clone(), total_wal_cost),
                true,
            )
        } else {
            let (first_id, first_ver, first_dig) = owned_wal_coins[0];
            let primary = builder.object(ObjectInput::owned(first_id, first_ver, first_dig));
            if owned_wal_coins.len() > 1 {
                let extras: Vec<_> = owned_wal_coins[1..]
                    .iter()
                    .map(|&(id, ver, dig)| builder.object(ObjectInput::owned(id, ver, dig)))
                    .collect();
                builder.merge_coins(primary, extras);
            }
            (primary, false)
        };

    let system_arg = builder.object(ObjectInput::shared(
        system.system_object_id,
        system.initial_shared_version,
        true,
    ));

    let encoded_size_arg = builder.pure(&encoded.encoded_size);
    let epochs_arg = builder.pure(&epochs);
    let storage_resource = builder.move_call(
        Function::new(
            system.call_package_id,
            Identifier::from_static("system"),
            Identifier::from_static("reserve_space"),
        ),
        vec![system_arg, encoded_size_arg, epochs_arg, wal_coin_arg],
    );

    let blob_id_arg = builder.pure(&encoded.blob_id.0);
    let root_hash_arg = builder.pure(&encoded.root_hash_bytes);
    let unencoded_size_arg = builder.pure(&encoded.unencoded_length);
    let encoding_type_arg = builder.pure(&1u8); // RS2 = 1
    let deletable_arg = builder.pure(&true);

    let blob_obj = builder.move_call(
        Function::new(
            system.call_package_id,
            Identifier::from_static("system"),
            Identifier::from_static("register_blob"),
        ),
        vec![
            system_arg,
            storage_resource,
            blob_id_arg,
            root_hash_arg,
            unencoded_size_arg,
            encoding_type_arg,
            deletable_arg,
            wal_coin_arg,
        ],
    );

    for (k, v) in attributes {
        let key_arg = builder.pure(&(*k).to_owned());
        let val_arg = builder.pure(v);
        builder.move_call(
            Function::new(
                system.call_package_id,
                Identifier::from_static("blob"),
                Identifier::from_static("insert_or_update_metadata_pair"),
            ),
            vec![blob_obj, key_arg, val_arg],
        );
    }

    if destroy_zero_after {
        builder.move_call(
            Function::new(
                Address::TWO,
                Identifier::from_static("coin"),
                Identifier::from_static("destroy_zero"),
            )
            .with_type_args(vec![wal_type_tag]),
            vec![wal_coin_arg],
        );
    }

    let sender_arg = builder.pure(&sender);
    builder.transfer_objects(vec![blob_obj], sender_arg);

    finalize_offline_ptb(builder, sender)
}

#[derive(Deserialize)]
struct RelayUploadResponse {
    confirmation_certificate: ConfirmationCertificate,
}

pub async fn post_blob_to_upload_relay(
    http: &reqwest::Client,
    relay_url: &str,
    blob_id_str: &str,
    blob_object_id: &str,
    register_tx_digest: &str,
    nonce: &[u8; 32],
    data: Vec<u8>,
) -> Result<ConfirmationCertificate, String> {
    let base = relay_url.trim().trim_end_matches('/');
    let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let url = format!(
        "{base}/v1/blob-upload-relay?blob_id={blob_id_str}&deletable_blob_object={blob_object_id}&tx_id={register_tx_digest}&nonce={nonce_b64}&encoding_type=RS2"
    );

    let resp = http
        .post(&url)
        .header("content-type", "application/octet-stream")
        .body(data)
        .timeout(Duration::from_secs(90))
        .send()
        .await
        .map_err(|e| format!("Walrus upload relay POST failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Walrus upload relay returned {status}: {body}"));
    }

    let parsed: RelayUploadResponse = resp
        .json()
        .await
        .map_err(|e| format!("failed to parse Walrus upload relay certificate JSON: {e}"))?;
    Ok(parsed.confirmation_certificate)
}

fn signers_to_bitmap(signers: &[u16], committee_size: u16) -> Vec<u8> {
    let max_signer = signers.iter().copied().max().unwrap_or(0) + 1;
    let effective_size = committee_size.max(max_signer).max(1) as usize;
    let mut bitmap = vec![0u8; effective_size.div_ceil(8)];
    for &signer in signers {
        let byte_idx = (signer / 8) as usize;
        let bit_idx = signer % 8;
        if byte_idx < bitmap.len() {
            bitmap[byte_idx] |= 1u8 << bit_idx;
        }
    }
    bitmap
}

async fn resolve_owned_object_ref(
    grpc_url: &str,
    object_id_str: &str,
) -> Result<(Address, u64, Digest), String> {
    let addr: Address = object_id_str
        .parse()
        .map_err(|e| format!("invalid object ID '{object_id_str}': {e}"))?;
    let mut client = shared_sui_grpc_client(grpc_url)?;
    let mut req = GetObjectRequest::default();
    req.object_id = Some(object_id_str.to_owned());
    req.read_mask = Some(FieldMask::from_paths(["object_id", "version", "digest"]));
    let obj = client
        .ledger_client()
        .get_object(req)
        .await
        .map_err(|e| format!("GetObject({object_id_str}) failed: {e}"))?
        .into_inner()
        .object
        .ok_or_else(|| format!("object {object_id_str} not found on chain"))?;
    let version = obj
        .version
        .ok_or_else(|| format!("object {object_id_str} omitted version"))?;
    let digest_str = obj
        .digest
        .ok_or_else(|| format!("object {object_id_str} omitted digest"))?;
    let digest: Digest = digest_str
        .parse()
        .map_err(|e| format!("invalid digest '{digest_str}' for {object_id_str}: {e}"))?;
    Ok((addr, version, digest))
}

/// Validates that `encrypted_bytes` is a valid BCS-serialized `seal_crypto::EncryptedObject`
/// whose `package_id` matches `immutable_package_id`, has a non-empty `id`, and (when
/// `configured_policy_pkg` is non-empty) `policy_package_id` matches `configured_policy_pkg`.
///
/// Mirrors `parseSealPersistenceFence` in `services/server/scripts/sidecar/blob-metadata.ts`.
pub fn validate_seal_persistence_ciphertext(
    encrypted_bytes: &[u8],
    immutable_package_id: &str,
    policy_package_id: &str,
    configured_policy_pkg: &str,
) -> Result<(EncryptedObject, Address), String> {
    let enc_obj: EncryptedObject = bcs::from_bytes(encrypted_bytes)
        .map_err(|e| format!("Invalid encrypted data for v1-new persistence fence: {e}"))?;

    if !immutable_package_id.trim().is_empty() {
        let immutable_addr: Address = immutable_package_id
            .trim()
            .parse()
            .map_err(|e| format!("Invalid packageId '{immutable_package_id}': {e}"))?;
        let expected_obj_id = seal_crypto::ObjectID::new(*immutable_addr.inner());
        if enc_obj.package_id != expected_obj_id {
            return Err("Ciphertext packageId does not match packageId".to_owned());
        }
    }

    if enc_obj.id.is_empty() {
        return Err("Ciphertext has an invalid SEAL id".to_owned());
    }

    let policy_pkg: Address = policy_package_id
        .trim()
        .parse()
        .map_err(|e| format!("Invalid or missing policyPackageId '{policy_package_id}': {e}"))?;

    if !configured_policy_pkg.trim().is_empty() {
        let configured_addr: Address = configured_policy_pkg
            .trim()
            .parse()
            .map_err(|e| format!("Sidecar SEAL policy package is invalid: {e}"))?;
        if policy_pkg != configured_addr {
            return Err(
                "policyPackageId does not match the configured SEAL policy package".to_owned(),
            );
        }
    }

    Ok((enc_obj, policy_pkg))
}

#[allow(clippy::too_many_arguments)]
async fn append_seal_persistence_fence(
    builder: &mut TransactionBuilder,
    grpc_url: &str,
    immutable_package_id: &str,
    policy_package_id: &str,
    configured_policy_pkg: &str,
    registry_id: &str,
    account_id: &str,
    encrypted_bytes: &[u8],
) -> Result<(), String> {
    let (enc_obj, policy_pkg) = validate_seal_persistence_ciphertext(
        encrypted_bytes,
        immutable_package_id,
        policy_package_id,
        configured_policy_pkg,
    )?;
    let reg_addr: Address = registry_id
        .parse()
        .map_err(|e| format!("invalid registry_id '{registry_id}': {e}"))?;
    let acct_addr: Address = account_id
        .parse()
        .map_err(|e| format!("invalid account_id '{account_id}': {e}"))?;

    let (acct_ver, reg_ver) =
        crate::storage::seal_native::fetch_shared_object_versions(grpc_url, account_id, registry_id)
            .await
            .unwrap_or((1, 1));

    let id_arg = builder.pure(&enc_obj.id);
    let reg_arg = builder.object(ObjectInput::shared(reg_addr, reg_ver, false));
    let acct_arg = builder.object(ObjectInput::shared(acct_addr, acct_ver, false));

    // Matches `blob-metadata.ts`: `${fence.policyPackageId}::account::seal_encrypt_fence(id_bytes, registry, account)`
    builder.move_call(
        Function::new(
            policy_pkg,
            Identifier::from_static("account"),
            Identifier::from_static("seal_encrypt_fence"),
        ),
        vec![id_arg, reg_arg, acct_arg],
    );
    Ok(())
}

pub async fn build_certify_ptb(
    grpc_url: &str,
    sender: Address,
    system: &WalrusSystemSnapshot,
    blob_object_id: &str,
    certificate: &ConfirmationCertificate,
) -> Result<ProgrammableTransaction, String> {
    let mut builder = TransactionBuilder::new();
    let (blob_addr, blob_ver, blob_digest) =
        resolve_owned_object_ref(grpc_url, blob_object_id).await?;
    let system_arg = builder.object(ObjectInput::shared(
        system.system_object_id,
        system.initial_shared_version,
        false,
    ));
    let blob_arg = builder.object(ObjectInput::owned(blob_addr, blob_ver, blob_digest));

    let sig_bytes: Vec<u8> = certificate.signature.as_ref().to_vec();
    let bitmap = signers_to_bitmap(&certificate.signers, system.committee_size);

    let sig_arg = builder.pure(&sig_bytes);
    let bitmap_arg = builder.pure(&bitmap);
    let msg_arg = builder.pure(&certificate.serialized_message);

    builder.move_call(
        Function::new(
            system.call_package_id,
            Identifier::from_static("system"),
            Identifier::from_static("certify_blob"),
        ),
        vec![system_arg, blob_arg, sig_arg, bitmap_arg, msg_arg],
    );

    finalize_offline_ptb(builder, sender)
}

// ---------------------------------------------------------------------------
// High-Level In-Process Upload & Durable Upload Step State Machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NativeFlowState {
    step: String,
    blob_id: String,
    blob_id_bytes: [u8; 32],
    root_hash_bytes: [u8; 32],
    unencoded_length: u64,
    encoded_size: u64,
    nonce: [u8; 32],
    blob_digest: [u8; 32],
    blob_object_id: Option<String>,
    register_tx_digest: Option<String>,
    confirmation_certificate: Option<ConfirmationCertificate>,
    end_epoch: Option<i32>,
}

fn find_created_blob_object_id(outcome: &WalletTxOutcome) -> Option<String> {
    outcome
        .created_objects
        .iter()
        .find(|obj| {
            obj.object_type
                .as_deref()
                .is_some_and(|ty| ty.ends_with("::blob::Blob"))
        })
        .or_else(|| outcome.created_objects.first())
        .map(|obj| obj.object_id.clone())
}

#[allow(clippy::too_many_arguments)]
pub async fn upload_blob_in_process(
    http: &reqwest::Client,
    data: &[u8],
    epochs: u64,
    owner_address: &str,
    key_index: usize,
    namespace: &str,
    package_id: &str,
    agent_id: Option<&str>,
    job_id: Option<&str>,
    defer_transfer: bool,
    seal_persistence: SealPersistence<'_>,
) -> Result<UploadResult, UploadBlobError> {
    let runtime = get_native_runtime_config();
    let private_key = runtime
        .key_for_slot(key_index)
        .map_err(|e| UploadBlobError::App(AppError::Internal(e)))?;

    // Validate the SEAL persistence fence upfront before spending WAL/gas on registration,
    // matching `parseSealPersistenceFence` in `walrus-upload.ts`.
    let SealPersistence::V1New {
        account_id,
        registry_id,
        policy_package_id,
    } = seal_persistence;
    if account_id.trim().parse::<Address>().is_err() {
        return Err(UploadBlobError::App(AppError::BadRequest(
            "Invalid or missing accountId for v1-new persistence fence".into(),
        )));
    }
    if registry_id.trim().parse::<Address>().is_err() {
        return Err(UploadBlobError::App(AppError::BadRequest(
            "Invalid or missing registryId for v1-new persistence fence".into(),
        )));
    }
    validate_seal_persistence_ciphertext(
        data,
        package_id,
        policy_package_id,
        &runtime.seal_policy_package_id,
    )
    .map_err(|e| UploadBlobError::App(AppError::BadRequest(e)))?;

    let _permit = global_upload_limiter()
        .acquire(1)
        .await
        .map_err(|e| UploadBlobError::App(AppError::Internal(e)))?;

    let mut journal = UploadJournal {
        wallet_index: key_index,
        wallet_address: None,
        execution_identity: None,
        resume_step: None,
        register_transaction: None,
    };

    let (blob_id, blob_object_id, end_epoch) = loop {
        let advanced = advance_durable_upload_in_process(
            http,
            data,
            epochs,
            owner_address,
            namespace,
            package_id,
            job_id.unwrap_or_default(),
            journal,
        )
        .await
        .map_err(UploadBlobError::App)?;

        match advanced {
            DurableUploadAdvance::Prepared(next)
            | DurableUploadAdvance::Reset { journal: next, .. } => {
                journal = next;
            }
            DurableUploadAdvance::Step {
                journal: mut next,
                step,
            } => {
                let kind = step
                    .get("step")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if kind == "certified" {
                    let blob_id = step
                        .get("blobId")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let object_id = step
                        .get("blobObjectId")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let end_epoch = step
                        .get("endEpoch")
                        .and_then(serde_json::Value::as_i64)
                        .map(|e| e as i32);
                    break (blob_id, object_id, end_epoch);
                }
                next.resume_step = Some(step);
                journal = next;
            }
        }
    };

    if !defer_transfer {
        let entry = SetMetadataBatchEntry {
            blob_object_id: blob_object_id.clone(),
            namespace: namespace.to_owned(),
            encrypted_data: Some(base64::engine::general_purpose::STANDARD.encode(data)),
        };
        if let Err(err) = set_metadata_batch_in_process(
            http,
            key_index,
            owner_address,
            package_id,
            agent_id,
            vec![entry],
            seal_persistence,
        )
        .await
        {
            return Err(UploadBlobError::MetadataTransferFailed {
                blob_id,
                object_id: blob_object_id,
                message: err.to_string(),
                end_epoch,
            });
        }
    }

    let _ = private_key;
    Ok(UploadResult {
        blob_id,
        object_id: Some(blob_object_id),
        end_epoch,
    })
}

/// Advances the durable Walrus upload state machine by one step in-process in Rust,
/// returning `DurableUploadAdvance::Step` with `step = "registered" -> "uploaded" -> "certified"`.
#[allow(clippy::too_many_arguments)]
pub async fn advance_durable_upload_in_process(
    http: &reqwest::Client,
    data: &[u8],
    epochs: u64,
    owner: &str,
    namespace: &str,
    package_id: &str,
    job_id: &str,
    mut journal: UploadJournal,
) -> Result<DurableUploadAdvance, AppError> {
    let runtime = get_native_runtime_config();
    let private_key = runtime
        .key_for_slot(journal.wallet_index)
        .map_err(AppError::Internal)?;
    let key = parse_sui_private_key(private_key).map_err(AppError::Internal)?;
    let sender = key.public_key().derive_address();

    let system = resolve_walrus_system_snapshot(
        &runtime.grpc_url,
        &runtime.sui_network,
        &runtime.walrus_package_id,
        &runtime.walrus_system_object_id,
    )
    .await
    .map_err(AppError::Internal)?;

    let epochs_u32 = (epochs as u32).clamp(1, 53);
    let end_epoch = (system.epoch + epochs_u32) as i32;

    if journal.wallet_address.is_none() {
        journal.wallet_address = Some(sender.to_string());
    }
    if journal.execution_identity.is_none() {
        journal.execution_identity = Some(UploadExecutionIdentity {
            chain_identifier: runtime.sui_network.clone(),
            walrus_package_id: system.call_package_id.to_string(),
        });
    }

    let flow_state: Option<NativeFlowState> = journal
        .resume_step
        .as_ref()
        .and_then(|v| v.get("nativeFlowState"))
        .and_then(|fs| serde_json::from_value(fs.clone()).ok());

    match flow_state {
        None => {
            // Step 1: RS2 encode + register_blob on-chain (stamping initial memwal_* attributes).
            let encoded = encode_walrus_blob_rs2(data.to_vec(), system.n_shards)
                .await
                .map_err(AppError::Internal)?;
            let tip_config = fetch_relay_tip_config(http, &runtime.walrus_publisher_url)
                .await
                .map_err(AppError::Internal)?;

            let mut attrs = vec![
                ("memwal_namespace", namespace.to_owned()),
                ("memwal_owner", owner.to_owned()),
            ];
            if !package_id.trim().is_empty() {
                attrs.push(("memwal_package_id", package_id.to_owned()));
            }
            if !job_id.trim().is_empty() {
                attrs.push(("memwal_job_id", job_id.to_owned()));
            }

            let register_ptb = build_register_blob_ptb(
                &runtime.grpc_url,
                &runtime.sui_network,
                sender,
                &system,
                &encoded,
                epochs_u32,
                &tip_config,
                &attrs,
            )
            .await
            .map_err(AppError::Internal)?;

            let mut allowed_addrs = vec![sender.to_string()];
            if let Some((tip_recipient, _)) =
                tip_config.calculate_tip(system.n_shards, encoded.unencoded_length)
            {
                let tip_str = tip_recipient.to_string();
                if !allowed_addrs.contains(&tip_str) {
                    allowed_addrs.push(tip_str);
                }
            }

            let outcome = match submit_wallet_ptb_with_allowed_addresses(
                http,
                &runtime.grpc_url,
                &runtime.sui_network,
                private_key,
                register_ptb,
                Some(allowed_addrs),
                false,
                true,
            )
            .await
            {
                Ok(out) => out,
                Err(err) => {
                    invalidate_walrus_system_snapshot_cache().await;
                    return Err(AppError::Internal(err));
                }
            };

            let blob_object_id = find_created_blob_object_id(&outcome).ok_or_else(|| {
                AppError::Internal(format!(
                    "register_blob transaction {} succeeded but created Blob object was not found",
                    outcome.digest
                ))
            })?;

            let next_flow = NativeFlowState {
                step: "registered".to_owned(),
                blob_id: encoded.blob_id_str.clone(),
                blob_id_bytes: encoded.blob_id.0,
                root_hash_bytes: encoded.root_hash_bytes,
                unencoded_length: encoded.unencoded_length,
                encoded_size: encoded.encoded_size,
                nonce: encoded.nonce,
                blob_digest: encoded.blob_digest,
                blob_object_id: Some(blob_object_id.clone()),
                register_tx_digest: Some(outcome.digest.clone()),
                confirmation_certificate: None,
                end_epoch: Some(end_epoch),
            };
            let step_json = serde_json::json!({
                "step": "registered",
                "blobId": encoded.blob_id_str,
                "blobObjectId": blob_object_id,
                "registerTxDigest": outcome.digest,
                "endEpoch": end_epoch,
                "nativeFlowState": next_flow,
            });
            journal.resume_step = Some(step_json.clone());
            journal.register_transaction = None;

            Ok(DurableUploadAdvance::Step {
                journal,
                step: step_json,
            })
        }
        Some(mut st) if st.step == "registered" => {
            // Step 2: Upload raw blob bytes to Walrus Upload Relay -> ConfirmationCertificate.
            let blob_object_id = st.blob_object_id.clone().ok_or_else(|| {
                AppError::Internal("missing blob_object_id in registered state".into())
            })?;
            let register_tx_digest = st.register_tx_digest.clone().ok_or_else(|| {
                AppError::Internal("missing register_tx_digest in registered state".into())
            })?;

            let cert = post_blob_to_upload_relay(
                http,
                &runtime.walrus_publisher_url,
                &st.blob_id,
                &blob_object_id,
                &register_tx_digest,
                &st.nonce,
                data.to_vec(),
            )
            .await
            .map_err(AppError::Internal)?;

            st.step = "uploaded".to_owned();
            st.confirmation_certificate = Some(cert);

            let step_json = serde_json::json!({
                "step": "uploaded",
                "blobId": st.blob_id,
                "blobObjectId": blob_object_id,
                "endEpoch": st.end_epoch,
                "nativeFlowState": st,
            });
            journal.resume_step = Some(step_json.clone());

            Ok(DurableUploadAdvance::Step {
                journal,
                step: step_json,
            })
        }
        Some(st) => {
            // Step 3: Certify blob on-chain.
            let blob_object_id = st.blob_object_id.clone().ok_or_else(|| {
                AppError::Internal("missing blob_object_id in uploaded state".into())
            })?;
            let cert = st.confirmation_certificate.as_ref().ok_or_else(|| {
                AppError::Internal("missing confirmation_certificate in uploaded state".into())
            })?;

            let certify_ptb = build_certify_ptb(
                &runtime.grpc_url,
                sender,
                &system,
                &blob_object_id,
                cert,
            )
            .await
            .map_err(AppError::Internal)?;

            let outcome = match submit_wallet_ptb(
                http,
                &runtime.grpc_url,
                &runtime.sui_network,
                private_key,
                certify_ptb,
                false,
                false,
            )
            .await
            {
                Ok(out) => out,
                Err(err) => {
                    invalidate_walrus_system_snapshot_cache().await;
                    return Err(AppError::Internal(err));
                }
            };

            let step_json = serde_json::json!({
                "step": "certified",
                "blobId": st.blob_id,
                "blobObjectId": blob_object_id,
                "certifyTxDigest": outcome.digest,
                "endEpoch": st.end_epoch.unwrap_or(end_epoch),
            });
            journal.resume_step = Some(step_json.clone());

            Ok(DurableUploadAdvance::Step {
                journal,
                step: step_json,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Batch Metadata & Ownership Transfer (`set_metadata_batch_in_process`)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn set_metadata_batch_in_process(
    http: &reqwest::Client,
    key_index: usize,
    owner_address: &str,
    package_id: &str,
    agent_id: Option<&str>,
    blobs: Vec<SetMetadataBatchEntry>,
    seal_persistence: SealPersistence<'_>,
) -> Result<usize, AppError> {
    if blobs.is_empty() {
        return Ok(0);
    }

    let runtime = get_native_runtime_config();
    let private_key = runtime
        .key_for_slot(key_index)
        .map_err(AppError::Internal)?;
    let key = parse_sui_private_key(private_key).map_err(AppError::Internal)?;
    let sender = key.public_key().derive_address();
    let owner: Address = owner_address
        .parse()
        .map_err(|e| AppError::Internal(format!("invalid owner address '{owner_address}': {e}")))?;

    let system = resolve_walrus_system_snapshot(
        &runtime.grpc_url,
        &runtime.sui_network,
        &runtime.walrus_package_id,
        &runtime.walrus_system_object_id,
    )
    .await
    .map_err(AppError::Internal)?;

    let SealPersistence::V1New {
        account_id,
        registry_id,
        policy_package_id,
    } = seal_persistence;

    let mut builder = TransactionBuilder::new();
    let mut blob_args = Vec::with_capacity(blobs.len());

    for entry in &blobs {
        if let Some(enc_b64) = &entry.encrypted_data {
            let enc_bytes = base64::engine::general_purpose::STANDARD
                .decode(enc_b64)
                .map_err(|e| {
                    AppError::Internal(format!("invalid encryptedData base64 in batch: {e}"))
                })?;
            append_seal_persistence_fence(
                &mut builder,
                &runtime.grpc_url,
                package_id,
                policy_package_id,
                &runtime.seal_policy_package_id,
                registry_id,
                account_id,
                &enc_bytes,
            )
            .await
            .map_err(AppError::Internal)?;
        }

        let (blob_addr, blob_ver, blob_digest) =
            resolve_owned_object_ref(&runtime.grpc_url, &entry.blob_object_id)
                .await
                .map_err(AppError::Internal)?;
        let blob_arg = builder.object(ObjectInput::owned(blob_addr, blob_ver, blob_digest));
        blob_args.push(blob_arg);

        let ns = if entry.namespace.trim().is_empty() {
            "default"
        } else {
            entry.namespace.as_str()
        };
        let canonical_owner_str = owner.to_string();
        let mut pairs = vec![
            ("memwal_namespace", ns.to_owned()),
            ("memwal_owner", canonical_owner_str),
        ];
        if !package_id.trim().is_empty() {
            pairs.push(("memwal_package_id", package_id.to_owned()));
        }
        if let Some(agent) = agent_id.filter(|s| !s.trim().is_empty()) {
            pairs.push(("memwal_agent_id", agent.to_owned()));
        }

        for (k, v) in pairs {
            let key_arg = builder.pure(&k.to_owned());
            let val_arg = builder.pure(&v);
            builder.move_call(
                Function::new(
                    system.call_package_id,
                    Identifier::from_static("blob"),
                    Identifier::from_static("insert_or_update_metadata_pair"),
                ),
                vec![blob_arg, key_arg, val_arg],
            );
        }
    }

    let owner_arg = builder.pure(&owner);
    builder.transfer_objects(blob_args, owner_arg);

    let ptb = finalize_offline_ptb(builder, sender).map_err(AppError::Internal)?;
    let count = blobs.len();
    let mut allowed_addrs = vec![sender.to_string()];
    if owner != sender {
        allowed_addrs.push(owner.to_string());
    }
    submit_wallet_ptb_with_allowed_addresses(
        http,
        &runtime.grpc_url,
        &runtime.sui_network,
        private_key,
        ptb,
        Some(allowed_addrs),
        false,
        false,
    )
    .await
    .map_err(AppError::Internal)?;

    Ok(count)
}

// ---------------------------------------------------------------------------
// 7. On-Chain Blob Queries (`query_blobs_by_owner`, `query_blob_storage_leases`, `find_blob_by_job`)
// ---------------------------------------------------------------------------

fn decimal_u256_to_blob_id(raw: &str) -> String {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return raw.to_owned();
    }
    let mut bytes = [0u8; 32];
    for digit in raw.bytes() {
        let mut carry = u32::from(digit - b'0');
        for byte in bytes.iter_mut() {
            let val = u32::from(*byte) * 10 + carry;
            *byte = (val & 0xff) as u8;
            carry = val >> 8;
        }
        if carry != 0 {
            return raw.to_owned();
        }
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
struct MoveDynamicField<K, V> {
    #[allow(dead_code)]
    id: Address,
    #[allow(dead_code)]
    name: K,
    value: V,
}

fn parse_metadata_from_proto_object(
    obj: &sui_rpc::proto::sui::rpc::v2::Object,
    out: &mut HashMap<String, String>,
) {
    // 1. Try BCS deserialization of `0x2::dynamic_field::Field<vector<u8>, Metadata>`
    // where `Metadata` is `{ metadata: VecMap<String, String> }` (identical in BCS to `Vec<(String, String)>`).
    if let Some(bcs_proto) = &obj.bcs {
        if let Ok(sdk_obj) = bcs_proto.deserialize::<sui_sdk_types::Object>() {
            if let ObjectData::Struct(move_struct) = sdk_obj.data() {
                if let Ok(field) = bcs::from_bytes::<MoveDynamicField<Vec<u8>, Vec<(String, String)>>>(
                    move_struct.contents(),
                ) {
                    for (k, v) in field.value {
                        out.insert(k, v);
                    }
                    return;
                }
            }
        }
    }
    // 2. Fallback to JSON traversal (`VecMap` entries `{ "key": ..., "value": ... }`).
    if let Some(json_proto) = &obj.json {
        let json_val = prost_to_json(json_proto);
        collect_vec_map_entries(&json_val, out);
    }
}

async fn read_blob_metadata_map(
    client: &mut sui_rpc::Client,
    blob_object_id: &str,
) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // Fast path: derive the `vector<u8>` dynamic child ID for `b"metadata"` directly (`1` gRPC GetObject).
    if let Ok(blob_addr) = blob_object_id.parse::<Address>() {
        if let Ok(key_bcs) = bcs::to_bytes(&b"metadata".to_vec()) {
            let metadata_field_id =
                blob_addr.derive_dynamic_child_id(&TypeTag::Vector(Box::new(TypeTag::U8)), &key_bcs);
            let mut obj_req = GetObjectRequest::default();
            obj_req.object_id = Some(metadata_field_id.to_string());
            obj_req.read_mask = Some(FieldMask::from_paths(["json", "bcs"]));
            if let Ok(obj_resp) = client.ledger_client().get_object(obj_req).await {
                if let Some(obj) = obj_resp.into_inner().object {
                    parse_metadata_from_proto_object(&obj, &mut map);
                    if !map.is_empty() {
                        return map;
                    }
                }
            }
        }
    }

    // Fallback: enumerate dynamic fields via `ListDynamicFields`.
    let mut df_req = ListDynamicFieldsRequest::default();
    df_req.parent = Some(blob_object_id.to_owned());
    df_req.page_size = Some(10);
    df_req.read_mask = Some(FieldMask::from_paths(["field_id"]));
    let Ok(df_resp) = client.state_client().list_dynamic_fields(df_req).await else {
        return map;
    };

    for field in df_resp.into_inner().dynamic_fields {
        let Some(field_id) = field.field_id else {
            continue;
        };
        let mut obj_req = GetObjectRequest::default();
        obj_req.object_id = Some(field_id);
        obj_req.read_mask = Some(FieldMask::from_paths(["json", "bcs"]));
        let Ok(obj_resp) = client.ledger_client().get_object(obj_req).await else {
            continue;
        };
        if let Some(obj) = obj_resp.into_inner().object {
            parse_metadata_from_proto_object(&obj, &mut map);
        }
    }
    map
}

fn collect_vec_map_entries(val: &serde_json::Value, out: &mut HashMap<String, String>) {
    match val {
        serde_json::Value::Object(obj) => {
            if let (Some(serde_json::Value::String(k)), Some(serde_json::Value::String(v))) =
                (obj.get("key"), obj.get("value"))
            {
                out.insert(k.clone(), v.clone());
            }
            for child in obj.values() {
                collect_vec_map_entries(child, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_vec_map_entries(item, out);
            }
        }
        _ => {}
    }
}

pub async fn query_blobs_by_owner_in_process(
    owner_address: &str,
    namespace: Option<&str>,
    package_id: Option<&str>,
    limit: Option<usize>,
) -> Result<(Vec<OnChainBlob>, bool), AppError> {
    let runtime = get_native_runtime_config();
    let mut client = shared_sui_grpc_client(&runtime.grpc_url)
        .map_err(AppError::UpstreamUnavailable)?;

    let canonical_owner = owner_address
        .trim()
        .parse::<Address>()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| owner_address.to_owned());

    // Match `walrus-query.ts` candidate cap formula:
    // `cap = useRecentTxPath ? Math.max(1, Math.min(desiredMatches * 5, 100)) : Infinity`
    // and probe `cap + 1` to determine `source_capped = probed.len() > cap`.
    let (cap, probe_cap) = match limit {
        Some(l) if l > 0 => {
            let desired = l.clamp(1, 500);
            let c = (desired * 5).clamp(1, 100);
            (c, c + 1)
        }
        _ => (1000, 1001),
    };

    let mut probed = Vec::new();
    let mut page_token: Option<Vec<u8>> = None;
    let blob_type = format!("{}::blob::Blob", runtime.walrus_package_id);

    while probed.len() < probe_cap {
        let mut req = ListOwnedObjectsRequest::default();
        req.owner = Some(canonical_owner.clone());
        req.page_size = Some(50);
        req.page_token = page_token.clone().map(Into::into);
        req.object_type = Some(blob_type.clone());
        req.read_mask = Some(FieldMask::from_paths(["object_id", "json"]));

        let resp = client
            .state_client()
            .list_owned_objects(req)
            .await
            .map_err(|e| AppError::UpstreamUnavailable(format!("ListOwnedObjects failed: {e}")))?
            .into_inner();

        for obj in resp.objects {
            probed.push(obj);
            if probed.len() >= probe_cap {
                break;
            }
        }

        match resp.next_page_token {
            Some(tok) if !tok.is_empty() && probed.len() < probe_cap => {
                page_token = Some(tok.to_vec());
            }
            _ => break,
        }
    }

    let source_capped = probed.len() > cap;
    probed.truncate(cap);

    let mut candidates: Vec<(String, String)> = Vec::with_capacity(probed.len());
    for obj in probed {
        let Some(object_id) = obj.object_id else {
            continue;
        };
        let json_val = obj.json.as_deref().map(prost_to_json);
        let raw_blob_id = json_val
            .as_ref()
            .and_then(|v| v.get("blob_id"))
            .and_then(|v| match v {
                serde_json::Value::String(s) => Some(s.clone()),
                serde_json::Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .unwrap_or_default();
        if raw_blob_id.is_empty() {
            continue;
        }
        let blob_id = decimal_u256_to_blob_id(&raw_blob_id);
        candidates.push((object_id, blob_id));
    }

    // Batch-fetch derived `b"metadata"` dynamic-field objects via `BatchGetObjectsRequest`
    // (chunks of 50) instead of issuing N sequential `GetObject` gRPC calls.
    let mut batch_metadata: HashMap<String, HashMap<String, String>> =
        HashMap::with_capacity(candidates.len());
    if let Ok(key_bcs) = bcs::to_bytes(&b"metadata".to_vec()) {
        let key_type = TypeTag::Vector(Box::new(TypeTag::U8));
        for chunk in candidates.chunks(50) {
            let mut reqs = Vec::with_capacity(chunk.len());
            let mut chunk_obj_ids = Vec::with_capacity(chunk.len());
            for (object_id, _) in chunk {
                if let Ok(blob_addr) = object_id.parse::<Address>() {
                    let df_id = blob_addr.derive_dynamic_child_id(&key_type, &key_bcs);
                    let mut get_req = GetObjectRequest::default();
                    get_req.object_id = Some(df_id.to_string());
                    reqs.push(get_req);
                    chunk_obj_ids.push(object_id.clone());
                }
            }
            if reqs.is_empty() {
                continue;
            }
            let mut batch_req = BatchGetObjectsRequest::default();
            batch_req.requests = reqs;
            batch_req.read_mask = Some(FieldMask::from_paths(["json", "bcs"]));
            if let Ok(batch_resp) = client.ledger_client().batch_get_objects(batch_req).await {
                for (object_id, obj_res) in chunk_obj_ids
                    .into_iter()
                    .zip(batch_resp.into_inner().objects)
                {
                    if let Some(
                        sui_rpc::proto::sui::rpc::v2::get_object_result::Result::Object(obj),
                    ) = obj_res.result
                    {
                        let mut map = HashMap::new();
                        parse_metadata_from_proto_object(&obj, &mut map);
                        if !map.is_empty() {
                            batch_metadata.insert(object_id, map);
                        }
                    }
                }
            }
        }
    }

    let mut blobs = Vec::new();
    for (object_id, blob_id) in candidates {
        let metadata = match batch_metadata.remove(&object_id) {
            Some(map) => map,
            None => read_blob_metadata_map(&mut client, &object_id).await,
        };

        let blob_ns = metadata
            .get("memwal_namespace")
            .cloned()
            .unwrap_or_else(|| "default".to_owned());
        if let Some(expected_ns) = namespace {
            if blob_ns != expected_ns {
                continue;
            }
        }
        let blob_pkg = metadata.get("memwal_package_id").cloned().unwrap_or_default();
        if let Some(expected_pkg) = package_id {
            if !blob_pkg.eq_ignore_ascii_case(expected_pkg) {
                continue;
            }
        }
        let agent_id = metadata.get("memwal_agent_id").cloned();

        blobs.push(OnChainBlob {
            blob_id,
            object_id,
            namespace: blob_ns,
            package_id: blob_pkg,
            agent_id,
        });
    }

    Ok((blobs, source_capped))
}

pub async fn query_blob_storage_leases_in_process(
    owner_address: &str,
    blob_ids: &[String],
) -> Result<BlobStorageLeases, AppError> {
    let runtime = get_native_runtime_config();
    let system = resolve_walrus_system_snapshot(
        &runtime.grpc_url,
        &runtime.sui_network,
        &runtime.walrus_package_id,
        &runtime.walrus_system_object_id,
    )
    .await
    .map_err(AppError::Internal)?;

    if blob_ids.is_empty() {
        return Ok(BlobStorageLeases {
            blobs: Vec::new(),
            current_epoch: system.epoch as i32,
        });
    }

    let mut client = shared_sui_grpc_client(&runtime.grpc_url).map_err(AppError::Internal)?;

    let requested: std::collections::HashSet<&str> = blob_ids.iter().map(String::as_str).collect();
    let mut found = Vec::new();
    let mut page_token: Option<Vec<u8>> = None;

    loop {
        let mut req = ListOwnedObjectsRequest::default();
        req.owner = Some(owner_address.to_owned());
        req.page_size = Some(500);
        req.page_token = page_token.clone().map(Into::into);
        req.object_type = Some(format!("{}::blob::Blob", runtime.walrus_package_id));
        req.read_mask = Some(FieldMask::from_paths(["object_id", "json"]));

        let resp = client
            .state_client()
            .list_owned_objects(req)
            .await
            .map_err(|e| AppError::Internal(format!("ListOwnedObjects (leases) failed: {e}")))?
            .into_inner();

        for obj in resp.objects {
            let Some(object_id) = obj.object_id else {
                continue;
            };
            let json_val = obj.json.as_deref().map(prost_to_json);
            let raw_blob_id = json_val
                .as_ref()
                .and_then(|v| v.get("blob_id"))
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            let blob_id = decimal_u256_to_blob_id(raw_blob_id);
            if !requested.contains(blob_id.as_str()) {
                continue;
            }
            let end_epoch = json_val
                .as_ref()
                .and_then(|v| v.get("storage"))
                .and_then(|s| json_u64(s.get("end_epoch")))
                .unwrap_or(system.epoch as u64) as i32;
            found.push(BlobStorageLease {
                blob_id,
                object_id,
                storage_end_epoch: end_epoch,
            });
        }

        if found.len() >= requested.len() {
            break;
        }
        match resp.next_page_token {
            Some(tok) if !tok.is_empty() => page_token = Some(tok.to_vec()),
            _ => break,
        }
    }

    Ok(BlobStorageLeases {
        blobs: found,
        current_epoch: system.epoch as i32,
    })
}

pub async fn find_blob_by_job_in_process(
    owner: &str,
    job_id: &str,
) -> Result<Option<FoundBlobByJob>, AppError> {
    let runtime = get_native_runtime_config();
    let user_owner_addr: Address = owner
        .trim()
        .parse()
        .map_err(|e| AppError::BadRequest(format!("invalid owner address '{owner}': {e}")))?;
    let user_owner = user_owner_addr.to_string();

    let mut client = shared_sui_grpc_client(&runtime.grpc_url).map_err(AppError::Internal)?;

    // Scan server pool wallets first (where a not-yet-transferred blob lives) AND
    // the user (where a transferred-but-unrecorded blob lives), matching `findBlobObjectByJob`
    // in `services/server/scripts/sidecar/routes/walrus-query.ts`.
    let mut candidate_owners = Vec::new();
    for key in &runtime.sui_private_keys {
        if let Ok(addr) = derive_sui_address(key) {
            if !candidate_owners.iter().any(|c| c == &addr) {
                candidate_owners.push(addr);
            }
        }
    }
    if !candidate_owners.iter().any(|c| c == &user_owner) {
        candidate_owners.push(user_owner);
    }

    let blob_type = format!("{}::blob::Blob", runtime.walrus_package_id);

    for candidate in candidate_owners {
        let mut page_token: Option<Vec<u8>> = None;
        loop {
            let mut req = ListOwnedObjectsRequest::default();
            req.owner = Some(candidate.clone());
            req.page_size = Some(50);
            req.page_token = page_token.clone().map(Into::into);
            req.object_type = Some(blob_type.clone());
            req.read_mask = Some(FieldMask::from_paths(["object_id", "json"]));

            let resp = client
                .state_client()
                .list_owned_objects(req)
                .await
                .map_err(|e| {
                    AppError::Internal(format!(
                        "find_blob_by_job ListOwnedObjects({candidate}) failed: {e}"
                    ))
                })?
                .into_inner();

            for obj in resp.objects {
                let Some(object_id) = obj.object_id else {
                    continue;
                };
                let metadata = read_blob_metadata_map(&mut client, &object_id).await;
                let job_matches =
                    metadata.get("memwal_job_id").map(String::as_str) == Some(job_id);
                let owner_matches = metadata
                    .get("memwal_owner")
                    .and_then(|v| v.trim().parse::<Address>().ok())
                    == Some(user_owner_addr);

                if job_matches && owner_matches {
                    let json_val = obj.json.as_deref().map(prost_to_json);
                    let raw_blob_id = json_val
                        .as_ref()
                        .and_then(|v| v.get("blob_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    return Ok(Some(FoundBlobByJob {
                        blob_id: decimal_u256_to_blob_id(raw_blob_id),
                        object_id: Some(object_id),
                    }));
                }
            }

            match resp.next_page_token {
                Some(tok) if !tok.is_empty() => page_token = Some(tok.to_vec()),
                _ => break,
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn walrus_core_rs2_encodes_blob_and_computes_deterministic_blob_id() {
        let payload = b"MemWal in-process Rust Walrus RS2 test payload".to_vec();
        let encoded_1 = encode_walrus_blob_rs2(payload.clone(), 1000)
            .await
            .expect("RS2 encoding should succeed");
        let encoded_2 = encode_walrus_blob_rs2(payload.clone(), 1000)
            .await
            .expect("RS2 encoding should succeed");

        assert_eq!(encoded_1.blob_id, encoded_2.blob_id);
        assert_eq!(encoded_1.blob_id_str, encoded_2.blob_id_str);
        assert_eq!(encoded_1.root_hash_bytes, encoded_2.root_hash_bytes);
        assert_eq!(encoded_1.unencoded_length, payload.len() as u64);
        assert!(encoded_1.encoded_size > encoded_1.unencoded_length);
        assert!(!encoded_1.blob_id_str.is_empty());
    }

    #[test]
    fn relay_tip_config_calculates_const_and_linear_tips() {
        let recipient = "0x00000000000000000000000000000000000000000000000000000000000000aa";
        let const_tip = RelayTipConfig::SendTip {
            address: recipient.to_owned(),
            kind: RelayTipKind::Const(12_345),
        };
        let (addr, amt) = const_tip.calculate_tip(1000, 512).unwrap();
        assert_eq!(addr, recipient.parse::<Address>().unwrap());
        assert_eq!(amt, 12_345);

        let linear_tip = RelayTipConfig::SendTip {
            address: recipient.to_owned(),
            kind: RelayTipKind::Linear {
                base: 1_000,
                encoded_size_mul_per_kib: 10,
            },
        };
        let (_, linear_amt) = linear_tip.calculate_tip(1000, 4096).unwrap();
        assert!(linear_amt > 1_000);
    }

    #[tokio::test]
    async fn register_blob_ptb_places_hashed_auth_package_at_input_zero_when_tipped() {
        let payload = b"hello tipped walrus relay".to_vec();
        let encoded = encode_walrus_blob_rs2(payload, 1000).await.unwrap();
        let system = WalrusSystemSnapshot {
            system_object_id: "0x6c2547cbbc38025cf3adac45f63cb0a8d12ecf777cdc75a4971612bf97fdf6af"
                .parse()
                .unwrap(),
            initial_shared_version: 1,
            call_package_id: TESTNET_WALRUS_PACKAGE_ID.parse().unwrap(),
            origin_package_id: TESTNET_WALRUS_PACKAGE_ID.parse().unwrap(),
            epoch: 457,
            n_shards: 1000,
            committee_size: 100,
            storage_price_per_unit_size: 1_000,
            write_price_per_unit_size: 2_000,
        };
        let tip_config = RelayTipConfig::SendTip {
            address: "0x00000000000000000000000000000000000000000000000000000000000000bb"
                .to_owned(),
            kind: RelayTipKind::Const(5_000),
        };
        let sender: Address =
            "0x00000000000000000000000000000000000000000000000000000000000000cc"
                .parse()
                .unwrap();

        let ptb = build_register_blob_ptb(
            "http://127.0.0.1:1",
            "testnet",
            sender,
            &system,
            &encoded,
            5,
            &tip_config,
            &[("memwal_namespace", "default".to_owned())],
        )
        .await
        .expect("should build register_blob PTB");

        match ptb.inputs.first() {
            Some(sui_sdk_types::Input::Pure(bytes)) => {
                assert_eq!(bytes.len(), 72, "HashedAuthPackage BCS must be 32+32+8=72 bytes");
                let decoded: HashedAuthPackage = bcs::from_bytes(bytes).unwrap();
                assert_eq!(decoded.blob_digest, encoded.blob_digest);
                assert_eq!(decoded.unencoded_length, encoded.unencoded_length);
            }
            other => panic!("expected Input::Pure at inputs[0], got {other:?}"),
        }
    }

    #[test]
    fn validate_seal_persistence_ciphertext_rejects_package_mismatch() {
        use fastcrypto::groups::Scalar as _;
        use seal_crypto::{ibe, seal_encrypt as crypto_seal_encrypt, EncryptionInput, IBEPublicKeys};

        let mut rng = rand::thread_rng();
        let msk = ibe::MasterKey::rand(&mut rng);
        let pk = ibe::public_key_from_master_key(&msk);
        let srv: seal_crypto::ObjectID =
            "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75"
                .parse()
                .unwrap();
        let pkg_a = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let pkg_b = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let policy_pkg = "0x3333333333333333333333333333333333333333333333333333333333333333";

        let (enc_obj, _) = crypto_seal_encrypt(
            pkg_a.parse().unwrap(),
            vec![1u8; 40],
            vec![srv],
            &IBEPublicKeys::BonehFranklinBLS12381(vec![pk]),
            1,
            EncryptionInput::Aes256Gcm {
                data: b"fence test".to_vec(),
                aad: None,
            },
        )
        .unwrap();
        let enc_bytes = bcs::to_bytes(&enc_obj).unwrap();

        // Matching package_id and policy_package_id succeeds.
        assert!(validate_seal_persistence_ciphertext(&enc_bytes, pkg_a, policy_pkg, policy_pkg).is_ok());

        // Mismatched immutable package_id fails closed.
        let err = validate_seal_persistence_ciphertext(&enc_bytes, pkg_b, policy_pkg, policy_pkg)
            .unwrap_err();
        assert!(err.contains("Ciphertext packageId does not match packageId"));

        // Mismatched policy_package_id fails closed.
        let err_pol = validate_seal_persistence_ciphertext(&enc_bytes, pkg_a, pkg_b, policy_pkg)
            .unwrap_err();
        assert!(err_pol.contains("policyPackageId does not match"));
    }

    #[test]
    fn move_dynamic_field_bcs_roundtrips_vec_map_metadata() {
        let id: Address = "0x0000000000000000000000000000000000000000000000000000000000000055"
            .parse()
            .unwrap();
        let name = b"metadata".to_vec();
        let pairs = vec![
            ("memwal_namespace".to_owned(), "work".to_owned()),
            (
                "memwal_owner".to_owned(),
                "0x0000000000000000000000000000000000000000000000000000000000000077".to_owned(),
            ),
        ];
        #[derive(Serialize)]
        struct EncodeField {
            id: Address,
            name: Vec<u8>,
            value: Vec<(String, String)>,
        }
        let encoded = bcs::to_bytes(&EncodeField {
            id,
            name: name.clone(),
            value: pairs.clone(),
        })
        .unwrap();
        let decoded: MoveDynamicField<Vec<u8>, Vec<(String, String)>> =
            bcs::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.name, name);
        assert_eq!(decoded.value, pairs);
    }

    #[test]
    fn effective_walrus_upload_relay_url_ignores_legacy_publisher_host() {
        assert_eq!(
            effective_walrus_upload_relay_url(
                "testnet",
                "https://publisher.walrus-testnet.walrus.space"
            ),
            "https://upload-relay.testnet.walrus.space"
        );
        assert_eq!(
            effective_walrus_upload_relay_url(
                "mainnet",
                "https://publisher.walrus-mainnet.walrus.space"
            ),
            "https://upload-relay.mainnet.walrus.space"
        );
        assert_eq!(
            effective_walrus_upload_relay_url("testnet", "http://127.0.0.1:19000"),
            "http://127.0.0.1:19000"
        );
    }
}


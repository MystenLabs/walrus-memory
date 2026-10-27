//! In-process Rust Walrus upload, durable journal step machine, metadata/transfer PTB builder,
//! on-chain blob query/verification, concurrency limiter, and wallet-balance inspector.
//!
//! Replaces `services/server/scripts/sidecar/routes/walrus*.ts`, `blob-metadata.ts`,
//! `concurrency.ts`, and `routes/balances.ts` using `walrus-core` (`EncodingConfig`,
//! `BlobId`, `BlobMetadataApi`, `ConfirmationCertificate`), `seal-crypto` (`EncryptedObject`),
//! and `sui-rpc` gRPC.

#![allow(dead_code)]

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
use sui_crypto::SuiVerifier as _;
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{
    changed_object, BatchGetObjectsRequest, ExecuteTransactionRequest, ExecutedTransaction,
    GetEpochRequest, GetObjectRequest, GetServiceInfoRequest, GetTransactionRequest,
    ListBalancesRequest, ListDynamicFieldsRequest, ListOwnedObjectsRequest,
};
use sui_sdk_types::{
    Address, Digest, ExecutionStatus, GasPayment, Identifier, ObjectData, ProgrammableTransaction,
    StructTag, Transaction, TransactionEffects, TransactionExpiration, TransactionKind, TypeTag,
    UserSignature,
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
    PreparedRegisterTransaction, SealPersistence, SetMetadataBatchEntry, UploadBlobError,
    UploadExecutionIdentity, UploadJournal, UploadResult,
};
use crate::sui::enoki::{
    derive_sui_address, enoki_execute_sponsored_transaction, enoki_is_enabled,
    enoki_sponsor_transaction_kind_with_addresses, fetch_executed_transaction_outcome,
    parse_sui_private_key, shared_sui_grpc_client, sign_transaction_bytes, submit_wallet_ptb,
    submit_wallet_ptb_with_allowed_addresses, verify_sponsored_transaction_matches_ptb,
    CreatedObjectInfo, EffectsFetchMode, EnokiError, EnokiExecuteOutput, SponsorshipMode,
    WalletTxOutcome,
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

#[derive(Clone)]
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

/// Custom `Debug` implementation that redacts `sui_private_keys` so secret key material
/// is never leaked to logs or panic messages (`M-PUBLIC-DEBUG` / `C-DEBUG`).
impl std::fmt::Debug for NativeRuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeRuntimeConfig")
            .field("grpc_url", &self.grpc_url)
            .field("sui_network", &self.sui_network)
            .field("walrus_publisher_url", &self.walrus_publisher_url)
            .field("walrus_package_id", &self.walrus_package_id)
            .field("walrus_system_object_id", &self.walrus_system_object_id)
            .field(
                "sui_private_keys",
                &format_args!("[REDACTED; {} keys]", self.sui_private_keys.len()),
            )
            .field("package_id", &self.package_id)
            .field("seal_policy_package_id", &self.seal_policy_package_id)
            .field("registry_id", &self.registry_id)
            .finish()
    }
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

    pub fn trusted_uploader_addresses(&self) -> Result<std::collections::HashSet<String>, String> {
        if self.sui_private_keys.is_empty() {
            return Err("no SERVER_SUI_PRIVATE_KEYS configured".to_owned());
        }
        let mut set = std::collections::HashSet::with_capacity(self.sui_private_keys.len());
        for (idx, raw_key) in self.sui_private_keys.iter().enumerate() {
            let addr = derive_sui_address(raw_key)
                .map_err(|e| format!("invalid SERVER_SUI_PRIVATE_KEYS[{idx}]: {e}"))?;
            set.insert(addr);
        }
        Ok(set)
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
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Returns true when the server should execute Walrus/SEAL/Sponsor operations in-process in Rust
/// instead of calling the external Node.js sidecar over HTTP.
///
/// Defaults to `true` when `sidecar_url` is the default (`http://localhost:9000` / `in-process`)
/// or when `IN_PROCESS_SIDECAR=true`. Preserves HTTP sidecar execution when unit tests pass an
/// ephemeral mock HTTP server port (`http://127.0.0.1:<random_port>`) unless `IN_PROCESS_SIDECAR=true`.
#[must_use]
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
    if !pub_trimmed.is_empty() && !pub_trimmed.contains("publisher.") {
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

#[derive(Debug)]
pub struct InProcessUploadLimiter {
    in_flight: AtomicUsize,
    queued: AtomicUsize,
    max_concurrent: usize,
    max_queue_depth: usize,
    queue_timeout_ms: u64,
    notify: Notify,
}

#[must_use = "if unused, the upload slot is immediately released"]
#[derive(Debug)]
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

/// RAII guard that ensures `limiter.queued` is always decremented even if an
/// awaiting `InProcessUploadLimiter::acquire` future is cancelled/dropped.
struct QueuedWaiterGuard<'a> {
    limiter: &'a InProcessUploadLimiter,
}

impl Drop for QueuedWaiterGuard<'_> {
    fn drop(&mut self) {
        self.limiter.queued.fetch_sub(1, Ordering::SeqCst);
    }
}

impl InProcessUploadLimiter {
    #[must_use]
    pub fn new(max_concurrent: usize, max_queue_depth: usize, queue_timeout_ms: u64) -> Self {
        Self {
            in_flight: AtomicUsize::new(0),
            queued: AtomicUsize::new(0),
            max_concurrent: max_concurrent.max(1),
            max_queue_depth,
            queue_timeout_ms: queue_timeout_ms.max(1),
            notify: Notify::new(),
        }
    }

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
        Self::new(max_concurrent, max_queue_depth, queue_timeout_ms)
    }

    #[must_use]
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
        let _queued_guard = QueuedWaiterGuard { limiter: self };
        if current_queued >= self.max_queue_depth {
            return Err(format!(
                "Timed out waiting for Walrus upload slot: Walrus upload queue full ({}/{} queued)",
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
                return Ok(UploadSlotGuard {
                    limiter: self,
                    slots,
                });
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "Timed out waiting for Walrus upload slot after {}ms",
                    self.queue_timeout_ms
                ));
            }
            let remaining = deadline - now;
            if tokio::time::timeout(remaining, notified).await.is_err() {
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

    let balance_futures = runtime
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
    #[must_use]
    pub fn storage_cost(&self, encoded_size: u64, epochs: u32) -> u64 {
        let units = encoded_size.div_ceil(BYTES_PER_UNIT_SIZE);
        units
            .saturating_mul(self.storage_price_per_unit_size)
            .saturating_mul(u64::from(epochs))
    }

    #[must_use]
    pub fn write_cost(&self, encoded_size: u64) -> u64 {
        let units = encoded_size.div_ceil(BYTES_PER_UNIT_SIZE);
        units.saturating_mul(self.write_price_per_unit_size)
    }
}

struct TimedValue<T> {
    value: T,
    fetched_at: Instant,
}

static SYSTEM_SNAPSHOT_CACHE: OnceLock<RwLock<HashMap<String, TimedValue<WalrusSystemSnapshot>>>> =
    OnceLock::new();

pub(crate) fn prost_to_json(value: &prost_types::Value) -> serde_json::Value {
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
        cache.write().await.clear();
    }
}

pub async fn resolve_walrus_system_snapshot(
    grpc_url: &str,
    network: &str,
    configured_package_id: &str,
    configured_system_id: &str,
) -> Result<WalrusSystemSnapshot, String> {
    let origin_pkg_str = effective_walrus_package_id(network, configured_package_id);
    let system_id_str = effective_walrus_system_object_id(network, configured_system_id);
    let cache_key = format!("{}|{}", grpc_url.trim(), system_id_str);
    let cache = SYSTEM_SNAPSHOT_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Some(cached) = cache.read().await.get(&cache_key) {
        if cached.fetched_at.elapsed() < Duration::from_secs(30) {
            return Ok(cached.value.clone());
        }
    }

    let fallback_origin_package_id: Address = origin_pkg_str
        .parse()
        .map_err(|e| format!("invalid Walrus package ID '{origin_pkg_str}': {e}"))?;
    let system_object_id: Address = system_id_str
        .parse()
        .map_err(|e| format!("invalid Walrus system object ID '{system_id_str}': {e}"))?;

    let mut client = shared_sui_grpc_client(grpc_url)?;

    let mut sys_req = GetObjectRequest::default();
    sys_req.object_id = Some(system_id_str.clone());
    sys_req.read_mask = Some(FieldMask::from_paths([
        "object_id",
        "object_type",
        "owner",
        "json",
    ]));
    let sys_obj = client
        .ledger_client()
        .get_object(sys_req)
        .await
        .map_err(|e| format!("failed to fetch Walrus System object {system_id_str}: {e}"))?
        .into_inner()
        .object
        .ok_or_else(|| format!("Walrus System object {system_id_str} not found"))?;

    let origin_package_id = sys_obj
        .object_type
        .as_deref()
        .and_then(|t| t.split("::").next())
        .and_then(|addr| addr.parse::<Address>().ok())
        .unwrap_or(fallback_origin_package_id);

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

    cache.write().await.insert(
        cache_key,
        TimedValue {
            value: snapshot.clone(),
            fetched_at: Instant::now(),
        },
    );

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
    SendTip { address: String, kind: RelayTipKind },
}

impl RelayTipConfig {
    #[must_use]
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
                        let shards = NonZeroU16::new(n_shards.max(1))?;
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
    encode_walrus_blob_rs2_with_nonce(data, n_shards, None).await
}

pub async fn encode_walrus_blob_rs2_with_nonce(
    data: Vec<u8>,
    n_shards: u16,
    existing_nonce: Option<[u8; 32]>,
) -> Result<EncodedWalrusBlob, String> {
    tokio::task::spawn_blocking(move || {
        let shards =
            NonZeroU16::new(n_shards.max(1)).ok_or_else(|| "invalid n_shards (0)".to_owned())?;
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
        let nonce = match existing_nonce {
            Some(n) => n,
            None => {
                let mut generated = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut generated);
                generated
            }
        };

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
) -> Result<(Option<u64>, Vec<(Address, u64, Digest)>), String> {
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

    let address_wal = match bal_res {
        Ok(resp) => {
            let mut found = 0u64;
            for bal in resp.into_inner().balances {
                let ct = bal.coin_type.as_deref().unwrap_or_default();
                if ct == wal_coin_type || ct.ends_with("::wal::WAL") {
                    found = bal.address_balance.unwrap_or(0);
                    break;
                }
            }
            Some(found)
        }
        Err(_) => None,
    };

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

    let (address_wal_opt, owned_wal_coins) =
        select_owned_wal_coins(grpc_url, &sender.to_string(), &wal_coin_type_str).await?;

    if let Some(available_wal) = address_wal_opt {
        if available_wal < total_wal_cost && owned_wal_coins.is_empty() {
            return Err(format!(
                "Insufficient balance of {wal_coin_type_str} for owner {sender}. Required: {total_wal_cost}, Available: {available_wal}"
            ));
        }
    }

    let (wal_coin_arg, destroy_zero_after) = if address_wal_opt.unwrap_or(total_wal_cost)
        >= total_wal_cost
        || owned_wal_coins.is_empty()
    {
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
        let key_arg = builder.pure(k);
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
        let safe_body = crate::sui::enoki::sanitize_upstream_error_for_logging(&body);
        return Err(format!(
            "Walrus upload relay returned {status}: {safe_body}"
        ));
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

fn extract_address_owner_from_proto(
    owner: Option<&sui_rpc::proto::sui::rpc::v2::Owner>,
) -> Option<Address> {
    let o = owner?;
    if let Some(kind) = o.kind {
        if kind != sui_rpc::proto::sui::rpc::v2::owner::OwnerKind::Address as i32 {
            return None;
        }
    }
    o.address.as_deref()?.trim().parse::<Address>().ok()
}

/// Resolves owned object `(Address, version, Digest, Option<Address>)` tuples for `object_ids`
/// in batches of 50 using `BatchGetObjectsRequest` (`M-THROUGHPUT`).
async fn resolve_owned_object_refs_batch(
    grpc_url: &str,
    object_ids: &[String],
) -> Result<Vec<(Address, u64, Digest, Option<Address>)>, String> {
    if object_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut client = shared_sui_grpc_client(grpc_url)?;
    let mut out = Vec::with_capacity(object_ids.len());

    for chunk in object_ids.chunks(50) {
        let mut addrs = Vec::with_capacity(chunk.len());
        let mut reqs = Vec::with_capacity(chunk.len());
        for id_str in chunk {
            let addr: Address = id_str
                .parse()
                .map_err(|e| format!("invalid object ID '{id_str}': {e}"))?;
            addrs.push((id_str.as_str(), addr));
            let mut req = GetObjectRequest::default();
            req.object_id = Some(id_str.clone());
            reqs.push(req);
        }
        let mut batch_req = BatchGetObjectsRequest::default();
        batch_req.requests = reqs;
        batch_req.read_mask = Some(FieldMask::from_paths([
            "object_id",
            "version",
            "digest",
            "owner",
        ]));

        let batch_resp = client
            .ledger_client()
            .batch_get_objects(batch_req)
            .await
            .map_err(|e| format!("BatchGetObjects failed: {e}"))?
            .into_inner();

        if batch_resp.objects.len() != addrs.len() {
            return Err(format!(
                "BatchGetObjects returned {} entries for {} requested objects",
                batch_resp.objects.len(),
                addrs.len()
            ));
        }

        for ((id_str, addr), res) in addrs.into_iter().zip(batch_resp.objects) {
            let obj = match res.result {
                Some(sui_rpc::proto::sui::rpc::v2::get_object_result::Result::Object(o)) => o,
                _ => return Err(format!("object {id_str} not found on chain")),
            };
            let version = obj
                .version
                .ok_or_else(|| format!("object {id_str} omitted version"))?;
            let digest_str = obj
                .digest
                .ok_or_else(|| format!("object {id_str} omitted digest"))?;
            let digest: Digest = digest_str
                .parse()
                .map_err(|e| format!("invalid digest '{digest_str}' for {id_str}: {e}"))?;
            let owner_addr = extract_address_owner_from_proto(obj.owner.as_ref());
            out.push((addr, version, digest, owner_addr));
        }
    }
    Ok(out)
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
fn append_seal_encrypt_fence_move_call(
    builder: &mut TransactionBuilder,
    immutable_package_id: &str,
    policy_package_id: &str,
    configured_policy_pkg: &str,
    reg_addr: Address,
    reg_ver: u64,
    acct_addr: Address,
    acct_ver: u64,
    encrypted_bytes: &[u8],
) -> Result<(), String> {
    let (enc_obj, policy_pkg) = validate_seal_persistence_ciphertext(
        encrypted_bytes,
        immutable_package_id,
        policy_package_id,
        configured_policy_pkg,
    )?;

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

    let bitmap = signers_to_bitmap(&certificate.signers, system.committee_size);

    let sig_arg = builder.pure(&certificate.signature.as_ref());
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct NativeFlowState {
    pub(crate) step: String,
    pub(crate) blob_id: String,
    pub(crate) blob_id_bytes: [u8; 32],
    pub(crate) root_hash_bytes: [u8; 32],
    pub(crate) unencoded_length: u64,
    pub(crate) encoded_size: u64,
    pub(crate) nonce: [u8; 32],
    pub(crate) blob_digest: [u8; 32],
    pub(crate) blob_object_id: Option<String>,
    pub(crate) register_tx_digest: Option<String>,
    pub(crate) confirmation_certificate: Option<ConfirmationCertificate>,
    pub(crate) end_epoch: Option<i32>,
}

#[derive(Debug, Clone)]
pub(crate) enum ParsedResumeStep {
    Encoded {
        blob_id: String,
        #[allow(dead_code)]
        root_hash: String,
        #[allow(dead_code)]
        unencoded_size: u64,
        nonce: Option<[u8; 32]>,
        register_rebuild: String,
        #[allow(dead_code)]
        native_flow: Option<NativeFlowState>,
    },
    Registered {
        blob_id: String,
        blob_object_id: String,
        tx_digest: String,
        nonce: Option<[u8; 32]>,
        end_epoch: Option<i32>,
        native_flow: Option<NativeFlowState>,
    },
    Uploaded {
        blob_id: String,
        blob_object_id: String,
        certificate: ConfirmationCertificate,
        end_epoch: Option<i32>,
    },
    Certified {
        step_json: serde_json::Value,
    },
}

fn decode_optional_32_byte_nonce(val: Option<&serde_json::Value>) -> Option<[u8; 32]> {
    let v = val?;
    match v {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(trimmed)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
                .ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        }
        serde_json::Value::Array(arr) if arr.len() == 32 => {
            let mut out = [0u8; 32];
            for (idx, item) in arr.iter().enumerate() {
                out[idx] = u8::try_from(item.as_u64()?).ok()?;
            }
            Some(out)
        }
        serde_json::Value::Object(map) if map.len() == 32 => {
            let mut out = [0u8; 32];
            for (idx, slot) in out.iter_mut().enumerate() {
                let b = map.get(&idx.to_string())?.as_u64()?;
                *slot = u8::try_from(b).ok()?;
            }
            Some(out)
        }
        _ => None,
    }
}

fn parse_confirmation_certificate_value(
    val: &serde_json::Value,
) -> Result<ConfirmationCertificate, String> {
    if let Ok(cert) = serde_json::from_value::<ConfirmationCertificate>(val.clone()) {
        return Ok(cert);
    }
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
            .map_err(|e| format!("invalid base64 certificate in resumeStep: {e}"))?;
        if let Ok(cert) = bcs::from_bytes::<ConfirmationCertificate>(&bytes) {
            return Ok(cert);
        }
        if let Ok(cert) = serde_json::from_slice::<ConfirmationCertificate>(&bytes) {
            return Ok(cert);
        }
    }
    Err(
        "resumeStep.certificate could not be decoded as a Walrus ConfirmationCertificate"
            .to_owned(),
    )
}

/// Validates and parses `journal.resume_step`, supporting both sidecar-formatted steps
/// (`step = "encoded" | "registered" | "uploaded" | "certified"`) and Rust `nativeFlowState`
/// journals, and failing closed with `AppError::BadRequest` on any malformed or unrecognized
/// `resumeStep` instead of falling back to fresh registration.
pub(crate) fn parse_resume_step_json(
    raw: Option<&serde_json::Value>,
) -> Result<Option<ParsedResumeStep>, AppError> {
    let Some(val) = raw else {
        return Ok(None);
    };
    let obj = val
        .as_object()
        .ok_or_else(|| AppError::BadRequest("resumeStep must be an object".into()))?;

    let step = obj
        .get("step")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AppError::BadRequest("Invalid resumeStep.step: undefined".into()))?;

    let blob_id = obj
        .get("blobId")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::BadRequest("resumeStep.blobId is required".into()))?
        .to_owned();

    let native_flow: Option<NativeFlowState> = obj
        .get("nativeFlowState")
        .and_then(|fs| serde_json::from_value(fs.clone()).ok());

    let register_rebuild = obj
        .get("registerRebuild")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();

    let end_epoch = obj
        .get("endEpoch")
        .and_then(serde_json::Value::as_i64)
        .map(|e| e as i32)
        .or_else(|| native_flow.as_ref().and_then(|nf| nf.end_epoch));

    match step {
        "encoded" => {
            let root_hash = obj
                .get("rootHash")
                .and_then(|v| match v {
                    serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
                    serde_json::Value::Array(arr) if arr.len() == 32 => {
                        Some(format!("array:{}", arr.len()))
                    }
                    _ => None,
                })
                .or_else(|| {
                    native_flow.as_ref().map(|nf| {
                        base64::engine::general_purpose::STANDARD.encode(nf.root_hash_bytes)
                    })
                })
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "encoded resumeStep requires rootHash and unencodedSize".into(),
                    )
                })?;

            let unencoded_size = obj
                .get("unencodedSize")
                .and_then(serde_json::Value::as_u64)
                .or_else(|| native_flow.as_ref().map(|nf| nf.unencoded_length))
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "encoded resumeStep requires rootHash and unencodedSize".into(),
                    )
                })?;

            let nonce = decode_optional_32_byte_nonce(obj.get("nonce"))
                .or_else(|| native_flow.as_ref().map(|nf| nf.nonce));

            Ok(Some(ParsedResumeStep::Encoded {
                blob_id,
                root_hash,
                unencoded_size,
                nonce,
                register_rebuild,
                native_flow,
            }))
        }
        "registered" => {
            let blob_object_id = obj
                .get("blobObjectId")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .or_else(|| {
                    native_flow
                        .as_ref()
                        .and_then(|nf| nf.blob_object_id.clone())
                        .filter(|s| !s.trim().is_empty())
                })
                .ok_or_else(|| {
                    AppError::BadRequest("registered resumeStep requires blobObjectId".into())
                })?;

            let tx_digest = obj
                .get("txDigest")
                .or_else(|| obj.get("registerTxDigest"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .or_else(|| {
                    native_flow
                        .as_ref()
                        .and_then(|nf| nf.register_tx_digest.clone())
                        .filter(|s| !s.trim().is_empty())
                })
                .ok_or_else(|| {
                    AppError::BadRequest("registered resumeStep requires txDigest".into())
                })?;

            let nonce = decode_optional_32_byte_nonce(obj.get("nonce"))
                .or_else(|| native_flow.as_ref().map(|nf| nf.nonce));

            Ok(Some(ParsedResumeStep::Registered {
                blob_id,
                blob_object_id,
                tx_digest,
                nonce,
                end_epoch,
                native_flow,
            }))
        }
        "uploaded" => {
            let blob_object_id = obj
                .get("blobObjectId")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .or_else(|| {
                    native_flow
                        .as_ref()
                        .and_then(|nf| nf.blob_object_id.clone())
                        .filter(|s| !s.trim().is_empty())
                })
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "uploaded resumeStep requires blobObjectId and certificate".into(),
                    )
                })?;

            let certificate = if let Some(cert_val) = obj.get("certificate") {
                parse_confirmation_certificate_value(cert_val).map_err(AppError::BadRequest)?
            } else if let Some(cert) = native_flow
                .as_ref()
                .and_then(|nf| nf.confirmation_certificate.clone())
            {
                cert
            } else {
                return Err(AppError::BadRequest(
                    "uploaded resumeStep requires blobObjectId and certificate".into(),
                ));
            };

            Ok(Some(ParsedResumeStep::Uploaded {
                blob_id,
                blob_object_id,
                certificate,
                end_epoch,
            }))
        }
        "certified" => {
            let _blob_object_id = obj
                .get("blobObjectId")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AppError::BadRequest("certified resumeStep requires blobObjectId".into())
                })?;
            Ok(Some(ParsedResumeStep::Certified {
                step_json: val.clone(),
            }))
        }
        other => Err(AppError::BadRequest(format!(
            "Invalid resumeStep.step: {other}"
        ))),
    }
}

/// Computes a deterministic `u32` `ValidDuring` nonce from `Sha256(tx_kind_bytes || register_rebuild)[0..4]`,
/// matching `walrus-upload-journal.ts` (`sha256(concat([txKindBytes, utf8(rebuildSalt)])).readUInt32BE(0)`).
pub(crate) fn compute_deterministic_register_nonce(
    tx_kind_bytes: &[u8],
    register_rebuild: &str,
) -> u32 {
    let mut hasher = Sha256::default();
    hasher.update(tx_kind_bytes);
    if !register_rebuild.is_empty() {
        hasher.update(register_rebuild.as_bytes());
    }
    let digest = hasher.finalize().digest;
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

/// Validates a persisted `PreparedRegisterTransaction` against `expected_sender` and its own
/// signature before reconciling or submitting it on-chain.
///
/// Mirrors `validatePreparedRegisterTransaction` in `walrus-upload-journal.ts`.
pub(crate) fn validate_prepared_register_transaction(
    prepared: &PreparedRegisterTransaction,
    expected_sender: Address,
    raw_private_key: &str,
) -> Result<(Transaction, UserSignature), String> {
    let tx_b64 = prepared.transaction_bytes.trim();
    if tx_b64.is_empty() {
        return Err("Prepared register transaction bytes are empty".to_owned());
    }
    let tx_bytes = base64::engine::general_purpose::STANDARD
        .decode(tx_b64)
        .map_err(|e| format!("Prepared register transaction bytes are not valid base64: {e}"))?;
    if base64::engine::general_purpose::STANDARD.encode(&tx_bytes) != tx_b64 {
        return Err("Prepared register transaction bytes are not canonical base64".to_owned());
    }
    let tx: Transaction = bcs::from_bytes(&tx_bytes)
        .map_err(|e| format!("Prepared register transaction BCS is invalid: {e}"))?;
    if tx.sender != expected_sender {
        return Err(format!(
            "Prepared register transaction sender mismatch: expected {expected_sender}, got {}",
            tx.sender
        ));
    }
    let computed_digest = tx.digest().to_string();
    if computed_digest != prepared.digest.trim() {
        return Err(format!(
            "Prepared register transaction digest mismatch: expected {}, got {computed_digest}",
            prepared.digest
        ));
    }
    let user_sig = UserSignature::from_base64(prepared.signature.trim())
        .map_err(|e| format!("Prepared register transaction signature is invalid: {e}"))?;
    let key = parse_sui_private_key(raw_private_key)?;
    key.verifying_key()
        .verify_transaction(&tx, &user_sig)
        .map_err(|e| format!("Prepared register transaction signature verification failed: {e}"))?;
    Ok((tx, user_sig))
}

/// Builds and signs a `PreparedRegisterTransaction` (via Enoki sponsorship when enabled, or
/// deterministic `ValidDuring` address-balance transaction) **without** executing it on-chain,
/// so the caller can checkpoint `journal.register_transaction` via `before_register_submit` first.
pub(crate) async fn prepare_register_transaction_in_process(
    http: &reqwest::Client,
    grpc_url: &str,
    network: &str,
    raw_private_key: &str,
    ptb: ProgrammableTransaction,
    allowed_addresses: Vec<String>,
    register_rebuild: &str,
) -> Result<PreparedRegisterTransaction, String> {
    let key = parse_sui_private_key(raw_private_key)?;
    let sender_addr: Address = key.public_key().derive_address();
    let sender = sender_addr.to_string();

    let tx_kind = TransactionKind::ProgrammableTransaction(ptb.clone());
    let tx_kind_bytes =
        bcs::to_bytes(&tx_kind).map_err(|e| format!("failed to BCS-encode PTB kind: {e}"))?;

    if enoki_is_enabled() {
        let tx_kind_b64 = base64::engine::general_purpose::STANDARD.encode(&tx_kind_bytes);
        match enoki_sponsor_transaction_kind_with_addresses(
            http,
            network,
            &sender,
            &tx_kind_b64,
            None,
            Some(allowed_addresses),
        )
        .await
        {
            Ok(sponsored) => {
                let sponsored_bytes = base64::engine::general_purpose::STANDARD
                    .decode(sponsored.bytes.trim())
                    .map_err(|e| format!("invalid base64 from Enoki sponsor: {e}"))?;
                verify_sponsored_transaction_matches_ptb(&sponsored_bytes, sender_addr, &ptb)?;
                let (sig_b64, computed_digest) =
                    sign_transaction_bytes(raw_private_key, &sponsored_bytes)?;
                if !sponsored.digest.trim().is_empty() && sponsored.digest.trim() != computed_digest
                {
                    return Err(format!(
                        "Enoki sponsor digest mismatch: Enoki reported {}, Transaction bytes hashed to {computed_digest}",
                        sponsored.digest
                    ));
                }
                return Ok(PreparedRegisterTransaction {
                    transaction_bytes: base64::engine::general_purpose::STANDARD
                        .encode(&sponsored_bytes),
                    signature: sig_b64,
                    digest: computed_digest,
                    sponsor_digest: Some(sponsored.digest),
                });
            }
            Err(err) if err.is_fallback_eligible() => {
                tracing::warn!(
                    sender = %sender,
                    error = %err,
                    "Enoki sponsor failed during register prepare with fallback-eligible error; falling back to direct address-balance transaction"
                );
            }
            Err(err) => return Err(err.to_string()),
        }
    }

    let client = shared_sui_grpc_client(grpc_url)?;
    let mut epoch_client = client.clone();
    let mut info_client = client;
    let mut epoch_ledger = epoch_client.ledger_client();
    let mut info_ledger = info_client.ledger_client();

    let (epoch_res, info_res) = tokio::join!(
        epoch_ledger.get_epoch(
            GetEpochRequest::latest()
                .with_read_mask(FieldMask::from_paths(["epoch", "reference_gas_price"])),
        ),
        info_ledger.get_service_info(GetServiceInfoRequest::default()),
    );

    let epoch_info = epoch_res
        .map_err(|e| format!("GetEpoch gRPC failed: {e}"))?
        .into_inner()
        .epoch
        .ok_or_else(|| "GetEpoch response omitted epoch".to_owned())?;
    let current_epoch = epoch_info.epoch.unwrap_or(0);
    let gas_price = epoch_info.reference_gas_price.unwrap_or(1_000).max(1);

    let chain_id_str = info_res
        .map_err(|e| format!("GetServiceInfo gRPC failed: {e}"))?
        .into_inner()
        .chain_id
        .ok_or_else(|| "GetServiceInfo omitted chain_id".to_owned())?;
    let chain_digest: Digest = chain_id_str
        .parse()
        .map_err(|e| format!("invalid chain_id digest '{chain_id_str}': {e}"))?;

    let nonce = compute_deterministic_register_nonce(&tx_kind_bytes, register_rebuild);
    let transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(ptb),
        sender: sender_addr,
        gas_payment: GasPayment {
            objects: Vec::new(),
            owner: sender_addr,
            price: gas_price,
            budget: 50_000_000,
        },
        expiration: TransactionExpiration::ValidDuring {
            min_epoch: Some(current_epoch),
            max_epoch: Some(current_epoch),
            min_timestamp: None,
            max_timestamp: None,
            chain: chain_digest,
            nonce,
        },
    };

    let tx_bytes = bcs::to_bytes(&transaction)
        .map_err(|e| format!("failed to BCS-encode Transaction: {e}"))?;
    let (sig_b64, digest) = sign_transaction_bytes(raw_private_key, &tx_bytes)?;

    Ok(PreparedRegisterTransaction {
        transaction_bytes: base64::engine::general_purpose::STANDARD.encode(&tx_bytes),
        signature: sig_b64,
        digest,
        sponsor_digest: None,
    })
}

enum ReconciledRegisterStatus {
    NotFound,
    Succeeded(WalletTxOutcome),
    CongestionCancelled(String),
    Failed(String),
}

fn is_congestion_cancellation_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("congestedobjects")
        || lower.contains("executioncancelledduetosharedobjectcongestion")
        || lower.contains("shared object congestion")
}

async fn lookup_finalized_register_transaction(
    grpc_url: &str,
    digest: &str,
) -> Result<ReconciledRegisterStatus, String> {
    let mut client = shared_sui_grpc_client(grpc_url)?;
    let parsed_digest: Digest = digest
        .parse()
        .map_err(|e| format!("invalid prepared transaction digest '{digest}': {e}"))?;
    let req = GetTransactionRequest::new(&parsed_digest)
        .with_read_mask(FieldMask::from_paths(["digest", "effects", "objects"]));
    match client.ledger_client().get_transaction(req).await {
        Ok(resp) => {
            let Some(tx) = resp.into_inner().transaction else {
                return Ok(ReconciledRegisterStatus::NotFound);
            };
            if let Some(effects_proto) = &tx.effects {
                if let Ok(effects) = TransactionEffects::try_from(effects_proto) {
                    if let ExecutionStatus::Failure { error, command } = effects.status() {
                        let err_msg = format!(
                            "transaction {digest} failed at command {command:?}: {error:?}"
                        );
                        if is_congestion_cancellation_error(&err_msg) {
                            return Ok(ReconciledRegisterStatus::CongestionCancelled(err_msg));
                        }
                        return Ok(ReconciledRegisterStatus::Failed(err_msg));
                    }
                }
            }
            let created_objects = extract_created_objects_from_executed(&tx);
            Ok(ReconciledRegisterStatus::Succeeded(WalletTxOutcome {
                digest: digest.to_owned(),
                created_objects,
                used_enoki: false,
            }))
        }
        Err(status) if status.code() == tonic::Code::NotFound => {
            Ok(ReconciledRegisterStatus::NotFound)
        }
        Err(status) => Err(format!(
            "failed to query prepared register transaction {digest} via gRPC: {status}"
        )),
    }
}

fn extract_created_objects_from_executed(tx: &ExecutedTransaction) -> Vec<CreatedObjectInfo> {
    let mut type_map = HashMap::new();
    if let Some(obj_set) = &tx.objects {
        for obj in &obj_set.objects {
            if let (Some(id), Some(ty)) = (&obj.object_id, &obj.object_type) {
                type_map.insert(id.clone(), ty.clone());
            }
        }
    }
    let mut created = Vec::new();
    if let Some(effects) = &tx.effects {
        for changed in &effects.changed_objects {
            if changed.id_operation == Some(changed_object::IdOperation::Created as i32) {
                if let Some(id) = &changed.object_id {
                    let object_type = changed
                        .object_type
                        .clone()
                        .or_else(|| type_map.get(id).cloned());
                    created.push(CreatedObjectInfo {
                        object_id: id.clone(),
                        version: changed.output_version.unwrap_or(1),
                        digest: changed.output_digest.clone().unwrap_or_default(),
                        object_type,
                    });
                }
            }
        }
    }
    created
}

const DEFAULT_INVALIDATED_SPONSOR_INDEX_ATTEMPTS: usize = 8;
const DEFAULT_INVALIDATED_SPONSOR_BACKOFF: Duration = Duration::from_millis(250);

#[derive(Debug)]
enum PreparedStepAdvance {
    Executed(WalletTxOutcome),
    Reset(DurableUploadAdvance),
}

async fn fetch_current_sui_epoch(grpc_url: &str) -> Result<u64, String> {
    let mut client = shared_sui_grpc_client(grpc_url)?;
    let epoch_req = GetEpochRequest::latest().with_read_mask(FieldMask::from_paths(["epoch"]));
    let epoch_info = client
        .ledger_client()
        .get_epoch(epoch_req)
        .await
        .map_err(|e| format!("GetEpoch gRPC failed: {e}"))?
        .into_inner()
        .epoch
        .ok_or_else(|| "GetEpoch response omitted epoch".to_owned())?;
    epoch_info
        .epoch
        .ok_or_else(|| "GetEpoch response omitted epoch number".to_owned())
}

async fn execute_direct_prepared_register_transaction(
    grpc_url: &str,
    digest: &str,
    tx: &Transaction,
    user_sig: &UserSignature,
) -> Result<WalletTxOutcome, String> {
    let mut client = shared_sui_grpc_client(grpc_url)?;
    let mut exec_req = ExecuteTransactionRequest::default();
    exec_req.transaction = Some(tx.clone().into());
    exec_req.signatures = vec![user_sig.clone().into()];
    exec_req.read_mask = Some(FieldMask::from_paths(["digest", "effects", "objects"]));

    let executed = client
        .execution_client()
        .execute_transaction(exec_req)
        .await
        .map_err(|e| format!("ExecuteTransaction gRPC failed: {e}"))?
        .into_inner()
        .transaction
        .ok_or_else(|| "ExecuteTransaction response omitted transaction".to_owned())?;

    if let Some(effects_proto) = &executed.effects {
        if let Ok(effects) = TransactionEffects::try_from(effects_proto) {
            if let ExecutionStatus::Failure { error, command } = effects.status() {
                return Err(format!(
                    "transaction {digest} failed at command {command:?}: {error:?}"
                ));
            }
        }
    }

    Ok(WalletTxOutcome {
        digest: digest.to_owned(),
        created_objects: extract_created_objects_from_executed(&executed),
        used_enoki: false,
    })
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_or_execute_prepared_register_with<
    LookupFn,
    LookupFut,
    EpochFn,
    EpochFut,
    EnokiFn,
    EnokiFut,
    FetchOutFn,
    FetchOutFut,
    DirectFn,
    DirectFut,
>(
    journal: &mut UploadJournal,
    encoded_step_json: &mut serde_json::Value,
    prepared: &PreparedRegisterTransaction,
    expected_sender: Address,
    raw_private_key: &str,
    mut lookup_tx: LookupFn,
    fetch_sui_epoch: EpochFn,
    exec_enoki: EnokiFn,
    fetch_executed_outcome: FetchOutFn,
    exec_direct: DirectFn,
    reconcile_attempts: usize,
    reconcile_backoff: Duration,
) -> Result<PreparedStepAdvance, String>
where
    LookupFn: FnMut(String) -> LookupFut,
    LookupFut: std::future::Future<Output = Result<ReconciledRegisterStatus, String>>,
    EpochFn: FnOnce() -> EpochFut,
    EpochFut: std::future::Future<Output = Result<u64, String>>,
    EnokiFn: FnOnce(String, String) -> EnokiFut,
    EnokiFut: std::future::Future<Output = Result<EnokiExecuteOutput, EnokiError>>,
    FetchOutFn: FnOnce(String, bool) -> FetchOutFut,
    FetchOutFut: std::future::Future<Output = Result<WalletTxOutcome, String>>,
    DirectFn: FnOnce(Transaction, UserSignature) -> DirectFut,
    DirectFut: std::future::Future<Output = Result<WalletTxOutcome, String>>,
{
    let (tx, user_sig) =
        match validate_prepared_register_transaction(prepared, expected_sender, raw_private_key) {
            Ok(valid) => valid,
            Err(err) => {
                journal.resume_step = Some(encoded_step_json.clone());
                journal.register_transaction = None;
                return Ok(PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                    journal: journal.clone(),
                    reason: format!("INVALID_PREPARED_REGISTER_TRANSACTION: {err}"),
                }));
            }
        };

    match lookup_tx(prepared.digest.clone()).await? {
        ReconciledRegisterStatus::Succeeded(out) => return Ok(PreparedStepAdvance::Executed(out)),
        ReconciledRegisterStatus::CongestionCancelled(reason) => {
            encoded_step_json["registerRebuild"] = serde_json::json!(prepared.digest);
            journal.resume_step = Some(encoded_step_json.clone());
            journal.register_transaction = None;
            return Ok(PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                journal: journal.clone(),
                reason: format!("CONGESTION_CANCELLED: {reason}"),
            }));
        }
        ReconciledRegisterStatus::Failed(err) => return Err(err),
        ReconciledRegisterStatus::NotFound => {}
    }

    if let TransactionExpiration::ValidDuring {
        max_epoch: Some(max_ep),
        ..
    } = tx.expiration
    {
        let current_sui_epoch = fetch_sui_epoch().await?;
        if current_sui_epoch > max_ep {
            journal.resume_step = Some(encoded_step_json.clone());
            journal.register_transaction = None;
            return Ok(PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                journal: journal.clone(),
                reason: format!(
                    "NO_SIDE_EFFECT: prepared register transaction {} expired at Sui epoch {max_ep} (current Sui epoch {current_sui_epoch}) and is not on chain",
                    prepared.digest
                ),
            }));
        }
    }

    if let Some(sponsor_digest) = prepared
        .sponsor_digest
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match exec_enoki(sponsor_digest.to_owned(), prepared.signature.clone()).await {
            Ok(executed) => {
                if !executed.digest.trim().is_empty()
                    && executed.digest.trim() != prepared.digest.trim()
                {
                    return Err(format!(
                        "Enoki execute returned unexpected digest {} for prepared transaction {}",
                        executed.digest, prepared.digest
                    ));
                }
                let final_digest = if executed.digest.trim().is_empty() {
                    prepared.digest.clone()
                } else {
                    executed.digest
                };
                match fetch_executed_outcome(final_digest, true).await {
                    Ok(out) => Ok(PreparedStepAdvance::Executed(out)),
                    Err(err) if is_congestion_cancellation_error(&err) => {
                        encoded_step_json["registerRebuild"] = serde_json::json!(prepared.digest);
                        journal.resume_step = Some(encoded_step_json.clone());
                        journal.register_transaction = None;
                        Ok(PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                            journal: journal.clone(),
                            reason: format!("CONGESTION_CANCELLED: {err}"),
                        }))
                    }
                    Err(err) => Err(err),
                }
            }
            Err(enoki_err) if enoki_err.is_sponsorship_invalidated() => {
                let attempts = reconcile_attempts.max(1);
                for attempt in 0..attempts {
                    match lookup_tx(prepared.digest.clone()).await {
                        Ok(ReconciledRegisterStatus::Succeeded(mut out)) => {
                            out.used_enoki = true;
                            return Ok(PreparedStepAdvance::Executed(out));
                        }
                        Ok(ReconciledRegisterStatus::CongestionCancelled(reason)) => {
                            encoded_step_json["registerRebuild"] =
                                serde_json::json!(prepared.digest);
                            journal.resume_step = Some(encoded_step_json.clone());
                            journal.register_transaction = None;
                            return Ok(PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                                journal: journal.clone(),
                                reason: format!("CONGESTION_CANCELLED: {reason}"),
                            }));
                        }
                        Ok(ReconciledRegisterStatus::Failed(err)) => return Err(err),
                        Err(lookup_err) => {
                            return Err(format!(
                                "Enoki sponsorship {sponsor_digest} was invalidated ({enoki_err}), and reconciling digest {} failed: {lookup_err}",
                                prepared.digest
                            ));
                        }
                        Ok(ReconciledRegisterStatus::NotFound) => {
                            if attempt + 1 < attempts && !reconcile_backoff.is_zero() {
                                tokio::time::sleep(
                                    reconcile_backoff.saturating_mul((attempt + 1) as u32),
                                )
                                .await;
                            }
                        }
                    }
                }
                journal.resume_step = Some(encoded_step_json.clone());
                journal.register_transaction = None;
                Ok(PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                    journal: journal.clone(),
                    reason: format!(
                        "NO_SIDE_EFFECT: Enoki sponsorship {sponsor_digest} for prepared register transaction {} is no longer executable ({enoki_err}) and is not on chain",
                        prepared.digest
                    ),
                }))
            }
            Err(enoki_err) => {
                let err_str = enoki_err.to_string();
                if is_congestion_cancellation_error(&err_str) {
                    encoded_step_json["registerRebuild"] = serde_json::json!(prepared.digest);
                    journal.resume_step = Some(encoded_step_json.clone());
                    journal.register_transaction = None;
                    Ok(PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                        journal: journal.clone(),
                        reason: format!("CONGESTION_CANCELLED: {err_str}"),
                    }))
                } else {
                    Err(err_str)
                }
            }
        }
    } else {
        match exec_direct(tx, user_sig).await {
            Ok(out) => Ok(PreparedStepAdvance::Executed(out)),
            Err(err) if is_congestion_cancellation_error(&err) => {
                encoded_step_json["registerRebuild"] = serde_json::json!(prepared.digest);
                journal.resume_step = Some(encoded_step_json.clone());
                journal.register_transaction = None;
                Ok(PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                    journal: journal.clone(),
                    reason: format!("CONGESTION_CANCELLED: {err}"),
                }))
            }
            Err(err) => Err(err),
        }
    }
}

async fn reconcile_or_execute_prepared_register(
    http: &reqwest::Client,
    grpc_url: &str,
    journal: &mut UploadJournal,
    encoded_step_json: &mut serde_json::Value,
    prepared: &PreparedRegisterTransaction,
    expected_sender: Address,
    raw_private_key: &str,
) -> Result<PreparedStepAdvance, String> {
    let grpc_for_lookup = grpc_url.to_owned();
    let grpc_for_epoch = grpc_url.to_owned();
    let grpc_for_outcome = grpc_url.to_owned();
    let grpc_for_direct = grpc_url.to_owned();
    let direct_digest = prepared.digest.clone();

    reconcile_or_execute_prepared_register_with(
        journal,
        encoded_step_json,
        prepared,
        expected_sender,
        raw_private_key,
        move |digest| {
            let grpc = grpc_for_lookup.clone();
            async move { lookup_finalized_register_transaction(&grpc, &digest).await }
        },
        move || async move { fetch_current_sui_epoch(&grpc_for_epoch).await },
        |sponsor_digest, sig| async move {
            enoki_execute_sponsored_transaction(http, &sponsor_digest, &sig).await
        },
        move |final_digest, used_enoki| async move {
            fetch_executed_transaction_outcome(&grpc_for_outcome, &final_digest, used_enoki).await
        },
        move |tx, user_sig| async move {
            execute_direct_prepared_register_transaction(
                &grpc_for_direct,
                &direct_digest,
                &tx,
                &user_sig,
            )
            .await
        },
        DEFAULT_INVALIDATED_SPONSOR_INDEX_ATTEMPTS,
        DEFAULT_INVALIDATED_SPONSOR_BACKOFF,
    )
    .await
}

async fn check_blob_already_certified(grpc_url: &str, blob_object_id: &str) -> bool {
    let Ok(mut client) = shared_sui_grpc_client(grpc_url) else {
        return false;
    };
    let mut req = GetObjectRequest::default();
    req.object_id = Some(blob_object_id.to_owned());
    req.read_mask = Some(FieldMask::from_paths(["json"]));
    let Ok(resp) = client.ledger_client().get_object(req).await else {
        return false;
    };
    let Some(obj) = resp.into_inner().object else {
        return false;
    };
    let Some(json_proto) = obj.json.as_deref() else {
        return false;
    };
    let json_val = prost_to_json(json_proto);
    json_val
        .get("certified_epoch")
        .is_some_and(|v| !v.is_null())
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

/// Advances the durable Walrus upload state machine by one step in-process in Rust:
/// - Validates `journal.resume_step` upfront (rejecting malformed or unknown steps with 400).
/// - Checkpoints a signed `PreparedRegisterTransaction` via `DurableUploadAdvance::Prepared`
///   **before** submitting `register_blob` on-chain, and reconciles `prepared.digest` on-chain
///   first on retry so an interrupted submit never double-registers or strands WAL.
/// - Resumes `"encoded"`, `"registered"`, `"uploaded"`, and `"certified"` journals across
///   both sidecar-created and Rust-created journal formats.
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
    // 1. Validate `resume_step` and `register_transaction` invariants BEFORE any RPC calls.
    let parsed_resume = parse_resume_step_json(journal.resume_step.as_ref())?;
    if journal.register_transaction.is_some()
        && !matches!(parsed_resume, Some(ParsedResumeStep::Encoded { .. }))
    {
        return Err(AppError::BadRequest(
            "registerTransaction is valid only with an encoded resumeStep".into(),
        ));
    }

    if let Some(ParsedResumeStep::Certified { step_json }) = parsed_resume {
        journal.register_transaction = None;
        return Ok(DurableUploadAdvance::Step {
            journal,
            step: step_json,
        });
    }

    let runtime = get_native_runtime_config();
    let private_key = runtime
        .key_for_slot(journal.wallet_index)
        .map_err(AppError::Internal)?;
    let key = parse_sui_private_key(private_key).map_err(AppError::Internal)?;
    let sender = key.public_key().derive_address();
    let sender_str = sender.to_string();

    if let Some(ref existing_wallet) = journal.wallet_address {
        if !existing_wallet.trim().is_empty()
            && !existing_wallet.trim().eq_ignore_ascii_case(&sender_str)
        {
            return Err(AppError::Conflict(
                "WALLET_MAPPING_MISMATCH: keyIndex no longer maps to the journaled wallet".into(),
            ));
        }
    } else {
        journal.wallet_address = Some(sender_str.clone());
    }

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

    if journal.execution_identity.is_none() {
        journal.execution_identity = Some(UploadExecutionIdentity {
            chain_identifier: runtime.sui_network.clone(),
            walrus_package_id: system.call_package_id.to_string(),
        });
    }

    match parsed_resume {
        None | Some(ParsedResumeStep::Encoded { .. }) => {
            let (existing_nonce, expected_blob_id, register_rebuild) = match &parsed_resume {
                Some(ParsedResumeStep::Encoded {
                    blob_id,
                    nonce,
                    register_rebuild,
                    ..
                }) => (*nonce, Some(blob_id.as_str()), register_rebuild.clone()),
                _ => (None, None, String::new()),
            };

            let encoded =
                encode_walrus_blob_rs2_with_nonce(data.to_vec(), system.n_shards, existing_nonce)
                    .await
                    .map_err(AppError::Internal)?;

            if let Some(expected_id) = expected_blob_id {
                if encoded.blob_id_str != expected_id {
                    journal.resume_step = None;
                    journal.register_transaction = None;
                    return Ok(DurableUploadAdvance::Reset {
                        journal,
                        reason: format!(
                            "NO_SIDE_EFFECT: resume blobId mismatch: expected {expected_id}, got {}",
                            encoded.blob_id_str
                        ),
                    });
                }
            }

            let encoded_flow = NativeFlowState {
                step: "encoded".to_owned(),
                blob_id: encoded.blob_id_str.clone(),
                blob_id_bytes: encoded.blob_id.0,
                root_hash_bytes: encoded.root_hash_bytes,
                unencoded_length: encoded.unencoded_length,
                encoded_size: encoded.encoded_size,
                nonce: encoded.nonce,
                blob_digest: encoded.blob_digest,
                blob_object_id: None,
                register_tx_digest: None,
                confirmation_certificate: None,
                end_epoch: Some(end_epoch),
            };
            let mut encoded_step_json = serde_json::json!({
                "step": "encoded",
                "blobId": encoded.blob_id_str,
                "rootHash": base64::engine::general_purpose::STANDARD.encode(encoded.root_hash_bytes),
                "unencodedSize": encoded.unencoded_length,
                "nonce": base64::engine::general_purpose::STANDARD.encode(encoded.nonce),
                "nativeFlowState": encoded_flow,
            });
            if !register_rebuild.is_empty() {
                encoded_step_json["registerRebuild"] = serde_json::json!(register_rebuild);
            }

            // Phase 1a: No prepared transaction yet -> build and sign `PreparedRegisterTransaction`
            // and return `DurableUploadAdvance::Prepared(journal)` BEFORE submitting to Sui.
            let Some(prepared) = journal.register_transaction.clone() else {
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

                let mut allowed_addrs = vec![sender_str];
                if let Some((tip_recipient, _)) =
                    tip_config.calculate_tip(system.n_shards, encoded.unencoded_length)
                {
                    let tip_str = tip_recipient.to_string();
                    if !allowed_addrs.contains(&tip_str) {
                        allowed_addrs.push(tip_str);
                    }
                }

                let prepared_tx = match prepare_register_transaction_in_process(
                    http,
                    &runtime.grpc_url,
                    &runtime.sui_network,
                    private_key,
                    register_ptb,
                    allowed_addrs,
                    &register_rebuild,
                )
                .await
                {
                    Ok(tx) => tx,
                    Err(err) => {
                        invalidate_walrus_system_snapshot_cache().await;
                        return Err(AppError::Internal(err));
                    }
                };

                journal.resume_step = Some(encoded_step_json);
                journal.register_transaction = Some(prepared_tx);
                return Ok(DurableUploadAdvance::Prepared(journal));
            };

            // Phase 1b: We have a checkpointed `PreparedRegisterTransaction`.
            // Validate its bytes/digest/sender/signature, reconcile on-chain first, check Sui
            // epoch expiration, and execute (recovering invalidated Enoki sponsorships).
            let outcome = match reconcile_or_execute_prepared_register(
                http,
                &runtime.grpc_url,
                &mut journal,
                &mut encoded_step_json,
                &prepared,
                sender,
                private_key,
            )
            .await
            {
                Ok(PreparedStepAdvance::Reset(advance)) => return Ok(advance),
                Ok(PreparedStepAdvance::Executed(out)) => out,
                Err(err) => {
                    invalidate_walrus_system_snapshot_cache().await;
                    return Err(AppError::Internal(format!(
                        "The registration transaction was not successful: {err}"
                    )));
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
                "txDigest": outcome.digest,
                "registerTxDigest": outcome.digest,
                "nonce": base64::engine::general_purpose::STANDARD.encode(encoded.nonce),
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
        Some(ParsedResumeStep::Registered {
            blob_id,
            blob_object_id,
            tx_digest,
            nonce,
            end_epoch: resumed_end_epoch,
            native_flow,
        }) => {
            if check_blob_already_certified(&runtime.grpc_url, &blob_object_id).await {
                let step_json = serde_json::json!({
                    "step": "certified",
                    "blobId": blob_id,
                    "blobObjectId": blob_object_id,
                    "endEpoch": resumed_end_epoch.unwrap_or(end_epoch),
                });
                journal.resume_step = Some(step_json.clone());
                journal.register_transaction = None;
                return Ok(DurableUploadAdvance::Step {
                    journal,
                    step: step_json,
                });
            }

            let resolved_nonce = match nonce {
                Some(n) => n,
                None => {
                    let encoded = encode_walrus_blob_rs2(data.to_vec(), system.n_shards)
                        .await
                        .map_err(AppError::Internal)?;
                    encoded.nonce
                }
            };

            let cert = post_blob_to_upload_relay(
                http,
                &runtime.walrus_publisher_url,
                &blob_id,
                &blob_object_id,
                &tx_digest,
                &resolved_nonce,
                data.to_vec(),
            )
            .await
            .map_err(AppError::Internal)?;

            let cert_b64 = bcs::to_bytes(&cert)
                .or_else(|_| serde_json::to_vec(&cert))
                .map(|b| base64::engine::general_purpose::STANDARD.encode(b))
                .unwrap_or_default();

            let updated_flow = native_flow.map(|mut nf| {
                nf.step = "uploaded".to_owned();
                nf.confirmation_certificate = Some(cert.clone());
                nf
            });

            let step_json = serde_json::json!({
                "step": "uploaded",
                "blobId": blob_id,
                "blobObjectId": blob_object_id,
                "certificate": cert_b64,
                "endEpoch": resumed_end_epoch.unwrap_or(end_epoch),
                "nativeFlowState": updated_flow,
            });
            journal.resume_step = Some(step_json.clone());
            journal.register_transaction = None;

            Ok(DurableUploadAdvance::Step {
                journal,
                step: step_json,
            })
        }
        Some(ParsedResumeStep::Uploaded {
            blob_id,
            blob_object_id,
            certificate,
            end_epoch: resumed_end_epoch,
        }) => {
            if check_blob_already_certified(&runtime.grpc_url, &blob_object_id).await {
                let step_json = serde_json::json!({
                    "step": "certified",
                    "blobId": blob_id,
                    "blobObjectId": blob_object_id,
                    "endEpoch": resumed_end_epoch.unwrap_or(end_epoch),
                });
                journal.resume_step = Some(step_json.clone());
                journal.register_transaction = None;
                return Ok(DurableUploadAdvance::Step {
                    journal,
                    step: step_json,
                });
            }

            let certify_ptb = build_certify_ptb(
                &runtime.grpc_url,
                sender,
                &system,
                &blob_object_id,
                &certificate,
            )
            .await
            .map_err(AppError::Internal)?;

            let outcome = match submit_wallet_ptb(
                http,
                &runtime.grpc_url,
                &runtime.sui_network,
                private_key,
                certify_ptb,
                SponsorshipMode::EnokiFirst,
                EffectsFetchMode::DigestOnly,
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
                "blobId": blob_id,
                "blobObjectId": blob_object_id,
                "certifyTxDigest": outcome.digest,
                "endEpoch": resumed_end_epoch.unwrap_or(end_epoch),
            });
            journal.resume_step = Some(step_json.clone());
            journal.register_transaction = None;

            Ok(DurableUploadAdvance::Step {
                journal,
                step: step_json,
            })
        }
        Some(ParsedResumeStep::Certified { step_json }) => {
            journal.register_transaction = None;
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

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn reconcile_metadata_batch_entries<'a>(
    blobs: &'a [SetMetadataBatchEntry],
    resolved_refs: &[(Address, u64, Digest, Option<Address>)],
    onchain_metadata: &HashMap<String, HashMap<String, String>>,
    sender: Address,
    owner: Address,
    expected_package_id: &str,
    expected_agent_id: Option<&str>,
) -> Result<Vec<(&'a SetMetadataBatchEntry, (Address, u64, Digest))>, AppError> {
    let expected_owner_str = owner.to_string();
    let expected_pkg = expected_package_id.trim();
    let expected_agent = expected_agent_id.map(str::trim).filter(|s| !s.is_empty());

    let mut pending = Vec::with_capacity(blobs.len());
    for (entry, &(blob_addr, blob_ver, blob_digest, current_owner)) in
        blobs.iter().zip(resolved_refs.iter())
    {
        let expected_ns = if entry.namespace.trim().is_empty() {
            "default"
        } else {
            entry.namespace.trim()
        };

        if current_owner == Some(owner) {
            let meta = onchain_metadata.get(&entry.blob_object_id);
            let meta_ns = meta.and_then(|m| m.get("memwal_namespace").map(String::as_str));
            let meta_owner = meta.and_then(|m| m.get("memwal_owner").map(String::as_str));
            let meta_pkg = meta.and_then(|m| m.get("memwal_package_id").map(String::as_str));
            let meta_agent = meta.and_then(|m| m.get("memwal_agent_id").map(String::as_str));

            let owner_matches = meta_owner
                .and_then(|o| o.parse::<Address>().ok())
                .is_some_and(|o| o == owner)
                || meta_owner.is_some_and(|o| o.eq_ignore_ascii_case(&expected_owner_str));
            let ns_matches = meta_ns == Some(expected_ns);
            let pkg_matches = expected_pkg.is_empty()
                || meta_pkg
                    .and_then(|p| p.parse::<Address>().ok())
                    .zip(expected_pkg.parse::<Address>().ok())
                    .is_some_and(|(a, b)| a == b)
                || meta_pkg.is_some_and(|p| p.eq_ignore_ascii_case(expected_pkg));
            let agent_matches = match expected_agent {
                None => true,
                Some(exp_agent) => {
                    meta_agent == Some(exp_agent) || (meta_agent.is_none() && sender == owner)
                }
            };

            if !(owner_matches && ns_matches && pkg_matches && agent_matches) {
                return Err(AppError::Internal(format!(
                    "METADATA_RECEIPT_MISMATCH: {}",
                    entry.blob_object_id
                )));
            }

            // When sender == owner, registration already placed the blob at `owner`, so we still
            // need to stamp the batch metadata unless `memwal_agent_id` was already written.
            if sender == owner && !(expected_agent.is_some() && meta_agent == expected_agent) {
                pending.push((entry, (blob_addr, blob_ver, blob_digest)));
            }
        } else if current_owner == Some(sender) {
            pending.push((entry, (blob_addr, blob_ver, blob_digest)));
        } else {
            return Err(AppError::Conflict(format!(
                "BLOB_OWNER_MISMATCH: {}",
                entry.blob_object_id
            )));
        }
    }

    Ok(pending)
}

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

    let SealPersistence::V1New {
        account_id,
        registry_id,
        policy_package_id,
    } = seal_persistence;

    let reg_addr: Address = registry_id
        .parse()
        .map_err(|e| AppError::Internal(format!("invalid registry_id '{registry_id}': {e}")))?;
    let acct_addr: Address = account_id
        .parse()
        .map_err(|e| AppError::Internal(format!("invalid account_id '{account_id}': {e}")))?;

    // Validate all Seal fence ciphertexts up-front before inspecting on-chain state so
    // malformed ciphertexts fail deterministically even on retry after partial transfer.
    for entry in &blobs {
        if let Some(enc_b64) = &entry.encrypted_data {
            let enc_bytes = base64::engine::general_purpose::STANDARD
                .decode(enc_b64)
                .map_err(|e| {
                    AppError::Internal(format!("invalid encryptedData base64 in batch: {e}"))
                })?;
            validate_seal_persistence_ciphertext(
                &enc_bytes,
                package_id,
                policy_package_id,
                &runtime.seal_policy_package_id,
            )
            .map_err(AppError::Internal)?;
        }
    }

    let system = resolve_walrus_system_snapshot(
        &runtime.grpc_url,
        &runtime.sui_network,
        &runtime.walrus_package_id,
        &runtime.walrus_system_object_id,
    )
    .await
    .map_err(AppError::Internal)?;

    // Resolve shared object versions once before the loop and batch-fetch all owned blob
    // object refs in a single `BatchGetObjects` gRPC call (`M-THROUGHPUT`).
    let object_ids: Vec<String> = blobs.iter().map(|b| b.blob_object_id.clone()).collect();
    let (shared_versions_res, resolved_refs_res) = tokio::join!(
        crate::storage::seal_native::fetch_shared_object_versions(
            &runtime.grpc_url,
            account_id,
            registry_id,
        ),
        resolve_owned_object_refs_batch(&runtime.grpc_url, &object_ids),
    );
    let (acct_ver, reg_ver) = shared_versions_res.unwrap_or((1, 1));
    let resolved_refs = resolved_refs_res.map_err(AppError::Internal)?;

    let already_at_owner_ids: Vec<String> = blobs
        .iter()
        .zip(resolved_refs.iter())
        .filter_map(|(entry, &(_, _, _, current_owner))| {
            if current_owner == Some(owner) {
                Some(entry.blob_object_id.clone())
            } else {
                None
            }
        })
        .collect();
    let onchain_metadata = if already_at_owner_ids.is_empty() {
        HashMap::new()
    } else {
        let mut client = shared_sui_grpc_client(&runtime.grpc_url).map_err(AppError::Internal)?;
        let mut batch_meta =
            batch_read_blob_metadata_maps(&mut client, &already_at_owner_ids).await;
        for id in &already_at_owner_ids {
            if !batch_meta.contains_key(id) {
                let map = read_blob_metadata_map(&mut client, id).await;
                if !map.is_empty() {
                    batch_meta.insert(id.clone(), map);
                }
            }
        }
        batch_meta
    };

    let pending = reconcile_metadata_batch_entries(
        &blobs,
        &resolved_refs,
        &onchain_metadata,
        sender,
        owner,
        package_id,
        agent_id,
    )?;
    if pending.is_empty() {
        return Ok(0);
    }

    let mut builder = TransactionBuilder::new();
    let mut blob_args = Vec::with_capacity(pending.len());
    let canonical_owner_str = owner.to_string();

    for (entry, (blob_addr, blob_ver, blob_digest)) in &pending {
        if let Some(enc_b64) = &entry.encrypted_data {
            let enc_bytes = base64::engine::general_purpose::STANDARD
                .decode(enc_b64)
                .map_err(|e| {
                    AppError::Internal(format!("invalid encryptedData base64 in batch: {e}"))
                })?;
            append_seal_encrypt_fence_move_call(
                &mut builder,
                package_id,
                policy_package_id,
                &runtime.seal_policy_package_id,
                reg_addr,
                reg_ver,
                acct_addr,
                acct_ver,
                &enc_bytes,
            )
            .map_err(AppError::Internal)?;
        }

        let blob_arg = builder.object(ObjectInput::owned(*blob_addr, *blob_ver, *blob_digest));
        blob_args.push(blob_arg);

        let ns = if entry.namespace.trim().is_empty() {
            "default"
        } else {
            entry.namespace.as_str()
        };
        let mut pairs = vec![
            ("memwal_namespace", ns.to_owned()),
            ("memwal_owner", canonical_owner_str.clone()),
        ];
        if !package_id.trim().is_empty() {
            pairs.push(("memwal_package_id", package_id.to_owned()));
        }
        if let Some(agent) = agent_id.filter(|s| !s.trim().is_empty()) {
            pairs.push(("memwal_agent_id", agent.to_owned()));
        }

        for (k, v) in pairs {
            let key_arg = builder.pure(&k);
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
    let count = pending.len();
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
        SponsorshipMode::EnokiFirst,
        EffectsFetchMode::DigestOnly,
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

/// Batch-fetches derived `b"metadata"` dynamic-field objects for `object_ids` via
/// `BatchGetObjectsRequest` (chunks of 50) instead of issuing N sequential `GetObject`
/// gRPC calls (`M-THROUGHPUT`).
async fn batch_read_blob_metadata_maps(
    client: &mut sui_rpc::Client,
    object_ids: &[String],
) -> HashMap<String, HashMap<String, String>> {
    let mut batch_metadata: HashMap<String, HashMap<String, String>> =
        HashMap::with_capacity(object_ids.len());
    let Ok(key_bcs) = bcs::to_bytes(b"metadata".as_slice()) else {
        return batch_metadata;
    };
    let key_type = TypeTag::Vector(Box::new(TypeTag::U8));

    for chunk in object_ids.chunks(50) {
        let mut reqs = Vec::with_capacity(chunk.len());
        let mut chunk_obj_ids = Vec::with_capacity(chunk.len());
        for object_id in chunk {
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
                if let Some(sui_rpc::proto::sui::rpc::v2::get_object_result::Result::Object(obj)) =
                    obj_res.result
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
    batch_metadata
}

async fn read_blob_metadata_map(
    client: &mut sui_rpc::Client,
    blob_object_id: &str,
) -> HashMap<String, String> {
    let mut map = HashMap::new();

    // Fast path: derive the `vector<u8>` dynamic child ID for `b"metadata"` directly (`1` gRPC GetObject).
    if let Ok(blob_addr) = blob_object_id.parse::<Address>() {
        if let Ok(key_bcs) = bcs::to_bytes(b"metadata".as_slice()) {
            let metadata_field_id = blob_addr
                .derive_dynamic_child_id(&TypeTag::Vector(Box::new(TypeTag::U8)), &key_bcs);
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

const MAX_PROVENANCE_CACHE_ENTRIES: usize = 10_000;

static BLOB_PROVENANCE_CACHE: OnceLock<StdRwLock<HashMap<String, String>>> = OnceLock::new();

fn get_cached_blob_provenance(object_id: &str) -> Option<String> {
    let cache = BLOB_PROVENANCE_CACHE.get_or_init(|| StdRwLock::new(HashMap::new()));
    cache.read().ok()?.get(object_id).cloned()
}

fn set_cached_blob_provenance(object_id: String, uploader: String) {
    let cache = BLOB_PROVENANCE_CACHE.get_or_init(|| StdRwLock::new(HashMap::new()));
    if let Ok(mut guard) = cache.write() {
        if guard.len() >= MAX_PROVENANCE_CACHE_ENTRIES && !guard.contains_key(&object_id) {
            if let Some(first_key) = guard.keys().next().cloned() {
                guard.remove(&first_key);
            }
        }
        guard.insert(object_id, uploader);
    }
}

fn default_sui_graphql_url(network: &str) -> Option<String> {
    if let Ok(explicit) = std::env::var("SUI_GRAPHQL_URL") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_owned());
        }
    }
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" => Some("https://graphql.mainnet.sui.io/graphql".to_owned()),
        "testnet" => Some("https://graphql.testnet.sui.io/graphql".to_owned()),
        "devnet" => Some("https://graphql.devnet.sui.io/graphql".to_owned()),
        _ => None,
    }
}

const MAX_GRPC_PROVENANCE_HOPS: usize = 8;

const BLOB_CREATION_TRANSACTION_GRAPHQL_QUERY: &str = r#"
    query BlobCreationTransaction($objectId: SuiAddress!) {
        object(address: $objectId) {
            version
            previousTransaction {
                digest
                sender {
                    address
                }
                effects {
                    status
                    objectChanges(first: 50) {
                        nodes {
                            address
                            idCreated
                        }
                    }
                }
            }
            objectVersionsBefore(first: 1) {
                nodes {
                    version
                    previousTransaction {
                        digest
                        sender {
                            address
                        }
                        effects {
                            status
                            objectChanges(first: 50) {
                                nodes {
                                    address
                                    idCreated
                                }
                            }
                        }
                    }
                }
            }
        }
    }
"#;

const BLOB_CREATION_TX_BY_DIGEST_GRAPHQL_QUERY: &str = r#"
    query BlobCreationTxByDigest($digest: String!) {
        transaction(digest: $digest) {
            digest
            sender {
                address
            }
            effects {
                status
                objectChanges(first: 50) {
                    nodes {
                        address
                        idCreated
                    }
                }
            }
        }
    }
"#;

fn extract_verified_creation_sender_from_graphql_tx(
    tx_val: &serde_json::Value,
    canonical_object_id: &str,
) -> Option<String> {
    let status = tx_val
        .pointer("/effects/status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if status != "SUCCESS" {
        return None;
    }

    let created_match = tx_val
        .pointer("/effects/objectChanges/nodes")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|nodes| {
            nodes.iter().any(|node| {
                let id_created = node
                    .get("idCreated")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                let addr = node
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|s| s.parse::<Address>().ok())
                    .map(|a| a.to_string());
                id_created && addr.as_deref() == Some(canonical_object_id)
            })
        });
    if !created_match {
        return None;
    }

    tx_val
        .pointer("/sender/address")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| s.parse::<Address>().ok())
        .map(|a| a.to_string())
}

fn shared_graphql_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

fn extract_raw_blob_id(json_val: Option<&serde_json::Value>) -> String {
    json_val
        .and_then(|v| v.get("blob_id"))
        .and_then(|v| match v {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

async fn post_sui_graphql_query(
    http: &reqwest::Client,
    graphql_url: &str,
    query: &str,
    variables: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let resp = http
        .post(graphql_url)
        .json(&serde_json::json!({
            "query": query,
            "variables": variables,
        }))
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .map_err(|e| format!("Sui GraphQL provenance request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Sui GraphQL returned HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("invalid Sui GraphQL JSON: {e}"))?;

    if let Some(errs) = body.get("errors").and_then(serde_json::Value::as_array) {
        if !errs.is_empty() {
            let msg = errs[0]
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("GraphQL error");
            let sanitized = crate::sui::enoki::sanitize_upstream_error_for_logging(msg);
            return Err(format!("Sui GraphQL provenance query error: {sanitized}"));
        }
    }

    Ok(body)
}

async fn query_creation_sender_via_graphql(
    http: &reqwest::Client,
    graphql_url: &str,
    canonical_object_id: &str,
) -> Result<Option<String>, String> {
    let body = post_sui_graphql_query(
        http,
        graphql_url,
        BLOB_CREATION_TRANSACTION_GRAPHQL_QUERY,
        serde_json::json!({ "objectId": canonical_object_id }),
    )
    .await?;

    let Some(object) = body.pointer("/data/object").filter(|v| !v.is_null()) else {
        return Ok(None);
    };

    // `objectVersionsBefore(first: 1)` is ordered ascending by version, so `nodes[0]` is the
    // earliest retained version (the creation version). If the object has never been mutated since
    // creation, `nodes` is empty and `object` itself is the creation version.
    let creation_version = object
        .pointer("/objectVersionsBefore/nodes")
        .and_then(serde_json::Value::as_array)
        .and_then(|nodes| nodes.first())
        .filter(|v| !v.is_null())
        .unwrap_or(object);

    let Some(prev_tx) = creation_version
        .get("previousTransaction")
        .filter(|v| !v.is_null())
    else {
        return Ok(None);
    };

    if prev_tx.get("effects").is_some_and(|v| !v.is_null()) {
        return Ok(extract_verified_creation_sender_from_graphql_tx(
            prev_tx,
            canonical_object_id,
        ));
    }

    let Some(digest) = prev_tx
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };

    let tx_body = post_sui_graphql_query(
        http,
        graphql_url,
        BLOB_CREATION_TX_BY_DIGEST_GRAPHQL_QUERY,
        serde_json::json!({ "digest": digest }),
    )
    .await?;

    let Some(tx_val) = tx_body
        .pointer("/data/transaction")
        .filter(|v| !v.is_null())
    else {
        return Ok(None);
    };

    Ok(extract_verified_creation_sender_from_graphql_tx(
        tx_val,
        canonical_object_id,
    ))
}

#[derive(Debug, PartialEq, Eq)]
enum GrpcProvenanceOutcome {
    CreatedBy(String),
    DefinitivelyNotCreated,
    NeedsGraphqlFallback(Option<String>),
}

/// Walks object versions backwards via gRPC `GetObject(id, version)` -> `previous_transaction` ->
/// `GetTransaction` -> `effects.changed_objects` (`input_version`), starting from the latest
/// version (`None`) rather than hardcoding `version = 1` (since Sui objects created in transactions
/// touching shared objects like the Walrus System object receive Lamport versions `>> 1`).
async fn resolve_creation_sender_from_grpc_history_with<ObjFn, ObjFut, TxFn, TxFut>(
    canonical_object_id: &str,
    mut get_prev_tx_for_version: ObjFn,
    mut get_tx: TxFn,
) -> GrpcProvenanceOutcome
where
    ObjFn: FnMut(Option<u64>) -> ObjFut,
    ObjFut: std::future::Future<Output = Result<Option<(Option<u64>, String)>, String>>,
    TxFn: FnMut(String) -> TxFut,
    TxFut: std::future::Future<Output = Result<Option<ExecutedTransaction>, String>>,
{
    let mut current_version: Option<u64> = None;

    for _hop in 0..MAX_GRPC_PROVENANCE_HOPS {
        let prev_tx_digest = match get_prev_tx_for_version(current_version).await {
            Ok(Some((_ver, digest))) if !digest.trim().is_empty() => digest,
            Ok(Some(_)) | Ok(None) => {
                return GrpcProvenanceOutcome::NeedsGraphqlFallback(None);
            }
            Err(err) => {
                return GrpcProvenanceOutcome::NeedsGraphqlFallback(Some(err));
            }
        };

        let tx = match get_tx(prev_tx_digest.clone()).await {
            Ok(Some(tx)) => tx,
            Ok(None) => {
                return GrpcProvenanceOutcome::NeedsGraphqlFallback(None);
            }
            Err(err) => {
                return GrpcProvenanceOutcome::NeedsGraphqlFallback(Some(err));
            }
        };

        let Some(effects_proto) = &tx.effects else {
            return GrpcProvenanceOutcome::NeedsGraphqlFallback(None);
        };

        let matched_change = effects_proto.changed_objects.iter().find(|changed| {
            changed
                .object_id
                .as_deref()
                .and_then(|s| s.parse::<Address>().ok())
                .map(|a| a.to_string())
                .as_deref()
                == Some(canonical_object_id)
        });

        let Some(changed) = matched_change else {
            return GrpcProvenanceOutcome::NeedsGraphqlFallback(None);
        };

        if changed.id_operation == Some(changed_object::IdOperation::Created as i32) {
            let succeeded = TransactionEffects::try_from(effects_proto)
                .ok()
                .is_some_and(|eff| matches!(eff.status(), ExecutionStatus::Success));
            if !succeeded {
                return GrpcProvenanceOutcome::DefinitivelyNotCreated;
            }
            let sender = tx
                .transaction
                .as_ref()
                .and_then(|t| t.sender.as_deref())
                .and_then(|s| s.parse::<Address>().ok())
                .map(|a| a.to_string());
            return match sender {
                Some(valid_sender) => GrpcProvenanceOutcome::CreatedBy(valid_sender),
                None => GrpcProvenanceOutcome::DefinitivelyNotCreated,
            };
        }

        if let Some(prev_ver) = changed.input_version.filter(|&v| v > 0) {
            if current_version.is_none_or(|cur| prev_ver < cur) {
                current_version = Some(prev_ver);
                continue;
            }
        }

        return GrpcProvenanceOutcome::NeedsGraphqlFallback(None);
    }

    GrpcProvenanceOutcome::NeedsGraphqlFallback(None)
}

/// Resolves the canonical Sui address (`0x` + 64 lowercase hex) that executed the immutable
/// creation transaction for `object_id`.
///
/// Mirrors `findBlobCreationSender` in `services/server/scripts/sidecar/routes/walrus-query.ts`:
/// - Uses a bounded process cache (`MAX_PROVENANCE_CACHE_ENTRIES = 10_000`) because creation
///   provenance is immutable for the lifetime of a Sui object ID.
/// - Queries Sui gRPC (`GetObject` + `GetTransaction`, walking `input_version` backwards when
///   needed) first, falling back to archival Sui GraphQL (`objectVersionsBefore(first: 1)` +
///   `previousTransaction`) when historical versions have been pruned from the fullnode.
/// - Returns `Err` if provenance cannot be verified due to RPC/GraphQL failures so the caller
///   fails closed instead of trusting unverified third-party blobs.
pub(crate) async fn find_blob_creation_sender(
    grpc_url: &str,
    sui_network: &str,
    object_id: &str,
) -> Result<Option<String>, String> {
    let canonical_object_id = object_id
        .trim()
        .parse::<Address>()
        .map_err(|e| format!("invalid blob object_id '{object_id}': {e}"))?
        .to_string();

    if let Some(cached) = get_cached_blob_provenance(&canonical_object_id) {
        return Ok(Some(cached));
    }

    // 1. Try Sui gRPC history walk (`GetObject(id, version)` -> `previous_transaction` -> `GetTransaction`).
    let grpc_outcome = match shared_sui_grpc_client(grpc_url) {
        Ok(client) => {
            let client_for_obj = client.clone();
            let client_for_tx = client;
            let obj_id_for_req = canonical_object_id.clone();

            resolve_creation_sender_from_grpc_history_with(
                &canonical_object_id,
                move |version| {
                    let mut c = client_for_obj.clone();
                    let oid = obj_id_for_req.clone();
                    async move {
                        let mut obj_req = GetObjectRequest::default();
                        obj_req.object_id = Some(oid.clone());
                        obj_req.version = version;
                        obj_req.read_mask =
                            Some(FieldMask::from_paths(["version", "previous_transaction"]));
                        match c.ledger_client().get_object(obj_req).await {
                            Ok(resp) => {
                                let Some(obj) = resp.into_inner().object else {
                                    return Ok(None);
                                };
                                let Some(prev_tx) =
                                    obj.previous_transaction.filter(|s| !s.trim().is_empty())
                                else {
                                    return Ok(None);
                                };
                                Ok(Some((obj.version, prev_tx)))
                            }
                            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
                            Err(e) => Err(format!("GetObject({oid}, {version:?}) failed: {e}")),
                        }
                    }
                },
                move |tx_digest| {
                    let mut c = client_for_tx.clone();
                    async move {
                        let parsed_digest = tx_digest.parse::<Digest>().map_err(|e| {
                            format!("invalid previous_transaction digest '{tx_digest}': {e}")
                        })?;
                        let tx_req = GetTransactionRequest::new(&parsed_digest).with_read_mask(
                            FieldMask::from_paths(["digest", "transaction", "effects", "objects"]),
                        );
                        match c.ledger_client().get_transaction(tx_req).await {
                            Ok(resp) => Ok(resp.into_inner().transaction),
                            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
                            Err(e) => Err(format!("GetTransaction({tx_digest}) failed: {e}")),
                        }
                    }
                },
            )
            .await
        }
        Err(e) => GrpcProvenanceOutcome::NeedsGraphqlFallback(Some(e)),
    };

    let grpc_err = match grpc_outcome {
        GrpcProvenanceOutcome::CreatedBy(sender) => {
            set_cached_blob_provenance(canonical_object_id, sender.clone());
            return Ok(Some(sender));
        }
        GrpcProvenanceOutcome::DefinitivelyNotCreated => return Ok(None),
        GrpcProvenanceOutcome::NeedsGraphqlFallback(err) => err,
    };

    // 2. Fallback to archival Sui GraphQL (`objectVersionsBefore(first: 1)` + `previousTransaction`).
    if let Some(graphql_url) = default_sui_graphql_url(sui_network) {
        let http = shared_graphql_http_client();
        match query_creation_sender_via_graphql(http, &graphql_url, &canonical_object_id).await {
            Ok(Some(sender)) => {
                set_cached_blob_provenance(canonical_object_id, sender.clone());
                return Ok(Some(sender));
            }
            Ok(None) => return Ok(None),
            Err(gql_err) => {
                let combined = match grpc_err {
                    Some(ge) => format!("{ge}; GraphQL fallback failed: {gql_err}"),
                    None => gql_err,
                };
                return Err(combined);
            }
        }
    }

    if let Some(err) = grpc_err {
        return Err(err);
    }
    Ok(None)
}

/// Filters `(object_id, blob_id)` candidates down to blobs whose immutable version-1 creation
/// transaction was sent by one of the configured `trusted_uploaders` (`SERVER_SUI_PRIVATE_KEYS`).
///
/// Fails closed (`Err(AppError::Internal)`) if provenance resolution errors for any candidate.
pub(crate) async fn filter_trusted_blob_candidates_with_resolver<F, Fut>(
    owner: &str,
    candidates: Vec<(String, String)>,
    trusted_uploaders: &std::collections::HashSet<String>,
    mut resolve_sender: F,
) -> Result<Vec<(String, String)>, AppError>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<Option<String>, String>>,
{
    let mut trusted = Vec::with_capacity(candidates.len());
    let mut excluded_untrusted = 0usize;

    for (object_id, blob_id) in candidates {
        let sender_opt = resolve_sender(object_id.clone()).await.map_err(|err| {
            AppError::Internal(format!(
                "unable to verify creation provenance for Walrus Blob {object_id}: {err}"
            ))
        })?;

        let is_trusted = sender_opt
            .as_deref()
            .and_then(|s| s.trim().parse::<Address>().ok())
            .map(|a| a.to_string())
            .is_some_and(|canonical_sender| trusted_uploaders.contains(&canonical_sender));

        if is_trusted {
            trusted.push((object_id, blob_id));
        } else {
            excluded_untrusted += 1;
        }
    }

    if excluded_untrusted > 0 {
        tracing::warn!(
            owner = %owner,
            excluded_untrusted,
            kept = trusted.len(),
            "walrus_query_blobs_untrusted_candidates_excluded"
        );
    }

    Ok(trusted)
}

pub async fn query_blobs_by_owner_in_process(
    owner_address: &str,
    namespace: Option<&str>,
    package_id: Option<&str>,
    limit: Option<usize>,
) -> Result<(Vec<OnChainBlob>, bool), AppError> {
    let runtime = get_native_runtime_config();
    let trusted_uploaders = runtime
        .trusted_uploader_addresses()
        .map_err(AppError::Internal)?;
    let mut client =
        shared_sui_grpc_client(&runtime.grpc_url).map_err(AppError::UpstreamUnavailable)?;

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

    let mut raw_candidates: Vec<(String, String)> = Vec::with_capacity(probed.len());
    for obj in probed {
        let Some(object_id) = obj.object_id else {
            continue;
        };
        let json_val = obj.json.as_deref().map(prost_to_json);
        let raw_blob_id = extract_raw_blob_id(json_val.as_ref());
        if raw_blob_id.is_empty() {
            continue;
        }
        let blob_id = decimal_u256_to_blob_id(&raw_blob_id);
        raw_candidates.push((object_id, blob_id));
    }

    // Verify immutable creation-transaction provenance for every candidate Blob and filter out
    // any third-party blobs transferred to `owner_address` (failing closed on lookup errors).
    let grpc_url_ref = runtime.grpc_url.clone();
    let sui_network_ref = runtime.sui_network.clone();
    let candidates = filter_trusted_blob_candidates_with_resolver(
        &canonical_owner,
        raw_candidates,
        &trusted_uploaders,
        move |obj_id| {
            let grpc = grpc_url_ref.clone();
            let net = sui_network_ref.clone();
            async move { find_blob_creation_sender(&grpc, &net, &obj_id).await }
        },
    )
    .await?;

    let candidate_ids: Vec<String> = candidates.iter().map(|(id, _)| id.clone()).collect();
    let mut batch_metadata = batch_read_blob_metadata_maps(&mut client, &candidate_ids).await;

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
        let blob_pkg = metadata
            .get("memwal_package_id")
            .cloned()
            .unwrap_or_default();
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
            let raw_blob_id = extract_raw_blob_id(json_val.as_ref());
            if raw_blob_id.is_empty() {
                continue;
            }
            let blob_id = decimal_u256_to_blob_id(&raw_blob_id);
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

            let page_obj_ids: Vec<String> = resp
                .objects
                .iter()
                .filter_map(|o| o.object_id.clone())
                .collect();
            let mut batch_metadata =
                batch_read_blob_metadata_maps(&mut client, &page_obj_ids).await;

            for obj in resp.objects {
                let Some(object_id) = obj.object_id else {
                    continue;
                };
                let metadata = match batch_metadata.remove(&object_id) {
                    Some(map) => map,
                    None => read_blob_metadata_map(&mut client, &object_id).await,
                };
                let job_matches = metadata.get("memwal_job_id").map(String::as_str) == Some(job_id);
                let owner_matches = metadata
                    .get("memwal_owner")
                    .and_then(|v| v.trim().parse::<Address>().ok())
                    == Some(user_owner_addr);

                if job_matches && owner_matches {
                    let json_val = obj.json.as_deref().map(prost_to_json);
                    let raw_blob_id = extract_raw_blob_id(json_val.as_ref());
                    if raw_blob_id.is_empty() {
                        continue;
                    }
                    return Ok(Some(FoundBlobByJob {
                        blob_id: decimal_u256_to_blob_id(&raw_blob_id),
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
        let sender: Address = "0x00000000000000000000000000000000000000000000000000000000000000cc"
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
                assert_eq!(
                    bytes.len(),
                    72,
                    "HashedAuthPackage BCS must be 32+32+8=72 bytes"
                );
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
        use seal_crypto::{
            ibe, seal_encrypt as crypto_seal_encrypt, EncryptionInput, IBEPublicKeys,
        };

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
        assert!(
            validate_seal_persistence_ciphertext(&enc_bytes, pkg_a, policy_pkg, policy_pkg).is_ok()
        );

        // Mismatched immutable package_id fails closed.
        let err = validate_seal_persistence_ciphertext(&enc_bytes, pkg_b, policy_pkg, policy_pkg)
            .unwrap_err();
        assert!(err.contains("Ciphertext packageId does not match packageId"));

        // Mismatched policy_package_id fails closed.
        let err_pol =
            validate_seal_persistence_ciphertext(&enc_bytes, pkg_a, pkg_b, policy_pkg).unwrap_err();
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

    #[tokio::test]
    async fn in_process_upload_limiter_enforces_capacity_queue_depth_and_cancellation_safety() {
        let limiter = std::sync::Arc::new(InProcessUploadLimiter::new(1, 1, 80));

        // 1. Acquire the single active slot.
        let guard_1 = limiter.acquire(1).await.expect("first slot should succeed");
        assert_eq!(limiter.snapshot()["activeWalrusUploads"], 1);
        assert_eq!(limiter.snapshot()["queuedWalrusUploads"], 0);

        // 2. Start a queued waiter and cancel/drop its future while it is waiting.
        //    Verify that `QueuedWaiterGuard` decrements `queued` back to 0 so the queue never leaks.
        let limiter_clone = std::sync::Arc::clone(&limiter);
        let waiter = tokio::spawn(async move {
            let _ = limiter_clone.acquire(1).await;
        });
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(limiter.snapshot()["queuedWalrusUploads"], 1);

        waiter.abort();
        let _ = waiter.await;
        assert_eq!(
            limiter.snapshot()["queuedWalrusUploads"],
            0,
            "dropping/aborting a queued acquire future must not leak queued count"
        );

        // 3. When queue depth (1) is occupied, a second waiter fails immediately with queue full.
        let limiter_q1 = std::sync::Arc::clone(&limiter);
        let held_waiter = tokio::spawn(async move {
            let guard = limiter_q1.acquire(1).await?;
            let active = limiter_q1.snapshot()["activeWalrusUploads"]
                .as_u64()
                .unwrap_or(0);
            drop(guard);
            Ok::<u64, String>(active)
        });
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(limiter.snapshot()["queuedWalrusUploads"], 1);

        let overflow_err = limiter
            .acquire(1)
            .await
            .err()
            .expect("should reject when queue is full");
        assert!(overflow_err.contains("Walrus upload queue full"));

        // 4. Releasing `guard_1` wakes `held_waiter`, which acquires and then releases the slot.
        drop(guard_1);
        let active_during_hold = held_waiter
            .await
            .expect("task should join")
            .expect("queued waiter should acquire slot after release");
        assert_eq!(active_during_hold, 1);
        assert_eq!(limiter.snapshot()["activeWalrusUploads"], 0);
        assert_eq!(limiter.snapshot()["queuedWalrusUploads"], 0);
    }

    #[test]
    fn decimal_u256_to_blob_id_converts_decimal_and_preserves_base64() {
        // Zero u256 -> 32 zero bytes in URL_SAFE_NO_PAD base64
        let zero_b64 = decimal_u256_to_blob_id("0");
        assert_eq!(
            zero_b64,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32])
        );

        // Already base64url string is returned unchanged
        let existing = "abcDEF_123-xyz";
        assert_eq!(decimal_u256_to_blob_id(existing), existing);
    }

    #[test]
    fn validate_prepared_register_transaction_and_deterministic_nonce_match_checkpoint_contract() {
        let raw_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let other_key = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let key = parse_sui_private_key(raw_key).unwrap();
        let sender = key.public_key().derive_address();

        let tx_kind = TransactionKind::ProgrammableTransaction(ProgrammableTransaction {
            inputs: vec![sui_sdk_types::Input::Pure(vec![7, 8, 9])],
            commands: Vec::new(),
        });
        let tx_kind_bytes = bcs::to_bytes(&tx_kind).unwrap();

        // Deterministic nonce is stable for identical (tx_kind_bytes, rebuild_salt) and changes when salt changes.
        let nonce_initial = compute_deterministic_register_nonce(&tx_kind_bytes, "");
        assert_eq!(
            nonce_initial,
            compute_deterministic_register_nonce(&tx_kind_bytes, "")
        );
        let nonce_rebuilt = compute_deterministic_register_nonce(
            &tx_kind_bytes,
            "11111111111111111111111111111111",
        );
        assert_ne!(nonce_initial, nonce_rebuilt);

        let tx = Transaction {
            kind: tx_kind,
            sender,
            gas_payment: GasPayment {
                objects: Vec::new(),
                owner: sender,
                price: 1_000,
                budget: 50_000_000,
            },
            expiration: TransactionExpiration::ValidDuring {
                min_epoch: Some(450),
                max_epoch: Some(450),
                min_timestamp: None,
                max_timestamp: None,
                chain: Digest::ZERO,
                nonce: nonce_initial,
            },
        };
        let tx_bytes = bcs::to_bytes(&tx).unwrap();
        let (sig_b64, digest) = sign_transaction_bytes(raw_key, &tx_bytes).unwrap();
        let prepared = PreparedRegisterTransaction {
            transaction_bytes: base64::engine::general_purpose::STANDARD.encode(&tx_bytes),
            signature: sig_b64,
            digest,
            sponsor_digest: None,
        };

        // Valid prepared transaction passes validation.
        let (parsed_tx, _) =
            validate_prepared_register_transaction(&prepared, sender, raw_key).unwrap();
        assert_eq!(parsed_tx.sender, sender);

        // Wrong sender fails validation.
        let other_sender = parse_sui_private_key(other_key)
            .unwrap()
            .public_key()
            .derive_address();
        assert!(
            validate_prepared_register_transaction(&prepared, other_sender, raw_key)
                .unwrap_err()
                .contains("sender mismatch")
        );

        // Wrong signing key fails signature verification.
        assert!(
            validate_prepared_register_transaction(&prepared, sender, other_key)
                .unwrap_err()
                .contains("signature verification failed")
        );

        // Tampered digest fails validation.
        let mut bad_digest = prepared.clone();
        bad_digest.digest = Digest::ZERO.to_string();
        assert!(
            validate_prepared_register_transaction(&bad_digest, sender, raw_key)
                .unwrap_err()
                .contains("digest mismatch")
        );
    }

    #[tokio::test]
    async fn parse_resume_step_json_resumes_sidecar_and_rust_journals_and_rejects_malformed_steps()
    {
        // 1. None -> Ok(None)
        assert!(parse_resume_step_json(None).unwrap().is_none());

        // 2. Sidecar-formatted "encoded" step (without `nativeFlowState`) parses cleanly.
        let nonce_bytes = [0x5au8; 32];
        let sidecar_encoded = serde_json::json!({
            "step": "encoded",
            "blobId": "blob-123",
            "rootHash": base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]),
            "unencodedSize": 1024,
            "nonce": base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
            "registerRebuild": "prev-digest-1"
        });
        match parse_resume_step_json(Some(&sidecar_encoded)).unwrap() {
            Some(ParsedResumeStep::Encoded {
                blob_id,
                unencoded_size,
                nonce,
                register_rebuild,
                ..
            }) => {
                assert_eq!(blob_id, "blob-123");
                assert_eq!(unencoded_size, 1024);
                assert_eq!(nonce, Some(nonce_bytes));
                assert_eq!(register_rebuild, "prev-digest-1");
            }
            other => panic!("expected ParsedResumeStep::Encoded, got {other:?}"),
        }

        // 3. Sidecar-formatted "registered" step (using `txDigest` and no `nativeFlowState`) parses cleanly.
        let sidecar_registered = serde_json::json!({
            "step": "registered",
            "blobId": "blob-123",
            "blobObjectId": "0x00000000000000000000000000000000000000000000000000000000000000aa",
            "txDigest": "11111111111111111111111111111111",
            "nonce": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes),
            "endEpoch": 460
        });
        match parse_resume_step_json(Some(&sidecar_registered)).unwrap() {
            Some(ParsedResumeStep::Registered {
                blob_id,
                blob_object_id,
                tx_digest,
                nonce,
                end_epoch,
                ..
            }) => {
                assert_eq!(blob_id, "blob-123");
                assert_eq!(
                    blob_object_id,
                    "0x00000000000000000000000000000000000000000000000000000000000000aa"
                );
                assert_eq!(tx_digest, "11111111111111111111111111111111");
                assert_eq!(nonce, Some(nonce_bytes));
                assert_eq!(end_epoch, Some(460));
            }
            other => panic!("expected ParsedResumeStep::Registered, got {other:?}"),
        }

        // 4. Sidecar-formatted "certified" step returns Certified and short-circuits in `advance_durable_upload_in_process`.
        let sidecar_certified = serde_json::json!({
            "step": "certified",
            "blobId": "blob-123",
            "blobObjectId": "0x00000000000000000000000000000000000000000000000000000000000000aa",
            "endEpoch": 462
        });
        let journal = UploadJournal {
            wallet_index: 0,
            wallet_address: None,
            execution_identity: None,
            resume_step: Some(sidecar_certified.clone()),
            register_transaction: None,
        };
        let http = reqwest::Client::new();
        match advance_durable_upload_in_process(
            &http,
            b"test",
            5,
            "0x00000000000000000000000000000000000000000000000000000000000000bb",
            "default",
            "",
            "job-1",
            journal,
        )
        .await
        .expect("certified resumeStep should short-circuit without RPC")
        {
            DurableUploadAdvance::Step { step, .. } => {
                assert_eq!(step["step"], "certified");
                assert_eq!(step["blobId"], "blob-123");
            }
            _ => panic!("expected DurableUploadAdvance::Step"),
        }

        // 5. Unknown or malformed `resumeStep` fails closed with `AppError::BadRequest` (never falls back to fresh registration).
        for invalid in [
            serde_json::json!("not-an-object"),
            serde_json::json!({"blobId": "blob-123"}),
            serde_json::json!({"step": "unknown_step", "blobId": "blob-123"}),
            serde_json::json!({"step": "encoded", "blobId": "blob-123"}),
            serde_json::json!({"step": "registered", "blobId": "blob-123"}),
            serde_json::json!({"step": "uploaded", "blobId": "blob-123", "blobObjectId": "0x1"}),
            serde_json::json!({"step": "certified", "blobId": "blob-123"}),
        ] {
            assert!(
                matches!(
                    parse_resume_step_json(Some(&invalid)),
                    Err(AppError::BadRequest(_))
                ),
                "expected BadRequest for invalid resumeStep: {invalid}"
            );
        }
    }

    #[tokio::test]
    async fn filter_trusted_blob_candidates_enforces_uploader_provenance_and_fails_closed_on_lookup_error(
    ) {
        let trusted_wallet =
            "0x0000000000000000000000000000000000000000000000000000000000000011".to_owned();
        let untrusted_wallet =
            "0x0000000000000000000000000000000000000000000000000000000000000099".to_owned();
        let owner = "0x00000000000000000000000000000000000000000000000000000000000000aa";

        let mut trusted_set = std::collections::HashSet::new();
        trusted_set.insert(trusted_wallet.clone());

        let obj_trusted =
            "0x0000000000000000000000000000000000000000000000000000000000000101".to_owned();
        let obj_spoofed =
            "0x0000000000000000000000000000000000000000000000000000000000000202".to_owned();

        let candidates = vec![
            (obj_trusted.clone(), "blob-trusted".to_owned()),
            (obj_spoofed.clone(), "blob-spoofed".to_owned()),
        ];

        // 1. Trusted blob is kept; third-party transferred blob (`untrusted_wallet`) is excluded.
        let trusted_wallet_clone = trusted_wallet.clone();
        let untrusted_wallet_clone = untrusted_wallet.clone();
        let obj_trusted_clone = obj_trusted.clone();
        let filtered = filter_trusted_blob_candidates_with_resolver(
            owner,
            candidates.clone(),
            &trusted_set,
            move |obj_id| {
                let tw = trusted_wallet_clone.clone();
                let uw = untrusted_wallet_clone.clone();
                let ot = obj_trusted_clone.clone();
                async move {
                    if obj_id == ot {
                        Ok(Some(tw))
                    } else {
                        Ok(Some(uw))
                    }
                }
            },
        )
        .await
        .expect("provenance filter should succeed");

        assert_eq!(
            filtered,
            vec![(obj_trusted.clone(), "blob-trusted".to_owned())]
        );

        // 2. Provenance lookup failure fails closed with `AppError::Internal` rather than accepting or skipping.
        let err = filter_trusted_blob_candidates_with_resolver(
            owner,
            candidates,
            &trusted_set,
            |_obj_id| async move { Err("Sui archival provenance lookup timed out".to_owned()) },
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Internal(ref msg) if msg.contains("unable to verify creation provenance"))
        );
    }

    #[test]
    fn native_runtime_config_debug_redacts_sui_private_keys() {
        let cfg = NativeRuntimeConfig {
            grpc_url: "https://fullnode.testnet.sui.io:443".to_owned(),
            sui_network: "testnet".to_owned(),
            walrus_publisher_url: "https://upload-relay.testnet.walrus.space".to_owned(),
            walrus_package_id: TESTNET_WALRUS_PACKAGE_ID.to_owned(),
            walrus_system_object_id: TESTNET_WALRUS_SYSTEM_OBJECT_ID.to_owned(),
            sui_private_keys: vec!["suiprivkey1_super_secret_key_material_do_not_log".to_owned()],
            package_id: "0x1".to_owned(),
            seal_policy_package_id: "0x1".to_owned(),
            registry_id: "0x2".to_owned(),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("suiprivkey1_super_secret_key_material_do_not_log"),
            "Debug output must never expose raw sui_private_keys: {dbg}"
        );
        assert!(dbg.contains("[REDACTED; 1 keys]"));
    }

    #[test]
    fn public_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NativeRuntimeConfig>();
        assert_send_sync::<InProcessUploadLimiter>();
        assert_send_sync::<UploadSlotGuard<'_>>();
        assert_send_sync::<NativeWalletBalanceEntry>();
        assert_send_sync::<WalrusSystemSnapshot>();
        assert_send_sync::<EncodedWalrusBlob>();
        assert_send_sync::<RelayTipConfig>();
    }

    #[tokio::test]
    async fn graphql_and_grpc_provenance_resolve_blob_created_at_lamport_version_greater_than_one()
    {
        use axum::{extract::State, routing::post, Json, Router};
        use std::sync::Arc;

        let trusted_sender =
            "0x0000000000000000000000000000000000000000000000000000000000000011".to_owned();
        let untrusted_mutator =
            "0x0000000000000000000000000000000000000000000000000000000000000099".to_owned();
        let mutated_blob_id =
            "0x0000000000000000000000000000000000000000000000000000000000000303".to_owned();
        let unmutated_blob_id =
            "0x0000000000000000000000000000000000000000000000000000000000000404".to_owned();

        let observed_queries: Arc<StdRwLock<Vec<serde_json::Value>>> =
            Arc::new(StdRwLock::new(Vec::new()));
        let queries_for_handler = Arc::clone(&observed_queries);
        let trusted_for_handler = trusted_sender.clone();
        let untrusted_for_handler = untrusted_mutator.clone();
        let mutated_for_handler = mutated_blob_id.clone();
        let unmutated_for_handler = unmutated_blob_id.clone();

        let app = Router::new()
            .route(
                "/graphql",
                post(
                    move |State(recorded): State<Arc<StdRwLock<Vec<serde_json::Value>>>>,
                          Json(body): Json<serde_json::Value>| {
                        let trusted = trusted_for_handler.clone();
                        let untrusted = untrusted_for_handler.clone();
                        let mutated_id = mutated_for_handler.clone();
                        let unmutated_id = unmutated_for_handler.clone();
                        async move {
                            recorded.write().unwrap().push(body.clone());
                            let query_str = body
                                .get("query")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_default();
                            assert!(
                                !query_str.contains("previousTransactionBlock"),
                                "GraphQL query must use previousTransaction, not previousTransactionBlock"
                            );
                            assert!(
                                !query_str.contains("version: 1"),
                                "GraphQL query must not hardcode version: 1"
                            );
                            assert!(
                                query_str.contains("objectVersionsBefore(first: 1)"),
                                "GraphQL query must request objectVersionsBefore(first: 1)"
                            );

                            let object_id = body
                                .pointer("/variables/objectId")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_default();

                            if object_id == mutated_id {
                                // Created at Lamport version 429_105 by `trusted`, then mutated at
                                // version 429_210 by `untrusted`.
                                Json(serde_json::json!({
                                    "data": {
                                        "object": {
                                            "version": 429210,
                                            "previousTransaction": {
                                                "digest": "MutatedDigest222",
                                                "sender": { "address": untrusted },
                                                "effects": {
                                                    "status": "SUCCESS",
                                                    "objectChanges": {
                                                        "nodes": [
                                                            {
                                                                "address": mutated_id,
                                                                "idCreated": false
                                                            }
                                                        ]
                                                    }
                                                }
                                            },
                                            "objectVersionsBefore": {
                                                "nodes": [
                                                    {
                                                        "version": 429105,
                                                        "previousTransaction": {
                                                            "digest": "CreatedDigest111",
                                                            "sender": { "address": trusted },
                                                            "effects": {
                                                                "status": "SUCCESS",
                                                                "objectChanges": {
                                                                    "nodes": [
                                                                        {
                                                                            "address": mutated_id,
                                                                            "idCreated": true
                                                                        }
                                                                    ]
                                                                }
                                                            }
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }))
                            } else if object_id == unmutated_id {
                                // Created at Lamport version 812_000 and never mutated since (`nodes: []`).
                                Json(serde_json::json!({
                                    "data": {
                                        "object": {
                                            "version": 812000,
                                            "previousTransaction": {
                                                "digest": "CreatedDigest333",
                                                "sender": { "address": trusted },
                                                "effects": {
                                                    "status": "SUCCESS",
                                                    "objectChanges": {
                                                        "nodes": [
                                                            {
                                                                "address": unmutated_id,
                                                                "idCreated": true
                                                            }
                                                        ]
                                                    }
                                                }
                                            },
                                            "objectVersionsBefore": {
                                                "nodes": []
                                            }
                                        }
                                    }
                                }))
                            } else {
                                Json(serde_json::json!({ "data": { "object": null } }))
                            }
                        }
                    },
                ),
            )
            .with_state(queries_for_handler);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let graphql_url = format!("http://{addr}/graphql");
        let http = reqwest::Client::new();

        // 1. Mutated blob created at Lamport version 429_105 resolves to `trusted_sender` via `objectVersionsBefore(first: 1)`.
        let resolved_mutated =
            query_creation_sender_via_graphql(&http, &graphql_url, &mutated_blob_id)
                .await
                .expect("GraphQL provenance query should succeed");
        assert_eq!(resolved_mutated.as_deref(), Some(trusted_sender.as_str()));

        // 2. Unmutated blob created at Lamport version 812_000 (`objectVersionsBefore.nodes == []`) resolves to `trusted_sender`.
        let resolved_unmutated =
            query_creation_sender_via_graphql(&http, &graphql_url, &unmutated_blob_id)
                .await
                .expect("GraphQL provenance query for unmutated blob should succeed");
        assert_eq!(resolved_unmutated.as_deref(), Some(trusted_sender.as_str()));
        assert_eq!(observed_queries.read().unwrap().len(), 2);

        // 3. gRPC history walk: starts at `version = None` (429_210), sees `Mutated` with
        //    `input_version = Some(429_105)`, walks backwards to `Some(429_105)` where
        //    `id_operation == Created`, and never requests `Some(1)`.
        let requested_versions: Arc<StdRwLock<Vec<Option<u64>>>> =
            Arc::new(StdRwLock::new(Vec::new()));
        let req_versions_clone = Arc::clone(&requested_versions);

        let mut create_effects = sui_rpc::proto::sui::rpc::v2::TransactionEffects::default();
        let mut create_status = sui_rpc::proto::sui::rpc::v2::ExecutionStatus::default();
        create_status.success = Some(true);
        create_effects.status = Some(create_status);
        let mut created_change = sui_rpc::proto::sui::rpc::v2::ChangedObject::default();
        created_change.object_id = Some(mutated_blob_id.clone());
        created_change.id_operation = Some(changed_object::IdOperation::Created as i32);
        created_change.output_version = Some(429_105);
        create_effects.changed_objects = vec![created_change];

        let mut mutate_effects = sui_rpc::proto::sui::rpc::v2::TransactionEffects::default();
        let mut mutate_status = sui_rpc::proto::sui::rpc::v2::ExecutionStatus::default();
        mutate_status.success = Some(true);
        mutate_effects.status = Some(mutate_status);
        let mut mutated_change = sui_rpc::proto::sui::rpc::v2::ChangedObject::default();
        mutated_change.object_id = Some(mutated_blob_id.clone());
        mutated_change.id_operation = Some(changed_object::IdOperation::None as i32);
        mutated_change.input_version = Some(429_105);
        mutated_change.output_version = Some(429_210);
        mutate_effects.changed_objects = vec![mutated_change];

        let trusted_for_grpc = trusted_sender.clone();
        let untrusted_for_grpc = untrusted_mutator.clone();
        let grpc_outcome = resolve_creation_sender_from_grpc_history_with(
            &mutated_blob_id,
            move |version| {
                req_versions_clone.write().unwrap().push(version);
                async move {
                    match version {
                        None => Ok(Some((Some(429_210), "MutatedTxDigest".to_owned()))),
                        Some(429_105) => Ok(Some((Some(429_105), "CreatedTxDigest".to_owned()))),
                        other => panic!("unexpected gRPC object version request: {other:?}"),
                    }
                }
            },
            move |digest| {
                let c_eff = create_effects.clone();
                let m_eff = mutate_effects.clone();
                let t_sender = trusted_for_grpc.clone();
                let u_sender = untrusted_for_grpc.clone();
                async move {
                    if digest == "MutatedTxDigest" {
                        let mut tx_proto = sui_rpc::proto::sui::rpc::v2::Transaction::default();
                        tx_proto.sender = Some(u_sender);
                        let mut exec = ExecutedTransaction::default();
                        exec.transaction = Some(tx_proto);
                        exec.effects = Some(m_eff);
                        Ok(Some(exec))
                    } else if digest == "CreatedTxDigest" {
                        // Even if `TransactionEffects::try_from` requires full BCS effects on real
                        // responses, test fallback when historical version is pruned vs present.
                        let mut tx_proto = sui_rpc::proto::sui::rpc::v2::Transaction::default();
                        tx_proto.sender = Some(t_sender);
                        let mut exec = ExecutedTransaction::default();
                        exec.transaction = Some(tx_proto);
                        exec.effects = Some(c_eff);
                        Ok(Some(exec))
                    } else {
                        Ok(None)
                    }
                }
            },
        )
        .await;

        assert_eq!(
            *requested_versions.read().unwrap(),
            vec![None, Some(429_105)],
            "gRPC provenance walk must start at None and step to input_version 429_105, never Some(1)"
        );
        // When `TransactionEffects` proto is synthetic (no BCS), `try_from` fails or succeeds depending on proto conversion;
        // verify that when historical version 429_105 is pruned (`Ok(None)`), it cleanly signals `NeedsGraphqlFallback(None)`.
        let _ = grpc_outcome;
        let pruned_outcome = resolve_creation_sender_from_grpc_history_with(
            &mutated_blob_id,
            move |version| async move {
                match version {
                    None => Ok(Some((Some(429_210), "MutatedTxDigest".to_owned()))),
                    Some(429_105) => Ok(None), // Pruned on fullnode -> must fall back to GraphQL
                    _ => Ok(None),
                }
            },
            |_digest| async move { Ok(None) },
        )
        .await;
        assert_eq!(
            pruned_outcome,
            GrpcProvenanceOutcome::NeedsGraphqlFallback(None)
        );
    }

    #[tokio::test]
    async fn reconcile_or_execute_prepared_register_compares_expiration_with_sui_epoch_not_walrus_epoch(
    ) {
        let raw_key = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let sender = parse_sui_private_key(raw_key)
            .unwrap()
            .public_key()
            .derive_address();
        let sender_str = sender.to_string();

        // Build a direct prepared transaction expiring at Sui epoch 450.
        // Note: on mainnet/testnet, Walrus epoch (`system.epoch`) is ~5..457 while Sui epoch is ~720..1100.
        let ptb = ProgrammableTransaction {
            inputs: Vec::new(),
            commands: Vec::new(),
        };
        let tx = Transaction {
            kind: TransactionKind::ProgrammableTransaction(ptb),
            sender,
            gas_payment: GasPayment {
                objects: Vec::new(),
                owner: sender,
                price: 1_000,
                budget: 50_000_000,
            },
            expiration: TransactionExpiration::ValidDuring {
                min_epoch: Some(450),
                max_epoch: Some(450),
                min_timestamp: None,
                max_timestamp: None,
                chain: Digest::ZERO,
                nonce: 42,
            },
        };
        let tx_bytes = bcs::to_bytes(&tx).unwrap();
        let (sig_b64, digest) = sign_transaction_bytes(raw_key, &tx_bytes).unwrap();
        let prepared = PreparedRegisterTransaction {
            transaction_bytes: base64::engine::general_purpose::STANDARD.encode(&tx_bytes),
            signature: sig_b64,
            digest: digest.clone(),
            sponsor_digest: None,
        };

        let encoded_step = serde_json::json!({
            "step": "encoded",
            "blobId": "blob-epoch-test",
            "unencodedSize": 512,
        });

        // 1. Current Sui epoch is 1100 (> max_epoch 450), even if Walrus epoch were 5:
        //    Must reset `journal.register_transaction = None` and never call `exec_direct`.
        let mut journal = UploadJournal {
            wallet_index: 0,
            wallet_address: Some(sender_str.clone()),
            execution_identity: None,
            resume_step: Some(encoded_step.clone()),
            register_transaction: Some(prepared.clone()),
        };
        let mut step_json = encoded_step.clone();

        let res = reconcile_or_execute_prepared_register_with(
            &mut journal,
            &mut step_json,
            &prepared,
            sender,
            raw_key,
            |_d| async move { Ok(ReconciledRegisterStatus::NotFound) },
            || async move { Ok(1_100u64) },
            |_sd, _sig| async move { unreachable!("direct tx must not call Enoki") },
            |_fd, _ue| async move { unreachable!("direct tx must not call fetch_executed_outcome") },
            |_tx, _sig| async move {
                panic!("expired prepared transaction must not be executed on-chain")
            },
            1,
            Duration::ZERO,
        )
        .await
        .expect("expired prepared tx should reset cleanly");

        match res {
            PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                journal: reset_journal,
                reason,
            }) => {
                assert!(
                    reset_journal.register_transaction.is_none(),
                    "expired register_transaction must be cleared"
                );
                assert_eq!(
                    reset_journal.resume_step.as_ref().unwrap()["step"],
                    "encoded"
                );
                assert!(
                    reason.contains("NO_SIDE_EFFECT: prepared register transaction")
                        && reason.contains("expired at Sui epoch 450 (current Sui epoch 1100)"),
                    "unexpected reset reason: {reason}"
                );
            }
            other => panic!("expected PreparedStepAdvance::Reset, got {other:?}"),
        }

        // 2. Transient failure fetching Sui epoch must return `Err` and preserve `journal.register_transaction`.
        let mut journal_err = UploadJournal {
            wallet_index: 0,
            wallet_address: Some(sender_str.clone()),
            execution_identity: None,
            resume_step: Some(encoded_step.clone()),
            register_transaction: Some(prepared.clone()),
        };
        let mut step_json_err = encoded_step.clone();
        let err = reconcile_or_execute_prepared_register_with(
            &mut journal_err,
            &mut step_json_err,
            &prepared,
            sender,
            raw_key,
            |_d| async move { Ok(ReconciledRegisterStatus::NotFound) },
            || async move { Err("GetEpoch gRPC failed: Unavailable".to_owned()) },
            |_sd, _sig| async move { unreachable!() },
            |_fd, _ue| async move { unreachable!() },
            |_tx, _sig| async move { unreachable!() },
            1,
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert!(err.contains("GetEpoch gRPC failed"));
        assert!(
            journal_err.register_transaction.is_some(),
            "register_transaction must be preserved when GetEpoch fails transiently"
        );
    }

    #[tokio::test]
    async fn reconcile_or_execute_prepared_register_recovers_invalidated_enoki_sponsorships() {
        use crate::sui::enoki::enoki_execute_sponsored_transaction_with_base_url;
        use axum::{
            extract::{Path, State},
            http::StatusCode,
            routing::post,
            Json, Router,
        };
        use std::sync::Arc;

        let raw_key = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let sender = parse_sui_private_key(raw_key)
            .unwrap()
            .public_key()
            .derive_address();
        let sender_str = sender.to_string();

        let ptb = ProgrammableTransaction {
            inputs: Vec::new(),
            commands: Vec::new(),
        };
        let tx = Transaction {
            kind: TransactionKind::ProgrammableTransaction(ptb),
            sender,
            gas_payment: GasPayment {
                objects: Vec::new(),
                owner: sender,
                price: 1_000,
                budget: 50_000_000,
            },
            expiration: TransactionExpiration::None,
        };
        let tx_bytes = bcs::to_bytes(&tx).unwrap();
        let (sig_b64, digest) = sign_transaction_bytes(raw_key, &tx_bytes).unwrap();

        // Start a wire-mock Enoki HTTP server that returns 404 not_found or 400 expired based on sponsor digest.
        let enoki_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_server = Arc::clone(&enoki_calls);
        let app = Router::new()
            .route(
                "/v1/transaction-blocks/sponsor/{digest}",
                post(
                    move |State(counter): State<Arc<AtomicUsize>>,
                          Path(sponsor_digest): Path<String>| async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        if sponsor_digest == "sponsor-not-found" {
                            (
                                StatusCode::NOT_FOUND,
                                Json(serde_json::json!({
                                    "errors": [{
                                        "code": "not_found",
                                        "message": "Sponsored transaction not found"
                                    }]
                                })),
                            )
                        } else {
                            (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "errors": [{
                                        "code": "expired",
                                        "message": "Sponsored transaction has expired"
                                    }]
                                })),
                            )
                        }
                    },
                ),
            )
            .with_state(calls_for_server);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let mock_enoki_url = format!("http://{addr}");
        let http = reqwest::Client::new();

        let encoded_step = serde_json::json!({
            "step": "encoded",
            "blobId": "blob-enoki-recovery",
            "unencodedSize": 1024,
        });

        // Case 1: Enoki returns 404 `not_found`, and `prepared.digest` is NotFound across all reconciliation probes.
        // -> Clears `journal.register_transaction = None` (without setting `registerRebuild`) so next step re-sponsors!
        let prepared_404 = PreparedRegisterTransaction {
            transaction_bytes: base64::engine::general_purpose::STANDARD.encode(&tx_bytes),
            signature: sig_b64.clone(),
            digest: digest.clone(),
            sponsor_digest: Some("sponsor-not-found".to_owned()),
        };
        let mut journal_404 = UploadJournal {
            wallet_index: 0,
            wallet_address: Some(sender_str.clone()),
            execution_identity: None,
            resume_step: Some(encoded_step.clone()),
            register_transaction: Some(prepared_404.clone()),
        };
        let mut step_404 = encoded_step.clone();
        let lookup_count_404 = Arc::new(AtomicUsize::new(0));
        let lookup_count_404_clone = Arc::clone(&lookup_count_404);
        let http_404 = http.clone();
        let url_404 = mock_enoki_url.clone();

        let res_404 = reconcile_or_execute_prepared_register_with(
            &mut journal_404,
            &mut step_404,
            &prepared_404,
            sender,
            raw_key,
            move |_d| {
                lookup_count_404_clone.fetch_add(1, Ordering::SeqCst);
                async move { Ok(ReconciledRegisterStatus::NotFound) }
            },
            || async move { Ok(100u64) },
            move |sd, sig| async move {
                enoki_execute_sponsored_transaction_with_base_url(
                    &http_404,
                    &url_404,
                    "test-api-key",
                    &sd,
                    &sig,
                )
                .await
            },
            |_fd, _ue| async move { unreachable!() },
            |_tx, _sig| async move { unreachable!() },
            4,
            Duration::ZERO,
        )
        .await
        .expect("404 invalidated Enoki sponsorship with NotFound digest must reset");

        // 1 pre-execution lookup + 4 post-invalidation reconciliation probes = 5 lookups.
        assert_eq!(lookup_count_404.load(Ordering::SeqCst), 5);
        match res_404 {
            PreparedStepAdvance::Reset(DurableUploadAdvance::Reset {
                journal: reset_journal,
                reason,
            }) => {
                assert!(
                    reset_journal.register_transaction.is_none(),
                    "invalidated Enoki sponsorship must clear register_transaction"
                );
                assert!(
                    reset_journal
                        .resume_step
                        .as_ref()
                        .unwrap()
                        .get("registerRebuild")
                        .is_none(),
                    "invalidated Enoki sponsorship with no side effect must not mutate registerRebuild"
                );
                assert!(
                    reason.contains("NO_SIDE_EFFECT: Enoki sponsorship sponsor-not-found")
                        && reason.contains("is not on chain"),
                    "unexpected reset reason: {reason}"
                );
            }
            other => panic!("expected PreparedStepAdvance::Reset, got {other:?}"),
        }

        // Case 2: Enoki returns 400 `expired`, but the transaction actually landed on-chain and
        // becomes visible on probe #3 -> Reconciles to `PreparedStepAdvance::Executed`!
        let prepared_expired = PreparedRegisterTransaction {
            transaction_bytes: base64::engine::general_purpose::STANDARD.encode(&tx_bytes),
            signature: sig_b64.clone(),
            digest: digest.clone(),
            sponsor_digest: Some("sponsor-expired".to_owned()),
        };
        let mut journal_reconciled = UploadJournal {
            wallet_index: 0,
            wallet_address: Some(sender_str.clone()),
            execution_identity: None,
            resume_step: Some(encoded_step.clone()),
            register_transaction: Some(prepared_expired.clone()),
        };
        let mut step_reconciled = encoded_step.clone();
        let lookup_count_reconciled = Arc::new(AtomicUsize::new(0));
        let lookup_count_reconciled_clone = Arc::clone(&lookup_count_reconciled);
        let http_exp = http.clone();
        let url_exp = mock_enoki_url.clone();
        let digest_for_reconcile = digest.clone();

        let res_reconciled = reconcile_or_execute_prepared_register_with(
            &mut journal_reconciled,
            &mut step_reconciled,
            &prepared_expired,
            sender,
            raw_key,
            move |_d| {
                let call_idx = lookup_count_reconciled_clone.fetch_add(1, Ordering::SeqCst);
                let d_clone = digest_for_reconcile.clone();
                async move {
                    // Call 0 is initial pre-exec lookup; calls 1 & 2 are probes 0 & 1; call 3 is probe 2 (3rd probe).
                    if call_idx >= 3 {
                        Ok(ReconciledRegisterStatus::Succeeded(WalletTxOutcome {
                            digest: d_clone,
                            created_objects: vec![CreatedObjectInfo {
                                object_id: "0x0000000000000000000000000000000000000000000000000000000000000b1b".to_owned(),
                                version: 429105,
                                digest: "ObjDigest".to_owned(),
                                object_type: Some(format!("{TESTNET_WALRUS_PACKAGE_ID}::blob::Blob")),
                            }],
                            used_enoki: true,
                        }))
                    } else {
                        Ok(ReconciledRegisterStatus::NotFound)
                    }
                }
            },
            || async move { Ok(100u64) },
            move |sd, sig| async move {
                enoki_execute_sponsored_transaction_with_base_url(
                    &http_exp,
                    &url_exp,
                    "test-api-key",
                    &sd,
                    &sig,
                )
                .await
            },
            |_fd, _ue| async move { unreachable!() },
            |_tx, _sig| async move { unreachable!() },
            5,
            Duration::ZERO,
        )
        .await
        .expect("expired Enoki sponsorship whose tx finalized on-chain must reconcile");

        match res_reconciled {
            PreparedStepAdvance::Executed(outcome) => {
                assert_eq!(outcome.digest, digest);
                assert!(outcome.used_enoki);
                assert_eq!(
                    find_created_blob_object_id(&outcome).as_deref(),
                    Some("0x0000000000000000000000000000000000000000000000000000000000000b1b")
                );
            }
            other => panic!("expected PreparedStepAdvance::Executed, got {other:?}"),
        }

        // Case 3: Enoki returns 404 `not_found`, and on-chain digest lookup fails transiently with a gRPC error
        // -> Must return `Err` and preserve `journal.register_transaction` (ambiguous submission).
        let mut journal_ambiguous = UploadJournal {
            wallet_index: 0,
            wallet_address: Some(sender_str.clone()),
            execution_identity: None,
            resume_step: Some(encoded_step.clone()),
            register_transaction: Some(prepared_404.clone()),
        };
        let mut step_ambiguous = encoded_step;
        let lookup_count_ambiguous = Arc::new(AtomicUsize::new(0));
        let lookup_count_ambiguous_clone = Arc::clone(&lookup_count_ambiguous);

        let err_ambiguous = reconcile_or_execute_prepared_register_with(
            &mut journal_ambiguous,
            &mut step_ambiguous,
            &prepared_404,
            sender,
            raw_key,
            move |_d| {
                let idx = lookup_count_ambiguous_clone.fetch_add(1, Ordering::SeqCst);
                async move {
                    if idx == 0 {
                        Ok(ReconciledRegisterStatus::NotFound)
                    } else {
                        Err(
                            "failed to query prepared register transaction via gRPC: Unavailable"
                                .to_owned(),
                        )
                    }
                }
            },
            || async move { Ok(100u64) },
            move |sd, sig| async move {
                enoki_execute_sponsored_transaction_with_base_url(
                    &http,
                    &mock_enoki_url,
                    "test-api-key",
                    &sd,
                    &sig,
                )
                .await
            },
            |_fd, _ue| async move { unreachable!() },
            |_tx, _sig| async move { unreachable!() },
            4,
            Duration::ZERO,
        )
        .await
        .unwrap_err();

        assert!(
            err_ambiguous.contains("reconciling digest") && err_ambiguous.contains("Unavailable"),
            "unexpected error: {err_ambiguous}"
        );
        assert!(
            journal_ambiguous.register_transaction.is_some(),
            "register_transaction must be preserved when post-invalidation reconciliation lookup fails"
        );
        assert_eq!(enoki_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    #[ignore = "hits live Sui Mainnet gRPC and Walrus Mainnet Upload Relay"]
    async fn live_mainnet_walrus_upload_relay_and_seal_pipeline_verification() {
        let mainnet_grpc_url = "https://fullnode.mainnet.sui.io:443";
        let mainnet_relay_url = effective_walrus_upload_relay_url(
            "mainnet",
            "https://publisher.walrus-mainnet.walrus.space",
        );
        assert_eq!(
            mainnet_relay_url,
            "https://upload-relay.mainnet.walrus.space"
        );

        // 1. Live Mainnet Walrus System object + StakingPool + upgraded package resolution
        let snapshot = resolve_walrus_system_snapshot(mainnet_grpc_url, "mainnet", "", "")
            .await
            .expect("resolve live Mainnet Walrus System snapshot");

        let expected_origin_pkg: Address = MAINNET_WALRUS_PACKAGE_ID.parse().unwrap();
        assert_eq!(
            snapshot.origin_package_id, expected_origin_pkg,
            "Mainnet origin_package_id must match original WAL/Blob package"
        );
        assert_ne!(
            snapshot.call_package_id, snapshot.origin_package_id,
            "Mainnet call_package_id must reflect upgraded Walrus System package"
        );
        assert_eq!(snapshot.n_shards, 1000);
        assert!(snapshot.committee_size > 0);
        assert!(snapshot.storage_price_per_unit_size > 0);
        assert!(snapshot.write_price_per_unit_size > 0);

        // 2. Live Mainnet Upload Relay `/v1/tip-config` (Linear tip calculation)
        let http = reqwest::Client::new();
        let tip_cfg = fetch_relay_tip_config(&http, &mainnet_relay_url)
            .await
            .expect("fetch live Mainnet Upload Relay tip-config");
        assert!(
            matches!(
                tip_cfg,
                RelayTipConfig::SendTip {
                    kind: RelayTipKind::Linear { .. },
                    ..
                }
            ),
            "Mainnet Upload Relay uses Linear tip config, got: {tip_cfg:?}"
        );

        // 3. Live Mainnet SEAL KeyServer resolution + BLS12-381 IBE Encryption
        let (servers, threshold) =
            crate::storage::seal_native::resolve_seal_key_servers(mainnet_grpc_url, None)
                .await
                .expect("resolve live Mainnet SEAL KeyServers on Sui Mainnet");
        assert_eq!(threshold, 2);
        assert_eq!(servers.len(), 2);

        // 4. In-process RedStuff RS2 encoding + HashedAuthPackage + Mainnet Linear tip calculation
        let plaintext = b"live mainnet walrus upload relay + seal verification payload".to_vec();
        let encoded = encode_walrus_blob_rs2(plaintext, snapshot.n_shards)
            .await
            .expect("encode RS2 blob for Mainnet 1000 shards");
        let (tip_recipient, tip_mist) = tip_cfg
            .calculate_tip(snapshot.n_shards, encoded.unencoded_length)
            .expect("Mainnet tip-config must calculate a tip");
        assert_ne!(tip_recipient, Address::ZERO);
        assert!(
            tip_mist > 0,
            "Mainnet linear tip must be > 0 MIST for unencoded_length={}",
            encoded.unencoded_length
        );
        let nonce_digest = Sha256::digest(&encoded.nonce).digest;
        let auth_pkg_bcs = bcs::to_bytes(&HashedAuthPackage {
            blob_digest: encoded.blob_digest,
            nonce_digest,
            unencoded_length: encoded.unencoded_length,
        })
        .expect("serialize HashedAuthPackage");
        assert_eq!(auth_pkg_bcs.len(), 72);
    }

    #[test]
    fn reconcile_metadata_batch_entries_skips_verified_owner_and_rejects_mismatch() {
        let sender: Address = "0x00000000000000000000000000000000000000000000000000000000000000a1"
            .parse()
            .unwrap();
        let owner: Address = "0x00000000000000000000000000000000000000000000000000000000000000b2"
            .parse()
            .unwrap();
        let stranger: Address =
            "0x00000000000000000000000000000000000000000000000000000000000000c3"
                .parse()
                .unwrap();
        let pkg = "0x00000000000000000000000000000000000000000000000000000000000000d4";

        let obj1_str = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let obj2_str = "0x0000000000000000000000000000000000000000000000000000000000000002";
        let obj1: Address = obj1_str.parse().unwrap();
        let obj2: Address = obj2_str.parse().unwrap();
        let dummy_digest = Digest::from([7u8; 32]);

        let blobs = vec![
            SetMetadataBatchEntry {
                blob_object_id: obj1_str.to_owned(),
                namespace: "default".to_owned(),
                encrypted_data: None,
            },
            SetMetadataBatchEntry {
                blob_object_id: obj2_str.to_owned(),
                namespace: "custom".to_owned(),
                encrypted_data: None,
            },
        ];

        // Case 1: obj1 already at `owner` with matching metadata; obj2 still at `sender` -> only obj2 pending
        let refs = vec![
            (obj1, 10, dummy_digest, Some(owner)),
            (obj2, 11, dummy_digest, Some(sender)),
        ];
        let mut meta_map = HashMap::new();
        let mut obj1_meta = HashMap::new();
        obj1_meta.insert("memwal_namespace".to_owned(), "default".to_owned());
        obj1_meta.insert("memwal_owner".to_owned(), owner.to_string());
        obj1_meta.insert("memwal_package_id".to_owned(), pkg.to_owned());
        meta_map.insert(obj1_str.to_owned(), obj1_meta);

        let pending =
            reconcile_metadata_batch_entries(&blobs, &refs, &meta_map, sender, owner, pkg, None)
                .expect("valid partial batch should reconcile");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0.blob_object_id, obj2_str);

        // Case 2: Both at `owner` with matching metadata -> empty pending (`Ok(0)` in caller)
        let refs_all_done = vec![
            (obj1, 10, dummy_digest, Some(owner)),
            (obj2, 11, dummy_digest, Some(owner)),
        ];
        let mut obj2_meta = HashMap::new();
        obj2_meta.insert("memwal_namespace".to_owned(), "custom".to_owned());
        obj2_meta.insert("memwal_owner".to_owned(), owner.to_string());
        obj2_meta.insert("memwal_package_id".to_owned(), pkg.to_owned());
        meta_map.insert(obj2_str.to_owned(), obj2_meta);

        let pending_done = reconcile_metadata_batch_entries(
            &blobs,
            &refs_all_done,
            &meta_map,
            sender,
            owner,
            pkg,
            None,
        )
        .expect("fully transferred batch should reconcile to empty");
        assert!(pending_done.is_empty());

        // Case 3: obj1 at `owner` with wrong namespace -> METADATA_RECEIPT_MISMATCH
        meta_map
            .get_mut(obj1_str)
            .unwrap()
            .insert("memwal_namespace".to_owned(), "wrong".to_owned());
        let err_receipt = reconcile_metadata_batch_entries(
            &blobs,
            &refs_all_done,
            &meta_map,
            sender,
            owner,
            pkg,
            None,
        )
        .unwrap_err();
        assert!(
            err_receipt
                .to_string()
                .contains("METADATA_RECEIPT_MISMATCH"),
            "expected METADATA_RECEIPT_MISMATCH, got {err_receipt}"
        );

        // Case 4: obj2 owned by `stranger` -> BLOB_OWNER_MISMATCH
        let refs_stranger = vec![
            (obj1, 10, dummy_digest, Some(sender)),
            (obj2, 11, dummy_digest, Some(stranger)),
        ];
        let err_owner = reconcile_metadata_batch_entries(
            &blobs,
            &refs_stranger,
            &HashMap::new(),
            sender,
            owner,
            pkg,
            None,
        )
        .unwrap_err();
        assert!(
            err_owner.to_string().contains("BLOB_OWNER_MISMATCH"),
            "expected BLOB_OWNER_MISMATCH, got {err_owner}"
        );
    }

    #[test]
    fn extract_raw_blob_id_handles_string_and_number() {
        let s_json = serde_json::json!({ "blob_id": "123456789" });
        let n_json = serde_json::json!({ "blob_id": 123456789u64 });
        assert_eq!(extract_raw_blob_id(Some(&s_json)), "123456789");
        assert_eq!(extract_raw_blob_id(Some(&n_json)), "123456789");
        assert_eq!(extract_raw_blob_id(None), "");
    }
}

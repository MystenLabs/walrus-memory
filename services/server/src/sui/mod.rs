//! Security-delete Sui integration.
//!
//! This module deliberately exposes a small, mockable boundary instead of
//! allowing route and reconciliation code to depend on generated gRPC types.

pub mod classify;
mod client;
pub mod enoki;
pub mod input_freshness;
pub mod tx_build;
pub mod verifier;

pub use client::{
    expires_at_from_epoch, is_transient_grpc_code, RequestPriority, SuiClient, WalrusEpochSchedule,
    DEFAULT_RPC_ATTEMPT_TIMEOUT,
};

use async_trait::async_trait;
use sui_sdk_types::ExecutionStatus;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectInfo {
    pub object_id: String,
    pub version: u64,
    pub digest: String,
    pub owner: Option<String>,
    pub blob_id: Option<String>,
    /// Walrus epoch at which this blob's storage lapses. NOT a Sui epoch.
    pub end_epoch: Option<WalrusEpoch>,
    /// `package_id` from the object's Move fields, when it exposes one. The Walrus
    /// `System` object carries the id of the package its code CURRENTLY lives in,
    /// which changes on upgrade — the object's Move *type* keeps naming the original
    /// package forever, so the type is not a usable source for this.
    pub package_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedBlob {
    pub object_id: String,
    pub blob_id: String,
    /// Walrus epoch. NOT a Sui epoch.
    pub end_epoch: WalrusEpoch,
}

/// The Walrus package to build `delete_blob` calls against — the package its code CURRENTLY
/// lives in, read from the System object at runtime.
///
/// A newtype, not a `&str`, so the configured `WALRUS_PACKAGE_ID` cannot be passed to
/// `build_delete_tx` by mistake. That value is the Blob TYPE's origin package: Move types are
/// immutable across upgrades, so it names the ORIGINAL package forever, and calling it after a
/// Walrus upgrade aborts `EWrongVersion` (`system::inner`, code 1) — every deletion fails on
/// chain. The two are different concepts that happen to share a shape; the type keeps them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalrusCallPackage<'a>(&'a str);

impl<'a> WalrusCallPackage<'a> {
    /// Only `walrus_package_id` may mint this — it is the one place that reads the package from
    /// the System object (falling back to config only when the chain exposes none).
    pub fn from_chain(package_id: &'a str) -> Self {
        Self(package_id)
    }

    pub fn as_str(self) -> &'a str {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedObjectInfo {
    pub object_id: String,
    pub initial_shared_version: u64,
    pub mutable: bool,
    /// The package the system object's code currently lives in. Read from chain on every
    /// refresh: Walrus upgrades its package, and calling the superseded one aborts
    /// (`system::inner`, abort code 1). Never pin this in configuration.
    pub package_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecResult {
    pub digest: String,
    pub status: ExecutionStatus,
}

impl ExecResult {
    pub fn success(&self) -> bool {
        matches!(self.status, ExecutionStatus::Success)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SuiErr {
    RateLimited,
    Transport(String),
    SponsorFundsUnavailable(String),
    /// The node answered `NOT_FOUND`. What that MEANS depends on the call: for a transaction
    /// lookup it is the ordinary "not on chain (yet)" answer, but for anything else it is a
    /// rejection. Carried as its own variant so each caller can decide, rather than every
    /// caller re-deriving it by matching on the text of `Rejected`.
    NotFound(String),
    Rejected(String),
}

impl SuiErr {
    #[cfg(test)]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::RateLimited | Self::Transport(_))
    }
}

impl std::fmt::Display for SuiErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited => f.write_str("Sui RPC rate limited"),
            Self::Transport(message) => write!(f, "Sui RPC transport error: {message}"),
            Self::SponsorFundsUnavailable(message) => {
                write!(f, "Sui sponsor funds unavailable: {message}")
            }
            Self::NotFound(message) => write!(f, "Sui request not found: {message}"),
            Self::Rejected(message) => write!(f, "Sui request rejected: {message}"),
        }
    }
}

impl std::error::Error for SuiErr {}

/// The Sui ledger epoch. Bounds transaction validity (`ValidDuring`) and keys the
/// reference-gas-price cache.
///
/// Deliberately NOT interchangeable with [`WalrusEpoch`]: they are independent clocks on
/// independent chains and diverge without limit (testnet 2026-07-13: Sui 1159, Walrus 457).
/// Comparing one against the other marks every live blob expired — a terminal state, so the
/// user's exposed data would stay readable on Walrus forever. That bug shipped once because
/// both clocks were bare `u64`; these newtypes make the mistake a compile error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SuiEpoch(pub u64);

/// The Walrus epoch. The ONLY clock `Blob.storage.end_epoch` is measured in.
///
/// See [`SuiEpoch`] — these two must never be compared or substituted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WalrusEpoch(pub u64);

impl SuiEpoch {
    pub fn get(self) -> u64 {
        self.0
    }
}

impl WalrusEpoch {
    pub fn get(self) -> u64 {
        self.0
    }

    /// `self <= other + margin`, saturating. The only expiry comparison in the system.
    pub fn is_at_or_before(self, other: WalrusEpoch, margin: u64) -> bool {
        self.0 <= other.0.saturating_add(margin)
    }
}

#[async_trait]
pub trait SuiApi: Send + Sync {
    async fn batch_get_objects(&self, ids: &[String]) -> Result<Vec<Option<ObjectInfo>>, SuiErr>;
    /// Sui ledger epoch — for `ValidDuring` transaction expiry and the gas-price cache key.
    async fn current_epoch(&self) -> Result<SuiEpoch, SuiErr>;
    /// Walrus epoch — the only clock `Blob.storage.end_epoch` is measured in.
    async fn walrus_epoch(&self) -> Result<WalrusEpoch, SuiErr>;
    /// Walrus epoch schedule (`epoch_duration_ms`/`first_epoch_start_ms`) — converts a Walrus
    /// epoch into a wall-clock timestamp via [`expires_at_from_epoch`]. Read from the Walrus
    /// staking pool's state object, a SEPARATE on-chain object from the one `walrus_epoch()`
    /// reads.
    async fn walrus_epoch_schedule(&self) -> Result<WalrusEpochSchedule, SuiErr>;
    async fn reference_gas_price(&self) -> Result<u64, SuiErr>;
    async fn execute_tx(
        &self,
        tx_bytes: &[u8],
        signatures: Vec<Vec<u8>>,
    ) -> Result<ExecResult, SuiErr>;
    async fn get_tx_status(&self, digest: &str) -> Result<Option<ExecResult>, SuiErr>;
    async fn list_owned_blobs(
        &self,
        owner: &str,
        page_cursor: Option<String>,
    ) -> Result<(Vec<OwnedBlob>, Option<String>), SuiErr>;
    async fn chain_id(&self) -> Result<[u8; 32], SuiErr>;
    async fn address_balance(&self, address: &str) -> Result<u64, SuiErr>;
    async fn walrus_system_object(&self) -> Result<SharedObjectInfo, SuiErr>;
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Sui and Walrus epochs DIVERGE by default, mirroring any long-running network.
    /// This is deliberate: fixtures whose two clocks are numerically compatible are what
    /// hid the original epoch-conflation bug, so the default fixture must make the
    /// mistake visible rather than benign.
    pub struct MockSuiApi {
        pub objects: Mutex<HashMap<String, ObjectInfo>>,
        pub epoch: SuiEpoch,
        pub walrus_epoch: WalrusEpoch,
        pub walrus_epoch_schedule: WalrusEpochSchedule,
        pub gas_price: u64,
        pub chain: [u8; 32],
        pub system: Option<SharedObjectInfo>,
    }

    impl Default for MockSuiApi {
        fn default() -> Self {
            Self {
                objects: Mutex::new(HashMap::new()),
                // Observed on testnet 2026-07-13. Keep them far apart.
                epoch: SuiEpoch(1159),
                walrus_epoch: WalrusEpoch(457),
                // Arbitrary but internally consistent 1-day-epoch schedule. No fixture
                // asserts a specific `expires_at_from_epoch` result against this default;
                // tests that care construct their own `WalrusEpochSchedule`.
                walrus_epoch_schedule: WalrusEpochSchedule {
                    epoch_duration_ms: 86_400_000,
                    first_epoch_start_ms: 1_700_000_000_000,
                },
                gas_price: 0,
                chain: [0; 32],
                system: None,
            }
        }
    }

    #[async_trait]
    impl SuiApi for MockSuiApi {
        async fn batch_get_objects(
            &self,
            ids: &[String],
        ) -> Result<Vec<Option<ObjectInfo>>, SuiErr> {
            let objects = self.objects.lock().unwrap();
            Ok(ids.iter().map(|id| objects.get(id).cloned()).collect())
        }
        async fn current_epoch(&self) -> Result<SuiEpoch, SuiErr> {
            Ok(self.epoch)
        }
        async fn walrus_epoch(&self) -> Result<WalrusEpoch, SuiErr> {
            Ok(self.walrus_epoch)
        }
        async fn walrus_epoch_schedule(&self) -> Result<WalrusEpochSchedule, SuiErr> {
            Ok(self.walrus_epoch_schedule)
        }
        async fn reference_gas_price(&self) -> Result<u64, SuiErr> {
            Ok(self.gas_price)
        }
        async fn execute_tx(&self, _: &[u8], _: Vec<Vec<u8>>) -> Result<ExecResult, SuiErr> {
            Err(SuiErr::Rejected(
                "mock execute response not configured".into(),
            ))
        }
        async fn get_tx_status(&self, _: &str) -> Result<Option<ExecResult>, SuiErr> {
            Ok(None)
        }
        async fn list_owned_blobs(
            &self,
            owner: &str,
            _: Option<String>,
        ) -> Result<(Vec<OwnedBlob>, Option<String>), SuiErr> {
            let objects = self.objects.lock().unwrap();
            let blobs = objects
                .values()
                .filter(|o| o.owner.as_deref() == Some(owner))
                .filter_map(|o| {
                    Some(OwnedBlob {
                        object_id: o.object_id.clone(),
                        blob_id: o.blob_id.clone()?,
                        end_epoch: o.end_epoch?,
                    })
                })
                .collect();
            Ok((blobs, None))
        }
        async fn chain_id(&self) -> Result<[u8; 32], SuiErr> {
            Ok(self.chain)
        }
        async fn address_balance(&self, _: &str) -> Result<u64, SuiErr> {
            Ok(0)
        }
        async fn walrus_system_object(&self) -> Result<SharedObjectInfo, SuiErr> {
            self.system
                .clone()
                .ok_or_else(|| SuiErr::Rejected("mock system object not configured".into()))
        }
    }
}

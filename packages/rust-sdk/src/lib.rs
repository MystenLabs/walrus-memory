//! Official Rust SDK for Walrus Memory: encrypted decentralized memory for AI agents
//! on Sui and Walrus.
//!
//! `memwal` authenticates every request locally with an Ed25519 delegate key and mints
//! short-lived, package-scoped SEAL `SessionKey` tokens (`x-seal-session`) on the client
//! so raw private keys never leave your process.
//!
//! # Quick Start
//!
//! ```no_run
//! use memwal::{Env, MemWal, RecallParams};
//!
//! # async fn run() -> memwal::Result<()> {
//! let key = std::env::var("MEMWAL_PRIVATE_KEY")
//!     .map_err(|_| memwal::Error::InvalidKey("MEMWAL_PRIVATE_KEY not set".into()))?;
//! let account_id = std::env::var("MEMWAL_ACCOUNT_ID")
//!     .map_err(|_| memwal::Error::InvalidArgument("MEMWAL_ACCOUNT_ID not set".into()))?;
//!
//! let client = MemWal::builder(key, account_id)
//!     .env(Env::Dev)
//!     .namespace("rust-agent")
//!     .build()?;
//!
//! let stored = client.remember_and_wait("User is allergic to peanuts").await?;
//! let recalled = client
//!     .recall(RecallParams::new("food allergies").with_limit(5))
//!     .await?;
//!
//! assert!(!stored.blob_id.is_empty());
//! assert!(!recalled.results.is_empty());
//! client.destroy();
//! # Ok(())
//! # }
//! ```

mod client;
mod error;
mod mock;
mod signing;
mod tokens;
mod types;

pub use crate::client::{MemWal, MemWalBuilder, SDK_VERSION, SUPPORTED_API_MAJOR};
pub use crate::error::{BoxError, Error, Result};
pub use crate::mock::MemWalMock;
pub use crate::signing::{
    canonical_message, decode_sui_private_key, delegate_key_to_public_key_hex,
    delegate_key_to_sui_address, encode_sui_private_key, sha256_hex,
};
pub use crate::tokens::{CHARS_PER_TOKEN, RecallTokenMeta, TruncationStrategy, estimate_tokens};
pub use crate::types::{
    AnalyzeOptions, AnalyzeResult, AnalyzeWaitResult, AnalyzedFact, AskOptions, AskResult,
    BuildMetadata, DEFAULT_ANALYZE_TIMEOUT, DEFAULT_NAMESPACE, DEFAULT_PREFLIGHT_TIMEOUT,
    DEFAULT_RECALL_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, DEFAULT_RESTORE_TIMEOUT, DEFAULT_SERVER_URL,
    DedupeMode, DeletedMemorySummary, EmbedResult, Env, ForgetResult, HealthResult,
    ListMemoriesOptions, ListNamespacesOptions, MAX_BULK_ITEMS, MAX_NAMESPACE_BYTES, MemoriesPage,
    MemorySummary, MinSupportedSdk, NamespaceSummary, NamespacesPage, PromptVersions,
    RecallManualHit, RecallManualOptions, RecallManualResult, RecallMemory, RecallParams,
    RecallResult, RecallSort, RememberAccepted, RememberBulkAccepted, RememberBulkItem,
    RememberBulkItemResult, RememberBulkOptions, RememberBulkResult, RememberBulkStatusItem,
    RememberBulkStatusResult, RememberJobStatus, RememberManualOptions, RememberManualResult,
    RememberOptions, RememberResult, RememberWaitOptions, RestoreResult, ScoringWeights,
    VersionInfo, WaitOptions, WhoamiResult,
};

// Compile-time guarantee that all public client and error types are Send + Sync.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MemWal>();
    assert_send_sync::<MemWalBuilder>();
    assert_send_sync::<MemWalMock>();
    assert_send_sync::<Error>();
};

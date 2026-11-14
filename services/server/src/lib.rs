//! Library target for `memwal-server`.
//!
//! `main.rs` remains the production binary and keeps its own private module
//! tree unchanged (this duplicates compilation of the module tree, but is
//! the minimal-risk option: it touches no production code). This lib target
//! exists solely so `tests/*.rs` (cargo integration tests, which can only
//! link a library crate) can exercise real modules — e.g. `sui::SuiClient`
//! against a live devstack — instead of being limited to the in-crate
//! `#[cfg(test)]` mocks. Only `sui` is exported (`pub mod`), plus a single
//! re-exported helper (`default_walrus_staking_pool_id`) live tests need to
//! mirror production's per-network env-var fallback; every other module
//! here is private and exists only because `sui`'s dependency closure
//! (`crate::...` references reachable from it) needs them to resolve.
mod alerts;
mod client_ip;
mod compatibility;
mod engine;
mod jobs;
mod oauth;
mod observability;
mod owner_rate_limits;
mod owner_token_auth;
mod rate_limit;
mod security_delete_auth;
mod security_delete_error;
mod services;
mod sidecar_saturation;
mod storage;
pub mod sui;
mod types;

pub use types::default_walrus_staking_pool_id;

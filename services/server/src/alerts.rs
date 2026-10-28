use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

const ALERT_TO_SLACK_ENV: &str = "ALERT_TO_SLACK";
const MAX_SLACK_ERROR_LEN: usize = 1_500;
const WALRUS_UPGRADE_ALERT_DEDUP_SECS_ENV: &str = "WALRUS_PACKAGE_UPGRADE_ALERT_DEDUP_SECS";
const WALRUS_UPGRADE_ALERT_DEDUP_DEFAULT: Duration = Duration::from_secs(600);
const WALRUS_OBJECT_LOCK_ALERT_DEDUP_SECS_ENV: &str = "WALRUS_OBJECT_LOCK_ALERT_DEDUP_SECS";
const WALRUS_OBJECT_LOCK_ALERT_DEDUP_DEFAULT: Duration = Duration::from_secs(600);
const WALRUS_GAS_POOL_ALERT_DEDUP_SECS_ENV: &str = "WALRUS_GAS_POOL_ALERT_DEDUP_SECS";
const WALRUS_GAS_POOL_ALERT_DEDUP_DEFAULT: Duration = Duration::from_secs(600);
const WALRUS_LOW_BALANCE_ALERT_DEDUP_SECS_ENV: &str = "WALRUS_LOW_BALANCE_ALERT_DEDUP_SECS";
const WALRUS_LOW_BALANCE_ALERT_DEDUP_DEFAULT: Duration = Duration::from_secs(600);
const WALRUS_QUEUE_SATURATION_ALERT_DEDUP_SECS_ENV: &str =
    "WALRUS_QUEUE_SATURATION_ALERT_DEDUP_SECS";
const WALRUS_QUEUE_SATURATION_ALERT_DEDUP_DEFAULT: Duration = Duration::from_secs(1800);
const WALLET_BALANCE_LOW_ALERT_DEDUP_SECS_ENV: &str = "WALLET_BALANCE_LOW_ALERT_DEDUP_SECS";
const WALLET_BALANCE_LOW_ALERT_DEDUP_DEFAULT: Duration = Duration::from_secs(43200);
const POSTGRES_STORAGE_ALERT_DEDUP_SECS_ENV: &str = "POSTGRES_STORAGE_ALERT_DEDUP_SECS";
const POSTGRES_STORAGE_ALERT_DEDUP_DEFAULT: Duration = Duration::from_secs(1800);
const EMBEDDING_PROVIDER_ALERT_DEDUP_SECS_ENV: &str = "EMBEDDING_PROVIDER_ALERT_DEDUP_SECS";
const EMBEDDING_PROVIDER_ALERT_DEDUP_DEFAULT: Duration = Duration::from_secs(600);
// A failed provider request must not wait for the shared HTTP client's 30s deadline.
const EMBEDDING_PROVIDER_ALERT_TIMEOUT: Duration = Duration::from_secs(1);

/// Mirrors the `@mysten/walrus` dep version in
/// `services/server/scripts/package.json`. Bump this constant in lockstep
/// when bumping the sidecar dep so the Slack alert reports the actual
/// runtime version, not a stale label.
pub const SIDECAR_WALRUS_DEP_VERSION: &str = "1.1.7";

/// Time-window dedup keyed by a `(String, String)` identity. Suppresses
/// duplicate alerts for the same logical event during a burst.
#[derive(Debug)]
struct AlertDedup {
    seen: Mutex<HashMap<(String, String), Instant>>,
    window: Duration,
}

impl AlertDedup {
    fn new(window: Duration) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            window,
        }
    }

    /// Returns `true` if an alert with this key fired within the window —
    /// caller should drop it. On the firing path (returns `false`) the entry
    /// is stamped to `now`, so the window slides from the most-recent fire.
    fn should_suppress(&self, key: (String, String)) -> bool {
        let now = Instant::now();
        let mut guard = self.seen.lock().expect("dedup mutex poisoned");
        // Opportunistic cleanup so the map can't grow without bound on a
        // long-running relayer: drop entries older than 2× the window.
        let cleanup_horizon = self.window.saturating_mul(2);
        guard.retain(|_, fired_at| {
            now.checked_duration_since(*fired_at)
                .map(|elapsed| elapsed < cleanup_horizon)
                .unwrap_or(true)
        });
        if let Some(fired_at) = guard.get(&key) {
            if let Some(elapsed) = now.checked_duration_since(*fired_at) {
                if elapsed < self.window {
                    return true;
                }
            }
        }
        guard.insert(key, now);
        false
    }
}

#[derive(Debug)]
pub struct AlertManager {
    slack: Option<SlackNotifier>,
    /// Suppresses Walrus package-upgrade alert spam during an upgrade burst.
    /// Keyed by `(sui_network, sidecar_walrus_dep_version)` — concurrent queued
    /// jobs all hit EWrongVersion against the same on-chain package change, so
    /// one notification per (network, dep) is enough until the dep bumps or the
    /// window elapses.
    walrus_upgrade_dedup: AlertDedup,
    /// Suppresses Walrus object-lock alert spam. Keyed by
    /// `(sui_network, locked_object_id)` — when one owned object equivocates,
    /// every concurrent job touching it raises the same error, so one
    /// notification per (network, object) is enough until the window elapses.
    walrus_object_lock_dedup: AlertDedup,
    /// Suppresses Walrus gas-pool alert spam. A gas-pool starvation is
    /// pool-wide, so every concurrent upload job raises the same
    /// `balance::split` ENotEnough — one notification per network is enough
    /// until ops tops up gas or the window elapses.
    walrus_gas_pool_dedup: AlertDedup,
    /// Suppresses low-WAL balance spam. WAL shortfalls are wallet-specific;
    /// one alert per (network, wallet_index) per window is enough.
    walrus_low_balance_dedup: AlertDedup,
    /// Suppresses upload-queue saturation spam. Saturation is pipeline-wide
    /// and the monitor keeps polling every interval while the backlog lasts,
    /// so one notification per network per window is enough.
    walrus_queue_saturation_dedup: AlertDedup,
    /// Suppresses wallet balance low spam. Keyed by `(wallet_type:token, address)`
    /// so WAL and SUI can each alert once for the same wallet per dedup window.
    wallet_balance_low_dedup: AlertDedup,
    /// Suppresses Postgres disk / Neon project-size-cap spam. The failure is
    /// cluster-wide, so one notification per network per window — not per job.
    postgres_storage_dedup: AlertDedup,
    /// Suppresses embedding/LLM provider auth or billing alert spam (401/402/403).
    /// Keyed per network so a revoked or exhausted `OPENAI_API_KEY` pages once
    /// per dedup window instead of spamming on every recall/embed/remember call.
    embedding_provider_dedup: AlertDedup,
}

impl AlertManager {
    pub fn from_env(http_client: reqwest::Client) -> Self {
        let webhook_raw = std::env::var(ALERT_TO_SLACK_ENV).ok();
        Self::from_webhook_value(http_client, webhook_raw.as_deref())
    }

    pub fn from_webhook_value(http_client: reqwest::Client, webhook_raw: Option<&str>) -> Self {
        let slack = webhook_raw.and_then(|raw| SlackNotifier::from_env_value(http_client, raw));

        Self {
            slack,
            walrus_upgrade_dedup: AlertDedup::new(dedup_window_from_env(
                WALRUS_UPGRADE_ALERT_DEDUP_SECS_ENV,
                WALRUS_UPGRADE_ALERT_DEDUP_DEFAULT,
            )),
            walrus_object_lock_dedup: AlertDedup::new(dedup_window_from_env(
                WALRUS_OBJECT_LOCK_ALERT_DEDUP_SECS_ENV,
                WALRUS_OBJECT_LOCK_ALERT_DEDUP_DEFAULT,
            )),
            walrus_gas_pool_dedup: AlertDedup::new(dedup_window_from_env(
                WALRUS_GAS_POOL_ALERT_DEDUP_SECS_ENV,
                WALRUS_GAS_POOL_ALERT_DEDUP_DEFAULT,
            )),
            walrus_low_balance_dedup: AlertDedup::new(dedup_window_from_env(
                WALRUS_LOW_BALANCE_ALERT_DEDUP_SECS_ENV,
                WALRUS_LOW_BALANCE_ALERT_DEDUP_DEFAULT,
            )),
            walrus_queue_saturation_dedup: AlertDedup::new(dedup_window_from_env(
                WALRUS_QUEUE_SATURATION_ALERT_DEDUP_SECS_ENV,
                WALRUS_QUEUE_SATURATION_ALERT_DEDUP_DEFAULT,
            )),
            wallet_balance_low_dedup: AlertDedup::new(dedup_window_from_env(
                WALLET_BALANCE_LOW_ALERT_DEDUP_SECS_ENV,
                WALLET_BALANCE_LOW_ALERT_DEDUP_DEFAULT,
            )),
            postgres_storage_dedup: AlertDedup::new(dedup_window_from_env(
                POSTGRES_STORAGE_ALERT_DEDUP_SECS_ENV,
                POSTGRES_STORAGE_ALERT_DEDUP_DEFAULT,
            )),
            embedding_provider_dedup: AlertDedup::new(dedup_window_from_env(
                EMBEDDING_PROVIDER_ALERT_DEDUP_SECS_ENV,
                EMBEDDING_PROVIDER_ALERT_DEDUP_DEFAULT,
            )),
        }
    }

    pub fn slack_enabled(&self) -> bool {
        self.slack.is_some()
    }

    pub async fn notify_walrus_upload_exhausted(
        &self,
        alert: WalrusUploadExhaustedAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        let payload = SlackPayload::for_walrus_upload_exhausted(&alert);
        slack.send_payload(&payload).await
    }

    pub async fn notify_walrus_package_upgrade_detected(
        &self,
        alert: WalrusPackageUpgradeDetectedAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        let key = (
            alert.sui_network.clone(),
            alert.sidecar_walrus_dep_version.clone(),
        );
        if self.walrus_upgrade_dedup.should_suppress(key) {
            return Ok(());
        }
        let payload = SlackPayload::for_walrus_package_upgrade_detected(&alert);
        slack.send_payload(&payload).await
    }

    pub async fn notify_walrus_object_locked(
        &self,
        alert: WalrusObjectLockedAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        // Dedup per (network, object). When object id is unparseable, fall back
        // to a constant so a burst of unparseable locks still collapses to one
        // alert per network rather than spamming.
        let key = (
            alert.sui_network.clone(),
            alert
                .locked_object_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        );
        if self.walrus_object_lock_dedup.should_suppress(key) {
            return Ok(());
        }
        let payload = SlackPayload::for_walrus_object_locked(&alert);
        slack.send_payload(&payload).await
    }

    pub async fn notify_walrus_gas_pool_exhausted(
        &self,
        alert: WalrusGasPoolExhaustedAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        // Gas-pool starvation is pool-wide: dedup per network so a burst of
        // concurrent jobs collapses to one ops notification per window.
        let key = (alert.sui_network.clone(), "gas_pool".to_string());
        if self.walrus_gas_pool_dedup.should_suppress(key) {
            return Ok(());
        }
        let payload = SlackPayload::for_walrus_gas_pool_exhausted(&alert);
        slack.send_payload(&payload).await
    }

    pub async fn notify_walrus_low_wal_balance(
        &self,
        alert: WalrusWalletBalanceLowAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        // Duplicate key is per network + wallet so repeated low-balance hits
        // from the same wallet collapse while still surfacing across wallets.
        let key = (
            alert.sui_network.clone(),
            format!("wallet-{}", alert.wallet_index),
        );
        if self.walrus_low_balance_dedup.should_suppress(key) {
            return Ok(());
        }
        let payload = SlackPayload::for_walrus_low_wal_balance(&alert);
        slack.send_payload(&payload).await
    }

    pub async fn notify_walrus_upload_queue_saturated(
        &self,
        alert: WalrusUploadQueueSaturatedAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        // Saturation is pipeline-wide: one notification per network per
        // window — the monitor re-fires after the dedup window elapses if
        // the backlog is still there.
        let key = (
            alert.sui_network.clone(),
            "upload_queue_saturated".to_string(),
        );
        if self.walrus_queue_saturation_dedup.should_suppress(key) {
            return Ok(());
        }
        let payload = SlackPayload::for_walrus_upload_queue_saturated(&alert);
        slack.send_payload(&payload).await
    }

    pub async fn notify_wallet_balance_low(
        &self,
        alert: WalletBalanceLowAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        // Dedup by the full address; abbreviating here could make two distinct
        // wallets with the same prefix/suffix suppress each other's alerts.
        if self.should_suppress_wallet_balance_low(&alert) {
            return Ok(());
        }
        let payload = SlackPayload::for_wallet_balance_low(&alert);
        slack.send_payload(&payload).await
    }

    pub async fn notify_postgres_storage_exhausted(
        &self,
        alert: PostgresStorageExhaustedAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        // Cluster-wide cap: one notification per network per window. Concurrent
        // remember/analyze jobs all hit the same Neon/Postgres size limit.
        if self
            .postgres_storage_dedup
            .should_suppress(postgres_storage_dedup_key(&alert.sui_network))
        {
            return Ok(());
        }
        let payload = SlackPayload::for_postgres_storage_exhausted(&alert);
        slack.send_payload(&payload).await
    }

    pub async fn notify_embedding_provider_auth_failed(
        &self,
        alert: EmbeddingProviderAuthAlert,
    ) -> Result<(), AlertError> {
        let Some(slack) = &self.slack else {
            return Ok(());
        };
        if self.should_suppress_embedding_provider_auth(&alert) {
            return Ok(());
        }
        let payload = SlackPayload::for_embedding_provider_auth_failed(&alert);
        tokio::time::timeout(
            EMBEDDING_PROVIDER_ALERT_TIMEOUT,
            slack.send_payload(&payload),
        )
        .await
        .map_err(|_| AlertError::Transport("embedding provider alert delivery timed out".into()))?
    }

    fn should_suppress_wallet_balance_low(&self, alert: &WalletBalanceLowAlert) -> bool {
        self.wallet_balance_low_dedup
            .should_suppress(wallet_balance_low_dedup_key(alert))
    }

    pub(crate) fn should_suppress_embedding_provider_auth(
        &self,
        alert: &EmbeddingProviderAuthAlert,
    ) -> bool {
        self.embedding_provider_dedup
            .should_suppress(embedding_provider_dedup_key(&alert.sui_network))
    }
}

fn wallet_balance_low_dedup_key(alert: &WalletBalanceLowAlert) -> (String, String) {
    (
        format!(
            "{}:{}:{}",
            alert.sui_network, alert.wallet_type, alert.token
        ),
        alert.address.clone(),
    )
}

fn postgres_storage_dedup_key(sui_network: &str) -> (String, String) {
    (sui_network.to_string(), "postgres-storage".to_string())
}

fn embedding_provider_dedup_key(sui_network: &str) -> (String, String) {
    (
        sui_network.to_string(),
        "embedding-provider-auth".to_string(),
    )
}

/// True when Postgres (or Neon) refused a write because the disk / project
/// size cap is exhausted. Matches the prod Neon message
/// `could not extend file because project size limit (3072 MB) has been exceeded`
/// plus vanilla `no space left on device`. sqlx 0.8 `Display` is message-only,
/// so SQLSTATE `53100` is matched via `DatabaseError::code` — not as a
/// substring of the message.
pub fn is_postgres_storage_exhausted(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("could not extend file")
        || lower.contains("project size limit")
        || lower.contains("no space left on device")
}

pub fn sqlx_error_is_postgres_storage_exhausted(err: &sqlx::Error) -> bool {
    if let Some(db) = err.as_database_error() {
        if db.code().as_deref() == Some("53100") {
            return true;
        }
        if is_postgres_storage_exhausted(db.message()) {
            return true;
        }
    }
    is_postgres_storage_exhausted(&err.to_string())
}

/// Slack the cluster-wide disk / Neon size-cap incident when `err` is
/// SQLSTATE `53100` or matches the string classifier.
pub async fn maybe_alert_sqlx_postgres_storage_exhausted(
    alerts: &AlertManager,
    sui_network: &str,
    err: &sqlx::Error,
) {
    if !sqlx_error_is_postgres_storage_exhausted(err) {
        return;
    }
    let alert = PostgresStorageExhaustedAlert {
        sui_network: sui_network.to_string(),
        error: err.to_string(),
    };
    if let Err(alert_err) = alerts.notify_postgres_storage_exhausted(alert).await {
        tracing::warn!(
            "failed to send Slack alert for Postgres storage exhaustion: {}",
            alert_err
        );
    }
}

/// Read a dedup window (seconds) from `env_var`, falling back to `default`
/// when unset, unparseable, or zero.
fn dedup_window_from_env(env_var: &str, default: Duration) -> Duration {
    std::env::var(env_var)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(default)
}

#[derive(Clone, Debug)]
struct SlackNotifier {
    http_client: reqwest::Client,
    webhook_url: String,
}

impl SlackNotifier {
    fn from_env_value(http_client: reqwest::Client, raw: &str) -> Option<Self> {
        let value = raw.trim();
        if value.is_empty() || is_disabled_env_value(value) {
            return None;
        }

        Some(Self {
            http_client,
            webhook_url: value.to_string(),
        })
    }

    async fn send_payload(&self, payload: &SlackPayload) -> Result<(), AlertError> {
        let resp = self
            .http_client
            .post(&self.webhook_url)
            .json(payload)
            .send()
            .await
            .map_err(|err| AlertError::Transport(err.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AlertError::HttpStatus {
                status: status.as_u16(),
                body: truncate(&body, 500),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WalrusUploadExhaustedAlert {
    pub remember_job_id: Option<String>,
    pub owner: String,
    pub namespace: String,
    pub attempt: usize,
    pub max_attempts: usize,
    pub wallet_index: usize,
    pub configured_wallets: usize,
    pub sui_network: String,
    pub error: String,
}

/// Fired when the TS sidecar surfaces a MoveAbort from
/// `walrus::system::inner_mut` (EWrongVersion = abort code 1). This means the
/// on-chain Walrus package was upgraded after the sidecar booted, and the
/// cached `@mysten/walrus` client is carrying stale package metadata.
///
/// The sidecar auto-recovers by recreating the client (sidecar logs
/// `[walrus/client] refreshed reason=walrus_package_version_mismatch`), and
/// the next Apalis retry succeeds. This alert is informational — it tells
/// the team that a Walrus on-chain upgrade just affected the upload path so
/// they can verify `@mysten/walrus` dep version is current.
#[derive(Debug, Clone)]
pub struct WalrusPackageUpgradeDetectedAlert {
    pub remember_job_id: Option<String>,
    pub owner: Option<String>,
    pub namespace: Option<String>,
    pub sui_network: String,
    pub sidecar_walrus_dep_version: String,
    pub on_chain_version_before: Option<String>,
    pub on_chain_version_after: Option<String>,
    pub action_taken: String,
    pub error: String,
}

/// Fired when a wallet job fails because a Sui owned object/version is locked
/// to a competing transaction (equivocation / ">1/3 of validators …
/// non-retriable"). Distinct from the "exhausted retries" alert: this case
/// aborts immediately rather than burning the wallet budget, and the on-call
/// message must name the real cause and surface the locked object + locking
/// transaction so they can check lock status / wait for the epoch boundary.
#[derive(Debug)]
pub struct WalrusObjectLockedAlert {
    pub remember_job_id: Option<String>,
    pub owner: Option<String>,
    pub namespace: Option<String>,
    pub sui_network: String,
    pub locked_object_id: Option<String>,
    pub locked_object_version: Option<String>,
    pub locking_transaction_digest: Option<String>,
    pub error: String,
}

/// Fired when a wallet job aborts because an Enoki sponsored dry-run failed in
/// `0x2::balance::split` with ENotEnough — the relayer pool wallets' SUI gas
/// coins are fragmented or too small to cover the sponsored budget. Distinct
/// from the "exhausted retries" alert: this aborts immediately rather than
/// burning the whole pool, and the on-call message must point ops at SUI gas
/// coin consolidation/top-up rather than implying an app bug.
#[derive(Debug)]
pub struct WalrusGasPoolExhaustedAlert {
    pub remember_job_id: Option<String>,
    pub owner: Option<String>,
    pub namespace: Option<String>,
    pub sui_network: String,
    pub wallet_index: usize,
    pub configured_wallets: usize,
    pub error: String,
}

/// Fired when the sidecar's Walrus upload queue stays saturated — every
/// upload slot busy AND more than `threshold` requests queued — for several
/// consecutive monitor checks. This is the early-warning for the
/// 2026-06-10-style incident: inflow exceeds the wallet pool's upload
/// throughput, and once queued requests outlive the sidecar's acquire
/// timeout, jobs start failing with "timed out waiting for wallet N upload
/// slot". Action: check for a bulk-write burst, and/or add wallets to
/// `SERVER_SUI_PRIVATE_KEYS` (throughput scales linearly with pool size).
#[derive(Debug)]
pub struct WalrusUploadQueueSaturatedAlert {
    pub sui_network: String,
    pub queued: u64,
    pub active: u64,
    pub global_capacity: u64,
    pub threshold: u64,
    pub consecutive_checks: u32,
}

#[derive(Debug)]
pub struct WalrusWalletBalanceLowAlert {
    pub remember_job_id: Option<String>,
    pub owner: Option<String>,
    pub namespace: Option<String>,
    pub sui_network: String,
    pub available: u64,
    pub required: Option<u64>,
    pub threshold: u64,
    pub wallet_index: usize,
    pub configured_wallets: usize,
    pub error: String,
}

/// Fired when a wallet balance falls below a configured threshold during
/// proactive monitoring (not during a transaction failure). This is a
/// forward-looking alert distinct from the in-flight Walrus job failures.
#[derive(Debug, Clone)]
pub struct WalletBalanceLowAlert {
    pub wallet_type: String,
    pub address: String,
    pub balance: u64,
    pub threshold: u64,
    pub token: String,
    pub sui_network: String,
    pub wallet_index: Option<usize>,
}

/// Fired when Postgres cannot extend a file — Neon `project size limit`
/// / SQLSTATE `53100` / `no space left on device`. Cluster-wide, not a
/// per-user storage quota.
#[derive(Debug, Clone)]
pub struct PostgresStorageExhaustedAlert {
    pub sui_network: String,
    pub error: String,
}

/// Fired when the upstream embedding/LLM provider returns HTTP 401, 402, or 403
/// (invalid/revoked `OPENAI_API_KEY` or exhausted provider credits).
#[derive(Debug, Clone)]
pub struct EmbeddingProviderAuthAlert {
    pub sui_network: String,
    pub status: u16,
    pub api_base: String,
    pub error: String,
}

#[derive(Debug)]
pub enum AlertError {
    Transport(String),
    HttpStatus { status: u16, body: String },
}

impl std::fmt::Display for AlertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertError::Transport(err) => write!(f, "alert transport error: {}", err),
            AlertError::HttpStatus { status, body } => {
                write!(f, "alert webhook returned HTTP {}: {}", status, body)
            }
        }
    }
}

impl std::error::Error for AlertError {}

#[derive(Serialize)]
struct SlackPayload {
    text: String,
    blocks: Vec<SlackBlock>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum SlackBlock {
    #[serde(rename = "header")]
    Header { text: SlackText },
    #[serde(rename = "section")]
    Section { text: SlackText },
}

#[derive(Serialize)]
struct SlackText {
    #[serde(rename = "type")]
    kind: &'static str,
    text: String,
}

impl SlackPayload {
    fn for_walrus_package_upgrade_detected(alert: &WalrusPackageUpgradeDetectedAlert) -> Self {
        let title = "MemWal Walrus on-chain package upgrade detected".to_string();
        let summary = format!(
            "Walrus package upgrade detected on {}; sidecar auto-recovered. Verify @mysten/walrus dep version is current.",
            alert.sui_network,
        );
        let job = alert.remember_job_id.as_deref().unwrap_or("-");
        let owner = alert
            .owner
            .as_deref()
            .map(short_address)
            .unwrap_or_else(|| "-".to_string());
        let namespace = alert.namespace.as_deref().unwrap_or("-");
        let version_line = match (
            alert.on_chain_version_before.as_deref(),
            alert.on_chain_version_after.as_deref(),
        ) {
            (Some(before), Some(after)) => {
                format!("*On-chain system version:* `{}` → `{}`\n", before, after)
            }
            (None, Some(after)) => {
                format!("*On-chain system version (after refresh):* `{}`\n", after)
            }
            (Some(before), None) => {
                format!("*On-chain system version (before refresh):* `{}`\n", before)
            }
            (None, None) => String::new(),
        };
        let details = format!(
            "*Network:* `{}`\n*Sidecar @mysten/walrus dep:* `{}`\n{}*Action taken:* {}\n*Job:* `{}`\n*Owner:* `{}`\n*Namespace:* `{}`\n*Original error:* ```{}```",
            alert.sui_network,
            alert.sidecar_walrus_dep_version,
            version_line,
            alert.action_taken,
            job,
            owner,
            namespace,
            truncate(&alert.error, MAX_SLACK_ERROR_LEN),
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }

    fn for_walrus_upload_exhausted(alert: &WalrusUploadExhaustedAlert) -> Self {
        let job = alert.remember_job_id.as_deref().unwrap_or("-");
        let title = "MemWal Walrus upload exhausted retries".to_string();
        let summary = format!(
            "Walrus upload failed after {}/{} wallet attempt(s) for job {}.",
            alert.attempt, alert.max_attempts, job
        );
        let details = format!(
            "*Job:* `{}`\n*Owner:* `{}`\n*Namespace:* `{}`\n*Network:* `{}`\n*Wallet index:* `{}`\n*Configured wallets:* `{}`\n*Error:* ```{}```",
            job,
            short_address(&alert.owner),
            alert.namespace,
            alert.sui_network,
            alert.wallet_index,
            alert.configured_wallets,
            truncate(&alert.error, MAX_SLACK_ERROR_LEN),
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }

    fn for_walrus_object_locked(alert: &WalrusObjectLockedAlert) -> Self {
        let title = "MemWal Walrus upload blocked — Sui object lock".to_string();
        let summary = format!(
            "Walrus upload hit a Sui owned-object lock / equivocation on {}. \
             Not retried (would re-fail against the same locked object); the lock \
             typically clears at the next epoch boundary.",
            alert.sui_network,
        );
        let object = alert.locked_object_id.as_deref().unwrap_or("unparsed");
        let version = alert.locked_object_version.as_deref().unwrap_or("unparsed");
        let locking = alert
            .locking_transaction_digest
            .as_deref()
            .unwrap_or("unparsed");
        let job = alert.remember_job_id.as_deref().unwrap_or("-");
        let owner = alert
            .owner
            .as_deref()
            .map(short_address)
            .unwrap_or_else(|| "-".to_string());
        let namespace = alert.namespace.as_deref().unwrap_or("-");
        let details = format!(
            "*Network:* `{}`\n*Locked object:* `{}`\n*Object version:* `{}`\n*Locked by tx:* `{}`\n*Job:* `{}`\n*Owner:* `{}`\n*Namespace:* `{}`\n*Error:* ```{}```",
            alert.sui_network,
            object,
            version,
            locking,
            job,
            owner,
            namespace,
            truncate(&alert.error, MAX_SLACK_ERROR_LEN),
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }

    fn for_walrus_gas_pool_exhausted(alert: &WalrusGasPoolExhaustedAlert) -> Self {
        let title = "MemWal Walrus upload blocked — SUI gas pool maintenance".to_string();
        let summary = format!(
            "Walrus upload aborted on {}: Enoki sponsored dry-run failed in \
             `0x2::balance::split` (ENotEnough). The relayer pool wallets' SUI \
             gas coins are fragmented or too small to cover the sponsored budget. \
             Not retried — retrying just rotates to the next starved pool wallet.",
            alert.sui_network,
        );
        let action = "*Action (ops):* consolidate/merge SUI gas coins on the \
             relayer pool wallets and top up SUI if low. See the gas-pool runbook."
            .to_string();
        let job = alert.remember_job_id.as_deref().unwrap_or("-");
        let owner = alert
            .owner
            .as_deref()
            .map(short_address)
            .unwrap_or_else(|| "-".to_string());
        let namespace = alert.namespace.as_deref().unwrap_or("-");
        let details = format!(
            "*Network:* `{}`\n*Pool wallet:* `{}` of `{}`\n*Job:* `{}`\n*Owner:* `{}`\n*Namespace:* `{}`\n*Error:* ```{}```",
            alert.sui_network,
            alert.wallet_index,
            alert.configured_wallets,
            job,
            owner,
            namespace,
            truncate(&alert.error, MAX_SLACK_ERROR_LEN),
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(action),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }

    fn for_walrus_upload_queue_saturated(alert: &WalrusUploadQueueSaturatedAlert) -> Self {
        let title = "MemWal Walrus upload queue saturated".to_string();
        let summary = format!(
            "Sidecar upload queue on {} has {} request(s) waiting (threshold {}) with all {} upload slot(s) busy for {} consecutive checks. \
             If this persists, queued uploads will start timing out (\"timed out waiting for wallet N upload slot\").",
            alert.sui_network,
            alert.queued,
            alert.threshold,
            alert.global_capacity,
            alert.consecutive_checks,
        );
        let action = "*Action (ops):* check for a bulk-write burst (sidecar `[walrus/upload] begin` rate vs ~3 uploads/min/wallet drain), \
and/or add wallets to `SERVER_SUI_PRIVATE_KEYS` — upload throughput scales linearly with pool size. \
Congestion-requeued jobs ride it out with minutes-scale backoff, but sustained saturation will eventually exhaust them."
            .to_string();
        let details = format!(
            "*Network:* `{}`\n*Queued uploads:* `{}`\n*Active uploads:* `{}`\n*Global capacity:* `{}`\n*Threshold:* `{}`\n*Consecutive checks:* `{}`",
            alert.sui_network,
            alert.queued,
            alert.active,
            alert.global_capacity,
            alert.threshold,
            alert.consecutive_checks,
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(action),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }

    fn for_walrus_low_wal_balance(alert: &WalrusWalletBalanceLowAlert) -> Self {
        let title = "MemWal Walrus upload blocked — insufficient WAL".to_string();
        let available_wal = format_wal_amount(alert.available);
        let threshold_wal = format_wal_amount(alert.threshold);
        let required_line = alert
            .required
            .map(|required| format!("*Required:* {} WAL\n", format_wal_amount(required)))
            .unwrap_or_default();
        let action = "*Action (ops):* top up WAL for this relayer wallet before retrying.
If the wallet is being topped up, rotate or temporarily remove that key from pool to keep uploads flowing."
            .to_string();
        let summary = format!(
            "Walrus operation blocked on {}: wallet ({}) has only {} WAL available, below the alert threshold of {} WAL.\n",
            alert.sui_network,
            alert.wallet_index,
            available_wal,
            threshold_wal,
        );
        let job = alert.remember_job_id.as_deref().unwrap_or("-");
        let owner = alert
            .owner
            .as_deref()
            .map(short_address)
            .unwrap_or_else(|| "-".to_string());
        let namespace = alert.namespace.as_deref().unwrap_or("-");
        let details = format!(
            "*Network:* `{}`\n*Wallet:* `{}` of `{}`\n*Job:* `{}`\n*Owner:* `{}`\n*Namespace:* `{}`\n{}*Available:* `{}` WAL\n*Error:* ```{}```",
            alert.sui_network,
            alert.wallet_index,
            alert.configured_wallets,
            job,
            owner,
            namespace,
            required_line,
            available_wal,
            truncate(&alert.error, MAX_SLACK_ERROR_LEN),
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(action),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }

    fn for_wallet_balance_low(alert: &WalletBalanceLowAlert) -> Self {
        let title = format!(
            "⚠️ Wallet Balance Low: {} {}",
            alert.wallet_type, alert.token
        );
        let abbrev_address = short_address(&alert.address);
        let balance_amount = format_token_amount(alert.balance);
        let threshold_amount = format_token_amount(alert.threshold);
        let percent_remaining = if alert.threshold > 0 {
            (alert.balance as f64 / alert.threshold as f64) * 100.0
        } else {
            0.0
        };
        let summary = format!(
            "Wallet balance alert on {}: {} balance is {} {}, below threshold of {} {} ({:.1}% remaining)",
            alert.sui_network, abbrev_address, balance_amount, alert.token, threshold_amount, alert.token, percent_remaining
        );
        let action = format!(
            "*Action (ops):* Top up the {} wallet at {} with {} tokens.",
            alert.wallet_type, abbrev_address, alert.token
        );
        let wallet_index = alert
            .wallet_index
            .map(|index| index.to_string())
            .unwrap_or_else(|| "-".to_string());
        let details = format!(
            "*Network:* `{}`\n*Wallet type:* `{}`\n*Wallet index:* `{}`\n*Address:* `{}`\n*Address balance:* {} {}\n*Threshold:* {} {}\n*Remaining:* {:.1}%",
            alert.sui_network,
            alert.wallet_type,
            wallet_index,
            alert.address,
            balance_amount,
            alert.token,
            threshold_amount,
            alert.token,
            percent_remaining
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(action),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }

    fn for_postgres_storage_exhausted(alert: &PostgresStorageExhaustedAlert) -> Self {
        let title = "MemWal Postgres storage exhausted".to_string();
        let summary = format!(
            "Postgres cannot accept writes on {}: the database disk/project size cap has been reached. \
             Writes (remember/analyze) are failing. GET /health write_ready will be false. \
             This is the database disk/project size cap, not a user quota; do not tell users to send SUI/WAL.",
            alert.sui_network,
        );
        let action = "*Action (ops):* raise the Neon project size limit or reclaim disk. \
This is not a per-user storage quota and is not a Walrus/SUI/WAL funding issue."
            .to_string();
        let details = format!(
            "*Network:* `{}`\n*Error:* ```{}```",
            alert.sui_network,
            truncate(&alert.error, MAX_SLACK_ERROR_LEN),
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(action),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }

    fn for_embedding_provider_auth_failed(alert: &EmbeddingProviderAuthAlert) -> Self {
        let title = "MemWal embedding provider credential/quota error".to_string();
        let summary = format!(
            "Upstream embedding/LLM provider returned HTTP {} on {}. \
             Recall, embed, analyze, and remember preparation are returning HTTP 503 (`EMBEDDING_PROVIDER_UNAVAILABLE`).",
            alert.status, alert.sui_network,
        );
        let action = "*Action (ops):* check and rotate `OPENAI_API_KEY` / top up OpenRouter or OpenAI provider credits."
            .to_string();
        let details = format!(
            "*Network:* `{}`\n*HTTP status:* `{}`\n*Provider base:* `{}`\n*Error:* ```{}```",
            alert.sui_network,
            alert.status,
            alert.api_base,
            truncate(&alert.error, MAX_SLACK_ERROR_LEN),
        );

        Self {
            text: summary.clone(),
            blocks: vec![
                SlackBlock::Header {
                    text: plain_text(title),
                },
                SlackBlock::Section {
                    text: mrkdwn(summary),
                },
                SlackBlock::Section {
                    text: mrkdwn(action),
                },
                SlackBlock::Section {
                    text: mrkdwn(details),
                },
            ],
        }
    }
}

fn plain_text(text: String) -> SlackText {
    SlackText {
        kind: "plain_text",
        text,
    }
}

fn mrkdwn(text: String) -> SlackText {
    SlackText {
        kind: "mrkdwn",
        text,
    }
}

fn is_disabled_env_value(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn short_address(address: &str) -> String {
    if address.len() <= 18 {
        return address.to_string();
    }
    format!("{}...{}", &address[..10], &address[address.len() - 6..])
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }

    format!("{}...", value.chars().take(max_len).collect::<String>())
}

fn format_wal_amount(mist: u64) -> String {
    let integer = mist / 1_000_000_000;
    let mut fractional = format!("{:09}", mist % 1_000_000_000);

    while fractional.ends_with('0') {
        fractional.pop();
    }

    if fractional.is_empty() {
        format!("{}.0", integer)
    } else {
        format!("{}.{}", integer, fractional)
    }
}

/// Format a token amount (mist/frost) to human-readable form.
/// Generic for any token that uses 9 decimal places (SUI, WAL, etc).
fn format_token_amount(mist: u64) -> String {
    let integer = mist / 1_000_000_000;
    let mut fractional = format!("{:09}", mist % 1_000_000_000);

    while fractional.ends_with('0') {
        fractional.pop();
    }

    if fractional.is_empty() {
        format!("{}.0", integer)
    } else {
        format!("{}.{}", integer, fractional)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_env_values_do_not_enable_slack() {
        let client = reqwest::Client::new();
        for raw in ["", "0", "false", "no", "off"] {
            assert!(SlackNotifier::from_env_value(client.clone(), raw).is_none());
        }
    }

    #[test]
    fn webhook_env_value_enables_slack() {
        let client = reqwest::Client::new();
        let notifier =
            SlackNotifier::from_env_value(client, "https://hooks.slack.com/services/T/B/C");
        assert!(notifier.is_some());
    }

    #[test]
    fn slack_payload_contains_upload_context() {
        let payload = SlackPayload::for_walrus_upload_exhausted(&WalrusUploadExhaustedAlert {
            remember_job_id: Some("job-1".into()),
            owner: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
            namespace: "default".into(),
            attempt: 5,
            max_attempts: 5,
            wallet_index: 4,
            configured_wallets: 5,
            sui_network: "mainnet".into(),
            error: "walrus upload failed".into(),
        });

        assert!(payload.text.contains("5/5"));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("job-1"));
        assert!(json.contains("default"));
        assert!(json.contains("mainnet"));
        assert!(json.contains("walrus upload failed"));
    }

    #[test]
    fn walrus_queue_saturated_payload_surfaces_queue_state_and_action() {
        let payload =
            SlackPayload::for_walrus_upload_queue_saturated(&WalrusUploadQueueSaturatedAlert {
                sui_network: "mainnet".into(),
                queued: 116,
                active: 5,
                global_capacity: 5,
                threshold: 20,
                consecutive_checks: 4,
            });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("mainnet"));
        assert!(json.contains("116"));
        assert!(json.contains("20"));
        // Ops action must point at pool sizing, not at a job bug.
        assert!(json.contains("SERVER_SUI_PRIVATE_KEYS"));
        // Early-warning copy explains what happens if the backlog persists.
        assert!(json.contains("timed out waiting for wallet"));
    }

    #[test]
    fn walrus_package_upgrade_payload_includes_version_diff() {
        let payload =
            SlackPayload::for_walrus_package_upgrade_detected(&WalrusPackageUpgradeDetectedAlert {
                remember_job_id: Some("job-42".into()),
                owner: Some(
                    "0xabc1234567890abcdef1234567890abcdef1234567890abcdef1234567890def0".into(),
                ),
                namespace: Some("notes".into()),
                sui_network: "mainnet".into(),
                sidecar_walrus_dep_version: "1.1.7".into(),
                on_chain_version_before: Some("3".into()),
                on_chain_version_after: Some("4".into()),
                action_taken: "Sidecar refreshed cached client; Apalis will retry.".into(),
                error: "MoveAbort in 1st command, abort code: 1, in '0xc1b6::system::inner_mut' (instruction 0)".into(),
            });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("mainnet"));
        assert!(json.contains("1.1.7"));
        assert!(json.contains("job-42"));
        assert!(json.contains("notes"));
        assert!(json.contains("inner_mut"));
        // version-diff line must show both ends
        assert!(json.contains("3"));
        assert!(json.contains("4"));
        // action narrative present
        assert!(json.contains("refreshed"));
    }

    #[test]
    fn walrus_package_upgrade_payload_handles_missing_version_data() {
        // RPC may be down in the error path → both versions null. Payload still ships.
        let payload =
            SlackPayload::for_walrus_package_upgrade_detected(&WalrusPackageUpgradeDetectedAlert {
                remember_job_id: None,
                owner: None,
                namespace: None,
                sui_network: "testnet".into(),
                sidecar_walrus_dep_version: SIDECAR_WALRUS_DEP_VERSION.into(),
                on_chain_version_before: None,
                on_chain_version_after: None,
                action_taken: "n/a".into(),
                error: "MoveAbort EWrongVersion".into(),
            });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("testnet"));
        assert!(json.contains("EWrongVersion"));
        // owner / job / namespace fall back to "-"
        assert!(json.contains("`-`"));
    }

    #[test]
    fn walrus_package_upgrade_payload_truncates_oversized_error() {
        // Slack error block uses MAX_SLACK_ERROR_LEN truncation — make sure that
        // contract still holds for the new payload formatter.
        let huge_error = "X".repeat(MAX_SLACK_ERROR_LEN * 2);
        let payload =
            SlackPayload::for_walrus_package_upgrade_detected(&WalrusPackageUpgradeDetectedAlert {
                remember_job_id: None,
                owner: None,
                namespace: None,
                sui_network: "mainnet".into(),
                sidecar_walrus_dep_version: "1.1.7".into(),
                on_chain_version_before: None,
                on_chain_version_after: None,
                action_taken: "client refreshed".into(),
                error: huge_error,
            });

        let json = serde_json::to_string(&payload).unwrap();
        // truncation marker present
        assert!(json.contains("..."));
        // total payload comfortably under twice the cap (header + metadata + body)
        assert!(json.len() < MAX_SLACK_ERROR_LEN * 3);
    }

    fn key(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn alert_dedup_lets_first_through() {
        let dedup = AlertDedup::new(Duration::from_secs(600));
        assert!(!dedup.should_suppress(key("mainnet", "1.1.7")));
    }

    #[test]
    fn alert_dedup_suppresses_burst_within_window() {
        // Concurrent jobs all raise the same logical event — only the first
        // fires; the rest are suppressed until the window elapses.
        let dedup = AlertDedup::new(Duration::from_secs(600));
        assert!(!dedup.should_suppress(key("mainnet", "obj-A")));
        for _ in 0..50 {
            assert!(dedup.should_suppress(key("mainnet", "obj-A")));
        }
    }

    #[test]
    fn alert_dedup_separates_distinct_keys() {
        // Different network or different second component are independent events.
        let dedup = AlertDedup::new(Duration::from_secs(600));
        assert!(!dedup.should_suppress(key("mainnet", "obj-A")));
        assert!(!dedup.should_suppress(key("testnet", "obj-A")));
        assert!(!dedup.should_suppress(key("mainnet", "obj-B")));
        // …but a repeat on the same key is still suppressed.
        assert!(dedup.should_suppress(key("mainnet", "obj-A")));
    }

    #[test]
    fn alert_dedup_re_fires_after_window_expires() {
        // Very short window → immediately past it on the second call.
        let dedup = AlertDedup::new(Duration::from_millis(1));
        assert!(!dedup.should_suppress(key("mainnet", "1.1.7")));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!dedup.should_suppress(key("mainnet", "1.1.7")));
    }

    #[test]
    fn walrus_object_locked_payload_surfaces_lock_metadata_not_exhausted_copy() {
        let payload = SlackPayload::for_walrus_object_locked(&WalrusObjectLockedAlert {
            remember_job_id: Some("3d607892".into()),
            owner: Some(
                "0xab27e2141234567890abcdef1234567890abcdef1234567890abcdef0064e132".into(),
            ),
            namespace: Some("autonomous-participation".into()),
            sui_network: "testnet".into(),
            locked_object_id: Some("0x36f866a4d400ec3dd5d8b0bac30cc36ab6d56172634a6b4dea9e2a554a43b08e".into()),
            locked_object_version: Some("884613305".into()),
            locking_transaction_digest: Some("8bjFgRyXRRYwrzQapgEjpHnGhdfNDY7d6xA82BtHrp3F".into()),
            error: "Transaction is rejected as invalid by more than 1/3 of validators by stake (non-retriable)".into(),
        });

        let json = serde_json::to_string(&payload).unwrap();
        // Names the real cause, NOT the misleading "exhausted retries" copy.
        assert!(json.contains("object lock") || json.contains("Sui object lock"));
        assert!(!json.to_lowercase().contains("exhausted retries"));
        // Surfaces lock metadata for triage.
        assert!(json.contains("0x36f866a4d400ec3dd5d8b0bac30cc36ab6d56172634a6b4dea9e2a554a43b08e"));
        assert!(json.contains("884613305"));
        assert!(json.contains("8bjFgRyXRRYwrzQapgEjpHnGhdfNDY7d6xA82BtHrp3F"));
        assert!(json.contains("testnet"));
        assert!(json.contains("autonomous-participation"));
    }

    #[test]
    fn walrus_object_locked_payload_handles_unparsed_metadata() {
        // When the error didn't yield object/version/digest, the payload still
        // ships with explicit `unparsed` placeholders rather than crashing.
        let payload = SlackPayload::for_walrus_object_locked(&WalrusObjectLockedAlert {
            remember_job_id: None,
            owner: None,
            namespace: None,
            sui_network: "mainnet".into(),
            locked_object_id: None,
            locked_object_version: None,
            locking_transaction_digest: None,
            error: "equivocation detected".into(),
        });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("unparsed"));
        assert!(json.contains("mainnet"));
    }

    #[test]
    fn walrus_gas_pool_payload_points_ops_to_gas_consolidation_not_exhausted_copy() {
        let payload = SlackPayload::for_walrus_gas_pool_exhausted(&WalrusGasPoolExhaustedAlert {
            remember_job_id: Some("591c13bc".into()),
            owner: Some(
                "0x51667727aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04bca2".into(),
            ),
            namespace: Some("people".into()),
            sui_network: "mainnet".into(),
            wallet_index: 4,
            configured_wallets: 5,
            error: "Dry run failed: MoveAbort(0x2::balance::split, 2)".into(),
        });

        let json = serde_json::to_string(&payload).unwrap();
        // Points ops at gas-coin maintenance, not the misleading exhausted copy.
        assert!(json.to_lowercase().contains("gas"));
        assert!(json.contains("consolidate") || json.contains("top up"));
        assert!(!json.to_lowercase().contains("exhausted retries"));
        assert!(json.contains("balance::split") || json.contains("balance"));
        assert!(json.contains("mainnet"));
        assert!(json.contains("people"));
    }

    #[test]
    fn walrus_low_balance_payload_promotes_available_below_threshold() {
        let payload = SlackPayload::for_walrus_low_wal_balance(&WalrusWalletBalanceLowAlert {
            remember_job_id: Some("low-wal-1".into()),
            owner: Some(
                "0xabc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
            ),
            namespace: Some("default".into()),
            sui_network: "mainnet".into(),
            available: 1_234_567_890,
            required: Some(64_367_730),
            threshold: 2_000_000_000,
            wallet_index: 3,
            configured_wallets: 5,
            error: "walrus upload failed: Insufficient balance ... available: 1234567890".into(),
        });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.to_lowercase().contains("insufficient wal"));
        assert!(json.contains("1.23456789"));
        assert!(json.contains("default"));
        assert!(json.contains("low-wal-1"));
        assert!(json.contains("wallet"));
    }

    #[test]
    fn wallet_balance_low_payload_includes_balance_and_threshold() {
        let payload = SlackPayload::for_wallet_balance_low(&WalletBalanceLowAlert {
            wallet_type: "sponsor".to_string(),
            address: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                .to_string(),
            balance: 500_000_000,
            threshold: 1_000_000_000,
            token: "SUI".to_string(),
            sui_network: "mainnet".to_string(),
            wallet_index: None,
        });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("sponsor"));
        assert!(json.contains("SUI"));
        assert!(json.contains("0.5"));
        assert!(json.contains("1.0"));
        assert!(json.to_lowercase().contains("balance"));
        assert!(json.contains("Top up"));
    }

    #[test]
    fn wallet_balance_low_payload_calculates_percentage_correctly() {
        let payload = SlackPayload::for_wallet_balance_low(&WalletBalanceLowAlert {
            wallet_type: "uploader_pool".to_string(),
            address: "0xabcdef".to_string(),
            balance: 250_000_000,
            threshold: 1_000_000_000,
            token: "WAL".to_string(),
            sui_network: "testnet".to_string(),
            wallet_index: Some(2),
        });

        let json = serde_json::to_string(&payload).unwrap();
        // 250M / 1B = 25%; routing context is actionable in Slack.
        assert!(json.contains("25.0"));
        assert!(json.contains("testnet"));
        assert!(json.contains("Wallet index"));
        assert!(json.contains("`2`"));
    }

    #[test]
    fn wallet_balance_low_payload_abbreviates_address() {
        let full_address = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let payload = SlackPayload::for_wallet_balance_low(&WalletBalanceLowAlert {
            wallet_type: "sponsor".to_string(),
            address: full_address.to_string(),
            balance: 10_000_000,
            threshold: 100_000_000,
            token: "SUI".to_string(),
            sui_network: "mainnet".to_string(),
            wallet_index: None,
        });

        let json = serde_json::to_string(&payload).unwrap();
        // Should show full address in details but abbreviated in summary
        assert!(json.contains(full_address));
    }

    #[test]
    fn wallet_balance_low_dedup_key_formation() {
        let address = "0x1234...abcd".to_string();
        let wal = WalletBalanceLowAlert {
            wallet_type: "uploader".to_string(),
            address: address.clone(),
            balance: 1,
            threshold: 2,
            token: "WAL".to_string(),
            sui_network: "mainnet".to_string(),
            wallet_index: Some(0),
        };
        let sui = WalletBalanceLowAlert {
            token: "SUI".to_string(),
            ..wal.clone()
        };
        let testnet = WalletBalanceLowAlert {
            sui_network: "testnet".to_string(),
            ..sui.clone()
        };
        let sponsor = WalletBalanceLowAlert {
            wallet_type: "sponsor".to_string(),
            wallet_index: None,
            ..sui.clone()
        };

        assert_eq!(
            wallet_balance_low_dedup_key(&wal),
            ("mainnet:uploader:WAL".to_string(), address.clone())
        );
        assert_eq!(
            wallet_balance_low_dedup_key(&sui),
            ("mainnet:uploader:SUI".to_string(), address.clone())
        );
        assert_eq!(
            wallet_balance_low_dedup_key(&testnet),
            ("testnet:uploader:SUI".to_string(), address.clone())
        );
        assert_eq!(
            wallet_balance_low_dedup_key(&sponsor),
            ("mainnet:sponsor:SUI".to_string(), address)
        );

        let manager = AlertManager::from_env(reqwest::Client::new());
        let first = manager.should_suppress_wallet_balance_low(&wal);
        let repeat = manager.should_suppress_wallet_balance_low(&wal);
        let other_token = manager.should_suppress_wallet_balance_low(&sui);
        assert!(!first);
        assert!(repeat);
        assert!(!other_token);
    }

    #[test]
    fn format_token_amount_handles_zero() {
        let amount = format_token_amount(0);
        assert_eq!(amount, "0.0");
    }

    #[test]
    fn format_token_amount_handles_whole_numbers() {
        let amount = format_token_amount(1_000_000_000);
        assert_eq!(amount, "1.0");
    }

    #[test]
    fn format_token_amount_handles_fractions() {
        let amount = format_token_amount(1_500_000_000);
        assert_eq!(amount, "1.5");
    }

    #[test]
    fn format_token_amount_strips_trailing_zeros() {
        let amount = format_token_amount(1_100_000_000);
        assert_eq!(amount, "1.1");
    }

    #[test]
    fn is_postgres_storage_exhausted_matches_prod_neon_message() {
        let prod = "could not extend file because project size limit (3072 MB) has been exceeded";
        assert!(is_postgres_storage_exhausted(prod));
        assert!(is_postgres_storage_exhausted(&prod.to_ascii_uppercase()));
        assert!(is_postgres_storage_exhausted(&format!(
            "Internal Error: Failed to insert reservation: error returned from database: {prod}"
        )));
        assert!(is_postgres_storage_exhausted(
            "ERROR: could not extend file \"base/16384/12345\": No space left on device"
        ));
        assert!(!is_postgres_storage_exhausted("sqlstate 53100 disk_full"));
        assert!(!is_postgres_storage_exhausted(
            "duplicate key value violates unique constraint"
        ));
        assert!(!is_postgres_storage_exhausted("Storage quota exceeded"));
    }

    #[test]
    fn sqlx_error_is_postgres_storage_exhausted_matches_sqlstate() {
        let disk_full = sqlx::Error::Database(Box::new(FakePgError {
            message: "the wording changed in a future postgres",
            code: Some("53100"),
        }));
        assert!(sqlx_error_is_postgres_storage_exhausted(&disk_full));

        let other = sqlx::Error::Database(Box::new(FakePgError {
            message: "duplicate key value violates unique constraint",
            code: Some("23505"),
        }));
        assert!(!sqlx_error_is_postgres_storage_exhausted(&other));
    }

    #[test]
    fn postgres_storage_exhausted_payload_names_write_outage_not_user_quota() {
        let payload =
            SlackPayload::for_postgres_storage_exhausted(&PostgresStorageExhaustedAlert {
                sui_network: "mainnet".into(),
                error:
                    "could not extend file because project size limit (3072 MB) has been exceeded"
                        .into(),
            });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("MemWal Postgres storage exhausted"));
        assert!(json.contains("mainnet"));
        assert!(json.contains("remember/analyze"));
        assert!(json.contains("write_ready"));
        assert!(json.contains("not a user quota"));
        assert!(json.contains("do not tell users to send SUI/WAL"));
        assert!(json.contains("project size limit (3072 MB)"));
        assert!(!json.to_lowercase().contains("exhausted retries"));
    }

    #[test]
    fn postgres_storage_dedup_is_per_network_not_per_job() {
        assert_eq!(
            postgres_storage_dedup_key("mainnet"),
            ("mainnet".to_string(), "postgres-storage".to_string())
        );

        // Do not read POSTGRES_STORAGE_ALERT_DEDUP_SECS: a real env value
        // would change the window (or make the second fire miss the window).
        let dedup = AlertDedup::new(POSTGRES_STORAGE_ALERT_DEDUP_DEFAULT);
        assert!(!dedup.should_suppress(postgres_storage_dedup_key("mainnet")));
        assert!(dedup.should_suppress(postgres_storage_dedup_key("mainnet")));
        assert!(!dedup.should_suppress(postgres_storage_dedup_key("testnet")));
    }

    #[test]
    fn embedding_provider_auth_payload_surfaces_status_and_action() {
        let payload =
            SlackPayload::for_embedding_provider_auth_failed(&EmbeddingProviderAuthAlert {
                sui_network: "mainnet".into(),
                status: 401,
                api_base: "https://openrouter.ai/api/v1".into(),
                error: r#"{"error":{"message":"User not found.","code":401}}"#.into(),
            });

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("MemWal embedding provider credential/quota error"));
        assert!(json.contains("mainnet"));
        assert!(json.contains("401"));
        assert!(json.contains("EMBEDDING_PROVIDER_UNAVAILABLE"));
        assert!(json.contains("OPENAI_API_KEY"));
        assert!(json.contains("User not found."));
    }

    #[tokio::test]
    async fn embedding_provider_auth_alert_sends_once_per_dedup_window() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        let app = axum::Router::new().route(
            "/slack",
            axum::routing::post(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let webhook_url = format!("http://{addr}/slack");
        let manager = AlertManager::from_webhook_value(reqwest::Client::new(), Some(&webhook_url));

        for status in [401, 402, 403] {
            manager
                .notify_embedding_provider_auth_failed(EmbeddingProviderAuthAlert {
                    sui_network: "mainnet".into(),
                    status,
                    api_base: "https://openrouter.ai/api/v1".into(),
                    error: format!(r#"{{"error":{{"message":"rejected","code":{status}}}}}"#),
                })
                .await
                .unwrap();
        }
        assert_eq!(
            received.load(Ordering::SeqCst),
            1,
            "401/402/403 burst on the same network must emit only 1 Slack alert per dedup window"
        );

        // A separate network is not suppressed by mainnet's dedup entry.
        manager
            .notify_embedding_provider_auth_failed(EmbeddingProviderAuthAlert {
                sui_network: "testnet".into(),
                status: 401,
                api_base: "https://openrouter.ai/api/v1".into(),
                error: r#"{"error":{"message":"User not found.","code":401}}"#.into(),
            })
            .await
            .unwrap();
        assert_eq!(received.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn embedding_provider_alert_timeout_does_not_change_shared_client_deadline() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        let app = axum::Router::new()
            .route(
                "/slack",
                axum::routing::post(move || {
                    let counter = Arc::clone(&counter);
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        std::future::pending::<axum::http::StatusCode>().await
                    }
                }),
            )
            .route(
                "/probe",
                axum::routing::get(|| async {
                    tokio::time::sleep(
                        EMBEDDING_PROVIDER_ALERT_TIMEOUT + Duration::from_millis(100),
                    )
                    .await;
                    axum::http::StatusCode::OK
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let manager =
            AlertManager::from_webhook_value(client.clone(), Some(&format!("http://{addr}/slack")));
        let alert = || EmbeddingProviderAuthAlert {
            sui_network: "mainnet".into(),
            status: 401,
            api_base: "https://provider.example/v1".into(),
            error: "provider rejected credentials".into(),
        };

        // The outer deadline catches a stalled delivery well before the
        // shared client's timeout. A later alert remains deduplicated.
        let result = tokio::time::timeout(
            EMBEDDING_PROVIDER_ALERT_TIMEOUT + Duration::from_secs(2),
            manager.notify_embedding_provider_auth_failed(alert()),
        )
        .await
        .expect("provider alert must not wait for the shared 30s deadline");
        assert!(
            matches!(result, Err(AlertError::Transport(message)) if message.contains("timed out"))
        );
        manager
            .notify_embedding_provider_auth_failed(alert())
            .await
            .unwrap();
        assert_eq!(received.load(Ordering::SeqCst), 1);

        // Requests using the same client may still exceed the alert deadline.
        assert!(client
            .get(format!("http://{addr}/probe"))
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        server.abort();
    }

    #[derive(Debug)]
    struct FakePgError {
        message: &'static str,
        code: Option<&'static str>,
    }

    impl std::fmt::Display for FakePgError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.message)
        }
    }

    impl std::error::Error for FakePgError {}

    impl sqlx::error::DatabaseError for FakePgError {
        fn message(&self) -> &str {
            self.message
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }

        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            self.code.map(std::borrow::Cow::Borrowed)
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
    }
}

//! Admin spend and action counts.
//!
//! Wallet outflow is the sum of decreases between balance samples. A top-up
//! in the same window does not cancel those decreases, which is the question
//! "are we draining faster?" needs. Action counts come from tables that
//! already record the work: remember jobs, memory tombstones, and (when the
//! legacy database is configured) security-delete batches. Sponsored account
//! transactions are logged here only after execute succeeds.

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::types::{AppError, AppState};

// A 30-day window is compared with the previous 30 days, and the burn
// baseline is the sample on that start boundary. One extra day keeps that
// sample from being deleted as soon as the prior window opens.
const SAMPLE_RETENTION: Duration = Duration::hours(24 * 61);
const MAX_WINDOW_HOURS: i64 = 24 * 30;
const MAX_SERIES_POINTS: usize = 48;
const SPONSOR_KINDS: [&str; 4] = [
    "create_account",
    "add_delegate_key",
    "remove_delegate_key",
    "reactivate_account",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BalancePoint {
    pub at_ms: i64,
    pub balance: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowBurn {
    pub outflow: i64,
    pub net: i64,
    pub latest: Option<i64>,
    pub latest_at: Option<i64>,
    /// Baseline plus samples inside the window. Two are required before a
    /// comparison means anything.
    pub observations: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploaderSpendable {
    pub wal_frost: Option<i64>,
    pub sui_mist: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ActivityQuery {
    #[serde(default)]
    pub hours: Option<i64>,
    /// Minutes east of UTC, so a chart day matches the viewer's calendar.
    /// Vietnam is 420. Missing means UTC.
    #[serde(default)]
    pub utc_offset_minutes: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct ActivityResponse {
    pub generated_at: String,
    pub window_hours: i64,
    pub balance_monitor_interval_secs: u64,
    pub uploader_wal: TokenWindow,
    pub uploader_sui: TokenWindow,
    pub sponsor_sui: TokenWindow,
    pub actions: ActionWindow,
}

#[derive(Debug, Serialize)]
pub struct TokenWindow {
    pub samples: i64,
    pub comparable: bool,
    pub latest: Option<String>,
    pub latest_at: Option<String>,
    pub outflow: String,
    pub prior_outflow: String,
    pub net: String,
    pub series: Vec<SeriesPoint>,
}

#[derive(Debug, Serialize)]
pub struct SeriesPoint {
    pub at: String,
    pub balance: String,
}

#[derive(Debug, Serialize)]
pub struct ActionWindow {
    pub uploads_completed: i64,
    pub uploads_completed_prior: i64,
    pub uploads_failed: i64,
    pub uploads_failed_prior: i64,
    pub uploads_in_flight: i64,
    pub memory_deletes: i64,
    pub memory_deletes_prior: i64,
    pub security_delete_batches: Option<i64>,
    pub security_delete_batches_prior: Option<i64>,
    pub security_delete_blobs: Option<i64>,
    pub security_delete_blobs_prior: Option<i64>,
    pub sponsored: Vec<SponsoredKindCount>,
    pub top_owners: Vec<TopOwner>,
    /// Completed remember jobs per calendar day. Days with none are included
    /// so the chart stays continuous. The day boundary follows the caller's
    /// UTC offset, and the first and last days can be partial.
    pub memories_by_day: Vec<MemoryDay>,
    /// Completed remember jobs per clock hour, only for windows of a day or
    /// less, where one bar per day would be a single bar. Hours with none are
    /// included, and the first and last hours can be partial. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memories_by_hour: Option<Vec<MemoryHour>>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MemoryDay {
    pub day: String,
    pub count: i64,
}

/// One clock hour on the viewer's calendar, as `YYYY-MM-DDTHH:00`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct MemoryHour {
    pub hour: String,
    pub count: i64,
}

/// Windows up to this long are also bucketed by hour.
pub const HOURLY_WINDOW_MAX_HOURS: i64 = 24;

#[derive(Debug, Serialize)]
pub struct SponsoredKindCount {
    pub kind: String,
    pub count: i64,
    pub prior_count: i64,
}

#[derive(Debug, Serialize)]
pub struct TopOwner {
    pub owner: String,
    pub uploads_completed: i64,
}

#[derive(sqlx::FromRow)]
struct SampleRow {
    sampled_at: DateTime<Utc>,
    uploader_wal_frost: Option<i64>,
    uploader_sui_mist: Option<i64>,
    sponsor_sui_mist: Option<i64>,
}

pub fn window_hours(hours: Option<i64>) -> i64 {
    hours.unwrap_or(24).clamp(1, MAX_WINDOW_HOURS)
}

pub fn utc_offset_minutes(minutes: Option<i32>) -> i32 {
    minutes.unwrap_or(0).clamp(-14 * 60, 14 * 60)
}

/// Fill every local calendar day from `start` through `end`, including zeros.
/// `utc_offset_minutes` is minutes east of UTC.
pub fn fill_memory_days(
    counts: &[(String, i64)],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    utc_offset_minutes: i32,
) -> Vec<MemoryDay> {
    let shift = Duration::minutes(i64::from(utc_offset_minutes));
    let Some(start_local) = start.checked_add_signed(shift) else {
        return Vec::new();
    };
    let Some(end_local) = end.checked_add_signed(shift) else {
        return Vec::new();
    };
    let mut day = start_local.date_naive();
    let end_day = end_local.date_naive();
    if end_day < day {
        return Vec::new();
    }
    let counts: std::collections::HashMap<&str, i64> = counts
        .iter()
        .map(|(day, count)| (day.as_str(), *count))
        .collect();
    let mut days = Vec::new();
    loop {
        let key = day.format("%Y-%m-%d").to_string();
        days.push(MemoryDay {
            count: counts.get(key.as_str()).copied().unwrap_or(0),
            day: key,
        });
        if day == end_day {
            break;
        }
        day = match day.succ_opt() {
            Some(next) => next,
            None => break,
        };
    }
    days
}

pub fn normalize_sponsor_kind(kind: &str) -> &'static str {
    match kind {
        "create_account" => "create_account",
        "add_delegate_key" => "add_delegate_key",
        "remove_delegate_key" => "remove_delegate_key",
        "reactivate_account" => "reactivate_account",
        _ => "unknown",
    }
}

/// Outflow counts every drop. Net is the last balance minus the baseline
/// (or the first in-window sample when no earlier sample exists). A point
/// exactly on `start` belongs to the previous window and is this window's
/// baseline, so the two windows do not double-count a drop.
pub fn window_burn(points: &[BalancePoint], start_ms: i64, end_ms: i64) -> WindowBurn {
    let baseline = points
        .iter()
        .take_while(|point| point.at_ms <= start_ms)
        .last()
        .copied();
    let inside: Vec<BalancePoint> = points
        .iter()
        .copied()
        .filter(|point| point.at_ms > start_ms && point.at_ms <= end_ms)
        .collect();

    let mut outflow = 0i64;
    let mut previous = baseline.map(|point| point.balance);
    for point in &inside {
        if let Some(before) = previous {
            let drop = before.saturating_sub(point.balance);
            if drop > 0 {
                outflow = outflow.saturating_add(drop);
            }
        }
        previous = Some(point.balance);
    }

    let net = match (
        baseline.or_else(|| inside.first().copied()),
        inside.last().copied(),
    ) {
        (Some(first), Some(last)) => last.balance.saturating_sub(first.balance),
        _ => 0,
    };
    let latest = inside.last().copied().or(baseline);
    let observations = usize::from(baseline.is_some()) + inside.len();

    WindowBurn {
        outflow,
        net,
        latest: latest.map(|point| point.balance),
        latest_at: latest.map(|point| point.at_ms),
        observations,
    }
}

pub fn windows_comparable(current: &WindowBurn, prior: &WindowBurn) -> bool {
    current.observations >= 2 && prior.observations >= 2
}

pub fn series_for_window(points: &[BalancePoint], start_ms: i64, end_ms: i64) -> Vec<BalancePoint> {
    let baseline = points
        .iter()
        .take_while(|point| point.at_ms <= start_ms)
        .last()
        .copied();
    let mut series = Vec::new();
    if let Some(point) = baseline {
        series.push(BalancePoint {
            at_ms: start_ms,
            balance: point.balance,
        });
    }
    series.extend(
        points
            .iter()
            .copied()
            .filter(|point| point.at_ms > start_ms && point.at_ms <= end_ms),
    );
    downsample(&series, MAX_SERIES_POINTS)
}

fn downsample(points: &[BalancePoint], max_points: usize) -> Vec<BalancePoint> {
    if max_points < 2 || points.len() <= max_points {
        return points.to_vec();
    }
    let last = points.len() - 1;
    let mut out: Vec<BalancePoint> = Vec::with_capacity(max_points);
    for step in 0..max_points {
        let index = step * last / (max_points - 1);
        let point = points[index];
        if out
            .last()
            .map(|kept| kept.at_ms != point.at_ms)
            .unwrap_or(true)
        {
            out.push(point);
        }
    }
    out
}

pub fn uploader_spendable_totals(metrics: &serde_json::Value) -> UploaderSpendable {
    let Some(entries) = metrics.get("perWallet").and_then(|value| value.as_array()) else {
        return UploaderSpendable {
            wal_frost: None,
            sui_mist: None,
        };
    };
    UploaderSpendable {
        wal_frost: sum_spendable(entries, "walAddressBalanceFrost", "walFrost"),
        sui_mist: sum_spendable(entries, "suiAddressBalanceMist", "suiMist"),
    }
}

fn sum_spendable(entries: &[serde_json::Value], address_key: &str, total_key: &str) -> Option<i64> {
    let mut total: u64 = 0;
    let mut any = false;
    for entry in entries {
        let address = entry
            .get("address")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if address.trim().is_empty() {
            continue;
        }
        let Some(amount) = spendable_u64(entry, address_key, total_key) else {
            continue;
        };
        any = true;
        total = total.checked_add(amount)?;
    }
    if any {
        i64::try_from(total).ok()
    } else {
        None
    }
}

fn spendable_u64(entry: &serde_json::Value, address_key: &str, total_key: &str) -> Option<u64> {
    let total = json_u64(entry, total_key)?;
    match entry.get(address_key).and_then(|value| value.as_str()) {
        Some(raw) if !raw.is_empty() => raw.parse().ok(),
        _ => Some(total),
    }
}

fn json_u64(entry: &serde_json::Value, key: &str) -> Option<u64> {
    entry
        .get(key)
        .and_then(|value| value.as_str())
        .and_then(|raw| raw.parse().ok())
}

pub async fn record_balance_sample(
    pool: &PgPool,
    uploader_wal_frost: Option<i64>,
    uploader_sui_mist: Option<i64>,
    sponsor_sui_mist: Option<i64>,
) -> Result<(), sqlx::Error> {
    if uploader_wal_frost.is_none() && uploader_sui_mist.is_none() && sponsor_sui_mist.is_none() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO wallet_balance_samples
            (sampled_at, uploader_wal_frost, uploader_sui_mist, sponsor_sui_mist)
         VALUES (NOW(), $1, $2, $3)",
    )
    .bind(uploader_wal_frost)
    .bind(uploader_sui_mist)
    .bind(sponsor_sui_mist)
    .execute(pool)
    .await?;
    sqlx::query("DELETE FROM wallet_balance_samples WHERE sampled_at < $1")
        .bind(Utc::now() - SAMPLE_RETENTION)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn record_sponsored_tx(
    pool: &PgPool,
    sender: &str,
    kind: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO sponsored_tx_log (created_at, sender, kind) VALUES (NOW(), $1, $2)")
        .bind(sender)
        .bind(normalize_sponsor_kind(kind))
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM sponsored_tx_log WHERE created_at < $1")
        .bind(Utc::now() - SAMPLE_RETENTION)
        .execute(pool)
        .await?;
    Ok(())
}

#[tracing::instrument(name = "admin.activity", skip_all)]
pub async fn get_admin_activity(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ActivityQuery>,
) -> Result<Json<ActivityResponse>, AppError> {
    let hours = window_hours(query.hours);
    let utc_offset_minutes = utc_offset_minutes(query.utc_offset_minutes);
    let now = Utc::now();
    let current_start = now - Duration::hours(hours);
    let prior_start = now - Duration::hours(hours * 2);
    let fetch_from = now - SAMPLE_RETENTION;

    let samples = load_samples(state.db.pool(), fetch_from).await?;
    let wal_points = column_points(&samples, |row| row.uploader_wal_frost);
    let uploader_sui_points = column_points(&samples, |row| row.uploader_sui_mist);
    let sponsor_points = column_points(&samples, |row| row.sponsor_sui_mist);

    let actions = load_actions(
        &state,
        prior_start,
        current_start,
        now,
        utc_offset_minutes,
        hours,
    )
    .await?;

    Ok(Json(ActivityResponse {
        generated_at: stamp(now),
        window_hours: hours,
        balance_monitor_interval_secs: state.config.balance_monitor_interval_secs,
        uploader_wal: token_window(&wal_points, current_start, now, prior_start),
        uploader_sui: token_window(&uploader_sui_points, current_start, now, prior_start),
        sponsor_sui: token_window(&sponsor_points, current_start, now, prior_start),
        actions,
    }))
}

fn column_points(
    rows: &[SampleRow],
    pick: impl Fn(&SampleRow) -> Option<i64>,
) -> Vec<BalancePoint> {
    rows.iter()
        .filter_map(|row| {
            pick(row).map(|balance| BalancePoint {
                at_ms: row.sampled_at.timestamp_millis(),
                balance,
            })
        })
        .collect()
}

fn token_window(
    points: &[BalancePoint],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    prior_start: DateTime<Utc>,
) -> TokenWindow {
    let start_ms = start.timestamp_millis();
    let end_ms = end.timestamp_millis();
    let current = window_burn(points, start_ms, end_ms);
    let prior = window_burn(points, prior_start.timestamp_millis(), start_ms);
    TokenWindow {
        samples: i64::try_from(current.observations).unwrap_or(i64::MAX),
        comparable: windows_comparable(&current, &prior),
        latest: current.latest.map(|value| value.to_string()),
        latest_at: current.latest_at.map(stamp_ms),
        outflow: current.outflow.to_string(),
        prior_outflow: prior.outflow.to_string(),
        net: current.net.to_string(),
        series: series_for_window(points, start_ms, end_ms)
            .into_iter()
            .map(|point| SeriesPoint {
                at: stamp_ms(point.at_ms),
                balance: point.balance.to_string(),
            })
            .collect(),
    }
}

async fn load_samples(
    pool: &PgPool,
    fetch_from: DateTime<Utc>,
) -> Result<Vec<SampleRow>, AppError> {
    sqlx::query_as(
        "SELECT sampled_at, uploader_wal_frost, uploader_sui_mist, sponsor_sui_mist
         FROM wallet_balance_samples
         WHERE sampled_at >= $1
         ORDER BY sampled_at ASC",
    )
    .bind(fetch_from)
    .fetch_all(pool)
    .await
    .map_err(|error| AppError::Internal(format!("Failed to load balance samples: {error}")))
}

/// Hour buckets from the one holding `start` to the one holding `end`, in the
/// viewer's wall clock, with zero for hours that had no completed jobs.
pub fn fill_memory_hours(
    counts: &[(String, i64)],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    utc_offset_minutes: i32,
) -> Vec<MemoryHour> {
    let shift = i64::from(utc_offset_minutes) * 60;
    let first = (start.timestamp() + shift).div_euclid(3600);
    let last = (end.timestamp() + shift).div_euclid(3600);
    // A window is at most HOURLY_WINDOW_MAX_HOURS long, so this stays at 25
    // buckets; the cap only guards against a caller passing a longer one.
    if last < first || last - first > HOURLY_WINDOW_MAX_HOURS * 31 {
        return Vec::new();
    }
    let counts: std::collections::HashMap<&str, i64> = counts
        .iter()
        .map(|(hour, count)| (hour.as_str(), *count))
        .collect();
    (first..=last)
        .filter_map(|bucket| DateTime::<Utc>::from_timestamp(bucket * 3600, 0))
        .map(|at| {
            let hour = at.format("%Y-%m-%dT%H:00").to_string();
            MemoryHour {
                count: counts.get(hour.as_str()).copied().unwrap_or(0),
                hour,
            }
        })
        .collect()
}

async fn load_actions(
    state: &AppState,
    prior_start: DateTime<Utc>,
    current_start: DateTime<Utc>,
    now: DateTime<Utc>,
    utc_offset_minutes: i32,
    window_hours: i64,
) -> Result<ActionWindow, AppError> {
    let pool = state.db.pool();
    let (uploads_completed, uploads_failed) = job_counts(pool, current_start, now).await?;
    let (uploads_completed_prior, uploads_failed_prior) =
        job_counts(pool, prior_start, current_start).await?;
    let uploads_in_flight: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM remember_jobs WHERE status IN ('pending', 'running', 'uploaded')",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| AppError::Internal(format!("Failed to count in-flight uploads: {error}")))?;
    let memory_deletes = tombstone_count(pool, current_start, now).await?;
    let memory_deletes_prior = tombstone_count(pool, prior_start, current_start).await?;
    let sponsored_now = sponsored_counts(pool, current_start, now).await?;
    let sponsored_prior = sponsored_counts(pool, prior_start, current_start).await?;
    let top_owners = top_owners(pool, current_start, now).await?;
    let memories_by_day =
        load_memories_by_day(pool, current_start, now, utc_offset_minutes).await?;
    let memories_by_hour = if window_hours <= HOURLY_WINDOW_MAX_HOURS {
        Some(load_memories_by_hour(pool, current_start, now, utc_offset_minutes).await?)
    } else {
        None
    };
    let (security_now, security_prior) =
        security_delete_counts(state, current_start, prior_start, now).await;

    Ok(ActionWindow {
        uploads_completed,
        uploads_completed_prior,
        uploads_failed,
        uploads_failed_prior,
        uploads_in_flight,
        memory_deletes,
        memory_deletes_prior,
        security_delete_batches: security_now.map(|row| row.0),
        security_delete_batches_prior: security_prior.map(|row| row.0),
        security_delete_blobs: security_now.map(|row| row.1),
        security_delete_blobs_prior: security_prior.map(|row| row.1),
        sponsored: merge_sponsored(&sponsored_now, &sponsored_prior),
        top_owners,
        memories_by_day,
        memories_by_hour,
    })
}

async fn load_memories_by_day(
    pool: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    utc_offset_minutes: i32,
) -> Result<Vec<MemoryDay>, AppError> {
    // Shift into the viewer's wall clock before truncating, so the day is not
    // the database session time zone. `AT TIME ZONE 'UTC'` yields a naive UTC
    // timestamp, then the offset minutes move it onto the local calendar.
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT to_char(
             date_trunc(
                 'day',
                 updated_at AT TIME ZONE 'UTC' + ($3::int * interval '1 minute')
             ),
             'YYYY-MM-DD'
         ),
         COUNT(*)::bigint
         FROM remember_jobs
         WHERE status = 'done' AND updated_at > $1 AND updated_at <= $2
         GROUP BY 1
         ORDER BY 1",
    )
    .bind(start)
    .bind(end)
    .bind(utc_offset_minutes)
    .fetch_all(pool)
    .await
    .map_err(|error| AppError::Internal(format!("Failed to count memories by day: {error}")))?;
    Ok(fill_memory_days(&rows, start, end, utc_offset_minutes))
}

async fn load_memories_by_hour(
    pool: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    utc_offset_minutes: i32,
) -> Result<Vec<MemoryHour>, AppError> {
    // Same shift as the daily query, truncated to the hour instead.
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT to_char(
             date_trunc(
                 'hour',
                 updated_at AT TIME ZONE 'UTC' + ($3::int * interval '1 minute')
             ),
             'YYYY-MM-DD\"T\"HH24:00'
         ),
         COUNT(*)::bigint
         FROM remember_jobs
         WHERE status = 'done' AND updated_at > $1 AND updated_at <= $2
         GROUP BY 1
         ORDER BY 1",
    )
    .bind(start)
    .bind(end)
    .bind(utc_offset_minutes)
    .fetch_all(pool)
    .await
    .map_err(|error| AppError::Internal(format!("Failed to count memories by hour: {error}")))?;
    Ok(fill_memory_hours(&rows, start, end, utc_offset_minutes))
}

async fn job_counts(
    pool: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<(i64, i64), AppError> {
    sqlx::query_as(
        "SELECT
            COUNT(*) FILTER (WHERE status = 'done'),
            COUNT(*) FILTER (WHERE status = 'failed')
         FROM remember_jobs
         WHERE updated_at > $1 AND updated_at <= $2
           AND status IN ('done', 'failed')",
    )
    .bind(start)
    .bind(end)
    .fetch_one(pool)
    .await
    .map_err(|error| AppError::Internal(format!("Failed to count remember jobs: {error}")))
}

async fn tombstone_count(
    pool: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM memory_tombstones WHERE deleted_at > $1 AND deleted_at <= $2",
    )
    .bind(start)
    .bind(end)
    .fetch_one(pool)
    .await
    .map_err(|error| AppError::Internal(format!("Failed to count memory deletes: {error}")))
}

async fn sponsored_counts(
    pool: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<(String, i64)>, AppError> {
    sqlx::query_as(
        "SELECT kind, COUNT(*)
         FROM sponsored_tx_log
         WHERE created_at > $1 AND created_at <= $2
         GROUP BY kind",
    )
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .await
    .map_err(|error| AppError::Internal(format!("Failed to count sponsored transactions: {error}")))
}

async fn top_owners(
    pool: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<TopOwner>, AppError> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT owner, COUNT(*)
         FROM remember_jobs
         WHERE status = 'done' AND updated_at > $1 AND updated_at <= $2
         GROUP BY owner
         ORDER BY COUNT(*) DESC, owner ASC
         LIMIT 8",
    )
    .bind(start)
    .bind(end)
    .fetch_all(pool)
    .await
    .map_err(|error| AppError::Internal(format!("Failed to rank upload owners: {error}")))?;
    Ok(rows
        .into_iter()
        .map(|(owner, uploads_completed)| TopOwner {
            owner,
            uploads_completed,
        })
        .collect())
}

async fn security_delete_counts(
    state: &AppState,
    current_start: DateTime<Utc>,
    prior_start: DateTime<Utc>,
    now: DateTime<Utc>,
) -> (Option<(i64, i64)>, Option<(i64, i64)>) {
    let Some(legacy) = state.legacy_db.as_ref() else {
        return (None, None);
    };
    let pool = legacy.pool();
    let current = security_delete_window(pool, current_start, now).await;
    let prior = security_delete_window(pool, prior_start, current_start).await;
    (current, prior)
}

async fn security_delete_window(
    pool: &PgPool,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Option<(i64, i64)> {
    match sqlx::query_as(
        "SELECT COUNT(*)::bigint, COALESCE(SUM(blob_count), 0)::bigint
         FROM deletion_batches
         WHERE state = 'completed' AND resolved_at > $1 AND resolved_at <= $2",
    )
    .bind(start)
    .bind(end)
    .fetch_one(pool)
    .await
    {
        Ok(row) => Some(row),
        Err(error) => {
            tracing::warn!("admin.activity: security-delete counts unavailable: {error}");
            None
        }
    }
}

fn merge_sponsored(current: &[(String, i64)], prior: &[(String, i64)]) -> Vec<SponsoredKindCount> {
    let mut kinds: Vec<&str> = SPONSOR_KINDS.to_vec();
    if count_of(current, "unknown") > 0 || count_of(prior, "unknown") > 0 {
        kinds.push("unknown");
    }
    kinds
        .into_iter()
        .map(|kind| SponsoredKindCount {
            kind: kind.to_string(),
            count: count_of(current, kind),
            prior_count: count_of(prior, kind),
        })
        .collect()
}

fn count_of(rows: &[(String, i64)], kind: &str) -> i64 {
    rows.iter()
        .find(|(row_kind, _)| row_kind == kind)
        .map(|(_, count)| *count)
        .unwrap_or(0)
}

fn stamp(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn stamp_ms(at_ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(at_ms)
        .map(stamp)
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn point(at_ms: i64, balance: i64) -> BalancePoint {
        BalancePoint { at_ms, balance }
    }

    #[test]
    fn outflow_sums_drops_and_ignores_top_ups() {
        let points = [point(0, 100), point(10, 150), point(20, 80), point(30, 70)];
        let burn = window_burn(&points, 0, 30);
        assert_eq!(burn.outflow, 80);
        assert_eq!(burn.net, -30);
        assert_eq!(burn.latest, Some(70));
        assert_eq!(burn.observations, 4);
    }

    #[test]
    fn a_sample_on_the_boundary_is_not_counted_twice() {
        let points = [point(0, 100), point(10, 90), point(20, 50)];
        let prior = window_burn(&points, 0, 10);
        let current = window_burn(&points, 10, 20);
        assert_eq!(prior.outflow, 10);
        assert_eq!(current.outflow, 40);
        assert_eq!(current.net, -40);
        assert!(windows_comparable(&current, &prior));
    }

    #[test]
    fn one_observation_is_not_comparable() {
        let points = [point(5, 40)];
        let current = window_burn(&points, 0, 10);
        let prior = window_burn(&points, -10, 0);
        assert_eq!(current.outflow, 0);
        assert_eq!(current.net, 0);
        assert_eq!(current.observations, 1);
        assert!(!windows_comparable(&current, &prior));
    }

    #[test]
    fn series_starts_at_the_baseline_and_keeps_both_ends_when_downsampling() {
        let points: Vec<BalancePoint> = (0..100).map(|index| point(index, 100 - index)).collect();
        let series = series_for_window(&points, 10, 90);
        assert_eq!(series.first().map(|point| point.at_ms), Some(10));
        assert_eq!(series.last().map(|point| point.at_ms), Some(90));
        assert!(series.len() <= MAX_SERIES_POINTS);
        assert!(series.len() > 2);
    }

    #[test]
    fn uploader_totals_use_spendable_balances_and_skip_a_blank_address() {
        let metrics = json!({
            "perWallet": [
                {
                    "address": "0xabc",
                    "walFrost": "100",
                    "walAddressBalanceFrost": "40",
                    "suiMist": "10",
                    "suiAddressBalanceMist": "7"
                },
                {
                    "address": "  ",
                    "walFrost": "999",
                    "walAddressBalanceFrost": "999",
                    "suiMist": "999",
                    "suiAddressBalanceMist": "999"
                },
                {
                    "address": "0xdef",
                    "walFrost": "5",
                    "suiMist": "3"
                }
            ]
        });
        let totals = uploader_spendable_totals(&metrics);
        assert_eq!(totals.wal_frost, Some(45));
        assert_eq!(totals.sui_mist, Some(10));
    }

    #[test]
    fn sponsor_kinds_outside_the_allowlist_collapse_to_unknown() {
        assert_eq!(normalize_sponsor_kind("create_account"), "create_account");
        assert_eq!(normalize_sponsor_kind("drop table"), "unknown");
    }

    #[test]
    fn window_hours_defaults_and_clamps() {
        assert_eq!(window_hours(None), 24);
        assert_eq!(window_hours(Some(0)), 1);
        assert_eq!(window_hours(Some(24 * 7)), 168);
        assert_eq!(window_hours(Some(24 * 30)), 720);
        assert_eq!(window_hours(Some(24 * 31)), 720);
        assert_eq!(utc_offset_minutes(None), 0);
        assert_eq!(utc_offset_minutes(Some(420)), 420);
        assert_eq!(utc_offset_minutes(Some(24 * 60)), 14 * 60);
    }

    #[test]
    fn memory_days_follow_the_viewer_calendar_and_keep_empty_days() {
        let start = DateTime::parse_from_rfc3339("2026-09-24T17:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-09-26T16:59:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let days = fill_memory_days(&[("2026-09-25".to_string(), 4)], start, end, 420);
        assert_eq!(
            days,
            vec![
                MemoryDay {
                    day: "2026-09-25".to_string(),
                    count: 4
                },
                MemoryDay {
                    day: "2026-09-26".to_string(),
                    count: 0
                },
            ]
        );
    }

    #[test]
    fn memory_hours_cover_a_day_window_on_the_viewer_clock() {
        // 24h ending 16:30 UTC, seen from UTC+7: 23:30 local on the 24th to
        // 23:30 local on the 25th.
        let start = DateTime::parse_from_rfc3339("2026-09-24T16:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-09-25T16:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let hours = fill_memory_hours(
            &[
                ("2026-09-24T23:00".to_string(), 3),
                ("2026-09-25T14:00".to_string(), 9),
            ],
            start,
            end,
            420,
        );
        // Partial first and last hours: 25 buckets for a 24h window.
        assert_eq!(hours.len(), 25);
        assert_eq!(hours[0].hour, "2026-09-24T23:00");
        assert_eq!(hours[0].count, 3);
        assert_eq!(hours[24].hour, "2026-09-25T23:00");
        let peak = hours.iter().find(|h| h.hour == "2026-09-25T14:00").unwrap();
        assert_eq!(peak.count, 9);
        assert_eq!(hours.iter().map(|h| h.count).sum::<i64>(), 12);
    }

    #[test]
    fn memory_hours_handle_negative_offsets_and_empty_windows() {
        let at = DateTime::parse_from_rfc3339("2026-09-25T02:10:00Z")
            .unwrap()
            .with_timezone(&Utc);
        // UTC-5: 02:10Z is 21:10 on the previous local day.
        let hours = fill_memory_hours(&[], at, at, -300);
        assert_eq!(
            hours,
            vec![MemoryHour {
                hour: "2026-09-24T21:00".to_string(),
                count: 0
            }]
        );
        assert!(fill_memory_hours(&[], at, at - Duration::hours(1), 0).is_empty());
    }
}

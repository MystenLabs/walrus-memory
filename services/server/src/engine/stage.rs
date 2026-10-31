//! Which step of a recall is running, so one that runs out of time can say
//! where it was stuck.
//!
//! The handler owns a [`StageMarker`] and runs the recall inside
//! [`run_with_deadline`], which makes that marker the task's current one.
//! Anything the recall awaits on the same task — the engine's `fetch_batch`
//! included — calls [`enter`] as it moves on, so the trait needs no extra
//! parameter. Outside a recall (`analyze` shares `fetch_batch`) `enter` does
//! nothing.

use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

/// Left for the 504 to reach the caller before its own deadline fires.
const DEADLINE_MARGIN: Duration = Duration::from_millis(1_000);
/// Least a short caller deadline is given: less cannot fit an embed, so
/// cutting there would only turn recalls that might have finished into errors.
const MIN_BUDGET: Duration = Duration::from_millis(2_000);
/// Upper bound on a caller-supplied deadline, so no number can overflow an
/// `Instant`. Ten minutes is far past anything a recall caller waits.
const MAX_DEADLINE_MS: u64 = 600_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecallStage {
    Embed = 0,
    VectorSearch = 1,
    WalrusDownload = 2,
    SealDecrypt = 3,
    /// Before the recall started: credential check and rate limiting. Only
    /// reported when that alone used up the caller's deadline.
    Auth = 4,
}

impl RecallStage {
    /// The id sent to callers in a `RECALL_TIMEOUT` body.
    pub fn as_str(self) -> &'static str {
        match self {
            RecallStage::Embed => "embed",
            RecallStage::VectorSearch => "vector_search",
            RecallStage::WalrusDownload => "walrus_download",
            RecallStage::SealDecrypt => "seal_decrypt",
            RecallStage::Auth => "auth",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            0 => RecallStage::Embed,
            1 => RecallStage::VectorSearch,
            2 => RecallStage::WalrusDownload,
            3 => RecallStage::SealDecrypt,
            _ => RecallStage::Auth,
        }
    }
}

/// The stage one recall is in. Shared, because the handler has to read it
/// after the timed-out work has been dropped.
#[derive(Clone, Default)]
pub struct StageMarker(Arc<AtomicU8>);

impl StageMarker {
    pub fn set(&self, stage: RecallStage) {
        self.0.store(stage as u8, Ordering::Relaxed);
    }

    pub fn get(&self) -> RecallStage {
        RecallStage::from_u8(self.0.load(Ordering::Relaxed))
    }
}

#[derive(Clone)]
struct RecallTaskContext {
    marker: StageMarker,
    deadline: Option<Instant>,
}

tokio::task_local! {
    static CURRENT: RecallTaskContext;
}

/// Mark `stage` as running for the recall this task is serving.
pub fn enter(stage: RecallStage) {
    let _ = CURRENT.try_with(|ctx| ctx.marker.set(stage));
}

/// Remaining deadline budget for the recall this task is serving, or `None`
/// when running without a deadline (or outside `run_with_deadline`).
pub fn remaining_budget() -> Option<Duration> {
    CURRENT
        .try_with(|ctx| {
            ctx.deadline
                .map(|deadline| deadline.saturating_duration_since(Instant::now()))
        })
        .ok()
        .flatten()
}

/// Sleep `backoff` before retrying transient work only if the remaining recall
/// deadline still leaves at least `backoff + min_headroom` for the retry to
/// complete. Returns `true` when the caller should proceed with the retry, or
/// `false` when insufficient budget remains.
pub async fn backoff_if_budget_allows(backoff: Duration, min_headroom: Duration) -> bool {
    if let Some(left) = remaining_budget() {
        if left < backoff.saturating_add(min_headroom) {
            return false;
        }
    }
    tokio::time::sleep(backoff).await;
    true
}

/// What a caller's deadline leaves for the recall.
#[derive(Debug, PartialEq, Eq)]
pub enum Budget {
    /// No deadline sent: run to completion.
    Unbounded,
    /// Stop after this long.
    Run(Duration),
    /// The deadline went on auth and rate limiting. Any work now would
    /// answer a caller that has already given up.
    Exhausted,
}

/// What a caller that waits `deadline_ms` leaves for the recall, `already`
/// having passed since the request arrived.
pub fn budget_for(deadline_ms: Option<u64>, already: Duration) -> Budget {
    let Some(deadline_ms) = deadline_ms else {
        return Budget::Unbounded;
    };
    // The floor is for a short deadline, never for time already spent.
    let usable = Duration::from_millis(deadline_ms.min(MAX_DEADLINE_MS))
        .saturating_sub(DEADLINE_MARGIN)
        .max(MIN_BUDGET);
    match usable.checked_sub(already) {
        Some(left) if !left.is_zero() => Budget::Run(left),
        _ => Budget::Exhausted,
    }
}

#[derive(Debug)]
pub struct StageTimedOut {
    pub stage: RecallStage,
    pub elapsed: Duration,
}

/// Run `fut` as the recall `marker` tracks, giving up at `deadline`.
pub async fn run_with_deadline<F: Future>(
    marker: &StageMarker,
    deadline: Option<Instant>,
    fut: F,
) -> Result<F::Output, StageTimedOut> {
    let started = Instant::now();
    let ctx = RecallTaskContext {
        marker: marker.clone(),
        deadline,
    };
    let tracked = CURRENT.scope(ctx, fut);
    let Some(deadline) = deadline else {
        return Ok(tracked.await);
    };
    tokio::time::timeout_at(deadline, tracked)
        .await
        .map_err(|_| StageTimedOut {
            stage: marker.get(),
            elapsed: started.elapsed(),
        })
}

/// Logs the stage a recall was in if it is dropped before finishing, which
/// is what happens when the caller hangs up. Covers every caller, including
/// those that send no deadline.
pub struct HangUpGuard {
    marker: StageMarker,
    owner: String,
    started: Instant,
    armed: bool,
}

impl HangUpGuard {
    pub fn new(marker: StageMarker, owner: String) -> Self {
        Self {
            marker,
            owner,
            started: Instant::now(),
            armed: true,
        }
    }

    /// The recall finished (or answered its own timeout); nothing to report.
    pub fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for HangUpGuard {
    fn drop(&mut self) {
        // A panic unwinding through the handler is not the caller hanging
        // up, and reports itself.
        if self.armed && !std::thread::panicking() {
            tracing::warn!(
                owner = %self.owner,
                stage = self.marker.get().as_str(),
                elapsed_ms = self.started.elapsed().as_millis() as u64,
                "recall abandoned by the caller before it finished"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_missed_deadline_names_the_stage_that_was_running() {
        let marker = StageMarker::default();
        let deadline = Instant::now() + Duration::from_secs(14);
        let outcome = run_with_deadline(&marker, Some(deadline), async {
            enter(RecallStage::Embed);
            tokio::time::sleep(Duration::from_secs(1)).await;
            enter(RecallStage::WalrusDownload);
            tokio::time::sleep(Duration::from_secs(60)).await;
        })
        .await;

        let timed_out = outcome.expect_err("a 60s download must not fit a 14s budget");
        assert_eq!(timed_out.stage, RecallStage::WalrusDownload);
        assert_eq!(timed_out.elapsed, Duration::from_secs(14));
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_budget_the_recall_runs_to_completion() {
        // Callers that send no deadline (Python, older SDKs) must see
        // exactly today's behaviour: however slow, the recall finishes.
        let marker = StageMarker::default();
        let outcome = run_with_deadline(&marker, None, async {
            tokio::time::sleep(Duration::from_secs(600)).await;
            7
        })
        .await;

        assert_eq!(outcome.unwrap(), 7);
    }

    #[tokio::test]
    async fn entering_a_stage_outside_a_recall_does_nothing() {
        // `analyze` shares `fetch_batch`, which marks the decrypt step.
        enter(RecallStage::SealDecrypt);
    }

    #[test]
    fn stage_ids_are_the_wire_names() {
        assert_eq!(RecallStage::Embed.as_str(), "embed");
        assert_eq!(RecallStage::VectorSearch.as_str(), "vector_search");
        assert_eq!(RecallStage::WalrusDownload.as_str(), "walrus_download");
        assert_eq!(RecallStage::SealDecrypt.as_str(), "seal_decrypt");
        assert_eq!(RecallStage::Auth.as_str(), "auth");
    }

    #[test]
    fn a_fresh_marker_starts_at_embed_and_follows_set() {
        let marker = StageMarker::default();
        assert_eq!(marker.get(), RecallStage::Embed);
        marker.set(RecallStage::SealDecrypt);
        assert_eq!(marker.get(), RecallStage::SealDecrypt);
    }

    #[test]
    fn the_budget_leaves_the_caller_a_second() {
        let none = Duration::ZERO;
        assert_eq!(budget_for(None, none), Budget::Unbounded);
        assert_eq!(
            budget_for(Some(15_000), none),
            Budget::Run(Duration::from_millis(14_000))
        );
        // Capped, so no caller-supplied number can overflow an `Instant`.
        assert_eq!(
            budget_for(Some(u64::MAX), none),
            Budget::Run(Duration::from_millis(599_000))
        );
    }

    #[test]
    fn a_short_deadline_still_gets_the_floor() {
        // Less than this cannot fit an embed.
        assert_eq!(
            budget_for(Some(1_500), Duration::ZERO),
            Budget::Run(Duration::from_millis(2_000))
        );
    }

    #[test]
    fn time_spent_before_the_handler_comes_out_of_the_budget() {
        // Auth on a cold delegate key can take seconds; the caller's clock
        // was running through all of it.
        assert_eq!(
            budget_for(Some(15_000), Duration::from_millis(3_000)),
            Budget::Run(Duration::from_millis(11_000))
        );
        // No floor once time is spent: 2s here would outlive the caller.
        assert_eq!(
            budget_for(Some(15_000), Duration::from_millis(13_500)),
            Budget::Run(Duration::from_millis(500))
        );
    }

    #[test]
    fn a_deadline_spent_before_the_recall_starts_is_exhausted() {
        assert_eq!(
            budget_for(Some(15_000), Duration::from_millis(14_000)),
            Budget::Exhausted
        );
        assert_eq!(
            budget_for(Some(15_000), Duration::from_millis(20_000)),
            Budget::Exhausted
        );
        assert_eq!(
            budget_for(Some(1_500), Duration::from_millis(3_000)),
            Budget::Exhausted
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_respects_remaining_deadline_headroom() {
        let marker = StageMarker::default();
        let deadline = Instant::now() + Duration::from_millis(1_500);
        run_with_deadline(&marker, Some(deadline), async {
            assert_eq!(remaining_budget(), Some(Duration::from_millis(1_500)));
            // 200ms backoff + 1000ms headroom = 1200ms <= 1500ms: allowed.
            let retried =
                backoff_if_budget_allows(Duration::from_millis(200), Duration::from_millis(1_000))
                    .await;
            assert!(retried);
            assert_eq!(remaining_budget(), Some(Duration::from_millis(1_300)));

            tokio::time::sleep(Duration::from_millis(250)).await;
            // Only 1050ms left (< 1200ms required): skipped immediately without sleeping.
            let skipped =
                backoff_if_budget_allows(Duration::from_millis(200), Duration::from_millis(1_000))
                    .await;
            assert!(!skipped);
            assert_eq!(remaining_budget(), Some(Duration::from_millis(1_050)));
        })
        .await
        .expect("within deadline");
    }
}

//! Client-side token estimation and recall budget truncation.
//!
//! Mirrors the TypeScript SDK token-budgeting utilities so Rust agents can bound
//! recalled context size deterministically without shipping a full BPE tokenizer.

use serde::{Deserialize, Serialize};

use crate::types::RecallMemory;

/// Average Unicode scalar values per token used by [`estimate_tokens`].
pub const CHARS_PER_TOKEN: usize = 4;

/// Strategy used when [`crate::RecallParams::with_max_tokens`] trims recalled hits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum TruncationStrategy {
    /// Retains whole lowest-distance hits that fit within the budget and returns
    /// them in the caller's original order. Never truncates individual memory text.
    #[default]
    HighRelevanceOnly,
    /// Allocates an equal `max_tokens / hit_count` share to every hit and trims
    /// each text to that share.
    PerHitCap,
    /// Keeps whole hits from the front and truncates the single boundary hit that
    /// straddles the remaining token budget.
    DropTail,
}

/// Token-budget telemetry attached to [`crate::RecallResult::meta`] when a
/// `max_tokens` budget was requested on `recall`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RecallTokenMeta {
    /// Post-truncation estimated token count across all returned `results`.
    pub token_estimate: usize,
    /// `true` when at least one hit was dropped or shortened to fit `max_tokens`.
    pub truncated: bool,
}

/// Estimates the LLM token cost of `text` using a deterministic `ceil(chars / 4)`
/// Unicode scalar approximation.
///
/// # Examples
///
/// ```
/// assert_eq!(memwal::estimate_tokens(""), 0);
/// assert_eq!(memwal::estimate_tokens("rust"), 1);
/// assert_eq!(memwal::estimate_tokens("hello world!"), 3);
/// ```
#[must_use]
pub fn estimate_tokens(text: &str) -> usize {
    let chars = text.chars().count();
    chars.div_ceil(CHARS_PER_TOKEN)
}

fn payload_tokens(results: &[RecallMemory]) -> usize {
    results.iter().map(|m| estimate_tokens(&m.text)).sum()
}

fn truncate_to_token_budget(text: &str, token_budget: usize) -> String {
    if token_budget == 0 {
        return String::new();
    }
    let max_chars = token_budget.saturating_mul(CHARS_PER_TOKEN);
    text.chars().take(max_chars).collect()
}

/// Applies `max_tokens` truncation to `results` according to `strategy`.
pub(crate) fn apply_token_budget(
    results: Vec<RecallMemory>,
    max_tokens: usize,
    strategy: TruncationStrategy,
) -> (Vec<RecallMemory>, RecallTokenMeta) {
    let original_count = results.len();
    if max_tokens == 0 {
        return (
            Vec::new(),
            RecallTokenMeta {
                token_estimate: 0,
                truncated: original_count > 0,
            },
        );
    }

    let full_cost = payload_tokens(&results);
    if full_cost <= max_tokens {
        return (
            results,
            RecallTokenMeta {
                token_estimate: full_cost,
                truncated: false,
            },
        );
    }

    match strategy {
        TruncationStrategy::PerHitCap => apply_per_hit_cap(results, max_tokens, original_count),
        TruncationStrategy::DropTail => apply_drop_tail(results, max_tokens),
        TruncationStrategy::HighRelevanceOnly => {
            apply_high_relevance(results, max_tokens, original_count)
        }
    }
}

fn apply_per_hit_cap(
    results: Vec<RecallMemory>,
    max_tokens: usize,
    original_count: usize,
) -> (Vec<RecallMemory>, RecallTokenMeta) {
    let per_hit = max_tokens / original_count.max(1);
    let mut capped = Vec::new();
    if per_hit > 0 {
        for mut memory in results {
            let trimmed = truncate_to_token_budget(&memory.text, per_hit);
            if !trimmed.is_empty() {
                memory.text = trimmed;
                capped.push(memory);
            }
        }
    }
    let estimate = payload_tokens(&capped);
    (
        capped,
        RecallTokenMeta {
            token_estimate: estimate,
            truncated: true,
        },
    )
}

fn apply_drop_tail(
    results: Vec<RecallMemory>,
    max_tokens: usize,
) -> (Vec<RecallMemory>, RecallTokenMeta) {
    let mut kept = Vec::new();
    let mut running = 0_usize;
    for mut memory in results {
        let cost = estimate_tokens(&memory.text);
        if running.saturating_add(cost) <= max_tokens {
            running = running.saturating_add(cost);
            kept.push(memory);
            continue;
        }
        let remaining = max_tokens.saturating_sub(running);
        if remaining > 0 {
            let trimmed = truncate_to_token_budget(&memory.text, remaining);
            if !trimmed.is_empty() {
                running = running.saturating_add(estimate_tokens(&trimmed));
                memory.text = trimmed;
                kept.push(memory);
            }
        }
        break;
    }
    (
        kept,
        RecallTokenMeta {
            token_estimate: running,
            truncated: true,
        },
    )
}

fn apply_high_relevance(
    results: Vec<RecallMemory>,
    max_tokens: usize,
    original_count: usize,
) -> (Vec<RecallMemory>, RecallTokenMeta) {
    let mut order: Vec<(usize, f64, usize)> = results
        .iter()
        .enumerate()
        .map(|(idx, m)| {
            let dist = if m.distance.is_finite() {
                m.distance.max(0.0)
            } else {
                f64::INFINITY
            };
            (idx, dist, estimate_tokens(&m.text))
        })
        .collect();

    order.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let mut keep_mask = vec![false; original_count];
    let mut running = 0_usize;
    for (idx, _dist, cost) in order {
        if running.saturating_add(cost) > max_tokens {
            break;
        }
        keep_mask[idx] = true;
        running = running.saturating_add(cost);
    }

    let kept = results
        .into_iter()
        .enumerate()
        .filter_map(|(idx, m)| keep_mask[idx].then_some(m))
        .collect();

    (
        kept,
        RecallTokenMeta {
            token_estimate: running,
            truncated: true,
        },
    )
}

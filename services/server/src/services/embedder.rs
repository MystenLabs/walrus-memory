//! Embedder service — turns text into a fixed-dimension vector for similarity search.
//!
//! The default production impl (`OpenAiEmbedder`) calls an OpenAI-compatible
//! `/embeddings` endpoint (OpenAI proper, OpenRouter, or any compatible
//! gateway) using `openai/text-embedding-3-small` (1536-dim). When no API
//! key is configured, it falls back to a deterministic hash-based mock so
//! dev environments can run without keys.
//!
//! Lifted verbatim from `routes.rs::generate_embedding` — same model,
//! same request shape, same mock fallback.

use async_trait::async_trait;
use std::sync::Arc;

use crate::types::{AppError, Config};

/// Embedding model used for both ingestion and recall-query embeddings.
/// Kept here (was a `routes.rs` const) — the recall query-embedding cache
/// key in `routes.rs` references it via `crate::services::embedder::EMBEDDING_MODEL`
/// so the cache key changes if the model changes.
pub const EMBEDDING_MODEL: &str = "openai/text-embedding-3-small";

/// Embedding vector dimensionality (text-embedding-3-small). Also the
/// width of the deterministic mock vector, and the fixed width of the
/// `vector_entries.embedding` pgvector column — client-supplied vectors
/// on the manual write path are validated against it.
pub const EMBEDDING_DIMS: usize = 1536;

/// 16384 = 8192 tokens × 2 chars/token under cl100k; do not use admin 64KiB.
///
/// A limit of [`EMBEDDING_MODEL`]'s context window, so it applies only when a
/// provider key is set. The key-less fallback hashes locally with no limit.
pub(crate) const MAX_EMBED_INPUT_BYTES: usize = 16384;

/// Whether a provider 400 complains about input length; any other 400 is a
/// server-side problem, not the caller's.
fn is_context_length_error(body: &str) -> bool {
    let body = body.to_ascii_lowercase();
    [
        "context_length_exceeded",
        "maximum context length",
        "reduce the length",
        "too many tokens",
        "string too long",
    ]
    .iter()
    .any(|needle| body.contains(needle))
}

fn reject_oversized_embed_input(text: &str) -> Result<(), AppError> {
    if text.len() > MAX_EMBED_INPUT_BYTES {
        return Err(AppError::BadRequest(format!(
            "input is over the embedding input limit of {MAX_EMBED_INPUT_BYTES} bytes"
        )));
    }
    Ok(())
}

#[async_trait]
pub trait Embedder: Send + Sync {
    /// Embed a single text into a vector. Returns the vector or an error if
    /// the embedding API call fails (network, auth, parse).
    async fn embed(&self, text: &str) -> Result<Vec<f32>, AppError>;
}

// ============================================================
// OpenAI / OpenRouter implementation (with mock fallback)
// ============================================================

pub struct OpenAiEmbedder {
    http_client: reqwest::Client,
    config: Arc<Config>,
    alerts: Option<Arc<crate::alerts::AlertManager>>,
}

impl OpenAiEmbedder {
    pub fn new(http_client: reqwest::Client, config: Arc<Config>) -> Self {
        Self {
            http_client,
            config,
            alerts: None,
        }
    }

    pub fn with_alerts(mut self, alerts: Arc<crate::alerts::AlertManager>) -> Self {
        self.alerts = Some(alerts);
        self
    }
}

#[async_trait]
impl Embedder for OpenAiEmbedder {
    #[tracing::instrument(name = "embedder.embed", skip_all, fields(text_len = text.len()))]
    async fn embed(&self, text: &str) -> Result<Vec<f32>, AppError> {
        let alert_ctx = self
            .alerts
            .as_deref()
            .map(|alerts| (alerts, self.config.sui_network.as_str()));
        embed_text_with_alerts(
            &self.http_client,
            self.config.openai_api_key.as_deref(),
            &self.config.openai_api_base,
            text,
            alert_ctx,
        )
        .await
    }
}

/// The embedding call itself, taking only what it reads from `Config` so the
/// tests can drive it against a local stand-in provider.
#[cfg(test)]
async fn embed_text(
    http_client: &reqwest::Client,
    api_key: Option<&str>,
    api_base: &str,
    text: &str,
) -> Result<Vec<f32>, AppError> {
    embed_text_with_alerts(http_client, api_key, api_base, text, None).await
}

pub(crate) async fn embed_text_with_alerts(
    http_client: &reqwest::Client,
    api_key: Option<&str>,
    api_base: &str,
    text: &str,
    alert_ctx: Option<(&crate::alerts::AlertManager, &str)>,
) -> Result<Vec<f32>, AppError> {
    match api_key {
        Some(api_key) => {
            reject_oversized_embed_input(text)?;
            // Real embedding via OpenRouter/OpenAI-compatible API
            let url = format!("{}/embeddings", api_base);

            let started = std::time::Instant::now();
            let resp = http_client
                .post(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&EmbeddingApiRequest {
                    model: EMBEDDING_MODEL.to_string(),
                    input: text.to_string(),
                })
                .send()
                .await
                .map_err(|e| {
                    crate::observability::observe_external(
                        "openai",
                        "embeddings",
                        "transport_error",
                        started.elapsed(),
                    );
                    AppError::EmbeddingProviderUnavailable(format!("Embedding API request failed: {}", e))
                })?;
            let status_label = resp.status().as_u16().to_string();
            crate::observability::observe_external(
                "openai",
                "embeddings",
                &status_label,
                started.elapsed(),
            );

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if crate::services::extractor::is_upstream_provider_auth_or_quota_status(status) {
                    if let Some((alerts, sui_network)) = alert_ctx {
                        let _ = alerts
                            .notify_embedding_provider_auth_failed(
                                crate::alerts::EmbeddingProviderAuthAlert {
                                    sui_network: sui_network.to_string(),
                                    status: status.as_u16(),
                                    api_base: api_base.to_string(),
                                    error: body.clone(),
                                },
                            )
                            .await;
                    }
                    return Err(AppError::EmbeddingProviderUnavailable(format!(
                        "Embedding API upstream error ({}): {}",
                        status, body
                    )));
                }
                if crate::services::extractor::is_upstream_status_transient(status)
                    || status == reqwest::StatusCode::REQUEST_TIMEOUT
                {
                    return Err(AppError::EmbeddingProviderUnavailable(format!(
                        "Embedding API upstream error ({}): {}",
                        status, body
                    )));
                }
                if status == reqwest::StatusCode::BAD_REQUEST && is_context_length_error(&body) {
                    tracing::warn!(%status, body, "embedding API rejected the input length");
                    return Err(AppError::BadRequest(
                        "embedding input exceeds the model context limit".into(),
                    ));
                }
                return Err(AppError::Internal(format!(
                    "Embedding API error ({}): {}",
                    status, body
                )));
            }

            // same pattern as the extractor — capture body
            // as text first so we can (1) treat transport-level
            // failures as transient, and (2) detect OpenRouter
            // error envelopes wrapped in HTTP 200. Both route to
            // `AppError::EmbeddingProviderUnavailable` (HTTP 503) so the
            // SDK / harness retry policy can recover. See
            // `extractor::parse_openrouter_error_envelope`.
            let body = resp.text().await.map_err(|e| {
                AppError::EmbeddingProviderUnavailable(format!(
                    "Failed to read embedding response body: {}",
                    e
                ))
            })?;

            if let Some(envelope) =
                crate::services::extractor::parse_openrouter_error_envelope(&body)
            {
                if matches!(envelope.code, 401..=403) {
                    if let Some((alerts, sui_network)) = alert_ctx {
                        let _ = alerts
                            .notify_embedding_provider_auth_failed(
                                crate::alerts::EmbeddingProviderAuthAlert {
                                    sui_network: sui_network.to_string(),
                                    status: envelope.code as u16,
                                    api_base: api_base.to_string(),
                                    error: body.clone(),
                                },
                            )
                            .await;
                    }
                }
                return Err(AppError::EmbeddingProviderUnavailable(format!(
                    "OpenRouter upstream error (code={}): {}",
                    envelope.code, envelope.message
                )));
            }

            let api_resp: EmbeddingApiResponse = serde_json::from_str(&body).map_err(|e| {
                AppError::EmbeddingProviderUnavailable(format!("Failed to parse embedding response: {}", e))
            })?;

            let vector = api_resp
                .data
                .into_iter()
                .next()
                .ok_or_else(|| {
                    AppError::EmbeddingProviderUnavailable("Embedding API returned no data".into())
                })?
                .embedding;
            Ok(vector)
        }
        None => {
            // Mock embedding (deterministic hash-based) — for keyless dev
            tracing::warn!("  → Using MOCK embedding (no OPENAI_API_KEY set)");
            use sha2::Digest;
            let hash = sha2::Sha256::digest(text.as_bytes());
            let mock_vector: Vec<f32> = hash
                .iter()
                .cycle()
                .take(EMBEDDING_DIMS)
                .enumerate()
                .map(|(i, &b)| {
                    let val = (b as f32 / 255.0) * 2.0 - 1.0;
                    val * (1.0 + (i as f32 * 0.001).sin())
                })
                .collect();
            Ok(mock_vector)
        }
    }
}

// ============================================================
// OpenAI-compatible API types (private to this module)
// ============================================================

#[derive(serde::Serialize)]
struct EmbeddingApiRequest {
    model: String,
    input: String,
}

#[derive(serde::Deserialize)]
struct EmbeddingApiResponse {
    data: Vec<EmbeddingData>,
}

#[derive(serde::Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

#[cfg(test)]
mod tests {
    /// parity test — the embedder routes OpenRouter-error-envelope
    /// bodies to `AppError::EmbeddingProviderUnavailable` via the SHARED helper
    /// `extractor::parse_openrouter_error_envelope`. If a future refactor
    /// breaks the cross-module import or call site, this catches it at
    /// compile time + test time without needing to mock reqwest.
    ///
    /// The full unit coverage of the envelope-parser shape (whitespace
    /// padding, valid-completion non-matches, both-fields edge case,
    /// malformed-JSON fallthrough) lives in `extractor::tests`. Don't
    /// duplicate it here — duplicating only adds maintenance cost; the
    /// helper is the same function.
    #[test]
    fn embedder_uses_shared_openrouter_envelope_parser() {
        // Real failing body shape captured from the LME v2 bench
        // investigation (200 OK wrapping a 504-gateway-timeout error).
        let body = r#"{"error":{"message":"The operation was aborted","code":504}}"#;
        let envelope = crate::services::extractor::parse_openrouter_error_envelope(body)
            .expect("embedder must be able to detect the same envelope shape as the extractor");
        assert_eq!(envelope.code, 504);
        assert_eq!(envelope.message, "The operation was aborted");
    }

    fn assert_bad_request(result: Result<(), crate::types::AppError>, needle: &str) {
        match result {
            Err(crate::types::AppError::BadRequest(msg)) => {
                assert!(
                    msg.contains(needle),
                    "expected error mentioning {needle:?}, got: {msg}"
                );
            }
            other => panic!("expected BadRequest containing {needle:?}, got: {other:?}"),
        }
    }

    #[test]
    fn embed_input_at_byte_limit_is_accepted() {
        super::reject_oversized_embed_input(&"q".repeat(super::MAX_EMBED_INPUT_BYTES)).unwrap();
    }

    #[test]
    fn embed_input_over_byte_limit_is_bad_request() {
        assert_bad_request(
            super::reject_oversized_embed_input(&"q".repeat(16400)),
            "input is over the embedding input limit",
        );
        assert_bad_request(
            super::reject_oversized_embed_input(&"q".repeat(16385)),
            "input is over the embedding input limit",
        );
    }

    // ── embed_text: size limit and upstream 400 mapping ──────────────

    /// Stand-in embeddings provider answering every `POST /embeddings` with
    /// `status` and `body`. Returns its base URL and a call counter.
    async fn stub_provider(
        status: u16,
        body: &'static str,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&calls);
        let app = axum::Router::new().route(
            "/embeddings",
            axum::routing::post(move || {
                let counter = std::sync::Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    (axum::http::StatusCode::from_u16(status).unwrap(), body)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), calls)
    }

    #[tokio::test]
    async fn without_a_key_input_over_the_model_limit_still_embeds() {
        let text = "a".repeat(100 * 1024);
        let vector = super::embed_text(
            &reqwest::Client::new(),
            None,
            "http://unused.invalid",
            &text,
        )
        .await
        .expect("key-less embedding has no input limit");
        assert_eq!(vector.len(), super::EMBEDDING_DIMS);
    }

    #[tokio::test]
    async fn with_a_key_oversized_input_is_rejected_before_calling_the_provider() {
        let (base, calls) = stub_provider(200, r#"{"data":[{"embedding":[0.0]}]}"#).await;
        let text = "q".repeat(super::MAX_EMBED_INPUT_BYTES + 1);
        let result = super::embed_text(&reqwest::Client::new(), Some("key"), &base, &text).await;
        assert!(
            matches!(result, Err(crate::types::AppError::BadRequest(_))),
            "got {result:?}"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_provider_400_about_input_length_is_the_callers_bad_request() {
        for body in [
            r#"{"error":{"code":"context_length_exceeded","message":"..."}}"#,
            r#"{"error":{"message":"This model's maximum context length is 8192 tokens"}}"#,
            r#"{"error":{"message":"Please reduce the length of the messages."}}"#,
            r#"{"error":{"message":"Too many tokens in input"}}"#,
            r#"{"error":{"message":"String too long. Expected a string with maximum length 8192"}}"#,
        ] {
            let (base, _) = stub_provider(400, body).await;
            let result = super::embed_text(&reqwest::Client::new(), Some("key"), &base, "q").await;
            assert!(
                matches!(result, Err(crate::types::AppError::BadRequest(_))),
                "{body} → {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn any_other_provider_400_is_an_internal_error() {
        for body in [
            r#"{"error":{"message":"The model `text-embedding-9` does not exist"}}"#,
            r#"{"error":{"code":"invalid_api_key","message":"Incorrect API key provided"}}"#,
            r#"{"error":{"message":"Unrecognized request argument supplied: dimensions"}}"#,
            "",
        ] {
            let (base, _) = stub_provider(400, body).await;
            let result = super::embed_text(&reqwest::Client::new(), Some("key"), &base, "q").await;
            assert!(
                matches!(result, Err(crate::types::AppError::Internal(_))),
                "{body} → {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn provider_401_unauthorized_returns_upstream_unavailable() {
        let (base, _) =
            stub_provider(401, r#"{"error":{"message":"User not found.","code":401}}"#).await;
        let result = super::embed_text(&reqwest::Client::new(), Some("key"), &base, "q").await;
        assert!(
            matches!(result, Err(crate::types::AppError::EmbeddingProviderUnavailable(_))),
            "401 must map to UpstreamUnavailable, got {result:?}"
        );
    }

    #[tokio::test]
    async fn provider_402_payment_required_returns_upstream_unavailable() {
        let (base, _) = stub_provider(
            402,
            r#"{"error":{"message":"Insufficient credits","code":402}}"#,
        )
        .await;
        let result = super::embed_text(&reqwest::Client::new(), Some("key"), &base, "q").await;
        assert!(
            matches!(result, Err(crate::types::AppError::EmbeddingProviderUnavailable(_))),
            "402 must map to UpstreamUnavailable, got {result:?}"
        );
    }

    #[tokio::test]
    async fn provider_403_forbidden_returns_upstream_unavailable() {
        let (base, _) =
            stub_provider(403, r#"{"error":{"message":"Key disabled","code":403}}"#).await;
        let result = super::embed_text(&reqwest::Client::new(), Some("key"), &base, "q").await;
        assert!(
            matches!(result, Err(crate::types::AppError::EmbeddingProviderUnavailable(_))),
            "403 must map to UpstreamUnavailable, got {result:?}"
        );
    }

    #[tokio::test]
    async fn transport_errors_connection_refused_and_timeout_return_upstream_unavailable() {
        // 1. Connection refused (bind and immediately drop listener).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = listener.local_addr().unwrap();
        drop(listener);
        let refused = super::embed_text(
            &reqwest::Client::new(),
            Some("key"),
            &format!("http://{closed_addr}"),
            "q",
        )
        .await;
        assert!(
            matches!(refused, Err(crate::types::AppError::EmbeddingProviderUnavailable(_))),
            "connection refused must map to UpstreamUnavailable, got {refused:?}"
        );

        // 2. Request timeout against a stalled provider.
        let app = axum::Router::new().route(
            "/embeddings",
            axum::routing::post(|| async move {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                (
                    axum::http::StatusCode::OK,
                    r#"{"data":[{"embedding":[0.0]}]}"#,
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let short_timeout_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(30))
            .build()
            .unwrap();
        let timed_out = super::embed_text(
            &short_timeout_client,
            Some("key"),
            &format!("http://{slow_addr}"),
            "q",
        )
        .await;
        assert!(
            matches!(
                timed_out,
                Err(crate::types::AppError::EmbeddingProviderUnavailable(_))
            ),
            "timeout must map to UpstreamUnavailable, got {timed_out:?}"
        );
    }

    #[tokio::test]
    async fn provider_200_with_non_json_or_empty_data_returns_upstream_unavailable() {
        for body in [
            "<html><body>502 Bad Gateway</body></html>",
            "not json",
            r#"{"data":[]}"#,
        ] {
            let (base, _) = stub_provider(200, body).await;
            let result = super::embed_text(&reqwest::Client::new(), Some("key"), &base, "q").await;
            assert!(
                matches!(result, Err(crate::types::AppError::EmbeddingProviderUnavailable(_))),
                "200 body {body:?} must map to UpstreamUnavailable, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn provider_401_402_403_emits_one_slack_alert_per_dedup_window() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let slack_hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&slack_hits);
        let slack_app = axum::Router::new().route(
            "/slack",
            axum::routing::post(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::OK
                }
            }),
        );
        let slack_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slack_addr = slack_listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(slack_listener, slack_app).await.unwrap() });

        let webhook_url = format!("http://{slack_addr}/slack");
        let alerts = crate::alerts::AlertManager::from_webhook_value(
            reqwest::Client::new(),
            Some(&webhook_url),
        );

        for (status, body) in [
            (401, r#"{"error":{"message":"User not found.","code":401}}"#),
            (
                402,
                r#"{"error":{"message":"Insufficient credits","code":402}}"#,
            ),
            (403, r#"{"error":{"message":"Key disabled","code":403}}"#),
        ] {
            let (base, _) = stub_provider(status, body).await;
            let result = super::embed_text_with_alerts(
                &reqwest::Client::new(),
                Some("key"),
                &base,
                "q",
                Some((&alerts, "mainnet")),
            )
            .await;
            assert!(
                matches!(result, Err(crate::types::AppError::EmbeddingProviderUnavailable(_))),
                "status {status} → {result:?}"
            );
        }

        assert_eq!(
            slack_hits.load(Ordering::SeqCst),
            1,
            "401/402/403 burst must emit exactly one Slack alert within the dedup window"
        );
    }

    #[tokio::test]
    async fn stub_provider_401_end_to_end_returns_503_code_without_leaking_body() {
        use axum::response::IntoResponse;

        let (base, _) =
            stub_provider(401, r#"{"error":{"message":"User not found.","code":401}}"#).await;
        let err = super::embed_text(&reqwest::Client::new(), Some("key"), &base, "hello")
            .await
            .expect_err("401 provider must fail");

        let resp = err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["code"].as_str(),
            Some(crate::types::EMBEDDING_PROVIDER_UNAVAILABLE_CODE)
        );
        assert!(
            json["traceId"].as_str().is_some_and(|t| !t.is_empty()),
            "expected non-empty traceId in 503 body: {json}"
        );
        assert!(
            !text.contains("User not found"),
            "503 response body must not leak upstream provider error message: {text}"
        );
    }
}

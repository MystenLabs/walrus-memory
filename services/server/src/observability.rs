use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use opentelemetry::{
    global,
    propagation::{Extractor, Injector},
    trace::TracerProvider as _,
    KeyValue,
};
use opentelemetry_sdk::{
    logs::SdkLoggerProvider, propagation::TraceContextPropagator, trace::SdkTracerProvider,
    Resource,
};
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec,
};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::types::AppState;

const X_REQUEST_ID: &str = "x-request-id";
const X_CORRELATION_ID: &str = "x-correlation-id";
const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
const OTLP_HEADERS_ENV: &str = "OTEL_EXPORTER_OTLP_HEADERS";
const OTLP_TRACES_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
const OTLP_LOGS_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT";
const OTEL_SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";
const DEFAULT_OTEL_SERVICE_NAME: &str = "memwal-relayer";

#[derive(Clone, Debug)]
pub struct RequestContext {
    request_id: String,
    route: String,
    /// When the request reached the relayer, before auth and rate limiting,
    /// so a caller-supplied deadline can be measured from arrival.
    started: Instant,
}

tokio::task_local! {
    static REQUEST_CONTEXT: RequestContext;
}

pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    logger_provider: Option<SdkLoggerProvider>,
}

impl TelemetryGuard {
    pub fn shutdown(self) {
        if let Some(tracer_provider) = self.tracer_provider {
            if let Err(err) = tracer_provider.shutdown() {
                eprintln!("failed to shut down OpenTelemetry tracer provider: {err:?}");
            }
        }
        if let Some(logger_provider) = self.logger_provider {
            if let Err(err) = logger_provider.shutdown() {
                eprintln!("failed to shut down OpenTelemetry logger provider: {err:?}");
            }
        }
    }
}

struct OtlpTelemetry {
    tracer_provider: SdkTracerProvider,
    logger_provider: SdkLoggerProvider,
    endpoint: String,
}

static HTTP_REQUESTS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_http_requests_total",
        "Total HTTP requests handled by the Walrus Memory relayer.",
        &["method", "route", "status"]
    )
    .expect("register memwal_http_requests_total")
});

static HTTP_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        HistogramOpts::new(
            "memwal_http_request_duration_seconds",
            "HTTP request latency in seconds."
        )
        .buckets(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
        ]),
        &["method", "route", "status"]
    )
    .expect("register memwal_http_request_duration_seconds")
});

static HTTP_REQUESTS_IN_FLIGHT: LazyLock<IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "memwal_http_requests_in_flight",
        "HTTP requests currently being handled by the Walrus Memory relayer."
    )
    .expect("register memwal_http_requests_in_flight")
});

static ERRORS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_errors_total",
        "Application errors returned by the Walrus Memory relayer.",
        &["kind", "route"]
    )
    .expect("register memwal_errors_total")
});

static MCP_HANDSHAKE_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_mcp_handshake_total",
        "MCP handshake attempts by route and outcome and, when refused, why.",
        &["route", "outcome", "reason"]
    )
    .expect("register memwal_mcp_handshake_total")
});

static MCP_TIME_TO_SESSION_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    prometheus::register_histogram!(HistogramOpts::new(
        "memwal_mcp_time_to_session_seconds",
        "Wall-clock from a client's first handshake attempt to the one that \
         succeeded, keyed by its connect-episode id. This is the number a user \
         experiences as \"nothing is happening\": no single request is slow, so \
         the per-request latency histogram cannot show it."
    )
    .buckets(vec![
        0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0
    ]))
    .expect("register memwal_mcp_time_to_session_seconds")
});

static RATE_LIMIT_DENIALS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_rate_limit_denials_total",
        "Rate-limit denials by limiter bucket.",
        &["bucket", "route"]
    )
    .expect("register memwal_rate_limit_denials_total")
});

static RATE_LIMIT_FALLBACKS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_rate_limit_fallbacks_total",
        "Times the relayer used in-memory rate limiting because Redis was unavailable.",
        &["scope"]
    )
    .expect("register memwal_rate_limit_fallbacks_total")
});

static SECURITY_DELETE_SUI_RPC_ADMISSIONS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "memwal_security_delete_sui_rpc_admissions_total",
        "Security-deletion Sui RPC attempts admitted by the rolling-window gate, including retries."
    )
    .expect("register memwal_security_delete_sui_rpc_admissions_total")
});

static SECURITY_DELETE_SUI_RPC_WINDOW_ADMISSIONS: LazyLock<IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "memwal_security_delete_sui_rpc_window_admissions",
        "Security-deletion Sui RPC admissions retained in the current rolling window."
    )
    .expect("register memwal_security_delete_sui_rpc_window_admissions")
});

static SECURITY_DELETE_SUI_RPC_WINDOW_LIMIT: LazyLock<IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "memwal_security_delete_sui_rpc_window_limit",
        "Configured effective security-deletion Sui RPC rolling-window limit."
    )
    .expect("register memwal_security_delete_sui_rpc_window_limit")
});

static SECURITY_DELETE_SUI_RPC_GATE_WAIT_SECONDS: LazyLock<Histogram> = LazyLock::new(|| {
    prometheus::register_histogram!(HistogramOpts::new(
        "memwal_security_delete_sui_rpc_gate_wait_seconds",
        "Time security-deletion Sui RPC attempts wait for rolling-window admission."
    )
    .buckets(vec![
        0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0
    ]))
    .expect("register memwal_security_delete_sui_rpc_gate_wait_seconds")
});

static SECURITY_DELETE_SUI_RPC_PROVIDER_RATE_LIMITS_TOTAL: LazyLock<IntCounter> =
    LazyLock::new(|| {
        prometheus::register_int_counter!(
            "memwal_security_delete_sui_rpc_provider_rate_limits_total",
            "Provider RESOURCE_EXHAUSTED responses observed by the security-deletion Sui client."
        )
        .expect("register memwal_security_delete_sui_rpc_provider_rate_limits_total")
    });

static SECURITY_DELETE_SUI_RPC_COOLDOWNS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "memwal_security_delete_sui_rpc_cooldowns_total",
        "Provider-directed cooldowns applied by the security-deletion Sui client."
    )
    .expect("register memwal_security_delete_sui_rpc_cooldowns_total")
});

static SECURITY_DELETE_SUI_RPC_COOLDOWN_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| {
        prometheus::register_histogram!(HistogramOpts::new(
        "memwal_security_delete_sui_rpc_cooldown_seconds",
        "Provider Retry-After or retry-pushback cooldown requested for security-deletion Sui RPC."
    )
    .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0, 3600.0]))
        .expect("register memwal_security_delete_sui_rpc_cooldown_seconds")
    });

static EXTERNAL_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        HistogramOpts::new(
            "memwal_external_request_duration_seconds",
            "External service request latency in seconds."
        )
        .buckets(vec![
            0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 180.0,
        ]),
        &["service", "operation", "status"]
    )
    .expect("register memwal_external_request_duration_seconds")
});

static SIDECAR_FAILURES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_sidecar_failures_total",
        "Sidecar failures seen by the Rust relayer.",
        &["operation", "reason"]
    )
    .expect("register memwal_sidecar_failures_total")
});

static MARKETING_CONSENT_ERASURES_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_marketing_consent_erasures_total",
        "Marketing consent records erased by trigger.",
        &["trigger"]
    )
    .expect("register memwal_marketing_consent_erasures_total")
});

static MARKETING_CONSENT_SWEEP_ERRORS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_marketing_consent_sweep_errors_total",
        "Marketing consent erasure sweep errors by reason.",
        &["reason"]
    )
    .expect("register memwal_marketing_consent_sweep_errors_total")
});

static EMAIL_SENDS_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    prometheus::register_int_counter_vec!(
        "memwal_email_sends_total",
        "Verification emails by delivery outcome",
        &["tag", "outcome"]
    )
    .expect("register memwal_email_sends_total")
});

pub fn record_email_send(tag: &'static str, outcome: &'static str) {
    EMAIL_SENDS_TOTAL.with_label_values(&[tag, outcome]).inc();
}

pub fn record_marketing_consent_erasure(trigger: &'static str) {
    MARKETING_CONSENT_ERASURES_TOTAL
        .with_label_values(&[trigger])
        .inc();
}

pub fn record_marketing_consent_sweep_error(reason: &'static str) {
    MARKETING_CONSENT_SWEEP_ERRORS_TOTAL
        .with_label_values(&[reason])
        .inc();
}

static DB_QUERY_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        HistogramOpts::new(
            "memwal_db_query_duration_seconds",
            "Database query latency in seconds."
        )
        .buckets(vec![
            0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
        ]),
        &["operation", "status"]
    )
    .expect("register memwal_db_query_duration_seconds")
});

static DB_POOL: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    prometheus::register_int_gauge_vec!(
        "memwal_db_pool_connections",
        "PostgreSQL pool connections by state.",
        &["state"]
    )
    .expect("register memwal_db_pool_connections")
});

pub fn init_tracing() -> TelemetryGuard {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "memwal_server=info,tower_http=info".into());
    let json_logs = std::env::var("LOG_FORMAT")
        .map(|value| value.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    global::set_text_map_propagator(TraceContextPropagator::new());
    let otlp = match build_otlp_telemetry() {
        Ok(otlp) => otlp,
        Err(err) => {
            eprintln!("OpenTelemetry disabled: {err}");
            None
        }
    };

    if json_logs {
        match otlp {
            Some(otlp) => {
                let tracer = otlp.tracer_provider.tracer(otel_service_name());
                let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
                let log_layer =
                    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                        &otlp.logger_provider,
                    );

                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .json()
                            .flatten_event(true)
                            .with_current_span(true),
                    )
                    .with(trace_layer)
                    .with(log_layer)
                    .init();

                tracing::info!(endpoint = %otlp.endpoint, "OpenTelemetry OTLP export enabled");
                TelemetryGuard {
                    tracer_provider: Some(otlp.tracer_provider),
                    logger_provider: Some(otlp.logger_provider),
                }
            }
            None => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(
                        tracing_subscriber::fmt::layer()
                            .json()
                            .flatten_event(true)
                            .with_current_span(true),
                    )
                    .init();
                TelemetryGuard {
                    tracer_provider: None,
                    logger_provider: None,
                }
            }
        }
    } else {
        match otlp {
            Some(otlp) => {
                let tracer = otlp.tracer_provider.tracer(otel_service_name());
                let trace_layer = tracing_opentelemetry::layer().with_tracer(tracer);
                let log_layer =
                    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(
                        &otlp.logger_provider,
                    );

                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().with_target(true))
                    .with(trace_layer)
                    .with(log_layer)
                    .init();

                tracing::info!(endpoint = %otlp.endpoint, "OpenTelemetry OTLP export enabled");
                TelemetryGuard {
                    tracer_provider: Some(otlp.tracer_provider),
                    logger_provider: Some(otlp.logger_provider),
                }
            }
            None => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(tracing_subscriber::fmt::layer().with_target(true))
                    .init();
                TelemetryGuard {
                    tracer_provider: None,
                    logger_provider: None,
                }
            }
        }
    }
}

fn build_otlp_telemetry() -> Result<Option<OtlpTelemetry>, String> {
    use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};

    let Some(base_endpoint) = env_non_empty(OTLP_ENDPOINT_ENV) else {
        return Ok(None);
    };
    let headers = parse_otlp_headers(env_non_empty(OTLP_HEADERS_ENV).as_deref());
    let traces_endpoint = signal_endpoint(&base_endpoint, OTLP_TRACES_ENDPOINT_ENV, "/v1/traces");
    let logs_endpoint = signal_endpoint(&base_endpoint, OTLP_LOGS_ENDPOINT_ENV, "/v1/logs");

    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(traces_endpoint)
        .with_headers(headers.clone())
        .build()
        .map_err(|err| format!("build OTLP trace exporter: {err}"))?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(otel_resource())
        .with_batch_exporter(span_exporter)
        .build();
    global::set_tracer_provider(tracer_provider.clone());

    let log_exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(logs_endpoint)
        .with_headers(headers)
        .build()
        .map_err(|err| format!("build OTLP log exporter: {err}"))?;
    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(otel_resource())
        .with_batch_exporter(log_exporter)
        .build();

    Ok(Some(OtlpTelemetry {
        tracer_provider,
        logger_provider,
        endpoint: base_endpoint,
    }))
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn otel_service_name() -> String {
    std::env::var(OTEL_SERVICE_NAME_ENV).unwrap_or_else(|_| DEFAULT_OTEL_SERVICE_NAME.to_string())
}

fn parse_otlp_headers(raw: Option<&str>) -> HashMap<String, String> {
    raw.unwrap_or_default()
        .split(',')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            Some((key.to_string(), value.trim().to_string()))
        })
        .collect()
}

fn signal_endpoint(base: &str, signal_env: &str, suffix: &str) -> String {
    env_non_empty(signal_env).unwrap_or_else(|| format!("{}{}", base.trim_end_matches('/'), suffix))
}

fn otel_resource() -> Resource {
    let mut attributes = vec![
        KeyValue::new("service.name", otel_service_name()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ];
    if let Some(environment) = env_non_empty("RAILWAY_ENVIRONMENT_NAME")
        .or_else(|| env_non_empty("DEPLOYMENT_ENVIRONMENT"))
        .or_else(|| env_non_empty("NODE_ENV"))
    {
        attributes.push(KeyValue::new("deployment.environment.name", environment));
    }
    Resource::builder_empty()
        .with_attributes(attributes)
        .build()
}

pub async fn request_context_middleware(mut request: Request, next: Next) -> Response {
    let request_id = resolve_request_id(request.headers());
    let route = route_label(request.uri().path());
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let span_name = format!("{method} {route}");
    let started = Instant::now();
    let parent_context = global::get_text_map_propagator(|propagator| {
        propagator.extract(&HeaderExtractor(request.headers()))
    });

    request.extensions_mut().insert(RequestContext {
        request_id: request_id.clone(),
        route: route.clone(),
        started,
    });
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request
            .headers_mut()
            .insert(request_id_header_name(), value);
    }

    let span = tracing::info_span!(
        "http.request",
        "otel.name" = %span_name,
        "otel.kind" = "server",
        request_id = %request_id,
        "http.request.method" = %method,
        "http.route" = %route,
        "url.path" = %path,
        "http.response.status_code" = tracing::field::Empty,
        "otel.status_code" = tracing::field::Empty,
        status = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
    );
    let _ = span.set_parent(parent_context);
    HTTP_REQUESTS_IN_FLIGHT.inc();

    let context = RequestContext {
        request_id: request_id.clone(),
        route: route.clone(),
        started,
    };

    REQUEST_CONTEXT
        .scope(context, async move {
            let request_span = span.clone();
            let mut response = next.run(request).instrument(request_span).await;
            let status = response.status();
            let elapsed = started.elapsed();
            span.record("status", status.as_u16());
            span.record("http.response.status_code", status.as_u16());
            if status.is_server_error() {
                span.record("otel.status_code", "error");
            }
            span.record("latency_ms", elapsed.as_millis() as u64);

            if let Ok(value) = HeaderValue::from_str(&request_id) {
                response
                    .headers_mut()
                    .insert(request_id_header_name(), value);
            }

            record_http_request(&method, &route, status, elapsed);
            HTTP_REQUESTS_IN_FLIGHT.dec();
            tracing::info!(
                request_id = %request_id,
                method = %method,
                route = %route,
                status = status.as_u16(),
                latency_ms = elapsed.as_millis(),
                "http request complete"
            );
            response
        })
        .await
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    update_db_pool_metrics(state.db.pool());

    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();
    match encoder.encode(&prometheus::gather(), &mut buffer) {
        Ok(()) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, encoder.format_type())
            .body(Body::from(buffer))
            .expect("build metrics response"),
        Err(err) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(format!("failed to encode metrics: {}", err)))
            .expect("build metrics error response"),
    }
}

pub fn current_request_id() -> Option<String> {
    REQUEST_CONTEXT.try_with(|ctx| ctx.request_id.clone()).ok()
}

/// When the current request reached the relayer, if this task serves one.
pub fn current_request_started() -> Option<Instant> {
    REQUEST_CONTEXT.try_with(|ctx| ctx.started).ok()
}

pub fn current_context() -> Option<RequestContext> {
    REQUEST_CONTEXT.try_with(Clone::clone).ok()
}

pub async fn with_request_context<F>(context: RequestContext, future: F) -> F::Output
where
    F: Future,
{
    REQUEST_CONTEXT.scope(context, future).await
}

pub fn current_route() -> String {
    REQUEST_CONTEXT
        .try_with(|ctx| ctx.route.clone())
        .unwrap_or_else(|_| "background".to_string())
}

pub fn request_id_header_name() -> HeaderName {
    HeaderName::from_static(X_REQUEST_ID)
}

pub fn apply_request_id_header(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let req = match current_request_id() {
        Some(request_id) => req.header(X_REQUEST_ID, request_id),
        None => req,
    };
    apply_trace_context(req)
}

fn apply_trace_context(mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    let mut headers = Vec::new();
    let context = tracing::Span::current().context();
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&context, &mut HeaderInjector(&mut headers));
    });
    for (key, value) in headers {
        req = req.header(key, value);
    }
    req
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

struct HeaderInjector<'a>(&'a mut Vec<(String, String)>);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.push((key.to_string(), value));
    }
}

pub fn record_app_error(kind: &'static str) {
    let route = current_route();
    ERRORS_TOTAL.with_label_values(&[kind, &route]).inc();
}

// ── Refusal log sampling ────────────────────────────────────────────
//
// `/api/mcp/*` has no rate limit ahead of it and a stuck client retries
// forever, so one log line per refusal is one log line per retry — the
// 784,627 × 401 this PR measures would have become 784,627 warn lines.
// The counter is the always-on signal; the line is a sample carrying the
// detail a counter cannot (which account, which client, which reason).

/// At most one refusal line per account per window.
pub const MCP_REFUSAL_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Bounded for the usual reason: the key is a caller-supplied header. At the
/// cap we stop tracking new accounts and simply do not log them — the metric
/// still counts every refusal, so nothing is lost that a dashboard needs.
pub const MCP_REFUSAL_LOG_MAX_ACCOUNTS: usize = 4_096;

static MCP_REFUSAL_LOG_SEEN: LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
> = LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Whether this refusal should be written out, given what was logged before.
/// Pure given the map, so the policy is unit-testable.
pub fn should_log_refusal_at(
    seen: &mut std::collections::HashMap<String, std::time::Instant>,
    account: &str,
    now: std::time::Instant,
) -> bool {
    match seen.get(account) {
        Some(last) if now.duration_since(*last) < MCP_REFUSAL_LOG_INTERVAL => false,
        Some(_) => {
            seen.insert(account.to_string(), now);
            true
        }
        None => {
            // Expire on insert: this map is only written on the sampled path,
            // so it is cheap, and it keeps an idle account from holding a slot.
            if seen.len() >= MCP_REFUSAL_LOG_MAX_ACCOUNTS {
                seen.retain(|_, last| now.duration_since(*last) < MCP_REFUSAL_LOG_INTERVAL);
            }
            if seen.len() >= MCP_REFUSAL_LOG_MAX_ACCOUNTS {
                return false;
            }
            seen.insert(account.to_string(), now);
            true
        }
    }
}

pub fn should_log_refusal(account: &str) -> bool {
    let Ok(mut seen) = MCP_REFUSAL_LOG_SEEN.lock() else {
        return false;
    };
    should_log_refusal_at(&mut seen, account, std::time::Instant::now())
}

static MCP_STALE_SERVE_LOG_SEEN: LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
> = LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Whether this stale-grace serve should be written out.
///
/// Same policy and same window as the refusal line, and for the same reason:
/// it fires on the hot path (every signed request and every MCP envelope) and
/// fires *hardest* during a Sui outage, when many requests fall past the TTL
/// at once — the 155,874 x 503 shape this PR measures. One line per request
/// there is the same unbounded repetition the refusal sampler was added to
/// stop.
///
/// Its own map, though. An account being refused must not suppress the very
/// different fact that it is being authenticated from a stale verification,
/// and vice versa — sharing one map would let either hide the other.
pub fn should_log_stale_serve(account: &str) -> bool {
    let Ok(mut seen) = MCP_STALE_SERVE_LOG_SEEN.lock() else {
        return false;
    };
    should_log_refusal_at(&mut seen, account, std::time::Instant::now())
}

/// Drop sampler entries that have aged out of their window.
///
/// Both maps already expire on insert, but only once they reach the cap, so
/// an account that was noisy an hour ago holds its slot until some unrelated
/// overflow reclaims it. Every other per-account map this service keeps is
/// swept periodically; this makes these two consistent with them. Returns how
/// many entries were dropped, for the sweep log.
pub fn sweep_log_samplers() -> usize {
    let now = std::time::Instant::now();
    let mut evicted = 0;
    for map in [&*MCP_REFUSAL_LOG_SEEN, &*MCP_STALE_SERVE_LOG_SEEN] {
        let Ok(mut seen) = map.lock() else { continue };
        let before = seen.len();
        seen.retain(|_, last| now.duration_since(*last) < MCP_REFUSAL_LOG_INTERVAL);
        evicted += before - seen.len();
    }
    evicted
}

// ── MCP connect episodes ────────────────────────────────────────────
//
// State for `time_to_session`. Lives here rather than in `mcp_proxy`
// because `AppState` is in the library crate and `mcp_proxy` is not.

/// Longest an unfinished connect episode is remembered. A client that gives
/// up, or is killed, leaves an entry behind; past this it is swept. Also the
/// ceiling on any single `time_to_session` observation.
pub const MCP_CONNECT_EPISODE_TTL: std::time::Duration = std::time::Duration::from_secs(900);

/// Hard ceiling on tracked episodes, for the same reason the rejection cache
/// has one: the key comes from the caller. At the cap new episodes are simply
/// not timed — the metric loses samples, nothing else degrades.
pub const MCP_CONNECT_EPISODE_MAX: usize = 4_096;

pub type McpConnectEpisodes =
    std::sync::Arc<tokio::sync::RwLock<HashMap<String, std::time::Instant>>>;

pub fn new_mcp_connect_episodes() -> McpConnectEpisodes {
    std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new()))
}

pub fn connect_episode_is_fresh(started: std::time::Instant) -> bool {
    started.elapsed() < MCP_CONNECT_EPISODE_TTL
}

/// Count one MCP handshake. `reason` is `"none"` on success — Prometheus
/// label sets must be uniform, and an empty string reads as missing data.
///
/// `route` names the `/api/mcp/*` entry point. Without it the SSE refusal
/// ratio cannot be read at all: `classify_and_resolve` runs on the handshake
/// *and* on every JSON-RPC envelope, so one live session's POSTs outnumber
/// the GET this metric exists to measure.
pub fn record_mcp_handshake(route: &str, outcome: &str, reason: &str) {
    MCP_HANDSHAKE_TOTAL
        .with_label_values(&[route, outcome, reason])
        .inc();
}

/// Record how long a client spent getting a session. Only called on the
/// attempt that succeeded, so the histogram counts episodes, not requests.
pub fn record_mcp_time_to_session(elapsed: std::time::Duration) {
    MCP_TIME_TO_SESSION_SECONDS.observe(elapsed.as_secs_f64());
}

pub fn record_rate_limit_denial(bucket: &str) {
    let route = current_route();
    RATE_LIMIT_DENIALS_TOTAL
        .with_label_values(&[bucket, &route])
        .inc();
}

pub fn record_rate_limit_fallback(scope: &'static str) {
    RATE_LIMIT_FALLBACKS_TOTAL.with_label_values(&[scope]).inc();
}

pub fn record_security_delete_sui_rpc_admission(in_window: usize, limit: usize, waited: Duration) {
    SECURITY_DELETE_SUI_RPC_ADMISSIONS_TOTAL.inc();
    SECURITY_DELETE_SUI_RPC_WINDOW_ADMISSIONS.set(in_window as i64);
    SECURITY_DELETE_SUI_RPC_WINDOW_LIMIT.set(limit as i64);
    SECURITY_DELETE_SUI_RPC_GATE_WAIT_SECONDS.observe(waited.as_secs_f64());
}

pub fn record_security_delete_sui_rpc_provider_rate_limit() {
    SECURITY_DELETE_SUI_RPC_PROVIDER_RATE_LIMITS_TOTAL.inc();
}

pub fn record_security_delete_sui_rpc_cooldown(duration: Duration) {
    SECURITY_DELETE_SUI_RPC_COOLDOWNS_TOTAL.inc();
    SECURITY_DELETE_SUI_RPC_COOLDOWN_SECONDS.observe(duration.as_secs_f64());
}

pub fn observe_external(
    service: &'static str,
    operation: &'static str,
    status: &str,
    elapsed: Duration,
) {
    EXTERNAL_REQUEST_DURATION_SECONDS
        .with_label_values(&[service, operation, status])
        .observe(elapsed.as_secs_f64());
}

pub fn record_sidecar_failure(operation: &'static str, reason: &'static str) {
    SIDECAR_FAILURES_TOTAL
        .with_label_values(&[operation, reason])
        .inc();
}

pub fn observe_db(operation: &'static str, status: &'static str, elapsed: Duration) {
    DB_QUERY_DURATION_SECONDS
        .with_label_values(&[operation, status])
        .observe(elapsed.as_secs_f64());
}

pub fn update_db_pool_metrics(pool: &sqlx::PgPool) {
    DB_POOL
        .with_label_values(&["open"])
        .set(i64::from(pool.size()));
    DB_POOL
        .with_label_values(&["idle"])
        .set(pool.num_idle() as i64);
}

fn record_http_request(method: &str, route: &str, status: StatusCode, elapsed: Duration) {
    let status = status.as_u16().to_string();
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, route, &status])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method, route, &status])
        .observe(elapsed.as_secs_f64());
}

fn resolve_request_id(headers: &axum::http::HeaderMap) -> String {
    [X_REQUEST_ID, X_CORRELATION_ID]
        .iter()
        .find_map(|name| {
            headers
                .get(*name)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| is_safe_request_id(value))
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

fn is_safe_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn route_label(path: &str) -> String {
    match path {
        "/health" => "/health".to_string(),
        "/config" => "/config".to_string(),
        "/metrics" => "/metrics".to_string(),
        "/sponsor" => "/sponsor".to_string(),
        "/sponsor/execute" => "/sponsor/execute".to_string(),
        "/api/remember" => "/api/remember".to_string(),
        "/api/remember/bulk" => "/api/remember/bulk".to_string(),
        "/api/remember/bulk/status" => "/api/remember/bulk/status".to_string(),
        "/api/remember/manual" => "/api/remember/manual".to_string(),
        "/api/recall" => "/api/recall".to_string(),
        "/api/recall/manual" => "/api/recall/manual".to_string(),
        "/api/analyze" => "/api/analyze".to_string(),
        "/api/ask" => "/api/ask".to_string(),
        "/api/embed" => "/api/embed".to_string(),
        "/api/restore" => "/api/restore".to_string(),
        "/api/forget" => "/api/forget".to_string(),
        "/api/stats" => "/api/stats".to_string(),
        "/api/mcp/sse" => "/api/mcp/sse".to_string(),
        "/api/mcp/messages" => "/api/mcp/messages".to_string(),
        "/api/mcp" => "/api/mcp".to_string(),
        "/v1/owner-sessions/marketing-consent/challenge"
        | "/v1/owner-sessions/marketing-consent/verify" => path.to_string(),
        _ if path.starts_with("/v1/owners/")
            && path.ends_with("/marketing-consent/verification") =>
        {
            crate::marketing_consent::OWNER_PATH.to_string()
        }
        _ if path.starts_with("/v1/owners/")
            && path.ends_with("/marketing-consent/verification/confirm") =>
        {
            crate::marketing_consent::CONFIRM_PATH.to_string()
        }
        _ if path
            .strip_prefix("/api/admin/marketing-consent/")
            .is_some_and(|owner| !owner.is_empty() && !owner.contains('/')) =>
        {
            crate::marketing_consent::ADMIN_PATH.to_string()
        }
        _ if path.starts_with("/api/remember/") => "/api/remember/{job_id}".to_string(),
        // Owner-scoped read API — {owner} is a variable Sui address path
        // segment, so these three fall back to prefix/suffix matching the
        // same way /api/remember/{job_id} does above.
        _ if path.starts_with("/v1/owners/") && path.ends_with("/namespaces") => {
            "/v1/owners/{owner}/namespaces".to_string()
        }
        _ if path.starts_with("/v1/owners/") && path.ends_with("/memories") => {
            "/v1/owners/{owner}/memories".to_string()
        }
        _ if path.starts_with("/v1/owners/") && path.ends_with("/agents") => {
            "/v1/owners/{owner}/agents".to_string()
        }
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_safe_request_id, parse_otlp_headers, route_label, signal_endpoint};

    #[test]
    fn request_id_validation_rejects_header_injection() {
        assert!(is_safe_request_id("req-123_ok.test:1"));
        assert!(!is_safe_request_id(""));
        assert!(!is_safe_request_id("bad\nid"));
        assert!(!is_safe_request_id(&"x".repeat(129)));
    }

    #[test]
    fn route_label_normalizes_remember_status_ids() {
        assert_eq!(route_label("/api/remember/abc"), "/api/remember/{job_id}");
        assert_eq!(route_label("/api/recall"), "/api/recall");
        assert_eq!(route_label("/unexpected"), "unknown");
    }

    #[test]
    fn route_label_normalizes_owner_scoped_read_api_routes() {
        assert_eq!(
            route_label("/v1/owners/0xabc123/namespaces"),
            "/v1/owners/{owner}/namespaces"
        );
        assert_eq!(
            route_label("/v1/owners/0xabc123/memories"),
            "/v1/owners/{owner}/memories"
        );
        assert_eq!(
            route_label("/v1/owners/0xabc123/agents"),
            "/v1/owners/{owner}/agents"
        );
        // Previously these three fell through to "unknown", making the new
        // routes invisible in metrics — this test is the regression guard.
        assert_ne!(route_label("/v1/owners/0xabc123/namespaces"), "unknown");
    }

    #[test]
    fn otlp_headers_follow_key_value_comma_format() {
        let headers = parse_otlp_headers(Some("Authorization=Basic abc, x-scope-orgid = memwal"));

        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Basic abc")
        );
        assert_eq!(
            headers.get("x-scope-orgid").map(String::as_str),
            Some("memwal")
        );
    }

    #[test]
    fn otlp_signal_endpoint_appends_suffix_to_base_endpoint() {
        std::env::remove_var("MEMWAL_TEST_OTLP_ENDPOINT");

        assert_eq!(
            signal_endpoint(
                "http://openobserve:5080/api/default/",
                "MEMWAL_TEST_OTLP_ENDPOINT",
                "/v1/logs",
            ),
            "http://openobserve:5080/api/default/v1/logs"
        );
    }
}

#[cfg(test)]
mod refusal_log_tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[test]
    fn a_refusal_and_a_stale_serve_do_not_share_a_sampling_slot() {
        // Same policy, same window, deliberately different maps. They report
        // unrelated things — "this key was refused" versus "this key is being
        // authenticated from a verification we could not refresh" — and an
        // account in trouble tends to produce both. One map would let
        // whichever fired first silence the other for the whole window, which
        // is exactly the attribution problem this PR set out to fix.
        let account = "0xsampler-independence-probe";
        assert!(
            should_log_refusal(account),
            "first refusal for this account must be written"
        );
        assert!(
            should_log_stale_serve(account),
            "the stale-serve line must not be suppressed by the refusal that just fired"
        );
        assert!(
            !should_log_stale_serve(account),
            "but it is still sampled within its own window"
        );
        // Fresh entries are never swept, so this is deterministic regardless
        // of what else ran before it.
        assert_eq!(
            sweep_log_samplers(),
            0,
            "entries inside the window must survive the periodic sweep"
        );
    }

    #[test]
    fn one_account_is_logged_once_per_window_however_hard_it_retries() {
        // The reason this exists: `/api/mcp/*` has no rate limit in front of
        // it and a stuck client retries forever, so an unsampled line is one
        // line per retry — 784,627 of them in the window this PR measures.
        let mut seen = HashMap::new();
        let t0 = Instant::now();
        assert!(should_log_refusal_at(&mut seen, "0xacct", t0));
        for i in 1..100 {
            assert!(
                !should_log_refusal_at(&mut seen, "0xacct", t0 + Duration::from_millis(i * 500)),
                "retry {i} must not produce a second line inside the window"
            );
        }
        assert!(should_log_refusal_at(
            &mut seen,
            "0xacct",
            t0 + MCP_REFUSAL_LOG_INTERVAL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn accounts_are_sampled_independently() {
        let mut seen = HashMap::new();
        let t0 = Instant::now();
        assert!(should_log_refusal_at(&mut seen, "0xdio", t0));
        assert!(
            should_log_refusal_at(&mut seen, "0xteo", t0),
            "one noisy account must not silence everyone else"
        );
    }

    #[test]
    fn the_sampling_map_cannot_be_grown_without_bound() {
        // Keyed by an unauthenticated header, so the cap matters. Past it we
        // stop logging new accounts; the counter still counts every refusal.
        let mut seen = HashMap::new();
        let t0 = Instant::now();
        for i in 0..MCP_REFUSAL_LOG_MAX_ACCOUNTS {
            assert!(should_log_refusal_at(&mut seen, &format!("0x{i}"), t0));
        }
        assert!(
            !should_log_refusal_at(&mut seen, "0xoverflow", t0),
            "at the cap a new account is counted but not logged"
        );
        assert_eq!(seen.len(), MCP_REFUSAL_LOG_MAX_ACCOUNTS);
    }

    #[test]
    fn expired_accounts_free_their_slot_for_a_new_one() {
        let mut seen = HashMap::new();
        let t0 = Instant::now();
        for i in 0..MCP_REFUSAL_LOG_MAX_ACCOUNTS {
            assert!(should_log_refusal_at(&mut seen, &format!("0x{i}"), t0));
        }
        let later = t0 + MCP_REFUSAL_LOG_INTERVAL + Duration::from_secs(1);
        assert!(
            should_log_refusal_at(&mut seen, "0xoverflow", later),
            "once the old entries age out the cap must not stay wedged"
        );
    }
}

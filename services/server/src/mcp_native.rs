//! In-process Rust MCP (Model Context Protocol) SSE + JSON-RPC + Streamable HTTP server.
//!
//! Replaces the Node.js sidecar's `/mcp/sse`, `/mcp/messages`, and `/mcp` Express routes
//! (`services/server/scripts/mcp/index.ts`) when `is_in_process_sidecar_enabled` is active,
//! allowing `memwal-server` to serve `@mysten-incubation/memwal-mcp` and Streamable HTTP
//! MCP clients with zero Node.js child processes.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, LazyLock, Mutex, OnceLock, RwLock,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use ed25519_dalek::{Signer, SigningKey};
use futures::stream;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::types::AppState;

const MCP_MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const STREAMABLE_IDLE_TTL: Duration = Duration::from_secs(15 * 60);
const STREAMABLE_REAPER_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct McpNativeSession {
    pub delegate_key_hex: String,
    pub account_id: String,
    pub default_namespace: String,
    pub oauth_scope: String,
    pub sse_tx: Option<mpsc::UnboundedSender<String>>,
}

/// Custom `Debug` implementation that redacts `delegate_key_hex` so session secrets
/// are never leaked to logs (`M-PUBLIC-DEBUG` / `C-DEBUG`).
impl std::fmt::Debug for McpNativeSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpNativeSession")
            .field("delegate_key_hex", &"[REDACTED]")
            .field("account_id", &self.account_id)
            .field("default_namespace", &self.default_namespace)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
struct McpStreamableSession {
    session: McpNativeSession,
    last_active: Instant,
    _slot_guard: Arc<SessionSlotGuard>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SessionLimitConfig {
    max_total_sessions: usize,
    max_sessions_per_ip: usize,
    max_new_sessions_per_ip_per_min: usize,
}

impl SessionLimitConfig {
    fn from_env() -> Self {
        fn parse_pos(name: &str, fallback: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(fallback)
        }
        Self {
            max_total_sessions: parse_pos("MCP_MAX_TOTAL_SESSIONS", 1000),
            max_sessions_per_ip: parse_pos("MCP_MAX_SESSIONS_PER_IP", 16),
            max_new_sessions_per_ip_per_min: parse_pos("MCP_MAX_NEW_SESSIONS_PER_IP_PER_MIN", 30),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionDenyReason {
    Global,
    IpActive,
    IpBurst { retry_after_secs: u64 },
}

#[derive(Default)]
struct IpSessionState {
    active: usize,
    opens: Vec<Instant>,
}

struct McpSessionRateLimiter {
    config: SessionLimitConfig,
    per_ip: HashMap<String, IpSessionState>,
    total_active: usize,
    last_prune: Option<Instant>,
}

impl McpSessionRateLimiter {
    fn new(config: SessionLimitConfig) -> Self {
        Self {
            config,
            per_ip: HashMap::new(),
            total_active: 0,
            last_prune: None,
        }
    }

    pub(crate) fn prune_inactive(&mut self, now: Instant) -> usize {
        self.expire_inactive(now)
    }

    pub(crate) fn expire_inactive(&mut self, now: Instant) -> usize {
        self.last_prune = Some(now);
        let window = Duration::from_secs(60);
        let before = self.per_ip.len();
        self.per_ip.retain(|_, state| {
            state
                .opens
                .retain(|&opened| now.saturating_duration_since(opened) < window);
            state.active > 0 || !state.opens.is_empty()
        });
        before.saturating_sub(self.per_ip.len())
    }

    fn acquire(&mut self, ip: &str, now: Instant) -> Result<(), SessionDenyReason> {
        let should_prune = match self.last_prune {
            None => {
                self.last_prune = Some(now);
                false
            }
            Some(last) => {
                now.saturating_duration_since(last) >= Duration::from_secs(10)
                    || (self.per_ip.len() > 64
                        && now.saturating_duration_since(last) >= Duration::from_secs(1))
            }
        };
        if should_prune {
            self.expire_inactive(now);
        }

        if self.total_active >= self.config.max_total_sessions {
            return Err(SessionDenyReason::Global);
        }
        let window = Duration::from_secs(60);
        let state = self.per_ip.entry(ip.to_owned()).or_default();
        state
            .opens
            .retain(|&opened| now.saturating_duration_since(opened) < window);

        if state.active >= self.config.max_sessions_per_ip {
            if state.active == 0 && state.opens.is_empty() {
                self.per_ip.remove(ip);
            }
            return Err(SessionDenyReason::IpActive);
        }
        if state.opens.len() >= self.config.max_new_sessions_per_ip_per_min {
            let oldest = state.opens.first().copied().unwrap_or(now);
            let elapsed = now.saturating_duration_since(oldest);
            let remaining = window.saturating_sub(elapsed);
            let retry_after_secs = remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() > 0))
                .max(1);
            return Err(SessionDenyReason::IpBurst { retry_after_secs });
        }

        state.opens.push(now);
        state.active += 1;
        self.total_active += 1;
        Ok(())
    }

    #[cfg(test)]
    fn release(&mut self, ip: &str) {
        if let Some(state) = self.per_ip.get_mut(ip) {
            state.active = state.active.saturating_sub(1);
            self.total_active = self.total_active.saturating_sub(1);
            if state.active == 0 && state.opens.is_empty() {
                self.per_ip.remove(ip);
            }
        }
    }

    fn release_at(&mut self, ip: &str, now: Instant) {
        if let Some(state) = self.per_ip.get_mut(ip) {
            state.active = state.active.saturating_sub(1);
            self.total_active = self.total_active.saturating_sub(1);
            let window = Duration::from_secs(60);
            state
                .opens
                .retain(|&opened| now.saturating_duration_since(opened) < window);
            if state.active == 0 && state.opens.is_empty() {
                self.per_ip.remove(ip);
            }
        }
    }
}

static MCP_SESSION_LIMITER: LazyLock<Mutex<McpSessionRateLimiter>> =
    LazyLock::new(|| Mutex::new(McpSessionRateLimiter::new(SessionLimitConfig::from_env())));

struct SessionSlotGuard {
    ip: String,
    released: AtomicBool,
}

impl std::fmt::Debug for SessionSlotGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSlotGuard")
            .field("ip", &self.ip)
            .finish_non_exhaustive()
    }
}

impl Drop for SessionSlotGuard {
    fn drop(&mut self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            if let Ok(mut limiter) = MCP_SESSION_LIMITER.lock() {
                limiter.release_at(&self.ip, Instant::now());
            }
        }
    }
}

fn canonical_client_ip(headers: &req_headers::HeaderMap) -> String {
    if let Some(raw) = extract_header_str(headers, "x-forwarded-for") {
        if !raw.contains(',') && raw.parse::<IpAddr>().is_ok() {
            return raw;
        }
    }
    "unknown".to_owned()
}

fn acquire_session_slot(
    headers: &req_headers::HeaderMap,
) -> Result<Arc<SessionSlotGuard>, Box<Response>> {
    ensure_streamable_reaper_started();
    let ip = canonical_client_ip(headers);
    let outcome = MCP_SESSION_LIMITER
        .lock()
        .map_err(|_| {
            Box::new(
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "session limiter unavailable",
                )
                    .into_response(),
            )
        })?
        .acquire(&ip, Instant::now());
    match outcome {
        Ok(()) => Ok(Arc::new(SessionSlotGuard {
            ip,
            released: AtomicBool::new(false),
        })),
        Err(reason) => Err(Box::new(session_rate_limit_response(reason))),
    }
}

fn session_rate_limit_response(reason: SessionDenyReason) -> Response {
    let (code_str, retry_after) = match reason {
        SessionDenyReason::Global => ("global_cap", None),
        SessionDenyReason::IpActive => ("ip_active_cap", None),
        SessionDenyReason::IpBurst { retry_after_secs } => ("ip_burst_cap", Some(retry_after_secs)),
    };
    let message = match retry_after {
        None => format!("MCP rate limit: {code_str}. Close another MCP session, then retry."),
        Some(secs) => format!("MCP rate limit: {code_str}. Try again in {secs}s."),
    };
    let payload = json!({
        "jsonrpc": "2.0",
        "error": {
            "code": -32000,
            "message": message,
        },
        "id": Value::Null,
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Some(secs) = retry_after {
        if let Ok(hv) = HeaderValue::from_str(&secs.to_string()) {
            headers.insert(axum::http::header::RETRY_AFTER, hv);
        }
    }
    (
        StatusCode::TOO_MANY_REQUESTS,
        headers,
        serde_json::to_vec(&payload).unwrap_or_default(),
    )
        .into_response()
}

static MCP_SSE_SESSIONS: LazyLock<RwLock<HashMap<String, McpNativeSession>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

static MCP_STREAMABLE_SESSIONS: LazyLock<RwLock<HashMap<String, McpStreamableSession>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

static STREAMABLE_REAPER_STARTED: OnceLock<()> = OnceLock::new();

fn reap_idle_streamable_sessions_at(now: Instant) -> usize {
    let reaped_sessions = if let Ok(mut guard) = MCP_STREAMABLE_SESSIONS.write() {
        let before = guard.len();
        guard.retain(|_, entry| {
            now.saturating_duration_since(entry.last_active) <= STREAMABLE_IDLE_TTL
        });
        before.saturating_sub(guard.len())
    } else {
        0
    };
    let _ = reap_expired_session_limits_at(now);
    reaped_sessions
}

pub(crate) fn reap_expired_session_limits_at(now: Instant) -> usize {
    if let Ok(mut limiter) = MCP_SESSION_LIMITER.lock() {
        limiter.expire_inactive(now)
    } else {
        0
    }
}

fn ensure_streamable_reaper_started() {
    STREAMABLE_REAPER_STARTED.get_or_init(|| {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut interval = tokio::time::interval(STREAMABLE_REAPER_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    let _ = reap_idle_streamable_sessions_at(Instant::now());
                }
            });
        }
    });
}

fn extract_header_str(headers: &req_headers::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

use reqwest::header as req_headers;

/// Fail-closed OAuth scope parser matching `registerTools` in `services/server/scripts/mcp/tools/index.ts`.
///
/// The relayer states the granted scope explicitly on every forwarded request via
/// `x-memwal-internal-oauth-scope` — the resolved grant for OAuth callers, and
/// `"memwal:read memwal:write"` for legacy delegate-key callers. An absent or empty
/// scope grants neither read nor write tools.
pub fn parse_granted_oauth_scopes(oauth_scope: &str) -> (bool, bool) {
    let mut can_read = false;
    let mut can_write = false;
    for token in oauth_scope.split_whitespace() {
        match token {
            "memwal:read" => can_read = true,
            "memwal:write" => can_write = true,
            _ => {}
        }
    }
    (can_read, can_write)
}

pub fn is_mcp_tool_permitted(tool_name: &str, oauth_scope: &str) -> bool {
    let (can_read, can_write) = parse_granted_oauth_scopes(oauth_scope);
    match tool_name {
        "memwal_health" | "memwal_recall" | "memwal_namespaces" => can_read,
        "memwal_remember"
        | "memwal_remember_status"
        | "memwal_remember_bulk"
        | "memwal_analyze"
        | "memwal_restore" => can_write,
        _ => false,
    }
}

fn is_known_mcp_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "memwal_health"
            | "memwal_recall"
            | "memwal_namespaces"
            | "memwal_remember"
            | "memwal_remember_status"
            | "memwal_remember_bulk"
            | "memwal_analyze"
            | "memwal_restore"
    )
}

fn normalize_oauth_scope(scope: &str) -> String {
    let mut tokens: Vec<&str> = scope.split_whitespace().collect();
    tokens.sort_unstable();
    tokens.dedup();
    tokens.join(" ")
}

fn delegate_pubkey_hex(private_key_hex: &str) -> Option<String> {
    let key_bytes: [u8; 32] = hex::decode(private_key_hex).ok()?.try_into().ok()?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    Some(hex::encode(signing_key.verifying_key().to_bytes()))
}

fn session_matches_caller(
    session: &McpNativeSession,
    caller_key_hex: &str,
    caller_account_id: &str,
    caller_oauth_scope: &str,
) -> bool {
    let Some(expected_pub) = delegate_pubkey_hex(&session.delegate_key_hex) else {
        return false;
    };
    let Some(caller_pub) = delegate_pubkey_hex(caller_key_hex) else {
        return false;
    };
    expected_pub == caller_pub
        && session.account_id.eq_ignore_ascii_case(caller_account_id)
        && normalize_oauth_scope(&session.oauth_scope) == normalize_oauth_scope(caller_oauth_scope)
}

fn mcp_rpc_error_response(status: StatusCode, message: impl Into<String>) -> Response {
    let code = if status == StatusCode::UNAUTHORIZED {
        -32001
    } else {
        -32603
    };
    let payload = json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message.into(),
        },
        "id": Value::Null,
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if status == StatusCode::UNAUTHORIZED {
        headers.insert(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"memwal\", error=\"invalid_token\""),
        );
    }
    (
        status,
        headers,
        serde_json::to_vec(&payload).unwrap_or_default(),
    )
        .into_response()
}

fn resolve_session_credentials(
    forwarded: &req_headers::HeaderMap,
) -> Result<(String, String, String, String), (StatusCode, &'static str)> {
    let bearer_key = extract_header_str(forwarded, "authorization")
        .and_then(|auth| {
            auth.strip_prefix("Bearer ")
                .or_else(|| auth.strip_prefix("bearer "))
                .map(str::trim)
                .map(str::to_owned)
        })
        .map(|k| {
            k.strip_prefix("0x")
                .or_else(|| k.strip_prefix("0X"))
                .unwrap_or(&k)
                .to_ascii_lowercase()
        })
        .filter(|k| {
            k.len() == 64
                && k.chars().all(|c| c.is_ascii_hexdigit())
                && delegate_pubkey_hex(k).is_some()
        });

    let Some(delegate_key_hex) = bearer_key else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Missing or invalid Ed25519 delegate key bearer",
        ));
    };

    let raw_account_id = extract_header_str(forwarded, "x-memwal-internal-oauth-account-id")
        .or_else(|| extract_header_str(forwarded, "x-memwal-account-id"))
        .unwrap_or_default();

    let valid_account = raw_account_id
        .strip_prefix("0x")
        .or_else(|| raw_account_id.strip_prefix("0X"))
        .filter(|rest| rest.len() == 64 && rest.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|rest| format!("0x{}", rest.to_ascii_lowercase()));

    let Some(account_id) = valid_account else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Missing or malformed X-MemWal-Account-Id header",
        ));
    };

    let default_namespace =
        extract_header_str(forwarded, "x-memwal-namespace").unwrap_or_else(|| "default".to_owned());

    // Fail closed: only trust the explicit `x-memwal-internal-oauth-scope` header injected
    // by `mcp_proxy::apply_internal_headers` after stripping any client-supplied copy.
    let oauth_scope =
        extract_header_str(forwarded, "x-memwal-internal-oauth-scope").unwrap_or_default();

    Ok((delegate_key_hex, account_id, default_namespace, oauth_scope))
}

/// Sign and execute a loopback HTTP request against the local `memwal-server` REST API
/// on behalf of the authenticated MCP session's delegate key.
async fn call_local_relayer(
    state: &AppState,
    delegate_key_hex: &str,
    account_id: &str,
    method: Method,
    path_and_query: &str,
    body_json: Option<&Value>,
    extra_headers: &[(&str, &str)],
) -> Result<(StatusCode, Value), String> {
    let key_bytes: [u8; 32] = hex::decode(delegate_key_hex)
        .map_err(|e| format!("invalid delegate key hex: {e}"))?
        .try_into()
        .map_err(|_| "delegate key must be 32 bytes".to_owned())?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let body_bytes = match body_json {
        Some(v) => serde_json::to_vec(v).map_err(|e| format!("serialize body: {e}"))?,
        None => Vec::new(),
    };
    let body_sha256 = hex::encode(Sha256::digest(&body_bytes));
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let nonce = uuid::Uuid::new_v4().to_string();
    let method_str = method.as_str();

    let canonical =
        format!("{timestamp}.{method_str}.{path_and_query}.{body_sha256}.{nonce}.{account_id}");
    let signature = signing_key.sign(canonical.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let url = format!("http://127.0.0.1:{}{}", state.config.port, path_and_query);
    let mut req = match method {
        Method::GET => state.http_client.get(&url),
        Method::POST => state.http_client.post(&url),
        Method::DELETE => state.http_client.delete(&url),
        _ => state.http_client.post(&url),
    };

    req = req
        .header("x-public-key", public_key_hex)
        .header("x-signature", signature_hex)
        .header("x-timestamp", timestamp.to_string())
        .header("x-nonce", nonce)
        .header("x-account-id", account_id)
        .header("x-delegate-key", delegate_key_hex)
        .timeout(Duration::from_secs(60));

    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }

    if !body_bytes.is_empty() {
        req = req
            .header("content-type", "application/json")
            .body(body_bytes);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("relayer loopback request failed: {e}"))?;
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let text = resp
        .text()
        .await
        .map_err(|e| format!("read relayer response failed: {e}"))?;
    let parsed = serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({ "raw": text }));
    Ok((status, parsed))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceEntry {
    pub name: String,
    pub memory_count: u64,
    pub storage_used: Option<u64>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacesPage {
    pub namespaces: Vec<NamespaceEntry>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredNamespaces {
    pub namespaces: Vec<NamespaceEntry>,
    pub has_more: bool,
}

/// Standard Levenshtein edit distance between two strings (case-folded and character-aware).
pub fn edit_distance(a: &str, b: &str) -> usize {
    let s: Vec<char> = a.to_lowercase().chars().collect();
    let t: Vec<char> = b.to_lowercase().chars().collect();
    if s == t {
        return 0;
    }
    if s.is_empty() {
        return t.len();
    }
    if t.is_empty() {
        return s.len();
    }

    let mut prev: Vec<usize> = (0..=t.len()).collect();
    let mut curr = vec![0; t.len() + 1];

    for i in 1..=s.len() {
        curr[0] = i;
        for j in 1..=t.len() {
            let cost = if s[i - 1] == t[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev.clone_from_slice(&curr);
    }
    prev[t.len()]
}

/// Check whether `candidate` is a close typo/prefix/substring match for `target`.
pub fn is_close_namespace_match(target: &str, candidate: &str) -> bool {
    let a = target.trim().to_lowercase();
    let b = candidate.trim().to_lowercase();
    if a.is_empty() || b.is_empty() || a == b {
        return false;
    }
    if edit_distance(&a, &b) <= 3 {
        return true;
    }
    if a.chars().count() >= 3 && b.chars().count() >= 3 && (a.contains(&b) || b.contains(&a)) {
        return true;
    }
    false
}

fn format_memory_count(count: u64) -> String {
    format!("{count} {}", if count == 1 { "memory" } else { "memories" })
}

pub fn rank_namespace_suggestions(
    target_namespace: &str,
    namespaces: &[NamespaceEntry],
) -> (Vec<NamespaceEntry>, Vec<NamespaceEntry>) {
    let non_empty = namespaces
        .iter()
        .filter(|ns| !ns.name.is_empty() && ns.name != target_namespace && ns.memory_count > 0);

    let mut close = Vec::new();
    let mut others = Vec::new();
    for ns in non_empty {
        if is_close_namespace_match(target_namespace, &ns.name) {
            close.push(ns.clone());
        } else {
            others.push(ns.clone());
        }
    }

    close.sort_by(|x, y| {
        edit_distance(target_namespace, &x.name)
            .cmp(&edit_distance(target_namespace, &y.name))
            .then_with(|| y.memory_count.cmp(&x.memory_count))
    });
    others.sort_by_key(|y| std::cmp::Reverse(y.memory_count));

    (close, others)
}

pub fn format_namespace_suggestion_hint(
    target_namespace: &str,
    namespaces: &[NamespaceEntry],
    max_listed: usize,
) -> String {
    let (close, others) = rank_namespace_suggestions(target_namespace, namespaces);
    if close.is_empty() && others.is_empty() {
        return String::new();
    }

    let mut parts: Vec<String> = Vec::new();
    if !close.is_empty() {
        let top: Vec<&NamespaceEntry> = close.iter().take(3).collect();
        if top.len() == 1 {
            parts.push(format!(
                "Did you mean namespace \"{}\" ({})?",
                top[0].name,
                format_memory_count(top[0].memory_count)
            ));
        } else {
            let formatted = top
                .iter()
                .map(|ns| format!("\"{}\" ({})", ns.name, format_memory_count(ns.memory_count)))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("Did you mean: {formatted}?"));
        }
    }

    let combined: Vec<&NamespaceEntry> =
        close.iter().chain(others.iter()).take(max_listed).collect();
    let list_str = combined
        .iter()
        .map(|ns| format!("\"{}\" ({})", ns.name, ns.memory_count))
        .collect::<Vec<_>>()
        .join(", ");
    let more_count = (close.len() + others.len()).saturating_sub(combined.len());
    let more_suffix = if more_count > 0 {
        format!(", +{more_count} more")
    } else {
        String::new()
    };
    parts.push(format!("Existing namespaces: {list_str}{more_suffix}."));

    parts.join(" ")
}

pub fn format_namespaces_result(page: &NamespacesPage) -> String {
    let non_empty: Vec<&NamespaceEntry> = page
        .namespaces
        .iter()
        .filter(|ns| !ns.name.is_empty() && ns.memory_count > 0)
        .collect();
    let next_cursor = page.next_cursor.as_deref().filter(|s| !s.is_empty());
    let has_more_pages = page.has_more;

    if non_empty.is_empty() {
        if has_more_pages {
            if let Some(cursor) = next_cursor {
                return format!(
                    "No non-empty namespaces found on this page.\n\nMore namespaces available (next_cursor=\"{cursor}\"). Call memwal_namespaces with cursor=\"{cursor}\" to inspect the next page."
                );
            }
            return "No non-empty namespaces found on this page. More namespaces exist on later pages.".to_owned();
        }
        return "No namespaces with stored memories found for this account.".to_owned();
    }

    let mut lines = Vec::with_capacity(non_empty.len() + 2);
    lines.push(format!(
        "Namespaces ({}{}):",
        non_empty.len(),
        if has_more_pages { "+" } else { "" }
    ));
    for ns in non_empty {
        let bytes = ns
            .storage_used
            .map(|b| format!(", storage_used={b}B"))
            .unwrap_or_default();
        let updated = ns
            .updated_at
            .as_deref()
            .and_then(|s| s.get(..10))
            .map(|prefix| format!(", updated={prefix}"))
            .unwrap_or_default();
        lines.push(format!(
            "- \"{}\": {}{}{}",
            ns.name,
            format_memory_count(ns.memory_count),
            bytes,
            updated
        ));
    }
    if has_more_pages {
        if let Some(cursor) = next_cursor {
            lines.push(format!(
                "\nMore namespaces available (next_cursor=\"{cursor}\")."
            ));
        }
    }
    lines.join("\n")
}

async fn resolve_caller_owner(
    state: &AppState,
    delegate_key_hex: &str,
    account_id: &str,
    default_namespace: &str,
) -> Result<String, String> {
    let (status, body) = call_local_relayer(
        state,
        delegate_key_hex,
        account_id,
        Method::POST,
        "/api/stats",
        Some(&json!({ "namespace": default_namespace })),
        &[],
    )
    .await?;

    if !status.is_success() {
        return Err(format!(
            "POST /api/stats failed (HTTP {}): {body}",
            status.as_u16()
        ));
    }

    body.get("owner")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "POST /api/stats returned no owner".to_owned())
}

fn parse_namespaces_page_json(body: &Value) -> Result<NamespacesPage, String> {
    let raw_namespaces = body
        .get("namespaces")
        .and_then(Value::as_array)
        .ok_or_else(|| "namespaces array missing in response".to_owned())?;

    let namespaces = raw_namespaces
        .iter()
        .map(|item| {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let memory_count = item
                .get("memory_count")
                .and_then(|v| {
                    v.as_u64()
                        .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
                })
                .unwrap_or(0);
            let storage_used = item.get("storage_used").and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_i64().and_then(|i| u64::try_from(i).ok()))
            });
            let updated_at = item
                .get("updated_at")
                .and_then(Value::as_str)
                .map(str::to_owned);
            NamespaceEntry {
                name,
                memory_count,
                storage_used,
                updated_at,
            }
        })
        .collect();

    let next_cursor = body
        .get("next_cursor")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let has_more = body
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(NamespacesPage {
        namespaces,
        next_cursor,
        has_more,
    })
}

async fn fetch_namespaces_page_for_owner(
    state: &AppState,
    delegate_key_hex: &str,
    account_id: &str,
    owner: &str,
    limit: u64,
    cursor: Option<&str>,
) -> Result<NamespacesPage, String> {
    let path_and_query = match cursor {
        Some(c) => {
            let encoded_cursor =
                percent_encoding::utf8_percent_encode(c, percent_encoding::NON_ALPHANUMERIC);
            format!("/v1/owners/{owner}/namespaces?limit={limit}&updated_after={encoded_cursor}")
        }
        None => format!("/v1/owners/{owner}/namespaces?limit={limit}"),
    };

    let (status, body) = call_local_relayer(
        state,
        delegate_key_hex,
        account_id,
        Method::GET,
        &path_and_query,
        None,
        &[],
    )
    .await?;

    if !status.is_success() {
        return Err(format!(
            "GET /v1/owners/{owner}/namespaces failed (HTTP {}): {body}",
            status.as_u16()
        ));
    }

    parse_namespaces_page_json(&body)
}

async fn fetch_namespaces_page(
    state: &AppState,
    delegate_key_hex: &str,
    account_id: &str,
    default_namespace: &str,
    limit: u64,
    cursor: Option<&str>,
) -> Result<NamespacesPage, String> {
    let owner =
        resolve_caller_owner(state, delegate_key_hex, account_id, default_namespace).await?;
    fetch_namespaces_page_for_owner(state, delegate_key_hex, account_id, &owner, limit, cursor)
        .await
}

async fn try_list_namespaces(
    state: &AppState,
    delegate_key_hex: &str,
    account_id: &str,
    default_namespace: &str,
    target_namespace: Option<&str>,
    limit: u64,
    max_pages: usize,
) -> Option<DiscoveredNamespaces> {
    let owner = resolve_caller_owner(state, delegate_key_hex, account_id, default_namespace)
        .await
        .ok()?;

    let mut all: Vec<NamespaceEntry> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut has_more = false;

    for _ in 0..max_pages {
        let page = fetch_namespaces_page_for_owner(
            state,
            delegate_key_hex,
            account_id,
            &owner,
            limit,
            cursor.as_deref(),
        )
        .await
        .ok()?;

        all.extend(page.namespaces);
        has_more = page.has_more;

        if !has_more || page.next_cursor.is_none() {
            break;
        }

        if let Some(target) = target_namespace {
            if all.iter().any(|ns| ns.name == target) {
                break;
            }
        }

        cursor = page.next_cursor;
    }

    Some(DiscoveredNamespaces {
        namespaces: all,
        has_more,
    })
}

const REMEMBER_RETRY_BUCKET_MS: u64 = 30 * 60 * 1000;

/// Derives a 30-minute bucketed idempotency key (`r1-<64hex>`) matching
/// `derivedIdempotencyKey` in `services/server/scripts/mcp/tools/remember-wait.ts`.
pub(crate) fn derived_remember_idempotency_key(
    text: &str,
    resolved_namespace: &str,
    now_ms: u64,
) -> String {
    let bucket = now_ms / REMEMBER_RETRY_BUCKET_MS;
    let digest = hex::encode(Sha256::digest(
        format!("{bucket}\0{resolved_namespace}\0{text}").as_bytes(),
    ));
    format!("r1-{digest}")
}

fn extract_written_date(created_at: Option<&str>) -> Option<&str> {
    let raw = created_at?.trim();
    if raw.len() >= 10 {
        let prefix = &raw[..10];
        let b = prefix.as_bytes();
        if b[0..4].iter().all(u8::is_ascii_digit)
            && b[4] == b'-'
            && b[5..7].iter().all(u8::is_ascii_digit)
            && b[7] == b'-'
            && b[8..10].iter().all(u8::is_ascii_digit)
        {
            return Some(prefix);
        }
    }
    None
}

fn normalize_recall_dedupe_key(text: &str) -> String {
    text.trim()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

struct CollapsedDuplicate {
    index: usize,
    total: usize,
    collapsed: usize,
    blob_ids: Vec<String>,
}

fn format_collapsed_duplicates_note(duplicates: &[CollapsedDuplicate]) -> String {
    if duplicates.is_empty() {
        return String::new();
    }
    if let [d] = duplicates {
        let copy_word = if d.collapsed == 1 { "copy" } else { "copies" };
        let backing = if d.blob_ids.len() > 1 {
            format!("#{} is stored across {} blobs", d.index, d.blob_ids.len())
        } else {
            format!("{} copies total", d.total)
        };
        return format!(
            "\n({} duplicate {copy_word} of #{} collapsed — {backing}; the same fact is stored more than once.)",
            d.collapsed, d.index
        );
    }

    let total_collapsed: usize = duplicates.iter().map(|d| d.collapsed).sum();
    let copy_word = if total_collapsed == 1 {
        "copy"
    } else {
        "copies"
    };
    let details = duplicates
        .iter()
        .map(|d| {
            let dup_word = if d.collapsed == 1 {
                "duplicate"
            } else {
                "duplicates"
            };
            let backing = if d.blob_ids.len() > 1 {
                format!("{} blobs", d.blob_ids.len())
            } else {
                format!("{} copies", d.total)
            };
            format!("#{} ({} {dup_word}, {backing})", d.index, d.collapsed)
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "\n({total_collapsed} duplicate {copy_word} collapsed: {details}; the same fact is stored more than once.)"
    )
}

pub(crate) fn format_recall_output_with_namespaces(
    results: &[Value],
    max_distance: Option<f64>,
    dropped_count: u64,
    namespace_context: Option<(&str, &DiscoveredNamespaces)>,
) -> String {
    let filtered: Vec<&Value> = results
        .iter()
        .filter(|item| {
            let dist = item.get("distance").and_then(Value::as_f64).unwrap_or(0.0);
            max_distance.is_none_or(|cutoff| dist < cutoff)
        })
        .collect();

    let mut seen: std::collections::HashMap<String, CollapsedDuplicate> =
        std::collections::HashMap::new();
    let mut seen_order: Vec<String> = Vec::new();
    let mut unique = Vec::with_capacity(filtered.len());
    for item in filtered {
        let text = item.get("text").and_then(Value::as_str).unwrap_or("");
        let key = normalize_recall_dedupe_key(text);
        let blob_id = item
            .get("blob_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if let Some(existing) = seen.get_mut(&key) {
            existing.total += 1;
            existing.collapsed += 1;
            if let Some(bid) = blob_id {
                if !existing.blob_ids.iter().any(|b| b == bid) {
                    existing.blob_ids.push(bid.to_owned());
                }
            }
        } else {
            unique.push(item);
            let index = unique.len();
            let mut blob_ids = Vec::new();
            if let Some(bid) = blob_id {
                blob_ids.push(bid.to_owned());
            }
            seen_order.push(key.clone());
            seen.insert(
                key,
                CollapsedDuplicate {
                    index,
                    total: 1,
                    collapsed: 0,
                    blob_ids,
                },
            );
        }
    }

    if unique.is_empty() {
        if !results.is_empty() {
            let dropped_note = if dropped_count > 0 {
                let match_word = if dropped_count == 1 {
                    "match was"
                } else {
                    "matches were"
                };
                format!(
                    " ({dropped_count} further {match_word} never checked against the cutoff: they failed to download or decrypt.)"
                )
            } else {
                String::new()
            };
            return format!(
                "All matching memories were outside maxDistance. Increase maxDistance or omit it to inspect weaker matches.{dropped_note}"
            );
        }
        if dropped_count > 0 {
            return format!(
                "No matching memories could be returned ({dropped_count} match(es) failed to decrypt)."
            );
        }
        if let Some((active_namespace, discovery)) = namespace_context {
            if let Some(active_entry) = discovery
                .namespaces
                .iter()
                .find(|ns| ns.name == active_namespace)
            {
                if active_entry.memory_count == 0 {
                    let hint = format_namespace_suggestion_hint(
                        active_namespace,
                        &discovery.namespaces,
                        5,
                    );
                    let suffix = if hint.is_empty() {
                        String::new()
                    } else {
                        format!(" {hint}")
                    };
                    return format!(
                        "No matching memories found (namespace \"{active_namespace}\" currently holds 0 memories).{suffix}"
                    );
                } else {
                    return format!(
                        "No matching memories found in namespace \"{active_namespace}\" (0 matches among {}).",
                        format_memory_count(active_entry.memory_count)
                    );
                }
            }
            if discovery.has_more {
                return format!("No matching memories found in namespace \"{active_namespace}\".");
            }
            let hint = format_namespace_suggestion_hint(active_namespace, &discovery.namespaces, 5);
            let suffix = if hint.is_empty() {
                String::new()
            } else {
                format!(" {hint}")
            };
            return format!(
                "No matching memories found (namespace \"{active_namespace}\" currently holds 0 memories).{suffix}"
            );
        }
        return "No matching memories found.".to_owned();
    }

    let mut lines = Vec::with_capacity(unique.len());
    for (idx, item) in unique.iter().enumerate() {
        let rank = idx + 1;
        let dist = item.get("distance").and_then(Value::as_f64).unwrap_or(0.0);
        let score = 1.0 - dist;
        let text = item.get("text").and_then(Value::as_str).unwrap_or("");
        let created_at = item.get("created_at").and_then(Value::as_str);
        if let Some(date) = extract_written_date(created_at) {
            lines.push(format!(
                "{rank}. [score={score:.3} distance={dist:.3}] [written={date}] {text}"
            ));
        } else {
            lines.push(format!(
                "{rank}. [score={score:.3} distance={dist:.3}] {text}"
            ));
        }
    }

    let duplicates: Vec<CollapsedDuplicate> = seen_order
        .into_iter()
        .filter_map(|k| seen.remove(&k))
        .filter(|d| d.collapsed > 0)
        .collect();

    let mut out = lines.join("\n");
    out.push_str(&format_collapsed_duplicates_note(&duplicates));
    if dropped_count > 0 {
        out.push_str(&format!(
            "\n({dropped_count} additional matches could not be decrypted and were omitted.)"
        ));
    }
    out
}

#[allow(dead_code)]
pub(crate) fn format_recall_output(
    results: &[Value],
    max_distance: Option<f64>,
    dropped_count: u64,
) -> String {
    format_recall_output_with_namespaces(results, max_distance, dropped_count, None)
}

pub(crate) fn format_restore_output_with_namespaces(
    body: &Value,
    resolved_namespace: &str,
    namespaces: Option<&[NamespaceEntry]>,
) -> String {
    let Some(total) = body.get("total").and_then(Value::as_u64) else {
        return body.to_string();
    };
    let restored = body.get("restored").and_then(Value::as_u64).unwrap_or(0);
    let skipped = body.get("skipped").and_then(Value::as_u64).unwrap_or(0);
    let failed = body.get("failed").and_then(Value::as_u64).unwrap_or(0);
    let truncated = body
        .get("truncated")
        .or_else(|| body.get("has_more"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let next_cursor = body.get("next_cursor").and_then(Value::as_str);

    let headline = if failed > 0 {
        "Restore partially complete."
    } else {
        "Restore page finished."
    };
    let mut lines = vec![format!(
        "{headline} namespace={resolved_namespace} total={total} restored={restored} skipped={skipped} failed={failed} truncated={truncated}"
    )];

    let is_empty = !truncated && total == 0 && restored == 0 && skipped == 0 && failed == 0;
    if is_empty {
        let suggestion_hint = namespaces
            .map(|ns_list| format_namespace_suggestion_hint(resolved_namespace, ns_list, 5))
            .unwrap_or_default();
        let hint_suffix = if suggestion_hint.is_empty() {
            String::new()
        } else {
            format!(" {suggestion_hint}")
        };
        lines.push(format!(
            "This restore query discovered 0 matching blobs in namespace \"{resolved_namespace}\".{hint_suffix}"
        ));
    }

    if truncated {
        let cursor_hint = next_cursor
            .map(|c| format!(" (next_cursor={c})"))
            .unwrap_or_default();
        lines.push(format!(
            "More blobs remain on-chain{cursor_hint}. Run memwal_restore again to continue."
        ));
    }

    if let Some(errors) = body.get("errors").and_then(Value::as_array) {
        if !errors.is_empty() {
            lines.push("Errors:".to_owned());
            for err in errors {
                let blob_id = err
                    .get("blob_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let object_id = err
                    .get("object_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let msg = err
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error");
                lines.push(format!(
                    "  - blob_id={blob_id} object_id={object_id}: {msg}"
                ));
            }
        }
    }

    lines.join("\n")
}

#[allow(dead_code)]
pub(crate) fn format_restore_output(body: &Value, resolved_namespace: &str) -> String {
    format_restore_output_with_namespaces(body, resolved_namespace, None)
}

// ============================================================================
// Credential Redaction & Write-Time Sanitization
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionKind {
    UrlCredentials,
    VendorApiKey,
    PrivateKeyBlock,
    Jwt,
    CredentialAssignment,
    AuthHeader,
    SeedPhrase,
    LabelledKeyMaterial,
    HighEntropySecret,
}

impl RedactionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UrlCredentials => "url-credentials",
            Self::VendorApiKey => "vendor-api-key",
            Self::PrivateKeyBlock => "private-key-block",
            Self::Jwt => "jwt",
            Self::CredentialAssignment => "credential-assignment",
            Self::AuthHeader => "auth-header",
            Self::SeedPhrase => "seed-phrase",
            Self::LabelledKeyMaterial => "labelled-key-material",
            Self::HighEntropySecret => "high-entropy-secret",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalReason {
    NoSaveDirective,
    CredentialOnly,
    PastedContent,
}

impl RefusalReason {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoSaveDirective => "no-save-directive",
            Self::CredentialOnly => "credential-only",
            Self::PastedContent => "pasted-content",
        }
    }
}

pub fn refusal_message(reason: RefusalReason) -> &'static str {
    match reason {
        RefusalReason::NoSaveDirective => "the text says not to save it",
        RefusalReason::CredentialOnly => "the text was a credential with no fact around it",
        RefusalReason::PastedContent => {
            "the text is pasted third-party content, not a fact about the user"
        }
    }
}

pub fn refusal_notice(reason: RefusalReason) -> String {
    format!(
        "NOT SAVED: {}. Nothing was written to Walrus Memory. Do not retry this text: if there is a durable fact in it, restate the fact without the sensitive part and save that instead.",
        refusal_message(reason)
    )
}

pub fn redaction_notice(kinds: &[RedactionKind], count: usize) -> String {
    if count == 0 || kinds.is_empty() {
        return String::new();
    }
    let mut ordered: Vec<&'static str> = Vec::new();
    for k in kinds {
        let s = k.as_str();
        if !ordered.contains(&s) {
            ordered.push(s);
        }
    }
    let kinds_str = ordered.join(", ");
    format!(
        "Note: {count} credential span(s) were removed before saving ({kinds_str}). What was stored is the redacted text: the secret was never sent to Walrus Memory and is not logged. Tell the user the credential was left out; do not re-send it."
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DroppedSpan {
    pub line: usize,
    pub reason: RefusalReason,
}

pub fn dropped_span_notice(dropped: &[DroppedSpan], segments: usize) -> String {
    if dropped.is_empty() {
        return String::new();
    }
    let detail = dropped
        .iter()
        .map(|d| format!("line {} ({})", d.line, refusal_message(d.reason)))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "Note: {} of {segments} span(s) were dropped before extraction and nothing from them was saved: {detail}. The rest of the passage was extracted from normally. Tell the user which part was left out; do not re-send it.",
        dropped.len()
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedText {
    pub text: String,
    pub changed: bool,
    pub kinds: Vec<RedactionKind>,
    pub count: usize,
    pub refusal: Option<RefusalReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedPassage {
    pub text: String,
    pub changed: bool,
    pub kinds: Vec<RedactionKind>,
    pub count: usize,
    pub refusal: Option<RefusalReason>,
    pub dropped: Vec<DroppedSpan>,
    pub segments: usize,
}

fn placeholder_str(kind: RedactionKind) -> &'static str {
    match kind {
        RedactionKind::UrlCredentials => "[redacted:url-credentials]",
        RedactionKind::VendorApiKey => "[redacted:vendor-api-key]",
        RedactionKind::PrivateKeyBlock => "[redacted:private-key-block]",
        RedactionKind::Jwt => "[redacted:jwt]",
        RedactionKind::CredentialAssignment => "[redacted:credential-assignment]",
        RedactionKind::AuthHeader => "[redacted:auth-header]",
        RedactionKind::SeedPhrase => "[redacted:seed-phrase]",
        RedactionKind::LabelledKeyMaterial => "[redacted:labelled-key-material]",
        RedactionKind::HighEntropySecret => "[redacted:high-entropy-secret]",
    }
}

#[inline]
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_no_save_directive(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();

    for needle in ["off the record", "off-the-record"] {
        let mut start = 0;
        while let Some(pos) = lower[start..].find(needle) {
            let abs_pos = start + pos;
            let end_pos = abs_pos + needle.len();
            let left_ok = abs_pos == 0 || !is_word_byte(lower.as_bytes()[abs_pos - 1]);
            let right_ok = end_pos == lower.len() || !is_word_byte(lower.as_bytes()[end_pos]);
            if left_ok && right_ok {
                return true;
            }
            start = abs_pos + needle.len();
        }
    }

    const PREFIXES: &[&str] = &[
        "please do not",
        "please don't",
        "please dont",
        "do not",
        "don't",
        "dont",
        "never",
    ];
    const VERBS: &[&str] = &[
        "save", "store", "remember", "record", "keep", "persist", "log",
    ];
    const OBJECTS: &[&str] = &[
        "any of this",
        "any of that",
        "any of it",
        "this",
        "that",
        "it",
        "these",
        "those",
    ];

    for prefix in PREFIXES {
        let mut start = 0;
        while let Some(pos) = lower[start..].find(prefix) {
            let abs_pos = start + pos;
            let end_pos = abs_pos + prefix.len();
            let left_ok = abs_pos == 0 || !is_word_byte(lower.as_bytes()[abs_pos - 1]);
            if left_ok {
                let rest = &lower[end_pos..];
                let trimmed_rest = rest.trim_start();
                if trimmed_rest.len() < rest.len() {
                    for verb in VERBS {
                        if trimmed_rest.starts_with(verb) {
                            let after_verb = &trimmed_rest[verb.len()..];
                            let trimmed_after_verb = after_verb.trim_start();
                            if trimmed_after_verb.len() < after_verb.len() {
                                for obj in OBJECTS {
                                    if trimmed_after_verb.starts_with(obj) {
                                        let end_obj = obj.len();
                                        let right_ok = end_obj == trimmed_after_verb.len()
                                            || !is_word_byte(
                                                trimmed_after_verb.as_bytes()[end_obj],
                                            );
                                        if right_ok {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            start = abs_pos + prefix.len();
        }
    }

    false
}

fn is_pasted_content(text: &str) -> bool {
    let s = text.trim();
    if s.starts_with("```") && s.ends_with("```") && s.len() >= 6 {
        return true;
    }
    let lines: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.len() >= 2 && lines.iter().all(|l| l.starts_with('>')) {
        return true;
    }
    if s.len() >= 200 {
        let starts_quote = s.starts_with('"') || s.starts_with('“');
        let ends_quote = s.ends_with('"') || s.ends_with('”');
        if starts_quote && ends_quote {
            return true;
        }
    }
    false
}

fn has_salvageable_content(text: &str) -> bool {
    let mut without_placeholders = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("[redacted:") {
        without_placeholders.push_str(&rest[..start]);
        let after = &rest[start + "[redacted:".len()..];
        if let Some(end) = after.find(']') {
            without_placeholders.push(' ');
            rest = &after[end + 1..];
        } else {
            without_placeholders.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    without_placeholders.push_str(rest);

    let mut word_count = 0usize;
    let mut current_word_chars = 0usize;
    for ch in without_placeholders.chars() {
        if ch.is_alphanumeric() {
            current_word_chars += 1;
        } else {
            if current_word_chars >= 2 {
                word_count += 1;
                if word_count >= 3 {
                    return true;
                }
            }
            current_word_chars = 0;
        }
    }
    if current_word_chars >= 2 {
        word_count += 1;
    }
    word_count >= 3
}

fn redact_pem(input: &str, kinds: &mut Vec<RedactionKind>, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(begin_pos) = rest.find("-----BEGIN ") {
        out.push_str(&rest[..begin_pos]);
        let candidate = &rest[begin_pos..];
        let Some(header_end) = candidate.find("PRIVATE KEY-----") else {
            out.push_str("-----BEGIN ");
            rest = &candidate["-----BEGIN ".len()..];
            continue;
        };
        let label = &candidate["-----BEGIN ".len()..header_end];
        if !label
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ')
        {
            out.push_str("-----BEGIN ");
            rest = &candidate["-----BEGIN ".len()..];
            continue;
        }
        let after_header = &candidate[header_end + "PRIVATE KEY-----".len()..];
        let mut closed_len = None;
        if let Some(end_idx) = after_header.find("-----END ") {
            let after_end = &after_header[end_idx + "-----END ".len()..];
            if let Some(footer_end) = after_end.find("PRIVATE KEY-----") {
                let footer_label = &after_end[..footer_end];
                if footer_label
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ')
                {
                    closed_len = Some(
                        header_end
                            + "PRIVATE KEY-----".len()
                            + end_idx
                            + "-----END ".len()
                            + footer_end
                            + "PRIVATE KEY-----".len(),
                    );
                }
            }
        }
        if !kinds.contains(&RedactionKind::PrivateKeyBlock) {
            kinds.push(RedactionKind::PrivateKeyBlock);
        }
        *count += 1;
        out.push_str(placeholder_str(RedactionKind::PrivateKeyBlock));
        if let Some(total_len) = closed_len {
            rest = &candidate[total_len..];
        } else {
            return out;
        }
    }
    out.push_str(rest);
    out
}

fn redact_url_credentials(
    input: &str,
    kinds: &mut Vec<RedactionKind>,
    count: &mut usize,
) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if i + 3 <= bytes.len() && &bytes[i..i + 3] == b"://" {
            let mut scheme_start = i;
            while scheme_start > 0
                && (i - scheme_start) <= 30
                && (bytes[scheme_start - 1].is_ascii_alphanumeric()
                    || matches!(bytes[scheme_start - 1], b'+' | b'.' | b'-'))
            {
                scheme_start -= 1;
            }
            let valid_scheme = scheme_start < i
                && bytes[scheme_start].is_ascii_alphabetic()
                && (scheme_start == 0 || !is_word_byte(bytes[scheme_start - 1]));
            if valid_scheme {
                let scheme = &input[scheme_start..i];
                let after_scheme = i + 3;
                let user_len = bytes[after_scheme..]
                    .iter()
                    .take_while(|&&b| {
                        !b.is_ascii_whitespace()
                            && !matches!(b, b'/' | b'@' | b':' | b'?' | b'=' | b'&')
                    })
                    .count();
                let colon_pos = after_scheme + user_len;
                if user_len > 0 && colon_pos < bytes.len() && bytes[colon_pos] == b':' {
                    let pass_start = colon_pos + 1;
                    let pass_len = bytes[pass_start..]
                        .iter()
                        .take_while(|&&b| {
                            !b.is_ascii_whitespace()
                                && !matches!(b, b'/' | b'@' | b'?' | b'=' | b'&')
                        })
                        .count();
                    let at_pos = pass_start + pass_len;
                    if pass_len > 0 && at_pos < bytes.len() && bytes[at_pos] == b'@' {
                        out.truncate(out.len() - (i - scheme_start));
                        out.push_str(scheme);
                        out.push_str("://");
                        out.push_str(placeholder_str(RedactionKind::UrlCredentials));
                        out.push('@');
                        if !kinds.contains(&RedactionKind::UrlCredentials) {
                            kinds.push(RedactionKind::UrlCredentials);
                        }
                        *count += 1;
                        i = at_pos + 1;
                        continue;
                    }
                }
            }
        }
        let ch = input[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_auth_and_cookie_headers(
    input: &str,
    kinds: &mut Vec<RedactionKind>,
    count: &mut usize,
) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
        let (byte_offset, _) = chars[i];
        let slice = &input[byte_offset..];
        let at_word_boundary = byte_offset == 0 || !is_word_byte(input.as_bytes()[byte_offset - 1]);

        if at_word_boundary {
            let bytes = slice.as_bytes();
            let header_match =
                if bytes.len() >= 19 && bytes[..19].eq_ignore_ascii_case(b"proxy-authorization") {
                    Some(19)
                } else if bytes.len() >= 13 && bytes[..13].eq_ignore_ascii_case(b"authorization") {
                    Some(13)
                } else {
                    None
                };

            if let Some(h_len) = header_match {
                let mut p = h_len;
                while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                    p += 1;
                }
                if p < bytes.len() && (bytes[p] == b':' || bytes[p] == b'=') {
                    p += 1;
                    while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                        p += 1;
                    }
                    let rem = &bytes[p..];
                    let prefix_len = if rem.len() >= 6 && rem[..6].eq_ignore_ascii_case(b"bearer") {
                        Some(6)
                    } else if rem.len() >= 5 && rem[..5].eq_ignore_ascii_case(b"basic") {
                        Some(5)
                    } else if rem.len() >= 5 && rem[..5].eq_ignore_ascii_case(b"token") {
                        Some(5)
                    } else if rem.len() >= 6 && rem[..6].eq_ignore_ascii_case(b"digest") {
                        Some(6)
                    } else {
                        None
                    };
                    if let Some(plen) = prefix_len {
                        p += plen;
                        while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                            p += 1;
                        }
                    }
                    let val_len = bytes[p..]
                        .iter()
                        .take_while(|&&b| !b.is_ascii_whitespace())
                        .count();
                    if val_len > 0 {
                        out.push_str(&slice[..p]);
                        out.push_str(placeholder_str(RedactionKind::AuthHeader));
                        if !kinds.contains(&RedactionKind::AuthHeader) {
                            kinds.push(RedactionKind::AuthHeader);
                        }
                        *count += 1;
                        let advance_bytes = p + val_len;
                        while i < chars.len() && chars[i].0 < byte_offset + advance_bytes {
                            i += 1;
                        }
                        continue;
                    }
                }
            }

            let cookie_match =
                if bytes.len() >= 10 && bytes[..10].eq_ignore_ascii_case(b"set-cookie") {
                    Some(10)
                } else if bytes.len() >= 6 && bytes[..6].eq_ignore_ascii_case(b"cookie") {
                    Some(6)
                } else {
                    None
                };
            if let Some(c_len) = cookie_match {
                let mut p = c_len;
                while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                    p += 1;
                }
                if p < bytes.len() && (bytes[p] == b':' || bytes[p] == b'=') {
                    p += 1;
                    while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                        p += 1;
                    }
                    let cookie_val_len = {
                        let mut cp = p;
                        let first_pair = bytes[cp..]
                            .iter()
                            .take_while(|&&b| !b.is_ascii_whitespace() && b != b';')
                            .count();
                        if first_pair > 0 {
                            cp += first_pair;
                            loop {
                                let mut look = cp;
                                while look < bytes.len()
                                    && (bytes[look] == b' ' || bytes[look] == b'\t')
                                {
                                    look += 1;
                                }
                                if look < bytes.len() && bytes[look] == b';' {
                                    look += 1;
                                    while look < bytes.len()
                                        && (bytes[look] == b' ' || bytes[look] == b'\t')
                                    {
                                        look += 1;
                                    }
                                    let next_pair = bytes[look..]
                                        .iter()
                                        .take_while(|&&b| !b.is_ascii_whitespace() && b != b';')
                                        .count();
                                    if next_pair > 0 {
                                        cp = look + next_pair;
                                        continue;
                                    }
                                }
                                break;
                            }
                            cp - p
                        } else {
                            0
                        }
                    };
                    if cookie_val_len > 0 {
                        out.push_str(&slice[..p]);
                        out.push_str(placeholder_str(RedactionKind::AuthHeader));
                        if !kinds.contains(&RedactionKind::AuthHeader) {
                            kinds.push(RedactionKind::AuthHeader);
                        }
                        *count += 1;
                        let advance_bytes = p + cookie_val_len;
                        while i < chars.len() && chars[i].0 < byte_offset + advance_bytes {
                            i += 1;
                        }
                        continue;
                    }
                }
            }
        }

        out.push(chars[i].1);
        i += 1;
    }
    out
}

fn redact_credential_assignments(
    input: &str,
    kinds: &mut Vec<RedactionKind>,
    count: &mut usize,
) -> String {
    // Keywords from CREDENTIAL_ASSIGNMENT
    const KEYWORDS: &[&str] = &[
        "passwords",
        "password",
        "passwd",
        "pwd",
        "db_passwords",
        "db_password",
        "db-passwords",
        "db-password",
        "dbpasswords",
        "dbpassword",
        "db_pass",
        "db-pass",
        "dbpass",
        "passphrases",
        "passphrase",
        "api_keys",
        "api_key",
        "api-keys",
        "api-key",
        "apikeys",
        "apikey",
        "secret_keys",
        "secret_key",
        "secret-keys",
        "secret-key",
        "access_keys",
        "access_key",
        "access-keys",
        "access-key",
        "encryption_keys",
        "encryption_key",
        "encryption-keys",
        "encryption-key",
        "enc_keys",
        "enc_key",
        "enc-keys",
        "enc-key",
        "client_secrets",
        "client_secret",
        "client-secrets",
        "client-secret",
        "secrets",
        "secret",
        "access_tokens",
        "access_token",
        "access-tokens",
        "access-token",
        "refresh_tokens",
        "refresh_token",
        "refresh-tokens",
        "refresh-token",
        "auth_tokens",
        "auth_token",
        "auth-tokens",
        "auth-token",
        "bearer_tokens",
        "bearer_token",
        "bearer-tokens",
        "bearer-token",
        "tokens",
        "token",
        "private_keys",
        "private_key",
        "private-keys",
        "private-key",
        "priv_keys",
        "priv_key",
        "priv-keys",
        "priv-key",
        "credentials",
        "credential",
    ];

    let mut out = String::with_capacity(input.len());
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
        let (byte_offset, _) = chars[i];
        let slice = &input[byte_offset..];
        // Allowed left boundary: start of text, non-word char, or [a-z0-9_-] (NOT uppercase ASCII)
        let left_ok = byte_offset == 0 || !input.as_bytes()[byte_offset - 1].is_ascii_uppercase();

        if left_ok {
            let bytes = slice.as_bytes();
            let mut matched_kw_len = None;
            for kw in KEYWORDS {
                let kw_bytes = kw.as_bytes();
                if bytes.len() >= kw_bytes.len()
                    && bytes[..kw_bytes.len()].eq_ignore_ascii_case(kw_bytes)
                {
                    matched_kw_len = Some(kw_bytes.len());
                    break;
                }
            }

            if let Some(kw_len) = matched_kw_len {
                let after_kw = &slice[kw_len..];
                let mut p = 0;
                let bytes = after_kw.as_bytes();
                let _quote_char = if p < bytes.len() && matches!(bytes[p], b'"' | b'\'' | b'`') {
                    let q = bytes[p];
                    p += 1;
                    Some(q)
                } else {
                    None
                };
                while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                    p += 1;
                }
                if p < bytes.len() && (bytes[p] == b':' || bytes[p] == b'=') {
                    p += 1;
                    while p < bytes.len() && (bytes[p] == b' ' || bytes[p] == b'\t') {
                        p += 1;
                    }
                    if p < bytes.len() {
                        let val_slice = &after_kw[p..];
                        let val_bytes = val_slice.as_bytes();
                        let val_len = if matches!(val_bytes[0], b'"' | b'\'' | b'`') {
                            let open_q = val_bytes[0];
                            let mut end_q = 1;
                            while end_q < val_bytes.len()
                                && val_bytes[end_q] != open_q
                                && val_bytes[end_q] != b'\n'
                            {
                                end_q += 1;
                            }
                            if end_q < val_bytes.len() && val_bytes[end_q] == open_q {
                                end_q + 1
                            } else {
                                0
                            }
                        } else {
                            val_bytes
                                .iter()
                                .take_while(|&&b| {
                                    !b.is_ascii_whitespace() && b != b',' && b != b';'
                                })
                                .count()
                        };

                        if val_len > 0 {
                            let key_orig = &slice[..kw_len];
                            let sep_orig = &after_kw[..p];
                            out.push_str(key_orig);
                            out.push_str(sep_orig);
                            out.push_str(placeholder_str(RedactionKind::CredentialAssignment));
                            if !kinds.contains(&RedactionKind::CredentialAssignment) {
                                kinds.push(RedactionKind::CredentialAssignment);
                            }
                            *count += 1;
                            let advance_bytes = kw_len + p + val_len;
                            while i < chars.len() && chars[i].0 < byte_offset + advance_bytes {
                                i += 1;
                            }
                            continue;
                        }
                    }
                }
            }
        }

        out.push(chars[i].1);
        i += 1;
    }
    out
}

fn redact_vendor_keys(input: &str, kinds: &mut Vec<RedactionKind>, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
        let (byte_offset, _) = chars[i];
        let slice = &input[byte_offset..];
        let at_word_boundary = byte_offset == 0 || !is_word_byte(input.as_bytes()[byte_offset - 1]);

        if at_word_boundary {
            let bytes = slice.as_bytes();

            // suiprivkey1
            let sui_priv = if bytes.len() >= 27 && bytes[..11].eq_ignore_ascii_case(b"suiprivkey1")
            {
                let body_len = bytes[11..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric())
                    .count();
                if body_len >= 16 {
                    Some(11 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            // sk-ant-
            let sk_ant = if bytes.starts_with(b"sk-ant-") {
                let body_len = bytes[7..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    .count();
                if body_len >= 16 {
                    Some(7 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            // sk-proj-
            let sk_proj = if bytes.starts_with(b"sk-proj-") {
                let body_len = bytes[8..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    .count();
                if body_len >= 16 {
                    Some(8 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            // sk-
            let sk_classic = if bytes.starts_with(b"sk-")
                && !bytes.starts_with(b"sk-ant-")
                && !bytes.starts_with(b"sk-proj-")
            {
                let body_len = bytes[3..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric())
                    .count();
                if body_len >= 20 {
                    Some(3 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            // ghp, gho, ghu, ghs, ghr
            let gh_token = if bytes.len() >= 24
                && (bytes.starts_with(b"ghp_")
                    || bytes.starts_with(b"gho_")
                    || bytes.starts_with(b"ghu_")
                    || bytes.starts_with(b"ghs_")
                    || bytes.starts_with(b"ghr_"))
            {
                let body_len = bytes[4..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric())
                    .count();
                if body_len >= 20 {
                    Some(4 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            // github_pat_
            let gh_pat = if bytes.starts_with(b"github_pat_") {
                let body_len = bytes[11..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_')
                    .count();
                if body_len >= 20 {
                    Some(11 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            // AKIA, ASIA
            let aws_key = if bytes.len() >= 20
                && (bytes.starts_with(b"AKIA") || bytes.starts_with(b"ASIA"))
            {
                let body = &bytes[4..20];
                if body
                    .iter()
                    .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit())
                    && (bytes.len() == 20 || !is_word_byte(bytes[20]))
                {
                    Some(20)
                } else {
                    None
                }
            } else {
                None
            };

            // xox[baprs]-
            let slack = if bytes.len() >= 15
                && bytes.starts_with(b"xox")
                && matches!(bytes[3], b'b' | b'a' | b'p' | b'r' | b's')
                && bytes[4] == b'-'
            {
                let body_len = bytes[5..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'-')
                    .count();
                if body_len >= 10 {
                    Some(5 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            // AIza
            let google_api = if bytes.len() >= 39 && bytes.starts_with(b"AIza") {
                let body = &bytes[4..39];
                if body
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    && (bytes.len() == 39 || !is_word_byte(bytes[39]))
                {
                    Some(39)
                } else {
                    None
                }
            } else {
                None
            };

            // glpat-
            let gitlab = if bytes.starts_with(b"glpat-") {
                let body_len = bytes[6..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    .count();
                if body_len >= 16 {
                    Some(6 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            // npm_
            let npm = if bytes.len() >= 40 && bytes.starts_with(b"npm_") {
                let body = &bytes[4..40];
                if body.iter().all(|&b| b.is_ascii_alphanumeric())
                    && (bytes.len() == 40 || !is_word_byte(bytes[40]))
                {
                    Some(40)
                } else {
                    None
                }
            } else {
                None
            };

            // SG.
            let sendgrid = if bytes.starts_with(b"SG.") {
                let seg1_len = bytes[3..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    .count();
                if seg1_len >= 16 && 3 + seg1_len < bytes.len() && bytes[3 + seg1_len] == b'.' {
                    let seg2_start = 3 + seg1_len + 1;
                    let seg2_len = bytes[seg2_start..]
                        .iter()
                        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                        .count();
                    if seg2_len >= 16 {
                        Some(seg2_start + seg2_len)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // [sprk]k_(live|test)_
            let stripe = if bytes.len() >= 24
                && matches!(bytes[0], b's' | b'p' | b'r' | b'k')
                && bytes[1] == b'k'
                && bytes[2] == b'_'
            {
                let prefix_len = if bytes[3..].starts_with(b"live_") {
                    Some(8)
                } else if bytes[3..].starts_with(b"test_") {
                    Some(8)
                } else {
                    None
                };
                if let Some(plen) = prefix_len {
                    let body_len = bytes[plen..]
                        .iter()
                        .take_while(|&&b| b.is_ascii_alphanumeric())
                        .count();
                    if body_len >= 16 {
                        Some(plen + body_len)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // shp(at|ss|ca|pa)_
            let shopify = if bytes.len() >= 38
                && bytes.starts_with(b"shp")
                && (bytes[3..].starts_with(b"at_")
                    || bytes[3..].starts_with(b"ss_")
                    || bytes[3..].starts_with(b"ca_")
                    || bytes[3..].starts_with(b"pa_"))
            {
                let hex_part = &bytes[6..38];
                if hex_part.iter().all(|&b| b.is_ascii_hexdigit())
                    && (bytes.len() == 38 || !is_word_byte(bytes[38]))
                {
                    Some(38)
                } else {
                    None
                }
            } else {
                None
            };

            // dop_v1_
            let do_token = if bytes.len() >= 71 && bytes.starts_with(b"dop_v1_") {
                let hex_part = &bytes[7..71];
                if hex_part.iter().all(|&b| b.is_ascii_hexdigit())
                    && (bytes.len() == 71 || !is_word_byte(bytes[71]))
                {
                    Some(71)
                } else {
                    None
                }
            } else {
                None
            };

            // hf_
            let hf = if bytes.starts_with(b"hf_") {
                let body_len = bytes[3..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric())
                    .count();
                if body_len >= 30
                    && (3 + body_len == bytes.len() || !is_word_byte(bytes[3 + body_len]))
                {
                    Some(3 + body_len)
                } else {
                    None
                }
            } else {
                None
            };

            let matched_len = sui_priv
                .or(sk_ant)
                .or(sk_proj)
                .or(sk_classic)
                .or(gh_token)
                .or(gh_pat)
                .or(aws_key)
                .or(slack)
                .or(google_api)
                .or(gitlab)
                .or(npm)
                .or(sendgrid)
                .or(stripe)
                .or(shopify)
                .or(do_token)
                .or(hf);

            if let Some(m_len) = matched_len {
                out.push_str(placeholder_str(RedactionKind::VendorApiKey));
                if !kinds.contains(&RedactionKind::VendorApiKey) {
                    kinds.push(RedactionKind::VendorApiKey);
                }
                *count += 1;
                while i < chars.len() && chars[i].0 < byte_offset + m_len {
                    i += 1;
                }
                continue;
            }
        }

        out.push(chars[i].1);
        i += 1;
    }
    out
}

fn redact_jwt(input: &str, kinds: &mut Vec<RedactionKind>, count: &mut usize) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
        let (byte_offset, _) = chars[i];
        let slice = &input[byte_offset..];
        let at_word_boundary = byte_offset == 0 || !is_word_byte(input.as_bytes()[byte_offset - 1]);

        if at_word_boundary && slice.starts_with("eyJ") {
            let bytes = slice.as_bytes();
            let seg1 = 3 + bytes[3..]
                .iter()
                .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                .count();
            if seg1 >= 11 && seg1 < bytes.len() && bytes[seg1] == b'.' {
                let seg2_len = bytes[seg1 + 1..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                    .count();
                let dot2 = seg1 + 1 + seg2_len;
                if seg2_len >= 8 && dot2 < bytes.len() && bytes[dot2] == b'.' {
                    let seg3_len = bytes[dot2 + 1..]
                        .iter()
                        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                        .count();
                    if seg3_len >= 8 {
                        let total_len = dot2 + 1 + seg3_len;
                        out.push_str(placeholder_str(RedactionKind::Jwt));
                        if !kinds.contains(&RedactionKind::Jwt) {
                            kinds.push(RedactionKind::Jwt);
                        }
                        *count += 1;
                        while i < chars.len() && chars[i].0 < byte_offset + total_len {
                            i += 1;
                        }
                        continue;
                    }
                }
            }
        }

        out.push(chars[i].1);
        i += 1;
    }
    out
}

fn redact_seed_phrase(input: &str, kinds: &mut Vec<RedactionKind>, count: &mut usize) -> String {
    const SEED_LABELS: &[&str] = &[
        "seed phrase",
        "seed_phrase",
        "seedphrase",
        "recovery phrase",
        "recovery_phrase",
        "secret phrase",
        "secret_phrase",
        "mnemonic phrase",
        "mnemonic_phrase",
        "seed words",
        "seed_words",
        "recovery words",
        "recovery_words",
        "secret words",
        "secret_words",
        "mnemonic words",
        "mnemonic_words",
        "mnemonic",
    ];

    let mut out = String::with_capacity(input.len());
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
        let (byte_offset, _) = chars[i];
        let slice = &input[byte_offset..];
        let left_ok = byte_offset == 0
            || !input.as_bytes()[byte_offset - 1].is_ascii_alphanumeric()
            || input.as_bytes()[byte_offset - 1].is_ascii_lowercase();

        if left_ok {
            let bytes = slice.as_bytes();
            let mut matched_label_len = None;
            for label in SEED_LABELS {
                let l_bytes = label.as_bytes();
                if bytes.len() >= l_bytes.len()
                    && bytes[..l_bytes.len()].eq_ignore_ascii_case(l_bytes)
                {
                    matched_label_len = Some(l_bytes.len());
                    break;
                }
            }

            if let Some(l_len) = matched_label_len {
                let after_label = &slice[l_len..];
                // Match separator: up to 4 non-alphanumeric, optional is/are, up to 4 non-alphanumeric
                let mut p = 0;
                let bytes = after_label.as_bytes();
                while p < bytes.len() && p < 4 && !bytes[p].is_ascii_alphanumeric() {
                    p += 1;
                }
                if bytes[p..].len() >= 2 && bytes[p..p + 2].eq_ignore_ascii_case(b"is") {
                    p += 2;
                } else if bytes[p..].len() >= 3 && bytes[p..p + 3].eq_ignore_ascii_case(b"are") {
                    p += 3;
                }
                let p_anchor = p;
                while p < bytes.len() && (p - p_anchor) < 4 && !bytes[p].is_ascii_alphanumeric() {
                    p += 1;
                }

                // Check 12 to 24 lowercase words (length 3 to 8 ascii letters) separated by space/tab
                let words_slice = &after_label[p..];
                let mut word_count = 0;
                let mut wp = 0;
                let wbytes = words_slice.as_bytes();
                while wp < wbytes.len() {
                    let wlen = wbytes[wp..]
                        .iter()
                        .take_while(|&&b| b.is_ascii_lowercase())
                        .count();
                    if wlen >= 3 && wlen <= 8 {
                        word_count += 1;
                        wp += wlen;
                        if wp < wbytes.len() && (wbytes[wp] == b' ' || wbytes[wp] == b'\t') {
                            wp += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if word_count >= 11 && word_count <= 24 {
                    out.push_str(&slice[..l_len]);
                    out.push_str(&after_label[..p]);
                    out.push_str(placeholder_str(RedactionKind::SeedPhrase));
                    if !kinds.contains(&RedactionKind::SeedPhrase) {
                        kinds.push(RedactionKind::SeedPhrase);
                    }
                    *count += 1;
                    let advance_bytes = l_len + p + wp;
                    while i < chars.len() && chars[i].0 < byte_offset + advance_bytes {
                        i += 1;
                    }
                    continue;
                }
            }
        }

        out.push(chars[i].1);
        i += 1;
    }
    out
}

const HEX_LABEL_WINDOW: usize = 48;

fn strip_placeholders_for_label_search(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("[redacted:") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "[redacted:".len()..];
        if let Some(end) = after.find(']') {
            out.push(' ');
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out
}

fn contains_credential_label_text(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    const LABELS: &[&str] = &[
        "delegateprivatekey",
        "delegate_private_key",
        "delegate-private-key",
        "delegate private key",
        "delegateprivate",
        "delegate_private",
        "delegate-private",
        "delegate private",
        "delegatekey",
        "delegate_key",
        "delegate-key",
        "delegate key",
        "privatekey",
        "private_key",
        "private-key",
        "private key",
        "secretkey",
        "secret_key",
        "secret-key",
        "secret key",
        "signingkey",
        "signing_key",
        "signing-key",
        "signing key",
        "privkey",
        "priv_key",
        "priv-key",
        "priv key",
        "encryptionkey",
        "encryption_key",
        "encryption-key",
        "encryption key",
        "encryptionkeys",
        "encryption_keys",
        "encryption-keys",
        "encryption keys",
        "enckey",
        "enc_key",
        "enc-key",
        "enc key",
        "enckeys",
        "enc_keys",
        "enc-keys",
        "enc keys",
        "apikey",
        "api_key",
        "api-key",
        "api key",
        "accesskey",
        "access_key",
        "access-key",
        "access key",
        "authkey",
        "auth_key",
        "auth-key",
        "auth key",
        "dbpassword",
        "db_password",
        "db-password",
        "db password",
        "dbpasswords",
        "db_passwords",
        "db-passwords",
        "db passwords",
        "dbpass",
        "db_pass",
        "db-pass",
        "db pass",
        "secret",
        "seed",
        "mnemonic",
        "passphrase",
    ];

    for label in LABELS {
        let mut idx = 0;
        while let Some(pos) = lower[idx..].find(label) {
            let abs_pos = idx + pos;
            let end_pos = abs_pos + label.len();
            let following = &lower[end_pos..];
            let preceding = &lower[..abs_pos];
            if *label == "secret"
                && (preceding.ends_with("not_") || following.starts_with("_store"))
            {
                idx = end_pos;
                continue;
            }
            if (*label == "seed" || *label == "secret") && following.starts_with('_') {
                idx = end_pos;
                continue;
            }
            return true;
        }
    }
    false
}

fn has_adjacent_credential_label(text: &str, start: usize, end: usize, window: usize) -> bool {
    let mut ws = start.saturating_sub(window);
    while ws > 0 && !text.is_char_boundary(ws) {
        ws -= 1;
    }
    let before_raw = &text[ws..start];
    let before_stripped = strip_placeholders_for_label_search(before_raw);
    if contains_credential_label_text(&before_stripped) {
        return true;
    }

    let mut we = (end + window).min(text.len());
    while we < text.len() && !text.is_char_boundary(we) {
        we += 1;
    }
    let after_raw = &text[end..we];
    let after_stripped = strip_placeholders_for_label_search(after_raw);
    let after_trimmed = after_stripped.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
    let after_lower = after_trimmed.to_ascii_lowercase();
    let rest = if after_lower.starts_with("is ") || after_lower.starts_with("was ") {
        after_lower[3..].trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
    } else {
        &after_lower
    };
    let rest = if rest.starts_with("my ")
        || rest.starts_with("the ")
        || rest.starts_with("our ")
        || rest.starts_with("his ")
        || rest.starts_with("her ")
        || rest.starts_with("their ")
    {
        rest.split_once(' ')
            .map(|x| x.1.trim_start_matches(|c: char| !c.is_ascii_alphanumeric()))
            .unwrap_or("")
    } else {
        rest
    };
    let rest = if rest.starts_with("delegate ")
        || rest.starts_with("delegate_")
        || rest.starts_with("delegate-")
    {
        rest[9..].trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
    } else {
        rest
    };

    contains_credential_label_text(rest)
}

fn is_inside_placeholder(text: &str, start: usize) -> bool {
    let window_start = start.saturating_sub(12);
    let before_bytes = &text.as_bytes()[window_start..start];
    before_bytes
        .windows(b"[redacted:".len())
        .any(|w| w == b"[redacted:")
}

fn looks_like_opaque_token(token: &str) -> bool {
    if token.len() < 20 {
        return false;
    }
    let has_lower = token.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = token.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = token.chars().any(|c| c.is_ascii_digit());
    let has_symbol = token.chars().any(|c| matches!(c, '+' | '/' | '='));
    (has_lower && has_upper) || has_digit || has_symbol
}

fn looks_like_secret_blob(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    if body.len() < 64 {
        return false;
    }
    let has_lower = body.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = body.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = body.chars().any(|c| c.is_ascii_digit());
    if !has_lower || !has_upper || !has_digit {
        return false;
    }
    if body.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    true
}

fn redact_labelled_and_high_entropy(
    input: &str,
    kinds: &mut Vec<RedactionKind>,
    count: &mut usize,
) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut i = 0;

    while i < chars.len() {
        let (byte_offset, _) = chars[i];
        let slice = &input[byte_offset..];
        let at_word_boundary = byte_offset == 0 || !is_word_byte(input.as_bytes()[byte_offset - 1]);

        if at_word_boundary {
            let bytes = slice.as_bytes();

            // 1. High entropy candidate: [A-Za-z0-9+/_-]{64,}={0,2}
            let candidate_len = bytes
                .iter()
                .take_while(|&&b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-')
                })
                .count();
            let mut total_candidate = candidate_len;
            if candidate_len >= 64 {
                if candidate_len < bytes.len() && bytes[candidate_len] == b'=' {
                    total_candidate += 1;
                    if total_candidate < bytes.len() && bytes[total_candidate] == b'=' {
                        total_candidate += 1;
                    }
                }
                let token = &slice[..total_candidate];
                let right_ok =
                    total_candidate == bytes.len() || !is_word_byte(bytes[total_candidate]);
                if right_ok && looks_like_secret_blob(token) {
                    out.push_str(placeholder_str(RedactionKind::HighEntropySecret));
                    if !kinds.contains(&RedactionKind::HighEntropySecret) {
                        kinds.push(RedactionKind::HighEntropySecret);
                    }
                    *count += 1;
                    while i < chars.len() && chars[i].0 < byte_offset + total_candidate {
                        i += 1;
                    }
                    continue;
                }
            }

            // 2. HEX_RUN: (?:0x)?[0-9a-fA-F]{32,}\b
            let has_0x = bytes.starts_with(b"0x");
            let hex_start = if has_0x { 2 } else { 0 };
            let hex_len = bytes[hex_start..]
                .iter()
                .take_while(|&&b| b.is_ascii_hexdigit())
                .count();
            if hex_len >= 32 {
                let total_hex = hex_start + hex_len;
                let right_ok = total_hex == bytes.len() || !is_word_byte(bytes[total_hex]);
                if right_ok
                    && has_adjacent_credential_label(
                        input,
                        byte_offset,
                        byte_offset + total_hex,
                        HEX_LABEL_WINDOW,
                    )
                {
                    out.push_str(placeholder_str(RedactionKind::LabelledKeyMaterial));
                    if !kinds.contains(&RedactionKind::LabelledKeyMaterial) {
                        kinds.push(RedactionKind::LabelledKeyMaterial);
                    }
                    *count += 1;
                    while i < chars.len() && chars[i].0 < byte_offset + total_hex {
                        i += 1;
                    }
                    continue;
                }
            }

            // 3. OPAQUE_RUN: [A-Za-z0-9+/_=-]{20,}
            let opaque_len = bytes
                .iter()
                .take_while(|&&b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'=' | b'-')
                })
                .count();
            if opaque_len >= 20 {
                let token = &slice[..opaque_len];
                let right_ok = opaque_len == bytes.len() || !is_word_byte(bytes[opaque_len]);
                if right_ok
                    && !is_inside_placeholder(input, byte_offset)
                    && looks_like_opaque_token(token)
                    && has_adjacent_credential_label(
                        input,
                        byte_offset,
                        byte_offset + opaque_len,
                        HEX_LABEL_WINDOW,
                    )
                {
                    out.push_str(placeholder_str(RedactionKind::LabelledKeyMaterial));
                    if !kinds.contains(&RedactionKind::LabelledKeyMaterial) {
                        kinds.push(RedactionKind::LabelledKeyMaterial);
                    }
                    *count += 1;
                    while i < chars.len() && chars[i].0 < byte_offset + opaque_len {
                        i += 1;
                    }
                    continue;
                }
            }
        }

        out.push(chars[i].1);
        i += 1;
    }
    out
}

pub fn sanitize_fact(input: &str) -> SanitizedText {
    if is_no_save_directive(input) {
        return SanitizedText {
            text: String::new(),
            changed: true,
            kinds: Vec::new(),
            count: 0,
            refusal: Some(RefusalReason::NoSaveDirective),
        };
    }

    if is_pasted_content(input) {
        return SanitizedText {
            text: String::new(),
            changed: true,
            kinds: Vec::new(),
            count: 0,
            refusal: Some(RefusalReason::PastedContent),
        };
    }

    let mut kinds = Vec::new();
    let mut count = 0;

    let text = redact_pem(input, &mut kinds, &mut count);
    let text = redact_url_credentials(&text, &mut kinds, &mut count);
    let text = redact_auth_and_cookie_headers(&text, &mut kinds, &mut count);
    let text = redact_credential_assignments(&text, &mut kinds, &mut count);
    let text = redact_vendor_keys(&text, &mut kinds, &mut count);
    let text = redact_jwt(&text, &mut kinds, &mut count);
    let text = redact_seed_phrase(&text, &mut kinds, &mut count);
    let text = redact_labelled_and_high_entropy(&text, &mut kinds, &mut count);

    if count == 0 {
        return SanitizedText {
            text: input.to_string(),
            changed: false,
            kinds: Vec::new(),
            count: 0,
            refusal: None,
        };
    }

    // Collapse whitespace
    let mut collapsed = String::with_capacity(text.len());
    let mut prev_space = false;
    for ch in text.trim().chars() {
        if ch == ' ' || ch == '\t' {
            if !prev_space {
                collapsed.push(' ');
                prev_space = true;
            }
        } else {
            collapsed.push(ch);
            prev_space = false;
        }
    }

    if !has_salvageable_content(&collapsed) {
        return SanitizedText {
            text: String::new(),
            changed: true,
            kinds,
            count,
            refusal: Some(RefusalReason::CredentialOnly),
        };
    }

    SanitizedText {
        text: collapsed,
        changed: true,
        kinds,
        count,
        refusal: None,
    }
}

fn has_credential_label_in_context(context: &str, start: usize, end: usize) -> bool {
    let before = &context[..start];
    let before_stripped = strip_placeholders_for_label_search(before);
    if contains_credential_label_text(&before_stripped) {
        return true;
    }
    let after = &context[end..];
    let after_stripped = strip_placeholders_for_label_search(after);
    contains_credential_label_text(&after_stripped)
}

fn words_around(text: &str, token: &str) -> usize {
    let stripped = strip_placeholders_for_label_search(text);
    let rest = stripped.replacen(token, " ", 1);
    let mut count = 0;
    let mut cur = 0;
    for ch in rest.chars() {
        if ch.is_alphanumeric() {
            cur += 1;
        } else {
            if cur >= 2 {
                count += 1;
            }
            cur = 0;
        }
    }
    if cur >= 2 {
        count += 1;
    }
    count
}

pub fn sanitize_fact_batch(inputs: &[String], bare_scope: &str) -> Vec<SanitizedText> {
    let per_entry: Vec<SanitizedText> = inputs.iter().map(|s| sanitize_fact(s)).collect();
    if per_entry.iter().all(|r| r.refusal.is_some()) {
        return per_entry;
    }

    let views: Vec<String> = per_entry
        .iter()
        .enumerate()
        .map(|(i, r)| {
            if r.refusal.is_some() {
                inputs[i].clone()
            } else {
                r.text.clone()
            }
        })
        .collect();
    let whole_batch = views.join("\n");

    if !contains_credential_label_text(&strip_placeholders_for_label_search(&whole_batch)) {
        return per_entry;
    }

    per_entry
        .into_iter()
        .enumerate()
        .map(|(i, result)| {
            if result.refusal.is_some() {
                return result;
            }
            let own = &views[i];
            let prev = if i > 0 { &views[i - 1] } else { "" };
            let next = if i + 1 < views.len() {
                &views[i + 1]
            } else {
                ""
            };
            let neighbourhood = format!("{prev}\n{own}\n{next}");
            let own_start = prev.len() + 1;

            let mut kinds = result.kinds.clone();
            let mut count = result.count;
            let mut hit_any = false;

            let mut out = String::with_capacity(own.len());
            let chars: Vec<(usize, char)> = own.char_indices().collect();
            let mut ci = 0;

            while ci < chars.len() {
                let (byte_offset, _) = chars[ci];
                let slice = &own[byte_offset..];
                let at_word_boundary =
                    byte_offset == 0 || !is_word_byte(own.as_bytes()[byte_offset - 1]);

                if at_word_boundary {
                    let bytes = slice.as_bytes();
                    let opaque_len = bytes
                        .iter()
                        .take_while(|&&b| {
                            b.is_ascii_alphanumeric()
                                || matches!(b, b'+' | b'/' | b'_' | b'=' | b'-')
                        })
                        .count();
                    if opaque_len >= 20 {
                        let token = &slice[..opaque_len];
                        let right_ok =
                            opaque_len == bytes.len() || !is_word_byte(bytes[opaque_len]);
                        if right_ok
                            && !is_inside_placeholder(own, byte_offset)
                            && looks_like_opaque_token(token)
                        {
                            let bare = bare_scope == "batch" && words_around(own, token) < 3;
                            let (context, start) = if bare {
                                let offset_in_batch =
                                    views[..i].iter().map(|v| v.len() + 1).sum::<usize>()
                                        + byte_offset;
                                (whole_batch.as_str(), offset_in_batch)
                            } else {
                                (neighbourhood.as_str(), own_start + byte_offset)
                            };

                            if has_credential_label_in_context(context, start, start + opaque_len) {
                                out.push_str(placeholder_str(RedactionKind::LabelledKeyMaterial));
                                if !kinds.contains(&RedactionKind::LabelledKeyMaterial) {
                                    kinds.push(RedactionKind::LabelledKeyMaterial);
                                }
                                count += 1;
                                hit_any = true;
                                while ci < chars.len() && chars[ci].0 < byte_offset + opaque_len {
                                    ci += 1;
                                }
                                continue;
                            }
                        }
                    }
                }

                out.push(chars[ci].1);
                ci += 1;
            }

            if !hit_any {
                return result;
            }

            let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
            if !has_salvageable_content(&collapsed) {
                SanitizedText {
                    text: String::new(),
                    changed: true,
                    kinds,
                    count,
                    refusal: Some(RefusalReason::CredentialOnly),
                }
            } else {
                SanitizedText {
                    text: collapsed,
                    changed: true,
                    kinds,
                    count,
                    refusal: None,
                }
            }
        })
        .collect()
}

fn unwrap_transcript_fence(text: &str) -> String {
    let s = text.trim();
    if s.starts_with("```") && s.ends_with("```") && s.len() >= 6 {
        let first_newline = s.find('\n');
        if let Some(fnl) = first_newline {
            let tag = s[3..fnl].trim();
            if tag.is_empty() {
                let inner = &s[fnl + 1..s.len() - 3].trim_end();
                let lines: Vec<&str> = inner.lines().filter(|l| !l.trim().is_empty()).collect();
                if lines.len() >= 4 {
                    return inner.to_string();
                }
            }
        }
    }
    text.to_string()
}

struct PassageSegment {
    text: String,
    line: usize,
    blank: bool,
}

fn split_passage(text: &str) -> Vec<PassageSegment> {
    let lines: Vec<&str> = text.lines().collect();
    let mut segments = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim_start().starts_with("```") {
            let start = i;
            let mut block = vec![line];
            i += 1;
            while i < lines.len() {
                block.push(lines[i]);
                if lines[i].trim_start().starts_with("```") {
                    break;
                }
                i += 1;
            }
            segments.push(PassageSegment {
                text: block.join("\n"),
                line: start + 1,
                blank: false,
            });
            i += 1;
            continue;
        }
        if line.trim_start().starts_with('>') {
            let start = i;
            let mut block = vec![line];
            while i + 1 < lines.len() && lines[i + 1].trim_start().starts_with('>') {
                i += 1;
                block.push(lines[i]);
            }
            segments.push(PassageSegment {
                text: block.join("\n"),
                line: start + 1,
                blank: false,
            });
            i += 1;
            continue;
        }
        segments.push(PassageSegment {
            text: line.to_string(),
            line: i + 1,
            blank: line.trim().is_empty(),
        });
        i += 1;
    }
    segments
}

pub fn sanitize_passage(input: &str) -> SanitizedPassage {
    let unwrapped = unwrap_transcript_fence(input);
    let segments = split_passage(&unwrapped);
    let non_blank_texts: Vec<String> = segments
        .iter()
        .filter(|s| !s.blank)
        .map(|s| s.text.clone())
        .collect();
    let screened = sanitize_fact_batch(&non_blank_texts, "neighbours");

    let mut next = 0;
    let mut results = Vec::new();
    for s in &segments {
        if s.blank {
            results.push(SanitizedText {
                text: String::new(),
                changed: false,
                kinds: Vec::new(),
                count: 0,
                refusal: None,
            });
        } else {
            results.push(screened[next].clone());
            next += 1;
        }
    }

    let mut dropped: Vec<Option<RefusalReason>> = results
        .iter()
        .enumerate()
        .map(|(i, r)| if segments[i].blank { None } else { r.refusal })
        .collect();

    let directive: Vec<bool> = dropped
        .iter()
        .map(|d| *d == Some(RefusalReason::NoSaveDirective))
        .collect();
    for i in 0..segments.len() {
        if !directive[i] {
            continue;
        }
        for j in [i.saturating_sub(1), i + 1] {
            if j < segments.len() && !segments[j].blank && dropped[j].is_none() {
                dropped[j] = Some(RefusalReason::NoSaveDirective);
            }
        }
    }

    let mut kinds = Vec::new();
    let mut count = 0;
    let mut kept = Vec::new();
    let mut dropped_spans = Vec::new();
    let mut non_blank = 0;

    for i in 0..segments.len() {
        let seg = &segments[i];
        if seg.blank {
            kept.push(String::new());
            continue;
        }
        non_blank += 1;
        let res = &results[i];
        count += res.count;
        for k in &res.kinds {
            if !kinds.contains(k) {
                kinds.push(*k);
            }
        }
        if let Some(reason) = dropped[i] {
            dropped_spans.push(DroppedSpan {
                line: seg.line,
                reason,
            });
            continue;
        }
        kept.push(res.text.clone());
    }

    let joined = kept.join("\n");
    let collapsed = joined.trim().to_string();
    let changed = count > 0 || !dropped_spans.is_empty();

    if !has_salvageable_content(&collapsed) {
        let mut tally: std::collections::HashMap<RefusalReason, usize> =
            std::collections::HashMap::new();
        for sp in &dropped_spans {
            *tally.entry(sp.reason).or_default() += 1;
        }
        let top_reason = tally
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(r, _)| r)
            .unwrap_or(RefusalReason::CredentialOnly);
        return SanitizedPassage {
            text: String::new(),
            changed: true,
            kinds,
            count,
            refusal: Some(top_reason),
            dropped: dropped_spans,
            segments: non_blank,
        };
    }

    SanitizedPassage {
        text: collapsed,
        changed,
        kinds,
        count,
        refusal: None,
        dropped: dropped_spans,
        segments: non_blank,
    }
}

fn mcp_tools_list(oauth_scope: &str) -> Value {
    let all_tools = vec![
        json!({
            "name": "memwal_health",
            "description": "Quick connectivity check for Walrus Memory. Calls the relayer's lightweight health endpoint and returns its status and version.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "memwal_remember",
            "description": "Save a durable fact about the user or project to their Walrus Memory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "The full, detailed fact to save." },
                    "namespace": { "type": "string", "description": "Optional namespace bucket." },
                    "dedupe": { "type": "boolean", "description": "Optional near-duplicate precheck flag (cosine similarity >= 0.85)." }
                },
                "required": ["text"]
            }
        }),
        json!({
            "name": "memwal_remember_status",
            "description": "Check the status of a background memwal_remember job by job_id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "job_id": { "type": "string", "description": "Job ID returned by memwal_remember." },
                    "waitMs": { "type": "number", "description": "Optional poll wait budget in ms." }
                },
                "required": ["job_id"]
            }
        }),
        json!({
            "name": "memwal_remember_bulk",
            "description": "Save multiple durable facts in a single batch.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": { "text": { "type": "string" } },
                            "required": ["text"]
                        }
                    },
                    "namespace": { "type": "string" },
                    "_idempotency_key": { "type": "string", "description": "Optional logical-call idempotency key injected by the MCP bridge." }
                },
                "required": ["items"]
            }
        }),
        json!({
            "name": "memwal_recall",
            "description": "Search the user's Walrus Memory for relevant facts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Natural-language search query." },
                    "limit": { "type": "number", "description": "Max number of memories to return (1-100)." },
                    "namespace": { "type": "string", "description": "Optional namespace bucket." },
                    "maxDistance": { "type": "number", "description": "Optional cosine-distance cutoff." }
                },
                "required": ["query"]
            }
        }),
        json!({
            "name": "memwal_namespaces",
            "title": "List Memory Namespaces",
            "description": "List the namespaces that hold memories in this Walrus Memory account, with each namespace's memory count and storage used (metadata only, no decryption). Call this when memwal_recall or memwal_restore reports 0 memories in a namespace, or when connecting to an unfamiliar account so you can discover existing namespaces instead of guessing.",
            "annotations": {
                "readOnlyHint": true,
                "destructiveHint": false
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 100,
                        "description": "Max number of namespaces to return per page (1-500)."
                    },
                    "cursor": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Pagination cursor (`next_cursor` from a previous call)."
                    }
                }
            }
        }),
        json!({
            "name": "memwal_analyze",
            "description": "Extract durable facts from conversation text and save them to Walrus Memory.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "Conversation text to analyze." },
                    "namespace": { "type": "string", "description": "Optional namespace bucket." }
                },
                "required": ["text"]
            }
        }),
        json!({
            "name": "memwal_restore",
            "description": "Rebuild the vector search index for a namespace from on-chain Walrus blobs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "namespace": { "type": "string", "description": "Optional namespace bucket." },
                    "limit": { "type": "number", "description": "Max blobs to restore (1-100, default 10)." }
                }
            }
        }),
    ];

    let filtered: Vec<Value> = all_tools
        .into_iter()
        .filter(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| is_mcp_tool_permitted(name, oauth_scope))
        })
        .collect();

    json!({ "tools": filtered })
}

async fn execute_mcp_tool(
    state: &AppState,
    delegate_key_hex: &str,
    account_id: &str,
    default_namespace: &str,
    oauth_scope: &str,
    tool_name: &str,
    args: &Value,
) -> Value {
    if is_known_mcp_tool(tool_name) && !is_mcp_tool_permitted(tool_name, oauth_scope) {
        return json!({
            "isError": true,
            "content": [{
                "type": "text",
                "text": format!("Tool {tool_name} is not permitted for the current OAuth scope")
            }]
        });
    }
    match tool_name {
        "memwal_health" => {
            let url = format!("http://127.0.0.1:{}/health", state.config.port);
            match state.http_client.get(&url).send().await {
                Ok(resp) => {
                    let body = resp.json::<Value>().await.unwrap_or_else(|_| json!({}));
                    let status = body.get("status").and_then(Value::as_str).unwrap_or("ok");
                    let version = body
                        .get("version")
                        .and_then(Value::as_str)
                        .unwrap_or(env!("CARGO_PKG_VERSION"));
                    let write_ready = body
                        .get("write_ready")
                        .and_then(Value::as_bool)
                        .unwrap_or(true);
                    let text = format!(
                        "Walrus Memory is reachable. status={status} version={version} relayer=http://127.0.0.1:{} write_ready={write_ready}",
                        state.config.port
                    );
                    json!({
                        "content": [{ "type": "text", "text": text }]
                    })
                }
                Err(e) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("Health check failed: {e}") }]
                }),
            }
        }
        "memwal_remember" => {
            let raw_text = args
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if raw_text.is_empty() {
                return json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": "text is required and cannot be empty" }]
                });
            }

            let safe = sanitize_fact(raw_text);
            if let Some(refusal) = safe.refusal {
                return json!({
                    "content": [{ "type": "text", "text": refusal_notice(refusal) }]
                });
            }
            let notice = redaction_notice(&safe.kinds, safe.count);
            let text = safe.text.as_str();

            let namespace = args
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(default_namespace);

            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let idem_key = derived_remember_idempotency_key(text, namespace, now_ms);
            let mut payload = json!({
                "text": text,
                "namespace": namespace,
                "idempotency_key": idem_key,
            });
            if let Some(dedupe) = args.get("dedupe").and_then(Value::as_bool) {
                payload["dedupe"] = Value::Bool(dedupe);
            }
            match call_local_relayer(
                state,
                delegate_key_hex,
                account_id,
                Method::POST,
                "/api/remember",
                Some(&payload),
                &[],
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let job_status = body
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("running");
                    if let Some(blob_id) = body
                        .get("blob_id")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        let mut rendered = if job_status == "already_exists" {
                            format!(
                                "Already in Walrus Memory (skipped duplicate write). blob_id={blob_id} namespace={namespace}"
                            )
                        } else {
                            format!(
                                "Saved to Walrus Memory. blob_id={blob_id} namespace={namespace}"
                            )
                        };
                        if !notice.is_empty() {
                            rendered.push_str("\n\n");
                            rendered.push_str(&notice);
                        }
                        json!({
                            "content": [{
                                "type": "text",
                                "text": rendered
                            }]
                        })
                    } else {
                        let job_id = body
                            .get("job_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let mut rendered = format!(
                            "Accepted by Walrus Memory (write in progress). job_id={job_id} status={job_status} namespace={namespace}\nResolve with memwal_remember_status."
                        );
                        if !notice.is_empty() {
                            rendered.push_str("\n\n");
                            rendered.push_str(&notice);
                        }
                        json!({
                            "content": [{
                                "type": "text",
                                "text": rendered
                            }]
                        })
                    }
                }
                Ok((status, body)) => json!({
                    "isError": true,
                    "content": [{
                        "type": "text",
                        "text": format!("memwal_remember failed (HTTP {}): {}", status.as_u16(), body)
                    }]
                }),
                Err(e) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_remember error: {e}") }]
                }),
            }
        }
        "memwal_remember_status" => {
            let job_id = args
                .get("job_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if job_id.is_empty() {
                return json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": "job_id is required" }]
                });
            }
            let path = format!("/api/remember/{job_id}");
            match call_local_relayer(
                state,
                delegate_key_hex,
                account_id,
                Method::GET,
                &path,
                None,
                &[],
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let st = body
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("running");
                    let blob_id = body
                        .get("blob_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if st == "done" && !blob_id.is_empty() {
                        json!({
                            "content": [{
                                "type": "text",
                                "text": format!("Saved to Walrus Memory. job_id={job_id} status=done blob_id={blob_id}")
                            }]
                        })
                    } else if st == "failed" {
                        let err_msg = body
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown error");
                        json!({
                            "isError": true,
                            "content": [{
                                "type": "text",
                                "text": format!("Walrus Memory write failed. job_id={job_id} status=failed error={err_msg}")
                            }]
                        })
                    } else {
                        json!({
                            "content": [{
                                "type": "text",
                                "text": format!("Walrus Memory write in progress. job_id={job_id} status={st}")
                            }]
                        })
                    }
                }
                Ok((status, body)) => json!({
                    "isError": true,
                    "content": [{
                        "type": "text",
                        "text": format!("memwal_remember_status failed (HTTP {}): {}", status.as_u16(), body)
                    }]
                }),
                Err(e) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_remember_status error: {e}") }]
                }),
            }
        }
        "memwal_remember_bulk" => {
            let namespace = args
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(default_namespace);

            let raw_items = args
                .get("items")
                .or_else(|| args.get("facts"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            if raw_items.is_empty() {
                return json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": "items array is required and cannot be empty" }]
                });
            }

            let mut fact_strings: Vec<String> = Vec::with_capacity(raw_items.len());
            for item in &raw_items {
                if let Some(s) = item.as_str() {
                    fact_strings.push(s.to_string());
                } else if let Some(s) = item.get("text").and_then(Value::as_str) {
                    fact_strings.push(s.to_string());
                } else {
                    fact_strings.push(item.to_string());
                }
            }

            let screened = sanitize_fact_batch(&fact_strings, "batch");
            let mut kept = Vec::new();
            let mut dropped = Vec::new();
            for (idx, res) in screened.into_iter().enumerate() {
                if res.refusal.is_some() {
                    dropped.push((idx, res));
                } else {
                    kept.push((idx, res));
                }
            }

            let dropped_note = if !dropped.is_empty() {
                format!(
                    "\n\nNOT SAVED ({}): {}. Do not re-send those; restate any durable fact without the sensitive part instead.",
                    dropped.len(),
                    dropped
                        .iter()
                        .map(|(idx, res)| format!("#{}: {}", idx + 1, refusal_message(res.refusal.unwrap())))
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            } else {
                String::new()
            };

            if kept.is_empty() {
                return json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Nothing was saved to Walrus Memory: every fact in this batch was withheld.{dropped_note}")
                    }]
                });
            }

            let mut redacted_kinds = Vec::new();
            let mut redacted_count = 0;
            for (_, res) in &kept {
                redacted_count += res.count;
                for k in &res.kinds {
                    if !redacted_kinds.contains(k) {
                        redacted_kinds.push(*k);
                    }
                }
            }
            let red_note = redaction_notice(&redacted_kinds, redacted_count);
            let policy_note = match (red_note.is_empty(), dropped_note.is_empty()) {
                (true, true) => String::new(),
                (false, true) => red_note,
                (true, false) => dropped_note.trim().to_string(),
                (false, false) => format!("{}\n\n{}", red_note, dropped_note.trim()),
            };

            let safe_items: Vec<Value> = kept
                .into_iter()
                .map(|(_, res)| json!({ "text": res.text, "namespace": namespace }))
                .collect();

            let mut payload = json!({
                "items": safe_items,
                "namespace": namespace,
            });
            if let Some(idem_key) = args
                .get("_idempotency_key")
                .or_else(|| args.get("idempotency_key"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                payload["idempotency_key"] = Value::String(idem_key.to_owned());
            }
            match call_local_relayer(
                state,
                delegate_key_hex,
                account_id,
                Method::POST,
                "/api/remember/bulk",
                Some(&payload),
                &[],
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let mut rendered = body.to_string();
                    if !policy_note.is_empty() {
                        rendered.push_str("\n\n");
                        rendered.push_str(&policy_note);
                    }
                    json!({
                        "content": [{ "type": "text", "text": rendered }]
                    })
                }
                Ok((status, body)) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_remember_bulk failed (HTTP {}): {}", status.as_u16(), body) }]
                }),
                Err(e) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_remember_bulk error: {e}") }]
                }),
            }
        }
        "memwal_recall" => {
            let query = args
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if query.is_empty() {
                return json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": "query is required and cannot be empty" }]
                });
            }
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(10);
            let namespace = args
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(default_namespace);
            let max_distance = args.get("maxDistance").and_then(Value::as_f64);

            let payload = json!({
                "query": query,
                "limit": limit,
                "namespace": namespace,
            });
            match call_local_relayer(
                state,
                delegate_key_hex,
                account_id,
                Method::POST,
                "/api/recall",
                Some(&payload),
                &[],
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let empty_vec = Vec::new();
                    let results = body
                        .get("results")
                        .and_then(Value::as_array)
                        .unwrap_or(&empty_vec);
                    let dropped_count = body
                        .get("dropped_count")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let discovery = if results.is_empty() && dropped_count == 0 {
                        try_list_namespaces(
                            state,
                            delegate_key_hex,
                            account_id,
                            default_namespace,
                            Some(namespace),
                            50,
                            5,
                        )
                        .await
                    } else {
                        None
                    };
                    let rendered = format_recall_output_with_namespaces(
                        results,
                        max_distance,
                        dropped_count,
                        discovery.as_ref().map(|d| (namespace, d)),
                    );
                    json!({
                        "content": [{ "type": "text", "text": rendered }]
                    })
                }
                Ok((status, body)) => json!({
                    "isError": true,
                    "content": [{
                        "type": "text",
                        "text": format!("memwal_recall failed (HTTP {}): {}", status.as_u16(), body)
                    }]
                }),
                Err(e) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_recall error: {e}") }]
                }),
            }
        }
        "memwal_analyze" => {
            let text = args
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim();
            if text.is_empty() {
                return json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": "text is required and cannot be empty" }]
                });
            }
            let safe = sanitize_passage(text);
            if let Some(refusal) = safe.refusal {
                return json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": refusal_notice(refusal) }]
                });
            }
            let red_note = redaction_notice(&safe.kinds, safe.count);
            let drop_note = dropped_span_notice(&safe.dropped, safe.segments);
            let notice = match (red_note.is_empty(), drop_note.is_empty()) {
                (true, true) => String::new(),
                (false, true) => red_note,
                (true, false) => drop_note,
                (false, false) => format!("{red_note}\n\n{drop_note}"),
            };

            let namespace = args
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(default_namespace);
            let payload = json!({
                "text": safe.text,
                "namespace": namespace,
            });
            match call_local_relayer(
                state,
                delegate_key_hex,
                account_id,
                Method::POST,
                "/api/analyze",
                Some(&payload),
                &[],
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let mut rendered = body.to_string();
                    if !notice.is_empty() {
                        rendered.push_str("\n\n");
                        rendered.push_str(&notice);
                    }
                    json!({
                        "content": [{ "type": "text", "text": rendered }]
                    })
                }
                Ok((status, body)) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_analyze failed (HTTP {}): {}", status.as_u16(), body) }]
                }),
                Err(e) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_analyze error: {e}") }]
                }),
            }
        }
        "memwal_restore" => {
            let namespace = args
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(default_namespace);
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(10)
                .clamp(1, 100);
            let payload = json!({
                "namespace": namespace,
                "limit": limit,
            });
            match call_local_relayer(
                state,
                delegate_key_hex,
                account_id,
                Method::POST,
                "/api/restore",
                Some(&payload),
                &[],
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    let total = body.get("total").and_then(Value::as_u64).unwrap_or(0);
                    let restored = body.get("restored").and_then(Value::as_u64).unwrap_or(0);
                    let skipped = body.get("skipped").and_then(Value::as_u64).unwrap_or(0);
                    let failed = body.get("failed").and_then(Value::as_u64).unwrap_or(0);
                    let truncated = body
                        .get("truncated")
                        .or_else(|| body.get("has_more"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let is_empty =
                        !truncated && total == 0 && restored == 0 && skipped == 0 && failed == 0;
                    let discovery = if is_empty {
                        try_list_namespaces(
                            state,
                            delegate_key_hex,
                            account_id,
                            default_namespace,
                            Some(namespace),
                            50,
                            5,
                        )
                        .await
                    } else {
                        None
                    };
                    let rendered = format_restore_output_with_namespaces(
                        &body,
                        namespace,
                        discovery.as_ref().map(|d| d.namespaces.as_slice()),
                    );
                    json!({
                        "content": [{ "type": "text", "text": rendered }]
                    })
                }
                Ok((status, body)) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_restore failed (HTTP {}): {}", status.as_u16(), body) }]
                }),
                Err(e) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_restore error: {e}") }]
                }),
            }
        }
        "memwal_namespaces" => {
            let limit = if let Some(limit_val) = args.get("limit").filter(|v| !v.is_null()) {
                let parsed_num = limit_val
                    .as_i64()
                    .or_else(|| limit_val.as_u64().and_then(|u| i64::try_from(u).ok()));
                match parsed_num {
                    Some(n) if (1..=500).contains(&n) => n as u64,
                    _ => {
                        return json!({
                            "isError": true,
                            "content": [{
                                "type": "text",
                                "text": "limit must be an integer between 1 and 500"
                            }]
                        });
                    }
                }
            } else {
                100
            };

            let cursor = args
                .get("cursor")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty());

            match fetch_namespaces_page(
                state,
                delegate_key_hex,
                account_id,
                default_namespace,
                limit,
                cursor,
            )
            .await
            {
                Ok(page) => {
                    let rendered = format_namespaces_result(&page);
                    json!({
                        "content": [{ "type": "text", "text": rendered }]
                    })
                }
                Err(e) => json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": format!("memwal_namespaces error: {e}") }]
                }),
            }
        }
        unknown => json!({
            "isError": true,
            "content": [{
                "type": "text",
                "text": format!("{unknown} is not a tool this Walrus Memory server offers. Walrus storage is append-only.")
            }]
        }),
    }
}

async fn handle_jsonrpc_envelope(
    state: Option<&AppState>,
    delegate_key_hex: &str,
    account_id: &str,
    default_namespace: &str,
    oauth_scope: &str,
    envelope: &Value,
) -> Option<Value> {
    let id = envelope.get("id").cloned()?;
    if id.is_null() {
        return None;
    }
    let method = envelope
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = envelope.get("params").cloned().unwrap_or_else(|| json!({}));

    let result = match method {
        "initialize" => {
            let protocol_version = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2024-11-05");
            json!({
                "protocolVersion": protocol_version,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "memwal",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "instructions": "Walrus Memory is this user's persistent memory system, exposed through the memwal_* tools."
            })
        }
        "ping" => json!({}),
        "tools/list" => mcp_tools_list(oauth_scope),
        "tools/call" => {
            let Some(app_state) = state else {
                return Some(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32603,
                        "message": "Relayer state unavailable for tool execution"
                    }
                }));
            };
            let tool_name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            execute_mcp_tool(
                app_state,
                delegate_key_hex,
                account_id,
                default_namespace,
                oauth_scope,
                tool_name,
                &args,
            )
            .await
        }
        other => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Method not found: {other}")
                }
            }));
        }
    };

    Some(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    }))
}

pub async fn handle_sse_in_process(
    _state: Arc<AppState>,
    forwarded: req_headers::HeaderMap,
) -> Response {
    let slot_guard = match acquire_session_slot(&forwarded) {
        Ok(guard) => guard,
        Err(resp) => return *resp,
    };

    let (delegate_key_hex, account_id, default_namespace, oauth_scope) =
        match resolve_session_credentials(&forwarded) {
            Ok(creds) => creds,
            Err((status, msg)) => return mcp_rpc_error_response(status, msg),
        };

    let session_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = mpsc::unbounded_channel::<String>();

    let endpoint_event =
        format!("event: endpoint\ndata: /api/mcp/messages?sessionId={session_id}\n\n");
    let _ = tx.send(endpoint_event);

    let session = McpNativeSession {
        delegate_key_hex,
        account_id,
        default_namespace,
        oauth_scope,
        sse_tx: Some(tx.clone()),
    };

    if let Ok(mut guard) = MCP_SSE_SESSIONS.write() {
        guard.insert(session_id.clone(), session);
    }

    let cleanup_session_id = session_id.clone();
    tokio::spawn(async move {
        let _slot_guard = slot_guard;
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        // Skip the immediate initial tick so we only ping every 10s while watching `tx.closed()`.
        interval.tick().await;
        loop {
            tokio::select! {
                () = tx.closed() => break,
                _ = interval.tick() => {
                    if tx.send(": ping\n\n".to_owned()).is_err() {
                        break;
                    }
                }
            }
        }
        if let Ok(mut guard) = MCP_SSE_SESSIONS.write() {
            guard.remove(&cleanup_session_id);
        }
    });

    let stream = stream::unfold(rx, |mut rx| async move {
        let chunk = rx.recv().await?;
        Some((Ok::<Bytes, Infallible>(Bytes::from(chunk)), rx))
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache, no-transform")
        .header("connection", "keep-alive")
        .header("x-accel-buffering", "no")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub async fn handle_messages_in_process(
    state: Arc<AppState>,
    session_id: String,
    forwarded: req_headers::HeaderMap,
    body: Bytes,
) -> Response {
    let session = MCP_SSE_SESSIONS
        .read()
        .ok()
        .and_then(|guard| guard.get(&session_id).cloned());

    let Some(session) = session else {
        return mcp_rpc_error_response(StatusCode::NOT_FOUND, "Unknown or expired MCP session");
    };

    let (caller_key, caller_account, _, caller_scope) =
        match resolve_session_credentials(&forwarded) {
            Ok(creds) => creds,
            Err((status, msg)) => return mcp_rpc_error_response(status, msg),
        };

    if !session_matches_caller(&session, &caller_key, &caller_account, &caller_scope) {
        return mcp_rpc_error_response(
            StatusCode::FORBIDDEN,
            "sessionId does not match authenticated caller",
        );
    }

    if body.len() > MCP_MAX_REQUEST_BODY_BYTES {
        return mcp_rpc_error_response(StatusCode::PAYLOAD_TOO_LARGE, "MCP request body too large");
    }

    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return mcp_rpc_error_response(
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON-RPC body: {e}"),
            );
        }
    };

    tokio::spawn(async move {
        if let Some(arr) = parsed.as_array() {
            for item in arr {
                if let Some(resp) = handle_jsonrpc_envelope(
                    Some(&state),
                    &session.delegate_key_hex,
                    &session.account_id,
                    &session.default_namespace,
                    &session.oauth_scope,
                    item,
                )
                .await
                {
                    if let (Some(tx), Ok(serialized)) =
                        (&session.sse_tx, serde_json::to_string(&resp))
                    {
                        let _ = tx.send(format!("event: message\ndata: {serialized}\n\n"));
                    }
                }
            }
        } else if let Some(resp) = handle_jsonrpc_envelope(
            Some(&state),
            &session.delegate_key_hex,
            &session.account_id,
            &session.default_namespace,
            &session.oauth_scope,
            &parsed,
        )
        .await
        {
            if let (Some(tx), Ok(serialized)) = (&session.sse_tx, serde_json::to_string(&resp)) {
                let _ = tx.send(format!("event: message\ndata: {serialized}\n\n"));
            }
        }
    });

    (StatusCode::ACCEPTED, "Accepted").into_response()
}

pub async fn handle_streamable_in_process(
    state: Arc<AppState>,
    method: Method,
    forwarded: req_headers::HeaderMap,
    body: Bytes,
) -> Response {
    handle_streamable_core(Some(state), method, forwarded, body).await
}

async fn handle_streamable_core(
    state: Option<Arc<AppState>>,
    method: Method,
    forwarded: req_headers::HeaderMap,
    body: Bytes,
) -> Response {
    if !matches!(method, Method::GET | Method::POST | Method::DELETE) {
        return (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed").into_response();
    }

    ensure_streamable_reaper_started();
    let now = Instant::now();
    let _ = reap_idle_streamable_sessions_at(now);

    let (delegate_key_hex, account_id, default_namespace, oauth_scope) =
        match resolve_session_credentials(&forwarded) {
            Ok(creds) => creds,
            Err((status, msg)) => return mcp_rpc_error_response(status, msg),
        };

    if let Some(session_id) = extract_header_str(&forwarded, "mcp-session-id") {
        match method {
            Method::DELETE => {
                let outcome = match MCP_STREAMABLE_SESSIONS.write() {
                    Ok(mut guard) => match guard.get(&session_id) {
                        None => Err(mcp_rpc_error_response(
                            StatusCode::NOT_FOUND,
                            "Unknown or expired mcp-session-id",
                        )),
                        Some(existing)
                            if !session_matches_caller(
                                &existing.session,
                                &delegate_key_hex,
                                &account_id,
                                &oauth_scope,
                            ) =>
                        {
                            Err(mcp_rpc_error_response(
                                StatusCode::FORBIDDEN,
                                "mcp-session-id does not match authenticated caller",
                            ))
                        }
                        Some(_) => Ok(guard.remove(&session_id)),
                    },
                    Err(_) => {
                        return mcp_rpc_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "session store unavailable",
                        );
                    }
                };
                return match outcome {
                    Ok(_evicted) => (StatusCode::NO_CONTENT, ()).into_response(),
                    Err(resp) => resp,
                };
            }
            Method::GET => {
                let checked = match MCP_STREAMABLE_SESSIONS.write() {
                    Ok(mut guard) => match guard.get_mut(&session_id) {
                        None => Err(mcp_rpc_error_response(
                            StatusCode::NOT_FOUND,
                            "Unknown or expired mcp-session-id",
                        )),
                        Some(existing)
                            if !session_matches_caller(
                                &existing.session,
                                &delegate_key_hex,
                                &account_id,
                                &oauth_scope,
                            ) =>
                        {
                            Err(mcp_rpc_error_response(
                                StatusCode::FORBIDDEN,
                                "mcp-session-id does not match authenticated caller",
                            ))
                        }
                        Some(existing) => {
                            existing.last_active = now;
                            Ok(())
                        }
                    },
                    Err(_) => {
                        return mcp_rpc_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "session store unavailable",
                        );
                    }
                };
                if let Err(resp) = checked {
                    return resp;
                }

                let (tx, rx) = mpsc::unbounded_channel::<String>();
                let _ = tx.send(": keepalive\n\n".to_owned());
                let tracked_session_id = session_id.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(15));
                    interval.tick().await;
                    loop {
                        tokio::select! {
                            () = tx.closed() => break,
                            _ = interval.tick() => {
                                let still_present = MCP_STREAMABLE_SESSIONS
                                    .write()
                                    .ok()
                                    .and_then(|mut guard| {
                                        let entry = guard.get_mut(&tracked_session_id)?;
                                        entry.last_active = Instant::now();
                                        Some(())
                                    })
                                    .is_some();
                                if !still_present || tx.send(": ping\n\n".to_owned()).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });

                let stream = stream::unfold(rx, |mut rx| async move {
                    let chunk = rx.recv().await?;
                    Some((Ok::<Bytes, Infallible>(Bytes::from(chunk)), rx))
                });

                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/event-stream")
                    .header("cache-control", "no-cache, no-transform")
                    .header("connection", "keep-alive")
                    .header("x-accel-buffering", "no");
                if let Ok(hv) = HeaderValue::from_str(&session_id) {
                    builder = builder.header("mcp-session-id", hv);
                }
                return builder
                    .body(Body::from_stream(stream))
                    .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
            Method::POST => {
                if body.len() > MCP_MAX_REQUEST_BODY_BYTES {
                    return mcp_rpc_error_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "MCP request body too large",
                    );
                }
                let session = match MCP_STREAMABLE_SESSIONS.write() {
                    Ok(mut guard) => match guard.get_mut(&session_id) {
                        None => {
                            return mcp_rpc_error_response(
                                StatusCode::NOT_FOUND,
                                "Unknown or expired mcp-session-id",
                            );
                        }
                        Some(existing)
                            if !session_matches_caller(
                                &existing.session,
                                &delegate_key_hex,
                                &account_id,
                                &oauth_scope,
                            ) =>
                        {
                            return mcp_rpc_error_response(
                                StatusCode::FORBIDDEN,
                                "mcp-session-id does not match authenticated caller",
                            );
                        }
                        Some(existing) => {
                            existing.last_active = now;
                            existing.session.clone()
                        }
                    },
                    Err(_) => {
                        return mcp_rpc_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "session store unavailable",
                        );
                    }
                };
                return execute_streamable_post_body(
                    state.as_deref(),
                    &session_id,
                    &session,
                    &body,
                )
                .await;
            }
            _ => unreachable!(),
        }
    }

    if method != Method::POST {
        return mcp_rpc_error_response(
            StatusCode::BAD_REQUEST,
            "missing mcp-session-id: open a new session with an initial POST",
        );
    }

    if body.len() > MCP_MAX_REQUEST_BODY_BYTES {
        return mcp_rpc_error_response(StatusCode::PAYLOAD_TOO_LARGE, "MCP request body too large");
    }

    let slot_guard = match acquire_session_slot(&forwarded) {
        Ok(guard) => guard,
        Err(resp) => return *resp,
    };

    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return mcp_rpc_error_response(
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON-RPC body: {e}"),
            );
        }
    };
    if parsed.as_array().is_some_and(Vec::is_empty) {
        return mcp_rpc_error_response(
            StatusCode::BAD_REQUEST,
            "Empty JSON-RPC batch is not allowed",
        );
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let session = McpNativeSession {
        delegate_key_hex,
        account_id,
        default_namespace,
        oauth_scope,
        sse_tx: None,
    };
    if let Ok(mut guard) = MCP_STREAMABLE_SESSIONS.write() {
        guard.insert(
            session_id.clone(),
            McpStreamableSession {
                session: session.clone(),
                last_active: now,
                _slot_guard: slot_guard,
            },
        );
    }

    execute_streamable_parsed(state.as_deref(), &session_id, &session, &parsed).await
}

async fn execute_streamable_post_body(
    state: Option<&AppState>,
    session_id: &str,
    session: &McpNativeSession,
    body: &Bytes,
) -> Response {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return mcp_rpc_error_response(
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON-RPC body: {e}"),
            );
        }
    };
    if parsed.as_array().is_some_and(Vec::is_empty) {
        return mcp_rpc_error_response(
            StatusCode::BAD_REQUEST,
            "Empty JSON-RPC batch is not allowed",
        );
    }
    execute_streamable_parsed(state, session_id, session, &parsed).await
}

async fn execute_streamable_parsed(
    state: Option<&AppState>,
    session_id: &str,
    session: &McpNativeSession,
    parsed: &Value,
) -> Response {
    let response_value = if let Some(arr) = parsed.as_array() {
        let mut responses = Vec::with_capacity(arr.len());
        for item in arr {
            if let Some(resp) = handle_jsonrpc_envelope(
                state,
                &session.delegate_key_hex,
                &session.account_id,
                &session.default_namespace,
                &session.oauth_scope,
                item,
            )
            .await
            {
                responses.push(resp);
            }
        }
        if responses.is_empty() {
            None
        } else {
            Some(Value::Array(responses))
        }
    } else {
        handle_jsonrpc_envelope(
            state,
            &session.delegate_key_hex,
            &session.account_id,
            &session.default_namespace,
            &session.oauth_scope,
            parsed,
        )
        .await
    };

    if let Some(resp) = response_value {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Ok(hv) = HeaderValue::from_str(session_id) {
            headers.insert("mcp-session-id", hv);
        }
        (
            StatusCode::OK,
            headers,
            serde_json::to_vec(&resp).unwrap_or_default(),
        )
            .into_response()
    } else {
        let mut headers = HeaderMap::new();
        if let Ok(hv) = HeaderValue::from_str(session_id) {
            headers.insert("mcp-session-id", hv);
        }
        (StatusCode::ACCEPTED, headers, ()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_names_for_scope(scope: &str) -> Vec<String> {
        let list = mcp_tools_list(scope);
        let tools = list
            .get("tools")
            .and_then(Value::as_array)
            .expect("tools array must exist");
        tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect()
    }

    #[test]
    fn mcp_tools_list_fails_closed_when_oauth_scope_is_missing_or_blank() {
        assert!(tool_names_for_scope("").is_empty());
        assert!(tool_names_for_scope("   ").is_empty());
        assert!(tool_names_for_scope("unknown:scope").is_empty());
    }

    #[test]
    fn mcp_tools_list_exposes_only_read_tools_for_memwal_read_scope() {
        assert_eq!(
            tool_names_for_scope("memwal:read"),
            vec!["memwal_health", "memwal_recall", "memwal_namespaces"]
        );
        assert!(is_mcp_tool_permitted("memwal_health", "memwal:read"));
        assert!(is_mcp_tool_permitted("memwal_recall", "memwal:read"));
        assert!(is_mcp_tool_permitted("memwal_namespaces", "memwal:read"));
        for write_tool in [
            "memwal_remember",
            "memwal_remember_status",
            "memwal_remember_bulk",
            "memwal_analyze",
            "memwal_restore",
        ] {
            assert!(
                !is_mcp_tool_permitted(write_tool, "memwal:read"),
                "{write_tool} must be rejected under read-only OAuth scope"
            );
        }
    }

    #[test]
    fn mcp_tools_list_exposes_all_seven_walrus_memory_tools_for_full_scope() {
        let list = mcp_tools_list("memwal:read memwal:write");
        let tools = list
            .get("tools")
            .and_then(Value::as_array)
            .expect("tools array must exist");
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        assert_eq!(
            names,
            vec![
                "memwal_health",
                "memwal_remember",
                "memwal_remember_status",
                "memwal_remember_bulk",
                "memwal_recall",
                "memwal_namespaces",
                "memwal_analyze",
                "memwal_restore",
            ]
        );
        for tool in tools {
            assert_eq!(tool["inputSchema"]["type"], "object");
            assert!(tool
                .get("description")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()));
        }
    }

    #[test]
    fn edit_distance_and_is_close_namespace_match_detect_typos_and_case_prefix_matches() {
        assert_eq!(edit_distance("pcl301", "pcl302"), 1);
        assert_eq!(edit_distance("study-note", "study-notes"), 1);
        assert_eq!(edit_distance("PCL301", "pcl302"), 1);
        assert_eq!(edit_distance("café", "cafe"), 1);

        assert!(is_close_namespace_match("pcl301", "pcl302"));
        assert!(is_close_namespace_match("pcl3o2", "pcl302"));
        assert!(is_close_namespace_match("study", "study-notes"));
        assert!(is_close_namespace_match("PCL301", "pcl302"));
        assert!(is_close_namespace_match("  study-note  ", "study-notes"));

        assert!(!is_close_namespace_match(
            "pcl301",
            "completely-different-bucket"
        ));
        assert!(!is_close_namespace_match("pcl301", "pcl301"));
        assert!(!is_close_namespace_match("", "pcl301"));
        assert!(!is_close_namespace_match("pcl301", ""));
    }

    #[test]
    fn format_namespace_suggestion_hint_prioritizes_close_edit_distance_matches() {
        let namespaces = vec![
            NamespaceEntry {
                name: "work-projects".to_owned(),
                memory_count: 50,
                storage_used: Some(1024),
                updated_at: None,
            },
            NamespaceEntry {
                name: "study-notes".to_owned(),
                memory_count: 12,
                storage_used: Some(2400),
                updated_at: None,
            },
            NamespaceEntry {
                name: "default".to_owned(),
                memory_count: 3,
                storage_used: None,
                updated_at: None,
            },
        ];

        let hint = format_namespace_suggestion_hint("study-note", &namespaces, 5);
        assert!(hint.contains("Did you mean namespace \"study-notes\" (12 memories)?"));
        assert!(hint.contains(
            "Existing namespaces: \"study-notes\" (12), \"work-projects\" (50), \"default\" (3)."
        ));

        let empty_hint = format_namespace_suggestion_hint("study-note", &[], 5);
        assert!(empty_hint.is_empty());

        let multiple_close = vec![
            NamespaceEntry {
                name: "pcl302".to_owned(),
                memory_count: 10,
                storage_used: None,
                updated_at: None,
            },
            NamespaceEntry {
                name: "pcl303".to_owned(),
                memory_count: 5,
                storage_used: None,
                updated_at: None,
            },
        ];
        let multi_hint = format_namespace_suggestion_hint("pcl301", &multiple_close, 5);
        assert!(
            multi_hint.contains("Did you mean: \"pcl302\" (10 memories), \"pcl303\" (5 memories)?")
        );

        let many = (1..=7)
            .map(|i| NamespaceEntry {
                name: format!("ns-{i}"),
                memory_count: i,
                storage_used: None,
                updated_at: None,
            })
            .collect::<Vec<_>>();
        let truncated_hint = format_namespace_suggestion_hint("other", &many, 3);
        assert!(truncated_hint.contains(", +4 more."));
    }

    #[test]
    fn format_recall_output_with_namespaces_distinguishes_empty_and_populated_namespaces() {
        let namespaces = vec![NamespaceEntry {
            name: "pcl302".to_owned(),
            memory_count: 15,
            storage_used: Some(4096),
            updated_at: None,
        }];

        let discovery = DiscoveredNamespaces {
            namespaces: namespaces.clone(),
            has_more: false,
        };

        // 1. Empty/misspelled namespace with suggestion
        let empty_out =
            format_recall_output_with_namespaces(&[], None, 0, Some(("pcl301", &discovery)));
        assert!(empty_out.contains(
            "No matching memories found (namespace \"pcl301\" currently holds 0 memories)."
        ));
        assert!(empty_out.contains("Did you mean namespace \"pcl302\" (15 memories)?"));

        // 2. Populated namespace with 0 semantic hits
        let populated_out =
            format_recall_output_with_namespaces(&[], None, 0, Some(("pcl302", &discovery)));
        assert_eq!(
            populated_out,
            "No matching memories found in namespace \"pcl302\" (0 matches among 15 memories)."
        );

        // 3. Incomplete page where target was not seen
        let discovery_has_more = DiscoveredNamespaces {
            namespaces,
            has_more: true,
        };
        let incomplete_out = format_recall_output_with_namespaces(
            &[],
            None,
            0,
            Some(("other-ns", &discovery_has_more)),
        );
        assert_eq!(
            incomplete_out,
            "No matching memories found in namespace \"other-ns\"."
        );
    }

    #[test]
    fn format_restore_output_with_namespaces_reports_empty_namespace_and_suggestions() {
        let empty_restore = json!({
            "total": 0,
            "restored": 0,
            "skipped": 0,
            "failed": 0,
            "truncated": false
        });

        let namespaces = vec![NamespaceEntry {
            name: "study-notes".to_owned(),
            memory_count: 12,
            storage_used: Some(2400),
            updated_at: Some("2026-08-20T10:00:00Z".to_owned()),
        }];

        let out =
            format_restore_output_with_namespaces(&empty_restore, "study-note", Some(&namespaces));
        assert!(out.contains(
            "This restore query discovered 0 matching blobs in namespace \"study-note\"."
        ));
        assert!(out.contains("Did you mean namespace \"study-notes\" (12 memories)?"));
        assert!(out.contains("Existing namespaces: \"study-notes\" (12)."));

        let out_no_ns = format_restore_output_with_namespaces(&empty_restore, "study-note", None);
        assert!(out_no_ns.contains(
            "This restore query discovered 0 matching blobs in namespace \"study-note\"."
        ));
        assert!(!out_no_ns.contains("Did you mean"));
    }

    #[test]
    fn format_namespaces_result_lists_entries_and_handles_pagination_edge_cases() {
        let page = NamespacesPage {
            namespaces: vec![
                NamespaceEntry {
                    name: "pcl302".to_owned(),
                    memory_count: 15,
                    storage_used: Some(4096),
                    updated_at: Some("2026-08-20T10:00:00Z".to_owned()),
                },
                NamespaceEntry {
                    name: "default".to_owned(),
                    memory_count: 1,
                    storage_used: Some(256),
                    updated_at: Some("2026-08-18T09:30:00Z".to_owned()),
                },
            ],
            next_cursor: Some("cursor-2".to_owned()),
            has_more: true,
        };

        let rendered = format_namespaces_result(&page);
        assert!(rendered.starts_with("Namespaces (2+):"));
        assert!(
            rendered.contains("- \"pcl302\": 15 memories, storage_used=4096B, updated=2026-08-20")
        );
        assert!(rendered.contains("- \"default\": 1 memory, storage_used=256B, updated=2026-08-18"));
        assert!(rendered.contains("More namespaces available (next_cursor=\"cursor-2\")."));

        // Terminal page with a non-null watermark cursor (`has_more: false`) must NOT claim more pages.
        let terminal_with_watermark = NamespacesPage {
            namespaces: vec![NamespaceEntry {
                name: "default".to_owned(),
                memory_count: 1,
                storage_used: Some(256),
                updated_at: Some("2026-08-18T09:30:00Z".to_owned()),
            }],
            next_cursor: Some("2026-08-18T09:30:00Z|default".to_owned()),
            has_more: false,
        };
        let terminal_rendered = format_namespaces_result(&terminal_with_watermark);
        assert!(terminal_rendered.starts_with("Namespaces (1):"));
        assert!(!terminal_rendered.contains("Namespaces (1+):"));
        assert!(!terminal_rendered.contains("More namespaces available"));

        // Empty terminal page with a non-null watermark cursor (`has_more: false`) must report empty, not continuation.
        let empty_terminal_with_watermark = NamespacesPage {
            namespaces: vec![],
            next_cursor: Some("2026-08-18T09:30:00Z|default".to_owned()),
            has_more: false,
        };
        assert_eq!(
            format_namespaces_result(&empty_terminal_with_watermark),
            "No namespaces with stored memories found for this account."
        );

        // Final empty page
        let empty_page = NamespacesPage {
            namespaces: vec![],
            next_cursor: None,
            has_more: false,
        };
        assert_eq!(
            format_namespaces_result(&empty_page),
            "No namespaces with stored memories found for this account."
        );

        // Tombstone-only final page
        let tombstone_final = NamespacesPage {
            namespaces: vec![NamespaceEntry {
                name: "tombstone".to_owned(),
                memory_count: 0,
                storage_used: None,
                updated_at: None,
            }],
            next_cursor: None,
            has_more: false,
        };
        assert_eq!(
            format_namespaces_result(&tombstone_final),
            "No namespaces with stored memories found for this account."
        );

        // Tombstone-only non-final page preserving next_cursor
        let tombstone_non_final = NamespacesPage {
            namespaces: vec![NamespaceEntry {
                name: "tombstone".to_owned(),
                memory_count: 0,
                storage_used: None,
                updated_at: None,
            }],
            next_cursor: Some("cursor-next".to_owned()),
            has_more: true,
        };
        let tombstone_rendered = format_namespaces_result(&tombstone_non_final);
        assert!(tombstone_rendered.contains("No non-empty namespaces found on this page."));
        assert!(tombstone_rendered.contains("next_cursor=\"cursor-next\""));
        assert!(tombstone_rendered.contains(
            "Call memwal_namespaces with cursor=\"cursor-next\" to inspect the next page."
        ));
        assert!(!tombstone_rendered
            .contains("No namespaces with stored memories found for this account."));
    }

    #[test]
    fn parse_namespaces_page_json_parses_valid_payload() {
        let payload = json!({
            "namespaces": [
                {
                    "name": "project-x",
                    "memory_count": 42,
                    "storage_used": 8192,
                    "updated_at": "2026-09-01T12:00:00Z"
                }
            ],
            "next_cursor": "cursor-abc",
            "has_more": true
        });
        let parsed = parse_namespaces_page_json(&payload).expect("should parse");
        assert_eq!(parsed.namespaces.len(), 1);
        assert_eq!(parsed.namespaces[0].name, "project-x");
        assert_eq!(parsed.namespaces[0].memory_count, 42);
        assert_eq!(parsed.namespaces[0].storage_used, Some(8192));
        assert_eq!(
            parsed.namespaces[0].updated_at.as_deref(),
            Some("2026-09-01T12:00:00Z")
        );
        assert_eq!(parsed.next_cursor.as_deref(), Some("cursor-abc"));
        assert!(parsed.has_more);
    }

    #[test]
    fn extract_header_str_trims_and_ignores_blank_values() {
        let mut headers = req_headers::HeaderMap::new();
        headers.insert(
            "x-memwal-namespace",
            req_headers::HeaderValue::from_static("  work-ns  "),
        );
        headers.insert("x-empty", req_headers::HeaderValue::from_static("   "));

        assert_eq!(
            extract_header_str(&headers, "x-memwal-namespace").as_deref(),
            Some("work-ns")
        );
        assert_eq!(extract_header_str(&headers, "x-empty"), None);
        assert_eq!(extract_header_str(&headers, "x-missing"), None);
    }

    #[test]
    fn mcp_native_session_debug_redacts_delegate_key() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let session = McpNativeSession {
            delegate_key_hex: "deadbeef0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
                .to_owned(),
            account_id: "0xabc".to_owned(),
            default_namespace: "default".to_owned(),
            oauth_scope: "memwal:read memwal:write".to_owned(),
            sse_tx: Some(tx),
        };
        let dbg = format!("{session:?}");
        assert!(
            !dbg.contains("deadbeef"),
            "Debug output must redact delegate_key_hex: {dbg}"
        );
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn public_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<McpNativeSession>();
    }

    #[test]
    fn derived_remember_idempotency_key_uses_30_minute_buckets_and_r1_prefix() {
        let base_ms: u64 = 1_800_000 * 1_000;
        let k1 = derived_remember_idempotency_key("Fact A", "default", base_ms);
        let k2 = derived_remember_idempotency_key("Fact A", "default", base_ms + 60_000);
        let k_next_bucket = derived_remember_idempotency_key(
            "Fact A",
            "default",
            base_ms + REMEMBER_RETRY_BUCKET_MS,
        );
        let k_other_ns = derived_remember_idempotency_key("Fact A", "work", base_ms);

        assert!(k1.starts_with("r1-"));
        assert_eq!(k1.len(), 3 + 64);
        assert_eq!(
            k1, k2,
            "retries within the same 30-minute window must share key"
        );
        assert_ne!(
            k1, k_next_bucket,
            "re-saves in a later 30-minute window must get a fresh key"
        );
        assert_ne!(k1, k_other_ns, "different namespaces must not collide");
    }

    #[test]
    fn format_recall_output_includes_written_date_collapses_duplicates_and_reports_dropped() {
        let results = vec![
            json!({
                "text": "User prefers dark mode",
                "distance": 0.12,
                "created_at": "2026-04-19T10:20:30Z",
                "blob_id": "blob-a"
            }),
            json!({
                "text": "  user   PREFERS dark mode ",
                "distance": 0.15,
                "created_at": "2026-04-18T08:00:00Z",
                "blob_id": "blob-b"
            }),
            json!({
                "text": "Uses Rust 2021 edition",
                "distance": 0.30
            }),
        ];

        // Strict `dist < cutoff` drops the 0.30 item when max_distance = Some(0.30).
        let rendered = format_recall_output(&results, Some(0.30), 2);
        assert_eq!(
            rendered,
            "1. [score=0.880 distance=0.120] [written=2026-04-19] User prefers dark mode\n(1 duplicate copy of #1 collapsed — #1 is stored across 2 blobs; the same fact is stored more than once.)\n(2 additional matches could not be decrypted and were omitted.)"
        );

        let multi_dup = vec![
            json!({ "text": "Fact one", "distance": 0.10, "blob_id": "b1" }),
            json!({ "text": "Fact two", "distance": 0.11, "blob_id": "b2" }),
            json!({ "text": "Fact three", "distance": 0.12 }),
            json!({ "text": "fact ONE", "distance": 0.13, "blob_id": "b3" }),
            json!({ "text": "fact THREE", "distance": 0.14 }),
            json!({ "text": "fact three ", "distance": 0.15 }),
        ];
        assert_eq!(
            format_recall_output(&multi_dup, None, 0),
            "1. [score=0.900 distance=0.100] Fact one\n2. [score=0.890 distance=0.110] Fact two\n3. [score=0.880 distance=0.120] Fact three\n(3 duplicate copies collapsed: #1 (1 duplicate, 2 blobs), #3 (2 duplicates, 3 copies); the same fact is stored more than once.)"
        );

        let all_filtered = format_recall_output(&results, Some(0.05), 0);
        assert_eq!(
            all_filtered,
            "All matching memories were outside maxDistance. Increase maxDistance or omit it to inspect weaker matches."
        );

        let all_filtered_with_dropped = format_recall_output(&results, Some(0.05), 1);
        assert_eq!(
            all_filtered_with_dropped,
            "All matching memories were outside maxDistance. Increase maxDistance or omit it to inspect weaker matches. (1 further match was never checked against the cutoff: they failed to download or decrypt.)"
        );

        let all_dropped = format_recall_output(&[], None, 3);
        assert_eq!(
            all_dropped,
            "No matching memories could be returned (3 match(es) failed to decrypt)."
        );
    }

    #[test]
    fn format_restore_output_reads_truncated_field_and_renders_cursor() {
        let page_truncated = json!({
            "total": 10,
            "restored": 7,
            "skipped": 3,
            "failed": 0,
            "truncated": true,
            "next_cursor": "cursor-xyz"
        });
        assert_eq!(
            format_restore_output(&page_truncated, "default"),
            "Restore page finished. namespace=default total=10 restored=7 skipped=3 failed=0 truncated=true\nMore blobs remain on-chain (next_cursor=cursor-xyz). Run memwal_restore again to continue."
        );
    }

    #[test]
    fn secret_redaction_sanitizes_credentials_and_formats_notices() {
        // 1. Connection string
        let out = sanitize_fact("I prefer dark mode, and the staging db is postgres://admin:hunter2@db.internal:5432/app");
        assert!(out.refusal.is_none());
        assert!(!out.text.contains("hunter2"));
        assert!(out
            .text
            .contains("postgres://[redacted:url-credentials]@db.internal:5432/app"));
        assert!(out.kinds.contains(&RedactionKind::UrlCredentials));

        // 2. Vendor keys
        let out = sanitize_fact("My deploy notes: the CI runner uses sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789 for pushes");
        assert!(!out
            .text
            .contains("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(out.text.contains("[redacted:vendor-api-key]"));

        // 3. PEM
        let pem = "Deploy key for the box:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Vk9mJ0ZwQ3\nabcdefghijklmnopqrstuvwxyz0123456789\n-----END RSA PRIVATE KEY-----\nIt lives in 1Password.";
        let out = sanitize_fact(pem);
        assert!(!out.text.contains("BEGIN RSA PRIVATE KEY"));
        assert!(out.text.contains("[redacted:private-key-block]"));

        // 4. JWT
        let jwt = "Our session tokens look like eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk and expire hourly";
        let out = sanitize_fact(jwt);
        assert!(out.kinds.contains(&RedactionKind::Jwt));
        assert!(out.text.contains("[redacted:jwt]"));

        // 5. Credential assignments
        let out =
            sanitize_fact("My local override file has password=hunter2 and I never commit it");
        assert!(!out.text.contains("hunter2"));
        assert!(out
            .text
            .contains("password=[redacted:credential-assignment]"));

        // 6. Auth header
        let out =
            sanitize_fact("To call the API: Authorization: Bearer abc123xyz789: then GET /v1/me");
        assert!(!out.text.contains("abc123xyz789"));
        assert!(out
            .text
            .contains("Authorization: Bearer [redacted:auth-header]"));

        // 7. Seed phrase
        let words =
            "abandon ability able about above absent absorb abstract absurd abuse access accident";
        let out = sanitize_fact(&format!(
            "My wallet recovery phrase is {words} and the wallet is on Sui mainnet"
        ));
        assert!(!out.text.contains(words));
        assert!(out.kinds.contains(&RedactionKind::SeedPhrase));

        // 8. Delegate private key
        let seed = "4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b";
        let out = sanitize_fact(&format!(
            "Notes from setup: delegatePrivateKey {seed} was written on this laptop"
        ));
        assert!(!out.text.contains(seed));
        assert!(out.kinds.contains(&RedactionKind::LabelledKeyMaterial));

        // 9. Unlabelled hex run preserved
        let fact = format!("The release digest is {seed} and I verified it");
        let out = sanitize_fact(&fact);
        assert_eq!(out.text, fact);
        assert!(!out.changed);

        // 10. Clean preferences
        let fact = "I always use pnpm, and TypeScript strict mode on every project.";
        let out = sanitize_fact(fact);
        assert_eq!(out.text, fact);
        assert!(!out.changed);

        // 11. Refusals: do not save
        let out = sanitize_fact("My bank PIN is 4821: don't save this.");
        assert_eq!(out.refusal, Some(RefusalReason::NoSaveDirective));
        assert_eq!(out.text, "");

        // 12. Refusals: bare secret
        let out = sanitize_fact("sk-abcdefghijklmnopqrstuvwxyz0123");
        assert_eq!(out.refusal, Some(RefusalReason::CredentialOnly));
        assert_eq!(out.text, "");
    }

    #[test]
    fn format_restore_output_renders_summary_cursor_and_errors() {
        let ok_page = json!({
            "total": 10,
            "restored": 7,
            "skipped": 3,
            "failed": 0,
            "has_more": true,
            "next_cursor": "cursor-abc"
        });
        assert_eq!(
            format_restore_output(&ok_page, "default"),
            "Restore page finished. namespace=default total=10 restored=7 skipped=3 failed=0 truncated=true\nMore blobs remain on-chain (next_cursor=cursor-abc). Run memwal_restore again to continue."
        );

        let partial = json!({
            "total": 4,
            "restored": 3,
            "skipped": 0,
            "failed": 1,
            "has_more": false,
            "errors": [
                { "blob_id": "b1", "object_id": "0x1", "error": "decrypt failed" }
            ]
        });
        assert_eq!(
            format_restore_output(&partial, "work"),
            "Restore partially complete. namespace=work total=4 restored=3 skipped=0 failed=1 truncated=false\nErrors:\n  - blob_id=b1 object_id=0x1: decrypt failed"
        );
    }

    #[test]
    fn sanitize_fact_handles_multibyte_unicode_without_panicking() {
        let emoji_repeated = "😀".repeat(8);
        let res = sanitize_fact(&emoji_repeated);
        assert_eq!(res.text, emoji_repeated);

        let mixed = format!("User prefers emoji {} in messages", "🔥".repeat(12));
        let res_mixed = sanitize_fact(&mixed);
        assert_eq!(res_mixed.text, mixed);

        let embedded_key = format!("Here is key suiprivkey1{} for testing", "1".repeat(32));
        let res_key = sanitize_fact(&embedded_key);
        assert!(res_key.text.contains("[redacted:vendor-api-key]"));
        assert!(!res_key.text.contains("suiprivkey1"));
    }

    #[test]
    fn sanitize_fact_performance_on_long_clean_text() {
        let paragraph =
            "The quick brown fox jumps over the lazy dog and enjoys writing durable memory facts. ";
        let long_input = paragraph.repeat(1500); // ~129 KiB
        let start = std::time::Instant::now();
        let res = sanitize_fact(&long_input);
        let elapsed = start.elapsed();
        assert_eq!(res.text, long_input);
        assert_eq!(res.count, 0);
        assert!(
            elapsed.as_millis() < 500,
            "128 KiB clean text sanitization took too long: {} ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn session_rate_limiter_enforces_active_burst_and_global_caps() {
        let mut limiter = McpSessionRateLimiter::new(SessionLimitConfig {
            max_total_sessions: 3,
            max_sessions_per_ip: 2,
            max_new_sessions_per_ip_per_min: 3,
        });
        let t0 = Instant::now();

        assert_eq!(limiter.acquire("198.51.100.1", t0), Ok(()));
        assert_eq!(limiter.acquire("198.51.100.1", t0), Ok(()));
        assert_eq!(
            limiter.acquire("198.51.100.1", t0),
            Err(SessionDenyReason::IpActive)
        );

        assert_eq!(limiter.acquire("198.51.100.2", t0), Ok(()));
        assert_eq!(
            limiter.acquire("198.51.100.3", t0),
            Err(SessionDenyReason::Global)
        );

        limiter.release("198.51.100.1");
        assert_eq!(
            limiter.acquire("198.51.100.1", t0 + Duration::from_secs(10)),
            Ok(())
        );
        limiter.release("198.51.100.1");

        match limiter.acquire("198.51.100.1", t0 + Duration::from_secs(20)) {
            Err(SessionDenyReason::IpBurst { retry_after_secs }) => {
                assert!((1..=60).contains(&retry_after_secs));
            }
            other => panic!("expected IpBurst, got {other:?}"),
        }

        assert_eq!(
            limiter.acquire("198.51.100.1", t0 + Duration::from_secs(61)),
            Ok(())
        );
    }

    #[test]
    fn session_rate_limiter_expires_inactive_per_ip_entries_after_burst_window() {
        let mut limiter = McpSessionRateLimiter::new(SessionLimitConfig {
            max_total_sessions: 20_000,
            max_sessions_per_ip: 16,
            max_new_sessions_per_ip_per_min: 30,
        });
        let t0 = Instant::now();

        // 10,000 distinct sequential IPs acquire and release a session at t0.
        for i in 0..10_000 {
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            assert_eq!(limiter.acquire(&ip, t0), Ok(()));
            if i % 2 == 0 {
                limiter.release(&ip);
            } else {
                limiter.release_at(&ip, t0);
            }
        }

        assert_eq!(limiter.total_active, 0);
        assert_eq!(limiter.per_ip.len(), 10_000);

        // Within the 60s burst window, entries must be preserved to prevent burst abuse.
        let mid = t0 + Duration::from_secs(30);
        let expired_mid = limiter.expire_inactive(mid);
        assert_eq!(expired_mid, 0);
        assert_eq!(limiter.per_ip.len(), 10_000);

        // After the 60s burst window, all inactive entries must expire cleanly.
        let after = t0 + Duration::from_secs(61);
        let expired_after = limiter.prune_inactive(after);
        assert_eq!(expired_after, 10_000);
        assert_eq!(limiter.per_ip.len(), 0);
        assert_eq!(limiter.total_active, 0);

        // Verify periodic expiry also triggers automatically during subsequent acquire.
        for i in 0..1_000 {
            let ip = format!("192.168.{}.{}", i / 256, i % 256);
            assert_eq!(limiter.acquire(&ip, after), Ok(()));
            limiter.release(&ip);
        }
        assert_eq!(limiter.per_ip.len(), 1_000);

        let t2 = after + Duration::from_secs(65);
        assert_eq!(limiter.acquire("203.0.113.1", t2), Ok(()));
        // The 1,000 inactive IPs were automatically pruned during acquire at t2.
        assert_eq!(limiter.per_ip.len(), 1);
        assert_eq!(limiter.total_active, 1);

        // Long-lived session closing after the 60s burst window removes its IP entry immediately.
        limiter.release_at("203.0.113.1", t2 + Duration::from_secs(61));
        assert_eq!(limiter.per_ip.len(), 0);
        assert_eq!(limiter.total_active, 0);
    }

    #[test]
    fn reap_idle_streamable_sessions_evicts_stale_entries_and_releases_slots() {
        let ip = "203.0.113.249";
        let mut hdrs = req_headers::HeaderMap::new();
        hdrs.insert("x-forwarded-for", req_headers::HeaderValue::from_static(ip));
        let guard = acquire_session_slot(&hdrs).expect("slot must acquire");
        let stale_sid = format!("test-stale-{}", uuid::Uuid::new_v4());
        let fresh_sid = format!("test-fresh-{}", uuid::Uuid::new_v4());
        let guard_fresh = acquire_session_slot(&hdrs).expect("second slot must acquire");
        let now = Instant::now();

        {
            let mut map = MCP_STREAMABLE_SESSIONS.write().unwrap();
            map.insert(
                stale_sid.clone(),
                McpStreamableSession {
                    session: McpNativeSession {
                        delegate_key_hex: "11".repeat(32),
                        account_id: format!("0x{}", "a".repeat(64)),
                        default_namespace: "default".to_owned(),
                        oauth_scope: "memwal:read".to_owned(),
                        sse_tx: None,
                    },
                    last_active: now,
                    _slot_guard: guard,
                },
            );
            map.insert(
                fresh_sid.clone(),
                McpStreamableSession {
                    session: McpNativeSession {
                        delegate_key_hex: "22".repeat(32),
                        account_id: format!("0x{}", "b".repeat(64)),
                        default_namespace: "default".to_owned(),
                        oauth_scope: "memwal:read".to_owned(),
                        sse_tx: None,
                    },
                    last_active: now + Duration::from_secs(10 * 60),
                    _slot_guard: guard_fresh,
                },
            );
        }

        let evicted =
            reap_idle_streamable_sessions_at(now + STREAMABLE_IDLE_TTL + Duration::from_secs(1));
        assert!(evicted >= 1);

        {
            let mut map = MCP_STREAMABLE_SESSIONS.write().unwrap();
            assert!(!map.contains_key(&stale_sid));
            assert!(map.remove(&fresh_sid).is_some());
        }
    }

    fn build_test_headers(
        key_hex: &str,
        account_id: &str,
        scope: Option<&str>,
        session_id: Option<&str>,
        ip: &str,
    ) -> req_headers::HeaderMap {
        let mut h = req_headers::HeaderMap::new();
        h.insert(
            "authorization",
            req_headers::HeaderValue::from_str(&format!("Bearer {key_hex}")).unwrap(),
        );
        h.insert(
            "x-memwal-account-id",
            req_headers::HeaderValue::from_str(account_id).unwrap(),
        );
        h.insert(
            "x-forwarded-for",
            req_headers::HeaderValue::from_str(ip).unwrap(),
        );
        if let Some(sc) = scope {
            h.insert(
                "x-memwal-internal-oauth-scope",
                req_headers::HeaderValue::from_str(sc).unwrap(),
            );
        }
        if let Some(sid) = session_id {
            h.insert(
                "mcp-session-id",
                req_headers::HeaderValue::from_str(sid).unwrap(),
            );
        }
        h
    }

    #[tokio::test]
    async fn streamable_http_enforces_auth_session_binding_scope_and_protocol() {
        use futures::StreamExt;

        let key_a = "33".repeat(32);
        let acct_a = format!("0x{}", "1".repeat(64));
        let key_b = "44".repeat(32);
        let acct_b = format!("0x{}", "2".repeat(64));
        let init_body = Bytes::from(
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "protocolVersion": "2025-03-26" }
            }))
            .unwrap(),
        );

        // 1. Open valid session for Caller A with read+write scope
        let init_resp = handle_streamable_core(
            None,
            Method::POST,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:read memwal:write"),
                None,
                "198.51.100.90",
            ),
            init_body.clone(),
        )
        .await;
        assert_eq!(init_resp.status(), StatusCode::OK);
        let sid = init_resp
            .headers()
            .get("mcp-session-id")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();

        // 2. Unauthenticated DELETE must fail with 401 + www-authenticate and keep session alive
        let mut unauth_del_headers = req_headers::HeaderMap::new();
        unauth_del_headers.insert(
            "mcp-session-id",
            req_headers::HeaderValue::from_str(&sid).unwrap(),
        );
        let unauth_del =
            handle_streamable_core(None, Method::DELETE, unauth_del_headers, Bytes::new()).await;
        assert_eq!(unauth_del.status(), StatusCode::UNAUTHORIZED);
        assert!(unauth_del
            .headers()
            .contains_key(axum::http::header::WWW_AUTHENTICATE));

        // 3. Cross-tenant DELETE, POST, and GET by Caller B must fail with 403
        let cross_del = handle_streamable_core(
            None,
            Method::DELETE,
            build_test_headers(
                &key_b,
                &acct_b,
                Some("memwal:read memwal:write"),
                Some(&sid),
                "198.51.100.91",
            ),
            Bytes::new(),
        )
        .await;
        assert_eq!(cross_del.status(), StatusCode::FORBIDDEN);

        let ping_body = Bytes::from(
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 2, "method": "ping"})).unwrap(),
        );
        let cross_post = handle_streamable_core(
            None,
            Method::POST,
            build_test_headers(
                &key_b,
                &acct_b,
                Some("memwal:read memwal:write"),
                Some(&sid),
                "198.51.100.91",
            ),
            ping_body.clone(),
        )
        .await;
        assert_eq!(cross_post.status(), StatusCode::FORBIDDEN);

        // 4. Narrowed or dropped OAuth scope on existing session must fail with 403
        let narrowed_post = handle_streamable_core(
            None,
            Method::POST,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:read"),
                Some(&sid),
                "198.51.100.90",
            ),
            ping_body.clone(),
        )
        .await;
        assert_eq!(narrowed_post.status(), StatusCode::FORBIDDEN);

        let dropped_scope_post = handle_streamable_core(
            None,
            Method::POST,
            build_test_headers(&key_a, &acct_a, None, Some(&sid), "198.51.100.90"),
            ping_body.clone(),
        )
        .await;
        assert_eq!(dropped_scope_post.status(), StatusCode::FORBIDDEN);

        // 5. Forged / unknown mcp-session-id on POST must fail with 404
        let forged_post = handle_streamable_core(
            None,
            Method::POST,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:read memwal:write"),
                Some("forged-session-id"),
                "198.51.100.90",
            ),
            ping_body.clone(),
        )
        .await;
        assert_eq!(forged_post.status(), StatusCode::NOT_FOUND);

        // 6. GET and DELETE without mcp-session-id must fail with 400
        let get_missing_sid = handle_streamable_core(
            None,
            Method::GET,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:read memwal:write"),
                None,
                "198.51.100.90",
            ),
            Bytes::new(),
        )
        .await;
        assert_eq!(get_missing_sid.status(), StatusCode::BAD_REQUEST);

        let del_missing_sid = handle_streamable_core(
            None,
            Method::DELETE,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:read memwal:write"),
                None,
                "198.51.100.90",
            ),
            Bytes::new(),
        )
        .await;
        assert_eq!(del_missing_sid.status(), StatusCode::BAD_REQUEST);

        // 7. Valid GET with matching mcp-session-id streams keepalive SSE without legacy endpoint event
        let get_ok = handle_streamable_core(
            None,
            Method::GET,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:write memwal:read"),
                Some(&sid),
                "198.51.100.90",
            ),
            Bytes::new(),
        )
        .await;
        assert_eq!(get_ok.status(), StatusCode::OK);
        assert_eq!(
            get_ok.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
        let mut data_stream = get_ok.into_body().into_data_stream();
        let first_frame = data_stream
            .next()
            .await
            .expect("first SSE frame")
            .expect("frame ok");
        let first_str = std::str::from_utf8(&first_frame).unwrap();
        assert_eq!(first_str, ": keepalive\n\n");
        assert!(!first_str.contains("/api/mcp/messages"));
        drop(data_stream);

        // 8. Oversized POST body returns 413 Payload Too Large
        let oversized = Bytes::from(vec![b' '; MCP_MAX_REQUEST_BODY_BYTES + 1]);
        let too_large = handle_streamable_core(
            None,
            Method::POST,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:read memwal:write"),
                Some(&sid),
                "198.51.100.90",
            ),
            oversized,
        )
        .await;
        assert_eq!(too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // 9. Owner DELETE returns 204 and subsequent POST returns 404
        let owner_del = handle_streamable_core(
            None,
            Method::DELETE,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:read memwal:write"),
                Some(&sid),
                "198.51.100.90",
            ),
            Bytes::new(),
        )
        .await;
        assert_eq!(owner_del.status(), StatusCode::NO_CONTENT);

        let after_del = handle_streamable_core(
            None,
            Method::POST,
            build_test_headers(
                &key_a,
                &acct_a,
                Some("memwal:read memwal:write"),
                Some(&sid),
                "198.51.100.90",
            ),
            ping_body,
        )
        .await;
        assert_eq!(after_del.status(), StatusCode::NOT_FOUND);
    }
}

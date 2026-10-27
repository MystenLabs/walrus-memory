//! In-process Rust MCP (Model Context Protocol) SSE + JSON-RPC + Streamable HTTP server.
//!
//! Replaces the Node.js sidecar's `/mcp/sse`, `/mcp/messages`, and `/mcp` Express routes
//! (`services/server/scripts/mcp/index.ts`) when `is_in_process_sidecar_enabled` is active,
//! allowing `memwal-server` to serve `@mysten-incubation/memwal-mcp` and Streamable HTTP
//! MCP clients with zero Node.js child processes.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

static MCP_NATIVE_SESSIONS: LazyLock<RwLock<HashMap<String, McpNativeSession>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

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
        "memwal_health" | "memwal_recall" => can_read,
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
            | "memwal_remember"
            | "memwal_remember_status"
            | "memwal_remember_bulk"
            | "memwal_analyze"
            | "memwal_restore"
    )
}

fn resolve_session_credentials(
    state: &AppState,
    forwarded: &req_headers::HeaderMap,
) -> Result<(String, String, String, String), (StatusCode, &'static str)> {
    let bearer_key = extract_header_str(forwarded, "authorization")
        .and_then(|auth| {
            auth.strip_prefix("Bearer ")
                .or_else(|| auth.strip_prefix("bearer "))
                .map(str::trim)
                .map(str::to_owned)
        })
        .map(|k| k.strip_prefix("0x").unwrap_or(&k).to_owned())
        .filter(|k| k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit()))
        .or_else(|| {
            state
                .config
                .sui_private_key
                .as_deref()
                .map(str::trim)
                .map(|k| k.strip_prefix("0x").unwrap_or(k).to_owned())
                .filter(|k| k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit()))
        });

    let Some(delegate_key_hex) = bearer_key else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Missing or invalid Ed25519 delegate key bearer",
        ));
    };

    let account_id = extract_header_str(forwarded, "x-memwal-internal-oauth-account-id")
        .or_else(|| extract_header_str(forwarded, "x-memwal-account-id"))
        .or_else(|| state.config.memwal_account_id.clone())
        .unwrap_or_default();

    if account_id.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "Missing X-MemWal-Account-Id"));
    }

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

pub(crate) fn format_recall_output(
    results: &[Value],
    max_distance: Option<f64>,
    dropped_count: u64,
) -> String {
    let filtered: Vec<&Value> = results
        .iter()
        .filter(|item| {
            let dist = item.get("distance").and_then(Value::as_f64).unwrap_or(0.0);
            max_distance.is_none_or(|cutoff| dist <= cutoff)
        })
        .collect();

    let mut seen = std::collections::HashSet::new();
    let mut unique = Vec::with_capacity(filtered.len());
    let mut collapsed: usize = 0;
    for item in filtered {
        let text = item.get("text").and_then(Value::as_str).unwrap_or("");
        let key = normalize_recall_dedupe_key(text);
        if seen.insert(key) {
            unique.push(item);
        } else {
            collapsed += 1;
        }
    }

    if unique.is_empty() {
        if !results.is_empty() {
            return "All matching memories were outside maxDistance. Increase maxDistance or omit it to inspect weaker matches.".to_owned();
        }
        if dropped_count > 0 {
            return format!(
                "No matching memories could be returned ({dropped_count} match(es) failed to decrypt)."
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

    let mut out = lines.join("\n");
    if collapsed > 0 {
        let noun = if collapsed == 1 { "copy" } else { "copies" };
        out.push_str(&format!(
            "\n({collapsed} duplicate {noun} of the above collapsed; the same fact is stored more than once.)"
        ));
    }
    if dropped_count > 0 {
        out.push_str(&format!(
            "\n({dropped_count} additional matches could not be decrypted and were omitted.)"
        ));
    }
    out
}

pub(crate) fn format_restore_output(body: &Value, resolved_namespace: &str) -> String {
    let Some(total) = body.get("total").and_then(Value::as_u64) else {
        return body.to_string();
    };
    let restored = body.get("restored").and_then(Value::as_u64).unwrap_or(0);
    let skipped = body.get("skipped").and_then(Value::as_u64).unwrap_or(0);
    let failed = body.get("failed").and_then(Value::as_u64).unwrap_or(0);
    let has_more = body
        .get("has_more")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let next_cursor = body.get("next_cursor").and_then(Value::as_str);

    let headline = if failed > 0 {
        "Restore partially complete."
    } else {
        "Restore page finished."
    };
    let mut lines = vec![format!(
        "{headline} namespace={resolved_namespace} total={total} restored={restored} skipped={skipped} failed={failed} truncated={has_more}"
    )];

    if has_more {
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
                        let rendered = if job_status == "already_exists" {
                            format!(
                                "Already in Walrus Memory (skipped duplicate write). blob_id={blob_id} namespace={namespace}"
                            )
                        } else {
                            format!(
                                "Saved to Walrus Memory. blob_id={blob_id} namespace={namespace}"
                            )
                        };
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
                        json!({
                            "content": [{
                                "type": "text",
                                "text": format!(
                                    "Accepted by Walrus Memory (write in progress). job_id={job_id} status={job_status} namespace={namespace}\nResolve with memwal_remember_status."
                                )
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
            let items = args.get("items").cloned().unwrap_or_else(|| json!([]));
            let namespace = args
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(default_namespace);
            let mut payload = json!({
                "items": items,
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
                Ok((status, body)) if status.is_success() => json!({
                    "content": [{ "type": "text", "text": body.to_string() }]
                }),
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
                    let rendered = format_recall_output(results, max_distance, dropped_count);
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
            let namespace = args
                .get("namespace")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(default_namespace);
            let payload = json!({
                "text": text,
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
                Ok((status, body)) if status.is_success() => json!({
                    "content": [{ "type": "text", "text": body.to_string() }]
                }),
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
                    let rendered = format_restore_output(&body, namespace);
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
    state: &AppState,
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
            let tool_name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            execute_mcp_tool(
                state,
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
    state: Arc<AppState>,
    forwarded: req_headers::HeaderMap,
) -> Response {
    let (delegate_key_hex, account_id, default_namespace, oauth_scope) =
        match resolve_session_credentials(&state, &forwarded) {
            Ok(creds) => creds,
            Err(err) => return err.into_response(),
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

    if let Ok(mut guard) = MCP_NATIVE_SESSIONS.write() {
        guard.insert(session_id.clone(), session);
    }

    let cleanup_session_id = session_id.clone();
    tokio::spawn(async move {
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
        if let Ok(mut guard) = MCP_NATIVE_SESSIONS.write() {
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
    let session = MCP_NATIVE_SESSIONS
        .read()
        .ok()
        .and_then(|guard| guard.get(&session_id).cloned());

    let Some(session) = session else {
        return (StatusCode::NOT_FOUND, "Unknown or expired MCP session").into_response();
    };

    let (caller_key, caller_account, _, _) = match resolve_session_credentials(&state, &forwarded) {
        Ok(creds) => creds,
        Err(err) => return err.into_response(),
    };

    if caller_key != session.delegate_key_hex || caller_account != session.account_id {
        return (
            StatusCode::FORBIDDEN,
            "sessionId does not match authenticated caller",
        )
            .into_response();
    }

    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid JSON-RPC body: {e}"),
            )
                .into_response();
        }
    };

    tokio::spawn(async move {
        if let Some(arr) = parsed.as_array() {
            for item in arr {
                if let Some(resp) = handle_jsonrpc_envelope(
                    &state,
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
            &state,
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
    match method {
        Method::DELETE => {
            if let Some(session_id) = extract_header_str(&forwarded, "mcp-session-id") {
                if let Ok(mut guard) = MCP_NATIVE_SESSIONS.write() {
                    guard.remove(&session_id);
                }
            }
            (StatusCode::NO_CONTENT, ()).into_response()
        }
        Method::GET => handle_sse_in_process(state, forwarded).await,
        Method::POST => {
            let (delegate_key_hex, account_id, default_namespace, oauth_scope) =
                match resolve_session_credentials(&state, &forwarded) {
                    Ok(creds) => creds,
                    Err(err) => return err.into_response(),
                };
            let parsed: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid JSON-RPC body: {e}"),
                    )
                        .into_response();
                }
            };
            let existing_session_id = extract_header_str(&forwarded, "mcp-session-id");
            let mut effective_scope = oauth_scope.clone();
            if let Some(ref sid) = existing_session_id {
                if let Some(existing) = MCP_NATIVE_SESSIONS
                    .read()
                    .ok()
                    .and_then(|guard| guard.get(sid).cloned())
                {
                    if existing.delegate_key_hex != delegate_key_hex
                        || existing.account_id != account_id
                    {
                        return (
                            StatusCode::FORBIDDEN,
                            "mcp-session-id does not match authenticated caller",
                        )
                            .into_response();
                    }
                    // Preserve the intersection of session scope and current request scope so a
                    // read-only session cannot escalate to write, nor can a narrowed token use a
                    // broader cached session scope.
                    let (sess_read, sess_write) = parse_granted_oauth_scopes(&existing.oauth_scope);
                    let (req_read, req_write) = parse_granted_oauth_scopes(&oauth_scope);
                    let mut scopes = Vec::new();
                    if sess_read && req_read {
                        scopes.push("memwal:read");
                    }
                    if sess_write && req_write {
                        scopes.push("memwal:write");
                    }
                    effective_scope = scopes.join(" ");
                }
            }
            let session_id =
                existing_session_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            if let Ok(mut guard) = MCP_NATIVE_SESSIONS.write() {
                guard
                    .entry(session_id.clone())
                    .or_insert_with(|| McpNativeSession {
                        delegate_key_hex: delegate_key_hex.clone(),
                        account_id: account_id.clone(),
                        default_namespace: default_namespace.clone(),
                        oauth_scope: effective_scope.clone(),
                        sse_tx: None,
                    });
            }

            let response_value = if let Some(arr) = parsed.as_array() {
                if arr.is_empty() {
                    return (
                        StatusCode::BAD_REQUEST,
                        "Empty JSON-RPC batch is not allowed",
                    )
                        .into_response();
                }
                let mut responses = Vec::with_capacity(arr.len());
                for item in arr {
                    if let Some(resp) = handle_jsonrpc_envelope(
                        &state,
                        &delegate_key_hex,
                        &account_id,
                        &default_namespace,
                        &effective_scope,
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
                    &state,
                    &delegate_key_hex,
                    &account_id,
                    &default_namespace,
                    &effective_scope,
                    &parsed,
                )
                .await
            };

            if let Some(resp) = response_value {
                let mut headers = HeaderMap::new();
                headers.insert(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                if let Ok(hv) = HeaderValue::from_str(&session_id) {
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
                if let Ok(hv) = HeaderValue::from_str(&session_id) {
                    headers.insert("mcp-session-id", hv);
                }
                (StatusCode::ACCEPTED, headers, ()).into_response()
            }
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, "Method not allowed").into_response(),
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
            vec!["memwal_health", "memwal_recall"]
        );
        assert!(is_mcp_tool_permitted("memwal_health", "memwal:read"));
        assert!(is_mcp_tool_permitted("memwal_recall", "memwal:read"));
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
                "created_at": "2026-04-19T10:20:30Z"
            }),
            json!({
                "text": "  user   PREFERS dark mode ",
                "distance": 0.15,
                "created_at": "2026-04-18T08:00:00Z"
            }),
            json!({
                "text": "Uses Rust 2021 edition",
                "distance": 0.45
            }),
        ];

        let rendered = format_recall_output(&results, Some(0.30), 2);
        assert_eq!(
            rendered,
            "1. [score=0.880 distance=0.120] [written=2026-04-19] User prefers dark mode\n(1 duplicate copy of the above collapsed; the same fact is stored more than once.)\n(2 additional matches could not be decrypted and were omitted.)"
        );

        let all_filtered = format_recall_output(&results, Some(0.05), 0);
        assert_eq!(
            all_filtered,
            "All matching memories were outside maxDistance. Increase maxDistance or omit it to inspect weaker matches."
        );

        let all_dropped = format_recall_output(&[], None, 3);
        assert_eq!(
            all_dropped,
            "No matching memories could be returned (3 match(es) failed to decrypt)."
        );
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
}

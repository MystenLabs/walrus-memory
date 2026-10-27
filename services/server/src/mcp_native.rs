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
    pub sse_tx: mpsc::UnboundedSender<String>,
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

fn resolve_session_credentials(
    state: &AppState,
    forwarded: &req_headers::HeaderMap,
) -> Result<(String, String, String), (StatusCode, &'static str)> {
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

    Ok((delegate_key_hex, account_id, default_namespace))
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

    let canonical = format!(
        "{timestamp}.{method_str}.{path_and_query}.{body_sha256}.{nonce}.{account_id}"
    );
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
    let status = StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let text = resp
        .text()
        .await
        .map_err(|e| format!("read relayer response failed: {e}"))?;
    let parsed = serde_json::from_str::<Value>(&text).unwrap_or_else(|_| json!({ "raw": text }));
    Ok((status, parsed))
}

fn mcp_tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "memwal_health",
                "description": "Quick connectivity check for Walrus Memory. Calls the relayer's lightweight health endpoint and returns its status and version.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "memwal_remember",
                "description": "Save a durable fact about the user or project to their Walrus Memory.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "description": "The full, detailed fact to save." },
                        "namespace": { "type": "string", "description": "Optional namespace bucket." }
                    },
                    "required": ["text"]
                }
            },
            {
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
            },
            {
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
                        "namespace": { "type": "string" }
                    },
                    "required": ["items"]
                }
            },
            {
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
            },
            {
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
            },
            {
                "name": "memwal_restore",
                "description": "Rebuild the vector search index for a namespace from on-chain Walrus blobs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "namespace": { "type": "string", "description": "Optional namespace bucket." },
                        "limit": { "type": "number", "description": "Max blobs to restore." }
                    }
                }
            }
        ]
    })
}

async fn execute_mcp_tool(
    state: &AppState,
    delegate_key_hex: &str,
    account_id: &str,
    default_namespace: &str,
    tool_name: &str,
    args: &Value,
) -> Value {
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

            let idem_hash = hex::encode(Sha256::digest(format!("{namespace}:{text}").as_bytes()));
            let idem_key = format!("mcp-{}", &idem_hash[..32]);
            let payload = json!({
                "text": text,
                "namespace": namespace,
            });
            match call_local_relayer(
                state,
                delegate_key_hex,
                account_id,
                Method::POST,
                "/api/remember",
                Some(&payload),
                &[("idempotency-key", &idem_key)],
            )
            .await
            {
                Ok((status, body)) if status.is_success() => {
                    if let Some(blob_id) = body.get("blob_id").and_then(Value::as_str) {
                        json!({
                            "content": [{
                                "type": "text",
                                "text": format!("Saved to Walrus Memory. blob_id={blob_id} namespace={namespace}")
                            }]
                        })
                    } else {
                        let job_id = body
                            .get("job_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let job_status = body
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("running");
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
            let payload = json!({
                "items": items,
                "namespace": namespace,
            });
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
                    let mut lines = Vec::new();
                    for item in results {
                        let dist = item.get("distance").and_then(Value::as_f64).unwrap_or(0.0);
                        if let Some(cutoff) = max_distance {
                            if dist >= cutoff {
                                continue;
                            }
                        }
                        let score = 1.0 - dist;
                        let text = item.get("text").and_then(Value::as_str).unwrap_or("");
                        let rank = lines.len() + 1;
                        lines.push(format!(
                            "{rank}. [score={score:.3} distance={dist:.3}] {text}"
                        ));
                    }
                    let rendered = if lines.is_empty() {
                        "No matching memories found.".to_owned()
                    } else {
                        lines.join("\n")
                    };
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
            let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50);
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
                Ok((status, body)) if status.is_success() => json!({
                    "content": [{ "type": "text", "text": body.to_string() }]
                }),
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
        "tools/list" => mcp_tools_list(),
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
    let (delegate_key_hex, account_id, default_namespace) =
        match resolve_session_credentials(&state, &forwarded) {
            Ok(creds) => creds,
            Err(err) => return err.into_response(),
        };

    let session_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = mpsc::unbounded_channel::<String>();

    let endpoint_event = format!("event: endpoint\ndata: /api/mcp/messages?sessionId={session_id}\n\n");
    let _ = tx.send(endpoint_event);

    let session = McpNativeSession {
        delegate_key_hex,
        account_id,
        default_namespace,
        sse_tx: tx.clone(),
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
    _forwarded: req_headers::HeaderMap,
    body: Bytes,
) -> Response {
    let session = MCP_NATIVE_SESSIONS
        .read()
        .ok()
        .and_then(|guard| guard.get(&session_id).cloned());

    let Some(session) = session else {
        return (StatusCode::NOT_FOUND, "Unknown or expired MCP session").into_response();
    };

    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON-RPC body: {e}"))
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
                    item,
                )
                .await
                {
                    if let Ok(serialized) = serde_json::to_string(&resp) {
                        let _ = session
                            .sse_tx
                            .send(format!("event: message\ndata: {serialized}\n\n"));
                    }
                }
            }
        } else if let Some(resp) = handle_jsonrpc_envelope(
            &state,
            &session.delegate_key_hex,
            &session.account_id,
            &session.default_namespace,
            &parsed,
        )
        .await
        {
            if let Ok(serialized) = serde_json::to_string(&resp) {
                let _ = session
                    .sse_tx
                    .send(format!("event: message\ndata: {serialized}\n\n"));
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
            let (delegate_key_hex, account_id, default_namespace) =
                match resolve_session_credentials(&state, &forwarded) {
                    Ok(creds) => creds,
                    Err(err) => return err.into_response(),
                };
            let parsed: Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, format!("Invalid JSON-RPC body: {e}"))
                        .into_response();
                }
            };
            let session_id = extract_header_str(&forwarded, "mcp-session-id")
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

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

    #[test]
    fn mcp_tools_list_exposes_all_seven_walrus_memory_tools_with_valid_schemas() {
        let list = mcp_tools_list();
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
        headers.insert(
            "x-empty",
            req_headers::HeaderValue::from_static("   "),
        );

        assert_eq!(
            extract_header_str(&headers, "x-memwal-namespace").as_deref(),
            Some("work-ns")
        );
        assert_eq!(extract_header_str(&headers, "x-empty"), None);
        assert_eq!(extract_header_str(&headers, "x-missing"), None);
    }
}


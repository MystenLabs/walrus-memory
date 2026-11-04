use axum::extract::{Extension, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::{channel, Receiver, Sender};

use crate::types::{AppError, AppState, AuthInfo};

const REDIS_EVENTS_CHANNEL: &str = "memwal:events";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RedisEventEnvelope {
    origin_instance_id: String,
    event: MemoryEvent,
}

pub type AuthRevalidator = Arc<dyn Fn() -> futures::future::BoxFuture<'static, bool> + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub owner: String,
    pub namespace: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct EventHub {
    instance_id: String,
    sender: Sender<MemoryEvent>,
    pub(crate) redis_tx: Arc<std::sync::OnceLock<tokio::sync::mpsc::Sender<String>>>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    pub fn new() -> Self {
        let (sender, _) = channel(1024);
        Self {
            instance_id: uuid::Uuid::new_v4().to_string(),
            sender,
            redis_tx: Arc::new(std::sync::OnceLock::new()),
        }
    }

    #[allow(dead_code)]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn subscribe(&self) -> Receiver<MemoryEvent> {
        self.sender.subscribe()
    }

    pub fn publish(&self, event: MemoryEvent) {
        let _ = self.sender.send(event.clone());
        if let Some(tx) = self.redis_tx.get() {
            let envelope = RedisEventEnvelope {
                origin_instance_id: self.instance_id.clone(),
                event,
            };
            if let Ok(payload) = serde_json::to_string(&envelope) {
                let _ = tx.try_send(payload);
            }
        }
    }

    pub fn ingest_remote_payload(&self, payload: &str) -> bool {
        let envelope: RedisEventEnvelope = match serde_json::from_str(payload) {
            Ok(env) => env,
            Err(e) => {
                tracing::warn!("Failed to deserialize Redis event envelope: {}", e);
                return false;
            }
        };
        if envelope.origin_instance_id == self.instance_id {
            return false;
        }
        let _ = self.sender.send(envelope.event);
        true
    }

    pub fn start_redis_bridge(&self, redis_url: String, redis_conn: redis::aio::ConnectionManager) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(2048);
        if self.redis_tx.set(tx).is_err() {
            return;
        }

        let mut pub_conn = redis_conn;
        tokio::spawn(async move {
            while let Some(payload) = rx.recv().await {
                let res: Result<(), redis::RedisError> = redis::cmd("PUBLISH")
                    .arg(REDIS_EVENTS_CHANNEL)
                    .arg(&payload)
                    .query_async(&mut pub_conn)
                    .await;
                if let Err(e) = res {
                    tracing::warn!("Failed to publish event to Redis channel: {}", e);
                }
            }
        });

        let hub = self.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(15);
            loop {
                let client = match redis::Client::open(redis_url.as_str()) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("Failed to open Redis client for events bridge: {}", e);
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                        continue;
                    }
                };

                let mut pubsub = match client.get_async_pubsub().await {
                    Ok(ps) => ps,
                    Err(e) => {
                        tracing::warn!("Failed to connect async pubsub for events bridge: {}", e);
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                        continue;
                    }
                };

                if let Err(e) = pubsub.subscribe(REDIS_EVENTS_CHANNEL).await {
                    tracing::warn!("Failed to subscribe to Redis events channel: {}", e);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                    continue;
                }

                backoff = Duration::from_secs(1);
                tracing::info!(
                    "Events Redis bridge subscribed to channel {}",
                    REDIS_EVENTS_CHANNEL
                );

                use futures::StreamExt;
                let mut msg_stream = pubsub.on_message();
                while let Some(msg) = msg_stream.next().await {
                    let payload: String = match msg.get_payload() {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("Failed to read message payload from Redis: {}", e);
                            continue;
                        }
                    };
                    hub.ingest_remote_payload(&payload);
                }

                tracing::warn!("Redis events pubsub stream closed; reconnecting...");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        });
    }

    pub fn publish_remember_accepted(
        &self,
        owner: impl Into<String>,
        namespace: impl Into<String>,
        job_id: Option<String>,
        count: Option<usize>,
    ) {
        self.publish(MemoryEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "memory.remember.accepted".to_string(),
            owner: owner.into(),
            namespace: namespace.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            job_id,
            blob_id: None,
            count,
            error: None,
        });
    }

    pub fn publish_remember_completed(
        &self,
        owner: impl Into<String>,
        namespace: impl Into<String>,
        job_id: Option<String>,
        blob_id: Option<String>,
        count: Option<usize>,
    ) {
        self.publish(MemoryEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "memory.remember.completed".to_string(),
            owner: owner.into(),
            namespace: namespace.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            job_id,
            blob_id,
            count,
            error: None,
        });
    }

    pub fn publish_remember_failed(
        &self,
        owner: impl Into<String>,
        namespace: impl Into<String>,
        job_id: Option<String>,
        error: Option<String>,
    ) {
        let sanitized =
            error.and_then(|e| crate::routes::sanitize_job_error_for_client("failed", Some(e)));
        self.publish(MemoryEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "memory.remember.failed".to_string(),
            owner: owner.into(),
            namespace: namespace.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            job_id,
            blob_id: None,
            count: None,
            error: sanitized,
        });
    }

    pub fn publish_forget(
        &self,
        owner: impl Into<String>,
        namespace: impl Into<String>,
        count: Option<usize>,
    ) {
        self.publish(MemoryEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "memory.forget".to_string(),
            owner: owner.into(),
            namespace: namespace.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            job_id: None,
            blob_id: None,
            count,
            error: None,
        });
    }

    pub fn publish_restore_completed(
        &self,
        owner: impl Into<String>,
        namespace: impl Into<String>,
        count: Option<usize>,
    ) {
        self.publish(MemoryEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "memory.restore.completed".to_string(),
            owner: owner.into(),
            namespace: namespace.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            job_id: None,
            blob_id: None,
            count,
            error: None,
        });
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventsStreamQuery {
    pub namespace: Option<String>,
    pub types: Option<String>,
}

struct EventStreamState {
    rx: Receiver<MemoryEvent>,
    revalidator: Option<AuthRevalidator>,
    revalidation_interval: Duration,
    next_revalidation: tokio::time::Instant,
    deadline: Option<tokio::time::Instant>,
}

#[allow(dead_code)]
pub fn create_event_stream(
    rx: Receiver<MemoryEvent>,
    owner: String,
    namespace: Option<String>,
    allowed_types: Option<HashSet<String>>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    create_event_stream_with_guards(
        rx,
        owner,
        namespace,
        allowed_types,
        None,
        None,
        Duration::from_secs(30),
    )
}

pub fn create_event_stream_with_guards(
    rx: Receiver<MemoryEvent>,
    owner: String,
    namespace: Option<String>,
    allowed_types: Option<HashSet<String>>,
    deadline: Option<tokio::time::Instant>,
    revalidator: Option<AuthRevalidator>,
    revalidation_interval: Duration,
) -> impl Stream<Item = Result<Event, Infallible>> {
    let next_revalidation = tokio::time::Instant::now() + revalidation_interval;
    let initial_state = EventStreamState {
        rx,
        revalidator,
        revalidation_interval,
        next_revalidation,
        deadline,
    };

    futures::stream::unfold(initial_state, move |mut state| {
        let allowed_types = allowed_types.clone();
        let namespace = namespace.clone();
        let owner = owner.clone();
        async move {
            loop {
                if let Some(dl) = state.deadline {
                    if tokio::time::Instant::now() >= dl {
                        return None;
                    }
                }

                tokio::select! {
                    biased;

                    _ = async {
                        match state.deadline {
                            Some(dl) => tokio::time::sleep_until(dl).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        return None;
                    }

                    _ = async {
                        if state.revalidator.is_some() {
                            tokio::time::sleep_until(state.next_revalidation).await
                        } else {
                            std::future::pending::<()>().await
                        }
                    } => {
                        if let Some(ref rev) = state.revalidator {
                            let valid = (rev)().await;
                            if !valid {
                                return None;
                            }
                            state.next_revalidation = tokio::time::Instant::now() + state.revalidation_interval;
                        }
                        continue;
                    }

                    recv_res = state.rx.recv() => {
                        if let Some(dl) = state.deadline {
                            if tokio::time::Instant::now() >= dl {
                                return None;
                            }
                        }
                        if let Some(ref rev) = state.revalidator {
                            if tokio::time::Instant::now() >= state.next_revalidation {
                                let valid = (rev)().await;
                                if !valid {
                                    return None;
                                }
                                state.next_revalidation = tokio::time::Instant::now() + state.revalidation_interval;
                            }
                        }

                        match recv_res {
                            Ok(event) => {
                                if event.owner != owner {
                                    continue;
                                }
                                if let Some(ref ns) = namespace {
                                    if event.namespace != *ns {
                                        continue;
                                    }
                                }
                                if let Some(ref types) = allowed_types {
                                    if !types.contains(&event.event_type) {
                                        continue;
                                    }
                                }
                                let sse_event = match Event::default()
                                    .id(event.id.clone())
                                    .event(event.event_type.clone())
                                    .json_data(&event)
                                {
                                    Ok(ev) => ev,
                                    Err(e) => {
                                        tracing::error!("Failed to serialize memory event for SSE: {}", e);
                                        continue;
                                    }
                                };
                                return Some((Ok(sse_event), state));
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                let lagged_payload = serde_json::json!({
                                    "type": "system.lagged",
                                    "skipped": skipped,
                                });
                                let sse_event = match Event::default()
                                    .event("system.lagged")
                                    .json_data(&lagged_payload)
                                {
                                    Ok(ev) => ev,
                                    Err(e) => {
                                        tracing::error!("Failed to serialize lagged event for SSE: {}", e);
                                        continue;
                                    }
                                };
                                return Some((Ok(sse_event), state));
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                return None;
                            }
                        }
                    }
                }
            }
        }
    })
}

pub async fn events_stream(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
    session_expiry: Option<Extension<crate::auth::AuthSessionExpiry>>,
    Query(params): Query<EventsStreamQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, AppError> {
    if let Some(ref ns) = params.namespace {
        crate::types::validate_namespace(ns)?;
    }

    let allowed_types: Option<HashSet<String>> = if let Some(ref raw_types) = params.types {
        let mut set = HashSet::new();
        for item in raw_types.split(',') {
            let trimmed = item.trim();
            if trimmed.is_empty() {
                return Err(AppError::BadRequest(
                    "Event type cannot be empty".to_string(),
                ));
            }
            set.insert(trimmed.to_string());
        }
        Some(set)
    } else {
        None
    };

    let deadline = if let Some(Extension(crate::auth::AuthSessionExpiry(exp))) = session_expiry {
        let now = chrono::Utc::now().timestamp();
        if exp <= now {
            return Err(AppError::Unauthorized("Session token expired".to_string()));
        }
        let remaining_secs = (exp - now).max(0) as u64;
        Some(tokio::time::Instant::now() + Duration::from_secs(remaining_secs))
    } else {
        None
    };

    let revalidator: Option<AuthRevalidator> = {
        let state = Arc::clone(&state);
        let auth = auth.clone();
        Some(Arc::new(move || {
            let state = Arc::clone(&state);
            let auth = auth.clone();
            Box::pin(async move {
                if auth.public_key.starts_with("ownertoken:") {
                    let matching_id = match state.db.find_account_by_owner(&auth.owner).await {
                        Ok(Some(id)) => id == auth.account_id,
                        _ => false,
                    };
                    if !matching_id {
                        return false;
                    }

                    match crate::storage::sui::verify_account_active_cached(
                        &state.delegate_verify_cache,
                        &state.delegate_reject_cache,
                        &state.http_client,
                        &state.config.sui_rpc_url,
                        state.sui_grpc_client.as_ref(),
                        &auth.account_id,
                        &state.config.package_id,
                    )
                    .await
                    {
                        Ok(onchain_owner) => {
                            if crate::security_delete_auth::same_owner(
                                Some(&onchain_owner),
                                &auth.owner,
                            ) {
                                true
                            } else {
                                state
                                    .delegate_keys_cache
                                    .write()
                                    .await
                                    .remove(&auth.account_id);
                                false
                            }
                        }
                        Err(e) => {
                            if !e.is_unavailable() {
                                state
                                    .delegate_keys_cache
                                    .write()
                                    .await
                                    .remove(&auth.account_id);
                            }
                            false
                        }
                    }
                } else {
                    let pk_bytes = match hex::decode(&auth.public_key) {
                        Ok(b) => b,
                        Err(_) => return false,
                    };
                    match crate::storage::sui::verify_delegate_key_cached(
                        &state.delegate_verify_cache,
                        &state.delegate_reject_cache,
                        &state.http_client,
                        &state.config.sui_rpc_url,
                        state.sui_grpc_client.as_ref(),
                        &auth.account_id,
                        &pk_bytes,
                        &state.config.package_id,
                    )
                    .await
                    {
                        Ok(onchain_owner) => {
                            if crate::security_delete_auth::same_owner(
                                Some(&onchain_owner),
                                &auth.owner,
                            ) {
                                true
                            } else {
                                state
                                    .delegate_keys_cache
                                    .write()
                                    .await
                                    .remove(&auth.account_id);
                                false
                            }
                        }
                        Err(ref e) => {
                            if !e.is_unavailable() {
                                state
                                    .delegate_keys_cache
                                    .write()
                                    .await
                                    .remove(&auth.account_id);
                            }
                            false
                        }
                    }
                }
            })
        }))
    };

    let rx = state.events.subscribe();
    let stream = create_event_stream_with_guards(
        rx,
        auth.owner,
        params.namespace,
        allowed_types,
        deadline,
        revalidator,
        Duration::from_secs(30),
    );

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_owner_isolation() {
        let hub = EventHub::new();
        let rx = hub.subscribe();
        let mut stream = Box::pin(create_event_stream(rx, "0xowner_a".to_string(), None, None));

        // Publish events for owner_b then owner_a
        hub.publish(MemoryEvent {
            id: "evt-1".to_string(),
            event_type: "memory.remember.accepted".to_string(),
            owner: "0xowner_b".to_string(),
            namespace: "default".to_string(),
            timestamp: "2026-11-03T00:00:00Z".to_string(),
            job_id: Some("job-b".to_string()),
            blob_id: None,
            count: Some(1),
            error: None,
        });

        hub.publish(MemoryEvent {
            id: "evt-2".to_string(),
            event_type: "memory.remember.accepted".to_string(),
            owner: "0xowner_a".to_string(),
            namespace: "default".to_string(),
            timestamp: "2026-11-03T00:00:01Z".to_string(),
            job_id: Some("job-a".to_string()),
            blob_id: None,
            count: Some(1),
            error: None,
        });

        let next = stream.next().await.expect("received event");
        let event = next.expect("valid sse event");
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("evt-2"));
        assert!(!debug_str.contains("evt-1"));
    }

    #[tokio::test]
    async fn test_namespace_filtering() {
        let hub = EventHub::new();
        let rx = hub.subscribe();
        let mut stream = Box::pin(create_event_stream(
            rx,
            "0xowner_a".to_string(),
            Some("work".to_string()),
            None,
        ));

        hub.publish(MemoryEvent {
            id: "evt-personal".to_string(),
            event_type: "memory.remember.accepted".to_string(),
            owner: "0xowner_a".to_string(),
            namespace: "personal".to_string(),
            timestamp: "2026-11-03T00:00:00Z".to_string(),
            job_id: Some("job-p".to_string()),
            blob_id: None,
            count: Some(1),
            error: None,
        });

        hub.publish(MemoryEvent {
            id: "evt-work".to_string(),
            event_type: "memory.remember.accepted".to_string(),
            owner: "0xowner_a".to_string(),
            namespace: "work".to_string(),
            timestamp: "2026-11-03T00:00:01Z".to_string(),
            job_id: Some("job-w".to_string()),
            blob_id: None,
            count: Some(1),
            error: None,
        });

        let next = stream.next().await.expect("received event");
        let event = next.expect("valid sse event");
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("evt-work"));
        assert!(!debug_str.contains("evt-personal"));
    }

    #[tokio::test]
    async fn test_event_type_filtering() {
        let hub = EventHub::new();
        let rx = hub.subscribe();
        let mut allowed = HashSet::new();
        allowed.insert("memory.remember.completed".to_string());
        allowed.insert("memory.forget".to_string());

        let mut stream = Box::pin(create_event_stream(
            rx,
            "0xowner_a".to_string(),
            None,
            Some(allowed),
        ));

        hub.publish_remember_accepted("0xowner_a", "default", Some("job-1".to_string()), Some(1));
        hub.publish_forget("0xowner_a", "default", Some(5));

        let next = stream.next().await.expect("received event");
        let event = next.expect("valid sse event");
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("memory.forget"));
        assert!(!debug_str.contains("memory.remember.accepted"));
    }

    #[test]
    fn test_sse_event_serialization() {
        let event = MemoryEvent {
            id: "test-uuid-1234".to_string(),
            event_type: "memory.remember.completed".to_string(),
            owner: "0xowner_test".to_string(),
            namespace: "docs".to_string(),
            timestamp: "2026-11-03T12:00:00Z".to_string(),
            job_id: Some("job-999".to_string()),
            blob_id: Some("blob-abc".to_string()),
            count: Some(1),
            error: None,
        };

        let serialized = serde_json::to_string(&event).expect("json serialize");
        assert!(serialized.contains("\"id\":\"test-uuid-1234\""));
        assert!(serialized.contains("\"type\":\"memory.remember.completed\""));
        assert!(serialized.contains("\"blob_id\":\"blob-abc\""));
        assert!(!serialized.contains("\"error\""));
    }

    #[tokio::test]
    async fn test_stream_terminates_on_authorization_revocation() {
        let hub = EventHub::new();
        let rx = hub.subscribe();
        let valid = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let valid_clone = Arc::clone(&valid);

        let revalidator: AuthRevalidator = Arc::new(move || {
            let v = Arc::clone(&valid_clone);
            Box::pin(async move { v.load(std::sync::atomic::Ordering::SeqCst) })
        });

        let mut stream = Box::pin(create_event_stream_with_guards(
            rx,
            "0xowner_a".to_string(),
            None,
            None,
            None,
            Some(revalidator),
            Duration::from_millis(20),
        ));

        hub.publish(MemoryEvent {
            id: "evt-auth-1".to_string(),
            event_type: "memory.remember.accepted".to_string(),
            owner: "0xowner_a".to_string(),
            namespace: "default".to_string(),
            timestamp: "2026-11-03T00:00:00Z".to_string(),
            job_id: Some("job-1".to_string()),
            blob_id: None,
            count: Some(1),
            error: None,
        });

        let ev1 = stream
            .next()
            .await
            .expect("stream produces item")
            .expect("valid event");
        assert!(format!("{:?}", ev1).contains("evt-auth-1"));

        valid.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(30)).await;

        hub.publish(MemoryEvent {
            id: "evt-auth-2".to_string(),
            event_type: "memory.remember.accepted".to_string(),
            owner: "0xowner_a".to_string(),
            namespace: "default".to_string(),
            timestamp: "2026-11-03T00:00:01Z".to_string(),
            job_id: Some("job-2".to_string()),
            blob_id: None,
            count: Some(1),
            error: None,
        });

        let post_revoke = stream.next().await;
        assert!(
            post_revoke.is_none(),
            "stream must close upon authorization revocation"
        );
    }

    #[tokio::test]
    async fn test_stream_terminates_on_deadline_expiry_without_events() {
        let hub = EventHub::new();
        let rx = hub.subscribe();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(30);

        let mut stream = Box::pin(create_event_stream_with_guards(
            rx,
            "0xowner_a".to_string(),
            None,
            None,
            Some(deadline),
            None,
            Duration::from_secs(30),
        ));

        let next = stream.next().await;
        assert!(
            next.is_none(),
            "stream must close when token lifetime expires"
        );
    }

    #[tokio::test]
    async fn test_cross_instance_event_forwarding_and_deduplication() {
        let hub_a = EventHub::new();
        let hub_b = EventHub::new();

        let mut rx_a = hub_a.subscribe();
        let mut rx_b = hub_b.subscribe();

        let (bridge_tx, mut bridge_rx) = tokio::sync::mpsc::channel::<String>(100);
        assert!(hub_b.redis_tx.set(bridge_tx).is_ok());

        let event = MemoryEvent {
            id: "evt-cross-inst".to_string(),
            event_type: "memory.remember.accepted".to_string(),
            owner: "0xowner_test".to_string(),
            namespace: "default".to_string(),
            timestamp: "2026-11-03T00:00:00Z".to_string(),
            job_id: Some("job-ci".to_string()),
            blob_id: None,
            count: Some(1),
            error: None,
        };
        hub_b.publish(event.clone());

        let local_evt = rx_b.try_recv().expect("local subscriber receives event");
        assert_eq!(local_evt.id, "evt-cross-inst");

        let payload = bridge_rx
            .try_recv()
            .expect("bridge received serialized envelope");

        let ignored_by_b = hub_b.ingest_remote_payload(&payload);
        assert!(!ignored_by_b, "hub_b must ignore its own echoed envelope");
        assert!(
            rx_b.try_recv().is_err(),
            "hub_b subscriber must not receive duplicate echoed event"
        );

        let ingested_by_a = hub_a.ingest_remote_payload(&payload);
        assert!(ingested_by_a, "hub_a must accept remote envelope");

        let remote_evt = rx_a
            .try_recv()
            .expect("hub_a subscriber receives forwarded event");
        assert_eq!(remote_evt.id, "evt-cross-inst");
    }
}

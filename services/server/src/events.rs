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
    sender: Sender<MemoryEvent>,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    pub fn new() -> Self {
        let (sender, _) = channel(1024);
        Self { sender }
    }

    pub fn subscribe(&self) -> Receiver<MemoryEvent> {
        self.sender.subscribe()
    }

    pub fn publish(&self, event: MemoryEvent) {
        let _ = self.sender.send(event);
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
        let sanitized = error.and_then(|e| {
            crate::routes::sanitize_job_error_for_client("failed", Some(e))
        });
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

pub fn create_event_stream(
    rx: Receiver<MemoryEvent>,
    owner: String,
    namespace: Option<String>,
    allowed_types: Option<HashSet<String>>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    futures::stream::unfold(rx, move |mut rx| {
        let allowed_types = allowed_types.clone();
        let namespace = namespace.clone();
        let owner = owner.clone();
        async move {
            loop {
                match rx.recv().await {
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
                        return Some((Ok(sse_event), rx));
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
                        return Some((Ok(sse_event), rx));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        return None;
                    }
                }
            }
        }
    })
}

pub async fn events_stream(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
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
                return Err(AppError::BadRequest("Event type cannot be empty".to_string()));
            }
            set.insert(trimmed.to_string());
        }
        Some(set)
    } else {
        None
    };

    let rx = state.events.subscribe();
    let stream = create_event_stream(rx, auth.owner, params.namespace, allowed_types);

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keepalive")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn test_owner_isolation() {
        let hub = EventHub::new();
        let rx = hub.subscribe();
        let mut stream = Box::pin(create_event_stream(
            rx,
            "0xowner_a".to_string(),
            None,
            None,
        ));

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
}

use super::*;
use crate::marketing_consent::tests::Logs;
use axum::{http::HeaderMap, routing::post, Json, Router};
use serde_json::Value;

const RECIPIENT: &str = "recipient-private@example.test";
const CODE: &str = "851207";
const KEY: &str = "example-key-never-logged";

fn mail() -> OutboundEmail {
    OutboundEmail::verification("0x1".into(), EmailAddress::parse(RECIPIENT).unwrap(), CODE)
}

#[test]
fn marketing_consent_delivery_config_fails_closed() {
    let parse = |network, mode: &str, key: Option<&str>, sender: Option<&str>| {
        EmailDelivery::parse(network, |name| match name {
            "EMAIL_DELIVERY_MODE" => Some(mode.into()),
            "EMAIL_PROVIDER_API_KEY" => key.map(String::from),
            "EMAIL_FROM_ADDRESS" => sender.map(String::from),
            _ => None,
        })
    };
    assert!(parse("mainnet", "log", None, None).is_err());
    assert!(matches!(
        parse("testnet", "log", None, None),
        Ok(EmailDelivery::Log)
    ));
    assert!(parse("mainnet", "provider", None, None).is_err());
    assert!(parse("mainnet", "provider", Some(KEY), None).is_err());
    let config = parse("mainnet", "provider", Some(KEY), Some("from@example.test")).unwrap();
    assert!(!format!("{config:?}").contains(KEY));
}

#[tokio::test]
async fn marketing_consent_log_delivery_masks_recipient() {
    let logs = Logs::default();
    let _subscriber = tracing::subscriber::set_default(logs.subscriber());
    LogEmailSender.send(mail()).await.unwrap();
    let text = logs.text();
    assert!(text.contains(CODE));
    assert!(text.contains("r***@example.test"));
    assert!(!text.contains("recipient-private"));
}

#[tokio::test]
async fn marketing_consent_provider_maps_status_and_redacts_rejection() {
    let client = reqwest::Client::new();
    let alerts = Arc::new(AlertManager::from_webhook_value(client.clone(), None));
    for (status, expected) in [
        (StatusCode::ACCEPTED, Ok(())),
        (StatusCode::UNAUTHORIZED, Err(EmailError::Auth)),
        (StatusCode::TOO_MANY_REQUESTS, Err(EmailError::RateLimited)),
        (StatusCode::BAD_REQUEST, Err(EmailError::Rejected)),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Err(EmailError::Transport),
        ),
    ] {
        let handler = move |headers: HeaderMap, Json(payload): Json<Value>| async move {
            assert_eq!(headers["authorization"], format!("Bearer {KEY}"));
            assert_eq!(payload["personalizations"][0]["to"][0]["email"], RECIPIENT);
            assert!(payload["content"][0]["value"]
                .as_str()
                .unwrap()
                .contains(CODE));
            (status, RECIPIENT)
        };
        let endpoint = stub(handler).await;
        let sender = provider(client.clone(), endpoint, alerts.clone());
        let logs = Logs::default();
        let _subscriber = tracing::subscriber::set_default(logs.subscriber());
        assert_eq!(sender.send(mail()).await, expected);
        let text = logs.text();
        if expected.is_err() {
            assert!(text.contains("verification email delivery failed"));
        }
        for private in [RECIPIENT, KEY, CODE] {
            assert!(!text.contains(private));
        }
    }
    let endpoint = stub(|| async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        StatusCode::ACCEPTED
    })
    .await;
    let mut sender = provider(client, endpoint, alerts);
    sender.timeout = Duration::from_millis(20);
    assert_eq!(sender.send(mail()).await, Err(EmailError::Timeout));
}

async fn stub<H, T>(handler: H) -> Url
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!(
        "http://{}/v3/mail/send",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/v3/mail/send", post(handler)),
        )
        .await
        .unwrap();
    });
    url
}

fn provider(
    client: reqwest::Client,
    endpoint: Url,
    alerts: Arc<AlertManager>,
) -> ProviderEmailSender {
    ProviderEmailSender {
        client,
        alerts,
        network: "testnet".into(),
        timeout: SEND_TIMEOUT,
        config: ProviderConfig {
            endpoint,
            api_key: Zeroizing::new(KEY.into()),
            from_address: EmailAddress::parse("from@example.test").unwrap(),
            from_name: "Walrus Memory".into(),
        },
    }
}

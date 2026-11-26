use std::borrow::Cow;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    response::Response,
    routing::post,
    Json, Router,
};
use rand::RngCore;
use serde_json::{json, Value};
use sui_crypto::{ed25519::Ed25519PrivateKey, SuiSigner};
use sui_sdk_types::{Address, PersonalMessage};
use tower::ServiceExt;

use crate::marketing_consent::{
    self, owner_session,
    tests::{Logs, TestDb},
    MarketingConsentConfig, CONFIRM_PATH, OWNER_PATH,
};
use crate::{
    mcp_rate_limit_tests::{denying_redis, rate_limit_test_config, test_state_with},
    services::email::EmailDelivery,
};

async fn send(app: &Router, path: &str, token: Option<&str>, body: Value) -> Response {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn response_json(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
}

#[tokio::test]
async fn disabled_routes_are_hidden_or_unavailable() {
    let redis = denying_redis().await;
    let pool = sqlx::PgPool::connect_lazy("postgres://memwal@127.0.0.1/memwal").unwrap();
    let mut config = rate_limit_test_config();
    let state = test_state_with(redis.clone(), pool.clone(), config.clone());
    let app = marketing_consent::owner_routes(state.clone()).with_state(state);
    let path = OWNER_PATH.replace("{owner}", "0x1");
    assert_eq!(
        send(&app, &path, None, json!({})).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, owner_session::CHALLENGE_PATH, None, json!({}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    config.marketing_consent = Some(MarketingConsentConfig::for_test());
    let state = test_state_with(redis, pool, config);
    let app = marketing_consent::owner_routes(state.clone()).with_state(state);
    let response = send(&app, &path, None, json!({})).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response_json(response).await["error"],
        "email_delivery_disabled"
    );
}

#[tokio::test]
async fn wallet_session_requests_and_confirms_email() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let Ok(redis_url) = std::env::var("TEST_REDIS_URL") else {
        db.close().await;
        eprintln!("skipping marketing consent HTTP flow: TEST_REDIS_URL is unset");
        return;
    };
    assert!(matches!(
        url::Url::parse(&redis_url).unwrap().host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]")
    ));
    let redis = redis::Client::open(redis_url)
        .unwrap()
        .get_connection_manager()
        .await
        .unwrap();
    let mut random_bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);
    let registry = Address::new(random_bytes).to_string();
    let mut cfg = rate_limit_test_config();
    cfg.sui_rpc_url = stub_chain(registry.clone()).await;
    cfg.registry_id = registry;
    cfg.package_id = "0x70".into();
    cfg.email_delivery = EmailDelivery::Log;
    cfg.marketing_consent = Some(MarketingConsentConfig::for_test());
    let state = test_state_with(redis, db.pool.clone(), cfg);
    let app = marketing_consent::owner_routes(state.clone()).with_state(state);

    rand::rngs::OsRng.fill_bytes(&mut random_bytes);
    let key = Ed25519PrivateKey::new(random_bytes);
    let probe = key
        .sign_personal_message(&PersonalMessage(Cow::Borrowed(b"test")))
        .unwrap();
    let address = probe.derive_address().to_string();
    let challenge = send(
        &app,
        owner_session::CHALLENGE_PATH,
        None,
        json!({"address": address}),
    )
    .await;
    assert_eq!(challenge.status(), StatusCode::OK);
    assert_eq!(challenge.headers()[header::CACHE_CONTROL], "no-store");
    let challenge = response_json(challenge).await;
    let signed = challenge["challenge"].as_str().unwrap();
    assert!(signed.contains("scope: marketing_consent"));
    let signature = key
        .sign_personal_message(&PersonalMessage(Cow::Borrowed(signed.as_bytes())))
        .unwrap();
    let verification = json!({"address": address, "challenge_id": challenge["challenge_id"], "signature": signature.to_base64()});
    let response = send(&app, owner_session::VERIFY_PATH, None, verification.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response_json(response).await;
    let token = session["token"].as_str().unwrap();
    assert_eq!(
        send(&app, owner_session::VERIFY_PATH, None, verification)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let email = format!("private-{}@example.test", uuid::Uuid::new_v4());
    let body = json!({"email": email, "policy_version": "v1", "source_surface": "settings"});
    let path = OWNER_PATH.replace("{owner}", &address);
    let deletion_token = crate::security_delete_auth::mint_token(
        b"deletion-secret",
        &address,
        60,
        chrono::Utc::now().timestamp(),
    );
    assert_eq!(
        send(&app, &path, Some(&deletion_token), body.clone())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(
            &app,
            &OWNER_PATH.replace("{owner}", "0x1"),
            Some(token),
            body.clone()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(
            &app,
            &path,
            Some(token),
            json!({"email": email, "policy_version": "v1", "source_surface": "invalid"})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    let logs = Logs::default();
    let _subscriber = tracing::subscriber::set_default(logs.subscriber());
    let response = send(&app, &path, Some(token), body.clone()).await;
    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "{}",
        response_json(response).await
    );
    assert_eq!(
        response_json(response).await["masked_address"],
        "p***@example.test"
    );
    let captured = logs.text();
    assert!(!captured.contains(&email));
    let code = captured
        .split_once(" code=")
        .unwrap()
        .1
        .split_whitespace()
        .next()
        .unwrap();
    assert_eq!(code.len(), 6);
    let limited = send(&app, &path, Some(token), body).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        limited.headers()[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    let response = send(
        &app,
        &CONFIRM_PATH.replace("{owner}", &address),
        Some(token),
        json!({"code": code}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["status"], "opted_in");
    let (status, verified, version): (String, bool, i64) = sqlx::query_as("SELECT status, verified_at IS NOT NULL, account_version FROM marketing_consent WHERE owner = $1")
        .bind(&address).fetch_one(&db.pool).await.unwrap();
    assert_eq!((status.as_str(), verified, version), ("opted_in", true, 12));
    db.close().await;
}

async fn stub_chain(registry: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let account = format!("0x{}", "70".repeat(32));
    let object = move |Json(body): Json<Value>| {
        let registry = registry.clone();
        let account = account.clone();
        async move {
            let id = body["params"][0].as_str().unwrap();
            let (kind, fields) = if id == registry {
                (
                    "0x70::account::AccountRegistry",
                    json!({"accounts": {"id": format!("0x{}", "71".repeat(32))}}),
                )
            } else if id == account {
                (
                    "0x70::account::MemWalAccount",
                    json!({"active": true, "delegate_keys": []}),
                )
            } else {
                ("0x2::dynamic_field::Field", json!({"value": account}))
            };
            Json(
                json!({"jsonrpc": "2.0", "id": 1, "result": {"data": {"version": "12", "content": {"type": kind, "fields": fields}}}}),
            )
        }
    };
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/", post(object)))
            .await
            .unwrap()
    });
    url
}

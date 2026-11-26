use std::{
    io,
    sync::{Arc, Mutex},
};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;

use super::{
    admin_routes, crypto, email::EmailAddress, store, ConsentStatus, MarketingConsentConfig,
    SourceSurface, WithdrawalReason,
};

const ADDRESS: &str = "consent-test-unique@example.test";

pub(crate) struct TestDb {
    pub pool: PgPool,
    setup: PgPool,
    schema: String,
}

impl TestDb {
    pub async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            eprintln!("skipping marketing consent database test: DATABASE_URL is unset");
            return None;
        };
        assert!(matches!(
            url::Url::parse(&url).unwrap().host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]")
        ));
        let setup = PgPool::connect(&url).await.unwrap();
        let schema = format!("mc_test_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&setup)
            .await
            .unwrap();
        let search_path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |conn, _| {
                let statement = search_path.clone();
                Box::pin(async move {
                    sqlx::query(&statement).execute(conn).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        for _ in 0..2 {
            sqlx::raw_sql(include_str!("../../migrations/028_marketing_consent.sql"))
                .execute(&pool)
                .await
                .unwrap();
            sqlx::raw_sql(include_str!(
                "../../migrations/029_marketing_consent_verification.sql"
            ))
            .execute(&pool)
            .await
            .unwrap();
        }
        Some(Self {
            pool,
            setup,
            schema,
        })
    }

    pub async fn close(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.setup)
            .await
            .unwrap();
        self.setup.close().await;
    }
}

#[derive(Clone, Default)]
pub(crate) struct Logs(Arc<Mutex<Vec<u8>>>);

impl io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Logs {
    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + 'static {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish()
    }

    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[test]
fn addresses_and_keys_are_redacted_and_ciphertext_is_owner_bound() {
    let config = MarketingConsentConfig::for_test();
    let email = EmailAddress::parse(" A@B.com ").unwrap();
    let envelope = crypto::encrypt(&config.encryption_key, "0x1", &email).unwrap();
    let decoded = crypto::decrypt(&config.encryption_key, "0x1", &envelope).unwrap();
    assert_eq!(decoded.masked(), "a***@b.com");
    assert_eq!(
        format!("{decoded:?} {decoded}"),
        "EmailAddress(<redacted>) EmailAddress(<redacted>)"
    );
    assert_eq!(format!("{:?}", config.encryption_key), "<redacted>");
    assert!(crypto::decrypt(&config.encryption_key, "0x2", &envelope).is_err());
    let tampered = format!("{}A", &envelope[..envelope.len() - 2]);
    assert!(crypto::decrypt(&config.encryption_key, "0x1", &tampered).is_err());
    assert!(crypto::decrypt(
        &config.encryption_key,
        "0x1",
        &envelope.replacen("v1", "v2", 1)
    )
    .is_err());
    assert_eq!(
        crypto::address_hash(&config.hash_key, &email),
        crypto::address_hash(&config.hash_key, &EmailAddress::parse("a@b.com").unwrap())
    );
    assert_ne!(
        crypto::address_hash(&config.hash_key, &email),
        crypto::address_hash(&config.encryption_key, &email)
    );
    for invalid in ["a@@b.com", "@b.com", "a@", "a@b", "a @b.com", "a\0@b.com"] {
        assert!(EmailAddress::parse(invalid).is_none());
    }
}

#[tokio::test]
async fn migration_replays_and_enforces_consent_shape() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let owner = store::owner_address("0x1").unwrap();
    let cases = [
        (
            "opted_in",
            Some("v1.encrypted"),
            &owner,
            "mc_opted_in_is_verified",
        ),
        (
            "withdrawn",
            Some("v1.encrypted"),
            &owner,
            "mc_withdrawn_drops_ciphertext",
        ),
        (
            "none",
            Some("v1.encrypted"),
            &owner,
            "mc_none_has_no_address",
        ),
        (
            "none",
            None,
            &"0x1".to_owned(),
            "marketing_consent_owner_check",
        ),
    ];
    for (status, ciphertext, owner, constraint) in cases {
        let error = sqlx::query(
            "INSERT INTO marketing_consent (owner, status, address_ciphertext) VALUES ($1,$2,$3)",
        )
        .bind(owner)
        .bind(status)
        .bind(ciphertext)
        .execute(&db.pool)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|err| err.constraint()),
            Some(constraint)
        );
    }
    db.close().await;
}

#[tokio::test]
async fn consent_lifecycle_admin_and_log_privacy() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let config = MarketingConsentConfig::for_test();
    let email = EmailAddress::parse(ADDRESS).unwrap();
    let logs = Logs::default();
    let _subscriber = tracing::subscriber::set_default(logs.subscriber());
    let owner = "0x1";
    assert!(store::get_state(&db.pool, &config, owner)
        .await
        .unwrap()
        .is_none());
    store::mark_prompt_dismissed(&db.pool, owner).await.unwrap();
    assert_eq!(
        store::get_state(&db.pool, &config, owner)
            .await
            .unwrap()
            .unwrap()
            .status,
        ConsentStatus::None
    );
    let hash = store::set_pending(
        &db.pool,
        &config,
        "0x01",
        &email,
        "v1",
        SourceSurface::Prompt,
        None,
    )
    .await
    .unwrap();
    let view = store::get_state(&db.pool, &config, owner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.status, ConsentStatus::PendingVerification);
    assert_eq!(view.masked_address.as_deref(), Some("c***@example.test"));
    let mut tx = db.pool.begin().await.unwrap();
    assert!(!store::mark_verified(&mut tx, owner, &"0".repeat(64))
        .await
        .unwrap());
    assert!(store::mark_verified(&mut tx, owner, &hash).await.unwrap());
    tx.commit().await.unwrap();
    assert!(store::get_state(&db.pool, &config, owner)
        .await
        .unwrap()
        .unwrap()
        .verified_at
        .is_some());

    let app: Router = admin_routes(&db.pool, Some(&config));
    let disabled: Router = admin_routes(&db.pool, None);
    let request = || Request::builder().uri("/api/admin/marketing-consent/0x1");
    assert_eq!(
        app.clone()
            .oneshot(request().body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        disabled
            .oneshot(request().body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    if let Ok(key) = std::env::var("ADMIN_API_KEY") {
        let response = app
            .clone()
            .oneshot(
                request()
                    .header("x-admin-api-key", &key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store, private");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["address"], ADDRESS);
        assert!(body["address_ciphertext"]
            .as_str()
            .unwrap()
            .starts_with("v1."));
    }

    let changed = EmailAddress::parse("second@example.test").unwrap();
    let new_hash = store::set_pending(
        &db.pool,
        &config,
        owner,
        &changed,
        "v2",
        SourceSurface::Settings,
        None,
    )
    .await
    .unwrap();
    assert_ne!(new_hash, hash);
    let view = store::get_state(&db.pool, &config, owner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.status, ConsentStatus::PendingVerification);
    assert!(view.verified_at.is_none());
    assert!(view.prompt_dismissed_at.is_some());
    store::withdraw(&db.pool, owner, WithdrawalReason::User)
        .await
        .unwrap();
    let record = serde_json::to_value(
        store::export(&db.pool, &config, owner)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(record["status"], "withdrawn");
    assert!(record["address"].is_null() && record["address_ciphertext"].is_null());
    assert_eq!(record["address_hash"], new_hash);
    if let Ok(key) = std::env::var("ADMIN_API_KEY") {
        let response = app
            .oneshot(
                request()
                    .method("DELETE")
                    .header("x-admin-api-key", key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    } else {
        assert!(store::erase(&db.pool, owner).await.unwrap());
    }
    assert!(!store::erase(&db.pool, owner).await.unwrap());
    let captured = logs.text();
    assert!(!captured.contains(ADDRESS));
    assert!(!captured.contains("consent-test-unique"));
    assert!(!captured.contains(&hash));
    db.close().await;
}

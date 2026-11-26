use super::*;
use crate::marketing_consent::{tests::TestDb, ConsentStatus, SourceSurface};

#[test]
fn generated_codes_are_six_digits_and_hashes_bind_the_request() {
    let cfg = MarketingConsentConfig::for_test();
    let hash = |owner, email, code| code_hash(&cfg.hash_key, owner, email, code);
    let key = hash("0x1", "address-a", "000007");
    assert_ne!(key, hash("0x2", "address-a", "000007"));
    assert_ne!(key, hash("0x1", "address-b", "000007"));
    assert_ne!(key, hash("0x1", "address-a", "000008"));
    for _ in 0..128 {
        let code = new_code();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
    }
}

#[tokio::test]
async fn replacement_expiry_attempts_and_single_use() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let cfg = MarketingConsentConfig::for_test();
    let owner = store::owner_address("0x12").unwrap();
    let revision = store::AccountRevision {
        id: store::owner_address("0x90").unwrap(),
        version: 2,
    };
    let email = EmailAddress::parse("test@example.test").unwrap();
    let (_, code) = issue(
        &db.pool,
        &cfg,
        &owner,
        &email,
        "v1",
        SourceSurface::Settings,
        &revision,
    )
    .await
    .unwrap();
    let wrong = if code == "000000" { "000001" } else { "000000" };
    for attempts_left in (0..3).rev() {
        assert_eq!(
            confirm(&db.pool, &cfg, &owner, wrong).await.unwrap(),
            ConfirmOutcome::InvalidCode { attempts_left }
        );
    }
    assert!(
        matches!(confirm(&db.pool, &cfg, &owner, &code).await, Err(AppError::BadRequest(code)) if code == "code_locked")
    );

    let email = EmailAddress::parse("other@example.test").unwrap();
    let (_, code) = issue(
        &db.pool,
        &cfg,
        &owner,
        &email,
        "v1",
        SourceSurface::Settings,
        &revision,
    )
    .await
    .unwrap();
    let (hash, stored_code, attempts): (String, String, i16) = sqlx::query_as(
        "UPDATE marketing_consent_verification SET expires_at = now() - interval '1 second' RETURNING address_hash, code_hash, attempts"
    ).fetch_one(&db.pool).await.unwrap();
    assert_eq!(hash, crypto::address_hash(&cfg.hash_key, &email));
    assert_eq!(stored_code, code_hash(&cfg.hash_key, &owner, &hash, &code));
    assert_eq!(attempts, 0);
    assert!(
        matches!(confirm(&db.pool, &cfg, &owner, &code).await, Err(AppError::BadRequest(code)) if code == "code_expired")
    );

    let (_, code) = issue(
        &db.pool,
        &cfg,
        &owner,
        &email,
        "v1",
        SourceSurface::Settings,
        &revision,
    )
    .await
    .unwrap();
    let stale = store::AccountRevision {
        id: revision.id.clone(),
        version: 1,
    };
    assert!(matches!(
        issue(
            &db.pool,
            &cfg,
            &owner,
            &email,
            "v1",
            SourceSurface::Settings,
            &stale
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    let results = tokio::join!(
        confirm(&db.pool, &cfg, &owner, &code),
        confirm(&db.pool, &cfg, &owner, &code)
    );
    assert!(
        matches!(results, (Ok(ConfirmOutcome::Verified), Err(AppError::BadRequest(code))) | (Err(AppError::BadRequest(code)), Ok(ConfirmOutcome::Verified)) if code == "code_used")
    );
    let view = store::get_state(&db.pool, &cfg, &owner)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view.status, ConsentStatus::OptedIn);
    assert!(view.verified_at.is_some());
    assert!(store::erase(&db.pool, &owner).await.unwrap());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM marketing_consent_verification")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    db.close().await;
}

//! Comprehensive Wiremock and unit integration suite for the `memwal` Rust SDK.
#![expect(
    clippy::panic_in_result_fn,
    reason = "integration tests use ? for concise setup alongside assert! macros"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use memwal::{
    AnalyzeOptions, AskOptions, DedupeMode, Env, Error, ListMemoriesOptions, ListNamespacesOptions,
    MemWal, MemWalMock, RecallManualOptions, RecallParams, RecallSort, RememberBulkItem,
    RememberBulkOptions, RememberManualOptions, RememberOptions, RememberWaitOptions,
    ScoringWeights, TruncationStrategy, WaitOptions, canonical_message, decode_sui_private_key,
    delegate_key_to_public_key_hex, delegate_key_to_sui_address, encode_sui_private_key,
};
use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TEST_KEY_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const TEST_ACCOUNT_ID: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TEST_PACKAGE_ID: &str = "0xcf6ad755a1cdff7217865c796778fabe5aa399cb0cf2eba986f4b582047229c6";
const TEST_OWNER: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn mount_standard_preflights(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "relayerVersion": "0.4.0",
            "apiVersion": "1.0.0",
            "minSupportedSdk": {
                "typescript": "0.0.4",
                "python": "0.1.0",
                "mcp": "0.0.1"
            },
            "featureFlags": {
                "auth.sealSessionHeader": true,
                "remember.asyncJobs": true
            },
            "deprecations": [],
            "build": { "commit": "deadbeef" }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packageId": TEST_PACKAGE_ID,
            "network": "localnet",
            "suiRpcUrl": format!("{}/sui-rpc", server.uri())
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/sui-rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "data": { "version": "1" }
            }
        })))
        .mount(server)
        .await;
}

fn verify_ed25519_request_headers(req: &Request, expected_path_and_query: &str) {
    let pubkey_hex = req
        .headers
        .get("x-public-key")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-public-key");
    let sig_hex = req
        .headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-signature");
    let timestamp = req
        .headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-timestamp");
    let nonce = req
        .headers
        .get("x-nonce")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-nonce");
    let account_id = req
        .headers
        .get("x-account-id")
        .and_then(|v| v.to_str().ok())
        .expect("missing x-account-id");

    assert_eq!(
        account_id, TEST_ACCOUNT_ID,
        "x-account-id header must match test account ID"
    );
    let expected_pubkey =
        delegate_key_to_public_key_hex(TEST_KEY_HEX).expect("valid test delegate key");
    assert_eq!(
        pubkey_hex, expected_pubkey,
        "x-public-key header must match derived Ed25519 public key"
    );

    let server_expected = format!(
        "{timestamp}.{}.{expected_path_and_query}.{}.{nonce}.{account_id}",
        req.method.as_str(),
        memwal::sha256_hex(&req.body),
    );
    let helper_msg = canonical_message(
        timestamp,
        req.method.as_str(),
        expected_path_and_query,
        &req.body,
        nonce,
        account_id,
    );
    assert_eq!(
        helper_msg, server_expected,
        "canonical_message output must match relayer auth format"
    );

    let pk_bytes: [u8; 32] = hex::decode(pubkey_hex)
        .expect("valid pubkey hex")
        .try_into()
        .expect("32-byte pubkey");
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .expect("valid sig hex")
        .try_into()
        .expect("64-byte sig");

    let vk = VerifyingKey::from_bytes(&pk_bytes).expect("valid verifying key");
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(server_expected.as_bytes(), &sig)
        .expect("Ed25519 signature over canonical message must verify");
}

#[test]
fn builder_redacts_secret_in_debug_and_validates_inputs() -> memwal::Result<()> {
    let mut builder = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID);
    builder.env(Env::Dev).namespace("team-alpha");

    let debug_text = format!("{builder:?}");
    assert!(
        !debug_text.contains(TEST_KEY_HEX),
        "MemWalBuilder Debug leaked raw secret key: {debug_text}"
    );
    assert!(debug_text.contains("<redacted>"));

    let client = builder.build()?;
    assert_eq!(client.server_url(), "https://relayer.dev.memwal.ai");
    assert_eq!(client.namespace(), "team-alpha");
    assert_eq!(client.account_id(), TEST_ACCOUNT_ID);

    let client_debug = format!("{client:?}");
    assert!(!client_debug.contains(TEST_KEY_HEX));

    let empty_account = MemWal::new(TEST_KEY_HEX, "   ");
    assert!(matches!(empty_account, Err(Error::InvalidArgument(_))));

    let bad_ns = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .namespace("")
        .build();
    assert!(matches!(bad_ns, Err(Error::InvalidArgument(_))));

    let bad_scheme = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url("ftp://example.com")
        .build();
    assert!(matches!(bad_scheme, Err(Error::InvalidUrl(_))));

    Ok(())
}

#[test]
fn key_formats_hex_0x_bech32_and_seed_bytes_produce_identical_identity() -> memwal::Result<()> {
    let seed: [u8; 32] = hex::decode(TEST_KEY_HEX)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let bech32 = encode_sui_private_key(&seed)?;
    let decoded = decode_sui_private_key(&bech32)?;
    assert_eq!(&*decoded, &seed);

    let prefixed = format!("0x{TEST_KEY_HEX}");
    let c_hex = MemWal::new(TEST_KEY_HEX, TEST_ACCOUNT_ID)?;
    let c_0x = MemWal::new(&prefixed, TEST_ACCOUNT_ID)?;
    let c_bech32 = MemWal::new(&bech32, TEST_ACCOUNT_ID)?;
    let c_bytes = MemWal::builder_from_seed_bytes(&seed, TEST_ACCOUNT_ID).build()?;

    let pk = c_hex.public_key_hex()?;
    assert_eq!(pk, c_0x.public_key_hex()?);
    assert_eq!(pk, c_bech32.public_key_hex()?);
    assert_eq!(pk, c_bytes.public_key_hex()?);
    assert_eq!(c_hex.sui_address()?, delegate_key_to_sui_address(&bech32)?);

    Ok(())
}

#[tokio::test]
async fn destroy_wipes_signer_and_invalidates_all_clones() -> memwal::Result<()> {
    let client = MemWal::new(TEST_KEY_HEX, TEST_ACCOUNT_ID)?;
    let cloned = client.clone();

    assert!(!client.is_destroyed());
    assert!(!cloned.is_destroyed());

    client.destroy();

    assert!(client.is_destroyed());
    assert!(cloned.is_destroyed());
    assert!(matches!(cloned.public_key_hex(), Err(Error::Destroyed)));
    assert!(matches!(cloned.sui_address(), Err(Error::Destroyed)));
    assert!(matches!(
        cloned.remember("hello").await,
        Err(Error::Destroyed)
    ));

    Ok(())
}

#[tokio::test]
async fn seal_session_verifies_package_v1_and_reuses_cached_token() -> memwal::Result<()> {
    let server = MockServer::start().await;
    mount_standard_preflights(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/remember"))
        .respond_with(|req: &Request| {
            verify_ed25519_request_headers(req, "/api/remember");
            let seal_b64 = req
                .headers
                .get("x-seal-session")
                .and_then(|v| v.to_str().ok())
                .expect("x-seal-session header must be present on /api/remember");
            let decoded = BASE64_STANDARD
                .decode(seal_b64)
                .expect("base64 ExportedSessionKey");
            let json_val: serde_json::Value =
                serde_json::from_slice(&decoded).expect("valid JSON ExportedSessionKey");
            assert_eq!(json_val["packageId"], TEST_PACKAGE_ID);
            assert_eq!(json_val["ttlMin"], 5);
            assert!(
                json_val["sessionKey"]
                    .as_str()
                    .expect("sessionKey str")
                    .starts_with("suiprivkey1")
            );
            let sig_raw = BASE64_STANDARD
                .decode(
                    json_val["personalMessageSignature"]
                        .as_str()
                        .expect("personalMessageSignature"),
                )
                .expect("base64 personal signature");
            assert_eq!(sig_raw.len(), 97);
            assert_eq!(sig_raw[0], 0x00);

            ResponseTemplate::new(202).set_body_json(json!({
                "job_id": "job_seal_1",
                "status": "pending"
            }))
        })
        .mount(&server)
        .await;

    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let r1 = client.remember("first memory").await?;
    let r2 = client.remember("second memory").await?;
    assert_eq!(r1.job_id, "job_seal_1");
    assert_eq!(r2.job_id, "job_seal_1");

    let received = server.received_requests().await.expect("requests");
    let config_calls = received
        .iter()
        .filter(|r| r.url.path() == "/config")
        .count();
    let rpc_calls = received
        .iter()
        .filter(|r| r.url.path() == "/sui-rpc")
        .count();
    let version_calls = received
        .iter()
        .filter(|r| r.url.path() == "/version")
        .count();
    assert_eq!(config_calls, 1, "/config must be cached after first call");
    assert_eq!(rpc_calls, 1, "package version 1 check must be cached");
    assert_eq!(version_calls, 1, "/version preflight must be cached");

    Ok(())
}

#[tokio::test]
async fn seal_session_rejects_upgraded_package_version_not_one() -> memwal::Result<()> {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "relayerVersion": "0.4.0",
            "apiVersion": "1.0.0"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packageId": TEST_PACKAGE_ID,
            "network": "localnet",
            "suiRpcUrl": format!("{}/sui-rpc", server.uri())
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/sui-rpc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "data": { "version": "2" } }
        })))
        .mount(&server)
        .await;

    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let err = client
        .remember("should fail before upload")
        .await
        .expect_err("package version 2 must be rejected");
    assert!(matches!(err, Error::SealSession(_)));
    assert!(err.to_string().contains("version 1"));

    Ok(())
}

struct SequenceResponder {
    counter: Arc<AtomicUsize>,
}

impl Respond for SequenceResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        assert!(
            req.headers.get("x-seal-session").is_none(),
            "status polling must not transmit x-seal-session"
        );
        verify_ed25519_request_headers(req, "/api/remember/job_poll_42");
        let step = self.counter.fetch_add(1, Ordering::SeqCst);
        match step {
            0 => ResponseTemplate::new(429)
                .insert_header("retry-after", "0.02")
                .set_body_json(json!({ "error": "rate limited" })),
            1 => ResponseTemplate::new(200).set_body_json(json!({
                "job_id": "job_poll_42",
                "status": "running",
                "owner": TEST_OWNER,
                "namespace": "work"
            })),
            _ => ResponseTemplate::new(200).set_body_json(json!({
                "job_id": "job_poll_42",
                "status": "done",
                "blob_id": "blob_walrus_99",
                "owner": TEST_OWNER,
                "namespace": "work"
            })),
        }
    }
}

#[tokio::test]
async fn remember_and_wait_recovers_from_429_and_settles_done() -> memwal::Result<()> {
    let server = MockServer::start().await;
    mount_standard_preflights(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/remember"))
        .respond_with(|req: &Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("remember JSON");
            assert_eq!(body["dedupe"], json!(true));
            assert!(
                body["idempotency_key"]
                    .as_str()
                    .expect("key")
                    .starts_with("dedupe:")
            );
            ResponseTemplate::new(202).set_body_json(json!({
                "job_id": "job_poll_42",
                "status": "pending"
            }))
        })
        .mount(&server)
        .await;

    let counter = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/api/remember/job_poll_42"))
        .respond_with(SequenceResponder {
            counter: Arc::clone(&counter),
        })
        .mount(&server)
        .await;

    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let opts = RememberWaitOptions::new()
        .with_namespace("work")
        .dedupe_by_content()
        .with_wait(
            WaitOptions::default()
                .with_poll_interval(Duration::from_millis(15))
                .with_timeout(Duration::from_secs(5)),
        );

    let res = client
        .remember_and_wait_with("Ship Rust SDK v0.1.0", &opts)
        .await?;
    assert_eq!(res.id, "job_poll_42");
    assert_eq!(res.blob_id, "blob_walrus_99");
    assert_eq!(res.namespace, "work");
    assert!(counter.load(Ordering::SeqCst) >= 3);

    Ok(())
}

#[tokio::test]
async fn remember_status_rejects_path_traversal_without_network_call() -> memwal::Result<()> {
    let server = MockServer::start().await;
    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let status = client.remember_status("../admin").await?;
    assert_eq!(status.status, "not_found");

    let wait_err = client
        .wait_for_remember_job("../admin", &WaitOptions::default())
        .await
        .expect_err("path traversal job_id must fail with JobNotFound");
    assert!(matches!(wait_err, Error::JobNotFound { .. }));

    let received = server.received_requests().await.expect("requests");
    assert_eq!(received.len(), 0);

    Ok(())
}

#[tokio::test]
async fn recall_applies_max_distance_dropped_count_sort_and_token_budgets() -> memwal::Result<()> {
    let server = MockServer::start().await;
    mount_standard_preflights(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/recall"))
        .respond_with(|req: &Request| {
            verify_ed25519_request_headers(req, "/api/recall");
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
            assert_eq!(body["sort"], "recent");
            assert_eq!(body["limit"], 5);
            ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {
                        "blob_id": "b1",
                        "text": "alpha beta",
                        "distance": 0.12,
                        "created_at": "2026-11-01T10:00:00Z"
                    },
                    {
                        "blob_id": "b2",
                        "text": "this memory is much longer than four tokens in total",
                        "distance": 0.25,
                        "created_at": "2026-11-01T09:00:00Z"
                    },
                    {
                        "blob_id": "b3",
                        "text": "far away memory",
                        "distance": 0.85,
                        "created_at": "2026-11-01T08:00:00Z"
                    }
                ],
                "total": 3,
                "dropped_count": 2
            }))
        })
        .mount(&server)
        .await;

    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let params = RecallParams::new("project alpha")
        .with_limit(5)
        .with_sort(RecallSort::Recent)
        .with_max_distance(0.5)
        .with_max_tokens(5)
        .with_truncation_strategy(TruncationStrategy::HighRelevanceOnly);

    let res = client.recall(params).await?;
    assert_eq!(res.total, 3);
    assert_eq!(res.dropped_count, 2);
    assert_eq!(res.results.len(), 1);
    assert_eq!(res.results[0].blob_id, "b1");
    let meta = res.meta.expect("token budget meta must be populated");
    assert!(meta.truncated);
    assert!(meta.token_estimate <= 5);

    // Non-finite weights and negative max_distance are rejected before signing.
    let bad_weights = ScoringWeights {
        semantic: f64::NAN,
        ..ScoringWeights::default()
    };
    let err = client
        .recall(RecallParams::new("q").with_scoring_weights(bad_weights))
        .await
        .expect_err("NaN weight must fail");
    assert!(matches!(err, Error::InvalidArgument(_)));

    let neg_dist = client
        .recall(RecallParams::new("q").with_max_distance(-0.1))
        .await
        .expect_err("negative max_distance must fail");
    assert!(matches!(neg_dist, Error::InvalidArgument(_)));

    Ok(())
}

#[tokio::test]
async fn analyze_and_wait_chunks_status_polls_over_twenty_jobs() -> memwal::Result<()> {
    let server = MockServer::start().await;
    mount_standard_preflights(&server).await;

    let job_ids: Vec<String> = (0..25).map(|i| format!("fact_job_{i}")).collect();
    let facts_json: Vec<serde_json::Value> = (0..25)
        .map(|i| {
            json!({
                "id": format!("fact_job_{i}"),
                "job_id": format!("fact_job_{i}"),
                "text": format!("Fact number {i}")
            })
        })
        .collect();

    let expected_jobs = job_ids.clone();
    Mock::given(method("POST"))
        .and(path("/api/analyze"))
        .respond_with(move |req: &Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
            assert_eq!(body["occurred_at"], "2026-05-25T17:50:00.000Z");
            ResponseTemplate::new(202).set_body_json(json!({
                "job_ids": expected_jobs,
                "facts": facts_json,
                "fact_count": 25,
                "status": "pending",
                "owner": TEST_OWNER
            }))
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/remember/bulk/status"))
        .respond_with(|req: &Request| {
            assert!(req.headers.get("x-seal-session").is_none());
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
            let ids = body["job_ids"].as_array().expect("job_ids array");
            assert!(
                ids.len() <= 20,
                "bulk status poll must chunk into <= 20 job_ids, got {}",
                ids.len()
            );
            let items: Vec<serde_json::Value> = ids
                .iter()
                .map(|id| {
                    let s = id.as_str().expect("id");
                    json!({
                        "job_id": s,
                        "status": "done",
                        "blob_id": format!("blob_for_{s}"),
                        "namespace": "conv"
                    })
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(json!({ "results": items }))
        })
        .mount(&server)
        .await;

    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let analyze_opts = AnalyzeOptions::new()
        .with_namespace("conv")
        .with_occurred_at("2026-05-25T19:50:00+02:00");
    let wait_opts = WaitOptions::default_bulk().with_poll_interval(Duration::from_millis(10));

    let res = client
        .analyze_and_wait("Long multi-fact transcript", &analyze_opts, &wait_opts)
        .await?;
    assert_eq!(res.total, 25);
    assert_eq!(res.succeeded, 25);
    assert_eq!(res.failed, 0);
    assert_eq!(res.timed_out, 0);
    assert_eq!(res.facts.len(), 25);

    Ok(())
}

#[tokio::test]
async fn owner_scoped_reads_sign_query_string_and_memoize_owner() -> memwal::Result<()> {
    let server = MockServer::start().await;
    mount_standard_preflights(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/stats"))
        .respond_with(|req: &Request| {
            assert!(req.headers.get("x-seal-session").is_none());
            verify_ed25519_request_headers(req, "/api/stats");
            ResponseTemplate::new(200).set_body_json(json!({
                "memory_count": 4,
                "storage_bytes": 512,
                "namespace": "default",
                "owner": TEST_OWNER
            }))
        })
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/v1/owners/.+/namespaces$"))
        .respond_with(|req: &Request| {
            assert!(req.headers.get("x-seal-session").is_none());
            let pq = match req.url.query() {
                Some(q) => format!("{}?{q}", req.url.path()),
                None => req.url.path().to_owned(),
            };
            verify_ed25519_request_headers(req, &pq);
            ResponseTemplate::new(200).set_body_json(json!({
                "namespaces": [
                    {
                        "id": "ns_1",
                        "name": "work",
                        "memory_count": 3,
                        "storage_used": 384,
                        "updated_at": "2026-11-01T12:00:00Z"
                    }
                ],
                "next_cursor": "cursor_tok_1",
                "has_more": false,
                "snapshot_version": 9
            }))
        })
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/v1/owners/.+/memories$"))
        .respond_with(|req: &Request| {
            assert!(req.headers.get("x-seal-session").is_none());
            ResponseTemplate::new(200).set_body_json(json!({
                "memories": [
                    {
                        "memory_id": "m1",
                        "namespace_id": "work",
                        "blob_id": "b1",
                        "created_at": "2026-11-01T12:00:00Z",
                        "updated_at": "2026-11-01T12:00:00Z",
                        "size": 128,
                        "status": "indexed"
                    },
                    {
                        "memory_id": "m2",
                        "namespace_id": "personal",
                        "blob_id": "b2",
                        "created_at": "2026-11-01T12:01:00Z",
                        "updated_at": "2026-11-01T12:01:00Z",
                        "size": 64,
                        "status": "indexed"
                    }
                ],
                "next_cursor": "cursor_mem_2",
                "has_more": true,
                "snapshot_version": 9
            }))
        })
        .mount(&server)
        .await;

    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let ns_page = client
        .list_namespaces(
            &ListNamespacesOptions::new()
                .with_cursor("2026-10-01T00:00:00Z|ns_0")
                .with_limit(25),
        )
        .await?;
    assert_eq!(ns_page.namespaces.len(), 1);
    assert_eq!(ns_page.namespaces[0].name, "work");

    let mem_page = client
        .list_memories(&ListMemoriesOptions::new().with_namespace("work"))
        .await?;
    assert_eq!(mem_page.memories.len(), 1);
    assert_eq!(mem_page.memories[0].memory_id, "m1");
    assert!(mem_page.has_more);

    let received = server.received_requests().await.expect("requests");
    let stats_calls = received
        .iter()
        .filter(|r| r.url.path() == "/api/stats")
        .count();
    assert_eq!(stats_calls, 1);

    Ok(())
}

#[tokio::test]
async fn manual_endpoints_omit_seal_session_and_reject_nan_vectors() -> memwal::Result<()> {
    let server = MockServer::start().await;
    mount_standard_preflights(&server).await;

    Mock::given(method("POST"))
        .and(path("/api/remember/manual"))
        .respond_with(|req: &Request| {
            assert!(
                req.headers.get("x-seal-session").is_none(),
                "remember_manual must never send x-seal-session"
            );
            let body: serde_json::Value = serde_json::from_slice(&req.body).expect("json");
            assert_eq!(body["encrypted_data"], "YWJjMTIz");
            assert_eq!(body["namespace"], "manual-ns");
            ResponseTemplate::new(200).set_body_json(json!({
                "id": "manual_1",
                "blob_id": "blob_manual_1",
                "owner": TEST_OWNER,
                "namespace": "manual-ns"
            }))
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/recall/manual"))
        .respond_with(|req: &Request| {
            assert!(
                req.headers.get("x-seal-session").is_none(),
                "recall_manual must never send x-seal-session"
            );
            ResponseTemplate::new(200).set_body_json(json!({
                "results": [{ "blob_id": "blob_manual_1", "distance": 0.04 }],
                "total": 1
            }))
        })
        .mount(&server)
        .await;

    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let manual_saved = client
        .remember_manual(
            &RememberManualOptions::new("YWJjMTIz", vec![0.1, 0.2, 0.3])
                .with_namespace("manual-ns"),
        )
        .await?;
    assert_eq!(manual_saved.blob_id, "blob_manual_1");

    let nan_vec_err = client
        .remember_manual(&RememberManualOptions::new("YWJjMTIz", vec![f32::NAN]))
        .await
        .expect_err("NaN vector must fail before signing");
    assert!(matches!(nan_vec_err, Error::InvalidArgument(_)));

    let manual_hits = client
        .recall_manual(&RecallManualOptions::new(vec![0.1, 0.2, 0.3]).with_limit(5))
        .await?;
    assert_eq!(manual_hits.results.len(), 1);

    Ok(())
}

#[tokio::test]
async fn auxiliary_endpoints_embed_ask_restore_forget_and_whoami() -> memwal::Result<()> {
    let server = MockServer::start().await;
    let graphql = MockServer::start().await;
    mount_standard_preflights(&server).await;

    Mock::given(method("GET"))
        .and(path("/config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packageId": TEST_PACKAGE_ID,
            "network": "localnet",
            "suiRpcUrl": graphql.uri()
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "data": { "version": "1" } }
        })))
        .mount(&graphql)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/embed"))
        .respond_with(|req: &Request| {
            assert!(req.headers.get("x-seal-session").is_none());
            ResponseTemplate::new(200).set_body_json(json!({
                "vector": [0.1, 0.2, 0.3]
            }))
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/forget"))
        .respond_with(|req: &Request| {
            assert!(req.headers.get("x-seal-session").is_none());
            ResponseTemplate::new(200).set_body_json(json!({
                "deleted": 3,
                "namespace": "work",
                "owner": TEST_OWNER
            }))
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/ask"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "answer": "You work on Rust SDKs.",
            "memories_used": 1,
            "memories": [{
                "blob_id": "b1",
                "text": "Works on Rust SDKs",
                "distance": 0.09
            }]
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/api/restore"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "restored": 2,
            "skipped": 1,
            "total": 3,
            "namespace": "work",
            "owner": TEST_OWNER
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/whoami"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "account_id": TEST_ACCOUNT_ID,
            "owner": TEST_OWNER,
            "package_id": TEST_PACKAGE_ID
        })))
        .mount(&server)
        .await;

    let client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(server.uri())
        .build()?;

    let embedded = client.embed("vectorize me").await?;
    assert_eq!(embedded.vector.len(), 3);

    let asked = client.ask("What do I work on?", &AskOptions::new()).await?;
    assert_eq!(asked.memories_used, 1);

    let restored = client.restore("work", 10).await?;
    assert_eq!(restored.restored, 2);
    assert_eq!(restored.failed, 0);
    assert!(!restored.truncated);

    let forgotten = client.forget(Some("work")).await?;
    assert_eq!(forgotten.deleted, 3);

    let who = client.whoami().await?;
    assert_eq!(who.owner, TEST_OWNER);

    Ok(())
}

#[tokio::test]
async fn compatibility_rejects_unsupported_api_major_and_detects_clock_drift() -> memwal::Result<()>
{
    let bad_major_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "relayerVersion": "2.0.0",
            "apiVersion": "2.0.0"
        })))
        .mount(&bad_major_server)
        .await;

    let bad_client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(bad_major_server.uri())
        .build()?;
    let compat_err = bad_client
        .compatibility()
        .await
        .expect_err("API v2.0.0 must be rejected");
    assert!(matches!(compat_err, Error::Incompatible { .. }));

    // Clock drift classification + /version 404 fallback to /health.
    let drift_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/version"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&drift_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "status": "ok",
            "version": "0.4.0",
            "apiVersion": "1.0.0"
        })))
        .mount(&drift_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/embed"))
        .respond_with(
            ResponseTemplate::new(401)
                .insert_header("x-auth-error", "timestamp_expired")
                .set_body_json(json!({ "error": "request timestamp out of range" })),
        )
        .mount(&drift_server)
        .await;

    let drift_client = MemWal::builder(TEST_KEY_HEX, TEST_ACCOUNT_ID)
        .server_url(drift_server.uri())
        .build()?;
    let drift_err = drift_client
        .embed("test clock drift")
        .await
        .expect_err("clock drift 401 must surface as Error::ClockDrift");
    assert!(matches!(drift_err, Error::ClockDrift { .. }));

    Ok(())
}

#[tokio::test]
async fn memwal_mock_supports_full_offline_lifecycle() -> memwal::Result<()> {
    let mock = MemWalMock::with_namespace("agent-test");

    let r1 = mock
        .remember_and_wait_with(
            "User lives in Hanoi and drinks espresso",
            &RememberWaitOptions::new().dedupe_by_content(),
        )
        .await?;
    let r2 = mock
        .remember_and_wait_with(
            "User lives in Hanoi and drinks espresso",
            &RememberWaitOptions::new().dedupe_by_content(),
        )
        .await?;
    assert_eq!(
        r1.blob_id, r2.blob_id,
        "content-hash dedupe in MemWalMock must reuse existing entry"
    );

    let batch = mock
        .remember_bulk_and_wait(
            &[
                RememberBulkItem::from("Prefers Rust edition 2024"),
                RememberBulkItem::new("Uses Sui testnet").with_namespace("chain"),
            ],
            &RememberBulkOptions::new(),
        )
        .await?;
    assert_eq!(batch.succeeded, 2);

    let recalled = mock.recall("espresso in Hanoi").await?;
    assert_eq!(recalled.results.len(), 2);
    assert!(recalled.results[0].text.contains("espresso"));

    let ns_page = mock.list_namespaces(&ListNamespacesOptions::new()).await?;
    assert_eq!(ns_page.namespaces.len(), 2);

    let forgotten = mock.forget(None).await?;
    assert_eq!(forgotten.deleted, 2);

    let mem_page = mock
        .list_memories(&ListMemoriesOptions::new().with_namespace("agent-test"))
        .await?;
    assert_eq!(mem_page.memories.len(), 0);
    assert_eq!(mem_page.deleted.len(), 2);

    let _ = RememberOptions::new().with_dedupe(DedupeMode::RetryWindow);
    mock.destroy();
    assert!(matches!(
        mock.recall("espresso").await,
        Err(Error::Destroyed)
    ));

    Ok(())
}

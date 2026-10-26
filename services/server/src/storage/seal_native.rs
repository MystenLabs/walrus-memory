//! In-process Rust SEAL encryption, session certificate caching, key-server committee
//! resolution, and batched threshold IBE decryption.
//!
//! Replaces `services/server/scripts/sidecar/routes/seal.ts`, `seal-ptb.ts`, and
//! `seal-identity.ts` using `seal-sdk` and `seal-crypto` (`MystenLabs/seal`).

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
use fastcrypto::encoding::{Base64 as FcBase64, Encoding as _};
use fastcrypto::groups::bls12381::G2Element;
use fastcrypto::serde_helpers::ToFromByteArray as _;
use fastcrypto::traits::{KeyPair as _, Signer as _, ToFromBytes as _};
use rand::thread_rng;
use seal_crypto::{
    seal_encrypt as crypto_seal_encrypt, EncryptedObject, EncryptionInput, IBEPublicKeys, ObjectID,
};
use seal_sdk::{
    decrypt_seal_responses, genkey, seal_decrypt_object, signed_message,
    types::FetchKeyResponse,
    IBEPublicKey,
};
use serde::{Deserialize, Serialize};
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{BatchGetObjectsRequest, GetObjectRequest};
use sui_sdk_types::{
    Address, Digest, Identifier, ObjectData, ProgrammableTransaction, TransactionKind, TypeTag,
};
use sui_transaction_builder::{Function, ObjectInput, TransactionBuilder};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::storage::seal::{DecryptOutcome, SealCredential};
use crate::storage::walrus_native::get_native_runtime_config;
use crate::sui::enoki::{
    derive_sui_address, parse_sui_private_key_bytes, sign_personal_message_bytes,
};
use crate::types::AppError;

const TESTNET_DEFAULT_SEAL_SERVERS: &[(&str, u8)] = &[
    (
        "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75",
        1,
    ),
    (
        "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8",
        1,
    ),
];

const SESSION_TTL_MIN: u16 = 10;
const SESSION_CACHE_DURATION: Duration = Duration::from_secs(9 * 60);

// ---------------------------------------------------------------------------
// 1. SEAL Identity Derivation (`[32B owner || 8B LE access_counter_version]`)
// ---------------------------------------------------------------------------

/// Derives the 40-byte SEAL identity (`[32-byte owner address || 8-byte LE access_counter_version]`)
/// matching `buildSealEncryptId` in `services/server/scripts/sidecar/seal-identity.ts` and
/// `contracts/memwal/sources/account.move`.
pub fn derive_seal_id(
    owner: &str,
    access_counter_version: u64,
) -> Result<(String, Vec<u8>), String> {
    let owner_addr: Address = owner
        .trim()
        .parse()
        .map_err(|e| format!("invalid owner Sui address '{owner}': {e}"))?;
    let mut id_bytes = Vec::with_capacity(40);
    id_bytes.extend_from_slice(owner_addr.inner());
    id_bytes.extend_from_slice(&access_counter_version.to_le_bytes());
    let id_hex = hex::encode(&id_bytes);
    Ok((id_hex, id_bytes))
}

// ---------------------------------------------------------------------------
// 2. Committee Configuration, Expected Identity Guard & On-Chain KeyServer Fetch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfiguredKeyServerSpec {
    #[serde(alias = "objectId", alias = "object_id")]
    pub object_id: String,
    #[serde(default = "default_weight")]
    pub weight: u8,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default, alias = "publicKey", alias = "public_key", alias = "pk")]
    pub public_key_hex: Option<String>,
}

fn default_weight() -> u8 {
    1
}

#[derive(Debug, Clone)]
pub struct ResolvedKeyServer {
    pub object_id: ObjectID,
    pub weight: u8,
    pub name: String,
    pub url: String,
    pub pk: IBEPublicKey,
}

#[derive(Deserialize)]
struct MoveField<K, V> {
    #[allow(dead_code)]
    id: Address,
    #[allow(dead_code)]
    name: K,
    value: V,
}

#[derive(Deserialize)]
struct MoveKeyServerV1 {
    name: String,
    url: String,
    #[allow(dead_code)]
    key_type: u8,
    pk: Vec<u8>,
}

#[derive(Deserialize)]
enum MoveServerTypeV2 {
    Independent {
        url: String,
    },
    Committee {
        #[allow(dead_code)]
        version: u32,
        #[allow(dead_code)]
        threshold: u16,
    },
}

#[derive(Deserialize)]
struct MoveKeyServerV2 {
    name: String,
    #[allow(dead_code)]
    key_type: u8,
    pk: Vec<u8>,
    server_type: MoveServerTypeV2,
}

fn parse_configured_key_servers() -> (Vec<ConfiguredKeyServerSpec>, u8) {
    let threshold = std::env::var("SEAL_THRESHOLD")
        .ok()
        .and_then(|v| v.trim().parse::<u8>().ok())
        .filter(|&t| t > 0)
        .unwrap_or(2);

    if let Ok(raw) = std::env::var("SEAL_KEY_SERVERS") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            if let Ok(specs) = serde_json::from_str::<Vec<ConfiguredKeyServerSpec>>(trimmed) {
                if !specs.is_empty() {
                    return (specs, threshold);
                }
            }
            // Also accept comma-separated object IDs.
            let specs: Vec<_> = trimmed
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|id| ConfiguredKeyServerSpec {
                    object_id: id.to_owned(),
                    weight: 1,
                    url: None,
                    public_key_hex: None,
                })
                .collect();
            if !specs.is_empty() {
                return (specs, threshold);
            }
        }
    }

    let specs = TESTNET_DEFAULT_SEAL_SERVERS
        .iter()
        .map(|&(id, weight)| ConfiguredKeyServerSpec {
            object_id: id.to_owned(),
            weight,
            url: None,
            public_key_hex: None,
        })
        .collect();
    (specs, threshold)
}

/// Validates `expected_committee_identity` against the configured key servers and threshold,
/// matching `sealEncryptCommitteeFailure` in `services/server/scripts/sidecar/routes/seal.ts`.
pub fn validate_expected_committee_identity(
    expected: Option<&serde_json::Value>,
    specs: &[ConfiguredKeyServerSpec],
    threshold: u8,
) -> Result<(), String> {
    let Some(expected_val) = expected else {
        return Ok(());
    };
    let expected_threshold = expected_val
        .get("threshold")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "expected_committee_identity is missing numeric 'threshold'".to_owned())?;
    if expected_threshold != u64::from(threshold) {
        return Err(format!(
            "SEAL_COMMITTEE_MISMATCH: expected threshold {expected_threshold}, configured {threshold}"
        ));
    }

    let servers_arr = expected_val
        .get("servers")
        .or_else(|| expected_val.get("keyServers"))
        .or_else(|| expected_val.get("key_servers"))
        .and_then(|v| v.as_array());
    if let Some(expected_servers) = servers_arr {
        if expected_servers.len() != specs.len() {
            return Err(format!(
                "SEAL_COMMITTEE_MISMATCH: expected {} servers, configured {}",
                expected_servers.len(),
                specs.len()
            ));
        }
        for (exp, actual) in expected_servers.iter().zip(specs.iter()) {
            let exp_id_str = exp
                .get("objectId")
                .or_else(|| exp.get("object_id"))
                .and_then(|v| v.as_str())
                .or_else(|| exp.as_str())
                .ok_or_else(|| {
                    "invalid keyServer entry in expected_committee_identity".to_owned()
                })?;
            let exp_addr: Address = exp_id_str
                .parse()
                .map_err(|e| format!("invalid expected key server address '{exp_id_str}': {e}"))?;
            let act_addr: Address = actual.object_id.parse().map_err(|e| {
                format!(
                    "invalid configured key server address '{}': {e}",
                    actual.object_id
                )
            })?;
            if exp_addr != act_addr {
                return Err(format!(
                    "SEAL_COMMITTEE_MISMATCH: expected key server {exp_addr}, configured {act_addr}"
                ));
            }
        }
    }
    Ok(())
}

struct TimedCommittee {
    servers: Vec<ResolvedKeyServer>,
    threshold: u8,
    fetched_at: Instant,
}

static SEAL_COMMITTEE_CACHE: OnceLock<RwLock<Option<TimedCommittee>>> = OnceLock::new();

fn parse_bls_g2_pk(bytes: &[u8]) -> Result<IBEPublicKey, String> {
    let arr: &[u8; 96] = bytes.try_into().map_err(|_| {
        format!(
            "expected 96-byte BLS12-381 G2 public key, got {} bytes",
            bytes.len()
        )
    })?;
    G2Element::from_byte_array(arr).map_err(|e| format!("invalid BLS12-381 G2 public key: {e}"))
}

pub async fn resolve_seal_key_servers(
    grpc_url: &str,
    expected_committee_identity: Option<&serde_json::Value>,
) -> Result<(Vec<ResolvedKeyServer>, u8), String> {
    let (specs, threshold) = parse_configured_key_servers();
    validate_expected_committee_identity(expected_committee_identity, &specs, threshold)?;

    // Check if all specs already provide inline URL + public_key_hex (e.g. unit tests / offline overrides).
    if specs
        .iter()
        .all(|s| s.url.is_some() && s.public_key_hex.is_some())
    {
        let mut resolved = Vec::with_capacity(specs.len());
        for s in &specs {
            let object_id: ObjectID = s
                .object_id
                .parse()
                .map_err(|e| format!("invalid key server object_id '{}': {e}", s.object_id))?;
            let pk_hex = s.public_key_hex.as_deref().unwrap().trim();
            let pk_bytes = hex::decode(pk_hex.strip_prefix("0x").unwrap_or(pk_hex))
                .map_err(|e| format!("invalid key server public_key hex: {e}"))?;
            let pk = parse_bls_g2_pk(&pk_bytes)?;
            resolved.push(ResolvedKeyServer {
                object_id,
                weight: s.weight,
                name: s.object_id.clone(),
                url: s.url.clone().unwrap(),
                pk,
            });
        }
        return Ok((resolved, threshold));
    }

    let cache = SEAL_COMMITTEE_CACHE.get_or_init(|| RwLock::new(None));
    if let Some(cached) = cache.read().await.as_ref() {
        if cached.fetched_at.elapsed() < Duration::from_secs(300) {
            return Ok((cached.servers.clone(), cached.threshold));
        }
    }

    let mut client = sui_rpc::Client::new(grpc_url)
        .map_err(|e| format!("invalid Sui gRPC URL '{grpc_url}': {e}"))?;

    let v1_key_bcs = bcs::to_bytes(&1u64).unwrap();
    let v2_key_bcs = bcs::to_bytes(&2u64).unwrap();

    let mut resolved = Vec::with_capacity(specs.len());
    for spec in &specs {
        let ks_addr: Address = spec
            .object_id
            .parse()
            .map_err(|e| format!("invalid SEAL key server objectId '{}': {e}", spec.object_id))?;
        let ks_obj_id = ObjectID::new(*ks_addr.inner());

        let v1_field_id = ks_addr.derive_dynamic_child_id(&TypeTag::U64, &v1_key_bcs);
        let v2_field_id = ks_addr.derive_dynamic_child_id(&TypeTag::U64, &v2_key_bcs);

        let mut batch_req = BatchGetObjectsRequest::default();
        for id in [v1_field_id, v2_field_id] {
            let mut r = GetObjectRequest::default();
            r.object_id = Some(id.to_string());
            batch_req.requests.push(r);
        }
        batch_req.read_mask = Some(FieldMask::from_paths(["object_id", "bcs"]));

        let batch_resp = client
            .ledger_client()
            .batch_get_objects(batch_req)
            .await
            .map_err(|e| format!("BatchGetObjects for SEAL KeyServer {ks_addr} failed: {e}"))?
            .into_inner();

        let mut extracted: Option<(String, String, Vec<u8>)> = None;
        for res in batch_resp.objects {
            let Some(sui_rpc::proto::sui::rpc::v2::get_object_result::Result::Object(proto_obj)) =
                res.result
            else {
                continue;
            };
            let Some(bcs_proto) = proto_obj.bcs else {
                continue;
            };
            let Ok(sdk_obj) = bcs_proto.deserialize::<sui_sdk_types::Object>() else {
                continue;
            };
            let ObjectData::Struct(move_struct) = sdk_obj.data() else {
                continue;
            };
            let contents = move_struct.contents();

            if let Ok(field_v1) = bcs::from_bytes::<MoveField<u64, MoveKeyServerV1>>(contents) {
                extracted = Some((field_v1.value.name, field_v1.value.url, field_v1.value.pk));
                break;
            }
            if let Ok(field_v2) = bcs::from_bytes::<MoveField<u64, MoveKeyServerV2>>(contents) {
                let url = match field_v2.value.server_type {
                    MoveServerTypeV2::Independent { url } => url,
                    MoveServerTypeV2::Committee { .. } => spec.url.clone().unwrap_or_default(),
                };
                extracted = Some((field_v2.value.name, url, field_v2.value.pk));
                break;
            }
        }

        let (name, url, pk_bytes) = extracted.ok_or_else(|| {
            format!("SEAL KeyServer {ks_addr} has neither V1 nor V2 dynamic field on chain")
        })?;
        let pk = parse_bls_g2_pk(&pk_bytes)?;

        resolved.push(ResolvedKeyServer {
            object_id: ks_obj_id,
            weight: spec.weight,
            name,
            url: spec.url.clone().unwrap_or(url),
            pk,
        });
    }

    *cache.write().await = Some(TimedCommittee {
        servers: resolved.clone(),
        threshold,
        fetched_at: Instant::now(),
    });

    Ok((resolved, threshold))
}

// ---------------------------------------------------------------------------
// 3. On-Chain `MemWalAccount` Reader & `seal_approve` PTB Builder
// ---------------------------------------------------------------------------

fn prost_to_json(value: &prost_types::Value) -> serde_json::Value {
    use prost_types::value::Kind;
    match &value.kind {
        Some(Kind::NullValue(_)) | None => serde_json::Value::Null,
        Some(Kind::NumberValue(n))
            if n.fract() == 0.0 && n.is_finite() && *n >= 0.0 && *n <= 9007199254740992.0 =>
        {
            serde_json::json!(*n as i64)
        }
        Some(Kind::NumberValue(n)) => serde_json::json!(n),
        Some(Kind::StringValue(s)) => serde_json::Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => serde_json::Value::Bool(*b),
        Some(Kind::StructValue(s)) => serde_json::Value::Object(
            s.fields
                .iter()
                .map(|(k, v)| (k.clone(), prost_to_json(v)))
                .collect(),
        ),
        Some(Kind::ListValue(l)) => {
            serde_json::Value::Array(l.values.iter().map(prost_to_json).collect())
        }
    }
}

/// Reads and validates the `MemWalAccount` encryption identity fresh from chain,
/// matching `fetchSealEncryptIdentity` in `services/server/scripts/sidecar/seal-identity.ts`.
pub async fn fetch_seal_encrypt_identity(
    grpc_url: &str,
    account_id: &str,
    expected_owner: &str,
    immutable_package_id: &str,
) -> Result<u64, String> {
    let expected_owner_addr: Address = expected_owner
        .trim()
        .parse()
        .map_err(|e| format!("invalid expected owner '{expected_owner}': {e}"))?;
    let expected_pkg_addr: Address = immutable_package_id
        .trim()
        .parse()
        .map_err(|e| format!("invalid package_id '{immutable_package_id}': {e}"))?;

    let mut client = sui_rpc::Client::new(grpc_url)
        .map_err(|e| format!("invalid Sui gRPC URL '{grpc_url}': {e}"))?;

    let mut req = GetObjectRequest::default();
    req.object_id = Some(account_id.to_owned());
    req.read_mask = Some(FieldMask::from_paths(["object_id", "object_type", "json"]));

    let obj = client
        .ledger_client()
        .get_object(req)
        .await
        .map_err(|e| format!("GetObject({account_id}) failed: {e}"))?
        .into_inner()
        .object
        .ok_or_else(|| format!("MemWalAccount {account_id} not found on chain"))?;

    let obj_type = obj.object_type.as_deref().unwrap_or_default();
    let type_parts: Vec<&str> = obj_type.split("::").collect();
    let pkg_matches = type_parts.len() == 3
        && type_parts[0].parse::<Address>().ok() == Some(expected_pkg_addr)
        && type_parts[1] == "account"
        && type_parts[2] == "MemWalAccount";
    if !pkg_matches {
        return Err(format!(
            "object {account_id} is not a {expected_pkg_addr}::account::MemWalAccount (found '{obj_type}')"
        ));
    }

    let json = obj
        .json
        .as_deref()
        .map(prost_to_json)
        .ok_or_else(|| format!("MemWalAccount {account_id} missing json representation"))?;

    let owner_str = json
        .get("owner")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("account {account_id} has no owner field"))?;
    let onchain_owner: Address = owner_str
        .parse()
        .map_err(|e| format!("account {account_id} has invalid owner '{owner_str}': {e}"))?;
    if onchain_owner != expected_owner_addr {
        return Err(format!(
            "account {account_id} owner ({onchain_owner}) does not match request owner ({expected_owner_addr})"
        ));
    }

    let active = json
        .get("active")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| format!("account {account_id} has no valid active field"))?;
    let admin_quarantined = json
        .get("admin_quarantined")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| format!("account {account_id} has no valid admin_quarantined field"))?;
    if admin_quarantined {
        return Err(format!("account {account_id} is admin quarantined"));
    }
    if !active {
        return Err(format!("account {account_id} is not active"));
    }

    let counter = json
        .get("access_counter_version")
        .and_then(|v| match v {
            serde_json::Value::Number(n) => n.as_u64(),
            serde_json::Value::String(s) => s.parse().ok(),
            _ => None,
        })
        .ok_or_else(|| {
            format!("account {account_id} has no access_counter_version field")
        })?;

    Ok(counter)
}

static SHARED_OBJECT_INITIAL_VERSIONS: OnceLock<std::sync::RwLock<HashMap<String, u64>>> =
    OnceLock::new();

pub async fn fetch_shared_object_versions(
    grpc_url: &str,
    account_id: &str,
    registry_id: &str,
) -> Result<(u64, u64), String> {
    let cache = SHARED_OBJECT_INITIAL_VERSIONS.get_or_init(|| std::sync::RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let (Some(&acct_ver), Some(&reg_ver)) = (guard.get(account_id), guard.get(registry_id)) {
            return Ok((acct_ver, reg_ver));
        }
    }

    let mut client = sui_rpc::Client::new(grpc_url)
        .map_err(|e| format!("invalid Sui gRPC URL '{grpc_url}': {e}"))?;

    let mut batch_req = BatchGetObjectsRequest::default();
    for id in [account_id, registry_id] {
        let mut r = GetObjectRequest::default();
        r.object_id = Some(id.to_owned());
        batch_req.requests.push(r);
    }
    batch_req.read_mask = Some(FieldMask::from_paths(["object_id", "owner"]));

    let resp = client
        .ledger_client()
        .batch_get_objects(batch_req)
        .await
        .map_err(|e| format!("BatchGetObjects for MemWalAccount/AccountRegistry failed: {e}"))?
        .into_inner();

    let acct_obj = resp
        .objects
        .first()
        .and_then(|r| match &r.result {
            Some(sui_rpc::proto::sui::rpc::v2::get_object_result::Result::Object(o)) => Some(o),
            _ => None,
        })
        .ok_or_else(|| format!("MemWalAccount {account_id} not found on chain"))?;

    let reg_obj = resp
        .objects
        .get(1)
        .and_then(|r| match &r.result {
            Some(sui_rpc::proto::sui::rpc::v2::get_object_result::Result::Object(o)) => Some(o),
            _ => None,
        })
        .ok_or_else(|| format!("AccountRegistry {registry_id} not found on chain"))?;

    let acct_shared_ver = acct_obj
        .owner
        .as_ref()
        .and_then(|o| o.version)
        .unwrap_or(1);
    let reg_shared_ver = reg_obj
        .owner
        .as_ref()
        .and_then(|o| o.version)
        .unwrap_or(1);

    if let Ok(mut guard) = cache.write() {
        guard.insert(account_id.to_owned(), acct_shared_ver);
        guard.insert(registry_id.to_owned(), reg_shared_ver);
    }

    Ok((acct_shared_ver, reg_shared_ver))
}

/// Builds a `ProgrammableTransaction` containing `account::seal_approve(id, registry, account)`
/// calls for each `seal_id` in `id_bytes_list`.
///
/// Mirrors `buildSealApproveTx` in `services/server/scripts/sidecar/seal-ptb.ts` (`v1-new` 3-arg ABI:
/// `[id, registry, account]`) and satisfies all `ValidPtb` constraints in `MystenLabs/seal`
/// (`crates/key-server/src/valid_ptb.rs`).
pub fn build_seal_approve_ptb(
    policy_package_id: Address,
    registry_id: Address,
    registry_initial_shared_version: u64,
    account_id: Address,
    account_initial_shared_version: u64,
    id_bytes_list: &[Vec<u8>],
) -> Result<ProgrammableTransaction, String> {
    if id_bytes_list.is_empty() {
        return Err("cannot build empty seal_approve PTB".to_owned());
    }

    let mut builder = TransactionBuilder::new();
    let registry_arg = builder.object(ObjectInput::shared(
        registry_id,
        registry_initial_shared_version,
        false,
    ));
    let account_arg = builder.object(ObjectInput::shared(
        account_id,
        account_initial_shared_version,
        false,
    ));

    for id_bytes in id_bytes_list {
        let id_arg = builder.pure_unique(id_bytes);
        builder.move_call(
            Function::new(
                policy_package_id,
                Identifier::from_static("account"),
                Identifier::from_static("seal_approve"),
            ),
            vec![id_arg, registry_arg, account_arg],
        );
    }

    builder.set_sender(Address::ZERO);
    builder.set_gas_price(1_000);
    builder.set_gas_budget(50_000_000);
    builder.add_gas_objects([ObjectInput::owned(Address::ZERO, 1, Digest::ZERO)]);
    let tx = builder
        .try_build()
        .map_err(|e| format!("failed to build seal_approve PTB: {e}"))?;
    match tx.kind {
        TransactionKind::ProgrammableTransaction(ptb) => Ok(ptb),
        _ => Err("unexpected non-PTB transaction kind".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// 4. In-Process SEAL Encryption (`seal_encrypt_in_process`)
// ---------------------------------------------------------------------------

pub async fn seal_encrypt_in_process(
    data: &[u8],
    owner_address: &str,
    account_id: &str,
    package_id: &str,
    expected_seal_committee_identity: Option<&serde_json::Value>,
) -> Result<Vec<u8>, AppError> {
    let grpc_url = get_native_runtime_config().grpc_url;
    let pkg_addr: ObjectID = package_id
        .trim()
        .parse()
        .map_err(|e| AppError::BadRequest(format!("invalid package_id '{package_id}': {e}")))?;

    let access_counter_version =
        fetch_seal_encrypt_identity(&grpc_url, account_id, owner_address, package_id)
            .await
            .map_err(|e| AppError::Internal(format!("seal encrypt failed: {e}")))?;
    let (_, id_bytes) = derive_seal_id(owner_address, access_counter_version)
        .map_err(|e| AppError::Internal(format!("seal encrypt failed: {e}")))?;

    let (servers, threshold) =
        resolve_seal_key_servers(&grpc_url, expected_seal_committee_identity)
            .await
            .map_err(|e| AppError::Internal(format!("seal encrypt failed: {e}")))?;

    let mut key_server_ids = Vec::new();
    let mut public_keys = Vec::new();
    for srv in &servers {
        for _ in 0..srv.weight.max(1) {
            key_server_ids.push(srv.object_id);
            public_keys.push(srv.pk);
        }
    }

    let plaintext = data.to_vec();
    let encrypted_bytes = tokio::task::spawn_blocking(move || {
        let (encrypted_object, _dem_key) = crypto_seal_encrypt(
            pkg_addr,
            id_bytes,
            key_server_ids,
            &IBEPublicKeys::BonehFranklinBLS12381(public_keys),
            threshold,
            EncryptionInput::Aes256Gcm {
                data: plaintext,
                aad: None,
            },
        )
        .map_err(|e| format!("seal_crypto::seal_encrypt failed: {e}"))?;

        bcs::to_bytes(&encrypted_object)
            .map_err(|e| format!("failed to BCS-serialize EncryptedObject: {e}"))
    })
    .await
    .map_err(|e| AppError::Internal(format!("seal_encrypt blocking task panicked: {e}")))?
    .map_err(|e| AppError::Internal(format!("seal encrypt failed: {e}")))?;

    tracing::info!(
        "seal encrypt (in-process Rust) ok: {} bytes -> {} encrypted bytes",
        data.len(),
        encrypted_bytes.len()
    );

    Ok(encrypted_bytes)
}

// ---------------------------------------------------------------------------
// 5. Session Key Resolution (`SealCredential::Session` & `SealCredential::DelegateKey`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct SessionCertificate {
    user: Address,
    session_vk: Ed25519PublicKey,
    creation_time: u64,
    ttl_min: u16,
    signature_base64: String,
    mvr_name: Option<String>,
}

#[derive(Serialize)]
struct SealRequestFormat {
    ptb: Vec<u8>,
    enc_key: Vec<u8>,
    enc_verification_key: Vec<u8>,
}

struct CachedSessionCert {
    keypair_bytes: Vec<u8>,
    certificate: SessionCertificate,
    created_at: Instant,
}

static SESSION_CERT_CACHE: OnceLock<std::sync::RwLock<HashMap<String, CachedSessionCert>>> =
    OnceLock::new();

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportedSessionKeyJson {
    address: String,
    package_id: String,
    #[serde(default)]
    mvr_name: Option<String>,
    creation_time_ms: u64,
    ttl_min: u16,
    personal_message_signature: String,
    session_key: String,
}

fn import_exported_session_key(
    session_b64: &str,
    expected_package_id: Address,
) -> Result<(Ed25519KeyPair, SessionCertificate), String> {
    let json_bytes = base64::engine::general_purpose::STANDARD
        .decode(session_b64.trim())
        .map_err(|e| format!("invalid x-seal-session base64: {e}"))?;
    let exported: ExportedSessionKeyJson = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("invalid x-seal-session JSON: {e}"))?;

    let session_pkg: Address = exported
        .package_id
        .trim()
        .parse()
        .map_err(|e| format!("invalid SessionKey packageId '{}': {e}", exported.package_id))?;
    if session_pkg != expected_package_id {
        return Err("SessionKey packageId does not match request packageId".to_owned());
    }

    let user_addr: Address = exported
        .address
        .trim()
        .parse()
        .map_err(|e| format!("invalid SessionKey address '{}': {e}", exported.address))?;

    let sk_seed = parse_sui_private_key_bytes(&exported.session_key)?;
    let session_kp = Ed25519KeyPair::from_bytes(&sk_seed)
        .map_err(|e| format!("invalid SessionKey Ed25519 secret key: {e}"))?;
    let session_vk = session_kp.public().clone();

    let sig_b64 = exported.personal_message_signature.trim().to_owned();
    base64::engine::general_purpose::STANDARD
        .decode(&sig_b64)
        .map_err(|e| format!("invalid personalMessageSignature base64: {e}"))?;

    let certificate = SessionCertificate {
        user: user_addr,
        session_vk,
        creation_time: exported.creation_time_ms,
        ttl_min: exported.ttl_min,
        signature_base64: sig_b64,
        mvr_name: exported.mvr_name,
    };

    Ok((session_kp, certificate))
}

fn get_or_create_session_cert_from_delegate_key(
    package_id: Address,
    private_key: &str,
) -> Result<(Ed25519KeyPair, SessionCertificate), String> {
    let user_addr_str = derive_sui_address(private_key)?;
    let user_addr: Address = user_addr_str
        .parse()
        .map_err(|e| format!("invalid user address '{user_addr_str}': {e}"))?;
    let cache_key = format!("{user_addr}:{package_id}");

    let cache = SESSION_CERT_CACHE.get_or_init(|| std::sync::RwLock::new(HashMap::new()));
    if let Ok(guard) = cache.read() {
        if let Some(entry) = guard.get(&cache_key) {
            if entry.created_at.elapsed() < SESSION_CACHE_DURATION {
                if let Ok(kp) = bcs::from_bytes::<Ed25519KeyPair>(&entry.keypair_bytes) {
                    return Ok((kp, entry.certificate.clone()));
                }
            }
        }
    }

    let mut rng = thread_rng();
    let session_kp = Ed25519KeyPair::generate(&mut rng);
    let session_vk = session_kp.public().clone();
    let creation_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let msg = signed_message(
        package_id.to_string(),
        &session_vk,
        creation_time,
        SESSION_TTL_MIN,
    );
    let signature_base64 = sign_personal_message_bytes(private_key, msg.as_bytes())?;

    let certificate = SessionCertificate {
        user: user_addr,
        session_vk,
        creation_time,
        ttl_min: SESSION_TTL_MIN,
        signature_base64,
        mvr_name: None,
    };

    if let Ok(kp_bytes) = bcs::to_bytes(&session_kp) {
        if let Ok(mut guard) = cache.write() {
            guard.insert(
                cache_key,
                CachedSessionCert {
                    keypair_bytes: kp_bytes,
                    certificate: certificate.clone(),
                    created_at: Instant::now(),
                },
            );
        }
    }

    Ok((session_kp, certificate))
}

fn resolve_credential_session(
    credential: &SealCredential,
    package_id: Address,
) -> Result<(Ed25519KeyPair, SessionCertificate), String> {
    match credential {
        SealCredential::Session(s) => import_exported_session_key(s, package_id),
        SealCredential::DelegateKey(k) => {
            get_or_create_session_cert_from_delegate_key(package_id, k)
        }
    }
}

// ---------------------------------------------------------------------------
// 6. In-Process SEAL Decryption (`seal_decrypt_in_process` & `seal_decrypt_batch_in_process`)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn seal_decrypt_in_process(
    http: &reqwest::Client,
    encrypted_data: &[u8],
    credential: &SealCredential,
    package_id: &str,
    policy_package_id: &str,
    registry_id: &str,
    account_id: &str,
) -> Result<Vec<u8>, AppError> {
    let items = vec![("single".to_owned(), encrypted_data.to_vec())];
    let mut outcomes = seal_decrypt_batch_in_process(
        http,
        &items,
        credential,
        package_id,
        policy_package_id,
        registry_id,
        account_id,
    )
    .await?;

    match outcomes.pop().unwrap_or(DecryptOutcome::Missing) {
        DecryptOutcome::Ok(plaintext) => Ok(plaintext),
        DecryptOutcome::Failed { error, .. } => {
            Err(AppError::Internal(format!("seal decrypt failed: {error}")))
        }
        DecryptOutcome::Missing => Err(AppError::Internal(
            "seal decrypt failed: missing decryption outcome".into(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn seal_decrypt_batch_in_process(
    http: &reqwest::Client,
    encrypted_blobs: &[(String, Vec<u8>)],
    credential: &SealCredential,
    package_id: &str,
    policy_package_id: &str,
    registry_id: &str,
    account_id: &str,
) -> Result<Vec<DecryptOutcome>, AppError> {
    if encrypted_blobs.is_empty() {
        return Ok(Vec::new());
    }

    let grpc_url = get_native_runtime_config().grpc_url;
    let pkg_addr: Address = package_id
        .trim()
        .parse()
        .map_err(|e| AppError::BadRequest(format!("invalid package_id '{package_id}': {e}")))?;
    let pkg_obj_id = ObjectID::new(*pkg_addr.inner());
    let effective_policy_pkg: Address = if policy_package_id.trim().is_empty() {
        pkg_addr
    } else {
        policy_package_id
            .trim()
            .parse()
            .map_err(|e| AppError::BadRequest(format!("invalid policy_package_id: {e}")))?
    };
    let acct_addr: Address = account_id
        .trim()
        .parse()
        .map_err(|e| AppError::BadRequest(format!("invalid account_id '{account_id}': {e}")))?;
    let reg_addr: Address = registry_id
        .trim()
        .parse()
        .map_err(|e| AppError::BadRequest(format!("invalid registry_id '{registry_id}': {e}")))?;

    // 1. Resolve SessionKey Certificate first so package mismatch fails fast.
    let (session_kp, certificate) = resolve_credential_session(credential, pkg_addr)
        .map_err(|e| AppError::Internal(format!("seal decrypt-batch failed: {e}")))?;

    // 2. Parse all EncryptedObjects and collect unique inner key IDs, keeping malformed/foreign
    // ciphertexts local to their batch item (`parseSealDecryptBatchItems` in `seal.ts`).
    let mut parsed_items: Vec<Result<EncryptedObject, String>> =
        Vec::with_capacity(encrypted_blobs.len());
    let mut unique_ids: Vec<Vec<u8>> = Vec::new();

    for (_, bytes) in encrypted_blobs {
        match bcs::from_bytes::<EncryptedObject>(bytes) {
            Ok(enc_obj) => {
                if enc_obj.package_id != pkg_obj_id {
                    parsed_items.push(Err(
                        "InvalidCiphertext: Ciphertext packageId does not match request packageId"
                            .to_owned(),
                    ));
                    continue;
                }
                if !unique_ids.iter().any(|existing| existing == &enc_obj.id) {
                    unique_ids.push(enc_obj.id.clone());
                }
                parsed_items.push(Ok(enc_obj));
            }
            Err(err) => {
                parsed_items.push(Err(format!("InvalidCiphertext: parse failed: {err}")));
            }
        }
    }

    if unique_ids.is_empty() {
        return Ok(parsed_items
            .into_iter()
            .map(|res| match res {
                Ok(_) => DecryptOutcome::Missing,
                Err(error) => {
                    let permanent = DecryptOutcome::permanent_from_error(&error);
                    DecryptOutcome::Failed { error, permanent }
                }
            })
            .collect());
    }

    // 3. Resolve shared object initial versions and key servers.
    let (acct_shared_ver, reg_shared_ver) =
        fetch_shared_object_versions(&grpc_url, account_id, registry_id)
            .await
            .map_err(|e| AppError::Internal(format!("seal decrypt-batch failed: {e}")))?;
    let (servers, threshold) = resolve_seal_key_servers(&grpc_url, None)
        .await
        .map_err(|e| AppError::Internal(format!("seal decrypt-batch failed: {e}")))?;

    let ptb = build_seal_approve_ptb(
        effective_policy_pkg,
        reg_addr,
        reg_shared_ver,
        acct_addr,
        acct_shared_ver,
        &unique_ids,
    )
    .map_err(|e| AppError::Internal(format!("seal decrypt-batch failed: {e}")))?;

    // 4. Build signed FetchKeyRequest with ephemeral ElGamal keypair + SessionKey Certificate.
    let (eg_sk, eg_pk, eg_vk): (
        seal_sdk::ElGamalSecretKey,
        seal_sdk::types::ElGamalPublicKey,
        seal_sdk::types::ElgamalVerificationKey,
    ) = genkey(&mut thread_rng());
    let ptb_bcs = bcs::to_bytes(&ptb)
        .map_err(|e| AppError::Internal(format!("BCS seal_approve PTB: {e}")))?;
    let req_msg = bcs::to_bytes(&SealRequestFormat {
        ptb: ptb_bcs.clone(),
        enc_key: bcs::to_bytes(&eg_pk)
            .map_err(|e| AppError::Internal(format!("BCS ElGamal public key: {e}")))?,
        enc_verification_key: bcs::to_bytes(&eg_vk)
            .map_err(|e| AppError::Internal(format!("BCS ElGamal verification key: {e}")))?,
    })
    .map_err(|e| AppError::Internal(format!("BCS SealRequestFormat: {e}")))?;
    let req_sig: Ed25519Signature = session_kp.sign(&req_msg);

    let fetch_req_json = serde_json::to_string(&serde_json::json!({
        "ptb": FcBase64::encode(&ptb_bcs),
        "enc_key": eg_pk,
        "enc_verification_key": eg_vk,
        "request_signature": req_sig,
        "certificate": {
            "user": certificate.user.to_string(),
            "session_vk": certificate.session_vk,
            "creation_time": certificate.creation_time,
            "ttl_min": certificate.ttl_min,
            "signature": certificate.signature_base64,
            "mvr_name": certificate.mvr_name,
        }
    }))
    .map_err(|e| AppError::Internal(format!("failed to serialize FetchKeyRequest JSON: {e}")))?;

    // 5. Query key servers concurrently for decryption key shares.
    let fetch_futures = servers.iter().map(|srv| {
        let http = http.clone();
        let req_json = fetch_req_json.clone();
        async move {
            let url = format!("{}/v1/fetch_key", srv.url.trim_end_matches('/'));
            let req_id = Uuid::new_v4().to_string();
            match http
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Client-Sdk-Type", "typescript")
                .header("Client-Sdk-Version", "0.9.6")
                .header("Request-Id", &req_id)
                .body(req_json)
                .timeout(Duration::from_secs(15))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<FetchKeyResponse>().await {
                        Ok(parsed) => Ok((srv.object_id, parsed)),
                        Err(e) => Err(format!("invalid FetchKeyResponse from {}: {e}", srv.name)),
                    }
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    let err_tag = if status.as_u16() == 403 {
                        "NoAccessError"
                    } else {
                        "KeyServerError"
                    };
                    Err(format!(
                        "fetch_keys failed: {err_tag}: key server {} returned {status}: {body}",
                        srv.name
                    ))
                }
                Err(e) => {
                    let timeout_prefix = if e.is_timeout() {
                        "TimeoutError: The operation was aborted due to timeout: "
                    } else {
                        ""
                    };
                    Err(format!(
                        "fetch_keys failed: {timeout_prefix}key server {} request failed: {e}",
                        srv.name
                    ))
                }
            }
        }
    });

    let mut seal_responses: Vec<(ObjectID, FetchKeyResponse)> = Vec::new();
    let mut last_err = String::new();
    for res in futures::future::join_all(fetch_futures).await {
        match res {
            Ok(pair) => {
                seal_responses.push(pair);
                if seal_responses.len() >= threshold as usize {
                    break;
                }
            }
            Err(err) => {
                last_err = err;
            }
        }
    }

    if seal_responses.len() < threshold as usize {
        let error = format!(
            "fetch_keys failed: Not enough shares ({}/{}): {}",
            seal_responses.len(),
            threshold,
            last_err
        );
        let permanent = DecryptOutcome::permanent_from_error(&error);
        return Ok(parsed_items
            .into_iter()
            .map(|res| match res {
                Ok(_) => DecryptOutcome::Failed {
                    error: error.clone(),
                    permanent,
                },
                Err(parse_err) => DecryptOutcome::Failed {
                    permanent: DecryptOutcome::permanent_from_error(&parse_err),
                    error: parse_err,
                },
            })
            .collect());
    }

    // 6. Decrypt ElGamal responses into user secret keys and decrypt each EncryptedObject.
    let pk_map: HashMap<ObjectID, IBEPublicKey> =
        servers.iter().map(|s| (s.object_id, s.pk)).collect();
    let usk_map = decrypt_seal_responses(&eg_sk, &seal_responses, &pk_map)
        .map_err(|e| AppError::Internal(format!("decrypt_seal_responses failed: {e}")))?;

    let mut out = Vec::with_capacity(parsed_items.len());
    for enc_res in parsed_items {
        match enc_res {
            Ok(enc_obj) => match seal_decrypt_object(&enc_obj, &usk_map, &pk_map) {
                Ok(plaintext) => {
                    out.push(DecryptOutcome::Ok(plaintext));
                }
                Err(e) => {
                    let error = format!("InvalidCiphertext: seal_decrypt_object failed: {e}");
                    let permanent = DecryptOutcome::permanent_from_error(&error);
                    out.push(DecryptOutcome::Failed { error, permanent });
                }
            },
            Err(error) => {
                let permanent = DecryptOutcome::permanent_from_error(&error);
                out.push(DecryptOutcome::Failed { error, permanent });
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::groups::Scalar as _;
    use seal_crypto::{create_full_id, elgamal, ibe};
    use seal_sdk::types::DecryptionKey;

    #[test]
    fn derive_seal_id_produces_40_byte_owner_plus_le_version() {
        let owner = "0x0000000000000000000000000000000000000000000000000000000000000007";
        let (hex_str, raw_bytes) = derive_seal_id(owner, 42).unwrap();
        assert_eq!(raw_bytes.len(), 40);
        assert_eq!(hex_str.len(), 80);
        assert_eq!(raw_bytes[31], 7);
        assert_eq!(&raw_bytes[32..40], &42u64.to_le_bytes());
    }

    #[test]
    fn seal_encrypt_and_decrypt_roundtrip_in_process_rust() {
        let mut rng = thread_rng();
        let msk_0 = ibe::MasterKey::rand(&mut rng);
        let msk_1 = ibe::MasterKey::rand(&mut rng);
        let pk_0 = ibe::public_key_from_master_key(&msk_0);
        let pk_1 = ibe::public_key_from_master_key(&msk_1);

        let srv_0: ObjectID =
            "0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75"
                .parse()
                .unwrap();
        let srv_1: ObjectID =
            "0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8"
                .parse()
                .unwrap();
        let pkg_id: ObjectID =
            "0x1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap();

        let (_, id_bytes) = derive_seal_id(
            "0x0000000000000000000000000000000000000000000000000000000000000099",
            3,
        )
        .unwrap();
        let plaintext = b"Top-secret Walrus Memory vector payload encrypted in pure Rust".to_vec();

        let (encrypted_obj, _) = crypto_seal_encrypt(
            pkg_id,
            id_bytes.clone(),
            vec![srv_0, srv_1],
            &IBEPublicKeys::BonehFranklinBLS12381(vec![pk_0, pk_1]),
            2,
            EncryptionInput::Aes256Gcm {
                data: plaintext.clone(),
                aad: None,
            },
        )
        .expect("seal_encrypt should succeed");

        let bcs_bytes = bcs::to_bytes(&encrypted_obj).unwrap();
        let decoded_obj: EncryptedObject = bcs::from_bytes(&bcs_bytes).unwrap();

        // Simulate key-server ElGamal responses and verify `decrypt_seal_responses` + `seal_decrypt_object`.
        let (eg_sk, eg_pk, _eg_vk): (
            seal_sdk::ElGamalSecretKey,
            seal_sdk::types::ElGamalPublicKey,
            seal_sdk::types::ElgamalVerificationKey,
        ) = genkey(&mut rng);
        let full_id = create_full_id(&pkg_id.into_inner(), &id_bytes);
        let resp_0 = FetchKeyResponse {
            decryption_keys: vec![DecryptionKey {
                id: full_id.clone(),
                encrypted_key: elgamal::encrypt(
                    &mut rng,
                    &ibe::extract(&msk_0, &full_id),
                    &eg_pk,
                ),
            }],
        };
        let resp_1 = FetchKeyResponse {
            decryption_keys: vec![DecryptionKey {
                id: full_id.clone(),
                encrypted_key: elgamal::encrypt(
                    &mut rng,
                    &ibe::extract(&msk_1, &full_id),
                    &eg_pk,
                ),
            }],
        };

        let mut pk_map = HashMap::new();
        pk_map.insert(srv_0, pk_0);
        pk_map.insert(srv_1, pk_1);

        let usk_map =
            decrypt_seal_responses(&eg_sk, &[(srv_0, resp_0), (srv_1, resp_1)], &pk_map).unwrap();

        let recovered = seal_decrypt_object(&decoded_obj, &usk_map, &pk_map)
            .expect("seal_decrypt_object should succeed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn build_seal_approve_ptb_produces_valid_3_arg_move_calls() {
        let pkg: Address =
            "0x1111111111111111111111111111111111111111111111111111111111111111"
                .parse()
                .unwrap();
        let reg: Address =
            "0x3333333333333333333333333333333333333333333333333333333333333333"
                .parse()
                .unwrap();
        let acct: Address =
            "0x2222222222222222222222222222222222222222222222222222222222222222"
                .parse()
                .unwrap();
        let (_, id1) = derive_seal_id(&acct.to_string(), 0).unwrap();
        let (_, id2) = derive_seal_id(&acct.to_string(), 1).unwrap();

        let ptb = build_seal_approve_ptb(pkg, reg, 20, acct, 10, &[id1, id2]).unwrap();
        assert_eq!(ptb.commands.len(), 2);
        for cmd in &ptb.commands {
            match cmd {
                sui_sdk_types::Command::MoveCall(mc) => {
                    assert_eq!(mc.package, pkg);
                    assert_eq!(mc.module.as_str(), "account");
                    assert_eq!(mc.function.as_str(), "seal_approve");
                    assert_eq!(mc.arguments.len(), 3);
                }
                other => panic!("expected MoveCall, got {other:?}"),
            }
        }
    }
}

//! Delegate-key revocation notice.
//!
//! `GET /api/accounts/{owner}/delegate-keys` reads that owner's
//! `MemWalAccount` from Sui RPC (registry dynamic field, then the account
//! object). It does not use the indexer or the delegate-key cache.
//!
//! `GET /api/accounts/{owner}/incident` answers only for the owner in the
//! path: affected, quarantined, active. Affected means the owner is in
//! `MEMWAL_AFFECTED_OWNERS`, a current delegate public key is in
//! `MEMWAL_LEAKED_DELEGATE_PUBLIC_KEYS`, or the account is
//! `admin_quarantined`. Both lists are comma-separated and optional. With
//! neither set, the banner follows the on-chain quarantine flag.
//!
//! The dashboard does not store an unblock request. It keeps the locked
//! banner until every highlighted key is gone, then shows reactivate.
//! Clearing the lock is an operator transaction.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

use crate::routes::sponsor::validate_sui_address;
use crate::security_delete_error::SdCode;
use crate::storage::sui::OnchainVerifyError;
use crate::types::*;

/// Canonical personal-message text. The dashboard builds the same string
/// in `apps/app/src/utils/unblockRequest.ts`.
pub fn unblock_request_message(owner: &str, account_id: &str) -> String {
    format!(
        "Walrus Memory unblock request\nowner:{}\naccount:{}",
        owner.to_ascii_lowercase(),
        account_id.to_ascii_lowercase(),
    )
}

/// Split a comma- or whitespace-separated hex list. `0x` is optional.
/// Comparison is lowercase and unprefixed so an address and a public key
/// use the same form.
pub fn parse_hex_set(raw: &str) -> HashSet<String> {
    raw.split(|c: char| c == ',' || c == '\n' || c.is_whitespace())
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(normalize_hex)
        .filter(|part| !part.is_empty())
        .collect()
}

pub fn normalize_hex(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_ascii_lowercase()
}

pub fn account_is_affected(
    owner: &str,
    public_keys_hex: &[String],
    quarantined: bool,
    affected_owners: &HashSet<String>,
    leaked_keys: &HashSet<String>,
) -> bool {
    quarantined
        || affected_owners.contains(&normalize_hex(owner))
        || public_keys_hex
            .iter()
            .any(|key| leaked_keys.contains(&normalize_hex(key)))
}

fn affected_owners_from_env() -> HashSet<String> {
    std::env::var("MEMWAL_AFFECTED_OWNERS")
        .ok()
        .map(|raw| parse_hex_set(&raw))
        .unwrap_or_default()
}

fn matching_leaked_keys(public_keys_hex: &[String], leaked_keys: &HashSet<String>) -> Vec<String> {
    public_keys_hex
        .iter()
        .map(|key| normalize_hex(key))
        .filter(|key| leaked_keys.contains(key))
        .collect()
}

/// First look at a preview account: one key whose label says migrate.
fn preview_sample(keys: &[(String, String)]) -> Vec<String> {
    keys.iter()
        .find(|(_, label)| label.to_ascii_lowercase().contains("migrat"))
        .map(|(public_key, _)| vec![normalize_hex(public_key)])
        .unwrap_or_default()
}

/// Pinned preview keys that are still on the account. Deleting one does not
/// highlight a replacement.
fn keys_still_present(pinned: &[String], current: &[String]) -> Vec<String> {
    let current: HashSet<String> = current.iter().map(|key| normalize_hex(key)).collect();
    pinned
        .iter()
        .filter(|key| current.contains(*key))
        .cloned()
        .collect()
}

fn preview_pin() -> &'static std::sync::Mutex<Option<Vec<String>>> {
    static PIN: std::sync::Mutex<Option<Vec<String>>> = std::sync::Mutex::new(None);
    &PIN
}

/// Leaked env keys win. The preview sample is only for an empty env, and it
/// does not replace a key the owner already deleted.
fn highlighted_for_owner(
    preview: bool,
    leaked_list_empty: bool,
    matched: Vec<String>,
    labeled_keys: &[(String, String)],
) -> Vec<String> {
    if preview && matched.is_empty() && leaked_list_empty {
        pinned_preview_keys(labeled_keys)
    } else {
        matched
    }
}

fn pinned_preview_keys(keys: &[(String, String)]) -> Vec<String> {
    let current: Vec<String> = keys
        .iter()
        .map(|(public_key, _)| public_key.clone())
        .collect();
    let mut pin = preview_pin().lock().unwrap_or_else(|err| err.into_inner());
    if pin.is_none() {
        let sample = preview_sample(keys);
        if !sample.is_empty() {
            *pin = Some(sample);
        }
    }
    keys_still_present(pin.as_deref().unwrap_or(&[]), &current)
}

fn leaked_keys_from_env() -> HashSet<String> {
    std::env::var("MEMWAL_LEAKED_DELEGATE_PUBLIC_KEYS")
        .ok()
        .map(|raw| parse_hex_set(&raw))
        .unwrap_or_default()
}

/// Testnet account `0x158a…93e7`. It is active on chain. The incident
/// response pretends it is locked so a dev deploy can walk the banner.
/// Mainnet ignores it. When the leaked-key list is empty, one current key
/// whose label contains "migrat" is pinned for this process. A non-empty
/// list uses only the keys that match, and deleting one does not pin another.
const TESTNET_PREVIEW_OWNER: &str =
    "158a78f06e4a85cdef1a1f10bc30c41e4860c1a19f3b049a05098aca588593e7";

fn is_testnet_preview_owner(network: &str, owner: &str) -> bool {
    network == "testnet" && normalize_hex(owner) == TESTNET_PREVIEW_OWNER
}

fn normalize_owner(owner: &str) -> Result<String, AppError> {
    if !validate_sui_address(owner) {
        return Err(AppError::BadRequest(
            "owner must be a 0x-prefixed 32-byte Sui address (66 characters)".into(),
        ));
    }
    Ok(owner.to_ascii_lowercase())
}

fn map_chain_error(err: OnchainVerifyError) -> AppError {
    AppError::UpstreamUnavailable(err.to_string())
}

#[derive(Debug, Serialize)]
pub struct DelegateKeyView {
    pub public_key: String,
    pub sui_address: String,
    pub label: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
pub struct DelegateKeysResponse {
    pub account_id: Option<String>,
    pub keys: Vec<DelegateKeyView>,
}

#[derive(Debug, Serialize)]
pub struct IncidentResponse {
    pub account_id: Option<String>,
    pub affected: bool,
    pub quarantined: bool,
    pub active: bool,
    /// This account's delegate public keys that are in the leaked set.
    /// Hex, no `0x`. Empty when none of the current keys were leaked.
    pub affected_public_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UnblockRequestBody {
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct UnblockRequestResponse {
    pub status: &'static str,
    pub requested_at: String,
}

#[derive(Debug, Serialize)]
pub struct UnblockRequestListResponse {
    pub requests: Vec<UnblockRequestItem>,
}

#[derive(Debug, Serialize)]
pub struct UnblockRequestItem {
    pub owner: String,
    pub account_id: String,
    pub requested_at: String,
}

/// GET /api/accounts/{owner}/delegate-keys
pub async fn delegate_keys(
    State(state): State<Arc<AppState>>,
    Path(owner): Path<String>,
) -> Result<Json<DelegateKeysResponse>, AppError> {
    let owner = normalize_owner(&owner)?;
    let snapshot = crate::storage::sui::load_owner_account_onchain(
        &state.http_client,
        &state.config.sui_rpc_url,
        state.sui_grpc_client.as_ref(),
        &state.config.registry_id,
        &state.config.package_id,
        &owner,
    )
    .await
    .map_err(map_chain_error)?;
    let Some(snapshot) = snapshot else {
        return Ok(Json(DelegateKeysResponse {
            account_id: None,
            keys: Vec::new(),
        }));
    };
    Ok(Json(DelegateKeysResponse {
        account_id: Some(snapshot.account_id),
        keys: snapshot
            .keys
            .into_iter()
            .map(|key| DelegateKeyView {
                public_key: key.public_key_hex,
                sui_address: key.sui_address,
                label: key.label,
                created_at: key.created_at,
            })
            .collect(),
    }))
}

/// GET /api/accounts/{owner}/incident
pub async fn incident_status(
    State(state): State<Arc<AppState>>,
    Path(owner): Path<String>,
) -> Result<Json<IncidentResponse>, AppError> {
    let owner = normalize_owner(&owner)?;
    let snapshot = crate::storage::sui::load_owner_account_onchain(
        &state.http_client,
        &state.config.sui_rpc_url,
        state.sui_grpc_client.as_ref(),
        &state.config.registry_id,
        &state.config.package_id,
        &owner,
    )
    .await
    .map_err(map_chain_error)?;
    let affected_owners = affected_owners_from_env();
    let leaked_keys = leaked_keys_from_env();
    let Some(snapshot) = snapshot else {
        return Ok(Json(IncidentResponse {
            account_id: None,
            affected: account_is_affected(&owner, &[], false, &affected_owners, &leaked_keys),
            quarantined: false,
            active: false,
            affected_public_keys: Vec::new(),
        }));
    };
    let public_keys: Vec<String> = snapshot
        .keys
        .iter()
        .map(|key| key.public_key_hex.clone())
        .collect();
    let labeled_keys: Vec<(String, String)> = snapshot
        .keys
        .iter()
        .map(|key| (key.public_key_hex.clone(), key.label.clone()))
        .collect();
    let preview = is_testnet_preview_owner(&state.config.sui_network, &owner);
    let matched = matching_leaked_keys(&public_keys, &leaked_keys);
    let affected_public_keys =
        highlighted_for_owner(preview, leaked_keys.is_empty(), matched, &labeled_keys);
    if preview {
        return Ok(Json(IncidentResponse {
            account_id: Some(snapshot.account_id),
            affected: true,
            quarantined: true,
            active: false,
            affected_public_keys,
        }));
    }
    Ok(Json(IncidentResponse {
        account_id: Some(snapshot.account_id),
        affected: account_is_affected(
            &owner,
            &public_keys,
            snapshot.admin_quarantined,
            &affected_owners,
            &leaked_keys,
        ),
        quarantined: snapshot.admin_quarantined,
        active: snapshot.active,
        affected_public_keys,
    }))
}

/// POST /api/accounts/{owner}/unblock-requests
pub async fn request_unblock(
    State(state): State<Arc<AppState>>,
    Path(owner): Path<String>,
    Json(body): Json<UnblockRequestBody>,
) -> Result<Json<UnblockRequestResponse>, AppError> {
    let owner = normalize_owner(&owner)?;
    if body.signature.trim().is_empty() || body.signature.len() > 4096 {
        return Err(AppError::BadRequest("signature is invalid".into()));
    }
    let snapshot = crate::storage::sui::load_owner_account_onchain(
        &state.http_client,
        &state.config.sui_rpc_url,
        state.sui_grpc_client.as_ref(),
        &state.config.registry_id,
        &state.config.package_id,
        &owner,
    )
    .await
    .map_err(map_chain_error)?;
    let Some(snapshot) = snapshot else {
        return Err(AppError::BadRequest("owner has no MemWalAccount".into()));
    };
    let preview = is_testnet_preview_owner(&state.config.sui_network, &owner);
    if !snapshot.admin_quarantined && !preview {
        return Err(AppError::Conflict("account is not quarantined".into()));
    }
    let message = unblock_request_message(&owner, &snapshot.account_id);
    state
        .security_delete_wallet_verifier
        .verify_personal(&owner, message.as_bytes(), body.signature.trim())
        .await
        .map_err(|error| match error.code {
            SdCode::RpcUnavailable | SdCode::InternalError => AppError::UpstreamUnavailable(
                format!("unblock signature check unavailable: {}", error.message),
            ),
            _ => AppError::Unauthorized("invalid unblock signature".into()),
        })?;
    let requested_at = state
        .db
        .upsert_unblock_request(&owner, &snapshot.account_id)
        .await?;
    Ok(Json(UnblockRequestResponse {
        status: "requested",
        requested_at: requested_at.to_rfc3339(),
    }))
}

/// GET /api/admin/unblock-requests
pub async fn list_unblock_requests(
    State(state): State<Arc<AppState>>,
) -> Result<Json<UnblockRequestListResponse>, AppError> {
    let rows = state.db.list_unblock_requests().await?;
    Ok(Json(UnblockRequestListResponse {
        requests: rows
            .into_iter()
            .map(|(owner, account_id, requested_at)| UnblockRequestItem {
                owner,
                account_id,
                requested_at: requested_at.to_rfc3339(),
            })
            .collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaked_keys_on_the_account_are_named() {
        let leaked = parse_hex_set("0xAABB, cc");
        let keys = vec!["aabb".to_string(), "dd".to_string()];
        assert_eq!(
            matching_leaked_keys(&keys, &leaked),
            vec!["aabb".to_string()]
        );
        let labeled = vec![("aabb".to_string(), "migration-fallback".to_string())];
        assert_eq!(
            highlighted_for_owner(true, false, Vec::new(), &labeled),
            Vec::<String>::new()
        );
        assert_eq!(
            highlighted_for_owner(false, true, vec!["aabb".to_string()], &labeled),
            vec!["aabb".to_string()]
        );
    }

    #[test]
    fn preview_sample_picks_one_migrate_key_and_does_not_refill() {
        let keys = vec![
            ("aa".to_string(), "Web App".to_string()),
            ("bb".to_string(), "migration-fallback".to_string()),
            ("cc".to_string(), "migration-decrypt".to_string()),
        ];
        let pinned = preview_sample(&keys);
        assert_eq!(pinned, vec!["bb".to_string()]);
        assert!(keys_still_present(&pinned, &["aa".to_string(), "cc".to_string()]).is_empty());
        assert_eq!(
            keys_still_present(&pinned, &["bb".to_string(), "cc".to_string()]),
            vec!["bb".to_string()]
        );
    }

    #[test]
    fn testnet_preview_owner_is_only_that_address_on_testnet() {
        let owner = format!("0x{TESTNET_PREVIEW_OWNER}");
        assert!(is_testnet_preview_owner("testnet", &owner));
        assert!(is_testnet_preview_owner(
            "testnet",
            &owner.to_ascii_uppercase()
        ));
        assert!(!is_testnet_preview_owner("mainnet", &owner));
        assert!(!is_testnet_preview_owner(
            "testnet",
            &format!("0x{}", "11".repeat(32))
        ));
    }

    #[test]
    fn unblock_message_is_stable() {
        let owner = format!("0x{}", "ab".repeat(32));
        let account = format!("0x{}", "cd".repeat(32));
        assert_eq!(
            unblock_request_message(&owner.to_ascii_uppercase(), &account.to_ascii_uppercase()),
            format!("Walrus Memory unblock request\nowner:{owner}\naccount:{account}")
        );
    }

    #[test]
    fn hex_set_ignores_prefix_case_and_separators() {
        let set = parse_hex_set("0xAa, BB\n0Xcc");
        assert!(set.contains("aa"));
        assert!(set.contains("bb"));
        assert!(set.contains("cc"));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn affected_matches_owner_leaked_key_or_quarantine() {
        let owner = format!("0x{}", "11".repeat(32));
        let other = format!("0x{}", "22".repeat(32));
        let leaked = "aa".repeat(32);
        let owners = parse_hex_set(&owner);
        let keys = parse_hex_set(&leaked);
        assert!(account_is_affected(
            &owner,
            &[],
            false,
            &owners,
            &HashSet::new()
        ));
        assert!(!account_is_affected(
            &other,
            &[],
            false,
            &owners,
            &HashSet::new()
        ));
        assert!(account_is_affected(
            &other,
            &[leaked.clone()],
            false,
            &HashSet::new(),
            &keys
        ));
        assert!(account_is_affected(
            &other,
            &[],
            true,
            &HashSet::new(),
            &HashSet::new()
        ));
        assert!(!account_is_affected(
            &other,
            &["bb".repeat(32)],
            false,
            &HashSet::new(),
            &keys
        ));
    }

    #[test]
    fn address_dynamic_field_id_matches_blake2b() {
        use sui_sdk_types::Address;
        let parent = Address::new([0x11; 32]);
        let key = Address::new([0x22; 32]);
        let id = crate::storage::sui::derive_address_dynamic_field_id(&parent, &key);
        assert_eq!(
            hex::encode(id.inner()),
            "107ab86fa49690f6d51066c936ee6ed15810f1a7cff0f258caa2b0b73c4dce17"
        );
    }

    #[test]
    fn registry_and_account_json_accept_flat_and_wrapped_shapes() {
        let table = format!("0x{}", "ab".repeat(32));
        let account = format!("0x{}", "cd".repeat(32));
        let mut flat_registry = serde_json::Map::new();
        flat_registry.insert(
            "accounts".into(),
            serde_json::json!({ "id": table, "size": "1" }),
        );
        assert_eq!(
            crate::storage::sui::registry_table_id(&flat_registry).as_deref(),
            Some(table.as_str())
        );

        let mut wrapped_field = serde_json::Map::new();
        wrapped_field.insert(
            "fields".into(),
            serde_json::json!({ "value": { "id": account } }),
        );
        assert_eq!(
            crate::storage::sui::dynamic_field_account_id(&wrapped_field).as_deref(),
            Some(account.as_str())
        );

        let public_key: Vec<u64> = (0u64..32).collect();
        let mut account_fields = serde_json::Map::new();
        account_fields.insert("active".into(), serde_json::json!(false));
        account_fields.insert("admin_quarantined".into(), serde_json::json!(true));
        account_fields.insert(
            "delegate_keys".into(),
            serde_json::json!([{
                "fields": {
                    "public_key": public_key,
                    "sui_address": "0xABCD",
                    "label": "Noter",
                    "created_at": "10"
                }
            }]),
        );
        let (active, quarantined, keys) =
            crate::storage::sui::parse_owner_account_fields(&account_fields).unwrap();
        assert!(!active);
        assert!(quarantined);
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0].public_key_hex,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert_eq!(keys[0].sui_address, "0xabcd");
        assert_eq!(keys[0].label, "Noter");
        assert_eq!(keys[0].created_at, 10);
    }
}

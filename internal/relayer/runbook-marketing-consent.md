# Marketing consent

The relayer stores one record per owner. An AES-256-GCM envelope binds each address to its canonical owner. A separate HMAC-SHA256 key supports lookup over the trimmed, lowercased address. The hash is shared by owners who enter the same address, so an email-level unsubscribe applies to every match. Withdrawal clears the ciphertext and retains the hash, consent and withdrawal timestamps, and sync metadata. The admin audit records the canonical owner and action. Application logs and metric labels exclude plaintext addresses, ciphertext, and hashes.

## Configuration and rotation

The database migration runs on boot. `ENABLE_MARKETING_CONSENT=true` enables the admin routes and erasure sweep and requires two distinct, unpadded base64url 32-byte keys. The relayer operator supplies `MARKETING_CONSENT_ENCRYPTION_KEY` and `MARKETING_CONSENT_HASH_KEY` from the environment's Walrus Memory 1Password vault. Theodoros owns the vault setup. The shared inventory records environment variable names only.

To rotate encryption, first add readers for the versioned `v2.<key_id>.<nonce>.<ct>` format and keep the original key available. Re-encrypt all `v1` rows with the new key and verify no `v1` rows remain before retiring the old key. Restore procedures must retain access to any key required by retained backups. The hash key must remain available for existing unsubscribe lookups. Withdrawn rows retain only their hash, which prevents re-hashing those rows under a replacement key.

## Erasure and export

The indexer records successful owner `account::deactivate_account` calls from the configured checkpoint source. Deploy the indexer with the relayer’s database and package type origin. Its `account_owner_deactivations_v1` watermark starts at `INDEXER_FIRST_CHECKPOINT` and catches up to the chain tip. Confirm the watermark is current before enabling consent.

The relayer removes consent preceding an indexed owner deactivation every `MARKETING_CONSENT_ERASURE_INTERVAL_SECS` (default one hour). Allow for checkpoint ingestion lag as well as the sweep interval. Account object versions preserve consent granted after reactivation. Admin quarantine and quarantine clear retain consent. Reactivation cannot restore erased consent.

For a data subject request, run the appropriate operation from a trusted terminal with access to the relayer's admin key. Treat the export body as personal data.

```sh
# Export consent metadata and the address, if retained.
curl --fail-with-body -H 'x-admin-api-key: <admin-key>' \
  'https://<relayer-host>/api/admin/marketing-consent/<owner>'

# Permanently erase the owner's consent record.
curl --fail-with-body -X DELETE -H 'x-admin-api-key: <admin-key>' \
  'https://<relayer-host>/api/admin/marketing-consent/<owner>'
```

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

## Owner verification

With `ENABLE_MARKETING_CONSENT=true`, the dashboard requests a challenge at `POST /v1/owner-sessions/marketing-consent/challenge` with `{ "address": "<owner>" }`. Sign the UTF-8 `challenge` as a Sui personal message and submit `address`, `challenge_id`, and the base64 `signature` to `POST /v1/owner-sessions/marketing-consent/verify`. A challenge expires in five minutes and can be submitted once. The returned bearer authorizes marketing consent for that owner for 15 minutes. Configure `SUI_GRPC_URL` for zkLogin signature verification and include the dashboard origin in `ALLOWED_ORIGINS`.

Send `email`, `policy_version`, and `source_surface` (`prompt` or `settings`) in the JSON body of `POST /v1/owners/{owner}/marketing-consent/verification`, with the bearer in `Authorization`. The relayer checks the active account and returns HTTP 202 with the masked address and timing. Submit the six-digit `code` to the same path with `/confirm` appended. Confirm returns `opted_in` on success. A code expires in 15 minutes or locks after three incorrect guesses. Resending replaces the code. On HTTP 429, wait for the seconds in `Retry-After` before retrying.

`EMAIL_DELIVERY_MODE=disabled` returns HTTP 503 from the verification endpoints. `log` logs the masked address and code on non-mainnet networks. `provider` uses SendGrid Mail Send. Set `EMAIL_PROVIDER_API_KEY` to a relayer-specific Mail Send key from the shared SendGrid account and `EMAIL_FROM_ADDRESS` to an address on Console's verified sending domain. Store the key in the environment's Walrus Memory 1Password vault. `EMAIL_API_BASE` defaults to `https://api.sendgrid.com` and accepts an HTTPS origin. `EMAIL_FROM_NAME` defaults to `Walrus Memory`.

The relayer commits the pending record and its code before sending. A delivery failure returns HTTP 503 and the pending record remains eligible for resend after the cooldown. `memwal_email_sends_total` reports delivery outcomes. Slack alerts are deduplicated by network and failure outcome. Provider response bodies never enter relayer logs.

On dev, run the challenge, signature, request, receive, and confirm flow with a testnet owner and a test inbox on the configured delivery mode. Verify `opted_in` and `verified_at` using the admin export. In log mode, retrieve the code from the relayer log and check for the masked address. Search the logs for the full test inbox address and confirm it does not appear.

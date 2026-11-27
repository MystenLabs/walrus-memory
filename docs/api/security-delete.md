## Security Delete API

The Security Delete API permanently deletes Walrus `Blob` objects owned by an
authenticated Sui wallet or zkLogin account across two isolated scopes:

- `scope=current`: post-migration memory blobs tracked in MemWal's primary
  database (`DATABASE_URL`).
- `scope=legacy` (default when `scope` is omitted): pre-migration memory blobs
  tracked in `LEGACY_DB_URL`.

The server selects and verifies the objects, builds and sponsors the
`walrus::system::delete_blob` Sui transaction, and executes it. The client only
authenticates its wallet (including browser wallets and zkLogin sessions, with
no private key export required) and signs the returned `TransactionData`.

This API never enrolls caller-supplied arbitrary blob IDs. In `scope=legacy` it
operates strictly on pre-seeded legacy tracking rows, and in `scope=current` it
synchronizes only the authenticated owner's own indexed post-migration blobs
from `vector_entries` and `remember_jobs`. When a deletion transaction commits
on Sui, finalization atomically deletes matching `vector_entries` rows, records
tombstones in `memory_tombstones` (when present) so deleted blobs are excluded
from `recall` and `restore`, and clears `remember_jobs.idempotency_key` so
re-saving identical content later is not blocked by a stale idempotency hit.

## Availability and feature flags

The new API is available only when both flags are enabled:

```text
ENABLE_MEMORY_DELETION=true
ENABLE_SECURITY_DELETE=true
```

The master flag without the selector exposes only the old deletion API. The
selector without the master flag is invalid and prevents server startup. No
configuration exposes both destructive API families simultaneously.

In every valid running configuration where the route pair is not enabled,
every endpoint in this guide returns the closed 404 `FEATURE_DISABLED`
response. This feature gate runs before authentication, query parsing, and
body extraction, so an unauthenticated or malformed request does not reveal a
disabled deployment.

Enabling the API requires `DATABASE_URL`, `SUI_GRPC_URL`, `WALRUS_PACKAGE_ID`,
`WALRUS_SYSTEM_OBJECT_ID`, `DELETION_TOKEN_SECRET`, and a base64-encoded
32-byte `SPONSOR_PRIVATE_KEY`. `LEGACY_DB_URL` is optional: when configured,
it must reference a dedicated pre-migration database distinct from `DATABASE_URL`
(pointing `LEGACY_DB_URL` at the primary database is rejected at boot because
pre-existing `vector_entries` rows lack unambiguous scope provenance).
When configured, both `scope=current` and `scope=legacy` are served against their
respective databases; when `LEGACY_DB_URL` is unset, `scope=current` operates
normally and requests with `scope=legacy` return `404 FEATURE_DISABLED`.
Configuration changes require a restart or rolling deployment.

The API supports browser requests from any origin. Cross-origin preflight
requests allow `GET`, `POST`, and `DELETE`, plus the `Content-Type` and
`Authorization` headers used by the flow below. Authentication and all other
authorization checks still apply to cross-origin callers.

The background selectors are independent of route exposure:
`DELETION_OBJECT_RESOLVER_ENABLED` might run with both route flags off, and
`DELETION_RECONCILER_ENABLED` might reconcile existing batches while routes are
off. Either job requires the primary database (plus `LEGACY_DB_URL` if legacy
reconciliation is used) and Sui gRPC configuration; the reconciler additionally
requires the sponsor key. Enabling a background job does not make any HTTP
endpoint reachable.

## Authentication

Authentication uses a single-use wallet challenge followed by a short-lived
Bearer token. Addresses are canonicalized to lowercase, 32-byte Sui hex form
before they are stored or compared.

### 1. Request a challenge

```http
POST /api/security-delete-auth/challenge
Content-Type: application/json

{"address":"0xabc"}
```

```json
{
  "challengeId": "31db510d-85f3-42ad-875a-0c14df36d40e",
  "challenge": "MemWal security deletion auth\naddress: 0x0000000000000000000000000000000000000000000000000000000000000abc\nnonce: 31db510d-85f3-42ad-875a-0c14df36d40e\nexpires: 1783760000",
  "expiresInSecs": 300
}
```

Sign the exact UTF-8 `challenge` string as a Sui personal message. Do not
reconstruct or normalize it on the client.

### 2. Verify the challenge

```http
POST /api/security-delete-auth/verify
Content-Type: application/json

{
  "challengeId": "31db510d-85f3-42ad-875a-0c14df36d40e",
  "address": "0xabc",
  "signature": "<base64 Sui user signature>"
}
```

```json
{
  "token": "<security-delete bearer token>",
  "expiresInSecs": 2700
}
```

`challengeId` is required and opaque. Challenges for the same wallet are
independent, but each ID can be consumed only once. Verification supports the
native Sui signature schemes and zkLogin through the fullnode's live onchain
JWK set.

Send the token on every endpoint below:

```http
Authorization: Bearer <token>
```

Malformed, tampered, and expired tokens intentionally share
`AUTH_TOKEN_EXPIRED`.

## List tracked blobs

```http
GET /api/security-deletable-blobs?scope=current&state=deletable&limit=100&cursor=<opaque>
Authorization: Bearer <token>
```

```json
{
  "items": [
    {
      "blobId": "X4...",
      "objectId": "0x123...",
      "createdAt": "2026-08-11T08:15:30.123456+00:00",
      "state": "deletable"
    }
  ],
  "counts": {
    "total": 12,
    "deletable": 8,
    "deleting": 2,
    "deleted": 1,
    "deletedExternal": 0,
    "notOwner": 1,
    "expired": 0
  },
  "limits": { "deleteBatchMax": 900 },
  "nextCursor": "<opaque-or-null>"
}
```

`scope` selects which tracking pool to query:

- `scope=current`: synchronizes the authenticated owner's post-migration blobs
  from `vector_entries` and `remember_jobs` in `DATABASE_URL` and lists their
  tracking states.
- `scope=legacy` (default when `scope` is omitted): lists pre-migration blobs in
  `LEGACY_DB_URL` (returns `404 FEATURE_DISABLED` if `LEGACY_DB_URL` is unset).
- Any other `scope` value returns `400 INVALID_REQUEST`.

The default state is `deletable`. `state` accepts one or more comma-separated
values from:

```text
deletable,deleting,deleted,deleted_external,not_owner,expired
```

Results use keyset ordering by `(createdAt, blobId)`. Cursors are opaque and
versioned; an invalid cursor never silently restarts at the first page. `limit`
must be between 1 and 200. Counts always cover all states for the authenticated
owner within the selected `scope`, regardless of the current `state` filter.

`limits.deleteBatchMax` is authoritative. It defaults to and is hard-capped at
900 because the measured 1,000-object Sui transaction exceeds the protocol's
128-KiB transaction-size limit.

## Prepare a deletion

Delete up to 900 currently deletable blobs selected by the backend in the
requested scope (`"legacy"` when `scope` is omitted, or `"current"` for
post-migration memories):

```http
POST /api/security-deletions
Authorization: Bearer <token>
Content-Type: application/json

{"mode":"all","scope":"current"}
```

Or request an exact single-blob or multi-blob tracked selection:

```json
{
  "mode": "selection",
  "scope": "current",
  "blobIds": ["blob-a"]
}
```

Successful preparation returns unsigned transaction bytes for the wallet:

```json
{
  "batchId": "ce77795f-ecf7-4a76-806f-abef834152b0",
  "txBytes": "<base64 BCS TransactionData>",
  "included": 2,
  "excluded": [
    { "blobId": "blob-c", "reason": "expired" }
  ],
  "expiresAt": "epoch:931"
}
```

Treat `expiresAt` as an informational, opaque expiration marker. Sign the
decoded `txBytes` as Sui transaction data (not as a personal message) and submit
that signature to the next endpoint.

If nothing remains after validation, preparation succeeds without a batch:

```json
{
  "batchId": null,
  "txBytes": null,
  "included": 0,
  "excluded": [],
  "expiresAt": null
}
```

Preparation is strict:

- `mode` must be exactly `all` or `selection`.
- `scope` is optional and must be `"legacy"` (default) or `"current"`.
- `all` must not include `blobIds`.
- `selection` must contain 1 to 900 unique, non-empty IDs.
- Every selected ID must already exist in the authenticated owner's tracking set
  for the requested `scope` and be `deletable`. One conflict rejects the entire
  selection; no row is partially claimed and no arbitrary untracked blob is
  inserted.
- Objects are re-read from Sui before the transaction is built. Missing,
  transferred, and near-expiry objects are removed from the batch and reported
  as `already_deleted`, `not_owner`, or `expired`.
- The returned transaction reflects the final included set. Its input ordering
  is persisted so later Sui failures can be mapped safely back to blob IDs.

Up to 16 batches per owner are active by default. The cap check and claim occur
under one short owner-scoped database lock, so concurrent prepares cannot race
past the cap. Independent prepared batches can be signed and submitted in
parallel afterward.

## Submit a signed batch

```http
POST /api/security-deletions/ce77795f-ecf7-4a76-806f-abef834152b0/submit
Authorization: Bearer <token>
Content-Type: application/json

{"signature":"<base64 Sui transaction signature>"}
```

```json
{
  "state": "completed",
  "deleted": 2,
  "digest": "8v..."
}
```

The server verifies the user signature against the stored bytes, atomically
claims execution, adds the sponsor signature, executes the transaction, checks
the returned digest and effects, then marks only that batch generation as
deleted.

If execution returns a timeout, rate-limit response, or another outcome whose
onchain result is unknown, the API returns `RPC_UNAVAILABLE` and deliberately
leaves the batch in `executing`. Do not immediately prepare replacements for
the same blobs. Poll the status endpoint; the reconciler confirms the
digest and finalize or release the batch.

Committed failures are resolved conservatively. When Sui identifies a culprit
input, MemWal rechecks that object, terminalizes only confirmed missing or
transferred blobs, and releases the remaining rows. Unknown failure shapes
trigger a full batch diff. Every write still includes the expected `batchId`,
so a late result from an older batch cannot mutate rows reclaimed by a newer
batch.

## Get batch status

```http
GET /api/security-deletions/ce77795f-ecf7-4a76-806f-abef834152b0
Authorization: Bearer <token>
```

```json
{
  "state": "executing",
  "blobCount": 2,
  "digest": "8v...",
  "resolvedAt": null
}
```

Possible states are `awaiting_signature`, `executing`, `completed`, `failed`,
and `rolled_back`. A batch owned by another wallet is indistinguishable from an
unknown batch and returns `BATCH_NOT_FOUND`.

## Cancel a prepared batch

```http
DELETE /api/security-deletions/ce77795f-ecf7-4a76-806f-abef834152b0
Authorization: Bearer <token>
```

Cancellation is accepted only while the batch is `awaiting_signature`. It
atomically changes the batch to `rolled_back` and releases only rows still
owned by that batch generation. The response uses the same shape as batch
status. Repeating the cancellation returns `BATCH_ALREADY_RESOLVED`.

## Validation and runtime limits

| Boundary | Limit |
|---|---:|
| Challenge body | 4 KiB |
| Verify body | 16 KiB |
| Prepare body | 256 KiB |
| Submit body | 16 KiB |
| List page | 1–200 items |
| Delete batch | 1–900 included blobs |
| Active batches per owner | 16 by default |
| Challenge lifetime | 300 seconds |
| Bearer lifetime | 2,700 seconds by default |
| Auth challenge/verify rate | 20 requests per IP per 60 seconds |
| Prepare rate | 10 requests per owner per 60 seconds |

Malformed JSON, oversized bodies, malformed UUID path parameters, malformed
query encoding, unknown filters, invalid cursors, and invalid selections all
use the same closed `INVALID_REQUEST` envelope. Client-supplied values are not
echoed in error messages.

## Error envelope

Every error has this shape:

```json
{
  "error": {
    "code": "BATCH_CONFLICT",
    "retriable": false,
    "action": "REFETCH",
    "message": "Deletion selection conflicts with current state",
    "details": { "conflictingBlobIds": ["blob-b"] }
  }
}
```

Clients should branch on `action`, use `code` for diagnostics, and treat
`message` as display text.

| Code | HTTP | Retriable | Action | Typical meaning |
|---|---:|:---:|---|---|
| `AUTH_CHALLENGE_EXPIRED` | 401 | no | `REAUTH` | Challenge expired, was consumed, or does not match the wallet |
| `AUTH_INVALID_SIGNATURE` | 401 | no | `NONE` | Challenge signature is invalid |
| `AUTH_TOKEN_EXPIRED` | 401 | no | `REAUTH` | Bearer is missing, malformed, tampered, or expired |
| `INVALID_REQUEST` | 400 | no | `NONE` | Request shape, filter, cursor, path, or selection is invalid |
| `ACTIVE_BATCH_LIMIT` | 409 | no | `REFETCH` | Owner has reached the active-batch cap; details include `activeBatchIds` |
| `BATCH_CONFLICT` | 409 | no | `REFETCH` | One or more selected blobs are missing or no longer deletable |
| `NOTHING_TO_DELETE` | 200* | no | `REFETCH` | Represented by the successful null-batch prepare response, not an error response |
| `BATCH_NOT_FOUND` | 404 | no | `REFETCH` | Batch does not exist for the authenticated owner |
| `BATCH_ALREADY_RESOLVED` | 409 | no | `REFETCH` | Batch is executing or terminal; details include its state |
| `BATCH_EXPIRED` | 410 | no | `RE_PREPARE` | Prepared batch was rolled back or expired |
| `TX_EXECUTION_FAILED` | 502 | no | `RE_PREPARE` | Sui committed a failure; details might include evicted blob IDs |
| `SPONSOR_FUNDS_UNAVAILABLE` | 503 | yes | `RETRY_AFTER` | Sponsor address balance cannot fund gas; do not re-prepare the unchanged blob pool |
| `INVALID_SIGNATURE` | 400 | no | `NONE` | Submit signature does not verify against stored transaction bytes |
| `RATE_LIMITED` | 429 | yes | `RETRY_AFTER` | Retry after `details.retryAfterSecs` |
| `RPC_UNAVAILABLE` | 503 | yes | `RETRY_AFTER` | Sui outcome is unavailable or uncertain; poll status when submit reached execution |
| `INTERNAL_ERROR` | 500 | yes | `RETRY_AFTER` | Sanitized server failure; details contain only a `traceId` |
| `FEATURE_DISABLED` | 404 | no | `NONE` | Master flag or security-delete selector is off |

`*` `NOTHING_TO_DELETE` is a semantic code used by the contract documentation;
the shipped HTTP response is the 200 prepare success shape with `batchId: null`.

## End-to-end example

```bash
# 1. Request and sign the returned personal-message challenge in the wallet.
curl -sS "$MEMWAL_URL/api/security-delete-auth/challenge" \
  -H 'content-type: application/json' \
  -d '{"address":"0xabc"}'

# 2. Exchange challengeId + exact-message signature for a Bearer.
curl -sS "$MEMWAL_URL/api/security-delete-auth/verify" \
  -H 'content-type: application/json' \
  -d '{"challengeId":"<id>","address":"0xabc","signature":"<personal-signature>"}'

# 3. Prepare a single-blob post-migration deletion (or use "scope":"legacy" / "mode":"all").
curl -sS "$MEMWAL_URL/api/security-deletions" \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"mode":"selection","scope":"current","blobIds":["<blob-id>"]}'

# 4. Sign decoded txBytes as Sui TransactionData, then submit.
curl -sS "$MEMWAL_URL/api/security-deletions/$BATCH_ID/submit" \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"signature":"<transaction-signature>"}'

# 5. Recover after a dropped/ambiguous submit response.
curl -sS "$MEMWAL_URL/api/security-deletions/$BATCH_ID" \
  -H "authorization: Bearer $TOKEN"
```

## Verification, cache limits, and fallback support

- **Verify deletion**: Confirm `state: "completed"` and a non-null Sui `digest`
  from submit or batch status, inspect `GET /api/security-deletable-blobs?scope=current&state=deleted`
  to see the blob in `deleted` state, verify on Sui that the `Blob` object ID no
  longer exists as a live object, and verify via `POST /api/recall` that the
  memory is absent from search results.
- **Caches and copies**: Destroying the onchain `Blob` object and purging the
  relayer index does not immediately evict ciphertext cached by HTTP aggregators
  or CDNs before TTL expiry, physical storage-node sliver reclamation completes
  asynchronously across Walrus epochs, and any plaintext already delivered to
  MCP clients, SDK callers, logs, or LLM chat histories remains outside Walrus
  Memory.
- **Fallback support**: When a newly stored blob has not yet completed ownership
  transfer (`not_owner`), or when self-service deletion routes return
  `404 FEATURE_DISABLED` on a deployment, owners can request verification and
  deletion support via [GitHub Issues](https://github.com/MystenLabs/MemWal/issues)
  or the official Walrus Discord by providing their public owner Sui address,
  target `blobId`, and a wallet-signed ownership message (never an exported
  private key).

## Concurrency and safety guarantees

- Owner identity always comes from the verified Bearer, never a request body.
- Selection claims update existing tracking rows for the requested `scope` only
  and are all-or-nothing.
- Active-cap checking, batch creation, and row claiming share one transaction
  under an owner-scoped advisory lock.
- Every batch transition compares the expected state.
- Every mutation of a claimed blob compares owner, blob ID, expected state,
  and expected batch ID.
- Cancel, failure rollback, and successful finalization are atomic database
  transactions.
- Transaction input-to-blob ordering is persisted before signing.
- Sponsor signatures are generated only at submit time and are never returned
  or stored.
- Transport failures with unknown execution outcomes remain `executing` until
  status reconciliation proves the result.

These rules prevent partial selection, active-cap races, arbitrary blob
enrollment, replay between batches, and stale asynchronous results overwriting
a newer claim.

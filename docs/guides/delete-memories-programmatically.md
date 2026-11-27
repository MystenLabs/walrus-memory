---
title: "Delete memories programmatically"
description: >-
  Find and permanently delete post-migration or pre-migration Walrus Memory blobs through
  the Security Delete API using wallet authentication and sponsored Sui transactions.
keywords:
  - Walrus Memory
  - MemWal
  - delete memories
  - Security Delete API
  - programmatic deletion
  - Sui transaction
goal:
  description: Write a script that signs with a wallet, lists post-migration or legacy memories by scope or cutoff date, and permanently deletes single blobs or batches via the Security Delete API.
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 300
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - "How do I delete Walrus Memory blobs programmatically?"
  - "How do I delete a single post-migration memory blob via the Security Delete API?"
  - "What endpoints does the MemWal Security Delete API use?"
  - "How do I authenticate with the Security Delete API to remove memories?"
answer: >-
  Use the Security Delete API with scope=current (post-migration) or scope=legacy
  (pre-migration) to authenticate with a wallet challenge, list deletable blobs, prepare
  a single-blob or batch sponsored deletion transaction, and submit the wallet signature.
  Interactive apps and zkLogin accounts sign challenges and transactions directly in the
  browser without exporting a private key.
---

## Overview

Use the Security Delete API to list memories owned by a wallet, select a single blob ID
or memories older than a cutoff date, and permanently delete them. Pass `scope=current`
to target post-migration memories in the active relayer database, or `scope=legacy`
(the default when omitted) to target pre-migration records. The API prepares and sponsors
the Sui transaction; your wallet authenticates the requests and signs the prepared
transaction.

<Warning>
  Deletion is permanent. Start with the dry run in this guide, review every blob ID, and
  only then enable deletion.
</Warning>

The deletion flow uses these endpoints:

| Step | Endpoint | Purpose |
| --- | --- | --- |
| 1 | `POST /api/security-delete-auth/challenge` | Request a single-use wallet challenge. |
| 2 | `POST /api/security-delete-auth/verify` | Exchange the signed challenge for a short-lived Bearer token. |
| 3 | `GET /api/security-deletable-blobs` | List tracked blobs in `scope=current` or `scope=legacy`. |
| 4 | `POST /api/security-deletions` | Prepare a sponsored single-blob or batch deletion transaction. |
| 5 | `POST /api/security-deletions/{batchId}/submit` | Submit the wallet signature and execute the deletion. |

## Before you begin

You need:

- Node.js 22.23.4+ (22.x), 24.22.1+ (24.x), or 26.12.1+ (26.x).
- The base URL of a MemWal deployment with the Security Delete API enabled.
- Either a local Sui keypair for unattended CLI automation, or an interactive browser
  wallet / zkLogin session.

The CLI example below uses an Ed25519 key stored in an environment variable or secret
manager (never commit keys to source control). If your account uses **zkLogin** or a
browser wallet without an exported private key, use the dashboard flow in
[Delete memories](/guides/delete-old-memories) or call the connected wallet's
`signPersonalMessage` and `signTransaction` hooks against the same HTTP endpoints.

Create a small Node.js project and install the Sui SDK:

```bash
npm install @mysten/sui
npm install --save-dev tsx
```

## Create the deletion script

Create `delete-old-memories.ts`:

```ts
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography'
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519'
import { fromBase64 } from '@mysten/sui/utils'

type Challenge = {
  challengeId: string
  challenge: string
  expiresInSecs: number
}

type BlobItem = {
  blobId: string
  objectId: string | null
  createdAt: string
  state: string
}

type BlobPage = {
  items: BlobItem[]
  limits: { deleteBatchMax: number }
  nextCursor: string | null
}

type PreparedBatch = {
  batchId: string | null
  txBytes: string | null
  included: number
  excluded: Array<{ blobId: string; reason: string }>
  expiresAt: string | null
}

type BatchStatus = {
  state: 'awaiting_signature' | 'executing' | 'completed' | 'failed' | 'rolled_back'
  blobCount: number
  digest: string | null
  resolvedAt: string | null
}

const baseUrl = requireEnv('MEMWAL_URL').replace(/\/$/, '')
const privateKey = requireEnv('SUI_PRIVATE_KEY')
const scope = parseScope(process.env.DELETE_SCOPE ?? 'current')
const targetBlobId = process.env.TARGET_BLOB_ID?.trim() || null
const maxAgeDays = positiveNumber(process.env.MEMORY_MAX_AGE_DAYS ?? '90')
const confirmed = process.env.CONFIRM_DELETE === 'true'

const decoded = decodeSuiPrivateKey(privateKey)
if (decoded.scheme !== 'ED25519') {
  throw new Error(`This example requires an Ed25519 key, received ${decoded.scheme}`)
}
const signer = Ed25519Keypair.fromSecretKey(decoded.secretKey)
const address = signer.toSuiAddress()

function requireEnv(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`${name} is required`)
  return value
}

function parseScope(value: string): 'current' | 'legacy' {
  const normalized = value.trim()
  if (normalized === 'current' || normalized === 'legacy') return normalized
  throw new Error('DELETE_SCOPE must be "current" or "legacy"')
}

function positiveNumber(value: string): number {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error('MEMORY_MAX_AGE_DAYS must be a positive number')
  }
  return parsed
}

async function api<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('accept', 'application/json')
  if (init.body) headers.set('content-type', 'application/json')
  if (token) headers.set('authorization', `Bearer ${token}`)

  const response = await fetch(`${baseUrl}${path}`, { ...init, headers })
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const error = body?.error
    throw new Error(
      `${response.status} ${error?.code ?? 'UNKNOWN'}: ${error?.message ?? 'Request failed'}`,
    )
  }
  return body as T
}

async function authenticate(): Promise<string> {
  const challenge = await api<Challenge>('/api/security-delete-auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ address }),
  })

  // Sign the exact UTF-8 bytes returned by the server. Do not rebuild the message.
  const signed = await signer.signPersonalMessage(
    new TextEncoder().encode(challenge.challenge),
  )

  const verified = await api<{ token: string }>('/api/security-delete-auth/verify', {
    method: 'POST',
    body: JSON.stringify({
      challengeId: challenge.challengeId,
      address,
      signature: signed.signature,
    }),
  })
  return verified.token
}

async function listDeletable(token: string): Promise<{
  items: BlobItem[]
  batchMax: number
}> {
  const items: BlobItem[] = []
  let cursor: string | null = null
  let batchMax = 900

  do {
    const query = new URLSearchParams({ scope, state: 'deletable', limit: '200' })
    if (cursor) query.set('cursor', cursor)
    const page = await api<BlobPage>(
      `/api/security-deletable-blobs?${query.toString()}`,
      {},
      token,
    )
    items.push(...page.items)
    batchMax = Math.min(batchMax, page.limits.deleteBatchMax)
    cursor = page.nextCursor
  } while (cursor)

  return { items, batchMax }
}

async function main() {
  const token = await authenticate()
  const { items, batchMax } = await listDeletable(token)
  const cutoff = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000)
  const candidates = (
    targetBlobId
      ? items.filter((item) => item.blobId === targetBlobId)
      : items.filter((item) => new Date(item.createdAt) < cutoff)
  ).sort((a, b) => a.createdAt.localeCompare(b.createdAt))

  console.log(`Wallet: ${address}`)
  console.log(`Scope: ${scope}`)
  console.log(targetBlobId ? `Target blob: ${targetBlobId}` : `Cutoff: ${cutoff.toISOString()}`)
  console.table(
    candidates.map(({ blobId, objectId, createdAt }) => ({ blobId, objectId, createdAt })),
  )

  if (candidates.length === 0) {
    console.log('No matching deletable memories found.')
    return
  }
  if (!confirmed) {
    console.log('Dry run only. Set CONFIRM_DELETE=true after reviewing the list.')
    return
  }

  let deleted = 0
  for (let offset = 0; offset < candidates.length; offset += batchMax) {
    const blobIds = candidates.slice(offset, offset + batchMax).map((item) => item.blobId)
    const prepared = await api<PreparedBatch>(
      '/api/security-deletions',
      {
        method: 'POST',
        body: JSON.stringify({ mode: 'selection', scope, blobIds }),
      },
      token,
    )

    if (!prepared.batchId || !prepared.txBytes) {
      console.log('The batch contained nothing that remained deletable.')
      continue
    }
    if (prepared.excluded.length > 0) {
      console.table(prepared.excluded)
    }

    // txBytes is the exact sponsored TransactionData prepared by the server.
    const signed = await signer.signTransaction(fromBase64(prepared.txBytes))

    try {
      const result = await api<{ deleted: number; digest: string }>(
        `/api/security-deletions/${encodeURIComponent(prepared.batchId)}/submit`,
        {
          method: 'POST',
          body: JSON.stringify({ signature: signed.signature }),
        },
        token,
      )
      deleted += result.deleted
      console.log(`Deleted ${result.deleted} memories in transaction ${result.digest}`)
    } catch (submitError) {
      // A transport error can leave execution outcome uncertain. Check the batch before
      // preparing a replacement transaction for the same blobs.
      const status = await api<BatchStatus>(
        `/api/security-deletions/${encodeURIComponent(prepared.batchId)}`,
        {},
        token,
      )
      console.error(`Batch ${prepared.batchId} is ${status.state}.`, submitError)
      throw new Error('Deletion stopped; resolve this batch before retrying.')
    }
  }

  console.log(`Deleted ${deleted} memories in total.`)
}

await main()
```

## Run a dry run

Set the API URL, wallet key, scope (`current` for post-migration memories or `legacy` for
pre-migration records), and either `TARGET_BLOB_ID` (for a single blob) or
`MEMORY_MAX_AGE_DAYS`. The script only lists candidates unless `CONFIRM_DELETE` is
exactly `true`.

```bash
export MEMWAL_URL="https://your-memwal-deployment.example"
export SUI_PRIVATE_KEY="suiprivkey1..."
export DELETE_SCOPE="current"
export TARGET_BLOB_ID="<optional-single-blob-id>"
export MEMORY_MAX_AGE_DAYS="90"

npx tsx delete-old-memories.ts
```

Review the wallet address, scope, target blob or cutoff timestamp, blob IDs, object IDs,
and creation dates in the output.

## Delete the reviewed memories

After you confirm the dry-run output, enable deletion and run the same script again:

```bash
export CONFIRM_DELETE="true"
npx tsx delete-old-memories.ts
```

The script chunks the selection using the server's `deleteBatchMax` value. Each batch
requires a newly prepared transaction and wallet signature.

## Verify the deletion, cache limits, and fallback support

Run the script again without `CONFIRM_DELETE`. Successfully deleted blobs no longer appear
in the default `deletable` list, their Sui `Blob` objects are destroyed onchain (check
the logged transaction `digest` in a Sui explorer), and post-migration rows are purged and
tombstoned in `recall`. To inspect terminal states directly, request them with the same
Bearer token:

```http
GET /api/security-deletable-blobs?scope=current&state=deleted,deleted_external&limit=200
Authorization: Bearer <token>
```

If submitting a batch times out or returns `RPC_UNAVAILABLE`, query
`GET /api/security-deletions/{batchId}` until it reaches a terminal state. Do not prepare a
replacement batch for the same blobs while its state is `executing`.

Note that HTTP aggregator or CDN caches may retain recently served ciphertext until cache
expiry, storage-node sliver reclamation finishes asynchronously across epochs, and copies
already fetched by MCP clients, SDK callers, or LLM chat histories must be cleared
separately. If a blob remains in `not_owner` or self-service deletion returns
`404 FEATURE_DISABLED`, follow the wallet-signed ownership verification and support path
documented in [Delete memories](/guides/delete-old-memories).

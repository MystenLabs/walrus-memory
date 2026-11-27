---
title: "Delete memories"
description: >-
  Review and permanently delete post-migration or pre-migration memories from your
  Walrus Memory account using the dashboard's Delete memories panel, including
  single-blob zkLogin and wallet deletion, preview, verification, cache limits, and fallback support.
keywords:
  - Walrus Memory
  - MemWal
  - delete memories
  - single blob deletion
  - zkLogin
  - dashboard
  - memory management
goal:
  description: Use the memory.walrus.xyz dashboard to preview and select post-migration or pre-migration memories, permanently delete a single blob or batch with a connected wallet or zkLogin account without exporting a private key, verify deletion, and understand cache limits and fallback support.
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
  - "How do I delete a single post-migration memory from Walrus Memory?"
  - "Can zkLogin accounts delete memories without exporting a private key?"
  - "How do I preview memories before deleting them in MemWal?"
  - "How do I verify that a memory blob was permanently deleted, and what cache limits apply?"
answer: >-
  Sign in to the Walrus Memory dashboard with your browser wallet or zkLogin account,
  open the Delete memories panel, choose Post-migration (or Pre-migration for older
  records), preview individual blobs, check a single blob or multiple rows, and sign
  the sponsored Sui deletion transaction directly in your wallet session without
  exporting a private key. Verify deletion via the Deleted status, the returned Sui
  transaction digest, and recall results, noting temporary aggregator caches and prior client copies.
---

## Overview

You can review and permanently delete individual post-migration memory blobs as well as
older pre-migration records directly from the dashboard. Because the server prepares and
sponsors the `walrus::system::delete_blob` Sui transaction while your connected session
only signs the challenge and transaction bytes, both browser wallets and zkLogin accounts
(such as Google sign-in via Enoki) can delete a single memory blob without exporting an
owner private key.

<Warning>
  Deleting a memory is permanent and you cannot undo it. Preview your memories before you
  delete them.
</Warning>

## Before you begin

Sign in with the browser wallet or zkLogin account that owns the memories you want to
remove. After you sign in, open the dashboard at `/dashboard`.

## Navigate to the Delete memories panel

On the dashboard, scroll down to the **Delete memories** panel and choose the storage
scope at the top right of the card:

- **Post-migration** (default): current Walrus Memory blobs stored on the active contract
  and relayer index.
- **Pre-migration**: legacy blobs stored before the July 30, 2026 migration.

Within the selected scope, the panel shows how many memories your account holds and their
current status:

- **Stored**: memories that your connected wallet currently owns and can delete.
- **In progress**: memories that have an active deletion transaction in flight.
- **Deleted**: memories whose onchain Walrus `Blob` objects have been deleted.

Each memory appears as a row with these columns:

| Column | Description |
| --- | --- |
| Select | Checkbox that you use to choose one or more memories for deletion. |
| Blob | The Walrus blob ID of the stored memory. |
| Object | The owned onchain Sui `Blob` object ID. |
| Created | The date you stored the memory. |
| State | The memory state, such as `deletable`, `deleting`, `not_owner`, or `deleted`. |
| Preview | Decrypts and opens a preview of the stored memory content in your browser. |

## Preview a memory before deleting

To check what a memory contains before you delete it, select **Preview** on its row. Your
connected wallet or zkLogin session signs a short-lived Seal session key so your browser
can decrypt the ciphertext locally and show the plaintext in the **Memory preview**
dialog. Close the preview when you finish.

<Note>
  Previewing helps you confirm the exact blob ID and text before deleting, because onchain
  blob deletion cannot be reversed.
</Note>

## Delete a single memory or a batch

Use the checkboxes in the **Select** column to pick the exact blob (or blobs) you want to
remove:

- **Delete a single memory**: check one row and select **Delete selected (1)**. The
  confirmation dialog displays the exact Walrus blob ID so you can double-check it before
  signing.
- **Delete multiple or all memories**: check several rows (or choose **Select page**) and
  select **Delete selected (n)**, or select **Delete all (n)** to remove every deletable
  blob in the active scope.

<Warning>
  Single-blob and batch deletions are permanent. You cannot recover deleted memories.
</Warning>

When you confirm, your wallet or zkLogin session signs a one-time authentication challenge
(if not already authenticated) and signs the sponsored Sui deletion transaction. No SUI gas
balance or exported private key is required. When execution completes, the banner shows
confirmation along with the Sui transaction digest (`Tx: ...`), and the row moves to the
`deleted` state.

## Verify the deletion

You can verify that a memory blob was permanently deleted across all three layers:

1. **Dashboard status and transaction digest**: In the **Delete memories** panel, confirm
   that the **Deleted** count increased, the row state is `deleted` under the **Deleted**
   filter tab, and a Sui transaction digest (`Tx: ...`) was returned.
2. **Onchain Sui `Blob` object**: Look up the transaction digest or the row's **Object**
   ID in a Sui explorer (or run `sui client object <objectId>`). Confirm that the
   transaction succeeded and destroyed the `walrus::blob::Blob` object so it no longer
   exists as a live owned object.
3. **Relayer search index**: Run a `recall` query for the deleted memory's phrasing. For
   post-migration deletions, the relayer atomically purges the `vector_entries` rows,
   records a deletion tombstone so `POST /api/recall` and `restore` will not resurrect the
   deleted blob, and clears any stored `remember` idempotency key for that blob.

## Limits involving caches and copies

Deleting a deletable Walrus `Blob` destroys the onchain object and removes the memory
from MemWal's search index, with the following boundaries:

- **Aggregator caches and Seal decryption**: Public Walrus HTTP aggregators, CDNs, or
  intermediate proxies that recently served the encrypted blob bytes may continue
  returning cached ciphertext until their cache TTL expires. Destroying a Walrus `Blob`
  does not revoke future Seal key release under the current contract because `account::seal_approve`
  authorizes the account owner or active delegates rather than checking blob deletion state.
  An authorized account can therefore still decrypt cached ciphertext retained by an
  aggregator after deletion.
- **Storage-node reclamation timing**: Destroying the onchain `Blob` object marks the
  storage resource as deleted on Sui immediately, while physical erasure of encrypted
  slivers on individual Walrus storage nodes completes asynchronously as nodes process
  deletion events and advance across epochs.
- **Copies outside Walrus Memory**: Deleting a blob cannot retract plaintext that an MCP
  client, SDK caller, agent runtime, terminal log, or LLM provider conversation history
  already fetched and stored before the deletion occurred. Clear any sensitive text in
  your local client history or third-party chat logs separately.

## Fallback support path

Self-service wallet deletion requires two conditions: the Security Delete feature is
enabled on the relayer deployment, and the Walrus `Blob` Sui object has already been
transferred to your owner wallet address (`deletable` state).

- **Newly written blobs still transferring (`not_owner` or `resolving`)**: Right after a
  memory is written, the relayer uploads the encrypted blob and transfers the Sui `Blob`
  object to your owner address asynchronously. Wait a moment for the background upload and
  transfer job to finish, then select **Refresh** in the **Delete memories** panel.
- **Stuck ownership transfer or disabled self-service deletion**: If a blob remains in
  `not_owner` after upload settles, if `objectId` cannot be resolved, or if self-service
  deletion is disabled on the deployment (`404 FEATURE_DISABLED`), open a support request
  on [GitHub Issues](https://github.com/MystenLabs/MemWal/issues) or reach out to the
  Mysten Labs team in the official Walrus Discord. Include:
  1. Your public owner Sui address and MemWal account object ID.
  2. The target Walrus `blobId` (and Sui `objectId`, if shown) plus the environment
     (`memory.walrus.xyz` or `dev.memwal.ai`).
  3. A personal-message signature from your owner wallet or zkLogin session over a
     statement naming the `blobId`, your owner address, and a current UTC timestamp so the
     team can verify ownership and coordinate index tombstoning or relayer-held blob
     cleanup. Never share a private key, seed phrase, or delegate private key in a support
     request.

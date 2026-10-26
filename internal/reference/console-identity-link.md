---
title: "Console Identity Link"
description: >-
  End-to-end sequence and API contract for how Walrus Console links a signed-in
  user to their Walrus Memory owner address, covering Enoki Connect, the
  wallet-signature fallback, and the MemWalAccount existence-check endpoint WM
  exposes to Console before a link is persisted.
keywords:
  - Walrus Memory
  - MemWal
  - Console
  - identity link
  - Enoki Connect
  - MemWalAccount
goal:
  description: Understand how a Console user's WM owner address gets verified and confirmed to exist, which side (Console vs WM) is responsible for each step, and what API contract WM exposes for this.
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
  - "How does Console verify which Walrus Memory address a signed-in user owns?"
  - "What does GET /api/accounts/:owner/exists return?"
  - "Why can't Console derive a user's Walrus Memory address on its own?"
  - "What is the MemWalAccount existence-check endpoint for?"
answer: >-
  Console and Walrus Memory (WM) are separate Enoki zkLogin apps, so the same
  human has a different Sui address in each. Console proves control of the WM
  address (Y) itself, via Enoki Connect or a wallet-signature challenge — WM is
  not involved in that proof. WM's only role is a read-only confirmation step:
  GET /api/accounts/:owner/exists, called after Console has already verified
  control of Y, to confirm a MemWalAccount actually exists at that address
  before Console persists the link record.
---

# Console Identity Link

## Overview

Console (Walrus Console) and Walrus Memory (WM) are separate Enoki zkLogin applications. The same signed-in human has **two different Sui addresses** — `X` in Console, `Y` in WM — because zkLogin address derivation includes the OAuth client ID (`aud`) as a direct input (see the [Sui zkLogin address derivation spec](https://docs.sui.io/concepts/cryptography/zklogin) — different `aud` values deterministically produce different addresses, even for the identical `iss`/`sub`/salt). Console cannot compute `Y` from its own session; it has to obtain and verify it separately. This document describes that flow and the one API contract WM exposes as part of it.

## Who does what

**Proving control of `Y` is entirely Console's responsibility.** WM does not participate in that proof — WM has no endpoint that verifies a signature or issues a challenge on Console's behalf. Console has two ways to do this itself:

- **Enoki Connect** — Console registers WM's Enoki Connect wallet (`registerEnokiConnectWallets`, using WM's Public App Slug — see `internal/reference/enoki-connect-requirements.md`) and drives a signed-challenge flow directly against that wallet.
- **Self-custody wallet fallback** — the user connects a wallet they hold directly and signs a Console-issued challenge proving they control `Y`.

**WM's only role is a read-only confirmation, after the fact:** once Console believes it has a verified `Y`, it calls WM's existence-check endpoint to confirm a `MemWalAccount` actually exists at that address before persisting the `console_user ↔ Y` link record. WM never sees Console's challenge, signature, or proof — it only ever receives an address and answers a yes/no question about on-chain registry membership.

## Sequence

```
User                Console                          WM
 |                     |                               |
 |--- sign in --------->|                               |
 |                     |--- Enoki Connect or wallet ---|  (Console-only; WM not involved)
 |<-- prove control of Y (address derived/signed) ------|
 |                     |                               |
 |                     |--- GET /api/accounts/Y/exists->|
 |                     |<-- { "exists": true|false } ---|
 |                     |                               |
 |                     |-- persist console_user <-> Y --|  (only if exists: true)
```

This identity-link step is a prerequisite for a separate, not-yet-built flow that issues Console an owner-scoped token for actually reading memory data. For the broader context this fits into, see the [Memory Indexing for Console PRD](https://app.notion.com/p/mystenlabs/PRD-Memory-Indexing-for-Console-Phase-1-3aa6d9dcb4e98022b0b5eb58a41e9163) (internal, requires Notion access). *Ticket references: this doc's endpoint is WALM-298; the follow-up token-issuance flow is WALM-297.*

## API contract: `GET /api/accounts/:owner/exists`

The only WM-side endpoint in this flow.

**Request**

```
GET /api/accounts/{owner}/exists
```

- `owner` — a Sui address, `0x` + 64 hex characters (case-insensitive; normalized to lowercase server-side before lookup).
- No authentication required (see "Why this is public" below).
- Rate-limited per IP (20 req/min, 120 req/hour) plus a deployment-wide aggregate cap, to prevent cheap large-scale address enumeration.

**Response — `200 OK`**

```json
{ "exists": true }
```

`exists` is `true` if `owner` has ever created a `MemWalAccount` (i.e. it appears in WM's indexed `AccountRegistry` projection), `false` otherwise. This is **existence in the registry, not current activation status** — a deactivated/frozen `MemWalAccount` still resolves `exists: true`, by design (see `docs/architecture/permanent-registry-design.md`: the on-chain registry is permanent and append-only, and WM's indexer only processes `AccountCreated` events, so off-chain rows are never removed on deactivation either). If a caller needs to distinguish "never created" from "created but deactivated," this endpoint does not provide that — it only answers whether an account was ever created.

**Response — `400 Bad Request`**

Returned if `owner` is not a syntactically valid Sui address. Does not touch the database.

**Why this is public/unauthenticated:** the underlying `AccountRegistry` is itself a public on-chain Sui object — any caller could already determine whether an address owns a `MemWalAccount` via a direct RPC scan. This endpoint is a convenience/performance wrapper around that already-public fact, not a new information disclosure, so it does not require Console-specific authentication. Abuse is bounded by rate limiting instead of an auth boundary.

**CORS:** unauthenticated does not mean unrestricted-by-browser. WM's server has its own `ALLOWED_ORIGINS`-driven CORS layer (deny-by-default), separate from the Enoki Developer Portal's "Allowed Origins" setting described in `internal/reference/enoki-connect-requirements.md` — the two are unrelated mechanisms that happen to share a name. If Console ever calls this endpoint directly from browser JavaScript rather than server-to-server, Console's origin needs to be added to *WM's* `ALLOWED_ORIGINS` env var too, or the browser will block the response. If the identity-link flow stays server-side (as the "persist link record" step implies), this doesn't apply — flagging it so it isn't confused with the Enoki Portal setting if it ever does.

**Eventual consistency (indexer lag):** `exists` reflects WM's indexed view of the registry, not a live chain read (see `find_account_by_owner` in `services/server/src/storage/db.rs`). A `MemWalAccount` created moments ago can transiently return `exists: false` until WM's indexer (`services/indexer`, `accounts_v1` pipeline) processes the corresponding `AccountCreated` event. Under normal operation this lag is small, but callers building a "link fails right after account creation" UX path should treat a `false` result as "not confirmed yet," not necessarily "never existed" — retrying after a short delay is reasonable. (This is a property of the indexer's operational state in a given environment, not something this endpoint's own logic controls — see `internal/reference/enoki-connect-requirements.md`'s troubleshooting section if a `false` result persists far longer than expected.)

**Implementation:** `services/server/src/routes/accounts.rs` (`MystenLabs/MemWal` PR #533).

## What this flow deliberately does not do

- **It does not mint any token or credential.** Owner-scoped token issuance for reading memory data is a separate, not-yet-built piece that consumes the verified `Y` this flow produces — it is out of scope here (see the ticket note under "Sequence" above).
- **It does not let Console sign transactions as `Y`.** Neither Enoki Connect nor the wallet-signature fallback, as used here, grants Console any signing capability beyond the one-time link proof.
- **It does not require WM to trust Console's proof.** WM's existence check is independent of however Console verified control of `Y` — WM simply confirms the address exists, regardless of which method Console used to arrive at it.

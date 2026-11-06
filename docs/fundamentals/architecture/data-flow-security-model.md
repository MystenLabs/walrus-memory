---
title: Trust and Security Model
description: >-
  Where trust lives in Walrus Memory and how to mitigate it. Covers onchain enforcement of
  ownership and delegates, the relayer trust trade-off, mitigation options including self-hosting
  and manual client flow, and the Ed25519 authentication flow.
keywords:
  - Walrus Memory
  - MemWal
  - security model
  - trust model
  - encryption
  - onchain enforcement
  - authentication
goal:
  description: Map where trust is placed at each step of a memory operation, identify what the relayer can and cannot access, and apply trust-mitigation strategies like TEE deployment or the manual client.
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
  - How does Walrus Memory handle security and trust?
  - What does the MemWal relayer see and how can I reduce that trust?
  - How does authentication work in Walrus Memory?
answer: >-
  Walrus Memory splits security between onchain enforcement (ownership, delegate authorization,
  access control through Sui smart contracts) and offchain operations (encryption, embeddings handled
  by the relayer). Trust in the relayer can be mitigated by self-hosting, running in a TEE, or
  using the manual client flow where the relayer never sees plaintext data.
---

Walrus Memory's security model is split between onchain enforcement and offchain operations. Understanding where trust lives helps you make informed decisions about your deployment.

<figure>
  <iframe src="https://docs.wal.app/diagrams/interactive_trust-boundary_v1.html"
    style={{width:'100%',height:'440px',border:'0'}}
    title="Walrus Memory trust boundary across four deployment models. In the default relayer-backed flow the relayer receives plaintext and encrypts memory content before storing it on Walrus: a managed relayer sits outside your trust boundary, a self-hosted relayer keeps the flow inside your infrastructure, and a TEE relayer processes plaintext only inside an attested enclave. Only the manual client flow encrypts on the client, so the relayer handles only ciphertext. Sui enforces ownership and delegation in every mode."
    loading="lazy"></iframe>
  <figcaption>
    Data on Walrus is public and immutable, so encrypting memory content before upload provides confidentiality, and ownership and delegate rules on Sui enforce access. The diagram cycles through four deployment models, which differ in where plaintext lives. A managed relayer receives plaintext, generates embeddings, and encrypts before storing, so you trust its operator. Self-hosting keeps that same flow inside infrastructure you control. A TEE relayer processes plaintext only inside an attested enclave, and you must verify the attestation. Only the manual client flow encrypts on the client, so the relayer handles only ciphertext and precomputed vectors.
  </figcaption>
</figure>

## What's enforced onchain

These guarantees are cryptographic and tamper-proof, and no one can bypass them:

- **Ownership**: only the owner's private key controls a Walrus Memory account
- **Delegate authorization**: the smart contract registers and verifies delegate keys onchain
- **Access control**: the smart contract determines who can act on an account

Even a compromised relayer cannot change who owns an account or forge delegate permissions.

## Where the relayer is trusted

The relayer abstracts Web3 complexity to give developers a basic REST API. This convenience comes with a trust trade-off, because the relayer handles sensitive operations on behalf of users:

| **What the relayer sees** | **Why** |
|----------------------|-----|
| Plaintext memory content | It generates embeddings and encrypts before storing |
| Decrypted content on recall | It decrypts blobs to return results to the SDK |
| Vector embeddings | It stores and searches them for semantic recall |

This means the **relayer operator can see your data in transit**. This is similar to how a traditional backend API works: your server sees the data it processes.

## Mitigating relayer trust

You have options depending on your trust requirements:

| **Option** | **Trust level** | **What the relayer sees** |
|--------|------------|----------------------|
| **Managed relayer** | You trust Walrus Foundation | Plaintext content, embeddings, decrypted results |
| **Self-hosted relayer** | You trust your own infra | Same as above, but under your control |
| **TEE relayer pattern** | You trust the attested enclave identity and configured external services | Plaintext inside the enclave; you reduce host trust only by verifying attestation |
| **Manual client flow** | Minimal trust | Only encrypted payloads and pre-computed vectors, never plaintext |

- **Use the managed relayer**: convenient for getting started and prototyping. You trust Walrus Foundation to operate it responsibly.
- **Self-host your own relayer**: you control the infrastructure, so the trust boundary is entirely yours. No third party sees your data.
- **Run the relayer in a TEE**: move plaintext processing into an attested enclave. This reduces trust in the host operator, but clients or gateway policy must verify the enclave identity before treating it as a TEE-backed deployment.
- **Manual client flow**: use `MemWalManual` to handle encryption and embedding entirely on the client side. The relayer only sees encrypted payloads and vectors, never plaintext. This flow suits Web3-native users who want full control over their data and are comfortable managing keys, signing, and Seal operations directly.

<Warning>
**Do not pass client-encrypted ciphertext to the default `MemWal.remember(text)` flow.** In the default flow, the relayer embeds `text` directly; passing ciphertext causes the relayer to embed ciphertext bytes, which silently breaks semantic `recall()`. When encrypting on the client, always use [`MemWalManual`](/sdk/usage/memwal-manual) (`rememberManual` / `recallManual`) so you compute the embedding from plaintext on the client and send `{ encryptedData, vector }` to the relayer.
</Warning>

## What lives where

```mermaid
flowchart LR
    subgraph Onchain [Onchain — trustless]
        Contract[Ownership & delegates]
    end
    subgraph Offchain [Offchain — operator trust]
        Relayer[Encryption, embeddings, orchestration]
        DB[Vector search & caching]
    end
    subgraph Decentralized [Decentralized — durable]
        Walrus[Encrypted blobs]
    end

    Contract -. verifies .-> Relayer
    Relayer --> DB
    Relayer --> Walrus
```

- **Onchain (trustless)**: Sui smart contracts enforce ownership, delegate keys, and access control
- **Offchain (operator trust)**: the relayer and indexed database handle encryption, embedding, and search
- **Decentralized (durable)**: Walrus stores encrypted memory payloads with no single point of failure

## Authentication flow

Every protected API call goes through Ed25519 signature verification:

1. The SDK signs a message: `{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}` using the delegate private key
2. The relayer verifies the Ed25519 signature against the provided public key
3. Timestamps must be within a **5-minute window**, and the relayer records each `x-nonce` UUID in Redis for replay protection
4. The relayer resolves the public key to a `MemWalAccount` from the delegate-key cache, or by verifying the signed `x-account-id` (or `MEMWAL_ACCOUNT_ID`). It does not scan `AccountRegistry`
5. The relayer fetches the onchain account to verify the delegate key appears in `delegate_keys`
6. The relayer scopes all subsequent operations to the resolved owner address

## Current status

This describes the current production model. The trust boundaries continue to evolve: future versions might introduce client-side encryption by default or additional verifiability layers. Self-hosting remains the strongest option for teams that need full control today.

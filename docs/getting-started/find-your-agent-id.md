---
title: "Find Your Agent ID"
description: "Your Agent ID is your delegate public key. Find and copy it from the dashboard, the MCP credential file, or the SDK."
keywords:
  - agent id
  - MEMWAL_AGENT_ID
  - delegate public key
  - memwal_agent_id
  - follow activity
  - beta testing
questions:
  - What is my Walrus Memory Agent ID?
  - Where can I find my delegate public key?
  - How do I copy my Agent ID from the dashboard or SDK?
answer: >-
  Your Agent ID is the 64-character hex-encoded public key of the delegate key your
  client uses. Copy it from the dashboard's Public key (Agent ID) column, the
  delegatePublicKeyHex field in the active MCP credentials file, or the SDK's
  public-key method.
---

Your **Agent ID** is your **delegate public key**: a hex-encoded Ed25519 public key (64 hex characters, without a `0x` prefix). Use this raw public key when asked for `MEMWAL_AGENT_ID`; the delegate Sui address and account ID are separate identifiers. The relayer records the delegate public key in the memory blob's on-chain `memwal_agent_id` metadata to identify the key that wrote it.

<Note>
Each delegate key has its own Agent ID. An account can hold more than one delegate key, so it can have more than one Agent ID. Share the Agent ID for the key your app is configured with.
</Note>

## Find your Agent ID on the dashboard

The dashboard is the fastest way to collect your Agent ID.

<Steps>
  <Step>
    Open the [Walrus Memory dashboard](https://memory.walrus.xyz/dashboard) and connect the wallet that owns your account.
  </Step>
  <Step>
    Go to the **Delegate keys** section. Each row is one delegate key.
  </Step>
  <Step>
    The **Public key (Agent ID)** column holds your Agent ID. Use the copy button on the row to copy the full value. The displayed value is shortened for readability, but the copy button always copies the complete key.
  </Step>
</Steps>

## Other ways to find your Agent ID

### MCP and CLI clients

The stdio MCP package stores credentials in its active credentials file, normally `~/.memwal/credentials.json`. An approved project-local file or `MEMWAL_CREDS_DIR` can select a different location; see [Credential locations](/mcp/reference#credential-locations). Copy only the **`delegatePublicKeyHex`** field from that file. It is your Agent ID; `delegateAddress` is a separate, derived address. The file also contains your private key, so keep the file itself private.

### SDK

With an existing `MemWal` client, both SDKs return the Agent ID for the current delegate key:

<Tabs>
  <Tab title="TypeScript">
    ```ts
    const agentId = await memwal.getPublicKeyHex();
    console.log(agentId);
    ```
  </Tab>
  <Tab title="Python">
    ```py
    agent_id = await memwal.get_public_key_hex()
    print(agent_id)
    ```
  </Tab>
</Tabs>

The Python example uses the asynchronous `MemWal` client. With `MemWalSync`, call `memwal.get_public_key_hex()` without `await`.

## Why the Agent ID matters

The `memwal_agent_id` metadata lets you attribute memory blobs to a given delegate key. When reporting a problem or sharing beta feedback, provide the Agent ID for the key your client uses so the Walrus Memory team can find the activity tied to that key.

<Note>
The Agent ID is your delegate **public** key, so it is safe to share. Never share your delegate **private** key (`MEMWAL_PRIVATE_KEY`). Anyone who holds the private key can act as your agent until you revoke it.
</Note>

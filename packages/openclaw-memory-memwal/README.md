<h1 align="center">@mysten-incubation/oc-memwal</h1>

<p align="center">
  Cloud-based long-term memory plugin for NemoClaw/OpenClaw — gives your AI agents persistent, encrypted, cross-session memory powered by <strong>Walrus Memory</strong>.
</p>

<p align="center">
  <a href="https://docs.wal.app/walrus-memory/openclaw/overview"><strong>Documentation</strong></a> ·
  <a href="#quick-start"><strong>Quick Start</strong></a> ·
  <a href="#verify"><strong>Verify</strong></a> ·
  <a href="#how-it-works"><strong>How It Works</strong></a>
</p>
<br/>

## Overview

Replaces OpenClaw's default file-based memory with a **remote memory backend**. After setup, the plugin runs silently — your agent remembers things from past conversations and learns new facts automatically, with no user intervention required.

Memories are **encrypted** and stored on **Walrus Memory**, a privacy-preserving memory protocol built on Walrus decentralized storage. Each user owns their memories via an **Ed25519 key** — no platform can access them without it.

**Features:**
- **Auto-recall** — relevant memories injected before each conversation turn
- **Auto-capture** — facts extracted and stored after each turn
- **Agent tools** — `memory_search` and `memory_store` for explicit LLM control
- **Multi-agent isolation** — each agent gets its own memory namespace
- **Prompt injection protection** — detection and escaping on all read/write paths
- **CLI** — `openclaw memwal search` and `openclaw memwal stats` for debugging

## Prerequisites

Use a supported, security-patched Node.js runtime: **22.23.4+ within 22.x**, **24.22.1+ within 24.x**, or **26.12.1+ within 26.x**. The package `engines` field describes API compatibility, not the minimum security patch. See the [October 2026 Node.js security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).

### OpenClaw

You need [OpenClaw](https://openclaw.ai) `>=2026.3.11` installed and running, and a package manager ([bun](https://bun.sh), pnpm, or npm).

### Walrus Memory Setup

**Walrus Memory** is an open-source, self-hostable memory infrastructure kit for encrypted, decentralized storage. You can run your own relayer or use a managed endpoint.

The plugin needs three values:

| Value | What it is |
|-------|-----------|
| **Delegate Key** | Private key (64-char hex) used to sign requests and encrypt memories |
| **Account ID** | Your Walrus Memory account object ID on Sui (`0x...`) |
| **Relayer URL** | The Walrus Memory relayer endpoint that handles search, storage, and encryption |

Get your delegate key and account ID from the [Walrus Memory dashboard](https://memory.walrus.xyz), or see the [Quick Start guide](https://docs.wal.app/walrus-memory/getting-started/quick-start) for detailed setup.

For the relayer, use a managed endpoint or [self-host your own](https://docs.wal.app/walrus-memory/relayer/self-hosting):

| Environment | Relayer URL |
|-------------|-------------|
| **Production** (mainnet) | `https://relayer.memory.walrus.xyz` |
| **Staging** (testnet) | `https://relayer.dev.memwal.ai` |

## Quick Start

### 1. Install

```bash
openclaw plugins install @mysten-incubation/oc-memwal
```

### 2. Set your delegate key

Store your delegate key as an environment variable so it's never hardcoded in config files:

```bash
# Add to your shell profile (.zshrc, .bashrc, etc.)
export MEMWAL_PRIVATE_KEY="your-64-char-hex-key"
```

### 3. Configure OpenClaw

Add the plugin config to `~/.openclaw/openclaw.json`:

```jsonc
{
  "plugins": {
    "slots": { "memory": "oc-memwal" },
    "entries": {
      "oc-memwal": {
        "enabled": true,
        "config": {
          "privateKey": "${MEMWAL_PRIVATE_KEY}",             // References the env var
          "accountId": "0x3247e3da...",                    // Your account ID from the dashboard
          "serverUrl": "https://relayer.dev.memwal.ai"    // Or your self-hosted relayer
        }
      }
    }
  }
}
```

Optional settings you can add to the `config` block:

| Option | Default | Description |
|--------|---------|-------------|
| `autoRecall` | `true` | Inject relevant memories before each turn |
| `autoCapture` | `true` | Extract and store facts after each turn |
| `maxRecallResults` | `5` | Max memories to inject per turn |
| `minRelevance` | `0.3` | Relevance threshold (0-1) for memory injection |
| `captureMaxMessages` | `10` | How many recent messages to analyze for facts |

The defaults work well for most setups — you don't need to change them to get started.

### 4. Start OpenClaw

```bash
openclaw gateway stop && openclaw gateway
```

You should see in the logs:

```
memory-memwal: registered (server: https://..., key: e21d...ed9b, namespace: default)
memory-memwal: connected (status: ok, version: ...)
```

If you see `health check failed`, double-check that your server URL is reachable and your private key env var is set.

## Verify

### Check connectivity

Run the stats command to confirm the plugin is connected and configured correctly:

```bash
openclaw memwal stats
```

This shows the server status, your key (masked), account ID, active namespace, and whether auto-recall/capture are enabled.

### Test the memory loop

The core value of the plugin is the automatic recall/capture cycle. Test it end-to-end:

1. **Store a fact** — start a conversation and share something memorable:

   ```
   You: I prefer TypeScript over JavaScript for backend work
   Bot: (responds normally)
   ```

   Check logs — you should see `memory-memwal: auto-captured 1 facts`. The plugin extracted the preference and stored it.

2. **Recall it** — in a **new conversation**, ask about it:

   ```
   You: What programming languages do I like?
   ```

   Check logs — you should see `memory-memwal: auto-recall injected 1 memories`. The plugin found the stored preference and injected it into the LLM's context.

3. **Search from terminal** — confirm the memory exists via CLI:

   ```bash
   openclaw memwal search "programming"
   ```

If all three steps work, the plugin is fully operational.

---

## How it works

The plugin sits between OpenClaw's gateway and the Walrus Memory server. It operates through **hooks** — automatic callbacks that run on every conversation turn. The LLM never sees them, doesn't trigger them, and can't prevent them.

```mermaid
graph TB
    subgraph "OpenClaw Gateway"
        RECALL["Auto-Recall Hook"]
        PROMPT["Prompt Assembly"]
        CAPTURE["Auto-Capture Hook"]
    end

    subgraph "LLM"
        LLM_PROC["Language Model"]
    end

    subgraph "Walrus Memory Server"
        SEARCH["Vector Search"]
        ANALYZE["Fact Extraction"]
        STORE["Encrypted Storage"]
    end

    WALRUS["Walrus Network"]

    USER([User Message]) --> RECALL
    RECALL -->|"search memories"| SEARCH
    SEARCH --> RECALL
    RECALL -->|"inject into prompt"| PROMPT
    PROMPT --> LLM_PROC
    LLM_PROC --> RESPONSE([Response to User])
    RESPONSE --> CAPTURE
    CAPTURE -->|"extract facts"| ANALYZE
    ANALYZE --> STORE
    STORE --> WALRUS

    style RECALL fill:#4a9eff,color:#fff
    style CAPTURE fill:#4a9eff,color:#fff
    style LLM_PROC fill:#ff9f4a,color:#fff
    style STORE fill:#6b7280,color:#fff
```

Every conversation turn goes through two phases:

- **Auto-recall** — before the LLM sees the user's message, the plugin searches Walrus Memory for relevant memories and injects them into the prompt as context. The LLM sees these as background knowledge — it doesn't know they were injected.

- **Auto-capture** — after the LLM responds, the plugin extracts the conversation, filters out trivial content (filler responses, emoji, etc.), and sends it to the Walrus Memory server. The server-side LLM extracts individual facts and stores them as encrypted blobs on Walrus.

The plugin also registers two optional **tools** (`memory_search` and `memory_store`) that give the LLM explicit control over memory operations. These require `tools.allow` in the agent profile and are a power-user feature — hooks handle the common case automatically.

## License

Apache-2.0

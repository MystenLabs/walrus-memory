---
title: Codex
description: Add portable Walrus Memory to OpenAI Codex as a full plugin with automatic-memory hooks via the plugin marketplace, or as a plain MCP server.
keywords: [MCP, Codex, Walrus Memory, MemWal, plugin, automatic memory, marketplace]
goal:
  description: Add MemWal to Codex as an automatic memory plugin via the marketplace or MCP-only server, authenticate with your account credentials, and confirm persistent memory is working across sessions.
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
  - How do I add Walrus Memory to Codex?
  - How do I install the MemWal plugin on Codex?
  - Does Codex have a plugin marketplace for MemWal?
answer: >-
  To add Walrus Memory to Codex, install the MemWal plugin through the marketplace (codex plugin marketplace add MystenLabs/MemWal, then codex plugin add memwal@memwal-plugins), or add it as MCP-only by editing ~/.codex/config.toml directly. The plugin includes lifecycle hooks that reinforce automatic recall and save behavior on top of the MCP tools.
---

Add MemWal to Codex so it recalls context and saves durable facts as you work. Install it as a **plugin** (recommended; adds automatic-memory hooks) or as **MCP-only** (just the tools).

## Prerequisites

- Node.js 22.23.4+ (22.x), 24.22.1+ (24.x), or 26.12.1+ (26.x)
- A Codex CLI build with `codex plugin` support (shipped since ~April 2026; check with `codex plugin --help`) if you want the plugin install. MCP-only works on any version.
- A Walrus Memory account. The first memory tool call opens a browser sign-in (`memwal_login`).

## Installation

<Tabs>
  <Tab title="Plugin (recommended)">
    <Steps>
      <Step title="Add the marketplace and install">
        ```bash
        codex plugin marketplace add MystenLabs/MemWal
        codex plugin add memwal@memwal-plugins
        codex plugin list
        ```
        This registers the MemWal plugin, which bundles the MCP server and the lifecycle hooks together as plugin-scoped resources. It does not write a `[mcp_servers.memwal]` block to `~/.codex/config.toml`.
      </Step>
      <Step title="Trust the plugin hooks">
        Codex loads plugin-bundled hooks but does not run them until you trust the definition. Run `/hooks` (or follow the startup review prompt) and trust the MemWal hook commands.
      </Step>
      <Step title="Restart and sign in">
        Restart Codex. On first use the agent runs `memwal_login` to connect your wallet.
      </Step>
    </Steps>

    <Note>
    Older Codex CLI builds without `codex plugin` support can still get the hooks from a cloned repo:
    ```bash
    node packages/mcp/plugin/scripts/install_codex_hooks.mjs
    ```
    This merges the MemWal hooks into `~/.codex/hooks.json` and registers `[mcp_servers.memwal]` in `~/.codex/config.toml`. Re-running is safe (idempotent); add `--uninstall` to remove the hooks. This path writes the hooks file directly, so it needs `[features] codex_hooks = true` (or the modern equivalent `[features] hooks = true`, already the default) rather than the plugin trust flow above.
    </Note>
  </Tab>
  <Tab title="MCP-only">
    Add to `~/.codex/config.toml`:
    ```toml
    [mcp_servers.memwal]
    command = "npx"
    args = ["-y", "@mysten-incubation/memwal-mcp"]
    ```
    Restart Codex, then ask the agent to run `memwal_login` on first use. The
    memory tools are proactive, so this is enough for automatic save and recall.
  </Tab>
</Tabs>

<Warning>
Do not combine options: the plugin bundles the memwal MCP server on its own. Do not also add a manual `[mcp_servers.memwal]` block, which duplicates the server. (The cloned-repo fallback installer does write `[mcp_servers.memwal]` directly, so that one warning doesn't apply if you used it instead.)
</Warning>

## What the plugin includes

| Component | Plugin | MCP-only |
|---|:-:|:-:|
| MemWal MCP (memory tools) | ✓ | ✓ |
| Lifecycle hooks (automatic recall/save) | ✓ | ✗ |

MCP-only still saves and recalls on its own because the tools are proactive. The plugin adds hooks that reinforce the behavior and make the agent prefer Walrus Memory over any built-in memory.

## Available tools

| Tool | Description |
|------|-------------|
| `memwal_remember` | Save a durable fact (preference, decision, constraint, identity). |
| `memwal_remember_bulk` | Save several distinct facts in one call. |
| `memwal_recall` | Semantic search across stored memories for relevant context. |
| `memwal_analyze` | Extract and save multiple facts from a passage of text. |
| `memwal_restore` | Rebuild the search index from Walrus (recovery). |
| `memwal_health` | Fast connectivity check. |
| `memwal_login` / `memwal_logout` | Connect or disconnect this client. |

See [Reference](/mcp/reference) for full parameters.

## Lifecycle hooks (plugin only)

| Hook | Event | What it does |
|------|-------|--------------|
| Session start | `SessionStart` | Announces that memory is active and reminds the agent to use the `memwal_*` tools. |
| User prompt | `UserPromptSubmit` | Injects a decision rubric so the agent chooses recall vs save from meaning (any language or spelling). |
| Post-tool | `PostToolUse` (Bash) | When a command errors, reminds the agent to recall prior fixes and save the resolution. |

## Verify

Ask the agent what MCP tools it has available. You should see the `memwal_*` tools, including `memwal_remember_bulk` and `memwal_health`. Then state a durable fact and confirm the agent saves it with `memwal_remember`.

## Troubleshooting

- **Tools missing**: restart Codex.
- **Duplicate `memwal` errors**: the plugin already bundles the MCP server; you likely also have a manual `[mcp_servers.memwal]` block. Remove it.
- **Hooks not firing (plugin install)**: run `/hooks` and confirm the MemWal hooks are trusted, not just installed.
- **Hooks not firing (cloned-repo fallback)**: confirm `codex_hooks = true` under `[features]` in `~/.codex/config.toml`, and that you restarted Codex.
- **`memwal_recall` returns nothing although you saved before**: run `memwal_restore <namespace>` to rebuild the index from Walrus.

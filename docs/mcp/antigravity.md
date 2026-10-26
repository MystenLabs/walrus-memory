---
title: Antigravity
description: >-
  Add portable Walrus Memory to Antigravity through the MemWal MCP server.
  Install as a plugin with automatic memory hooks or as MCP-only for just the memory tools.
keywords:
  - MCP
  - Antigravity
  - Walrus Memory
  - MemWal
  - plugin
  - automatic memory
goal:
  description: Add MemWal to Antigravity as a plugin with lifecycle hooks or as a standalone MCP server, authenticate with your account credentials, and verify the connection with a test recall.
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
  - How do I add Walrus Memory to Antigravity?
  - How do I install the MemWal plugin on Antigravity?
  - What lifecycle hooks does the MemWal Antigravity plugin provide?
answer: >-
  To add Walrus Memory to Antigravity, install MemWal as a plugin by deploying to Antigravity's plugin directory using npx degit, or configure it as MCP-only by adding the server to Antigravity's MCP configuration. The plugin includes lifecycle hooks for session start, user prompt, and post-tool events that drive automatic recall and save behavior.
---

Add MemWal to Antigravity so the agent recalls context and saves durable facts. Install it as a **plugin** (adds automatic-memory hooks) or as **MCP-only** (just the tools).

## Prerequisites

- Node.js 22.23.4+ (22.x), 24.22.1+ (24.x), or 26.12.1+ (26.x)
- A Walrus Memory account. The first memory tool call opens a browser sign-in (`memwal_login`).

## Installation

<Tabs>
  <Tab title="Plugin (recommended)">
    Deploy the plugin (MCP server + lifecycle hooks) into Antigravity's plugin directory:
    ```bash
    npx degit MystenLabs/MemWal/packages/mcp/plugin ~/.gemini/config/plugins/memwal
    ```
    Restart Antigravity, then ask the agent to run `memwal_login` on first use.
  </Tab>
  <Tab title="MCP-only">
    Add the MemWal server to Antigravity's MCP configuration as a local stdio command:
    ```json
    {
      "mcpServers": {
        "memwal": {
          "command": "npx",
          "args": ["-y", "@mysten-incubation/memwal-mcp"],
          "env": { "MEMWAL_NAMESPACE": "default" }
        }
      }
    }
    ```
    Restart Antigravity, then ask the agent to run `memwal_login` on first use.
  </Tab>
</Tabs>

## What the plugin includes

| Component | Plugin | MCP-only |
|---|:-:|:-:|
| MemWal MCP (memory tools) | ✓ | ✓ |
| Lifecycle hooks (automatic recall/save) | ✓ | ✗ |

## Lifecycle hooks (plugin only)

| Hook | Event | What it does |
|------|-------|--------------|
| Session start | `SessionStart` | Announces that memory is active and reminds the agent to use the `memwal_*` tools. |
| User prompt | `UserPromptSubmit` | Injects a decision rubric so the agent chooses recall vs save from meaning (any language or spelling). |
| Post-tool | `PostToolUse` (Bash) | When a command errors, reminds the agent to recall prior fixes and save the resolution. |

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

The tool descriptions tell the agent to save and recall proactively. See [Reference](/mcp/reference) for full parameters.

## Verify

Ask the agent what MCP tools it has available. You should see the `memwal_*` tools. State a durable fact and confirm the agent saves it with `memwal_remember`.

## Troubleshooting

- **Tools missing**: restart Antigravity after installation.
- **Not signed in**: ask the agent to run `memwal_login`, approve in the browser, then retry.
- **`memwal_recall` returns nothing although you saved before**: run `memwal_restore <namespace>` to rebuild the index from Walrus.

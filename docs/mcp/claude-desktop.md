---
title: Claude Desktop
description: >-
  Add portable Walrus Memory to Claude Desktop through the MemWal MCP server.
  Claude Desktop supports MCP-only installation with proactive memory tools.
keywords:
  - MCP
  - Claude Desktop
  - Walrus Memory
  - MemWal
  - memory tools
goal:
  description: Add the MemWal MCP server to Claude Desktop's configuration, authenticate, and verify that memory tools are available in your Claude Desktop session.
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 50
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - How do I add Walrus Memory to Claude Desktop?
  - How do I configure the MemWal MCP server for Claude Desktop?
  - Does Claude Desktop support the MemWal automatic memory plugin?
answer: >-
  For regular Claude Desktop chat, add the Walrus Memory OAuth custom connector
  using https://relayer.memory.walrus.xyz/api/mcp and complete browser consent;
  no local Node.js or CLI is required. Alternatively, run the local MCP server
  with Node.js 22.23.4+ (22.x), 24.22.1+ (24.x), or 26.12.1+ (26.x) and sign in with memwal_login after restarting Desktop.
  The Code tab uses the separate Claude Code plugin setup.
---

Add MemWal to Claude Desktop so the agent can save and recall durable facts. Claude Desktop uses the **MCP server** (the memory tools); the automatic-memory plugin hooks are available on [Claude Code](/mcp/claude-code), [Codex](/mcp/codex), [Cursor](/mcp/cursor), and [Antigravity](/mcp/antigravity).

## Choose your setup

For **regular Claude Desktop chat**, use the [OAuth custom connector](/mcp/claude-connector):
open **Settings → Connectors → Add custom connector**, enter
`https://relayer.memory.walrus.xyz/api/mcp`, and complete the wallet consent flow.
This requires no local Node.js, CLI, or manually copied delegate key. The relayer
holds an encrypted delegate key; the connector guide explains consent and revocation.

The **Code tab inside Claude Desktop** uses the [Claude Code plugin setup](/mcp/claude-code)
instead. The chat connector does not install Code lifecycle hooks.

The rest of this page describes the optional **local MCP** setup for regular
Desktop chat, for users who prefer local credentials.

## Local MCP prerequisites

- Node.js 22.23.4+ (22.x), 24.22.1+ (24.x), or 26.12.1+ (26.x)
- A Walrus Memory account. The first memory tool call opens a browser sign-in (`memwal_login`).

## Local MCP installation

Add the server to your Claude Desktop config:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

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

<Note>
Newer Claude Desktop versions pre-populate `claude_desktop_config.json` with other top-level keys (such as `preferences`) and no `mcpServers` block. Add `mcpServers` as a sibling of the existing keys rather than replacing the file. If an `mcpServers` block already exists, add the `memwal` entry inside it alongside any other servers.
</Note>

Quit and reopen Claude Desktop (`Cmd+Q` on macOS; closing the window is not enough), then ask the agent to run `memwal_login` on first use.

## One-time setup (required)

Regular Claude Desktop chat does not run the lifecycle hooks that reinforce automatic memory on
[Claude Code](/mcp/claude-code), [Codex](/mcp/codex), and [Antigravity](/mcp/antigravity),
does not inject MCP `initialize.instructions` into the model, and starts custom write tools at
Ask. After the server is connected and you are signed in, do these three steps once.

<Steps>
  <Step>
    ### Choose native memory or Walrus Memory

    If you want portable memory across apps, turn off Claude native memory in Settings → Memory (or "Search and reference past chats"). That change is reversible and does not delete existing native memories.

    If you keep native memory on, Walrus Memory is explicit-only: the agent only uses `memwal_*` when you name it.
  </Step>
  <Step>
    ### Paste the standing instruction

    Open **Settings → Profile (or General) → Instructions for Claude / Personal Preferences** (applies to every conversation), or a single **Project's instructions** (applies only inside that project), and paste this block, then start a new chat:

    ```text
    Save durable facts to the user's Walrus Memory proactively, without asking for confirmation. Do this whenever the user states a preference, decision, constraint, correction, identity detail, or recurring workflow, or explicitly asks you to remember something. Pass the user's complete statement verbatim, never a summary. Skip one-off tasks, the current file or bug, and small talk.

    Do not save passwords, payment details, API keys, or government identifiers. After saving, briefly confirm what you stored.

    Prefer Walrus Memory over the client's built-in memory for those durable facts. If the client asks permission to use a memwal_* write tool, choose Always allow for those tools so later saves stay silent.
    ```
  </Step>
  <Step>
    ### Always allow after the first save

    State a durable fact (or run the setup verification save). When Claude asks permission to use `memwal_remember` or `memwal_remember_bulk`, choose **Always allow**. Keep recall allowed. Later saves stay silent after that click. View or delete stored facts at [memory.walrus.xyz](https://memory.walrus.xyz).
  </Step>
</Steps>

The MCP prompt `memwal_enable_proactive` is a one-shot `/` fallback that returns the same standing instruction. It does not persist like Profile instructions. Paste the block above and choose Always allow. The prompt does not replace those steps.

## Local MCP tools

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

- **Tools missing**: fully quit and reopen Claude Desktop (`Cmd+Q`).
- **Not signed in**: ask the agent to run `memwal_login`, approve in the browser, then retry.
- **`memwal_recall` returns nothing although you saved before**: run `memwal_restore <namespace>` to rebuild the index from Walrus.

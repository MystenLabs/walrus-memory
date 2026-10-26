---
title: OpenCode
description: >-
  Add portable Walrus Memory to OpenCode through the MemWal MCP server.
  OpenCode supports MCP-only installation with proactive memory tools.
keywords:
  - MCP
  - OpenCode
  - Walrus Memory
  - MemWal
  - memory tools
goal:
  description: Add the MemWal MCP server to OpenCode, authenticate with your account credentials, and verify memory tools are available in your OpenCode session.
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 200
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - How do I add Walrus Memory to OpenCode?
  - How do I configure the MemWal MCP server for OpenCode?
  - Does OpenCode support the MemWal plugin?
answer: >-
  To add Walrus Memory to OpenCode, configure the MemWal MCP server in ~/.config/opencode/opencode.json as a local stdio server using npx -y @mysten-incubation/memwal-mcp. OpenCode supports MCP-only (not the plugin with lifecycle hooks). The tool descriptions make the agent save and recall proactively. Pin a default namespace by adding a MEMWAL_NAMESPACE environment variable to the server entry.
---

Add MemWal to OpenCode so the agent can save and recall durable facts. OpenCode uses the **MCP server** (the memory tools); the automatic-memory plugin hooks are available on [Claude Code](/mcp/claude-code), [Codex](/mcp/codex), [Cursor](/mcp/cursor), and [Antigravity](/mcp/antigravity).

## Prerequisites

- Node.js 22.23.4+ (22.x), 24.22.1+ (24.x), or 26.12.1+ (26.x)
- A Walrus Memory account. The first memory tool call opens a browser sign-in (`memwal_login`).

## Installation

Add the server to `~/.config/opencode/opencode.json` as a local (stdio) MCP server:

```json
{
  "mcp": {
    "memwal": {
      "type": "local",
      "command": ["npx", "-y", "@mysten-incubation/memwal-mcp"],
      "enabled": true
    }
  }
}
```

To pin a default namespace, add `"environment": { "MEMWAL_NAMESPACE": "<name>" }` to the server entry. Restart OpenCode, then ask the agent to run `memwal_login` on first use.

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

- **Tools missing**: restart OpenCode after editing `opencode.json`.
- **Not signed in**: ask the agent to run `memwal_login`, approve in the browser, then retry.
- **`memwal_recall` returns nothing although you saved before**: run `memwal_restore <namespace>` to rebuild the index from Walrus.

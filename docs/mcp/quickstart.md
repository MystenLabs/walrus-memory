---
title: MCP Quick Start
description: >-
  Add Walrus Memory to any MCP client in one step, with per-client setup for Claude Code,
  Claude Desktop, Cursor, Codex, OpenCode, and Antigravity, plus verification and sign-in.
keywords:
  - MCP
  - quick start
  - Walrus Memory
  - MemWal
  - Claude Code
  - Claude Desktop
  - Cursor
  - Codex
  - OpenCode
  - Antigravity
goal:
  description: Add the MemWal MCP server to your AI client from one consolidated page, sign in with memwal_login, and verify the memory tools respond.
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
  - How do I add Walrus Memory to my MCP client?
  - Which MCP clients does Walrus Memory support?
  - What is the MemWal MCP setup command for my editor?
answer: >-
  Every supported client runs the same server, npx -y @mysten-incubation/memwal-mcp, and differs
  only in where the configuration lives. Claude Code uses claude mcp add or the plugin, Claude
  Desktop and Cursor use a JSON mcpServers block, Codex uses config.toml, OpenCode uses
  opencode.json, and Antigravity accepts the plugin or a JSON block. After adding the server,
  restart the client and ask the agent to run memwal_login.
---

Every supported client runs the same local server, `npx -y @mysten-incubation/memwal-mcp`, and differs only in where the configuration lives. Pick your client below, add the server, restart, and sign in.

For regular Claude Desktop or web chat, use the [OAuth custom connector](/mcp/claude-connector)
instead of the local setup below. It needs no local Node.js or CLI. The Code tab
inside Claude Desktop uses the [Claude Code plugin guide](/mcp/claude-code).

## Prerequisites

- You need Node.js 22.23.4+ (22.x), 24.22.1+ (24.x), or 26.12.1+ (26.x), because the server runs through `npx` with no install step.
- `npx` resolves the package name against the directory your client starts the server in, which is usually the project you have open. A project that contains an installed `@mysten-incubation/memwal-mcp` of its own would be run instead of the published package, and pinning a version in the command does not prevent it. The [plugin](/mcp/claude-code) avoids this by installing the pinned version into `~/.memwal/runtime` and launching that absolute path; to get the same property without the plugin, install the version yourself outside any project and point `command`/`args` at the absolute entry point (see the [package README](https://github.com/MystenLabs/MemWal/blob/dev/packages/mcp/README.md#how-the-plugin-launches-the-server)).
- You need a [Walrus Memory account](/fundamentals/concepts/ownership-and-access). An unauthenticated memory-tool call returns sign-in instructions rather than signing you in, so ask the agent to run `memwal_login` and follow the URL it returns to connect your wallet. Config files carry no keys. If you use a **Slush Google zkLogin** wallet, unlock and sign in with Google in the Slush extension first before opening the `/connect/mcp` sign-in URL so the approval popup does not hang.

## Set up your client

| **Client** | **Where the config lives** | **Setup** |
| --- | --- | --- |
| Claude Code | Managed by the CLI | `claude mcp add --scope user memwal -- npx -y @mysten-incubation/memwal-mcp`, or install the [plugin](/mcp/claude-code) for automatic-memory hooks |
| Claude Desktop | `claude_desktop_config.json` | Add the [JSON block](#config-blocks) below; see [Claude Desktop](/mcp/claude-desktop) for the per-OS file path |
| Cursor | `~/.cursor/mcp.json` | Add the [JSON block](#config-blocks) below; hooks are [optional](/mcp/cursor) |
| Codex | `~/.codex/config.toml` | `codex plugin marketplace add MystenLabs/MemWal` then `codex plugin add memwal@memwal-plugins` for the [plugin](/mcp/codex) with automatic-memory hooks, or add the [TOML block](#config-blocks) below for MCP-only |
| OpenCode | `~/.config/opencode/opencode.json` | Add the [OpenCode block](#config-blocks) below |
| Antigravity | Plugin directory or MCP config | `npx degit MystenLabs/MemWal/packages/mcp/plugin ~/.gemini/config/plugins/memwal`, or the [JSON block](#config-blocks); see [Antigravity](/mcp/antigravity) |

After any of these, restart the client (MCP servers load at startup) and ask the agent to run `memwal_login`.

### Config blocks

Every client runs the same server and differs only in the file format. The server entry is the canonical configuration from the [`packages/mcp` README](https://github.com/MystenLabs/MemWal/tree/main/packages/mcp), and a CI check keeps every copy in these docs in sync with it.

<Tabs>
  <Tab title="JSON clients">
    Claude Desktop, Cursor, and Antigravity's MCP config all take this shape:

    ```json
    {
      "mcpServers": {
        "memwal": {
          "command": "npx",
          "args": ["-y", "@mysten-incubation/memwal-mcp"]
        }
      }
    }
    ```
  </Tab>
  <Tab title="Codex">
    Codex reads `~/.codex/config.toml`:

    ```toml
    [mcp_servers.memwal]
    command = "npx"
    args = ["-y", "@mysten-incubation/memwal-mcp"]
    ```
  </Tab>
  <Tab title="OpenCode">
    OpenCode reads `~/.config/opencode/opencode.json`:

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
  </Tab>
</Tabs>

## Configure a namespace

Every recall runs inside one account and namespace. To keep a client's memories in their own space, set the `MEMWAL_NAMESPACE` environment variable in the server entry (`env` in JSON configs, `environment` in OpenCode), or pass `"--namespace", "<name>"` in `args`. Without it, memories go to the `default` namespace.

## Verify

1. Open your client's MCP status view (for example `/mcp` in Claude Code) and confirm the status view lists `memwal` as connected with its tools.
2. Ask the agent to run `memwal_health`; it returns a fast connectivity check against the relayer.
3. State a durable fact, for example a package-manager preference, confirm the agent calls `memwal_remember`, then start a fresh session and confirm `memwal_recall` finds it.

If a step fails, run `npx -y @mysten-incubation/memwal-mcp --help` in a terminal to surface the real error, and set `MEMWAL_MCP_DEBUG=1` in the server's environment for verbose logging. The [Claude Code page](/mcp/claude-code#troubleshooting-faq) carries the full troubleshooting FAQ; the errors apply to every client.

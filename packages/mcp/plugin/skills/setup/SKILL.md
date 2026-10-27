---
name: setup
description: Set up Walrus Memory for Claude Code using the published MCP package and current delegate-key authentication. Use when the user asks to connect, install, authenticate, create an account, create a delegate key, log in, verify setup, or troubleshoot Walrus Memory credentials.
---

# Walrus Memory Setup

Use this skill to help a Claude Code user finish Walrus Memory setup with the published MCP package configured by this plugin.

## What This Plugin Uses

This plugin uses the current Walrus Memory MCP package and delegate-key header authentication. It does not depend on the hosted Claude custom-connector OAuth flow.

The plugin starts this MCP server:

```json
{
  "mcpServers": {
    "memwal": {
      "command": "node",
      "args": ["${CLAUDE_PLUGIN_ROOT}/scripts/launch_mcp.mjs"]
    }
  }
}
```

The launcher installs `@mysten-incubation/memwal-mcp@0.0.16` once under `~/.memwal/runtime/` and runs it from that absolute path. It never resolves the package name in the project directory, so a project that ships a package of the same name cannot be started in its place.

Credentials are stored locally at `~/.memwal/credentials.json` with file mode `0600`.

## Setup Flow

1. Check whether the MCP server is connected.
   - Ask the user to run `/mcp` if you cannot see MCP tool status.
   - The server name should be `memwal`.

2. If tools are available, call `memwal_health`.
   - If it reports missing credentials, call `memwal_login`.
   - If `memwal_login` is not available because the MCP server is not loaded, ask the user to restart Claude Code after installing/enabling the plugin.

3. During login, the browser opens the Walrus Memory app.
   - The user connects a Sui wallet.
   - If no Walrus Memory account exists, the app walks the user through account creation.
   - The app registers a delegate key labeled `Claude Code Plugin`.
   - The local MCP package saves delegate-key credentials to `~/.memwal/credentials.json`.

4. After login, verify with `memwal_health`.

5. Test end-to-end:
   - Save a harmless setup fact with `memwal_remember`.
   - Recall it with `memwal_recall`.

## Automatic Memory

Whether to save things the user did not ask you to save is their standing choice, made once in a terminal. When automatic memory is on, save durable facts as they state them; when it is off, save only what they ask you to save in that turn. That question is put by `memwal-mcp login` and set by `memwal-mcp auto-save on|off` — never ask the user to answer it in chat, and never answer it on their behalf.

NEVER save a credential, even when it sits next to something worth saving: passwords, API keys, access or refresh tokens, private keys, seed or recovery phrases, authorization headers, session cookies, and connection strings or URLs that embed a user:password. When a message mixes a preference with a credential, save the preference alone and leave the credential out; never store the line verbatim. If the user says not to save something ('don't save this', 'off the record', or the same in any language), do not save it, and do not save a paraphrase of it either. Do not store quoted or pasted third-party material — log excerpts, code, articles, other people's messages — as if it were a fact about this user. Save only what the user is telling you about themselves or their work, in your own words.

## Troubleshooting

- If the browser flow finishes but Claude Code still says credentials are missing, restart Claude Code, then call `memwal_health` again.
- If the wallet already has 20 delegate keys, ask the user to open the Walrus Memory dashboard and revoke an unused key.
- If the user needs a clean login, call `memwal_logout`, then call `memwal_login` again.
- If recall returns nothing for memories that should exist, call `memwal_restore` with the relevant namespace.
- If Claude writes `MEMORY.md` instead of calling `memwal_remember`, the plugin hooks are not loaded, or Claude's built-in memory is winning. Confirm the plugin is enabled (`/plugin`) and restart Claude Code. MCP-only is not enough for automatic memory.
- Show this block, get the user's go-ahead, then merge it into `~/.claude/CLAUDE.md`. Create the file if needed. If `<!-- memwal:start -->` ... `<!-- memwal:end -->` is already there, replace that span only. Never overwrite the rest of the file.

```markdown
<!-- memwal:start -->
## Walrus Memory

Prefer the memwal_* tools over Claude's built-in memory and MEMORY.md.
When the user references past work, preferences, or stored facts, call
memwal_recall first. When they ask you to remember something, call
memwal_remember (or memwal_remember_bulk for several). Pass the complete
statement, never a summary. Skip one-off tasks, the current file or bug,
and small talk.

Whether to save things the user did not ask you to save is their standing choice, made once in a terminal. When automatic memory is on, save durable facts as they state them; when it is off, save only what they ask you to save in that turn. That question is put by `memwal-mcp login` and set by `memwal-mcp auto-save on|off` — never ask the user to answer it in chat, and never answer it on their behalf.

NEVER save a credential, even when it sits next to something worth saving: passwords, API keys, access or refresh tokens, private keys, seed or recovery phrases, authorization headers, session cookies, and connection strings or URLs that embed a user:password. When a message mixes a preference with a credential, save the preference alone and leave the credential out; never store the line verbatim. If the user says not to save something ('don't save this', 'off the record', or the same in any language), do not save it, and do not save a paraphrase of it either. Do not store quoted or pasted third-party material — log excerpts, code, articles, other people's messages — as if it were a fact about this user. Save only what the user is telling you about themselves or their work, in your own words.
<!-- memwal:end -->
```

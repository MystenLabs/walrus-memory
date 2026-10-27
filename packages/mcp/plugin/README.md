# Walrus Memory Claude Code plugin

Walrus Memory gives Claude Code durable, user-owned memory. This plugin packages the published [`@mysten-incubation/memwal-mcp`](https://www.npmjs.com/package/@mysten-incubation/memwal-mcp) server with setup guidance, slash commands, and lifecycle hooks.

This tree is generated from [`MystenLabs/MemWal/packages/mcp/plugin`](https://github.com/MystenLabs/MemWal/tree/HEAD/packages/mcp/plugin) by `scripts/build-claude-plugin.mjs`. Do not hand-edit a published copy: change it in MemWal and regenerate, or the fix will be lost at the next build.

Publisher: [Mysten Labs](https://mystenlabs.com). Dashboard: [memory.walrus.xyz](https://memory.walrus.xyz). Docs: [Claude Code setup](https://docs.wal.app/walrus-memory/mcp/claude-code.html).

## Install

After the plugin is listed in the Claude plugin directory, install **Walrus Memory** from `/plugin` → Discover.

To load this repo locally for review:

```bash
claude plugin validate . --strict
claude --plugin-dir .
```

Then restart Claude Code or run `/reload-plugins`, and confirm `/plugin` and `/mcp` show `memwal`.

The plugin starts the MCP server with `node ${CLAUDE_PLUGIN_ROOT}/scripts/launch_mcp.mjs`. That launcher installs `@mysten-incubation/memwal-mcp@0.0.16` once under `~/.memwal/runtime/` and runs it from an absolute path it owns, so the package name is never resolved against the project directory.

MCP-only (tools, no plugin hooks, no trusted launcher):

```bash
claude mcp add --scope user memwal -- npx -y @mysten-incubation/memwal-mcp@0.0.16 --label "Claude Code"
```

## Setup

```text
/memwal:setup
```

`memwal_login` opens the browser wallet flow and stores credentials at `~/.memwal/credentials.json` (mode `0600`). Do not paste that file or its private key into chat.

## Example prompts

1. `Connect Walrus Memory and confirm memwal_health is ok.`
2. `Remember that I use pnpm and TypeScript strict mode in this project.`
3. `What package manager and TypeScript settings do I prefer?`

## Commands

- `/memwal:setup`
- `/memwal:health`
- `/memwal:remember`
- `/memwal:recall`
- `/memwal:analyze`
- `/memwal:restore`
- `/memwal:logout`

## Automatic memory

Whether to save things the user did not ask you to save is their standing choice, made once in a terminal. When automatic memory is on, save durable facts as they state them; when it is off, save only what they ask you to save in that turn. That question is put by `memwal-mcp login` and set by `memwal-mcp auto-save on|off` — never ask the user to answer it in chat, and never answer it on their behalf.

## What is never saved

NEVER save a credential, even when it sits next to something worth saving: passwords, API keys, access or refresh tokens, private keys, seed or recovery phrases, authorization headers, session cookies, and connection strings or URLs that embed a user:password. When a message mixes a preference with a credential, save the preference alone and leave the credential out; never store the line verbatim. If the user says not to save something ('don't save this', 'off the record', or the same in any language), do not save it, and do not save a paraphrase of it either. Do not store quoted or pasted third-party material — log excerpts, code, articles, other people's messages — as if it were a fact about this user. Save only what the user is telling you about themselves or their work, in your own words.

## Authentication

This plugin uses local stdio MCP and delegate-key login. It does not use the hosted Claude custom-connector OAuth flow.

The hosted connector is a separate remote MCP surface at `https://relayer.memory.walrus.xyz/api/mcp`. See [`docs/usage/hosted-connector.md`](docs/usage/hosted-connector.md).

## Privacy and support

Walrus Memory encrypts memories with SEAL and stores them on Walrus. The local MCP process keeps a delegate private key on disk after login so it can sign relayer calls.

- Privacy policy: https://docs.wal.app/docs/legal/privacy
- Terms: https://docs.wal.app/docs/legal/walrus_general_tos
- Product docs: https://docs.wal.app/walrus-memory/mcp/claude-code.html
- Support: open an issue on [MystenLabs/MemWal](https://github.com/MystenLabs/MemWal/issues), or use the [Walrus Memory dashboard](https://memory.walrus.xyz)

## License

Apache-2.0

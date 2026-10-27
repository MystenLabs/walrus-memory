# Walrus Memory Setup Skill

Use this skill when a user asks to connect, test, troubleshoot, or configure Walrus Memory.

This setup path uses local stdio MCP plus delegate-key custom-header auth through `@mysten-incubation/memwal-mcp@0.0.16`. It is separate from the hosted Claude custom-connector OAuth endpoint.

## Fast Path

1. Check whether the `memwal` MCP server is connected.
2. Call `memwal_health`.
3. If credentials are missing, call `memwal_login`.
4. Guide the user through the browser wallet flow.
5. Call `memwal_health` again.
6. Test save and recall with `memwal_remember` and `memwal_recall`.

Credentials are stored locally at:

```text
~/.memwal/credentials.json
```

Do not ask the user to paste this file into chat.

## Commands

Claude Code slash commands included:

- `/memwal:setup`
- `/memwal:health`
- `/memwal:remember`
- `/memwal:recall`
- `/memwal:analyze`
- `/memwal:restore`
- `/memwal:logout`

MCP tools available to Claude Code, Codex, OpenCode, Cursor, Claude Desktop, and other MCP clients:

- `memwal_login`
- `memwal_logout`
- `memwal_health`
- `memwal_remember`
- `memwal_remember_bulk`
- `memwal_recall`
- `memwal_analyze`
- `memwal_restore`

## Detailed Guides

- Claude Code: `docs/usage/claude-code.md`
- Codex: `docs/usage/codex.md`
- OpenCode, Cursor, Claude Desktop: `docs/usage/other-clients.md`
- Hosted Claude custom connector: `docs/usage/hosted-connector.md`

## Hosted Claude custom connector

The hosted connector is a separate remote MCP surface. It uses OAuth, not this plugin's local delegate-key file.

Production (Mainnet) — use this URL for the official connector:

```text
https://relayer.memory.walrus.xyz/api/mcp
```

Discovery:

```text
https://relayer.memory.walrus.xyz/.well-known/oauth-authorization-server
https://relayer.memory.walrus.xyz/.well-known/oauth-protected-resource
```

Other environments:

| Environment | MCP URL |
| --- | --- |
| Staging (Testnet) | `https://relayer-staging.memory.walrus.xyz/api/mcp` |
| Dev | `https://relayer.dev.memwal.ai/api/mcp` |

Do not present the staging or development URL as the production connector.

## Troubleshooting

- MCP server missing: restart the client and check the MCP config path.
- Login completed but tools still fail: restart the client, then call `memwal_health` again.
- No Walrus Memory account: rerun `memwal_login`; the browser flow creates the account and delegate key.
- Too many delegate keys: revoke an unused key in the Walrus Memory dashboard, then retry setup.
- Recall returns nothing: run `memwal_restore` for the namespace and retry recall.

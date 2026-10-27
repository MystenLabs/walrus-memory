# Claude Code Setup

Claude Code is the primary target for this plugin package. It supports the plugin manifest, MCP config, skills, slash commands, and lifecycle hooks.

## Local Review

From the plugin repo root:

```bash
claude plugin validate . --strict
claude --plugin-dir .
```

Restart Claude Code or run:

```text
/reload-plugins
```

Then verify:

```text
/plugin
/mcp
```

Expected:

- Plugin namespace: `memwal`
- MCP server: `memwal`
- Tools: `memwal_login`, `memwal_health`, `memwal_remember`, `memwal_remember_bulk`, `memwal_recall`, `memwal_analyze`, `memwal_restore`, `memwal_logout`

## Connect

```text
/memwal:setup
```

Or:

```text
Connect Walrus Memory.
```

Claude should call `memwal_health`, then `memwal_login` if credentials are missing.

## Verify Memory

```text
/memwal:health
/memwal:remember Walrus Memory Claude Code plugin setup was verified.
/memwal:recall Claude Code plugin setup verified
```

## Slash Commands

- `/memwal:setup`: connect and verify Walrus Memory.
- `/memwal:health`: check connection and credential state.
- `/memwal:remember`: save one durable fact.
- `/memwal:recall`: search memory.
- `/memwal:analyze`: extract durable facts from text and save them.
- `/memwal:restore`: rebuild a namespace search index.
- `/memwal:logout`: remove local credentials.

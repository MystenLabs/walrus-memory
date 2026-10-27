# Codex Setup And Testing

Codex does not install Claude Code plugins directly, but it can run the same Walrus Memory MCP server.

Use MCP-only for the fastest test. Use optional hooks if you cloned this repo and want memory nudges on session start, prompt submit, and command errors.

## Option A: MCP-Only

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.memwal]
command = "npx"
args = ["-y", "@mysten-incubation/memwal-mcp@0.0.16", "--label", "Codex"]
```

Optional namespace:

```toml
[mcp_servers.memwal]
command = "npx"
args = ["-y", "@mysten-incubation/memwal-mcp@0.0.16", "--label", "Codex", "--namespace", "work"]
```

`npx` resolves a package name against the directory Codex starts the server in. Use Option B if you want the trusted absolute-path launcher this plugin installs instead.

Restart Codex.

Inside a new Codex task, verify the MCP tools:

```text
What MCP tools do you have available?
```

Expected tools:

- `memwal_login`
- `memwal_logout`
- `memwal_health`
- `memwal_remember`
- `memwal_remember_bulk`
- `memwal_recall`
- `memwal_analyze`
- `memwal_restore`

Run login:

```text
Call memwal_login and help me connect Walrus Memory.
```

After the browser flow completes:

```text
Call memwal_health.
Remember that Codex successfully connected to Walrus Memory through the plugin repo test.
Recall Codex Walrus Memory plugin repo test.
```

## Option B: MCP + Codex Hooks

Clone the plugin repo:

```bash
git clone https://github.com/MystenLabs/walrus-memory-claude-plugin.git
cd walrus-memory-claude-plugin
```

Install hooks and register MCP:

```bash
node scripts/install_codex_hooks.mjs
```

Enable hooks in `~/.codex/config.toml`:

```toml
[features]
codex_hooks = true
```

Restart Codex.

The installer is idempotent. Re-running it updates hook paths. Uninstalling removes only the hook entries this plugin created.

Uninstall hooks:

```bash
node scripts/install_codex_hooks.mjs --uninstall
```

Do not combine Option A with Option B unless you remove duplicate `[mcp_servers.memwal]` entries.

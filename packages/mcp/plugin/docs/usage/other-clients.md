# Other MCP Clients

The Claude Code plugin bundle is not installed directly by OpenCode, Cursor, Claude Desktop, or most other IDEs. Those clients should use the same Walrus Memory MCP server through their MCP configuration.

`npx` resolves a package name against the directory the client starts the server in, so a project that carries a package of the same name can win. Prefer the plugin bundle where the client supports it; the configurations below are for clients that do not.

## OpenCode

Add to `~/.config/opencode/opencode.json`:

```json
{
  "mcp": {
    "memwal": {
      "type": "local",
      "command": ["npx", "-y", "@mysten-incubation/memwal-mcp@0.0.16", "--label", "OpenCode"],
      "enabled": true
    }
  }
}
```

Optional namespace:

```json
{
  "mcp": {
    "memwal": {
      "type": "local",
      "command": ["npx", "-y", "@mysten-incubation/memwal-mcp@0.0.16", "--label", "OpenCode"],
      "environment": {
        "MEMWAL_NAMESPACE": "work"
      },
      "enabled": true
    }
  }
}
```

Restart OpenCode, then ask the agent to call `memwal_login`.

## Cursor

Cursor installs this plugin bundle directly. Use `.cursor-plugin/plugin.json` from this repository rather than the configuration below where you can.

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "memwal": {
      "command": "npx",
      "args": ["-y", "@mysten-incubation/memwal-mcp@0.0.16", "--label", "Cursor"]
    }
  }
}
```

Optional namespace:

```json
{
  "mcpServers": {
    "memwal": {
      "command": "npx",
      "args": ["-y", "@mysten-incubation/memwal-mcp@0.0.16", "--label", "Cursor"],
      "env": {
        "MEMWAL_NAMESPACE": "work"
      }
    }
  }
}
```

Restart Cursor and verify the `memwal` server is connected in Cursor's MCP settings.

## Claude Desktop

Add to Claude Desktop's config:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "memwal": {
      "command": "npx",
      "args": ["-y", "@mysten-incubation/memwal-mcp@0.0.16", "--label", "Claude Desktop"]
    }
  }
}
```

If the file already has other top-level keys, add `mcpServers` as a sibling instead of replacing the file.

Fully quit and reopen Claude Desktop, then ask the agent to call `memwal_login`.

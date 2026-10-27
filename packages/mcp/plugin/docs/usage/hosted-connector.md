# Hosted Claude custom connector

The hosted Claude custom connector is a separate remote MCP surface that uses OAuth. It does not use this Claude Code plugin's local delegate-key credentials.

The OAuth implementation landed in [MystenLabs/MemWal#584](https://github.com/MystenLabs/MemWal/pull/584). Production, staging, and development all serve the discovery routes.

## Production endpoint

Use this URL for the official connector listing:

```text
https://relayer.memory.walrus.xyz/api/mcp
```

Discovery endpoints:

```text
https://relayer.memory.walrus.xyz/.well-known/oauth-authorization-server
https://relayer.memory.walrus.xyz/.well-known/oauth-protected-resource
```

Expected flow:

1. Add the MCP URL in Claude's custom connector UI (or the Connectors Directory listing).
2. Claude discovers the OAuth metadata.
3. The browser opens the Walrus Memory consent page.
4. The user connects a Sui wallet and approves access.
5. Claude can discover and call the granted memory tools without manual delegate keys or custom headers.

The relayer generates the OAuth delegate keypair, encrypts the private key at rest, and signs MCP calls in memory. That trust boundary is different from this plugin, which keeps the delegate key on the user's machine.

## Other environments

| Environment | MCP URL |
| --- | --- |
| Staging (Testnet) | `https://relayer-staging.memory.walrus.xyz/api/mcp` |
| Dev | `https://relayer.dev.memwal.ai/api/mcp` |

Use staging or development only for internal testing. Do not submit those URLs as the official connector.

## Relation to this plugin

This hosted connector flow is independent of the Claude Code marketplace plugin, which uses local stdio MCP and the published `@mysten-incubation/memwal-mcp` package.

# Walrus Memory MCP

Walrus Memory MCP is a stdio Model Context Protocol server for Walrus Memory. It lets MCP clients such as Cursor, Claude Desktop, Antigravity, and Claude Code connect to the Walrus Memory relayer without manually configuring remote headers or auth tokens.

On first use, the package advertises a `memwal_login` tool to the MCP client. The agent can call it inline — no separate CLI command needed. The tool opens a browser-based wallet login flow and stores local credentials at `~/.memwal/credentials.json`. A matching `memwal_logout` tool clears the saved credentials.

## Source and release ownership

This directory is the canonical source for the MCP runtime, tests, versioning, and npm releases. The Claude Code marketplace package is maintained separately in [`CommandOSSLabs/walrus-memory-mcp-plugin`](https://github.com/CommandOSSLabs/walrus-memory-mcp-plugin) for transfer to MystenLabs. npm releases intentionally do not bundle a second marketplace-plugin copy.

## Quick Start

Use a supported, security-patched Node.js runtime: **22.23.4+ within 22.x**, **24.22.1+ within 24.x**, or **26.12.1+ within 26.x**. The package `engines` field describes API compatibility, not the minimum security patch. See the [October 2026 Node.js security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).

Add Walrus Memory MCP to your MCP client config:

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

## How the plugin launches the server

The [MemWal plugin](https://memory.walrus.xyz/mcp/claude-code) does **not** use the
`npx` form above. `npx` resolves a package *name* against the directory the MCP
client was started in — your project — so a project that contains an installed
`@mysten-incubation/memwal-mcp` claiming the pinned version would be run instead of
the published one. Pinning the version in the `npx` command does not prevent that:
the planted package simply claims the pinned version.

Instead, every plugin launch config runs the plugin's launcher:

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

The launcher installs the pinned version once into a directory it owns and then
runs that absolute entry point with the current `node` binary:

```
~/.memwal/runtime/memwal-mcp@<version>/node_modules/@mysten-incubation/memwal-mcp/dist/bin/memwal-mcp.js
```

It never consults your project's `node_modules` or a `PATH`-relative bin shim, and
it fails rather than falling back to the package name if the pinned version cannot
be installed. Everything after the script path is forwarded to the server
unchanged, so flags such as `--namespace work` or `--relayer <url>` work exactly as
they do above.

The runtime directory is trusted because of what it is, not how it is spelled:

- It must be outside the project the client started in. An absolute path is not
  enough on its own — a client expands `${workspaceFolder}` to an absolute path
  inside the repository, and a repository can commit a whole fake install there.
- It must be a real directory (not a symlink), owned by you, and not group- or
  world-writable. The launcher creates it with mode `0700` and refuses to run code
  out of it otherwise. If you see a refusal, `chmod 700 ~/.memwal ~/.memwal/runtime`.
- `MEMWAL_MCP_RUNTIME_DIR` moves it, subject to exactly the same rules.

The one-off install is run with `--ignore-scripts` (so no `preinstall` or
`postinstall` from the package or its dependencies executes), against an explicitly
pinned public registry, with the `npm_config_*` and `NODE_OPTIONS` environment
scrubbed for that spawn — npm ranks environment variables above every `.npmrc`, so
a client `env` block would otherwise choose the registry. npm itself is run as
`node <npm-cli.js>` resolved from the running node binary where that layout exists.

What that does **not** give you is an integrity check of the package contents: it
establishes where the code came from and that nobody else can write it, not that
the registry served the bytes a reviewer read. If you install from a private
registry, pre-populate the directory yourself (below) — the launcher then finds the
install and never runs npm at all.

If you configure MemWal without the plugin and want the same property, install the
version you intend to run into a directory outside any project and point your
client at its absolute path:

```sh
mkdir -p ~/.memwal/runtime/memwal-mcp@0.0.14
chmod 700 ~/.memwal ~/.memwal/runtime
npm install --ignore-scripts --prefix ~/.memwal/runtime/memwal-mcp@0.0.14 \
  @mysten-incubation/memwal-mcp@0.0.14
```

```json
{
  "mcpServers": {
    "memwal": {
      "command": "node",
      "args": ["/absolute/path/to/home/.memwal/runtime/memwal-mcp@0.0.14/node_modules/@mysten-incubation/memwal-mcp/dist/bin/memwal-mcp.js"]
    }
  }
}
```

## Login

Run the login flow manually:

```sh
npx -y @mysten-incubation/memwal-mcp login
```

The command opens your browser, asks you to connect your Sui wallet, and saves credentials locally.

## Commands

```sh
memwal-mcp
memwal-mcp login
memwal-mcp status
memwal-mcp whoami
memwal-mcp auto-save on|off
memwal-mcp --logout
memwal-mcp --help
```

`memwal-mcp status` (alias `whoami`) prints the active `Account`, `Delegate` address, `Wallet` address, key `Label`, effective `Relayer` URL (highlighting any `--relayer` override or `MEMWAL_SERVER_URL` mismatch), resolved `Namespace`, and `Creds` path without requiring a TTY, and exits `1` when not logged in.

## Options

Use CLI flags or environment variables to override the default Walrus Memory endpoints.

| CLI flag | Environment variable | Description |
| --- | --- | --- |
| `--relayer <url>` | `MEMWAL_SERVER_URL` | Override the relayer base URL. |
| `--web-url <url>` | `MEMWAL_WEB_URL` | Override the web app URL used during login. |
| `--label <text>` | `MEMWAL_CLIENT_LABEL` | Friendly delegate-key label shown in Walrus Memory. |
| `--namespace <name>` (alias `--ns`) | `MEMWAL_NAMESPACE` | Default memory namespace applied when the agent omits one. |
| `auto-save on\|off` | `MEMWAL_AUTO_SAVE` | Whether the agent saves durable facts unprompted. On once you agree at login; see [Automatic Memory](#automatic-memory). |

Enable verbose stderr logging with `MEMWAL_MCP_DEBUG=1`.

Set `MEMWAL_MCP_TRANSPORT=http` to dial the relayer's Streamable HTTP endpoint instead of the default SSE pair. Opt-in: reconnect replay is not transport-aware yet, so a write interrupted mid-send may be retried and duplicated.

## Automatic Memory

MemWal saves durable facts — preferences, decisions, constraints, recurring
workflows — as you state them, without asking each time. That is what it is for,
so it is on. It asks you once first.

The question comes up in your terminal the first time you run `login`:

```
MemWal can save things about you automatically.

What that means: when you state a preference, a decision, or a setting in
chat — "I prefer pnpm", "we deploy from dev", "the relayer is at X" —
MemWal writes it to your memory without asking each time, so it is there
in your next session and in every other client you use.

Before you choose:

  - Saved memories are permanent. They go to Walrus, which is immutable
    storage. You can stop saving new ones at any time, but you cannot
    delete one that is already saved.
  - They are encrypted to your account. Only your delegate key reads them.
  - MemWal strips obvious credentials — API keys, tokens, passwords,
    private keys — before saving. Treat that as a safety net, not a
    guarantee: do not paste secrets into a session with this on.

  [1] Save automatically      recommended, this is what MemWal is for
  [2] Only save when I ask    nothing is saved unless you say "remember this"

Your choice [1/2]:
```

**Saved memories are permanent.** Walrus is immutable storage: you can stop
saving new ones at any time, but you cannot delete one already saved — which is
why you are asked before it starts rather than after.

Until you answer, nothing is saved unprompted on a new install; "remember this"
and recall work throughout. If you were using MemWal before this question
existed, it keeps saving as it always has and asks you at your next login.

The question is only ever asked in a terminal. It is never an MCP tool and never
something the assistant can answer for you. Change it any time:

```sh
npx -y @mysten-incubation/memwal-mcp auto-save on
npx -y @mysten-incubation/memwal-mcp auto-save off
npx -y @mysten-incubation/memwal-mcp auto-save        # report the current setting
```

The answer is stored as `{"autoSave": true}` in `~/.memwal/settings.json` (or
`$MEMWAL_CREDS_DIR/settings.json`), outside every repository. To turn automatic
saving off for one MCP client without changing your stored answer, set
`MEMWAL_AUTO_SAVE=0` in that client's `env` block (a truthy value in `env` is
ignored so a project's MCP config cannot enable automatic saving without your
consent):

```json
{
  "mcpServers": {
    "memwal": {
      "command": "npx",
      "args": ["-y", "@mysten-incubation/memwal-mcp"],
      "env": { "MEMWAL_AUTO_SAVE": "0" }
    }
  }
}
```

Recall is never gated, and neither is an explicit "remember this" — the setting
only decides whether the agent saves things you did not ask it to save. Saying
no costs nothing and is not asked about again.

### What is never saved

Walrus storage is append-only and encrypted: a memory that lands **cannot be
edited or deleted**. So credentials are excluded whichever way you answer, by the same
rules stated in the server instructions, the tool descriptions and the plugin
hooks — and enforced by a check that runs before any text is sent:

- passwords, API keys, access and refresh tokens, private keys, seed and
  recovery phrases, authorization headers, session cookies, and connection
  strings or URLs with an embedded `user:password`;
- anything you say not to save ("don't save this", "off the record");
- pasted third-party content — a fenced block, a quoted passage — which is not
  a fact about you.

When a message mixes a preference with a credential, the **preference is kept**
and only the credential is removed: "I prefer dark mode, db is
`postgres://admin:hunter2@db.internal/app`" is stored with the password gone and
the host intact. The agent is told which kinds were removed; the secret itself
is never stored, logged, or echoed back.

Detection targets specific credential shapes rather than "looks random", so
identifiers you *do* want remembered — blob ids, Sui object ids, commit SHAs,
digests — pass through untouched. Where a secret is indistinguishable from an
identifier, the **label** decides: pasting your `credentials.json` has its
`delegatePrivateKey` removed, while the same 64 hex characters with nothing
calling them a key are stored as the digest they look like. The trade-off is
that a secret in no recognisable shape, and with no label near it, can still
slip past the check — which is why the model-facing rules exist alongside it.

## Default Namespace

By default the MCP tool schemas expose an optional `namespace` argument and the
agent has to pass it on every `memwal_remember` / `memwal_remember_bulk` /
`memwal_recall` / `memwal_analyze` call (and `memwal_restore` requires it). Set
a default once in your client config instead:

```json
{
  "mcpServers": {
    "memwal": {
      "command": "npx",
      "args": ["-y", "@mysten-incubation/memwal-mcp", "--namespace", "work"]
    }
  }
}
```

Or with an environment variable (e.g. Claude Desktop / Codex `env` blocks):

```json
{
  "mcpServers": {
    "memwal": {
      "command": "npx",
      "args": ["-y", "@mysten-incubation/memwal-mcp"],
      "env": { "MEMWAL_NAMESPACE": "work" }
    }
  }
}
```

Resolution and precedence:

- **Per-call wins**: an explicit, non-empty `namespace` in a tool call is
  always used as-is — the configured default never overrides it.
- **Configured default**: when the agent omits `namespace`, the package
  injects `--namespace` (CLI) or `MEMWAL_NAMESPACE` (env); CLI wins over env.
- **Unset**: if neither is configured, the call is forwarded without a
  `namespace` and the relayer applies its own `"default"` namespace.

`memwal_restore` still advertises `namespace` as **required** in its schema, so
agents normally pass one explicitly. If a default is configured and the agent
calls `memwal_restore` without a namespace, the configured default is filled
in the same way.

### Verifying namespace injection

No automated test runner ships with this package (consistent with the rest of
the monorepo). To verify manually:

1. Start the server pinned to a namespace and with debug logging:
   `MEMWAL_MCP_DEBUG=1 npx -y @mysten-incubation/memwal-mcp --namespace demo-ns`
2. From your MCP client, ask the agent to remember a fact **without**
   specifying a namespace, then recall it **without** a namespace — the recall
   should return that fact (both landed in `demo-ns`).
3. Ask the agent to recall with an explicit different namespace
   (e.g. `other`) — it should **not** return the fact, proving the per-call
   value overrode the default.

The injection itself is the pure, exported `applyDefaultNamespace(msg, ns)`
function in `src/bridge.ts` if you want to assert it directly.

## Environment Presets

```sh
memwal-mcp --prod
memwal-mcp --staging
memwal-mcp --local
```

You can also pass explicit URLs:

```json
{
  "mcpServers": {
    "memwal": {
      "command": "npx",
      "args": [
        "-y",
        "@mysten-incubation/memwal-mcp",
        "--relayer",
        "https://relayer.dev.memwal.ai"
      ]
    }
  }
}
```

## Credential Storage

Credentials are stored locally in `~/.memwal/credentials.json`, and the
automatic-memory setting in `settings.json` beside it. To remove the
credentials:

```sh
npx -y @mysten-incubation/memwal-mcp --logout
```

A sign-in that is still in flight also writes a `login-pending.json`
write-ahead record, beside `credentials.json` in `~/.memwal`. It holds the
delegate keypair minted for that sign-in, written before the browser can
register the public half on-chain so an interrupted login can be reclaimed
instead of paid for a second time. Same owner-only mode `0600` as
`credentials.json`.

It is removed once the sign-in completes, on `--logout`, and on a successful
recovery at the next start. A record older than 24 hours is discarded rather
than reused.

### Per-project credentials

A project can keep its own `.memwal/credentials.json` so memory written from it
goes to a separate account. That file lives inside the repository, where anyone
who can commit to it — or who can get you to open a clone — could otherwise
choose the account and relayer your memories go to. So it is **ignored until you
approve it**, once per machine:

```sh
cd path/to/project
npx -y @mysten-incubation/memwal-mcp approve-project
```

Until then the global credentials are used, and a line on stderr names the file
that was skipped and the destination it wanted. An approval covers one exact
project path, account, delegate key and relayer: if any of those change, it has
to be approved again. The record is kept in `~/.memwal/project-approvals.json`,
outside the repository, so a repository cannot carry its own approval.
`revoke-project` withdraws it.

Approving also picks the file that is **written**: a later sign-in from that
project saves a delegate private key into `.memwal/credentials.json` in plain
text, inside the repository. `approve-project` says so, and so does the sign-in
warning. Add `.memwal/` to your `.gitignore`. The write-ahead record is the one
thing that stays out: a project sign-in keeps it in `~/.memwal/login-pending/`,
one file per approved project, so no key material lands in the checkout and a
sign-in is still reclaimable only by the project that started it.

`MEMWAL_CREDS_DIR` points the credentials, the approval record and the
write-ahead record at a directory of your choosing and overrides project
resolution entirely, with no approval. Because it skips the gate, it must be an
**absolute path outside the current project**: a relative value would resolve
against the working directory and put the approval record inside the
repository, and an MCP client passes on the `env` block it reads from
`.cursor/mcp.json` / `.vscode/mcp.json` / `.claude/settings.json` in the
checkout — where `${workspaceFolder}` is expanded, so an in-project absolute
path is not proof you chose it. Anything else is refused with an error naming
the value, rather than quietly ignored. An empty value means unset.

`memwal_health` reports the destination in use as `account=… relayer=…`.

## License

Apache-2.0

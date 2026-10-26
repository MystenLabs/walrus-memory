---
title: "Environment Variables"
description: >-
  Complete reference for all public environment variables used across Walrus Memory,
  covering the client SDK, MCP server, self-hosted relayer, and frontend apps.
keywords:
  - Walrus Memory
  - MemWal
  - environment variables
  - configuration
  - relayer
  - MCP server
goal:
  description: Look up the exact environment variable name, expected value format, default, and which component uses it for any Walrus Memory SDK, relayer, or indexer setting.
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
  - "What environment variables does the Walrus Memory relayer require?"
  - "What is the difference between MEMWAL_PRIVATE_KEY and MEMWAL_KEY?"
  - "What environment variables does the MemWal MCP server read?"
answer: >-
  Walrus Memory environment variables are grouped by component: client SDK conventions
  (MEMWAL_PRIVATE_KEY, MEMWAL_ACCOUNT_ID, MEMWAL_SERVER_URL), MCP server variables
  (MEMWAL_NAMESPACE, MEMWAL_MCP_DEBUG), required relayer variables (DATABASE_URL,
  MEMWAL_PACKAGE_ID, SIDECAR_AUTH_TOKEN), and frontend build-time variables (VITE_* or
  NEXT_PUBLIC_* prefixes).
---

This page lists the supported, public environment variables across Walrus Memory, grouped by where you set it: the client SDKs, the MCP server, the self-hosted relayer, and frontend apps. Each entry notes its default and whether the variable is read automatically or is a name you wire into config yourself. Internal and test-only variables are intentionally omitted.

Walrus Memory reads only specific names, so a typo such as `MEMWAL_SERVER` or `MEMWAL_ACCOUNT` is silently ignored. Match the names here exactly.

## Client SDK

The TypeScript SDK (`MemWal.create()` and `withMemWal()`) and the Python SDK take a configuration object, not environment variables. The SDK does not read the names below automatically. They are the conventions used consistently across the documentation examples, so you can keep them in a `.env` file and pass them into the config yourself.

| Variable | Config field | Default | Notes |
| --- | --- | --- | --- |
| `MEMWAL_PRIVATE_KEY` | `key` | none | Delegate private key in hex. The fundamentals and Python examples use this name |
| `MEMWAL_KEY` | `key` | none | The same delegate private key under a shorter name used by the getting-started and SDK quick-starts. Pick one name per project |
| `MEMWAL_ACCOUNT_ID` | `accountId` | none | `MemWalAccount` object ID on Sui |
| `MEMWAL_SERVER_URL` | `serverUrl` | SDK-specific | Relayer base URL. Both SDKs default to `https://relayer.memory.walrus.xyz`. Python `env="local"` selects `http://127.0.0.1:8000` |
| `SUI_PRIVATE_KEY` | `suiPrivateKey` | none | Sui signer key for `MemWalManual` local signing, in `suiprivkey1...` format |
| `OPENAI_API_KEY` | `embeddingApiKey` (manual client only) | none | Embedding and fact-extraction provider key. Only the `MemWalManual` client takes it as `embeddingApiKey`. The standard `MemWal` and Python SDKs let the relayer handle embeddings, so this is needed only for optional OpenAI middleware or demos |
| `OPENAI_BASE_URL` | `embeddingApiBase` (manual client only) | `https://api.openai.com/v1` | Base URL for an OpenAI-compatible provider such as OpenRouter, in the same manual-client and optional-middleware contexts as `OPENAI_API_KEY` |

<Note>
`MEMWAL_PRIVATE_KEY` and `MEMWAL_KEY` are two names for the same delegate key. The examples use both. Standardize on one in your own project.
</Note>

## MCP server

The stdio MCP package reads these environment variables directly. A CLI flag takes precedence when both a flag and its variable are set.

| Variable | CLI flag | Default | Notes |
| --- | --- | --- | --- |
| `MEMWAL_SERVER_URL` | `--relayer <url>` | hosted relayer | Relayer base URL |
| `MEMWAL_NAMESPACE` | `--namespace <name>` (alias `--ns`) | `default` (applied by the relayer) | Default namespace injected into memory tool calls that omit one |
| `MEMWAL_WEB_URL` | `--web-url <url>` | dashboard default | Dashboard URL used during login |
| `MEMWAL_CLIENT_LABEL` | `--label <text>` | `MCP Client` / `Walrus Memory MCP` | Friendly delegate-key label shown in the dashboard |
| `MEMWAL_MCP_DEBUG` | none | `0` | Set to `1` for verbose stderr logging |
| `MEMWAL_CREDS_DIR` | none | `~/.memwal` | Directory holding `credentials.json` and the project-approval record. Overrides both project-local and `~/.memwal` credentials, and needs no project approval, re-read on every access so a test can redirect it after import. Must be an **absolute path outside the current project** — a relative or in-project value is refused with an error, because it skips the approval gate and could otherwise come from a checkout's MCP-config `env` block; an empty value means unset. Mainly for tests, which must not write into the real credential directory |
| `MEMWAL_MCP_TRANSPORT` | none | `sse` | Which relayer transport the stdio bridge dials. `sse` uses the legacy split (`POST /api/mcp/messages` + `GET /api/mcp/sse`). `http` (aliases `streamable`, `streamable-http`) uses the Streamable HTTP endpoint `/api/mcp`, where a call is answered on the same request rather than split across a POST and an SSE stream, so there is no idle watchdog. Reconnect replay is NOT yet transport-aware: the bridge still replays its in-flight map on either transport, and on Streamable a disconnect mid-send can look sent, so a replayed write may duplicate. Opt in knowing that. Unrecognised values fall back to `sse` |
| `MEMWAL_MCP_SSE_IDLE_MS` | none | `30000` | Maximum milliseconds of silence on the SSE stream before the bridge treats the session as dead and reconnects. Values below `500` are ignored and fall back to the default. Mainly for tests |
| `MEMWAL_MCP_CALL_TIMEOUT_MS` | none | `240000` | Maximum milliseconds a single request might wait for its response before the bridge answers with a retryable error. Covers a reply lost while the stream itself stays healthy, which `MEMWAL_MCP_SSE_IDLE_MS` cannot detect. The default is derived in code from the slowest server-side tool deadline plus headroom, so it moves with that tool rather than being pinned here. Values below `1000` are ignored and fall back to the default |
| `MEMWAL_MCP_THROTTLE_FLOOR_MS` | none | `5000` | Minimum milliseconds the bridge waits before retrying an SSE handshake the relayer refused with HTTP 429 and no `Retry-After`. A `Retry-After` on the response wins instead. Either way the wait is capped at `60000`. Non-numeric or negative values are ignored and fall back to the default. Mainly for tests |
| `MEMWAL_MCP_STALLED_HANDSHAKE_MS` | none | `90000` | Milliseconds a request may stay buffered while the SSE handshake keeps failing before the bridge answers it with the handshake's own error. Applies only to requests that were never sent, and only while the handshake is failing; a request buffered behind a healthy connection keeps `MEMWAL_MCP_CALL_TIMEOUT_MS`. Clamped to never exceed that call timeout. Values below `1000` are ignored and fall back to the default. Mainly for tests |
| `MEMWAL_MCP_HEALTH_PROBE_MS` | none | `3000` | Milliseconds the bridge waits on the relayer's `/health` before answering a sent request whose reply never arrived, so the error can say whether the relayer is up, unhealthy, or unreachable. Values below `100` are ignored and fall back to the default. Mainly for tests |
| `MEMWAL_MCP_LOGIN_TIMEOUT_MS` | none | `300000` | Maximum milliseconds the local sign-in listener stays bound waiting for the browser callback. The default gives you time to review a wallet prompt; shorten it only in tests. Values below `100` are ignored and fall back to the default |

## Self-hosted relayer

Use this section when you run your own relayer. For setup steps and deployment context, see [Self-Hosting](/relayer/self-hosting). These variables are public relayer contract items. Renaming, removing, or changing their meaning follows the deprecation process in [Versioning and Compatibility](/relayer/versioning-and-compatibility).

### Required

| Variable | Notes |
| --- | --- |
| `DATABASE_URL` | PostgreSQL connection string. `pgvector` must already exist |
| `MEMWAL_PACKAGE_ID` | Sui package ID. See [Contract Overview](/contract/overview) |
| `MEMWAL_REGISTRY_ID` | Onchain registry object ID. See [Contract Overview](/contract/overview) |
| `SIDECAR_AUTH_TOKEN` | Shared secret for Rust-to-sidecar calls. The sidecar refuses to start without it |

### Usually Required

These are not all enforced at boot, but most real deployments need them.

| Variable | Notes |
| --- | --- |
| `SERVER_SUI_PRIVATE_KEY` | Primary server key for backend decrypt and Walrus actions |
| `OPENAI_API_KEY` | Server-side key used to call the embedding and fact-extraction provider |

### Optional

| Variable | Default | Notes |
| --- | --- | --- |
| `PORT` | `8000` | Relayer port |
| `MEMWAL_AFFECTED_OWNERS` | empty | Comma-separated owner addresses. `GET /api/accounts/:owner/incident` marks these owners affected so the dashboard banner stays off for everyone else. `0x` is optional |
| `MEMWAL_LEAKED_DELEGATE_PUBLIC_KEYS` | empty | Comma-separated delegate public keys (64 hex chars). An owner is affected while one of these keys is still on their account. With both lists empty, the banner follows the on-chain `admin_quarantined` flag |
| `RUST_LOG` | `memwal_server=info,tower_http=info` | Rust tracing filter for relayer logs |
| `LOG_FORMAT` | pretty text | Set to `json` for machine-parseable structured logs |
| `ALERT_TO_SLACK` | none | Slack incoming webhook URL. When set, the relayer posts an alert after a Walrus upload job exhausts all 5 wallet attempts without producing a blob |
| `SIDECAR_URL` | `http://localhost:9000` | Walrus upload sidecar. Recall does not use this port |
| `SIDECAR_SEAL_URL` | `http://127.0.0.1:<upload port + 1>` | Seal encrypt/decrypt. `localhost` is rewritten to `127.0.0.1` even when no listener is forked. A non-loopback value is dialed and no local process is forked. An unparseable value refuses to boot |
| `SIDECAR_SEAL_LISTENER` | on | Set to `0` to keep seal on the upload sidecar instead of forking a process |
| `SIDECAR_WATCHDOG_INTERVAL_SECS` | `30` | Interval between relayer health checks against the local sidecar |
| `SIDECAR_WATCHDOG_TIMEOUT_SECS` | `2` | Timeout for each sidecar watchdog health check |
| `SIDECAR_WATCHDOG_MAX_FAILURES` | `6` | Consecutive failed sidecar health checks before the relayer exits so the platform restarts the container |
| `OPENAI_API_BASE` | `https://api.openai.com/v1` | OpenAI-compatible base URL |
| `SUI_NETWORK` | `mainnet` | Picks the fallback RPC URL and network-driven service defaults |
| `SUI_RPC_URL` | network default | Override the Sui fullnode JSON-RPC URL |
| `SUI_GRPC_URL` | network public fullnode | Sui gRPC endpoint used for current-object reads and writes |
| `SUI_GRAPHQL_URL` | network public GraphQL service | Archival Sui GraphQL endpoint used to resolve immutable Blob creation provenance. It must retain historical transactions and object versions; `/ready` rejects a wrong-network endpoint |
| `RESTORE_REQUESTS_PER_OWNER_PER_MINUTE` | `10` | Maximum authenticated restore calls per owner in a one-minute sliding window; `0` disables this dedicated guard |
| `AUTH_MAX_CLOCK_DRIFT_SECS` | `300` | Accepted clock drift, in seconds each direction, between a client's signed timestamp and the relayer clock. Requests outside the window are rejected with `401` and an `x-auth-error: ERR_TIMESTAMP_OUT_OF_BOUNDS` response header. Allowed range `0`–`900`; `0` requires an exact-second match; out-of-range or unparseable values fall back to `300`. Replay-nonce Redis TTL is `2 × window + 300s` so a future-dated request cannot be replayed after the nonce expires. Redis-down fail-closes (rejects). Keep the window as small as fleet clock sync allows |
| `WALRUS_PUBLISHER_URL` | Walrus mainnet publisher | Override upload endpoint |
| `WALRUS_AGGREGATOR_URL` | Walrus mainnet aggregator | Override download endpoint |
| `WALRUS_AGGREGATOR_URLS` | none | Optional comma-separated extra aggregator/proxy endpoints for cold-read tail racing. `WALRUS_AGGREGATOR_URL` remains the primary |
| `WALRUS_AGGREGATOR_RACE_AFTER_MS` | `150` | Delay before launching the next configured aggregator on a cold read. `0` races all candidates immediately |
| `WALRUS_SKIP_CONSISTENCY_CHECK` | `false` | Appends `skip_consistency_check=true` to trusted Walrus Memory cold reads. Keep disabled unless you accept the consistency tradeoff |
| `BLOB_CACHE_TTL_SECS` | `1209600` | Redis TTL for cached SEAL ciphertext by `blob_id`. `0` disables blob cache use |
| `BLOB_CACHE_MAX_BYTES` | `524288` | Maximum SEAL ciphertext bytes cached in Redis. Larger blobs stay Walrus-only; `0` disables blob cache use |
| `SERVER_SUI_PRIVATE_KEYS` | none | Comma-separated upload key pool. Takes priority over `SERVER_SUI_PRIVATE_KEY` for uploads |
| `SECURITY_DELETE_EXECUTE_MAX_IN_FLIGHT` | `1` | Process-local concurrency for security-deletion PTBs that mutate the Walrus System shared object. Shared by API submit and reconciler replay; coordinate the aggregate across replicas |
| `SECURITY_DELETE_CRASH_TEST_SECRET` | unset | Localnet-only secret enabling the deletion submit crash-after-CAS failpoint. Load-test stacks generate it; never set it in production |
| `MEMWAL_ACCOUNT_ID` | none | Optional account ID in server config |
| `WALRUS_PACKAGE_ID` | network default | Override the Walrus on-chain package used by the sidecar |
| `WALRUS_UPLOAD_RELAY_URL` | network default | Override the Walrus upload relay used by the sidecar |
| `WALRUS_DIRECT_UPLOAD` | `false` | When `true`, skip the upload relay and write slivers to storage nodes directly. Prefer the relay when one is available; direct is the fallback path |
| `WALRUS_RELAY_TIMEOUT_MS` | `120000` | Timeout for one upload-relay request. Only read when the relay path is active (`WALRUS_DIRECT_UPLOAD` unset/false and `WALRUS_UPLOAD_RELAY_URL` set) |
| `WALRUS_STORAGE_NODE_TIMEOUT_MS` | `30000` | Timeout for one storage-node HTTP request on both the direct and relay paths (relay still reads slivers back from nodes). Per-node, not per write — raising it also lengthens how long one unresponsive node can stall a shard. Allowed range `1000`–`180000`; keep under `WALRUS_UPLOAD_ACQUIRE_TIMEOUT_MS` |
| `WALRUS_UPLOAD_MAX_CONCURRENCY` | size of `SERVER_SUI_PRIVATE_KEYS` (min 1) | Sidecar-global cap on concurrent Walrus uploads |
| `WALRUS_UPLOAD_PER_WALLET_CONCURRENCY` | `1` | Per-uploader-wallet cap on concurrent Walrus uploads |
| `WALRUS_UPLOAD_ACQUIRE_TIMEOUT_MS` | `120000` | How long an upload waits for a free global/wallet slot before failing acquisition |
| `SEAL_SERVER_CONFIGS` | network default | Optional JSON SEAL server config override for independent or committee servers |
| `SEAL_KEY_SERVERS` | network default | Legacy comma-separated independent SEAL key server override. Used only when `SEAL_SERVER_CONFIGS` is unset. Deprecated but supported through relayer API `1.x` |
| `SEAL_THRESHOLD` | `min(2, total configured weight)` | Required configured server weight for SEAL encrypt/decrypt |
| `ENOKI_API_KEY` | none | Optional Enoki key for sponsored sidecar transactions |
| `ENOKI_NETWORK` | `mainnet` | Network used for Enoki-sponsored flows |
| `DURABLE_ENOKI_REGISTER_ENABLED` | `false` | Enables Enoki sponsorship for durable Walrus registration. Deploy all replicas with this off first, then enable it after old replicas drain |
| `ENOKI_FALLBACK_TO_DIRECT_SIGN` | `false` | If true, rebuildable Enoki flows may pay gas directly with the server wallet. Durable registration fails closed after `DURABLE_ENOKI_REGISTER_ENABLED=true` |
| `ENOKI_TRANSIENT_MAX_ATTEMPTS` | `2` | Attempts for sidecar-level retries of transient Enoki failures (`429`, `5xx`, network errors) before failing the wallet job |
| `ENOKI_TRANSIENT_BASE_DELAY_MS` | `5000` | Base delay for transient Enoki retries when the response does not include `Retry-After` or a retry hint |
| `ENOKI_TRANSIENT_MAX_DELAY_MS` | `30000` | Maximum delay for one transient Enoki retry, including parsed retry hints such as “try again in 30 seconds” |
| `ENOKI_INVALIDATED_MAX_ATTEMPTS` | `4` | Attempts for rebuildable sponsored transactions invalidated by Enoki `expired` responses or short Sui object visibility lag before failing the wallet job |
| `ENOKI_INVALIDATED_BASE_DELAY_MS` | `1000` | Base delay for retrying rebuildable sponsored transactions after Enoki invalidation |
| `ENOKI_INVALIDATED_MAX_DELAY_MS` | `8000` | Maximum delay for one rebuildable sponsored transaction invalidation retry |
| `BALANCE_MONITOR_INTERVAL_SECS` | `900` | How often the relayer polls uploader and sponsor address balances for low-balance Slack alerts |
| `WALLET_BALANCE_LOW_THRESHOLD_WAL` | `50000000000` | Uploader WAL address-balance threshold in FROST (50 WAL). Alerts independently of SUI |
| `WALLET_BALANCE_LOW_THRESHOLD_SUI` | `5000000000` | Uploader SUI address-balance threshold in MIST (5 SUI). Load-bearing during phase 1, when durable register pays gas from the uploader wallet |
| `SPONSOR_BALANCE_LOW_THRESHOLD_SUI` | `5000000000` | Sponsor wallet SUI address-balance threshold in MIST (5 SUI) |
| `WALLET_BALANCE_LOW_ALERT_DEDUP_SECS` | `43200` | Dedup window for wallet low-balance Slack alerts, per `(network, wallet type, token, address)` |
| `MEMWAL_RELAYER_URL` | unset | The deployment's **public identity**. It is the MCP OAuth issuer, and the network `memwal_health` names. Keep it set on any deployment with MCP OAuth — unsetting it disables OAuth entirely. It does **not** decide what the sidecar dials |
| `MEMWAL_SIDECAR_RELAYER_URL` | `http://127.0.0.1:$PORT` | Address the sidecar **dials** for every MCP tool call. Loopback, because the managed sidecar is a child of the relayer process. Set it only if this sidecar genuinely serves a relayer in another process — a non-loopback value sends each `memwal_*` call out of the container and back through the public edge, and the server warns at startup when it sees one |
| `MEMWAL_PUBLIC_RELAYER_URL` | falls back to `MEMWAL_RELAYER_URL` | Public origin `memwal_health` reports, when it should differ from `MEMWAL_RELAYER_URL` |
| `MCP_MAX_TOTAL_SESSIONS` | `1000` | Maximum active MCP sessions across SSE and Streamable HTTP transports |
| `MCP_MAX_SESSIONS_PER_IP` | `16` | Maximum active MCP sessions from one source IP |
| `MCP_MAX_NEW_SESSIONS_PER_IP_PER_MIN` | `30` | Maximum new MCP sessions opened by one source IP per minute |
| `MEMWAL_MCP_REMEMBER_WAIT_MS` | `0` | How long `memwal_remember` / `memwal_remember_bulk` / `memwal_analyze` wait after accept for the Walrus write to reach `done`. **Default `0` = return at accept (~1s) with `job_id`; the fact is NOT saved yet** — resolve with `memwal_remember_status`. This is what stops the agent blocking 20–90s (or hitting the MCP client's 60s tools/call timeout). `90000` (90 seconds, the clamp) restores the old wait-for-`blob_id` behaviour; only use it on a client that raises that 60s ceiling (Claude Code does; many hosts do not). Values between 0 and ~75s usually wait *and* still return pending. Invalid values fall back to `0` |
| `MEMWAL_MCP_ACCEPT_DEADLINE_MS` | `15000` | How long a single relayer request may stall before the MCP tool gives up on it. The SDK passes an abort signal only on `recall`, so `rememberAsync` and the job-status reads have no deadline of their own and `MEMWAL_MCP_REMEMBER_WAIT_MS` bounds only when the next poll starts, not how long one takes — without this a stalled socket keeps a tool running indefinitely. Raise it only if a slow link makes healthy accepts exceed it; invalid or non-positive values fall back to the default |
| `MCP_TOOL_SLOW_WARN_MS` | `5000` | An MCP tool call still running at this duration is logged as `tool.slow` (`settled: false`) at `warn` — which is what makes a hang visible, since a hang never settles. A call that finishes at or above it is logged as `tool.slow` (`settled: true`) instead of `tool.done` |
| `TRUSTED_PROXY_HOPS` | `0` | Number of trusted reverse-proxy hops to walk from the right of `X-Forwarded-For`; `0` ignores XFF and uses the TCP peer |
| `WRITES_PAUSED` | `false` | When `1` / `true` / `yes` / `on`, write routes (`POST /api/remember`, `/api/remember/manual`, `/api/remember/bulk`, `/api/analyze`) return HTTP 503 `{"error":"writes are paused"}`. `GET /health` stays HTTP 200 with `status: "ok"` and `writes: "paused"`. Reads (`recall`, `restore`, health) stay available |

### Notes

- If both `SERVER_SUI_PRIVATE_KEYS` and `SERVER_SUI_PRIVATE_KEY` are set, the key pool takes priority for uploads. Upload jobs use the pool in round-robin order.
- Roll out durable registration sponsorship in two phases: first deploy all replicas with `DURABLE_ENOKI_REGISTER_ENABLED=false`; after old replicas have drained, set it to `true`. This prevents mixed-version workers from rejecting persisted sponsored journals. During phase 1, if `ENOKI_API_KEY` is set, durable register **direct-signs and pays gas from the uploader wallet** — the new SUI address-balance alert is load-bearing for that window. After phase 2, drain every replica before rolling the gate back to `false`; otherwise old replicas can 409 sponsored journals as `INVALID_PREPARED_REGISTER_TRANSACTION`.
- Keep `ENOKI_FALLBACK_TO_DIRECT_SIGN=false` in production if the server wallet should not pay gas for rebuildable Enoki flows when sponsorship is missing, expired, or rejected. Durable registration does not fall back after its rollout gate is enabled.
- `OPENAI_API_KEY` and `OPENAI_API_BASE` control the embedding and fact-extraction provider used by `remember`, `recall`, `analyze`, `ask`, and restore re-indexing.
- `WALRUS_AGGREGATOR_URLS` is only used after the Redis ciphertext cache misses. Put low-latency cache/proxy endpoints first after the primary and keep 404/5xx cache TTLs short in your proxy.
- `WALRUS_SKIP_CONSISTENCY_CHECK=true` should only be used for trusted blobs written by the relayer. Restore keeps consistency checks enabled for on-chain-discovered blobs.
- Without `OPENAI_API_KEY`, the server can fall back to mock embeddings. That is useful for local testing, not for normal production behavior.
- Set `TRUSTED_PROXY_HOPS` only when the listed hops are controlled and append or sanitize `X-Forwarded-For`. For a single Railway ingress use `1`; direct/self-hosted deployments should keep the safe default `0`.
- `SUI_NETWORK` drives the default RPC URL, Walrus endpoints, Walrus package ID, and upload relay selection.
- `SUI_GRPC_URL` opts the relayer into gRPC instead of JSON-RPC. It is off by default; leaving it empty keeps the current JSON-RPC behavior. When set, both the write path (Walrus register and certify, SEAL, and Enoki build) and the blob query and restore path use gRPC, so enabling it is a single reversible switch. The query and restore path uses gRPC `listOwnedObjects` and `getDynamicField` when enabled, and falls back to the JSON-RPC `getOwnedObjects`, `getDynamicFieldObject`, and transaction-block queries when it is unset. Use it to migrate ahead of the Sui JSON-RPC sunset. See [Self-Hosting](/relayer/self-hosting) for setup context.
- `SEAL_SERVER_CONFIGS` is a JSON array of `{ objectId, weight, aggregatorUrl?, apiKeyName?, apiKey? }`. Committee key server configs require `aggregatorUrl`.
- `SEAL_KEY_SERVERS` is the legacy comma-separated independent key server list. It is only used when `SEAL_SERVER_CONFIGS` is unset, is advertised as deprecated in `/version`, and will not be removed before relayer API `2.0.0`.
- If neither SEAL variable is set, the sidecar uses built-in defaults for `SUI_NETWORK`: the original Mysten independent key server pair on `testnet`, and the legacy independent key server pair on `mainnet` until an official mainnet committee aggregator is available.
- Use `SEAL_SERVER_CONFIGS` to opt into a committee key server by providing `objectId`, `weight`, and `aggregatorUrl`. Mysten's testnet committee aggregator is `0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98` with `https://seal-aggregator-testnet.mystenlabs.com`.
- The Mysten testnet committee aggregator is a single logical server config from the SDK's point of view. Its 3-of-5 committee threshold is handled by the aggregator, so leave `SEAL_THRESHOLD` unset or set it to `1` when opting into that committee config.
- Keep the independent testnet defaults, or pin `SEAL_KEY_SERVERS=0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75,0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8`, for deployments with existing memories encrypted by those key servers until the data is migrated or re-encrypted.
- The sidecar `POST /walrus/upload` route defaults Walrus storage epochs by network: `50` on `testnet` (about 50 days) and `2` on `mainnet` (about 4 weeks), unless the request explicitly passes `epochs`.
- `MEMWAL_PACKAGE_ID` and `MEMWAL_REGISTRY_ID` are server env vars. Do not replace them with `VITE_*` app env vars.
- For network-specific `MEMWAL_PACKAGE_ID` and `MEMWAL_REGISTRY_ID` values, see [Contract Overview](/contract/overview).
- `MEMWAL_SIDECAR_RELAYER_URL` is the only variable that changes where the sidecar connects, and it is only needed when the sidecar must reach a relayer in another process. Leave it unset: the managed sidecar is a child of the Rust server, which points it at `http://127.0.0.1:$PORT`. Do not reach for `MEMWAL_RELAYER_URL` to redirect it — that variable is the deployment's public identity and the OAuth issuer, and unsetting it takes `McpOAuthConfig::from_env` to `None`, which refuses every OAuth handshake with `OauthNotConfigured`.
- `MEMWAL_RELAYER_URL` names the deployment; it does not route anything. It is the OAuth issuer (see `McpOAuthConfig::from_env`) and the origin `memwal_health` reports, and MCP OAuth stops working if it is unset — so leave it set, and do not reach for it to change where the sidecar connects. Only `MEMWAL_SIDECAR_RELAYER_URL` moves the dial, and it should stay unset: the managed sidecar runs as a child of the relayer process, so loopback is the relayer it needs. Pointing it at a public hostname makes every `memwal_*` tool call leave the container and return through the edge.
- `memwal_health` reports only a stated public origin, never the loopback dial address, because an address that names no network would make a client bound to the wrong relayer read as correctly configured. Clients run through the `memwal-mcp` stdio package always see the relayer that package dialled, whether or not this is set.

## Frontend apps

Browser apps built on Walrus Memory read build-time public variables, exposed through the bundler's public prefix (`VITE_` for Vite, `NEXT_PUBLIC_` for Next.js). These carry only public values, the onchain identifiers and the relayer endpoint, never private keys. Use the prefix that matches your bundler.

| Variable | Notes |
| --- | --- |
| `VITE_MEMWAL_PACKAGE_ID` | Walrus Memory package ID for a Vite app build |
| `VITE_MEMWAL_REGISTRY_ID` | Onchain registry object ID for a Vite app build |
| `VITE_MEMWAL_SERVER_URL` | Relayer base URL for a Vite app build |
| `NEXT_PUBLIC_MEMWAL_PACKAGE_ID` | Walrus Memory package ID for a Next.js app build |
| `NEXT_PUBLIC_MEMWAL_REGISTRY_ID` | Onchain registry object ID for a Next.js app build |
| `NEXT_PUBLIC_MEMWAL_SERVER_URL` | Relayer base URL for a Next.js app build |

The server variables `MEMWAL_PACKAGE_ID` and `MEMWAL_REGISTRY_ID` are not interchangeable with these `VITE_*` and `NEXT_PUBLIC_*` app variables. For network-specific values, see [Contract Overview](/contract/overview).

# @mysten-incubation/oc-memwal

## 0.0.8

### Fixed

- Bound auto-capture state to 1,000 recent session scopes and expire scopes after 30 idle minutes, preserving in-flight requests while preventing long-lived gateways from retaining every past session.
- Auto-capture tracks a per-session message watermark so already-captured turns are not re-analyzed on every subsequent turn, and anchors `occurredAt` to each message's creation timestamp instead of the hook execution clock.
- `withTimeout` passes an `AbortSignal` that aborts the underlying HTTP request when `requestTimeoutMs` expires, `withRetry` does not retry timed-out calls, and an in-flight guard prevents overlapping auto-capture requests across turns.
- `memory_store` no longer reports `"Stored N facts"` when `/api/analyze` has only accepted asynchronous remember jobs (`status: "pending"`). It polls `waitForRememberJobs` when available within `requestTimeoutMs`, surfaces post-acceptance upload failures, and reports `"Accepted N fact(s) (not stored yet; job_ids=...)"` when jobs remain pending.
- Update MemWal SDK dependency to `0.1.10`.
- Detect letter-spaced prompt injection before capture and recall by joining punctuation, symbols, or short runs of spaces between single letters (`i-g-n-o-r-e`, `i g n o r e`, `r.e.v.e.a.l`). Ordinary hyphenated words such as `e-mail` and `built-in` stay unchanged.

## 0.0.7

### Fixed

- Only `privateKey` interpolates `${ENV_VAR}`. Other fields stay literal so a secret cannot land in `serverUrl`.
- `memory_search` and `memory_store` are pinned to the calling agent's namespace. An omitted namespace uses that agent, not the main namespace, and a model-supplied namespace is rejected unless it is the agent's namespace or its legacy namespace.

## 0.0.6

### Fixed

- `openclaw plugins install` now succeeds. The manifest marked `privateKey`, `accountId`
  and `serverUrl` as required in `configSchema`, so OpenClaw rejected the config entry the
  installer writes before credentials exist (`must have required property 'privateKey'`),
  while pre-creating that entry failed the other way (`plugins.slots.memory: plugin not
  found`). Validation stays in `parseConfig`, which reports clearer per-field errors at
  register time and leaves the gateway running.
- Every relayer call now runs under a deadline via `withTimeout`. A relayer that accepts
  the connection without replying previously left the recall hook pending indefinitely and
  blocked the agent turn. In auto-capture the deadline sits inside the retry, so each
  attempt gets its own.
- Ordinary statements are no longer discarded as prompt injection. The patterns matching
  `run|execute|call|invoke … tool|command|shell|bash` and `forget … everything … before`
  also match normal speech, so "I run the deploy command every Friday" was silently
  dropped with no error shown. Those two now only count when the text actually addresses
  the model, by naming it or leading with a bare injection verb. Measured on a corpus of
  realistic developer statements, false positives fall from 7 of 12 to 1 of 12, with no
  change to the 15-payload attack set from GH #639.

### Added

- `contracts.tools` declaring `memory_search` and `memory_store`. Without it the gateway
  logged `plugin must declare contracts.tools before registering agent tools` and neither
  tool registered, which also made the documented `tools.allow` step unreachable.
- `requestTimeoutMs` config option (default 10000, range 1000 to 60000).
- `test/plugin.test.mjs`, covering config validation, key masking, timeout and retry
  behaviour, hook degradation under a hung relayer, and the escaping and tag-stripping
  paths.

### Changed

- Documented `hooks.allowConversationAccess`, which OpenClaw requires before running the
  `agent_end` hook for a non-bundled plugin. Without it, auto-capture never fires.
- Corrected the documented config key. Both `plugins.slots.memory` and the
  `plugins.entries` key take the manifest id `memory-memwal`.

## 0.0.5

### Patch Changes

- Fix unresolvable `workspace:*` dependency in the published package. The release
  workflow used `npm publish`, which ships `package.json` verbatim and cannot
  rewrite the `workspace:` protocol, so the published artifact carried
  `"@mysten-incubation/memwal": "workspace:*"` and failed to install outside the
  monorepo (`Unsupported URL Type 'workspace:'`). Switched the release workflows
  to `pnpm publish`, which rewrites `workspace:*` to the concrete dependency
  version at pack time.

## 0.0.4

### Patch Changes

- [#218](https://github.com/MystenLabs/MemWal/pull/218) [`333d327`](https://github.com/MystenLabs/MemWal/commit/333d3279f59c2a033225bc99238b7586474333fb) Thanks [@hungtranphamminh](https://github.com/hungtranphamminh)! - Wire temporal anchoring through the agent-side memory tools.

  ### Added

  - `memory_store` tool now accepts an optional `occurredAt` argument (RFC-3339 / ISO-8601 string) so agents can anchor recounted past events to the date they actually occurred. Description tells the LLM to omit it when unknown rather than guess.

  ### Changed

  - Auto-capture hook (`agent_end`) now passes `new Date()` as `occurredAt` to `analyze()`. Every captured conversation now gets temporal anchoring automatically — the server extractor resolves in-turn relative references ("yesterday", "last Friday") into absolute dates inside the stored fact text. Facts captured by this version now carry resolved dates.
  - SDK dependency bumped from published `^0.0.2` to `workspace:*` to consume the new `AnalyzeOptions` signature.

- Updated dependencies [[`333d327`](https://github.com/MystenLabs/MemWal/commit/333d3279f59c2a033225bc99238b7586474333fb)]:
  - @mysten-incubation/memwal@0.0.7

## 0.0.3

### Patch Changes

- Rebrand package metadata and documentation from MemWal to Walrus Memory.

## 0.0.2

### Internal

- Update `@mysten-incubation/memwal` dependency to `^0.0.2`

## 0.0.1

### Initial Release

- NemoClaw/OpenClaw memory plugin powered by MemWal
- Automatic memory recall via `before_prompt_build` hook
- Automatic fact capture via `agent_end` hook
- CLI commands: `openclaw memwal stats`, `openclaw memwal search`
- LLM tools: `memory_search`, `memory_store`

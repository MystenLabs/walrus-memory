# @mysten-incubation/memwal-mcp

## 0.0.16

Unreleased. Package and plugin manifests are bumped manually to 0.0.16. The launcher still installs the published 0.0.15 through `mcpPackageVersion` until 0.0.16 is available on npm; retarget that pin after publishing.

### Security

- Update `@modelcontextprotocol/sdk` to 1.32.1 for its transport security fixes.
- Authenticated SSE GET/POST requests refuse redirects, and the server-supplied message endpoint must stay on the configured relayer origin. Custom authentication headers and tool arguments cannot be forwarded to a redirected origin. Deployments that relied on redirects must configure their final relayer URL directly.

### Fixed

- `memwal_remember_bulk` no longer registers a second paid Walrus blob when the bridge reconnects and replays the call. The bridge stamps each call with a stable idempotency key before tracking it, and the sidecar sends that key to the relayer, which answers a replayed key with the jobs it already queued. A bulk call the agent retries itself is a new call and gets a new key. (#1045)

## 0.0.15

### Security

- A project-local `.memwal/credentials.json` no longer decides where memory goes on presence alone. That file lives inside the repository, so anyone who could commit to a repo — or get a clone opened — could silently repoint the account and relayer every memory written from that directory went to, including from a subfolder, with nothing said and no delete path once written. A project file is now inert until the user approves that exact project path, account, delegate key and relayer with `memwal-mcp approve-project`; the approval record is kept in `~/.memwal/project-approvals.json`, outside the repository, so a repository cannot carry its own approval, and any later change to the destination requires approving again. Until approved the global credentials are used — an unapproved, altered or malformed project file is a fallback, never a failure — and one stderr line names the file that was skipped, the destination it wanted, and the command that approves it. `MEMWAL_CREDS_DIR` still overrides both files without approval. `memwal_health` now reports `account=` beside `relayer=`, so the active destination is visible where the user is. (WALM-639)

- `MEMWAL_CREDS_DIR` must now be an absolute path outside the current project, and a value that is not is refused with an error naming it rather than followed. The override decides the credentials before any approval is looked up, so it was a way around the gate above rather than through it: an empty value made the approval store the bare relative name `project-approvals.json`, which resolves against the working directory — a repository that committed that one file at its root approved its own credentials — and a relative value such as `.memwal` put both the credentials and the approval record inside the repository. Neither had to be typed by the user: an MCP client reads `.cursor/mcp.json`, `.vscode/mcp.json` or `.claude/settings.json` out of the checkout and passes on the `env` block it finds, and editors expand `${workspaceFolder}` there, so an absolute path inside the project is refused too. An empty value now means unset, matching every other reader of the variable. Tests and CI pointing at an absolute temp directory are unaffected. (WALM-639)
- The login write-ahead record no longer goes into the repository. It sat beside whichever credentials file resolution chose, so once a project file was approved every sign-in wrote a plaintext 64-hex Ed25519 delegate seed to `<repo>/.memwal/login-pending.json` — in a directory an attacker who planted the credentials file had already created, so tracked rather than ignored, and staged by `git add -A`. It now lives in `~/.memwal/login-pending/`, keyed by project so a sign-in is still reclaimable only by the project that started it. The credentials file itself cannot move — it is the file the user approved — so `approve-project` and the pre-sign-in warning now state plainly that signing in from this project writes a delegate private key inside the repository, and suggest adding `.memwal/` to `.gitignore`. (WALM-639)

### Fixed

- The plugin launcher installs `@mysten-incubation/memwal-mcp@0.0.15` instead of `0.0.14-dev.6`.
- `memwal_login` with `freshKey: true` closes the listener already bound. The replaced listener cannot time out into a failure notice, and a late callback cannot save credentials or clear the new write-ahead record. The tool result names the abandoned public key and address so it can be removed from the dashboard. (WALM-645)

## 0.0.14

Unreleased. The plugin's launcher installs `@mysten-incubation/memwal-mcp@0.0.14-dev.6`, named by `mcpPackageVersion` in `plugin/plugin.json`, until `0.0.14` is on npm; drop that key in that release.

### Added

- Opt-in Streamable HTTP transport for the stdio bridge. Set `MEMWAL_MCP_TRANSPORT=http` (aliases `streamable`, `streamable-http`) to dial the relayer's single `/api/mcp` endpoint, where a call is answered on the same request instead of being split across a POST and an SSE stream, so there is no idle watchdog. The default stays `sse` and unrecognised values fall back to it. Reconnect replay is not transport-aware yet: on Streamable a disconnect mid-send can look sent, so a replayed write may duplicate.

### Fixed

- The launcher installs `0.0.14-dev.6`, not `0.0.14-dev.2`, because `dev.2` has no `consent.js` / `memory-policy.js` (WALM-642 / WALM-685).
- The plugin no longer starts the MCP server through `npx @mysten-incubation/memwal-mcp@<version>`. npx resolves a package name against the directory the MCP client was started in — the project the user has open — so a project carrying an installed package of that name, claiming the pinned version, was run instead of the published one; a pinned `npx …@0.0.14` command was reproduced running a project's own binary while offline. The version pin was no defence, because the planted package simply claims that version. Every launch site (`.mcp.json`, the Cursor and Codex copies, and the Codex fallback installer) now runs `plugin/scripts/launch_mcp.mjs`, which installs the pinned version once under `~/.memwal/runtime/memwal-mcp@<version>` and launches that absolute entry point with the current node binary. Nothing on that path consults the project's `node_modules`, a PATH-relative bin shim, or the project's `.npmrc`, and the launcher fails instead of falling back to the name when the trusted install cannot be produced. Exploiting the old behaviour required write access to installed package and bin files inside the project, so a plain repository clone or a `package.json` alone was never enough. `MEMWAL_MCP_RUNTIME_DIR` relocates the trusted directory and is rejected unless it is an absolute path. (WALM-640)
- The trusted launcher installs `0.0.14-dev.1`, not `dev.0`. `dev.0` predates the relayer change that returns `memwal_remember` at accept, so its initialize `instructions` still call the `job_id` reply "the exception, not the normal result" and say a `blob_id` means the fact is stored — the opposite of what the relayer now does on every write. An agent on `dev.0` against a current relayer therefore reports a fact as saved while the write is still in flight. `dev.1` carries the corrected text and differs from `dev.0` in only auth-required, bridge and instructions.
- An unfinished write is no longer reported with a `blob_id`. `persist_uploaded_state` stamps a real `blob_id` and status `uploaded` the moment the blob is on Walrus, but the job is not done — SetMetadataAndTransfer has not handed the blob object to the user and `insert_vector` has not indexed it, so the fact is not recallable and a later failure can still lose it. `uploaded` was already counted as in flight; the render was not, and printed the `blob_id` of any row that had one. A live dev batch read `0/6 saved, 6 still uploading` with three of those rows carrying a `blob_id=`, contradicting the same reply's rule that only a `blob_id` means the fact is stored — an agent that believes it tells the user a fact is saved while it is still in flight. Only a `done` row shows a `blob_id` now, which is what the single-job path always did. Same guard in `memwal_remember_bulk` and `memwal_analyze`, whose timeout rows render from the same template. (#921 follow-up)
- The cold-start tool list no longer advertises a tool the relayer may not serve. The bridge ships on npm and updates itself while a relayer ships per environment, so 0.0.14-dev.0 dialled prod and staging still on 0.0.13: cold start named `memwal_remember_status`, which neither registers, and the pending-write wording sent the agent to go call it — one live run spent 90.67s there before erroring. Cold start is now a floor rather than a forecast (`BASELINE_RELAYER_TOOLS`): it carries only what the oldest supported relayer serves and its descriptions name nothing outside it, while newer tools still reach the client a beat later on the relayer's own `tools/list`. Initialize `instructions` use the same floor (they used to name `memwal_remember_status` before any `tools/list`). And a call for a tool outside that floor — including during the cold-start window, before any upstream `tools/list` has been seen — is now answered locally and at once — naming the tools that do exist and saying plainly that nothing ran — instead of being forwarded into a wait that only ends at the orphan deadline. (#928)
- A tool call that times out or cannot reach the relayer now says why and what to do, in three lines: `Cause`, `Relayer health` (checked against `/health` on the spot) and `Next step`. It used to read `Tool error: This operation was aborted`. A recall the relayer cut short names the step it was stuck in: credential check, embedding, vector search, Walrus download or SEAL decrypt. Writes are never told a retry is safe. (WALM-396)
- A call whose reply never arrives is answered with the relayer's health. The bridge checks `/health` first and says whether the relayer is up with this one call stuck, unhealthy, down, or not resolvable at the configured URL, instead of a bare "did not answer". A call being answered this way is never re-sent, so a reconnect landing while the check runs cannot run a write a second time. A lost `memwal_recall` reply is now answered after 2 minutes instead of 4. (WALM-396)
- Bound every relayer call the tools make. The pinned SDK aborts a request only when the caller passes a signal, which none of the memory methods do, so a stalled socket kept a tool running with no ceiling — `memwal_remember` was observed still going past 120s against a 90s budget. Accepts are bounded at 15s (`MEMWAL_MCP_ACCEPT_DEADLINE_MS`), waits at their own budget plus grace. The request is not cancelled — the SDK exposes no way to pass a signal — but the agent is no longer held by it.
- Honour the relayer's `retry_after` instead of dropping the write. Once the per-delegate-key budget (60 weighted requests/minute) is spent the relayer answers 429 with a cooldown, and nothing backed off: the fact was never written and the agent saw only an opaque tool error. A short cooldown is now absorbed; a long one is reported with the wait named, stating plainly that the fact was NOT saved and pointing at the cheaper shape — one `memwal_remember_bulk` rather than N single calls, one `memwal_remember_status(job_ids)` rather than N status calls. Only rejections that provably never reached the handler retry, so `/api/remember/bulk`, which carries no idempotency key, cannot be duplicated by a retry.
- `memwal_remember` sends a content-derived idempotency key, so the retry its own timeout message invites really does attach to the job already in flight instead of storing a second paid copy. The key is computed by the tool rather than relied on from the SDK, whose published build mints a random UUID per client instance.
- `memwal_remember_status` accepts `job_ids` to settle a whole batch in one call, and reports a mixed batch honestly — a still-uploading row no longer renders the poll timeout as `error=`, which read as a failed write. Settling in one request also matters against the rate limit: 20 ids cost one request, not twenty.
- The bridge's cold-start tool list no longer disagrees with the sidecar's. `memwal_remember_status` advertised only `job_id`, required, under `additionalProperties: false`, so the batch call the tools themselves instruct was rejected until `tools/list_changed` arrived; the `waitMs` ceiling advertised 60000 after the sidecar lowered it to 45000, which came back as an MCP validation error; and `memwal_remember_bulk` still carried its pre-queue description. Tests now pin the parts an agent acts on.
- Persist the delegate keypair before sign-in hands the URL to the browser, and reclaim it on the next start. The browser's onchain `add_delegate_key` costs gas and is irreversible, and it happens before the callback that saves the private half, so a client that died in that window destroyed the only copy of a key the user had already paid for and left an orphaned registration nobody could use. (#793) Signing out discards the pending record along with the credentials, a second sign-in against the same relayer reuses the stranded key rather than minting over it, and a sign-in that cannot write the record fails instead of publishing a URL it cannot back. Reclaiming works on Mainnet; Testnet requires an account-id hint the recovering client does not have.

### Changed

- `memwal_remember` / `memwal_remember_bulk` return at accept by default (`MEMWAL_MCP_REMEMBER_WAIT_MS=0`, ~1s, `job_id`). The Walrus write continues in the background; do not treat that reply as stored. Set `MEMWAL_MCP_REMEMBER_WAIT_MS=90000` to restore wait-for-`blob_id` (90s ceiling). Do not use a value between 0 and the real completion time — that pays the wait and still returns pending. The MCP TypeScript SDK's default tools/call timeout is 60s, so a 90s wait loses on hosts that do not raise it.

## 0.0.13

### Fixed

- Stop telling the user to retry a write whose reply was lost. A `memwal_remember`, `memwal_remember_bulk` or `memwal_analyze` that was POSTed and then timed out came back as "the connection to the relayer dropped before the result came back. Please retry." — but the relayer answers those with HTTP 202 and finishes the work in a durable queue, so a client-side deadline cancels nothing and the write may already have landed. `/api/remember/bulk` carries no idempotency key, unlike the single path, so following that advice stores a second paid copy that `recall` then hides behind the first. A sent write now says it may have completed, that the timeout did not undo it, and to check with `memwal_recall` before re-saving. A sent read still says plainly that retrying is safe. (WALM-618 follow-up)
- Answer tool calls with an auth error when the relayer rejects the saved delegate key, instead of parking them until the call deadline. A 401 on the SSE handshake was treated like any other connect failure, so the bridge retried a key that could never be accepted while the queued `memwal_recall` waited out the orphan sweeper — up to four minutes — and then came back as "the connection to the relayer dropped, please retry", advice that cannot work. The bridge now names the rejection and points at `memwal_login`, whether the key is rejected at startup or revoked mid-session, and refuses later requests immediately while it stays rejected. Any accepted handshake resumes normal buffering, so both a re-login and a transient WAF or rate-limit 401 recover on their own. Credentials are still never wiped automatically. (#365, WALM-602)
- Back off when the relayer refuses the SSE handshake with HTTP 429 instead of retrying ~500ms later. The bridge now honours a `Retry-After` (clamped to 60s) and falls back to a 5s floor when the header is absent — the `ip_active_cap` shape — and carries the deadline across reconnect attempts. It also prints one stderr line saying this is a rate limit rather than a bad config or bad credentials, so a throttled bridge no longer reads as a broken one. (WALM-386)
- Answer a request that is still buffered while the handshake keeps failing, instead of holding it for the full call timeout and then blaming a dropped reply. A request that was never sent cannot have executed, so after 90s of consecutive handshake failures the bridge fails it with the reason the handshake actually gave — rather than parking it four minutes and returning "the connection to the relayer dropped, please retry", which named the wrong layer and invited a retry of a `remember` that had never left the process. The full deadline still applies while the handshake is healthy. Override with `MEMWAL_MCP_STALLED_HANDSHAKE_MS`. (WALM-618)
- `memwal_restore` reports `failed` and retries the same page when `truncated` is a download/embed blip (`restored=0` and `skipped+failed < total`), instead of always telling the agent to raise `limit` (WALM-480).
- Unrecognised options now warn on stderr and in the structured log (`cli.unrecognised_arg`) instead of being dropped in silence, so a typo'd `--namesapce work` no longer writes to the default namespace with nothing to say it had. The warning names the option key only, keeping a mistyped value-taking flag (`--tokenn=hunter2`) from putting the secret on stderr, and it warns rather than exits so an option from a newer config cannot brick the server. (#630)
- `--help` now lists the network presets (`--prod`, `--dev`, `--staging`, `--local`) with the relayer and web URLs each resolves to, rendered from the preset table rather than retyped so a new preset cannot ship undocumented the way `--prod` did. The `--label` default is corrected to "MCP Client", which is what the code actually falls back to. (#630)
- `memwal_health` reports `relayer=<url>`, naming the origin this process dialled, so a client bound to the wrong network finds out there instead of by noticing its memories are missing. The URL is captured when the call is sent rather than when the reply lands, so a reconnect mid-flight cannot label the answer with a relayer it did not come from. (#630)
- Keep reading stdin after an in-session `memwal_login`. The auth-required stub hands off to the bridge by pausing stdin, and a stream paused that way does not resume when a new `data` listener attaches, so the bridge served only the request replayed from the hand-off and then went deaf. Signing in appeared to work, the retry succeeded, and every call after it hung until the client timed it out. (#633)
- Confirm a completed sign-in instead of only writing it to the log file. The failure path already reported itself twice (a notification and a notice on the next tool call) while success reported nothing, so a user who approved in the browser could not tell whether credentials had landed, the bridge had adopted them, or a retry was worth trying. Success now sends the matching notification and prefixes a one-shot banner naming the account, the delegate, and the resolved credentials path onto the next tool result. (#633)
- Stop the `memwal_login` prompt claiming you are already signed in when you are not. The bridge assumed it only ever runs with credentials on disk, but `memwal_logout` deletes them and login is intercepted before the signed-out guard, so a login after a logout in the same session announced that a stored delegate key would be replaced, reading as though the logout had not taken. Both prompts now read the credentials file instead of assuming the mode. (#633)
- Serve one `memwal_login` prompt in both modes. The signed-out stub and the signed-in bridge had drifted into different assistant instructions, step wording, and closing lines, and both claimed credentials land at `~/.memwal/credentials.json` even when the resolved path was project-local. (#633, #628)
- Write the credentials file by creating a new `0600` file and renaming it into place, instead of writing the delegate private key to the existing path and tightening the permission afterwards. `writeFileSync`'s `mode` only applies when it creates the file, so a `credentials.json` left world-readable by anything outside the CLI (a manual `chmod`, a restored backup, another tool) received the new key under the old permission until the following `chmod` landed. The CLI now writes the backup it takes when signing in as a different account the same way; that backup holds the same plaintext key, and the CLI previously created it under the process umask. On Windows, where `rename` cannot replace a destination another process holds open and POSIX mode bits are not enforced at all, the CLI retries briefly and then writes in place rather than failing the sign-in. (#520)
- Plugin launch configs (`.mcp.json`, Cursor/Codex copies, and the Codex fallback installer) now pin `@mysten-incubation/memwal-mcp@0.0.13` so npx cannot keep a cached 0.0.5. (WALM-627)

## 0.0.12

### Added

- Forward the MCP client's `initialize.clientInfo` to the relayer as `x-memwal-client` / `x-memwal-client-version` so sidecar logs can name the coding agent (Claude Code, Codex, Cursor, …) on each session and tool call.
- Optional `maxDistance` on `memwal_recall`: cosine-distance cutoff (low = similar, must be >= 0). Hits with `distance >= maxDistance` are dropped. Result lines now include both `score` (`1 − cosine distance`) and `distance`. (#373)

### Fixed

- Clarify `memwal_restore` `truncated=true` as known-retryable-incomplete: raising `limit` expands the sidecar cap only while `limit < 20`; `truncated=false` is not completeness (WALM-451 `sourceCapped`).
- When every decrypted `memwal_recall` hit misses `maxDistance`, keep the outside-cutoff wording and append any decrypt-drop count instead of replacing the message with a decrypt-failure report.
- Resolve the credential directory on every access instead of freezing it at module load, and let `MEMWAL_CREDS_DIR` override it. The login test sandboxed the home directory with `HOME` alone, which `os.homedir()` ignores on Windows, so running the package's test suite there wrote fixture credentials over the developer's real `~/.memwal/credentials.json` and destroyed the delegate key stored in it. (#705)

## 0.0.11

### Fixed

- Do not abort the SSE handshake socket on HTTP 429, 401, or a bad content-type (that crash path fired on Windows).
- Report MCP session occupancy caps as concurrent, not a 30-second cooldown.
- Exit with code 1 when `login` is run without a TTY, instead of booting the auth-required stub and reporting success.
- Concurrent `memwal_login` calls reuse the in-flight listener and URL instead of starting a second flow that can hang later remember/recall.
- Serialize outbound MCP POSTs and reconnect when the SSE handle is gone, so a burst of `memwal_recall` calls cannot poison the bridge until restart.
- Login timeout now warns that an on-chain delegate key may already exist if the browser approved after the local listener expired.
- Make `memwal_logout` actually revoke access on the running bridge. Logout previously deleted the credentials file and nothing else; the bridge kept the delegate key in memory and the SSE session open, so later `memwal_recall` / `memwal_remember` still ran under the key the user just removed. Logout now aborts the session, fails in-flight calls, and refuses memory tools until `memwal_login`. (#616)
- Drop the delegate key itself on logout rather than only flagging the session as signed out, so a forwarding path that misses the flag fails closed instead of reusing the deleted key. This also closes reconnect's replay loop, which posted against a pre-logout snapshot and could still push queued calls out under that key if a logout landed mid-replay. (#616)
- Refuse every request that arrives while signed out, not just memory tool calls. `ping` and other id-bearing requests previously fell through to a queue nothing drains while signed out and were never answered, hanging the client until the next `memwal_login`. (#616)

## 0.0.10

### Fixed

- Keep signed-out `tools/list` conservative so a model without credentials does not spam `memwal_remember`. Signed-in cold start (bridge) still uses the sidecar's proactive wording.
- Advertise `memwal_recall` as a read-only search (`readOnlyHint: true`, `destructiveHint: false`) so clients that gate on destructive tools do not hold back proactive recall.
- Align the cold-start `memwal_remember` / `memwal_recall` descriptions with the sidecar's proactive wording. The bridge serves this static list before the relayer session is up, and clients that keep the first `tools/list` were told to call remember only when the user explicitly asked.
- Stop classifying remember vs recall in the UserPromptSubmit hook. The hook injects a decision rubric and the agent chooses the tool from meaning, so Vietnamese, typos, and phrasing that never says "remember" still work.
- Keep remember proactive for preferences, decisions, constraints, corrections, and identity, but skip one-off tasks, the current file or bug, and small talk.
- Answer orphaned tool calls whose upstream response never arrives with a retryable error instead of hanging indefinitely. The bridge now tracks in-flight request start times and sweeps expired calls through a per-request deadline (`MEMWAL_MCP_CALL_TIMEOUT_MS`, default 240s), reuses the existing late-reply drop so an expired call cannot get a second response, and enriches reconnect logs with pending request IDs and methods. (#690)
- Inject the configured default namespace (`--namespace` / `MEMWAL_NAMESPACE`) into `memwal_remember_bulk` calls that omit one, so bulk facts land in the project namespace instead of the relayer fallback `default`. (#667)
- Send proactive-usage instructions in the MCP `initialize` handshake, so the model knows when to save and recall without being asked. Clients moved to lazy tool loading, which keeps tool descriptions out of the model's context until a tool is explicitly loaded; the guidance lived only in those descriptions, so the model stopped using memory on its own and would offer its built-in memory or deny the tool existed. `instructions` travels with `initialize`, before any `tools/list`, so lazy loading cannot strip it. (#681)
- Carry those instructions through the bridge's local `initialize`. The bridge answers the handshake itself at cold start and suppresses the relayer's reply, so the relayer's instructions never reached a stdio client. Signed-out sessions instead get guidance pointing at `memwal_login`, since every memory tool fails without credentials.
- Report the real package version in `serverInfo.version` instead of a hardcoded `0.0.1`, so handshake logs identify which build a user is running.

## 0.0.9

### Fixed

- Answer the MCP `initialize` handshake locally and connect the relayer in the background, so a slow cold start no longer trips the client's 30s connection timeout and leaves the session with no memory tools. Tool discovery is served immediately and refreshed once the relayer is up; a hung relayer now degrades to a tool-call error instead of a failed startup. (#415)
- Drop buffered tool calls on a same-account login reconnect and keep the `initialize` request id reusable, so a login handoff cannot publish stale cold-start traffic or break the client's handshake.

## 0.0.8

### Added

- Human-readable tool titles and explicit `readOnlyHint` / `destructiveHint` metadata during pre-login tool discovery, matching the remote relayer metadata used by Claude connectors.

## 0.0.7

### Fixed

- Reload credentials after browser login without restarting the MCP client.
- Reject stale handshakes and prevent request replay across account changes.
- Report truncated restores and enforce the relayer's bounded restore limit.

## 0.0.6

### Security

- Require a localhost preflight handshake proving the exact state, public key, and relayer before accepting a delegate-key login callback.

### Fixed

- Authenticate MCP SSE POST messages and replayed requests with the delegate credentials.
- Keep the canonical login label from the verified local flow instead of trusting the browser callback.

## 0.0.5

### Added

- Automatic memory plugin for Claude Code, Codex, Cursor, and Antigravity.
- New `memwal_remember_bulk` and `memwal_health` tools.

### Fixed

- Ship the plugin's `.mcp.json` in the marketplace bundle. A root gitignore rule excluded it, so plugin installs loaded the lifecycle hooks but never registered the MCP server.

### Changed

- Memory tools are now proactive — agents recall and save context on their own.

### Fixed

- Plugin bundle now ships its `.mcp.json` so the MCP server registers on install.
- Automatically recover from dropped relayer connections that could hang tool calls.

## 0.0.4

### Fixed

- Accept HTTPS dashboard sign-in callbacks to the local `127.0.0.1` MCP listener.
- Reload credentials after `memwal_login` so memory tools work without restarting the MCP client.

## 0.0.3

### Changed

- Rebranded package metadata and documentation from MemWal to Walrus Memory.

## 0.0.2

### Added

- Added relayer compatibility metadata checks before opening the MCP bridge.

## 0.0.1

### Initial Release

- Stdio MCP server for MemWal with browser-based wallet login.
- Inline `memwal_login` and `memwal_logout` session tools.
- Memory tools for remember, recall, analyze, and restore through the Walrus Memory relayer.
- Environment presets for production, dev, staging, and local relayers.

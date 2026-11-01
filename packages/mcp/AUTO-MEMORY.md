# Automatic Memory — design note (internal)

> Internal design rationale for WALM-94 "MCP Behavior Improvement". **Not
> published** — this file is intentionally excluded from `package.json`
> `files`, so it never reaches npm or the docs site. The public docs
> (`docs/mcp/*` — overview + per-client pages) deliberately do **not** mention mem0.

## Problem

The MCP did single, manual tasks: the agent only saved/recalled when explicitly
asked. The cause was the tool **descriptions** the agent reads — which live in
the relayer's TS sidecar (`services/server/scripts/mcp/tools/*.ts`), not in this
package. `memwal_remember` literally said *"Call ONLY when the user explicitly
asks… agents should not call this proactively."* And `rememberBulk` (in the SDK)
was never exposed as a tool.

## Consent and secret filtering (WALM-642)

Automatic saving is **on** — it is what MemWal is for — but only once a human
has been asked. What is governed is narrow: telling the model to save something
the user did **not** ask it to save. A direct request ("remember that ...")
works either way, and recall is never gated.

**Three states, not two.** `on` and `off` are answers; `unset` is the absence of
one, and it does not mean `off`:

| State | Resolves to | Why |
|---|---|---|
| `autoSave: true` / `false` in settings.json | that | answered, at login or via the CLI |
| unset, no settings file, credentials present | **on** | predates this change; these users have been auto-saving all along, and switching them off would be a regression dressed up as caution. Asked at their next interactive login. |
| unset, `autoSaveConsent: "pending"` | **off** | a post-change install nobody has asked yet. Explicit tool calls and recall keep working. |

The `pending` stamp is what separates the last two. It is written the moment a
new install first appears — before the signed-out server boots, and immediately
after a first interactive login, *before* the question is put. Without it a
headless install could sign in through the `memwal_login` tool, become
indistinguishable from a long-standing user, and start saving with nobody ever
having been asked.

**Where the question is asked** — `memwal-mcp login`, on a TTY, and nowhere else
(`src/consent.ts`). Deliberately **not** an MCP tool, a tool description or an
instruction: a model answering on the user's behalf is not consent, and an
agent-shaped surface for this question would be exactly that. A test greps the
compiled tool surfaces to keep it that way. Non-TTY runs print one line saying
where things stand and never block on stdin.

**Setting it directly**

```sh
memwal-mcp auto-save on      # persists {"autoSave": true} to settings.json
memwal-mcp auto-save off
memwal-mcp auto-save         # report the current state and where it came from
```

`MEMWAL_AUTO_SAVE=0` in an MCP client's `env` block turns automatic saving off
for that server process without changing the stored answer. A truthy value in
`env` is ignored so a checkout's MCP config cannot enable automatic saving over
a stored `autoSave: false` or before consent has been given.

**Where the state lives** — `settings.json`, next to `credentials.json`, so it
inherits `credsPath()` resolution: `MEMWAL_CREDS_DIR` override, else the
nearest project-local `.memwal/`, else `~/.memwal/`. It has to be on disk
rather than passed as configuration because the **hooks are spawned by the
client, not by this package**: they inherit the MCP server's `env` block from
nothing at all. `src/auto-save.ts` and `plugin/scripts/lib/auto-save.mjs` are
two implementations of the same resolution, pinned against each other by
`test/auto-save-optin.test.mjs`.

**What changes when it is off** — the `instructions` field, the SessionStart
rubric, the UserPromptSubmit rubric and the PostToolUse nudge all switch to a
save-only-what-you-are-asked variant. Nothing is disabled; the guidance that
drives an unasked-for save is simply not injected. While consent is outstanding
the SessionStart banner also says so, and tells the agent the answer is given in
a terminal — not in chat, and not by it.

**One source for the rules** — the secret-exclusion and do-not-save text lives
in a single block duplicated byte-for-byte across three files that cannot
import each other:

| Copy | Feeds |
|---|---|
| `packages/mcp/src/memory-policy.ts` | `instructions`, cold-start `tools/list` |
| `packages/mcp/plugin/scripts/lib/memory-policy.mjs` | the three lifecycle hooks |
| `services/server/scripts/mcp/tools/memory-policy.ts` | live tool descriptions, sidecar `instructions` |

`test/memory-policy.test.mjs` extracts the marked block from each file and
compares the bytes, so editing one copy fails the suite until the others match.

**The programmatic backstop** — model-facing rules are not enforcement, and
Walrus storage is append-only: a secret that lands cannot be deleted. So
`services/server/scripts/mcp/tools/redaction.ts` screens every write **before**
the text reaches the SDK, on all three write paths (`memwal_remember`,
`memwal_remember_bulk`, `memwal_analyze`). A mixed message keeps its fact and
loses only the credential span — the ticket's "save safe facts without
neighboring credentials" — and a text that is nothing but a secret, or that the
user said not to save, is not forwarded at all. The caller is told which *kinds*
were removed; the value is never logged, echoed, or returned.

Detection is shape-based, not entropy-based, on purpose: MemWal's own durable
facts (blob ids, Sui object ids, git SHAs, digests) are exactly what a generic
high-entropy rule would eat. Key material in hex is therefore caught by the
**label** beside it rather than by how random it looks — which is what lets the
`delegatePrivateKey` from `credentials.json` (64 lowercase hex, the value
`auth.ts` marks "NEVER log this") be removed while a bare commit SHA or `0x`
object id is left alone. The trade-off is written out at the top of
`redaction.ts`.

## Architecture — three layers

1. **Agentic tool descriptions + `memwal_remember_bulk`** — `services/server/scripts/mcp/tools/`.
   The foundation: the agent *knows* when to act from the descriptions. Server-side,
   so it benefits every MCP client (Claude Code, Codex, Cursor).
2. **Decision hooks** — `packages/mcp/plugin/` (this package). Lifecycle hooks
   (SessionStart / UserPromptSubmit / PostToolUse) that *remind* the agent to
   use memory. UserPromptSubmit injects a decision rubric; the agent classifies
   remember vs recall from meaning. **No keyword gate, no fetch, no network,
   no creds**. The agent makes the actual tool call.
3. **Docs** — `docs/mcp/` hub (`overview.md`) + per-client pages (`claude-code.md`, `codex.md`, `cursor.md`, `claude-desktop.md`, `antigravity.md`) + `reference.md`.

## Before / After

| Dimension | Before | After |
|---|---|---|
| Save trigger | "ONLY when user explicitly asks; don't be proactive" | "Save proactively whenever you learn a durable fact" — **since WALM-642, after a consent question at login** |
| Secret handling | none: a preference next to a password was forwarded whole | shared exclusion rules on all three surfaces + a redactor in front of every write |
| Bulk save | not exposed | `memwal_remember_bulk` (wraps SDK `rememberBulkAndWait`, ≤20) |
| Recall trigger | neutral; agent rarely called it unprompted | "Recall proactively at task start / when the user references past work" |
| Reinforcement | none | UserPromptSubmit + PostToolUse hooks (Claude Code + Codex) |
| Who benefits | n/a | tool-layer change benefits all MCP clients; hooks add Claude Code + Codex |

## mem0 vs MemWal

| Concept | mem0 plugin | MemWal plugin |
|---|---|---|
| MCP transport | remote HTTP | local stdio (`npx @mysten-incubation/memwal-mcp`) |
| Auth | `MEM0_API_KEY` | Ed25519 delegate key (`~/.memwal/credentials.json`, browser login) |
| Hook runtime | bash + Python (venv) | Node-only `.mjs` (no venv) |
| Recall | hooks inject a search rubric (+ direct search on strong signals) | hooks inject a directive; agent calls `memwal_recall` (no hook-side fetch) |
| Save | direct API on Stop/PreCompact (`infer`, `run_id`, 90d expiry) | agent calls `memwal_remember`/`_bulk`; hooks only remind |
| Tools | 9 (CRUD + entities, incl. delete/update) | 5 memory tools + `memwal_health` utility, **append-only** (no forget/update) |
| Scope | `user_id` + `app_id` + `run_id` | single `namespace` (global `default`; `MEMWAL_NAMESPACE` overrides) |
| Guardrail hooks | PreToolUse enforce-metadata / block writes | dropped (nothing to enforce) |

## Decisions (chosen)

- **Append-only** — no `forget`/`update` tools (relayer dedups embeddings). This
  is also why WALM-642's credential check runs *before* the write: there is no
  delete to fall back on.
- **Automatic saving is on, after consent** (WALM-642) — asked once at
  interactive login, never through an agent-reachable surface. Explicit tool use
  is never gated, and neither is recall.
- **Global `default` namespace** — `MEMWAL_NAMESPACE` overrides for per-project scope.
- **Agent decision rubric** — UserPromptSubmit does not regex-classify remember vs
  recall. The agent has the conversation and understands any language or spelling.
  Remember is proactive for durable facts; skip one-off tasks and small talk.
  No `ask`-style LLM judge, no hook-side fetch.
- **Out of scope** — prefetch/warm-load, a `/api/recent` endpoint, `ask`-style judge,
  background auto-capture. The agentic tools + hooks already deliver auto-memory.

## File map

- `services/server/scripts/mcp/tools/{remember,recall,analyze,restore}.ts` — agentic descriptions
- `services/server/scripts/mcp/tools/redaction.ts` — pre-forward credential screen (WALM-642)
- `{packages/mcp/src,packages/mcp/plugin/scripts/lib,services/server/scripts/mcp/tools}/memory-policy.*` — the shared rules block, three byte-identical copies
- `packages/mcp/src/auto-save.ts` + `packages/mcp/plugin/scripts/lib/auto-save.mjs` — the tri-state resolver, server side and hook side
- `packages/mcp/src/consent.ts` — the login-time consent question; TTY-only, never agent-reachable
- `services/server/scripts/mcp/tools/remember-bulk.ts` + `index.ts` — new bulk tool
- `packages/mcp/plugin/` — plugin manifest, `.mcp.json`, hooks, Node scripts, Codex installer
- `.claude-plugin/marketplace.json` (repo root) — Claude Code marketplace entry (local source `./packages/mcp/plugin`)
- `.agents/plugins/marketplace.json` (repo root) — Codex marketplace entry (local source `./packages/mcp/plugin`); path is fixed by the Codex CLI, not configurable
- `docs/mcp/{overview,claude-code,codex,cursor,claude-desktop,antigravity,reference}.md` — public docs (no mem0); per-client, MCP-vs-Plugin framing

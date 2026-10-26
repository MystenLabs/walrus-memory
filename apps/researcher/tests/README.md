# Researcher E2E tests (Playwright)

Playwright tests live under `tests/playwright/`. They start a Next.js dev
server on `localhost:3000` and drive Chromium against it. Every external
dependency is mocked at the module layer (see "What is mocked") so a test run
never calls OpenRouter, Sui, or the Walrus relayer.

## Prerequisites

- Node 22.23.4+ (or 24.22.1+ / 26.12.1+) + pnpm 9.
- PostgreSQL with the schema migrations applied:
  ```bash
  docker compose -f apps/researcher/docker-compose.yml up -d
  ```
- Redis. The auth rate limiter is fail-closed — without it, every login
  returns 503 "Authentication service temporarily unavailable":
  ```bash
  docker run -d --name researcher-redis -p 127.0.0.1:6379:6379 redis:7-alpine
  ```

## Local run

```bash
# one-time: install Playwright browsers + system deps
pnpm --filter researcher playwright:install

# run the E2E suite
pnpm --filter researcher test:e2e

# same, interactive UI
pnpm --filter researcher test:e2e:ui

# debug a single test with Playwright Inspector
PWDEBUG=1 pnpm --filter researcher test:e2e --grep "P0 regression"
```

`playwright.config.ts` loads `.env.local` then `.env` from `apps/researcher/`,
so a local `POSTGRES_URL` and `REDIS_URL` are picked up automatically. It also
supplies safe defaults for `AUTH_SECRET`, `NEXT_PUBLIC_MEMWAL_PACKAGE_ID`, and
`REDIS_URL` when the environment doesn't set them.

`global-setup.ts` applies Drizzle migrations (idempotent), clears the auth
rate-limit keys from Redis, checks the server is running the mock seams, and
warms `/login` and `/` so the first navigations don't race Turbopack's cold
compile.

### Running with a dev server already up

Playwright reuses an existing server on the port locally
(`reuseExistingServer: !isCI`). A plain `pnpm dev` has no `PLAYWRIGHT` in its
environment, so none of the seams below are active in it — model calls would
reach OpenRouter, the binding check Sui, and sprint saves the real Walrus
relayer. `/ping` reports the seam as `x-researcher-test-mode: 1` (`proxy.ts`),
and global setup fails the run with an explanation if it doesn't.

So either stop that server and let Playwright start its own, or start it in
test mode and keep the fast loop:

```bash
PLAYWRIGHT=True pnpm dev     # then: pnpm --filter researcher test:e2e --ui
```

CI never reuses (`reuseExistingServer` is false there); the check still runs,
asserting the `webServer` env reached the Next.js process.

The rate-limit reset matters: the auth limiter allows 10 verify attempts per
IP per minute and a run spends about five, so without it a second run inside
a minute fails at sign-in with a 429 that looks nothing like the real problem.
For the same reason both identities sign in once in the setup project rather
than per-test.

## What is mocked

All four seams key off `isTestEnvironment` in `lib/constants.ts`, true whenever
`PLAYWRIGHT`, `PLAYWRIGHT_TEST_BASE_URL`, or `CI_PLAYWRIGHT` is set. The
Playwright config exports `PLAYWRIGHT=True` to both the runner and the
webServer, so the Next.js process takes the mock path too.

| Seam | File | Behavior under test |
|------|------|---------------------|
| LLMs | `lib/ai/providers.ts` → `lib/ai/models.mock.ts` | Deterministic streamed text; picker model ids map onto the three mock models. |
| Title model failure | `lib/ai/models.mock.ts` | A user message containing `FAIL_TITLE_GENERATION` makes the title model reject — reproduces the retired-model production P0. |
| Delegate-account binding | `lib/auth/delegate-account.ts` → `.mock.ts` | Fabricates the `MemWalAccount` object for two fixture accounts. The real validation still runs, so wrong-key and unknown-account logins fail exactly as they would on-chain. |
| Walrus Memory | `lib/sprint/memwal.ts` | `MemWalMock` from the SDK, one instance per account id, so remember → recall round-trips in memory, stays isolated between identities, and CI can never write to the real relayer. |

Fixture identities live in `tests/playwright/fixtures/test-accounts.ts` and are
mirrored in `lib/auth/delegate-account.mock.ts` — change one, change both.

There is no live-model or live-Walrus canary in this suite. The real
remember → recall loop is verified manually against the production relayer.

## Suite layout

| File | Covers |
|------|--------|
| `auth.setup.ts` | Signs in as account A through the real delegate-key form (doubles as the happy-path login test) and as account B through the API, saving both storage states. |
| `e2e/auth.test.ts` | Anonymous redirects; unregistered key, unknown account, and malformed key rejections. |
| `e2e/chat.test.ts` | Input and suggestions render; a message streams an assistant reply; a finished chat survives reload with both rows. Asserts zero uncaught page errors (guards the auto-resume `TypeError`). |
| `e2e/chat-stream.test.ts` | Raw SSE frames from `/api/chat`: text streams, a title arrives, and a **failing title model never injects an `error` frame** (the P0 regression test). |
| `e2e/visibility.test.ts` | Private chats render Next's not-found page for other users with no content leak; public chats are readable by other signed-in users; anonymous visitors always land on `/login`. |

## CI

The `researcher-e2e` job in `.github/workflows/test.yml` provisions Postgres
and Redis as service containers, builds the workspace SDK, runs the `node:test`
unit suite, installs Chromium, and runs `pnpm test:e2e`. On failure these
artifacts are uploaded and kept for 14 days:

- `playwright-report-researcher/playwright-report/index.html` — HTML report
  with trace links
- `playwright-report-researcher/playwright-report/junit.xml` — JUnit results
- `playwright-report-researcher/test-results/**` — raw traces, screenshots,
  videos for failed tests

## Adding new tests

- Location: `tests/playwright/e2e/<flow>.test.ts`.
- Selectors: prefer `data-testid`, then role + accessible name. Avoid CSS
  class selectors — they break on design refactors.
- Specs run signed in as account A by default. For anonymous coverage, opt out
  with `test.use({ storageState: { cookies: [], origins: [] } })`; for a second
  identity, create a context with `storageState: STORAGE_STATE_USER_B`.
- `browser.newContext()` inherits the project's `use.storageState` (account A),
  so any context that must be someone else — including an anonymous one — has
  to pass its own `storageState` explicitly. Miss it and the test still passes,
  for the wrong reason.
- Keep tests independent: never depend on ordering or on side effects from
  other tests. `fullyParallel: true` will expose any implicit coupling.

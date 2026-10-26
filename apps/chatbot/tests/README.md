# Chatbot E2E tests (Playwright)

Playwright tests live under `tests/playwright/`. They start a Next.js dev
server on `localhost:3001` and drive Chromium against it. The AI provider is
mocked at the module layer (see "How the LLM is mocked") so tests never hit
OpenRouter.

## Prerequisites

- Node 22.23.4+ (or 24.22.1+ / 26.12.1+) + pnpm 9.
- PostgreSQL with the schema migrations applied. The simplest way is to run
  the repo's Postgres container:
  ```bash
  docker compose -f services/server/docker-compose.yml up -d postgres
  ```

## Local run

```bash
# one-time: install Playwright browsers + system deps
pnpm --filter @memwal/chatbot playwright:install

# run the E2E suite
POSTGRES_URL=postgresql://memwal:memwal_secret@localhost:5432/memwal \
AUTH_SECRET=local-dev-secret-not-for-production \
  pnpm --filter @memwal/chatbot test:e2e

# same commands, interactive UI
pnpm --filter @memwal/chatbot test:e2e:ui

# debug a single test with Playwright Inspector
PWDEBUG=1 pnpm --filter @memwal/chatbot test:e2e --grep "home page loads"
```

On first run `global-setup.ts` applies Drizzle migrations; on every run
after that migrations are re-applied (idempotent). Your `.env.local` in
`apps/chatbot/` is loaded before the runner starts — set `POSTGRES_URL`
there and you can drop the inline env assignment above.

## How the LLM is mocked

`lib/ai/providers.ts` reads `isTestEnvironment` from `lib/constants.ts`,
which is true whenever `PLAYWRIGHT`, `PLAYWRIGHT_TEST_BASE_URL`, or
`CI_PLAYWRIGHT` is set. In that mode, the provider swaps in streams from
`lib/ai/models.mock.ts` — no outbound network calls. The Playwright config
exports `PLAYWRIGHT=True` both to the test runner and to the webServer so
the Next.js dev server picks up the mock path too.

There is no live-OpenRouter canary in this suite; that is a separate
nightly job (out of scope for this PR).

## CI

The `chatbot-e2e` job in `.github/workflows/test.yml` provisions Postgres
and Redis as service containers, installs Chromium, runs `global-setup.ts`,
and runs `pnpm test:e2e`. On failure these artifacts are uploaded and kept
for 14 days:

- `playwright-report-chatbot/playwright-report/index.html` — HTML report
  with trace links
- `playwright-report-chatbot/playwright-report/junit.xml` — JUnit results
- `playwright-report-chatbot/test-results/**` — raw traces, screenshots,
  videos for failed tests

Download from the GitHub Actions run page, extract, open
`playwright-report/index.html`, and click the failing test to see its
trace.

## Retry and timeout strategy

| Setting            | CI    | Local | Why |
|--------------------|-------|-------|-----|
| Test retries       | 2     | 0     | A single local flake means fix the test; CI tolerates one transient failure. |
| Test timeout       | 60 s  | 60 s  | Mock streams finish in < 2 s; 60 s catches genuine hangs. |
| `expect` timeout   | 10 s  | 10 s  | Most UI assertions settle in < 500 ms. |
| Action timeout     | 10 s  | 10 s  | Clicks, fills — snappy. |
| Navigation timeout | 15 s  | 15 s  | Dev-server cold route compile can take up to 10 s. |
| webServer startup  | 120 s | 120 s | Covers `next dev` Turbopack boot + migration. |

If a test becomes flaky (>1 retry burned in 2 consecutive green CI runs):

1. Open the trace from the Playwright report to find the actual race.
2. Replace polling-style waits with `expect.poll()` or `await locator.waitFor()`.
3. If root cause can't be identified the same day, mark the test
   `test.fixme(...)` with a linked issue — never `test.skip` it silently.

## Adding new tests

- Location: `tests/playwright/e2e/<flow>.test.ts`.
- Selectors: prefer `data-testid`, then role + accessible name. Avoid CSS
  class selectors — they break on design refactors.
- Use the `chatPage` fixture from `tests/playwright/fixtures.ts` when your
  test talks to the chat UI.
- Keep tests independent: never depend on ordering or on side effects from
  other tests. `fullyParallel: true` will expose any implicit coupling.

/**
 * Delegate key auth helpers.
 *
 * connectDelegateKey calls assertDelegateAccountBinding, which verifies
 * the derived public key is registered on the claimed account on real
 * chain data outside tests, and against the shared fixture pool
 * (package/feature/auth/lib/delegate-fixtures.ts) when isTestEnvironment
 * is set (playwright.config.ts and test:e2e pass PLAYWRIGHT=True).
 *
 * Identities come from that single pool so the mock and this fixture cannot
 * drift. The allocator throws when the pool is exhausted rather than wrapping
 * back to fixture 0 (which would collide two tests on the same notes).
 *
 * A fixture key is NOT enough to write to Walrus Memory: isTestEnvironment
 * is true for every Playwright-started server, so the binding check only
 * ever consults the fixture pool. There is no live-write path in this suite
 * by design; see the note in e2e/memory.test.ts.
 */
import { mkdirSync } from "node:fs";
import path from "node:path";
import type { Page } from "@playwright/test";
import {
  DELEGATE_FIXTURE_COUNT,
  delegateFixtureAt,
} from "../../../package/feature/auth/lib/delegate-fixtures";

export type DelegateCredentials = {
  privateKey: string;
  accountId: string;
};

export function getDelegateClaimsDir(): string {
  return (
    process.env.NOTER_DELEGATE_CLAIMS_DIR ||
    path.resolve(__dirname, "../../../test-results/.delegate-fixture-claims")
  );
}

/**
 * A never-yet-used fixture identity from the pool.
 *
 * Claims are allocated via atomic directory creation in a shared claims
 * directory across all worker processes. On retry, respawned workers see
 * existing claims on disk and allocate fresh fixtures without colliding with
 * prior workers.
 */
export function nextDelegateCredentials(claimsDirOverride?: string): DelegateCredentials {
  const claimsDir = claimsDirOverride || getDelegateClaimsDir();
  mkdirSync(claimsDir, { recursive: true });

  for (let i = 0; i < DELEGATE_FIXTURE_COUNT; i += 1) {
    const claimPath = path.join(claimsDir, String(i));
    try {
      mkdirSync(claimPath);
      const fixture = delegateFixtureAt(i);
      return { accountId: fixture.accountId, privateKey: fixture.privateKey };
    } catch (err: unknown) {
      if (
        typeof err === "object" &&
        err !== null &&
        "code" in err &&
        (err as { code: string }).code === "EEXIST"
      ) {
        continue;
      }
      throw err;
    }
  }

  throw new Error(
    `Delegate fixture pool exhausted (need index ${DELEGATE_FIXTURE_COUNT}, have ${DELEGATE_FIXTURE_COUNT}). ` +
      `Bump DELEGATE_FIXTURE_COUNT in package/feature/auth/lib/delegate-fixtures.ts.`
  );
}

/** Open the collapsed "Sign in with delegate key" form on the landing page. */
export async function openDelegateKeyForm(page: Page): Promise<void> {
  await page.getByRole("button", { name: /sign in with delegate key/i }).click();
  await page.getByPlaceholder(/private key/i).waitFor({ state: "visible" });
}

/**
 * Drive the real login UI end to end and land on /note.
 * Returns the credentials used so the caller can reuse them.
 */
export async function signInWithDelegateKey(
  page: Page,
  credentials: DelegateCredentials = nextDelegateCredentials(),
): Promise<DelegateCredentials> {
  await page.goto("/");
  await openDelegateKeyForm(page);

  await page.getByPlaceholder(/account id/i).fill(credentials.accountId);
  await page.getByPlaceholder(/private key/i).fill(credentials.privateKey);
  await page.getByRole("button", { name: "Sign In", exact: true }).click();

  // The form hard-navigates with window.location.href = "/note"; wait for that
  // full page load to land. If the sessionAtom-hydration regression (guarded
  // by auth.test.ts) ever comes back, this, and every test that depends on
  // it, fails loudly instead of silently working around the bounce.
  await page.waitForURL(/\/note(\/|$)/);
  return credentials;
}

/** Cold-load the notes route. Use instead of page.reload() when a test needs to be on /note afterwards. */
export async function gotoNotes(page: Page): Promise<void> {
  await page.goto("/note");
}

/**
 * Read the session id the app persists for tRPC's `x-session-id` header.
 * Jotai's atomWithStorage may wrap the payload under `value`.
 */
export async function readSessionId(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    const raw = sessionStorage.getItem("zklogin:session:id");
    if (!raw) return null;
    try {
      const outer = JSON.parse(raw);
      return (outer?.value ?? outer)?.sessionId ?? null;
    } catch {
      return null;
    }
  });
}

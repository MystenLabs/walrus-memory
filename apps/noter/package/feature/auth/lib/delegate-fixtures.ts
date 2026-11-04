/**
 * Deterministic delegate-key identities for Playwright.
 *
 * Shared by the server-side gRPC mock (`delegate-account.mock.ts`) and the
 * Playwright fixture (`tests/playwright/fixtures/delegate-key.ts`) so the
 * two cannot drift. Index N: accountId byte `N` repeated, owner byte
 * `N + 0x80` repeated, privateKey byte `N + 0x40` repeated.
 *
 * Sized as a pool (not a pair) because noter authenticates a fresh identity
 * per test: with 2 workers and retried test runs, two shared identities
 * would collide on each other's notes.
 */
export const DELEGATE_FIXTURE_COUNT = 128;

export type DelegateFixture = {
  accountId: string;
  owner: string;
  privateKey: string;
};

function hex2(n: number): string {
  return n.toString(16).padStart(2, "0");
}

export function delegateFixtureAt(index: number): DelegateFixture {
  if (!Number.isInteger(index) || index < 0 || index >= DELEGATE_FIXTURE_COUNT) {
    throw new Error(
      `Delegate fixture index ${index} is out of range (0..${DELEGATE_FIXTURE_COUNT - 1}). ` +
        `Bump DELEGATE_FIXTURE_COUNT if the suite needs more identities.`
    );
  }
  return {
    accountId: `0x${hex2(index).repeat(32)}`,
    owner: `0x${hex2(index + 0x80).repeat(32)}`,
    privateKey: hex2(index + 0x40).repeat(32),
  };
}

export const TEST_DELEGATE_ACCOUNTS: readonly DelegateFixture[] = Array.from(
  { length: DELEGATE_FIXTURE_COUNT },
  (_, i) => delegateFixtureAt(i)
);

export function findDelegateFixture(
  accountId: string
): DelegateFixture | undefined {
  const needle = accountId.toLowerCase();
  return TEST_DELEGATE_ACCOUNTS.find(
    (account) => account.accountId.toLowerCase() === needle
  );
}

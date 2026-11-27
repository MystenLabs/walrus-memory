import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  DELEGATE_FIXTURE_COUNT,
  delegateFixtureAt,
} from "../../../package/feature/auth/lib/delegate-fixtures";
import {
  getDelegateClaimsDir,
  nextDelegateCredentials,
} from "./delegate-key";

describe("delegate-key fixture allocator", () => {
  let tempDir: string;
  const originalEnvDir = process.env.NOTER_DELEGATE_CLAIMS_DIR;

  beforeEach(() => {
    tempDir = mkdtempSync(path.join(tmpdir(), "noter-claims-test-"));
    process.env.NOTER_DELEGATE_CLAIMS_DIR = tempDir;
  });

  afterEach(() => {
    if (originalEnvDir === undefined) {
      delete process.env.NOTER_DELEGATE_CLAIMS_DIR;
    } else {
      process.env.NOTER_DELEGATE_CLAIMS_DIR = originalEnvDir;
    }
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("allocates sequential unique delegate credentials using atomic filesystem claims", () => {
    const cred0 = nextDelegateCredentials();
    const cred1 = nextDelegateCredentials();

    const expected0 = delegateFixtureAt(0);
    const expected1 = delegateFixtureAt(1);

    expect(cred0).toEqual({
      accountId: expected0.accountId,
      privateKey: expected0.privateKey,
    });
    expect(cred1).toEqual({
      accountId: expected1.accountId,
      privateKey: expected1.privateKey,
    });
    expect(cred0.accountId).not.toBe(cred1.accountId);
  });

  it("never returns duplicate credentials across concurrent or simulated worker processes", async () => {
    const totalAllocations = 30;
    const workerAllocations = await Promise.all(
      Array.from({ length: totalAllocations }, async () => {
        return nextDelegateCredentials();
      }),
    );

    const accountIds = new Set(workerAllocations.map((c) => c.accountId));
    const privateKeys = new Set(workerAllocations.map((c) => c.privateKey));

    expect(accountIds.size).toBe(totalAllocations);
    expect(privateKeys.size).toBe(totalAllocations);
  });

  it("re-reads and skips existing claims on disk when a worker process respawns", () => {
    mkdirSync(path.join(tempDir, "0"));
    mkdirSync(path.join(tempDir, "1"));
    mkdirSync(path.join(tempDir, "2"));

    const respawnedWorkerCred = nextDelegateCredentials();
    const expectedFixture3 = delegateFixtureAt(3);

    expect(respawnedWorkerCred).toEqual({
      accountId: expectedFixture3.accountId,
      privateKey: expectedFixture3.privateKey,
    });
  });

  it("throws descriptive pool exhaustion error when all fixtures are claimed", () => {
    for (let i = 0; i < DELEGATE_FIXTURE_COUNT; i += 1) {
      mkdirSync(path.join(tempDir, String(i)));
    }

    expect(() => nextDelegateCredentials()).toThrowError(
      `Delegate fixture pool exhausted (need index ${DELEGATE_FIXTURE_COUNT}, have ${DELEGATE_FIXTURE_COUNT}). Bump DELEGATE_FIXTURE_COUNT in package/feature/auth/lib/delegate-fixtures.ts.`,
    );
  });

  it("falls back to default claims path when NOTER_DELEGATE_CLAIMS_DIR is unset", () => {
    delete process.env.NOTER_DELEGATE_CLAIMS_DIR;
    const defaultDir = getDelegateClaimsDir();
    expect(defaultDir).toContain(path.join("test-results", ".delegate-fixture-claims"));
  });
});

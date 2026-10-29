import { beforeEach, describe, expect, it, vi } from "vitest";

// Tests the insert-only credential guard in upsertEnokiUser: once a user row has
// a delegate private key, the connect/register path must not overwrite it with
// caller-supplied values (that would let a caller replace an existing owner's
// stored signing key). A minimal drizzle-shaped mock stands in for the DB.

// service.ts pulls in server-only modules transitively; stub the guard so it can
// be imported into the vitest (node) environment.
vi.mock("server-only", () => ({}));

const ADDR = `0x${"3".repeat(64)}`;

let existingRow: Record<string, unknown> | undefined;
const updateSet = vi.fn();
const insertValues = vi.fn();

// Minimal chainable drizzle mock: select().from().where().limit() resolves to
// [existingRow] (or []); update()/insert() record their payloads.
function makeDb() {
  return {
    select: () => ({
      from: () => ({
        where: () => ({
          limit: async () => (existingRow ? [existingRow] : []),
        }),
      }),
    }),
    update: () => ({
      set: (payload: unknown) => {
        updateSet(payload);
        return {
          where: () => ({ returning: async () => [{ id: "u1", ...(payload as object) }] }),
        };
      },
    }),
    insert: () => ({
      values: (payload: unknown) => {
        insertValues(payload);
        return { returning: async () => [{ id: "u-new", ...(payload as object) }] };
      },
    }),
  };
}

async function load() {
  return await import("./service");
}

beforeEach(() => {
  vi.clearAllMocks();
  existingRow = undefined;
});

describe("upsertEnokiUser — insert-only credential guard", () => {
  it("inserts a new user when no row exists and encrypts delegatePrivateKey at rest", async () => {
    const { upsertEnokiUser, getDelegateKeyForOwner } = await load();
    const { decryptDelegatePrivateKey, isEncryptedDelegateKeyEnvelope } =
      await import("../lib/delegate-key-crypto");
    const db = makeDb();
    const created = await upsertEnokiUser(db as never, {
      suiAddress: ADDR,
      delegatePrivateKey: "a".repeat(64),
      delegateAccountId: "acct-new",
    });
    expect(insertValues).toHaveBeenCalledTimes(1);
    expect(updateSet).not.toHaveBeenCalled();

    const written = insertValues.mock.calls[0]?.[0] as {
      delegatePrivateKey: string;
    };
    expect(written.delegatePrivateKey).not.toBe("a".repeat(64));
    expect(isEncryptedDelegateKeyEnvelope(written.delegatePrivateKey)).toBe(
      true
    );
    expect(decryptDelegatePrivateKey(written.delegatePrivateKey)).toBe(
      "a".repeat(64)
    );

    existingRow = created as Record<string, unknown>;
    const resolved = await getDelegateKeyForOwner(db as never, ADDR);
    expect(resolved).toEqual({
      delegatePrivateKey: "a".repeat(64),
      delegateAccountId: "acct-new",
    });
  });

  it("provisions creds on an existing row that has none yet and encrypts at rest", async () => {
    existingRow = { id: "u1", authMethod: "enoki", delegatePrivateKey: null };
    const { upsertEnokiUser } = await load();
    const { decryptDelegatePrivateKey, isEncryptedDelegateKeyEnvelope } =
      await import("../lib/delegate-key-crypto");
    const db = makeDb();
    await upsertEnokiUser(db as never, {
      suiAddress: ADDR,
      delegatePrivateKey: "b".repeat(64),
      delegateAccountId: "acct-first",
    });
    expect(updateSet).toHaveBeenCalledTimes(1);
    expect(insertValues).not.toHaveBeenCalled();

    const updated = updateSet.mock.calls[0]?.[0] as {
      delegatePrivateKey: string;
    };
    expect(updated.delegatePrivateKey).not.toBe("b".repeat(64));
    expect(isEncryptedDelegateKeyEnvelope(updated.delegatePrivateKey)).toBe(
      true
    );
    expect(decryptDelegatePrivateKey(updated.delegatePrivateKey)).toBe(
      "b".repeat(64)
    );
  });

  it("refuses to overwrite an existing row that already has a delegate key", async () => {
    existingRow = {
      id: "u1",
      authMethod: "enoki",
      delegatePrivateKey: "existing-secret",
      delegateAccountId: "existing-acct",
    };
    const { upsertEnokiUser, DelegateCredentialConflictError } = await load();
    const db = makeDb();
    await expect(
      upsertEnokiUser(db as never, {
        suiAddress: ADDR,
        delegatePrivateKey: "attacker-key",
        delegateAccountId: "attacker-acct",
      })
    ).rejects.toBeInstanceOf(DelegateCredentialConflictError);
    // The stored key must never be replaced.
    expect(updateSet).not.toHaveBeenCalled();
    expect(insertValues).not.toHaveBeenCalled();
  });
});

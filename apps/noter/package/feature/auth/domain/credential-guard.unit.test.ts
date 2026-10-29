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
let updateReturningOverride: (() => Promise<unknown[]>) | undefined;
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
          then: (resolve: (rows: unknown[]) => void) =>
            resolve(existingRow ? [existingRow] : []),
        }),
        then: (resolve: (rows: unknown[]) => void) =>
          resolve(existingRow ? [existingRow] : []),
      }),
    }),
    update: () => ({
      set: (payload: unknown) => {
        updateSet(payload);
        if (!updateReturningOverride && existingRow && payload && typeof payload === "object") {
          existingRow = { ...existingRow, ...(payload as object) };
        }
        return {
          where: () => ({
            returning: async () => {
              if (updateReturningOverride) return updateReturningOverride();
              return [existingRow ?? { id: "u1", ...(payload as object) }];
            },
          }),
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
  updateReturningOverride = undefined;
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

  it("migrates a pre-upgrade 64-hex plaintext row in place on returning Enoki lookup and key resolution without replacing the account", async () => {
    const legacyPlaintextKey = "c".repeat(64);
    existingRow = {
      id: "u-legacy",
      suiAddress: ADDR,
      authMethod: "enoki",
      delegatePrivateKey: legacyPlaintextKey,
      delegateAccountId: "0x" + "9".repeat(64),
    };

    const { getEnokiUserBySuiAddress, getDelegateKeyForOwner } = await load();
    const { decryptDelegatePrivateKey, isEncryptedDelegateKeyEnvelope } =
      await import("../lib/delegate-key-crypto");
    const db = makeDb();

    // Returning user check succeeds (does not return null / needsSetup) and backfills v1 envelope
    const returningUser = await getEnokiUserBySuiAddress(db as never, ADDR);
    expect(returningUser).not.toBeNull();
    expect(returningUser?.id).toBe("u-legacy");
    expect(returningUser?.delegateAccountId).toBe("0x" + "9".repeat(64));
    expect(updateSet).toHaveBeenCalledTimes(1);

    const migratedColumn = existingRow.delegatePrivateKey as string;
    expect(isEncryptedDelegateKeyEnvelope(migratedColumn)).toBe(true);
    expect(decryptDelegatePrivateKey(migratedColumn)).toBe(legacyPlaintextKey);

    // Subsequent key resolution uses the migrated v1 envelope without further DB writes
    updateSet.mockClear();
    const resolved = await getDelegateKeyForOwner(db as never, ADDR);
    expect(resolved).toEqual({
      delegatePrivateKey: legacyPlaintextKey,
      delegateAccountId: "0x" + "9".repeat(64),
    });
    expect(updateSet).not.toHaveBeenCalled();
  });

  it("reloads and propagates the complete credential tuple when migration races with a concurrent credential update", async () => {
    const legacyKey = "c".repeat(64);
    const newRotatedKey = "e".repeat(64);
    const oldAccountId = "0x" + "1".repeat(64);
    const newRotatedAccountId = "0x" + "2".repeat(64);
    const { encryptDelegatePrivateKey } = await import("../lib/delegate-key-crypto");
    const newRotatedEnvelope = encryptDelegatePrivateKey(newRotatedKey);

    existingRow = {
      id: "u-racing",
      suiAddress: ADDR,
      authMethod: "enoki",
      delegatePrivateKey: legacyKey,
      delegateAccountId: oldAccountId,
    };

    const { getEnokiUserBySuiAddress, getDelegateKeyForOwner } = await load();
    const db = makeDb();

    // Simulate concurrent rotation updating the database row before our CAS update lands
    updateReturningOverride = async () => {
      existingRow = {
        ...existingRow,
        delegatePrivateKey: newRotatedEnvelope,
        delegateAccountId: newRotatedAccountId,
      };
      // CAS condition did not match because stored key was no longer legacyKey
      return [];
    };

    const returningUser = await getEnokiUserBySuiAddress(db as never, ADDR);
    expect(returningUser).not.toBeNull();
    expect(returningUser?.delegatePrivateKey).toBe(newRotatedEnvelope);
    expect(returningUser?.delegateAccountId).toBe(newRotatedAccountId);

    // Reset row to legacy state to also verify getDelegateKeyForOwner caller tuple on lost CAS race
    existingRow = {
      id: "u-racing",
      suiAddress: ADDR,
      authMethod: "enoki",
      delegatePrivateKey: legacyKey,
      delegateAccountId: oldAccountId,
    };

    const ownerTuple = await getDelegateKeyForOwner(db as never, ADDR);
    expect(ownerTuple).toEqual({
      delegatePrivateKey: newRotatedKey,
      delegateAccountId: newRotatedAccountId,
    });
    expect(existingRow.delegatePrivateKey).toBe(newRotatedEnvelope);
    expect(existingRow.delegateAccountId).toBe(newRotatedAccountId);
  });

  it("backfillLegacyDelegateKeys uses atomic CAS and skips rows updated concurrently", async () => {
    const legacyKey = "d".repeat(64);
    const rotatedKey = "f".repeat(64);
    const { encryptDelegatePrivateKey } = await import("../lib/delegate-key-crypto");
    const rotatedEnvelope = encryptDelegatePrivateKey(rotatedKey);

    existingRow = {
      id: "u-batch",
      suiAddress: ADDR,
      authMethod: "enoki",
      delegatePrivateKey: legacyKey,
      delegateAccountId: "0x" + "3".repeat(64),
    };

    const { backfillLegacyDelegateKeys } = await load();
    const db = makeDb();

    // Simulate concurrent update on the row right after initial select
    updateReturningOverride = async () => {
      existingRow = {
        ...existingRow,
        delegatePrivateKey: rotatedEnvelope,
      };
      return []; // CAS matched 0 rows
    };

    const count = await backfillLegacyDelegateKeys(db as never);
    expect(count).toBe(0);
    expect(existingRow.delegatePrivateKey).toBe(rotatedEnvelope);
  });
});

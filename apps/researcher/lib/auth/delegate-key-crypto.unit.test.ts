import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { before, beforeEach, mock, test } from "node:test";
import { PgDialect } from "drizzle-orm/pg-core";
import type { SQL } from "drizzle-orm";
import type { MigratedUserCredentials } from "../db/queries";
import {
  decryptDelegatePrivateKey,
  DelegateKeyCryptoError,
  encryptDelegatePrivateKey,
  isEncryptedDelegateKeyEnvelope,
  isLegacyPlaintextDelegateKey,
  openOrMigrateDelegatePrivateKey,
} from "./delegate-key-crypto";

const SECRET_A = "0123456789abcdef0123456789abcdef";
const SECRET_B = "fedcba9876543210fedcba9876543210";
const SAMPLE_KEY = "cd".repeat(32);

let updateRows: Array<{ delegatePrivateKey: string }>;
let reloadedRows: Array<Partial<MigratedUserCredentials>>;
let writtenEnvelope: string;
let updatePredicate: SQL;
let selectedFields: string[];

beforeEach(() => {
  updateRows = [];
  reloadedRows = [];
  writtenEnvelope = "";
  selectedFields = [];
});

mock.module("server-only", { namedExports: {} });
mock.module("@/lib/db/drizzle", {
  namedExports: {
    db: {
      update: () => ({
        set: (values: { delegatePrivateKey: string }) => {
          writtenEnvelope = values.delegatePrivateKey;
          return {
            where: (predicate: SQL) => {
              updatePredicate = predicate;
              return { returning: async () => updateRows };
            },
          };
        },
      }),
      select: (fields: Record<string, unknown>) => {
        selectedFields = Object.keys(fields);
        return { from: () => ({ where: async () => reloadedRows }) };
      },
    },
  },
});

let resolveAndMigrateUserDelegateKey:
  typeof import("../db/queries").resolveAndMigrateUserDelegateKey;
before(async () => {
  ({ resolveAndMigrateUserDelegateKey } = await import("../db/queries"));
});

test("encrypts into a v1.<nonce>.<ct> envelope and round-trips", () => {
  const envelope = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
  assert.equal(isEncryptedDelegateKeyEnvelope(envelope), true);
  assert.match(envelope, /^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
  assert.equal(envelope.includes(SAMPLE_KEY), false);
  assert.ok(envelope.length <= 128, `expected <= 128 chars, got ${envelope.length}`);

  const decrypted = decryptDelegatePrivateKey(envelope, SECRET_A);
  assert.equal(decrypted, SAMPLE_KEY);
});

test("uses a fresh random nonce on every encryption", () => {
  const env1 = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
  const env2 = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
  assert.notEqual(env1, env2);
  assert.equal(decryptDelegatePrivateKey(env1, SECRET_A), SAMPLE_KEY);
  assert.equal(decryptDelegatePrivateKey(env2, SECRET_A), SAMPLE_KEY);
});

test("rejects tampered ciphertext or authentication tag", () => {
  const envelope = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
  const parts = envelope.split(".");
  const payload = Buffer.from(parts[2]!, "base64url");
  payload[0] ^= 0xff;
  const tampered = `${parts[0]}.${parts[1]}.${payload.toString("base64url")}`;

  assert.throws(
    () => decryptDelegatePrivateKey(tampered, SECRET_A),
    DelegateKeyCryptoError
  );
});

test("rejects decryption with a different secret", () => {
  const envelope = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
  assert.throws(
    () => decryptDelegatePrivateKey(envelope, SECRET_B),
    DelegateKeyCryptoError
  );
});

test("rejects double encryption, raw plaintext on decrypt, and short secrets", () => {
  const envelope = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
  assert.throws(
    () => encryptDelegatePrivateKey(envelope, SECRET_A),
    DelegateKeyCryptoError
  );
  assert.throws(
    () => decryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A),
    DelegateKeyCryptoError
  );
  assert.throws(
    () => encryptDelegatePrivateKey(SAMPLE_KEY, "short-secret"),
    DelegateKeyCryptoError
  );
});

test("migrates pre-upgrade 64-hex plaintext delegate keys into v1 envelopes and opens existing v1 envelopes", () => {
  assert.equal(isLegacyPlaintextDelegateKey(SAMPLE_KEY), true);
  assert.equal(isLegacyPlaintextDelegateKey("not-a-hex-key"), false);

  const migrated = openOrMigrateDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
  assert.equal(migrated.migrated, true);
  assert.equal(migrated.plaintextKey, SAMPLE_KEY);
  assert.equal(isEncryptedDelegateKeyEnvelope(migrated.encryptedEnvelope), true);

  const reopened = openOrMigrateDelegatePrivateKey(
    migrated.encryptedEnvelope,
    SECRET_A
  );
  assert.equal(reopened.migrated, false);
  assert.equal(reopened.plaintextKey, SAMPLE_KEY);
  assert.equal(reopened.encryptedEnvelope, migrated.encryptedEnvelope);

  assert.throws(
    () => openOrMigrateDelegatePrivateKey("malformed-non-hex", SECRET_A),
    DelegateKeyCryptoError
  );
});

test("queries.ts, session.ts, and enoki/route.ts wire encryptDelegatePrivateKey and resolveAndMigrateUserDelegateKey", () => {
  const queriesSource = readFileSync(resolve("lib/db/queries.ts"), "utf8");
  const sessionSource = readFileSync(resolve("lib/auth/session.ts"), "utf8");
  const enokiRouteSource = readFileSync(
    resolve("app/api/auth/enoki/route.ts"),
    "utf8"
  );

  assert.match(queriesSource, /encryptDelegatePrivateKey\(delegatePrivateKey\)/);
  assert.match(queriesSource, /openOrMigrateDelegatePrivateKey\(/);
  assert.doesNotMatch(
    queriesSource,
    /\.values\(\{[^}]*delegatePrivateKey\s*,/
  );
  assert.match(
    queriesSource,
    /eq\(user\.delegatePrivateKey,\s*originalPlaintext\)/
  );
  assert.match(
    queriesSource,
    /eq\(user\.delegatePrivateKey,\s*row\.delegatePrivateKey\)/
  );
  assert.match(
    sessionSource,
    /resolveAndMigrateUserDelegateKey\(user\)/
  );
  assert.match(
    enokiRouteSource,
    /resolveAndMigrateUserDelegateKey\(existing\)/
  );
});

test("migration losing its CAS reloads the complete rotated credential tuple", async () => {
  const legacyPlaintext = "a".repeat(64);
  const rotatedKey = "b".repeat(64);
  const rotatedEnvelope = encryptDelegatePrivateKey(rotatedKey, SECRET_A);

  const targetUser = {
    id: "user-1",
    publicKey: "pk-1",
    accountId: "acct-1",
    delegatePrivateKey: legacyPlaintext,
  };

  reloadedRows = [{
    delegatePrivateKey: rotatedEnvelope,
    publicKey: "pk-rotated",
    accountId: "acct-rotated",
  }];

  const privateKey = await resolveAndMigrateUserDelegateKey(targetUser, SECRET_A);

  assert.equal(privateKey, rotatedKey);
  assert.deepEqual(targetUser, { id: "user-1", ...reloadedRows[0] });
  assert.deepEqual(selectedFields.sort(), ["accountId", "delegatePrivateKey", "publicKey"]);
  assert.deepEqual(new PgDialect().sqlToQuery(updatePredicate).params, [
    targetUser.id,
    legacyPlaintext,
  ]);
});

test("successful migration encrypts the existing plaintext key without changing account metadata", async () => {
  const targetUser = {
    id: "user-1",
    delegatePrivateKey: SAMPLE_KEY,
    publicKey: "pk-existing",
    accountId: "acct-existing",
  };
  updateRows = [{ delegatePrivateKey: "updated" }];

  assert.equal(await resolveAndMigrateUserDelegateKey(targetUser, SECRET_A), SAMPLE_KEY);
  assert.equal(decryptDelegatePrivateKey(writtenEnvelope, SECRET_A), SAMPLE_KEY);
  assert.equal(targetUser.delegatePrivateKey, writtenEnvelope);
  assert.equal(targetUser.publicKey, "pk-existing");
  assert.equal(targetUser.accountId, "acct-existing");
  assert.deepEqual(selectedFields, []);
});

test("migration fails closed when a concurrent rotation leaves an incomplete credential tuple", async () => {
  const targetUser = {
    id: "user-1",
    delegatePrivateKey: SAMPLE_KEY,
    publicKey: "pk-existing",
    accountId: "acct-existing",
  };
  reloadedRows = [{
    delegatePrivateKey: encryptDelegatePrivateKey("b".repeat(64), SECRET_A),
    publicKey: "pk-rotated",
    accountId: null,
  }];

  await assert.rejects(
    resolveAndMigrateUserDelegateKey(targetUser, SECRET_A),
    DelegateKeyCryptoError
  );
  assert.equal(targetUser.delegatePrivateKey, SAMPLE_KEY);
  assert.equal(targetUser.accountId, "acct-existing");
});

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";
import {
  decryptDelegatePrivateKey,
  DelegateKeyCryptoError,
  encryptDelegatePrivateKey,
  isEncryptedDelegateKeyEnvelope,
} from "./delegate-key-crypto";

const SECRET_A = "0123456789abcdef0123456789abcdef";
const SECRET_B = "fedcba9876543210fedcba9876543210";
const SAMPLE_KEY = "cd".repeat(32);

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

test("queries.ts and session.ts wire encryptDelegatePrivateKey and decryptDelegatePrivateKey", () => {
  const queriesSource = readFileSync(resolve("lib/db/queries.ts"), "utf8");
  const sessionSource = readFileSync(resolve("lib/auth/session.ts"), "utf8");

  assert.match(queriesSource, /encryptDelegatePrivateKey\(delegatePrivateKey\)/);
  assert.doesNotMatch(
    queriesSource,
    /\.values\(\{[^}]*delegatePrivateKey\s*,/
  );
  assert.match(sessionSource, /decryptDelegatePrivateKey\(user\.delegatePrivateKey\)/);
});

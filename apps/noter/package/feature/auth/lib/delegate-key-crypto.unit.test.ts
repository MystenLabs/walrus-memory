import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));

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
const SAMPLE_KEY = "ab".repeat(32);

describe("delegate-key-crypto (Noter)", () => {
  it("encrypts into a v1.<nonce>.<ct> envelope and round-trips", () => {
    const envelope = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
    expect(isEncryptedDelegateKeyEnvelope(envelope)).toBe(true);
    expect(envelope.startsWith("v1.")).toBe(true);
    expect(envelope).not.toContain(SAMPLE_KEY);
    expect(envelope.length).toBeLessThanOrEqual(128);

    const decrypted = decryptDelegatePrivateKey(envelope, SECRET_A);
    expect(decrypted).toBe(SAMPLE_KEY);
  });

  it("uses a fresh random nonce on every encryption", () => {
    const env1 = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
    const env2 = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
    expect(env1).not.toBe(env2);
    expect(decryptDelegatePrivateKey(env1, SECRET_A)).toBe(SAMPLE_KEY);
    expect(decryptDelegatePrivateKey(env2, SECRET_A)).toBe(SAMPLE_KEY);
  });

  it("rejects tampered ciphertext or authentication tag", () => {
    const envelope = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
    const parts = envelope.split(".");
    const payload = Buffer.from(parts[2]!, "base64url");
    payload[0] ^= 0xff;
    const tampered = `${parts[0]}.${parts[1]}.${payload.toString("base64url")}`;

    expect(() => decryptDelegatePrivateKey(tampered, SECRET_A)).toThrow(
      DelegateKeyCryptoError
    );
  });

  it("rejects decryption with a different secret", () => {
    const envelope = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
    expect(() => decryptDelegatePrivateKey(envelope, SECRET_B)).toThrow(
      DelegateKeyCryptoError
    );
  });

  it("rejects double encryption and plaintext or malformed envelopes", () => {
    const envelope = encryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
    expect(() => encryptDelegatePrivateKey(envelope, SECRET_A)).toThrow(
      DelegateKeyCryptoError
    );
    expect(() => decryptDelegatePrivateKey(SAMPLE_KEY, SECRET_A)).toThrow(
      DelegateKeyCryptoError
    );
    expect(() => decryptDelegatePrivateKey("v2.abc.def", SECRET_A)).toThrow(
      DelegateKeyCryptoError
    );
  });

  it("rejects short secrets (< 32 chars)", () => {
    expect(() => encryptDelegatePrivateKey(SAMPLE_KEY, "too-short")).toThrow(
      DelegateKeyCryptoError
    );
  });

  it("migrates legacy 64-hex plaintext keys into v1 envelopes and opens existing v1 envelopes", () => {
    expect(isLegacyPlaintextDelegateKey(SAMPLE_KEY)).toBe(true);
    expect(isLegacyPlaintextDelegateKey("not-a-hex-key")).toBe(false);

    const migrated = openOrMigrateDelegatePrivateKey(SAMPLE_KEY, SECRET_A);
    expect(migrated.migrated).toBe(true);
    expect(migrated.plaintextKey).toBe(SAMPLE_KEY);
    expect(isEncryptedDelegateKeyEnvelope(migrated.encryptedEnvelope)).toBe(
      true
    );

    const reopened = openOrMigrateDelegatePrivateKey(
      migrated.encryptedEnvelope,
      SECRET_A
    );
    expect(reopened.migrated).toBe(false);
    expect(reopened.plaintextKey).toBe(SAMPLE_KEY);
    expect(reopened.encryptedEnvelope).toBe(migrated.encryptedEnvelope);

    expect(() =>
      openOrMigrateDelegatePrivateKey("malformed-non-hex", SECRET_A)
    ).toThrow(DelegateKeyCryptoError);
  });
});

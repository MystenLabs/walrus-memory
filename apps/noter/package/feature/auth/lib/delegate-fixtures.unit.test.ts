import * as ed from "@noble/ed25519";
import { blake2b } from "@noble/hashes/blake2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import {
  DELEGATE_FIXTURE_COUNT,
  TEST_DELEGATE_ACCOUNTS,
  delegateFixtureAt,
  findDelegateFixture,
} from "./delegate-fixtures";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...messages: Uint8Array[]) => {
    const hash = sha512.create();
    for (const msg of messages) hash.update(msg);
    return hash.digest();
  };
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function deriveSuiAddress(publicKeyBytes: Uint8Array): string {
  const addrInput = new Uint8Array(33);
  addrInput[0] = 0x00;
  addrInput.set(publicKeyBytes, 1);
  const addressBytes = blake2b(addrInput, { dkLen: 32 });
  return "0x" + Array.from(addressBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("delegate fixtures", () => {
  it("builds a unique deterministic pool of 128 valid identities", () => {
    expect(DELEGATE_FIXTURE_COUNT).toBe(128);
    expect(TEST_DELEGATE_ACCOUNTS).toHaveLength(128);

    const accountIds = new Set<string>();
    const owners = new Set<string>();
    const privateKeys = new Set<string>();
    const publicKeys = new Set<string>();
    const suiAddresses = new Set<string>();

    for (let i = 0; i < DELEGATE_FIXTURE_COUNT; i += 1) {
      const fixture = delegateFixtureAt(i);

      expect(fixture.accountId).toMatch(/^0x[0-9a-f]{64}$/);
      expect(fixture.owner).toMatch(/^0x[0-9a-f]{64}$/);
      expect(fixture.privateKey).toMatch(/^[0-9a-f]{64}$/);

      const pubKeyBytes = ed.getPublicKey(hexToBytes(fixture.privateKey));
      const pubKeyHex = Array.from(pubKeyBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
      const suiAddress = deriveSuiAddress(pubKeyBytes);

      expect(pubKeyHex).toMatch(/^[0-9a-f]{64}$/);
      expect(suiAddress).toMatch(/^0x[0-9a-f]{64}$/);

      accountIds.add(fixture.accountId);
      owners.add(fixture.owner);
      privateKeys.add(fixture.privateKey);
      publicKeys.add(pubKeyHex);
      suiAddresses.add(suiAddress);
    }

    expect(accountIds.size).toBe(128);
    expect(owners.size).toBe(128);
    expect(privateKeys.size).toBe(128);
    expect(publicKeys.size).toBe(128);
    expect(suiAddresses.size).toBe(128);

    expect(delegateFixtureAt(0)).toEqual({
      accountId: `0x${"00".repeat(32)}`,
      owner: `0x${"80".repeat(32)}`,
      privateKey: "40".repeat(32),
    });

    expect(delegateFixtureAt(127)).toEqual({
      accountId: `0x${"7f".repeat(32)}`,
      owner: `0x${"ff".repeat(32)}`,
      privateKey: "bf".repeat(32),
    });
  });

  it("looks up by account id case-insensitively", () => {
    const fixture = delegateFixtureAt(1);
    expect(findDelegateFixture(fixture.accountId.toUpperCase())).toEqual(fixture);
    expect(findDelegateFixture(`0x${"ff".repeat(32)}`)).toBeUndefined();
  });

  it("throws instead of wrapping past the pool", () => {
    expect(() => delegateFixtureAt(DELEGATE_FIXTURE_COUNT)).toThrow(/out of range/);
    expect(() => delegateFixtureAt(-1)).toThrow(/out of range/);
    expect(() => delegateFixtureAt(128)).toThrow(/out of range/);
  });
});

import assert from "node:assert/strict";
import test from "node:test";
import { delegateAccountBindingError } from "./delegate-account";

const PACKAGE_ID = `0x${"2".repeat(64)}`;
const PUBLIC_KEY = "ab".repeat(32);

test("Researcher delegate login requires an active matching on-chain key", () => {
  assert.equal(
    delegateAccountBindingError(
      `${PACKAGE_ID}::account::MemWalAccount`,
      {
        active: true,
        delegate_keys: [{ public_key: PUBLIC_KEY }],
      },
      { packageId: PACKAGE_ID, publicKeyHex: PUBLIC_KEY }
    ),
    null
  );

  assert.match(
    delegateAccountBindingError(
      `${PACKAGE_ID}::account::MemWalAccount`,
      {
        active: true,
        delegate_keys: [{ public_key: "cd".repeat(32) }],
      },
      { packageId: PACKAGE_ID, publicKeyHex: PUBLIC_KEY }
    ) ?? "",
    /not registered/
  );
});

test("Researcher Enoki registration requires the authenticated wallet to own the account (#1008)", () => {
  const OWNER = `0x${"1".repeat(64)}`;
  const type = `${PACKAGE_ID}::account::MemWalAccount`;
  const fields = { active: true, owner: OWNER, delegate_keys: [{ public_key: PUBLIC_KEY }] };

  assert.equal(
    delegateAccountBindingError(type, fields, { owner: OWNER, packageId: PACKAGE_ID, publicKeyHex: PUBLIC_KEY }),
    null
  );
  // Short and long address forms of the same owner are equal.
  assert.equal(
    delegateAccountBindingError(type, { ...fields, owner: "0x1" }, {
      owner: `0x${"0".repeat(63)}1`,
      packageId: PACKAGE_ID,
      publicKeyHex: PUBLIC_KEY,
    }),
    null
  );
  for (const owner of [`0x${"9".repeat(64)}`, undefined, 42]) {
    assert.match(
      delegateAccountBindingError(type, { ...fields, owner }, {
        owner: OWNER,
        packageId: PACKAGE_ID,
        publicKeyHex: PUBLIC_KEY,
      }) ?? "",
      /owner does not match the authenticated wallet/
    );
  }
  // Manual delegate login has no wallet, so it does not check the owner.
  assert.equal(
    delegateAccountBindingError(type, { ...fields, owner: `0x${"9".repeat(64)}` }, {
      packageId: PACKAGE_ID,
      publicKeyHex: PUBLIC_KEY,
    }),
    null
  );
});

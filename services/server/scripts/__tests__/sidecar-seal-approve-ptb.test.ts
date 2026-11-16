import test from "node:test";
import assert from "node:assert/strict";
import { normalizeSuiAddress } from "@mysten/sui/utils";
import {
    buildSealApproveTx,
    sealApproveArgsError,
    sealApprovePackageId,
    sealIdentityPackageError,
} from "../sidecar/seal-ptb.js";

// Pins the on-chain `seal_approve(id, registry, account, ctx)` argument order.
// registry and account are both `tx.object` args, so a swap or a dropped
// registry still builds locally and only reverts on-chain (EWrongVersion /
// wrong owner) — nothing else fails loudly if this drifts.

const PKG = "0x" + "2".repeat(64);
const POLICY_PKG = "0x" + "4".repeat(64);
const REG = "0x" + "9".repeat(64);
const ACC = "0x" + "3".repeat(64);
const POLICY = { allowLegacySealAbi: true, policyPackageId: POLICY_PKG };

test("seal_approve PTB passes [id, registry, account] in that order", () => {
    const data = buildSealApproveTx(PKG, REG, ACC, ["aabbccdd"]).getData();

    const calls = data.commands.filter((c) => c.$kind === "MoveCall");
    assert.equal(calls.length, 1, "one seal_approve call per id");

    const mc = (calls[0] as any).MoveCall;
    assert.equal(mc.module, "account");
    assert.equal(mc.function, "seal_approve");
    assert.equal(normalizeSuiAddress(mc.package), normalizeSuiAddress(PKG));
    assert.equal(mc.arguments.length, 3, "id, registry, account — not the old 2-arg form");

    // Resolve each moveCall argument back to its transaction input.
    const inputs = mc.arguments.map((a: any) => data.inputs[a.Input]);

    assert.equal(inputs[0].$kind, "Pure", "arg 0 is the SEAL id bytes");

    assert.equal(inputs[1].$kind, "UnresolvedObject", "arg 1 is an object (registry)");
    assert.equal(
        normalizeSuiAddress(inputs[1].UnresolvedObject.objectId),
        normalizeSuiAddress(REG),
        "registry must precede account",
    );

    assert.equal(inputs[2].$kind, "UnresolvedObject", "arg 2 is an object (account)");
    assert.equal(
        normalizeSuiAddress(inputs[2].UnresolvedObject.objectId),
        normalizeSuiAddress(ACC),
    );
});

test("one seal_approve call is emitted per SEAL id", () => {
    const data = buildSealApproveTx(PKG, REG, ACC, ["aabb", "ccdd", "eeff"]).getData();
    const calls = data.commands.filter((c) => c.$kind === "MoveCall");
    assert.equal(calls.length, 3);
});

test("current policy package is independent from the immutable ciphertext package", () => {
    assert.equal(sealApprovePackageId({ packageId: PKG, sealAbi: "v1-new" }, POLICY_PKG), POLICY_PKG);
    assert.equal(sealApprovePackageId({ packageId: PKG, sealAbi: "v1" }, POLICY_PKG), PKG);

    const data = buildSealApproveTx(POLICY_PKG, REG, ACC, ["aabb"]).getData();
    const call = data.commands.find(command => command.$kind === "MoveCall") as any;
    assert.equal(
        normalizeSuiAddress(call.MoveCall.package),
        normalizeSuiAddress(POLICY_PKG),
        "the PTB executes the upgraded policy package",
    );
});

test("SEAL identity package comparison is canonical and binds ciphertext and session", () => {
    const canonicalShortId = normalizeSuiAddress("0x2");
    assert.equal(
        sealIdentityPackageError("0x2", [canonicalShortId], canonicalShortId),
        null,
    );
    assert.match(sealIdentityPackageError(PKG, [PKG], POLICY_PKG)!, /SessionKey/);
    assert.match(sealIdentityPackageError(PKG, [PKG, POLICY_PKG], PKG)!, /Ciphertext/);
});

// The legacy/source V1 package predates the single registry and exposes the
// 2-arg `seal_approve(id, account, ctx)`. The migrator's source decrypt leg
// calls this route with no registry (sealAbi "v1"), which must build the old
// shape — passing the registry would not match the source package ABI.
test("seal_approve PTB drops registry to [id, account] when registryId is omitted", () => {
    const data = buildSealApproveTx(PKG, undefined, ACC, ["aabbccdd"]).getData();

    const calls = data.commands.filter((c) => c.$kind === "MoveCall");
    assert.equal(calls.length, 1, "one seal_approve call per id");

    const mc = (calls[0] as any).MoveCall;
    assert.equal(mc.module, "account");
    assert.equal(mc.function, "seal_approve");
    assert.equal(mc.arguments.length, 2, "id, account — the legacy 2-arg form");

    const inputs = mc.arguments.map((a: any) => data.inputs[a.Input]);

    assert.equal(inputs[0].$kind, "Pure", "arg 0 is the SEAL id bytes");

    assert.equal(inputs[1].$kind, "UnresolvedObject", "arg 1 is an object (account)");
    assert.equal(
        normalizeSuiAddress(inputs[1].UnresolvedObject.objectId),
        normalizeSuiAddress(ACC),
        "account is passed directly after the id, with no registry between",
    );
});

test("sealApproveArgsError enforces the ids and the sealAbi/registryId pairing", () => {
    const base = { packageId: PKG, accountId: ACC };
    assert.equal(sealApproveArgsError({ ...base, sealAbi: "v1" }, POLICY), null, "v1 without registry is valid");
    assert.equal(sealApproveArgsError({ ...base, sealAbi: "v1-new", registryId: REG, policyPackageId: POLICY_PKG }, POLICY), null, "v1-new with registry is valid");
    assert.match(sealApproveArgsError({ ...base, sealAbi: "v1-new" }, POLICY)!, /registryId/, "v1-new needs a registry");
    assert.match(sealApproveArgsError({ ...base, sealAbi: "v1", registryId: REG }, POLICY)!, /not valid/, "v1 must not carry a registry");
    assert.match(sealApproveArgsError({ ...base, sealAbi: undefined }, POLICY)!, /sealAbi/, "sealAbi is required");
    assert.match(sealApproveArgsError({ sealAbi: "v1" }, POLICY)!, /packageId/, "packageId and accountId are required");
    assert.match(sealApproveArgsError({ ...base, packageId: "bad", sealAbi: "v1" }, POLICY)!, /packageId format/);
    for (const accountId of ["bad", "0x", `0x${"1".repeat(65)}`, 123, {}]) {
        assert.match(
            sealApproveArgsError({ ...base, accountId, sealAbi: "v1" } as any, POLICY)!,
            /accountId format/,
        );
    }
    for (const registryId of ["bad", "0x", `0x${"1".repeat(65)}`, 123, {}]) {
        assert.match(
            sealApproveArgsError({ ...base, registryId, sealAbi: "v1-new" } as any, POLICY)!,
            /registryId format/,
        );
    }
    assert.match(sealApproveArgsError({ ...base, sealAbi: "v1" }, { ...POLICY, allowLegacySealAbi: false })!, /disabled/);
    assert.match(sealApproveArgsError({ ...base, sealAbi: "v1-new", registryId: REG, policyPackageId: PKG }, POLICY)!, /configured/);
});

test("seal_approve PTB builds locally without RPC client when immutable initialSharedVersions are supplied", async () => {
    const tx = buildSealApproveTx(POLICY_PKG, REG, ACC, ["aabbccdd"], {
        registryInitialSharedVersion: "941625040",
        accountInitialSharedVersion: "966338902",
    });
    const data = tx.getData();
    const mc = (data.commands[0] as any).MoveCall;
    const inputs = mc.arguments.map((a: any) => data.inputs[a.Input]);

    assert.equal(inputs[0].$kind, "Pure");
    assert.equal(inputs[1].$kind, "Object");
    assert.equal(normalizeSuiAddress(inputs[1].Object.SharedObject.objectId), normalizeSuiAddress(REG));
    assert.equal(String(inputs[1].Object.SharedObject.initialSharedVersion), "941625040");
    assert.equal(inputs[1].Object.SharedObject.mutable, false);

    assert.equal(inputs[2].$kind, "Object");
    assert.equal(normalizeSuiAddress(inputs[2].Object.SharedObject.objectId), normalizeSuiAddress(ACC));
    assert.equal(String(inputs[2].Object.SharedObject.initialSharedVersion), "966338902");
    assert.equal(inputs[2].Object.SharedObject.mutable, false);

    const bytes = await tx.build({ onlyTransactionKind: true });
    assert.ok(bytes.length > 64);
});

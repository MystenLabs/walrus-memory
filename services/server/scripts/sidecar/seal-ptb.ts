import { Inputs, Transaction, TransactionArgument } from "@mysten/sui/transactions";
import { normalizeSuiAddress } from "@mysten/sui/utils";

/**
 * Which on-chain `seal_approve` ABI a request targets. Two package versions are
 * live at once during the V1 → v1-new migration and one sidecar route serves
 * both, so every caller states its ABI explicitly instead of implying it:
 *   - "v1":     legacy/source package  `seal_approve(id, account, ctx)`
 *   - "v1-new": current/destination    `seal_approve(id, registry, account, ctx)`
 */
type SealAbi = "v1" | "v1-new";

export interface SealApproveSharedVersions {
    registryInitialSharedVersion?: string | number;
    accountInitialSharedVersion?: string | number;
}

/**
 * Validate the seal_approve arguments in a decrypt request body: the
 * package/account ids plus the sealAbi/registryId pairing. Returns an error
 * message (for a 400), or null when they are valid. "v1-new" requires a
 * registryId (3-arg seal_approve), "v1" forbids one (the old source package has
 * no registry to pass and no 3-arg entry to pass it to). Each route still checks
 * its own payload field (data / items).
 */
export function sealApproveArgsError(body: {
    packageId?: string;
    policyPackageId?: string;
    accountId?: string;
    registryId?: string;
    sealAbi?: SealAbi;
}, policy: { allowLegacySealAbi: boolean; policyPackageId: string }): string | null {
    const { packageId, policyPackageId, accountId, registryId, sealAbi } = body;
    if (!packageId || !accountId) return "Missing required fields: packageId, accountId";
    if (typeof packageId !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(packageId)) {
        return "Invalid packageId format";
    }
    if (typeof accountId !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(accountId)) {
        return "Invalid accountId format";
    }
    if (
        policyPackageId !== undefined
        && (typeof policyPackageId !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(policyPackageId))
    ) {
        return "Invalid policyPackageId format";
    }
    if (sealAbi === "v1") {
        if (!policy.allowLegacySealAbi) return "sealAbi=v1 is disabled on this sidecar";
        if (registryId) return "registryId is not valid when sealAbi=v1 (2-arg seal_approve)";
        if (
            policyPackageId !== undefined
            && normalizeSuiAddress(policyPackageId) !== normalizeSuiAddress(packageId)
        ) {
            return "policyPackageId must equal packageId when sealAbi=v1";
        }
        return null;
    }
    if (sealAbi === "v1-new") {
        if (!registryId) return "Missing registryId (required when sealAbi=v1-new)";
        if (typeof registryId !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(registryId)) {
            return "Invalid registryId format";
        }
        if (!/^0x[0-9a-fA-F]{1,64}$/.test(policy.policyPackageId)) {
            return "Sidecar SEAL policy package is not configured";
        }
        const requestedPolicy = policyPackageId || packageId;
        if (normalizeSuiAddress(requestedPolicy) !== normalizeSuiAddress(policy.policyPackageId)) {
            return "policyPackageId does not match the configured SEAL policy package";
        }
        return null;
    }
    return 'Missing or invalid sealAbi: expected "v1" or "v1-new"';
}

/**
 * Select the package that executes `seal_approve`. `packageId` remains the
 * immutable SEAL ciphertext namespace; upgraded deployments send the current
 * published package separately. Falling back keeps legacy migrator requests
 * compatible with unupgraded packages.
 */
export function sealApprovePackageId(
    body: { packageId?: string; sealAbi?: SealAbi },
    configuredPolicyPackageId: string,
): string | undefined {
    return body.sealAbi === "v1" ? body.packageId : configuredPolicyPackageId;
}

/** Bind the request, ciphertext, and SessionKey to one immutable SEAL namespace. */
export function sealIdentityPackageError(
    packageId: string,
    ciphertextPackageIds: string[],
    sessionPackageId: string,
): string | null {
    const expected = normalizeSuiAddress(packageId);
    if (normalizeSuiAddress(sessionPackageId) !== expected) {
        return "SessionKey packageId does not match request packageId";
    }
    if (ciphertextPackageIds.some(id => normalizeSuiAddress(id) !== expected)) {
        return "Ciphertext packageId does not match request packageId";
    }
    return null;
}

function sharedOrUnresolvedObjectArg(
    tx: Transaction,
    objectId: string,
    initialSharedVersion?: string | number,
): TransactionArgument {
    if (initialSharedVersion !== undefined && /^\d+$/.test(String(initialSharedVersion))) {
        // Both `&AccountRegistry` and `&MemWalAccount` in `account::seal_approve`
        // are immutable shared-object references (`mutable: false`). Supplying
        // their immutable `initialSharedVersion` avoids a live Sui
        // `SimulateTransaction` round-trip inside `tx.build()`.
        return tx.object(
            Inputs.SharedObjectRef({
                objectId,
                initialSharedVersion: String(initialSharedVersion),
                mutable: false,
            }),
        );
    }
    return tx.object(objectId);
}

/**
 * Build the `seal_approve` policy PTB — one moveCall per SEAL key id.
 *
 * Pass `registryId` for the current/destination package (3-arg ABI), omit it
 * for the legacy/source package (2-arg ABI). Handing the old package a registry
 * argument would not build against its 2-arg entry, and the old source package
 * has no registry to pass. Callers validate the sealAbi/registryId pairing up
 * front with `sealApproveArgsError`.
 *
 * Kept in its own side-effect-free module (no clients/express) so it can be
 * unit-tested directly. With a registry it pins the on-chain argument order:
 * `registry` drives the version gate and `account` drives the owner/delegate
 * access check. Both are `tx.object` args, so a swap still builds locally and
 * only reverts on-chain — see the test that pins this order.
 */
export function buildSealApproveTx(
    policyPackageId: string,
    registryId: string | undefined,
    accountId: string,
    ids: string[],
    sharedVersions?: SealApproveSharedVersions,
): Transaction {
    const tx = new Transaction();
    for (const id of ids) {
        // Convert hex ID to byte array for PTB
        const idBytes = Array.from(
            Uint8Array.from(id.match(/.{1,2}/g)!.map((b: string) => parseInt(b, 16))),
        );
        const idArg = tx.pure("vector<u8>", idBytes);
        let approveArgs: TransactionArgument[];
        if (registryId) {
            // Current/destination package: [id, registry, account].
            approveArgs = [
                idArg,
                sharedOrUnresolvedObjectArg(tx, registryId, sharedVersions?.registryInitialSharedVersion),
                sharedOrUnresolvedObjectArg(tx, accountId, sharedVersions?.accountInitialSharedVersion),
            ];
        } else {
            // Legacy/source package: [id, account].
            approveArgs = [
                idArg,
                sharedOrUnresolvedObjectArg(tx, accountId, sharedVersions?.accountInitialSharedVersion),
            ];
        }
        tx.moveCall({
            target: `${policyPackageId}::account::seal_approve`,
            arguments: approveArgs,
        });
    }
    return tx;
}

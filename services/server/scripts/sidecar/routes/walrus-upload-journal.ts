/**
 * One durable Walrus SDK boundary per request. Registration first returns an
 * exact signed transaction for the Rust writer to checkpoint; later requests
 * advance and return one checkpointable WriteBlobStep.
 */

import { createHash } from "node:crypto";
import express, { type Express } from "express";
import type {
    WriteBlobStep,
    WriteBlobStepCertified,
    WriteBlobStepEncoded,
    WriteBlobStepRegistered,
    WriteBlobStepUploaded,
} from "@mysten/walrus";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { TransactionDataBuilder, type Transaction } from "@mysten/sui/transactions";
import { normalizeStructTag, normalizeSuiAddress } from "@mysten/sui/utils";
import { verifyTransactionSignature } from "@mysten/sui/verify";
import {
    DEFAULT_WALRUS_EPOCHS,
    DURABLE_ENOKI_REGISTER_ENABLED,
    DURABLE_UPLOAD_PROTOCOL_VERSION,
    ENOKI_API_KEY,
    ENOKI_NETWORK,
    JSON_LIMIT_WALRUS_UPLOAD,
    MAX_WALRUS_EPOCHS,
    SERVER_SUI_PRIVATE_KEYS,
    SUI_CHAIN_IDENTIFIER,
    SUI_NETWORK,
    SUI_TYPE,
    WALRUS_PACKAGE_ID,
    parseDurableWalrusEpochs,
} from "../config.js";
import {
    getUploadRelayTipAddress,
    getWalrusClient,
    refreshWalrusClientIfStale,
    suiClient,
} from "../clients.js";
import {
    acquireWalrusUploadSlots,
    WalrusUploadCancelledError,
    type UploadSlotRelease,
} from "../concurrency.js";
import { requestIdFor, sanitizeRequestId, sidecarLog } from "../log.js";
import {
    classifyDurableSideEffectError,
    DurableSideEffectVerifyError,
    NoSideEffectError,
    withRpcRetry,
} from "../retry/rpc.js";
import { MEMWAL_JOB_TAG_KEY, delayInjectedResponseOnce, errorMessage, parseWalrusKeySlot } from "../util.js";
import {
    DURABLE_WALLET_FALLBACK_POLICY,
    assertFinalizedTransactionSuccess,
    submitRebuildableWalletTransaction,
    trackWalletSubmission,
} from "../wallet.js";
import {
    blobObjectMatchesRegistration,
    chainBlobIdFromRaw,
    isWalrusBlobObjectType,
    readBlobObject,
} from "./walrus-query.js";
import { uploadWalrusBlobWithEffectsRetry } from "./walrus-upload.js";
import { enforceAddressBalanceCoinIntents } from "../address-balance.js";
import {
    callEnoki,
    refreshWalrusClientOnStaleWalPrice,
    type EnokiExecuteResponse,
    type EnokiSponsorResponse,
} from "../enoki.js";
import { isSponsoredTransactionInvalidatedMessage } from "../../enoki-retry.js";
import { isEnokiSponsoredTransactionExpired } from "../../walrus-error-detection.js";
import {
    assertUploadExecutionIdentity,
    executionIdentity,
    parseUploadExecutionIdentity,
} from "./health.js";

function parseResumeStep(raw: unknown): WriteBlobStep | null {
    if (raw === null || raw === undefined) return null;
    if (!raw || typeof raw !== "object") throw new Error("resumeStep must be an object");
    const step = (raw as any).step;
    if (!["encoded", "registered", "uploaded", "certified"].includes(step)) {
        throw new Error(`Invalid resumeStep.step: ${String(step)}`);
    }
    if (typeof (raw as any).blobId !== "string" || !(raw as any).blobId) {
        throw new Error("resumeStep.blobId is required");
    }
    if (step === "encoded") {
        if (typeof (raw as any).rootHash !== "string"
            || !Number.isSafeInteger((raw as any).unencodedSize)
            || (raw as any).unencodedSize < 0) {
            throw new Error("encoded resumeStep requires rootHash and unencodedSize");
        }
    } else {
        if (typeof (raw as any).blobObjectId !== "string" || !(raw as any).blobObjectId) {
            throw new Error(`${step} resumeStep requires blobObjectId`);
        }
        if (step === "registered" && (typeof (raw as any).txDigest !== "string" || !(raw as any).txDigest)) {
            throw new Error("registered resumeStep requires txDigest");
        }
        if (step === "uploaded" && (typeof (raw as any).certificate !== "string" || !(raw as any).certificate)) {
            throw new Error("uploaded resumeStep requires certificate");
        }
    }
    return raw as WriteBlobStep;
}

export async function readUploadBlobObject(
    blobObjectId: string,
    include: { json?: true; previousTransaction?: true },
    client: Pick<typeof suiClient, "getObject"> = suiClient,
) {
    return withRpcRetry(
        `[walrus/upload-step-v3] getObject ${blobObjectId}`,
        () => readBlobObject(blobObjectId, include, client),
        // Five capped sleeps keep replica lag in this flow for about 30 seconds.
        6,
    );
}

export async function certifiedStep(
    blobId: string,
    blobObjectId: string,
    client: Pick<typeof suiClient, "getObject"> = suiClient,
): Promise<WriteBlobStepCertified | null> {
    const response = await readUploadBlobObject(blobObjectId, { json: true }, client);
    const json = response.object.json as any;
    if (!json) throw new DurableSideEffectVerifyError(`Blob ${blobObjectId} has no JSON fields`);
    const chainBlobId = chainBlobIdFromRaw(json.blob_id ?? json.blobId);
    if (chainBlobId !== blobId) {
        throw new DurableSideEffectVerifyError(
            `Blob ${blobObjectId} id mismatch: expected ${blobId}, got ${chainBlobId}`,
        );
    }
    const certifiedEpoch = json.certified_epoch ?? json.certifiedEpoch ?? null;
    if (certifiedEpoch === null) return null;
    const blobObject = { ...json, id: blobObjectId, certified_epoch: certifiedEpoch };
    return { step: "certified", blobId, blobObjectId, blobObject };
}

export async function waitForCertifiedStep(
    blobId: string,
    blobObjectId: string,
    maxAttempts = 8,
    initialDelayMs = 500,
    client: Pick<typeof suiClient, "getObject"> = suiClient,
): Promise<WriteBlobStepCertified | null> {
    let delay = initialDelayMs;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        const certified = await certifiedStep(blobId, blobObjectId, client);
        if (certified) return certified;
        if (attempt < maxAttempts - 1) {
            await new Promise((resolve) => setTimeout(resolve, delay));
            delay = Math.min(Math.round(delay * 1.5), 3000);
        }
    }
    return null;
}

export function durableRegisterDirectSigningAllowed(
    enokiConfigured: boolean,
    durableSponsorshipEnabled: boolean,
): boolean {
    // The explicit rollout gate keeps newly deployed replicas journal-compatible
    // with pre-sponsorship replicas. Once enabled, an Enoki-configured service
    // fails closed instead of silently draining the upload wallet on outage.
    return !durableSponsorshipEnabled || !enokiConfigured;
}

export function createdBlobObjectIdFromTransaction(result: any): string {
    const transaction = assertFinalizedTransactionSuccess(result, "registration transaction");
    const blobType = `${WALRUS_PACKAGE_ID}::blob::Blob`;
    const objectTypes = transaction.objectTypes ?? {};
    const matches = (transaction.effects?.changedObjects ?? [])
        .filter((object: any) => object?.idOperation === "Created")
        .map((object: any) => object.objectId)
        .filter((objectId: unknown): objectId is string => (
            typeof objectId === "string"
            && isWalrusBlobObjectType(objectTypes[objectId], blobType)
        ));
    if (matches.length !== 1) {
        throw new Error(`registration transaction created ${matches.length} Walrus Blob objects`);
    }
    return matches[0];
}

async function validateRegisteredBlob(
    blobObjectId: string,
    encoded: WriteBlobStepEncoded,
): Promise<void> {
    const response = await readUploadBlobObject(blobObjectId, { json: true });
    const json = response.object.json as any;
    if (!json
        || chainBlobIdFromRaw(json.blob_id ?? json.blobId) !== encoded.blobId
        || !blobObjectMatchesRegistration({
            rawSize: json.size ?? null,
            deletable: typeof json.deletable === "boolean" ? json.deletable : null,
        }, encoded.unencodedSize)) {
        throw new DurableSideEffectVerifyError(
            `registered Blob ${blobObjectId} does not match the encoded upload intent`,
        );
    }
}

function registeredStep(
    encoded: WriteBlobStepEncoded,
    blobObjectId: string,
    txDigest: string,
): WriteBlobStepRegistered {
    return {
        step: "registered",
        blobId: encoded.blobId,
        blobObjectId,
        txDigest,
        ...(encoded.nonce ? { nonce: encoded.nonce } : {}),
    };
}

export type PreparedRegisterTransaction = {
    transactionBytes: string;
    signature: string;
    digest: string;
    /** Enoki's sponsorship handle. Absent on legacy/direct-signed journals. */
    sponsorDigest?: string;
};

export type ValidatedPreparedRegisterTransaction = PreparedRegisterTransaction & {
    bytes: Uint8Array;
    maxEpoch?: bigint;
};

type PreparedRegisterClient = {
    getTransaction(options: {
        digest: string;
        include: { effects: true; objectTypes: true };
    }): Promise<unknown>;
    executeTransaction(options: {
        transaction: Uint8Array;
        signatures: string[];
        include: { effects: true; objectTypes: true };
    }): Promise<unknown>;
};

type PreparedRegisterSponsorExecutor = (
    sponsorDigest: string,
    signature: string,
) => Promise<EnokiExecuteResponse>;

async function executePreparedRegisterWithEnoki(
    sponsorDigest: string,
    signature: string,
): Promise<EnokiExecuteResponse> {
    return callEnoki<EnokiExecuteResponse>(
        `/transaction-blocks/sponsor/${encodeURIComponent(sponsorDigest)}`,
        { digest: sponsorDigest, signature },
    );
}

function parsePreparedRegisterTransaction(raw: unknown): PreparedRegisterTransaction | null {
    if (raw === null || raw === undefined) return null;
    if (!raw || typeof raw !== "object") {
        throw new Error("registerTransaction must be an object");
    }
    const { transactionBytes, signature, digest, sponsorDigest } = raw as Record<string, unknown>;
    if (typeof transactionBytes !== "string" || !transactionBytes
        || typeof signature !== "string" || !signature
        || typeof digest !== "string" || !digest) {
        throw new Error("registerTransaction requires transactionBytes, signature, and digest");
    }
    if (sponsorDigest !== undefined && (typeof sponsorDigest !== "string" || !sponsorDigest)) {
        throw new Error("registerTransaction.sponsorDigest must be a non-empty string");
    }
    return {
        transactionBytes,
        signature,
        digest,
        ...(typeof sponsorDigest === "string" ? { sponsorDigest } : {}),
    };
}

/**
 * The expiration a direct-signed register needs: one epoch of address-balance
 * withdrawal.
 *
 * Paying gas from the address balance puts a `FundsWithdrawal` input in the
 * transaction, and Sui admits that withdrawal only inside a `ValidDuring`
 * window — the same rule `assertAddressBalanceRegisterTransaction` re-checks
 * one line later. Neither `flow.register()` nor `Transaction.build()` sets one,
 * so every direct-signed register failed its own assertion with
 * "registerTransaction must use a ValidDuring address-balance expiration" and
 * no blob was ever certified on this path.
 *
 * One epoch wide rather than a range: `validatePreparedRegisterTransaction`
 * hands `maxEpoch` back as the journal's expiry guard, so a window outliving
 * the reservation would keep replaying an entry Sui has already retired.
 *
 * The nonce is a hash of the transaction kind, not a random draw, so the
 * first prepare of a register repeats byte-identical and a replay does not
 * pay for a second blob. A rebuild passes the cancelled digest as `rebuild`:
 * the same kind alone would sign that cancelled transaction again. Gas price
 * is not an input here; within an epoch it does not change the bytes.
 */
export function addressBalanceExpiration(
    epoch: bigint,
    transactionKind: Uint8Array,
    rebuild = "",
) {
    const hash = createHash("sha256").update(transactionKind);
    if (rebuild) hash.update(rebuild);
    const bounded = String(epoch);
    return {
        ValidDuring: {
            minEpoch: bounded,
            maxEpoch: bounded,
            minTimestamp: null,
            maxTimestamp: null,
            chain: SUI_CHAIN_IDENTIFIER,
            nonce: hash.digest().readUInt32BE(0),
        },
    } as const;
}

async function bindAddressBalanceExpiration(
    transaction: Transaction,
    rebuild = "",
): Promise<void> {
    const transactionKind = await transaction.build({
        client: suiClient as any,
        onlyTransactionKind: true,
    });
    transaction.setExpiration(
        addressBalanceExpiration(await currentSuiEpoch(), transactionKind, rebuild),
    );
}

export async function prepareRegisterTransaction(
    transaction: Transaction,
    signer: Ed25519Keypair,
    allowedAddresses: string[] = [signer.toSuiAddress()],
    rebuild = "",
): Promise<PreparedRegisterTransaction> {
    const signerAddress = signer.toSuiAddress();
    transaction.setSenderIfNotSet(signerAddress);

    if (ENOKI_API_KEY && DURABLE_ENOKI_REGISTER_ENABLED) {
        // Journal the exact sponsored bytes before execution. Replays use the
        // Enoki sponsorship handle below, so the upload remains idempotent
        // without making the sender wallet the gas owner.
        const transactionKind = await transaction.build({
            client: suiClient as any,
            onlyTransactionKind: true,
        });
        const sponsored = await callEnoki<EnokiSponsorResponse>(
            "/transaction-blocks/sponsor",
            {
                network: ENOKI_NETWORK,
                transactionBlockKindBytes: Buffer.from(transactionKind).toString("base64"),
                sender: signerAddress,
                ...(allowedAddresses.length ? { allowedAddresses } : {}),
            },
        );
        const bytes = new Uint8Array(Buffer.from(sponsored.bytes, "base64"));
        if (!bytes.length || Buffer.from(bytes).toString("base64") !== sponsored.bytes) {
            throw new Error("Enoki returned non-canonical sponsored transaction bytes");
        }
        const transactionData = TransactionDataBuilder.fromBytes(bytes);
        assertSponsoredRegisterTransaction(transactionData, signerAddress);
        assertSponsoredRegisterTransactionKind(transactionData, transactionKind);
        const digest = TransactionDataBuilder.getDigestFromBytes(bytes);
        const signed = await signer.signTransaction(bytes);
        return {
            transactionBytes: signed.bytes,
            signature: signed.signature,
            digest,
            sponsorDigest: sponsored.digest,
        };
    }

    // Fail-closed sponsorship already returned above. Remaining path is the
    // explicit phase-1 / unconfigured-Enoki direct sign.
    transaction.setGasPayment([]);
    await bindAddressBalanceExpiration(transaction, rebuild);
    const bytes = await transaction.build({ client: suiClient });
    assertAddressBalanceRegisterTransaction(TransactionDataBuilder.fromBytes(bytes));
    const signed = await signer.signTransaction(bytes);
    return {
        transactionBytes: signed.bytes,
        signature: signed.signature,
        digest: TransactionDataBuilder.getDigestFromBytes(bytes),
    };
}

function assertRegisterTransactionUsesAddressBalanceWal(
    transactionData: TransactionDataBuilder,
): void {
    let usesGasCoin = false;
    transactionData.mapArguments((argument) => {
        if (argument.$kind === "GasCoin") usesGasCoin = true;
        return argument;
    });
    if (usesGasCoin) {
        throw new Error("registerTransaction resolved the relay tip from an owned SUI coin");
    }

    const ownedInputs = transactionData.inputs.filter(
        (input) => input.Object?.ImmOrOwnedObject,
    );
    if (ownedInputs.length > 0) {
        throw new Error("registerTransaction resolved WAL from an owned coin");
    }
    const suiType = normalizeStructTag(SUI_TYPE);
    const hasWalWithdrawal = transactionData.inputs.some(
        (input) => input.$kind === "FundsWithdrawal"
            && normalizeStructTag(input.FundsWithdrawal.typeArg.Balance) !== suiType,
    );
    if (!hasWalWithdrawal) {
        throw new Error("registerTransaction has no WAL address-balance withdrawal");
    }
}

export function assertSponsoredRegisterTransactionKind(
    transactionData: TransactionDataBuilder,
    expectedKindBytes: Uint8Array,
): void {
    const returnedKindBytes = transactionData.build({ onlyTransactionKind: true });
    if (!Buffer.from(returnedKindBytes).equals(Buffer.from(expectedKindBytes))) {
        throw new Error("Enoki returned a sponsored transaction whose kind differs from the requested transaction");
    }
}

export function assertSponsoredRegisterTransaction(
    transactionData: TransactionDataBuilder,
    expectedWalletAddress: string,
): void {
    const walletAddress = normalizeSuiAddress(expectedWalletAddress);
    if (!transactionData.sender
        || normalizeSuiAddress(transactionData.sender) !== walletAddress) {
        throw new Error("sponsored registerTransaction sender does not match the wallet");
    }
    if (!transactionData.gasData.owner
        || normalizeSuiAddress(transactionData.gasData.owner) === walletAddress) {
        throw new Error("sponsored registerTransaction must use a distinct gas owner");
    }
    // Enoki-sponsored journals do not carry a ValidDuring maxEpoch. They are
    // intentionally unbounded and rebuild only via the expired-sponsorship
    // path below, not the epoch-expiry guard used by direct-signed journals.
    assertRegisterTransactionUsesAddressBalanceWal(transactionData);
}

/** Render a bound the way the guard tests it, so `null` and `undefined` — which
 * the guard treats differently but a template string renders identically — stay
 * distinguishable in a log line. */
function describeExpirationBound(value: unknown): string {
    if (value === null) return "null";
    if (value === undefined) return "undefined";
    return JSON.stringify(value);
}

/** Describe an expiration precisely enough to act on it from a production log.
 *
 * The guard below rejects on three separate conditions joined by `||`, so the
 * bare sentence it used to throw could not say which one fired. A run of these
 * failures on testnet (every upload job, both deployments, 2026-09-17) could not
 * be diagnosed from the relayer logs at all: the classifier reported the string,
 * and the string named the invariant rather than the value that broke it. */
function describeExpiration(expiration: TransactionDataBuilder["expiration"]): string {
    if (!expiration) return "expiration=none";
    if (expiration.$kind !== "ValidDuring") return `expiration=${expiration.$kind}`;
    const { minEpoch, maxEpoch, minTimestamp, maxTimestamp } = expiration.ValidDuring;
    return "expiration=ValidDuring"
        + ` minEpoch=${describeExpirationBound(minEpoch)}`
        + ` maxEpoch=${describeExpirationBound(maxEpoch)}`
        + ` minTimestamp=${describeExpirationBound(minTimestamp)}`
        + ` maxTimestamp=${describeExpirationBound(maxTimestamp)}`;
}

export function assertAddressBalanceRegisterTransaction(
    transactionData: TransactionDataBuilder,
): bigint {
    if (transactionData.gasData.payment?.length !== 0) {
        throw new Error(
            "registerTransaction must pay gas from the address balance"
            + ` (gasData.payment.length=${String(transactionData.gasData.payment?.length ?? "undefined")})`,
        );
    }

    const expiration = transactionData.expiration;
    if (
        expiration?.$kind !== "ValidDuring"
        || expiration.ValidDuring.minTimestamp !== null
        || expiration.ValidDuring.maxTimestamp !== null
    ) {
        throw new Error(
            "registerTransaction must use a ValidDuring address-balance expiration"
            + ` (${describeExpiration(expiration)})`,
        );
    }

    assertRegisterTransactionUsesAddressBalanceWal(transactionData);
    return BigInt(expiration.ValidDuring.maxEpoch);
}

export async function validatePreparedRegisterTransaction(
    prepared: PreparedRegisterTransaction,
    expectedWalletAddress: string,
): Promise<ValidatedPreparedRegisterTransaction> {
    const bytes = new Uint8Array(Buffer.from(prepared.transactionBytes, "base64"));
    if (!bytes.length || Buffer.from(bytes).toString("base64") !== prepared.transactionBytes) {
        throw new Error("registerTransaction.transactionBytes is not canonical base64");
    }
    const digest = TransactionDataBuilder.getDigestFromBytes(bytes);
    if (digest !== prepared.digest) {
        throw new Error(`registerTransaction digest mismatch: expected ${prepared.digest}, got ${digest}`);
    }

    let transactionData: TransactionDataBuilder;
    try {
        transactionData = TransactionDataBuilder.fromBytes(bytes);
    } catch (error: unknown) {
        throw new Error(`registerTransaction contains invalid TransactionData: ${errorMessage(error)}`);
    }
    const walletAddress = normalizeSuiAddress(expectedWalletAddress);
    if (!transactionData.sender
        || normalizeSuiAddress(transactionData.sender) !== walletAddress) {
        throw new Error("registerTransaction sender does not match the journaled wallet");
    }
    if (prepared.sponsorDigest) {
        assertSponsoredRegisterTransaction(transactionData, walletAddress);
    } else if (!transactionData.gasData.owner
        || normalizeSuiAddress(transactionData.gasData.owner) !== walletAddress) {
        throw new Error("registerTransaction gas owner does not match the journaled wallet");
    }
    // Protocol-v3 journals created before address-balance enforcement may mix
    // address-balance gas with owned WAL coins. Preserve their exact bytes;
    // every newly prepared transaction is checked above before journaling.
    const maxEpoch = transactionData.expiration?.$kind === "ValidDuring"
        ? BigInt(transactionData.expiration.ValidDuring.maxEpoch)
        : undefined;
    await verifyTransactionSignature(bytes, prepared.signature, { address: walletAddress });
    return { ...prepared, bytes, maxEpoch };
}

let currentEpochCache: { epoch: bigint; loadedAtMs: number } | undefined;
async function currentSuiEpoch(): Promise<bigint> {
    if (currentEpochCache && Date.now() - currentEpochCache.loadedAtMs < 5_000) {
        return currentEpochCache.epoch;
    }
    const { systemState } = await suiClient.core.getCurrentSystemState();
    const epoch = BigInt(systemState.epoch);
    currentEpochCache = { epoch, loadedAtMs: Date.now() };
    return epoch;
}

async function lookupPreparedRegisterTransaction(
    client: PreparedRegisterClient,
    digest: string,
    include: { effects: true; objectTypes: true },
    assertExpectedDigest: (result: unknown) => unknown,
    attempts: number,
): Promise<unknown | undefined> {
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
        try {
            return assertExpectedDigest(
                await client.getTransaction({ digest, include }),
            );
        } catch (error: any) {
            if (error?.code !== "NOT_FOUND") throw error;
            if (attempt < attempts) {
                await new Promise((resolve) => setTimeout(resolve, attempt * 250));
            }
        }
    }
    return undefined;
}

export async function executePreparedRegisterTransaction(
    prepared: ValidatedPreparedRegisterTransaction,
    client: PreparedRegisterClient = suiClient,
    onTransactionObservedOrSubmitted: () => void = () => {},
    getCurrentEpoch: () => Promise<bigint> = currentSuiEpoch,
    mayHaveBeenSubmitted = false,
    executeSponsored: PreparedRegisterSponsorExecutor = executePreparedRegisterWithEnoki,
    indexAttempts = 8,
): Promise<unknown> {
    const include = { effects: true, objectTypes: true } as const;
    const assertExpectedDigest = (result: any): unknown => {
        const digest = result?.Transaction?.digest ?? result?.FailedTransaction?.digest;
        if (digest !== prepared.digest) {
            throw new Error(`register transaction response digest mismatch: expected ${prepared.digest}, got ${String(digest)}`);
        }
        return result;
    };
    let existing: unknown;
    try {
        existing = await client.getTransaction({ digest: prepared.digest, include });
    } catch (error: any) {
        if (error?.code !== "NOT_FOUND") throw error;
    }
    if (existing !== undefined) {
        onTransactionObservedOrSubmitted();
        return assertExpectedDigest(existing);
    }
    const maxEpoch = prepared.maxEpoch;
    if (maxEpoch !== undefined && await getCurrentEpoch() > maxEpoch) {
        if (mayHaveBeenSubmitted) {
            throw Object.assign(
                new Error(
                    `prepared register transaction ${prepared.digest} expired at epoch ${maxEpoch} but remains ambiguous`,
                ),
                { code: "UNAVAILABLE" },
            );
        }
        throw new NoSideEffectError(
            `prepared register transaction ${prepared.digest} expired at epoch ${maxEpoch} and is not on chain`,
        );
    }
    // TransactionData bytes determine the Sui digest. Re-executing this exact
    // signed payload can only submit the already-journaled digest.
    onTransactionObservedOrSubmitted();
    if (prepared.sponsorDigest) {
        let executed: EnokiExecuteResponse;
        try {
            executed = await trackWalletSubmission(() =>
                executeSponsored(prepared.sponsorDigest!, prepared.signature),
            );
        } catch (error: unknown) {
            const message = errorMessage(error);
            const expired = isEnokiSponsoredTransactionExpired(message);
            const invalidated = isSponsoredTransactionInvalidatedMessage(message);
            // Both `expired` and `not_found` mean Enoki no longer holds this
            // sponsorship. An unused handle expires as 404 not_found; replaying
            // it can never land. A handle that was consumed and did land is
            // returned by the digest lookup below. Only a reconcile attempt,
            // which may already have submitted these bytes, stays ambiguous.
            if (!invalidated) throw error;

            const finalized = await lookupPreparedRegisterTransaction(
                client,
                prepared.digest,
                include,
                assertExpectedDigest,
                indexAttempts,
            );
            if (finalized !== undefined) return finalized;
            if (mayHaveBeenSubmitted) {
                throw Object.assign(
                    new Error(
                        `sponsored register transaction ${prepared.digest} was invalidated but remains ambiguous`,
                    ),
                    { code: "UNAVAILABLE" },
                );
            }
            throw new NoSideEffectError(
                expired
                    ? `sponsored register transaction ${prepared.digest} expired and is not on chain; rebuild sponsorship`
                    : `sponsored register transaction ${prepared.digest} sponsorship was not found and is not on chain; rebuild sponsorship`,
            );
        }
        if (executed.digest !== prepared.digest) {
            throw new Error(
                `Enoki executed unexpected register digest: expected ${prepared.digest}, got ${executed.digest}`,
            );
        }
        // Enoki returns only a digest. Read the finalized transaction so the
        // caller can validate the created Walrus Blob object exactly as it did
        // for the legacy direct-execution path.
        const finalized = await lookupPreparedRegisterTransaction(
            client,
            prepared.digest,
            include,
            assertExpectedDigest,
            indexAttempts,
        );
        if (finalized !== undefined) return finalized;
        throw new Error(`sponsored register transaction ${prepared.digest} was not found after execution`);
    }

    const result = await trackWalletSubmission(() =>
        client.executeTransaction({
            transaction: prepared.bytes,
            signatures: [prepared.signature],
            include,
        }),
    );
    return assertExpectedDigest(result);
}

const UPLOAD_STEP_FLIGHT_TTL_MS = 60_000;

export type UploadStepFlightResult = { status: number; body: unknown };

type UploadStepFlight = {
    promise: Promise<UploadStepFlightResult>;
    resolve: (result: UploadStepFlightResult) => void;
    settled: boolean;
    result?: UploadStepFlightResult;
};

const uploadStepFlights = new Map<string, UploadStepFlight>();

type RejectedRegisterPreparation = { key: string; digest: string; sponsorDigest?: string };

/** Same job and same checkpoint share one sidecar step. A dropped client retries this key instead of starting a second upload. */
export function uploadStepFlightKey(
    jobId: string,
    resumeStep: string | undefined,
    blobId: string | undefined,
    preparedDigest: string | undefined,
    sponsorDigest?: string,
): string {
    return [jobId, resumeStep ?? "start", blobId ?? "", preparedDigest ?? "", sponsorDigest ?? ""].join("|");
}

export function beginOrJoinUploadStepFlight(key: string): { leader: boolean; flight: UploadStepFlight } {
    const existing = uploadStepFlights.get(key);
    if (existing) return { leader: false, flight: existing };
    let resolve!: (result: UploadStepFlightResult) => void;
    const promise = new Promise<UploadStepFlightResult>((done) => {
        resolve = done;
    });
    const flight: UploadStepFlight = { promise, resolve, settled: false };
    uploadStepFlights.set(key, flight);
    return { leader: true, flight };
}

export function settleUploadStepFlight(
    key: string,
    flight: UploadStepFlight,
    result: UploadStepFlightResult,
    rejectedPreparation?: RejectedRegisterPreparation,
): void {
    if (flight.settled) return;
    flight.settled = true;
    flight.result = result;
    flight.resolve(result);
    const code = (result.body as { code?: unknown } | null)?.code;
    if (rejectedPreparation && result.status >= 400
        && (code === "NO_SIDE_EFFECT"
            || code === "INVALID_PREPARED_REGISTER_TRANSACTION"
            || code === "CONGESTION_CANCELLED_TRANSACTION")) {
        // Rust clears the rejected transaction and asks to prepare again. A
        // cached prepare would otherwise hand it the same unusable sponsorship
        // for another minute. Evict only that exact prepared digest; completed
        // side effects and ambiguous submissions must remain replayable.
        const prepared = uploadStepFlights.get(rejectedPreparation.key);
        const preparedBody = prepared?.result?.body as { registerTransaction?: { digest?: string; sponsorDigest?: string } } | undefined;
        if (preparedBody?.registerTransaction?.digest === rejectedPreparation.digest
            && preparedBody.registerTransaction.sponsorDigest === rejectedPreparation.sponsorDigest) {
            uploadStepFlights.delete(rejectedPreparation.key);
        }
        if (uploadStepFlights.get(key) === flight) uploadStepFlights.delete(key);
        return;
    }
    // Keep a success long enough for the relayer to reconnect and persist it.
    // Drop an error quickly so the same journal can try the step again.
    const ttl = result.status >= 400 ? 2_000 : UPLOAD_STEP_FLIGHT_TTL_MS;
    const drop = setTimeout(() => {
        if (uploadStepFlights.get(key) === flight) uploadStepFlights.delete(key);
    }, ttl);
    drop.unref?.();
}

export function resetUploadStepFlightsForTests(): void {
    uploadStepFlights.clear();
}

export function registerWalrusUploadJournalRoute(app: Express): void {
    app.post(
        "/walrus/upload-step-v3",
        express.json({ limit: JSON_LIMIT_WALRUS_UPLOAD }),
        async (req, res) => {
            const traceId = requestIdFor(req);
            const phaseStartedAt = Date.now();
            // `close` also fires after a normal end(). `writableEnded` is set
            // by res.json, so this aborts only when the client leaves first.
            const clientDisconnect = new AbortController();
            const abortIfDropped = () => {
                if (!res.writableEnded) clientDisconnect.abort();
            };
            res.on("close", abortIfDropped);
            let phase = "request";
            let releaseWalrusUploadSlots: UploadSlotRelease | undefined;
            let keepJobSlot = false;
            let phaseCanSubmitSideEffect = false;
            let submissionStarted = false;
            let encodeMs: number | undefined;
            let flightKey: string | undefined;
            let flight: UploadStepFlight | undefined;
            let rejectedPreparation: RejectedRegisterPreparation | undefined;
            const settleFlight = (status: number, body: unknown) => {
                if (!flightKey || !flight) return;
                settleUploadStepFlight(flightKey, flight, { status, body }, rejectedPreparation);
            };
            const deliver = (body: unknown, keep: boolean) => {
                settleFlight(200, body);
                if (keep) keepJobSlot = true;
                if (clientDisconnect.signal.aborted || res.writableEnded || res.destroyed) return;
                res.json(body);
            };
            const reply = (status: number, body: unknown) => {
                settleFlight(status, body);
                if (clientDisconnect.signal.aborted || res.writableEnded || res.destroyed) return;
                res.status(status).json(body);
            };
            try {
                const {
                    data,
                    keyIndex,
                    jobId: rawJobId,
                    walletAddress: rawWalletAddress,
                    owner,
                    namespace,
                    packageId,
                    uploadExecutionIdentity: rawExecutionIdentity,
                    uploadProtocolVersion,
                    epochs: rawEpochs = DEFAULT_WALRUS_EPOCHS,
                    reconcileOnly = false,
                    registerTransaction: rawRegisterTransaction,
                    resumeStep: rawResumeStep,
                } = req.body;
                const jobId = sanitizeRequestId(rawJobId);
                if (!data || keyIndex === undefined || !jobId) {
                    return res.status(400).json({ error: "Missing required fields: data, keyIndex, jobId" });
                }
                if (owner && !/^0x[0-9a-fA-F]{64}$/.test(owner)) {
                    return res.status(400).json({ error: "Invalid owner address format" });
                }
                const targetOwner = owner ? normalizeSuiAddress(owner) : owner;
                if (packageId && !/^0x[0-9a-fA-F]{1,64}$/.test(packageId)) {
                    return res.status(400).json({ error: "Invalid packageId format" });
                }
                const keySlot = parseWalrusKeySlot(keyIndex);
                if (keySlot === null || !SERVER_SUI_PRIVATE_KEYS[keySlot]) {
                    return res.status(400).json({ error: `Invalid keyIndex: ${keyIndex}` });
                }
                const { secretKey } = decodeSuiPrivateKey(SERVER_SUI_PRIVATE_KEYS[keySlot]);
                const signer = Ed25519Keypair.fromSecretKey(secretKey);
                const signerAddress = signer.toSuiAddress();
                const walletAddress = rawWalletAddress ?? signerAddress;
                if (!/^0x[0-9a-fA-F]{64}$/.test(walletAddress)) {
                    return res.status(400).json({ error: "Invalid walletAddress format" });
                }
                // New Rust callers can omit walletAddress on the first prepare;
                // the sidecar derives it from the pinned key slot. Subsequent
                // replay requests persist and send the derived address.
                const journaledWalletAddress = normalizeSuiAddress(walletAddress);
                const epochs = parseDurableWalrusEpochs(rawEpochs);
                if (epochs === null) {
                    return res.status(400).json({
                        error: SUI_NETWORK === "mainnet"
                            ? `Invalid epochs: mainnet requires exactly ${MAX_WALRUS_EPOCHS}, got ${String(rawEpochs)}`
                            : `Invalid epochs: expected an integer from 1 to ${MAX_WALRUS_EPOCHS}, got ${String(rawEpochs)}`,
                    });
                }

                // A malformed resumeStep is a caller bug, not an ambiguous
                // durable phase: reject it as a 400 before the durable section
                // so it never surfaces as a protocol-ambiguous 500.
                let resume: WriteBlobStep | null;
                let preparedRegisterTransaction: PreparedRegisterTransaction | null;
                // A cancelled register names its digest here. Strip it before
                // the Walrus SDK sees the checkpoint; it is only a nonce salt.
                const registerRebuild = typeof rawResumeStep?.registerRebuild === "string"
                    ? rawResumeStep.registerRebuild
                    : "";
                if (rawResumeStep && typeof rawResumeStep === "object") {
                    delete rawResumeStep.registerRebuild;
                }
                try {
                    resume = parseResumeStep(rawResumeStep);
                    preparedRegisterTransaction = parsePreparedRegisterTransaction(rawRegisterTransaction);
                } catch (resumeError: unknown) {
                    return res.status(400).json({ error: errorMessage(resumeError) });
                }
                phase = !resume
                    ? "encode"
                    : resume.step === "encoded"
                        ? preparedRegisterTransaction
                            ? "register_execute"
                            : "register_prepare"
                        : resume.step;
                if (preparedRegisterTransaction && resume?.step !== "encoded") {
                    return res.status(400).json({
                        error: "registerTransaction is valid only with an encoded resumeStep",
                    });
                }
                if (uploadProtocolVersion !== DURABLE_UPLOAD_PROTOCOL_VERSION) {
                    return res.status(409).json({
                        error: `upload protocol mismatch: expected ${DURABLE_UPLOAD_PROTOCOL_VERSION}, got ${String(uploadProtocolVersion)}`,
                        code: "UPLOAD_PROTOCOL_VERSION_MISMATCH",
                        expectedUploadProtocolVersion: DURABLE_UPLOAD_PROTOCOL_VERSION,
                        actualUploadProtocolVersion: uploadProtocolVersion ?? null,
                    });
                }
                phaseCanSubmitSideEffect = !reconcileOnly
                    && (resume?.step === "encoded" || resume?.step === "uploaded");
                const uploadExecutionIdentity = rawExecutionIdentity === undefined
                    ? null
                    : parseUploadExecutionIdentity(rawExecutionIdentity);
                if (rawExecutionIdentity !== undefined && !uploadExecutionIdentity) {
                    return res.status(400).json({ error: "Invalid uploadExecutionIdentity" });
                }
                if (uploadExecutionIdentity) await assertUploadExecutionIdentity(uploadExecutionIdentity);
                if (signerAddress !== journaledWalletAddress) {
                    return res.status(409).json({
                        error: "keyIndex no longer maps to the journaled wallet",
                        code: "WALLET_MAPPING_MISMATCH",
                        expectedWalletAddress: journaledWalletAddress,
                        actualWalletAddress: signerAddress,
                    });
                }
                const blobData = new Uint8Array(Buffer.from(data, "base64"));
                refreshWalrusClientIfStale();
                const client = getWalrusClient();
                const flow = client.writeBlobFlow({
                    blob: blobData,
                    ...(resume ? { resume } : {}),
                });
                // Encode stays after the slot acquire: its WASM step blocks the
                // process, so it has to stay inside the same concurrency limit.
                const encodeFlow = async () => {
                    if (encodeMs !== undefined) return flow.encode();
                    const started = Date.now();
                    const encoded = await flow.encode();
                    encodeMs = Date.now() - started;
                    return encoded;
                };
                flightKey = uploadStepFlightKey(
                    jobId,
                    resume?.step,
                    resume && "blobId" in resume ? resume.blobId : undefined,
                    preparedRegisterTransaction?.digest,
                    preparedRegisterTransaction?.sponsorDigest,
                );
                if (preparedRegisterTransaction && resume?.step === "encoded") {
                    rejectedPreparation = {
                        key: uploadStepFlightKey(jobId, "encoded", resume.blobId, undefined),
                        digest: preparedRegisterTransaction.digest,
                        sponsorDigest: preparedRegisterTransaction.sponsorDigest,
                    };
                }
                const joined = beginOrJoinUploadStepFlight(flightKey);
                if (!joined.leader) {
                    const outcome = await joined.flight.promise;
                    if (!res.writableEnded && !res.destroyed) {
                        res.status(outcome.status).json(outcome.body);
                    }
                    return;
                }
                flight = joined.flight;
                // Do not cancel this step when the caller disconnects. The
                // retry joins the same flight and needs the result. Cancelling
                // here is what turned one dropped connection into a new upload.
                releaseWalrusUploadSlots = await acquireWalrusUploadSlots(keySlot, traceId, jobId, {
                    holdForJob: true,
                });

                let step: WriteBlobStep;
                if (!resume) {
                    step = await encodeFlow();
                } else if (resume.step === "encoded") {
                    const encoded = await encodeFlow();
                    if (preparedRegisterTransaction) {
                        let validated: ValidatedPreparedRegisterTransaction;
                        try {
                            validated = await validatePreparedRegisterTransaction(
                                preparedRegisterTransaction,
                                journaledWalletAddress,
                            );
                        } catch (validationError: unknown) {
                            reply(409, {
                                error: errorMessage(validationError),
                                code: "INVALID_PREPARED_REGISTER_TRANSACTION",
                                jobId,
                            });
                            return;
                        }
                        phaseCanSubmitSideEffect = true;
                        // A persisted *_started marker means an earlier request
                        // may already have submitted these exact bytes. Until a
                        // digest lookup proves absence, lookup failures must
                        // preserve the prepared transaction for reconciliation.
                        if (reconcileOnly) submissionStarted = true;
                        const result = await executePreparedRegisterTransaction(
                            validated,
                            suiClient,
                            () => {
                                // A successful digest lookup proves the effect
                                // already exists; an execute call may create it.
                                submissionStarted = true;
                            },
                            currentSuiEpoch,
                            reconcileOnly,
                        );
                        const blobObjectId = createdBlobObjectIdFromTransaction(result);
                        await validateRegisteredBlob(blobObjectId, encoded);
                        step = registeredStep(encoded, blobObjectId, validated.digest);
                    } else {
                        if (reconcileOnly) {
                            reply(409, {
                                error: "register reconciliation requires the journaled signed transaction",
                                code: "MISSING_PREPARED_REGISTER_TRANSACTION",
                                jobId,
                                blobId: encoded.blobId,
                            });
                            return;
                        }
                        const registerTx = flow.register({
                            epochs,
                            owner: signerAddress,
                            deletable: true,
                            attributes: {
                                ...(namespace ? { memwal_namespace: namespace } : {}),
                                ...(targetOwner ? { memwal_owner: targetOwner } : {}),
                                ...(packageId ? { memwal_package_id: packageId } : {}),
                                [MEMWAL_JOB_TAG_KEY]: jobId,
                            },
                        });
                        enforceAddressBalanceCoinIntents(registerTx);
                        const tipRecipient = ENOKI_API_KEY && DURABLE_ENOKI_REGISTER_ENABLED
                            ? await getUploadRelayTipAddress()
                            : null;
                        const allowedAddresses = [...new Set(
                            [signerAddress, tipRecipient]
                                .filter((address): address is string => typeof address === "string"),
                        )];
                        const registerTransaction = await prepareRegisterTransaction(
                            registerTx,
                            signer,
                            allowedAddresses,
                            registerRebuild,
                        );
                        console.log(`[walrus/upload-step-v3] [${traceId}] prepared ${JSON.stringify({
                            jobId,
                            keyIndex: keySlot,
                            step: "register_prepared",
                            blobId: encoded.blobId,
                            digest: registerTransaction.digest,
                            sponsored: !!registerTransaction.sponsorDigest,
                            encodeMs,
                        })}`);
                        deliver({
                            registerTransaction,
                            resumeStep: encoded,
                            walletAddress: signerAddress,
                            uploadExecutionIdentity: await executionIdentity(),
                        }, true);
                        return;
                    }
                } else if (resume.step === "registered") {
                    const alreadyCertified = await certifiedStep(resume.blobId, resume.blobObjectId);
                    if (alreadyCertified) {
                        step = alreadyCertified;
                    } else {
                        await encodeFlow();
                        step = await uploadWalrusBlobWithEffectsRetry(flow, resume.txDigest, {
                            traceId,
                            jobId,
                            keyIndex: keySlot,
                            // getBlobObject caches a miss. Clear it or the retry
                            // reads the same Error and the job burns its attempts.
                            resetWalrusCache: () => client.reset(),
                        }, true) as WriteBlobStepUploaded;
                    }
                } else if (resume.step === "uploaded") {
                    const alreadyCertified = await certifiedStep(resume.blobId, resume.blobObjectId);
                    if (alreadyCertified) {
                        step = alreadyCertified;
                    } else if (reconcileOnly) {
                        reply(409, {
                            error: "Blob is not certified after an ambiguous certify phase",
                            code: "AMBIGUOUS_CERTIFY_NOT_FOUND",
                            jobId,
                            blobId: resume.blobId,
                            objectId: resume.blobObjectId,
                        });
                        return;
                    } else {
                        const digest = await submitRebuildableWalletTransaction(
                            "certify_sponsor",
                            () => client.certifyBlobTransaction({
                                blobId: resume.blobId,
                                blobObjectId: resume.blobObjectId,
                                certificate: resume.certificate,
                                deletable: true,
                            }),
                            signer,
                            undefined,
                            { traceId, jobId, keyIndex: keySlot },
                            DURABLE_WALLET_FALLBACK_POLICY,
                            () => {
                                submissionStarted = true;
                            },
                        );
                        const result = await suiClient.waitForTransaction({ digest });
                        assertFinalizedTransactionSuccess(
                            result,
                            `certification transaction ${digest}`,
                        );
                        const certified = await waitForCertifiedStep(resume.blobId, resume.blobObjectId);
                        if (!certified) throw new Error(`certified Blob ${resume.blobObjectId} is not certified on chain`);
                        step = certified;
                    }
                } else {
                    step = resume;
                }

                console.log(`[walrus/upload-step-v3] [${traceId}] ok ${JSON.stringify({
                    jobId,
                    keyIndex: keySlot,
                    step: step.step,
                    blobId: step.blobId,
                    reconcileOnly: !!reconcileOnly,
                    encodeMs,
                })}`);
                await delayInjectedResponseOnce(submissionStarted, jobId);
                deliver({ step }, step.step !== "certified");
                return;
            } catch (error: unknown) {
                if (error instanceof WalrusUploadCancelledError) {
                    reply(499, {
                        error: error.message,
                        code: "CLIENT_DISCONNECTED",
                        traceId,
                    });
                    return;
                }
                const message = errorMessage(error);
                // A stale-price abort can occur during sponsorship or after
                // registration lands. Refresh the client before the rejected
                // preparation is evicted by settleUploadStepFlight.
                refreshWalrusClientOnStaleWalPrice(message);
                sidecarLog("error", "walrus_upload_step_failed", {
                    requestId: traceId,
                    phase,
                    elapsedMs: Date.now() - phaseStartedAt,
                    error: message,
                    causeCode: (error as any)?.cause?.code ?? (error as any)?.code ?? null,
                    causeName: (error as any)?.cause?.name ?? null,
                });
                const durableError = classifyDurableSideEffectError(
                    error,
                    phaseCanSubmitSideEffect,
                    submissionStarted,
                );
                if (durableError) {
                    const status = durableError.code === "DURABLE_SIDE_EFFECT_VERIFY_FAILED" ? 422 : 503;
                    reply(status, {
                        error: message,
                        ...durableError,
                        traceId,
                    });
                    return;
                }
                reply(500, { error: message, traceId });
                return;
            } finally {
                sidecarLog("info", "upload_phase_timing", { requestId: traceId, jobId: sanitizeRequestId(req.body?.jobId), phase, elapsedMs: Date.now() - phaseStartedAt, encodeMs, status: res.statusCode });
                settleFlight(500, { error: "upload step ended without a result", traceId });
                res.off("close", abortIfDropped);
                // A continuable checkpoint keeps the permit for the next step.
                // Anything else — error, disconnect, certified — frees it here,
                // including when res.json never reached the client.
                if (!keepJobSlot) releaseWalrusUploadSlots?.finishJob();
                releaseWalrusUploadSlots?.();
            }
        },
    );
}

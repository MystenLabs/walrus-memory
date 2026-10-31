/**
 * Enoki sponsored-transaction API client.
 *
 * `callEnoki` wraps the raw HTTP API with transient-error retries;
 * `executeWithEnokiSponsor` is the high-level sponsor → sign → execute
 * path with optional direct-sign fallback.
 */

import { Buffer } from "buffer";
import { setTimeout as sleepWithSignal } from "node:timers/promises";
import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import type { Transaction } from "@mysten/sui/transactions";
import { getEnokiRetryDelayMs, isSponsoredTransactionInvalidatedMessage } from "../enoki-retry.js";
import {
    ENOKI_API_BASE_URL,
    ENOKI_API_KEY,
    ENOKI_FALLBACK_TO_DIRECT_SIGN,
    ENOKI_NETWORK,
    ENOKI_TRANSIENT_BASE_DELAY_MS,
    ENOKI_TRANSIENT_MAX_ATTEMPTS,
    ENOKI_TRANSIENT_MAX_DELAY_MS,
} from "./config.js";
import { refreshWalrusClient, suiClient } from "./clients.js";
import { enforceAddressBalanceCoinIntents } from "./address-balance.js";
import { errorMessage, truncateForLog } from "./util.js";

type EnokiDataWrapper<T> = { data: T };
export type EnokiSponsorResponse = { bytes: string; digest: string };
export type EnokiExecuteResponse = { digest: string };
export type EnokiFallbackPolicy = {
    directSignIfUnconfigured: boolean;
    directSignAfterSponsorFailure: boolean;
    gasMode: "auto" | "addressBalance";
};

const DEFAULT_FALLBACK_POLICY: EnokiFallbackPolicy = {
    directSignIfUnconfigured: ENOKI_FALLBACK_TO_DIRECT_SIGN,
    directSignAfterSponsorFailure: ENOKI_FALLBACK_TO_DIRECT_SIGN,
    gasMode: "addressBalance",
};

// The migrator's controller lease reserves 60s for one Enoki call plus 10s
// margin. Keep retries and backoff inside that same deadline.
const ENOKI_REQUEST_TIMEOUT_MS = 60_000;

// SuiGrpcClient resolves to the discriminated union
// `{Transaction: {digest}} | {FailedTransaction: {digest}}`. Keep the flat
// digest case for SDK-version compatibility.
function extractTransactionDigest(result: any): string {
    if (typeof result?.digest === "string") return result.digest;
    const digest = result?.Transaction?.digest ?? result?.FailedTransaction?.digest;
    if (typeof digest === "string") return digest;
    throw new Error("signAndExecuteTransaction: could not resolve digest from result");
}

export function redactEnokiPath(path: string): string {
    return path.replace(/\/transaction-blocks\/sponsor\/[^/?]+/, "/transaction-blocks/sponsor/<digest>");
}

export function summarizeEnokiError(text: string): Record<string, unknown> {
    try {
        const parsed = JSON.parse(text) as { errors?: Array<{ code?: string; message?: string }> };
        if (Array.isArray(parsed.errors)) {
            return {
                errors: parsed.errors.map((err) => ({
                    code: err.code,
                    message: truncateForLog(err.message || ""),
                    hasMoveAbort: /moveabort/i.test(err.message || ""),
                    hasBalanceSplit: /balance.*split|split.*balance/i.test(err.message || ""),
                })),
            };
        }
    } catch {
        // Fall through to raw body summary.
    }
    return { body: truncateForLog(text) };
}

export function isMoveAbortBalanceSplit(message: string): boolean {
    return /moveabort/i.test(message) && /balance.*split|split.*balance/i.test(message);
}

/**
 * `account::reactivate_account` aborts the sponsor dry-run when the account
 * is already active (11) or still quarantined (20). Callers map these to a
 * stable code. Every other MoveAbort stays unclassified.
 */
export function reactivateRejectionCode(
    message: string,
): "account_already_active" | "account_quarantined" | null {
    if (!/moveabort/i.test(message)) return null;
    const namesThisFunction =
        /::account::reactivate_account\b/.test(message) ||
        /"functionName"\s*:\s*"reactivate_account"/.test(message);
    if (!namesThisFunction) return null;
    const abort =
        message.match(/abort code:\s*(11|20)\b/i)?.[1] ??
        message.match(/"abortCode"\s*:\s*"(11|20)"/)?.[1];
    if (abort === "11") return "account_already_active";
    if (abort === "20") return "account_quarantined";
    return null;
}

/**
 * `account::add_delegate_key` aborts the sponsor dry-run with
 * `ETooManyDelegateKeys` (abort code 2) once the account holds 20 delegate
 * keys. Callers map this to `max_delegate_keys` so the UI directs the user to
 * revoke an unused key on `/dashboard` instead of reporting a sponsor outage.
 */
export function addDelegateKeyRejectionCode(
    message: string,
): "max_delegate_keys" | null {
    if (!/moveabort/i.test(message)) return null;
    const namesThisFunction =
        /::account::add_delegate_key\b/.test(message) ||
        /"functionName"\s*:\s*"add_delegate_key"/.test(message) ||
        /function_name:\s*Some\(\\?"add_delegate_key\\?"\)/.test(message);
    if (!namesThisFunction) return null;
    const abort =
        message.match(/abort code:\s*(\d+)\b/i)?.[1] ??
        message.match(/'ETooManyDelegateKeys':\s*(\d+)\b/)?.[1] ??
        message.match(/\\"abortCode\\"\s*:\s*\\?"(\d+)\\?"/)?.[1] ??
        message.match(/"abortCode"\s*:\s*"?(\d+)"?/)?.[1] ??
        message.match(/function_name:\s*Some\(\\?"add_delegate_key\\?"\)\s*\},\s*(\d+)\)/)?.[1];
    if (abort === "2") return "max_delegate_keys";
    return null;
}

/**
 * Detect the `0x2::coin::destroy_zero` abort (ENonZero, abort code 0) that the
 * Walrus register PTB raises when the WAL payment coin still holds a non-zero
 * remainder. The `@mysten/walrus` `#withWal` helper pre-funds an *exact* WAL
 * amount (`storageUnits × price × epochs`) computed from the client's cached
 * `systemState`, then asserts the coin is empty via `destroy_zero`. When the
 * on-chain storage/write price drops between the cached read and execution, the
 * contract deducts less WAL than we split off, leaving change that trips
 * `destroy_zero`. It is not input-specific — refreshing the Walrus client so the
 * next attempt re-reads the live price clears it, so callers treat it as
 * transient rather than a permanent MoveAbort.
 */
export function isMoveAbortWalDestroyZero(message: string): boolean {
    return /moveabort/i.test(message) && /destroy_zero/i.test(message);
}

/**
 * Drop the process-wide Walrus client when the register payment was sized
 * from a stale cached price. `#withWal` pre-funds an exact WAL amount from
 * `systemState`. A price drop leaves a remainder and `coin::destroy_zero`
 * aborts. A price rise makes `system::reserve_space` split more than that
 * coin holds, so `balance::split` aborts with ENotEnough. The next attempt
 * rebuilds the register from a client that re-reads the live price. Waiting
 * for the max-age refresh spends the attempt budget on the same snapshot.
 *
 * The two detectors stay disjoint, so one abort refreshes once.
 */
export function refreshWalrusClientOnStaleWalPrice(message: string): void {
    if (isMoveAbortWalDestroyZero(message)) {
        refreshWalrusClient("walrus_wal_payment_destroy_zero");
        return;
    }
    if (isMoveAbortBalanceSplit(message)) {
        refreshWalrusClient("walrus_wal_payment_balance_split");
    }
}

export async function callEnoki<T>(path: string, payload: unknown): Promise<T> {
    if (!ENOKI_API_KEY) {
        throw new Error("ENOKI_API_KEY is not configured");
    }

    const signal = AbortSignal.timeout(ENOKI_REQUEST_TIMEOUT_MS);
    for (let attempt = 1; ; attempt += 1) {
        let resp: globalThis.Response;
        try {
            resp = await fetch(`${ENOKI_API_BASE_URL}${path}`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${ENOKI_API_KEY}`,
                },
                body: JSON.stringify(payload),
                signal,
            });
        } catch (err) {
            if (signal.aborted) throw signal.reason;
            const retryDelayMs = getEnokiRetryDelayMs({
                attempt,
                maxAttempts: ENOKI_TRANSIENT_MAX_ATTEMPTS,
                baseDelayMs: ENOKI_TRANSIENT_BASE_DELAY_MS,
                maxDelayMs: ENOKI_TRANSIENT_MAX_DELAY_MS,
                transportError: true,
            });
            if (retryDelayMs === null) throw err;
            console.warn(`[enoki] transport_retry ${JSON.stringify({
                path: redactEnokiPath(path),
                network: ENOKI_NETWORK,
                attempt,
                maxAttempts: ENOKI_TRANSIENT_MAX_ATTEMPTS,
                retryDelayMs,
                error: errorMessage(err),
            })}`);
            await sleepWithSignal(retryDelayMs, undefined, { signal });
            continue;
        }

        const text = await resp.text();
        if (!resp.ok) {
            const retryDelayMs = getEnokiRetryDelayMs({
                attempt,
                maxAttempts: ENOKI_TRANSIENT_MAX_ATTEMPTS,
                baseDelayMs: ENOKI_TRANSIENT_BASE_DELAY_MS,
                maxDelayMs: ENOKI_TRANSIENT_MAX_DELAY_MS,
                status: resp.status,
                retryAfter: resp.headers.get("retry-after"),
                body: text,
            });
            console.error(`[enoki] api_error ${JSON.stringify({
                path: redactEnokiPath(path),
                status: resp.status,
                network: ENOKI_NETWORK,
                attempt,
                maxAttempts: ENOKI_TRANSIENT_MAX_ATTEMPTS,
                retryDelayMs,
                ...summarizeEnokiError(text),
            })}`);
            if (retryDelayMs !== null) {
                await sleepWithSignal(retryDelayMs, undefined, { signal });
                continue;
            }
            // Structured status keeps the strict durable-path classifier
            // treating Enoki outages as shared-infra (budget-free).
            const error = new Error(`Enoki API error (${resp.status}): ${text}`);
            (error as Error & { status?: number }).status = resp.status;
            throw error;
        }

        const parsed = JSON.parse(text) as EnokiDataWrapper<T>;
        return parsed.data;
    }
}

async function executeSponsoredTransactionOnce(
    tx: Transaction,
    signer: Ed25519Keypair,
    allowedAddresses?: string[],
    onSubmissionStarted: () => void = () => {},
): Promise<string> {
    // Resolve owned-object inputs against the correct sender. The gRPC client
    // validates object ownership against the tx sender during build/resolution;
    // the Walrus `certify` tx is built WITHOUT a sender (0x0) — register sets its
    // own, certify does not — so gRPC rejects it ("Transaction was not signed by
    // the correct sender ... given owner/signer 0x0"). Enoki still sponsors with
    // its own sender and `onlyTransactionKind` excludes the sender from the
    // bytes, so this only fixes resolution.
    tx.setSenderIfNotSet(signer.toSuiAddress());
    const txKindBytes = await tx.build({
        client: suiClient as any,
        onlyTransactionKind: true,
    });

    const sponsored = await callEnoki<EnokiSponsorResponse>("/transaction-blocks/sponsor", {
        network: ENOKI_NETWORK,
        transactionBlockKindBytes: Buffer.from(txKindBytes).toString("base64"),
        sender: signer.toSuiAddress(),
        ...(allowedAddresses?.length ? { allowedAddresses } : {}),
    });

    const signature = await signer.signTransaction(
        new Uint8Array(Buffer.from(sponsored.bytes, "base64"))
    );

    // Defense-in-depth — encode digest before path interpolation.
    const encodedSponsoredDigest = encodeURIComponent(sponsored.digest);
    onSubmissionStarted();
    const executed = await callEnoki<EnokiExecuteResponse>(
        `/transaction-blocks/sponsor/${encodedSponsoredDigest}`,
        {
            digest: sponsored.digest,
            signature: signature.signature,
        }
    );

    return executed.digest;
}

export async function executeDirectSignedTransaction(
    tx: Transaction,
    signer: Ed25519Keypair,
    onSubmissionStarted: () => void = () => {},
    client = suiClient,
): Promise<string> {
    tx.setSenderIfNotSet(signer.toSuiAddress());
    const transaction = await tx.build({ client });
    const { signature } = await signer.signTransaction(transaction);
    onSubmissionStarted();
    const result = await client.executeTransaction({
        transaction,
        signatures: [signature],
    });
    return extractTransactionDigest(result);
}

export async function executeWithEnokiSponsor(
    tx: Transaction,
    signer: Ed25519Keypair,
    allowedAddresses?: string[],
    fallbackPolicy: EnokiFallbackPolicy = DEFAULT_FALLBACK_POLICY,
    onSubmissionStarted: () => void = () => {},
): Promise<string> {
    if (fallbackPolicy.gasMode === "addressBalance") {
        enforceAddressBalanceCoinIntents(tx);
        tx.setGasPayment([]);
    }

    if (!ENOKI_API_KEY) {
        if (!fallbackPolicy.directSignIfUnconfigured) {
            throw new Error("ENOKI_API_KEY is not configured and direct signing is disabled");
        }

        console.warn("[enoki-sponsor] ENOKI_API_KEY not configured, falling back to direct signing");
        return executeDirectSignedTransaction(tx, signer, onSubmissionStarted);
    }

    let sponsorError: unknown;
    try {
        return await executeSponsoredTransactionOnce(
            tx,
            signer,
            allowedAddresses,
            onSubmissionStarted,
        );
    } catch (err: any) {
        if (isSponsoredTransactionInvalidatedMessage(errorMessage(err))) {
            console.warn(`[enoki-sponsor] sponsored tx invalidated; retrying sponsor/execute once: ${err?.message || err}`);
            try {
                return await executeSponsoredTransactionOnce(
                    tx,
                    signer,
                    allowedAddresses,
                    onSubmissionStarted,
                );
            } catch (retryErr: any) {
                sponsorError = retryErr;
            }
        } else {
            sponsorError = err;
        }
    }

    {
        const err = sponsorError;
        const errMsg = errorMessage(err);
        if (!fallbackPolicy.directSignAfterSponsorFailure) {
            console.error(`[enoki-sponsor] sponsor failed and fallback disabled: ${errMsg}`);
            throw err;
        }

        console.warn(`[enoki-sponsor] sponsor failed, falling back to direct signing: ${errMsg}`);
        return executeDirectSignedTransaction(tx, signer, onSubmissionStarted);
    }
}

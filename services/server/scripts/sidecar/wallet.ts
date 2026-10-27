/**
 * Server-wallet transaction submission.
 *
 * Wraps the Enoki sponsor path with metrics, lock-error classification
 * (the validation canary) and the rebuild-and-retry loop for sponsored
 * transactions that get invalidated before execution.
 */

import type { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import type { Transaction } from "@mysten/sui/transactions";
import {
    classifyEnokiSponsoredTransactionInvalidation,
    isWalrusObjectLockEquivocation,
} from "../walrus-error-detection.js";
import {
    ENOKI_FALLBACK_TO_DIRECT_SIGN,
    ENOKI_INVALIDATED_BASE_DELAY_MS,
    ENOKI_INVALIDATED_MAX_ATTEMPTS,
    ENOKI_INVALIDATED_MAX_DELAY_MS,
    SUI_TYPE,
} from "./config.js";
import {
    executeWithEnokiSponsor,
    type EnokiFallbackPolicy,
} from "./enoki.js";
import { sidecarMetrics } from "./state.js";
import { CongestionCancelledTransaction, FinalizedTransactionFailure } from "./retry/rpc.js";
import { errorMessage, sleep, truncateForLog } from "./util.js";

export const DURABLE_WALLET_FALLBACK_POLICY: EnokiFallbackPolicy = {
    // Testnet can direct-sign when Enoki is absent. Once sponsorship begins,
    // never submit a second transaction after an ambiguous response.
    directSignIfUnconfigured: true,
    directSignAfterSponsorFailure: false,
    gasMode: "addressBalance",
};

// Legacy uploads are not journaled, so preserve their configured direct-sign
// fallback while ensuring every transaction uses address balances.
export const ADDRESS_BALANCE_WALLET_FALLBACK_POLICY: EnokiFallbackPolicy = {
    directSignIfUnconfigured: ENOKI_FALLBACK_TO_DIRECT_SIGN,
    directSignAfterSponsorFailure: ENOKI_FALLBACK_TO_DIRECT_SIGN,
    gasMode: "addressBalance",
};

function executionFailureText(error: unknown): string {
    if (typeof error === "string") return error.trim();
    if (!error || typeof error !== "object") return "";
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string" && message.trim()) return message.trim();
    try {
        const text = JSON.stringify(error, (_key, value) => (
            typeof value === "bigint" ? value.toString() : value
        ));
        return text === "{}" ? "" : text;
    } catch {
        return "";
    }
}

export function assertFinalizedTransactionSuccess(result: any, label: string): any {
    if (
        result?.$kind === "FailedTransaction"
        && result.FailedTransaction?.status?.success === false
    ) {
        // Keep congestion cancellation distinct so retries rebuild with a new nonce.
        if (result.FailedTransaction.status.error?.$kind === "CongestedObjects") {
            throw new CongestionCancelledTransaction(
                `${label} was cancelled by shared-object congestion`,
            );
        }
        // Only register failures carry abort details for stale WAL-price recovery.
        // Certify and metadata transfer must retain their retryable message.
        const detail = label === "registration transaction"
            ? executionFailureText(result.FailedTransaction.status.error)
            : "";
        throw new FinalizedTransactionFailure(
            detail ? `${label} was not successful: ${detail}` : `${label} was not successful`,
        );
    }
    if (
        result?.$kind === "Transaction"
        && result.Transaction?.status?.success === true
    ) {
        return result.Transaction;
    }

    // Unknown SDK shapes do not prove that submission had no side effect.
    // Keep the journal marker so reconciliation remains query-only.
    throw new Error(`${label} returned an unexpected finalization result`);
}

const COIN_WITH_BALANCE_INTENT = "CoinWithBalance";
const GAS_INTENT_TYPE = "gas";
type TxIntentCommand = {
    $kind?: string;
    $Intent?: {
        name?: string;
        data?: { type?: string };
    };
};
type TxDataWithCommands = { commands: TxIntentCommand[] };

/**
 * Rewrite CoinWithBalance "gas" intents to explicit SUI coin type so Enoki
 * sponsorship can build the transaction (Enoki rejects GasCoin tx arguments).
 */
export function patchGasCoinIntents(tx: Transaction): void {
    tx.addSerializationPlugin(async (transactionData: TxDataWithCommands, _buildOptions, next) => {
        let patched = 0;
        for (const command of transactionData.commands) {
            if (
                command.$kind === "$Intent" &&
                command.$Intent?.name === COIN_WITH_BALANCE_INTENT &&
                command.$Intent?.data?.type === GAS_INTENT_TYPE
            ) {
                command.$Intent.data.type = SUI_TYPE;
                patched += 1;
            }
        }

        if (patched > 0) {
            console.log(`[patch] converted ${patched} CoinWithBalance intent(s) from GasCoin -> sender SUI coins`);
        }

        await next();
    });
}

/**
 * Submit a Sui transaction via the Enoki sponsor path (or direct sign as
 * fallback). Wraps `executeWithEnokiSponsor` with metrics + lock-error
 * detection for the validation canary.
 */
export async function trackWalletSubmission<T>(
    submit: () => Promise<T>,
): Promise<T> {
    try {
        const result = await submit();
        sidecarMetrics.walletSubmittedTotal += 1;
        return result;
    } catch (err: any) {
        const msg = err?.message || String(err);
        if (isWalrusObjectLockEquivocation(msg)) {
            // Non-recoverable owned-object lock — held until the lock clears
            // (typically the next epoch boundary). The Rust worker classifies
            // this as ObjectLockedUntilEpoch and aborts rather than burning
            // wallet retries; here we only categorize the metric.
            sidecarMetrics.walletObjectLockEquivocationTotal += 1;
            console.error(`[wallet] object lock / equivocation: ${msg}`);
        } else if (/objectlocked|locked at version|object is locked/i.test(msg)) {
            sidecarMetrics.walletLockErrorsTotal += 1;
            console.error(`[wallet] coin-object lock error: ${msg}`);
        } else if (/moveabort|move abort/i.test(msg)) {
            sidecarMetrics.walletPermanentFailuresTotal += 1;
        }
        throw err;
    }
}

export async function submitWalletTransaction(
    tx: Transaction,
    signer: Ed25519Keypair,
    allowedAddresses?: string[],
    fallbackPolicy?: EnokiFallbackPolicy,
    onSubmissionStarted?: () => void,
): Promise<string> {
    return trackWalletSubmission(() =>
        executeWithEnokiSponsor(
            tx,
            signer,
            allowedAddresses,
            fallbackPolicy,
            onSubmissionStarted,
        ),
    );
}

function getEnokiInvalidatedRetryDelayMs(attempt: number): number | null {
    if (attempt >= ENOKI_INVALIDATED_MAX_ATTEMPTS) {
        return null;
    }

    const delay = ENOKI_INVALIDATED_BASE_DELAY_MS * 2 ** (attempt - 1);
    return Math.min(delay, ENOKI_INVALIDATED_MAX_DELAY_MS);
}

/**
 * Submit a transaction that can be cheaply rebuilt from scratch. When the
 * sponsored transaction gets invalidated (expired / referenced object stale)
 * the transaction is rebuilt via `buildTransaction` and resubmitted with
 * exponential backoff.
 */
export async function submitRebuildableWalletTransaction(
    phaseName: string,
    buildTransaction: () => Transaction,
    signer: Ed25519Keypair,
    allowedAddresses?: string[],
    logContext: Record<string, unknown> = {},
    fallbackPolicy?: EnokiFallbackPolicy,
    onSubmissionStarted?: () => void,
): Promise<string> {
    for (let attempt = 1; ; attempt += 1) {
        try {
            return await submitWalletTransaction(
                buildTransaction(),
                signer,
                allowedAddresses,
                fallbackPolicy,
                onSubmissionStarted,
            );
        } catch (err: unknown) {
            const message = errorMessage(err);
            const reason = classifyEnokiSponsoredTransactionInvalidation(message);
            const retryDelayMs = getEnokiInvalidatedRetryDelayMs(attempt);
            if (!reason || retryDelayMs === null) {
                throw err;
            }

            console.warn(`[enoki-sponsor] rebuildable_retry ${JSON.stringify({
                phase: phaseName,
                ...logContext,
                attempt,
                nextAttempt: attempt + 1,
                maxAttempts: ENOKI_INVALIDATED_MAX_ATTEMPTS,
                retryDelayMs,
                reason,
                message: truncateForLog(message),
            })}`);
            await sleep(retryDelayMs);
        }
    }
}

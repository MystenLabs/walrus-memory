/**
 * Enoki sponsorship endpoints for the frontend.
 *
 *   POST /sponsor          — TransactionKind bytes + sender → sponsored { bytes, digest }
 *   POST /sponsor/execute  — { digest, signature } after user wallet signs → { digest }
 */

import express, { type Express } from "express";
import { suiClient } from "../clients.js";
import { ENOKI_API_KEY, ENOKI_NETWORK, JSON_LIMIT_METADATA } from "../config.js";
import {
    addDelegateKeyRejectionCode,
    callEnoki,
    reactivateRejectionCode,
    type EnokiExecuteResponse,
    type EnokiSponsorResponse,
} from "../enoki.js";
import { requestIdFor, sidecarLog } from "../log.js";
import { errorMessage } from "../util.js";

const MAX_DELEGATE_KEYS_MESSAGE =
    "This Walrus Memory account already has the maximum number of delegate keys (20). Go to /dashboard and revoke an unused key, then try again.";

function sponsorAbortRejection(
    message: string,
): { code: "account_already_active" | "account_quarantined" | "max_delegate_keys"; error: string } | null {
    const code = reactivateRejectionCode(message);
    if (code === "account_already_active") {
        return { code, error: "This account is already active, so it cannot be reactivated." };
    }
    if (code === "account_quarantined") {
        return { code, error: "This account is still locked, so it cannot be reactivated yet." };
    }
    const addKeyCode = addDelegateKeyRejectionCode(message);
    if (addKeyCode === "max_delegate_keys") {
        return { code: addKeyCode, error: MAX_DELEGATE_KEYS_MESSAGE };
    }
    return null;
}

/**
 * Confirm an executed sponsored transaction actually SUCCEEDED
 * on-chain and report its sender. Enoki's execute endpoint returns 200 once
 * the transaction is submitted — effects status is not part of that
 * contract — so callers that key irreversible side-effects off "execute
 * returned 200" must verify effects
 * themselves. Uses the gRPC core getTransaction API.
 */
async function verifyExecutedTransaction(
    digest: string,
): Promise<{ success: boolean; sender: string | null; error: string | null }> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 10; attempt++) {
        try {
            const result: any = await (suiClient as any).core.getTransaction({
                digest,
                include: { transaction: true },
            });
            const tx = result?.Transaction ?? result?.FailedTransaction;
            if (tx) {
                const success = tx.status?.success === true;
                return {
                    success,
                    sender: tx.transaction?.sender ?? null,
                    error: success ? null : errorMessage(tx.status?.error ?? "transaction failed"),
                };
            }
        } catch (err) {
            // Not indexed yet (or transient) — retry below.
            lastError = err;
        }
        await new Promise((resolve) => setTimeout(resolve, 1_000 + attempt * 500));
    }
    throw new Error(
        `executed transaction not found on-chain after retries: ${errorMessage(lastError)}`,
    );
}

export function registerSponsorRoutes(app: Express): void {
    app.post("/sponsor", express.json({ limit: JSON_LIMIT_METADATA }), async (req, res) => {
        try {
            const { transactionBlockKindBytes, sender } = req.body;
            if (!transactionBlockKindBytes || !sender) {
                return res.status(400).json({ error: "Missing required fields: transactionBlockKindBytes, sender" });
            }
            if (!ENOKI_API_KEY) {
                return res.status(503).json({ error: "Enoki sponsorship is not configured (ENOKI_API_KEY missing)" });
            }


            // Redact full sender address (PII / deanonymisation) — log only
            // a short prefix for correlation. Never log the full digest here either.
            const senderPrefix = typeof sender === "string" ? sender.slice(0, 10) : "unknown";
            console.log(`[sponsor] creating sponsored tx for sender=${senderPrefix}...`);
            const sponsored = await callEnoki<EnokiSponsorResponse>("/transaction-blocks/sponsor", {
                network: ENOKI_NETWORK,
                transactionBlockKindBytes,
                sender,
            });

            console.log(`[sponsor] sponsored tx created (digest_len=${sponsored.digest.length})`);
            res.json(sponsored); // { bytes, digest }
        } catch (err: any) {
            const traceId = requestIdFor(req);
            const message = errorMessage(err);
            sidecarLog("error", "sponsor_failed", {
                requestId: traceId,
                error: message,
            });
            const rejection = sponsorAbortRejection(message);
            if (rejection) {
                return res.status(409).json({ error: rejection.error, code: rejection.code, traceId });
            }
            res.status(500).json({ error: message, traceId });
        }
    });

    app.post("/sponsor/execute", express.json({ limit: JSON_LIMIT_METADATA }), async (req, res) => {
        try {
            const { digest, signature, verifyEffects } = req.body;
            if (!digest || !signature) {
                return res.status(400).json({ error: "Missing required fields: digest, signature" });
            }
            if (!ENOKI_API_KEY) {
                return res.status(503).json({ error: "Enoki sponsorship is not configured (ENOKI_API_KEY missing)" });
            }

            // Percent-encode digest before path interpolation. The digest is
            // attacker-controlled when the sidecar is reached directly (no auth,
            // S1 in audit) or via the Rust proxy which validates base58 but the
            // sidecar must not rely on that. encodeURIComponent neutralises any
            // path traversal (`..`), query injection (`?`), or fragment (`#`)
            // payloads in the digest segment.
            const encodedDigest = encodeURIComponent(digest);
            const executed = await callEnoki<EnokiExecuteResponse>(
                `/transaction-blocks/sponsor/${encodedDigest}`,
                { digest, signature }
            );

            // Redact digest from console logs — it's a high-cardinality
            // value that ties log lines to individual user transactions. Log only
            // a length indicator for diagnostics.
            console.log(`[sponsor/execute] executed sponsored tx (digest_len=${digest.length})`);

            // Callers key irreversible DB updates off this
            // response, so it asks us to confirm effects success + sender. The
            // plain proxy path skips this (no behavior change).
            if (verifyEffects === true) {
                const verdict = await verifyExecutedTransaction(executed.digest ?? digest);
                if (!verdict.success) {
                    sidecarLog("error", "sponsor_execute_effects_failed", {
                        requestId: requestIdFor(req),
                        error: verdict.error,
                    });
                    return res.status(422).json({
                        error: `sponsored transaction did not succeed on-chain: ${verdict.error ?? "unknown"}`,
                    });
                }
                return res.json({ digest: executed.digest, sender: verdict.sender });
            }

            res.json(executed); // { digest }
        } catch (err: any) {
            const traceId = requestIdFor(req);
            const message = errorMessage(err);
            sidecarLog("error", "sponsor_execute_failed", {
                requestId: traceId,
                error: message,
            });
            const rejection = sponsorAbortRejection(message);
            if (rejection) {
                return res.status(409).json({ error: rejection.error, code: rejection.code, traceId });
            }
            res.status(500).json({ error: message, traceId });
        }
    });
}

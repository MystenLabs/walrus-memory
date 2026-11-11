/**
 * SEAL encrypt / decrypt endpoints.
 *
 *   POST /seal/encrypt        → { data, owner, packageId, accountId, expectedSealCommitteeIdentity? }
 *                             → { encryptedData }
 *   POST /migration/seal/encrypt → migration-only equivalent that may preserve inactive accounts
 *   POST /e2e/legacy/seal/encrypt → optional test-only route for the pre-v4 source account shape
 *   POST /seal/decrypt        → { data, packageId, policyPackageId?, registryId?, accountId, sealAbi } → { decryptedData }
 *   POST /seal/decrypt-batch  → { items[], packageId, policyPackageId?, registryId?, accountId, sealAbi } → { results[], errors[] }
 *
 * sealAbi selects the seal_approve shape: "v1-new" (registryId required) vs the
 * legacy "v1" source package (registryId forbidden). See seal-ptb.ts.
 */

import { randomUUID } from "crypto";
import { setTimeout as delay } from "node:timers/promises";
import express, { type Express, type Response as ExpressResponse } from "express";
import { decodeSuiPrivateKey } from "@mysten/sui/cryptography";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { normalizeSuiAddress } from "@mysten/sui/utils";
import { EncryptedObject, SessionKey } from "@mysten/seal";
import {
  JSON_LIMIT_SEAL_DECRYPT,
  JSON_LIMIT_SEAL_DECRYPT_BATCH,
  JSON_LIMIT_SEAL_ENCRYPT,
  SEAL_COMMITTEE_IDENTITY,
  SEAL_KEY_SERVER_TIMEOUT_MS,
  SEAL_POLICY_PACKAGE_ID,
  SEAL_THRESHOLD,
  SIDECAR_ENABLE_LEGACY_SEAL_ABI,
  SIDECAR_ENABLE_MIGRATION_SEAL_ROUTE,
} from "../config.js";
import { sealCommitteeIdentityMatches, type SealCommitteeIdentity } from "../../seal-config.js";
import { createDecryptSealClient, sealEncryptClient, suiClient, sealSessionCacheMetrics } from "../clients.js";
import { decryptBatchSealItems, decryptSingleSealItem } from "../seal-decrypt-pool.js";
import { buildSealEncryptId, fetchSealEncryptIdentity, type SealEncryptPurpose } from "../seal-identity.js";
import {
  buildSealApproveTx,
  sealApproveArgsError,
  sealIdentityPackageError,
  sealApprovePackageId,
} from "../seal-ptb.js";
import {
  assertSealSessionClientLive,
  getCachedInitialSharedVersion,
  hasSealSessionApprovedKeys,
  readSealAuthorizationVersions,
} from "../seal-session-pool.js";
import { requestIdFor } from "../log.js";
import { isRetryableRpcError } from "../retry/rpc.js";
import { errorMessage, errorName, formattedError } from "../util.js";

export function sealKeyFetchErrorCode(err: unknown): "SHARED_SERVICE_UNAVAILABLE" | "KEY_FETCH_FAILED" {
    return isRetryableRpcError(err) ? "SHARED_SERVICE_UNAVAILABLE" : "KEY_FETCH_FAILED";
}

// SEAL_REQUIRE_COMMITTEE_IDENTITY=true (or 1/yes/on) makes /seal/encrypt reject
// requests that omit expectedSealCommitteeIdentity, so migration deployments
// can enforce the "the Rust caller always pins the committee" contract.
// Parsed once at module load, following config.ts boolean conventions.
export const SEAL_REQUIRE_COMMITTEE_IDENTITY = (() => {
    const raw = (process.env.SEAL_REQUIRE_COMMITTEE_IDENTITY || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
})();

const SIDECAR_ENABLE_LEGACY_SEED_ROUTE = (() => {
    const raw = (process.env.SIDECAR_ENABLE_LEGACY_SEED_ROUTE || "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes";
})();

/**
 * Validate the caller's committee pin for /seal/encrypt.
 *
 * A pinned-committee mismatch is a pod/deployment misconfiguration, not a
 * transient outage: it is reported as 409 SEAL_COMMITTEE_MISMATCH, which the
 * Rust migrator's read_error maps to MigratorError::Other → ErrorClass::
 * Transient — a budgeted retry that quarantines the row instead of the old
 * budget-free SHARED_SERVICE_UNAVAILABLE infinite retry.
 */
export function sealEncryptCommitteeFailure(
  expectedSealCommitteeIdentity: unknown,
  requireCommitteeIdentity: boolean,
  actualIdentity: SealCommitteeIdentity
): { status: number; body: Record<string, unknown> } | null {
  if (expectedSealCommitteeIdentity === undefined) {
    if (!requireCommitteeIdentity) return null;
    return {
      status: 400,
      body: {
        error:
          "Missing required field: expectedSealCommitteeIdentity " +
          "(required because SEAL_REQUIRE_COMMITTEE_IDENTITY=true)",
      },
    };
  }
    if (!sealCommitteeIdentityMatches(expectedSealCommitteeIdentity, actualIdentity)) {
    return {
      status: 409,
      body: {
        error: "Seal encryption committee does not match the migration intent",
        code: "SEAL_COMMITTEE_MISMATCH",
        actualSealCommitteeIdentity: actualIdentity,
      },
    };
  }
  return null;
}

function sendSealFailure(
  res: ExpressResponse,
  operation: string,
  phase: string,
  err: unknown,
  traceId: string = randomUUID()
) {
  const message = formattedError(err);
  const error = `${operation} failed during ${phase}: ${message} (traceId=${traceId}, timeoutMs=${SEAL_KEY_SERVER_TIMEOUT_MS})`;
  const sharedServiceUnavailable = isRetryableRpcError(err);
  console.error(
    `[${operation}] [${traceId}] phase=${phase} timeoutMs=${SEAL_KEY_SERVER_TIMEOUT_MS} error: ${message}`
  );
  res.status(sharedServiceUnavailable ? 503 : 500).json({
    error,
    ...(sharedServiceUnavailable ? { code: "SHARED_SERVICE_UNAVAILABLE" } : {}),
    traceId,
    phase,
    timeoutMs: SEAL_KEY_SERVER_TIMEOUT_MS,
    errorName: errorName(err),
  });
}

/**
 * Resolve a SEAL SessionKey from the request headers.
 *
 * Preferred path: `x-seal-session` contains a base64-encoded
 * `ExportedSessionKey` (built by the SDK on the client). We import it and
 * skip touching any private-key material.
 *
 * Legacy path: `x-delegate-key` contains the raw delegate private key
 * (hex or suiprivkey bech32). We reconstruct the keypair and build the
 * SessionKey here — same behavior as before the migration. This path
 * will be removed at EOL once all SDK clients emit `x-seal-session`.
 *
 * Returns `null` when neither header is present so the caller can emit a
 * 400 with a clear error message.
 */
async function resolveSessionKey(req: express.Request, packageId: string): Promise<SessionKey | null> {
  const sessionHeader = req.headers["x-seal-session"] as string | undefined;
  if (sessionHeader) {
    const exportedJson = Buffer.from(sessionHeader, "base64").toString("utf8");
    const exported = JSON.parse(exportedJson);
    return SessionKey.import(exported, suiClient as any);
  }

  const privateKey = req.headers["x-delegate-key"] as string | undefined;
  if (!privateKey) return null;

  let keypair: Ed25519Keypair;
  if (privateKey.startsWith("suiprivkey")) {
    const { secretKey } = decodeSuiPrivateKey(privateKey);
    keypair = Ed25519Keypair.fromSecretKey(secretKey);
  } else {
    // Validate hex format before parsing to prevent injection
    if (!/^[0-9a-fA-F]+$/.test(privateKey) || privateKey.length !== 64) {
            throw new Error("privateKey must be 64-char hex string or suiprivkey bech32");
    }
        const keyBytes = Uint8Array.from(privateKey.match(/.{1,2}/g)!.map((b: string) => parseInt(b, 16)));
    keypair = Ed25519Keypair.fromSecretKey(keyBytes);
  }
  return await SessionKey.create({
    address: keypair.getPublicKey().toSuiAddress(),
    packageId,
    ttlMin: 5,
    signer: keypair,
    suiClient: suiClient as any,
  });
}

const ACCOUNT_READ_ATTEMPTS = 4;

/**
 * For Seal encrypt-side calls with no side effects: the MemWalAccount read and
 * the encrypt itself (key-server object reads; a retry only yields a fresh
 * ciphertext). Covers the gRPC-web transport's bare "fetch failed" (dropped
 * connection, no status code), which the shared classifier does not retry.
 * One such drop failed a whole remember before any paid work in each of
 * bench-w7-pr1055-204e580-100 (account read) and
 * bench-w9-merged-9e9a10c-r3 (encrypt).
 */
export async function retryTransientSealRpc<T>(
  read: () => Promise<T>,
  sleep: (ms: number) => Promise<unknown> = delay,
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await read();
    } catch (err) {
      const transient = isRetryableRpcError(err) || errorMessage(err).toLowerCase().includes("fetch failed");
      if (!transient || attempt >= ACCOUNT_READ_ATTEMPTS) throw err;
      await sleep(500 * 2 ** (attempt - 1));
    }
  }
}

const DECRYPT_FETCH_KEYS_ATTEMPTS = 2;
const DECRYPT_FETCH_KEYS_BACKOFF_MS = 250;

/**
 * Bounded single retry for SEAL decrypt key fetches so transient key-server
 * socket drops ("fetch failed"), 429s, or 5xx blips recover inline without
 * blowing past interactive recall deadlines or retrying permanent auth errors.
 */
export async function retryTransientSealDecryptRpc<T>(
  op: () => Promise<T>,
  sleep: (ms: number) => Promise<unknown> = delay,
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await op();
    } catch (err) {
      const transient = isRetryableRpcError(err) || errorMessage(err).toLowerCase().includes("fetch failed");
      if (!transient || attempt >= DECRYPT_FETCH_KEYS_ATTEMPTS) throw err;
      await sleep(DECRYPT_FETCH_KEYS_BACKOFF_MS);
    }
  }
}

const accountReader = {
  async getObject(input: { objectId: string; include: { json: true } }) {
    return await retryTransientSealRpc(() => suiClient.getObject(input));
  },
};

/** Keep malformed/foreign ciphertext local to its batch item. */
export function parseSealDecryptBatchItems(items: unknown[], packageId: string) {
  const expectedPackageId = normalizeSuiAddress(packageId);
  const parsedItems: {
    index: number;
    encryptedData: Uint8Array;
    fullId: string;
  }[] = [];
  const errors: { index: number; code: string; error: string }[] = [];

  for (let i = 0; i < items.length; i++) {
    try {
            const encryptedData = new Uint8Array(Buffer.from(items[i] as string, "base64"));
      const parsed = EncryptedObject.parse(encryptedData);
      if (normalizeSuiAddress(parsed.packageId) !== expectedPackageId) {
        errors.push({
          index: i,
          code: "CORRUPT_CIPHERTEXT",
          error: "Ciphertext packageId does not match request packageId",
        });
        continue;
      }
      parsedItems.push({ index: i, encryptedData, fullId: parsed.id });
    } catch (err: any) {
      errors.push({
        index: i,
        code: "CORRUPT_CIPHERTEXT",
        error: `parse failed: ${errorMessage(err)}`,
      });
    }
  }

  return { parsedItems, errors };
}

/**
 * Build the seal_approve PTB for a set of SEAL key IDs.
 * Uses cached immutable `initialSharedVersion` values from `readSealAuthorizationVersions`
 * when available so `tx.build({ onlyTransactionKind: true })` encodes locally in <0.1ms
 * without a redundant Sui `SimulateTransaction` RPC.
 */
async function buildSealApproveTxBytes(
  policyPackageId: string,
  registryId: string | undefined,
  accountId: string,
  ids: string[]
): Promise<Uint8Array> {
  let accountInitialSharedVersion = getCachedInitialSharedVersion(accountId);
  let registryInitialSharedVersion = registryId ? getCachedInitialSharedVersion(registryId) : undefined;
  if (
    registryId !== undefined &&
    (accountInitialSharedVersion === undefined || registryInitialSharedVersion === undefined)
  ) {
    try {
      await readSealAuthorizationVersions(suiClient, accountId, registryId);
      accountInitialSharedVersion = getCachedInitialSharedVersion(accountId);
      registryInitialSharedVersion = getCachedInitialSharedVersion(registryId);
    } catch {
      // Fall back to client-backed tx.build below to preserve exact RPC error reporting.
    }
  }

  const canBuildLocally =
    accountInitialSharedVersion !== undefined &&
    (registryId === undefined || registryInitialSharedVersion !== undefined);
  const tx = buildSealApproveTx(
    policyPackageId,
    registryId,
    accountId,
    ids,
    canBuildLocally
      ? { registryInitialSharedVersion, accountInitialSharedVersion }
      : undefined,
  );
  return canBuildLocally
    ? await tx.build({ onlyTransactionKind: true })
    : await tx.build({
        client: suiClient as any,
        onlyTransactionKind: true,
      });
}

class PtbBuildFailure {
  constructor(public readonly cause: unknown) {}
}

export type SealRoutePolicy = {
  enableMigrationSealRoute: boolean;
  enableLegacySealAbi: boolean;
  sealPolicyPackageId: string;
};

const DEFAULT_SEAL_ROUTE_POLICY: SealRoutePolicy = {
  enableMigrationSealRoute: SIDECAR_ENABLE_MIGRATION_SEAL_ROUTE,
  enableLegacySealAbi: SIDECAR_ENABLE_LEGACY_SEAL_ABI,
  sealPolicyPackageId: SEAL_POLICY_PACKAGE_ID,
};

export function registerSealRoutes(app: Express, policy = DEFAULT_SEAL_ROUTE_POLICY): void {
    // Protected by the sidecar's existing shared-secret middleware.
    app.get("/metrics/seal", (_req, res) => res.type("text/plain").send(sealSessionCacheMetrics()));
  // /seal/encrypt receives the full plaintext for SEAL encryption. Must
  // accept up to PROTECTED_BODY_LIMIT_BYTES (1.5 MiB) of plaintext plus
  // base64 + JSON framing overhead.
    const registerEncryptRoute = (path: string, purpose: SealEncryptPurpose) =>
        app.post(path, express.json({ limit: JSON_LIMIT_SEAL_ENCRYPT }), async (req, res) => {
        let phase = "validate";
        try {
                const { data, owner, packageId, accountId, expectedSealCommitteeIdentity } = req.body;
          if (!data || !owner || !packageId || !accountId) {
            return res.status(400).json({
                        error: "Missing required fields: data, owner, packageId, accountId",
            });
          }
          const committeeFailure = sealEncryptCommitteeFailure(
            expectedSealCommitteeIdentity,
            SEAL_REQUIRE_COMMITTEE_IDENTITY,
            SEAL_COMMITTEE_IDENTITY
          );
          if (committeeFailure) {
                    return res.status(committeeFailure.status).json(committeeFailure.body);
          }

          phase = "read_account_identity";
                const identity = await fetchSealEncryptIdentity(accountId, owner, packageId, purpose, accountReader);

          phase = "encrypt";
          const plaintext = Buffer.from(data, "base64");
                const result = await retryTransientSealRpc(() => sealEncryptClient.encrypt({
            threshold: SEAL_THRESHOLD,
            packageId: identity.immutablePackageId,
                    id: buildSealEncryptId(identity.owner, identity.accessCounterVersion),
            data: new Uint8Array(plaintext),
          }));

                const encryptedBase64 = Buffer.from(result.encryptedObject).toString("base64");
          res.json({ encryptedData: encryptedBase64 });
        } catch (err: any) {
          sendSealFailure(res, "seal/encrypt", phase, err, requestIdFor(req));
        }
        });

  // The purpose is selected by the authenticated internal route, never by
  // request data. Normal server writes are hardcoded to /seal/encrypt.
  registerEncryptRoute("/seal/encrypt", "normal");
  if (policy.enableMigrationSealRoute) {
    registerEncryptRoute("/migration/seal/encrypt", "migration");
  }
  if (SIDECAR_ENABLE_LEGACY_SEED_ROUTE) {
    registerEncryptRoute("/e2e/legacy/seal/encrypt", "legacy-seed");
  }

    app.post("/seal/decrypt", express.json({ limit: JSON_LIMIT_SEAL_DECRYPT }), async (req, res) => {
      let phase = "validate";
      try {
        const { data, packageId, registryId, accountId } = req.body;
        if (!data) {
                return res.status(400).json({ error: "Missing required field: data" });
        }
        // Payload validated above; here validate the shared fields: the ids
        // and the sealAbi/registryId pairing.
        const argsError = sealApproveArgsError(req.body, {
          allowLegacySealAbi: policy.enableLegacySealAbi,
          policyPackageId: policy.sealPolicyPackageId,
        });
        if (argsError) {
          return res.status(400).json({ error: argsError });
        }

        phase = "resolve_session";
        // resolve credential (x-seal-session preferred; legacy
        // x-delegate-key supported during the deprecation window).
            const sessionKey = await resolveSessionKey(req, normalizeSuiAddress(packageId));
        if (!sessionKey) {
          return res.status(400).json({
                    error: "Missing credential: provide x-seal-session (preferred) or x-delegate-key header",
          });
        }

        phase = "parse";
        // Parse encrypted object to get key ID
        const encryptedData = new Uint8Array(Buffer.from(data, "base64"));
        const parsed = EncryptedObject.parse(encryptedData);
        const fullId = parsed.id;
            const identityError = sealIdentityPackageError(packageId, [parsed.packageId], sessionKey.getPackageId());
        if (identityError) {
          return res.status(400).json({ error: identityError });
        }

        const policyPkgId = sealApprovePackageId(req.body, policy.sealPolicyPackageId)!;
        let cachedTxBytesPromise: Promise<Uint8Array> | undefined;
        const getTxBytes = () => {
          cachedTxBytesPromise ??= buildSealApproveTxBytes(policyPkgId, registryId, accountId, [fullId]).catch(
            (err) => {
              cachedTxBytesPromise = undefined;
              throw new PtbBuildFailure(err);
            },
          );
          return cachedTxBytesPromise;
        };

        phase = "fetch_keys";
        // Fetch keys from key servers with one bounded retry on transient RPC drops.
        // Warm session hits skip building the PTB entirely.
        let sealClient: Awaited<ReturnType<typeof createDecryptSealClient>>;
        try {
          sealClient = await retryTransientSealDecryptRpc(async () => {
            const client = await createDecryptSealClient({
              sessionHeader: typeof req.headers["x-seal-session"] === "string" ? req.headers["x-seal-session"] : undefined,
              session: sessionKey,
              packageId: normalizeSuiAddress(packageId),
              policyPackageId: policyPkgId,
              accountId: normalizeSuiAddress(accountId),
              registryId: registryId ? normalizeSuiAddress(registryId) : undefined,
              ids: [fullId],
            });
            if (!hasSealSessionApprovedKeys(client, [fullId], SEAL_THRESHOLD)) {
              const txBytes = await getTxBytes();
              await client.fetchKeys({
                ids: [fullId],
                txBytes,
                sessionKey,
                threshold: SEAL_THRESHOLD,
              });
            }
            return client;
          });
        } catch (err) {
          if (err instanceof PtbBuildFailure) {
            phase = "build_ptb";
            throw err.cause;
          }
          throw err;
        }

        phase = "decrypt";
        const assertLive = () => {
          if (sessionKey.isExpired()) throw new Error("SEAL session expired");
          assertSealSessionClientLive(sealClient);
        };
        const decrypted = await decryptSingleSealItem({
          sealClient,
          encryptedData,
          parsedObject: parsed,
          fullId,
          sessionKey,
          getTxBytes: async () => {
            try {
              return await getTxBytes();
            } catch (err) {
              throw err instanceof PtbBuildFailure ? err.cause : err;
            }
          },
          assertLive,
        });

        const decryptedBase64 = Buffer.from(decrypted).toString("base64");
        res.json({ decryptedData: decryptedBase64 });
      } catch (err: any) {
        sendSealFailure(res, "seal/decrypt", phase, err, requestIdFor(req));
      }
    });

  // Decrypt multiple SEAL-encrypted blobs with a single SessionKey.
  // Avoids "Not enough shares" errors when decrypting many blobs at once.
  // The batch body can be large (up to 25 × ~320 KiB max-item = ~8 MB).
    app.post("/seal/decrypt-batch", express.json({ limit: JSON_LIMIT_SEAL_DECRYPT_BATCH }), async (req, res) => {
      let phase = "validate";
      try {
        const { items, packageId, registryId, accountId } = req.body;
        if (!items || !Array.isArray(items) || items.length === 0) {
          return res.status(400).json({
                    error: "Missing required field: items (array of base64 encrypted data)",
          });
        }
        // Cap items. 25 × max-item body = ~8 MB (matches the
        // per-route body limit above). Tightened from 50 to 25 so worst-case
        // in-memory allocation stays bounded even at the new limit.
        if (items.length > 25) {
                return res.status(400).json({
                    error: "items array exceeds maximum of 25 elements",
                });
        }
        // Payload validated above; here validate the shared fields: the ids
        // and the sealAbi/registryId pairing.
        const argsError = sealApproveArgsError(req.body, {
          allowLegacySealAbi: policy.enableLegacySealAbi,
          policyPackageId: policy.sealPolicyPackageId,
        });
        if (argsError) {
          return res.status(400).json({ error: argsError });
        }

        phase = "resolve_session";
        // resolve credential (x-seal-session preferred; legacy
        // x-delegate-key supported during the deprecation window).
            const sessionKey = await resolveSessionKey(req, normalizeSuiAddress(packageId));
        if (!sessionKey) {
          return res.status(400).json({
                    error: "Missing credential: provide x-seal-session (preferred) or x-delegate-key header",
          });
        }
            const sessionIdentityError = sealIdentityPackageError(packageId, [], sessionKey.getPackageId());
        if (sessionIdentityError) {
          return res.status(400).json({ error: sessionIdentityError });
        }

        phase = "parse";
        // Parse all encrypted objects and collect unique SEAL IDs. A
        // foreign immutable package is corrupt for that item, not for the
        // valid subset sharing this request's SessionKey.
            const { parsedItems, errors } = parseSealDecryptBatchItems(items, packageId);

        if (parsedItems.length === 0) {
          return res.json({ results: [], errors });
        }

        const allIds = [...new Set(parsedItems.map((p) => p.fullId))];
        const policyPkgId = sealApprovePackageId(req.body, policy.sealPolicyPackageId)!;
        let buildMs = 0;
        let cachedTxBytesPromise: Promise<Uint8Array> | undefined;
        const getTxBytes = () => {
          if (!cachedTxBytesPromise) {
            const buildStarted = performance.now();
            cachedTxBytesPromise = buildSealApproveTxBytes(
              policyPkgId,
              registryId,
              accountId,
              allIds,
            )
              .then((bytes) => {
                buildMs += performance.now() - buildStarted;
                return bytes;
              })
              .catch((err) => {
                buildMs += performance.now() - buildStarted;
                cachedTxBytesPromise = undefined;
                throw new PtbBuildFailure(err);
              });
          }
          return cachedTxBytesPromise;
        };

        const keysStarted = performance.now();
        phase = "fetch_keys";
        // ONE fetchKeys call for ALL IDs on cold misses; warm session hits skip PTB
        // construction and key-server round-trips while still verifying live auth state.
        let sealClient: Awaited<ReturnType<typeof createDecryptSealClient>>;
        try {
          sealClient = await retryTransientSealDecryptRpc(async () => {
            const client = await createDecryptSealClient({
              sessionHeader: typeof req.headers["x-seal-session"] === "string" ? req.headers["x-seal-session"] : undefined,
              session: sessionKey,
              packageId: normalizeSuiAddress(packageId),
              policyPackageId: policyPkgId,
              accountId: normalizeSuiAddress(accountId),
              registryId: registryId ? normalizeSuiAddress(registryId) : undefined,
              ids: allIds,
            });
            if (!hasSealSessionApprovedKeys(client, allIds, SEAL_THRESHOLD)) {
              const txBytes = await getTxBytes();
              await client.fetchKeys({
                ids: allIds,
                txBytes,
                sessionKey,
                threshold: SEAL_THRESHOLD,
              });
            }
            return client;
          });
        } catch (err: any) {
          if (err instanceof PtbBuildFailure) {
            phase = "build_ptb";
            throw err.cause;
          }
          const traceId = randomUUID();
          const message = formattedError(err);
          const error = `fetch_keys failed: ${message} (traceId=${traceId}, timeoutMs=${SEAL_KEY_SERVER_TIMEOUT_MS})`;
          console.error(
            `[seal/decrypt-batch] [${traceId}] phase=fetch_keys items=${parsedItems.length} uniqueIds=${allIds.length} timeoutMs=${SEAL_KEY_SERVER_TIMEOUT_MS} error: ${message}`,
            err
          );
          return res.json({
            results: [],
            errors: [
              ...errors,
              ...parsedItems.map((item) => ({
                index: item.index,
                code: sealKeyFetchErrorCode(err),
                error,
              })),
            ],
          });
        }

        const keysMs = Math.max(0, performance.now() - keysStarted - buildMs);
        const decryptStarted = performance.now();
        phase = "decrypt";
        const assertLive = () => {
          if (sessionKey.isExpired()) throw new Error("SEAL session expired");
          assertSealSessionClientLive(sealClient);
        };
        const batchOut = await decryptBatchSealItems({
          sealClient,
          parsedItems,
          uniqueIds: allIds,
          sessionKey,
          getTxBytes: async () => {
            try {
              return await getTxBytes();
            } catch (err) {
              throw err instanceof PtbBuildFailure ? err.cause : err;
            }
          },
          assertLive,
        });
        const results = batchOut.results;
        errors.push(...batchOut.errors);

            console.log(JSON.stringify({ event: "seal_decrypt_batch", request_id: requestIdFor(req),
                items: items.length, unique_ids: allIds.length, results: results.length, errors: errors.length,
                build_ptb_ms: Math.round(buildMs), fetch_keys_ms: Math.round(keysMs),
                decrypt_ms: Math.round(performance.now() - decryptStarted) }));
        res.json({ results, errors });
      } catch (err: any) {
            sendSealFailure(res, "seal/decrypt-batch", phase, err, requestIdFor(req));
    }
    });
}

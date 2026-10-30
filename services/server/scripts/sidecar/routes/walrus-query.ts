/**
 * POST /walrus/query-blobs — query the user's Walrus Blob objects from the
 * Sui chain and filter by memwal_* metadata (namespace, packageId).
 */

import express, { type Express } from "express";
import { blobIdFromInt } from "@mysten/walrus";
import { bcs } from "@mysten/sui/bcs";
import { normalizeSuiAddress } from "@mysten/sui/utils";
import {
    JSON_LIMIT_METADATA,
    JSON_LIMIT_WALRUS_VERIFY,
    SERVER_SUI_ADDRESSES,
    SERVER_SUI_ADDRESS_SET,
    WALRUS_PACKAGE_ID,
} from "../config.js";
import { getWalrusClient, refreshWalrusClientIfStale, suiClient, suiGraphqlClient } from "../clients.js";
import { requestIdFor, sanitizeRequestId, sidecarLog } from "../log.js";
import { withRpcRetry } from "../retry/rpc.js";
import { MEMWAL_JOB_TAG_KEY, errorMessage, mapConcurrent } from "../util.js";

/**
 * blob_id from chain is a big integer (U256); convert to base64url
 * (little-endian) — the form Walrus aggregators expect.
 */
export function blobIdFromRaw(rawBlobId: string | number | null | undefined): string | null {
    if (!rawBlobId) return null;
    let blobIdStr = String(rawBlobId);
    if (/^\d+$/.test(blobIdStr) && blobIdStr.length > 20) {
        try {
            const bigInt = BigInt(blobIdStr);
            const hex = bigInt.toString(16).padStart(64, "0");
            const bytesBE = hex.match(/.{2}/g)!.map((b) => parseInt(b, 16));
            const bytesLE = new Uint8Array(bytesBE.reverse());
            blobIdStr = Buffer.from(bytesLE).toString("base64url");
        } catch {
            // Keep as-is if conversion fails.
        }
    }
    return blobIdStr;
}

/**
 * Canonical Sui address form (lowercase, 0x-prefixed, zero-padded) for
 * comparisons, or null for non-string/empty inputs. gRPC returns lowercase
 * addresses while journaled callers may send mixed-case hex, so exact-string
 * equality would strand otherwise-completed transfers.
 */
export function normalizedSuiAddressOrNull(value: unknown): string | null {
    if (typeof value !== "string" || value.length === 0) return null;
    return normalizeSuiAddress(value);
}

export function ownerMatchesRecipient(recipient: any, owner: string): boolean {
    const target = normalizedSuiAddressOrNull(owner);
    if (target === null) return false;
    if (typeof recipient === "string") return normalizedSuiAddressOrNull(recipient) === target;
    if (!recipient || typeof recipient !== "object") return false;
    return [recipient.AddressOwner, recipient.ObjectOwner, recipient.SingleOwner, recipient.owner].some(
        (candidate) => normalizedSuiAddressOrNull(candidate) === target
    );
}

export function isWalrusBlobObjectType(objectType: any, blobType: string): boolean {
    if (objectType === blobType) return true;
    if (typeof objectType !== "string") return false;
    const objectParts = objectType.split("::");
    const blobParts = blobType.split("::");
    return (
        objectParts.length === 3 &&
        blobParts.length === 3 &&
        objectParts[1] === blobParts[1] &&
        objectParts[2] === blobParts[2] &&
        objectParts[0].toLowerCase().replace(/^0x0+/, "0x") === blobParts[0].toLowerCase().replace(/^0x0+/, "0x")
    );
}

export function blobIdMatchesRequested(
    rawBlobId: string | number | null | undefined,
    requestedBlobIds?: ReadonlySet<string>
): boolean {
    if (!requestedBlobIds) return true;
    const blobId = blobIdFromRaw(rawBlobId);
    return blobId !== null && requestedBlobIds.has(blobId);
}

export function chainBlobIdFromRaw(rawBlobId: string | number | null | undefined): string | null {
    if (rawBlobId === null || rawBlobId === undefined || rawBlobId === "") return null;
    const value = String(rawBlobId);
    return /^\d+$/.test(value) ? blobIdFromInt(value) : blobIdFromRaw(value);
}

export function strictWalrusEpoch(value: unknown, field: string): number {
    if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new Error(`[query-blobs] ${field} must be a u32`);
    }
    return value;
}

export function isVerifiedNonexistentSource(status: { type?: unknown }): boolean {
    return status.type === "nonexistent";
}

export async function readBlobObject(
    blobObjectId: string,
    include: { json?: true; previousTransaction?: true },
    client: Pick<typeof suiClient, "getObject"> = suiClient
) {
    try {
        return await client.getObject({ objectId: blobObjectId, include });
    } catch (error: unknown) {
        const message = errorMessage(error);
        const missingObject = message.match(/\bObject (0x[0-9a-f]{64}) not found\b/i)?.[1];
        // Transaction effects can reach one RPC replica before its created object.
        if (missingObject?.toLowerCase() === blobObjectId.toLowerCase()) {
            throw Object.assign(new Error(message), {
                code: "UNAVAILABLE",
                cause: error,
            });
        }
        throw error;
    }
}

type RawBlobObj = {
    objectId: string;
    owner: unknown;
    rawBlobId: string | number | null;
    rawSize: string | number | null;
    deletable: boolean | null;
    storageEndEpoch: unknown;
    previousTransaction?: string | null;
    timestampMs?: string | null;
};

type BlobHistoryClient = {
    getTransaction(digest: string): Promise<any>;
    getCreationTransaction(objectId: string): Promise<string | null>;
};

function finalizedTransaction(response: any): any | null {
    if (response?.$kind === "Transaction") return response.Transaction ?? null;
    // Keep the helper usable with a narrow mock and with SDK transports that
    // return the transaction payload directly.
    return response?.effects && response?.transaction ? response : null;
}

/**
 * Resolve the immutable UID-creation transaction through archival GraphQL and
 * return its sender. The current object's `previousTransaction` is insufficient:
 * metadata attachment, lease renewal and ownership transfer all mutate a Blob.
 */
export async function findBlobCreationSender(
    blob: Pick<RawBlobObj, "objectId" | "previousTransaction">,
    client: BlobHistoryClient
): Promise<string | null> {
    const digest = await client.getCreationTransaction(blob.objectId);
    if (!digest) return null;
    const transaction = finalizedTransaction(await client.getTransaction(digest));
    if (!transaction?.status?.success) return null;
    const created = transaction.effects?.changedObjects?.find(
        (object: any) =>
            normalizedSuiAddressOrNull(object?.objectId) === normalizedSuiAddressOrNull(blob.objectId) &&
            object?.idOperation === "Created"
    );
    if (!created) return null;
    const createdAt =
        typeof transaction.effects?.timestamp === "string" && transaction.effects.timestamp.length > 0
            ? transaction.effects.timestamp
            : typeof transaction.timestamp === "string" && transaction.timestamp.length > 0
              ? transaction.timestamp
              : null;
    if (createdAt) {
        cacheBlobCreationTimestamp(blob.objectId, createdAt);
    }
    return normalizedSuiAddressOrNull(transaction.transaction?.sender);
}

const CREATION_TRANSACTION_QUERY = `
query BlobCreationTransaction($objectId: SuiAddress!) {
  object(address: $objectId) {
    previousTransaction { digest effects { timestamp } }
    objectVersionsBefore(first: 1) {
      nodes { previousTransaction { digest effects { timestamp } } }
    }
  }
}`;

const blobHistoryClient: BlobHistoryClient = {
    getTransaction: (digest) =>
        withRpcRetry(
            `[query-blobs] archival transaction ${digest}`,
            () =>
                suiGraphqlClient.getTransaction({
                    digest,
                    include: { effects: true, transaction: true },
                }),
            2
        ),
    getCreationTransaction: async (objectId) => {
        const result: any = await withRpcRetry(
            `[query-blobs] creation version ${objectId}`,
            () =>
                suiGraphqlClient.query({
                    query: CREATION_TRANSACTION_QUERY,
                    variables: { objectId },
                }),
            2
        );
        if (Array.isArray(result?.errors) && result.errors.length > 0) {
            throw new Error(`archival GraphQL lookup failed: ${result.errors[0]?.message ?? "unknown error"}`);
        }
        const object = result?.data?.object;
        if (!object) return null;
        // GraphQL connections are ascending for `first`; node[0] is the UID's
        // earliest retained version. A never-mutated object has no prior nodes,
        // so its current version is itself the creation version.
        const creationVersion = object.objectVersionsBefore?.nodes?.[0] ?? object;
        const createdAt = creationVersion?.previousTransaction?.effects?.timestamp;
        if (typeof createdAt === "string" && createdAt.length > 0) {
            cacheBlobCreationTimestamp(objectId, createdAt);
        }
        return typeof creationVersion?.previousTransaction?.digest === "string"
            ? creationVersion.previousTransaction.digest
            : null;
    },
};

// Creation provenance is immutable for an object ID. Bound the process cache
// so repeated restores avoid walking the same version history while memory use
// remains predictable. Null/error results are not cached because they may be
// caused by transient archive-node lag.
const BLOB_PROVENANCE_CACHE_MAX = 10_000;
const blobCreationSenderCache = new Map<string, string>();
const blobCreationTimestampCache = new Map<string, string>();

function cacheBlobCreationTimestamp(objectId: string, createdAt: string): void {
    blobCreationTimestampCache.delete(objectId);
    blobCreationTimestampCache.set(objectId, createdAt);
    if (blobCreationTimestampCache.size > BLOB_PROVENANCE_CACHE_MAX) {
        blobCreationTimestampCache.delete(blobCreationTimestampCache.keys().next().value!);
    }
}

export function getCachedBlobCreationTimestamp(objectId: string): string | null {
    return blobCreationTimestampCache.get(objectId) ?? null;
}

async function cachedBlobCreationSender(blob: Pick<RawBlobObj, "objectId" | "previousTransaction">) {
    const cached = blobCreationSenderCache.get(blob.objectId);
    if (cached) {
        // Refresh insertion order for simple LRU eviction.
        blobCreationSenderCache.delete(blob.objectId);
        blobCreationSenderCache.set(blob.objectId, cached);
        return cached;
    }
    const sender = await findBlobCreationSender(blob, blobHistoryClient);
    if (sender) {
        blobCreationSenderCache.set(blob.objectId, sender);
        if (blobCreationSenderCache.size > BLOB_PROVENANCE_CACHE_MAX) {
            blobCreationSenderCache.delete(blobCreationSenderCache.keys().next().value!);
        }
    }
    return sender;
}

export async function trustedBlobCandidate(
    blob: Pick<RawBlobObj, "objectId" | "owner" | "previousTransaction">,
    recipient: string,
    trustedUploaders: ReadonlySet<string>,
    client: BlobHistoryClient
): Promise<{ trusted: boolean; reason: "trusted" | "owner" | "provenance"; uploader: string | null }> {
    if (!ownerMatchesRecipient(blob.owner, recipient)) {
        return { trusted: false, reason: "owner", uploader: null };
    }
    const uploader = await findBlobCreationSender(blob, client);
    return uploader && trustedUploaders.has(uploader)
        ? { trusted: true, reason: "trusted", uploader }
        : { trusted: false, reason: "provenance", uploader };
}

export async function filterTrustedBlobCandidates<
    T extends Pick<RawBlobObj, "objectId" | "owner" | "previousTransaction">
>(
    candidates: T[],
    recipient: string,
    requestId: string,
    creationSender: (blob: T) => Promise<string | null> = cachedBlobCreationSender
): Promise<T[]> {
    const provenance = await mapConcurrent(candidates, 2, async (blob) => {
        try {
            const result = !ownerMatchesRecipient(blob.owner, recipient)
                ? { trusted: false as const, reason: "owner" as const, uploader: null }
                : await creationSender(blob).then((uploader) =>
                      uploader && SERVER_SUI_ADDRESS_SET.has(uploader)
                          ? { trusted: true as const, reason: "trusted" as const, uploader }
                          : { trusted: false as const, reason: "provenance" as const, uploader }
                  );
            return { blob, result };
        } catch (error: unknown) {
            // Abort this query on the first exhausted archival lookup rather
            // than silently omitting a legitimate Blob or waiting for every
            // remaining candidate to fail during an outage.
            throw new Error(`unable to verify creation provenance for ${blob.objectId}: ${errorMessage(error)}`);
        }
    });
    const excluded = provenance.filter(({ result }) => !result.trusted);
    if (excluded.length > 0) {
        sidecarLog("warn", "walrus_query_blobs_untrusted_candidates_excluded", {
            requestId,
            owner: recipient,
            excludedCount: excluded.length,
            ownershipMismatchCount: excluded.filter(({ result }) => result.reason === "owner").length,
            unverifiedProvenanceCount: excluded.filter(({ result }) => result.reason === "provenance").length,
            sample: excluded.slice(0, 5).map(({ blob, result }) => ({
                objectId: blob.objectId,
                uploader: result.uploader,
                reason: result.reason,
            })),
        });
    }
    return provenance.filter(({ result }) => result.trusted).map(({ blob }) => blob);
}

/**
 * True when the raw candidate fetch proved more than `cap` objects exist for
 * the owner (WALM-319). The call site probes with `cap + 1` (see
 * `listBlobObjectsGrpc` invocation below) and passes that raw fetched count
 * here alongside the real `cap`, so `fetchedCount > cap` means the probe
 * turned up at least one candidate beyond the cap — proof discovery didn't
 * complete. `fetchedCount === cap` means the owner had at most `cap` Blob
 * objects and discovery finished on its own, so that case must NOT read as
 * capped (PR #538 review: exact-cap results were being reported as
 * definitely truncated).
 */
export function isSourceCapped(fetchedCount: number, cap: number): boolean {
    return fetchedCount > cap;
}

/**
 * gRPC path for step 1: listOwnedObjects filters by object type server-side
 * and `include.json` returns the flattened Move fields (blob_id included), so
 * one paginated call replaces both the queryTransactionBlocks candidate scan
 * and the multiGetObjects content fetch. Unlike the tx scan the order is
 * unspecified rather than newest-first, so `cap` bounds work, not recency.
 */
async function listBlobObjectsGrpc(
    owner: string,
    blobType: string,
    cap: number,
    requestedBlobIds?: ReadonlySet<string>
): Promise<RawBlobObj[]> {
    const out: RawBlobObj[] = [];
    let cursor: string | null = null;

    while (out.length < cap) {
        const page = await withRpcRetry<any>("[query-blobs] listOwnedObjects", () =>
            (suiClient as any).listOwnedObjects({
                owner,
                type: blobType,
                include: { json: true, previousTransaction: true },
                cursor: cursor ?? undefined,
                limit: 50,
            })
        );

        for (const obj of page?.objects ?? []) {
            if (typeof obj?.objectId !== "string") continue;
            const rawBlobId = obj.json?.blob_id ?? obj.json?.blobId ?? null;
            // Migration already knows the legacy blob IDs. Filter directly
            // from the Blob fields returned by listOwnedObjects so metadata is
            // fetched only for requested candidates, not every owned Blob.
            if (requestedBlobIds && !requestedBlobIds.has(chainBlobIdFromRaw(rawBlobId) ?? "")) continue;
            out.push({
                objectId: obj.objectId,
                owner: obj.owner,
                rawBlobId,
                rawSize: obj.json?.size ?? null,
                deletable: typeof obj.json?.deletable === "boolean" ? obj.json.deletable : null,
                storageEndEpoch: obj.json?.storage?.end_epoch,
                previousTransaction: obj.previousTransaction,
            });
            if (out.length >= cap) break;
        }

        if (!page?.hasNextPage || !page?.cursor) break;
        cursor = page.cursor;
    }

    return out;
}

export function blobObjectMatchesRegistration(
    blob: Pick<RawBlobObj, "rawSize" | "deletable">,
    unencodedSize: number
): boolean {
    return blob.deletable === true && String(blob.rawSize) === String(unencodedSize);
}

type CompletionBlobAudit = {
    objectId: string;
    owner: string;
    size: number;
};

export function assertCompletionBlobObject(
    object: any,
    expected: CompletionBlobAudit & { blobId: string },
    currentEpoch: number
): number {
    const json = object?.json;
    if (!json) throw new Error(`Blob ${expected.objectId} has no JSON fields`);
    const blobType = `${WALRUS_PACKAGE_ID}::blob::Blob`;
    if (!isWalrusBlobObjectType(object.objectType ?? object.type, blobType)) {
        throw new Error(`object ${expected.objectId} is not a Walrus Blob`);
    }
    if (chainBlobIdFromRaw(json.blob_id ?? json.blobId) !== expected.blobId) {
        throw new Error(`Blob ${expected.objectId} does not contain ${expected.blobId}`);
    }
    if (String(json.size) !== String(expected.size)) {
        throw new Error(`Blob ${expected.objectId} size does not match the migration receipt`);
    }
    if (json.deletable !== true || json.certified_epoch === null || json.certified_epoch === undefined) {
        throw new Error(`Blob ${expected.objectId} is not a certified deletable Blob`);
    }
    if (!ownerMatchesRecipient(object.owner, expected.owner)) {
        throw new Error(`Blob ${expected.objectId} is not owned by ${expected.owner}`);
    }
    const endEpoch = strictWalrusEpoch(json.storage?.end_epoch, `Blob ${expected.objectId} storage end epoch`);
    if (endEpoch <= currentEpoch) {
        throw new Error(
            `Blob ${expected.objectId} expired at Walrus epoch ${endEpoch}; current epoch is ${currentEpoch}`
        );
    }
    return endEpoch;
}

export function assertCompletionBlobResponse(
    response: any,
    expected: CompletionBlobAudit & { blobId: string },
    currentEpoch: number
): number {
    if (!response?.object) {
        throw new Error(`Blob ${expected.objectId} is missing from the gRPC response`);
    }
    return assertCompletionBlobObject(response.object, expected, currentEpoch);
}

/**
 * Reconciliation lookup for the write crash-window (GH #477): given a user owner
 * and a remember job id — NOT a blob id — find the blob (if any) that a prior
 * upload minted for that job and then lost the record of.
 *
 * CRITICAL ownership detail: the upload registers the blob owned by the SERVER
 * signer wallet and only transfers it to the user in the final step. So a blob
 * whose write crashed mid-flight is (still) owned by a server pool wallet, not
 * the user. We therefore scan the server pool wallets AND the user, and match on
 * BOTH `memwal_job_id == jobId` and `memwal_owner == user` — the job tag alone is
 * not enough to prove the blob belongs to this user (guards against tag reuse /
 * collision adopting another user's paid blob).
 *
 * Discriminated result so the caller never mistakes "couldn't check" for
 * "not minted":
 *   - { status: "found", blobId, objectId }
 *   - { status: "not_found" } — every scanned owner fully scanned, no match
 * The lookup paginates every scanned owner to exhaustion. A bounded prefix is
 * not safe here: once a wallet owns more than the old cap, a matching paid blob
 * outside that prefix would leave every retry permanently indeterminate.
 * Per-blob metadata errors are intentionally not swallowed: a throw propagates
 * to the relayer, which retries without uploading.
 */
export type FindBlobByJobResult =
    | { status: "found"; blobId: string; objectId: string }
    | { status: "not_found" };

async function scanOwnerForJobBlob(
    scanOwner: string,
    userOwner: string,
    jobId: string
): Promise<FindBlobByJobResult> {
    const blobType = `${WALRUS_PACKAGE_ID}::blob::Blob`;
    const blobs = await listBlobObjectsGrpc(normalizeSuiAddress(scanOwner), blobType, Infinity);
    for (const blob of blobs) {
        const entries = await fetchBlobMetadataEntries(blob.objectId);
        const jobMatches = entries.some(({ key, value }) => key === MEMWAL_JOB_TAG_KEY && value === jobId);
        // Normalize the tagged owner before comparing — the register stores the
        // raw `owner` the relayer sent, which may be mixed-case / unpadded hex.
        const ownerMatches = entries.some(
            ({ key, value }) =>
                key === "memwal_owner" &&
                /^0x[0-9a-fA-F]{1,64}$/.test(value) &&
                normalizeSuiAddress(value) === userOwner
        );
        if (jobMatches && ownerMatches) {
            const blobId = blobIdFromRaw(blob.rawBlobId);
            if (blobId) return { status: "found", blobId, objectId: blob.objectId };
        }
    }
    return { status: "not_found" };
}

export async function findBlobObjectByJob(
    owner: string,
    jobId: string
): Promise<FindBlobByJobResult> {
    const userOwner = normalizeSuiAddress(owner);
    // Scan the server pool wallets (where a not-yet-transferred blob lives) AND
    // the user (where a transferred-but-unrecorded blob lives). De-dup in case a
    // server key coincides with the user address.
    const scanOwners = [...new Set([...SERVER_SUI_ADDRESSES.map((a) => normalizeSuiAddress(a)), userOwner])];
    for (const scanOwner of scanOwners) {
        const result = await scanOwnerForJobBlob(scanOwner, userOwner, jobId);
        if (result.status === "found") return result;
    }
    return { status: "not_found" };
}

export async function findOwnedBlobObjects(
    owner: string,
    blobId: string,
    migrationJobId?: string
): Promise<RawBlobObj[]> {
    const blobType = `${WALRUS_PACKAGE_ID}::blob::Blob`;
    // gRPC owner filters are exact; canonicalize so mixed-case journaled
    // addresses still find their blobs.
    const blobs = await listBlobObjectsGrpc(normalizeSuiAddress(owner), blobType, Infinity, new Set([blobId]));
    if (!migrationJobId) return blobs;

    const tagged: RawBlobObj[] = [];
    for (const blob of blobs) {
        const entries = await fetchBlobMetadataEntries(blob.objectId);
        if (entries.some(({ key, value }) => key === "memwal_migration_job" && value === migrationJobId)) {
            tagged.push(blob);
        }
    }
    return tagged;
}

// Walrus's `Metadata` struct is `{ metadata: VecMap<String, String> }`;
// VecMap's BCS byte layout (struct { contents: vector<Entry<K, V>> }) is
// identical to bcs.map's vector-of-pairs, so this parses the dynamic field
// value bytes returned by gRPC getDynamicField.
const WALRUS_METADATA_BCS = bcs.struct("Metadata", {
    metadata: bcs.map(bcs.string(), bcs.string()),
});

// Dynamic field name b"metadata" as gRPC wants it: BCS bytes, not a JSON value.
const METADATA_FIELD_NAME_GRPC = {
    type: "vector<u8>",
    bcs: bcs
        .vector(bcs.u8())
        .serialize(Array.from(Buffer.from("metadata")))
        .toBytes(),
};

/**
 * Fetch the memwal_* metadata entries attached to a Blob object as key/value
 * pairs over gRPC. Returns [] when the blob has no metadata dynamic field.
 */
export async function fetchBlobMetadataEntries(objectId: string): Promise<Array<{ key: string; value: string }>> {
    const dynField = await withRpcRetry<any>(`[query-blobs] getDynamicField ${objectId}`, () =>
        (suiClient as any).getDynamicField({
            parentId: objectId,
            name: METADATA_FIELD_NAME_GRPC,
        })
    );
    const valueBcs = dynField?.dynamicField?.value?.bcs;
    if (!valueBcs) return [];
    const parsed = WALRUS_METADATA_BCS.parse(valueBcs);
    return [...parsed.metadata.entries()].map(([key, value]) => ({
        key,
        value,
    }));
}

export function registerWalrusQueryRoute(app: Express): void {
    app.post("/walrus/verify-blob", express.json({ limit: JSON_LIMIT_WALRUS_VERIFY }), async (req, res) => {
        const { blobId, data, audit } = req.body;
        if (typeof blobId !== "string" || !blobId || typeof data !== "string" || !data) {
            return res.status(400).json({ error: "blobId and base64 data are required" });
        }

        let computedBlobId: string;
        try {
            computedBlobId = (
                await getWalrusClient().computeBlobMetadata({
                    bytes: Buffer.from(data, "base64"),
                })
            ).blobId;
        } catch (err: unknown) {
            const traceId = requestIdFor(req);
            const message = errorMessage(err);
            sidecarLog("error", "walrus_verify_blob_compute_failed", {
                requestId: traceId,
                error: message,
            });
            return res.status(503).json({
                error: message,
                code: "SHARED_SERVICE_UNAVAILABLE",
                traceId,
            });
        }

        if (audit === undefined) return res.json({ computedBlobId });
        if (
            !audit ||
            typeof audit.objectId !== "string" ||
            typeof audit.owner !== "string" ||
            !Number.isSafeInteger(audit.size) ||
            audit.size <= 0
        ) {
            return res.status(400).json({
                error: "audit requires objectId, owner, and a positive integer size",
            });
        }

        try {
            // Epoch only. A shorter max age resets the shared client and
            // re-parses system state on the main thread, which stalls /health.
            refreshWalrusClientIfStale();
            const systemState = await withRpcRetry("[verify-blob] Walrus systemState", () =>
                getWalrusClient().systemState()
            );
            const currentEpoch = strictWalrusEpoch(systemState?.committee?.epoch, "current Walrus epoch");
            const object = await withRpcRetry(`[verify-blob] Blob ${audit.objectId}`, () =>
                readBlobObject(audit.objectId, { json: true })
            );
            const storageEndEpoch = assertCompletionBlobResponse(object, { ...audit, blobId }, currentEpoch);
            return res.json({
                computedBlobId,
                currentEpoch,
                storageEndEpoch,
            });
        } catch (err: unknown) {
            const traceId = requestIdFor(req);
            const message = errorMessage(err);
            sidecarLog("error", "walrus_verify_blob_audit_failed", {
                requestId: traceId,
                error: message,
            });
            return res.status(422).json({ error: message, traceId });
        }
    });

    app.post("/walrus/query-blobs", express.json({ limit: JSON_LIMIT_METADATA }), async (req, res) => {
        try {
            const { owner: rawOwner, namespace, packageId, limit, blobIds, includeStorageLease } = req.body;
            if (!rawOwner) {
                return res.status(400).json({ error: "Missing required field: owner" });
            }
            if (includeStorageLease !== undefined && typeof includeStorageLease !== "boolean") {
                return res.status(400).json({
                    error: "includeStorageLease must be a boolean",
                });
            }
            if (includeStorageLease === true && (!Array.isArray(blobIds) || blobIds.length === 0)) {
                return res.status(400).json({
                    error: "includeStorageLease requires blobIds",
                });
            }
            // Canonicalize hex owners; leave anything else untouched so the
            // downstream error behavior for malformed input is unchanged.
            const owner =
                typeof rawOwner === "string" && /^0x[0-9a-fA-F]{1,64}$/.test(rawOwner)
                ? normalizeSuiAddress(rawOwner)
                : rawOwner;
            const desiredMatches = Math.max(1, Math.min(Number(limit) || 0, 500));
            const useRecentTxPath = Number.isFinite(Number(limit)) && Number(limit) > 0;
            const requestedBlobIds = Array.isArray(blobIds)
                ? new Set(blobIds.filter((value): value is string => typeof value === "string" && value.length > 0))
                : undefined;

            // Walrus Blob type (derived from env-driven WALRUS_PACKAGE_ID)
            const WALRUS_BLOB_TYPE = `${WALRUS_PACKAGE_ID}::blob::Blob`;

            // Step 1: Collect raw blob objects over gRPC. Restore passes
            // `limit`; cap work when no exact blob IDs were supplied.
            const cap =
                useRecentTxPath && !requestedBlobIds ? Math.max(1, Math.min(desiredMatches * 5, 100)) : Infinity;
            // Rust `SIDECAR_CANDIDATE_CAP_SATURATES_AT_LIMIT = 20` is derived from this formula.
            // Probe with `cap + 1` (when finite) so the raw fetch can prove
            // whether more than `cap` candidates actually exist, rather than
            // inferring "capped" merely from hitting `cap` exactly — an
            // owner with precisely `cap` blobs would otherwise read as
            // truncated even though discovery completed (PR #538 review).
            const probeCap = cap === Infinity ? Infinity : cap + 1;
            const probedObjs = await listBlobObjectsGrpc(owner, WALRUS_BLOB_TYPE, probeCap, requestedBlobIds);
            const ownedCandidates = probedObjs.slice(0, cap);
            // WALM-319: the candidate fetch above is capped independent of
            // `limit` once desiredMatches >= 20 (`cap` saturates at 100) and
            // shared across all of the owner's namespaces — a caller (namely
            // restore()) can't otherwise tell "found everything" apart from
            // "stopped early because of the cap" once results are filtered
            // down to one namespace.
            const sourceCapped = isSourceCapped(probedObjs.length, cap);

            if (includeStorageLease === true) {
                // Lease queries supply exact blob IDs and skip metadata, so
                // provenance is the first candidate-level gate on this path.
                const rawObjs = await filterTrustedBlobCandidates(
                    ownedCandidates,
                    owner,
                    requestIdFor(req)
                );
                // Epoch only. Do not pass a sub-minute max age: that resets the
                // shared Walrus client, and the expiry sweep then re-parses
                // system state on the main thread until /health stops answering.
                // A stale epoch delays expiry; it does not expire a blob early.
                refreshWalrusClientIfStale();
                const systemState = await withRpcRetry("[query-blobs] Walrus systemState", () =>
                    getWalrusClient().systemState()
                );
                const currentEpoch = strictWalrusEpoch(systemState?.committee?.epoch, "current Walrus epoch");
                const blobs = rawObjs.flatMap((obj) => {
                    const blobId = chainBlobIdFromRaw(obj.rawBlobId);
                    return blobId
                        ? [
                              {
                            blobId,
                            objectId: obj.objectId,
                            storageEndEpoch: strictWalrusEpoch(
                                obj.storageEndEpoch,
                                      `Blob ${obj.objectId} storage end epoch`
                            ),
                              },
                          ]
                        : [];
                });
                const leasedBlobIds = new Set(blobs.map((blob) => blob.blobId));
                const missingBlobIds = [...requestedBlobIds!].filter((blobId) => !leasedBlobIds.has(blobId));
                const nonexistentBlobIds = (
                    await mapConcurrent(missingBlobIds, 2, async (blobId) => {
                        const status = await withRpcRetry(
                            `[query-blobs] verified Walrus status ${blobId}`,
                            () =>
                                getWalrusClient().getVerifiedBlobStatus({
                                blobId,
                                signal: AbortSignal.timeout(30_000),
                            }),
                            2
                        );
                        return isVerifiedNonexistentSource(status) ? blobId : null;
                    })
                ).filter((blobId): blobId is string => blobId !== null);
                console.log(
                    `[query-blobs] returning ${blobs.length} source leases and ${nonexistentBlobIds.length} verified nonexistent blobs for owner=${owner} currentEpoch=${currentEpoch}`
                );
                return res.json({
                    blobs,
                    total: blobs.length,
                    currentEpoch,
                    nonexistentBlobIds,
                });
            }
            console.log(
                `[query-blobs] found ${ownedCandidates.length} raw blob objects for owner=${owner} via gRPC` +
                (requestedBlobIds
                    ? ` (requested=${requestedBlobIds.size})`
                        : useRecentTxPath
                        ? ` (candidateCap=${cap})`
                        : "")
            );

            // Step 2: Fetch metadata for each blob with bounded concurrency
            // to avoid overwhelming Sui RPC and hitting 429 rate limits.
            type BlobMeta = RawBlobObj & {
                blobNamespace: string;
                blobOwner: string;
                blobPackageId: string;
                blobAgentId: string;
            };

            const metadataConcurrency = useRecentTxPath ? 2 : 5;
            const metas: BlobMeta[] = await mapConcurrent(ownedCandidates, metadataConcurrency, async (obj) => {
                let blobNamespace = "default";
                let blobOwner = "";
                let blobPackageId = "";
                let blobAgentId = "";

                try {
                    for (const { key, value } of await fetchBlobMetadataEntries(obj.objectId)) {
                        if (key === "memwal_namespace") blobNamespace = value;
                        if (key === "memwal_owner") blobOwner = value;
                        if (key === "memwal_package_id") blobPackageId = value;
                        if (key === "memwal_agent_id") blobAgentId = value;
                    }
                } catch {
                    // No dynamic field = no metadata = use defaults
                }

                return {
                    ...obj,
                    blobNamespace,
                    blobOwner,
                    blobPackageId,
                    blobAgentId,
                };
            });

            // Step 3: Narrow by cheap metadata first, then perform the more
            // expensive immutable-history provenance walk only for candidates
            // that can actually belong to this restore request.
            const metadataMatches = metas.filter(
                (meta) =>
                    (!namespace || meta.blobNamespace === namespace) &&
                    (!packageId || meta.blobPackageId === packageId)
            );
            const trustedMetas = await filterTrustedBlobCandidates(
                metadataMatches,
                owner,
                requestIdFor(req)
            );

            // Step 4: Convert trusted blob IDs.
            const blobs: {
                blobId: string;
                objectId: string;
                namespace: string;
                packageId: string;
                agentId: string;
                createdAt?: string;
            }[] = [];

            for (const meta of trustedMetas) {
                if (meta.rawBlobId) {
                    const blobIdStr = blobIdFromRaw(meta.rawBlobId);
                    if (blobIdStr) {
                        const createdAt = getCachedBlobCreationTimestamp(meta.objectId);
                        blobs.push({
                            blobId: blobIdStr,
                            objectId: meta.objectId,
                            namespace: meta.blobNamespace,
                            packageId: meta.blobPackageId,
                            agentId: meta.blobAgentId,
                            ...(createdAt ? { createdAt } : {}),
                        });
                    }
                }
            }

            console.log(
                `[query-blobs] returning ${blobs.length} blobs (filtered from ${
                    ownedCandidates.length
                }) for owner=${owner} ns=${namespace || "*"}`
            );
            res.json({ blobs, total: blobs.length, sourceCapped });
        } catch (err: any) {
            const traceId = requestIdFor(req);
            const message = errorMessage(err);
            sidecarLog("error", "walrus_query_blobs_failed", {
                requestId: traceId,
                error: message,
            });
            res.status(500).json({ error: message, traceId });
        }
    });

    // GH #477 reconciliation: find a blob a prior write minted for a remember
    // job whose record was lost to a crash — by (owner, job_id), no blob id
    // needed. The relayer calls this before re-uploading a `running` job so it
    // can adopt an already-minted blob instead of minting a duplicate.
    app.post("/walrus/find-blob-by-job", express.json({ limit: JSON_LIMIT_METADATA }), async (req, res) => {
        try {
            const { owner: rawOwner, jobId: rawJobId } = req.body;
            if (typeof rawOwner !== "string" || !rawOwner) {
                return res.status(400).json({ error: "Missing required field: owner" });
            }
            if (typeof rawJobId !== "string" || !rawJobId) {
                return res.status(400).json({ error: "Missing required field: jobId" });
            }
            // Match on the SAME canonical form the register wrote the tag with
            // (`sanitizeRequestId`), so the query value can never silently diverge
            // from the stored value. A job id that doesn't survive sanitization was
            // never tag-able, so it can't be reconciled — say so explicitly rather
            // than querying with a value that could never match.
            const jobId = sanitizeRequestId(rawJobId);
            if (jobId === null) {
                return res.status(400).json({ error: "jobId is not a valid tag value" });
            }
            const owner = /^0x[0-9a-fA-F]{1,64}$/.test(rawOwner) ? normalizeSuiAddress(rawOwner) : rawOwner;
            const result = await findBlobObjectByJob(owner, jobId);
            if (result.status === "found") {
                return res.json({ blob_id: result.blobId, object_id: result.objectId });
            }
            // The exhaustive scan completed without a matching job tag.
            return res.json({ blob_id: null, object_id: null });
        } catch (error: unknown) {
            const message = errorMessage(error);
            sidecarLog("error", "walrus_find_blob_by_job_failed", { error: message });
            res.status(500).json({ error: message });
        }
    });
}

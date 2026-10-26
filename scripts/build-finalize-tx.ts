#!/usr/bin/env tsx
/**
 * Build the UNSIGNED transaction bytes (base64) that FINALIZE the migration —
 * `account::finalize_migration(&AdminCap, &mut AccountRegistry, &Clock,
 * evidence_sha256, evidence_expires_at_ms)`, a one-way latch that permanently
 * closes the legacy import path. Uses @mysten/sui over gRPC (no JSON-RPC).
 * Output is signed later (multisig / ledger / offline) and submitted separately
 * — nothing here executes.
 *
 *   tsx scripts/build-finalize-tx.ts
 *   tsx scripts/build-finalize-tx.ts --self-test   # pure-logic check, no network
 *
 * This is the AdminCap action, so SENDER is the multisig that holds the AdminCap.
 * Burning the spent MigrationCap is a separate tx signed by the wallet that owns
 * the cap (the controller's), not this one.
 * A fresh completion report from the in-cluster one-shot Job is mandatory.
 * After a security migration, write the operator completion artifact with scripts/write-migration-completion-artifact.mjs (internal/ops/migration-completion-artifact.md).
 *
 * Gas is auto-selected by build(): address balance when available, otherwise an
 * owned SUI coin. The transaction is chain-bound to the current Sui epoch. Sui
 * does not yet support timestamp expiration, so build, review, sign, and submit
 * must remain one controlled operation while the evidence is fresh.
 *
 * Env (parsed up front; missing required ones throw before any work):
 *   GRPC_URL       grpc-web base url of a fullnode              (required)
 *   SENDER         0x.. AdminCap holder / signer (the multisig) (required)
 *   PACKAGE_ID     0x.. published memwal package                (required)
 *   ADMIN_CAP_ID   0x.. AdminCap held by SENDER                 (required)
 *   REGISTRY_ID    0x.. shared AccountRegistry to finalize      (required)
 *   SOURCE_PACKAGE_ID  0x.. reviewed legacy package             (required)
 *   SOURCE_REGISTRY_ID 0x.. reviewed legacy registry            (required)
 *   DB_CUTOVER_REV immutable source-dataset revision             (required)
 *   WALRUS_PACKAGE_ID reviewed Walrus package                     (required)
 *   WALRUS_RETENTION_EPOCHS reviewed blob retention; mainnet=15   (required)
 *   SEAL_ENCRYPT_COMMITTEE_IDENTITY reviewed committee JSON or path(required)
 *   SOURCE_INVENTORY_JSON reviewed source cutoff inventory JSON/path(required)
 *   COMPLETION_EVIDENCE_JSON  completion-report JSON, inline or path (required)
 *   COMPLETION_EVIDENCE_SHA256 independently reviewed evidence digest (required)
 *   MANIFEST_SHA256 independently reviewed migration manifest digest  (required)
 *   NETWORK        mainnet|testnet          (default mainnet)
 *   GAS_BUDGET     MIST                     (default 500000000 = 0.5 SUI)
 *   OUT            file to write base64 to  (default: stdout)
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { Transaction } from "@mysten/sui/transactions";
import { SuiGrpcClient } from "@mysten/sui/grpc";
import { fromHex, normalizeSuiAddress, toBase64 } from "@mysten/sui/utils";
import {
  accountType,
  assertAddress,
  assertChainIdentifier,
  assertObjectId,
  assertObjectTypes,
  env,
  GOVERNANCE_CHAIN_IDENTIFIERS,
  governanceNetwork,
  type GovernanceNetwork,
  requireEnv,
} from "./assertions.js";

const MAX_SEAL_WEIGHTED_SERVERS = 254;
const FULL_MANIFEST_SCOPE = "full-registry";
const MANIFEST_AUTHORITY_POLICY = "pinned-exact-source-authority-v2";

const REQUIRED_CHECKS = [
  "sourceDbWriteFenceHeld",
  "destinationDbWriteFenceHeld",
  "sourceAuthorityCutoffPinned",
  "sourceInventoryMatchesReviewedCommitment",
  "sourceSnapshotsStable",
  "sourceDeletionQueueDrained",
  "controllerExcluded",
  "allRowsTerminal",
  "sourceAndDestinationMatch",
  "noOrphanedDestinationRows",
  "strandedReplacementBlobsReviewed",
  "accountsComplete",
  "noChainAmbiguity",
  "noUnsafeUploadJournals",
  "destinationBlobsLive",
  "destinationDecryptCanaryVerified",
  "destinationCanaryOwnerScoped",
  "walrusUploadRouteMatchesReviewedPolicy",
  "sealEncryptCommitteeMatchesReviewedPolicy",
] as const;

type CompletionEvidence = {
  raw: string;
  sha256: string;
  expiresAtMs: number;
  root: string;
  accounts: bigint;
  delegates: bigint;
};

type ExpectedCompletionRoute = {
  srcPackageId: string;
  srcRegistryId: string;
  dstPackageId: string;
  dstRegistryId: string;
  dbCutoverRev: string;
};

type SealCommitteeIdentity = {
  servers: Array<{ objectId: string; weight: number }>;
  threshold: number;
};

type ExpectedCompletionPolicy = {
  walrusUploadRoute: {
    suiNetwork: GovernanceNetwork;
    executionIdentity: {
      chainIdentifier: string;
      walrusPackageId: string;
    };
    retentionEpochs: number;
  };
  sealEncryptCommitteeIdentity: SealCommitteeIdentity;
};

type SourceInventoryCommitment = {
  schemaVersion: 1;
  dbCutoverRev: string;
  sourceLiveCount: number;
  sourceSnapshotSha256: string;
};

function parsePositiveU64(value: unknown, label: string): bigint {
  const text = String(value ?? "");
  if (!/^\d+$/.test(text))
    throw new Error(`${label} must be a positive integer`);
  const parsed = BigInt(text);
  if (parsed === 0n || parsed > 0xffff_ffff_ffff_ffffn)
    throw new Error(`${label} must be a positive u64`);
  return parsed;
}

function parseU64(value: unknown, label: string): bigint {
  const text = String(value ?? "");
  if (!/^\d+$/.test(text))
    throw new Error(`${label} must be a non-negative integer`);
  const parsed = BigInt(text);
  if (parsed > 0xffff_ffff_ffff_ffffn)
    throw new Error(`${label} must be a u64`);
  return parsed;
}

function parseJson(raw: string, label: string): any {
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${(error as Error).message}`);
  }
}

function readJson(spec: string, label: string): any {
  return parseJson(existsSync(spec) ? readFileSync(spec, "utf8") : spec, label);
}

function assertExactKeys(
  value: unknown,
  expected: readonly string[],
  label: string
): asserts value is Record<string, unknown> {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort())
  )
    throw new Error(`${label} contains missing or unknown fields`);
}

function parseSealCommitteeIdentity(spec: string): SealCommitteeIdentity {
  const value = readJson(spec, "SEAL_ENCRYPT_COMMITTEE_IDENTITY");
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !Array.isArray(value.servers) ||
    value.servers.length === 0 ||
    !Number.isSafeInteger(value.threshold) ||
    value.threshold <= 0
  )
    throw new Error(
      "SEAL_ENCRYPT_COMMITTEE_IDENTITY must contain non-empty servers and a positive integer threshold"
    );
  if (
    Object.keys(value).sort().join(",") !== "servers,threshold" ||
    value.servers.some(
      (server: any) =>
        !server ||
        typeof server !== "object" ||
        Array.isArray(server) ||
        Object.keys(server).sort().join(",") !== "objectId,weight" ||
        assertObjectId(
          String(server.objectId ?? ""),
          "Seal server objectId"
        ) !== server.objectId ||
        !Number.isSafeInteger(server.weight) ||
        server.weight <= 0
    )
  )
    throw new Error(
      "SEAL_ENCRYPT_COMMITTEE_IDENTITY servers must contain only canonical objectId and positive integer weight"
    );
  if (
    new Set(
      value.servers.map((server: { objectId: string }) => server.objectId)
    ).size !== value.servers.length
  )
    throw new Error(
      "SEAL_ENCRYPT_COMMITTEE_IDENTITY contains duplicate server object IDs"
    );
  const totalWeight = value.servers.reduce(
    (total: number, server: { weight: number }) => total + server.weight,
    0
  );
  if (
    !Number.isSafeInteger(totalWeight) ||
    totalWeight > MAX_SEAL_WEIGHTED_SERVERS ||
    value.threshold > totalWeight ||
    value.threshold > MAX_SEAL_WEIGHTED_SERVERS
  )
    throw new Error(
      "SEAL_ENCRYPT_COMMITTEE_IDENTITY must use at most 254 weighted server slots"
    );
  return value as SealCommitteeIdentity;
}

function parseSourceInventory(
  spec: string,
  dbCutoverRev: string
): SourceInventoryCommitment {
  const value = readJson(spec, "SOURCE_INVENTORY_JSON");
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "dbCutoverRev,schemaVersion,sourceLiveCount,sourceSnapshotSha256" ||
    value.schemaVersion !== 1 ||
    value.dbCutoverRev !== dbCutoverRev ||
    !Number.isSafeInteger(value.sourceLiveCount) ||
    value.sourceLiveCount <= 0 ||
    !/^[0-9a-f]{64}$/.test(String(value.sourceSnapshotSha256 ?? ""))
  )
    throw new Error(
      "SOURCE_INVENTORY_JSON must be the exact schema-v1 inventory for DB_CUTOVER_REV"
    );
  return value as SourceInventoryCommitment;
}

function completionPolicy(
  network: GovernanceNetwork,
  walrusPackageId: string,
  retentionEpochs: bigint,
  sealEncryptCommitteeIdentity: SealCommitteeIdentity
): ExpectedCompletionPolicy {
  if (retentionEpochs > 15n)
    throw new Error("WALRUS_RETENTION_EPOCHS must be at most 15");
  if (network === "mainnet" && retentionEpochs !== 15n)
    throw new Error("WALRUS_RETENTION_EPOCHS must be 15 on mainnet");
  return {
    walrusUploadRoute: {
      suiNetwork: network,
      executionIdentity: {
        chainIdentifier: GOVERNANCE_CHAIN_IDENTIFIERS[network],
        walrusPackageId,
      },
      retentionEpochs: Number(retentionEpochs),
    },
    sealEncryptCommitteeIdentity,
  };
}

function parseCompletionEvidence(
  spec: string,
  expectedSha256: string,
  expectedManifestSha256: string,
  expectedRoute: ExpectedCompletionRoute,
  expectedPolicy: ExpectedCompletionPolicy,
  expectedSourceInventory: SourceInventoryCommitment,
  now = Date.now()
): CompletionEvidence {
  const raw = existsSync(spec) ? readFileSync(spec, "utf8") : spec;
  const value = parseJson(raw, "COMPLETION_EVIDENCE_JSON");
  if (raw !== JSON.stringify(value, null, 2))
    throw new Error(
      "completion evidence must be the unchanged canonical JSON emitted by completion-report"
    );
  assertExactKeys(
    value,
    [
      "schemaVersion",
      "generatedAt",
      "expiresAt",
      "complete",
      "route",
      "walrusUploadRoute",
      "sealEncryptCommitteeIdentity",
      "reviewedSourceInventory",
      "manifestSha256",
      "manifestScope",
      "sourceAuthorityPolicy",
      "manifestAccountCount",
      "manifestDelegateCount",
      "quietSeconds",
      "audit",
      "checks",
    ],
    "completion evidence"
  );
  assertExactKeys(
    value.route,
    [
      "srcPackageId",
      "srcRegistryId",
      "dstPackageId",
      "dstRegistryId",
      "dbCutoverRev",
      "manifestRoot",
    ],
    "completion evidence route"
  );
  assertExactKeys(
    value.audit,
    [
      "safety",
      "sourceLiveCount",
      "sourceDeletingCount",
      "sourceActiveDeletionBatchCount",
      "migrationRowCount",
      "destinationOrphanCount",
      "reviewedDeadCount",
      "reviewedDeadIds",
      "reviewedDeadIdsSha256",
      "reviewedOrphanBlobCount",
      "reviewedOrphanBlobs",
      "reviewedOrphanBlobsSha256",
      "sourceSnapshotSha256",
      "sourceAuthoritySnapshotSha256",
      "destinationSnapshotSha256",
    ],
    "completion evidence audit"
  );
  assertExactKeys(
    value.audit.safety,
    ["importedAccounts", "doneMemories", "deadMemories", "driftSweptMemories"],
    "completion evidence safety audit"
  );
  assertExactKeys(value.checks, REQUIRED_CHECKS, "completion evidence checks");
  const sha256 = createHash("sha256").update(raw).digest("hex");
  if (!/^[0-9a-f]{64}$/.test(expectedSha256) || sha256 !== expectedSha256)
    throw new Error(
      "completion evidence SHA-256 does not match the independently reviewed digest"
    );
  if (value?.schemaVersion !== 5 || value?.complete !== true)
    throw new Error(
      "completion evidence must have schemaVersion=5 and complete=true"
    );
  const timestampPattern =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
  if (
    typeof value.generatedAt !== "string" ||
    typeof value.expiresAt !== "string" ||
    !timestampPattern.test(value.generatedAt) ||
    !timestampPattern.test(value.expiresAt)
  )
    throw new Error("completion evidence timestamps are invalid");
  const generatedAt = Date.parse(value.generatedAt);
  const expiresAt = Date.parse(value.expiresAt);
  if (!Number.isFinite(generatedAt) || !Number.isFinite(expiresAt))
    throw new Error("completion evidence timestamps are invalid");
  if (
    generatedAt > now + 60_000 ||
    expiresAt <= now ||
    expiresAt <= generatedAt ||
    expiresAt > generatedAt + 15 * 60_000
  )
    throw new Error(
      "completion evidence is stale, future-dated, or has an invalid lifetime"
    );
  for (const [field, expected] of Object.entries(expectedRoute)) {
    const actual = String(value.route?.[field] ?? "");
    const matches =
      field === "dbCutoverRev"
        ? actual === expected
        : normalizeSuiAddress(actual) === expected;
    if (!matches)
      throw new Error(
        `completion evidence route ${field} does not match the reviewed value`
      );
  }
  if (
    !isDeepStrictEqual(
      value.walrusUploadRoute,
      expectedPolicy.walrusUploadRoute
    )
  )
    throw new Error(
      "completion evidence Walrus upload route does not match the reviewed policy"
    );
  if (
    !isDeepStrictEqual(
      value.sealEncryptCommitteeIdentity,
      expectedPolicy.sealEncryptCommitteeIdentity
    )
  )
    throw new Error(
      "completion evidence Seal encrypt committee does not match the reviewed policy"
    );
  if (
    !isDeepStrictEqual(value.reviewedSourceInventory, expectedSourceInventory)
  )
    throw new Error(
      "completion evidence source inventory does not match the independently reviewed commitment"
    );
  if (
    !/^[0-9a-f]{64}$/.test(expectedManifestSha256) ||
    value.manifestSha256 !== expectedManifestSha256
  )
    throw new Error(
      "completion evidence manifestSha256 does not match the independently reviewed digest"
    );
  if (value.manifestScope !== FULL_MANIFEST_SCOPE)
    throw new Error("completion evidence manifestScope must be full-registry");
  if (value.sourceAuthorityPolicy !== MANIFEST_AUTHORITY_POLICY)
    throw new Error(
      "completion evidence sourceAuthorityPolicy does not match the reviewed cutoff policy"
    );
  const root = String(value.route?.manifestRoot ?? "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(root))
    throw new Error("completion evidence manifest root is invalid");
  for (const check of REQUIRED_CHECKS) {
    if (value.checks?.[check] !== true)
      throw new Error(`completion evidence check ${check} is not true`);
  }
  if (!/^[0-9a-f]{64}$/.test(String(value.audit?.sourceSnapshotSha256 ?? "")))
    throw new Error("completion evidence source snapshot digest is invalid");
  if (
    !/^[0-9a-f]{64}$/.test(
      String(value.audit?.sourceAuthoritySnapshotSha256 ?? "")
    )
  )
    throw new Error(
      "completion evidence source authority snapshot digest is invalid"
    );
  if (!/^[0-9a-f]{64}$/.test(String(value.audit?.reviewedDeadIdsSha256 ?? "")))
    throw new Error("completion evidence reviewed dead IDs digest is invalid");
  const reviewedDeadIds = value.audit?.reviewedDeadIds;
  if (
    !Array.isArray(reviewedDeadIds) ||
    reviewedDeadIds.some(
      (id: unknown) => typeof id !== "string" || id.length === 0
    ) ||
    reviewedDeadIds.some(
      (id: string, index: number) =>
        index > 0 && reviewedDeadIds[index - 1] >= id
    )
  )
    throw new Error(
      "completion evidence reviewedDeadIds must be unique, non-empty, and lexically sorted"
    );
  const reviewedDeadIdsSha256 = createHash("sha256")
    .update(JSON.stringify(reviewedDeadIds))
    .digest("hex");
  if (reviewedDeadIdsSha256 !== value.audit.reviewedDeadIdsSha256)
    throw new Error(
      "completion evidence reviewedDeadIds digest does not match its exact list"
    );
  if (
    !/^[0-9a-f]{64}$/.test(String(value.audit?.reviewedOrphanBlobsSha256 ?? ""))
  )
    throw new Error(
      "completion evidence reviewed orphan blobs digest is invalid"
    );
  // Blobs uploaded for a memory whose source row was then deleted. Only the
  // owner can delete them, and objectId is their only handle once the
  // migration schema is dropped, so the finalize digest commits to the list.
  const reviewedOrphanBlobs = value.audit?.reviewedOrphanBlobs;
  if (
    !Array.isArray(reviewedOrphanBlobs) ||
    reviewedOrphanBlobs.some(
      (orphan: any) =>
        !orphan ||
        typeof orphan !== "object" ||
        Array.isArray(orphan) ||
        Object.keys(orphan).sort().join(",") !==
          "blobId,legacyEntryId,objectId,owner" ||
        typeof orphan.blobId !== "string" ||
        orphan.blobId.length === 0 ||
        typeof orphan.legacyEntryId !== "string" ||
        orphan.legacyEntryId.length === 0 ||
        assertAddress(String(orphan.owner ?? ""), "orphan blob owner") !==
          orphan.owner ||
        assertObjectId(
          String(orphan.objectId ?? ""),
          "orphan blob objectId"
        ) !== orphan.objectId
    ) ||
    reviewedOrphanBlobs.some(
      (orphan: { owner: string; blobId: string }, index: number) =>
        index > 0 &&
        `${reviewedOrphanBlobs[index - 1].owner}\u0000${
          reviewedOrphanBlobs[index - 1].blobId
        }` >= `${orphan.owner}\u0000${orphan.blobId}`
    )
  )
    throw new Error(
      "completion evidence reviewedOrphanBlobs must be canonical, unique by owner and blob, and sorted"
    );
  const reviewedOrphanBlobsSha256 = createHash("sha256")
    .update(JSON.stringify(reviewedOrphanBlobs))
    .digest("hex");
  if (reviewedOrphanBlobsSha256 !== value.audit.reviewedOrphanBlobsSha256)
    throw new Error(
      "completion evidence reviewedOrphanBlobs digest does not match its exact list"
    );
  if (
    BigInt(reviewedOrphanBlobs.length) !==
    parseU64(
      value.audit?.reviewedOrphanBlobCount,
      "completion reviewedOrphanBlobCount"
    )
  )
    throw new Error(
      "completion evidence reviewedOrphanBlobs length does not match reviewedOrphanBlobCount"
    );
  if (
    !/^[0-9a-f]{64}$/.test(String(value.audit?.destinationSnapshotSha256 ?? ""))
  )
    throw new Error(
      "completion evidence destination snapshot digest is invalid"
    );
  const accounts = parsePositiveU64(
    value.manifestAccountCount,
    "completion manifestAccountCount"
  );
  const delegates = parseU64(
    value.manifestDelegateCount,
    "completion manifestDelegateCount"
  );
  const sourceLive = parsePositiveU64(
    value.audit?.sourceLiveCount,
    "completion sourceLiveCount"
  );
  if (
    sourceLive !== BigInt(expectedSourceInventory.sourceLiveCount) ||
    value.audit?.sourceSnapshotSha256 !==
      expectedSourceInventory.sourceSnapshotSha256
  )
    throw new Error(
      "completion evidence source snapshot differs from the independently reviewed inventory"
    );
  const sourceDeleting = parseU64(
    value.audit?.sourceDeletingCount,
    "completion sourceDeletingCount"
  );
  const activeDeletionBatches = parseU64(
    value.audit?.sourceActiveDeletionBatchCount,
    "completion sourceActiveDeletionBatchCount"
  );
  const migrationRows = parsePositiveU64(
    value.audit?.migrationRowCount,
    "completion migrationRowCount"
  );
  const destinationOrphans = parseU64(
    value.audit?.destinationOrphanCount,
    "completion destinationOrphanCount"
  );
  const reviewedDead = parseU64(
    value.audit?.reviewedDeadCount,
    "completion reviewedDeadCount"
  );
  if (BigInt(reviewedDeadIds.length) !== reviewedDead)
    throw new Error(
      "completion evidence reviewedDeadIds length does not match reviewedDeadCount"
    );
  const importedAccounts = parsePositiveU64(
    value.audit?.safety?.importedAccounts,
    "completion importedAccounts"
  );
  const done = parseU64(
    value.audit?.safety?.doneMemories,
    "completion doneMemories"
  );
  const dead = parseU64(
    value.audit?.safety?.deadMemories,
    "completion deadMemories"
  );
  const driftSwept = parseU64(
    value.audit?.safety?.driftSweptMemories,
    "completion driftSweptMemories"
  );
  const quietSeconds = parsePositiveU64(
    value.quietSeconds,
    "completion quietSeconds"
  );
  if (quietSeconds > 300n)
    throw new Error("completion quietSeconds exceeds 300");
  if (sourceDeleting !== 0n || activeDeletionBatches !== 0n)
    throw new Error("completion evidence contains in-flight source deletions");
  if (destinationOrphans !== 0n)
    throw new Error("completion evidence contains orphaned destination rows");
  if (
    importedAccounts !== accounts ||
    dead !== reviewedDead ||
    reviewedDead < driftSwept ||
    done + reviewedDead - driftSwept !== sourceLive ||
    done + dead !== migrationRows
  )
    throw new Error("completion evidence counts are internally inconsistent");
  return {
    raw,
    sha256,
    expiresAtMs: expiresAt,
    root,
    accounts,
    delegates,
  };
}

function bindCompletionExpiration(
  tx: Transaction,
  evidence: CompletionEvidence,
  chainIdentifier: string,
  currentEpoch: bigint
): void {
  tx.setExpiration({
    ValidDuring: {
      minEpoch: String(currentEpoch),
      maxEpoch: String(currentEpoch),
      minTimestamp: null,
      maxTimestamp: null,
      chain: chainIdentifier,
      nonce: Number.parseInt(evidence.sha256.slice(0, 8), 16),
    },
  });
}

async function assertRegistryComplete(
  client: SuiGrpcClient,
  registryId: string,
  evidence: CompletionEvidence
): Promise<void> {
  const { object } = await client.getObject({
    objectId: registryId,
    include: { json: true },
  });
  const value: any = object?.json;
  if (!value) throw new Error(`REGISTRY_ID ${registryId} has no Move JSON`);
  const root = value.pinned_allowlist_root;
  const rootHex = Array.isArray(root)
    ? Buffer.from(root).toString("hex")
    : Buffer.from(String(root ?? ""), "base64").toString("hex");
  const expectedAccounts = BigInt(
    String(value.expected_account_imports ?? "-1")
  );
  const expectedDelegates = BigInt(
    String(value.expected_delegate_imports ?? "-1")
  );
  const importedAccounts = BigInt(String(value.imported_accounts ?? "-1"));
  const importedDelegates = BigInt(String(value.imported_delegates ?? "-1"));
  if (`0x${rootHex}` !== evidence.root)
    throw new Error("on-chain pinned root differs from completion evidence");
  if (
    expectedAccounts !== evidence.accounts ||
    expectedDelegates !== evidence.delegates
  )
    throw new Error(
      "on-chain expected import counts differ from completion evidence"
    );
  if (
    importedAccounts !== expectedAccounts ||
    importedDelegates !== expectedDelegates
  )
    throw new Error("on-chain account/delegate imports are incomplete");
  if (value.migration_finalized !== false)
    throw new Error("registry migration is already finalized");
}

function addFinalizeCall(
  tx: Transaction,
  packageId: string,
  adminCapId: string,
  registryId: string,
  evidence: CompletionEvidence
): void {
  tx.moveCall({
    target: `${packageId}::account::finalize_migration`,
    arguments: [
      tx.object(adminCapId),
      tx.object(registryId),
      tx.object.clock(),
      tx.pure.vector("u8", fromHex(evidence.sha256)),
      tx.pure.u64(BigInt(evidence.expiresAtMs)),
    ],
  });
}

async function main() {
  if (process.argv.includes("--self-test")) return selfTest();

  // 1. parse env → strings (throws early if a required var is missing).
  const grpcUrlStr = requireEnv("GRPC_URL");
  const senderStr = requireEnv("SENDER");
  const packageIdStr = requireEnv("PACKAGE_ID");
  const adminCapIdStr = requireEnv("ADMIN_CAP_ID");
  const registryIdStr = requireEnv("REGISTRY_ID");
  const sourcePackageIdStr = requireEnv("SOURCE_PACKAGE_ID");
  const sourceRegistryIdStr = requireEnv("SOURCE_REGISTRY_ID");
  const dbCutoverRev = requireEnv("DB_CUTOVER_REV");
  const walrusPackageIdStr = requireEnv("WALRUS_PACKAGE_ID");
  const walrusRetentionEpochsStr = requireEnv("WALRUS_RETENTION_EPOCHS");
  const sealEncryptCommitteeIdentityStr = requireEnv(
    "SEAL_ENCRYPT_COMMITTEE_IDENTITY"
  );
  const sourceInventoryStr = requireEnv("SOURCE_INVENTORY_JSON");
  const completionEvidenceStr = requireEnv("COMPLETION_EVIDENCE_JSON");
  const completionEvidenceSha256 = requireEnv("COMPLETION_EVIDENCE_SHA256");
  const manifestSha256 = requireEnv("MANIFEST_SHA256");
  const networkStr = env("NETWORK", "mainnet")!;
  const gasBudgetStr = env("GAS_BUDGET", "500000000")!;
  const outStr = env("OUT");

  // 2. validate → fully-typed values.
  const sender = assertAddress(senderStr, "SENDER");
  const packageId = assertObjectId(packageIdStr, "PACKAGE_ID");
  const adminCapId = assertObjectId(adminCapIdStr, "ADMIN_CAP_ID");
  const registryId = assertObjectId(registryIdStr, "REGISTRY_ID");
  const sourcePackageId = assertObjectId(
    sourcePackageIdStr,
    "SOURCE_PACKAGE_ID"
  );
  const sourceRegistryId = assertObjectId(
    sourceRegistryIdStr,
    "SOURCE_REGISTRY_ID"
  );
  const network = governanceNetwork(networkStr);
  const expectedPolicy = completionPolicy(
    network,
    assertObjectId(walrusPackageIdStr, "WALRUS_PACKAGE_ID"),
    parsePositiveU64(walrusRetentionEpochsStr, "WALRUS_RETENTION_EPOCHS"),
    parseSealCommitteeIdentity(sealEncryptCommitteeIdentityStr)
  );
  const expectedSourceInventory = parseSourceInventory(
    sourceInventoryStr,
    dbCutoverRev
  );
  const completionEvidence = parseCompletionEvidence(
    completionEvidenceStr,
    completionEvidenceSha256,
    manifestSha256,
    {
      srcPackageId: sourcePackageId,
      srcRegistryId: sourceRegistryId,
      dstPackageId: packageId,
      dstRegistryId: registryId,
      dbCutoverRev,
    },
    expectedPolicy,
    expectedSourceInventory
  );
  const gasBudget = BigInt(gasBudgetStr);

  // 3. logic.
  const client = new SuiGrpcClient({ network, baseUrl: grpcUrlStr });
  const { chainIdentifier } = await client.core.getChainIdentifier();
  assertChainIdentifier(network, chainIdentifier);

  await assertObjectTypes(client, packageId, [
    { id: adminCapId, struct: "AdminCap", what: "ADMIN_CAP_ID" },
    { id: registryId, struct: "AccountRegistry", what: "REGISTRY_ID" },
  ]);
  await assertRegistryComplete(client, registryId, completionEvidence);

  const tx = new Transaction();
  // The evidence digest and deadline are signed into the Move call; Clock makes
  // the 15-minute completion report lifetime enforceable at execution time.
  addFinalizeCall(tx, packageId, adminCapId, registryId, completionEvidence);
  const { systemState } = await client.core.getCurrentSystemState();
  bindCompletionExpiration(
    tx,
    completionEvidence,
    chainIdentifier,
    BigInt(systemState.epoch)
  );
  console.error(
    `finalize_migration on registry ${registryId} (package ${packageId})`
  );
  console.error(`completion evidence sha256: ${completionEvidence.sha256}`);

  tx.setSender(sender);
  tx.setGasBudget(gasBudget);
  // Gas payment is left unset on purpose. The explicit ValidDuring epoch above
  // applies whether build() selects address-balance or coin-object gas.
  const b64 = toBase64(await tx.build({ client }));
  if (outStr) {
    writeFileSync(outStr, b64);
    console.error(`wrote unsigned tx bytes -> ${outStr}`);
  } else {
    process.stdout.write(b64 + "\n");
  }
}

function selfTest() {
  const assert = (c: unknown, m: string) => {
    if (!c) throw new Error("self-test failed: " + m);
  };
  const threw = (fn: () => unknown) => {
    try {
      fn();
      return false;
    } catch {
      return true;
    }
  };
  const ID = "0x" + "1".repeat(64);

  assert(assertAddress(ID, "x") === ID, "valid address accepted");
  assert(assertObjectId(ID, "x") === ID, "valid object id accepted");
  assert(
    threw(() => assertAddress("0x123", "x")),
    "short address rejected"
  );
  assert(
    threw(() => assertObjectId("not-an-id", "x")),
    "non-id rejected"
  );
  assert(
    threw(() => requireEnv("WM_FINALIZE_SELFTEST_MISSING")),
    "missing required env rejected"
  );

  assert(
    accountType(ID, "AdminCap") === `${ID}::account::AdminCap`,
    "admin cap type built"
  );
  assert(
    accountType("0x2", "AdminCap") ===
      accountType("0x" + "0".repeat(63) + "2", "AdminCap"),
    "type address padded"
  );
  const now = Date.now();
  const expectedRoute = {
    srcPackageId: ID,
    srcRegistryId: ID,
    dstPackageId: ID,
    dstRegistryId: ID,
    dbCutoverRev: "cutover-1",
  };
  const expectedPolicy = completionPolicy("testnet", ID, 5n, {
    servers: [{ objectId: ID, weight: 1 }],
    threshold: 1,
  });
  const expectedSourceInventory = parseSourceInventory(
    JSON.stringify({
      schemaVersion: 1,
      dbCutoverRev: "cutover-1",
      sourceLiveCount: 1,
      sourceSnapshotSha256: "c".repeat(64),
    }),
    "cutover-1"
  );
  const sealIdentityJson = JSON.stringify(
    expectedPolicy.sealEncryptCommitteeIdentity
  );
  assert(
    isDeepStrictEqual(
      parseSealCommitteeIdentity(sealIdentityJson),
      expectedPolicy.sealEncryptCommitteeIdentity
    ),
    "reviewed Seal committee parsed"
  );
  assert(
    threw(() =>
      parseSealCommitteeIdentity(
        JSON.stringify({
          ...expectedPolicy.sealEncryptCommitteeIdentity,
          unexpected: true,
        })
      )
    ),
    "Seal committee with extra fields rejected"
  );
  assert(
    threw(() =>
      parseSealCommitteeIdentity(
        JSON.stringify({
          servers: [
            { objectId: ID, weight: 1 },
            { objectId: ID, weight: 1 },
          ],
          threshold: 2,
        })
      )
    ),
    "duplicate Seal servers rejected"
  );
  assert(
    threw(() =>
      parseSealCommitteeIdentity(
        JSON.stringify({
          servers: [{ objectId: ID, weight: 255 }],
          threshold: 1,
        })
      )
    ),
    "oversized Seal weighted committee rejected"
  );
  const reviewedDeadIds: string[] = [];
  const reviewedOrphanBlobs: Array<Record<string, string>> = [];
  const evidence = {
    schemaVersion: 5,
    generatedAt: new Date(now - 60_000).toISOString(),
    expiresAt: new Date(now + 10 * 60_000).toISOString(),
    complete: true,
    route: {
      dstPackageId: ID,
      dstRegistryId: ID,
      srcPackageId: ID,
      srcRegistryId: ID,
      dbCutoverRev: "cutover-1",
      manifestRoot: "0x" + "a".repeat(64),
    },
    ...expectedPolicy,
    reviewedSourceInventory: expectedSourceInventory,
    manifestSha256: "b".repeat(64),
    manifestScope: FULL_MANIFEST_SCOPE,
    sourceAuthorityPolicy: MANIFEST_AUTHORITY_POLICY,
    manifestAccountCount: 1,
    manifestDelegateCount: 0,
    audit: {
      sourceLiveCount: 1,
      sourceDeletingCount: 0,
      sourceActiveDeletionBatchCount: 0,
      migrationRowCount: 1,
      destinationOrphanCount: 0,
      reviewedDeadCount: 0,
      reviewedDeadIds,
      reviewedOrphanBlobCount: 0,
      reviewedOrphanBlobs,
      safety: {
        importedAccounts: 1,
        doneMemories: 1,
        deadMemories: 0,
        driftSweptMemories: 0,
      },
      sourceSnapshotSha256: "c".repeat(64),
      sourceAuthoritySnapshotSha256: "e".repeat(64),
      reviewedDeadIdsSha256: createHash("sha256")
        .update(JSON.stringify(reviewedDeadIds))
        .digest("hex"),
      reviewedOrphanBlobsSha256: createHash("sha256")
        .update(JSON.stringify(reviewedOrphanBlobs))
        .digest("hex"),
      destinationSnapshotSha256: "d".repeat(64),
    },
    quietSeconds: 60,
    checks: {
      sourceDbWriteFenceHeld: true,
      destinationDbWriteFenceHeld: true,
      sourceAuthorityCutoffPinned: true,
      sourceInventoryMatchesReviewedCommitment: true,
      sourceSnapshotsStable: true,
      sourceDeletionQueueDrained: true,
      controllerExcluded: true,
      allRowsTerminal: true,
      sourceAndDestinationMatch: true,
      noOrphanedDestinationRows: true,
      strandedReplacementBlobsReviewed: true,
      accountsComplete: true,
      noChainAmbiguity: true,
      noUnsafeUploadJournals: true,
      destinationBlobsLive: true,
      destinationDecryptCanaryVerified: true,
      destinationCanaryOwnerScoped: true,
      walrusUploadRouteMatchesReviewedPolicy: true,
      sealEncryptCommitteeMatchesReviewedPolicy: true,
    },
  };
  const parse = (
    candidate: any,
    route = expectedRoute,
    policy = expectedPolicy,
    sourceInventory = expectedSourceInventory
  ) => {
    const raw = JSON.stringify(candidate, null, 2);
    return parseCompletionEvidence(
      raw,
      createHash("sha256").update(raw).digest("hex"),
      evidence.manifestSha256,
      route,
      policy,
      sourceInventory,
      now
    );
  };
  assert(parse(evidence).accounts === 1n, "fresh evidence accepted");
  const canonicalEvidence = JSON.stringify(evidence, null, 2);
  assert(
    threw(() =>
      parseCompletionEvidence(
        JSON.stringify(evidence),
        createHash("sha256").update(JSON.stringify(evidence)).digest("hex"),
        evidence.manifestSha256,
        expectedRoute,
        expectedPolicy,
        expectedSourceInventory,
        now
      )
    ),
    "non-canonical evidence rejected"
  );
  assert(
    threw(() =>
      parseCompletionEvidence(
        canonicalEvidence,
        "0".repeat(64),
        evidence.manifestSha256,
        expectedRoute,
        expectedPolicy,
        expectedSourceInventory,
        now
      )
    ),
    "unreviewed evidence digest rejected"
  );
  assert(
    threw(() => parse({ ...evidence, unexpected: true })),
    "unknown evidence field rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        audit: { ...evidence.audit, unexpected: true },
      })
    ),
    "unknown audit field rejected"
  );

  // Stranded replacement blobs: the owner is the only party who can delete
  // them, so the finalize digest has to commit to the exact list.
  const strandedOrphan = {
    owner: "0x" + "2".repeat(64),
    blobId: "stranded-blob",
    objectId: "0x" + "3".repeat(64),
    legacyEntryId: "entry-1",
  };
  const withOrphans = (orphans: unknown[]) => ({
    ...evidence,
    audit: {
      ...evidence.audit,
      reviewedOrphanBlobCount: orphans.length,
      reviewedOrphanBlobs: orphans,
      reviewedOrphanBlobsSha256: createHash("sha256")
        .update(JSON.stringify(orphans))
        .digest("hex"),
    },
  });
  assert(
    !threw(() => parse(withOrphans([strandedOrphan]))),
    "reviewed stranded blob accepted"
  );
  assert(
    threw(() =>
      parse({
        ...withOrphans([strandedOrphan]),
        audit: {
          ...withOrphans([strandedOrphan]).audit,
          reviewedOrphanBlobsSha256: "f".repeat(64),
        },
      })
    ),
    "stranded blob list not matching its digest rejected"
  );
  assert(
    threw(() =>
      parse({
        ...withOrphans([strandedOrphan]),
        audit: {
          ...withOrphans([strandedOrphan]).audit,
          reviewedOrphanBlobCount: 2,
        },
      })
    ),
    "stranded blob count disagreeing with the list rejected"
  );
  assert(
    threw(() =>
      parse(withOrphans([{ ...strandedOrphan, objectId: "not-an-id" }]))
    ),
    "stranded blob with a non-canonical object id rejected"
  );
  assert(
    threw(() => parse(withOrphans([{ ...strandedOrphan, extra: true }]))),
    "stranded blob with unknown fields rejected"
  );
  assert(
    threw(() => parse(withOrphans([strandedOrphan, strandedOrphan]))),
    "duplicate stranded blob rejected"
  );
  assert(
    threw(() =>
      parse(
        withOrphans([
          { ...strandedOrphan, blobId: "zzz" },
          { ...strandedOrphan, blobId: "aaa" },
        ])
      )
    ),
    "unsorted stranded blob list rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        checks: { ...evidence.checks, strandedReplacementBlobsReviewed: false },
      })
    ),
    "unreviewed stranded blobs check rejected"
  );
  const duplicateSchemaVersion = canonicalEvidence.replace(
    '  "schemaVersion": 5,',
    '  "schemaVersion": 5,\n  "schemaVersion": 5,'
  );
  assert(
    threw(() =>
      parseCompletionEvidence(
        duplicateSchemaVersion,
        createHash("sha256").update(duplicateSchemaVersion).digest("hex"),
        evidence.manifestSha256,
        expectedRoute,
        expectedPolicy,
        expectedSourceInventory,
        now
      )
    ),
    "duplicate evidence key rejected"
  );
  assert(
    threw(() => parse({ ...evidence, complete: false })),
    "incomplete evidence rejected"
  );
  assert(
    threw(() => parse({ ...evidence, manifestScope: "subset-test" })),
    "subset manifest evidence rejected"
  );
  assert(
    threw(() =>
      parseCompletionEvidence(
        canonicalEvidence,
        createHash("sha256").update(canonicalEvidence).digest("hex"),
        "0".repeat(64),
        expectedRoute,
        expectedPolicy,
        expectedSourceInventory,
        now
      )
    ),
    "unreviewed manifest digest rejected"
  );
  assert(
    threw(() =>
      parse({ ...evidence, sourceAuthorityPolicy: "live-source-v1" })
    ),
    "wrong source authority policy rejected"
  );
  assert(
    threw(() =>
      parse({ ...evidence, expiresAt: new Date(now - 1).toISOString() })
    ),
    "stale evidence rejected"
  );
  assert(
    threw(() =>
      parse(evidence, {
        ...expectedRoute,
        dstPackageId: normalizeSuiAddress("0x2"),
      })
    ),
    "wrong route rejected"
  );
  assert(
    threw(() =>
      parse(evidence, { ...expectedRoute, dbCutoverRev: "cutover-2" })
    ),
    "wrong source revision rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        audit: { ...evidence.audit, sourceDeletingCount: 1 },
      })
    ),
    "in-flight source deletion rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        audit: { ...evidence.audit, destinationOrphanCount: 1 },
      })
    ),
    "orphaned destination row rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        audit: {
          ...evidence.audit,
          safety: { ...evidence.audit.safety, doneMemories: 0 },
        },
      })
    ),
    "inconsistent counts rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        generatedAt: new Date(now + 60_000).toISOString(),
        expiresAt: new Date(now + 30_000).toISOString(),
      })
    ),
    "evidence that expires before generation is rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        walrusUploadRoute: {
          ...evidence.walrusUploadRoute,
          retentionEpochs: 6,
        },
      })
    ),
    "unreviewed Walrus policy rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        sealEncryptCommitteeIdentity: {
          ...evidence.sealEncryptCommitteeIdentity,
          threshold: 2,
        },
      })
    ),
    "unreviewed Seal committee rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        reviewedSourceInventory: {
          ...evidence.reviewedSourceInventory,
          sourceLiveCount: 2,
        },
      })
    ),
    "unreviewed source inventory rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        audit: {
          ...evidence.audit,
          reviewedDeadIds: ["dead-1"],
        },
      })
    ),
    "reviewed-dead list tampering rejected"
  );
  assert(
    threw(() =>
      parse({
        ...evidence,
        audit: {
          ...evidence.audit,
          reviewedDeadCount: 2,
          reviewedDeadIds: ["dead-2", "dead-1"],
          reviewedDeadIdsSha256: createHash("sha256")
            .update(JSON.stringify(["dead-2", "dead-1"]))
            .digest("hex"),
        },
      })
    ),
    "unsorted reviewed-dead list rejected"
  );
  assert(
    threw(() =>
      completionPolicy(
        "mainnet",
        ID,
        14n,
        expectedPolicy.sealEncryptCommitteeIdentity
      )
    ),
    "mainnet retention below 15 rejected"
  );
  assert(
    completionPolicy(
      "mainnet",
      ID,
      15n,
      expectedPolicy.sealEncryptCommitteeIdentity
    ).walrusUploadRoute.retentionEpochs === 15,
    "mainnet 15-epoch retention accepted"
  );
  const tx = new Transaction();
  const parsed = parse(evidence);
  addFinalizeCall(tx, ID, ID, "0x" + "2".repeat(64), parsed);
  bindCompletionExpiration(tx, parsed, "11111111111111111111111111111111", 42n);
  const call: any = tx.getData().commands[0];
  assert(
    call.$kind === "MoveCall" && call.MoveCall.arguments.length === 5,
    "finalize ABI pinned"
  );
  const expiration: any = tx.getData().expiration;
  assert(
    expiration?.$kind === "ValidDuring" &&
      expiration.ValidDuring.minEpoch === "42" &&
      expiration.ValidDuring.maxEpoch === "42" &&
      expiration.ValidDuring.minTimestamp === null &&
      expiration.ValidDuring.maxTimestamp === null,
    "current-epoch validity is embedded in the unsigned transaction"
  );
  console.log("self-test OK");
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});

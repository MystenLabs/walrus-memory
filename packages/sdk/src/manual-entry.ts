/**
 * @mysten-incubation/memwal/manual
 *
 * Manual (client-side) mode entry point.
 * Requires: @mysten/seal, @mysten/sui. Walrus downloads use HTTP, not @mysten/walrus.
 *
 * Usage:
 *   import { MemWalManual } from "@mysten-incubation/memwal/manual";
 */

export { MemWalManual } from "./manual.js";
export {
    MEMWAL_TYPESCRIPT_COMPATIBILITY_VERSION,
    MemWalCompatibilityError,
    SUPPORTED_RELAYER_API_MAJOR,
} from "./compatibility.js";

export type {
    MemWalManualConfig,
    RelayerVersionMetadata,
    SealServerConfig,
    WalletSigner,
    ScoringWeights,
    RememberManualOptions,
    RememberManualResult,
    RecallManualOptions,
    MemWalManualRecallOptions,
    RecallManualHitResult,
    RecallManualMemoryResult,
    RecallManualResult,
    RecallManualHit,
    RecallManualMemory,
    RestoreResult,
    ForgetResult,
} from "./types.js";

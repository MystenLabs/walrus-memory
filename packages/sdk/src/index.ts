/**
 * @mysten-incubation/memwal
 *
 * Privacy-first AI memory SDK.
 * Ed25519 delegate key auth + server-side TEE processing.
 *
 * This is the default entry point — Walrus Memory client + types only.
 * Does NOT import account.js (which requires @mysten/sui).
 *
 * For account management, import from "@mysten-incubation/memwal/account".
 * For manual (client-side SEAL + Walrus), import from "@mysten-incubation/memwal/manual".
 */

// Core client (server-mode: server handles SEAL + Walrus + embedding)
export { MemWal } from "./memwal.js";
// Deterministic, dependency-free in-memory client for tests and CI.
export { MemWalMock } from "./mock.js";
export type { MemWalMockConfig, MemWalMockSeed } from "./mock.js";
export {
    MEMWAL_TYPESCRIPT_COMPATIBILITY_VERSION,
    MemWalCompatibilityError,
    SUPPORTED_RELAYER_API_MAJOR,
} from "./compatibility.js";
// Typed failures for remember-job waits, catchable with `instanceof`. (WALM-615)
export {
    MemWalRateLimitedError,
    MemWalRememberJobFailedError,
    MemWalRememberJobNotFoundError,
    MemWalRememberJobTimeoutError,
    MemWalValidationError,
} from "./errors.js";
export {
    MAX_REMEMBER_TEXT_BYTES,
    validateRemember,
    assertValidRememberText,
} from "./validation.js";
export type {
    SecretPatternKind,
    RememberValidationCode,
    RememberValidationIssue,
    RememberValidationResult,
    ValidateRememberOptions,
} from "./validation.js";

// Delegate key utilities (no @mysten/sui dependency)
export { delegateKeyToSuiAddress, delegateKeyToPublicKey } from "./utils.js";
// Request deadlines. `isTimeoutError` tells a blown budget apart from a
// transport failure; `phase` says which round-trip blew it.
export {
    isTimeoutError,
    DEFAULT_RECALL_TIMEOUT_MS,
    DEFAULT_PREFLIGHT_TIMEOUT_MS,
} from "./utils.js";
export type { TimeoutError } from "./utils.js";
export {
    estimateTokens,
    truncateToTokenBudget,
    applyTokenBudget,
    validateMaxTokens,
    CHARS_PER_TOKEN,
} from "./tokens.js";
export type { TokenCounter } from "./tokens.js";
export {
    createSponsorAuthorization,
    sponsorAuthorizationMessage,
} from "./sponsor-auth.js";
export type {
    SponsorAuthorization,
    SponsorPersonalMessageSigner,
} from "./sponsor-auth.js";

// Types for the default client, including its lightweight manual endpoints.
export type {
    MemWalConfig,
    RememberOptions,
    RememberWaitOptions,
    RememberAcceptedResult,
    RememberJobStatus,
    RememberResult,
    RecallResult,
    RecallMemory,
    RecallOptions,
    RecallParams,
    RecallTokenMeta,
    TruncationStrategy,
    ScoringWeights,
    EmbedResult,
    AnalyzeOptions,
    AnalyzeResult,
    AnalyzeWaitResult,
    AnalyzedFact,
    HealthResult,
    RestoreResult,
    RememberBulkItem,
    RememberBulkOptions,
    RememberBulkAsyncOptions,
    RememberBulkAcceptedResult,
    RememberBulkStatusItem,
    RememberBulkStatusResult,
    RememberBulkResult,
    RememberBulkItemResult,
    RememberManualOptions,
    RememberManualResult,
    RecallManualOptions,
    RecallManualHitResult,
    RecallManualMemoryResult,
    RecallManualResult,
    RecallManualHit,
    MinSupportedSdk,
    RelayerBuildMetadata,
    RelayerDeprecationNotice,
    RelayerVersionMetadata,
    NamespaceSummary,
    NamespacesResult,
    ListNamespacesOptions,
    MemorySummary,
    DeletedMemorySummary,
    MemoriesResult,
    ListMemoriesOptions,
} from "./types.js";

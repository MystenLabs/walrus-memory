/**
 * Local project memory importer for Walrus Memory MCP.
 *
 * Scans allowlisted instruction and rule files in a project,
 * chunks them into provenance-tagged memory candidates,
 * screens for secrets and opt-out markers,
 * and previews or uploads them in batches to Walrus Memory.
 */
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { join, resolve, sep } from "node:path";
import { homedir } from "node:os";
import { getPublicKeyAsync } from "@noble/ed25519";
import { loadCreds } from "./auth.js";
import { bytesToHex, hexToBytes, signMessage } from "./crypto.js";
import { log, note } from "./logger.js";

export interface ImportClient {
    rememberBulk(
        items: Array<{ text: string; namespace: string }>,
        options?: { timeoutMs?: number; signal?: AbortSignal },
    ): Promise<{
        job_ids?: string[];
    }>;
    waitForRememberJobs?(
        jobIds: string[],
        namespaces: string[],
        options?: { timeoutMs?: number; pollIntervalMs?: number; signal?: AbortSignal },
    ): Promise<{
        results: Array<{ id: string; status: string; namespace?: string; error?: string }>;
        total?: number;
        succeeded?: number;
        failed?: number;
    }>;
}

/** Allowlisted project instruction and rule files. */
export const ALLOWED_IMPORT_FILES = [
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "MEMORY.md",
    ".cursorrules",
    ".clinerules",
    ".windsurfrules",
    ".github/copilot-instructions.md",
] as const;

export type AllowedImportFile = (typeof ALLOWED_IMPORT_FILES)[number];

export interface CandidateChunk {
    file: string;
    section: string;
    charCount: number;
    snippet: string;
    text: string;
}

export interface SkippedSection {
    file: string;
    section: string;
    reason: "secret_detected" | "opt_out_marker";
    snippet: string;
}

export interface ImportOptions {
    targetDir?: string;
    dryRun?: boolean;
    yes?: boolean;
    namespace?: string;
    maxItems?: number;
    relayerUrl?: string;
    key?: string;
    accountId?: string;
    client?: ImportClient;
    print?: (msg: string) => void;
}

export interface ImportPreviewResult {
    mode: "preview";
    discoveredFiles: string[];
    candidates: CandidateChunk[];
    skipped: SkippedSection[];
    targetDir: string;
    namespace: string;
}

export interface ImportUploadResult {
    mode: "uploaded";
    discoveredFiles: string[];
    candidates: CandidateChunk[];
    skipped: SkippedSection[];
    targetDir: string;
    namespace: string;
    accepted: number;
    completed: number;
    pending: number;
    failed: number;
    jobIds: string[];
}

export type ImportResult = ImportPreviewResult | ImportUploadResult;

/** Clamp max items to valid range 1..100, defaulting to 20. */
export function clampMaxItems(n: number | undefined): number {
    if (n === undefined || Number.isNaN(n)) return 20;
    if (n < 1) return 1;
    if (n > 100) return 100;
    return Math.floor(n);
}

/** Flatten whitespace and produce a single-line snippet up to maxLen chars. */
export function makeSnippet(text: string, maxLen = 80): string {
    const flattened = text.replace(/\s+/g, " ").trim();
    if (flattened.length <= maxLen) return flattened;
    return flattened.slice(0, maxLen);
}

const OPT_OUT_PATTERNS: RegExp[] = [
    /<\s*private[\s>][\s\S]*?<\s*\/\s*private\s*>/i,
    /<\s*\/?\s*private\s*>/i,
    /\[no-memory\]/i,
    /\bMEMWAL_IGNORE\b/,
    /\b(?:do\s+not|don'?t|dont|never|please\s+do\s+not|please\s+don'?t)\s+(?:save|store|remember|record|keep|persist|log)\s+(?:this|that|it|these|those|any\s+of\s+(?:this|that|it))\b/i,
    /\boff[-\s]the[-\s]record\b/i,
];

/** Check whether text contains any opt-out marker. */
export function hasOptOutMarker(text: string): boolean {
    return OPT_OUT_PATTERNS.some((pattern) => pattern.test(text));
}

const WHOLE_SECTION_OPT_OUT_PATTERNS: RegExp[] = [
    /\[no-memory\]/i,
    /\bMEMWAL_IGNORE\b/,
    /\b(?:do\s+not|don'?t|dont|never|please\s+do\s+not|please\s+don'?t)\s+(?:save|store|remember|record|keep|persist|log)\s+(?:this|that|it|these|those|any\s+of\s+(?:this|that|it))\b/i,
    /\boff[-\s]the[-\s]record\b/i,
];

/** Check whether text contains whole-section / conversational opt-out markers that propagate to child sections. */
export function hasWholeSectionOptOut(text: string): boolean {
    return WHOLE_SECTION_OPT_OUT_PATTERNS.some((pattern) => pattern.test(text));
}

const SECRET_PATTERNS: RegExp[] = [
    // Sui private key (suiprivkey1...)
    /suiprivkey1[0-9a-zA-Z]+/,
    // PEM private key block
    /-----BEGIN [A-Z0-9_\s-]+PRIVATE KEY-----/,
    // Embedded URL credentials (scheme://user:password@host)
    /([A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/)([^\s/@:?=&]+):([^\s/@?=&]+)@/,
    // Standard and vendor API keys
    /\bsk-ant-[A-Za-z0-9_-]{16,}/,
    /\bsk-proj-[A-Za-z0-9_-]{16,}/,
    /\bsk-[0-9a-zA-Z_-]{20,}/,
    /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{20,}/,
    /\bgithub_pat_[0-9a-zA-Z_]{20,}/,
    /\bxox[baprs]-[0-9a-zA-Z-]{10,}/,
    /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    /\bAIza[0-9A-Za-z_-]{35}\b/,
    /\bglpat-[A-Za-z0-9_-]{16,}/,
    /\bnpm_[A-Za-z0-9]{36}\b/,
    /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,
    /\b[sprk]k_(?:live|test)_[A-Za-z0-9]{16,}/,
    /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/,
    /\bdop_v1_[a-f0-9]{64}\b/,
    /\bhf_[A-Za-z0-9]{30,}/,
    // JSON Web Token
    /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
    // Plainly labelled private keys and delegate keys
    /(?:private[\s_-]*key|secret[\s_-]*key|delegate[\s_-]*(?:private[\s_-]*)?key|signing[\s_-]*key|priv[\s_-]*key)\s*[:=]\s*\S+/i,
    /(?:private[\s_-]*key|secret[\s_-]*key|delegate[\s_-]*(?:private[\s_-]*)?key|signing[\s_-]*key|priv[\s_-]*key)\b[^.]{0,48}\b(?:0x)?[0-9a-fA-F]{32,}\b/i,
    /\b(?:0x)?[0-9a-fA-F]{32,}\b[^A-Za-z0-9]{0,8}(?:is|was)?[^A-Za-z0-9]{0,8}(?:my|the|our)?[^A-Za-z0-9]{0,8}(?:delegate[\s_-]*)?(?:private|secret|signing)[\s_-]*key\b/i,
    /\bsui[\s._-]*keystore\b/i,
    // Credential assignments
    /(?:\b|(?<=[a-z0-9_-]))(?:passwords?|passwd|pwd|db[_-]?pass(?:word)?s?|passphrases?|api[_-\s]?keys?|apikeys?|secret[_-\s]?keys?|access[_-\s]?keys?|encryption[_-\s]?keys?|client[_-\s]?secrets?|secrets?|tokens?|access[_-\s]?tokens?|refresh[_-\s]?tokens?|auth[_-\s]?tokens?|bearer[_-\s]?tokens?|session[_-\s]?tokens?|api[_-\s]?tokens?|private[_-\s]?keys?|priv[_-\s]?keys?|delegate[_-\s]?(?:private[_-\s]*)?keys?)["'`]?\s*[:=]\s*(?:["'`](?!\s*["'`])[^"'`\n]{4,}["'`]|(?!(?:string|number|boolean|null|undefined|none|true|false|required|optional)\b)[^\s'",;}{)\]]{4,})/i,
    /\btokens?["'`]?\s*[:=]\s*(?:["'`](?!\s*["'`])[^"'`\n]{4,}["'`]|(?!(?:string|number|boolean|null|undefined|none|true|false|required|optional)\b)[^\s'",;}{)\]]{4,})/i,
    // Auth, bearer, and cookie headers
    /\b(?:(?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|token|digest)?\s*\S+|bearer\s+[A-Za-z0-9._~+/=-]{20,})/i,
    /\b(?:set-)?cookie\s*[:=]\s*[^\s;]+(?:\s*;\s*[^\s;]+)*/i,
    // Seed phrases (including across line breaks after heading or label)
    /(?:\b|(?<=[a-z]))(?:(?:seed|recovery|secret|mnemonic)[\s_-]*(?:phrase|words)|mnemonic)[^A-Za-z0-9]{0,12}(?:is|are)?[^A-Za-z0-9]{0,12}(?:[a-z]{3,8}[\s]+){11,23}[a-z]{3,8}\b/i,
    // .env style secret assignments and plain token assignments
    /\b(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH_TOKEN|SESSION_TOKEN|ACCESS_TOKEN)\s*[:=]\s*\S+/i,
    /\b(?:api_key|secret|token|password|private_key|auth_token|session_token|access_token)\s*[:=]\s*\S+/i,
];

const HEX_RUN = /\b(?:0x)?[0-9a-fA-F]{32,}\b/g;
const OPAQUE_RUN = /[A-Za-z0-9+/_=-]{20,}/g;
const HIGH_ENTROPY_CANDIDATE = /\b[A-Za-z0-9+/_-]{64,}={0,2}/g;
const HEX_LABEL_WINDOW = 128;

const HEX_CREDENTIAL_LABEL =
    /private[\s_-]*key|secret[\s_-]*key|delegate[\s_-]*key|delegate[\s_-]*private|signing[\s_-]*key|priv[\s_-]*key|encryption[\s_-]*keys?(?![A-Za-z0-9])|enc[\s_-]*keys?(?![A-Za-z0-9])|api[\s_-]*key|access[\s_-]*key|auth[\s_-]*key|db[\s_-]*pass(?:word)?s?(?![A-Za-z0-9])|secret|seed|mnemonic|passphrase/i;

const HEX_LABEL_AFTER =
    /^[^A-Za-z0-9]{0,8}(?:is|was)?[^A-Za-z0-9]{0,8}(?:my|the|our|his|her|their)?[^A-Za-z0-9]{0,8}(?:delegate[\s_-]*)?(?:private[\s_-]*key|secret[\s_-]*key|signing[\s_-]*key|priv[\s_-]*key|encryption[\s_-]*keys?(?![A-Za-z0-9])|enc[\s_-]*keys?(?![A-Za-z0-9])|seed|mnemonic|passphrase|api[\s_-]*key|db[\s_-]*pass(?:word)?s?(?![A-Za-z0-9]))/i;

function hasAdjacentCredentialLabel(
    text: string,
    start: number,
    end: number,
    window: number = HEX_LABEL_WINDOW,
): boolean {
    const before = text.slice(Math.max(0, start - window), start);
    if (HEX_CREDENTIAL_LABEL.test(before)) return true;
    const after = text.slice(end, end + window);
    return HEX_LABEL_AFTER.test(after);
}

function looksLikeOpaqueToken(token: string): boolean {
    if (token.length < 20) return false;
    const hasLower = /[a-z]/.test(token);
    const hasUpper = /[A-Z]/.test(token);
    const hasDigit = /[0-9]/.test(token);
    const hasSymbol = /[+/=]/.test(token);
    return (hasLower && hasUpper) || hasDigit || hasSymbol;
}

function looksLikeSecretBlob(token: string): boolean {
    const body = token.replace(/=+$/, "");
    if (body.length < 64) return false;
    if (!/[a-z]/.test(body)) return false;
    if (!/[A-Z]/.test(body)) return false;
    if (!/[0-9]/.test(body)) return false;
    if (/^[0-9a-fA-F]+$/.test(body)) return false;
    return true;
}

function hasLabelledOrHighEntropySecret(text: string): boolean {
    for (const match of text.matchAll(HEX_RUN)) {
        const start = match.index ?? 0;
        const end = start + match[0].length;
        if (hasAdjacentCredentialLabel(text, start, end)) {
            return true;
        }
    }
    for (const match of text.matchAll(OPAQUE_RUN)) {
        const token = match[0];
        if (!looksLikeOpaqueToken(token)) continue;
        const start = match.index ?? 0;
        const end = start + token.length;
        if (hasAdjacentCredentialLabel(text, start, end)) {
            return true;
        }
    }
    for (const match of text.matchAll(HIGH_ENTROPY_CANDIDATE)) {
        if (looksLikeSecretBlob(match[0])) {
            return true;
        }
    }
    return false;
}

/** Screen text for secrets or opt-out markers. */
export function screenContentForSafety(text: string): {
    safe: boolean;
    reason?: "secret_detected" | "opt_out_marker";
} {
    for (const pattern of OPT_OUT_PATTERNS) {
        if (pattern.test(text)) {
            return { safe: false, reason: "opt_out_marker" };
        }
    }
    for (const pattern of SECRET_PATTERNS) {
        if (pattern.test(text)) {
            return { safe: false, reason: "secret_detected" };
        }
    }
    if (hasLabelledOrHighEntropySecret(text)) {
        return { safe: false, reason: "secret_detected" };
    }
    return { safe: true };
}

/** Discover allowlisted files in targetDir with path containment verification. */
export function discoverImportFiles(targetDir: string): { realRoot: string; files: string[] } {
    const resolvedTarget = resolve(targetDir);
    if (!existsSync(resolvedTarget)) {
        throw new Error(`Target directory does not exist: ${resolvedTarget}`);
    }
    const realRoot = realpathSync(resolvedTarget);
    const rootStat = statSync(realRoot);
    if (!rootStat.isDirectory()) {
        throw new Error(`Target path is not a directory: ${realRoot}`);
    }

    const discovered: string[] = [];
    const rootPrefix = realRoot.endsWith(sep) ? realRoot : realRoot + sep;

    for (const relPath of ALLOWED_IMPORT_FILES) {
        const fullCandidatePath = join(realRoot, relPath);
        if (!existsSync(fullCandidatePath)) {
            continue;
        }

        try {
            const lstat = lstatSync(fullCandidatePath);
            if (lstat.isDirectory()) {
                continue;
            }

            const realFile = realpathSync(fullCandidatePath);
            if (!realFile.startsWith(rootPrefix)) {
                log.warn("import.symlink_escape_refused", {
                    file: relPath,
                    target: realFile,
                    root: realRoot,
                });
                continue;
            }

            const realStat = statSync(realFile);
            if (!realStat.isFile()) {
                continue;
            }

            discovered.push(relPath);
        } catch {
            continue;
        }
    }

    return { realRoot, files: discovered };
}

export interface RawSection {
    heading: string;
    content: string;
    inheritedOptOut?: boolean;
    optOutSource?: string;
    ancestors?: string[];
}

function countPrivateTags(text: string): { openings: number; closings: number } {
    const openMatches = text.match(/<\s*private(?:\s[^>]*)?>/gi);
    const closeMatches = text.match(/<\s*\/\s*private\s*>/gi);
    return {
        openings: openMatches ? openMatches.length : 0,
        closings: closeMatches ? closeMatches.length : 0,
    };
}

function linesContainPrivate(lines: string[]): boolean {
    for (const l of lines) {
        if (/<\s*private(?:\s[^>]*)?>/i.test(l) || /<\s*\/\s*private\s*>/i.test(l)) {
            return true;
        }
    }
    return false;
}

export function parseSections(content: string, relPath: string): RawSection[] {
    const lines = content.split(/\r?\n/);
    const sections: RawSection[] = [];
    const fallbackHeading = relPath.startsWith(".") ? "Rules" : "General";

    let currentHeading = "";
    let currentLines: string[] = [];
    let currentOptedOut = false;
    let sectionInPrivate = false;
    let sectionHasBodyOptOut = false;
    let sectionStartedInPrivate = false;
    let currentAncestors: string[] = [];

    // Heading ancestor stack: levels 1 through 6
    const headingStack: Array<{ level: number; heading: string; optedOut: boolean }> = [];
    let privateDepth = 0;

    // Fenced code block tracking (``` or ~~~)
    let inCodeFence = false;
    let codeFenceChar: string | null = null;
    let codeFenceLen = 0;

    const headingRegex = /^(#{1,6})\s+(.+)$/;
    const fenceRegex = /^\s*(`{3,}|~{3,})/;

    function flushCurrentSection(): void {
        if (currentLines.length > 0 || currentHeading) {
            const text = currentLines.join("\n").trim();
            if (text) {
                const isOptedOut = currentOptedOut || (privateDepth > 0 && sectionStartedInPrivate);
                sections.push({
                    heading: currentHeading || fallbackHeading,
                    content: text,
                    inheritedOptOut: isOptedOut,
                    ancestors: [...currentAncestors],
                });
            }
        }
    }

    for (const line of lines) {
        // Check for fenced code block toggle
        const fenceMatch = line.match(fenceRegex);
        if (fenceMatch) {
            const char = fenceMatch[1][0];
            const len = fenceMatch[1].length;
            if (!inCodeFence) {
                inCodeFence = true;
                codeFenceChar = char;
                codeFenceLen = len;
            } else if (char === codeFenceChar && len >= codeFenceLen) {
                inCodeFence = false;
                codeFenceChar = null;
                codeFenceLen = 0;
            }
            currentLines.push(line);
            continue;
        }

        // Inside fenced code blocks, lines are literal content:
        // never parse headings or count tags/opt-out markers inside code fences!
        if (inCodeFence) {
            currentLines.push(line);
            continue;
        }

        // Outside code fences, check for markdown ATX headings
        const headingMatch = line.match(headingRegex);
        if (headingMatch) {
            // Before flushing previous section on a new heading:
            // if previous section's accumulated lines contain a whole-section opt-out marker,
            // mark the top entry of headingStack (if any) as optedOut = true!
            if (sectionHasBodyOptOut || hasWholeSectionOptOut(currentLines.join("\n"))) {
                if (headingStack.length > 0) {
                    headingStack[headingStack.length - 1].optedOut = true;
                }
                currentOptedOut = true;
            }

            // Check if trailing lines before this heading are standalone <private> tags
            // intended to open private scope for the upcoming heading/block.
            let pendingPrivateOpenings = 0;
            while (
                currentLines.length > 0 &&
                currentLines[currentLines.length - 1].trim() === ""
            ) {
                currentLines.pop();
            }
            while (
                currentLines.length > 0 &&
                /^\s*<\s*private(?:\s[^>]*)?>\s*$/i.test(currentLines[currentLines.length - 1])
            ) {
                currentLines.pop();
                pendingPrivateOpenings++;
                while (
                    currentLines.length > 0 &&
                    currentLines[currentLines.length - 1].trim() === ""
                ) {
                    currentLines.pop();
                }
            }

            if (pendingPrivateOpenings > 0) {
                if (!sectionStartedInPrivate && !linesContainPrivate(currentLines)) {
                    sectionInPrivate = false;
                }
            }

            if (currentHeading || currentLines.some((l) => l.trim().length > 0)) {
                flushCurrentSection();
            }

            const level = headingMatch[1].length;
            const headingText = headingMatch[2].trim();

            // Pop entries from headingStack while top level >= current level
            while (headingStack.length > 0 && headingStack[headingStack.length - 1].level >= level) {
                headingStack.pop();
            }

            // Current ancestors are the surviving headings in stack:
            currentAncestors = headingStack.map((h) => h.heading);

            // Check self and parent opt-out
            const selfOptOut = hasWholeSectionOptOut(headingText) || hasOptOutMarker(headingText) || privateDepth > 0;
            const parentOptOut = headingStack.some((h) => h.optedOut);
            const headingOptedOut = selfOptOut || parentOptOut;

            headingStack.push({
                level,
                heading: headingText,
                optedOut: headingOptedOut,
            });

            // Update privateDepth if headingText opens or closes <private>
            const headingTags = countPrivateTags(headingText);
            let headingTouchesPrivate = false;
            if (headingTags.openings > 0 || headingTags.closings > 0) {
                headingTouchesPrivate = true;
                privateDepth += headingTags.openings;
                privateDepth = Math.max(0, privateDepth - headingTags.closings);
            }

            currentHeading = headingText;
            currentOptedOut = headingOptedOut;
            currentLines = [];
            sectionStartedInPrivate = privateDepth > 0;
            sectionInPrivate = privateDepth > 0 || headingTouchesPrivate;
            sectionHasBodyOptOut = false;
        } else {
            // Normal line outside code fence
            if (privateDepth > 0) {
                sectionInPrivate = true;
            }
            const lineTags = countPrivateTags(line);
            if (lineTags.openings > 0 || lineTags.closings > 0) {
                sectionInPrivate = true;
                privateDepth += lineTags.openings;
                privateDepth = Math.max(0, privateDepth - lineTags.closings);
            }
            if (privateDepth > 0) {
                sectionInPrivate = true;
            }
            if (hasWholeSectionOptOut(line)) {
                sectionHasBodyOptOut = true;
            }
            currentLines.push(line);
        }
    }

    // EOF: check body opt-out on final section
    if (sectionHasBodyOptOut || hasWholeSectionOptOut(currentLines.join("\n"))) {
        if (headingStack.length > 0) {
            headingStack[headingStack.length - 1].optedOut = true;
        }
        currentOptedOut = true;
    }

    flushCurrentSection();

    if (sections.length === 0 && content.trim()) {
        const isOptedOut =
            hasOptOutMarker(content) || sectionInPrivate || sectionHasBodyOptOut;
        sections.push({
            heading: fallbackHeading,
            content: content.trim(),
            inheritedOptOut: isOptedOut,
            ancestors: [],
        });
    }

    return sections;
}

function splitIntoParagraphs(text: string, maxChars = 1500): string[] {
    const paragraphs = text
        .split(/\n\s*\n+/)
        .map((p) => p.trim())
        .filter(Boolean);
    const chunks: string[] = [];
    let currentChunk = "";

    for (const para of paragraphs) {
        if (!currentChunk) {
            if (para.length > maxChars) {
                const lines = para
                    .split(/\n+/)
                    .map((l) => l.trim())
                    .filter(Boolean);
                let lineChunk = "";
                for (const line of lines) {
                    if (!lineChunk) {
                        lineChunk = line;
                    } else if (lineChunk.length + 1 + line.length <= maxChars) {
                        lineChunk += "\n" + line;
                    } else {
                        chunks.push(lineChunk);
                        lineChunk = line;
                    }
                }
                if (lineChunk) {
                    currentChunk = lineChunk;
                }
            } else {
                currentChunk = para;
            }
        } else if (currentChunk.length + 2 + para.length <= maxChars) {
            currentChunk += "\n\n" + para;
        } else {
            chunks.push(currentChunk);
            currentChunk = para;
        }
    }
    if (currentChunk) {
        chunks.push(currentChunk);
    }
    return chunks;
}

/** Extract chunks and screen for safety from file content. */
export function extractCandidateChunks(
    content: string,
    relPath: string,
): { candidates: CandidateChunk[]; skipped: SkippedSection[] } {
    const rawSections = parseSections(content, relPath);
    const candidates: CandidateChunk[] = [];
    const skipped: SkippedSection[] = [];

    for (const section of rawSections) {
        if (section.inheritedOptOut) {
            skipped.push({
                file: relPath,
                section: section.heading,
                reason: "opt_out_marker",
                snippet: makeSnippet(section.content || section.heading),
            });
            continue;
        }

        // 1. Screen all ancestor headings
        let ancestorFailed = false;
        if (section.ancestors && section.ancestors.length > 0) {
            for (const anc of section.ancestors) {
                const ancSafety = screenContentForSafety(anc);
                if (!ancSafety.safe) {
                    skipped.push({
                        file: relPath,
                        section: section.heading,
                        reason: ancSafety.reason!,
                        snippet: makeSnippet(anc),
                    });
                    ancestorFailed = true;
                    break;
                }
            }
        }
        if (ancestorFailed) {
            continue;
        }

        const headingSafety = screenContentForSafety(section.heading);
        if (!headingSafety.safe) {
            skipped.push({
                file: relPath,
                section: section.heading,
                reason: headingSafety.reason!,
                snippet: makeSnippet(section.heading),
            });
            continue;
        }

        // Strip scoped <private>...</private> blocks from content
        let contentToProcess = section.content;
        if (/<\s*private[\s>]/i.test(contentToProcess)) {
            contentToProcess = contentToProcess.replace(/<\s*private[\s>][\s\S]*?<\s*\/\s*private\s*>/gi, "").trim();
        }
        if (!contentToProcess) {
            skipped.push({
                file: relPath,
                section: section.heading,
                reason: "opt_out_marker",
                snippet: makeSnippet(section.content),
            });
            continue;
        }

        const safety = screenContentForSafety(contentToProcess);
        if (!safety.safe) {
            skipped.push({
                file: relPath,
                section: section.heading,
                reason: safety.reason!,
                snippet: makeSnippet(contentToProcess),
            });
            continue;
        }

        const fullHierarchyHeading = section.ancestors && section.ancestors.length > 0
            ? [...section.ancestors, section.heading].join("\n")
            : section.heading;

        const combinedSectionSafety = screenContentForSafety(`${fullHierarchyHeading}\n${contentToProcess}`);
        if (!combinedSectionSafety.safe) {
            skipped.push({
                file: relPath,
                section: section.heading,
                reason: combinedSectionSafety.reason!,
                snippet: makeSnippet(contentToProcess),
            });
            continue;
        }

        // Check if any ancestor heading contains a credential label
        const ancestorHasCredentialLabel = section.ancestors?.some((anc) =>
            HEX_CREDENTIAL_LABEL.test(anc) || /(?:private|secret|signing|priv|delegate)[\s_-]*key/i.test(anc)
        );
        if (ancestorHasCredentialLabel) {
            let foundSecretInChild = false;
            for (const match of contentToProcess.matchAll(HEX_RUN)) {
                skipped.push({
                    file: relPath,
                    section: section.heading,
                    reason: "secret_detected",
                    snippet: makeSnippet(contentToProcess),
                });
                foundSecretInChild = true;
                break;
            }
            if (foundSecretInChild) {
                continue;
            }
        }

        const subChunks = splitIntoParagraphs(contentToProcess, 1500);
        for (const sub of subChunks) {
            const trimmed = sub.trim();
            if (trimmed.length < 20) {
                continue;
            }
            const subSafety = screenContentForSafety(trimmed);
            if (!subSafety.safe) {
                skipped.push({
                    file: relPath,
                    section: section.heading,
                    reason: subSafety.reason!,
                    snippet: makeSnippet(trimmed),
                });
                continue;
            }

            const combinedSubSafety = screenContentForSafety(`${fullHierarchyHeading}\n${trimmed}`);
            if (!combinedSubSafety.safe) {
                skipped.push({
                    file: relPath,
                    section: section.heading,
                    reason: combinedSubSafety.reason!,
                    snippet: makeSnippet(trimmed),
                });
                continue;
            }

            if (ancestorHasCredentialLabel) {
                let foundSecretInSub = false;
                for (const match of trimmed.matchAll(HEX_RUN)) {
                    skipped.push({
                        file: relPath,
                        section: section.heading,
                        reason: "secret_detected",
                        snippet: makeSnippet(trimmed),
                    });
                    foundSecretInSub = true;
                    break;
                }
                if (foundSecretInSub) {
                    continue;
                }
            }

            const provenanceText = `[source: ${relPath} | section: ${section.heading}]\n${trimmed}`;
            const provenanceSafety = screenContentForSafety(provenanceText);
            if (!provenanceSafety.safe) {
                skipped.push({
                    file: relPath,
                    section: section.heading,
                    reason: provenanceSafety.reason!,
                    snippet: makeSnippet(provenanceText),
                });
                continue;
            }

            candidates.push({
                file: relPath,
                section: section.heading,
                charCount: provenanceText.length,
                snippet: makeSnippet(trimmed),
                text: provenanceText,
            });
        }
    }

    return { candidates, skipped };
}

function loadConfigJson(): { key?: string; accountId?: string; serverUrl?: string } | null {
    try {
        const configPath = join(homedir(), ".memwal", "config.json");
        if (existsSync(configPath)) {
            const parsed = JSON.parse(readFileSync(configPath, "utf8"));
            if (typeof parsed === "object" && parsed !== null) {
                return {
                    key: parsed.key ?? parsed.delegatePrivateKey ?? parsed.privateKey,
                    accountId: parsed.accountId ?? parsed.account_id,
                    serverUrl: parsed.serverUrl ?? parsed.relayerUrl ?? parsed.server_url,
                };
            }
        }
    } catch {
        // Ignore unreadable config
    }
    return null;
}

export function createSignedRelayerClient(params: {
    key: string;
    accountId: string;
    serverUrl: string;
}): ImportClient {
    const baseUrl = params.serverUrl.replace(/\/+$/, "");
    let pubKeyHexPromise: Promise<string> | null = null;

    async function getPublicKeyHex(): Promise<string> {
        if (!pubKeyHexPromise) {
            pubKeyHexPromise = getPublicKeyAsync(hexToBytes(params.key)).then(bytesToHex);
        }
        return pubKeyHexPromise;
    }

    async function signedPost<T>(
        path: string,
        payload: unknown,
        options: { timeoutMs?: number; signal?: AbortSignal } = {},
    ): Promise<T> {
        const bodyStr = JSON.stringify(payload);
        const bodyHash = createHash("sha256").update(bodyStr, "utf8").digest("hex");
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const nonce = randomUUID();
        const canonical = `${timestamp}.POST.${path}.${bodyHash}.${nonce}.${params.accountId}`;
        const signature = await signMessage(params.key, canonical);
        const publicKeyHex = await getPublicKeyHex();

        const signals: AbortSignal[] = [];
        if (options.signal) signals.push(options.signal);
        if (typeof options.timeoutMs === "number" && options.timeoutMs > 0) {
            signals.push(AbortSignal.timeout(options.timeoutMs));
        }
        const effectiveSignal =
            signals.length === 1 ? signals[0] : signals.length > 1 ? AbortSignal.any(signals) : undefined;

        const resp = await fetch(`${baseUrl}${path}`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                "x-public-key": publicKeyHex,
                "x-signature": signature,
                "x-timestamp": timestamp,
                "x-nonce": nonce,
                "x-account-id": params.accountId,
            },
            body: bodyStr,
            signal: effectiveSignal,
        });

        const text = await resp.text();
        if (!resp.ok) {
            throw new Error(`Relayer ${path} failed (${resp.status}): ${text}`);
        }
        return JSON.parse(text) as T;
    }

    return {
        async rememberBulk(items, options = {}) {
            // Keep acceptance deadlines separate so ambiguous writes are not blindly retried
            const timeoutMs = options.timeoutMs ?? 30_000;
            return signedPost<{ job_ids?: string[] }>(
                "/api/remember/bulk",
                { items },
                { timeoutMs, signal: options.signal },
            );
        },
        async waitForRememberJobs(jobIds, namespaces, options = {}) {
            const timeoutMs = options.timeoutMs ?? 60_000;
            const pollIntervalMs = options.pollIntervalMs ?? 1000;
            const deadline = Date.now() + timeoutMs;
            const latest = new Map<string, { id: string; status: string; namespace?: string; error?: string }>();
            for (let i = 0; i < jobIds.length; i++) {
                latest.set(jobIds[i], { id: jobIds[i], status: "pending", namespace: namespaces[i] });
            }

            while (Date.now() < deadline) {
                const remainingBudget = deadline - Date.now();
                if (remainingBudget <= 0) break;

                const pendingIds = jobIds.filter((id) => {
                    const st = latest.get(id)?.status;
                    return st !== "done" && st !== "failed";
                });
                if (pendingIds.length === 0) break;

                try {
                    const statusResp = await signedPost<{
                        results?: Array<{ job_id?: string; id?: string; status: string; error?: string }>;
                        jobs?: Array<{ job_id?: string; id?: string; status: string; error?: string }>;
                    }>(
                        "/api/remember/bulk/status",
                        { job_ids: pendingIds },
                        { timeoutMs: remainingBudget, signal: options.signal },
                    );

                    const rawList = statusResp.results ?? statusResp.jobs ?? [];
                    for (const job of rawList) {
                        const id = job.job_id ?? job.id;
                        if (id && latest.has(id)) {
                            const prev = latest.get(id)!;
                            latest.set(id, { ...prev, status: job.status, error: job.error });
                        }
                    }
                } catch (err: any) {
                    if (Date.now() >= deadline || err?.name === "TimeoutError" || err?.name === "AbortError") {
                        break;
                    }
                }

                const stillPending = jobIds.some((id) => {
                    const st = latest.get(id)?.status;
                    return st !== "done" && st !== "failed";
                });
                if (!stillPending) break;

                const nextSleep = Math.min(pollIntervalMs, Math.max(0, deadline - Date.now()));
                if (nextSleep <= 0) break;
                await new Promise((r) => setTimeout(r, nextSleep));
            }

            return {
                results: jobIds.map((id) => latest.get(id)!),
            };
        },
    };
}

/** Execute import in preview mode or confirmed upload mode. */
export async function importProjectMemories(options: ImportOptions = {}): Promise<ImportResult> {
    const targetDir = options.targetDir ?? process.cwd();
    const { realRoot, files: discoveredFiles } = discoverImportFiles(targetDir);
    const namespace = options.namespace ?? process.env.MEMWAL_NAMESPACE ?? "default";
    const maxItems = clampMaxItems(options.maxItems);
    const dryRun = options.dryRun ?? false;
    const isYes = options.yes ?? false;
    const print = options.print ?? note;

    const allCandidates: CandidateChunk[] = [];
    const allSkipped: SkippedSection[] = [];

    for (const relPath of discoveredFiles) {
        const fullPath = join(realRoot, relPath);
        const content = readFileSync(fullPath, "utf8");
        const { candidates, skipped } = extractCandidateChunks(content, relPath);
        allCandidates.push(...candidates);
        allSkipped.push(...skipped);
    }

    const candidates = allCandidates.slice(0, maxItems);

    if (!isYes || dryRun) {
        print("Local project memory import preview:");
        print(`  Project root: ${realRoot}`);
        print(`  Namespace:    ${namespace}`);
        print(`  Discovered:   ${discoveredFiles.length} file(s) (${discoveredFiles.join(", ")})`);
        print(`  Candidates:   ${candidates.length} chunk(s)`);
        print("");

        candidates.forEach((c, idx) => {
            print(`[${idx + 1}] ${c.file} | section: ${c.section} (${c.charCount} chars)`);
            print(`    "${c.snippet}"`);
        });

        if (allSkipped.length > 0) {
            print("");
            const secretCount = allSkipped.filter((s) => s.reason === "secret_detected").length;
            const optOutCount = allSkipped.filter((s) => s.reason === "opt_out_marker").length;
            print(
                `Skipped ${allSkipped.length} section(s) for safety: ` +
                    `${secretCount} secret(s), ${optOutCount} opt-out marker(s).`,
            );
        }

        print("");
        print(`Run with --yes to upload these ${candidates.length} memory chunks to Walrus Memory.`);

        return {
            mode: "preview",
            discoveredFiles,
            candidates,
            skipped: allSkipped,
            targetDir: realRoot,
            namespace,
        };
    }

    let client = options.client;
    if (!client) {
        const savedCreds = loadCreds();
        const savedConfig = loadConfigJson();

        const key =
            options.key ??
            process.env.MEMWAL_PRIVATE_KEY ??
            savedCreds?.delegatePrivateKey ??
            savedConfig?.key;
        const accountId =
            options.accountId ??
            process.env.MEMWAL_ACCOUNT_ID ??
            savedCreds?.accountId ??
            savedConfig?.accountId;
        const serverUrl =
            options.relayerUrl ??
            process.env.MEMWAL_SERVER_URL ??
            savedCreds?.relayerUrl ??
            savedConfig?.serverUrl ??
            "https://relayer.memory.walrus.xyz";

        if (!key || !accountId) {
            const missingMsg =
                "Credentials required for upload. Please run memwal-mcp login first, " +
                "or set MEMWAL_PRIVATE_KEY and MEMWAL_ACCOUNT_ID.";
            print(`Error: ${missingMsg}`);
            throw new Error(missingMsg);
        }

        log.info("import.target_relayer", {
            relayerUrl: serverUrl,
            accountId,
        });

        client = createSignedRelayerClient({
            key,
            accountId,
            serverUrl,
        });
    }

    print(`Uploading ${candidates.length} memory chunk(s) to Walrus Memory (namespace: ${namespace})...`);

    const batchSize = 20;
    let accepted = 0;
    let completed = 0;
    let pending = 0;
    let failed = 0;
    const allJobIds: string[] = [];

    for (let i = 0; i < candidates.length; i += batchSize) {
        const batch = candidates.slice(i, i + batchSize);
        const items = batch.map((c) => ({
            text: c.text,
            namespace,
        }));

        const acceptedResult = await client.rememberBulk(items);
        const jobIds = acceptedResult?.job_ids ?? [];
        accepted += jobIds.length;
        allJobIds.push(...jobIds);

        if (typeof (client as any).waitForRememberJobs === "function" && jobIds.length > 0) {
            try {
                const waitResult = await (client as any).waitForRememberJobs(
                    jobIds,
                    items.map((it) => it.namespace),
                    { timeoutMs: 60_000, pollIntervalMs: 1000 },
                );
                if (waitResult && Array.isArray(waitResult.results)) {
                    for (const res of waitResult.results) {
                        if (res.status === "done") {
                            completed++;
                        } else if (res.status === "failed") {
                            failed++;
                        } else {
                            pending++;
                        }
                    }
                } else {
                    pending += jobIds.length;
                }
            } catch {
                pending += jobIds.length;
            }
        } else {
            pending += jobIds.length;
        }
    }

    print("Upload outcome:");
    print(`  Accepted:  ${accepted}`);
    print(`  Completed: ${completed}`);
    print(`  Pending:   ${pending}`);
    print(`  Failed:    ${failed}`);

    return {
        mode: "uploaded",
        discoveredFiles,
        candidates,
        skipped: allSkipped,
        targetDir: realRoot,
        namespace,
        accepted,
        completed,
        pending,
        failed,
        jobIds: allJobIds,
    };
}

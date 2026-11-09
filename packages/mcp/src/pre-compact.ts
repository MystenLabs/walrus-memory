/**
 * Synchronous pre-compaction memory extraction and save.
 *
 * Runs before Claude Code compacts conversation context. Claude Code passes
 * { session_id, transcript_path, cwd, hook_event_name: "PreCompact", trigger, custom_instructions }
 * on stdin to `on_pre_compact.mjs` and waits synchronously for the hook to exit 0.
 *
 * This module:
 * 1. Checks that automatic saving is enabled (both settings.json and auto-save-state.json).
 * 2. Resolves credentials safely (respecting repository project approvals).
 * 3. Safely reads newly appended lines in transcript_path using an incremental byte watermark.
 * 4. Extracts plain text from user and assistant turns (excluding tool_use, tool_result, thinking).
 * 5. Filters out opt-out markers ([no-memory], MEMWAL_IGNORE, <private>...</private>) and slash commands.
 * 6. Redacts secrets (private keys, bearer tokens, API keys, URLs with credentials, assignments).
 * 7. Sends a signed POST /api/analyze request to the relayer.
 * 8. Advances the watermark only upon HTTP 2xx success.
 */
import { createHash, randomUUID } from "node:crypto";
import {
    existsSync,
    lstatSync,
    openSync,
    readSync,
    closeSync,
    writeSync,
    chmodSync,
    mkdirSync,
    statSync,
    constants,
    readFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadCreds, type MemWalCredentials } from "./auth.js";
import { autoSaveStatus, hookStatePath, parseBooleanSetting } from "./auto-save.js";
import { signMessage } from "./crypto.js";
import { log } from "./logger.js";

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;
const O_NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const MAX_EXCERPT_BYTES = 24_000;
const MIN_CLEAN_TEXT_LENGTH = 40;

export interface PreCompactInput {
    session_id?: string;
    transcript_path?: string;
    cwd?: string;
    hook_event_name?: string;
    trigger?: string;
    custom_instructions?: string | null;
}

export interface PreCompactResult {
    saved: boolean;
    reason?:
        | "auto_save_disabled"
        | "no_credentials"
        | "no_transcript"
        | "transcript_invalid"
        | "nothing_to_save"
        | "request_failed";
    bytesAnalyzed?: number;
    error?: string;
}

/** Check if automatic saving is enabled across both auto-save.ts and auto-save-state.json. */
export function isPreCompactAutoSaveEnabled(): boolean {
    const envVal = parseBooleanSetting(process.env.MEMWAL_AUTO_SAVE);
    if (envVal === false) return false;

    // Check published auto-save-state.json if it exists
    try {
        const publishedPath = hookStatePath();
        if (existsSync(publishedPath)) {
            const raw = readFileSync(publishedPath, "utf8");
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed.enabled === "boolean" && !parsed.enabled) {
                return false;
            }
        }
    } catch {
        return false;
    }

    // Check src/auto-save.ts resolution (settings.json / legacy / pending)
    const status = autoSaveStatus();
    if (!status.enabled) return false;

    return true;
}

/** Resolve credentials for pre-compaction, respecting repository project approval. */
export function resolvePreCompactCreds(cwd?: string): {
    creds: MemWalCredentials;
    baseUrl: string;
} | null {
    let creds: MemWalCredentials | null = null;
    const targetCwd =
        cwd && typeof cwd === "string" && existsSync(cwd) && statSync(cwd).isDirectory()
            ? cwd
            : null;

    if (targetCwd) {
        const origCwd = process.cwd();
        try {
            process.chdir(targetCwd);
            creds = loadCreds();
        } catch {
            creds = null;
        } finally {
            try {
                process.chdir(origCwd);
            } catch {
                /* ignore */
            }
        }
    } else {
        try {
            creds = loadCreds();
        } catch {
            creds = null;
        }
    }

    if (!creds || !creds.delegatePrivateKey || !creds.delegatePublicKeyHex || !creds.accountId) {
        return null;
    }

    const baseUrl = (process.env.MEMWAL_SERVER_URL || creds.relayerUrl || "").replace(/\/+$/, "");
    if (!baseUrl) {
        return null;
    }

    return { creds, baseUrl };
}

/** State directory for hook watermarks. */
export function getHookStateDir(): string | null {
    const base = join(process.env.TMPDIR || tmpdir(), "memwal-hooks");
    try {
        mkdirSync(base, { recursive: true, mode: DIR_MODE });
    } catch {
        /* best effort */
    }
    try {
        const st = lstatSync(base);
        if (!st.isDirectory()) return null;
        if (typeof process.getuid === "function") {
            if (st.uid !== process.getuid()) return null;
            if (st.mode & 0o077) chmodSync(base, DIR_MODE);
        }
        return base;
    } catch {
        return null;
    }
}

function safeSessionKey(sessionId?: string): string {
    return String(sessionId || "default")
        .replace(/[^a-zA-Z0-9_-]/g, "_")
        .slice(0, 64);
}

const memoryWatermarks = new Map<string, number>();

export function getWatermark(dir: string | null, safeId: string): number {
    if (!dir) return memoryWatermarks.get(safeId) ?? 0;
    const filePath = join(dir, `precompact_offset_${safeId}`);
    try {
        const st = lstatSync(filePath);
        if (!st.isFile()) return 0;
        const fd = openSync(filePath, constants.O_RDONLY | O_NOFOLLOW);
        try {
            const buf = Buffer.alloc(64);
            const bytesRead = readSync(fd, buf, 0, 64, 0);
            const str = buf.toString("utf8", 0, bytesRead).trim();
            const val = parseInt(str, 10);
            return Number.isFinite(val) && val >= 0 ? val : 0;
        } finally {
            closeSync(fd);
        }
    } catch {
        return 0;
    }
}

export function setWatermark(dir: string | null, safeId: string, offset: number): void {
    if (!dir) {
        memoryWatermarks.set(safeId, offset);
        return;
    }
    const filePath = join(dir, `precompact_offset_${safeId}`);
    try {
        const fd = openSync(
            filePath,
            constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | O_NOFOLLOW,
            FILE_MODE
        );
        try {
            const data = Buffer.from(String(offset), "utf8");
            writeSync(fd, data, 0, data.length, 0);
        } finally {
            closeSync(fd);
        }
    } catch {
        memoryWatermarks.set(safeId, offset);
    }
}

interface TranscriptTurn {
    role: "user" | "assistant";
    text: string;
}

/** Parse one JSONL line from a Claude Code transcript. */
export function parseTranscriptLine(line: string): TranscriptTurn | null {
    const trimmed = line.trim();
    if (!trimmed) return null;
    let obj: any;
    try {
        obj = JSON.parse(trimmed);
    } catch {
        return null;
    }

    if (!obj || typeof obj !== "object") return null;

    let roleStr: string | undefined;
    if (obj.type === "user" || obj.type === "assistant") {
        roleStr = obj.type;
    } else if (obj.role === "user" || obj.role === "assistant") {
        roleStr = obj.role;
    }

    if (obj.message && typeof obj.message === "object") {
        if (obj.message.role === "user" || obj.message.role === "assistant") {
            roleStr = obj.message.role;
        }
    }

    if (roleStr !== "user" && roleStr !== "assistant") {
        return null;
    }

    const rawContent = obj.message?.content ?? obj.content ?? obj.text;
    const textParts: string[] = [];

    if (typeof rawContent === "string") {
        textParts.push(rawContent);
    } else if (Array.isArray(rawContent)) {
        for (const block of rawContent) {
            if (!block || typeof block !== "object") continue;
            // Explicitly skip tool calls, tool outputs, and reasoning
            if (block.type === "tool_use" || block.type === "tool_result" || block.type === "thinking") {
                continue;
            }
            if (block.type === "text" && typeof block.text === "string") {
                textParts.push(block.text);
            } else if (!block.type && typeof block.text === "string") {
                textParts.push(block.text);
            }
        }
    }

    const combinedText = textParts.join("\n").trim();
    if (!combinedText) return null;

    return { role: roleStr as "user" | "assistant", text: combinedText };
}

/** Redact credentials, secrets, tokens, private keys, and connection URLs. */
export function redactSecrets(input: string): string {
    let s = input;

    // 1. PEM private key blocks (closed and open-ended)
    s = s.replace(
        /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
        "[redacted:private-key]"
    );
    s = s.replace(
        /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*/g,
        "[redacted:private-key]"
    );

    // 2. Sui private key
    s = s.replace(/\bsuiprivkey1[0-9a-z]{40,}\b/gi, "[redacted:sui-private-key]");

    // 3. Authorization / Cookie headers and Bearer tokens
    s = s.replace(
        /\b((?:proxy-)?authorization)(\s*[:=]\s*)(?:bearer|basic|token|digest)?\s*\S+/gi,
        "$1$2[redacted:auth-header]"
    );
    s = s.replace(
        /\b((?:set-)?cookie)(\s*[:=]\s*)[^\s;]+(?:\s*;\s*[^\s;]+)*/gi,
        "$1$2[redacted:auth-header]"
    );
    s = s.replace(
        /\bBearer\s+[A-Za-z0-9_\-\.]{16,}\b/gi,
        "Bearer [redacted:token]"
    );

    // 4. Connection URLs with user:pass (postgres://, mongodb://, redis://, etc.)
    s = s.replace(
        /([A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/)([^\s/@:?=&]+):([^\s/@?=&]+)@/g,
        "$1[redacted:url-credentials]@"
    );

    // 5. Vendor API keys
    const vendorPatterns = [
        /\bsk-ant-[A-Za-z0-9_-]{16,}/g, // Anthropic
        /\bsk-proj-[A-Za-z0-9_-]{16,}/g, // OpenAI project
        /\bsk-[A-Za-z0-9]{20,}/g, // OpenAI classic
        /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/g, // GitHub
        /\bgithub_pat_[A-Za-z0-9_]{20,}/g, // GitHub fine-grained
        /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, // AWS access key id
        /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, // Slack
        /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google API
        /\bglpat-[A-Za-z0-9_-]{16,}/g, // GitLab
        /\bnpm_[A-Za-z0-9]{36}\b/g, // npm
        /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, // SendGrid
        /\b[sprk]k_(?:live|test)_[A-Za-z0-9]{16,}/g, // Stripe
        /\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b/g, // Shopify
        /\bdop_v1_[a-f0-9]{64}\b/g, // DigitalOcean
        /\bhf_[A-Za-z0-9]{30,}\b/g, // Hugging Face
    ];
    for (const pat of vendorPatterns) {
        s = s.replace(pat, "[redacted:api-key]");
    }

    // 6. JWT tokens
    s = s.replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[redacted:jwt]");

    // 7. KEY/SECRET/TOKEN/PASSWORD=... assignments
    s = s.replace(
        /(?:\b|(?<=[a-z0-9_-]))(passwords?|passwd|pwd|db[_-]?pass(?:word)?s?|passphrases?|api[_-]?keys?|apikeys?|secret[_-]?keys?|access[_-]?keys?|encryption[_-]?keys?|enc[_-]?keys?|client[_-]?secrets?|secrets?|access[_-]?tokens?|refresh[_-]?tokens?|auth[_-]?tokens?|bearer[_-]?tokens?|tokens?|priv(?:ate)?[_-]?keys?|credentials?)(["'`]?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s,;]+)/gi,
        "$1$2[redacted:credential]"
    );

    // 8. Plainly labelled private keys, delegate keys, or hex keys in prose / markdown
    const HEX_CREDENTIAL_LABEL_BEFORE =
        /(?:(?:#+\s*|\b|(?<=[_*`]))(?:(?:my|the|our|his|her|their)\s+)?(?:(?:delegate[\s_-]*)?(?:private|secret|signing|priv|encryption|enc)[\s_-]*key|delegate[\s_-]*key)(?:s)?(?![A-Za-z0-9])|sui[\s._-]*keystore)/i;
    const HEX_CREDENTIAL_LABEL_AFTER =
        /^[^A-Za-z0-9]{0,16}(?:is|was)?[^A-Za-z0-9]{0,16}(?:my|the|our|his|her|their)?[^A-Za-z0-9]{0,16}(?:(?:delegate[\s_-]*)?(?:private|secret|signing|priv|encryption)[\s_-]*key|delegate[\s_-]*key|seed|mnemonic|passphrase)/i;

    const HEX_CANDIDATE = /(?:`|'|")?\b(?:0x)?[0-9a-fA-F]{32,}\b(?:`|'|")?/g;
    s = s.replace(HEX_CANDIDATE, (match, offset, fullStr) => {
        const windowSize = 80;
        const before = fullStr.slice(Math.max(0, offset - windowSize), offset);
        if (HEX_CREDENTIAL_LABEL_BEFORE.test(before)) {
            return "[redacted:private-key]";
        }
        const after = fullStr.slice(offset + match.length, offset + match.length + windowSize);
        if (HEX_CREDENTIAL_LABEL_AFTER.test(after)) {
            return "[redacted:private-key]";
        }
        return match;
    });

    // 9. Labelled seed / recovery mnemonic phrases (including across line breaks / headings)
    s = s.replace(
        /(?:\b|(?<=[a-z#*_`]))((?:(?:#+\s*)?(?:seed|recovery|secret|mnemonic)[\s_-]*(?:phrase|words)|mnemonic))([^A-Za-z0-9]{0,16}(?:is|are)?[^A-Za-z0-9]{0,16})((?:[a-z]{3,8}[ \t\r\n]+){11,23}[a-z]{3,8})\b/gi,
        "$1$2[redacted:seed-phrase]"
    );

    return s;
}

const CLAUSE_IMPERATIVE_PREFIX =
    "(?:^|[.!?;:,(\\[\\n]\\s*|\\b(?:please|just)\\s+|\\byou\\s+(?:must\\s+|should\\s+|can\\s+)?)";

const IMPERATIVE_NEGATION_PREFIX =
    "(?:^|[.!?;:,(\\[\\n]\\s*|\\b(?:and|but|please|just)\\s+|\\byou\\s+(?:must\\s+|should\\s+|can\\s+)?)";

/** Conversational opt-out patterns that instruct the assistant not to persist the turn. */
export const CONVERSATIONAL_OPT_OUT_PATTERNS: RegExp[] = [
    new RegExp(
        `${CLAUSE_IMPERATIVE_PREFIX}(?:do\\s+not|don['\\u2019]?t|never)\\s+(?:ever\\s+)?(?:remember|memorize)(?:\\s+or\\s+(?:save|store|record|capture|keep|persist))?\\b`,
        "i"
    ),
    new RegExp(
        `${IMPERATIVE_NEGATION_PREFIX}(?:do\\s+not|don['\\u2019]?t|never)\\s+(?:ever\\s+)?(?:remember|memorize)(?:\\s+or\\s+(?:save|store|record|capture|keep|persist)\\b|\\s+(?:any(?:\\s+of)?(?:\\s+(?:this|that|these|those|it))?|anything(?:\\s+(?:here|from\\s+this))?|this|that|these|those|it|the\\s+following\\b|(?:in|to)\\s+memory|the\\s+(?:conversation|chat|message|turn|discussion|note|notes|details))\\b)`,
        "i"
    ),
    new RegExp(
        `${IMPERATIVE_NEGATION_PREFIX}(?:do\\s+not|don['\\u2019]?t|never)\\s+(?:ever\\s+)?(?:save|store|record|capture|keep|persist)(?:\\s+or\\s+(?:remember|memorize|save|store|record|capture|keep|persist))?(?:\\s+(?:any(?:\\s+of)?(?:\\s+(?:this|that|these|those|it))?|anything(?:\\s+(?:here|from\\s+this))?|this|that|these|those|it|what\\s+i|where\\s+i|who\\s+i|how\\s+i|my\\b|our\\b|the\\s+following\\b|(?:in|to)\\s+memory|the\\s+(?:conversation|chat|message|turn|discussion|note|notes|details))\\b|(?=\\s*(?:$|[.!?:;,)\\]])))`,
        "i"
    ),
    new RegExp(
        `${IMPERATIVE_NEGATION_PREFIX}(?:do\\s+not|don['\\u2019]?t|never)\\s+(?:ever\\s+)?log\\s+(?:this(?:\\s+(?:conversation|message|chat|turn|session))?|anything\\s+(?:here|from\\s+this)|our\\s+(?:conversation|chat))\\b`,
        "i"
    ),
    /\b(?:off\s+the\s+record|(?:do\s+not|don['\u2019]?t|never)\s+keep\s+(?:this\s+|that\s+|it\s+)?in\s+memory|(?:please\s+)?forget\s+(?:this(?:\s+(?:conversation|message|chat|turn))?|what\s+i\s+just\s+said))\b/i,
    /(?:^|\s)(?:\[\s*no[-_\s]?save\s*\]|#no[-_]?save\b|\[\s*no[-_\s]?memory\s*\]|#no[-_]?memory\b|\bMEMWAL_IGNORE\b)/i,
];

export function hasConversationalOptOut(text: string): boolean {
    if (!text) return false;
    return CONVERSATIONAL_OPT_OUT_PATTERNS.some((pat) => pat.test(text));
}

/** Check if text contains explicit opt-out directives or markers. */
export function isOptOutTurn(text: string): boolean {
    if (!text) return false;
    if (hasConversationalOptOut(text)) return true;
    if (/(?:^|\s)(?:\[\s*no[-_\s]?(?:memory|save)\s*\]|#no[-_]?(?:memory|save)\b|\bMEMWAL_IGNORE\b)/i.test(text)) return true;
    return false;
}

/** Check if text contains private blocks or credentials/secrets. */
export function containsSensitiveContent(text: string): boolean {
    if (!text) return false;
    if (/<private>/i.test(text)) return true;
    if (redactSecrets(text) !== text) return true;
    return false;
}

function hasSalvageableContent(text: string): boolean {
    const withoutPlaceholders = text.replace(/\[redacted:[a-z-]+\]/g, " ");
    const words = withoutPlaceholders.match(/[\p{L}\p{N}]{2,}/gu) ?? [];
    return words.length >= 3;
}

/** Clean, filter opt-out markers, and format a turn. Returns null if skipped. */
export function cleanAndFilterTurn(turn: TranscriptTurn): string | null {
    let text = turn.text;

    // Screen each message/block for opt-out markers:
    if (/\[no-memory\]/i.test(text) || /MEMWAL_IGNORE/i.test(text) || hasConversationalOptOut(text)) {
        return null;
    }

    // Check for unclosed <private>
    const openPrivateCount = (text.match(/<private>/gi) || []).length;
    const closePrivateCount = (text.match(/<\/private>/gi) || []).length;
    if (openPrivateCount !== closePrivateCount) {
        return null;
    }

    // Strip <private>...</private> blocks
    text = text.replace(/<private>[\s\S]*?<\/private>/gi, "");

    // Strip system reminders
    text = text.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/gi, "");

    // Skip slash commands
    if (/^\s*\/(compact|clear|help|model|cost|summary)\b/i.test(text)) {
        return null;
    }

    // Redact secrets
    const beforeRedact = text;
    text = redactSecrets(text);
    if (text !== beforeRedact && !hasSalvageableContent(text)) {
        return null;
    }

    text = text.trim();
    if (!text) return null;

    const prefix = turn.role === "user" ? "User: " : "Assistant: ";
    return `${prefix}${text}`;
}

/** Cap string to the most recent maxBytes UTF-8 bytes without splitting characters. */
export function capUtf8BytesFromEnd(str: string, maxBytes: number): string {
    const buf = Buffer.from(str, "utf8");
    if (buf.length <= maxBytes) return str;

    let sliceStart = buf.length - maxBytes;
    while (sliceStart < buf.length && (buf[sliceStart] & 0xc0) === 0x80) {
        sliceStart++;
    }
    const truncatedBuf = buf.subarray(sliceStart);
    let result = truncatedBuf.toString("utf8");

    // If slice cut mid-turn, skip forward to the next turn boundary
    const firstNewline = result.indexOf("\n\n");
    if (firstNewline !== -1 && firstNewline < 400) {
        result = result.slice(firstNewline + 2);
    }
    return result;
}

/**
 * Execute the synchronous pre-compaction save.
 */
export async function runPreCompactSave(input: PreCompactInput): Promise<PreCompactResult> {
    // 1. Verify automatic saving is enabled
    if (!isPreCompactAutoSaveEnabled()) {
        return { saved: false, reason: "auto_save_disabled" };
    }

    // 2. Validate transcript path
    if (!input.transcript_path || typeof input.transcript_path !== "string") {
        return { saved: false, reason: "no_transcript" };
    }

    let st;
    try {
        st = lstatSync(input.transcript_path);
    } catch {
        return { saved: false, reason: "no_transcript" };
    }

    if (!st.isFile()) {
        return { saved: false, reason: "transcript_invalid" };
    }

    // 3. Resolve credentials
    const credsResult = resolvePreCompactCreds(input.cwd);
    if (!credsResult) {
        return { saved: false, reason: "no_credentials" };
    }
    const { creds, baseUrl } = credsResult;

    // 4. Determine incremental byte offset
    const stateDir = getHookStateDir();
    const safeId = safeSessionKey(input.session_id);
    const fileSize = st.size;
    let startOffset = getWatermark(stateDir, safeId);

    // If file shrank, reset offset to 0
    if (startOffset > fileSize) {
        startOffset = 0;
    }

    // Nothing new appended
    if (startOffset === fileSize) {
        return { saved: false, reason: "nothing_to_save" };
    }

    // Read newly appended bytes
    const bytesToRead = fileSize - startOffset;
    let rawChunk = "";
    try {
        const fd = openSync(input.transcript_path, constants.O_RDONLY | O_NOFOLLOW);
        try {
            const buf = Buffer.alloc(bytesToRead);
            let totalRead = 0;
            while (totalRead < bytesToRead) {
                const r = readSync(fd, buf, totalRead, bytesToRead - totalRead, startOffset + totalRead);
                if (r === 0) break;
                totalRead += r;
            }
            rawChunk = buf.toString("utf8", 0, totalRead);
        } finally {
            closeSync(fd);
        }
    } catch (err) {
        return { saved: false, reason: "transcript_invalid", error: String(err) };
    }

    // 5. Parse turns and filter
    const lines = rawChunk.split("\n");
    const formattedTurns: string[] = [];
    let userTurnOptedOut = false;
    let suppressAssistantEcho = false;

    for (const line of lines) {
        const turn = parseTranscriptLine(line);
        if (!turn) continue;

        if (turn.role === "user") {
            userTurnOptedOut = isOptOutTurn(turn.text);
            suppressAssistantEcho = userTurnOptedOut || containsSensitiveContent(turn.text);
        }

        if (userTurnOptedOut) {
            continue;
        }

        if (turn.role === "assistant" && suppressAssistantEcho) {
            continue;
        }

        const cleaned = cleanAndFilterTurn(turn);
        if (cleaned) {
            formattedTurns.push(cleaned);
        }
    }

    if (formattedTurns.length === 0) {
        return { saved: false, reason: "nothing_to_save" };
    }

    let excerpt = formattedTurns.join("\n\n");
    excerpt = capUtf8BytesFromEnd(excerpt, MAX_EXCERPT_BYTES);

    if (excerpt.trim().length < MIN_CLEAN_TEXT_LENGTH) {
        return { saved: false, reason: "nothing_to_save" };
    }

    // 6. Sign and send POST /api/analyze
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonce = randomUUID();
    const path = "/api/analyze";
    const method = "POST";
    const bodyObj = {
        text: excerpt,
        namespace: process.env.MEMWAL_NAMESPACE || "default",
    };
    const bodyStr = JSON.stringify(bodyObj);
    const bodyHash = createHash("sha256").update(bodyStr).digest("hex");
    const canonical = `${timestamp}.${method}.${path}.${bodyHash}.${nonce}.${creds.accountId}`;

    let signature: string;
    try {
        signature = await signMessage(creds.delegatePrivateKey, canonical);
    } catch (err) {
        return { saved: false, reason: "request_failed", error: `Signing failed: ${err}` };
    }

    const timeoutMs = parseInt(process.env.MEMWAL_PRECOMPACT_TIMEOUT_MS || "5500", 10);
    const signal = AbortSignal.timeout(Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 5500);

    try {
        const resp = await fetch(`${baseUrl}${path}`, {
            method,
            headers: {
                "content-type": "application/json",
                "x-public-key": creds.delegatePublicKeyHex.toLowerCase(),
                "x-signature": signature.toLowerCase(),
                "x-timestamp": timestamp,
                "x-nonce": nonce,
                "x-account-id": creds.accountId,
            },
            body: bodyStr,
            signal,
        });

        if (resp.ok) {
            // Only advance watermark when request succeeds!
            setWatermark(stateDir, safeId, fileSize);
            return {
                saved: true,
                bytesAnalyzed: Buffer.byteLength(excerpt, "utf8"),
            };
        }

        return {
            saved: false,
            reason: "request_failed",
            error: `HTTP ${resp.status}`,
        };
    } catch (err) {
        log.debug("precompact.analyze_failed", { error: String(err) });
        return {
            saved: false,
            reason: "request_failed",
            error: String(err),
        };
    }
}

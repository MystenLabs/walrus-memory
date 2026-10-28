/**
 * Walrus Memory — Write-Path Input Validation & Secret Screening (#435)
 *
 * Synchronous, offline validator shared by `MemWal`, `MemWalMock`, and callers
 * that want a preflight / dry-run check before signing or persisting text to
 * append-only Walrus storage.
 *
 * Pattern parity with `services/server/scripts/mcp/tools/redaction.ts`:
 * - Enforces non-blank / non-zero-width text and `MAX_REMEMBER_TEXT_BYTES` (1 MiB)
 * - Detects URL credentials, vendor API keys (including `suiprivkey1...`),
 *   PEM private key blocks, JWTs, credential assignments, auth/cookie headers,
 *   labelled seed phrases, labelled hex/opaque key material (including
 *   `delegatePrivateKey` and `sui.keystore`), and high-entropy secret blobs
 * - Leaves legitimate MemWal identifiers (Sui `0x` + 64 hex addresses/object IDs,
 *   Walrus 43-char base64url blob IDs, 40-hex git SHAs, SHA-256 digests) untouched
 */

import { MemWalValidationError } from "./errors.js";

/** Maximum UTF-8 byte length accepted by `/api/remember` (1 MiB). */
export const MAX_REMEMBER_TEXT_BYTES = 1_048_576;

export type SecretPatternKind =
    | "url-credentials"
    | "vendor-api-key"
    | "private-key-block"
    | "jwt"
    | "credential-assignment"
    | "auth-header"
    | "seed-phrase"
    | "labelled-key-material"
    | "high-entropy-secret";

export type RememberValidationCode =
    | "empty_text"
    | "text_too_long"
    | "secret_pattern_detected";

export interface RememberValidationIssue {
    code: RememberValidationCode;
    kind?: SecretPatternKind;
    message: string;
}

export interface RememberValidationResult {
    valid: boolean;
    byteLength: number;
    issues: RememberValidationIssue[];
    kinds: SecretPatternKind[];
    sanitizedText: string;
}

export interface ValidateRememberOptions {
    /** When true, secret patterns do not mark the validation result invalid. */
    allowSecrets?: boolean;
    /** Alias for `allowSecrets`. */
    skipValidation?: boolean;
}

const ZERO_WIDTH_ONLY = /^[\s\u200B-\u200D\u2060\uFEFF]*$/;

function placeholder(kind: SecretPatternKind): string {
    return `[redacted:${kind}]`;
}

const PEM_CLOSED =
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const PEM_OPEN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*/g;

const URL_USERINFO =
    /([A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/)([^\s/@:?=&]+):([^\s/@?=&]+)@/g;

const AUTH_HEADER =
    /\b((?:proxy-)?authorization)(\s*[:=]\s*)(?:bearer|basic|token|digest)?\s*\S+/gi;
const COOKIE_HEADER =
    /\b((?:set-)?cookie)(\s*[:=]\s*)[^\s;]+(?:\s*;\s*[^\s;]+)*/gi;

const CREDENTIAL_ASSIGNMENT =
    /(?:\b|(?<=[a-z0-9_-]))(passwords?|passwd|pwd|db[_-]?pass(?:word)?s?|passphrases?|api[_-]?keys?|apikeys?|secret[_-]?keys?|access[_-]?keys?|encryption[_-]?keys?|enc[_-]?keys?|client[_-]?secrets?|secrets?|access[_-]?tokens?|refresh[_-]?tokens?|auth[_-]?tokens?|bearer[_-]?tokens?|tokens?|priv(?:ate)?[_-]?keys?|credentials?)(["'`]?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s,;]+)/gi;

const VENDOR_KEYS: RegExp[] = [
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
    /\b(?:suiprivkey1[0-9a-z]{16,}|SUIPRIVKEY1[0-9A-Z]{16,})\b/g, // Sui bech32 private key (#435)
];

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

const SEED_PHRASE =
    /(?:\b|(?<=[a-z]))((?:seed|recovery|secret|mnemonic)[\s_-]*(?:phrase|words)|mnemonic)([^A-Za-z0-9]{0,4}(?:is|are)?[^A-Za-z0-9]{0,4})((?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8})\b/gi;

const HEX_RUN = /\b(?:0x)?[0-9a-fA-F]{32,}\b/g;
const HEX_LABEL_WINDOW = 48;

const HEX_CREDENTIAL_LABEL =
    /private[\s_-]*key|secret[\s_-]*key|delegate[\s_-]*key|delegate[\s_-]*private|signing[\s_-]*key|priv[\s_-]*key|sui[\s._-]*keystore|encryption[\s_-]*keys?(?![A-Za-z0-9])|enc[\s_-]*keys?(?![A-Za-z0-9])|api[\s_-]*key|access[\s_-]*key|auth[\s_-]*key|db[\s_-]*pass(?:word)?s?(?![A-Za-z0-9])|secret|seed|mnemonic|passphrase/i;

const HEX_LABEL_AFTER =
    /^[^A-Za-z0-9]{0,4}(?:is|was)?[^A-Za-z0-9]{0,4}(?:my|the|our|his|her|their)?[^A-Za-z0-9]{0,4}(?:delegate[\s_-]*)?(?:private[\s_-]*key|secret[\s_-]*key|priv[\s_-]*key|sui[\s._-]*keystore|encryption[\s_-]*keys?(?![A-Za-z0-9])|enc[\s_-]*keys?(?![A-Za-z0-9])|seed|mnemonic|passphrase|api[\s_-]*key|db[\s_-]*pass(?:word)?s?(?![A-Za-z0-9]))/i;

const PLACEHOLDER_RUN = /\[redacted:[a-z-]+\]/g;

function isInsidePlaceholder(text: string, start: number): boolean {
    const before = text.slice(Math.max(0, start - 10), start);
    return /\[redacted:$/.test(before);
}

function hasAdjacentCredentialLabel(
    text: string,
    start: number,
    end: number,
    window: number = HEX_LABEL_WINDOW,
): boolean {
    const before = text
        .slice(Math.max(0, start - window), start)
        .replace(PLACEHOLDER_RUN, " ");
    if (HEX_CREDENTIAL_LABEL.test(before)) return true;
    return HEX_LABEL_AFTER.test(
        text.slice(end, end + HEX_LABEL_WINDOW).replace(PLACEHOLDER_RUN, " "),
    );
}

const OPAQUE_RUN = /[A-Za-z0-9+/_=-]{20,}/g;

function looksLikeOpaqueToken(token: string): boolean {
    if (token.length < 20) return false;
    const hasLower = /[a-z]/.test(token);
    const hasUpper = /[A-Z]/.test(token);
    const hasDigit = /[0-9]/.test(token);
    const hasSymbol = /[+/=]/.test(token);
    return (hasLower && hasUpper) || hasDigit || hasSymbol;
}

const HIGH_ENTROPY_CANDIDATE = /\b[A-Za-z0-9+/_-]{64,}={0,2}/g;

function looksLikeSecretBlob(token: string): boolean {
    const body = token.replace(/=+$/, "");
    if (body.length < 64) return false;
    if (!/[a-z]/.test(body)) return false;
    if (!/[A-Z]/.test(body)) return false;
    if (!/[0-9]/.test(body)) return false;
    if (/^[0-9a-fA-F]+$/.test(body)) return false;
    return true;
}

function scanSecrets(original: string): {
    sanitizedText: string;
    kinds: SecretPatternKind[];
} {
    const kinds: SecretPatternKind[] = [];
    const hit = (kind: SecretPatternKind) => {
        if (!kinds.includes(kind)) kinds.push(kind);
        return placeholder(kind);
    };

    let text = original;

    text = text.replace(PEM_CLOSED, () => hit("private-key-block"));
    text = text.replace(PEM_OPEN, () => hit("private-key-block"));

    text = text.replace(URL_USERINFO, (_m, scheme: string) => {
        hit("url-credentials");
        return `${scheme}${placeholder("url-credentials")}@`;
    });

    text = text.replace(AUTH_HEADER, (_m, name: string, sep: string) => {
        hit("auth-header");
        return `${name}${sep}${placeholder("auth-header")}`;
    });
    text = text.replace(COOKIE_HEADER, (_m, name: string, sep: string) => {
        hit("auth-header");
        return `${name}${sep}${placeholder("auth-header")}`;
    });

    text = text.replace(CREDENTIAL_ASSIGNMENT, (_m, key: string, sep: string) => {
        hit("credential-assignment");
        return `${key}${sep}${placeholder("credential-assignment")}`;
    });

    for (const pattern of VENDOR_KEYS) {
        text = text.replace(pattern, () => hit("vendor-api-key"));
    }

    text = text.replace(JWT, () => hit("jwt"));

    text = text.replace(SEED_PHRASE, (_m, label: string, sep: string) => {
        hit("seed-phrase");
        return `${label}${sep}${placeholder("seed-phrase")}`;
    });

    text = text.replace(HEX_RUN, (match: string, offset: number, whole: string) =>
        hasAdjacentCredentialLabel(whole, offset, offset + match.length)
            ? hit("labelled-key-material")
            : match,
    );

    text = text.replace(OPAQUE_RUN, (match: string, offset: number, whole: string) => {
        if (isInsidePlaceholder(whole, offset)) return match;
        if (!looksLikeOpaqueToken(match)) return match;
        return hasAdjacentCredentialLabel(whole, offset, offset + match.length)
            ? hit("labelled-key-material")
            : match;
    });

    text = text.replace(HIGH_ENTROPY_CANDIDATE, (token: string) =>
        looksLikeSecretBlob(token) ? hit("high-entropy-secret") : token,
    );

    if (kinds.length > 0) {
        text = text.replace(/[ \t]{2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim();
    }

    return { sanitizedText: text, kinds };
}

/**
 * Validate memory text locally without opening a socket or contacting the relayer.
 *
 * Checks:
 * - `empty_text`: non-string, empty, whitespace-only, or zero-width-only text
 * - `text_too_long`: UTF-8 byte length exceeds `MAX_REMEMBER_TEXT_BYTES` (1 MiB)
 * - `secret_pattern_detected`: high-confidence credential patterns (unless
 *   `{ allowSecrets: true }` or `{ skipValidation: true }` is passed)
 */
export function validateRemember(
    text: string,
    options: ValidateRememberOptions = {},
): RememberValidationResult {
    if (typeof text !== "string") {
        return {
            valid: false,
            byteLength: 0,
            issues: [
                {
                    code: "empty_text",
                    message: "text must be a non-empty string",
                },
            ],
            kinds: [],
            sanitizedText: "",
        };
    }

    const byteLength = new TextEncoder().encode(text).length;
    const issues: RememberValidationIssue[] = [];

    if (text.trim().length === 0 || ZERO_WIDTH_ONLY.test(text)) {
        issues.push({
            code: "empty_text",
            message: "text cannot be empty",
        });
    }

    if (byteLength > MAX_REMEMBER_TEXT_BYTES) {
        issues.push({
            code: "text_too_long",
            message: `text exceeds maximum length of ${MAX_REMEMBER_TEXT_BYTES} bytes (got ${byteLength} bytes)`,
        });
    }

    // Cap secret scan input to MAX_REMEMBER_TEXT_BYTES so multi-MiB inputs stay fast.
    const scanInput =
        text.length > MAX_REMEMBER_TEXT_BYTES
            ? text.slice(0, MAX_REMEMBER_TEXT_BYTES)
            : text;
    const { sanitizedText, kinds } = scanSecrets(scanInput);

    const allowSecrets = options.allowSecrets === true || options.skipValidation === true;
    if (!allowSecrets) {
        for (const kind of kinds) {
            issues.push({
                code: "secret_pattern_detected",
                kind,
                message: `detected potential secret (${kind}) in memory text`,
            });
        }
    }

    return {
        valid: issues.length === 0,
        byteLength,
        issues,
        kinds,
        sanitizedText,
    };
}

/**
 * Enforce `MAX_REMEMBER_TEXT_BYTES` and default secret-pattern rejection on the
 * SDK write path (`remember`, `rememberAsync`, `rememberAndWait`, `rememberBulk*`).
 */
export function assertValidRememberText(
    text: string,
    options: ValidateRememberOptions = {},
    field = "text",
): RememberValidationResult {
    const result = validateRemember(text, options);
    const lengthIssue = result.issues.find((i) => i.code === "text_too_long");
    if (lengthIssue) {
        throw new MemWalValidationError(
            `${field} exceeds maximum length of ${MAX_REMEMBER_TEXT_BYTES} bytes (got ${result.byteLength} bytes)`,
            "text_too_long",
            result.issues,
            result.kinds,
        );
    }
    const secretIssue = result.issues.find((i) => i.code === "secret_pattern_detected");
    if (secretIssue) {
        throw new MemWalValidationError(
            `${field} contains detected secret pattern(s) (${result.kinds.join(", ")}); remove the credential before storing or pass { allowSecrets: true } if intentional`,
            "secret_pattern_detected",
            result.issues,
            result.kinds,
        );
    }
    return result;
}

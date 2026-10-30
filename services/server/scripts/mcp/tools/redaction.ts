/**
 * Credential redaction for the memory write path (WALM-642).
 *
 * Every tool that forwards free text to the SDK — `memwal_remember`,
 * `memwal_remember_bulk`, `memwal_analyze` — runs its input through
 * `sanitizeFact` FIRST. The model-facing rules in `memory-policy.ts` are
 * guidance; this module is the backstop that does not depend on a model having
 * read them. Walrus storage is append-only and immutable: a secret that reaches
 * it cannot be deleted, so the check has to sit in front of the write rather
 * than behind it.
 *
 * Two shapes of answer:
 *
 *   - REDACT (the common case, and what the ticket asks for): a message that
 *     mixes a durable preference with a credential keeps the preference and
 *     loses only the credential span, replaced by `[redacted:<kind>]`. Dropping
 *     the whole fact would lose the thing the user actually wanted stored.
 *   - REFUSE: nothing safe is left, the user said not to save it, or the text
 *     is plainly pasted third-party material. The caller forwards nothing.
 *
 * ── False positives, deliberately ───────────────────────────────────────────
 * The patterns below are SHAPE-based, not entropy-based. That is a choice, and
 * it costs recall:
 *
 *   - There is no free-standing "long random-looking string" rule. MemWal's own
 *     durable facts are exactly that shape — Walrus blob ids (43-char
 *     base64url), Sui object and account ids (`0x` + 64 hex), git SHAs (40 hex),
 *     content digests. A generic high-entropy rule would redact the product's
 *     primary nouns. The one entropy rule that survived
 *     (`HIGH_ENTROPY_SECRET`) demands ≥64 characters AND mixed case AND a
 *     digit, which excludes every one of those (all-lowercase hex, or shorter),
 *     while still catching a raw base64 key blob.
 *   - `password:`-style assignments redact whatever follows the separator, so
 *     "password: ask Marta" loses "ask Marta". Over-redacting a sentence about
 *     a credential is cheap; under-redacting the credential is permanent.
 *   - Hex key material is caught by the LABEL next to it, never by its shape —
 *     see `HEX_RUN`. That is what lets MemWal's own 64-hex delegate private key
 *     be removed while a bare 40-hex commit SHA or a `0x`-prefixed Sui object id
 *     is left alone. The cost is that a hex secret pasted with no label at all
 *     still passes; the model-facing rules are what cover that.
 *   - Quoted-content detection only fires on unambiguous pastes (a fenced
 *     block, a multi-line `>` quotation, or a ≥200-char fully quoted passage).
 *     A short quoted sentence is left to the model-facing rules, because an
 *     agent legitimately quotes the user's own words back when saving a fact.
 *
 * Nothing here logs, echoes, or returns the matched secret. Callers get the
 * redacted text and the KINDS that were removed — never the values.
 */

export type RedactionKind =
    | "url-credentials"
    | "vendor-api-key"
    | "private-key-block"
    | "jwt"
    | "credential-assignment"
    | "auth-header"
    | "seed-phrase"
    | "labelled-key-material"
    | "high-entropy-secret";

/** Why a text was refused outright instead of redacted. */
export type RefusalReason =
    /** The user said not to save it. */
    | "no-save-directive"
    /** After redaction there was no fact left — the text was only a secret. */
    | "credential-only"
    /** Pasted third-party material, not a fact about this user. */
    | "pasted-content";

export interface SanitizedText {
    /** Text safe to forward. Empty when `refusal` is set. */
    text: string;
    /** True when the text was changed or refused. */
    changed: boolean;
    /** Kinds removed, first-seen order. Never contains a secret value. */
    kinds: RedactionKind[];
    /** Number of spans replaced. */
    count: number;
    /** Set when the caller must forward nothing at all. */
    refusal?: RefusalReason;
}

function placeholder(kind: RedactionKind): string {
    return `[redacted:${kind}]`;
}

/**
 * An explicit instruction not to save, from the user.
 *
 * Deliberately demands a demonstrative object ("this", "that", "it"): without
 * it, "remember that I don't save screenshots to the Desktop" — a perfectly
 * good durable preference — would be refused as a do-not-save directive.
 */
const NO_SAVE_DIRECTIVE =
    /\b(?:do\s+not|don'?t|dont|never|please\s+do\s+not|please\s+don'?t)\s+(?:save|store|remember|record|keep|persist|log)\s+(?:this|that|it|these|those|any\s+of\s+(?:this|that|it))\b/i;

/** The idiom, which carries the same instruction without naming saving. */
const OFF_THE_RECORD = /\boff[-\s]the[-\s]record\b/i;

/**
 * PEM private key blocks. The second pattern is not redundant: a paste that was
 * cut off mid-key has a BEGIN line and no END line, and without the open-ended
 * form the key body would survive untouched.
 */
const PEM_CLOSED =
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const PEM_OPEN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*/g;

/**
 * `scheme://user:password@host` — the exact shape in the WALM-642 repro, and
 * the shape of every connection string that carries its own credentials
 * (`postgres://`, `mongodb+srv://`, `amqp://`, `redis://`, ...).
 *
 * Only the userinfo is replaced: scheme, host, port and path are the part of a
 * connection string worth remembering.
 *
 * Two bounds on this pattern, both load-bearing:
 *
 *   - The scheme repeat is CAPPED. Unbounded (`[A-Za-z0-9+.-]*`) it had to be
 *     tried and abandoned at every start offset, which is quadratic in the
 *     input: 30 KB took 317 ms, 60 KB 1254 ms and 120 KB 4814 ms on one core.
 *     `memwal_analyze` forwards a whole transcript and the sidecar is
 *     single-threaded, so a long paste was a stall for every other caller, not
 *     just for itself. 30 characters is longer than any registered scheme.
 *   - The userinfo groups exclude `?`, `=` and `&`, not just `/` and
 *     whitespace. Without that,
 *     `https://app.example.com:8443?owner=alice@corp.com` matched with
 *     `app.example.com` as the user and `8443?owner=alice` as the password:
 *     the host and port were destroyed, `corp.com` was promoted to hostname,
 *     the mangled fact was written to append-only storage, and the result told
 *     the agent a credential had been removed when there was none. A query
 *     string cannot appear before the userinfo in a real URL, so excluding
 *     them costs nothing but a password that literally contains one.
 */
const URL_USERINFO =
    /([A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/)([^\s/@:?=&]+):([^\s/@?=&]+)@/g;

/**
 * Authorization / cookie headers, value dropped, header name kept.
 *
 * The cookie value stops at whitespace rather than at the end of the line, and
 * then continues across `;`-separated pairs. A real header (`Cookie: a=1; b=2`)
 * is matched whole; a header quoted mid-sentence loses the cookie and not the
 * rest of the sentence. Cookie values are token-shaped by spec, so the only
 * thing this gives up is a value that contains a raw space — which is not
 * legal in one anyway.
 */
const AUTH_HEADER =
    /\b((?:proxy-)?authorization)(\s*[:=]\s*)(?:bearer|basic|token|digest)?\s*\S+/gi;
const COOKIE_HEADER =
    /\b((?:set-)?cookie)(\s*[:=]\s*)[^\s;]+(?:\s*;\s*[^\s;]+)*/gi;

/**
 * `key=value` / `key: value` where the key names a credential.
 *
 * The separator must still follow the keyword (allowing one closing quote),
 * which is what keeps ordinary prose out: "my password manager is 1Password"
 * has no separator after "password" and does not match.
 *
 * ── What the gate has to let in ────────────────────────────────────────────
 * The keyword may start the identifier, sit mid-identifier, or follow a
 * separator character, so the left gate is `\b` OR a lookbehind covering
 * letters, digits, `_` and `-`:
 *
 *   - `(?<=[a-z])` is what makes `delegatePrivateKey` match — MemWal's own
 *     worst secret, where `PrivateKey` sits mid-identifier and a plain `\b`
 *     never fires.
 *   - `_` is a WORD character, so `\b` does not fire between `_` and `P`
 *     either, and `_` is not `[a-z]`. That left the entire SCREAMING_SNAKE
 *     namespace open: `POSTGRES_PASSWORD=`, `AWS_SECRET_ACCESS_KEY=`,
 *     `DB_PASSWORD=`, `X_AUTH_TOKEN:`, `SESSION_SECRET=` and `my_api_key=`
 *     all passed through verbatim — the exact spelling a credential arrives in
 *     when someone pastes an env file or a shell export.
 *
 * And a closing quote may sit between the keyword and the separator, because
 * that is what a JSON object looks like: `{"username": "alice", "password":
 * "hunter2-prod-9xQ"}` matched nothing at all before. The quote is captured
 * with the separator and written back, so the shape of the line survives; only
 * the value is replaced.
 *
 * `access[_-]?keys?` is in the list for `AWS_SECRET_ACCESS_KEY`: `secret` is
 * there, but the separator does not follow it, and no alternative covered the
 * `ACCESS_KEY` that does precede the `=`.
 */
const CREDENTIAL_ASSIGNMENT =
    /(?:\b|(?<=[a-z0-9_-]))(passwords?|passwd|pwd|db[_-]?pass(?:word)?s?|passphrases?|api[_-]?keys?|apikeys?|secret[_-]?keys?|access[_-]?keys?|encryption[_-]?keys?|enc[_-]?keys?|client[_-]?secrets?|secrets?|access[_-]?tokens?|refresh[_-]?tokens?|auth[_-]?tokens?|bearer[_-]?tokens?|tokens?|priv(?:ate)?[_-]?keys?|credentials?)(["'`]?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[^\s,;]+)/gi;

/**
 * Vendor-prefixed keys. Each prefix is issued by exactly one service and never
 * appears at the head of ordinary text, so these are the highest-confidence
 * patterns in the file — no context needed.
 */
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
    /\bsuiprivkey1[0-9a-z]{16,}\b/g, // Sui bech32 private key (#435)
    /\bSUIPRIVKEY1[0-9A-Z]{16,}\b/g, // Sui uppercase bech32 private key (#435)
];

/** Three base64url segments — a signed JWT, whatever it encodes. */
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

/**
 * A BIP-39 mnemonic, gated on the user naming it.
 *
 * Twelve consecutive lowercase words is also what an ordinary sentence looks
 * like, so the words alone prove nothing; "seed phrase" / "mnemonic" /
 * "recovery phrase" in front of them is what makes the match safe. A mnemonic
 * pasted with no label is left to `SECRET_EXCLUSION_RULES` — carrying the
 * 2048-word list here to catch it would be a lot of weight for a case the model
 * rules already cover.
 */
const SEED_PHRASE =
    /(?:\b|(?<=[a-z]))((?:seed|recovery|secret|mnemonic)[\s_-]*(?:phrase|words)|mnemonic)([^A-Za-z0-9]{0,4}(?:is|are)?[^A-Za-z0-9]{0,4})((?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8})\b/gi;

/**
 * Key material in hex, identified by the LABEL beside it rather than by how
 * random it looks.
 *
 * This exists because of one specific secret: `delegatePrivateKey` in
 * `~/.memwal/credentials.json` is a 64-hex Ed25519 seed, the thing auth.ts
 * marks "NEVER log this", and whoever holds it can read and write the user's
 * memories until the delegate is revoked. It is the worst thing this product
 * can leak — and it is pure lowercase hex, so it is deliberately excluded by
 * `looksLikeSecretBlob` below and was sailing straight through.
 *
 * The exclusion is still right: a bare hex run is a git SHA, a Walrus blob id,
 * a Sui object or account id, a content digest — the identifiers users most
 * want remembered. So the discriminator is not entropy, it is the label. A hex
 * run is removed only when a credential word sits next to it, which catches
 * every shape the secret actually arrives in:
 *
 *     delegatePrivateKey 4f3c...        (prose / a pasted line)
 *     "delegatePrivateKey": "4f3c..."   (the credentials.json file itself)
 *     my delegate private key is 4f3c...
 *     4f3c... is my private key         (label after the value)
 *
 * while `Pin the build to commit 4f2b8c1e...` and `my account id is 0x7f3a...`
 * keep passing through untouched. That asymmetry is the whole design, and it is
 * pinned from both sides in secret-redaction.test.ts.
 */
const HEX_RUN = /\b(?:0x)?[0-9a-fA-F]{32,}\b/g;

/** How far either side of a hex run a label may sit — a few tokens. */
const HEX_LABEL_WINDOW = 48;

/**
 * Words that make an adjacent hex run key material.
 *
 * Not anchored on a word boundary, so it matches inside a camelCase identifier
 * (`delegatePrivateKey`). `credential(s)` is deliberately ABSENT: MemWal's own
 * prose says "credentials.json" constantly, and a sentence naming that file
 * next to a commit SHA would lose the SHA.
 */
const HEX_CREDENTIAL_LABEL =
    /private[\s_-]*key|secret[\s_-]*key|delegate[\s_-]*key|delegate[\s_-]*private|signing[\s_-]*key|priv[\s_-]*key|sui[\s._-]*keystore|encryption[\s_-]*keys?(?![A-Za-z0-9])|enc[\s_-]*keys?(?![A-Za-z0-9])|api[\s_-]*key|access[\s_-]*key|auth[\s_-]*key|db[\s_-]*pass(?:word)?s?(?![A-Za-z0-9])|secret|seed|mnemonic|passphrase/i;

/**
 * The same, for a label that FOLLOWS the value ("4f3c... is my private key").
 * Tighter than the backward form — it has to march through the small joining
 * phrase rather than search a window — because a trailing window would sweep
 * in whatever sentence happens to come next.
 */
const HEX_LABEL_AFTER =
    /^[^A-Za-z0-9]{0,4}(?:is|was)?[^A-Za-z0-9]{0,4}(?:my|the|our|his|her|their)?[^A-Za-z0-9]{0,4}(?:delegate[\s_-]*)?(?:private[\s_-]*key|secret[\s_-]*key|priv[\s_-]*key|sui[\s._-]*keystore|encryption[\s_-]*keys?(?![A-Za-z0-9])|enc[\s_-]*keys?(?![A-Za-z0-9])|seed|mnemonic|passphrase|api[\s_-]*key|db[\s_-]*pass(?:word)?s?(?![A-Za-z0-9]))/i;

/** Placeholders this module writes, for stripping out of a context window. */
const PLACEHOLDER_RUN = /\[redacted:[a-z-]+\]/g;

/**
 * True when the span at [start, end) is itself part of a placeholder an earlier
 * rule already wrote.
 *
 * `labelled-key-material` and `credential-assignment` are both 21 characters of
 * exactly the alphabet {@link OPAQUE_RUN} scans for, so without this a run of
 * redactions would start redacting its own output.
 */
function isInsidePlaceholder(text: string, start: number): boolean {
    const before = text.slice(Math.max(0, start - 10), start);
    return /\[redacted:$/.test(before);
}

/**
 * True when a credential word sits within `window` characters of [start, end).
 *
 * `window` is a parameter because the batch screen (see
 * {@link sanitizeFactBatch}) looks across entry boundaries, where the label and
 * the value are further apart than "a few tokens" by construction.
 */
function hasAdjacentCredentialLabel(
    text: string,
    start: number,
    end: number,
    window: number = HEX_LABEL_WINDOW,
): boolean {
    // Placeholders left by earlier rules carry the words "secret" and "key",
    // so a run of redactions would otherwise start labelling its own
    // neighbours — and the neighbour after `private_key=[redacted:...]` is
    // exactly the kind of bare SHA this rule must not touch.
    const before = text
        .slice(Math.max(0, start - window), start)
        .replace(PLACEHOLDER_RUN, " ");
    if (HEX_CREDENTIAL_LABEL.test(before)) return true;
    return HEX_LABEL_AFTER.test(
        text.slice(end, end + HEX_LABEL_WINDOW).replace(PLACEHOLDER_RUN, " "),
    );
}

/**
 * The same label gate, for key material that is not hex.
 *
 * `HEX_RUN` only ever looked at hex, and `HIGH_ENTROPY_CANDIDATE` demands 64+
 * characters, so everything in between passed with a label in front of it:
 * `My AWS secret access key is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY for
 * prod` came back completely unchanged, three label words and all. In an AWS
 * key pair that meant the non-secret `AKIA...` id was redacted by the vendor
 * rule while the 40-character secret half survived — the wrong half of the
 * pair, every time.
 *
 * Same discriminator as the hex rule, for the same reason: the LABEL, never the
 * shape. A bare 43-character blob id, a commit SHA or a Sui object id with no
 * credential word near it still passes, which is the property the rest of this
 * file is built around.
 */
const OPAQUE_RUN = /[A-Za-z0-9+/_=-]{20,}/g;

/**
 * A shape guard on top of the label, so an ordinary long word next to the word
 * "secret" is not mistaken for key material.
 *
 * A generated credential is mixed case, or carries digits, or carries base64
 * padding and separators; `my_api_key_rotation_policy` is none of those. This
 * is not an entropy test and is not trying to be one — the label is still what
 * decides. It only keeps prose out.
 */
function looksLikeOpaqueToken(token: string): boolean {
    if (token.length < 20) return false;
    const hasLower = /[a-z]/.test(token);
    const hasUpper = /[A-Z]/.test(token);
    const hasDigit = /[0-9]/.test(token);
    const hasSymbol = /[+/=]/.test(token);
    return (hasLower && hasUpper) || hasDigit || hasSymbol;
}

/**
 * A ≥64-character base64/base64url run carrying lower case, upper case AND a
 * digit. See the false-positive note at the top: the three conditions together
 * are what exclude blob ids, Sui addresses, git SHAs and hex digests, all of
 * which are shorter, single-case, or both.
 */
const HIGH_ENTROPY_CANDIDATE = /\b[A-Za-z0-9+/_-]{64,}={0,2}/g;

function looksLikeSecretBlob(token: string): boolean {
    const body = token.replace(/=+$/, "");
    if (body.length < 64) return false;
    if (!/[a-z]/.test(body)) return false;
    if (!/[A-Z]/.test(body)) return false;
    if (!/[0-9]/.test(body)) return false;
    // Hex is single-case by convention and covers digests, SHAs and Sui ids;
    // a mixed-case hex string is still far more likely a digest than a key.
    if (/^[0-9a-fA-F]+$/.test(body)) return false;
    return true;
}

/**
 * Unambiguously pasted third-party material.
 *
 * Narrow on purpose — see the false-positive note. An agent saving a fact
 * routinely quotes the user's own sentence, so a short quoted string is NOT
 * treated as a paste.
 */
function isPastedContent(text: string): boolean {
    const s = text.trim();
    if (/^```[\s\S]*```$/.test(s)) return true;
    const lines = s.split(/\r?\n/).filter((l) => l.trim() !== "");
    if (lines.length >= 2 && lines.every((l) => /^\s*>/.test(l))) return true;
    if (s.length >= 200 && /^["“][\s\S]*["”]$/.test(s)) return true;
    return false;
}

/**
 * Is there still a fact here once the placeholders are taken out?
 *
 * Three words of two or more letters. "sk-live-..." on its own redacts to a
 * bare placeholder and has none; "I keep the staging key in 1Password,
 * api_key=..." keeps its sentence and has plenty.
 */
function hasSalvageableContent(text: string): boolean {
    const withoutPlaceholders = text.replace(/\[redacted:[a-z-]+\]/g, " ");
    const words = withoutPlaceholders.match(/[\p{L}\p{N}]{2,}/gu) ?? [];
    return words.length >= 3;
}

/**
 * Strip credentials from one piece of text before it is forwarded to the SDK.
 *
 * Pure, synchronous and side-effect free: no logging, no I/O. The secret exists
 * only in the caller's argument and never leaves this function.
 */
export function sanitizeFact(input: string): SanitizedText {
    const original = input ?? "";

    if (NO_SAVE_DIRECTIVE.test(original) || OFF_THE_RECORD.test(original)) {
        return {
            text: "",
            changed: true,
            kinds: [],
            count: 0,
            refusal: "no-save-directive",
        };
    }

    if (isPastedContent(original)) {
        return {
            text: "",
            changed: true,
            kinds: [],
            count: 0,
            refusal: "pasted-content",
        };
    }

    const kinds: RedactionKind[] = [];
    let count = 0;
    const hit = (kind: RedactionKind) => {
        if (!kinds.includes(kind)) kinds.push(kind);
        count += 1;
        return placeholder(kind);
    };

    let text = original;

    // PEM first: it spans lines, and running the line-oriented patterns over a
    // key body would shred it into several partial matches instead of one.
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

    // Before the vendor patterns, so `api_key=sk-...` is reported once as an
    // assignment rather than twice.
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

    // Label-gated, and therefore run over the text as it stands now: the
    // window check reads the characters on either side, so it has to see the
    // real neighbours rather than a half-rewritten string.
    text = text.replace(HEX_RUN, (match: string, offset: number, whole: string) =>
        hasAdjacentCredentialLabel(whole, offset, offset + match.length)
            ? hit("labelled-key-material")
            : match,
    );

    // Everything else a label makes into key material: the 20+ character
    // base64/base64url runs that are too short for the entropy rule and not hex
    // enough for HEX_RUN. Same window, same gate, same asymmetry — a bare run
    // with nothing calling it a key still passes.
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

    if (count === 0) {
        return { text: original, changed: false, kinds: [], count: 0 };
    }

    // Collapse the whitespace a removed block leaves behind, so the stored fact
    // does not carry the shape of what was taken out.
    text = text.replace(/[ \t]{2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim();

    if (!hasSalvageableContent(text)) {
        return {
            text: "",
            changed: true,
            kinds,
            count,
            refusal: "credential-only",
        };
    }

    return { text, changed: true, kinds, count };
}

/** Human-readable reason, for the note handed back to the agent. */
export function refusalMessage(reason: RefusalReason): string {
    switch (reason) {
        case "no-save-directive":
            return "the text says not to save it";
        case "credential-only":
            return "the text was a credential with no fact around it";
        case "pasted-content":
            return "the text is pasted third-party content, not a fact about the user";
    }
}

/**
 * The line appended to a tool result when something was removed.
 *
 * Names the kinds and nothing else — an agent needs to know a redaction
 * happened so it does not tell the user the whole line was stored, and it never
 * needs the value back.
 */
export function redactionNotice(kinds: RedactionKind[], count: number): string {
    if (count === 0) return "";
    return (
        `Note: ${count} credential span(s) were removed before saving ` +
        `(${kinds.join(", ")}). What was stored is the redacted text — the secret ` +
        `was never sent to Walrus Memory and is not logged. Tell the user the ` +
        `credential was left out; do not re-send it.`
    );
}

/**
 * The line for a text that was not saved at all.
 */
export function refusalNotice(reason: RefusalReason): string {
    return (
        `NOT SAVED: ${refusalMessage(reason)}. Nothing was written to Walrus ` +
        `Memory. Do not retry this text — if there is a durable fact in it, ` +
        `restate the fact without the sensitive part and save that instead.`
    );
}

/* ───────────────────────────────────────────────────────────────────────────
 * Screening a BATCH, not one string at a time (WALM-642).
 *
 * `sanitizeFact` sees one entry, and every label-gated rule in this file
 * searches a window inside that one string. `memwal_remember_bulk` takes up to
 * twenty of them, which is a way around all of it: put the label in one entry
 * and the value in the next and each is individually unremarkable.
 *
 *     ["my delegate private key for the mainnet account",
 *      "4f3c...789"]
 *
 * Both entries passed untouched, while the same words as ONE string were
 * correctly redacted. That value is MemWal's own delegate private key — the
 * thing this module calls the worst secret the product can leak — and an agent
 * that paraphrases a user across two entries is all it takes. Nothing about it
 * requires malice.
 *
 * So a batch is screened as a batch. The per-entry pass runs first and is
 * unchanged, which keeps the refusal granularity that already works (one bad
 * entry is dropped, the rest of the batch still lands). Then a second pass asks
 * a question the first one cannot: is there a credential label in the text
 * ADJACENT to this value, where adjacent means the entries either side of it as
 * well as its own?
 *
 * A value that is an entry all by itself is screened against the whole batch
 * rather than its neighbours. A bare token with no words around it has no
 * meaning of its own to lose, and "which entry did the label end up in" is not
 * something the user controls.
 * ------------------------------------------------------------------------ */

/** What separates two entries when the batch is viewed as one passage. */
const BATCH_SEPARATOR = "\n";

/**
 * A label anywhere in `context`, on either side of [start, end).
 *
 * The per-entry gate measures a character window because it is looking inside
 * one sentence. Across entries the unit is the entry: the caller passes exactly
 * the text that counts as adjacent and this searches all of it, so there is no
 * second magic number to keep in step with the first.
 */
function hasCredentialLabelInContext(
    context: string,
    start: number,
    end: number,
): boolean {
    const before = context.slice(0, start).replace(PLACEHOLDER_RUN, " ");
    if (HEX_CREDENTIAL_LABEL.test(before)) return true;
    const after = context.slice(end).replace(PLACEHOLDER_RUN, " ");
    return HEX_CREDENTIAL_LABEL.test(after);
}

/** Words left once the placeholders and one candidate token are removed. */
function wordsAround(text: string, token: string): number {
    const rest = text
        .replace(PLACEHOLDER_RUN, " ")
        .replace(token, " ")
        .match(/[\p{L}\p{N}]{2,}/gu);
    return rest?.length ?? 0;
}

/**
 * Screen a whole batch. One result per input, in input order.
 *
 * Drop-in for `inputs.map(sanitizeFact)` — every entry comes back with the same
 * shape and the same per-entry refusals — plus the cross-entry pass above.
 */
export function sanitizeFactBatch(
    inputs: string[],
    { bareScope = "batch" }: { bareScope?: "batch" | "neighbours" } = {},
): SanitizedText[] {
    const perEntry = inputs.map((text) => sanitizeFact(text ?? ""));
    // Nothing survived the per-entry pass, so there is nothing left to screen.
    if (perEntry.every((r) => r.refusal)) return perEntry;

    // What each entry contributes as CONTEXT. A refused entry is never
    // forwarded, but its words still say what the batch is about, so it keeps
    // supplying label context from its original text.
    const views = perEntry.map((r, i) => (r.refusal ? (inputs[i] ?? "") : r.text));
    const wholeBatch = views.join(BATCH_SEPARATOR);
    // Placeholders carry the words "secret" and "key" (`high-entropy-secret`
    // most obviously), so a batch where one entry was already redacted would
    // otherwise label itself.
    if (!HEX_CREDENTIAL_LABEL.test(wholeBatch.replace(PLACEHOLDER_RUN, " "))) {
        return perEntry;
    }

    return perEntry.map((result, i) => {
        if (result.refusal) return result;
        const own = views[i];
        const prev = i > 0 ? views[i - 1] : "";
        const next = i + 1 < views.length ? views[i + 1] : "";
        // The neighbours, with this entry in the middle, and this entry's
        // offset inside it.
        const neighbourhood = [prev, own, next].join(BATCH_SEPARATOR);
        const ownStart = prev.length + BATCH_SEPARATOR.length;

        const kinds = [...result.kinds];
        let count = result.count;
        let hitAny = false;
        const text = own.replace(
            OPAQUE_RUN,
            (match: string, offset: number, whole: string) => {
                if (isInsidePlaceholder(whole, offset)) return match;
                if (!looksLikeOpaqueToken(match)) return match;
                // An entry that is essentially just this token is screened
                // against every entry in batch mode; one with a sentence around
                // it, against the entries either side. Passage mode always uses
                // neighbours so one label in a long transcript cannot take every
                // lone blob id or SHA with it.
                const bare = bareScope === "batch" && wordsAround(own, match) < 3;
                const context = bare ? wholeBatch : neighbourhood;
                const start = bare
                    ? views.slice(0, i).reduce(
                          (n, v) => n + v.length + BATCH_SEPARATOR.length,
                          0,
                      ) + offset
                    : ownStart + offset;
                if (!hasCredentialLabelInContext(context, start, start + match.length)) {
                    return match;
                }
                if (!kinds.includes("labelled-key-material")) {
                    kinds.push("labelled-key-material");
                }
                count += 1;
                hitAny = true;
                return placeholder("labelled-key-material");
            },
        );

        if (!hitAny) return result;
        const collapsed = text.replace(/[ \t]{2,}/g, " ").trim();
        if (!hasSalvageableContent(collapsed)) {
            return { text: "", changed: true, kinds, count, refusal: "credential-only" };
        }
        return { text: collapsed, changed: true, kinds, count };
    });
}

/* ───────────────────────────────────────────────────────────────────────────
 * Screening a PASSAGE (WALM-642).
 *
 * `NO_SAVE_DIRECTIVE`, `OFF_THE_RECORD` and `isPastedContent` are whole-string
 * predicates, written for one fact and correct there. `memwal_analyze` applies
 * them to a whole transcript, where "whole string" means something else
 * entirely: one "don't save this part" line in a forty-turn conversation
 * refused the entire passage — `refusal`, `text: ""`, all forty turns
 * discarded, and a note telling the agent not to retry it. The call carried no
 * `isError`, so the client saw a successful call that had saved nothing.
 *
 * The fix is the one `memwal_remember_bulk` already uses on entries: scope the
 * refusal to the span that earned it. A passage is split into segments, the
 * segment texts are screened together, the offending ones are dropped and
 * named, and everything else is extracted from.
 *
 * Three deliberate wrinkles:
 *
 *   - A no-save directive drops its NEIGHBOURS too, within its own paragraph.
 *     "My bank PIN is 4821" on one line and "don't save this" on the next is
 *     the ordinary way people write it, and dropping only the second line would
 *     save the first — a far worse outcome than losing a turn either side.
 *   - A fenced block WRAPPING THE WHOLE PASSAGE is unwrapped rather than
 *     refused, when it has no language tag and holds a transcript's worth of
 *     lines. That shape is what this tool documents as its canonical input, and
 *     refusing it discarded exactly the passages people most wanted analysed. A
 *     tagged fence (```json, ```sh) is code, a short one is a snippet, and a
 *     fence INSIDE the passage is still dropped as a paste — none of those
 *     change.
 *   - A credential split across lines is the same shape as one split across
 *     bulk entries (WALM-687). Non-blank segment texts go through
 *     `sanitizeFactBatch` with `bareScope: "neighbours"`, so blank lines do not
 *     break neighbour adjacency and a bare token is not screened against the
 *     whole passage. A dropped segment still contributes its kinds; `dropped`
 *     stays line and reason, never the secret text.
 * ------------------------------------------------------------------------ */

/**
 * Non-blank lines an untagged outer fence must hold before it is read as a
 * transcript rather than a pasted snippet.
 */
const TRANSCRIPT_FENCE_MIN_LINES = 4;

/** One dropped span, named by position and reason. Never carries its text. */
export interface DroppedSpan {
    /** 1-based line number in the passage as it was received. */
    line: number;
    reason: RefusalReason;
}

export interface SanitizedPassage extends SanitizedText {
    /** Spans removed before extraction. Empty when the passage came through whole. */
    dropped: DroppedSpan[];
    /** Non-blank segments the passage was split into. */
    segments: number;
}

/** Strip one outer fence when it is a transcript rather than a code paste. */
function unwrapTranscriptFence(text: string): string {
    const s = text.trim();
    const m = /^```([^\n]*)\n([\s\S]*?)\n?```$/.exec(s);
    if (!m) return text;
    // A language tag is an author saying "this is code", so take them at their
    // word and leave it to the per-segment paste rule.
    if (m[1].trim() !== "") return text;
    const body = m[2];
    const lines = body.split(/\r?\n/).filter((l) => l.trim() !== "");
    if (lines.length < TRANSCRIPT_FENCE_MIN_LINES) return text;
    return body;
}

interface PassageSegment {
    text: string;
    /** 1-based line the segment starts on. */
    line: number;
    blank: boolean;
}

/**
 * Split a passage into the units a refusal may apply to.
 *
 * One line per segment, except that a fenced block and a run of `>` quotation
 * stay whole — both are multi-line by nature, and `isPastedContent` can only
 * recognise them as one piece.
 */
function splitPassage(text: string): PassageSegment[] {
    const lines = text.split(/\r?\n/);
    const segments: PassageSegment[] = [];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*```/.test(line)) {
            const start = i;
            const block = [line];
            i++;
            while (i < lines.length) {
                block.push(lines[i]);
                if (/^\s*```/.test(lines[i])) break;
                i++;
            }
            segments.push({ text: block.join("\n"), line: start + 1, blank: false });
            continue;
        }
        if (/^\s*>/.test(line)) {
            const start = i;
            const block = [line];
            while (i + 1 < lines.length && /^\s*>/.test(lines[i + 1])) {
                block.push(lines[++i]);
            }
            segments.push({ text: block.join("\n"), line: start + 1, blank: false });
            continue;
        }
        segments.push({ text: line, line: i + 1, blank: line.trim() === "" });
    }
    return segments;
}

/**
 * Strip credentials from a passage, dropping only the spans that must go.
 *
 * `text` is what is safe to forward, `dropped` says what was removed and why,
 * and `refusal` is set only when nothing survived at all.
 */
export function sanitizePassage(input: string): SanitizedPassage {
    const segments = splitPassage(unwrapTranscriptFence(input ?? ""));
    // Blank lines are left out, so a label and a value with a blank line
    // between them are still neighbours. A bare token is screened against its
    // neighbours only: one label in a 200k-character passage must not take
    // every lone blob id or SHA with it.
    const screened = sanitizeFactBatch(
        segments.filter((s) => !s.blank).map((s) => s.text),
        { bareScope: "neighbours" },
    );
    let next = 0;
    const results = segments.map((s) =>
        s.blank ? { text: "", changed: false, kinds: [], count: 0 } : screened[next++],
    );
    const dropped: (RefusalReason | null)[] = results.map((r, i) =>
        segments[i].blank ? null : (r.refusal ?? null),
    );

    // A directive takes its immediate neighbours with it, unless a blank line
    // stands between them — see the note above. Computed against the ORIGINAL
    // drop list so one directive cannot cascade down a whole passage.
    const directive = dropped.map((d) => d === "no-save-directive");
    for (let i = 0; i < segments.length; i++) {
        if (!directive[i]) continue;
        for (const j of [i - 1, i + 1]) {
            if (j < 0 || j >= segments.length) continue;
            if (segments[j].blank) continue;
            if (dropped[j] === null) dropped[j] = "no-save-directive";
        }
    }

    const kinds: RedactionKind[] = [];
    let count = 0;
    const kept: string[] = [];
    const droppedSpans: DroppedSpan[] = [];
    let nonBlank = 0;
    for (let i = 0; i < segments.length; i++) {
        const segment = segments[i];
        if (segment.blank) {
            kept.push("");
            continue;
        }
        nonBlank += 1;
        const result = results[i];
        // Fold kinds even when the segment is dropped. A bare key is refused
        // as `credential-only` with empty text, and skipping it here would
        // report no kind at all (WALM-687). `dropped` stays line + reason.
        count += result.count;
        for (const kind of result.kinds) {
            if (!kinds.includes(kind)) kinds.push(kind);
        }
        const reason = dropped[i];
        if (reason) {
            droppedSpans.push({ line: segment.line, reason });
            continue;
        }
        kept.push(result.text);
    }

    const text = kept
        .join("\n")
        .replace(/[ \t]{2,}/g, " ")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
    const changed = count > 0 || droppedSpans.length > 0;

    if (!hasSalvageableContent(text)) {
        // Nothing usable left. Report the reason that took the most of it, so
        // the agent is told the truth about why rather than a generic refusal.
        const tally = new Map<RefusalReason, number>();
        for (const span of droppedSpans) {
            tally.set(span.reason, (tally.get(span.reason) ?? 0) + 1);
        }
        const [top] = [...tally.entries()].sort((a, b) => b[1] - a[1]);
        return {
            text: "",
            changed: true,
            kinds,
            count,
            refusal: top?.[0] ?? "credential-only",
            dropped: droppedSpans,
            segments: nonBlank,
        };
    }

    return { text, changed, kinds, count, dropped: droppedSpans, segments: nonBlank };
}

/**
 * The line naming spans that were dropped from a passage but not the whole of
 * it. Positions and reasons only — never the text that was removed.
 */
export function droppedSpanNotice(dropped: DroppedSpan[], segments: number): string {
    if (dropped.length === 0) return "";
    const detail = dropped
        .map((d) => `line ${d.line} (${refusalMessage(d.reason)})`)
        .join("; ")
    return (
        `Note: ${dropped.length} of ${segments} span(s) were dropped before ` +
        `extraction and nothing from them was saved — ${detail}. The rest of the ` +
        `passage was extracted from normally. Tell the user which part was left ` +
        `out; do not re-send it.`
    );
}

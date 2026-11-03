/**
 * Capture filtering — determines whether a conversation turn
 * is worth sending to analyze() for fact extraction.
 */

import { MIN_CAPTURE_LENGTH, MAX_EMOJI_COUNT } from "./constants.js";

/** Filler patterns — exact-match trivial responses. */
const FILLER_PATTERN = /^(ok|okay|sure|thanks|thank you|thx|yes|yep|yeah|no|nope|nah|got it|hmm|hm|ah|oh|lol|haha|nice|cool|great|right|alright|fine|k|kk)\s*[.!?]*$/i;

/** Visual lookalike character map (Cyrillic, Greek, Latin symbols). */
const VISUAL_CONFUSABLES: Record<string, string> = {
  "а": "a", "А": "a", "б": "b", "Б": "b", "в": "b", "В": "b", "ь": "b", "Ь": "b",
  "с": "c", "С": "c", "д": "d", "Д": "d", "е": "e", "Е": "e", "ѐ": "e", "Ѐ": "e",
  "ё": "e", "Ё": "e", "є": "e", "Є": "e", "і": "i", "І": "i", "ї": "i", "Ї": "i",
  "ј": "j", "Ј": "j", "к": "k", "К": "k", "л": "l", "Л": "l", "м": "m", "М": "m",
  "н": "h", "Н": "h", "п": "n", "П": "n", "о": "o", "О": "o", "ѻ": "o", "Ѻ": "o",
  "р": "p", "Р": "p", "ҏ": "p", "Ҏ": "p", "ѕ": "s", "Ѕ": "s", "т": "t", "Т": "t",
  "и": "u", "И": "u", "й": "u", "Й": "u", "у": "y", "У": "y", "х": "x", "Х": "x",
  "α": "a", "Α": "a", "β": "b", "Β": "b", "γ": "y", "Γ": "r", "δ": "d", "Δ": "d",
  "ε": "e", "Ε": "e", "ζ": "z", "Ζ": "z", "η": "n", "Η": "h", "θ": "o", "Θ": "o",
  "ι": "i", "Ι": "i", "κ": "k", "Κ": "k", "λ": "l", "Λ": "l", "μ": "u", "Μ": "m",
  "ν": "v", "Ν": "n", "ξ": "x", "Ξ": "x", "ο": "o", "Ο": "o", "π": "n", "Π": "n",
  "ρ": "p", "Ρ": "p", "σ": "o", "Σ": "e", "ς": "s", "τ": "t", "Τ": "t", "υ": "u",
  "Υ": "y", "φ": "o", "Φ": "o", "χ": "x", "Χ": "x", "ψ": "y", "Ψ": "y", "ω": "w",
  "Ω": "o", "ℓ": "l", "ø": "o", "Ø": "o", "đ": "d", "Đ": "d", "ħ": "h", "Ħ": "h",
  "ł": "l", "Ł": "l", "ŋ": "n", "Ŋ": "n", "ŧ": "t", "Ŧ": "t",
};

/** Prompt injection patterns — never capture or recall these. */
const INJECTION_PATTERNS = [
  /\b(ign[o0a]re|disregard|override|f[o0]rget|bypass)\b[\s\S]{0,140}?\b(instruct\w*|instr\w{1,8}tions?|pr[o0]mpt|rules|c[o0]nstraints|guidelines|safety)\b/i,
  /\b(?:do\s+not|don\x27?t|st[o0]p)\s+f[o0]ll[o0]w(?:ing)?\b[\s\S]{0,80}?\b(?:system|devel[o0]per|safety|rules|instructions?|instr\w{1,8}tions?)\b/i,
  /\b(?:new\s+instructions|system\s+override)\s*:\s*/i,
  /\byou\s+are\s+now\s+(?:dan|unrestricted|jailbroken|unfiltered)\b/i,
  /\bsystem\s+pr[o0]mpt\b/i,
  /\breveal\s+(?:all\s+)?(?:your\s+)?(?:system\s+)?instructions?\b/i,
  /<\s*\/?\s*(system|assistant|developer|tool|function|prompt)\b/i,
];

/**
 * Patterns broad enough to match ordinary speech, so they only count when the
 * text is actually aimed at the model.
 *
 * "I run the deploy command every Friday" is a fact worth remembering;
 * "run the shell command" is an instruction aimed at the agent. Both match the
 * same regex, so the regex alone cannot separate them. Without this split these
 * two patterns silently discard normal developer speech — measured at 7 of 12
 * realistic statements dropped, with no error surfaced to the user.
 */
const CONTEXTUAL_INJECTION_PATTERNS = [
  /\b(ign[o0a]re|disregard|f[o0]rget|override)\b[\s\S]{0,80}?\b(everything|anything)\b[\s\S]{0,80}?\b(bef[o0]re|pri[o0]r|t[o0]ld|pr[o0]mpt)\b/i,
  /\b(run|execute|call|invoke)\b.{0,40}\b(tool|command|shell|bash)\b/i,
];

/**
 * Is the text addressing the model rather than describing the speaker?
 *
 * Injection has to reach the model to work, so it either names it ("you",
 * "your") or leads with a bare imperative built from an injection verb. A
 * sentence that does neither is someone talking about their own workflow.
 */
const ADDRESSES_MODEL = [
  /\b(you|your|yourself)\b/i,
  /^(ign[o0a]re|disregard|f[o0]rget|override|bypass|run|execute|call|invoke|reveal|print|output)\b/i,
];

const CLAUSE_IMPERATIVE_PREFIX =
  "(?:^|[.!?;:,(\\[\\n]\\s*|\\b(?:please|just)\\s+|\\byou\\s+(?:must\\s+|should\\s+|can\\s+)?)";

const IMPERATIVE_NEGATION_PREFIX = CLAUSE_IMPERATIVE_PREFIX;

/** Conversational opt-out patterns that instruct the assistant not to persist the turn. */
const OPT_OUT_PATTERNS = [
  new RegExp(
    `${CLAUSE_IMPERATIVE_PREFIX}(?:do\\s+not|don['\\u2019]?t|never)\\s+(?:ever\\s+)?(?:remember|memorize)(?:\\s+or\\s+(?:save|store|record|capture|keep))?\\b`,
    "i",
  ),
  new RegExp(
    `${IMPERATIVE_NEGATION_PREFIX}(?:do\\s+not|don['\\u2019]?t|never)\\s+(?:ever\\s+)?(?:remember|memorize)(?:\\s+or\\s+(?:save|store|record|capture|keep)\\b|\\s+(?:any(?:\\s+of)?(?:\\s+(?:this|that|these|those|it))?|anything(?:\\s+(?:here|from\\s+this))?|this|that|these|those|it|what\\s+i|where\\s+i|who\\s+i|how\\s+i|my\\b|our\\b|the\\s+following\\b|(?:in|to)\\s+memory|the\\s+(?:conversation|chat|message|turn|discussion|note|notes|details))\\b)`,
    "i",
  ),
  new RegExp(
    `${IMPERATIVE_NEGATION_PREFIX}(?:do\\s+not|don['\\u2019]?t|never)\\s+(?:ever\\s+)?(?:save|store|record|capture|keep)(?:\\s+or\\s+(?:remember|memorize|save|store|record|capture|keep))?(?:\\s+(?:any(?:\\s+of)?(?:\\s+(?:this|that|these|those|it))?|anything(?:\\s+(?:here|from\\s+this))?|this|that|these|those|it|what\\s+i|where\\s+i|who\\s+i|how\\s+i|my\\b|our\\b|the\\s+following\\b|(?:in|to)\\s+memory|the\\s+(?:conversation|chat|message|turn|discussion|note|notes|details))\\b|(?=\\s*(?:$|[.!?:;,)\\]])))`,
    "i",
  ),
  new RegExp(
    `${IMPERATIVE_NEGATION_PREFIX}(?:do\\s+not|don['\\u2019]?t|never)\\s+(?:ever\\s+)?log\\s+(?:this(?:\\s+(?:conversation|message|chat|turn|session))?|anything\\s+(?:here|from\\s+this)|our\\s+(?:conversation|chat))\\b`,
    "i",
  ),
  /\b(?:off\s+the\s+record|(?:do\s+not|don['\u2019]?t|never)\s+keep\s+(?:this\s+|that\s+|it\s+)?in\s+memory|(?:please\s+)?forget\s+(?:this(?:\s+(?:conversation|message|chat|turn))?|what\s+i\s+just\s+said))\b/i,
  /(?:^|\s)(?:\[\s*no[-_\s]?save\s*\]|#no[-_]?save\b)/i,
];

/** High-confidence inline credential and secret patterns excluded from automatic capture. */
const SECRET_PATTERNS = [
  /\bsuiprivkey1[02-9ac-hj-np-z]{50,}\b/i,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\bsk-(?:proj-|ant-(?:api\d+-)?|live-|test-)?[A-Za-z0-9_-]{20,}\b/,
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\b(?:glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{36}|[sprk]k_(?:live|test)_[A-Za-z0-9]{16,}|hf_[A-Za-z0-9]{30,})\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\/[^\s/@:?=&]+:[^\s/@?=&]+@/,
  /\b(?:(?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|token|digest)\s+\S+|bearer\s+[A-Za-z0-9._~+/=-]{20,})/i,
  /(?:\b|(?<=[a-z0-9_-]))(?:passwords?|passwd|pwd|db[_-]?pass(?:word)?s?|passphrases?|api[_-\s]?keys?|apikeys?|secret[_-\s]?keys?|access[_-\s]?keys?|encryption[_-\s]?keys?|client[_-\s]?secrets?|secrets?|access[_-\s]?tokens?|refresh[_-\s]?tokens?|auth[_-\s]?tokens?|bearer[_-\s]?tokens?|session[_-\s]?tokens?|api[_-\s]?tokens?|private[_-\s]?keys?|priv[_-\s]?keys?|delegate[_-\s]?(?:private[_-\s]*)?keys?)["'`]?\s*[:=]\s*(?:["'`](?!\s*["'`])[^"'`\n]{4,}["'`]|(?!(?:string|number|boolean|null|undefined|none|true|false|required|optional)\b)[^\s'",;}{)\]]{6,})/i,
  /\btoken["'`]?\s*[:=]\s*(?:["'`](?!\s*["'`])[^"'`\n]{8,}["'`]|(?!(?:string|number|boolean|null|undefined|none|true|false|required|optional)\b)[^\s'",;}{)\]]{12,})/i,
  /(?:private[\s_-]*key|secret[\s_-]*key|delegate[\s_-]*(?:private[\s_-]*)?key|signing[\s_-]*key|api[\s_-]*key|seed)\b[^.\n]{0,32}\b(?:0x)?[0-9a-fA-F]{64}\b/i,
  /\b(?:0x)?[0-9a-fA-F]{64}\b[^A-Za-z0-9\n]{0,4}(?:is|was)?[^A-Za-z0-9\n]{0,4}(?:my|the|our)?[^A-Za-z0-9\n]{0,4}(?:delegate[\s_-]*)?(?:private|secret|signing)[\s_-]*key\b/i,
  /(?:\b|(?<=[a-z]))(?:(?:seed|recovery|secret|mnemonic)[\s_-]*(?:phrase|words)|mnemonic)[^A-Za-z0-9\n]{0,4}(?:is|are)?[^A-Za-z0-9\n]{0,4}(?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8}\b/i,
];

/** Memory trigger patterns — always capture if matched. */
const TRIGGER_PATTERNS = [
  /remember|prefer|radši|zapamatuj/i,
  /i (like|prefer|hate|love|want|need|use|am|work)/i,
  /my\s+\w+\s+is|is\s+my/i,
  /always|never|important/i,
  /decided|will use|switched to/i,
  /\+\d{10,}/,
  /[\w.-]+@[\w.-]+\.\w+/,
];

/** Normalize text by stripping invisible/format characters, decomposing Unicode, mapping confusable scripts, and joining single-character letter spacing. */
export function normalizeForInjectionCheck(text: string): string {
  const noInvisible = text.replace(/[\p{Cf}\p{Cc}\p{Co}\p{Cs}]/gu, "");
  const decomposed = noInvisible
    .normalize("NFKD")
    .replace(/[\p{Diacritic}\p{M}]/gu, "");

  let mapped = "";
  for (const char of decomposed) {
    mapped += VISUAL_CONFUSABLES[char] ?? char;
  }

  // Join characters that stand alone between separators (i-g-n-o-r-e, i  g  n),
  // but never a character that is part of a longer word, so e-mail stays e-mail.
  // Punctuation pass first so word gaps in "i-g-n y-o-u" survive the space pass.
  const joined = mapped
    .replace(
      /(?<=(?:^|[^A-Za-z0-9])[A-Za-z0-9])\s{0,3}[\p{P}\p{S}]{1,3}\s{0,3}(?=[A-Za-z0-9](?:[^A-Za-z0-9]|$))/gu,
      "",
    )
    .replace(
      /(?<=(?:^|[^A-Za-z0-9])[A-Za-z])\s{1,3}(?=[A-Za-z](?:[^A-Za-z0-9]|$))/gu,
      "",
    );
  return joined.replace(/\s+/g, " ").trim();
}

/** Check if text matches known prompt injection patterns. */
export function looksLikeInjection(text: string): boolean {
  if (!text) return false;
  const normalized = normalizeForInjectionCheck(text);
  if (!normalized) return false;
  if (INJECTION_PATTERNS.some((p) => p.test(normalized))) return true;
  // Broad patterns only count when the text is aimed at the model, otherwise
  // they swallow ordinary statements about shells, commands and tools.
  return (
    CONTEXTUAL_INJECTION_PATTERNS.some((p) => p.test(normalized)) &&
    ADDRESSES_MODEL.some((p) => p.test(normalized))
  );
}

/** Check if text contains an explicit conversational opt-out directive. */
export function hasCaptureOptOut(text: string): boolean {
  if (!text) return false;
  if (OPT_OUT_PATTERNS.some((p) => p.test(text))) return true;
  const normalized = normalizeForInjectionCheck(text);
  return Boolean(normalized && OPT_OUT_PATTERNS.some((p) => p.test(normalized)));
}

/** Alias for `hasCaptureOptOut` kept for callers checking opt-out predicates. */
export function looksLikeOptOut(text: string): boolean {
  return hasCaptureOptOut(text);
}

/** Check if text contains high-confidence inline credentials or secret keys. */
export function looksLikeSecret(text: string): boolean {
  if (!text) return false;
  return SECRET_PATTERNS.some((p) => p.test(text));
}

/** Determine whether a conversation turn is worth capturing. */
export function shouldCapture(text: string): boolean {
  if (text.length < MIN_CAPTURE_LENGTH) return false;
  if (FILLER_PATTERN.test(text.trim())) return false;
  if (text.trim().startsWith("<") && text.includes("</")) return false;

  const emojiCount = (text.match(/[\u{1F300}-\u{1F9FF}]/gu) || []).length;
  if (emojiCount > MAX_EMOJI_COUNT) return false;

  if (looksLikeInjection(text)) return false;
  if (hasCaptureOptOut(text)) return false;
  if (looksLikeSecret(text)) return false;
  if (TRIGGER_PATTERNS.some((p) => p.test(text))) return true;

  return true;
}

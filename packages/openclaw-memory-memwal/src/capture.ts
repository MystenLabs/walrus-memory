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

/** Conversational opt-out patterns that instruct the assistant not to persist the turn. */
const OPT_OUT_PATTERNS = [
  /\b(?:do\s+not|don['\u2019]?t|please\s+do\s+not|please\s+don['\u2019]?t|never)\s+(?:ever\s+)?(?:remember|save|store|capture|record|log|keep|memorize|index)\b/i,
  /\b(?:off\s+the\s+record|do\s+not\s+keep\s+(?:this\s+)?in\s+memory|don['\u2019]?t\s+keep\s+(?:this\s+)?in\s+memory)\b/i,
  /(?:^|\s)(?:\[\s*no[-_\s]?save\s*\]|#no[-_]?save\b)/i,
];

/** High-confidence inline credential and secret patterns excluded from automatic capture. */
const SECRET_PATTERNS = [
  /\bsuiprivkey1[02-9ac-hj-np-z]{50,}\b/i,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}\b/,
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\b(?:authorization\s*:\s*(?:bearer|basic)\s+\S+|bearer\s+[A-Za-z0-9._~+/=-]{20,})/i,
  /\b(?:api[_-\s]?key|secret[_-\s]?key|private[_-\s]?key|delegate[_-\s]?key|access[_-\s]?token|refresh[_-\s]?token|client[_-\s]?secret|password|passwd|pwd)\s*(?:[:=]|\bis\b)\s*['"]?(?:0x[0-9a-fA-F]{64}|[0-9a-fA-F]{64}|[^\s'",;]{8,})/i,
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
export function looksLikeOptOut(text: string): boolean {
  if (!text) return false;
  if (OPT_OUT_PATTERNS.some((p) => p.test(text))) return true;
  const normalized = normalizeForInjectionCheck(text);
  return Boolean(normalized && OPT_OUT_PATTERNS.some((p) => p.test(normalized)));
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
  if (looksLikeOptOut(text)) return false;
  if (looksLikeSecret(text)) return false;
  if (TRIGGER_PATTERNS.some((p) => p.test(text))) return true;

  return true;
}

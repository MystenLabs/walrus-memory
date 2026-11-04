import { test } from "node:test";
import assert from "node:assert/strict";
import {
    CONSENT_INSTRUCTION,
    ENABLE_PROACTIVE_PROMPT_DESCRIPTION,
    ENABLE_PROACTIVE_PROMPT_NAME,
    ENABLE_PROACTIVE_PROMPT_TITLE,
    EXPLICIT_ONLY_INSTRUCTION,
    localPromptReply,
} from "../dist/consent-instruction.js";

test("canonical consent instruction excludes secrets and names Always allow", () => {
    assert.match(CONSENT_INSTRUCTION, /without asking for confirmation/);
    assert.match(CONSENT_INSTRUCTION, /passwords/);
    assert.match(CONSENT_INSTRUCTION, /API keys/);
    assert.match(CONSENT_INSTRUCTION, /Always allow/);
});

test("canonical explicit-only instruction excludes secrets and restricts saving to explicit requests", () => {
    assert.match(EXPLICIT_ONLY_INSTRUCTION, /built-in memory/);
    assert.match(EXPLICIT_ONLY_INSTRUCTION, /explicitly names Walrus Memory or memwal/);
    assert.match(EXPLICIT_ONLY_INSTRUCTION, /passwords/);
    assert.match(EXPLICIT_ONLY_INSTRUCTION, /API keys/);
});

test("prompts/list advertises memwal_enable_proactive", () => {
    const reply = localPromptReply("prompts/list", {});
    assert.equal(reply?.result?.prompts?.[0]?.name, ENABLE_PROACTIVE_PROMPT_NAME);
    assert.equal(reply?.result?.prompts?.[0]?.title, ENABLE_PROACTIVE_PROMPT_TITLE);
    assert.equal(reply?.result?.prompts?.[0]?.description, ENABLE_PROACTIVE_PROMPT_DESCRIPTION);
});

test("prompts/get returns the canonical consent instruction", () => {
    const reply = localPromptReply("prompts/get", { name: ENABLE_PROACTIVE_PROMPT_NAME });
    assert.equal(reply?.result?.messages?.[0]?.content?.text, CONSENT_INSTRUCTION);
});

test("prompts/get rejects an unknown name", () => {
    const reply = localPromptReply("prompts/get", { name: "not_a_prompt" });
    assert.equal(reply?.error?.code, -32602);
});

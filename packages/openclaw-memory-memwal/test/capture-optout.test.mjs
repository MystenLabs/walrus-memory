import assert from "node:assert/strict";
import test from "node:test";

import {
  hasCaptureOptOut,
  looksLikeOptOut,
  looksLikeSecret,
  shouldCapture,
} from "../dist/capture.js";
import { registerCaptureHook } from "../dist/hooks/capture.js";

test("shouldCapture rejects explicit conversational opt-out directives before TRIGGER_PATTERNS", () => {
  const optOutTurns = [
    "Please do not remember or save this conversation (off the record): we are acquiring WidgetCorp on Friday.",
    "Do not save this: I prefer working from Tokyo next month.",
    "Please don't save any of this: I prefer working from Tokyo next month",
    "Please don’t save any of this: I prefer working from Tokyo next month",
    "Do not remember the following: I prefer working from Tokyo next month.",
    "Please don't remember where I live: 123 Example Street.",
    "For privacy, don't remember my home address: 123 Example Street.",
    "For privacy, do not remember where I live: 123 Example Street.",
    "Do not save or remember this: my temporary medical appointment is at 3 PM.",
    "Please don't remember my temporary medical appointment at 3 PM.",
    "Never store this in memory: our internal codename is Project Aurora.",
    "Never memorize my temporary hotel room number 412.",
    "Do not record this conversation about executive compensation.",
    "Don't capture this message about the upcoming reorg.",
    "This is off the record, I am interviewing at another company.",
    "Forget this conversation: we are considering a pivot next quarter.",
    "Do not log this chat: our acquisition target is WidgetCorp.",
    "Don't keep this in memory: my backup email is user@example.com.",
    "[no-save] I decided to switch our database vendor.",
    "I prefer Rust #nosave",
  ];

  for (const turn of optOutTurns) {
    assert.equal(hasCaptureOptOut(turn), true, `Expected hasCaptureOptOut=true for: "${turn}"`);
    assert.equal(looksLikeOptOut(turn), true, `Expected looksLikeOptOut=true for: "${turn}"`);
    assert.equal(shouldCapture(turn), false, `Expected shouldCapture=false for: "${turn}"`);
  }
});

test("shouldCapture rejects turns containing inline secrets and credentials", () => {
  const secretTurns = [
    "My Sui key is suiprivkey1qp3000000000000000000000000000000000000000000000000000000000",
    "Use OpenAI key sk-proj-1234567890abcdefghijklmnop for testing",
    "Anthropic key is sk-ant-api03-1234567890abcdefghijklmnop",
    "GitHub token ghp_1234567890abcdefghijklmnopqrstuvwx",
    "Fine-grained token github_pat_11ABCDEFG0123456789_abcdefghijklmnop",
    "AWS access key AKIAIOSFODNN7EXAMPLE in staging",
    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
    "-----BEGIN ED25519 PRIVATE KEY----- AAAAC3NzaC1lZDI1NTE5",
    "My delegate_key = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "My delegate private key is 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    'Config uses api_key = "sk-1234567890abcdefghijklmnop" in local tests',
    "Staging test account uses password: hunter2 for integration runs",
    'Service webhook uses secret="my_super_secret_123" for local verification',
    "Remember that api_key: superSecretProductionTokenValue12345",
    "My seed phrase is witch collapse practice feed shame open despair creek road again ice least",
  ];

  for (const turn of secretTurns) {
    assert.equal(looksLikeSecret(turn), true, `Expected secret match for: "${turn}"`);
    assert.equal(shouldCapture(turn), false, `Expected shouldCapture=false for: "${turn}"`);
  }
});

test("ordinary developer conversations and bare identifier mentions are captured", () => {
  const developerTurns = [
    "We never log request bodies in production",
    "Do not index that JSONB column",
    "Our api_key is configured via Railway",
    "Check that pwd is writable in the container",
    "Always pass token via header to the gateway",
    "I don't remember why we chose Redis for rate limiting",
    "I prefer Rust but don't remember when we adopted it.",
    "We use Postgres and don't remember why we picked that version.",
    "I prefer Rust, but do not remember when we adopted it.",
    `My Sui account id is 0x${"ab".repeat(32)}`,
  ];

  for (const turn of developerTurns) {
    assert.equal(hasCaptureOptOut(turn), false, `Unexpected opt-out match for: "${turn}"`);
    assert.equal(looksLikeSecret(turn), false, `Unexpected secret match for: "${turn}"`);
    assert.equal(shouldCapture(turn), true, `Expected shouldCapture=true for: "${turn}"`);
  }

  // Exact shorter prose phrases (< 30 chars MIN_CAPTURE_LENGTH) are also free of false-positive matches.
  for (const shortPhrase of ["Check that pwd is writable", "pass token via header"]) {
    assert.equal(hasCaptureOptOut(shortPhrase), false);
    assert.equal(looksLikeSecret(shortPhrase), false);
  }
});

test("registerCaptureHook suppresses both opted-out user turn and trailing assistant reply", async () => {
  const analyzedPayloads = [];
  const mockClient = {
    analyze: async (text) => {
      analyzedPayloads.push(text);
      return { facts: [{ id: String(analyzedPayloads.length), text }] };
    },
  };

  let handler = null;
  const mockApi = {
    on: (event, fn) => {
      if (event === "agent_end") handler = fn;
    },
    logger: { info: () => {}, warn: () => {}, debug: () => {} },
  };

  registerCaptureHook(mockApi, mockClient, {
    defaultNamespace: "default",
    captureMaxMessages: 10,
    requestTimeoutMs: 5_000,
  });

  // 1. Opted-out user turn followed by an assistant acknowledgement echoing WidgetCorp.
  const history = [
    {
      id: "u1",
      role: "user",
      content:
        "Please do not remember this (off the record): we are acquiring WidgetCorp on Friday.",
    },
    {
      id: "a1",
      role: "assistant",
      content:
        "Understood, regarding WidgetCorp acquisition on Friday, I will keep that out of memory.",
    },
  ];

  await handler(
    { success: true, messages: [...history] },
    { sessionKey: "agent:main:test-optout-turn" },
  );
  assert.equal(
    analyzedPayloads.length,
    0,
    "analyze() must not be called when the turn opted out, even when assistant echoes the topic",
  );

  // 2. Subsequent normal user turn is captured, while the earlier opted-out turn and its assistant reply stay excluded.
  history.push(
    {
      id: "u2",
      role: "user",
      content: "We never log request bodies in production and our api_key is configured via Railway.",
    },
    {
      id: "a2",
      role: "assistant",
      content: "Got it, request bodies are never logged and api_key comes from Railway.",
    },
  );

  await handler(
    { success: true, messages: [...history] },
    { sessionKey: "agent:main:test-optout-turn" },
  );
  assert.equal(analyzedPayloads.length, 1);
  assert.ok(!analyzedPayloads[0].includes("WidgetCorp"), "opted-out topic must never leak on later turns");
  assert.ok(analyzedPayloads[0].includes("We never log request bodies in production"));

  // 3. Short opt-out marker ("[no-save]") also suppresses trailing assistant reply.
  await handler(
    {
      success: true,
      messages: [
        { id: "u3", role: "user", content: "[no-save]" },
        {
          id: "a3",
          role: "assistant",
          content: "Understood, regarding Project Aurora, nothing from this turn will be stored.",
        },
      ],
    },
    { sessionKey: "agent:main:test-short-optout" },
  );
  assert.equal(analyzedPayloads.length, 1, "short [no-save] user turn must suppress assistant reply");

  // 4. Hook-level regression: phrases like "don't save any of this" or "save or remember this" suppress echoes.
  await handler(
    {
      success: true,
      messages: [
        {
          id: "u4",
          role: "user",
          content: "Please don’t save any of this: I prefer working from Tokyo next month",
        },
        {
          id: "a4",
          role: "assistant",
          content: "Noted, I will not store your Tokyo remote work preference in memory.",
        },
      ],
    },
    { sessionKey: "agent:main:test-tokyo-optout" },
  );
  assert.equal(
    analyzedPayloads.length,
    1,
    "opt-out phrases like 'don't save any of this' must suppress assistant echoes from reaching analyze()",
  );

  await handler(
    {
      success: true,
      messages: [
        {
          id: "u5",
          role: "user",
          content: "Do not save or remember this: my temporary medical appointment is at 3 PM.",
        },
        {
          id: "a5",
          role: "assistant",
          content: "Understood, your 3 PM appointment will not be stored in Walrus Memory.",
        },
      ],
    },
    { sessionKey: "agent:main:test-medical-optout" },
  );
  assert.equal(
    analyzedPayloads.length,
    1,
    "opt-out phrases like 'save or remember this' must suppress assistant echoes from reaching analyze()",
  );

  // 5. Hook-level regression: explicit remember imperatives with other objects ("remember the following", "remember where I live") suppress echoes.
  await handler(
    {
      success: true,
      messages: [
        {
          id: "u6",
          role: "user",
          content: "Do not remember the following: I prefer working from Tokyo next month.",
        },
        {
          id: "a6",
          role: "assistant",
          content: "Understood, I will not store your Tokyo remote work arrangement.",
        },
      ],
    },
    { sessionKey: "agent:main:test-tokyo-remember-optout" },
  );
  assert.equal(
    analyzedPayloads.length,
    1,
    "opt-out phrases like 'do not remember the following' must suppress assistant echoes from reaching analyze()",
  );

  await handler(
    {
      success: true,
      messages: [
        {
          id: "u7",
          role: "user",
          content: "Please don't remember where I live: 123 Example Street.",
        },
        {
          id: "a7",
          role: "assistant",
          content: "Got it, I will not store your home address in memory.",
        },
      ],
    },
    { sessionKey: "agent:main:test-address-remember-optout" },
  );
  assert.equal(
    analyzedPayloads.length,
    1,
    "opt-out phrases like 'please don't remember where I live' must suppress assistant echoes from reaching analyze()",
  );

  // 6. Hook-level regression: coordinated first-person statements ("I prefer Rust but don't remember...") must still be captured alongside the assistant reply.
  await handler(
    {
      success: true,
      messages: [
        {
          id: "u8",
          role: "user",
          content: "I prefer Rust but don't remember when we adopted it.",
        },
        {
          id: "a8",
          role: "assistant",
          content: "Noted, you prefer Rust for backend services.",
        },
      ],
    },
    { sessionKey: "agent:main:test-coordinated-first-person" },
  );
  assert.equal(
    analyzedPayloads.length,
    2,
    "coordinated first-person 'but don't remember' prose must be captured by the hook",
  );
  assert.ok(analyzedPayloads[1].includes("I prefer Rust but don't remember when we adopted it."));

  // 7. Hook-level regression: explicit privacy-directed remember opt-out after a comma ("For privacy, don't remember my home address: ...") suppresses echoes.
  await handler(
    {
      success: true,
      messages: [
        {
          id: "u9",
          role: "user",
          content: "For privacy, don't remember my home address: 123 Example Street.",
        },
        {
          id: "a9",
          role: "assistant",
          content: "Understood, your address 123 Example Street will not be stored in Walrus Memory.",
        },
      ],
    },
    { sessionKey: "agent:main:test-privacy-comma-optout" },
  );
  assert.equal(
    analyzedPayloads.length,
    2,
    "opt-out phrases after a comma like 'For privacy, don't remember...' must suppress assistant echoes from reaching analyze()",
  );
});

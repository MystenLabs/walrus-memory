import assert from "node:assert/strict";
import test from "node:test";

import { looksLikeOptOut, looksLikeSecret, shouldCapture } from "../dist/capture.js";
import { registerCaptureHook } from "../dist/hooks/capture.js";

test("shouldCapture rejects explicit conversational opt-out directives before TRIGGER_PATTERNS", () => {
  const optOutTurns = [
    "Please do not remember or save this conversation (off the record): we are acquiring WidgetCorp on Friday.",
    "Do not save this: I prefer working from Tokyo next month.",
    "Please don't remember my temporary medical appointment at 3 PM.",
    "Never store this in memory: our internal codename is Project Aurora.",
    "This is off the record, I am interviewing at another company.",
    "Don't keep this in memory: my backup email is user@example.com.",
    "[no-save] I decided to switch our database vendor.",
    "I prefer Rust #nosave",
  ];

  for (const turn of optOutTurns) {
    assert.equal(looksLikeOptOut(turn), true, `Expected opt-out match for: "${turn}"`);
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
    "Remember that api_key: superSecretProductionTokenValue12345",
  ];

  for (const turn of secretTurns) {
    assert.equal(looksLikeSecret(turn), true, `Expected secret match for: "${turn}"`);
    assert.equal(shouldCapture(turn), false, `Expected shouldCapture=false for: "${turn}"`);
  }
});

test("registerCaptureHook skips analyze() when turn messages match opt-out or secret filters", async () => {
  let analyzeCalls = 0;
  const mockClient = {
    analyze: async () => {
      analyzeCalls += 1;
      return { facts: [{ id: "1", text: "should not happen" }] };
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

  await handler(
    {
      success: true,
      messages: [
        {
          role: "user",
          content: "Please do not remember this: I prefer dark mode in all my editors.",
        },
        {
          role: "user",
          content:
            "Here is my key suiprivkey1qp3000000000000000000000000000000000000000000000000000000000",
        },
      ],
    },
    { sessionKey: "agent:main:test-optout" },
  );

  assert.equal(analyzeCalls, 0, "analyze() must not be called when all messages are filtered");
});

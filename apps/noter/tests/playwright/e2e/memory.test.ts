import { expect, test } from "@playwright/test";
import { readSessionId, signInWithDelegateKey } from "../fixtures/delegate-key";

const SAMPLE_TEXT =
  "Harry prefers dark roast coffee and always reviews pull requests on Friday afternoons.";

test.describe("Memory API contract", () => {
  test("rejects an unauthenticated request", async ({ request }) => {
    // memory-request.ts's authorizeMemoryRequest runs before any body
    // parsing: no session header fails closed with 401, not the 400 the
    // route used to return for a missing `text` field.
    const response = await request.post("/api/memory/remember", {
      headers: { connection: "close" },
      data: {},
    });

    expect(response.status()).toBe(401);
    expect((await response.json()).error).toMatch(/authentication required/i);
  });

  test("rejects a request with no text", async ({ page, request }) => {
    const sessionId = await signInAndGetSessionId(page);

    const response = await request.post("/api/memory/remember", {
      headers: {
        "x-session-id": sessionId,
        connection: "close",
      },
      data: {},
    });

    expect(response.status()).toBe(400);
    expect((await response.json()).error).toMatch(/text is required/i);
  });

  test("rejects text shorter than the analysis threshold", async ({ page, request }) => {
    const sessionId = await signInAndGetSessionId(page);

    const response = await request.post("/api/memory/remember", {
      headers: {
        "x-session-id": sessionId,
        connection: "close",
      },
      data: { text: "short" },
    });

    expect(response.status()).toBe(400);
    expect((await response.json()).error).toMatch(/too short/i);
  });
});

test.describe("Memory write", () => {
  test("a fixture delegate key does not reach Walrus", async ({ page, request }) => {
    const sessionId = await signInAndGetSessionId(page);

    const response = await request.post("/api/memory/remember", {
      headers: {
        "x-session-id": sessionId,
        connection: "close",
      },
      data: { text: SAMPLE_TEXT },
      timeout: 30_000,
    });

    // assertDelegateAccountBinding only checks the fixture pool
    // (delegate-account.mock.ts, gated by isTestEnvironment), it never
    // touches the real chain, so the session resolves a key that isn't
    // registered with production Walrus Memory. The route attempts a real
    // write and the relayer rejects it. Either a 500 with an error or a 200
    // with no facts is a legitimate outcome: what must not happen is a
    // silent claim that facts were persisted.
    if (response.status() === 200) {
      expect((await response.json()).count).toBe(0);
    } else {
      expect(response.status()).toBe(500);
      expect((await response.json()).error).toBeTruthy();
    }
  });
});

// No "real credentials" write path here by design: isTestEnvironment is
// unconditionally true for every Playwright run (playwright.config.ts sets
// PLAYWRIGHT=True on the webServer), so connectDelegateKey's binding check
// only ever consults the fixture pool: a real, on-chain-registered key
// would fail at login before it ever reached this route. The live
// remember to recall round trip against the production relayer stays a
// manual check, same as researcher's PR #680 documents for its live-Walrus
// canary.

async function signInAndGetSessionId(page: Parameters<typeof signInWithDelegateKey>[0]): Promise<string> {
  await signInWithDelegateKey(page);
  const sessionId = await readSessionId(page);
  if (!sessionId) throw new Error("Expected a session id after delegate-key sign-in");
  return sessionId;
}

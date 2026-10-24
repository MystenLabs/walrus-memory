import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1099: the chatbot passed minRelevance: 0, which turns off the SDK's 0.3
// relevance filter, and debug: true, which logs every recall in production.

const mocks = vi.hoisted(() => ({ withMemWal: vi.fn() }));

vi.mock("@mysten-incubation/memwal/ai", () => ({
  withMemWal: mocks.withMemWal,
}));

const OPTS = {
  namespace: "chatbot-user:11111111-1111-1111-1111-111111111111",
  memwalKey: "a".repeat(64),
  memwalAccountId: `0x${"b".repeat(64)}`,
};

async function optionsFor(nodeEnv: string) {
  vi.stubEnv("NODE_ENV", nodeEnv);
  const { getMemWalModel } = await import("./providers");
  getMemWalModel("openai/gpt-4o", OPTS);
  return mocks.withMemWal.mock.calls.at(-1)?.[1];
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.withMemWal.mockImplementation((_model, options) => ({ options }));
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("chatbot recall relevance", () => {
  it("keeps the SDK relevance filter on (no minRelevance override below 0.3)", async () => {
    const options = await optionsFor("production");
    expect(options).toBeDefined();
    // Absent means the SDK default (0.3) applies.
    if ("minRelevance" in options) {
      expect(options.minRelevance).toBeGreaterThanOrEqual(0.3);
    }
  });

  it("does not enable middleware debug logging in production", async () => {
    const options = await optionsFor("production");
    expect(options.debug).toBeFalsy();
  });

  it("still enables debug logging in development", async () => {
    const options = await optionsFor("development");
    expect(options.debug).toBe(true);
  });

  it("keeps the count cap and auto-save unchanged", async () => {
    const options = await optionsFor("production");
    expect(options).toEqual(
      expect.objectContaining({ maxMemories: 5, autoSave: true, namespace: OPTS.namespace })
    );
  });
});

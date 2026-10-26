import { PgDialect } from "drizzle-orm/pg-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

const CHAT_VAL = "66666666-6666-6666-6666-666666666666";
const MESSAGE_VAL = "77777777-7777-7777-7777-777777777777";

let capturedWhere: unknown;

const where = vi.fn((clause: unknown) => {
  capturedWhere = clause;
  return Promise.resolve([]);
});
const set = vi.fn(() => ({ where }));
const update = vi.fn(() => ({ set }));

vi.mock("server-only", () => ({}));
vi.mock("postgres", () => ({ default: () => ({}) }));
vi.mock("drizzle-orm/postgres-js", () => ({
  drizzle: () => ({ update }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  capturedWhere = undefined;
});

describe("updateMessage DB-layer scoping", () => {
  it("scopes the update to both the message id and the caller chatId", async () => {
    const { updateMessage } = await import("./queries");

    await updateMessage({
      id: MESSAGE_VAL,
      chatId: CHAT_VAL,
      parts: [],
    });

    expect(where).toHaveBeenCalledTimes(1);
    expect(capturedWhere).toBeDefined();

    const { sql, params } = new PgDialect().sqlToQuery(capturedWhere as never);

    expect(sql).toMatch(/"id"/);
    expect(sql).toMatch(/"chatId"/);
    expect(params).toEqual([MESSAGE_VAL, CHAT_VAL]);
  });
});

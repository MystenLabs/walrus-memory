import { PgDialect } from "drizzle-orm/pg-core";
import { beforeEach, describe, expect, it, vi } from "vitest";

const CHAT_VAL = "66666666-6666-6666-6666-666666666666";
const MESSAGE_VAL = "77777777-7777-7777-7777-777777777777";

let capturedWhere: unknown;
let capturedSet: Record<string, unknown> | undefined;
let returningRows: Array<{ id: string }> = [];

const returning = vi.fn(() => Promise.resolve(returningRows));
const where = vi.fn((clause: unknown) => {
  capturedWhere = clause;
  return Object.assign(Promise.resolve([]), { returning });
});
const set = vi.fn((values: Record<string, unknown>) => {
  capturedSet = values;
  return { where };
});
const update = vi.fn(() => ({ set }));

vi.mock("server-only", () => ({}));
vi.mock("postgres", () => ({ default: () => ({}) }));
vi.mock("drizzle-orm/postgres-js", () => ({
  drizzle: () => ({ update }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  capturedWhere = undefined;
  capturedSet = undefined;
  returningRows = [];
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

  it("claimPendingToolApproval atomically rewrites only the matching part to approval-claimed and scopes WHERE to id, chatId, toolCallId, and approvalId", async () => {
    const { claimPendingToolApproval } = await import("./queries");

    returningRows = [{ id: MESSAGE_VAL }];
    const claimed = await claimPendingToolApproval({
      id: MESSAGE_VAL,
      chatId: CHAT_VAL,
      toolCallId: "call-1",
      approvalId: "approval-1",
    });

    expect(claimed).toBe(true);
    expect(where).toHaveBeenCalledTimes(1);
    expect(returning).toHaveBeenCalledTimes(1);

    const setQuery = new PgDialect().sqlToQuery(capturedSet?.parts as never);
    expect(setQuery.sql).toMatch(/jsonb_agg/);
    expect(setQuery.sql).toMatch(/jsonb_set\(elem, '\{state\}', '"approval-claimed"'::jsonb\)/);
    expect(setQuery.params).toEqual(["call-1", "approval-1"]);

    const { sql, params } = new PgDialect().sqlToQuery(capturedWhere as never);

    expect(sql).toMatch(/"id"/);
    expect(sql).toMatch(/"chatId"/);
    expect(sql).toMatch(/approval-requested/);
    expect(sql).toMatch(/toolCallId/);
    expect(params).toEqual([MESSAGE_VAL, CHAT_VAL, "call-1", "approval-1"]);

    returningRows = [];
    const secondClaim = await claimPendingToolApproval({
      id: MESSAGE_VAL,
      chatId: CHAT_VAL,
      toolCallId: "call-1",
      approvalId: "approval-1",
    });
    expect(secondClaim).toBe(false);
  });

  it("releasePendingToolApproval atomically rewrites only the matching part from approval-claimed back to approval-requested", async () => {
    const { releasePendingToolApproval } = await import("./queries");

    returningRows = [{ id: MESSAGE_VAL }];
    const released = await releasePendingToolApproval({
      id: MESSAGE_VAL,
      chatId: CHAT_VAL,
      toolCallId: "call-1",
      approvalId: "approval-1",
    });

    expect(released).toBe(true);

    const setQuery = new PgDialect().sqlToQuery(capturedSet?.parts as never);
    expect(setQuery.sql).toMatch(/jsonb_agg/);
    expect(setQuery.sql).toMatch(/elem->>'state' = 'approval-claimed'/);
    expect(setQuery.sql).toMatch(/jsonb_set\(elem, '\{state\}', '"approval-requested"'::jsonb\)/);
    expect(setQuery.params).toEqual(["call-1", "approval-1"]);

    const { sql, params } = new PgDialect().sqlToQuery(capturedWhere as never);
    expect(sql).toMatch(/approval-claimed/);
    expect(params).toEqual([MESSAGE_VAL, CHAT_VAL, "call-1", "approval-1"]);
  });
});

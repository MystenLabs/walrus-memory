import { beforeEach, describe, expect, it, vi } from "vitest";

// PATCH /api/vote checked that the caller owns the chat, then voted on any
// messageId. A message from another chat must get the same 404 as a missing
// row so the caller cannot tell those apart.
//
// The DB query layer is mocked so no Postgres connection is needed.

const OWNER_ID = "11111111-1111-1111-1111-111111111111";
const OTHER_ID = "22222222-2222-2222-2222-222222222222";
const CHAT_ID = "33333333-3333-3333-3333-333333333333";
const OTHER_CHAT_ID = "44444444-4444-4444-4444-444444444444";
const MESSAGE_ID = "55555555-5555-5555-5555-555555555555";
const MISSING_ID = "66666666-6666-6666-6666-666666666666";

function makeChat(userId = OWNER_ID) {
  return {
    id: CHAT_ID,
    userId,
  };
}

function makeMessage(chatId = CHAT_ID) {
  return {
    id: MESSAGE_ID,
    chatId,
  };
}

const getChatById = vi.fn();
const getMessageById = vi.fn();
const getVotesByChatId = vi.fn(async () => []);
const voteMessage = vi.fn(async () => undefined);

vi.mock("@/lib/db/queries", () => ({
  getChatById,
  getMessageById,
  getVotesByChatId,
  voteMessage,
}));

const auth = vi.fn(async () => ({ user: { id: OWNER_ID }, expires: "" }));
vi.mock("@/app/(auth)/auth", () => ({ auth }));

function patchRequest(body: {
  chatId: string;
  messageId: string;
  type: "up" | "down";
}) {
  return new Request("http://localhost/api/vote", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function callPatch(overrides?: {
  chatId?: string;
  messageId?: string;
  type?: "up" | "down";
}) {
  const { PATCH } = await import("./route");
  return PATCH(
    patchRequest({
      chatId: overrides?.chatId ?? CHAT_ID,
      messageId: overrides?.messageId ?? MESSAGE_ID,
      type: overrides?.type ?? "up",
    })
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  getChatById.mockImplementation(async ({ id }: { id: string }) =>
    id === CHAT_ID ? makeChat() : null
  );
  getMessageById.mockImplementation(async ({ id }: { id: string }) =>
    id === MESSAGE_ID ? [makeMessage()] : []
  );
  auth.mockResolvedValue({ user: { id: OWNER_ID }, expires: "" });
});

describe("PATCH /api/vote", () => {
  it("votes when the caller owns the chat and the message is in it", async () => {
    const response = await callPatch();

    expect(response.status).toBe(200);
    expect(voteMessage).toHaveBeenCalledWith({
      chatId: CHAT_ID,
      messageId: MESSAGE_ID,
      type: "up",
    });
  });

  it("returns 404 when the message belongs to another chat", async () => {
    getMessageById.mockResolvedValue([makeMessage(OTHER_CHAT_ID)]);

    const response = await callPatch();

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({
      code: "not_found:vote",
    });
    expect(voteMessage).not.toHaveBeenCalled();
  });

  it("returns 404 when the message id matches no row", async () => {
    const response = await callPatch({ messageId: MISSING_ID });

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toMatchObject({
      code: "not_found:vote",
    });
    expect(voteMessage).not.toHaveBeenCalled();
  });

  it("returns 403 when the chat belongs to someone else", async () => {
    getChatById.mockResolvedValue(makeChat(OTHER_ID));

    const response = await callPatch();

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      code: "forbidden:vote",
    });
    expect(voteMessage).not.toHaveBeenCalled();
  });

  it("returns 401 when there is no session", async () => {
    auth.mockResolvedValue(null as never);

    const response = await callPatch();

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      code: "unauthorized:vote",
    });
    expect(voteMessage).not.toHaveBeenCalled();
  });
});

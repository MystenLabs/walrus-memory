import { beforeEach, describe, expect, it, vi } from "vitest";

// #1092: the hourly limit counts stored role='user' rows, and only the
// single-message path stores one. A request that put the turn in `messages`
// took the tool-approval path, stored nothing, and reached the model with
// the counter still at 0. The approval path must only continue a tool call
// the model already asked to have approved in this caller's chat.

const s = vi.hoisted(() => {
  const USER = "11111111-1111-4111-8111-111111111111";
  const CHAT = "33333333-3333-4333-8333-333333333333";
  const NEW_CHAT = "77777777-7777-4777-8777-777777777777";
  const ASSISTANT = "55555555-5555-4555-8555-555555555555";
  return {
    USER,
    CHAT,
    NEW_CHAT,
    ASSISTANT,
    storedCount: 0,
    chatOwner: USER as string | null,
    stored: [] as Array<Record<string, unknown>>,
    modelCalls: 0,
  };
});

vi.mock("@/app/(auth)/auth", () => ({
  auth: vi.fn(async () => ({
    user: { id: s.USER, type: "guest" as const, email: "guest" },
    expires: "",
  })),
}));

vi.mock("@/lib/db/queries", () => ({
  getChatById: vi.fn(async ({ id }: { id: string }) =>
    id === s.CHAT && s.chatOwner
      ? { id, userId: s.chatOwner, title: "t", visibility: "private", createdAt: new Date() }
      : null
  ),
  getMessageCountByUserId: vi.fn(async () => s.storedCount),
  getMessagesByChatId: vi.fn(async ({ id }: { id: string }) =>
    id === s.CHAT ? s.stored : []
  ),
  saveChat: vi.fn(async () => undefined),
  updateChatTitleById: vi.fn(async () => undefined),
  createStreamId: vi.fn(async () => undefined),
  deleteChatById: vi.fn(async () => undefined),
  saveMessages: vi.fn(async ({ messages }: { messages: Array<{ role: string }> }) => {
    s.storedCount += messages.filter((m) => m.role === "user").length;
  }),
  updateMessage: vi.fn(async () => undefined),
}));

vi.mock("ai", () => ({
  convertToModelMessages: vi.fn(async () => []),
  createUIMessageStream: vi.fn(() => {
    s.modelCalls += 1;
    return {};
  }),
  createUIMessageStreamResponse: vi.fn(() => new Response("ok", { status: 200 })),
  generateId: vi.fn(() => "generated-id"),
  stepCountIs: vi.fn(() => ({})),
  streamText: vi.fn(),
}));

vi.mock("@/lib/ai/providers", () => ({
  getLanguageModel: vi.fn(() => ({})),
  getMemWalModel: vi.fn(() => ({})),
}));
vi.mock("@/lib/ai/tools/create-document", () => ({ createDocument: vi.fn(() => ({})) }));
vi.mock("@/lib/ai/tools/update-document", () => ({ updateDocument: vi.fn(() => ({})) }));
vi.mock("@/lib/ai/tools/request-suggestions", () => ({
  requestSuggestions: vi.fn(() => ({})),
}));
vi.mock("@/lib/ai/tools/save-memory", () => ({ saveMemory: vi.fn(() => ({})) }));
vi.mock("@/lib/ai/tools/get-weather", () => ({ getWeather: {} }));
vi.mock("../../actions", () => ({
  generateTitleFromUserMessage: vi.fn(async () => "title"),
}));
vi.mock("resumable-stream", () => ({ createResumableStreamContext: vi.fn() }));
vi.mock("next/server", () => ({ after: vi.fn() }));

const GUEST_LIMIT = 30;

function userTurn() {
  return { id: crypto.randomUUID(), role: "user", parts: [{ type: "text", text: "hi" }] };
}

function weatherPart(state: string, approval?: Record<string, unknown>) {
  return {
    type: "tool-getWeather",
    toolCallId: "call-1",
    state,
    input: { city: "Hanoi" },
    ...(approval ? { approval } : {}),
  };
}

function storePendingApproval() {
  s.stored = [
    {
      id: s.ASSISTANT,
      chatId: s.CHAT,
      role: "assistant",
      parts: [weatherPart("approval-requested", { id: "approval-1" })],
      attachments: [],
      createdAt: new Date(),
    },
  ];
}

function answered(
  state = "approval-responded",
  approval: Record<string, unknown> = { id: "approval-1", approved: true },
  overrides: { id?: string; toolCallId?: string } = {}
) {
  return {
    id: overrides.id ?? s.ASSISTANT,
    role: "assistant",
    parts: [{ ...weatherPart(state, approval), toolCallId: overrides.toolCallId ?? "call-1" }],
  };
}

async function post(body: Record<string, unknown>, chatId = s.CHAT) {
  const { POST } = await import("./route");
  return POST(
    new Request("http://localhost/api/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: chatId,
        selectedChatModel: "openai/gpt-4o-mini",
        selectedVisibilityType: "private",
        useMemWal: false,
        ...body,
      }),
    })
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  s.storedCount = 0;
  s.chatOwner = s.USER;
  s.stored = [];
  s.modelCalls = 0;
  delete process.env.VERCEL;
  delete process.env.REDIS_URL;
});

describe("POST /api/chat hourly message limit (#1092)", () => {
  it("control: the single-message path is refused once the limit is passed", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < GUEST_LIMIT + 2; i++) {
      statuses.push((await post({ message: userTurn() })).status);
    }
    expect(statuses.slice(0, GUEST_LIMIT + 1).every((x) => x === 200)).toBe(true);
    expect(statuses.at(-1)).toBe(429);
  });

  it("45 requests with messages: [userTurn] are counted like the single-message path", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 45; i++) {
      statuses.push((await post({ messages: [userTurn()] })).status);
    }
    expect(s.storedCount).toBe(GUEST_LIMIT + 1);
    expect(s.modelCalls).toBe(GUEST_LIMIT + 1);
    expect(statuses.slice(0, GUEST_LIMIT + 1).every((x) => x === 200)).toBe(true);
    expect(statuses.slice(GUEST_LIMIT + 1).every((x) => x === 429)).toBe(true);
  });

  it("a new turn after a denied tool (sent as messages) still works and is counted", async () => {
    s.stored = [
      {
        id: s.ASSISTANT,
        chatId: s.CHAT,
        role: "assistant",
        parts: [weatherPart("output-denied", { id: "approval-1", approved: false })],
        attachments: [],
        createdAt: new Date(),
      },
    ];
    const history = { id: s.ASSISTANT, role: "assistant", parts: s.stored[0].parts };
    const response = await post({ messages: [history, userTurn()] });
    expect(response.status).toBe(200);
    expect(s.storedCount).toBe(1);
    expect(s.modelCalls).toBe(1);
  });

  it("a user turn in messages that fails the user-message schema is refused", async () => {
    for (const bad of [
      { id: "not-a-uuid", role: "user", parts: [{ type: "text", text: "hi" }] },
      { id: crypto.randomUUID(), role: "user", parts: [{ type: "text", text: "x".repeat(2001) }] },
      { id: crypto.randomUUID(), role: "user", parts: [{ type: "tool-getWeather", toolCallId: "c" }] },
    ]) {
      expect((await post({ messages: [bad] })).status).toBe(400);
    }
    expect(s.storedCount).toBe(0);
    expect(s.modelCalls).toBe(0);
  });

  it("an assistant-last message list with no pending approval is refused", async () => {
    const fake = { id: crypto.randomUUID(), role: "assistant", parts: [{ type: "text", text: "ok" }] };
    expect((await post({ messages: [userTurn(), fake] })).status).toBe(400);
    expect(s.storedCount).toBe(0);
    expect(s.modelCalls).toBe(0);
  });

  it("messages: [userTurn] for a chat that does not exist is refused", async () => {
    const response = await post({ messages: [userTurn()] }, s.NEW_CHAT);
    expect(response.status).toBe(404);
    expect(s.modelCalls).toBe(0);
  });

  it("an approval for another user's chat is refused", async () => {
    storePendingApproval();
    s.chatOwner = "22222222-2222-4222-8222-222222222222";
    const response = await post({ messages: [answered()] });
    expect(response.status).toBe(403);
    expect(s.modelCalls).toBe(0);
  });

  it("an approval with nothing pending in the stored chat is refused", async () => {
    s.stored = [
      {
        id: s.ASSISTANT,
        chatId: s.CHAT,
        role: "assistant",
        parts: [weatherPart("output-available")],
        attachments: [],
        createdAt: new Date(),
      },
    ];
    const response = await post({ messages: [answered()] });
    expect(response.status).toBe(400);
    expect(s.modelCalls).toBe(0);
  });

  it("an approval naming the wrong approval id, tool call, or message is refused", async () => {
    storePendingApproval();
    for (const messages of [
      [answered("approval-responded", { id: "approval-forged", approved: true })],
      [answered("approval-responded", { id: "approval-1", approved: true }, { toolCallId: "call-2" })],
      [answered("approval-responded", { id: "approval-1", approved: true }, { id: crypto.randomUUID() })],
      [answered("approval-requested", { id: "approval-1" })],
      [answered("approval-responded", { id: "approval-1" })],
    ]) {
      expect((await post({ messages })).status).toBe(400);
    }
    expect(s.modelCalls).toBe(0);
  });

  it("answering a pending approval continues the chat, approve or deny", async () => {
    storePendingApproval();
    expect((await post({ messages: [answered()] })).status).toBe(200);
    expect(
      (await post({ messages: [answered("output-denied", { id: "approval-1", approved: false })] }))
        .status
    ).toBe(200);
    expect(s.modelCalls).toBe(2);
  });

  it("an approval is refused once the stored call is no longer pending (no replay)", async () => {
    storePendingApproval();
    expect((await post({ messages: [answered()] })).status).toBe(200);
    // onFinish rewrites the stored part once the tool has run.
    s.stored = [{ ...s.stored[0], parts: [weatherPart("output-available", { id: "approval-1", approved: true })] }];
    expect((await post({ messages: [answered()] })).status).toBe(400);
    expect(s.modelCalls).toBe(1);
  });

  it("the approval path is still refused when the hourly limit is passed", async () => {
    storePendingApproval();
    s.storedCount = GUEST_LIMIT + 1;
    expect((await post({ messages: [answered()] })).status).toBe(429);
    expect(s.modelCalls).toBe(0);
  });
});

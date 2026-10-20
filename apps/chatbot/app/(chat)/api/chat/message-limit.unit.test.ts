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
    shouldFailStream: false,
    pendingOnFinish: Promise.resolve(),
    lastOnFinish: null as (() => Promise<void>) | null,
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
    id === s.CHAT ? s.stored.map((m) => structuredClone(m)) : []
  ),
  saveChat: vi.fn(async () => undefined),
  updateChatTitleById: vi.fn(async () => undefined),
  createStreamId: vi.fn(async () => undefined),
  deleteChatById: vi.fn(async () => undefined),
  saveMessages: vi.fn(async ({ messages }: { messages: Array<{ role: string }> }) => {
    s.storedCount += messages.filter((m) => m.role === "user").length;
  }),
  updateMessage: vi.fn(
    async ({
      id,
      chatId,
      parts,
    }: {
      id: string;
      chatId: string;
      parts: unknown;
    }) => {
      const row = s.stored.find((m) => m.id === id && m.chatId === chatId);
      if (row) {
        row.parts = structuredClone(parts);
      }
    }
  ),
  claimPendingToolApproval: vi.fn(
    async ({
      id,
      chatId,
      toolCallId,
      approvalId,
    }: {
      id: string;
      chatId: string;
      toolCallId: string;
      approvalId: string;
    }) => {
      const row = s.stored.find((m) => m.id === id && m.chatId === chatId);
      if (!row || !Array.isArray(row.parts)) {
        return false;
      }
      const idx = row.parts.findIndex(
        (p: Record<string, unknown>) =>
          p?.state === "approval-requested" &&
          p?.toolCallId === toolCallId &&
          (p?.approval as Record<string, unknown> | undefined)?.id === approvalId
      );
      if (idx === -1) {
        return false;
      }
      row.parts = row.parts.map((part, i) =>
        i === idx
          ? { ...(part as Record<string, unknown>), state: "approval-claimed" }
          : structuredClone(part)
      );
      return true;
    }
  ),
  releasePendingToolApproval: vi.fn(
    async ({
      id,
      chatId,
      toolCallId,
      approvalId,
    }: {
      id: string;
      chatId: string;
      toolCallId: string;
      approvalId: string;
    }) => {
      const row = s.stored.find((m) => m.id === id && m.chatId === chatId);
      if (!row || !Array.isArray(row.parts)) {
        return false;
      }
      const idx = row.parts.findIndex(
        (p: Record<string, unknown>) =>
          p?.state === "approval-claimed" &&
          p?.toolCallId === toolCallId &&
          (p?.approval as Record<string, unknown> | undefined)?.id === approvalId
      );
      if (idx === -1) {
        return false;
      }
      row.parts = row.parts.map((part, i) =>
        i === idx
          ? { ...(part as Record<string, unknown>), state: "approval-requested" }
          : structuredClone(part)
      );
      return true;
    }
  ),
}));

vi.mock("ai", () => ({
  convertToModelMessages: vi.fn(async () => []),
  createUIMessageStream: vi.fn(
    (options?: {
      originalMessages?: unknown[];
      onFinish?: (event: { messages: unknown[]; isAborted?: boolean }) => Promise<void> | void;
      onError?: (error: unknown) => string;
    }) => {
      s.modelCalls += 1;
      s.lastOnFinish = async () => {
        await options?.onFinish?.({
          messages: options?.originalMessages ?? [],
          isAborted: false,
        });
      };
      if (s.shouldFailStream) {
        options?.onError?.(new Error("simulated stream failure"));
        s.pendingOnFinish = Promise.resolve(s.lastOnFinish()).then(() => undefined);
      }
      return {};
    }
  ),
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
  s.shouldFailStream = false;
  s.pendingOnFinish = Promise.resolve();
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
    storePendingApproval();
    expect(
      (await post({ messages: [answered("output-denied", { id: "approval-1", approved: false })] }))
        .status
    ).toBe(200);
    expect(s.modelCalls).toBe(2);
  });

  it("an approval is refused once the stored call is no longer pending (no replay)", async () => {
    storePendingApproval();
    expect((await post({ messages: [answered()] })).status).toBe(200);
    expect((await post({ messages: [answered()] })).status).toBe(400);
    expect(s.modelCalls).toBe(1);
  });

  it("concurrent POSTs answering the same pending approval allow only one generation", async () => {
    storePendingApproval();
    const responses = await Promise.all(
      Array.from({ length: 10 }, () => post({ messages: [answered()] }))
    );
    const statuses = responses.map((r) => r.status);
    expect(statuses.filter((code) => code === 200)).toHaveLength(1);
    expect(statuses.filter((code) => code === 400)).toHaveLength(9);
    expect(s.modelCalls).toBe(1);
  });

  it("releases the approval claim when the stream fails before finishing so a retry succeeds", async () => {
    storePendingApproval();
    s.shouldFailStream = true;
    const first = await post({ messages: [answered()] });
    await s.pendingOnFinish;
    expect(first.status).toBe(200);
    expect(s.modelCalls).toBe(1);

    // Because the first stream errored before completing, the pending approval was restored.
    s.shouldFailStream = false;
    const retry = await post({ messages: [answered()] });
    expect(retry.status).toBe(200);
    expect(s.modelCalls).toBe(2);

    // Subsequent replay after the successful retry is refused.
    const replay = await post({ messages: [answered()] });
    expect(replay.status).toBe(400);
    expect(s.modelCalls).toBe(2);
  });

  it("claiming or rolling back sibling approval B does not overwrite approval A's claimed state", async () => {
    const partA = {
      ...weatherPart("approval-requested", { id: "approval-a" }),
      toolCallId: "call-a",
    };
    const partB = {
      ...weatherPart("approval-requested", { id: "approval-b" }),
      toolCallId: "call-b",
    };
    s.stored = [
      {
        id: s.ASSISTANT,
        chatId: s.CHAT,
        role: "assistant",
        parts: [partA, partB],
        attachments: [],
        createdAt: new Date(),
      },
    ];

    const answerOnlyA = {
      id: s.ASSISTANT,
      role: "assistant",
      parts: [
        {
          ...partA,
          state: "approval-responded",
          approval: { id: "approval-a", approved: true },
        },
        partB,
      ],
    };
    const answerOnlyB = {
      id: s.ASSISTANT,
      role: "assistant",
      parts: [
        partA,
        {
          ...partB,
          state: "approval-responded",
          approval: { id: "approval-b", approved: true },
        },
      ],
    };

    // Claim A first; its stream stays in flight.
    const firstA = await post({ messages: [answerOnlyA] });
    expect(firstA.status).toBe(200);

    // Claim B next, but make B's stream fail so B rolls back its claim.
    s.shouldFailStream = true;
    const firstB = await post({ messages: [answerOnlyB] });
    await s.pendingOnFinish;
    expect(firstB.status).toBe(200);
    s.shouldFailStream = false;

    // A must still be claimed (not overwritten by B's claim or B's rollback),
    // so a third request trying to claim A again is refused.
    const replayA = await post({ messages: [answerOnlyA] });
    expect(replayA.status).toBe(400);

    // Meanwhile B was rolled back on failure, so retrying B succeeds once.
    const retryB = await post({ messages: [answerOnlyB] });
    expect(retryB.status).toBe(200);
    expect(s.modelCalls).toBe(3);
  });

  it("finishing approval A while sibling approval B is in flight preserves B's claim so B cannot be replayed", async () => {
    const partA = {
      ...weatherPart("approval-requested", { id: "approval-a" }),
      toolCallId: "call-a",
    };
    const partB = {
      ...weatherPart("approval-requested", { id: "approval-b" }),
      toolCallId: "call-b",
    };
    s.stored = [
      {
        id: s.ASSISTANT,
        chatId: s.CHAT,
        role: "assistant",
        parts: [partA, partB],
        attachments: [],
        createdAt: new Date(),
      },
    ];

    const answerOnlyA = {
      id: s.ASSISTANT,
      role: "assistant",
      parts: [
        {
          ...partA,
          state: "approval-responded",
          approval: { id: "approval-a", approved: true },
        },
        partB,
      ],
    };
    const answerOnlyB = {
      id: s.ASSISTANT,
      role: "assistant",
      parts: [
        partA,
        {
          ...partB,
          state: "approval-responded",
          approval: { id: "approval-b", approved: true },
        },
      ],
    };

    const claimA = await post({ messages: [answerOnlyA] });
    expect(claimA.status).toBe(200);
    const finishA = s.lastOnFinish;
    expect(finishA).toBeTypeOf("function");

    const claimB = await post({ messages: [answerOnlyB] });
    expect(claimB.status).toBe(200);

    // Finish A while B is still in flight; A's original snapshot had B as
    // "approval-requested", which must not overwrite B's live "approval-claimed" state.
    await finishA?.();

    const replayB = await post({ messages: [answerOnlyB] });
    expect(replayB.status).toBe(400);
    expect(s.modelCalls).toBe(2);
  });

  it("the approval path is still refused when the hourly limit is passed", async () => {
    storePendingApproval();
    s.storedCount = GUEST_LIMIT + 1;
    expect((await post({ messages: [answered()] })).status).toBe(429);
    expect(s.modelCalls).toBe(0);
  });
});

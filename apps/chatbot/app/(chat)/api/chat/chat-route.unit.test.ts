import { beforeEach, describe, expect, it, vi } from "vitest";

// WALM-798: a tool-approval POST carries every message id in the thread.
// onFinish updates by id, and the DB predicate (id AND caller chatId) is what
// keeps another user's row unchanged when both ids are submitted.

type StoredMessage = {
  id: string;
  chatId: string;
  role: string;
  parts: unknown;
  attachments: unknown[];
  createdAt: Date;
};

const state = vi.hoisted(() => {
  const USER_B = "22222222-2222-4222-8222-222222222222";
  const CHAT_A = "33333333-3333-4333-8333-333333333333";
  const CHAT_B = "44444444-4444-4444-8444-444444444444";
  const MESSAGE_A = "55555555-5555-4555-8555-555555555555";
  const MESSAGE_B = "66666666-6666-4666-8666-666666666666";
  const ORIGINAL_A = [{ type: "text", text: "A original text" }];
  // B is waiting on a tool approval, so the approval POST is a real
  // continuation of B's chat (#1092).
  const PENDING_TOOL = {
    type: "tool-getWeather",
    toolCallId: "call-b",
    state: "approval-requested",
    input: { city: "Hanoi" },
    approval: { id: "approval-b" },
  };
  const ORIGINAL_B = [{ type: "text", text: "B original text" }, PENDING_TOOL];
  const ANSWERED_B = [
    { type: "text", text: "B original text" },
    {
      ...PENDING_TOOL,
      state: "approval-responded",
      approval: { id: "approval-b", approved: true },
    },
  ];
  const FINISHED_A = [{ type: "text", text: "A rewritten by approval" }];
  const FINISHED_B = [{ type: "text", text: "B finished text" }];

  const messages = new Map<string, StoredMessage>();
  const pending = { onFinish: Promise.resolve() };

  const updateMessage = vi.fn(
    async ({
      id,
      chatId,
      parts,
    }: {
      id: string;
      chatId: string;
      parts: unknown;
    }) => {
      const row = messages.get(id);
      if (row && row.chatId === chatId) {
        row.parts = parts;
      }
    }
  );

  const saveMessages = vi.fn(
    async ({ messages: rows }: { messages: StoredMessage[] }) => {
      for (const row of rows) {
        messages.set(row.id, { ...row });
      }
    }
  );

  const auth = vi.fn(async () => ({
    user: { id: USER_B, type: "regular" as const, email: "b@example.com" },
    expires: "",
  }));

  const getChatById = vi.fn(async ({ id }: { id: string }) =>
    id === CHAT_B
      ? {
          id: CHAT_B,
          userId: USER_B,
          title: "B chat",
          visibility: "private" as const,
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
        }
      : null
  );

  const claimPendingToolApproval = vi.fn(
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
      const row = messages.get(id);
      if (!row || row.chatId !== chatId || !Array.isArray(row.parts)) {
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
          : part
      );
      return true;
    }
  );

  const releasePendingToolApproval = vi.fn(
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
      const row = messages.get(id);
      if (!row || row.chatId !== chatId || !Array.isArray(row.parts)) {
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
          ? {
              ...(part as Record<string, unknown>),
              state: "approval-requested",
            }
          : part
      );
      return true;
    }
  );

  return {
    USER_B,
    CHAT_A,
    CHAT_B,
    MESSAGE_A,
    MESSAGE_B,
    ORIGINAL_A,
    ORIGINAL_B,
    ANSWERED_B,
    FINISHED_A,
    FINISHED_B,
    messages,
    pending,
    updateMessage,
    claimPendingToolApproval,
    releasePendingToolApproval,
    saveMessages,
    auth,
    getChatById,
  };
});

vi.mock("@/app/(auth)/auth", () => ({ auth: state.auth }));

vi.mock("@/lib/db/queries", () => ({
  getChatById: state.getChatById,
  getMessageCountByUserId: vi.fn(async () => 0),
  getMessagesByChatId: vi.fn(async ({ id }: { id: string }) =>
    [...state.messages.values()].filter((row) => row.chatId === id)
  ),
  saveChat: vi.fn(async () => undefined),
  updateChatTitleById: vi.fn(async () => undefined),
  createStreamId: vi.fn(async () => undefined),
  deleteChatById: vi.fn(async () => undefined),
  saveMessages: state.saveMessages,
  updateMessage: state.updateMessage,
  claimPendingToolApproval: state.claimPendingToolApproval,
  releasePendingToolApproval: state.releasePendingToolApproval,
}));

vi.mock("ai", () => ({
  convertToModelMessages: vi.fn(async () => []),
  createUIMessageStream: vi.fn(
    (options: {
      onFinish?: (event: { messages: unknown[] }) => Promise<void> | void;
    }) => {
      state.pending.onFinish = Promise.resolve(
        options.onFinish?.({
          messages: [
            { id: state.MESSAGE_A, role: "assistant", parts: state.FINISHED_A },
            { id: state.MESSAGE_B, role: "assistant", parts: state.FINISHED_B },
          ],
        })
      ).then(() => undefined);
      return { mocked: true };
    }
  ),
  createUIMessageStreamResponse: vi.fn(
    () => new Response("ok", { status: 200 })
  ),
  generateId: vi.fn(() => "generated-id"),
  stepCountIs: vi.fn(() => ({})),
  streamText: vi.fn(),
}));

vi.mock("@/lib/ai/providers", () => ({
  getLanguageModel: vi.fn(() => ({})),
  getMemWalModel: vi.fn(() => ({})),
}));

vi.mock("@/lib/ai/tools/create-document", () => ({
  createDocument: vi.fn(() => ({})),
}));
vi.mock("@/lib/ai/tools/update-document", () => ({
  updateDocument: vi.fn(() => ({})),
}));
vi.mock("@/lib/ai/tools/request-suggestions", () => ({
  requestSuggestions: vi.fn(() => ({})),
}));
vi.mock("@/lib/ai/tools/save-memory", () => ({
  saveMemory: vi.fn(() => ({})),
}));
vi.mock("@/lib/ai/tools/get-weather", () => ({
  getWeather: {},
}));

vi.mock("../../actions", () => ({
  generateTitleFromUserMessage: vi.fn(async () => "title"),
}));

vi.mock("resumable-stream", () => ({
  createResumableStreamContext: vi.fn(),
}));

vi.mock("next/server", () => ({
  after: vi.fn(),
}));

function seedMessages() {
  state.messages.clear();
  state.messages.set(state.MESSAGE_A, {
    id: state.MESSAGE_A,
    chatId: state.CHAT_A,
    role: "assistant",
    parts: structuredClone(state.ORIGINAL_A),
    attachments: [],
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
  });
  state.messages.set(state.MESSAGE_B, {
    id: state.MESSAGE_B,
    chatId: state.CHAT_B,
    role: "assistant",
    parts: structuredClone(state.ORIGINAL_B),
    attachments: [],
    createdAt: new Date("2026-01-01T00:00:01.000Z"),
  });
}

function approvalRequest() {
  return new Request("http://localhost/api/chat", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      id: state.CHAT_B,
      messages: [
        { id: state.MESSAGE_A, role: "assistant", parts: state.ORIGINAL_A },
        { id: state.MESSAGE_B, role: "assistant", parts: state.ANSWERED_B },
      ],
      selectedChatModel: "openai/gpt-4o-mini",
      selectedVisibilityType: "private",
      useMemWal: false,
    }),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  state.auth.mockResolvedValue({
    user: { id: state.USER_B, type: "regular", email: "b@example.com" },
    expires: "",
  });
  seedMessages();
  delete process.env.VERCEL;
  delete process.env.REDIS_URL;
});

describe("POST /api/chat tool approval", () => {
  it("updates B's message and leaves A's parts unchanged", async () => {
    const { POST } = await import("./route");
    const response = await POST(approvalRequest());
    await state.pending.onFinish;

    const body = await response.clone().text();
    expect(response.status, body).toBe(200);
    expect(state.messages.get(state.MESSAGE_A)?.parts).toEqual(state.ORIGINAL_A);
    expect(state.messages.get(state.MESSAGE_B)?.parts).toEqual(state.FINISHED_B);
    expect(state.updateMessage).toHaveBeenCalledWith({
      id: state.MESSAGE_A,
      chatId: state.CHAT_B,
      parts: state.FINISHED_A,
    });
    expect(state.updateMessage).toHaveBeenCalledWith({
      id: state.MESSAGE_B,
      chatId: state.CHAT_B,
      parts: state.FINISHED_B,
    });
  });
});

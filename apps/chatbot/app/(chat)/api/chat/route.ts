// Vercel-specific — only used when running on Vercel
const isVercel = !!process.env.VERCEL;
const vercelFunctions = isVercel ? require("@vercel/functions") : null;
import {
  convertToModelMessages,
  createUIMessageStream,
  createUIMessageStreamResponse,
  generateId,
  stepCountIs,
  streamText,
} from "ai";
// BotId is Vercel-only
const checkBotId = isVercel ? require("botid/server").checkBotId : async () => ({ isBot: false });
import { after } from "next/server";
import { createResumableStreamContext } from "resumable-stream";
import { auth, type UserType } from "@/app/(auth)/auth";
import { entitlementsByUserType } from "@/lib/ai/entitlements";
import { memoryNamespaceForUser } from "@/lib/ai/memory-namespace";
import {
  allowedModelIds,
  isReasoningModelId,
  MAX_OUTPUT_TOKENS,
  MAX_REASONING_OUTPUT_TOKENS,
} from "@/lib/ai/models";
import { type RequestHints, systemPrompt } from "@/lib/ai/prompts";
import { getLanguageModel, getMemWalModel } from "@/lib/ai/providers";
import { createDocument } from "@/lib/ai/tools/create-document";
import { getWeather } from "@/lib/ai/tools/get-weather";
import { requestSuggestions } from "@/lib/ai/tools/request-suggestions";
import { saveMemory } from "@/lib/ai/tools/save-memory";
import { updateDocument } from "@/lib/ai/tools/update-document";
import { isProductionEnvironment } from "@/lib/constants";
import {
  createStreamId,
  deleteChatById,
  getChatById,
  getMessageCountByUserId,
  getMessagesByChatId,
  saveChat,
  saveMessages,
  updateChatTitleById,
  updateMessage,
} from "@/lib/db/queries";
import type { DBMessage } from "@/lib/db/schema";
import { ChatbotError } from "@/lib/errors";
import { checkIpRateLimit } from "@/lib/ratelimit";
import type { ChatMessage } from "@/lib/types";
import { convertToUIMessages, generateUUID } from "@/lib/utils";
import { generateTitleFromUserMessage } from "../../actions";
import {
  type PostRequestBody,
  postRequestBodySchema,
  userMessageSchema,
} from "./schema";
import { answersPendingApproval } from "./tool-approval";

export const maxDuration = 60;

/**
 * Summarize an error for logging without the full object. AI SDK errors
 * thrown from a provider call (title generation, or the main streamText
 * call) are commonly APICallError-shaped and carry requestBodyValues /
 * responseBody — the actual outgoing prompt, which for the main chat can
 * include memory content withMemWal injected via recall. `console.error`
 * prints an Error's own enumerable extra properties alongside the message,
 * so logging the raw object would put full conversation (and recalled
 * memory) content into server logs on every upstream provider hiccup.
 * message/name/statusCode are enough to debug from.
 */
function summarizeErrorForLogging(error: unknown): unknown {
  if (!(error instanceof Error)) {
    return error;
  }
  const statusCode = (error as { statusCode?: unknown }).statusCode;
  return {
    name: error.name,
    message: error.message,
    ...(statusCode === undefined ? {} : { statusCode }),
  };
}

function getStreamContext() {
  try {
    return createResumableStreamContext({ waitUntil: after });
  } catch (_) {
    return null;
  }
}

export { getStreamContext };

export async function POST(request: Request) {
  let requestBody: PostRequestBody;

  try {
    const json = await request.json();
    requestBody = postRequestBodySchema.parse(json);
  } catch (_) {
    return new ChatbotError("bad_request:api").toResponse();
  }

  try {
    const { id, message, messages, selectedChatModel, selectedVisibilityType, useMemWal, memwalKey, memwalAccountId } =
      requestBody;

    const [botResult, session] = await Promise.all([checkBotId(), auth()]);

    if (botResult.isBot) {
      return new ChatbotError("unauthorized:chat").toResponse();
    }

    if (!session?.user) {
      return new ChatbotError("unauthorized:chat").toResponse();
    }
    const memoryNamespace = memoryNamespaceForUser(session.user.id);
    if (!memoryNamespace) {
      return new ChatbotError("unauthorized:chat").toResponse();
    }

    if (!allowedModelIds.has(selectedChatModel)) {
      return new ChatbotError("bad_request:api").toResponse();
    }

    if (isVercel) {
      await checkIpRateLimit(vercelFunctions.ipAddress(request));
    }

    const userType: UserType = session.user.type;

    const messageCount = await getMessageCountByUserId({
      id: session.user.id,
      differenceInHours: 1,
    });

    if (messageCount > entitlementsByUserType[userType].maxMessagesPerHour) {
      return new ChatbotError("rate_limit:chat").toResponse();
    }

    const isToolApprovalFlow = Boolean(messages);

    // The client also uses `messages` for an ordinary turn once the chat has
    // an answered approval in its history (components/chat.tsx).
    let newUserTurn: PostRequestBody["message"];
    if (isToolApprovalFlow && messages?.at(-1)?.role === "user") {
      const parsed = userMessageSchema.safeParse(messages.at(-1));
      if (!parsed.success) {
        return new ChatbotError("bad_request:api").toResponse();
      }
      newUserTurn = parsed.data;
    }

    const chat = await getChatById({ id });
    let messagesFromDb: DBMessage[] = [];
    let titlePromise: Promise<string> | null = null;

    if (chat) {
      if (chat.userId !== session.user.id) {
        return new ChatbotError("forbidden:chat").toResponse();
      }
      if (isToolApprovalFlow) {
        // The hourly limit counts stored user rows (#1092). A new user turn
        // sent in `messages` is stored below like the single-message path;
        // anything else must answer a tool approval the model requested in
        // this chat that is still pending.
        if (newUserTurn === undefined) {
          const stored = await getMessagesByChatId({ id });
          if (!answersPendingApproval(stored, messages ?? [])) {
            return new ChatbotError("bad_request:api").toResponse();
          }
        }
      } else {
        messagesFromDb = await getMessagesByChatId({ id });
      }
    } else if (isToolApprovalFlow) {
      // An approval can only answer a chat that already exists.
      return new ChatbotError("not_found:chat").toResponse();
    } else if (message?.role === "user") {
      await saveChat({
        id,
        userId: session.user.id,
        title: "New chat",
        visibility: selectedVisibilityType,
      });
      titlePromise = generateTitleFromUserMessage({ message });
    }

    const uiMessages = isToolApprovalFlow
      ? (messages as ChatMessage[])
      : [...convertToUIMessages(messagesFromDb), message as ChatMessage];

    const geo = isVercel ? vercelFunctions.geolocation(request) : {};

    const requestHints: RequestHints = {
      longitude: geo.longitude,
      latitude: geo.latitude,
      city: geo.city,
      country: geo.country,
    };

    const userTurn = message?.role === "user" ? message : newUserTurn;
    if (userTurn) {
      await saveMessages({
        messages: [
          {
            chatId: id,
            id: userTurn.id,
            role: "user",
            parts: userTurn.parts,
            attachments: [],
            createdAt: new Date(),
          },
        ],
      });
    }

    const isReasoningModel = isReasoningModelId(selectedChatModel);

    const modelMessages = await convertToModelMessages(uiMessages);

    const stream = createUIMessageStream({
      originalMessages: isToolApprovalFlow ? uiMessages : undefined,
      execute: async ({ writer: dataStream }) => {
        const result = streamText({
          model: useMemWal !== false
            ? getMemWalModel(selectedChatModel, {
                namespace: memoryNamespace,
                memwalKey,
                memwalAccountId,
              })
            : getLanguageModel(selectedChatModel),
          system: systemPrompt({ selectedChatModel, requestHints }),
          messages: modelMessages,
          maxOutputTokens: isReasoningModel
            ? MAX_REASONING_OUTPUT_TOKENS
            : MAX_OUTPUT_TOKENS,
          stopWhen: stepCountIs(5),
          experimental_activeTools: isReasoningModel
            ? []
            : [
              "getWeather",
              "createDocument",
              "updateDocument",
              "requestSuggestions",
              "saveMemory",
            ],
          providerOptions: isReasoningModel
            ? {
              anthropic: {
                thinking: { type: "enabled", budgetTokens: 10_000 },
              },
            }
            : undefined,
          tools: {
            getWeather,
            createDocument: createDocument({ session, dataStream }),
            updateDocument: updateDocument({ session, dataStream }),
            requestSuggestions: requestSuggestions({ session, dataStream }),
            saveMemory: saveMemory({
              namespace: memoryNamespace,
              memwalKey,
              memwalAccountId,
            }),
          },
          experimental_telemetry: {
            isEnabled: isProductionEnvironment,
            functionId: "stream-text",
          },
        });

        dataStream.merge(
          result.toUIMessageStream({ sendReasoning: isReasoningModel, sendFinish: false })
        );

        if (titlePromise) {
          try {
            const title = await titlePromise;
            dataStream.write({ type: "data-chat-title", data: title });
            updateChatTitleById({ chatId: id, title });
          } catch (error) {
            // Title generation is a non-fatal side effect of the response
            // already being streamed below it (dataStream.merge above).
            // Left unguarded, a title-model failure (bad slug, no credits,
            // upstream 5xx) threw here and was caught by createUIMessageStream's
            // own onError below, which turned an unrelated, recoverable
            // title-gen failure into a fatal "error" part on the whole chat
            // response — even though the real answer above continued to
            // stream successfully. The chat still works without a title.
            console.error(
              "[chat] title generation failed:",
              summarizeErrorForLogging(error)
            );
          }
        }
      },
      generateId: generateUUID,
      onFinish: async ({ messages: finishedMessages }) => {
        if (isToolApprovalFlow) {
          for (const finishedMsg of finishedMessages) {
            const existingMsg = uiMessages.find((m) => m.id === finishedMsg.id);
            if (existingMsg) {
              await updateMessage({
                id: finishedMsg.id,
                chatId: id,
                parts: finishedMsg.parts,
              });
            } else {
              await saveMessages({
                messages: [
                  {
                    id: finishedMsg.id,
                    role: finishedMsg.role,
                    parts: finishedMsg.parts,
                    createdAt: new Date(),
                    attachments: [],
                    chatId: id,
                  },
                ],
              });
            }
          }
        } else if (finishedMessages.length > 0) {
          await saveMessages({
            messages: finishedMessages.map((currentMessage) => ({
              id: currentMessage.id,
              role: currentMessage.role,
              parts: currentMessage.parts,
              createdAt: new Date(),
              attachments: [],
              chatId: id,
            })),
          });
        }
      },
      onError: (error) => {
        console.error(
          "[chat] stream execute() error:",
          summarizeErrorForLogging(error)
        );
        if (
          error instanceof Error &&
          error.message?.includes(
            "AI Gateway requires a valid credit card on file to service requests"
          )
        ) {
          return "AI Gateway requires a valid credit card on file to service requests. Please visit https://vercel.com/d?to=%2F%5Bteam%5D%2F%7E%2Fai%3Fmodal%3Dadd-credit-card to add a card and unlock your free credits.";
        }
        return "Oops, an error occurred!";
      },
    });

    return createUIMessageStreamResponse({
      stream,
      async consumeSseStream({ stream: sseStream }) {
        if (!process.env.REDIS_URL) {
          return;
        }
        try {
          const streamContext = getStreamContext();
          if (streamContext) {
            const streamId = generateId();
            await createStreamId({ streamId, chatId: id });
            await streamContext.createNewResumableStream(
              streamId,
              () => sseStream
            );
          }
        } catch (_) {
          // ignore redis errors
        }
      },
    });
  } catch (error) {
    const vercelId = request.headers.get("x-vercel-id");

    if (error instanceof ChatbotError) {
      return error.toResponse();
    }

    if (
      error instanceof Error &&
      error.message?.includes(
        "AI Gateway requires a valid credit card on file to service requests"
      )
    ) {
      return new ChatbotError("bad_request:activate_gateway").toResponse();
    }

    console.error("Unhandled error in chat API:", error, { vercelId });
    return new ChatbotError("offline:chat").toResponse();
  }
}

export async function DELETE(request: Request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get("id");

  if (!id) {
    return new ChatbotError("bad_request:api").toResponse();
  }

  const session = await auth();

  if (!session?.user) {
    return new ChatbotError("unauthorized:chat").toResponse();
  }

  const chat = await getChatById({ id });

  if (chat?.userId !== session.user.id) {
    return new ChatbotError("forbidden:chat").toResponse();
  }

  const deletedChat = await deleteChatById({ id });

  return Response.json(deletedChat, { status: 200 });
}

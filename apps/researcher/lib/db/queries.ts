import "server-only";

import {
  and,
  asc,
  count,
  desc,
  eq,
  gt,
  gte,
  inArray,
  lt,
  lte,
  sql,
  type SQL,
} from "drizzle-orm";
import type { VisibilityType } from "@/components/chat/visibility-selector";
import {
  DelegateKeyCryptoError,
  encryptDelegatePrivateKey,
  isLegacyPlaintextDelegateKey,
  openOrMigrateDelegatePrivateKey,
} from "@/lib/auth/delegate-key-crypto";
import type { Citation, SourceMeta } from "@/lib/sprint/types";
import { ChatbotError } from "../errors";
import {
  type Chat,
  chat,
  type DBMessage,
  message,
  type User,
  user,
  stream,
  source,
  sourceChunk,
  researchBlob,
  type Source,
  type SourceChunk,
  type ResearchBlob,
} from "./schema";
import { db } from "./drizzle";

// ============================================================
// User queries
// ============================================================

/** Look up a user by their UUID primary key. */
export async function getUserById(id: string): Promise<User | null> {
  try {
    const [found] = await db.select().from(user).where(eq(user.id, id));
    return found ?? null;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get user by id"
    );
  }
}

export async function getUserByPublicKey(publicKey: string): Promise<User | null> {
  try {
    const [found] = await db.select().from(user).where(eq(user.publicKey, publicKey));
    return found ?? null;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get user by public key"
    );
  }
}

export async function createUserByPublicKey(publicKey: string): Promise<User> {
  const email = `key-${publicKey.slice(0, 8)}@ed25519`;
  try {
    const [created] = await db.insert(user).values({ email, publicKey }).returning();
    return created;
  } catch (_error) {
    throw new ChatbotError("bad_request:database", "Failed to create user");
  }
}

/** Persist manual-login credentials server-side so session JWTs stay identity-only. */
export async function upsertDelegateCredentialsByPublicKey({
  publicKey,
  delegatePrivateKey,
  accountId,
}: {
  publicKey: string;
  delegatePrivateKey: string;
  accountId: string;
}): Promise<User> {
  const encryptedDelegateKey = encryptDelegatePrivateKey(delegatePrivateKey);
  const existing = await getUserByPublicKey(publicKey);
  try {
    if (existing) {
      const [updated] = await db
        .update(user)
        .set({ delegatePrivateKey: encryptedDelegateKey, accountId })
        .where(eq(user.id, existing.id))
        .returning();
      return updated;
    }

    const email = `key-${publicKey.slice(0, 8)}@ed25519`;
    const [created] = await db
      .insert(user)
      .values({
        email,
        publicKey,
        delegatePrivateKey: encryptedDelegateKey,
        accountId,
      })
      .returning();
    return created;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to store delegate credentials"
    );
  }
}

/** Look up an Enoki user by their stable zkLogin Sui address. */
export async function getUserBySuiAddress(suiAddress: string): Promise<User | null> {
  try {
    const [found] = await db.select().from(user).where(eq(user.suiAddress, suiAddress));
    return found ?? null;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get user by Sui address"
    );
  }
}

/** Create a new user from Enoki zkLogin with stored delegate key credentials for returning login. */
export async function createEnokiUser({
  publicKey,
  suiAddress,
  delegatePrivateKey,
  accountId,
}: {
  publicKey: string;
  suiAddress: string;
  delegatePrivateKey: string;
  accountId: string;
}): Promise<User> {
  const encryptedDelegateKey = encryptDelegatePrivateKey(delegatePrivateKey);
  const email = `enoki-${suiAddress.slice(0, 8)}@zklogin`;
  try {
    const [created] = await db
      .insert(user)
      .values({
        email,
        publicKey,
        suiAddress,
        delegatePrivateKey: encryptedDelegateKey,
        accountId,
      })
      .returning();
    return created;
  } catch (_error) {
    throw new ChatbotError("bad_request:database", "Failed to create Enoki user");
  }
}

/** Update an existing Enoki user's delegate key credentials (e.g. after key rotation). */
export async function updateEnokiUserCredentials({
  userId,
  publicKey,
  delegatePrivateKey,
  accountId,
}: {
  userId: string;
  publicKey: string;
  delegatePrivateKey: string;
  accountId: string;
}): Promise<void> {
  const encryptedDelegateKey = encryptDelegatePrivateKey(delegatePrivateKey);
  try {
    await db
      .update(user)
      .set({ publicKey, delegatePrivateKey: encryptedDelegateKey, accountId })
      .where(eq(user.id, userId));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to update Enoki user credentials"
    );
  }
}

/**
 * Decrypt an at-rest `v1.` delegate key envelope, or transparently encrypt and
 * backfill a pre-upgrade 64-hex plaintext delegate key in PostgreSQL so
 * existing accounts and memory access survive the upgrade without generating a
 * replacement account.
 */
export async function resolveAndMigrateUserDelegateKey(
  targetUser: Pick<User, "id" | "delegatePrivateKey">,
  secretOverride?: string
): Promise<string> {
  if (!targetUser.delegatePrivateKey) {
    throw new DelegateKeyCryptoError("Encrypted delegate key envelope is empty");
  }
  const resolved = openOrMigrateDelegatePrivateKey(
    targetUser.delegatePrivateKey,
    secretOverride
  );
  if (resolved.migrated) {
    try {
      await db
        .update(user)
        .set({ delegatePrivateKey: resolved.encryptedEnvelope })
        .where(eq(user.id, targetUser.id));
      targetUser.delegatePrivateKey = resolved.encryptedEnvelope;
    } catch (_error) {
      throw new ChatbotError(
        "bad_request:database",
        "Failed to migrate legacy delegate credentials"
      );
    }
  }
  return resolved.plaintextKey;
}

/**
 * Batch-backfill any remaining pre-upgrade 64-hex plaintext delegate keys in
 * `"User"` into AES-256-GCM `v1.` envelopes in place.
 */
export async function backfillLegacyDelegateKeys(
  secretOverride?: string
): Promise<number> {
  const rows = await db
    .select({
      id: user.id,
      delegatePrivateKey: user.delegatePrivateKey,
    })
    .from(user);
  let migratedCount = 0;
  for (const row of rows) {
    if (
      row.delegatePrivateKey &&
      isLegacyPlaintextDelegateKey(row.delegatePrivateKey)
    ) {
      const encryptedEnvelope = encryptDelegatePrivateKey(
        row.delegatePrivateKey,
        secretOverride
      );
      await db
        .update(user)
        .set({ delegatePrivateKey: encryptedEnvelope })
        .where(eq(user.id, row.id));
      migratedCount += 1;
    }
  }
  return migratedCount;
}

// ============================================================
// Chat queries
// ============================================================

export async function saveChat({
  id,
  userId,
  title,
  visibility,
  sprintIds,
}: {
  id: string;
  userId: string;
  title: string;
  visibility: VisibilityType;
  sprintIds?: string[];
}) {
  try {
    return await db.insert(chat).values({
      id,
      createdAt: new Date(),
      userId,
      title,
      visibility,
      sprintIds: sprintIds ?? null,
    });
  } catch (_error) {
    throw new ChatbotError("bad_request:database", "Failed to save chat");
  }
}

export async function deleteChatById({ id }: { id: string }) {
  try {
    await db.delete(message).where(eq(message.chatId, id));
    await db.delete(stream).where(eq(stream.chatId, id));
    await db
      .update(researchBlob)
      .set({ chatId: null })
      .where(eq(researchBlob.chatId, id));

    const [chatsDeleted] = await db
      .delete(chat)
      .where(eq(chat.id, id))
      .returning();
    return chatsDeleted;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to delete chat by id"
    );
  }
}

export async function deleteAllChatsByUserId({ userId }: { userId: string }) {
  try {
    const userChats = await db
      .select({ id: chat.id })
      .from(chat)
      .where(eq(chat.userId, userId));

    if (userChats.length === 0) {
      return { deletedCount: 0 };
    }

    const chatIds = userChats.map((c) => c.id);

    await db.delete(message).where(inArray(message.chatId, chatIds));
    await db.delete(stream).where(inArray(stream.chatId, chatIds));
    await db
      .update(researchBlob)
      .set({ chatId: null })
      .where(inArray(researchBlob.chatId, chatIds));

    const deletedChats = await db
      .delete(chat)
      .where(eq(chat.userId, userId))
      .returning();

    return { deletedCount: deletedChats.length };
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to delete all chats by user id"
    );
  }
}

export async function getChatsByUserId({
  id,
  limit,
  startingAfter,
  endingBefore,
}: {
  id: string;
  limit: number;
  startingAfter: string | null;
  endingBefore: string | null;
}) {
  try {
    const extendedLimit = limit + 1;

    const query = (whereCondition?: SQL<any>) =>
      db
        .select()
        .from(chat)
        .where(
          whereCondition
            ? and(whereCondition, eq(chat.userId, id))
            : eq(chat.userId, id)
        )
        .orderBy(desc(chat.createdAt))
        .limit(extendedLimit);

    let filteredChats: Chat[] = [];

    if (startingAfter) {
      const [selectedChat] = await db
        .select()
        .from(chat)
        .where(eq(chat.id, startingAfter))
        .limit(1);

      if (!selectedChat) {
        throw new ChatbotError(
          "not_found:database",
          `Chat with id ${startingAfter} not found`
        );
      }

      filteredChats = await query(gt(chat.createdAt, selectedChat.createdAt));
    } else if (endingBefore) {
      const [selectedChat] = await db
        .select()
        .from(chat)
        .where(eq(chat.id, endingBefore))
        .limit(1);

      if (!selectedChat) {
        throw new ChatbotError(
          "not_found:database",
          `Chat with id ${endingBefore} not found`
        );
      }

      filteredChats = await query(lt(chat.createdAt, selectedChat.createdAt));
    } else {
      filteredChats = await query();
    }

    const hasMore = filteredChats.length > limit;

    return {
      chats: hasMore ? filteredChats.slice(0, limit) : filteredChats,
      hasMore,
    };
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get chats by user id"
    );
  }
}

export async function getChatById({ id }: { id: string }) {
  try {
    const [selectedChat] = await db.select().from(chat).where(eq(chat.id, id));
    if (!selectedChat) {
      return null;
    }

    return selectedChat;
  } catch (_error) {
    throw new ChatbotError("bad_request:database", "Failed to get chat by id");
  }
}

// ============================================================
// Message queries
// ============================================================

export async function saveMessages({ messages }: { messages: DBMessage[] }) {
  try {
    return await db.insert(message).values(messages);
  } catch (_error) {
    throw new ChatbotError("bad_request:database", "Failed to save messages");
  }
}

export async function updateMessage({
  id,
  parts,
}: {
  id: string;
  parts: DBMessage["parts"];
}) {
  try {
    return await db.update(message).set({ parts }).where(eq(message.id, id));
  } catch (_error) {
    throw new ChatbotError("bad_request:database", "Failed to update message");
  }
}

export async function getMessagesByChatId({ id }: { id: string }) {
  try {
    return await db
      .select()
      .from(message)
      .where(eq(message.chatId, id))
      .orderBy(asc(message.createdAt));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get messages by chat id"
    );
  }
}

export async function getMessageById({ id }: { id: string }) {
  try {
    return await db.select().from(message).where(eq(message.id, id));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get message by id"
    );
  }
}

export async function deleteMessagesByChatIdAfterTimestamp({
  chatId,
  timestamp,
}: {
  chatId: string;
  timestamp: Date;
}) {
  try {
    const messagesToDelete = await db
      .select({ id: message.id })
      .from(message)
      .where(
        and(eq(message.chatId, chatId), gte(message.createdAt, timestamp))
      );

    const messageIds = messagesToDelete.map(
      (currentMessage) => currentMessage.id
    );

    if (messageIds.length > 0) {
      return await db
        .delete(message)
        .where(
          and(eq(message.chatId, chatId), inArray(message.id, messageIds))
        );
    }
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to delete messages by chat id after timestamp"
    );
  }
}

export async function getMessageCountByUserId({
  id,
  differenceInHours,
}: {
  id: string;
  differenceInHours: number;
}) {
  try {
    const twentyFourHoursAgo = new Date(
      Date.now() - differenceInHours * 60 * 60 * 1000
    );

    const [stats] = await db
      .select({ count: count(message.id) })
      .from(message)
      .innerJoin(chat, eq(message.chatId, chat.id))
      .where(
        and(
          eq(chat.userId, id),
          gte(message.createdAt, twentyFourHoursAgo),
          eq(message.role, "user")
        )
      )
      .execute();

    return stats?.count ?? 0;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get message count by user id"
    );
  }
}

// ============================================================
// Chat visibility
// ============================================================

export async function updateChatVisibilityById({
  chatId,
  visibility,
}: {
  chatId: string;
  visibility: "private" | "public";
}) {
  try {
    return await db.update(chat).set({ visibility }).where(eq(chat.id, chatId));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to update chat visibility by id"
    );
  }
}

export async function updateChatSprintContext({
  chatId,
  sprintContext,
}: {
  chatId: string;
  sprintContext: string;
}) {
  try {
    return await db
      .update(chat)
      .set({ sprintContext })
      .where(eq(chat.id, chatId));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to update chat sprint context"
    );
  }
}

export async function updateChatTitleById({
  chatId,
  title,
}: {
  chatId: string;
  title: string;
}) {
  try {
    return await db.update(chat).set({ title }).where(eq(chat.id, chatId));
  } catch (error) {
    console.warn("Failed to update title for chat", chatId, error);
    return;
  }
}

// ============================================================
// Stream queries
// ============================================================

export async function createStreamId({
  streamId,
  chatId,
}: {
  streamId: string;
  chatId: string;
}) {
  try {
    await db
      .insert(stream)
      .values({ id: streamId, chatId, createdAt: new Date() });
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to create stream id"
    );
  }
}

export async function getStreamIdsByChatId({ chatId }: { chatId: string }) {
  try {
    const streamIds = await db
      .select({ id: stream.id })
      .from(stream)
      .where(eq(stream.chatId, chatId))
      .orderBy(asc(stream.createdAt))
      .execute();

    return streamIds.map(({ id }) => id);
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get stream ids by chat id"
    );
  }
}

// ============================================================
// Source queries (research-specific)
// ============================================================

export async function createSource({
  chatId,
  userId,
  type,
  title,
  url,
  summary,
  claims,
  chunkCount,
}: {
  chatId?: string;
  userId: string;
  type: "url" | "pdf";
  title?: string;
  url?: string;
  summary?: string;
  claims?: string[];
  chunkCount?: number;
}) {
  try {
    const [created] = await db
      .insert(source)
      .values({ chatId, userId, type, title, url, summary, claims, chunkCount })
      .returning();
    return created;
  } catch (_error) {
    throw new ChatbotError("bad_request:database", "Failed to create source");
  }
}

export async function getSourcesByUserId({ userId }: { userId: string }) {
  try {
    return await db
      .select()
      .from(source)
      .where(eq(source.userId, userId))
      .orderBy(desc(source.createdAt));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get sources by user id"
    );
  }
}

export async function createSourceChunks({
  chunks,
}: {
  chunks: {
    sourceId: string;
    section: string;
    content: string;
    embedding: number[];
    chunkIndex: number;
    tokenCount: number;
    expiresAt: Date;
  }[];
}) {
  try {
    return await db.insert(sourceChunk).values(
      chunks.map((chunk) => ({
        sourceId: chunk.sourceId,
        section: chunk.section,
        content: chunk.content,
        embedding: chunk.embedding,
        chunkIndex: chunk.chunkIndex,
        tokenCount: chunk.tokenCount,
        searchVector: sql`to_tsvector('english', ${chunk.content})`,
        expiresAt: chunk.expiresAt,
      }))
    );
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to create source chunks"
    );
  }
}

export async function getChunksByIds({
  chunkIds,
  userId,
}: {
  chunkIds: string[];
  userId: string;
}) {
  if (chunkIds.length === 0) return [];

  try {
    return await db
      .select({
        id: sourceChunk.id,
        section: sourceChunk.section,
        content: sourceChunk.content,
        sourceId: sourceChunk.sourceId,
        sourceTitle: source.title,
        sourceUrl: source.url,
        chunkIndex: sourceChunk.chunkIndex,
        tokenCount: sourceChunk.tokenCount,
      })
      .from(sourceChunk)
      .innerJoin(source, eq(sourceChunk.sourceId, source.id))
      .where(
        and(
          inArray(sourceChunk.id, chunkIds),
          eq(source.userId, userId),
          gt(sourceChunk.expiresAt, new Date())
        )
      )
      .orderBy(asc(sourceChunk.chunkIndex));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get chunks by ids"
    );
  }
}

export async function getChunkNeighbors({
  chunkId,
  windowSize,
  userId,
}: {
  chunkId: string;
  windowSize: number;
  userId: string;
}) {
  try {
    // Look up the target chunk's sourceId and chunkIndex
    const [target] = await db
      .select({
        sourceId: sourceChunk.sourceId,
        chunkIndex: sourceChunk.chunkIndex,
      })
      .from(sourceChunk)
      .innerJoin(source, eq(sourceChunk.sourceId, source.id))
      .where(
        and(
          eq(sourceChunk.id, chunkId),
          eq(source.userId, userId),
          gt(sourceChunk.expiresAt, new Date())
        )
      )
      .limit(1);

    if (!target) return [];

    // Get chunks within the window range from the same source
    return await db
      .select({
        id: sourceChunk.id,
        section: sourceChunk.section,
        content: sourceChunk.content,
        sourceId: sourceChunk.sourceId,
        chunkIndex: sourceChunk.chunkIndex,
        tokenCount: sourceChunk.tokenCount,
      })
      .from(sourceChunk)
      .where(
        and(
          eq(sourceChunk.sourceId, target.sourceId),
          gte(sourceChunk.chunkIndex, target.chunkIndex - windowSize),
          lte(sourceChunk.chunkIndex, target.chunkIndex + windowSize),
          gt(sourceChunk.expiresAt, new Date())
        )
      )
      .orderBy(asc(sourceChunk.chunkIndex));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get chunk neighbors"
    );
  }
}

// ============================================================
// Research blob queries (My Stuff — Phase 2, but schema ready)
// ============================================================

export async function createResearchBlob({
  blobId,
  userId,
  type,
  title,
  summary,
  tags,
}: {
  blobId: string;
  userId: string;
  type: "sprint";
  title: string;
  summary?: string;
  tags?: string[];
}) {
  try {
    const [created] = await db
      .insert(researchBlob)
      .values({ blobId, userId, type, title, summary, tags })
      .returning();
    return created;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to create research blob"
    );
  }
}

export async function getResearchBlobsByUserId({
  userId,
}: {
  userId: string;
}) {
  try {
    return await db
      .select()
      .from(researchBlob)
      .where(eq(researchBlob.userId, userId))
      .orderBy(desc(researchBlob.createdAt));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get research blobs by user id"
    );
  }
}

// ============================================================
// Sprint blob queries
// ============================================================

export async function createSprintBlob({
  chatId,
  userId,
  blobId,
  title,
  summary,
  reportContent,
  citations,
  sources,
  tags,
  memoryCount,
}: {
  chatId: string;
  userId: string;
  blobId: string;
  title: string;
  summary?: string;
  reportContent: string;
  citations: Citation[];
  sources: SourceMeta[];
  tags?: string[];
  memoryCount: number;
}) {
  try {
    const [created] = await db
      .insert(researchBlob)
      .values({
        blobId,
        userId,
        chatId,
        type: "sprint",
        title,
        summary,
        reportContent,
        citations,
        sources,
        tags,
        memoryCount,
      })
      .returning();
    return created;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to create sprint blob"
    );
  }
}

export async function getSprintByChatId({ chatId }: { chatId: string }) {
  try {
    const [sprint] = await db
      .select()
      .from(researchBlob)
      .where(
        and(eq(researchBlob.chatId, chatId), eq(researchBlob.type, "sprint"))
      );
    return sprint ?? null;
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get sprint by chat id"
    );
  }
}

export async function getSprintsByUserId({ userId }: { userId: string }) {
  try {
    return await db
      .select()
      .from(researchBlob)
      .where(
        and(eq(researchBlob.userId, userId), eq(researchBlob.type, "sprint"))
      )
      .orderBy(desc(researchBlob.createdAt));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get sprints by user id"
    );
  }
}

export async function getSprintsByIds({
  sprintIds,
  userId,
}: {
  sprintIds: string[];
  userId: string;
}) {
  if (sprintIds.length === 0) return [];
  try {
    return await db
      .select()
      .from(researchBlob)
      .where(
        and(
          inArray(researchBlob.id, sprintIds),
          eq(researchBlob.userId, userId),
          eq(researchBlob.type, "sprint")
        )
      )
      .orderBy(desc(researchBlob.createdAt));
  } catch (_error) {
    throw new ChatbotError(
      "bad_request:database",
      "Failed to get sprints by ids"
    );
  }
}

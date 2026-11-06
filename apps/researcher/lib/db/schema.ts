import type { InferSelectModel } from "drizzle-orm";
import {
  customType,
  integer,
  json,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uuid,
  varchar,
  vector,
  foreignKey,
} from "drizzle-orm/pg-core";
import type { Citation, SourceMeta } from "@/lib/sprint/types";

/** PostgreSQL tsvector type for full-text search */
const tsvectorType = customType<{ data: string }>({
  dataType() {
    return "tsvector";
  },
});

// ============================================================
// Core tables (from v2-test base)
// ============================================================

export const user = pgTable("User", {
  id: uuid("id").primaryKey().notNull().defaultRandom(),
  email: varchar("email", { length: 64 }).notNull(),
  password: varchar("password", { length: 64 }),
  publicKey: varchar("publicKey", { length: 128 }).unique(),
  suiAddress: varchar("suiAddress", { length: 128 }).unique(),
  delegatePrivateKey: text("delegatePrivateKey"),
  accountId: varchar("accountId", { length: 128 }),
});

export type User = InferSelectModel<typeof user>;

export const chat = pgTable("Chat", {
  id: uuid("id").primaryKey().notNull().defaultRandom(),
  createdAt: timestamp("createdAt").notNull(),
  title: text("title").notNull(),
  userId: uuid("userId")
    .notNull()
    .references(() => user.id),
  visibility: varchar("visibility", { enum: ["public", "private"] })
    .notNull()
    .default("private"),
  sprintIds: json("sprintIds").$type<string[]>(),
  sprintContext: text("sprintContext"),
});

export type Chat = InferSelectModel<typeof chat>;

export const message = pgTable("Message_v2", {
  id: uuid("id").primaryKey().notNull().defaultRandom(),
  chatId: uuid("chatId")
    .notNull()
    .references(() => chat.id),
  role: varchar("role").notNull(),
  parts: json("parts").notNull(),
  attachments: json("attachments").notNull(),
  createdAt: timestamp("createdAt").notNull(),
});

export type DBMessage = InferSelectModel<typeof message>;

export const stream = pgTable(
  "Stream",
  {
    id: uuid("id").notNull().defaultRandom(),
    chatId: uuid("chatId").notNull(),
    createdAt: timestamp("createdAt").notNull(),
  },
  (table) => ({
    pk: primaryKey({ columns: [table.id] }),
    chatRef: foreignKey({
      columns: [table.chatId],
      foreignColumns: [chat.id],
    }),
  })
);

export type Stream = InferSelectModel<typeof stream>;

// ============================================================
// Research tables (new for researcher app)
// ============================================================

/** Processed sources (PDFs, URLs) — metadata is permanent */
export const source = pgTable("Source", {
  id: uuid("id").primaryKey().notNull().defaultRandom(),
  chatId: uuid("chatId").references(() => chat.id, { onDelete: "set null" }),
  userId: uuid("userId")
    .notNull()
    .references(() => user.id),
  type: varchar("type", { enum: ["url", "pdf"] }).notNull(),
  title: text("title"),
  url: text("url"),
  summary: text("summary"),
  claims: json("claims").$type<string[]>(),
  chunkCount: integer("chunkCount").default(0),
  createdAt: timestamp("createdAt").notNull().defaultNow(),
});

export type Source = InferSelectModel<typeof source>;

/** Source chunks with embeddings — ephemeral, 30-day TTL */
export const sourceChunk = pgTable("SourceChunk", {
  id: uuid("id").primaryKey().notNull().defaultRandom(),
  sourceId: uuid("sourceId")
    .notNull()
    .references(() => source.id, { onDelete: "cascade" }),
  section: text("section").notNull(),
  content: text("content").notNull(),
  embedding: vector("embedding", { dimensions: 1536 }),
  chunkIndex: integer("chunkIndex").notNull().default(0),
  tokenCount: integer("tokenCount").notNull().default(0),
  searchVector: tsvectorType("searchVector"),
  expiresAt: timestamp("expiresAt").notNull(),
  createdAt: timestamp("createdAt").notNull().defaultNow(),
});

export type SourceChunk = InferSelectModel<typeof sourceChunk>;

/** Research blob index (My Stuff) — references blobs stored in Walrus Memory/Walrus */
export const researchBlob = pgTable("ResearchBlob", {
  id: uuid("id").primaryKey().notNull().defaultRandom(),
  blobId: text("blobId").unique().notNull(),
  userId: uuid("userId")
    .notNull()
    .references(() => user.id),
  chatId: uuid("chatId").references(() => chat.id),
  type: varchar("type", { enum: ["sprint"] }).notNull(),
  title: text("title").notNull(),
  summary: text("summary"),
  reportContent: text("reportContent"),
  tags: json("tags").$type<string[]>(),
  citations: json("citations").$type<Citation[]>(),
  sources: json("sources").$type<SourceMeta[]>(),
  memoryCount: integer("memoryCount").default(0),
  createdAt: timestamp("createdAt").notNull().defaultNow(),
});

export type ResearchBlob = InferSelectModel<typeof researchBlob>;

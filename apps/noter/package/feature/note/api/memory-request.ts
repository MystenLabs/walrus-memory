import "server-only";

import { isIP } from "node:net";
import { eq } from "drizzle-orm";
import { db } from "@/shared/lib/db";
import { users, walletSessions } from "@/shared/db/schema";
import { requireSharedRedisClient } from "@/shared/lib/shared-redis";
import { resolveAndMigrateUserDelegateKey } from "@/feature/auth/domain/service";
import { memoryTextWithinLimit } from "./memory-policy";

export { MAX_MEMORY_TEXT_BYTES } from "./memory-policy";
const MEMORY_RATE_LIMIT_TTL_SECONDS = 60;
const MEMORY_RATE_LIMIT_PER_USER = 30;
const MEMORY_RATE_LIMIT_PER_IP = 60;
const MEMORY_RATE_LIMIT_GLOBAL = 300;

const MEMORY_RATE_LIMIT_LUA = `
local user_key     = KEYS[1]
local ip_key       = KEYS[2]
local global_key   = KEYS[3]
local user_limit   = tonumber(ARGV[1])
local ip_limit     = tonumber(ARGV[2])
local global_limit = tonumber(ARGV[3])
local ttl          = tonumber(ARGV[4])

local user_count = tonumber(redis.call('GET', user_key) or '0')
local ip_count = tonumber(redis.call('GET', ip_key) or '0')
local global_count = tonumber(redis.call('GET', global_key) or '0')
if user_count >= user_limit or ip_count >= ip_limit or global_count >= global_limit then
  return 0
end

user_count = redis.call('INCR', user_key)
ip_count = redis.call('INCR', ip_key)
global_count = redis.call('INCR', global_key)
if user_count == 1 then redis.call('EXPIRE', user_key, ttl) end
if ip_count == 1 then redis.call('EXPIRE', ip_key, ttl) end
if global_count == 1 then redis.call('EXPIRE', global_key, ttl) end
return 1
`;

export class MemoryRequestError extends Error {
  constructor(readonly status: 400 | 401 | 413 | 429 | 503, message: string) {
    super(message);
    this.name = "MemoryRequestError";
  }
}

function validIp(value: string | undefined): string | undefined {
  const candidate = value?.trim();
  return candidate && isIP(candidate) ? candidate : undefined;
}

function trustedClientIp(req: Request): string | undefined {
  const vercelForwarded = req.headers
    .get("x-vercel-forwarded-for")
    ?.split(",")[0];
  if (process.env.VERCEL) return validIp(vercelForwarded);

  const realIp = req.headers.get("x-real-ip") ?? undefined;
  // Railway's edge appends the nearest proxy-observed client address last.
  const forwarded = req.headers.get("x-forwarded-for")?.split(",").at(-1);
  return validIp(realIp) ?? validIp(forwarded);
}

export async function checkMemoryRateLimit(
  req: Request,
  userId: string
): Promise<void> {
  // Unit/dev environments remain usable without Redis. Production fails closed.
  if (process.env.NODE_ENV !== "production") return;

  try {
    const redis = await requireSharedRedisClient();
    const ipBucket = trustedClientIp(req) ?? `session-user:${userId}`;
    const result = await redis.eval(MEMORY_RATE_LIMIT_LUA, {
      arguments: [
        String(MEMORY_RATE_LIMIT_PER_USER),
        String(MEMORY_RATE_LIMIT_PER_IP),
        String(MEMORY_RATE_LIMIT_GLOBAL),
        String(MEMORY_RATE_LIMIT_TTL_SECONDS),
      ],
      keys: [
        `noter-memory-rate:{noter-memory}:user:${userId}`,
        `noter-memory-rate:{noter-memory}:ip:${ipBucket}`,
        "noter-memory-rate:{noter-memory}:global",
      ],
    });
    if (Number(result) !== 1) {
      throw new MemoryRequestError(429, "Too many memory write requests");
    }
  } catch (error) {
    if (error instanceof MemoryRequestError) throw error;
    throw new MemoryRequestError(503, "Memory write limiter unavailable");
  }
}

/** Resolve only credentials bound to the active wallet session. */
export async function resolveMemoryCredentials(req: Request): Promise<{
  key: string;
  accountId: string;
  userId: string;
}> {
  const sessionId = req.headers.get("x-session-id")?.trim();
  if (!sessionId || sessionId.length > 128) {
    throw new MemoryRequestError(401, "Authentication required");
  }

  const [session] = await db
    .select()
    .from(walletSessions)
    .where(eq(walletSessions.id, sessionId))
    .limit(1);
  if (!session?.userId || session.expiresAt <= new Date()) {
    throw new MemoryRequestError(401, "Authentication required");
  }

  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.id, session.userId))
    .limit(1);
  if (!user?.delegatePrivateKey || !user.delegateAccountId) {
    throw new MemoryRequestError(
      401,
      "Session has no Walrus Memory credentials"
    );
  }

  let decryptedKey: string;
  try {
    const resolved = await resolveAndMigrateUserDelegateKey(db, user);
    decryptedKey = resolved.plaintextKey;
  } catch {
    throw new MemoryRequestError(
      401,
      "Session has no Walrus Memory credentials"
    );
  }

  return {
    key: decryptedKey,
    accountId: user.delegateAccountId,
    userId: user.id,
  };
}

/** Authenticate first, then consume the Redis-backed memory-write budget. */
export async function authorizeMemoryRequest(req: Request): Promise<{
  key: string;
  accountId: string;
}> {
  const credentials = await resolveMemoryCredentials(req);
  await checkMemoryRateLimit(req, credentials.userId);
  return { key: credentials.key, accountId: credentials.accountId };
}

export async function readMemoryText(req: Request): Promise<string> {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    throw new MemoryRequestError(400, "Invalid JSON body");
  }
  const text = (body as { text?: unknown } | null)?.text;
  if (typeof text !== "string" || !text.trim()) {
    throw new MemoryRequestError(400, "text is required");
  }
  if (!memoryTextWithinLimit(text)) {
    throw new MemoryRequestError(413, "Memory text is too large");
  }
  return text;
}

export function memoryErrorResponse(error: unknown): Response | null {
  if (!(error instanceof MemoryRequestError)) return null;
  return Response.json(
    { error: error.message },
    {
      status: error.status,
      headers: error.status === 429 ? { "Retry-After": "60" } : undefined,
    }
  );
}

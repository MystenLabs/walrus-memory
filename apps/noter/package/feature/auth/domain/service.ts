/**
 * AUTH SERVICE LAYER
 *
 * DB operations for authentication feature.
 * All service functions take db as first parameter (dependency injection pattern).
 * Called exclusively by api/route.ts handlers.
 */

import type { db as dbClient } from "@/shared/lib/db";
import type { User } from "@/shared/db/type";
import { users, zkLoginSessions, walletSessions } from "@/shared/db/schema";
import { eq, and } from "drizzle-orm";
import {
  DelegateKeyCryptoError,
  encryptDelegatePrivateKey,
  isLegacyPlaintextDelegateKey,
  openOrMigrateDelegatePrivateKey,
} from "../lib/delegate-key-crypto";

type DbClient = typeof dbClient;

// ══════════════════════════════════════════════════════════════
// SAFE USER DTO
// ══════════════════════════════════════════════════════════════

/**
 * The subset of a user row that is safe to hand back to the client.
 * Deliberately omits secrets (delegatePrivateKey) and PII the client
 * has no need for (email, providerSub).
 */
export type SafeUser = {
  id: string;
  suiAddress: string;
  name: string | null;
  avatar: string | null;
  authMethod: string;
  delegateAccountId: string | null;
};

/** Project a raw user row down to the client-safe DTO. */
export function toSafeUser(user: User): SafeUser {
  return {
    id: user.id,
    suiAddress: user.suiAddress,
    name: user.name ?? null,
    avatar: user.avatar ?? null,
    authMethod: user.authMethod,
    delegateAccountId: user.delegateAccountId ?? null,
  };
}

// ══════════════════════════════════════════════════════════════
// WALLET USER MANAGEMENT
// ══════════════════════════════════════════════════════════════

/**
 * Create or update user from wallet authentication
 * Returns existing user if suiAddress matches, otherwise creates new user
 */
export async function upsertWalletUser(
  db: DbClient,
  input: {
    address: string;
    walletType: string;
  }
) {
  const [existingUser] = await db
    .select()
    .from(users)
    .where(eq(users.suiAddress, input.address))
    .limit(1);

  if (existingUser) {
    const [user] = await db
      .update(users)
      .set({
        lastSeenAt: new Date(),
        walletType: input.walletType,
      })
      .where(eq(users.id, existingUser.id))
      .returning();
    return user;
  }

  const [user] = await db
    .insert(users)
    .values({
      suiAddress: input.address,
      authMethod: "wallet",
      walletType: input.walletType,
      name: `${input.walletType} User`,
      lastSeenAt: new Date(),
    })
    .returning();
  return user;
}

// ══════════════════════════════════════════════════════════════
// SESSION RETRIEVAL
// ══════════════════════════════════════════════════════════════

/**
 * Get active session by ID (wallet / enoki sessions only).
 * Returns null if the session doesn't exist, is expired, or has no associated
 * user. The legacy zklogin_sessions table is no longer trusted.
 */
export async function getActiveSession(db: DbClient, sessionId: string) {
  const [walletSession] = await db
    .select()
    .from(walletSessions)
    .where(eq(walletSessions.id, sessionId))
    .limit(1);

  if (walletSession?.userId && walletSession.expiresAt > new Date()) {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.id, walletSession.userId))
      .limit(1);

    if (user) {
      return {
        user: toSafeUser(user),
        sessionId: walletSession.id,
        suiAddress: user.suiAddress,
        expiresAt: walletSession.expiresAt,
      };
    }
  }

  return null;
}

// ══════════════════════════════════════════════════════════════
// ENOKI USER MANAGEMENT
// ══════════════════════════════════════════════════════════════

/**
 * Thrown when a registration attempt would clobber delegate credentials that
 * are already provisioned for a user under an incompatible auth method. The
 * route layer maps this to a 409/CONFLICT-style response.
 */
export class DelegateCredentialConflictError extends Error {
  constructor() {
    super("Delegate credentials already provisioned for this address");
    this.name = "DelegateCredentialConflictError";
  }
}

/** Create or update user from Enoki zkLogin. Stores delegate key for returning-user fast path. */
export async function upsertEnokiUser(
  db: DbClient,
  input: {
    suiAddress: string;
    delegatePrivateKey: string;
    delegateAccountId: string;
  }
) {
  const [existingUser] = await db
    .select()
    .from(users)
    .where(eq(users.suiAddress, input.suiAddress))
    .limit(1);

  if (existingUser) {
    // Credential provisioning is insert-only: once a row has a delegate key, the
    // connect/register path must never overwrite it with caller-supplied values
    // (the server can't verify the delegate key/account binding here, so an
    // overwrite would let a caller replace an existing owner's stored key).
    // Rotation, if ever needed, must be a separate authenticated, on-chain-verified
    // flow. Registering again for an already-provisioned address is a no-op that
    // returns the existing row.
    if (existingUser.delegatePrivateKey) {
      throw new DelegateCredentialConflictError();
    }

    const encryptedDelegateKey = encryptDelegatePrivateKey(
      input.delegatePrivateKey
    );

    const [user] = await db
      .update(users)
      .set({
        authMethod: "enoki",
        delegatePrivateKey: encryptedDelegateKey,
        delegateAccountId: input.delegateAccountId,
        lastSeenAt: new Date(),
      })
      .where(eq(users.id, existingUser.id))
      .returning();
    return user;
  }

  const encryptedDelegateKey = encryptDelegatePrivateKey(
    input.delegatePrivateKey
  );

  const [user] = await db
    .insert(users)
    .values({
      suiAddress: input.suiAddress,
      authMethod: "enoki",
      delegatePrivateKey: encryptedDelegateKey,
      delegateAccountId: input.delegateAccountId,
      name: "Enoki User",
      lastSeenAt: new Date(),
    })
    .returning();
  return user;
}

/**
 * Decrypt an at-rest `v1.` delegate key envelope, or transparently encrypt and
 * backfill a pre-upgrade 64-hex plaintext delegate key in PostgreSQL so the
 * existing account and memory access survive the upgrade without generating a
 * replacement account.
 *
 * Uses an atomic compare-and-swap on `delegatePrivateKey` to protect against
 * concurrent credential rotations. If another session updated credentials
 * between the initial read and migration, reloads the current row and returns
 * the fresh credentials instead of overwriting with the stale migrated key.
 */
export async function resolveAndMigrateUserDelegateKey(
  db: DbClient,
  user: Pick<User, "id" | "delegatePrivateKey">,
  secretOverride?: string
): Promise<{
  plaintextKey: string;
  encryptedEnvelope: string;
  migrated: boolean;
}> {
  if (!user.delegatePrivateKey) {
    throw new DelegateKeyCryptoError("Encrypted delegate key envelope is empty");
  }
  const originalPlaintext = user.delegatePrivateKey;
  const resolved = openOrMigrateDelegatePrivateKey(
    originalPlaintext,
    secretOverride
  );
  if (resolved.migrated) {
    const updated = await db
      .update(users)
      .set({
        delegatePrivateKey: resolved.encryptedEnvelope,
      })
      .where(
        and(
          eq(users.id, user.id),
          eq(users.delegatePrivateKey, originalPlaintext)
        )
      )
      .returning();

    if (updated.length > 0) {
      user.delegatePrivateKey = resolved.encryptedEnvelope;
      return resolved;
    }

    // Lost race: a concurrent credential rotation modified delegatePrivateKey.
    // Reload current credentials rather than returning the stale key.
    const [reloaded] = await db
      .select({ delegatePrivateKey: users.delegatePrivateKey })
      .from(users)
      .where(eq(users.id, user.id));

    if (!reloaded || !reloaded.delegatePrivateKey) {
      throw new DelegateKeyCryptoError("Encrypted delegate key envelope is empty");
    }
    user.delegatePrivateKey = reloaded.delegatePrivateKey;
    return openOrMigrateDelegatePrivateKey(
      reloaded.delegatePrivateKey,
      secretOverride
    );
  }
  return resolved;
}

/**
 * Batch-backfill any remaining pre-upgrade 64-hex plaintext delegate keys in
 * `users` into AES-256-GCM `v1.` envelopes in place.
 *
 * Compares `users.delegatePrivateKey` with the read plaintext atomically to
 * avoid clobbering concurrent credential updates.
 */
export async function backfillLegacyDelegateKeys(
  db: DbClient,
  secretOverride?: string
): Promise<number> {
  const rows = await db
    .select({
      id: users.id,
      delegatePrivateKey: users.delegatePrivateKey,
    })
    .from(users);
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
      const updated = await db
        .update(users)
        .set({
          delegatePrivateKey: encryptedEnvelope,
        })
        .where(
          and(
            eq(users.id, row.id),
            eq(users.delegatePrivateKey, row.delegatePrivateKey)
          )
        )
        .returning();
      if (updated.length > 0) {
        migratedCount += 1;
      }
    }
  }
  return migratedCount;
}

/** Look up Enoki user with stored credentials for returning-user fast path. */
export async function getEnokiUserBySuiAddress(db: DbClient, suiAddress: string) {
  const [user] = await db
    .select()
    .from(users)
    .where(
      and(eq(users.suiAddress, suiAddress), eq(users.authMethod, "enoki"))
    )
    .limit(1);

  if (user?.delegatePrivateKey && user?.delegateAccountId) {
    try {
      await resolveAndMigrateUserDelegateKey(db, user);
      return user;
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Return the delegate key material for a verified owner, scoped strictly to the
 * given suiAddress. This is the ONLY path that exposes the private key, and it
 * must be gated by a proven ownership challenge at the route layer.
 */
export async function getDelegateKeyForOwner(
  db: DbClient,
  suiAddress: string
): Promise<{ delegatePrivateKey: string; delegateAccountId: string } | null> {
  const [user] = await db
    .select()
    .from(users)
    .where(eq(users.suiAddress, suiAddress))
    .limit(1);

  if (user?.delegatePrivateKey && user?.delegateAccountId) {
    const { plaintextKey } = await resolveAndMigrateUserDelegateKey(db, user);
    return {
      delegatePrivateKey: plaintextKey,
      delegateAccountId: user.delegateAccountId,
    };
  }
  return null;
}

/** Look up a user's Sui address by id (used to bind an export to its session). */
export async function getUserAddressById(
  db: DbClient,
  userId: string
): Promise<string | null> {
  const [user] = await db
    .select({ suiAddress: users.suiAddress })
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);
  return user?.suiAddress ?? null;
}

/** Create an Enoki session. Reuses walletSessions table with walletType "enoki". */
export async function createEnokiSession(
  db: DbClient,
  input: { sessionId: string; userId: string; suiAddress: string }
) {
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await db.insert(walletSessions).values({
    id: input.sessionId,
    userId: input.userId,
    walletAddress: input.suiAddress,
    walletType: "enoki",
    signedMessage: "enoki-zklogin",
    signature: "",
    signedAt: new Date(),
    expiresAt,
  });
  return { sessionId: input.sessionId, expiresAt };
}

// ══════════════════════════════════════════════════════════════
// SESSION CLEANUP
// ══════════════════════════════════════════════════════════════

/**
 * Delete all sessions for a given session ID (logout)
 * Removes from both zkLoginSessions and walletSessions tables
 */
export async function deleteSession(db: DbClient, sessionId: string) {
  await db.delete(zkLoginSessions).where(eq(zkLoginSessions.id, sessionId));
  await db.delete(walletSessions).where(eq(walletSessions.id, sessionId));
}

/**
 * POST /api/auth/enoki Phase 2 (register) must verify on-chain that the
 * submitted delegate key is registered on an active MemWalAccount owned by
 * the wallet that just passed the Enoki challenge (#1008). Noter performs the
 * same check at the identical step.
 *
 * Runs the real route and the real binding validation. Only the leaf I/O is
 * faked: the Sui gRPC read, the DB, the session cookie, the challenge store,
 * and the rate limiter. No network is touched.
 */
import assert from "node:assert/strict";
import { before, beforeEach, mock, test } from "node:test";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";

if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m: Uint8Array[]) => {
    const h = sha512.create();
    for (const msg of m) h.update(msg);
    return h.digest();
  };
}

const PACKAGE_ID = `0x${"2".repeat(64)}`;
process.env.NEXT_PUBLIC_MEMWAL_PACKAGE_ID = PACKAGE_ID;
for (const key of ["PLAYWRIGHT", "PLAYWRIGHT_TEST_BASE_URL", "CI_PLAYWRIGHT"]) {
  delete process.env[key];
}

const WALLET = `0x${"1".repeat(64)}`;
const OTHER_WALLET = `0x${"9".repeat(64)}`;
const ACCOUNT_ID = `0x${"ac".repeat(32)}`;
const PRIVATE_KEY = "5".repeat(64);
const PUBLIC_KEY = Buffer.from(
  ed.getPublicKey(Buffer.from(PRIVATE_KEY, "hex"))
).toString("hex");

type ChainObject = { type?: string; json?: unknown } | undefined;
let chain: { object: ChainObject; throws: boolean; reads: string[] };
let persisted: Array<{ op: string; accountId: string }>;
let sessions: Array<{ accountId: string }>;
let existingUser: { id: string } | null;

beforeEach(() => {
  chain = { object: undefined, throws: false, reads: [] };
  persisted = [];
  sessions = [];
  existingUser = null;
});

mock.module("@mysten/sui/grpc", {
  namedExports: {
    SuiGrpcClient: class {
      async getObject({ objectId }: { objectId: string }) {
        chain.reads.push(objectId);
        if (chain.throws) throw new Error("fullnode unavailable");
        return { object: chain.object };
      }
    },
  },
});
mock.module("@/lib/auth/session", {
  namedExports: {
    createSession: async (_id: string, _pk: string, accountId: string) => {
      sessions.push({ accountId });
    },
  },
});
mock.module("@/lib/db/queries", {
  namedExports: {
    getUserBySuiAddress: async () => existingUser,
    createEnokiUser: async (input: { accountId: string }) => {
      persisted.push({ op: "create", accountId: input.accountId });
      return { id: "user-new" };
    },
    updateEnokiUserCredentials: async (input: { accountId: string }) => {
      persisted.push({ op: "update", accountId: input.accountId });
    },
  },
});
mock.module("@/lib/auth/enoki-challenge", {
  namedExports: { verifyAndConsumeEnokiChallenge: async () => true },
});
mock.module("@/lib/auth/request-security", {
  namedExports: { isSameOriginRequest: () => true },
});
class AuthRateLimitError extends Error {
  status = 429;
}
mock.module("@/lib/ratelimit", {
  namedExports: { AuthRateLimitError, checkAuthRateLimit: async () => {} },
});
class SharedRedisUnavailableError extends Error {}
mock.module("@/lib/shared-redis", {
  namedExports: { SharedRedisUnavailableError },
});

type RoutePost = (request: Request) => Promise<Response>;
let POST: RoutePost;
before(async () => {
  ({ POST } = await import("@/app/api/auth/enoki/route"));
});

function account(fields: Record<string, unknown>, type?: string): ChainObject {
  return {
    type: type ?? `${PACKAGE_ID}::account::MemWalAccount`,
    json: {
      active: true,
      owner: WALLET,
      delegate_keys: [{ public_key: PUBLIC_KEY }],
      ...fields,
    },
  };
}

async function register(overrides: Record<string, unknown> = {}) {
  const res = await POST(
    new Request("http://researcher.local/api/auth/enoki", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        suiAddress: WALLET,
        signature: "sig",
        privateKey: PRIVATE_KEY,
        accountId: ACCOUNT_ID,
        ...overrides,
      }),
    })
  );
  return { status: res.status, body: (await res.json()) as { error?: string } };
}

function assertRejected(
  result: { status: number; body: { error?: string } },
  pattern: RegExp
) {
  assert.equal(result.status, 401, JSON.stringify(result.body));
  assert.match(result.body.error ?? "", pattern);
  assert.deepEqual(persisted, [], "unverified credentials must not be stored");
  assert.deepEqual(sessions, [], "no session for unverified credentials");
}

test("rejects an account owned by a different wallet", async () => {
  chain.object = account({ owner: OTHER_WALLET });
  assertRejected(await register(), /owner does not match the authenticated wallet/);
  assert.deepEqual(chain.reads, [ACCOUNT_ID]);
});

test("rejects an account object with no owner field", async () => {
  chain.object = account({ owner: undefined });
  assertRejected(await register(), /owner does not match/);
});

test("rejects a self-generated key that is not registered on the account", async () => {
  chain.object = account({ delegate_keys: [{ public_key: "cd".repeat(32) }] });
  assertRejected(await register(), /not registered/);
});

test("rejects an inactive account", async () => {
  chain.object = account({ active: false });
  assertRejected(await register(), /inactive/);
});

test("rejects an object that is not a MemWalAccount of the configured package", async () => {
  chain.object = account({}, `0x${"3".repeat(64)}::account::MemWalAccount`);
  assertRejected(await register(), /not a configured MemWalAccount/);
});

test("rejects when the account does not exist", async () => {
  chain.object = undefined;
  assertRejected(await register(), /no Move type/);
});

test("fails closed when the chain read errors", async () => {
  chain.throws = true;
  assertRejected(await register(), /Unable to verify/);
});

test("does not overwrite an existing user's credentials with unverified ones", async () => {
  existingUser = { id: "user-1" };
  chain.object = account({ owner: OTHER_WALLET });
  assertRejected(await register(), /owner does not match/);
});

test("accepts a key registered on an active account owned by the wallet", async () => {
  chain.object = account({});
  const result = await register();
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.deepEqual(persisted, [{ op: "create", accountId: ACCOUNT_ID }]);
  assert.deepEqual(sessions, [{ accountId: ACCOUNT_ID }]);
});

test("accepts an on-chain owner in a different but equivalent address form", async () => {
  existingUser = { id: "user-1" };
  chain.object = account({ owner: WALLET.toUpperCase().replace("0X", "0x") });
  const result = await register();
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.deepEqual(persisted, [{ op: "update", accountId: ACCOUNT_ID }]);
});

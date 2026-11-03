/**
 * Unit and integration tests for multi-user and sender sub-namespace isolation.
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
  parseConfig,
  sanitizeNamespaceSegment,
  extractSenderId,
  extractSessionId,
  resolveScopedAgent,
  resolveScopedToolNamespace,
} from "../dist/config.js";
import { registerHooks } from "../dist/hooks/index.js";
import { registerRecallHook } from "../dist/hooks/recall.js";
import { registerCaptureHook } from "../dist/hooks/capture.js";
import { registerTools } from "../dist/tools/index.js";
import { registerSearchTool } from "../dist/tools/search.js";
import { registerStoreTool } from "../dist/tools/store.js";

function makeApi(ctx) {
  const hooks = {};
  const logs = [];
  const tools = {};
  return {
    hooks,
    logs,
    tools,
    api: {
      on: (event, fn) => {
        hooks[event] = fn;
      },
      registerTool: (toolOrFactory) => {
        const tool =
          typeof toolOrFactory === "function"
            ? toolOrFactory(ctx ?? { sessionKey: "agent:main:default" })
            : toolOrFactory;
        if (tool?.name) tools[tool.name] = tool;
      },
      registerCli: () => {},
      registerService: () => {},
      logger: {
        info: (m) => logs.push(m),
        warn: (m) => logs.push(m),
        debug: (m) => logs.push(m),
        error: (m) => logs.push(m),
      },
    },
  };
}

const BASE_CONFIG = {
  privateKey: "a".repeat(64),
  accountId: "0x" + "1".repeat(40),
  serverUrl: "https://relayer.dev.memwal.ai",
  defaultNamespace: "default",
  requestTimeoutMs: 5000,
};

test("sanitizeNamespaceSegment sanitizes, collapses underscores, and bounds length", () => {
  assert.equal(sanitizeNamespaceSegment("alice"), "alice");
  assert.equal(sanitizeNamespaceSegment("  alice.smith  "), "alice.smith");
  assert.equal(sanitizeNamespaceSegment("user@domain.com"), "user_domain.com");
  assert.equal(sanitizeNamespaceSegment("___test___user___"), "test_user");
  assert.equal(sanitizeNamespaceSegment("!@#$%^&*()"), "");
  assert.equal(sanitizeNamespaceSegment(""), "");

  const longRaw = "a".repeat(100);
  const sanitizedLong = sanitizeNamespaceSegment(longRaw);
  assert.equal(sanitizedLong.length, 64);
  assert.equal(sanitizedLong, "a".repeat(64));
});

test("extractSenderId checks priority order and rejects placeholder identities", () => {
  assert.equal(extractSenderId({ senderId: "ctx-sender" }), "ctx-sender");
  assert.equal(
    extractSenderId({ senderId: "ctx-sender" }, { senderId: "event-sender" }),
    "event-sender",
  );
  assert.equal(extractSenderId({ userId: "ctx-user" }), "ctx-user");
  assert.equal(extractSenderId({ from: "+1234567890" }), "+1234567890");
  assert.equal(
    extractSenderId({ metadata: { senderId: "meta-sender" } }),
    "meta-sender",
  );

  // Placeholder identities must be rejected
  assert.equal(extractSenderId({ senderId: "anonymous" }), undefined);
  assert.equal(extractSenderId({ senderId: "unknown" }), undefined);
  assert.equal(extractSenderId({ senderId: "undefined" }), undefined);
  assert.equal(extractSenderId({ senderId: "null" }), undefined);
  assert.equal(extractSenderId({ senderId: "   " }), undefined);
  assert.equal(extractSenderId(undefined, { senderId: "none" }), undefined);
});

test("extractSessionId checks event, context, and sessionKey third segment", () => {
  assert.equal(extractSessionId({ sessionId: "sess-ctx" }), "sess-ctx");
  assert.equal(
    extractSessionId({ sessionId: "sess-ctx" }, { sessionId: "sess-event" }),
    "sess-event",
  );
  assert.equal(
    extractSessionId({ metadata: { sessionId: "meta-sess" } }),
    "meta-sess",
  );

  // Check 3rd segment of sessionKey
  assert.equal(
    extractSessionId({ sessionKey: "agent:support:session-999" }),
    "session-999",
  );
  assert.equal(
    extractSessionId({ sessionKey: "agent:main:main" }),
    undefined,
  );
  assert.equal(
    extractSessionId({ sessionKey: "agent:main:default" }),
    undefined,
  );
  assert.equal(
    extractSessionId({ sessionKey: "agent:main:anonymous" }),
    undefined,
  );
  assert.equal(
    extractSessionId({ sessionKey: "agent:main" }),
    undefined,
  );
});

test("isolateBySender: false preserves legacy namespace resolution", () => {
  const config = {
    ...BASE_CONFIG,
    isolateBySender: false,
    includeSharedNamespaceOnRecall: false,
  };

  const scoped = resolveScopedAgent(config, {
    sessionKey: "agent:support:ticket-101",
    senderId: "alice",
  });

  assert.equal(scoped.isolationMode, "disabled");
  assert.equal(scoped.agentId, "support");
  assert.equal(scoped.namespace, "support");
  assert.equal(scoped.sharedNamespace, undefined);
  assert.equal(scoped.sessionId, "ticket-101");

  const resolved = resolveScopedToolNamespace(
    config,
    { sessionKey: "agent:support:ticket-101" },
    undefined,
  );
  assert.equal(resolved.namespace, "support");
  assert.equal(resolved.error, undefined);

  const rejected = resolveScopedToolNamespace(
    config,
    { sessionKey: "agent:support:ticket-101" },
    "default",
  );
  assert.equal(rejected.namespace, undefined);
  assert.equal(rejected.error, "namespace_rejected");
});

test("isolateBySender: true isolates two senders under the same agent", () => {
  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
    includeSharedNamespaceOnRecall: false,
  };

  const scopedAlice = resolveScopedAgent(
    config,
    { sessionKey: "agent:bot:session-1", senderId: "sender_alice" },
  );
  const scopedBob = resolveScopedAgent(
    config,
    { sessionKey: "agent:bot:session-2", senderId: "sender_bob" },
  );

  assert.equal(scopedAlice.isolationMode, "sender");
  assert.equal(scopedAlice.namespace, "bot:sender:sender_alice");
  assert.equal(scopedAlice.sharedNamespace, undefined);

  assert.equal(scopedBob.isolationMode, "sender");
  assert.equal(scopedBob.namespace, "bot:sender:sender_bob");
  assert.equal(scopedBob.sharedNamespace, undefined);
});

test("isolateBySender: true falls back to session ID when sender ID is missing", () => {
  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
    includeSharedNamespaceOnRecall: false,
  };

  // Missing sender, valid sessionId in context
  const scopedSession = resolveScopedAgent(
    config,
    { sessionId: "sess-42" },
  );
  assert.equal(scopedSession.isolationMode, "session");
  assert.equal(scopedSession.namespace, "default:session:sess-42");
  assert.equal(scopedSession.sessionId, "sess-42");

  // Anonymous sender, valid sessionKey 3rd segment
  const scopedFallback = resolveScopedAgent(
    config,
    { sessionKey: "agent:main:sess-fallback", senderId: "anonymous" },
  );
  assert.equal(scopedFallback.isolationMode, "session");
  assert.equal(scopedFallback.namespace, "default:session:sess-fallback");
  assert.equal(scopedFallback.sessionId, "sess-fallback");
});

test("isolateBySender: true refuses with missing_identity when neither sender nor session exists", () => {
  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
    includeSharedNamespaceOnRecall: false,
  };

  const scoped = resolveScopedAgent(
    config,
    { sessionKey: "agent:main:default", senderId: "unknown" },
  );

  assert.equal(scoped.isolationMode, "missing_identity");
  assert.equal(scoped.namespace, undefined);
  assert.equal(scoped.sharedNamespace, undefined);
  assert.equal(scoped.sessionId, undefined);
});

test("includeSharedNamespaceOnRecall: true sets sharedNamespace for recall", () => {
  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
    includeSharedNamespaceOnRecall: true,
  };

  const scoped = resolveScopedAgent(
    config,
    { sessionKey: "agent:assistant:session-1", senderId: "alice" },
  );

  assert.equal(scoped.isolationMode, "sender");
  assert.equal(scoped.namespace, "assistant:sender:alice");
  assert.equal(scoped.sharedNamespace, "assistant");
});

test("auto-recall skips and logs warning when identity is missing in isolated mode", async () => {
  const warnings = [];
  const mockApi = {
    on: (event, handler) => {
      if (event === "before_prompt_build") mockApi.handler = handler;
    },
    logger: {
      warn: (msg) => warnings.push(msg),
      info: () => {},
      debug: () => {},
    },
  };

  let clientCalled = false;
  const mockClient = {
    recall: async () => {
      clientCalled = true;
      return { results: [] };
    },
  };

  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
  };

  registerRecallHook(mockApi, mockClient, config);
  assert.ok(mockApi.handler);

  const res = await mockApi.handler(
    { prompt: "Tell me about my tasks today" },
    { sessionKey: "agent:main:default" },
  );

  assert.equal(res, undefined);
  assert.equal(clientCalled, false);
  assert.ok(
    warnings.some((w) =>
      w.includes(
        "skipping auto-recall because isolateBySender is enabled and no sender or session identity was provided",
      ),
    ),
  );
});

test("auto-recall merges shared namespace memories keeping sender memories first", async () => {
  const queriedNamespaces = [];
  const mockApi = {
    on: (event, handler) => {
      if (event === "before_prompt_build") mockApi.handler = handler;
    },
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
    },
  };

  const mockClient = {
    recall: async (_prompt, _limit, namespace) => {
      queriedNamespaces.push(namespace);
      if (namespace === "main:sender:alice") {
        return {
          results: [
            { id: "mem-sender-1", text: "Alice personal preference", distance: 0.1 },
            { id: "mem-shared-dup", text: "Duplicate fact across scopes", distance: 0.2 },
          ],
        };
      }
      if (namespace === "main") {
        return {
          results: [
            { id: "mem-shared-dup", text: "Duplicate fact across scopes", distance: 0.05 },
            { id: "mem-shared-2", text: "Global team project guideline", distance: 0.15 },
          ],
        };
      }
      return { results: [] };
    },
  };

  const config = {
    ...BASE_CONFIG,
    defaultNamespace: "main",
    isolateBySender: true,
    includeSharedNamespaceOnRecall: true,
    maxRecallResults: 5,
  };

  registerRecallHook(mockApi, mockClient, config);
  const response = await mockApi.handler(
    { prompt: "What are the project preferences?" },
    { sessionKey: "agent:main:session-10", senderId: "alice" },
  );

  assert.ok(queriedNamespaces.includes("main:sender:alice"));
  assert.ok(queriedNamespaces.includes("main"));

  // Sender preference is placed before shared memories
  assert.ok(response.prependContext.includes("Alice personal preference"));
  assert.ok(response.prependContext.includes("Global team project guideline"));

  // Deduplication check: duplicate fact must appear only once
  const occurrences = (
    response.prependContext.match(/Duplicate fact across scopes/g) || []
  ).length;
  assert.equal(occurrences, 1);
});

test("auto-capture skips when identity is missing in isolated mode", async () => {
  const warnings = [];
  let analyzeCalled = false;
  const mockApi = {
    on: (event, handler) => {
      if (event === "agent_end") mockApi.handler = handler;
    },
    logger: {
      warn: (msg) => warnings.push(msg),
      info: () => {},
      debug: () => {},
    },
  };
  const mockClient = {
    analyze: async () => {
      analyzeCalled = true;
      return { facts: [] };
    },
  };

  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
  };

  registerCaptureHook(mockApi, mockClient, config);
  await mockApi.handler(
    {
      success: true,
      messages: [{ role: "user", content: "Remember to buy milk tomorrow morning" }],
    },
    { sessionKey: "agent:main:default" },
  );

  assert.equal(analyzeCalled, false);
  assert.ok(
    warnings.some((w) =>
      w.includes(
        "skipping auto-capture because isolateBySender is enabled and no sender or session identity was provided",
      ),
    ),
  );
});

test("auto-capture includes session_id provenance prefix in conversation text", async () => {
  let capturedText = "";
  let capturedNamespace = "";
  const mockApi = {
    on: (event, handler) => {
      if (event === "agent_end") mockApi.handler = handler;
    },
    logger: {
      warn: () => {},
      info: () => {},
      debug: () => {},
    },
  };
  const mockClient = {
    analyze: async (text, opts) => {
      capturedText = text;
      capturedNamespace = opts.namespace;
      return { facts: [{ id: "f1", text: "captured fact" }] };
    },
  };

  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
  };

  registerCaptureHook(mockApi, mockClient, config);
  await mockApi.handler(
    {
      success: true,
      messages: [{ role: "user", content: "We chose Redis for caching layer" }],
    },
    { sessionKey: "agent:main:sess-1234", senderId: "alice" },
  );

  assert.equal(capturedNamespace, "default:sender:alice");
  assert.ok(capturedText.startsWith("[session_id: sess-1234]\n\n"));
  assert.ok(capturedText.includes("We chose Redis for caching layer"));
});

test("memory_search blocks cross-sender namespace access", async () => {
  const calls = [];
  const client = {
    recall: async (_q, _l, ns) => {
      calls.push(["recall", ns]);
      return { results: [{ text: "sample memory", distance: 0.1 }] };
    },
  };

  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
    includeSharedNamespaceOnRecall: true,
  };

  const h = makeApi({ sessionKey: "agent:main:sess-1", senderId: "alice" });
  registerTools(h.api, client, config);

  // 1. Omitting namespace defaults to caller's sender sub-namespace
  const ownSearch = await h.tools.memory_search.execute("s1", { query: "pref" });
  assert.equal(ownSearch.details.namespace, "default:sender:alice");
  assert.deepEqual(calls, [["recall", "default:sender:alice"]]);

  // 2. Querying shared namespace is allowed when includeSharedNamespaceOnRecall: true
  calls.length = 0;
  const sharedSearch = await h.tools.memory_search.execute("s2", {
    query: "team guide",
    namespace: "default",
  });
  assert.equal(sharedSearch.details.namespace, "default");
  assert.deepEqual(calls, [["recall", "default"]]);

  // 3. Querying another sender's sub-namespace is blocked
  calls.length = 0;
  const crossSearch = await h.tools.memory_search.execute("s3", {
    query: "secret",
    namespace: "default:sender:bob",
  });
  assert.equal(crossSearch.details.error, "cross_sender_namespace_forbidden");
  assert.equal(crossSearch.error, "cross_sender_namespace_forbidden");
  assert.deepEqual(calls, []);

  // 4. Querying an unrelated arbitrary namespace is blocked
  const attackerSearch = await h.tools.memory_search.execute("s4", {
    query: "secret",
    namespace: "other_agent_namespace",
  });
  assert.equal(attackerSearch.details.error, "cross_sender_namespace_forbidden");
  assert.deepEqual(calls, []);
});

test("memory_store blocks cross-sender namespace writes and maps default to sender namespace", async () => {
  const calls = [];
  const client = {
    analyze: async (text, opts) => {
      calls.push(["analyze", opts.namespace, text]);
      return { facts: [{ id: "f-1", text }] };
    },
  };

  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
    includeSharedNamespaceOnRecall: true,
  };

  const h = makeApi({ sessionKey: "agent:main:sess-alpha", senderId: "alice" });
  registerTools(h.api, client, config);

  // 1. Storing without namespace uses caller's sender sub-namespace
  const ownStore = await h.tools.memory_store.execute("st1", {
    text: "Alice prefers daily standups at 9am UTC",
  });
  assert.equal(ownStore.details.namespace, "default:sender:alice");
  assert.equal(ownStore.details.sessionId, "sess-alpha");
  assert.equal(calls[0][1], "default:sender:alice");

  // 2. Passing the base namespace by habit maps to caller's sender namespace (never writes to shared)
  calls.length = 0;
  const habitStore = await h.tools.memory_store.execute("st2", {
    text: "Alice notes our team launch deadline is Friday",
    namespace: "default",
  });
  assert.equal(habitStore.details.namespace, "default:sender:alice");
  assert.equal(calls[0][1], "default:sender:alice");

  // 3. Storing into another sender's namespace is blocked
  calls.length = 0;
  const crossStore = await h.tools.memory_store.execute("st3", {
    text: "Malicious injection into Bob's namespace",
    namespace: "default:sender:bob",
  });
  assert.equal(crossStore.details.error, "cross_sender_namespace_forbidden");
  assert.equal(crossStore.error, "cross_sender_namespace_forbidden");
  assert.deepEqual(calls, []);
});

test("memory_search and memory_store require identity when sender isolation is enabled", async () => {
  const client = {
    recall: async () => ({ results: [] }),
    analyze: async () => ({ facts: [] }),
  };

  const config = {
    ...BASE_CONFIG,
    isolateBySender: true,
  };

  const h = makeApi({ sessionKey: "agent:main:default" });
  registerTools(h.api, client, config);

  const searchRes = await h.tools.memory_search.execute("req1", { query: "test" });
  assert.equal(searchRes.details.error, "sender_identity_required");
  assert.equal(searchRes.error, "sender_identity_required");

  const storeRes = await h.tools.memory_store.execute("req2", { text: "Some fact" });
  assert.equal(storeRes.details.error, "sender_identity_required");
  assert.equal(storeRes.error, "sender_identity_required");
});

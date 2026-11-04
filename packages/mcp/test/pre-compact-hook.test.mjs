import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { Worker } from "node:worker_threads";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAsync } from "@noble/ed25519";

import {
    publishHookState,
    AUTO_SAVE_ENV,
} from "../dist/auto-save.js";
import {
    redactSecrets,
} from "../dist/pre-compact.js";
import {
    SECRET_EXCLUSION_RULES,
    PRE_COMPACT_PROMPT,
} from "../dist/memory-policy.js";
import {
    generateKeypair,
    hexToBytes,
} from "../dist/crypto.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = resolve(__dirname, "../plugin");
const HOOK_SCRIPT = join(PLUGIN_ROOT, "scripts", "on_pre_compact.mjs");
const HOOKS_JSON = join(PLUGIN_ROOT, "hooks.json");

function freshTempDir(prefix = "memwal-precompact-test-") {
    return mkdtempSync(join(tmpdir(), prefix));
}

function writeSettings(dir, value) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "settings.json"), JSON.stringify(value));
    const saved = process.env.MEMWAL_CREDS_DIR;
    const savedAutoSave = process.env[AUTO_SAVE_ENV];
    try {
        process.env.MEMWAL_CREDS_DIR = dir;
        delete process.env[AUTO_SAVE_ENV];
        publishHookState();
    } finally {
        if (saved === undefined) delete process.env.MEMWAL_CREDS_DIR;
        else process.env.MEMWAL_CREDS_DIR = saved;
        if (savedAutoSave === undefined) delete process.env[AUTO_SAVE_ENV];
        else process.env[AUTO_SAVE_ENV] = savedAutoSave;
    }
}

async function writeTestCreds(dir, overrides = {}) {
    const keypair = await generateKeypair();
    const creds = {
        delegatePrivateKey: keypair.privateKeyHex,
        delegatePublicKeyHex: keypair.publicKeyHex,
        delegateAddress: keypair.suiAddress,
        walletAddress: "0x" + "1".repeat(64),
        accountId: "0x" + "2".repeat(64),
        packageId: "0x" + "3".repeat(64),
        relayerUrl: "http://127.0.0.1:9999",
        createdAt: new Date().toISOString(),
        version: 1,
        ...overrides,
    };
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "credentials.json"), JSON.stringify(creds, null, 2), { mode: 0o600 });
    return { creds, keypair };
}

function runPreCompactHook(env = {}, input = {}) {
    return spawnSync(process.execPath, [HOOK_SCRIPT], {
        input: JSON.stringify(input),
        encoding: "utf8",
        env: {
            ...process.env,
            ...env,
        },
    });
}

/**
 * Run a mock HTTP relayer in a Worker thread.
 * Because spawnSync blocks the main Node thread, running the mock HTTP server
 * in a Worker thread allows it to respond to synchronous child-process requests.
 */
function startWorkerMockRelayer(options = {}) {
    const workerCode = `
import { createServer } from "node:http";
import { parentPort } from "node:worker_threads";

let reqCount = 0;
let config = ${JSON.stringify(options)};

const server = createServer((req, res) => {
    const idx = reqCount++;
    const status = (config.statusCodes && config.statusCodes[idx] !== undefined)
        ? config.statusCodes[idx]
        : (config.statusCode || 200);
    const delay = config.delayMs || 0;
    let body = "";
    req.on("data", chunk => (body += chunk));
    req.on("end", () => {
        const receivedAt = Date.now();
        setTimeout(() => {
            const respondedAt = Date.now();
            parentPort.postMessage({
                type: "request",
                req: {
                    method: req.method,
                    url: req.url,
                    headers: req.headers,
                    body,
                    receivedAt,
                    respondedAt,
                }
            });
            res.writeHead(status, { "Content-Type": "application/json" });
            res.end(JSON.stringify(status === 200 ? { status: "ok" } : { error: "relayer error" }));
        }, delay);
    });
});

server.listen(0, "127.0.0.1", () => {
    parentPort.postMessage({ type: "listening", port: server.address().port });
});
`;

    const worker = new Worker(workerCode, { eval: true });
    const requests = [];

    worker.on("message", (msg) => {
        if (msg.type === "request") {
            requests.push(msg.req);
        }
    });

    return new Promise((resolvePromise) => {
        worker.on("message", (msg) => {
            if (msg.type === "listening") {
                resolvePromise({
                    url: `http://127.0.0.1:${msg.port}`,
                    requests,
                    close: () => worker.terminate(),
                });
            }
        });
    });
}

async function waitForRequests(mock, count, timeoutMs = 2000) {
    const start = Date.now();
    while (mock.requests.length < count && Date.now() - start < timeoutMs) {
        await new Promise((r) => setTimeout(r, 10));
    }
    // Yield to let any pending messages flush
    await new Promise((r) => setImmediate(r));
}

test("hooks.json registers PreCompact pointing to on_pre_compact.mjs with reasonable timeout", () => {
    const raw = readFileSync(HOOKS_JSON, "utf8");
    const parsed = JSON.parse(raw);
    assert.ok(parsed.hooks, "hooks object must exist");
    assert.ok(Array.isArray(parsed.hooks.PreCompact), "PreCompact hook array must exist");
    assert.ok(parsed.hooks.PreCompact.length > 0, "PreCompact hook array must not be empty");

    const commands = [];
    let timeout = 0;
    for (const group of parsed.hooks.PreCompact) {
        for (const hook of group.hooks || []) {
            if (hook.command) commands.push(hook.command);
            if (hook.timeout) timeout = hook.timeout;
        }
    }

    assert.ok(
        commands.some((cmd) => cmd.includes("on_pre_compact.mjs")),
        `hooks.json must register on_pre_compact.mjs: ${JSON.stringify(commands)}`
    );
    assert.ok(timeout >= 8, `timeout must be at least 8 seconds: got ${timeout}`);
});

test("on_pre_compact.mjs outputs nothing and exits 0 when autoSave is false via settings", () => {
    const dir = freshTempDir();
    try {
        writeSettings(dir, { autoSave: false });
        const result = runPreCompactHook({ MEMWAL_CREDS_DIR: dir });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout.trim(), "");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("on_pre_compact.mjs outputs nothing and exits 0 when autoSave is false via MEMWAL_AUTO_SAVE env", () => {
    const dir = freshTempDir();
    try {
        writeSettings(dir, { autoSave: true });
        const result = runPreCompactHook({
            MEMWAL_CREDS_DIR: dir,
            [AUTO_SAVE_ENV]: "false",
        });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout.trim(), "");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("on_pre_compact.mjs outputs nothing and exits 0 when autoSave is unset", () => {
    const dir = freshTempDir();
    try {
        const result = runPreCompactHook({
            MEMWAL_CREDS_DIR: dir,
            [AUTO_SAVE_ENV]: undefined,
        });
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout.trim(), "");
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("PRE_COMPACT_PROMPT meets behavioral and secret exclusion specifications", () => {
    assert.match(PRE_COMPACT_PROMPT, /Before the conversation context is compacted/);
    assert.match(PRE_COMPACT_PROMPT, /durable user preferences/);
    assert.match(PRE_COMPACT_PROMPT, /architectural decisions/);
    assert.match(PRE_COMPACT_PROMPT, /project conventions/);
    assert.match(PRE_COMPACT_PROMPT, /resolved bug root causes/);
    assert.match(PRE_COMPACT_PROMPT, /memwal_remember/);
    assert.match(PRE_COMPACT_PROMPT, /memwal_remember_bulk/);
    assert.match(PRE_COMPACT_PROMPT, /ephemeral progress notes/);
    assert.match(PRE_COMPACT_PROMPT, /raw command output/);
    assert.ok(PRE_COMPACT_PROMPT.includes(SECRET_EXCLUSION_RULES));
});

test("on_pre_compact.mjs outputs strictly empty stdout and never emits hookSpecificOutput on allow", async () => {
    const tempDir = freshTempDir();
    const mock = await startWorkerMockRelayer({ statusCode: 200 });

    try {
        writeSettings(tempDir, { autoSave: true });
        await writeTestCreds(tempDir, { relayerUrl: mock.url });

        const transcriptPath = join(tempDir, "session.jsonl");
        const lines = [
            JSON.stringify({
                type: "user",
                message: {
                    role: "user",
                    content: "We should consistently use pnpm workspaces for all TypeScript packages in this repository.",
                },
            }),
            JSON.stringify({
                type: "assistant",
                message: {
                    role: "assistant",
                    content: [{ type: "text", text: "Understood, all future packages will be configured as pnpm workspaces." }],
                },
            }),
        ];
        writeFileSync(transcriptPath, lines.join("\n") + "\n");

        const result = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-session-stdout-empty",
                transcript_path: transcriptPath,
            }
        );

        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout, "", "stdout must be strictly empty (Claude Code PreCompact contract)");
        assert.ok(!result.stdout.includes("hookSpecificOutput"), "hookSpecificOutput must never be emitted on PreCompact");
        await waitForRequests(mock, 1);
        assert.equal(mock.requests.length, 1);
    } finally {
        await mock.close();
        rmSync(tempDir, { recursive: true, force: true });
    }
});

test("mock relayer receives signed POST /api/analyze with verified Ed25519 signature and headers", async () => {
    const tempDir = freshTempDir();
    const mock = await startWorkerMockRelayer({ statusCode: 200 });

    try {
        writeSettings(tempDir, { autoSave: true });
        const { creds, keypair } = await writeTestCreds(tempDir, { relayerUrl: mock.url });

        const transcriptPath = join(tempDir, "transcript.jsonl");
        const turn = JSON.stringify({
            role: "user",
            content: "Architectural decision: We will use PostgreSQL with pgvector for persistent vector memory storage.",
        });
        writeFileSync(transcriptPath, turn + "\n");

        const result = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-session-ed25519",
                transcript_path: transcriptPath,
            }
        );

        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stdout, "");
        await waitForRequests(mock, 1);
        assert.equal(mock.requests.length, 1);

        const req = mock.requests[0];
        assert.equal(req.method, "POST");
        assert.equal(req.url, "/api/analyze");

        // Verify headers
        assert.equal(req.headers["x-public-key"], keypair.publicKeyHex.toLowerCase());
        assert.equal(req.headers["x-account-id"], creds.accountId);
        assert.ok(req.headers["x-signature"], "x-signature header must be present");
        assert.ok(req.headers["x-nonce"], "x-nonce header must be present");
        assert.ok(req.headers["x-timestamp"], "x-timestamp header must be present");
        assert.equal(req.headers["content-type"], "application/json");

        // Verify Ed25519 signature
        const timestamp = req.headers["x-timestamp"];
        const nonce = req.headers["x-nonce"];
        const signature = req.headers["x-signature"];
        const publicKey = req.headers["x-public-key"];
        const bodyHash = createHash("sha256").update(req.body).digest("hex");
        const canonical = `${timestamp}.POST./api/analyze.${bodyHash}.${nonce}.${creds.accountId}`;

        const verified = await verifyAsync(
            hexToBytes(signature),
            new TextEncoder().encode(canonical),
            hexToBytes(publicKey)
        );
        assert.ok(verified, "Ed25519 signature verification against canonical message must succeed");

        // Verify parsed payload
        const parsedBody = JSON.parse(req.body);
        assert.equal(parsedBody.namespace, "default");
        assert.ok(parsedBody.text.includes("Architectural decision: We will use PostgreSQL"));
    } finally {
        await mock.close();
        rmSync(tempDir, { recursive: true, force: true });
    }
});

test("on_pre_compact.mjs blocks synchronously until POST /api/analyze finishes", async () => {
    const tempDir = freshTempDir();
    const mock = await startWorkerMockRelayer({ statusCode: 200, delayMs: 150 });

    try {
        writeSettings(tempDir, { autoSave: true });
        await writeTestCreds(tempDir, { relayerUrl: mock.url });

        const transcriptPath = join(tempDir, "block-test.jsonl");
        writeFileSync(
            transcriptPath,
            JSON.stringify({
                role: "user",
                content: "Important architectural invariant: Always authenticate before accessing the private database.",
            }) + "\n"
        );

        const result = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-session-block",
                transcript_path: transcriptPath,
            }
        );

        const hookFinishedAt = Date.now();
        assert.equal(result.status, 0);
        await waitForRequests(mock, 1);
        assert.equal(mock.requests.length, 1);
        const req = mock.requests[0];
        assert.ok(req.respondedAt > 0, "Server must have responded to the request");
        assert.ok(
            hookFinishedAt >= req.respondedAt,
            `Hook must finish after server response (finished=${hookFinishedAt}, server=${req.respondedAt})`
        );
    } finally {
        await mock.close();
        rmSync(tempDir, { recursive: true, force: true });
    }
});

test("transcript filtering: skips tool calls, opt-outs, and redacts secrets while durable turns reach relayer", async () => {
    const tempDir = freshTempDir();
    const mock = await startWorkerMockRelayer({ statusCode: 200 });

    try {
        writeSettings(tempDir, { autoSave: true });
        await writeTestCreds(tempDir, { relayerUrl: mock.url });

        const transcriptPath = join(tempDir, "filter-test.jsonl");
        const lines = [
            // 1. Tool use + thinking
            JSON.stringify({
                role: "assistant",
                content: [
                    { type: "thinking", thinking: "I should run tests now to be safe." },
                    { type: "tool_use", id: "t1", name: "Bash", input: { command: "ls -la" } },
                ],
            }),
            // 2. Tool result
            JSON.stringify({
                role: "user",
                content: [{ type: "tool_result", tool_use_id: "t1", content: "total 0" }],
            }),
            // 3. Opt-out via [no-memory]
            JSON.stringify({
                role: "user",
                content: "This is a temporary secret fact [no-memory] that must not be stored anywhere.",
            }),
            // 4. Opt-out via MEMWAL_IGNORE
            JSON.stringify({
                role: "user",
                content: "Another note with MEMWAL_IGNORE to be dropped entirely.",
            }),
            // 5. Slash command
            JSON.stringify({
                role: "user",
                content: "/compact please keep it concise",
            }),
            // 6. Private block stripped + secrets redacted + durable decision kept
            JSON.stringify({
                role: "user",
                content: [
                    {
                        type: "text",
                        text: "Architecture: We deploy all nodes to AWS us-west-2. <private>Personal phone 555-1234</private> Database url is postgres://admin:superSecret123@db.internal:5432/app with AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE and API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456789 and sui key suiprivkey1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq.",
                    },
                ],
            }),
        ];

        writeFileSync(transcriptPath, lines.join("\n") + "\n");

        const result = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-session-filtering",
                transcript_path: transcriptPath,
            }
        );

        assert.equal(result.status, 0);
        await waitForRequests(mock, 1);
        assert.equal(mock.requests.length, 1);
        const analyzedText = JSON.parse(mock.requests[0].body).text;
        assert.ok(analyzedText.length > 0, "Analyzed text should be non-empty");

        // Verify durable fact survived
        assert.ok(analyzedText.includes("Architecture: We deploy all nodes to AWS us-west-2."));

        // Verify tool_use, tool_result, thinking were excluded
        assert.ok(!analyzedText.includes("I should run tests now"));
        assert.ok(!analyzedText.includes("ls -la"));
        assert.ok(!analyzedText.includes("total 0"));

        // Verify opt-outs were excluded
        assert.ok(!analyzedText.includes("temporary secret fact"));
        assert.ok(!analyzedText.includes("MEMWAL_IGNORE"));

        // Verify slash command was excluded
        assert.ok(!analyzedText.includes("/compact"));

        // Verify private block was stripped
        assert.ok(!analyzedText.includes("Personal phone 555-1234"));

        // Verify secrets were redacted
        assert.ok(!analyzedText.includes("superSecret123"));
        assert.ok(!analyzedText.includes("AKIAIOSFODNN7EXAMPLE"));
        assert.ok(!analyzedText.includes("sk-ant-api03-"));
        assert.ok(!analyzedText.includes("suiprivkey1"));
        assert.ok(analyzedText.includes("[redacted:url-credentials]"));
        assert.ok(analyzedText.includes("[redacted:sui-private-key]"));
    } finally {
        await mock.close();
        rmSync(tempDir, { recursive: true, force: true });
    }
});

test("incremental watermark: second run on same transcript makes 0 calls, appending turn sends only new turn", async () => {
    const tempDir = freshTempDir();
    const mock = await startWorkerMockRelayer({ statusCode: 200 });

    try {
        writeSettings(tempDir, { autoSave: true });
        await writeTestCreds(tempDir, { relayerUrl: mock.url });

        const transcriptPath = join(tempDir, "watermark.jsonl");
        const turn1 = JSON.stringify({
            role: "user",
            content: "Turn 1: We selected Rust for high-performance low-latency relayer services.",
        });
        writeFileSync(transcriptPath, turn1 + "\n");

        // First run
        const res1 = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-watermark-session",
                transcript_path: transcriptPath,
            }
        );
        assert.equal(res1.status, 0);
        await waitForRequests(mock, 1);
        assert.equal(mock.requests.length, 1);
        const text1 = JSON.parse(mock.requests[0].body).text;
        assert.ok(text1.includes("Turn 1: We selected Rust"));

        // Second run with identical transcript (no new turns)
        const res2 = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-watermark-session",
                transcript_path: transcriptPath,
            }
        );
        assert.equal(res2.status, 0);
        assert.equal(res2.stdout, "");
        await waitForRequests(mock, 1, 100);
        assert.equal(mock.requests.length, 1, "Second run with no new lines must make 0 calls");

        // Append Turn 2
        const turn2 = JSON.stringify({
            role: "user",
            content: "Turn 2: We choose Tokio as our asynchronous runtime executor in Rust.",
        });
        writeFileSync(transcriptPath, turn2 + "\n", { flag: "a" });

        // Third run with newly appended turn
        const res3 = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-watermark-session",
                transcript_path: transcriptPath,
            }
        );
        assert.equal(res3.status, 0);
        await waitForRequests(mock, 2);
        assert.equal(mock.requests.length, 2, "Third run must make exactly 1 new call");
        const text2 = JSON.parse(mock.requests[1].body).text;
        assert.ok(text2.includes("Turn 2: We choose Tokio"));
        assert.ok(!text2.includes("Turn 1: We selected Rust"), "Turn 2 must NOT include Turn 1");
    } finally {
        await mock.close();
        rmSync(tempDir, { recursive: true, force: true });
    }
});

test("unapproved project credentials in cwd are NOT used without global credentials (0 calls)", async () => {
    const tempDir = freshTempDir();
    const projectDir = join(tempDir, "unapproved-project");
    const mock = await startWorkerMockRelayer({ statusCode: 200 });

    try {
        // Only settings in global dir, NO credentials.json in global dir
        writeSettings(tempDir, { autoSave: true });

        // Unapproved credentials inside projectDir
        const projectCredsDir = join(projectDir, ".memwal");
        mkdirSync(projectCredsDir, { recursive: true });
        const keypair = await generateKeypair();
        writeFileSync(
            join(projectCredsDir, "credentials.json"),
            JSON.stringify({
                delegatePrivateKey: keypair.privateKeyHex,
                delegatePublicKeyHex: keypair.publicKeyHex,
                delegateAddress: keypair.suiAddress,
                walletAddress: "0x" + "4".repeat(64),
                accountId: "0x" + "5".repeat(64),
                packageId: "0x" + "6".repeat(64),
                relayerUrl: mock.url,
                createdAt: new Date().toISOString(),
                version: 1,
            })
        );

        const transcriptPath = join(projectDir, "transcript.jsonl");
        writeFileSync(
            transcriptPath,
            JSON.stringify({
                role: "user",
                content: "This project has unapproved credentials that must not be used.",
            }) + "\n"
        );

        // Run hook with cwd pointing to unapproved project
        const result = runPreCompactHook(
            {
                HOME: tempDir,
                USERPROFILE: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-unapproved-creds",
                transcript_path: transcriptPath,
                cwd: projectDir,
            }
        );

        assert.equal(result.status, 0);
        assert.equal(result.stdout, "");
        await waitForRequests(mock, 0, 100);
        assert.equal(mock.requests.length, 0, "Must make 0 calls when project credentials are unapproved and global credentials absent");
    } finally {
        await mock.close();
        rmSync(tempDir, { recursive: true, force: true });
    }
});

test("unapproved project credentials in cwd fall back to approved global credentials", async () => {
    const tempDir = freshTempDir();
    const projectDir = join(tempDir, "repo");
    const mock = await startWorkerMockRelayer({ statusCode: 200 });

    try {
        // Global credentials in HOME/.memwal/credentials.json
        const globalCredsDir = join(tempDir, ".memwal");
        mkdirSync(globalCredsDir, { recursive: true });
        writeFileSync(join(globalCredsDir, "settings.json"), JSON.stringify({ autoSave: true }));

        const globalKeypair = await generateKeypair();
        const globalAccountId = "0x" + "a".repeat(64);
        writeFileSync(
            join(globalCredsDir, "credentials.json"),
            JSON.stringify({
                delegatePrivateKey: globalKeypair.privateKeyHex,
                delegatePublicKeyHex: globalKeypair.publicKeyHex,
                delegateAddress: globalKeypair.suiAddress,
                walletAddress: "0x" + "1".repeat(64),
                accountId: globalAccountId,
                packageId: "0x" + "2".repeat(64),
                relayerUrl: mock.url,
                createdAt: new Date().toISOString(),
                version: 1,
            })
        );

        // Write published hook state so autoSave check passes
        writeFileSync(
            join(globalCredsDir, "auto-save-state.json"),
            JSON.stringify({
                version: 1,
                enabled: true,
                state: "on",
                source: "settings",
                pendingConsent: false,
                settingsPath: join(globalCredsDir, "settings.json"),
                updatedAt: new Date().toISOString(),
            })
        );

        // Unapproved credentials in projectDir/.memwal/credentials.json
        const projectCredsDir = join(projectDir, ".memwal");
        mkdirSync(projectCredsDir, { recursive: true });
        const projectKeypair = await generateKeypair();
        const projectAccountId = "0x" + "b".repeat(64);
        writeFileSync(
            join(projectCredsDir, "credentials.json"),
            JSON.stringify({
                delegatePrivateKey: projectKeypair.privateKeyHex,
                delegatePublicKeyHex: projectKeypair.publicKeyHex,
                delegateAddress: projectKeypair.suiAddress,
                walletAddress: "0x" + "3".repeat(64),
                accountId: projectAccountId,
                packageId: "0x" + "4".repeat(64),
                relayerUrl: mock.url,
                createdAt: new Date().toISOString(),
                version: 1,
            })
        );

        const transcriptPath = join(projectDir, "transcript.jsonl");
        writeFileSync(
            transcriptPath,
            JSON.stringify({
                role: "user",
                content: "Crucial fact: This project has unapproved credentials, so fallback to global must be used.",
            }) + "\n"
        );

        const env = { ...process.env };
        delete env.MEMWAL_CREDS_DIR;
        env.HOME = tempDir;
        env.USERPROFILE = tempDir;
        env.TMPDIR = tempDir;
        env.MEMWAL_SERVER_URL = mock.url;

        const result = spawnSync(process.execPath, [HOOK_SCRIPT], {
            input: JSON.stringify({
                session_id: "test-unapproved-fallback",
                transcript_path: transcriptPath,
                cwd: projectDir,
            }),
            encoding: "utf8",
            env,
        });

        assert.equal(result.status, 0, result.stderr);
        await waitForRequests(mock, 1);
        assert.equal(mock.requests.length, 1);
        assert.equal(
            mock.requests[0].headers["x-account-id"],
            globalAccountId,
            "Request must use global account id, never unapproved project account id"
        );
    } finally {
        await mock.close();
        rmSync(tempDir, { recursive: true, force: true });
    }
});

test("relayer HTTP 500 degrades gracefully and does not advance watermark so compaction retries", async () => {
    const tempDir = freshTempDir();
    // First call returns 500, second call returns 200
    const mock = await startWorkerMockRelayer({ statusCodes: [500, 200] });

    try {
        writeSettings(tempDir, { autoSave: true });
        await writeTestCreds(tempDir, { relayerUrl: mock.url });

        const transcriptPath = join(tempDir, "retry.jsonl");
        writeFileSync(
            transcriptPath,
            JSON.stringify({
                role: "user",
                content: "Crucial fact: This fact must retry on next compaction if the relayer is temporarily 500.",
            }) + "\n"
        );

        // First run -> HTTP 500
        const res1 = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-session-retry",
                transcript_path: transcriptPath,
            }
        );

        assert.equal(res1.status, 0, "Hook must still exit 0 on server 500 error");
        assert.equal(res1.stdout, "");
        await waitForRequests(mock, 1);
        assert.equal(mock.requests.length, 1);

        // Second run -> should RETRY the same lines because watermark was NOT advanced!
        const res2 = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-session-retry",
                transcript_path: transcriptPath,
            }
        );

        assert.equal(res2.status, 0);
        assert.equal(res2.stdout, "");
        await waitForRequests(mock, 2);
        assert.equal(mock.requests.length, 2, "Second run must retry the call since watermark did not advance");

        // Third run -> watermark advanced on 200, so 0 calls
        const res3 = runPreCompactHook(
            {
                MEMWAL_CREDS_DIR: tempDir,
                MEMWAL_SERVER_URL: mock.url,
                TMPDIR: tempDir,
            },
            {
                session_id: "test-session-retry",
                transcript_path: transcriptPath,
            }
        );
        assert.equal(res3.status, 0);
        await waitForRequests(mock, 2, 100);
        assert.equal(mock.requests.length, 2, "Third run makes no call because second call succeeded and advanced watermark");
    } finally {
        await mock.close();
        rmSync(tempDir, { recursive: true, force: true });
    }
});

test("redactSecrets redacts labelled private keys, delegate keys, and mnemonic seed phrases", () => {
    const rawKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    const sample1 = `Please remember that my delegate private key is ${rawKey} for future sessions.`;
    const redacted1 = redactSecrets(sample1);
    assert.doesNotMatch(redacted1, new RegExp(rawKey));
    assert.match(redacted1, /\[redacted:private-key\]/);

    const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const sample2 = `Account recovery seed phrase is ${mnemonic} please do not share.`;
    const redacted2 = redactSecrets(sample2);
    assert.doesNotMatch(redacted2, new RegExp(mnemonic));
    assert.match(redacted2, /\[redacted:seed-phrase\]/);

    const benign = "This project uses Sui TypeScript SDK version 1.2.0 with PostgreSQL storage.";
    assert.equal(redactSecrets(benign), benign);
});

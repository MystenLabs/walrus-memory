import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
    clampMaxItems,
    createSignedRelayerClient,
    discoverImportFiles,
    extractCandidateChunks,
    helpText,
    importProjectMemories,
    makeSnippet,
    parseArgs,
    screenContentForSafety,
} from "../dist/index.js";

test("parseArgs parses import subcommand and options", () => {
    const defaultImport = parseArgs(["import"]);
    assert.equal(defaultImport.importCmd, true);
    assert.equal(defaultImport.importPath, undefined);
    assert.equal(defaultImport.dryRun, undefined);
    assert.equal(defaultImport.yes, undefined);
    assert.deepEqual(defaultImport.unknown, []);

    const pathImport = parseArgs(["import", "./custom/project", "--yes"]);
    assert.equal(pathImport.importCmd, true);
    assert.equal(pathImport.importPath, "./custom/project");
    assert.equal(pathImport.yes, true);
    assert.deepEqual(pathImport.unknown, []);

    const dryRunImport = parseArgs(["import", "--dry-run", "--max-items", "35"]);
    assert.equal(dryRunImport.importCmd, true);
    assert.equal(dryRunImport.dryRun, true);
    assert.equal(dryRunImport.maxItems, 35);
    assert.deepEqual(dryRunImport.unknown, []);

    const shortYesImport = parseArgs(["import", "-y", "--max-items=50"]);
    assert.equal(shortYesImport.importCmd, true);
    assert.equal(shortYesImport.yes, true);
    assert.equal(shortYesImport.maxItems, 50);
    assert.deepEqual(shortYesImport.unknown, []);
});

test("an unknown flag does not swallow the import command", () => {
    const args = parseArgs(["--typo", "import"]);
    assert.deepEqual(args.unknown, ["--typo"]);
    assert.equal(args.importCmd, true);
});

test("--help documents the import command and options", () => {
    const help = helpText();
    assert.ok(help.includes("memwal-mcp import"), "import command missing from help");
    assert.ok(help.includes("--dry-run"), "--dry-run option missing from help");
    assert.ok(help.includes("--yes"), "--yes option missing from help");
    assert.ok(help.includes("--max-items"), "--max-items option missing from help");
});

test("clampMaxItems clamps numbers between 1 and 100", () => {
    assert.equal(clampMaxItems(undefined), 20);
    assert.equal(clampMaxItems(Number.NaN), 20);
    assert.equal(clampMaxItems(0), 1);
    assert.equal(clampMaxItems(-10), 1);
    assert.equal(clampMaxItems(150), 100);
    assert.equal(clampMaxItems(45.8), 45);
});

test("makeSnippet flattens whitespace and limits length", () => {
    const text = "Line 1\n  Line 2\twith   multiple   spaces";
    const snippet = makeSnippet(text, 30);
    assert.equal(snippet.length <= 30, true);
    assert.ok(!snippet.includes("\n"));
});

test("allowlist discovery finds allowed files and ignores unallowed files", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-import-test-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    // Create allowlisted files
    writeFileSync(join(dir, "AGENTS.md"), "# Agents\nInstructions for agents.");
    writeFileSync(join(dir, "CLAUDE.md"), "# Claude\nInstructions for Claude.");
    mkdirSync(join(dir, ".github"), { recursive: true });
    writeFileSync(join(dir, ".github", "copilot-instructions.md"), "# Copilot\nCopilot instructions.");

    // Create unallowed files
    writeFileSync(join(dir, ".env"), "SECRET=hunter2");
    writeFileSync(join(dir, ".env.local"), "SECRET=local");
    writeFileSync(join(dir, "secrets.json"), "{\"token\": \"xyz\"}");
    writeFileSync(join(dir, "README.md"), "# Readme");

    const { realRoot, files } = discoverImportFiles(dir);
    assert.equal(typeof realRoot, "string");
    assert.ok(files.includes("AGENTS.md"));
    assert.ok(files.includes("CLAUDE.md"));
    assert.ok(files.includes(".github/copilot-instructions.md"));
    assert.equal(files.includes(".env"), false);
    assert.equal(files.includes(".env.local"), false);
    assert.equal(files.includes("secrets.json"), false);
    assert.equal(files.includes("README.md"), false);
});

test("symlink escape rejection refuses symlinks pointing outside project root", (t) => {
    const projectDir = mkdtempSync(join(tmpdir(), "memwal-project-"));
    const outsideDir = mkdtempSync(join(tmpdir(), "memwal-outside-"));
    t.after(() => {
        rmSync(projectDir, { recursive: true, force: true });
        rmSync(outsideDir, { recursive: true, force: true });
    });

    const outsideTarget = join(outsideDir, "secret-rules.md");
    writeFileSync(outsideTarget, "# Secret\nOutside secret rules.");

    // Create escaping symlink
    symlinkSync(outsideTarget, join(projectDir, "CLAUDE.md"));

    // Create legitimate internal file and internal symlink
    const internalTarget = join(projectDir, "internal-agents.md");
    writeFileSync(internalTarget, "# Internal\nInternal agent instructions.");
    symlinkSync(internalTarget, join(projectDir, "AGENTS.md"));

    const { files } = discoverImportFiles(projectDir);
    assert.equal(files.includes("CLAUDE.md"), false, "Escaping symlink must be refused");
    assert.equal(files.includes("AGENTS.md"), true, "Internal symlink within root must be allowed");
});

test("secret screening identifies private keys, tokens, and env assignments", () => {
    assert.equal(screenContentForSafety("Clean text without any secrets.").safe, true);

    const suiKey = screenContentForSafety("My key is suiprivkey1abcdef0123456789abcdef0123456789.");
    assert.equal(suiKey.safe, false);
    assert.equal(suiKey.reason, "secret_detected");

    const pemKey = screenContentForSafety("-----BEGIN EC PRIVATE KEY-----\nMIGqAgEAAwIBAQ==\n-----END EC PRIVATE KEY-----");
    assert.equal(pemKey.safe, false);
    assert.equal(pemKey.reason, "secret_detected");

    const openAiKey = screenContentForSafety("Authorization: Bearer sk-abcdef1234567890abcdef1234567890");
    assert.equal(openAiKey.safe, false);
    assert.equal(openAiKey.reason, "secret_detected");

    const githubPat = screenContentForSafety("Token ghp_123456789012345678901234567890123456");
    assert.equal(githubPat.safe, false);
    assert.equal(githubPat.reason, "secret_detected");

    const envAssignment = screenContentForSafety("Set API_KEY=mysupersecretvalue123 in your environment.");
    assert.equal(envAssignment.safe, false);
    assert.equal(envAssignment.reason, "secret_detected");
});

test("opt-out markers are detected and recorded with opt_out_marker reason", () => {
    const noMem = screenContentForSafety("Scratchpad notes [no-memory] not to remember.");
    assert.equal(noMem.safe, false);
    assert.equal(noMem.reason, "opt_out_marker");

    const ignoreTag = screenContentForSafety("MEMWAL_IGNORE this block of text.");
    assert.equal(ignoreTag.safe, false);
    assert.equal(ignoreTag.reason, "opt_out_marker");

    const privateTag = screenContentForSafety("Some text <private>private data</private> more text");
    assert.equal(privateTag.safe, false);
    assert.equal(privateTag.reason, "opt_out_marker");
});

test("extractCandidateChunks chunks markdown by headings and skips secrets", () => {
    const content = [
        "# Overview",
        "This is an architectural overview of the system with sufficient length.",
        "",
        "## Coding Standards",
        "Always write comprehensive unit tests for every new feature added.",
        "",
        "## Secret Notes",
        "Here is a private key: suiprivkey1abcdef0123456789abcdef.",
        "",
        "## Temporary Thoughts",
        "[no-memory] These are temporary thoughts not to be persisted.",
        "",
        "## Short",
        "Short.",
    ].join("\n");

    const { candidates, skipped } = extractCandidateChunks(content, "AGENTS.md");

    assert.equal(candidates.length, 2);
    assert.equal(candidates[0].section, "Overview");
    assert.ok(candidates[0].text.startsWith("[source: AGENTS.md | section: Overview]"));
    assert.equal(candidates[1].section, "Coding Standards");
    assert.ok(candidates[1].text.startsWith("[source: AGENTS.md | section: Coding Standards]"));

    assert.equal(skipped.length, 2);
    const secretSkip = skipped.find((s) => s.section === "Secret Notes");
    assert.ok(secretSkip);
    assert.equal(secretSkip.reason, "secret_detected");

    const optOutSkip = skipped.find((s) => s.section === "Temporary Thoughts");
    assert.ok(optOutSkip);
    assert.equal(optOutSkip.reason, "opt_out_marker");
});

test("importProjectMemories runs in preview mode by default without network calls or credentials", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-preview-test-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    writeFileSync(
        join(dir, "AGENTS.md"),
        "# Agent Instructions\nFollow all architectural guidelines when building features.",
    );

    const logged = [];
    const result = await importProjectMemories({
        targetDir: dir,
        yes: false,
        print: (msg) => logged.push(msg),
    });

    assert.equal(result.mode, "preview");
    assert.equal(result.discoveredFiles.length, 1);
    assert.equal(result.candidates.length, 1);
    assert.equal(result.candidates[0].file, "AGENTS.md");
    assert.ok(logged.some((line) => line.includes("Local project memory import preview:")));
    assert.ok(logged.some((line) => line.includes("Run with --yes to upload")));
});

test("importProjectMemories confirmed upload batches items and reports accurate status tallies", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-upload-test-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    writeFileSync(
        join(dir, "CLAUDE.md"),
        [
            "# First Section",
            "This is the first substantive instruction section for tests.",
            "# Second Section",
            "This is the second substantive instruction section for tests.",
            "# Third Section",
            "This is the third substantive instruction section for tests.",
        ].join("\n"),
    );

    const batchesReceived = [];
    const mockClient = {
        async rememberBulk(items) {
            batchesReceived.push(items);
            return {
                job_ids: items.map((_, idx) => `job-${idx + 1}`),
            };
        },
        async waitForRememberJobs(jobIds, namespaces) {
            return {
                results: jobIds.map((id, idx) => {
                    if (idx === 0) return { id, status: "done", namespace: namespaces[idx] };
                    if (idx === 1) return { id, status: "failed", namespace: namespaces[idx], error: "relayer error" };
                    return { id, status: "timeout", namespace: namespaces[idx] };
                }),
                total: jobIds.length,
                succeeded: 1,
                failed: 1,
            };
        },
    };

    const logged = [];
    const result = await importProjectMemories({
        targetDir: dir,
        yes: true,
        dryRun: false,
        client: mockClient,
        namespace: "test-ns",
        print: (msg) => logged.push(msg),
    });

    assert.equal(result.mode, "uploaded");
    assert.equal(result.accepted, 3);
    assert.equal(result.completed, 1);
    assert.equal(result.failed, 1);
    assert.equal(result.pending, 1);
    assert.equal(batchesReceived.length, 1);
    assert.equal(batchesReceived[0].length, 3);
    assert.equal(batchesReceived[0][0].namespace, "test-ns");

    assert.ok(logged.some((line) => line.includes("Accepted:  3")));
    assert.ok(logged.some((line) => line.includes("Completed: 1")));
    assert.ok(logged.some((line) => line.includes("Pending:   1")));
    assert.ok(logged.some((line) => line.includes("Failed:    1")));
});

test("importProjectMemories caps candidates by maxItems", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-cap-test-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const sections = [];
    for (let i = 1; i <= 25; i++) {
        sections.push(`# Section ${i}\nSubstantive content for section number ${i} with more than twenty characters.`);
    }
    writeFileSync(join(dir, "AGENTS.md"), sections.join("\n\n"));

    const result = await importProjectMemories({
        targetDir: dir,
        yes: false,
        maxItems: 5,
        print: () => {},
    });

    assert.equal(result.mode, "preview");
    assert.equal(result.candidates.length, 5);
});

test("importProjectMemories batches uploads exceeding 20 items", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-batch-test-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    const sections = [];
    for (let i = 1; i <= 25; i++) {
        sections.push(`# Section ${i}\nSubstantive content for section number ${i} with more than twenty characters.`);
    }
    writeFileSync(join(dir, "AGENTS.md"), sections.join("\n\n"));

    const batchesReceived = [];
    const mockClient = {
        async rememberBulk(items) {
            batchesReceived.push(items);
            return {
                job_ids: items.map((_, idx) => `batch-${batchesReceived.length}-job-${idx + 1}`),
            };
        },
        async waitForRememberJobs(jobIds, namespaces) {
            return {
                results: jobIds.map((id, idx) => ({ id, status: "done", namespace: namespaces[idx] })),
                total: jobIds.length,
                succeeded: jobIds.length,
                failed: 0,
            };
        },
    };

    const result = await importProjectMemories({
        targetDir: dir,
        yes: true,
        maxItems: 25,
        client: mockClient,
        print: () => {},
    });

    assert.equal(result.mode, "uploaded");
    assert.equal(result.accepted, 25);
    assert.equal(result.completed, 25);
    assert.equal(result.failed, 0);
    assert.equal(result.pending, 0);
    assert.equal(batchesReceived.length, 2);
    assert.equal(batchesReceived[0].length, 20);
    assert.equal(batchesReceived[1].length, 5);
});

test("importProjectMemories confirmed upload throws when credentials are missing", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-missing-creds-test-"));
    const credsDir = mkdtempSync(join(tmpdir(), "memwal-empty-creds-dir-"));
    const prevCredsDir = process.env.MEMWAL_CREDS_DIR;
    const prevKey = process.env.MEMWAL_PRIVATE_KEY;
    const prevAccount = process.env.MEMWAL_ACCOUNT_ID;

    process.env.MEMWAL_CREDS_DIR = credsDir;
    delete process.env.MEMWAL_PRIVATE_KEY;
    delete process.env.MEMWAL_ACCOUNT_ID;

    t.after(() => {
        if (prevCredsDir === undefined) delete process.env.MEMWAL_CREDS_DIR;
        else process.env.MEMWAL_CREDS_DIR = prevCredsDir;
        if (prevKey === undefined) delete process.env.MEMWAL_PRIVATE_KEY;
        else process.env.MEMWAL_PRIVATE_KEY = prevKey;
        if (prevAccount === undefined) delete process.env.MEMWAL_ACCOUNT_ID;
        else process.env.MEMWAL_ACCOUNT_ID = prevAccount;
        rmSync(dir, { recursive: true, force: true });
        rmSync(credsDir, { recursive: true, force: true });
    });

    writeFileSync(
        join(dir, "AGENTS.md"),
        "# Instructions\nSome instructions with more than twenty characters.",
    );

    await assert.rejects(
        () =>
            importProjectMemories({
                targetDir: dir,
                yes: true,
                print: () => {},
            }),
        /Credentials required for upload/,
    );
});

test("extractCandidateChunks screens headings for secrets and opt-out markers", () => {
    const content = [
        "# API_KEY=synthetic-heading-only-secret",
        "Substantive paragraph content that should be skipped because its heading is a secret.",
        "",
        "# [no-memory]",
        "Another substantive paragraph that should be skipped because of the opt-out heading.",
        "",
        "# Safe Heading",
        "This paragraph is safe and should be kept as a candidate memory chunk.",
    ].join("\n");

    const { candidates, skipped } = extractCandidateChunks(content, "AGENTS.md");
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].section, "Safe Heading");
    assert.equal(skipped.length, 2);
    assert.equal(skipped[0].reason, "secret_detected");
    assert.equal(skipped[1].reason, "opt_out_marker");
});

test("createSignedRelayerClient reads bulk-status results envelope", async () => {
    const originalFetch = globalThis.fetch;
    try {
        let called = false;
        globalThis.fetch = async (url, _init) => {
            called = true;
            assert.ok(String(url).endsWith("/api/remember/bulk/status"));
            return {
                ok: true,
                status: 200,
                text: async () =>
                    JSON.stringify({
                        results: [{ job_id: "test-job-1", status: "done" }],
                    }),
            };
        };

        const client = createSignedRelayerClient({
            key: "11".repeat(32),
            accountId: "0x" + "22".repeat(32),
            serverUrl: "http://127.0.0.1:9999",
        });

        const outcome = await client.waitForRememberJobs(["test-job-1"], ["default"], {
            timeoutMs: 2000,
            pollIntervalMs: 50,
        });

        assert.equal(called, true);
        assert.equal(outcome.results.length, 1);
        assert.equal(outcome.results[0].id, "test-job-1");
        assert.equal(outcome.results[0].status, "done");
    } finally {
        globalThis.fetch = originalFetch;
    }
});


import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
    clampMaxItems,
    createSignedRelayerClient,
    discoverImportFiles,
    extractCandidateChunks,
    hasOptOutMarker,
    helpText,
    importProjectMemories,
    main,
    makeSnippet,
    parseArgs,
    parseSections,
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

    const labelledPrivateKey = screenContentForSafety("private key: 0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");
    assert.equal(labelledPrivateKey.safe, false);
    assert.equal(labelledPrivateKey.reason, "secret_detected");

    const colonDelegateKey = screenContentForSafety("delegate_private_key: 11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");
    assert.equal(colonDelegateKey.safe, false);
    assert.equal(colonDelegateKey.reason, "secret_detected");

    const proseKey = screenContentForSafety("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff is my private key for signing");
    assert.equal(proseKey.safe, false);
    assert.equal(proseKey.reason, "secret_detected");

    const urlWithPassword = screenContentForSafety(
        "Connect to postgres://demo:synthetic-password@db.example.invalid:5432/project for local testing.",
    );
    assert.equal(urlWithPassword.safe, false);
    assert.equal(urlWithPassword.reason, "secret_detected");

    const cookieHeader = screenContentForSafety(
        "Cookie: session=synthetic-session-cookie-value-for-tests; theme=dark",
    );
    assert.equal(cookieHeader.safe, false);
    assert.equal(cookieHeader.reason, "secret_detected");

    const setCookieHeader = screenContentForSafety(
        "Set-Cookie: auth_token=synthetic-cookie-token; HttpOnly; Secure",
    );
    assert.equal(setCookieHeader.safe, false);
    assert.equal(setCookieHeader.reason, "secret_detected");
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

test("importProjectMemories skips URL passwords and session cookies before upload", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-url-cookie-test-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));

    writeFileSync(
        join(dir, "MEMORY.md"),
        [
            "# Safe Rule",
            "Always run unit tests before opening a pull request on this repository.",
            "",
            "# Database URL",
            "Use postgres://demo:synthetic-password@db.example.invalid/project when debugging locally.",
            "",
            "# Session Header",
            "Send Cookie: session=synthetic-session-cookie-value-for-tests when reproducing the issue.",
        ].join("\n"),
    );

    const batchesReceived = [];
    const mockClient = {
        async rememberBulk(items) {
            batchesReceived.push(items);
            return { job_ids: items.map((_, idx) => `job-${idx + 1}`) };
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
        client: mockClient,
        namespace: "test-ns",
        print: () => {},
    });

    assert.equal(result.mode, "uploaded");
    assert.equal(result.accepted, 1);
    assert.equal(result.skipped.length, 2);
    assert.equal(batchesReceived.length, 1);
    assert.equal(batchesReceived[0].length, 1);
    assert.ok(!batchesReceived[0][0].text.includes("synthetic-password"));
    assert.ok(!batchesReceived[0][0].text.includes("synthetic-session-cookie-value-for-tests"));
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

test("parent opt-out heading propagates to child heading and leaves sibling candidate intact", () => {
    const content = [
        "# [no-memory]",
        "## Personal context",
        "This is personal context with substantive paragraph content exceeding twenty characters.",
        "",
        "# Architecture",
        "This is public architecture documentation with substantive paragraph content exceeding twenty characters.",
    ].join("\n");

    const { candidates, skipped } = extractCandidateChunks(content, "CLAUDE.md");
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].section, "Architecture");
    assert.ok(candidates[0].text.includes("This is public architecture documentation"));

    const skippedOptOut = skipped.filter((s) => s.reason === "opt_out_marker");
    assert.equal(skippedOptOut.length, 1);
    assert.equal(skippedOptOut[0].section, "Personal context");
    assert.equal(skippedOptOut[0].reason, "opt_out_marker");
});

test("multi-level nesting opt-out and parent body opt-out marker before child heading", () => {
    // Multi-level nesting: # [no-memory] -> ## Sub 1 -> ### Sub 2 -> # Safe Sibling
    const nestedContent = [
        "# [no-memory]",
        "## Sub 1",
        "### Sub 2",
        "Deeply nested private thoughts with substantive paragraph content exceeding twenty characters.",
        "",
        "# Safe Sibling",
        "Safe sibling documentation with substantive paragraph content exceeding twenty characters.",
    ].join("\n");

    const nestedResult = extractCandidateChunks(nestedContent, "AGENTS.md");
    assert.equal(nestedResult.candidates.length, 1);
    assert.equal(nestedResult.candidates[0].section, "Safe Sibling");
    assert.equal(nestedResult.skipped.length, 1);
    assert.equal(nestedResult.skipped[0].section, "Sub 2");
    assert.equal(nestedResult.skipped[0].reason, "opt_out_marker");

    // Parent body containing [no-memory] / MEMWAL_IGNORE before ## Child
    const bodyOptOutContent = [
        "# Parent with Body Opt-Out",
        "Some initial parent text.",
        "MEMWAL_IGNORE",
        "",
        "## Child Section",
        "Child section text that inherits parent opt-out scope with more than twenty characters.",
        "",
        "# Sibling Section",
        "Sibling section text that is safe and should be imported as a candidate chunk.",
    ].join("\n");

    const bodyResult = extractCandidateChunks(bodyOptOutContent, "AGENTS.md");
    assert.equal(bodyResult.candidates.length, 1);
    assert.equal(bodyResult.candidates[0].section, "Sibling Section");
    const bodySkipped = bodyResult.skipped.filter((s) => s.reason === "opt_out_marker");
    assert.equal(bodySkipped.length, 2);
    assert.ok(bodySkipped.some((s) => s.section === "Parent with Body Opt-Out"));
    assert.ok(bodySkipped.some((s) => s.section === "Child Section"));
});

test("<private> block spanning across subheadings excludes only enclosed sections", () => {
    const content = [
        "<private>",
        "## Subheading A",
        "Subheading A private content with substantive length exceeding twenty characters.",
        "",
        "## Subheading B",
        "Subheading B private content with substantive length exceeding twenty characters.",
        "</private>",
        "",
        "## Public Section",
        "Public section content that is outside the private tag and should be imported.",
    ].join("\n");

    const { candidates, skipped } = extractCandidateChunks(content, "CLAUDE.md");
    assert.equal(candidates.length, 1);
    assert.equal(candidates[0].section, "Public Section");
    assert.ok(candidates[0].text.includes("Public section content"));

    const optOutSkips = skipped.filter((s) => s.reason === "opt_out_marker");
    assert.equal(optOutSkips.length, 2);
    assert.ok(optOutSkips.some((s) => s.section === "Subheading A"));
    assert.ok(optOutSkips.some((s) => s.section === "Subheading B"));
});

test("fenced code block containing bash comment does not split section or drop opt-out scope", () => {
    // 1. Safe section with code block containing # bash comment
    const safeContent = [
        "# Architecture",
        "Here is the setup script for building and deploying the services:",
        "",
        "```bash",
        "# bash comment that must not be parsed as a markdown heading",
        "echo 'starting build pipeline'",
        "```",
        "",
        "Followed by substantive operational notes with more than twenty characters.",
    ].join("\n");

    const safeResult = extractCandidateChunks(safeContent, "CLAUDE.md");
    assert.equal(safeResult.candidates.length, 1);
    assert.equal(safeResult.candidates[0].section, "Architecture");
    assert.ok(safeResult.candidates[0].text.includes("# bash comment that must not be parsed"));
    assert.equal(safeResult.skipped.length, 0);

    // 2. Opted-out section with code block containing # bash comment does not drop opt-out scope
    const optedOutContent = [
        "# [no-memory]",
        "## Private Automation",
        "```bash",
        "# another bash comment",
        "curl https://example.com/internal",
        "```",
        "Private automation explanation with more than twenty characters.",
    ].join("\n");

    const optResult = extractCandidateChunks(optedOutContent, "CLAUDE.md");
    assert.equal(optResult.candidates.length, 0);
    assert.equal(optResult.skipped.length, 1);
    assert.equal(optResult.skipped[0].section, "Private Automation");
    assert.equal(optResult.skipped[0].reason, "opt_out_marker");
});

test("saved credentials relayerUrl is preserved when CLI has no override, and overridden with --relayer", async (t) => {
    const credsDir = mkdtempSync(join(tmpdir(), "memwal-creds-test-"));
    const projectDir = mkdtempSync(join(tmpdir(), "memwal-proj-test-"));

    const prevCredsDir = process.env.MEMWAL_CREDS_DIR;
    const prevServerUrl = process.env.MEMWAL_SERVER_URL;
    const prevKey = process.env.MEMWAL_PRIVATE_KEY;
    const prevAccount = process.env.MEMWAL_ACCOUNT_ID;

    // Ephemeral servers for saved relayer and override relayer
    const savedRequests = [];
    const savedServer = createServer((req, res) => {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
            savedRequests.push({ method: req.method, url: req.url, body });
            if (req.url === "/api/remember/bulk") {
                res.writeHead(200, { "content-type": "application/json" });
                res.end(JSON.stringify({ job_ids: ["saved-job-1"] }));
            } else if (req.url === "/api/remember/bulk/status") {
                res.writeHead(200, { "content-type": "application/json" });
                res.end(JSON.stringify({ results: [{ id: "saved-job-1", status: "done" }] }));
            } else {
                res.writeHead(404);
                res.end();
            }
        });
    });

    const overrideRequests = [];
    const overrideServer = createServer((req, res) => {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
            overrideRequests.push({ method: req.method, url: req.url, body });
            if (req.url === "/api/remember/bulk") {
                res.writeHead(200, { "content-type": "application/json" });
                res.end(JSON.stringify({ job_ids: ["override-job-1"] }));
            } else if (req.url === "/api/remember/bulk/status") {
                res.writeHead(200, { "content-type": "application/json" });
                res.end(JSON.stringify({ results: [{ id: "override-job-1", status: "done" }] }));
            } else {
                res.writeHead(404);
                res.end();
            }
        });
    });

    await new Promise((r) => savedServer.listen(0, "127.0.0.1", r));
    await new Promise((r) => overrideServer.listen(0, "127.0.0.1", r));

    const savedPort = savedServer.address().port;
    const overridePort = overrideServer.address().port;
    const savedRelayerUrl = `http://127.0.0.1:${savedPort}`;
    const overrideRelayerUrl = `http://127.0.0.1:${overridePort}`;

    t.after(() => {
        savedServer.close();
        overrideServer.close();
        if (prevCredsDir === undefined) delete process.env.MEMWAL_CREDS_DIR;
        else process.env.MEMWAL_CREDS_DIR = prevCredsDir;
        if (prevServerUrl === undefined) delete process.env.MEMWAL_SERVER_URL;
        else process.env.MEMWAL_SERVER_URL = prevServerUrl;
        if (prevKey === undefined) delete process.env.MEMWAL_PRIVATE_KEY;
        else process.env.MEMWAL_PRIVATE_KEY = prevKey;
        if (prevAccount === undefined) delete process.env.MEMWAL_ACCOUNT_ID;
        else process.env.MEMWAL_ACCOUNT_ID = prevAccount;
        rmSync(credsDir, { recursive: true, force: true });
        rmSync(projectDir, { recursive: true, force: true });
    });

    // Write saved credentials pointing to savedRelayerUrl
    writeFileSync(
        join(credsDir, "credentials.json"),
        JSON.stringify({
            delegatePrivateKey: "11".repeat(32),
            delegatePublicKeyHex: "22".repeat(32),
            delegateAddress: "0x" + "22".repeat(32),
            walletAddress: "0x" + "33".repeat(32),
            accountId: "0x" + "44".repeat(32),
            packageId: "0x" + "55".repeat(32),
            relayerUrl: savedRelayerUrl,
            createdAt: new Date().toISOString(),
            version: 1,
        }),
    );

    // Create an allowlisted file in projectDir
    writeFileSync(
        join(projectDir, "AGENTS.md"),
        "# Project Instructions\nThis is substantive project documentation for relayer tests with more than twenty characters.",
    );

    process.env.MEMWAL_CREDS_DIR = credsDir;
    delete process.env.MEMWAL_SERVER_URL;
    delete process.env.MEMWAL_PRIVATE_KEY;
    delete process.env.MEMWAL_ACCOUNT_ID;

    // Run import without --relayer flag: must send bulk request to savedRelayerUrl
    await main(["import", projectDir, "--yes"]);
    assert.ok(savedRequests.length >= 1, "Requests must reach saved relayer URL");
    assert.equal(savedRequests[0].url, "/api/remember/bulk");
    assert.equal(overrideRequests.length, 0, "Override server must not receive requests yet");

    // Run import with explicit --relayer override flag: must send bulk request to overrideRelayerUrl
    await main(["import", projectDir, "--yes", "--relayer", overrideRelayerUrl]);
    assert.ok(overrideRequests.length >= 1, "Requests must reach explicit override relayer URL");
    assert.equal(overrideRequests[0].url, "/api/remember/bulk");
});

test("screens heading-labelled private keys across Markdown line breaks and conversational body opt-outs across child headings before built-in signed client upload", async (t) => {
    const projectDir = mkdtempSync(join(tmpdir(), "memwal-proj-multiline-test-"));

    const capturedPayloads = [];
    const server = createServer((req, res) => {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => {
            if (req.url === "/api/remember/bulk") {
                capturedPayloads.push(JSON.parse(body));
                res.writeHead(200, { "content-type": "application/json" });
                res.end(JSON.stringify({ job_ids: ["job-safe-1"] }));
            } else if (req.url === "/api/remember/bulk/status") {
                res.writeHead(200, { "content-type": "application/json" });
                res.end(JSON.stringify({ results: [{ job_id: "job-safe-1", status: "done" }] }));
            } else {
                res.writeHead(404);
                res.end();
            }
        });
    });

    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const port = server.address().port;
    const relayerUrl = `http://127.0.0.1:${port}`;

    t.after(() => {
        server.close();
        rmSync(projectDir, { recursive: true, force: true });
    });

    const syntheticHexKey = "a".repeat(64);
    const syntheticSeed = "abandon ability able about above absent absorb abstract absurd abuse access accident";

    writeFileSync(
        join(projectDir, "MEMORY.md"),
        [
            "# Delegate private key",
            syntheticHexKey,
            "",
            "# Seed phrase",
            syntheticSeed,
            "",
            "# Personal notes",
            "Do not store this.",
            "",
            "## Medical detail",
            "Sensitive medical history paragraph that must remain excluded under parent opt-out scope.",
            "",
            "### Prescription schedule",
            "Nested level three detail that must also remain excluded under parent opt-out scope.",
            "",
            "# Off the record section",
            "This note is off the record for the team.",
            "",
            "## Internal compensation notes",
            "Private compensation details that must remain excluded under off-the-record parent scope.",
            "",
            "# Build conventions",
            "Pin deterministic workspace builds and verify all unit tests before opening a pull request.",
        ].join("\n"),
    );

    const directScreen = screenContentForSafety(`# Delegate private key\n${syntheticHexKey}`);
    assert.equal(directScreen.safe, false);
    assert.equal(directScreen.reason, "secret_detected");

    const result = await importProjectMemories({
        targetDir: projectDir,
        yes: true,
        namespace: "ns-multiline-guard",
        relayerUrl,
        key: "11".repeat(32),
        accountId: "0x" + "22".repeat(32),
        print: () => {},
    });

    assert.equal(result.mode, "uploaded");
    assert.equal(result.candidates.length, 1);
    assert.equal(result.candidates[0].section, "Build conventions");
    assert.equal(result.completed, 1);

    assert.equal(capturedPayloads.length, 1);
    const uploadedItems = capturedPayloads[0].items;
    assert.equal(uploadedItems.length, 1);
    const outgoingText = JSON.stringify(uploadedItems);
    assert.ok(!outgoingText.includes(syntheticHexKey), "Heading-labelled hex key must never reach outgoing upload");
    assert.ok(!outgoingText.includes("abandon ability"), "Heading-labelled seed phrase must never reach outgoing upload");
    assert.ok(!outgoingText.includes("Medical detail"), "Child section under Do not store this must never reach outgoing upload");
    assert.ok(!outgoingText.includes("Prescription schedule"), "Grandchild section under Do not store this must never reach outgoing upload");
    assert.ok(!outgoingText.includes("Internal compensation"), "Child section under off the record must never reach outgoing upload");
    assert.ok(outgoingText.includes("Build conventions"), "Sibling safe section after opted-out parent must still upload");
});



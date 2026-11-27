import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "../../..");
const skillFilePath = join(repoRoot, "skills/walrus-memory/SKILL.md");

test("public walrus-memory SKILL.md exists at repository root", () => {
    assert.equal(
        existsSync(skillFilePath),
        true,
        `Expected skills/walrus-memory/SKILL.md to exist at ${skillFilePath}`
    );
});

test("public walrus-memory SKILL.md contains valid YAML frontmatter", () => {
    const content = readFileSync(skillFilePath, "utf8");
    assert.match(
        content,
        /^---\r?\nname:\s*walrus-memory\r?\ndescription:\s*.+\r?\n---/,
        "SKILL.md must start with YAML frontmatter containing name and description"
    );

    const description =
        "Persist and recall encrypted long-term agent memories across sessions using Walrus Memory (@mysten-incubation/memwal-mcp).";
    assert.ok(
        content.includes(description),
        "SKILL.md description frontmatter must describe Walrus Memory"
    );
});

test("public walrus-memory SKILL.md documents all core MCP tools", () => {
    const content = readFileSync(skillFilePath, "utf8");
    const requiredTools = [
        "memwal_recall",
        "memwal_remember",
        "memwal_remember_bulk",
        "memwal_analyze",
        "memwal_restore",
    ];

    for (const tool of requiredTools) {
        assert.ok(
            content.includes(`\`${tool}\``),
            `SKILL.md must document tool ${tool}`
        );
    }
});

test("public walrus-memory SKILL.md documents required setup and workflows", () => {
    const content = readFileSync(skillFilePath, "utf8");

    assert.ok(
        content.includes("npx -y @mysten-incubation/memwal-mcp login"),
        "SKILL.md must document login command"
    );
    assert.ok(
        content.includes("npx -y @mysten-incubation/memwal-mcp auto-save on"),
        "SKILL.md must document auto-save on command"
    );
    assert.ok(
        content.includes("npx -y @mysten-incubation/memwal-mcp auto-save off"),
        "SKILL.md must document auto-save off command"
    );
    assert.ok(
        content.includes("<private>...</private>"),
        "SKILL.md must document private tag exclusion"
    );
    assert.ok(
        content.includes("[no-memory]"),
        "SKILL.md must document no-memory exclusion"
    );
});

test("public walrus-memory SKILL.md adheres to zero-dashes prose rules", () => {
    const raw = readFileSync(skillFilePath, "utf8");
    const lines = raw.split(/\r?\n/);

    let inFrontmatter = false;
    let frontmatterDone = false;
    let inCodeFence = false;

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNum = i + 1;

        if (i === 0 && line.trim() === "---") {
            inFrontmatter = true;
            continue;
        }

        if (inFrontmatter) {
            if (line.trim() === "---") {
                inFrontmatter = false;
                frontmatterDone = true;
            }
            continue;
        }

        if (line.trim().startsWith("```")) {
            inCodeFence = !inCodeFence;
            continue;
        }

        if (inCodeFence) {
            continue;
        }

        // Outside code fences and frontmatter
        assert.doesNotMatch(
            line,
            /\u2014/,
            `Line ${lineNum} contains an em-dash (\\u2014)`
        );
        assert.doesNotMatch(
            line,
            /\u2013/,
            `Line ${lineNum} contains an en-dash (\\u2013)`
        );
        assert.doesNotMatch(
            line,
            /\u2015/,
            `Line ${lineNum} contains a horizontal bar (\\u2015)`
        );

        if (line.trim() === "---") {
            assert.fail(
                `Line ${lineNum} contains a Markdown horizontal rule (---)`
            );
        }

        // Allow table row separators like | :--- | :--- |
        const isTableSeparator = /^\s*\|(?:\s*:?-{2,}:?\s*\|)+\s*$/.test(line);
        if (!isTableSeparator) {
            assert.doesNotMatch(
                line,
                /\s-\s/,
                `Line ${lineNum} contains a spaced hyphen separator (" - ")`
            );
            assert.doesNotMatch(
                line,
                /^\s*-\s+/,
                `Line ${lineNum} contains an unordered dash bullet ("- ")`
            );
        }
    }

    assert.equal(frontmatterDone, true, "YAML frontmatter must be closed");
});

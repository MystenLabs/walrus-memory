/**
 * The canonical consent instruction must stay byte-equal in every
 * user-pasteable copy. One failure if any copy drifts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CONSENT_INSTRUCTION } from "../dist/consent-instruction.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function read(rel) {
    return readFileSync(resolve(root, rel), "utf8");
}

function extractTsConsent(src, label) {
    const match = src.match(/CONSENT_INSTRUCTION = `([\s\S]*?)`/);
    assert.ok(match, `${label}: missing CONSENT_INSTRUCTION template literal`);
    return match[1];
}

function dedent(text) {
    const lines = text.split("\n");
    const indents = lines.filter((line) => line.trim().length > 0).map((line) => {
        const m = line.match(/^ */);
        return m ? m[0].length : 0;
    });
    const n = indents.length > 0 ? Math.min(...indents) : 0;
    return lines.map((line) => line.slice(n)).join("\n");
}

function extractFencedConsent(src, label) {
    const re = /```text\n([\s\S]*?)```/g;
    let match;
    while ((match = re.exec(src))) {
        const body = dedent(match[1]).replace(/\n$/, "");
        if (body.startsWith("Save durable facts to the user's Walrus Memory proactively")) {
            return body;
        }
    }
    assert.fail(`${label}: no fenced consent instruction block`);
}

const copies = [
    ["services/server/scripts/mcp/consent-instruction.ts", (s, l) => extractTsConsent(s, l)],
    ["apps/app/src/pages/ConnectMcp.tsx", (s, l) => extractTsConsent(s, l)],
    ["apps/app/public/skills/setup", extractFencedConsent],
    ["docs/guides/system-prompt-templates.md", extractFencedConsent],
    ["docs/mcp/claude-desktop.md", extractFencedConsent],
    ["docs/mcp/claude-connector.md", extractFencedConsent],
];

test("CONSENT_INSTRUCTION is byte-equal in every user-pasteable copy", () => {
    for (const [rel, extract] of copies) {
        const got = extract(read(rel), rel);
        assert.equal(
            got,
            CONSENT_INSTRUCTION,
            `${rel} drifted from packages/mcp/src/consent-instruction.ts`,
        );
    }
});

/**
 * The secret-exclusion rules have to reach the model through whichever channel
 * a given client actually reads, and they have to say the same thing on all of
 * them (WALM-642).
 *
 * Three channels, three packages, no workspace link between them:
 *   - `instructions` on initialize — the only one that survives lazy tool
 *     loading, and the one Claude Desktop / Codex rely on;
 *   - tool descriptions — what a client shows once tools ARE loaded;
 *   - the plugin's lifecycle hooks — the Claude Code / Codex install path,
 *     which never loads this package's `dist/` at all.
 *
 * So the text is duplicated by necessity. These tests are what stops the
 * duplicates drifting: the block is extracted from each file on disk and the
 * bytes compared. Edit one copy and this fails until the others match.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
    SECRET_EXCLUSION_RULES,
    SECRET_EXCLUSION_SUMMARY,
    AUTO_SAVE_OPT_IN_RULE,
    MEMORY_POLICY_VERSION,
    PRE_COMPACT_PROMPT,
} from "../dist/memory-policy.js";
import * as hookPolicy from "../plugin/scripts/lib/memory-policy.mjs";
import {
    buildProactiveInstructions,
    PROACTIVE_INSTRUCTIONS,
} from "../dist/instructions.js";
import { TOOL_DEFINITIONS } from "../dist/auth-required.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const COPIES = {
    "packages/mcp/src/memory-policy.ts": resolve(__dirname, "../src/memory-policy.ts"),
    "packages/mcp/plugin/scripts/lib/memory-policy.mjs": resolve(
        __dirname,
        "../plugin/scripts/lib/memory-policy.mjs",
    ),
    // Lives in the standalone `memwal-server-scripts` package. Present in the
    // monorepo, absent from an npm-only checkout of this package — hence the
    // existence guard rather than a hard path assumption.
    "services/server/scripts/mcp/tools/memory-policy.ts": resolve(
        __dirname,
        "../../../services/server/scripts/mcp/tools/memory-policy.ts",
    ),
};

const START = "// ─── memwal:policy-block:start";
const END = "// ─── memwal:policy-block:end";

/** The shared region of one copy, markers included, as raw source bytes. */
function policyBlock(path) {
    const src = readFileSync(path, "utf8");
    const start = src.indexOf(START);
    const end = src.indexOf(END);
    assert.notEqual(start, -1, `${path} has no policy-block start marker`);
    assert.notEqual(end, -1, `${path} has no policy-block end marker`);
    const endOfLine = src.indexOf("\n", end);
    return src.slice(start, endOfLine === -1 ? undefined : endOfLine);
}

test("every copy of the policy block is byte-identical", () => {
    const present = Object.entries(COPIES).filter(([, path]) => existsSync(path));
    assert.ok(
        present.length >= 2,
        "at least the two in-package copies must exist for this test to mean anything",
    );

    const [firstName, firstPath] = present[0];
    const reference = policyBlock(firstPath);
    for (const [name, path] of present.slice(1)) {
        assert.equal(
            policyBlock(path),
            reference,
            `${name} has drifted from ${firstName} — copy the block across verbatim, markers included`,
        );
    }
});

test("the relayer sidecar's copy is present in the monorepo", () => {
    // Guarded above so an npm-only checkout still passes; asserted here so the
    // monorepo cannot quietly lose the third copy and leave the comparison
    // running over two files that happen to agree.
    const path = COPIES["services/server/scripts/mcp/tools/memory-policy.ts"];
    if (!existsSync(resolve(__dirname, "../../../services"))) return;
    assert.ok(existsSync(path), "the sidecar copy of the policy block is missing");
});

test("the compiled client copy and the hook copy agree at runtime", () => {
    // The byte comparison above covers the source. This covers what each side
    // actually evaluates to, so a stray escape or join separator is caught too.
    assert.equal(hookPolicy.SECRET_EXCLUSION_RULES, SECRET_EXCLUSION_RULES);
    assert.equal(hookPolicy.SECRET_EXCLUSION_SUMMARY, SECRET_EXCLUSION_SUMMARY);
    assert.equal(hookPolicy.AUTO_SAVE_OPT_IN_RULE, AUTO_SAVE_OPT_IN_RULE);
    assert.equal(hookPolicy.MEMORY_POLICY_VERSION, MEMORY_POLICY_VERSION);
    assert.equal(hookPolicy.PRE_COMPACT_PROMPT, PRE_COMPACT_PROMPT);
    assert.ok(PRE_COMPACT_PROMPT.includes(SECRET_EXCLUSION_RULES));
});

test("the rules name every credential class the ticket lists", () => {
    for (const term of [
        /passwords/i,
        /API keys/i,
        /tokens/i,
        /private keys/i,
        /seed or recovery phrases/i,
        /authorization\s*\n?\s*headers/i,
        /session cookies/i,
        /user:password/i,
    ]) {
        assert.match(SECRET_EXCLUSION_RULES, term);
    }
    // The two non-credential rules the ticket asks for by name.
    assert.match(SECRET_EXCLUSION_RULES, /do not save it/i);
    assert.match(SECRET_EXCLUSION_RULES, /third-party material/i);
    // And the instruction that makes a mixed message salvageable rather than
    // dropped — the difference between "save the preference" and "save nothing".
    assert.match(SECRET_EXCLUSION_RULES, /save the preference alone/i);
});

test("both instruction variants carry the rules verbatim", () => {
    const automatic = buildProactiveInstructions({ autoSave: true });
    const manual = buildProactiveInstructions({ autoSave: false });
    assert.ok(automatic.includes(SECRET_EXCLUSION_RULES));
    assert.ok(manual.includes(SECRET_EXCLUSION_RULES));
    assert.equal(PROACTIVE_INSTRUCTIONS, automatic);
});

test("the instruction variants differ on unprompted saving and nothing else", () => {
    const automatic = buildProactiveInstructions({ autoSave: true });
    const manual = buildProactiveInstructions({ autoSave: false });

    assert.match(automatic, /automatic memory ON/i);
    assert.match(automatic, /Do not ask whether to save it/i);

    assert.match(manual, /automatic memory is OFF/i);
    assert.match(manual, /do NOT save anything they did not ask/i);
    assert.doesNotMatch(manual, /Do not ask whether to save it/i);

    // Recall is not gated — it reads, it does not write.
    for (const text of [automatic, manual]) {
        assert.match(text, /RECALL: before answering/);
        assert.match(text, /memwal_restore/);
        assert.match(text, /never substitute your own memory/);
    }
});

test("the cold-start write tools state the rules too", () => {
    // A client that lazily loads schemas sees these and not `instructions`;
    // a client that eagerly lists sees both. Either way the rules are there.
    for (const name of ["memwal_remember", "memwal_remember_bulk", "memwal_analyze"]) {
        const tool = TOOL_DEFINITIONS.find((t) => t.name === name);
        assert.ok(tool, `missing ${name}`);
        assert.ok(
            tool.description.includes(SECRET_EXCLUSION_RULES),
            `${name} does not state the shared secret-exclusion rules`,
        );
        assert.ok(
            tool.description.includes(AUTO_SAVE_OPT_IN_RULE),
            `${name} does not state that automatic saving is opt-in`,
        );
    }
});

test("read-only tools are not burdened with write rules", () => {
    const recall = TOOL_DEFINITIONS.find((t) => t.name === "memwal_recall");
    assert.ok(recall);
    assert.ok(!recall.description.includes(SECRET_EXCLUSION_RULES));
});

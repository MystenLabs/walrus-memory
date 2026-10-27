import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT = fileURLToPath(new URL("./build-claude-plugin.mjs", import.meta.url));
const ROOT = fileURLToPath(new URL("..", import.meta.url));

function listing(dir) {
    const found = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) found.push(...listing(full).map((child) => `${entry.name}/${child}`));
        else found.push(entry.name);
    }
    return found.sort();
}

function generate(outDir, cwd = ROOT) {
    const result = spawnSync(process.execPath, [SCRIPT, "--out", outDir], {
        cwd,
        encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    return listing(outDir);
}

function runCheckPluginTree(cwd, pin = "0.0.16") {
    const packument = { versions: { [pin]: {} }, "dist-tags": { latest: pin } };
    const entry = pathToFileURL(path.join(cwd, ".github/scripts/check-plugin-tree.mjs")).href;
    const code =
        `globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => (${JSON.stringify(packument)}) }); ` +
        `await import(${JSON.stringify(entry)});`;
    return spawnSync(process.execPath, ["--input-type=module", "-e", code], {
        cwd,
        encoding: "utf8",
    });
}

test("the generated plugin tree is deterministic, complete, free of placeholders, and passes its own CI checks", async () => {
    const repoCheck = spawnSync(process.execPath, [SCRIPT, "--check"], {
        cwd: ROOT,
        encoding: "utf8",
    });
    assert.equal(repoCheck.status, 0, repoCheck.stderr);

    for (const relative of listing(path.join(ROOT, "packages/mcp/plugin"))) {
        const text = readFileSync(path.join(ROOT, "packages/mcp/plugin", relative), "utf8");
        assert.doesNotMatch(
            text,
            /__MEMWAL_[A-Z_]+__/,
            `committed packages/mcp/plugin/${relative} still carries a generator placeholder`,
        );
    }

    const workspace = mkdtempSync(path.join(tmpdir(), "memwal-plugin-"));
    try {
        const first = path.join(workspace, "first");
        const second = path.join(workspace, "second");
        const paths = generate(first);
        assert.deepEqual(generate(second), paths);

        for (const target of paths) {
            assert.deepEqual(
                readFileSync(path.join(first, target)),
                readFileSync(path.join(second, target)),
                `${target} is not reproducible`,
            );
        }

        for (const target of [
            ".claude-plugin/plugin.json",
            ".codex-mcp.json",
            ".cursor-mcp.json",
            ".github/scripts/check-plugin-tree.mjs",
            ".github/workflows/ci.yml",
            ".mcp.json",
            "LICENSE",
            "README.md",
            "commands/analyze.md",
            "commands/remember.md",
            "hooks/hooks.json",
            "plugin.json",
            "scripts/install_codex_hooks.mjs",
            "scripts/launch_mcp.mjs",
            "scripts/lib/hook-template.mjs",
            "scripts/lib/mcp-launch.mjs",
            "scripts/lib/memory-policy.mjs",
            "scripts/on_user_prompt.mjs",
            "skills/setup/SETUP.md",
            "skills/setup/SKILL.md",
            "test/signals.test.mjs",
            "test/user-prompt-hook.test.mjs",
        ]) {
            assert.ok(paths.includes(target), `${target} is not in the generated tree`);
        }

        assert.ok(!paths.includes(".github/CODEOWNERS"), "CODEOWNERS belongs to the published repository");

        for (const target of paths) {
            if (target === ".github/scripts/check-plugin-tree.mjs") continue;
            assert.doesNotMatch(
                readFileSync(path.join(first, target), "utf8"),
                /__MEMWAL_[A-Z_]+__/,
                `${target} still carries a generator placeholder`,
            );
        }

        const { AUTO_SAVE_OPT_IN_RULE, SECRET_EXCLUSION_RULES } = await import(
            pathToFileURL(path.join(first, "scripts/lib/memory-policy.mjs")).href
        );

        for (const target of ["README.md", "commands/remember.md", "commands/analyze.md", "skills/setup/SKILL.md"]) {
            const text = readFileSync(path.join(first, target), "utf8");
            assert.ok(
                text.includes(SECRET_EXCLUSION_RULES),
                `${target} does not contain SECRET_EXCLUSION_RULES verbatim`,
            );
        }

        for (const target of ["README.md", "skills/setup/SKILL.md"]) {
            const text = readFileSync(path.join(first, target), "utf8");
            assert.ok(
                text.includes(AUTO_SAVE_OPT_IN_RULE),
                `${target} does not contain AUTO_SAVE_OPT_IN_RULE verbatim`,
            );
        }

        const skillText = readFileSync(path.join(first, "skills/setup/SKILL.md"), "utf8");
        const span = /^<!-- memwal:start -->\r?\n([\s\S]*?)\r?\n<!-- memwal:end -->$/m.exec(skillText)?.[1] ?? "";
        assert.ok(span.includes(AUTO_SAVE_OPT_IN_RULE), "SKILL.md CLAUDE.md span is missing AUTO_SAVE_OPT_IN_RULE");
        assert.ok(span.includes(SECRET_EXCLUSION_RULES), "SKILL.md CLAUDE.md span is missing SECRET_EXCLUSION_RULES");

        const manifest = JSON.parse(readFileSync(path.join(first, "plugin.json"), "utf8"));
        const pin = manifest.mcpPackageVersion ?? manifest.version;
        const treeCheck = runCheckPluginTree(first, pin);
        assert.equal(treeCheck.status, 0, treeCheck.stderr);

        const hookTests = spawnSync(
            process.execPath,
            ["--test", "test/signals.test.mjs", "test/user-prompt-hook.test.mjs"],
            { cwd: first, encoding: "utf8" },
        );
        assert.equal(hookTests.status, 0, hookTests.stderr);

        const check = spawnSync(process.execPath, [SCRIPT, "--check", "--against", first], {
            cwd: ROOT,
            encoding: "utf8",
        });
        assert.equal(check.status, 0, check.stderr);

        // Verify --check --against reports missing, differing, and extra files
        unlinkSync(path.join(second, "commands/analyze.md"));
        writeFileSync(path.join(second, "README.md"), "drifted\n", "utf8");
        writeFileSync(path.join(second, "extra.txt"), "extra\n", "utf8");
        const diffCheck = spawnSync(process.execPath, [SCRIPT, "--check", "--against", second], {
            cwd: ROOT,
            encoding: "utf8",
        });
        assert.notEqual(diffCheck.status, 0);
        assert.match(diffCheck.stderr, /commands\/analyze\.md is missing/);
        assert.match(diffCheck.stderr, /README\.md differs/);
        assert.match(diffCheck.stderr, /extra\.txt is in .* but is not generated/);

        // Verify emitted check-plugin-tree.mjs fails closed on missing files, placeholders, or missing span policy
        const broken = path.join(workspace, "broken");
        cpSync(first, broken, { recursive: true });
        unlinkSync(path.join(broken, ".codex-mcp.json"));
        writeFileSync(
            path.join(broken, "skills/setup/SETUP.md"),
            readFileSync(path.join(broken, "skills/setup/SETUP.md"), "utf8") + "\n__MEMWAL_LEFTOVER__\n",
        );
        writeFileSync(
            path.join(broken, "skills/setup/SKILL.md"),
            skillText.replace(
                /^<!-- memwal:start -->\r?\n[\s\S]*?\r?\n<!-- memwal:end -->$/m,
                "<!-- memwal:start -->\nstripped\n<!-- memwal:end -->",
            ),
        );
        const brokenCheck = runCheckPluginTree(broken, pin);
        assert.notEqual(brokenCheck.status, 0);
        assert.match(brokenCheck.stderr, /Missing \.codex-mcp\.json/);
        assert.match(brokenCheck.stderr, /skills\/setup\/SETUP\.md still carries the generator placeholder/);
        assert.match(brokenCheck.stderr, /span does not carry AUTO_SAVE_OPT_IN_RULE/);
    } finally {
        rmSync(workspace, { recursive: true, force: true });
    }
});

test("committed plugin markdown drift or unresolved placeholders fail --check and are repaired by --sync-in-place", () => {
    const tempRoot = mkdtempSync(path.join(tmpdir(), "memwal-plugin-root-"));
    try {
        for (const rel of ["packages/mcp/plugin", "packages/mcp/plugin-repo", "packages/mcp/test", "LICENSE"]) {
            cpSync(path.join(ROOT, rel), path.join(tempRoot, rel), { recursive: true });
        }

        const rememberPath = path.join(tempRoot, "packages/mcp/plugin/commands/remember.md");
        const originalRemember = readFileSync(rememberPath, "utf8");
        writeFileSync(
            rememberPath,
            originalRemember.replace(/NEVER save a credential[\s\S]*?in your own words\./, "__MEMWAL_SECRET_POLICY__"),
            "utf8",
        );

        const placeholderCheck = spawnSync(process.execPath, [SCRIPT, "--check"], {
            cwd: tempRoot,
            encoding: "utf8",
        });
        assert.notEqual(placeholderCheck.status, 0);
        assert.match(placeholderCheck.stderr, /carries unresolved placeholder __MEMWAL_SECRET_POLICY__/);

        writeFileSync(
            rememberPath,
            originalRemember.replace(/NEVER save a credential[\s\S]*?in your own words\./, "Outdated policy."),
            "utf8",
        );

        const driftCheck = spawnSync(process.execPath, [SCRIPT, "--check"], {
            cwd: tempRoot,
            encoding: "utf8",
        });
        assert.notEqual(driftCheck.status, 0);
        assert.match(driftCheck.stderr, /has drifted/);

        const sync = spawnSync(process.execPath, [SCRIPT, "--sync-in-place", "--check"], {
            cwd: tempRoot,
            encoding: "utf8",
        });
        assert.equal(sync.status, 0, sync.stderr);
        assert.equal(readFileSync(rememberPath, "utf8"), originalRemember);
    } finally {
        rmSync(tempRoot, { recursive: true, force: true });
    }
});

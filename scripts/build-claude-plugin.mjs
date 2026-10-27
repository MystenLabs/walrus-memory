#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const ROOT = process.cwd();
const PLUGIN_DIR = "packages/mcp/plugin";
const OVERLAY_DIR = "packages/mcp/plugin-repo";
const MCP_TEST_DIR = "packages/mcp/test";
const POLICY_MODULE = "packages/mcp/plugin/scripts/lib/memory-policy.mjs";
const PLUGIN_REPO = "https://github.com/MystenLabs/walrus-memory-claude-plugin";
const DEFAULT_OUT = path.join(os.tmpdir(), "memwal-claude-plugin");

const RETIRED_HOSTS = [
    "relayer-staging.memory.walrus.xyz",
    "staging.memory.walrus.xyz",
    "memwal-staging.mystenlabs.com",
];

const COPIED_TESTS = ["signals.test.mjs", "user-prompt-hook.test.mjs"];

const RESERVED = [".github/CODEOWNERS"];

const FORBIDDEN = [
    /(^|\/)node_modules(\/|$)/,
    /(^|\/)dist(\/|$)/,
    /(^|\/)\.DS_Store$/,
    /(^|\/)\.env(\..*)?$/,
    /\.tgz$/,
];

const REQUIRED = [
    ".claude-plugin/plugin.json",
    ".codex-mcp.json",
    ".codex-plugin/plugin.json",
    ".cursor-mcp.json",
    ".cursor-plugin/plugin.json",
    ".github/scripts/check-plugin-tree.mjs",
    ".github/workflows/ci.yml",
    ".gitignore",
    ".mcp.json",
    "LICENSE",
    "README.md",
    "commands/analyze.md",
    "commands/health.md",
    "commands/logout.md",
    "commands/recall.md",
    "commands/remember.md",
    "commands/restore.md",
    "commands/setup.md",
    "docs/usage/claude-code.md",
    "docs/usage/codex.md",
    "docs/usage/hosted-connector.md",
    "docs/usage/other-clients.md",
    "hooks.json",
    "hooks/codex-hooks.json",
    "hooks/cursor-hooks.json",
    "hooks/hooks.json",
    "plugin.json",
    "scripts/install_codex_hooks.mjs",
    "scripts/launch_mcp.mjs",
    "scripts/lib/auto-save.mjs",
    "scripts/lib/codex-config.mjs",
    "scripts/lib/decision-rubric.mjs",
    "scripts/lib/hook-io.mjs",
    "scripts/lib/hook-template.mjs",
    "scripts/lib/mcp-launch.mjs",
    "scripts/lib/memory-policy.mjs",
    "scripts/lib/signals.mjs",
    "scripts/on_post_tool.mjs",
    "scripts/on_session_start.mjs",
    "scripts/on_user_prompt.mjs",
    "skills/setup/SETUP.md",
    "skills/setup/SKILL.md",
    "test/signals.test.mjs",
    "test/user-prompt-hook.test.mjs",
];

const PLACEHOLDER = /__MEMWAL_[A-Z_]+__/g;

function walk(dir, base = dir) {
    const found = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === ".git") continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) found.push(...walk(full, base));
        else if (entry.isFile()) found.push(path.relative(base, full).split(path.sep).join("/"));
    }
    return found.sort();
}

function pinnedVersion(manifest, manifestPath) {
    const version = manifest.mcpPackageVersion ?? manifest.version;
    if (typeof version !== "string" || version.trim() === "") {
        throw new Error(`${manifestPath} has no usable "mcpPackageVersion" or "version"`);
    }
    return version;
}

async function substitutions() {
    const manifestPath = path.join(ROOT, PLUGIN_DIR, "plugin.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

    const policyPath = path.join(ROOT, POLICY_MODULE);
    if (!fs.existsSync(policyPath)) {
        throw new Error(
            `${POLICY_MODULE} is missing. The plugin's commands, skill and README state the ` +
                `secret-exclusion policy verbatim from that module; without it the generated tree ` +
                `would ship automatic-memory instructions with no policy at all.`,
        );
    }
    const policy = await import(pathToFileURL(policyPath).href);

    return new Map([
        ["__MEMWAL_MCP_VERSION__", pinnedVersion(manifest, manifestPath)],
        ["__MEMWAL_PLUGIN_REPO__", PLUGIN_REPO],
        ["__MEMWAL_SECRET_POLICY__", policy.SECRET_EXCLUSION_RULES],
        ["__MEMWAL_AUTO_SAVE_RULE__", policy.AUTO_SAVE_OPT_IN_RULE],
    ]);
}

function replaceSection(text, pattern, replacement, source, description) {
    if (!pattern.test(text)) {
        throw new Error(`${source} is missing expected section: ${description}`);
    }
    return text.replace(pattern, replacement);
}

/**
 * Render canonical policy and version pin text into a plugin markdown file.
 *
 * Explicit-save slash commands (`commands/remember.md`, `commands/analyze.md`)
 * carry `SECRET_EXCLUSION_RULES` only because invoking `/memwal:remember` or
 * `/memwal:analyze` is an explicit request in that turn. `skills/setup/SKILL.md`
 * (including the `~/.claude/CLAUDE.md` paste block that outlives plugin
 * uninstall) and `README.md` carry both `AUTO_SAVE_OPT_IN_RULE` and
 * `SECRET_EXCLUSION_RULES`.
 */
function renderMarkdown(relative, text, values, source) {
    const pin = values.get("__MEMWAL_MCP_VERSION__");
    const secretPolicy = values.get("__MEMWAL_SECRET_POLICY__");
    const autoSaveRule = values.get("__MEMWAL_AUTO_SAVE_RULE__");

    let rendered = text.replace(PLACEHOLDER, (token) => {
        const value = values.get(token);
        if (value === undefined) throw new Error(`${source} uses unknown placeholder ${token}`);
        return value;
    });

    rendered = rendered.replaceAll(
        /@mysten-incubation\/memwal-mcp@[0-9A-Za-z._-]+/g,
        `@mysten-incubation/memwal-mcp@${pin}`,
    );

    if (relative === "commands/remember.md") {
        rendered = replaceSection(
            rendered,
            /(If `\$ARGUMENTS` is empty, ask the user what they want remembered\.\r?\n\r?\n)[\s\S]*?(\r?\n\r?\nMemory to save:)/,
            `$1${secretPolicy}$2`,
            source,
            "remember.md secret-exclusion policy block",
        );
    } else if (relative === "commands/analyze.md") {
        rendered = replaceSection(
            rendered,
            /(Use `memwal_analyze` to extract durable facts from the text below and save them as separate Walrus Memory entries\.\r?\n\r?\n)[\s\S]*?(\r?\n\r?\nText:)/,
            `$1${secretPolicy}$2`,
            source,
            "analyze.md secret-exclusion policy block",
        );
    } else if (relative === "skills/setup/SKILL.md") {
        rendered = replaceSection(
            rendered,
            /(## Automatic Memory\r?\n\r?\n)[\s\S]*?(\r?\n\r?\n## Troubleshooting)/,
            `$1${autoSaveRule}\n\n${secretPolicy}$2`,
            source,
            "SKILL.md ## Automatic Memory section",
        );
        rendered = replaceSection(
            rendered,
            /(^<!-- memwal:start -->\r?\n[\s\S]*?and small talk\.\r?\n\r?\n)[\s\S]*?(\r?\n<!-- memwal:end -->$)/m,
            `$1${autoSaveRule}\n\n${secretPolicy}$2`,
            source,
            "SKILL.md <!-- memwal:start --> ... <!-- memwal:end --> span",
        );
    } else if (relative === "README.md") {
        rendered = replaceSection(
            rendered,
            /(## Automatic memory\r?\n\r?\n)[\s\S]*?(\r?\n\r?\n## What is never saved\r?\n\r?\n)[\s\S]*?(\r?\n\r?\n## Authentication)/,
            `$1${autoSaveRule}$2${secretPolicy}$3`,
            source,
            "README.md ## Automatic memory and ## What is never saved sections",
        );
    }

    const leftover = rendered.match(PLACEHOLDER);
    if (leftover) throw new Error(`${source} still carries ${leftover[0]} after substitution`);
    return rendered;
}

function verifyCommittedMarkdown(relative, rawText, renderedText, values, source) {
    const unresolved = rawText.match(PLACEHOLDER);
    if (unresolved) {
        throw new Error(
            `${source} carries unresolved placeholder ${unresolved[0]}. ` +
                `${PLUGIN_DIR} is installed directly by the marketplace and degit; commit the ` +
                `rendered text via \`node scripts/build-claude-plugin.mjs --sync-in-place\`.`,
        );
    }
    if (rawText !== renderedText) {
        throw new Error(
            `${source} has drifted from ${POLICY_MODULE} or ${PLUGIN_DIR}/plugin.json; ` +
                `run \`node scripts/build-claude-plugin.mjs --sync-in-place\`.`,
        );
    }

    for (const retiredHost of RETIRED_HOSTS) {
        if (rawText.includes(retiredHost)) {
            throw new Error(
                `${source} references retired staging host ${retiredHost}; use relayer.dev.memwal.ai`,
            );
        }
    }

    const secretPolicy = values.get("__MEMWAL_SECRET_POLICY__");
    const autoSaveRule = values.get("__MEMWAL_AUTO_SAVE_RULE__");

    if (
        ["README.md", "commands/remember.md", "commands/analyze.md", "skills/setup/SKILL.md"].includes(
            relative,
        ) &&
        !rawText.includes(secretPolicy)
    ) {
        throw new Error(`${source} does not contain SECRET_EXCLUSION_RULES verbatim`);
    }
    if (["README.md", "skills/setup/SKILL.md"].includes(relative) && !rawText.includes(autoSaveRule)) {
        throw new Error(`${source} does not contain AUTO_SAVE_OPT_IN_RULE verbatim`);
    }
    if (relative === "skills/setup/SKILL.md") {
        const span = /^<!-- memwal:start -->\r?\n([\s\S]*?)\r?\n<!-- memwal:end -->$/m.exec(rawText)?.[1] ?? "";
        if (!span.includes(autoSaveRule) || !span.includes(secretPolicy)) {
            throw new Error(
                `${source} <!-- memwal:start --> ... <!-- memwal:end --> span is missing policy rules`,
            );
        }
    }
}

async function syncInPlace() {
    const values = await substitutions();
    const absolute = path.join(ROOT, PLUGIN_DIR);
    let updated = 0;
    for (const relative of walk(absolute)) {
        if (!relative.endsWith(".md")) continue;
        const source = `${PLUGIN_DIR}/${relative}`;
        const filePath = path.join(absolute, relative);
        const raw = fs.readFileSync(filePath, "utf8");
        const rendered = renderMarkdown(relative, raw, values, source);
        if (raw !== rendered) {
            fs.writeFileSync(filePath, rendered, "utf8");
            updated += 1;
        }
    }
    return updated;
}

function add(files, target, contents, source) {
    if (FORBIDDEN.some((pattern) => pattern.test(target))) {
        throw new Error(`${source} would emit ${target}, which the plugin tree must not carry`);
    }
    if (RESERVED.includes(target)) {
        throw new Error(`${source} would emit ${target}, which belongs to the published repository`);
    }
    if (files.has(target)) throw new Error(`${target} is emitted twice; ${source} collides`);
    files.set(target, contents);
}

async function build() {
    const values = await substitutions();
    const files = new Map();

    for (const dir of [PLUGIN_DIR, OVERLAY_DIR]) {
        const absolute = path.join(ROOT, dir);
        for (const relative of walk(absolute)) {
            const source = `${dir}/${relative}`;
            const raw = fs.readFileSync(path.join(absolute, relative));
            if (relative !== ".github/scripts/check-plugin-tree.mjs") {
                const token = raw.toString("utf8").match(PLACEHOLDER);
                if (token && !relative.endsWith(".md")) {
                    throw new Error(`${source} carries unresolved placeholder ${token[0]}`);
                }
            }
            let contents = raw;
            if (relative.endsWith(".md")) {
                const rawText = raw.toString("utf8");
                const renderedText = renderMarkdown(relative, rawText, values, source);
                if (dir === PLUGIN_DIR) {
                    verifyCommittedMarkdown(relative, rawText, renderedText, values, source);
                }
                contents = Buffer.from(renderedText, "utf8");
            }
            add(files, relative, contents, source);
        }
    }

    add(files, "LICENSE", fs.readFileSync(path.join(ROOT, "LICENSE")), "LICENSE");

    for (const name of COPIED_TESTS) {
        const source = `${MCP_TEST_DIR}/${name}`;
        const text = fs.readFileSync(path.join(ROOT, source), "utf8");
        if (!text.includes("../plugin/scripts/")) {
            throw new Error(`${source} no longer imports from ../plugin/scripts/; update the rewrite`);
        }
        add(files, `test/${name}`, Buffer.from(text.replaceAll("../plugin/scripts/", "../scripts/")), source);
    }

    const missing = REQUIRED.filter((target) => !files.has(target));
    if (missing.length > 0) {
        throw new Error(`the generated tree is missing required files: ${missing.join(", ")}`);
    }

    return new Map([...files].sort(([left], [right]) => (left < right ? -1 : 1)));
}

function digest(files) {
    return [...files].map(([target, contents]) => `${sha256(contents)}  ${target}`).join("\n");
}

function sha256(contents) {
    return createHash("sha256").update(contents).digest("hex");
}

function canonicalizePath(targetPath) {
    const resolved = path.resolve(targetPath);
    const tail = [];
    let current = resolved;
    while (!fs.existsSync(current)) {
        const parent = path.dirname(current);
        if (parent === current) break;
        tail.unshift(path.basename(current));
        current = parent;
    }
    const base = fs.existsSync(current) ? fs.realpathSync(current) : current;
    return tail.length > 0 ? path.join(base, ...tail) : base;
}

function assertSafeOutDir(outDir, rootDir = ROOT) {
    const rootCanonical = canonicalizePath(rootDir);
    const outCanonical = canonicalizePath(outDir);
    if (path.parse(outCanonical).root === outCanonical) {
        throw new Error(`refusing to emit into filesystem root ${outCanonical}`);
    }
    if (outCanonical === rootCanonical || rootCanonical.startsWith(outCanonical + path.sep)) {
        throw new Error(
            `refusing to emit into ${outDir}: output path overlaps the repository root or its ancestors (${rootCanonical})`,
        );
    }
    if (outCanonical.startsWith(rootCanonical + path.sep)) {
        throw new Error(
            `refusing to emit into ${outDir}: output path is inside the repository checkout (${rootCanonical})`,
        );
    }
}

function emit(outDir, files) {
    assertSafeOutDir(outDir);
    fs.rmSync(outDir, { recursive: true, force: true });
    for (const [target, contents] of files) {
        const destination = path.join(outDir, target);
        fs.mkdirSync(path.dirname(destination), { recursive: true });
        fs.writeFileSync(destination, contents);
    }
}

function compare(files, againstDir) {
    const problems = [];
    const present = new Set(
        walk(againstDir).filter(
            (target) => target !== ".git" && !target.startsWith(".git/") && !RESERVED.includes(target),
        ),
    );

    for (const [target, contents] of files) {
        if (!present.has(target)) {
            problems.push(`${target} is missing from ${againstDir}`);
            continue;
        }
        present.delete(target);
        const actual = fs.readFileSync(path.join(againstDir, target));
        if (sha256(actual) !== sha256(contents)) problems.push(`${target} differs from the generated tree`);
    }

    for (const target of present) problems.push(`${target} is in ${againstDir} but is not generated`);

    return problems;
}

function argument(name) {
    const index = process.argv.indexOf(name);
    if (index === -1) return null;
    const value = process.argv[index + 1];
    if (!value || value.startsWith("--")) {
        throw new Error(`${name} requires a value`);
    }
    return value;
}

async function main() {
    if (process.argv.includes("--sync-in-place")) {
        const updated = await syncInPlace();
        console.log(`synced ${PLUGIN_DIR} markdown in place (${updated} file(s) updated)`);
        if (!process.argv.includes("--check") && !process.argv.includes("--out")) return;
    }

    const checking = process.argv.includes("--check");
    const against = argument("--against");
    const outDir = checking ? null : path.resolve(ROOT, argument("--out") ?? DEFAULT_OUT);
    if (outDir !== null) {
        assertSafeOutDir(outDir);
    }

    const files = await build();

    if (!checking) {
        emit(outDir, files);
        console.log(`wrote ${files.size} files to ${path.relative(ROOT, outDir) || outDir}`);
        return;
    }

    const problems = [];

    const second = await build();
    if (digest(files) !== digest(second)) problems.push("generating twice produced different output");

    if (against) problems.push(...compare(files, path.resolve(ROOT, against)));

    if (problems.length > 0) {
        for (const problem of problems) console.error(problem);
        process.exit(1);
    }

    console.log(`claude plugin tree OK; ${files.size} files, pinned to the plugin manifest`);
}

await main();

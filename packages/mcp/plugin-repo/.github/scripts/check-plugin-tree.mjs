#!/usr/bin/env node

import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import {
    AUTO_SAVE_OPT_IN_RULE,
    SECRET_EXCLUSION_RULES,
} from "../../scripts/lib/memory-policy.mjs";

const PACKAGE = "@mysten-incubation/memwal-mcp";
const REGISTRY = "https://registry.npmjs.org/@mysten-incubation%2Fmemwal-mcp";
const PLACEHOLDER = /__MEMWAL_[A-Z_]+__/;

const REQUIRED_FILES = [
    ".claude-plugin/plugin.json",
    ".codex-mcp.json",
    ".codex-plugin/plugin.json",
    ".cursor-mcp.json",
    ".cursor-plugin/plugin.json",
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
];

function walk(dir, base = dir) {
    const found = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === ".git") continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) found.push(...walk(full, base));
        else if (entry.isFile()) found.push(path.relative(base, full).split(path.sep).join("/"));
    }
    return found.sort();
}

const problems = [];
const fail = (message) => problems.push(message);

for (const file of REQUIRED_FILES) {
    if (!existsSync(file)) fail(`Missing ${file}`);
}

if (existsSync(".claude-plugin/plugin.json")) {
    const manifest = JSON.parse(readFileSync(".claude-plugin/plugin.json", "utf8"));
    if (manifest.skills === "./skills" || manifest.skills === "./skills/") {
        fail(
            '.claude-plugin/plugin.json sets "skills" to the default ./skills/ directory, ' +
                "which makes Claude Code register the default skills twice",
        );
    }
    for (const key of ["mcpServers", "skills", "commands", "hooks"]) {
        const target = manifest[key];
        if (target && !existsSync(target)) {
            fail(`.claude-plugin/plugin.json "${key}" points at missing ${target}`);
        }
    }
}

for (const [file, variable] of Object.entries({
    ".mcp.json": "CLAUDE_PLUGIN_ROOT",
    ".codex-mcp.json": "PLUGIN_ROOT",
    ".cursor-mcp.json": "CURSOR_PLUGIN_ROOT",
})) {
    if (!existsSync(file)) continue;
    const server = JSON.parse(readFileSync(file, "utf8")).mcpServers?.memwal;
    const entry = server?.args?.length === 1 ? server.args[0] : null;
    const pattern = new RegExp(`^\\$\\{${variable}\\}/(scripts/[A-Za-z0-9_./-]+\\.mjs)$`);
    const match = entry ? pattern.exec(entry) : null;
    if (server?.command !== "node" || !match) {
        fail(
            `${file} must start the server as node \${${variable}}/scripts/<launcher>.mjs. ` +
                `A bare package name is resolved against the project directory, so a project ` +
                `shipping a package of the same name wins.`,
        );
        continue;
    }
    if (!existsSync(match[1])) fail(`${file} points at ${match[1]}, which is not in this tree`);
}

let pin = "";
if (existsSync("plugin.json")) {
    const pluginManifest = JSON.parse(readFileSync("plugin.json", "utf8"));
    pin = pluginManifest.mcpPackageVersion ?? pluginManifest.version;
    if (typeof pin !== "string" || pin.trim() === "") {
        fail('plugin.json has no usable "mcpPackageVersion" or "version"');
    } else {
        const response = await fetch(REGISTRY, { headers: { accept: "application/json" } });
        if (!response.ok) {
            fail(`npm registry answered HTTP ${response.status} for ${PACKAGE}; retry the job`);
        } else {
            const packument = await response.json();
            if (!packument.versions?.[pin]) {
                fail(
                    `plugin.json pins ${PACKAGE}@${pin}, which npm does not carry. The launcher ` +
                        `installs that exact version, so every fresh install would fail.`,
                );
            }
        }
    }
}

for (const file of walk(".")) {
    if (file === ".github/scripts/check-plugin-tree.mjs") continue;
    const text = readFileSync(file, "utf8");
    const unresolved = text.match(PLACEHOLDER);
    if (unresolved) fail(`${file} still carries the generator placeholder ${unresolved[0]}`);
    if (pin && file.endsWith(".md")) {
        for (const match of text.matchAll(/@mysten-incubation\/memwal-mcp@([0-9A-Za-z._-]+)/g)) {
            if (match[1] !== pin) {
                fail(`${file} pins ${PACKAGE}@${match[1]}, expected ${pin} from plugin.json`);
            }
        }
    }
}

for (const file of ["README.md", "commands/remember.md", "commands/analyze.md", "skills/setup/SKILL.md"]) {
    if (!existsSync(file)) continue;
    const text = readFileSync(file, "utf8");
    if (!text.includes(SECRET_EXCLUSION_RULES)) {
        fail(
            `${file} does not carry SECRET_EXCLUSION_RULES verbatim from scripts/lib/memory-policy.mjs. ` +
                `Every surface that drives a save must state the same rules.`,
        );
    }
}

for (const file of ["README.md", "skills/setup/SKILL.md"]) {
    if (!existsSync(file)) continue;
    const text = readFileSync(file, "utf8");
    if (!text.includes(AUTO_SAVE_OPT_IN_RULE)) {
        fail(
            `${file} does not carry AUTO_SAVE_OPT_IN_RULE verbatim from scripts/lib/memory-policy.mjs.`,
        );
    }
}

if (existsSync("skills/setup/SKILL.md")) {
    const skillText = readFileSync("skills/setup/SKILL.md", "utf8");
    const span = /^<!-- memwal:start -->\r?\n([\s\S]*?)\r?\n<!-- memwal:end -->$/m.exec(skillText)?.[1];
    if (!span) {
        fail("skills/setup/SKILL.md is missing the <!-- memwal:start --> ... <!-- memwal:end --> span");
    } else {
        if (!span.includes(AUTO_SAVE_OPT_IN_RULE)) {
            fail("skills/setup/SKILL.md <!-- memwal:start --> span does not carry AUTO_SAVE_OPT_IN_RULE");
        }
        if (!span.includes(SECRET_EXCLUSION_RULES)) {
            fail("skills/setup/SKILL.md <!-- memwal:start --> span does not carry SECRET_EXCLUSION_RULES");
        }
    }
}

if (existsSync("README.md")) {
    const readmeText = readFileSync("README.md", "utf8");
    const neverSavedSection = /## What is never saved\r?\n([\s\S]*?)(?=\r?\n## |$)/.exec(readmeText)?.[1] ?? "";
    if (neverSavedSection.includes(AUTO_SAVE_OPT_IN_RULE)) {
        fail('README.md places AUTO_SAVE_OPT_IN_RULE under "## What is never saved" instead of "## Automatic memory"');
    }
}

if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    process.exit(1);
}

console.log(`plugin tree OK; ${PACKAGE}@${pin} is published`);

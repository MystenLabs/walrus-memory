import "./verify-package-version-bumps.test.mjs";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";

const files = [
    "packages/sdk/package.json", "packages/sdk/CHANGELOG.md", "docs/sdk/changelog.mdx",
    "packages/python-sdk-memwal/pyproject.toml", "packages/python-sdk-memwal/memwal/__init__.py",
    "packages/python-sdk-memwal/CHANGELOG.md", "docs/python-sdk/changelog.mdx",
    "packages/mcp/package.json", "packages/mcp/CHANGELOG.md", "docs/mcp/changelog.mdx",
    ".claude-plugin/marketplace.json", ".cursor-plugin/marketplace.json",
    "packages/mcp/plugin/.claude-plugin/plugin.json", "packages/mcp/plugin/.codex-plugin/plugin.json",
    "packages/mcp/plugin/.cursor-plugin/plugin.json", "packages/mcp/plugin/plugin.json",
    "packages/mcp/plugin/.mcp.json", "packages/mcp/plugin/.cursor-mcp.json", "packages/mcp/plugin/.codex-mcp.json",
    "packages/mcp/plugin/scripts/install_codex_hooks.mjs", "packages/mcp/plugin/scripts/launch_mcp.mjs",
    "packages/mcp/plugin/scripts/lib/codex-config.mjs",
    "packages/openclaw-memory-memwal/package.json", "packages/openclaw-memory-memwal/CHANGELOG.md",
    "docs/openclaw/changelog.mdx",
];
const verifier = resolve("scripts/verify-manual-sdk-release.mjs");

function check(t, mutate = () => {}) {
    const directory = mkdtempSync(join(tmpdir(), "memwal-release-check-"));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    for (const file of files) {
        const destination = join(directory, file);
        mkdirSync(dirname(destination), { recursive: true });
        writeFileSync(destination, readFileSync(file));
    }
    mutate(directory);
    return spawnSync(process.execPath, [verifier], { cwd: directory, encoding: "utf8" });
}
function edit(directory, file, transform) {
    const path = join(directory, file);
    writeFileSync(path, transform(readFileSync(path, "utf8")));
}

test("current manually bumped manifests and changelogs agree", (t) => {
    const result = check(t);
    assert.equal(result.status, 0, result.stderr);
});

test("a stale plugin manifest is rejected", (t) => {
    const result = check(t, (directory) => edit(directory, "packages/mcp/plugin/.codex-plugin/plugin.json", (text) => {
        const manifest = JSON.parse(text); manifest.version = "0.0.0"; return JSON.stringify(manifest);
    }));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /codex-plugin\/plugin.json: expected/);
});

test("an older matching changelog section cannot hide an incorrect newest release", (t) => {
    const result = check(t, (directory) => edit(directory, "docs/mcp/changelog.mdx", (text) => `## 99.0.0\n\n${text}`));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /newest release must be/);
});

test("a mismatched Python runtime version is rejected", (t) => {
    const result = check(t, (directory) => edit(directory, "packages/python-sdk-memwal/memwal/__init__.py", (text) => text.replace(/^__version__ = ".*"$/m, '__version__ = "0.0.0"')));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /__init__.py: expected/);
});

test("a launcher pin for a future release is rejected", (t) => {
    const result = check(t, (directory) => edit(directory, "packages/mcp/plugin/plugin.json", (text) => {
        const manifest = JSON.parse(text); manifest.mcpPackageVersion = "99.0.0"; return JSON.stringify(manifest);
    }));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /expected a stable release at or before/);
});

function checkRegistry(t, published) {
    const directory = mkdtempSync(join(tmpdir(), "memwal-pin-check-"));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    const version = JSON.parse(readFileSync("packages/mcp/package.json", "utf8")).version;
    for (const [file, data] of [
        ["packages/mcp/package.json", { version }],
        ["packages/mcp/plugin/plugin.json", { version, mcpPackageVersion: "0.0.1" }],
    ]) {
        const destination = join(directory, file);
        mkdirSync(dirname(destination), { recursive: true });
        writeFileSync(destination, JSON.stringify(data));
    }
    const versions = { "0.0.1": {} };
    if (published) versions[version] = {};
    const packument = { versions, "dist-tags": { latest: "0.0.1" } };
    const code = `globalThis.fetch = async () => ({ ok: true, json: async () => (${JSON.stringify(packument)}) }); await import(${JSON.stringify(resolve("scripts/check-mcp-pin.mjs"))});`;
    return spawnSync(process.execPath, ["--input-type=module", "-e", code], {
        cwd: directory, encoding: "utf8", env: { ...process.env, GITHUB_BASE_REF: "main", GITHUB_STEP_SUMMARY: "" },
    });
}

test("a previous published stable pin is usable while the prepared release is unpublished", (t) => {
    const result = checkRegistry(t, false);
    assert.equal(result.status, 0, result.stderr);
});

test("publication ends the old-pin window and requires retargeting the launcher", (t) => {
    const result = checkRegistry(t, true);
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /pending-release window has ended/);
});

test("an invalid or future bootstrap cannot bypass release validation", (t) => {
    for (const bootstrap of ["latest", "99.0.0"]) {
        const result = check(t, directory => edit(directory, "packages/mcp/plugin/plugin.json", text => {
            const manifest = JSON.parse(text); manifest.mcpBootstrapVersion = bootstrap; return JSON.stringify(manifest);
        }));
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /bootstrap/i);
    }
});

test("the pending exact stable release can use its explicit published bootstrap", (t) => {
    const directory = mkdtempSync(join(tmpdir(), "memwal-bootstrap-check-"));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    const version = "0.0.18", bootstrap = "0.0.17-dev.3";
    for (const [file, value] of [["packages/mcp/package.json", { version }], ["packages/mcp/plugin/plugin.json", { version, mcpPackageVersion: version, mcpBootstrapVersion: bootstrap }]]) {
        mkdirSync(dirname(join(directory, file)), { recursive: true });
        writeFileSync(join(directory, file), JSON.stringify(value));
    }
    for (const stablePublished of [false, true]) {
        const versions = { [bootstrap]: {} };
        if (stablePublished) versions[version] = {};
        const packument = { versions, "dist-tags": { latest: stablePublished ? version : "0.0.17" } };
        const code = `globalThis.fetch = async () => ({ok:true,json:async()=>(${JSON.stringify(packument)})});await import(${JSON.stringify(resolve("scripts/check-mcp-pin.mjs"))});`;
        const result = spawnSync(process.execPath, ["--input-type=module", "-e", code], { cwd: directory, encoding: "utf8", env: { ...process.env, GITHUB_BASE_REF: "dev", GITHUB_STEP_SUMMARY: "" } });
        assert.equal(result.status, 0, result.stdout + result.stderr);
    }
});

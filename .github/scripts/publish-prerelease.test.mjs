// Tests for .github/scripts/publish-prerelease.sh with npm and pnpm stubbed
// on PATH. Run: node .github/scripts/publish-prerelease.test.mjs
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "publish-prerelease.sh");

const NPM_STUB = `#!/usr/bin/env bash
# Stub: \`npm view <name> versions --json\` answers from env.
[ -n "\${STUB_NPM_STDOUT-}" ] && printf '%s\\n' "$STUB_NPM_STDOUT"
[ -n "\${STUB_NPM_STDERR-}" ] && printf '%s\\n' "$STUB_NPM_STDERR" >&2
exit "\${STUB_NPM_EXIT:-0}"
`;

const PNPM_STUB = `#!/usr/bin/env bash
# Stub: record the version being published; fail the first STUB_PNPM_STAGED
# attempts with a staged-version 409.
v="$(node -p "require('./package.json').version")"
echo "$v" >> "$STUB_PUBLISH_LOG"
n="$(wc -l < "$STUB_PUBLISH_LOG")"
if [ "$n" -le "\${STUB_PNPM_STAGED:-0}" ]; then
  echo "npm error code E409"
  echo "npm error Cannot publish over previously staged version $v"
  exit 1
fi
echo "+ pkg@$v"
`;

function run(env) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "publish-prerelease-"));
    const bin = path.join(root, "bin");
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, "npm"), NPM_STUB, { mode: 0o755 });
    fs.writeFileSync(path.join(bin, "pnpm"), PNPM_STUB, { mode: 0o755 });
    fs.mkdirSync(path.join(root, "pkg"));
    fs.writeFileSync(
        path.join(root, "pkg", "package.json"),
        JSON.stringify({ name: "@scope/pkg", version: "0.2.0" }, null, 4) + "\n",
    );
    const log = path.join(root, "published.log");
    fs.writeFileSync(log, "");
    const res = spawnSync("bash", [SCRIPT, "pkg", "@scope/pkg", "dev"], {
        cwd: root,
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, STUB_PUBLISH_LOG: log, ...env },
    });
    const published = fs.readFileSync(log, "utf8").split("\n").filter(Boolean);
    fs.rmSync(root, { recursive: true, force: true });
    return { ...res, published };
}

test("publishes max+1 of the channel", () => {
    const r = run({ STUB_NPM_STDOUT: JSON.stringify(["0.1.0", "0.2.0-dev.3", "0.2.0-dev.26", "0.2.0-rc.40"]) });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.published, ["0.2.0-dev.27"]);
});

test("a single published version (npm prints a bare string) still counts", () => {
    const r = run({ STUB_NPM_STDOUT: JSON.stringify("0.2.0-dev.4") });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.published, ["0.2.0-dev.5"]);
});

test("no version on this channel starts at .0", () => {
    const r = run({ STUB_NPM_STDOUT: JSON.stringify(["0.1.0", "0.2.0-rc.1"]) });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.published, ["0.2.0-dev.0"]);
});

test("E404 (never published) is a valid none and starts at .0", () => {
    const r = run({
        STUB_NPM_EXIT: "1",
        STUB_NPM_STDOUT: JSON.stringify({ error: { code: "E404", summary: "Not Found - 404" } }),
        STUB_NPM_STDERR: "npm error code E404",
    });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.published, ["0.2.0-dev.0"]);
});

test("E404 reported only on stderr is also none", () => {
    const r = run({ STUB_NPM_EXIT: "1", STUB_NPM_STDERR: "npm error code E404" });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.published, ["0.2.0-dev.0"]);
});

test("any other npm view failure aborts and never publishes", () => {
    const r = run({
        STUB_NPM_EXIT: "1",
        STUB_NPM_STDOUT: JSON.stringify(["0.2.0-dev.26"]),
        STUB_NPM_STDERR: "npm error code ETIMEDOUT",
    });
    assert.notEqual(r.status, 0);
    assert.deepEqual(r.published, []);
    assert.match(r.stderr, /npm view @scope\/pkg versions failed .*refusing to publish/);
    assert.doesNotMatch(r.stdout + r.stderr, /dev\.-1|Publishing/);
});

test("a failure with no output at all aborts", () => {
    const r = run({ STUB_NPM_EXIT: "1" });
    assert.notEqual(r.status, 0);
    assert.deepEqual(r.published, []);
});

test("garbage from npm view aborts and never publishes", () => {
    const r = run({ STUB_NPM_STDOUT: "<html>proxy error</html>" });
    assert.notEqual(r.status, 0);
    assert.deepEqual(r.published, []);
    assert.match(r.stderr, /refusing to publish/);
});

test("multiple lines of output abort rather than doing math on them", () => {
    const r = run({ STUB_NPM_STDOUT: "26\n-1" });
    assert.notEqual(r.status, 0);
    assert.deepEqual(r.published, []);
});

test("non-numeric suffixes are ignored, not parsed loosely", () => {
    const r = run({ STUB_NPM_STDOUT: JSON.stringify(["0.2.0-dev.2", "0.2.0-dev.1e3", "0.2.0-dev.9.1", "0.2.0-dev.-1"]) });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.published, ["0.2.0-dev.3"]);
});

test("a staged-version collision retries the next number", () => {
    const r = run({ STUB_NPM_STDOUT: JSON.stringify(["0.2.0-dev.26"]), STUB_PNPM_STAGED: "2" });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.published, ["0.2.0-dev.27", "0.2.0-dev.28", "0.2.0-dev.29"]);
});

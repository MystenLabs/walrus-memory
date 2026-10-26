/**
 * The plugin must never run an MCP server that came out of the user's project
 * (WALM-640).
 *
 * The plugin used to start the server with `npx -y @mysten-incubation/memwal-mcp@<pin>`.
 * npx resolves that name against the working directory the MCP client was started
 * in — the project the user has open — so a project carrying an installed package
 * of the same name that *claims the pinned version* won, offline. The version pin
 * is no defence: the fake package just says it is that version.
 *
 * Every test here plants exactly that: a fake `@mysten-incubation/memwal-mcp` in a
 * temp project's node_modules, with the real pinned version in its manifest and a
 * bin that prints LOCAL_PACKAGE_EXECUTED, plus the `node_modules/.bin` shim npx
 * would have found. The launcher must resolve and run the trusted absolute path
 * instead — and when the trusted install cannot be produced, it must fail rather
 * than fall back to the name.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
    chmodSync,
    lstatSync,
    mkdirSync,
    mkdtempSync,
    readFileSync,
    rmSync,
    symlinkSync,
    writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
    MCP_PACKAGE_NAME,
    MCP_REGISTRY,
    assertRuntimeRootLocation,
    canonicalPath,
    enclosingProjectRoot,
    expectedEntryPath,
    installArguments,
    installDir,
    installEnvironment,
    npmSpawnPlan,
    pinnedVersion,
    prepareRuntimeRoot,
    quoteWindowsArgument,
    resolveInstalledEntry,
    resolveNpm,
    runtimeRoot,
    verifyTrustedDirectory,
} from "../plugin/scripts/lib/mcp-launch.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLUGIN_DIR = resolve(__dirname, "../plugin");
const LAUNCHER = join(PLUGIN_DIR, "scripts", "launch_mcp.mjs");
const PIN = pinnedVersion();

const LOCAL_MARKER = "LOCAL_PACKAGE_EXECUTED";
const TRUSTED_MARKER = "TRUSTED_ENTRY_EXECUTED";

/**
 * Write a package that looks exactly like the real one to any resolver: same name,
 * same `bin` layout, and whatever version the caller wants it to claim.
 */
function plantPackage(nodeModulesParent, { version, marker }) {
    const packageDir = join(nodeModulesParent, "node_modules", ...MCP_PACKAGE_NAME.split("/"));
    const binDir = join(packageDir, "dist", "bin");
    mkdirSync(binDir, { recursive: true });
    writeFileSync(
        join(packageDir, "package.json"),
        JSON.stringify({
            name: MCP_PACKAGE_NAME,
            version,
            bin: { "memwal-mcp": "dist/bin/memwal-mcp.js" },
        }),
    );
    const entry = join(binDir, "memwal-mcp.js");
    writeFileSync(
        entry,
        `console.log(${JSON.stringify(marker)});\n` +
            `console.log("ARGV:" + process.argv.slice(2).join(" "));\n`,
    );
    return entry;
}

/** The PATH-relative shim npx would have reached for inside the project. */
function plantBinShim(projectDir, marker) {
    const binDir = join(projectDir, "node_modules", ".bin");
    mkdirSync(binDir, { recursive: true });
    const shim = join(binDir, "memwal-mcp");
    writeFileSync(shim, `#!/bin/sh\necho ${marker}\n`);
    chmodSync(shim, 0o755);
    return shim;
}

/**
 * A project a user might have open, carrying a fake package that claims the exact
 * version the plugin pins.
 */
function makeHostileProject(t, { version = PIN } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "memwal-hostile-project-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const entry = plantPackage(dir, { version, marker: LOCAL_MARKER });
    plantBinShim(dir, LOCAL_MARKER);
    return { dir, entry };
}

/** A trusted runtime root with the pinned version already installed in it. */
function makeTrustedRuntime(t, { version = PIN, populate = true } = {}) {
    const root = mkdtempSync(join(tmpdir(), "memwal-runtime-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    if (!populate) return { root, entry: null };
    const target = installDir(version, root);
    mkdirSync(target, { recursive: true });
    const entry = plantPackage(target, { version, marker: TRUSTED_MARKER });
    return { root, entry };
}

function runLauncher(args, { cwd, env }) {
    return spawnSync(process.execPath, [LAUNCHER, ...args], {
        cwd,
        encoding: "utf8",
        env: { ...process.env, ...env },
    });
}

test("the planted package claims the exact pinned version", (t) => {
    const project = makeHostileProject(t);
    const manifest = JSON.parse(
        readFileSync(
            join(project.dir, "node_modules", ...MCP_PACKAGE_NAME.split("/"), "package.json"),
            "utf8",
        ),
    );
    // If this drifts the rest of the file stops testing the reported attack.
    assert.equal(manifest.version, PIN);
    assert.equal(manifest.name, MCP_PACKAGE_NAME);
});

test("resolution ignores the project entirely and lands in the trusted directory", (t) => {
    const project = makeHostileProject(t);
    const trusted = makeTrustedRuntime(t);

    const previousCwd = process.cwd();
    t.after(() => process.chdir(previousCwd));
    process.chdir(project.dir);

    const resolved = resolveInstalledEntry(installDir(PIN, trusted.root), PIN);
    assert.equal(resolved, trusted.entry);
    assert.equal(resolved, expectedEntryPath({ version: PIN, root: trusted.root }));
    assert.ok(resolved.startsWith(trusted.root), `${resolved} is not under ${trusted.root}`);
    assert.ok(!resolved.includes(project.dir), `${resolved} points into the project`);
});

test("--print-entry from inside the hostile project prints the trusted path", (t) => {
    const project = makeHostileProject(t);
    const trusted = makeTrustedRuntime(t);

    const result = runLauncher(["--print-entry"], {
        cwd: project.dir,
        env: { MEMWAL_MCP_RUNTIME_DIR: trusted.root },
    });

    assert.equal(result.status, 0, result.stderr);
    const printed = result.stdout.trim();
    assert.equal(printed, trusted.entry);
    assert.notEqual(printed, project.entry);
    assert.ok(!printed.includes(project.dir), `${printed} points into the project`);
});

test("launching from the hostile project runs the trusted entry, not the local one", (t) => {
    const project = makeHostileProject(t);
    const trusted = makeTrustedRuntime(t);

    const result = runLauncher([], {
        cwd: project.dir,
        env: { MEMWAL_MCP_RUNTIME_DIR: trusted.root },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, new RegExp(TRUSTED_MARKER));
    assert.doesNotMatch(result.stdout, new RegExp(LOCAL_MARKER));
});

test("server flags and env are forwarded to the trusted entry unchanged", (t) => {
    const project = makeHostileProject(t);
    const trusted = makeTrustedRuntime(t);

    const result = runLauncher(["--dev", "--namespace", "work"], {
        cwd: project.dir,
        env: { MEMWAL_MCP_RUNTIME_DIR: trusted.root },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /ARGV:--dev --namespace work/);
});

test("an install under a different version is not accepted for the pin", (t) => {
    const project = makeHostileProject(t);
    // Trusted directory holds a stale build; the pinned directory is empty.
    const trusted = makeTrustedRuntime(t, { version: "0.0.0-stale" });

    assert.equal(resolveInstalledEntry(installDir(PIN, trusted.root), PIN), null);
    assert.equal(
        resolveInstalledEntry(installDir("0.0.0-stale", trusted.root), PIN),
        null,
        "a directory whose manifest disagrees with the pin must not be used",
    );
    assert.ok(!String(trusted.entry).includes(project.dir));
});

test("with no trusted install and a failing install, the launcher fails instead of falling back", (t) => {
    const project = makeHostileProject(t);
    const trusted = makeTrustedRuntime(t, { populate: false });

    // A read-only trusted root makes the install fail the way an offline or broken
    // toolchain would, without going near the network. (An empty PATH no longer does
    // it: npm is resolved from process.execPath, which is the point of that change.)
    let result;
    chmodSync(trusted.root, 0o500);
    try {
        result = runLauncher([], {
            cwd: project.dir,
            env: { MEMWAL_MCP_RUNTIME_DIR: trusted.root },
        });
    } finally {
        chmodSync(trusted.root, 0o700);
    }

    assert.notEqual(result.status, 0, "launcher must not succeed without a trusted install");
    assert.doesNotMatch(result.stdout, new RegExp(LOCAL_MARKER));
    assert.doesNotMatch(result.stderr, new RegExp(LOCAL_MARKER));
    assert.match(result.stderr, /refusing to fall back/);
});

test("a relative MEMWAL_MCP_RUNTIME_DIR is rejected, not resolved against the project", (t) => {
    const project = makeHostileProject(t);

    const result = runLauncher(["--print-entry"], {
        cwd: project.dir,
        env: { MEMWAL_MCP_RUNTIME_DIR: "node_modules" },
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /absolute path/);
    assert.doesNotMatch(result.stdout, new RegExp(LOCAL_MARKER));
});

test("the default trusted root is ~/.memwal/runtime", (t) => {
    const project = makeHostileProject(t);
    const home = mkdtempSync(join(tmpdir(), "memwal-home-"));
    t.after(() => rmSync(home, { recursive: true, force: true }));

    const target = join(home, ".memwal", "runtime", `memwal-mcp@${PIN}`);
    mkdirSync(target, { recursive: true });
    const entry = plantPackage(target, { version: PIN, marker: TRUSTED_MARKER });

    // USERPROFILE alongside HOME: os.homedir() reads USERPROFILE on Windows and
    // would otherwise escape the sandbox into the real home.
    const result = runLauncher(["--print-entry"], {
        cwd: project.dir,
        env: { HOME: home, USERPROFILE: home, MEMWAL_MCP_RUNTIME_DIR: "" },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), entry);
});

test("runtimeRoot honours an absolute override and otherwise sits under the home dir", () => {
    const previous = process.env.MEMWAL_MCP_RUNTIME_DIR;
    try {
        const absolute = join(tmpdir(), "memwal-runtime-override");
        process.env.MEMWAL_MCP_RUNTIME_DIR = absolute;
        assert.equal(runtimeRoot(), absolute);

        delete process.env.MEMWAL_MCP_RUNTIME_DIR;
        assert.match(runtimeRoot(), /[\\/]\.memwal[\\/]runtime$/);
    } finally {
        if (previous === undefined) delete process.env.MEMWAL_MCP_RUNTIME_DIR;
        else process.env.MEMWAL_MCP_RUNTIME_DIR = previous;
    }
});

test("no plugin launch manifest resolves the server through npx", () => {
    const manifests = [
        [".mcp.json", "${CLAUDE_PLUGIN_ROOT}"],
        [".cursor-mcp.json", "${CURSOR_PLUGIN_ROOT}"],
        [".codex-mcp.json", "${PLUGIN_ROOT}"],
    ];
    for (const [name, root] of manifests) {
        const server = JSON.parse(readFileSync(join(PLUGIN_DIR, name), "utf8")).mcpServers.memwal;
        assert.equal(server.command, "node", `${name} must not launch through npx`);
        assert.deepEqual(server.args, [`${root}/scripts/launch_mcp.mjs`], name);
    }

    const installer = readFileSync(
        join(PLUGIN_DIR, "scripts", "install_codex_hooks.mjs"),
        "utf8",
    );
    assert.doesNotMatch(
        installer,
        /command\s*=\s*\\?"npx/,
        "the Codex fallback installer must register the launcher, not npx",
    );
    assert.match(installer, /launch_mcp\.mjs/);
});

test("the launcher pin is the release, its prerelease, or a previous stable release", () => {
    const manifest = JSON.parse(readFileSync(join(PLUGIN_DIR, "plugin.json"), "utf8"));
    const pin = manifest.mcpPackageVersion;

    assert.equal(typeof pin, "string", "plugin.json must carry mcpPackageVersion");
    assert.match(
        pin,
        /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/,
        `mcpPackageVersion is not a semver: ${pin}`,
    );

    // A manually prepared release can retain the previous stable install until
    // npm serves the new version. check-mcp-pin.mjs verifies publication and
    // rejects this lag as soon as the prepared release exists on npm. An old
    // prerelease remains forbidden because it can outlive its relayer contract.
    const stablePin = /^\d+\.\d+\.\d+$/.test(pin);
    const releaseParts = manifest.version.split(".").map(Number);
    const pinParts = pin.split(".").map(Number);
    const difference = pinParts.findIndex((part, index) => part !== releaseParts[index]);
    const previousStable = stablePin && difference >= 0 && pinParts[difference] < releaseParts[difference];
    assert.ok(
        pin === manifest.version || pin.startsWith(`${manifest.version}-`) || previousStable,
        `mcpPackageVersion ${pin} must be ${manifest.version}, its prerelease, or a previous stable release`,
    );

    assert.equal(
        pinnedVersion(PLUGIN_DIR),
        pin,
        "the launcher must install exactly what plugin.json pins",
    );
});

test("pinnedVersion prefers mcpPackageVersion, falls back to version, and refuses neither", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-plugin-manifest-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const write = (manifest) =>
        writeFileSync(join(dir, "plugin.json"), JSON.stringify(manifest));

    write({ version: "9.9.9", mcpPackageVersion: "9.9.9-dev.3" });
    assert.equal(pinnedVersion(dir), "9.9.9-dev.3");

    write({ version: "9.9.9" });
    assert.equal(pinnedVersion(dir), "9.9.9", "an absent mcpPackageVersion falls back to version");

    write({ version: "   " });
    assert.throws(() => pinnedVersion(dir), /no usable/, "a blank version is not a pin");
});

/* ------------------------------------------------------------------------- *
 * Review follow-ups (WALM-640): an absolute runtime root is not a trusted
 * runtime root, and the install step must not execute what it has not verified.
 * ------------------------------------------------------------------------- */

const POSIX = process.platform !== "win32";

/** A project that a repository could really ship: markers, config, planted runtime. */
function makeRepoProject(t) {
    const dir = mkdtempSync(join(tmpdir(), "memwal-repo-project-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    mkdirSync(join(dir, ".git"), { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "victim", version: "1.0.0" }));
    return dir;
}

/** The whole WALM-640 tree, committed inside the repository under `name`. */
function plantRuntimeRoot(projectDir, name = ".memwal-runtime") {
    const root = join(projectDir, name);
    const target = installDir(PIN, root);
    mkdirSync(target, { recursive: true });
    plantPackage(target, { version: PIN, marker: LOCAL_MARKER });
    return root;
}

test("an absolute MEMWAL_MCP_RUNTIME_DIR inside the project is refused", (t) => {
    const project = makeHostileProject(t);
    // What a client writes into ${workspaceFolder}/.cursor/mcp.json expands to: an
    // absolute path, which the old check accepted, pointing straight back into the
    // repository that supplied it.
    const plantedRoot = plantRuntimeRoot(project.dir);

    const result = runLauncher(["--print-entry"], {
        cwd: project.dir,
        env: { MEMWAL_MCP_RUNTIME_DIR: plantedRoot },
    });

    assert.notEqual(result.status, 0, "an in-project runtime root must not be usable");
    assert.match(result.stderr, /inside the project tree/);
    assert.match(result.stderr, /refusing to fall back/);
    assert.doesNotMatch(result.stdout, new RegExp(LOCAL_MARKER));
    assert.doesNotMatch(result.stdout, new RegExp(plantedRoot.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("the planted in-project tree is otherwise a complete, usable install", (t) => {
    // Without this the test above could pass for the wrong reason (a tree that would
    // not have resolved anyway). It is refused because of where it is, not what it is.
    const project = makeHostileProject(t);
    const plantedRoot = plantRuntimeRoot(project.dir);
    assert.ok(
        resolveInstalledEntry(installDir(PIN, plantedRoot), PIN),
        "the planted tree must be a resolvable install, so the refusal is about location",
    );
});

test("a runtime root inside the repository but above the cwd is refused too", (t) => {
    const repo = makeRepoProject(t);
    const plantedRoot = plantRuntimeRoot(repo);
    const nested = join(repo, "packages", "app");
    mkdirSync(nested, { recursive: true });

    const result = runLauncher(["--print-entry"], {
        cwd: nested,
        env: { MEMWAL_MCP_RUNTIME_DIR: plantedRoot },
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /inside the project tree/);
    assert.doesNotMatch(result.stdout, new RegExp(LOCAL_MARKER));
});

test("a runtime root that only looks external is refused once symlinks resolve", (t) => {
    if (!POSIX) return;
    const project = makeHostileProject(t);
    const plantedRoot = plantRuntimeRoot(project.dir);
    const outside = mkdtempSync(join(tmpdir(), "memwal-link-"));
    t.after(() => rmSync(outside, { recursive: true, force: true }));
    const link = join(outside, "runtime");
    symlinkSync(plantedRoot, link);

    const result = runLauncher(["--print-entry"], {
        cwd: project.dir,
        env: { MEMWAL_MCP_RUNTIME_DIR: link },
    });

    assert.notEqual(result.status, 0, "a symlink into the project is still the project");
    assert.match(result.stderr, /inside the project tree/);
    assert.doesNotMatch(result.stdout, new RegExp(LOCAL_MARKER));
});

test("assertRuntimeRootLocation accepts a root outside the project and rejects one inside", (t) => {
    const repo = makeRepoProject(t);
    const outside = mkdtempSync(join(tmpdir(), "memwal-outside-"));
    t.after(() => rmSync(outside, { recursive: true, force: true }));

    assert.equal(assertRuntimeRootLocation(outside, { cwd: repo }), resolve(outside));
    assert.throws(
        () => assertRuntimeRootLocation(join(repo, ".memwal-runtime"), { cwd: repo }),
        /inside the project tree/,
    );
    assert.throws(
        () => assertRuntimeRootLocation(repo, { cwd: repo }),
        /inside the project tree/,
    );
    // The reverse containment is just as wrong: the project must not sit inside the
    // directory whose contents we are about to execute.
    assert.throws(
        () => assertRuntimeRootLocation(dirname(repo), { cwd: repo }),
        /inside the project tree/,
    );
});

/**
 * A monorepo: `.git` and a workspace manifest at the root, a member package with
 * its own `package.json` underneath. The client is started in the member.
 */
function makeMonorepo(t) {
    const root = mkdtempSync(join(tmpdir(), "memwal-monorepo-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    mkdirSync(join(root, ".git"), { recursive: true });
    writeFileSync(
        join(root, "package.json"),
        JSON.stringify({ name: "monorepo", workspaces: ["apps/*"] }),
    );
    const member = join(root, "apps", "web");
    mkdirSync(member, { recursive: true });
    writeFileSync(join(member, "package.json"), JSON.stringify({ name: "web", version: "1.0.0" }));
    return { root, member };
}

test("a nested package does not become its own trust boundary", (t) => {
    // WALM-684: enclosingProjectRoot() stopped at the first ancestor carrying a
    // marker, so a client started in apps/web treated apps/web as the whole
    // project. The repository that controls apps/web was then "outside" it.
    const { root, member } = makeMonorepo(t);

    assert.equal(canonicalPath(enclosingProjectRoot(member)), canonicalPath(root));
    assert.equal(canonicalPath(enclosingProjectRoot(root)), canonicalPath(root));
});

test("a runtime override elsewhere in the repository is refused from a nested package", (t) => {
    const { root, member } = makeMonorepo(t);

    // The sibling that used to pass: inside the repo, outside the nested package.
    for (const cwd of [member, root]) {
        assert.throws(
            () => assertRuntimeRootLocation(join(root, ".memwal-runtime"), { cwd }),
            /inside the project tree/,
            `<repo>/.memwal-runtime must be refused when launching from ${cwd}`,
        );
        assert.throws(
            () => assertRuntimeRootLocation(join(root, "apps", "other", "runtime"), { cwd }),
            /inside the project tree/,
            `a sibling package's runtime dir must be refused when launching from ${cwd}`,
        );
    }
});

test("a legitimate runtime outside the repository still works from a nested package", (t) => {
    const { member } = makeMonorepo(t);
    const outside = mkdtempSync(join(tmpdir(), "memwal-outside-nested-"));
    t.after(() => rmSync(outside, { recursive: true, force: true }));

    assert.equal(assertRuntimeRootLocation(outside, { cwd: member }), resolve(outside));
});

test("a worktree .git file marks the boundary the same way a directory does", (t) => {
    // `git worktree add` and submodules write `.git` as a *file* containing a
    // gitdir: pointer. existsSync covers both, but the walk has to keep going past
    // the nested package to reach it.
    const root = mkdtempSync(join(tmpdir(), "memwal-worktree-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    writeFileSync(join(root, ".git"), "gitdir: /elsewhere/.git/worktrees/wt\n");
    const member = join(root, "packages", "inner");
    mkdirSync(member, { recursive: true });
    writeFileSync(join(member, "package.json"), JSON.stringify({ name: "inner" }));

    assert.equal(canonicalPath(enclosingProjectRoot(member)), canonicalPath(root));
    assert.throws(
        () => assertRuntimeRootLocation(join(root, ".memwal-runtime"), { cwd: member }),
        /inside the project tree/,
    );
});

test("a package tree with no repository around it is still a boundary", (t) => {
    // No .git anywhere: fall back to the outermost package.json rather than
    // treating the innermost one as the project.
    const root = mkdtempSync(join(tmpdir(), "memwal-nogit-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    writeFileSync(join(root, "package.json"), JSON.stringify({ name: "outer" }));
    const member = join(root, "packages", "inner");
    mkdirSync(member, { recursive: true });
    writeFileSync(join(member, "package.json"), JSON.stringify({ name: "inner" }));

    assert.equal(canonicalPath(enclosingProjectRoot(member)), canonicalPath(root));
    assert.throws(
        () => assertRuntimeRootLocation(join(root, "runtime"), { cwd: member }),
        /inside the project tree/,
    );
});

test("the boundary is the same when the project is reached through a symlink", (t) => {
    if (!POSIX) return;
    const { root, member } = makeMonorepo(t);
    const link = mkdtempSync(join(tmpdir(), "memwal-symlink-"));
    t.after(() => rmSync(link, { recursive: true, force: true }));
    const aliased = join(link, "alias");
    symlinkSync(member, aliased);

    // Reaching apps/web by another spelling must not change which tree owns it.
    assert.equal(canonicalPath(enclosingProjectRoot(aliased)), canonicalPath(root));
    assert.throws(
        () => assertRuntimeRootLocation(join(root, ".memwal-runtime"), { cwd: aliased }),
        /inside the project tree/,
    );
});

test("a marker at the filesystem root does not swallow the real checkout", () => {
    // Container images often carry /package.json or /.git (WORKDIR /). Walking to
    // the outermost marker picked "/" over the checkout under it, and a project of
    // "/" turns the location guard off. The root is excluded like home is.
    const present = new Set(["/package.json", "/.git", "/srv/app/.git", "/srv/app/package.json"]);
    const exists = (path) => present.has(path);

    assert.equal(
        enclosingProjectRoot("/srv/app/packages/web", "/home/nobody", { exists }),
        "/srv/app",
    );
});

test("a marker only at the filesystem root means no project, not a project of /", () => {
    const exists = (path) => path === "/package.json" || path === "/.git";

    // cwd itself becomes the project: the guard still has something to compare.
    assert.equal(
        enclosingProjectRoot("/srv/app", "/home/nobody", { exists }),
        "/srv/app",
    );
});

test("a group-writable runtime root is refused", (t) => {
    if (!POSIX) return;
    const project = makeHostileProject(t);
    const trusted = makeTrustedRuntime(t);
    chmodSync(trusted.root, 0o777);

    const result = runLauncher(["--print-entry"], {
        cwd: project.dir,
        env: { MEMWAL_MCP_RUNTIME_DIR: trusted.root },
    });
    chmodSync(trusted.root, 0o700);

    assert.notEqual(result.status, 0, "a root anyone can write is not a trusted root");
    assert.match(result.stderr, /group- or world-writable/);
    assert.match(result.stderr, /refusing to fall back/);
    assert.doesNotMatch(result.stdout, new RegExp(LOCAL_MARKER));
});

test("verifyTrustedDirectory rejects loose modes, symlinks and foreign owners", (t) => {
    if (!POSIX) return;
    const root = mkdtempSync(join(tmpdir(), "memwal-verify-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));

    const good = join(root, "good");
    mkdirSync(good, { mode: 0o700 });
    assert.equal(verifyTrustedDirectory(good), true);
    assert.equal(verifyTrustedDirectory(join(root, "absent")), false);

    for (const mode of [0o770, 0o707, 0o777, 0o755 | 0o020]) {
        chmodSync(good, mode);
        assert.throws(() => verifyTrustedDirectory(good), /group- or world-writable/, `mode ${mode.toString(8)}`);
    }
    chmodSync(good, 0o700);

    const link = join(root, "link");
    symlinkSync(good, link);
    assert.throws(() => verifyTrustedDirectory(link), /not a directory/);

    const file = join(root, "file");
    writeFileSync(file, "");
    assert.throws(() => verifyTrustedDirectory(file), /not a directory/);

    // A directory owned by somebody else. Skipped when the suite runs as that
    // somebody else (root in a container), where the check cannot fire.
    const foreign = "/usr";
    if (process.getuid() !== 0 && lstatSync(foreign).uid !== process.getuid()) {
        assert.throws(() => verifyTrustedDirectory(foreign), /owned by uid/);
    }
});

test("the runtime root and ~/.memwal are created 0700, not at the umask default", (t) => {
    if (!POSIX) return;
    const home = mkdtempSync(join(tmpdir(), "memwal-home-mode-"));
    t.after(() => rmSync(home, { recursive: true, force: true }));

    const previousHome = process.env.HOME;
    t.after(() => {
        if (previousHome === undefined) delete process.env.HOME;
        else process.env.HOME = previousHome;
    });
    process.env.HOME = home;

    const root = prepareRuntimeRoot(join(home, ".memwal", "runtime"));
    assert.equal(lstatSync(root).mode & 0o7777, 0o700);
    // The launcher can run before the first login, so it is this call that creates
    // ~/.memwal — the directory credentials.json later lands in.
    assert.equal(lstatSync(join(home, ".memwal")).mode & 0o7777, 0o700);

    // An override root is created 0700 as well, parents included.
    const override = prepareRuntimeRoot(join(home, "elsewhere", "runtime"));
    assert.equal(lstatSync(override).mode & 0o7777, 0o700);
});

test("the install never runs package scripts and never inherits the registry", () => {
    const args = installArguments(`${MCP_PACKAGE_NAME}@${PIN}`, "/tmp/staging");
    assert.ok(args.includes("--ignore-scripts"), `--ignore-scripts missing from ${args.join(" ")}`);
    assert.ok(
        args.includes(`--registry=${MCP_REGISTRY}`),
        `an explicit registry is missing from ${args.join(" ")}`,
    );
    assert.equal(MCP_REGISTRY, "https://registry.npmjs.org/");

    // npm puts the environment above every .npmrc, so a repository-supplied MCP env
    // block would otherwise choose the registry no matter what cwd we install from.
    const env = installEnvironment({
        PATH: "/usr/bin",
        HOME: "/home/user",
        NPM_CONFIG_REGISTRY: "http://attacker.example/",
        npm_config_registry: "http://attacker.example/",
        npm_config_ca: "-----BEGIN CERTIFICATE-----",
        npm_config_ignore_scripts: "false",
        NODE_OPTIONS: "--require /tmp/evil.js",
    });
    assert.equal(env.PATH, "/usr/bin");
    assert.equal(env.HOME, "/home/user");
    assert.equal(env.npm_config_registry, MCP_REGISTRY);
    assert.equal(env.npm_config_ignore_scripts, "true");
    assert.equal(env.NPM_CONFIG_REGISTRY, undefined);
    assert.equal(env.npm_config_ca, undefined);
    assert.equal(env.NODE_OPTIONS, undefined);
});

test("npm is spawned as node <npm-cli.js>, with no .cmd and no shell, on win32 too", () => {
    const nodeExe = "C:\\Program Files\\nodejs\\node.exe";
    const npmCli = "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js";
    const args = installArguments("pkg@1.0.0", "C:\\Users\\a b\\.memwal\\runtime\\staging");

    const plan = npmSpawnPlan({ kind: "js", path: npmCli }, args, {
        platform: "win32",
        execPath: nodeExe,
    });

    assert.equal(plan.command, nodeExe);
    assert.equal(plan.shell, false, "node.exe must never be spawned through a shell");
    assert.deepEqual(plan.args, [npmCli, ...args]);
    // Arguments go straight to the process, so they are NOT shell-quoted here.
    assert.ok(plan.args.includes("C:\\Users\\a b\\.memwal\\runtime\\staging"));
});

test("the win32 npm.cmd fallback uses shell:true with cmd.exe-quoted arguments", () => {
    // Since the CVE-2024-27980 fix (Node >= 18.20.2 / 20.12.2 / 21.7.3) spawning a
    // .cmd without shell:true is EINVAL, which used to mean the server never started
    // on Windows at all: ensureTrustedEntry -> install -> throw -> exit 1.
    const npmCmd = "C:\\Program Files\\nodejs\\npm.cmd";
    const staging = "C:\\Users\\a b\\.memwal\\runtime\\staging";
    const plan = npmSpawnPlan({ kind: "bin", path: npmCmd }, installArguments("pkg@1.0.0", staging), {
        platform: "win32",
    });

    assert.equal(plan.shell, true, "a .cmd target needs shell:true or spawnSync returns EINVAL");
    assert.equal(plan.command, `"${npmCmd}"`, "the command path contains a space and must be quoted");
    assert.ok(plan.args.includes(`"${staging}"`), "a path with a space must reach cmd.exe quoted");
    assert.ok(plan.args.includes("--ignore-scripts"));
    assert.ok(plan.args.includes(`--registry=${MCP_REGISTRY}`));
    // Flags without metacharacters stay bare, so the command line stays readable.
    assert.ok(plan.args.includes("install"));
    assert.ok(plan.args.includes("pkg@1.0.0"));
});

test("quoteWindowsArgument quotes what cmd.exe would otherwise eat", () => {
    assert.equal(quoteWindowsArgument("install"), "install");
    assert.equal(quoteWindowsArgument("@scope/pkg@1.0.0"), "@scope/pkg@1.0.0");
    assert.equal(quoteWindowsArgument("C:\\a b\\c"), '"C:\\a b\\c"');
    assert.equal(quoteWindowsArgument("a&b"), '"a&b"');
    assert.equal(quoteWindowsArgument('say "hi"'), '"say \\"hi\\""');
});

test("a posix npm binary is spawned directly, never through a shell", () => {
    const plan = npmSpawnPlan({ kind: "bin", path: "/usr/local/bin/npm" }, ["install"], {
        platform: "linux",
    });
    assert.equal(plan.command, "/usr/local/bin/npm");
    assert.equal(plan.shell, false);
    assert.deepEqual(plan.args, ["install"]);
    assert.throws(() => npmSpawnPlan({ kind: "none", path: null }, ["install"]), /could not locate npm/);
});

test("resolveNpm returns an absolute path and skips PATH entries inside the project", (t) => {
    const found = resolveNpm();
    assert.notEqual(found.kind, "none", "npm must be resolvable in the test environment");
    assert.ok(resolve(found.path) === found.path, `${found.path} is not absolute`);

    const project = makeHostileProject(t);
    const projectBin = join(project.dir, "node_modules", ".bin");
    mkdirSync(projectBin, { recursive: true });
    writeFileSync(join(projectBin, "npm"), "#!/bin/sh\necho PROJECT_NPM\n");
    chmodSync(join(projectBin, "npm"), 0o755);

    const elsewhere = mkdtempSync(join(tmpdir(), "memwal-npm-"));
    t.after(() => rmSync(elsewhere, { recursive: true, force: true }));
    writeFileSync(join(elsewhere, "npm"), "#!/bin/sh\necho OUTSIDE_NPM\n");
    chmodSync(join(elsewhere, "npm"), 0o755);

    // An execPath with no npm layout next to it forces the PATH scan.
    const bare = mkdtempSync(join(tmpdir(), "memwal-bare-node-"));
    t.after(() => rmSync(bare, { recursive: true, force: true }));
    const resolved = resolveNpm({
        execPath: join(bare, "node"),
        platform: "linux",
        env: { PATH: [".", "relative/bin", projectBin, elsewhere].join(":") },
        cwd: project.dir,
    });

    assert.equal(resolved.kind, "bin");
    assert.equal(canonicalPath(resolved.path), canonicalPath(join(elsewhere, "npm")));
    assert.ok(!resolved.path.includes(project.dir), "npm must never come out of the project");
});

test("a client started in the home directory still gets the default root", (t) => {
    // enclosingProjectRoot() must not treat $HOME as a project: ~/.memwal/runtime is
    // inside the home directory by design, and refusing it would break every client
    // that starts its servers there.
    const home = mkdtempSync(join(tmpdir(), "memwal-home-cwd-"));
    t.after(() => rmSync(home, { recursive: true, force: true }));
    const target = join(home, ".memwal", "runtime", `memwal-mcp@${PIN}`);
    mkdirSync(target, { recursive: true });
    const entry = plantPackage(target, { version: PIN, marker: TRUSTED_MARKER });

    const result = runLauncher(["--print-entry"], {
        cwd: home,
        env: { HOME: home, USERPROFILE: home, MEMWAL_MCP_RUNTIME_DIR: "" },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), entry);
});

test("a subdirectory of the home directory is a project again", (t) => {
    const home = mkdtempSync(join(tmpdir(), "memwal-home-sub-"));
    t.after(() => rmSync(home, { recursive: true, force: true }));
    const project = join(home, "code", "victim");
    mkdirSync(project, { recursive: true });
    writeFileSync(join(project, "package.json"), JSON.stringify({ name: "victim" }));
    const planted = join(project, ".memwal-runtime");
    mkdirSync(installDir(PIN, planted), { recursive: true });
    plantPackage(installDir(PIN, planted), { version: PIN, marker: LOCAL_MARKER });

    const result = runLauncher(["--print-entry"], {
        cwd: project,
        env: { HOME: home, USERPROFILE: home, MEMWAL_MCP_RUNTIME_DIR: planted },
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /inside the project tree/);
    assert.doesNotMatch(result.stdout, new RegExp(LOCAL_MARKER));
});

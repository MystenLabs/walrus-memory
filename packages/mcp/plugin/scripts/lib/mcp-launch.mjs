/**
 * Trusted-path resolution for the MemWal MCP server (WALM-640).
 *
 * The plugin used to start the server with `npx -y @mysten-incubation/memwal-mcp@<pin>`.
 * npx resolves a package name against the *current working directory* first, and an
 * MCP client starts its servers in the project the user has open. A project that
 * carries an installed package of the same name whose `version` matches the pin
 * therefore wins: the pinned `npx` command ran the project's own binary, offline,
 * with the user's credentials in reach. The version pin does not help, because the
 * fake package simply claims the pinned version.
 *
 * The fix is to stop resolving a *name* in an untrusted directory and to run an
 * *absolute path* inside a directory we own:
 *
 *   ~/.memwal/runtime/memwal-mcp@<version>/node_modules/@mysten-incubation/memwal-mcp
 *
 * What "a directory we own" means is enforced, not assumed. The runtime root — the
 * default one just as much as a `MEMWAL_MCP_RUNTIME_DIR` override — must be an
 * absolute path outside the project tree the client started in, must be a real
 * directory (`lstat`, so a symlink is refused), must belong to the current uid, and
 * must not be group- or world-writable. We create it with mode 0700. An absolute
 * path is *not* by itself a trusted path: `${workspaceFolder}/.memwal-runtime` is
 * absolute too, and a repository can commit a whole tree there.
 *
 * The pinned version is installed there once with npm, and every later launch is a
 * plain `node <absolute entry point>`. Nothing here ever looks at `process.cwd()`,
 * at a project `node_modules`, or at a bin shim found through PATH.
 *
 * Limits of the install step, stated plainly because a previous version of this
 * header overstated them:
 *
 *   - The install runs with `--ignore-scripts` and an explicitly pinned registry,
 *     and the `npm_config_*` / `NODE_OPTIONS` environment is scrubbed for that one
 *     spawn, so a repository-supplied client env block cannot redirect it. npm is
 *     invoked as `node <npm-cli.js>` resolved from `process.execPath` where that
 *     layout exists; only if it does not do we fall back to scanning PATH entries
 *     ourselves, skipping relative entries and entries inside the project tree.
 *   - Verification of the installed tree is a manifest check (name, pinned version,
 *     a `bin` that resolves back inside the package directory) plus the ownership
 *     and permission checks above. It is not a signature or integrity check of the
 *     package contents: it establishes *where* the code came from and that nobody
 *     else can write it, not that the registry served what a reviewer read.
 *
 * The version pin lives in exactly one place — `plugin/plugin.json` — so the
 * manifests cannot drift from the version that actually gets installed. It is
 * that file's `version`, which the release verifier keeps equal to
 * `packages/mcp/package.json`, unless `mcpPackageVersion` overrides it for the
 * window where the release version is bumped in-tree but not yet on npm.
 */
import {
    existsSync,
    lstatSync,
    mkdirSync,
    mkdtempSync,
    readFileSync,
    realpathSync,
    renameSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, delimiter, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";

export const MCP_PACKAGE_NAME = "@mysten-incubation/memwal-mcp";
export const MCP_BIN_NAME = "memwal-mcp";

/**
 * The registry the reviewed version is installed from. Deliberately a constant and
 * not an environment lookup: npm puts environment configuration above every
 * `.npmrc`, so `npm_config_registry` in a repository-supplied MCP `env` block would
 * otherwise choose where our "trusted" code comes from. Behind a private registry,
 * pre-populate the runtime directory by hand (see packages/mcp/README.md) — the
 * launcher then finds the install and never runs npm at all.
 */
export const MCP_REGISTRY = "https://registry.npmjs.org/";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
/** plugin/scripts/lib -> plugin/scripts -> plugin */
export const PLUGIN_ROOT = dirname(dirname(SCRIPT_DIR));

/**
 * The single source of truth for the version the plugin launches: `version`, kept
 * equal to packages/mcp/package.json by scripts/verify-manual-sdk-release.mjs, or
 * `mcpPackageVersion` while that release version is not yet published — installing
 * a version npm does not have fails the launch outright.
 */
export function pinnedVersion(pluginRoot = PLUGIN_ROOT) {
    const manifest = JSON.parse(readFileSync(join(pluginRoot, "plugin.json"), "utf8"));
    const version = manifest.mcpPackageVersion ?? manifest.version;
    if (typeof version !== "string" || version.trim() === "") {
        throw new Error(
            `${join(pluginRoot, "plugin.json")} has no usable "mcpPackageVersion" or "version"`,
        );
    }
    return version;
}

function isInside(parent, child) {
    const rel = relative(parent, child);
    return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/**
 * Resolve symlinks in the part of a path that exists, keeping the rest verbatim.
 *
 * Without this, containment checks are comparing spellings rather than locations:
 * `/tmp/x` and `/private/tmp/x` are the same directory on macOS, and a symlink
 * inside a project is a one-line way to point a "safe looking" path back into it.
 */
export function canonicalPath(target) {
    let dir = resolve(target);
    const tail = [];
    for (;;) {
        try {
            return tail.length === 0 ? realpathSync(dir) : join(realpathSync(dir), ...tail);
        } catch {
            const parent = dirname(dir);
            if (parent === dir) return resolve(target);
            tail.unshift(basename(dir));
            dir = parent;
        }
    }
}

/**
 * The project tree the client started us in, or null when the working directory is
 * not usefully inside one (the home directory and the filesystem root are not
 * projects — treating them as such would refuse the default runtime root).
 *
 * "Project" is the *outermost* ancestor carrying a `.git`, else the outermost
 * carrying a `package.json`, and the working directory itself when neither is
 * found: a runtime root under any of those is a root a repository could have
 * shipped.
 *
 * Outermost, not nearest. Stopping at the first marker made a nested package its
 * own trust boundary, so in a monorepo a client started in `apps/web` treated
 * `apps/web` as the whole project and `assertRuntimeRootLocation` would accept an
 * override pointing at a sibling — `<repo>/.memwal-runtime`, say — as "outside the
 * project", even though the same repository controls it. `.git` is preferred over
 * `package.json` because it marks the checkout boundary rather than a workspace
 * member; a bare `package.json` tree still counts when there is no repository
 * around it at all (WALM-684).
 *
 * The walk keeps going past a match rather than returning, so a worktree's `.git`
 * *file* and a submodule's are found the same way a directory is.
 */
export function enclosingProjectRoot(
    cwd = process.cwd(),
    home = homedir(),
    { exists = existsSync } = {},
) {
    const start = canonicalPath(cwd);
    const stop = canonicalPath(home);
    const marked = (() => {
        let dir = start;
        let outermostRepo = null;
        let outermostPackage = null;
        while (dir !== stop) {
            const parent = dirname(dir);
            // The filesystem root is never a candidate, the same way home is not.
            // Walking to the *outermost* marker made a stray `/package.json` or
            // `/.git` — common in container images built with WORKDIR / — win over
            // the real checkout below it, and a project of `/` then disables the
            // guard entirely (see the null return below). Nearest-marker never hit
            // this; outermost has to exclude it explicitly.
            if (parent === dir) break;
            if (exists(join(dir, ".git"))) outermostRepo = dir;
            if (exists(join(dir, "package.json"))) outermostPackage = dir;
            dir = parent;
        }
        return outermostRepo ?? outermostPackage;
    })();
    const project = marked ?? start;
    if (project === stop || project === dirname(project)) return null;
    return project;
}

/**
 * Absoluteness is not trust. `${workspaceFolder}/.memwal-runtime` expands to an
 * absolute path inside the repository, and a repository can commit a complete fake
 * install there; the launcher would then find it, skip the install, and run it.
 */
export function assertRuntimeRootLocation(root, { cwd = process.cwd() } = {}) {
    const resolved = resolve(root);
    const canonical = canonicalPath(resolved);
    // The project root contains the working directory, so checking it also catches a
    // root planted below the cwd. When there is no project (the client started in the
    // home directory, say) there is nothing to refuse: `~/.memwal/runtime` is inside
    // the home directory by design.
    const project = enclosingProjectRoot(cwd);
    if (
        project !== null &&
        (canonical === project || isInside(project, canonical) || isInside(canonical, project))
    ) {
        throw new Error(
            `refusing to use "${resolved}" as the MemWal runtime directory: it is ` +
                `inside the project tree at "${project}". A runtime root must live outside ` +
                `any directory a project can write — being an absolute path is not ` +
                `enough, since a client expands "\${workspaceFolder}" to one.`,
        );
    }
    return resolved;
}

/**
 * Root of the trusted install area. `MEMWAL_MCP_RUNTIME_DIR` may relocate it, but
 * only to an absolute path outside the project the client has open: a relative path
 * would resolve against that project, and an absolute path inside it is the same
 * attack with an extra step.
 */
export function runtimeRoot() {
    const override = process.env.MEMWAL_MCP_RUNTIME_DIR;
    if (override !== undefined && override !== "") {
        if (!isAbsolute(override)) {
            throw new Error(
                `MEMWAL_MCP_RUNTIME_DIR must be an absolute path, received "${override}"`,
            );
        }
        return assertRuntimeRootLocation(override);
    }
    return assertRuntimeRootLocation(join(homedir(), ".memwal", "runtime"));
}

/** One directory per pinned version, so an upgrade never mutates a running install. */
export function installDir(version = pinnedVersion(), root = runtimeRoot()) {
    return join(root, `${MCP_BIN_NAME}@${version}`);
}

/**
 * Verify a directory we are about to trust with executable code, with the same
 * checks MemWal applies to the state directories it owns: `lstat` (so a symlink
 * never passes as a directory), a real directory, owned by the current uid, and
 * not group- or world-writable.
 *
 * Returns false when the directory does not exist, true when it exists and is
 * trustworthy, and throws otherwise. On Windows there is no meaningful uid or mode,
 * so only the "is a real directory" half applies.
 */
export function verifyTrustedDirectory(dir, { label = dir } = {}) {
    let stats;
    try {
        stats = lstatSync(dir);
    } catch (err) {
        if (err?.code === "ENOENT") return false;
        throw new Error(`could not inspect ${label}: ${err?.message ?? String(err)}`);
    }
    if (!stats.isDirectory()) {
        throw new Error(
            `${label} is not a directory (a symlink or file there could redirect the ` +
                `MemWal runtime into a tree we do not control)`,
        );
    }
    const uid = typeof process.getuid === "function" ? process.getuid() : null;
    if (uid === null) return true;
    if (stats.uid !== uid) {
        throw new Error(
            `${label} is owned by uid ${stats.uid}, not by the current user (uid ${uid}); ` +
                `refusing to run code from a directory somebody else controls`,
        );
    }
    if ((stats.mode & 0o022) !== 0) {
        throw new Error(
            `${label} is group- or world-writable (mode ${(stats.mode & 0o7777)
                .toString(8)
                .padStart(4, "0")}); another account could replace the entry point we ` +
                `trust. Run: chmod 700 ${label}`,
        );
    }
    return true;
}

/**
 * Create the runtime root (mode 0700) if it is missing and verify it either way.
 * For the default layout the `~/.memwal` parent is prepared the same way: the
 * launcher can run before the first login, and `credentials.json` is written into
 * that directory later by a `mkdirSync` that is a no-op once it exists.
 */
export function prepareRuntimeRoot(root) {
    const resolved = resolve(root);
    const managed = [];
    const defaultRoot = join(homedir(), ".memwal", "runtime");
    if (resolved === resolve(defaultRoot)) managed.push(dirname(resolved));
    managed.push(resolved);

    for (const dir of managed) {
        if (verifyTrustedDirectory(dir)) continue;
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        verifyTrustedDirectory(dir);
    }
    return resolved;
}

/**
 * The absolute entry point of the pinned package inside `dir`, or null when `dir`
 * does not hold a usable install. Never throws for a merely-absent install; throws
 * only when a present install is malformed in a way worth surfacing.
 */
export function resolveInstalledEntry(dir, version) {
    const packageDir = join(dir, "node_modules", ...MCP_PACKAGE_NAME.split("/"));
    const manifestPath = join(packageDir, "package.json");
    if (!existsSync(manifestPath)) return null;

    let manifest;
    try {
        manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    } catch {
        return null;
    }
    if (manifest.name !== MCP_PACKAGE_NAME) return null;
    if (version !== undefined && manifest.version !== version) return null;

    const bin = manifest.bin;
    const relBin = typeof bin === "string" ? bin : bin?.[MCP_BIN_NAME];
    if (typeof relBin !== "string" || relBin === "") return null;

    const entry = resolve(packageDir, relBin);
    if (!isInside(packageDir, entry)) {
        throw new Error(
            `${manifestPath} declares a bin outside its own package directory (${entry})`,
        );
    }
    if (!existsSync(entry)) return null;
    return entry;
}

/**
 * Locate npm without going through PATH resolution where that is possible.
 *
 * Preferred result is npm's JS entry point next to the running node binary, which
 * we then run as `node npm-cli.js`. That avoids a PATH-relative binary entirely and
 * also sidesteps the Windows `spawnSync("npm.cmd")` EINVAL that CVE-2024-27980's
 * fix introduced for `.cmd`/`.bat` targets spawned without a shell.
 *
 * Only if no such layout exists do we scan PATH ourselves — skipping empty and
 * relative entries and anything inside the project tree, which is what an inherited
 * PATH could otherwise smuggle in.
 */
export function resolveNpm({
    execPath = process.execPath,
    platform = process.platform,
    env = process.env,
    cwd = process.cwd(),
} = {}) {
    const execDirs = [dirname(execPath)];
    try {
        const real = dirname(realpathSync(execPath));
        if (!execDirs.includes(real)) execDirs.push(real);
    } catch {
        /* execPath should always resolve; a failure just means one fewer candidate */
    }

    const relativeLayouts =
        platform === "win32"
            ? [
                  ["node_modules", "npm", "bin", "npm-cli.js"],
                  ["..", "node_modules", "npm", "bin", "npm-cli.js"],
              ]
            : [
                  ["..", "lib", "node_modules", "npm", "bin", "npm-cli.js"],
                  ["..", "..", "..", "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"],
                  ["node_modules", "npm", "bin", "npm-cli.js"],
              ];

    for (const dir of execDirs) {
        for (const layout of relativeLayouts) {
            const candidate = resolve(join(dir, ...layout));
            if (existsSync(candidate)) return { kind: "js", path: candidate };
        }
    }

    const project = enclosingProjectRoot(cwd);
    const binNames = platform === "win32" ? ["npm.cmd", "npm.exe", "npm"] : ["npm"];
    for (const rawEntry of String(env.PATH ?? env.Path ?? "").split(delimiter)) {
        const entry = rawEntry.trim();
        // A relative PATH entry resolves against the project the client started in.
        if (entry === "" || !isAbsolute(entry)) continue;
        const dir = canonicalPath(entry);
        if (project && (dir === project || isInside(project, dir))) continue;

        // A node installation reached through PATH still usually ships npm's JS entry
        // point next to it; prefer that over the shim.
        for (const layout of relativeLayouts) {
            const candidate = resolve(join(dir, ...layout));
            if (existsSync(candidate)) return { kind: "js", path: candidate };
        }
        for (const name of binNames) {
            const candidate = join(dir, name);
            if (existsSync(candidate)) return { kind: "bin", path: candidate };
        }
    }
    return { kind: "none", path: null };
}

/** cmd.exe quoting for the one case where we must go through a shell. */
export function quoteWindowsArgument(value) {
    const text = String(value);
    if (text !== "" && !/[\s"^&|<>()%!]/.test(text)) return text;
    return `"${text.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
}

/**
 * Turn a resolved npm into an actual spawn plan.
 *
 * `kind: "js"` is the path we want everywhere: `node npm-cli.js …`, no shell, no
 * PATH. `kind: "bin"` on win32 is `npm.cmd`, which since Node 18.20.2 / 20.12.2 /
 * 21.7.3 cannot be spawned without `shell: true` (EINVAL) — so that branch sets it
 * and quotes every argument for cmd.exe itself.
 */
export function npmSpawnPlan(npm, args, { platform = process.platform, execPath = process.execPath } = {}) {
    if (npm.kind === "js") {
        return { command: execPath, args: [npm.path, ...args], shell: false };
    }
    if (npm.kind === "bin") {
        if (platform === "win32") {
            return {
                command: quoteWindowsArgument(npm.path),
                args: args.map(quoteWindowsArgument),
                shell: true,
            };
        }
        return { command: npm.path, args, shell: false };
    }
    throw new Error(
        "could not locate npm: no npm-cli.js next to the running node binary and no " +
            "usable npm on PATH outside the project directory",
    );
}

/** Environment for the install spawn: the caller's, minus everything npm reads from it. */
export function installEnvironment(env = process.env) {
    const scrubbed = {};
    for (const [key, value] of Object.entries(env)) {
        if (/^npm_config_/i.test(key)) continue;
        if (/^npm_package_/i.test(key)) continue;
        if (key === "NODE_OPTIONS") continue;
        scrubbed[key] = value;
    }
    // Belt and braces: even if a key slipped through the filter above, these lose to
    // the command line flags we pass, and npm resolves its own config from here.
    scrubbed.npm_config_registry = MCP_REGISTRY;
    scrubbed.npm_config_ignore_scripts = "true";
    return scrubbed;
}

/** The install arguments, exported so the tests can assert the hardening flags. */
export function installArguments(spec, staging) {
    return [
        "install",
        spec,
        "--prefix",
        staging,
        // The package tree is fetched and unpacked, never executed: npm would
        // otherwise run preinstall/install/postinstall of the whole dependency tree
        // as the user, before any of our verification runs.
        "--ignore-scripts",
        "--json",
        `--registry=${MCP_REGISTRY}`,
        "--no-audit",
        "--no-fund",
        "--no-save",
        "--loglevel=error",
    ];
}

/** Only an exact missing-version npm error can use the reviewed bootstrap. */
export function isMissingPinnedVersion(result, version) {
    try {
        const error = JSON.parse(result.stdout).error;
        return error?.code === "ETARGET"
            && error.summary === `No matching version found for ${MCP_PACKAGE_NAME}@${version}.`;
    } catch { return false; }
}

/** No fallback on network, integrity, permissions or dependency failures. */
export function resolvePinnedEntry(preferred, bootstrap, load) {
    try { return load(preferred); }
    catch (error) {
        if (!bootstrap || bootstrap === preferred
            || error?.code !== "MCP_VERSION_UNAVAILABLE" || error.version !== preferred) throw error;
        return load(bootstrap);
    }
}

/**
 * Install the pinned version into the trusted area and return its absolute entry
 * point. Staged in a sibling temp directory and renamed into place, so a second
 * client starting at the same moment either wins the rename or finds the finished
 * install — neither ever reads a half-written tree.
 */
function install(version, root) {
    const target = installDir(version, root);
    const staging = mkdtempSync(join(root, `.staging-${MCP_BIN_NAME}-`));

    try {
        // A private manifest stops npm from walking up out of the trusted area
        // looking for a package.json to attach the install to.
        writeFileSync(
            join(staging, "package.json"),
            JSON.stringify(
                { name: "memwal-mcp-runtime", version: "0.0.0", private: true },
                null,
                2,
            ) + "\n",
        );

        const spec = `${MCP_PACKAGE_NAME}@${version}`;
        const npm = resolveNpm();
        const plan = npmSpawnPlan(npm, installArguments(spec, staging));
        const result = spawnSync(plan.command, plan.args, {
            // cwd inside the trusted area: npm reads .npmrc from cwd upward, and the
            // project's .npmrc must not get to choose the registry we install the
            // reviewed version from. (The environment outranks every .npmrc, which is
            // why installEnvironment() scrubs it as well.)
            cwd: staging,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
            shell: plan.shell,
            env: installEnvironment(),
        });
        if (result.error) {
            throw new Error(`could not run npm (${npm.path}): ${result.error.message}`);
        }
        if (result.status !== 0) {
            if (isMissingPinnedVersion(result, version)) {
                const error = new Error(`The pinned ${MCP_PACKAGE_NAME}@${version} is not published`);
                error.code = "MCP_VERSION_UNAVAILABLE";
                error.version = version;
                throw error;
            }
            throw new Error(
                `npm install ${spec} failed (exit ${result.status}): ` +
                    `${(result.stderr || result.stdout || "").trim()}`,
            );
        }

        const staged = resolveInstalledEntry(staging, version);
        if (!staged) {
            throw new Error(
                `npm install ${spec} reported success but produced no usable ` +
                    `${MCP_PACKAGE_NAME} entry point in ${staging}`,
            );
        }

        try {
            renameSync(staging, target);
        } catch (err) {
            // Lost the race, or a previous run left the directory behind: fall back to
            // whatever is at the final path, but only if it verifies.
            verifyTrustedDirectory(target);
            const existing = resolveInstalledEntry(target, version);
            if (!existing) throw err;
            return existing;
        }
    } finally {
        rmSync(staging, { recursive: true, force: true });
    }

    const entry = resolveInstalledEntry(target, version);
    if (!entry) {
        throw new Error(`installed ${MCP_PACKAGE_NAME}@${version} is missing from ${target}`);
    }
    return entry;
}

/**
 * The absolute path the plugin should launch. Installs the pinned version into the
 * trusted area on first use; later calls are a stat of a known path.
 *
 * A reviewed bootstrap is permitted only for npm's exact missing-version error.
 * Every candidate uses the same trusted install path and verification; the launcher
 * never resolves a package from the user's project.
 */
export function ensureTrustedEntry(options = {}) {
    const { version = pinnedVersion(), root = runtimeRoot() } = options;
    const trustedRoot = prepareRuntimeRoot(assertRuntimeRootLocation(root));
    const manifest = options.version === undefined
        ? JSON.parse(readFileSync(join(PLUGIN_ROOT, "plugin.json"), "utf8")) : {};
    const bootstrap = manifest.mcpBootstrapVersion;
    if (bootstrap !== undefined && !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(bootstrap)) {
        throw new Error("Invalid MCP bootstrap version");
    }
    return resolvePinnedEntry(version, bootstrap, candidate => {
        const dir = installDir(candidate, trustedRoot);
        if (verifyTrustedDirectory(dir)) {
            const existing = resolveInstalledEntry(dir, candidate);
            if (existing) return existing;
        }
        return install(candidate, trustedRoot);
    });
}

/** Exported for the regression test: the path we expect, without installing anything. */
export function expectedEntryPath({ version = pinnedVersion(), root = runtimeRoot() } = {}) {
    return join(
        installDir(version, root),
        "node_modules",
        ...MCP_PACKAGE_NAME.split("/"),
        "dist",
        "bin",
        `${MCP_BIN_NAME}.js`,
    );
}

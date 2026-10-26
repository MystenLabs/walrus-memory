#!/usr/bin/env node
/**
 * Write a migration completion artifact JSON file.
 *
 *   node scripts/write-migration-completion-artifact.mjs \
 *     --package-id 0x… --manifest-sha256 <64-hex> \
 *     --imported N --skipped N --verified true \
 *     --approver user:alice --out artifact.json
 *
 * Flags override env of the same name. Missing required fields exit 1.
 * See internal/ops/migration-completion-artifact.md.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const USAGE = `Write a migration completion artifact JSON file.

Usage:
  node scripts/write-migration-completion-artifact.mjs \\
    --package-id <id> --manifest-sha256 <64-hex> \\
    --imported <n> --skipped <n> --verified <true|false> \\
    --approver <who> --out <file>

Flags (override env):
  --package-id        PACKAGE_ID         target package id
  --manifest-sha256   MANIFEST_SHA256    reviewed manifest digest
  --imported          IMPORTED           imported count
  --skipped           SKIPPED            skipped count
  --verified          VERIFIED           verification result (true|false)
  --approver          APPROVER           ceremony approver
  --out               OUT                output JSON path

  --force             replace an existing --out file (flag only, no env)

  --help, -h          print this help
  --self-test         write/read round-trip and missing-field checks
`;

const REQUIRED = [
    ["package-id", "PACKAGE_ID"],
    ["manifest-sha256", "MANIFEST_SHA256"],
    ["imported", "IMPORTED"],
    ["skipped", "SKIPPED"],
    ["verified", "VERIFIED"],
    ["approver", "APPROVER"],
    ["out", "OUT"],
];

// Every flag the parser accepts. An unrecognized --flag is a typo, and a typo
// on a value flag would otherwise fall through to the env var of the same name
// and record something the operator never typed.
const KNOWN_FLAGS = new Set([
    ...REQUIRED.map(([flag]) => flag),
    "force",
    "help",
    "h",
    "self-test",
]);

function main(argv = process.argv.slice(2), env = process.env) {
    const flags = parseArgv(argv);
    if (flags.has("help") || flags.has("h")) {
        process.stdout.write(USAGE);
        return 0;
    }
    if (flags.has("self-test")) {
        selfTest();
        return 0;
    }

    const raw = Object.fromEntries(
        REQUIRED.map(([flag, envName]) => [flag, valueOf(flags, env, flag, envName)]),
    );
    const missing = REQUIRED.filter(([flag]) => raw[flag] === "").map(
        ([flag, envName]) => `--${flag} (or ${envName})`,
    );
    if (missing.length > 0) {
        process.stderr.write(`missing required fields: ${missing.join(", ")}\n`);
        return 1;
    }

    let artifact;
    try {
        artifact = buildArtifact(raw);
    } catch (error) {
        process.stderr.write(`${error.message}\n`);
        return 1;
    }

    const outPath = path.resolve(raw.out);
    if (statSync(outPath, { throwIfNoEntry: false })?.isDirectory()) {
        // "wx" reports EEXIST for a directory, so without this the operator is
        // told to pass --force, which then fails with EISDIR.
        process.stderr.write(`--out is a directory, not a file: ${outPath}\n`);
        return 1;
    }
    mkdirSync(path.dirname(outPath), { recursive: true });
    try {
        // "wx" fails if the path exists: a completion artifact is an audit
        // record, so replacing one has to be deliberate.
        writeFileSync(outPath, `${JSON.stringify(artifact, null, 2)}\n`, {
            flag: flags.has("force") ? "w" : "wx",
        });
    } catch (error) {
        if (error.code !== "EEXIST") throw error;
        process.stderr.write(
            `refusing to overwrite existing artifact: ${outPath}\n` +
                "pass --force to replace it\n",
        );
        return 1;
    }
    process.stdout.write(`wrote ${outPath}\n`);
    return 0;
}

function parseArgv(argv) {
    const flags = new Map();
    for (let i = 0; i < argv.length; i += 1) {
        const arg = argv[i];
        if (arg === "--help" || arg === "-h") {
            flags.set("help", "true");
            continue;
        }
        if (arg === "--self-test") {
            flags.set("self-test", "true");
            continue;
        }
        if (arg === "--force") {
            flags.set("force", "true");
            continue;
        }
        if (!arg.startsWith("--")) {
            throw new Error(`unexpected argument: ${arg}`);
        }
        const eq = arg.indexOf("=");
        if (eq !== -1) {
            const name = assertKnown(arg.slice(2, eq));
            flags.set(name, arg.slice(eq + 1));
            continue;
        }
        const name = assertKnown(arg.slice(2));
        const next = argv[i + 1];
        if (next === undefined || next.startsWith("--")) {
            flags.set(name, "");
            continue;
        }
        flags.set(name, next);
        i += 1;
    }
    return flags;
}

function assertKnown(name) {
    if (!KNOWN_FLAGS.has(name)) {
        throw new Error(`unknown flag: --${name}`);
    }
    return name;
}

function valueOf(flags, env, flag, envName) {
    if (flags.has(flag)) return String(flags.get(flag) ?? "").trim();
    return String(env[envName] ?? "").trim();
}

function buildArtifact(raw) {
    const packageId = parsePackageId(raw["package-id"]);

    const manifestSha256 = parseManifestSha256(raw["manifest-sha256"]);
    const imported = parseCount(raw.imported, "imported");
    const skipped = parseCount(raw.skipped, "skipped");
    const verified = parseBoolean(raw.verified, "verified");
    const approver = raw.approver;
    if (!approver) throw new Error("approver is required");

    return {
        packageId,
        manifestSha256,
        imported,
        skipped,
        verified,
        approver,
        timestamp: new Date().toISOString(),
    };
}

/**
 * Mirrors assertObjectId() in scripts/assertions.ts, which is
 * isValidSuiObjectId() + normalizeSuiAddress() from @mysten/sui/utils: a Sui
 * object id is exactly 32 bytes of hex, optionally 0x-prefixed, and normalizes
 * to lowercase with the prefix. Reimplemented rather than imported because the
 * CI job runs this under bare `node` with no install step. An artifact whose
 * packageId does not round-trip to what build-finalize-tx.ts used is not
 * evidence of anything, so reject instead of recording it verbatim.
 */
function parsePackageId(value) {
    const hex = /^0[xX]/.test(value) ? value.slice(2) : value;
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
        throw new Error(
            "packageId must be a Sui object id: 32 bytes of hex (64 characters),"
                + " optionally 0x-prefixed",
        );
    }
    return `0x${hex.toLowerCase()}`;
}

function parseManifestSha256(value) {
    if (!/^[0-9a-fA-F]{64}$/.test(value)) {
        throw new Error("manifestSha256 must be a 64-character hex digest");
    }
    return value.toLowerCase();
}

function parseCount(value, field) {
    if (!/^(0|[1-9][0-9]*)$/.test(value)) {
        throw new Error(`${field} must be a non-negative integer`);
    }
    const n = Number(value);
    if (!Number.isSafeInteger(n)) {
        throw new Error(`${field} must be a non-negative integer`);
    }
    return n;
}

function parseBoolean(value, field) {
    const normalized = value.toLowerCase();
    if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
    if (normalized === "false" || normalized === "0" || normalized === "no") return false;
    throw new Error(`${field} must be true or false`);
}

function selfTest() {
    const self = fileURLToPath(import.meta.url);
    const env = { ...process.env };
    for (const [, envName] of REQUIRED) delete env[envName];

    const help = spawnSync(process.execPath, [self, "--help"], {
        encoding: "utf8",
        env,
    });
    assert(help.status === 0, `help exit ${help.status}: ${help.stderr}`);
    assert(help.stdout.includes("--package-id"), "help missing --package-id");
    assert(help.stdout.includes("--manifest-sha256"), "help missing --manifest-sha256");

    const missing = spawnSync(process.execPath, [self], { encoding: "utf8", env });
    assert(missing.status === 1, `missing fields exit ${missing.status}`);
    assert(
        missing.stderr.includes("missing required fields"),
        `missing-field stderr: ${missing.stderr}`,
    );

    const dir = mkdtempSync(path.join(tmpdir(), "migration-completion-artifact-"));
    try {
        const out = path.join(dir, "artifact.json");
        const packageId = `0x${"ab".repeat(32)}`;
        const manifestSha256 = "a".repeat(64);
        const write = spawnSync(
            process.execPath,
            [
                self,
                "--package-id",
                packageId,
                "--manifest-sha256",
                manifestSha256,
                "--imported",
                "3",
                "--skipped",
                "1",
                "--verified",
                "true",
                "--approver",
                "user:alice",
                "--out",
                out,
            ],
            { encoding: "utf8", env },
        );
        assert(write.status === 0, `write exit ${write.status}: ${write.stderr}`);
        const before = readFileSync(out, "utf8");
        const artifact = JSON.parse(before);
        assert(artifact.packageId === packageId, "packageId mismatch");
        assert(artifact.manifestSha256 === manifestSha256, "manifestSha256 mismatch");
        assert(artifact.imported === 3, "imported mismatch");
        assert(artifact.skipped === 1, "skipped mismatch");
        assert(artifact.verified === true, "verified mismatch");
        assert(artifact.approver === "user:alice", "approver mismatch");
        assert(
            typeof artifact.timestamp === "string" &&
                /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(artifact.timestamp),
            `timestamp invalid: ${artifact.timestamp}`,
        );
        assert(
            JSON.stringify(Object.keys(artifact).sort()) ===
                JSON.stringify([
                    "approver",
                    "imported",
                    "manifestSha256",
                    "packageId",
                    "skipped",
                    "timestamp",
                    "verified",
                ]),
            `unexpected keys: ${Object.keys(artifact)}`,
        );

        // Same valid inputs as above, with per-case overrides appended.
        const run = (extra) =>
            spawnSync(
                process.execPath,
                [
                    self,
                    "--package-id",
                    packageId,
                    "--manifest-sha256",
                    manifestSha256,
                    "--imported",
                    "3",
                    "--skipped",
                    "1",
                    "--verified",
                    "true",
                    "--approver",
                    "user:alice",
                    ...extra,
                ],
                { encoding: "utf8", env },
            );

        // A second write to the same path must not clobber the record.
        const clobber = run(["--out", out]);
        assert(clobber.status === 1, `clobber exit ${clobber.status}`);
        assert(
            clobber.stderr.includes("refusing to overwrite existing artifact"),
            `clobber stderr: ${clobber.stderr}`,
        );
        assert(
            readFileSync(out, "utf8") === before,
            "refused write still modified the artifact",
        );

        // --force is the deliberate replace.
        const forced = run(["--out", out, "--skipped", "2", "--force"]);
        assert(forced.status === 0, `force exit ${forced.status}: ${forced.stderr}`);
        assert(
            JSON.parse(readFileSync(out, "utf8")).skipped === 2,
            "--force did not replace the artifact",
        );

        // A typo in a value flag must not fall through to the env var of the
        // same name and record something the operator never typed.
        const unknown = run(["--out", path.join(dir, "unknown.json"), "--aprover", "user:bob"]);
        assert(unknown.status === 1, `unknown flag exit ${unknown.status}`);
        assert(
            unknown.stderr.includes("unknown flag: --aprover"),
            `unknown flag stderr: ${unknown.stderr}`,
        );

        // A directory --out is caught before the overwrite check, which would
        // otherwise tell the operator to pass --force.
        const dirOut = run(["--out", dir]);
        assert(dirOut.status === 1, `directory --out exit ${dirOut.status}`);
        assert(
            dirOut.stderr.includes("--out is a directory"),
            `directory --out stderr: ${dirOut.stderr}`,
        );

        // packageId mirrors assertObjectId: reject non-ids and wrong lengths.
        const badIds = ["not-a-package-id", "0x2", `0x${"ab".repeat(31)}`, `0x${"a".repeat(65)}`];
        for (const bad of badIds) {
            const rejected = run(["--package-id", bad, "--out", path.join(dir, "bad.json")]);
            assert(rejected.status === 1, `bad packageId ${bad} exit ${rejected.status}`);
            assert(
                rejected.stderr.includes("packageId must be a Sui object id"),
                `bad packageId ${bad} stderr: ${rejected.stderr}`,
            );
        }

        // ...and normalizes case and the 0x prefix the way finalize-tx does.
        const normOut = path.join(dir, "normalized.json");
        const normalized = run([
            "--package-id",
            "AB".repeat(32),
            "--out",
            normOut,
        ]);
        assert(
            normalized.status === 0,
            `normalize exit ${normalized.status}: ${normalized.stderr}`,
        );
        assert(
            JSON.parse(readFileSync(normOut, "utf8")).packageId === `0x${"ab".repeat(32)}`,
            "packageId was not normalized to lowercase 0x form",
        );
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }

    process.stdout.write("self-test OK\n");
}

function assert(condition, message) {
    if (!condition) throw new Error(`self-test failed: ${message}`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
    try {
        process.exit(main());
    } catch (error) {
        process.stderr.write(`${error.message}\n`);
        process.exit(1);
    }
}

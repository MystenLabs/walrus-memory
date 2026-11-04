import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(__dirname, "../dist/bin/memwal-mcp.js");

function runCli(args, env = {}) {
    return spawnSync(process.execPath, [CLI, ...args], {
        encoding: "utf8",
        env: {
            ...process.env,
            MEMWAL_SERVER_URL: "",
            MEMWAL_NAMESPACE: "",
            MEMWAL_CLIENT_LABEL: "",
            ...env,
        },
    });
}

test("memwal-mcp status exits 1 with a clear message when logged out (non-TTY)", () => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-status-empty-"));
    try {
        const res = runCli(["status"], { MEMWAL_CREDS_DIR: dir });
        assert.equal(res.status, 1);
        assert.match(res.stderr, /Not logged in/);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("memwal-mcp status and whoami print full account, delegate, wallet, label, relayer, and namespace", () => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-status-creds-"));
    try {
        const creds = {
            version: 1,
            delegatePrivateKey: "11".repeat(32),
            delegatePublicKeyHex: "22".repeat(32),
            delegateAddress: `0x${"aa".repeat(32)}`,
            accountId: `0x${"bb".repeat(32)}`,
            walletAddress: `0x${"cc".repeat(32)}`,
            packageId: `0x${"dd".repeat(32)}`,
            relayerUrl: "https://relayer.memory.walrus.xyz",
            webUrl: "https://memory.walrus.xyz",
            label: "Cursor Laptop",
            createdAt: "2026-10-28T00:00:00.000Z",
        };
        writeFileSync(join(dir, "credentials.json"), JSON.stringify(creds, null, 2), {
            mode: 0o600,
        });

        const statusRes = runCli(["status"], { MEMWAL_CREDS_DIR: dir });
        assert.equal(statusRes.status, 0, statusRes.stderr);
        assert.ok(statusRes.stderr.includes(`Logged in as ${creds.walletAddress}`));
        assert.ok(statusRes.stderr.includes(`Account:   ${creds.accountId}`));
        assert.ok(statusRes.stderr.includes(`Delegate:  ${creds.delegateAddress}`));
        assert.ok(!statusRes.stderr.includes("Wallet:   "));
        assert.ok(statusRes.stderr.includes("Label:     Cursor Laptop"));
        assert.ok(statusRes.stderr.includes("Relayer:   https://relayer.memory.walrus.xyz"));
        assert.ok(statusRes.stderr.includes("Namespace: default (relayer default)"));
        assert.ok(!statusRes.stderr.includes("11".repeat(32)), "private key must not appear in output");

        const whoamiRes = runCli(
            ["whoami", "--relayer", "https://relayer.dev.memwal.ai", "--namespace", "work"],
            {
                MEMWAL_CREDS_DIR: dir,
            },
        );
        assert.equal(whoamiRes.status, 0, whoamiRes.stderr);
        assert.ok(
            whoamiRes.stderr.includes(
                "Relayer:   https://relayer.dev.memwal.ai (overrides saved https://relayer.memory.walrus.xyz via --relayer)",
            ),
        );
        assert.ok(whoamiRes.stderr.includes("Namespace: work (via --namespace)"));
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("memwal-mcp status enforces saved label precedence over env and flag", () => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-status-label-"));
    try {
        const creds = {
            version: 1,
            delegatePrivateKey: "11".repeat(32),
            delegatePublicKeyHex: "22".repeat(32),
            delegateAddress: `0x${"aa".repeat(32)}`,
            accountId: `0x${"bb".repeat(32)}`,
            walletAddress: `0x${"cc".repeat(32)}`,
            packageId: `0x${"dd".repeat(32)}`,
            relayerUrl: "https://relayer.memory.walrus.xyz",
            label: "SavedKey",
            createdAt: "2026-10-28T00:00:00.000Z",
        };
        writeFileSync(join(dir, "credentials.json"), JSON.stringify(creds, null, 2), {
            mode: 0o600,
        });

        const envRes = runCli(["status"], {
            MEMWAL_CREDS_DIR: dir,
            MEMWAL_CLIENT_LABEL: "EnvLabel",
        });
        assert.equal(envRes.status, 0, envRes.stderr);
        assert.ok(
            envRes.stderr.includes(
                "Label:     SavedKey (saved; MEMWAL_CLIENT_LABEL=EnvLabel is ignored when signed in)",
            ),
        );

        const flagRes = runCli(["status", "--label", "FlagLabel"], {
            MEMWAL_CREDS_DIR: dir,
        });
        assert.equal(flagRes.status, 0, flagRes.stderr);
        assert.ok(
            flagRes.stderr.includes(
                "Label:     SavedKey (saved; --label=FlagLabel is ignored when signed in)",
            ),
        );
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

test("memwal-mcp status reports relayer mismatch note and namespace precedence", () => {
    const dir = mkdtempSync(join(tmpdir(), "memwal-status-relayer-ns-"));
    try {
        const creds = {
            version: 1,
            delegatePrivateKey: "11".repeat(32),
            delegatePublicKeyHex: "22".repeat(32),
            delegateAddress: `0x${"aa".repeat(32)}`,
            accountId: `0x${"bb".repeat(32)}`,
            walletAddress: `0x${"cc".repeat(32)}`,
            packageId: `0x${"dd".repeat(32)}`,
            relayerUrl: "https://relayer.memory.walrus.xyz",
            createdAt: "2026-10-28T00:00:00.000Z",
        };
        writeFileSync(join(dir, "credentials.json"), JSON.stringify(creds, null, 2), {
            mode: 0o600,
        });

        const mismatchRes = runCli(["status"], {
            MEMWAL_CREDS_DIR: dir,
            MEMWAL_SERVER_URL: "https://relayer.dev.memwal.ai",
            MEMWAL_NAMESPACE: "team-shared",
        });
        assert.equal(mismatchRes.status, 0, mismatchRes.stderr);
        assert.ok(
            mismatchRes.stderr.includes(
                "Relayer:   https://relayer.memory.walrus.xyz (saved; MEMWAL_SERVER_URL=https://relayer.dev.memwal.ai is ignored when signed in; pass --relayer to override)",
            ),
        );
        assert.ok(mismatchRes.stderr.includes("Namespace: team-shared (via MEMWAL_NAMESPACE)"));

        const nsFlagRes = runCli(["status", "--ns", "custom-ns"], {
            MEMWAL_CREDS_DIR: dir,
            MEMWAL_NAMESPACE: "team-shared",
        });
        assert.equal(nsFlagRes.status, 0, nsFlagRes.stderr);
        assert.ok(nsFlagRes.stderr.includes("Namespace: custom-ns (via --namespace)"));
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});

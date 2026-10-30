import assert from "node:assert/strict";
import test from "node:test";

import { helpText, parseArgs } from "../dist/index.js";

// An unrecognised flag used to fall through parseArgs' default branch and
// vanish: a typo'd `--namesapce` still wrote to the relayer's "default"
// namespace with nothing on stderr to explain why. parseArgs now collects what
// it did not understand so main() can name it.

test("parseArgs collects a typo'd flag instead of dropping it", () => {
    const args = parseArgs(["--namesapce", "work"]);
    assert.deepEqual(args.unknown, ["--namesapce"]);
    // The typo must NOT have set the real namespace.
    assert.equal(args.namespace, undefined);
});

test("parseArgs reports every unknown flag, not just the first", () => {
    const args = parseArgs(["--nope", "--alsobad"]);
    assert.deepEqual(args.unknown, ["--nope", "--alsobad"]);
});

test("an unknown flag swallows its value rather than reporting it too", () => {
    // Warning once about `--namesapce` beats warning twice, the second time
    // naming the user's data. Also keeps a mistyped secret out of the logs.
    assert.deepEqual(parseArgs(["--tokenn", "hunter2"]).unknown, ["--tokenn"]);
});

test("an unknown flag does not swallow the flag that follows it", () => {
    const args = parseArgs(["--typo", "--prod"]);
    assert.deepEqual(args.unknown, ["--typo"]);
    assert.equal(args.relayerUrl, "https://relayer.memory.walrus.xyz");
});

test("a known flag after an unknown flag's value still applies", () => {
    const args = parseArgs(["--typo", "value", "--ns", "work"]);
    assert.deepEqual(args.unknown, ["--typo"]);
    assert.equal(args.namespace, "work");
});

test("an unknown flag does not swallow the `login` command", () => {
    // `login` is a command, not a value. Consuming it turned
    // `memwal-mcp --typo login` into a run that never logged in.
    const args = parseArgs(["--typo", "login"]);
    assert.deepEqual(args.unknown, ["--typo"]);
    assert.equal(args.forceLogin, true, "`login` was swallowed as a flag value");
});

test("an unknown `--key=value` flag reports the key and never the value", () => {
    // The warning goes to stderr, so a mistyped secret must not survive into it.
    const args = parseArgs(["--tokenn=hunter2"]);
    assert.deepEqual(args.unknown, ["--tokenn"]);
    assert.ok(
        !args.unknown.some((u) => u.includes("hunter2")),
        "the flag's value reached the warning",
    );
});

test("an unknown `--key=value` flag does not also swallow the next token", () => {
    // Its value is already attached, so the following token is someone else's.
    const args = parseArgs(["--tokenn=hunter2", "login"]);
    assert.deepEqual(args.unknown, ["--tokenn"]);
    assert.equal(args.forceLogin, true);
});

test("parseArgs treats no known flag as unknown", () => {
    const known = [
        "--help", "-h",
        "--logout",
        "--login", "login",
        "--approve-project", "approve-project",
        "--revoke-project", "revoke-project",
        "--prod", "--dev", "--staging", "--local",
        "--relayer", "https://r.example",
        "--relayer-url", "https://r.example",
        "--web-url", "https://w.example",
        "--web", "https://w.example",
        "--label", "my label",
        "--namespace", "ns",
        "--ns", "ns",
        "--relayer=https://r.example",
        "--web-url=https://w.example",
        "--label=my-label",
        "--namespace=ns",
        "--ns=ns",
    ];
    assert.deepEqual(parseArgs(known).unknown, []);
});

test("an unknown flag does not swallow the project-approval commands", () => {
    // They are commands, not values. Swallowing one turns an approval the user
    // typed into a run that silently approves nothing (WALM-639).
    for (const command of ["approve-project", "revoke-project"]) {
        const args = parseArgs(["--typo", command]);
        assert.deepEqual(args.unknown, ["--typo"]);
        assert.equal(
            command === "approve-project" ? args.approveProject : args.revokeProject,
            true,
            `\`${command}\` was swallowed as a flag value`,
        );
    }
});

test("--help documents how to approve project-local credentials", () => {
    // The gate is only actionable if the command that lifts it is discoverable.
    const help = helpText();
    assert.ok(help.includes("approve-project"), "approve-project missing from --help");
    assert.ok(help.includes("revoke-project"), "revoke-project missing from --help");
    assert.deepEqual(parseArgs(["approve-project"]).unknown, []);
});

test("parseArgs does not mistake a flag's value for an unknown flag", () => {
    // `next()` consumes the value, so "MCP Client" must never be reported.
    const args = parseArgs(["--label", "MCP Client"]);
    assert.deepEqual(args.unknown, []);
    assert.equal(args.label, "MCP Client");
});

test("env presets still resolve both URLs (regression guard)", () => {
    const args = parseArgs(["--prod"]);
    assert.equal(args.relayerUrl, "https://relayer.memory.walrus.xyz");
    assert.equal(args.webUrl, "https://memory.walrus.xyz");
    assert.deepEqual(args.unknown, []);
});

// Help must list every preset the parser honours, and stay listing them as
// presets are added.

test("--help documents every network preset the parser accepts", () => {
    const help = helpText();
    for (const preset of ["--prod", "--dev", "--staging", "--local"]) {
        // Not merely mentioned somewhere — parseArgs must accept it too.
        assert.deepEqual(parseArgs([preset]).unknown, [], `${preset} not accepted`);
        assert.ok(help.includes(preset), `${preset} missing from --help`);
    }
    // The URLs a preset resolves to are what tell you which network you're on.
    assert.ok(help.includes("https://relayer.dev.memwal.ai"));
    assert.ok(help.includes("http://127.0.0.1:8000"));
});

test("--help does not promise that flag order decides a preset override", () => {
    // Preset application is `??=`, so an explicit URL wins from either side.
    // Help used to say the flag overrides "the preset it follows".
    const help = helpText();
    assert.ok(!help.includes("the preset it follows"), "help still implies order matters");
    const before = parseArgs(["--relayer", "https://custom.example", "--prod"]);
    const after = parseArgs(["--prod", "--relayer", "https://custom.example"]);
    assert.equal(before.relayerUrl, "https://custom.example");
    assert.equal(after.relayerUrl, "https://custom.example");
});

test("parseArgs recognises status and whoami subcommands and flags", () => {
    for (const token of ["status", "--status", "whoami", "--whoami"]) {
        const args = parseArgs([token]);
        assert.equal(args.status, true, `${token} should set status=true`);
        assert.deepEqual(args.unknown, []);
    }
    const help = helpText();
    assert.ok(help.includes("memwal-mcp status"), "status missing from --help");
    assert.ok(help.includes("whoami"), "whoami missing from --help");
});

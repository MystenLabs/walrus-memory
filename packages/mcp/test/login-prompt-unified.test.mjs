/**
 * One sign-in prompt, whichever mode the user is in.
 *
 * `memwal_login` is answered locally in two places — the auth-required stub
 * when signed out, and the bridge when already signed in — and the two copies
 * had drifted: different assistant instructions, different step wording,
 * different closing line. Same tool, same user, two voices.
 *
 * They differ legitimately in exactly one respect: signing in while already
 * signed in REPLACES the stored delegate key, and that is worth saying. This
 * pins everything else as shared, so the next edit to one cannot silently
 * fork the other again.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

const { loginPrompt, remoteLoginCommand } = await import("../dist/messages.js");

const URL_ = "https://memory.example/connect/mcp?port=1&publicKey=ab&connectState=cd";
const CREDS = "/tmp/sandbox/.memwal/credentials.json";

const signedOut = loginPrompt({ url: URL_, credentialsPath: CREDS, signedIn: false });
const signedIn = loginPrompt({ url: URL_, credentialsPath: CREDS, signedIn: true });

test("both modes repeat the URL in all three forms", () => {
    // Deliberate armor against clients that paraphrase tool output: plain,
    // code-block, and link form, so at least one survives. Neither mode may
    // quietly drop it.
    for (const [name, text] of [["signed out", signedOut], ["signed in", signedIn]]) {
        assert.ok(text.includes(`**URL:** ${URL_}`), `${name}: plain URL`);
        assert.ok(text.includes(`\`\`\`\n${URL_}\n\`\`\``), `${name}: code-block URL`);
        assert.ok(text.includes(`](${URL_})`), `${name}: markdown link URL`);
    }
});

test("both modes give the assistant the same instruction and closing line", () => {
    const instruction = "**IMPORTANT for the assistant**";
    const closing = "_The login link stays valid for 5 minutes";

    const lineWith = (text, needle) =>
        text.split("\n").filter((l) => l.includes(needle)).join("\n");

    assert.equal(lineWith(signedOut, instruction), lineWith(signedIn, instruction));
    assert.equal(lineWith(signedOut, closing), lineWith(signedIn, closing));
});

test("both modes name the resolved credentials path, never a hardcoded home", () => {
    // Which file a sign-in lands in is exactly the confusion behind GH #628,
    // so neither mode may claim `~/.memwal/credentials.json` when the real
    // path is elsewhere.
    for (const [name, text] of [["signed out", signedOut], ["signed in", signedIn]]) {
        assert.ok(text.includes(CREDS), `${name}: should state the resolved path`);
        assert.ok(
            !text.includes("~/.memwal/credentials.json"),
            `${name}: should not hardcode the global path`,
        );
    }
});

test("only the signed-in prompt warns that the stored key is replaced", () => {
    assert.match(signedIn, /replac/i, "re-signing in overwrites the delegate key — say so");
    assert.doesNotMatch(
        signedOut,
        /replac/i,
        "a first sign-in replaces nothing; the warning would be a lie",
    );
});

test("a discarded key is named so it can be removed from the dashboard", () => {
    const publicKey = "ab".repeat(32);
    const address = "0x" + "cd".repeat(32);
    const text = loginPrompt({
        url: URL_,
        credentialsPath: CREDS,
        signedIn: false,
        discardedKey: { publicKey, address },
    });
    assert.ok(text.includes(publicKey));
    assert.ok(text.includes(address));
    assert.match(text, /remove it from the dashboard/);
});

test("the two prompts differ ONLY in that warning", () => {
    // Drop the warning, then collapse the blank line that separated it — the
    // claim under test is that no other CONTENT differs.
    const strip = (text) =>
        text
            .split("\n")
            .filter((l) => !/replac/i.test(l))
            .join("\n")
            .replace(/\n{3,}/g, "\n\n");
    assert.equal(strip(signedOut), strip(signedIn));
});

test("both modes state the same-machine browser requirement and remote host credential transfer", () => {
    for (const [name, text] of [["signed out", signedOut], ["signed in", signedIn]]) {
        assert.match(text, /same machine running this MCP server/i, `${name}: same-machine browser requirement`);
        assert.match(text, /remote host or bot/i, `${name}: remote host guidance`);
        assert.ok(text.includes(CREDS), `${name}: remote credential target path`);
    }
});

test("remote fallback retains environment presets and explicit relayer flags", () => {
    // Default prod URL
    assert.equal(
        remoteLoginCommand({ url: "https://memory.walrus.xyz/connect/mcp?port=1" }),
        "npx -y @mysten-incubation/memwal-mcp login",
    );
    // Dev preset from relayer query param
    assert.equal(
        remoteLoginCommand({
            url: "https://dev.memwal.ai/connect/mcp?port=1&relayer=https%3A%2F%2Frelayer.dev.memwal.ai",
        }),
        "npx -y @mysten-incubation/memwal-mcp login --dev",
    );
    // Dev preset from environment field
    assert.equal(
        remoteLoginCommand({ url: URL_, environment: "dev" }),
        "npx -y @mysten-incubation/memwal-mcp login --dev",
    );
    // Local preset from relayer query param
    assert.equal(
        remoteLoginCommand({
            url: "http://localhost:5173/connect/mcp?port=1&relayer=http%3A%2F%2F127.0.0.1%3A8000",
        }),
        "npx -y @mysten-incubation/memwal-mcp login --local",
    );
    // Staging preset
    assert.equal(
        remoteLoginCommand({ url: URL_, environment: "staging" }),
        "npx -y @mysten-incubation/memwal-mcp login --staging",
    );
    // Custom relayer
    assert.equal(
        remoteLoginCommand({
            url: "https://memory.example/connect/mcp?port=1&relayer=https%3A%2F%2Fcustom.relayer",
        }),
        "npx -y @mysten-incubation/memwal-mcp login --relayer https://custom.relayer",
    );

    // Prompt includes the --dev flag when dev URL is provided
    const devPrompt = loginPrompt({
        url: "https://dev.memwal.ai/connect/mcp?port=1&publicKey=ab&relayer=https%3A%2F%2Frelayer.dev.memwal.ai&connectState=cd",
        credentialsPath: CREDS,
        signedIn: false,
    });
    assert.match(devPrompt, /login --dev/, "prompt fallback preserves --dev flag");
});

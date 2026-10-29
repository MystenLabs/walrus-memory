import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { MemWalSession } from "../auth.js";
import {
    CONSENT_INSTRUCTION,
    ENABLE_PROACTIVE_PROMPT_DESCRIPTION,
    ENABLE_PROACTIVE_PROMPT_NAME,
    ENABLE_PROACTIVE_PROMPT_TITLE,
} from "../consent-instruction.js";
import { createMcpServer } from "../server.js";

test("prompts/list includes memwal_enable_proactive with the consent instruction", async (t) => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createMcpServer({
        oauthScope: "memwal:read memwal:write",
    } as MemWalSession);
    const client = new Client({ name: "prompts-test", version: "1.0.0" });

    t.after(async () => {
        await client.close();
        await server.close();
    });

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const { prompts } = await client.listPrompts();
    const prompt = prompts.find((p) => p.name === ENABLE_PROACTIVE_PROMPT_NAME);
    assert.ok(prompt, "memwal_enable_proactive must be listed");
    assert.equal(prompt.title, ENABLE_PROACTIVE_PROMPT_TITLE);
    assert.equal(prompt.description, ENABLE_PROACTIVE_PROMPT_DESCRIPTION);

    const got = await client.getPrompt({ name: ENABLE_PROACTIVE_PROMPT_NAME });
    assert.equal(got.messages[0]?.content?.type, "text");
    assert.equal(
        got.messages[0] && "text" in got.messages[0].content
            ? got.messages[0].content.text
            : undefined,
        CONSENT_INSTRUCTION,
    );
});

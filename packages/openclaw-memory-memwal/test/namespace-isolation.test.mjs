import assert from "node:assert/strict";
import test from "node:test";

import { resolveAgent, resolveToolNamespace } from "../dist/config.js";

test("resolveAgent prevents sub-agent namespace collision with main defaultNamespace", () => {
  const cases = [
    { defaultNs: "default", subSession: "agent:default:subagent:abc" },
    { defaultNs: "research", subSession: "agent:research:subagent:abc" },
    { defaultNs: "agent-research", subSession: "agent:agent-research:subagent:abc" },
    { defaultNs: "Research", subSession: "agent:Research:subagent:abc" },
  ];

  for (const { defaultNs, subSession } of cases) {
    const mainResolved = resolveAgent(defaultNs, "agent:main:discord:channel:1");
    const subResolved = resolveAgent(defaultNs, subSession);

    assert.equal(mainResolved.namespace, defaultNs);
    assert.notEqual(
      subResolved.namespace,
      defaultNs,
      `Sub-agent (${subSession}) namespace must not collide with defaultNamespace="${defaultNs}"`,
    );
    assert.notEqual(
      subResolved.legacyNamespace,
      defaultNs,
      `Sub-agent (${subSession}) legacyNamespace must not equal defaultNamespace="${defaultNs}"`,
    );
    assert.equal(
      resolveToolNamespace(defaultNs, subSession, defaultNs),
      undefined,
      `Sub-agent (${subSession}) must not be permitted to access defaultNamespace="${defaultNs}"`,
    );
    assert.equal(
      resolveToolNamespace(defaultNs, subSession, undefined),
      subResolved.namespace,
    );
  }
});

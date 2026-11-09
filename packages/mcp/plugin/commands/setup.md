---
description: Connect Walrus Memory and verify the MCP tools are ready.
argument-hint: [optional setup question]
---

Use the Walrus Memory setup skill and MCP tools to connect this client.

First call `memwal_health` if the tool is available. If credentials are missing, call `memwal_login` and guide the user through the browser wallet flow. After login, verify with `memwal_health`.

If `$ARGUMENTS` is not empty, address this setup question too:

```text
$ARGUMENTS
```

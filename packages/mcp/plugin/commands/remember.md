---
description: Save a durable fact, decision, preference, constraint, or project note to Walrus Memory.
argument-hint: <fact to remember>
---

Save the following durable fact to Walrus Memory using `memwal_remember`.

If `$ARGUMENTS` is empty, ask the user what they want remembered.

NEVER save a credential, even when it sits next to something worth saving: passwords, API keys, access or refresh tokens, private keys, seed or recovery phrases, authorization headers, session cookies, and connection strings or URLs that embed a user:password. When a message mixes a preference with a credential, save the preference alone and leave the credential out; never store the line verbatim. If the user says not to save something ('don't save this', 'off the record', or the same in any language), do not save it, and do not save a paraphrase of it either. Do not store quoted or pasted third-party material — log excerpts, code, articles, other people's messages — as if it were a fact about this user. Save only what the user is telling you about themselves or their work, in your own words.

Memory to save:

```text
$ARGUMENTS
```

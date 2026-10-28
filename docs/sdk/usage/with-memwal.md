---
title: "withMemWal"
description: >-
  Drop-in memory middleware for Vercel AI SDK apps. Automatically recalls relevant memories before generation and optionally saves new facts after generation.
keywords:
  - withMemWal
  - Vercel AI SDK
  - middleware
  - memory recall
  - auto-save
  - Walrus Memory
goal:
  description: Wrap a Vercel AI SDK streamText or generateText call with withMemWal, configure the recall and save filters, and verify that relevant memories are injected and notable outputs are persisted.
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 100
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - How do I add memory to a Vercel AI SDK app?
  - What does the withMemWal middleware do?
  - When should I use withMemWal vs direct SDK calls?
answer: >-
  withMemWal is drop-in memory middleware for Vercel AI SDK apps. Before generation it recalls relevant memories and injects them into the prompt. After generation it optionally runs analyze() to extract and save new facts. Use direct SDK calls instead when you need precise control over when memory is stored or how recall results are used.
---

Drop-in memory middleware for Vercel AI SDK apps.

```ts
import { generateText } from "ai";
import { withMemWal } from "@mysten-incubation/memwal/ai";
import { openai } from "@ai-sdk/openai";

const model = withMemWal(openai("gpt-4o"), {
  key: "<your-ed25519-private-key>",
  accountId: "<your-memwal-account-id>",
  serverUrl: "https://your-relayer-url.com",
  namespace: "chatbot-prod",
  maxMemories: 5,
  autoSave: true,
});

const result = await generateText({
  model,
  messages: [{ role: "user", content: "What do you know about me?" }],
});
```

## What It Does

Before generation:

- Reads the last user message
- Runs `recall()` against Walrus Memory (bounded by `maxMemories` and optional `maxTokens`)
- Filters by minimum similarity (`minRelevance`, default `0.3`)
- Injects memory context into the prompt

After generation:

- Optionally runs `analyze()` on the user message (`autoSave`, default `true`)
- Saves extracted facts asynchronously

## Options

| Option | Default | Description |
| --- | --- | --- |
| `maxMemories` | `5` | Maximum number of memories to recall and inject per request (top-K limit) |
| `maxTokens` | `undefined` | Optional token budget cap on recalled memories injected into the prompt (forwarded to `recall({ maxTokens })`) |
| `minRelevance` | `0.3` | Minimum similarity score (`0`–`1`) required for a recalled memory to be injected |
| `autoSave` | `true` | Automatically run `analyze()` after generation to extract and store new facts |
| `debug` | `false` | Log recall and auto-save activity to `console.warn` |

Set a namespace explicitly for each product surface that uses the middleware. Otherwise recalled
and auto-saved memories fall back to `"default"`.

## When To Use Direct SDK Calls Instead

Use direct SDK methods when your app needs precise control over:

- When memory is stored
- Which text is analyzed
- How recall results are displayed or filtered

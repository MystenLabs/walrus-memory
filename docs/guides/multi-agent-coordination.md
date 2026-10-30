---
title: Coordinate Multiple Agents
description: >-
  Patterns for running several agents against one Walrus Memory account: give each agent its own
  delegate key, use namespaces to decide what they share, and hand work from one agent to the next.
keywords:
  - multi-agent
  - coordination
  - shared memory
  - delegate key
  - namespace
  - handoff
  - MemWal
  - Walrus
goal:
  description: Decide how several agents share or isolate memory, and implement a handoff between them
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 100
      label: Needs enough content to cover the patterns
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - How do I share memory between multiple agents?
  - Can two agents use the same Walrus Memory account?
  - How do I hand off context from one agent to another?
  - Should each agent have its own delegate key?
answer: >-
  Give each agent its own delegate key on one account, then use namespaces to decide what they
  share. Agents that read and write the same namespace share memory, because any delegate the
  account authorizes can decrypt everything that account owns. Agents that use separate namespaces
  never read each other's writes, because recall never crosses a namespace. A handoff is one agent writing to a
  shared namespace and the next recalling from it.
---

Several agents can work against one Walrus Memory account. Two things decide how they share memory: how many delegate keys you issue, and which namespaces each agent reads and writes.

## Give each agent its own delegate key

An account has one owner and any number of [delegates](/fundamentals/concepts/ownership-and-access). A delegate is a keypair the owner authorizes onchain, and the relayer verifies that authorization against the contract on every request.

Issue one delegate key per agent rather than sharing a single key. The keys grant identical access, so this is not an access-control boundary, but issuing one per agent gives you two things:

1. The dashboard labels each key, so you can see which agent is running.
2. You can revoke one agent without disturbing the others.

<Warning>
Any delegate the account authorizes can decrypt everything that account owns, across every namespace. Delegate keys separate identity, not data. If two agents must not read each other's memory, give them separate accounts, not separate namespaces.
</Warning>

## Decide what the agents share

[Namespaces](/fundamentals/concepts/memory-space) decide what agents see, because recall and restore match a namespace exactly and never cross one.

| **Pattern** | **Setup** | **Result** |
| --- | --- | --- |
| Shared memory | Every agent uses the same namespace | Each agent recalls what the others wrote |
| Isolated memory | Each agent uses its own namespace | No agent recalls another's writes |
| Shared plus private | A common namespace, plus one per agent | Agents pool findings and keep working notes apart |

Shared plus private suits most multi-agent systems. A research agent writes conclusions to `findings` and keeps its own scratch work in `research-agent`, so a planner agent reading `findings` sees the conclusions without wading through intermediate steps.

```ts
const shared = MemWal.create({
  key: process.env.RESEARCH_AGENT_KEY!,
  accountId: process.env.MEMWAL_ACCOUNT_ID!,
  serverUrl: process.env.MEMWAL_SERVER_URL,
  namespace: "findings",
});

const scratch = MemWal.create({
  key: process.env.RESEARCH_AGENT_KEY!,
  accountId: process.env.MEMWAL_ACCOUNT_ID!,
  serverUrl: process.env.MEMWAL_SERVER_URL,
  namespace: "research-agent",
});
```

Both clients use the same delegate key and the same account. Only the namespace differs.

## Hand off work between agents

A handoff is a write followed by a recall. The first agent writes what the next one needs into a shared namespace, and the next agent recalls it when it starts.

```ts
// Research agent, finishing its turn.
await shared.rememberAndWait(
  "The customer runs Postgres 14 and cannot upgrade before Q3, so the migration plan must stay compatible with 14.",
);

// Planner agent, starting its turn against the same namespace.
const context = await planner.recall({ query: "customer database constraints", limit: 10 });
```

Recall has two properties that change how you write for a handoff:

1. It matches by meaning rather than by key, so the receiving agent finds a memory by describing what it needs instead of knowing an identifier.
2. It returns whole memories, so write one complete, self-contained statement per fact rather than a fragment that only makes sense beside the one before it.

<Tip>
Use `rememberAndWait` for the last write before a handoff. `remember` returns as soon as the relayer creates the background job, and embedding, encryption, upload, and vector indexing continue afterwards, so you cannot recall it yet. `rememberAndWait` polls until that job finishes, which is the point the next agent can find it.
</Tip>

## Choose a boundary

Match the boundary to what you actually need to separate:

- Agents cooperating on one user's work: one account, one delegate key each, namespaces to divide the work.
- Agents serving different users: one account per user, never one shared account split by namespace, because any delegate reads every namespace on the account.
- Agents running against different deployments: separate app IDs already isolate them, because the package ID scopes encryption and blob discovery.

---
title: "Run Docs Locally"
description: >-
  Instructions for running the Walrus Memory Mintlify documentation site locally
  using Node 22.23.4 and pnpm, including build commands for verification.
keywords:
  - Walrus Memory
  - MemWal
  - docs
  - Mintlify
  - local development
goal:
  description: Start the Mintlify dev server, verify pages render correctly in the browser, and run the production build to catch broken links or frontmatter errors before opening a PR.
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 50
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - "How do I run the Walrus Memory docs locally?"
  - "What Node version does Mintlify require for MemWal docs?"
  - "How do I build the MemWal documentation site?"
answer: >-
  Run pnpm install and pnpm dev:docs from the repository root to start the Mintlify docs site
  locally. Use Node 22.23.4 from .nvmrc because Mintlify fails on Node 25+. Build with pnpm build:docs
  to verify the output.
---

Run these commands from the repository root:

```bash
nvm install
nvm use
pnpm install
pnpm dev:docs
```

This starts the Mintlify site using the docs in this repository.

Use Node 22.23.4 from `.nvmrc` for Mintlify local preview. If you use another
version manager, select that version before running pnpm. Mintlify fails on Node 25+.

## Build the Docs

```bash
pnpm build:docs
```

---
title: Claude Code
description: >-
  Add portable Walrus Memory to Claude Code as a full plugin with automatic memory, or as a plain MCP server.
  The plugin adds lifecycle hooks that make the agent prefer Walrus Memory over built-in memory.
keywords:
  - MCP
  - Claude Code
  - Walrus Memory
  - MemWal
  - plugin
  - automatic memory
goal:
  description: Add MemWal to Claude Code as an automatic memory plugin or MCP-only server, authenticate with your account credentials, and confirm persistent memory is working across sessions.
  requires:
    - has_frontmatter:
        - title
        - description
        - keywords
      label: Has required frontmatter fields
    - min_words: 300
      label: Needs more content depth
    - has_questions: true
      label: Needs questions for AI search visibility
    - has_answer: true
      label: Needs answer summary for AI citation
questions:
  - How do I add Walrus Memory to Claude Code?
  - How do I install the MemWal plugin on Claude Code?
  - What is the difference between the MemWal plugin and MCP-only on Claude Code?
  - How do I fix the memwal MCP server when it shows as failed in Claude Code?
answer: >-
  To add Walrus Memory to Claude Code, install the MemWal plugin through the marketplace (/plugin marketplace add https://github.com/MystenLabs/MemWal.git, then /plugin install memwal@memwal-plugins), or add it as MCP-only with claude mcp add. The plugin includes lifecycle hooks for session start, user prompt, and post-tool events that reinforce automatic memory behavior and make the agent prefer Walrus Memory over Claude Code's built-in memory.
---

Add MemWal to Claude Code so it recalls context and saves durable facts as you work. Install it as a **plugin** (recommended; adds automatic-memory hooks) or as **MCP-only** (just the tools).

This guide covers Claude Code, including the **Code tab inside Claude Desktop**.
For regular Desktop or web chat, use the [OAuth custom connector](/mcp/claude-connector),
which does not require Node.js or the Claude Code CLI.

## Prerequisites

- Confirm `claude --version` works in the terminal you will use. Installing the Desktop app does not guarantee the CLI is on your `PATH`; see [Claude Code setup](https://code.claude.com/docs/en/setup).
- Install Node.js 22.23.4+ (22.x), 24.22.1+ (24.x), or 26.12.1+ (26.x) with `npx` on your `PATH`; check with `node --version`.
- Use a Claude Code version with plugin support if you want the plugin install; the `/plugin` command confirms support, and MCP-only works on any version with `claude mcp add`.
- Have a [Walrus Memory account](/fundamentals/concepts/ownership-and-access) ready. An unauthenticated memory-tool call returns sign-in instructions rather than signing you in, so ask the agent to run `memwal_login` and open the URL it returns. You can create the account during that flow at [memory.walrus.xyz](https://memory.walrus.xyz). Config files carry no keys: credentials land in `~/.memwal/credentials.json` after sign-in.

## Installation

<Tabs>
  <Tab title="Plugin (recommended)">
    <Steps>
      <Step title="Add the marketplace and install">
        Run these as separate commands in a terminal, stopping if one fails. Agents with a shell tool can run them after checking the prerequisites, then verify the plugin is enabled. A manually added `enabledPlugins` setting alone does not verify installation.

        ```bash
        claude plugin marketplace add https://github.com/MystenLabs/MemWal.git
        claude plugin install memwal@memwal-plugins -s user
        claude plugin list
        ```

        In Claude Desktop's Code tab, use the plugin UI instead: open the `+`
        menu beside the prompt, choose **Plugins → Add plugin**, select MemWal
        from a configured marketplace, then confirm it under **Manage plugins**.
        Do not paste slash commands into chat as plain text.

        Slash commands are an alternative only in an interactive Claude Code
        session that exposes `/plugin`:

        ```
        /plugin marketplace add https://github.com/MystenLabs/MemWal.git
        /plugin install memwal@memwal-plugins
        ```
      </Step>
      <Step title="Restart and sign in">
        Restart Claude Code, then ask the agent to run `memwal_login` and open the URL it returns to connect your wallet. MCP-only is not a complete Claude Code setup: without the plugin, the agent often writes Claude's built-in `MEMORY.md` instead of calling `memwal_remember`.

        Claude's system prompt still prefers `MEMORY.md` over MCP instructions. Show this block, get the user's go-ahead, then merge it into `~/.claude/CLAUDE.md` (do not replace the file). If `<!-- memwal:start -->` ... `<!-- memwal:end -->` is already there, replace that span only. Turn off Claude's built-in / native memory in account settings if it is on:

        ```markdown
        <!-- memwal:start -->
        ## Walrus Memory

        Prefer the memwal_* tools over Claude's built-in memory and MEMORY.md.
        When the user states a preference, decision, constraint, correction, identity detail, or recurring workflow, call memwal_remember (or memwal_remember_bulk) without being asked. Also call it when they explicitly ask to remember something. Pass the complete statement, never a summary. Skip one-off tasks, the current file or bug, and small talk.
        When the user references past work, preferences, or stored facts, call memwal_recall first.
        <!-- memwal:end -->
        ```
      </Step>
    </Steps>
  </Tab>
  <Tab title="MCP-only">
    ```bash
    claude mcp add --scope user memwal -- npx -y @mysten-incubation/memwal-mcp
    ```
    Restart Claude Code, then ask the agent to run `memwal_login` on first use.

    Or connect to the relayer over HTTP directly (no local package):
    ```bash
    claude mcp add --transport http memwal https://relayer.memory.walrus.xyz/api/mcp
    ```
  </Tab>
</Tabs>

## What the plugin includes

| **Component** | **Plugin** | **MCP-only** |
|---|:-:|:-:|
| MemWal MCP (memory tools) | ✓ | ✓ |
| Lifecycle hooks (automatic recall/save) | ✓ | ✗ |

MCP-only still saves and recalls on its own because the tools are proactive. The plugin adds hooks that reinforce the behavior and make the agent **prefer Walrus Memory over Claude Code's built-in memory**.

The plugin also starts the server differently. Instead of resolving the package name with `npx`, it installs the pinned version once into `~/.memwal/runtime/memwal-mcp@<version>` and launches that absolute path. `npx` resolves a name against the directory the client was started in, which is your project, so a package installed there under the same name and claiming the pinned version would have been run instead — the version pin does not prevent that. The plugin's launcher never looks at your project's `node_modules`, and it fails rather than falling back if the pinned version cannot be installed.

## Available tools

| **Tool** | **Description** |
|------|-------------|
| `memwal_remember` | Save a durable fact (preference, decision, constraint, identity). |
| `memwal_remember_bulk` | Save several distinct facts in one call. |
| `memwal_recall` | Semantic search across stored memories for relevant context. |
| `memwal_analyze` | Extract and save multiple facts from a passage of text. |
| `memwal_restore` | Rebuild the search index from Walrus (recovery). |
| `memwal_health` | Fast connectivity check. |
| `memwal_login` / `memwal_logout` | Connect or disconnect this client. |

See [Reference](/mcp/reference) for full parameters.

## Lifecycle hooks (plugin only)

| **Hook** | **Event** | **What it does** |
|------|-------|--------------|
| Session start | `SessionStart` | Announces that memory is active and reminds the agent to use the `memwal_*` tools (preferring them over any built-in memory). |
| User prompt | `UserPromptSubmit` | Injects a decision rubric so the agent chooses recall vs save from meaning (any language or spelling). |
| Post-tool | `PostToolUse` (Bash) | When a command's output looks like an error, reminds the agent to recall prior fixes and save the resolution. |

## Example workflow

**Session 1**

```
You:   I prefer pnpm and always use TypeScript strict mode.
Agent: (calls memwal_remember on its own to store both preferences)
```

**Session 2: a brand-new chat**

```
You:   set up a new package in this repo
Agent: (calls memwal_recall, finds your preferences)
       Scaffolding with pnpm and "strict": true, matching how you like to work.
```

## Verify

Work through these three checks in order; each one isolates a different layer.

<Steps>
  <Step>
    ### Server connected

    Run `/mcp` and confirm the list reports `memwal` as Connected. Expand its tools and confirm the list includes `memwal_remember_bulk` and `memwal_health`.
  </Step>

  <Step>
    ### Relayer reachable

    Ask the agent to run `memwal_health`. A healthy response returns within a few seconds; anything else points at network access to `relayer.memory.walrus.xyz`.
  </Step>

  <Step>
    ### End to end

    State a durable fact, for example a package-manager preference, confirm the agent calls `memwal_remember`, then open a brand-new session and confirm `memwal_recall` surfaces it.
  </Step>
</Steps>

## Troubleshooting FAQ

**`/mcp` reports memwal as failed or missing.**
Restart Claude Code first; MCP servers load at startup. If it still fails, run `npx -y @mysten-incubation/memwal-mcp --help` in a plain terminal: that surfaces the real error, most often a Node version below the supported security patch minimum (22.23.4 / 24.22.1 / 26.12.1) or a `PATH` without `npx` in the environment Claude Code inherits. For a full trace, add `MEMWAL_MCP_DEBUG=1` to the server's environment.

**`/plugin` commands are not recognized.**
Your Claude Code version predates plugin support. Update Claude Code, or use the MCP-only install; the memory tools behave the same, you only lose the automatic-memory hooks.

**The browser sign-in cannot open (SSH, containers, headless machines).**
`memwal_login` needs a browser. Sign in once on a desktop machine, then copy `~/.memwal/credentials.json` to the same path on the headless machine.

That file holds the raw delegate private key, so treat it as a secret: transfer it over a secure channel such as `scp` rather than pasting it or sending it through chat, and restrict it on arrival.

```sh
$ chmod 600 ~/.memwal/credentials.json
```

For fully headless servers, the [headless setup guide](/sdk/headless-setup) covers credential-based configuration.

**Signed in with the wrong account.**
Ask the agent to run `memwal_logout`, which wipes `~/.memwal/credentials.json`, then run `memwal_login` again with the right wallet.

**The agent saves but recall returns nothing.**
Every recall runs inside one account and namespace. If you set `MEMWAL_NAMESPACE` (or `--namespace`) after saving, earlier memories live in the previous namespace. If the namespace matches and results are still missing, run `memwal_restore <namespace>` to rebuild the search index from Walrus; the stored memories are the source of truth, and you can rebuild the index at any time.

**Hooks are not firing.**
The lifecycle hooks ship only with the **plugin** install; MCP-only provides the tools without hooks. Confirm the plugin appears in `/plugin` and restart after installing.

**The agent writes `MEMORY.md` instead of calling `memwal_remember`.**
Claude Code's built-in memory is in the system prompt and outranks MCP instructions. Confirm the plugin is enabled, merge the Walrus Memory block into `~/.claude/CLAUDE.md`, and turn off Claude's built-in / native memory in account settings.

**Tool calls fail with an authentication error after working before.**
The stored credential can lapse if you revoked its delegate key from the dashboard. Run `memwal_logout` then `memwal_login` to mint a fresh delegate key.

**Corporate proxy or restricted network.**
The server needs outbound HTTPS to `relayer.memory.walrus.xyz` (and the sign-in flow needs `memory.walrus.xyz`). If only the relayer is blocked, the HTTP transport option above fails identically; allowlist both hosts.

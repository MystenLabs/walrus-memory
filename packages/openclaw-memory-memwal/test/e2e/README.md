# Plugin E2E

Two suites live here. They are separated by what they cost to run.

## `mock-relayer.test.mjs`

Serves a deliberately broken relayer from the test process: rate limiting, 5xx,
and a socket held open with no reply. No credentials, no network, no cost, so it
runs anywhere.

The hang case is the one that matters. Before the request deadline existed, a
relayer that accepted the connection and then went quiet left the recall hook
pending indefinitely and the agent turn never completed. An unreachable host
fails fast at DNS and hides this; only a hung one reproduces it.

## `live-relayer.test.mjs`

Runs against a real relayer. Skips itself unless credentials are present:

| Variable | Meaning |
|---|---|
| `MEMWAL_PRIVATE_KEY` | 64-char hex delegate key |
| `MEMWAL_ACCOUNT_ID` | MemWalAccount object ID |
| `MEMWAL_SERVER_URL` | Relayer base URL, defaults to staging |
| `MEMWAL_E2E_WRITE` | Set to `1` to enable the writing cases |

Reads are free. Writes are not, and they are irreversible: Walrus storage is
append-only with no per-blob delete, so every write leaves permanent data and
costs gas plus storage. They are therefore opt-in, and they go to a throwaway
`e2e-<timestamp>` namespace so they can never touch `default`.

Health alone does not prove much, since `/health` is unauthenticated and answers
even for a revoked key. The authorisation check issues a signed `recall()`
instead.

## Running

```bash
# mock only; live cases skip
pnpm --filter @mysten-incubation/oc-memwal test:e2e

# full suite, including permanent writes
MEMWAL_PRIVATE_KEY=... MEMWAL_ACCOUNT_ID=0x... MEMWAL_E2E_WRITE=1 \
  pnpm --filter @mysten-incubation/oc-memwal test:e2e
```

## In CI

`OpenClaw Plugin / E2E` runs on merges to `staging` and `main` only, never per
pull request, because of the write cost. It always targets the staging relayer,
even on a `main` merge, since there is no reason to leave test data on mainnet.
Without the secrets the live cases skip and the mock cases still run, so the job
cannot fail a branch just because credentials are absent.

Unit tests are separate and run on every PR through `OpenClaw Plugin / Unit
tests`.

## A known limitation

`withTimeout` races the request rather than aborting it, because `recall()`
builds its own `AbortController` and accepts no external signal, and the
compatibility preflight carries none at all. The turn is released on time, but
the abandoned request keeps its socket open until the server or the OS gives up.
The mock server force-closes connections for that reason; against a genuinely
hung relayer the sockets accumulate. Fixing it properly means threading an
`AbortSignal` through the SDK.

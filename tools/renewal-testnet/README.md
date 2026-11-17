# Testnet renewal harness

Run the existing-data migration through one entry point:

```sh
./run-renewal-testnet.command --plan
./run-renewal-testnet.command
```

The default selects an existing completed canonical cohort, preferring 1,000
memories, and uses 16 async workers / 8 concurrent transactions. It downloads
ciphertext and metadata, registers and uploads a new Blob, certifies and transfers
it to the original owner, then atomically updates the existing database mapping.
It does not create source data, wallets, accounts or vector rows in migration mode.

## First live run

Requirements: Node.js 22+, Python 3.9+, Git, Docker/OrbStack, and Sui CLI already
configured for testnet. The harness checks the network and never switches the
global CLI environment. The operator wallet needs sufficient address-balance
SUI and WAL; payment does not fall back to owned coin objects.

Public testnet protocol defaults are versioned in `testnet-defaults.json`.
Operator-specific wallet settings are supplied on first live use:

```sh
./run-renewal-testnet.command --full --count 6 \
  --funding-alias 'YOUR_TESTNET_ALIAS' \
  --funding-public-key 'FLAGGED_ED25519_PUBLIC_KEY_BASE64'
```

Use the 33-byte Sui flagged Ed25519 **public** key from your CLI wallet's public
metadata (`sui keytool list --json`). Never supply or export a private key.
Both flags are required together. Their validated public settings are saved with
mode 0600 in ignored local `operator.json`, so later launches need no flags.
The signature is verified against that configured public key before submission.
Incomplete runs cannot silently switch their operator.

`--full` explicitly creates synthetic sources/accounts and funds the fixture
owners before running migration. It is needed once on a fresh checkout with no
source cohort. Choose `--full --count 1000` when creating a full benchmark dataset;
normal launches thereafter reuse it. Live commands spend testnet tokens.

Pinned product source is `856fb01793fdb4301cc1b1a9c8673c4c55595f08` in a detached
cached worktree. Shallow clones must make that commit available first:

```sh
git fetch origin 856fb01793fdb4301cc1b1a9c8673c4c55595f08
```

The script caches public dependencies and starts an isolated PostgreSQL 17.12 +
pgvector 0.8.2 container bound only to localhost. It refuses to reset an existing
container whose matching local credential state is missing.

## Migration, metadata cache and recovery

The optimized path uses two transactions per memory: registration, then
certification + the product SEAL persistence fence + original-owner transfer.
Attributes are copied during registration and checked before database commit.

Metadata cache keys bind ciphertext SHA-256/size, expected blob ID, current shard
count, codec and SDK/WASM implementation hashes. Cache hits independently verify
root-to-blob-ID commitment and integrity. Misses run in a persistent four-thread
pool; their time is included in migration timing. The cache never supplies an old
nonce, certificate, lease or transaction. Old unqualified journals are not
imported blindly.

Explicit SDK calls reuse successful receipts and avoid repeated visibility/object
lookups. One visibility fence, fresh object/metadata/readback checks, aggregate
fund reservations and exact immutable lease plans remain. Original vector IDs,
owner, namespace, embedding, creation history and encrypted content are preserved.
Byte-identical ciphertext keeps its Walrus blob ID; the new Sui Blob object has a
later lease. Actual on-chain end epoch is authoritative.

Each cycle has its own journal. The canonical parent head, original vector lease
and cycle receipt update in one database transaction with compare-and-swap guards.
Only one mutating process runs at a time. An unknown prepared transaction is
reconciled by digest and exact bytes before further mutations; it is never
silently replaced. Run the same entry again after a failure to resume.

All runtime state belongs to this checkout under `.grok/renewal-testnet/`, including
operator settings, database credentials, fixture keys, cache, ciphertext, receipts
and logs. It is ignored by Git. Keep the matching database volume and private
state together for recovery; source code alone does not recreate an old inventory.

## Options

```sh
# Migrate a small range of an existing cohort
./run-renewal-testnet.command --count 6

# Select an existing canonical source and offset
./run-renewal-testnet.command --source-run-id 'EXISTING_SOURCE_RUN_ID' \
  --source-offset 0 --count 1000 --workers 16 --chain-concurrency 8

# Open/resume an exact saved run
./run-renewal-testnet.command --run-id 'EXISTING_RUN_ID' --no-open
```

`--new-run` starts a new migration cycle instead of resuming. `--unfused` selects
the diagnostic three-transaction path. Completed historical reports can be opened
without loading the current runtime or accessing a wallet. `--plan` and
`--self-test` do not require operator settings or call Docker, wallets or a network.

Reports include exact fees, attempts, cache hit/miss/computation counts, and timers
for build, balance admission, signing, execution, visibility and relay work.
Independent [audit tools](audit/README.md) verify the saved evidence.

## Offline development checks

Install from the committed runtime lockfile, without lifecycle scripts:

```sh
npm ci --prefix tools/renewal-testnet/runtime --ignore-scripts --no-audit --no-fund
export MEMWAL_RENEWAL_TEST_DEPENDENCIES="$PWD/tools/renewal-testnet/runtime/node_modules"
python3 -B -m unittest discover -s tools/renewal-testnet/tests -v
./run-renewal-testnet.command --self-test
./run-renewal-testnet.command --plan --count 6
node --import ./tools/renewal-testnet/runtime/node_modules/tsx/dist/loader.mjs tools/renewal-testnet/tests/test-metadata-cache.mjs
node tools/renewal-testnet/tests/test-explicit-flow.mjs
node tools/renewal-testnet/audit/audit.mjs --deps "$MEMWAL_RENEWAL_TEST_DEPENDENCIES" --self-test
node tools/renewal-testnet/audit/cost-audit.mjs --deps "$MEMWAL_RENEWAL_TEST_DEPENDENCIES" --self-test
node tools/renewal-testnet/audit/metadata-checkpoint-audit.mjs --deps "$MEMWAL_RENEWAL_TEST_DEPENDENCIES" --self-test
```

These checks use synthetic in-memory fixtures and temporary files only. They do
not read real keys, sign, access a database, or submit transactions. The offline
GitHub workflow runs the same checks; live testnet runs remain manual.

See the [sanitized 1,000-memory result](../../docs/relayer/renewal-testnet-1000-results.md).
This is a protocol + local DB harness; production HTTP/auth/queues and MCP
notification delivery are outside its coverage. No mainnet, Enoki, paid LLM or
customer data is used. Production sidecar integration is a separate change.

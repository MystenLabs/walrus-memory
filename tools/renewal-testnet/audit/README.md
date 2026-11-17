# Independent renewal audits

These standalone validators support the one-click runner. They do not import
runtime validators, read fixture keys, sign or submit transactions. Local run
evidence is kept outside version control.

The orchestrator runs SQL using its labeled local PostgreSQL container:

```text
psql -XqAt -v ON_ERROR_STOP=1 -v run_id=ID -v expected_count=N -v expected_owners=2 -f source-verify.sql
psql -XqAt -v ON_ERROR_STOP=1 -v run_id=ID -v expected_count=N -v expected_owners=2 -f snapshot.sql
psql -XqAt -v ON_ERROR_STOP=1 -v run_id=ID -v expected_count=N -v expected_owners=2 -f verify.sql
psql -XqAt -v ON_ERROR_STOP=1 -v run_id=ID -v expected_count=N -v expected_owners=2 -f artifact-manifest.sql
```

Each emits one JSON value. `source-verify.sql` gates the complete seeded cohort
before migration. Preserve the first complete `snapshot.sql` output as the
baseline; never replace it after migration starts. Run snapshot again afterward.
`verify.sql` requires all rows migrated, six unique finalized flow transactions
per memory, no unresolved digest, consistent DB references and vector recall.
It detects the optional security-delete table and uses feature-off behavior if
that table is absent. `artifact-manifest.sql` exports all public rows for the run
so extra rows cannot be hidden by an ID limit.

```text
python3 compare-snapshots.py BEFORE.json AFTER.json --expected-count N
python3 verify-artifacts.py MANIFEST.json SCRATCH --expected-count N
node audit.mjs --config CONFIG.json --expected-count N --container NAME --manifest MANIFEST.json --execute --out CHAIN_DIR
node cost-audit.mjs --config CONFIG.json --expect-seed N --expect-renew N --expect-setup 3 --require-complete --details --out COST.json
```

Both Python tools print JSON and exit nonzero on failure. The snapshot comparison
requires every expiry to increase as well as stable-field equality and a complete
cohort. The file verifier checks exact saved source/download bytes, sizes,
SHA-256, metadata and source object references. Counts may be 6, 180, 1000 or any
positive cohort supported by the runner.

The chain auditor uses fresh gRPC reads and its own BCS schemas, including
insertion-order-preserving Walrus VecMap metadata. It verifies old/new objects,
owner, type, size, certification, blob ID, exact metadata and chain/DB epochs;
new leases must be live. All four objects per memory are fetched in batches of
50, at most two batches at once. Without `--execute` it prints a plan and can
validate a supplied manifest offline. Omit `--manifest` to independently export
the public manifest through `docker exec psql`; `--container` or
`config.container` supplies the dynamic container name. The local DB URL may use
any localhost port but must name `renewal_e2e`. RPC calls have an explicit read
allowlist excluding execute/simulate operations.

The cost auditor queries only the local DB by default. Every successful receipt,
including fixture funding and account creation, needs matching saved prepared
BCS and digest. The original strict SplitCoins/withdrawal/return-zero tracing is
preserved for storage, write fees and relay tips. Setup has one `fund_owners`
receipt at ID -100 and two `create_account` receipts at IDs -1/-2. Funding must
send only SUI principal to the synthetic owners; that principal is reported in
`suiFixtureFundingPrincipal*` and excluded from fee totals. Account creation may
use each fixture owner's newly funded coin for gas. Service writer payments
remain address-balance-only. SUI fee totals are net actual gas plus proven relay
tips; nonrefundable storage is not added a second time. Expected counts apply to
all three phases per seed/renew group. `--require-complete` also validates stage
completion and pending receipts. A baseline cost check can use `--expect-renew 0`.

Legacy RPC recovery is disabled unless explicitly passed `--allow-rpc-missing`,
then limited to eight read-only transaction lookups. New runs require zero such
calls. `--journal SNAPSHOT.json` accepts an offline public cost snapshot with
`rows`, `pending`, `stages`, `owners` for reproducible parser checking.

Node dependencies resolve from the copied worktree's node_modules. For isolated
offline checks pass `--deps /absolute/path/to/node_modules`. Both Node auditors
have `--self-test`; the cost self-test builds and decodes an actual SDK funding
BCS transaction with a mock balance source and rejects unauthorized recipients,
excess withdrawals and owned-coin fallback without network access.

All results cover the testnet protocol plus local DB/files. They do not claim
product HTTP/authentication/queue coverage. Onchain end_epoch is authoritative;
the product's wall-clock expires_at is an estimate.

## Migration-only cycles

Use `source-verify-existing.sql`, `snapshot-existing.sql`, `verify-existing.sql`
and `artifact-manifest-existing.sql` instead of the four full-mode SQL files.
Keep the same psql variables and add `source_offset` (default 0) and
`renew_mode=fused|unfused` (default fused). Child memory IDs are dense; each
references the canonical root through `parent_run_id`, `parent_memory_id`,
`origin_run_id`, `origin_memory_id` and the unchanged `vector_entry_id`.
The original metadata tags use `provenance_run_id` and `origin_memory_id`,
not the new cycle ID. No child-prefixed vector rows, seed or setup transactions
are allowed. The source gate verifies the existing input head; final gates
verify child and canonical head/expiry, original vector identity, exact cycle
receipts and immutable lease plans. Before/after fingerprints cover canonical
parent original-source provenance as well as vector fields; the global vector
row count must stay unchanged.

Pass `--source-cipher-dir ORIGINAL_CIPHERTEXT_DIR` to `verify-artifacts.py`.
It uses `origin_memory_id` for original filenames and the child memory ID for
download filenames. The chain auditor recognizes `config.mode=migration-only`,
`config.parentSourceRunId` and `config.sourceOffset`; all fresh-object/metadata
checks remain unchanged. The public manifest includes linkage/provenance fields.

The migration-only cost command is:

```text
node cost-audit.mjs --config CONFIG.json --expect-seed 0 --expect-setup 0 --expect-renew N --renew-mode fused --require-complete --details --out COST.json
```

Fused renewal requires exactly one `renew.register` and one
`renew.certify_transfer` per item. The latter is strictly three commands:
`certify_blob`, the product SEAL fence and one transfer of that same new Blob to
its original owner, with no extra withdrawal or owned-coin input. The register
receipt proves copied attributes exactly match source metadata. Lease-plan
epochs/targets must match the BCS purchase and produce a later actual lease.
The diagnostic `--renew-mode unfused` requires register/certify/metadata-transfer
instead. Both require zero seed/setup receipts. Full mode retains its original
three-transaction flow and SQL schemas; use `renewMode=unfused` there.

## Metadata, nonce and upload checkpoint audit

For the explicit fused flow, independently verify qualified metadata, fresh
nonce ordering, registration BCS/auth, relay certificate and actual POST bindings:

```sh
node metadata-checkpoint-audit.mjs --run-dir RUN_DIR --container LOCAL_CONTAINER --expected-count N --out RESULT.json --deps NODE_MODULES
```

It queries only the local exercise database and writes a public journal/log
sidecar alongside its summary. Replay that snapshot using `--journal SNAPSHOT.json`
to avoid database access. Downloaded ciphertext remains an explicit local input.
All RPC, signing and key reads are prohibited. Only synthetic self-test data is
used by `--self-test`.

The cost auditor requires the configured operator address instead of assuming a
developer wallet. Its self-test passes an explicit synthetic writer. Operator
settings, journal exports and live results remain in ignored local state.

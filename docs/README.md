# Walrus Memory documentation

The public Walrus Memory documentation is published at
[docs.wal.app/walrus-memory](https://docs.wal.app/walrus-memory). Its source lives in
[MystenLabs/walrus-documentation](https://github.com/MystenLabs/walrus-documentation) under
`walrus-memory-content/`; open documentation pull requests there.

This directory keeps the engineering documentation that is not published: contributor guides,
runbooks, migration and operations notes, internal API notes, and the per-package changelogs that
the release tooling maintains. The docs checks in CI (`scripts/check-docs-code-sync.mjs` and
`scripts/check-docs-freshness.mjs`) still run over these files.

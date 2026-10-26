---
title: "Runtime security updates"
description: "Patch Node, Python, certificates, and MCP dependencies and verify the deployed services."
---

Use a supported runtime with the security patches listed below or newer patches in the same release line. Package engine ranges describe API compatibility; they do not make older patch releases safe.

| Component | October 2026 security baseline |
| --- | --- |
| Node.js | 22.23.4, 24.22.1, or 26.12.1 |
| Python | 3.11.17, 3.12.15, 3.13.17, or 3.14.9 |
| pip | 26.2.2 |
| certifi | 2026.10.19 |
| uv, when used | 0.13.4 |
| setuptools, when present | 83.0.0 |

`.nvmrc` selects the repository's Node runtime. `.python-version` selects its default Python runtime. The Python SDK requires Python 3.11+ starting with version 0.2.0; Python 3.9 and 3.10 have reached end of life. CI also exercises supported Python release lines at patched versions.

## Update Python environments

Recreate each virtual environment after changing its interpreter. Installing a newer system Python does not change existing virtual environments. The benchmark environment is separate from the SDK environment and must be updated separately.

Before installing other packages, bootstrap pip from the pinned wheel whose SHA-256 comes from the Python security announcement:

```bash
python -m venv .venv
source .venv/bin/activate
python scripts/bootstrap-python-security.py
python -m pip install -e 'packages/python-sdk-memwal[dev]'
```

Run these commands from the repository root. The bootstrap refuses an incorrect wheel hash before invoking pip, installs the verified wheel without an index, then updates certifi and setuptools. Python 3.11 environments can contain an older seeded setuptools even after pip is updated. pip contains its own vendored CA bundle; updating certifi or the operating system alone does not replace that bundle. If you use uv, update it to 0.13.4+ following the upstream certificate-security guidance before resolving dependencies.

For the benchmark harness, install its hash-locked requirements from `services/server/benchmarks/requirements.lock`. Regenerate that file from `pyproject.toml` after changing its dependency requirements, review the diff, and run the benchmark unit tests. Dependency changes do not require running a paid live benchmark.

## Update and validate services

Rebuild Node services from the pinned patched Docker images. Next.js apps use Next 16.4.1+ and sharp 0.35.5+ for the October image-processing and Server Actions fixes. The relayer sidecar uses its own npm lockfile, independently of the root pnpm lockfile; update and test both dependency graphs. Workspace apps use only the root `pnpm-lock.yaml`; do not create app-local pnpm/npm locks. The sidecar uses `services/server/scripts/package-lock.json`, not a second pnpm lock.

The MCP server bounds tool-input element counts and HTTP body sizes. Its older SSE route applies body parsing only after authentication and session ownership checks. Keep those protections when changing transport code. MCP clients reject redirects on authenticated SSE requests and reject a message endpoint on another origin. Configure the final relayer URL directly instead of relying on a redirect.

Rust TLS validation and root certificates also require updates: rebuild relayer/indexer binaries after updating their Cargo lockfiles. Changing only a Node container tag does not update compiled Rust dependencies.

After staging validation, deploy rebuilt images through the normal release process. Record the commit, image digest, `node -v`, and applicable Python/package versions from the running environment. Check health, MCP login and requests, remember/recall, and SEAL/Walrus operations. A merged PR, a restarted container, or a passing dependency audit is not evidence that production has been patched.

Credential rotation for the Railway incident remains a separate operational task. Never restore potentially exposed credentials as a rollback.

## Prepare package releases

This update manually bumps the MCP package and all plugin/marketplace manifests to 0.0.16, and the Python SDK to 0.2.0. Both package and website changelogs must start with the matching version. The TypeScript SDK and OpenClaw package do not need a version bump for changes confined to consuming apps and build tooling.

Run `node scripts/verify-manual-sdk-release.mjs` to check manifest/changelog agreement, and `node scripts/check-mcp-pin.mjs` to check that the launcher target is published. Keep an explicit override pointing to the previous published MCP release while the new one is unavailable. After the release workflow successfully publishes the new package, verify that exact version on npm and retarget the override. A source version bump alone does not update existing plugin installs. This PR removes its consumed changeset so the stable workflow cannot bump the manual MCP version twice.

## Upstream advisories

- [Node security releases, October 21](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [Python certificate incident and secure bootstrap](https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576)
- [Next Server Actions denial of service](https://github.com/vercel/next.js/security/advisories/GHSA-p3m5-59mp-jv5r)
- [MCP input-validation memory limits](https://github.com/modelcontextprotocol/typescript-sdk/security/advisories/GHSA-46jr-4wx8-v453)
- [Rust certificate roots](https://rustsec.org/advisories/RUSTSEC-2026-0381.html)

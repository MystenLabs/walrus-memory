#!/usr/bin/env python3
"""
Integration tests for the Walrus Memory Python SDK against a live server.

Targets MEMWAL_SERVER_URL (default: https://relayer.dev.memwal.ai).

No-auth tests (always run, no env vars needed):
  - /health endpoint
  - Unsigned request → 401
  - Wrong signature → 401
  - Expired timestamp → 401
  - Future timestamp → 401
  - Unregistered key → SDK raises MemWalError

Authenticated tests (require MEMWAL_PRIVATE_KEY + MEMWAL_ACCOUNT_ID):
  - remember() acceptance
  - remember_and_wait()
  - recall()
  - analyze()
  - ask()
  - Full e2e: remember → recall → verify
  - Async variants

Usage:
  # Run only no-auth tests (no keys needed)
  python -m pytest tests/test_integration.py -v -m "not requires_key"

  # Run full suite with real credentials
  MEMWAL_PRIVATE_KEY=<hex> MEMWAL_ACCOUNT_ID=0x... python -m pytest tests/test_integration.py -v

  # Run against staging using env vars
  export MEMWAL_PRIVATE_KEY="<your-ed25519-delegate-private-key-hex>"
  export MEMWAL_ACCOUNT_ID="0x-your-walrus-memory-account-id"
  export MEMWAL_SERVER_URL="https://relayer.dev.memwal.ai"
  python -m pytest tests/test_integration.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid

import httpx
import nacl.signing
import pytest

from memwal.client import MemWal, MemWalCompatibilityError, MemWalError, MemWalSync
from memwal.utils import build_signature_message

pytestmark = pytest.mark.integration

# ── Config ───────────────────────────────────────────────────────────────────

SERVER_URL = os.environ.get("MEMWAL_SERVER_URL", "https://relayer.dev.memwal.ai")
PRIVATE_KEY_HEX = os.environ.get("MEMWAL_PRIVATE_KEY", "")
ACCOUNT_ID = os.environ.get("MEMWAL_ACCOUNT_ID", "")

# A live write runs embed -> SEAL encrypt -> Walrus upload -> on-chain metadata.
# Measured around 44s against the dev relayer, so the SDK's 60s default leaves
# too little headroom to be reliable in CI. 120s matches what the SDK already
# uses for bulk pipelines.
_REMEMBER_TIMEOUT_MS = int(os.environ.get("MEMWAL_REMEMBER_TIMEOUT_MS", "120000"))

# Every authenticated test writes into a namespace unique to this run. The bench
# account is shared, and `default` in particular is what real users get, so a
# recurring job must not leave live Walrus blobs there.
_E2E_NAMESPACE = f"sdk-e2e-{uuid.uuid4().hex[:8]}"
_E2E_NAMESPACE_ALT = f"{_E2E_NAMESPACE}-alt"

HAS_KEY = bool(PRIVATE_KEY_HEX and ACCOUNT_ID)

requires_key = pytest.mark.skipif(
    not HAS_KEY,
    reason="MEMWAL_PRIVATE_KEY and MEMWAL_ACCOUNT_ID not set",
)


def _sync_client(namespace: str = _E2E_NAMESPACE) -> MemWalSync:
    return MemWalSync.create(
        key=PRIVATE_KEY_HEX,
        account_id=ACCOUNT_ID,
        server_url=SERVER_URL,
        namespace=namespace,
    )


def _async_client(namespace: str = _E2E_NAMESPACE) -> MemWal:
    return MemWal.create(
        key=PRIVATE_KEY_HEX,
        account_id=ACCOUNT_ID,
        server_url=SERVER_URL,
        namespace=namespace,
    )

# ── Helpers ───────────────────────────────────────────────────────────────────


_HTTP_CLIENT = httpx.Client(timeout=30, transport=httpx.HTTPTransport(retries=3))


def _raw_signed_request(
    method: str,
    path: str,
    body: dict,
    signing_key: nacl.signing.SigningKey,
    *,
    base_url: str = SERVER_URL,
    timestamp_override: str | None = None,
    pub_key_override: str | None = None,
) -> httpx.Response:
    """Make a raw signed request without using the SDK (for auth rejection tests)."""
    body_bytes = json.dumps(body, separators=(",", ":")).encode()
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    timestamp = timestamp_override or str(int(time.time()))
    nonce = str(uuid.uuid4())
    message = build_signature_message(
        timestamp=timestamp,
        method=method.upper(),
        path=path,
        body_sha256=body_hash,
        nonce=nonce,
        account_id=ACCOUNT_ID or "0x0",
    )
    signed = signing_key.sign(message.encode())
    signature_hex = signed.signature.hex()
    pub_key_hex = pub_key_override or signing_key.verify_key.encode().hex()

    return _HTTP_CLIENT.request(
        method,
        f"{base_url}{path}",
        content=body_bytes,
        headers={
            "Content-Type": "application/json",
            "x-public-key": pub_key_hex,
            "x-signature": signature_hex,
            "x-timestamp": timestamp,
            "x-nonce": nonce,
            "x-account-id": ACCOUNT_ID or "0x0",
        },
    )


# ── No-auth tests (always run) ────────────────────────────────────────────────


class TestHealth:
    """Health endpoint — no auth, always passes."""

    def test_health_returns_ok(self) -> None:
        mw = MemWalSync.create(key="aa" * 32, account_id="0x0", server_url=SERVER_URL)
        result = mw.health()
        assert result.status == "ok", f"Expected 'ok', got '{result.status}'"
        print(f"\n  server version={result.version}")

    def test_health_has_version(self) -> None:
        mw = MemWalSync.create(key="aa" * 32, account_id="0x0", server_url=SERVER_URL)
        result = mw.health()
        assert result.version is not None
        assert isinstance(result.version, str)


class TestAuthRejection:
    """Verify the server correctly rejects bad auth — no registered key needed."""

    _key = nacl.signing.SigningKey.generate()
    _body = {"text": "hello", "namespace": "default"}

    def test_unsigned_request_rejected(self) -> None:
        """Request with no auth headers → 401."""
        resp = _HTTP_CLIENT.post(f"{SERVER_URL}/api/remember", json=self._body)
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    def test_wrong_signature_rejected(self) -> None:
        """Valid format but signature made with a different key → 401."""
        key_a = nacl.signing.SigningKey.generate()
        key_b = nacl.signing.SigningKey.generate()
        # Sign with key_a but claim to be key_b
        wrong_pub = key_b.verify_key.encode().hex()
        resp = _raw_signed_request(
            "POST", "/api/remember", self._body, key_a, pub_key_override=wrong_pub
        )
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    def test_expired_timestamp_rejected(self) -> None:
        """Timestamp >5 minutes ago → 401."""
        old_ts = str(int(time.time()) - 600)  # 10 minutes ago
        resp = _raw_signed_request(
            "POST", "/api/remember", self._body, self._key, timestamp_override=old_ts
        )
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    def test_future_timestamp_rejected(self) -> None:
        """Timestamp far in the future → 401."""
        future_ts = str(int(time.time()) + 600)
        resp = _raw_signed_request(
            "POST", "/api/remember", self._body, self._key, timestamp_override=future_ts
        )
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    def test_sdk_surfaces_401_as_memwal_error(self) -> None:
        """SDK wraps unregistered key auth failures as MemWalError."""
        unregistered_key = "bb" * 32  # random, not registered on-chain
        mw = MemWalSync.create(key=unregistered_key, account_id="0x0", server_url=SERVER_URL)
        with pytest.raises(MemWalError) as exc_info:
            mw.remember("hello")
        if isinstance(exc_info.value, MemWalCompatibilityError):
            pytest.skip("live relayer does not expose compatibility metadata yet")
        err = str(exc_info.value)
        assert "401" in err or "403" in err, f"Expected 401/403 in: {err}"


# ── Authenticated tests ───────────────────────────────────────────────────────


@requires_key
class TestRemember:
    """remember() / remember_and_wait() against live server."""

    def test_remember_returns_job_id_and_status(self) -> None:
        mw = _sync_client()
        result = mw.remember("Integration test: the sky is blue")
        assert result.job_id is not None and isinstance(result.job_id, str)
        assert result.status in ("pending", "running")
        print(f"\n  accepted job={result.job_id[:8]}... status={result.status}")

    def test_remember_and_wait_returns_blob_and_owner(self) -> None:
        mw = _sync_client()
        result = mw.remember_and_wait(
            "Integration test: the sky is blue", timeout_ms=_REMEMBER_TIMEOUT_MS
        )
        assert result.id is not None and isinstance(result.id, str)
        assert result.blob_id is not None and isinstance(result.blob_id, str)
        assert result.owner.startswith("0x")
        print(f"\n  done job={result.id[:8]}... blob={result.blob_id[:8]}...")

    def test_remember_uses_the_client_namespace(self) -> None:
        """Omitting `namespace` falls back to the one the client was built with.

        The literal `"default"` fallback is asserted in the mocked suite; proving
        it here would mean writing a live blob into the namespace real users get.
        """
        mw = _sync_client()
        result = mw.remember_and_wait(
            "Integration test: namespace fallback", timeout_ms=_REMEMBER_TIMEOUT_MS
        )
        assert result.namespace == _E2E_NAMESPACE

    def test_remember_custom_namespace(self) -> None:
        mw = _sync_client()
        result = mw.remember_and_wait(
            "Integration test: custom namespace",
            namespace=_E2E_NAMESPACE_ALT,
            timeout_ms=_REMEMBER_TIMEOUT_MS,
        )
        assert result.namespace == _E2E_NAMESPACE_ALT


@requires_key
class TestListNamespaces:
    """list_namespaces() against live server. Read-only; writes nothing."""

    def test_walks_every_page_on_has_more(self) -> None:
        # Step 1: verify signed cursor pagination with limit=1 across the first
        # two pages (2 requests = 4 rate-limit points) so we prove the relayer
        # accepts a signed query string containing `updated_after=<cursor>&limit=1`.
        # Walking all 200+ historical namespaces on the shared benchmark account
        # with limit=1 would exceed the 200 weighted-requests/min read_delegate_key
        # budget on its own (each read is weight 2 -> 100 calls/min).
        mw = _sync_client()
        first_page = mw.list_namespaces(limit=1)
        assert len(first_page.namespaces) <= 1
        assert first_page.snapshot_version >= 1
        if first_page.has_more:
            assert first_page.next_cursor is not None
            second_page = mw.list_namespaces(cursor=first_page.next_cursor, limit=1)
            assert len(second_page.namespaces) <= 1
            assert second_page.snapshot_version >= 1
            if first_page.namespaces and second_page.namespaces:
                assert first_page.namespaces[0].name != second_page.namespaces[0].name

        # Step 2: walk the full namespace rollup using the default page size
        # (100 per page) to assert has_more termination and uniqueness without
        # burning the per-key read budget.
        names: list[str] = []
        cursor = None
        for _ in range(100):
            page = mw.list_namespaces(cursor=cursor)
            assert page.snapshot_version >= 1
            names.extend(ns.name for ns in page.namespaces)
            cursor = page.next_cursor
            if not page.has_more:
                break
        else:
            pytest.fail("namespace walk did not finish in 100 pages")
        assert len(names) == len(set(names)), "a single walk must not repeat a namespace"
        print(f"\n  namespaces={len(names)}")


@requires_key
class TestRecall:
    """recall() against live server."""

    def test_recall_returns_list(self) -> None:
        mw = _sync_client()
        result = mw.recall("sky blue", limit=5)
        assert isinstance(result.results, list)
        assert result.total >= 0
        print(f"\n  recall total={result.total}")

    def test_recall_respects_limit(self) -> None:
        mw = _sync_client()
        result = mw.recall("test", limit=2)
        assert len(result.results) <= 2

    def test_recall_result_has_expected_fields(self) -> None:
        mw = _sync_client()
        result = mw.recall("test", limit=3)
        for mem in result.results:
            assert isinstance(mem.text, str)
            assert isinstance(mem.blob_id, str)
            assert isinstance(mem.distance, float)


@requires_key
class TestAnalyze:
    """analyze() against live server."""

    def test_analyze_returns_facts(self) -> None:
        mw = _sync_client()
        result = mw.analyze("I love hiking and my favorite food is pho.")
        assert isinstance(result.facts, list)
        assert result.total >= 0
        assert result.owner.startswith("0x")
        print(f"\n  extracted {result.total} facts")
        for fact in result.facts:
            print(f"    - {fact.text}")


@requires_key
class TestAsk:
    """ask() against live server."""

    def test_ask_returns_string_answer(self) -> None:
        mw = _sync_client()
        result = mw.ask("What outdoor activities do I enjoy?", limit=3)
        assert isinstance(result.answer, str)
        assert len(result.answer) > 0
        assert isinstance(result.memories_used, int)
        assert isinstance(result.memories, list)
        print(f"\n  answer: {result.answer[:80]}...")
        print(f"  memories_used={result.memories_used}")


@requires_key
class TestFullFlow:
    """End-to-end: remember → recall → verify the stored memory surfaces."""

    def test_remember_then_recall_finds_it(self) -> None:
        import uuid

        unique = str(uuid.uuid4())[:8]
        text = f"SDK e2e test {unique}: quantum entanglement in photonics"
        ns = f"sdk-e2e-{unique}"

        mw = _sync_client()

        # Store a distinctive memory in an isolated namespace
        mem = mw.remember_and_wait(text, namespace=ns, timeout_ms=_REMEMBER_TIMEOUT_MS)
        assert mem.id is not None

        # Recall — should find the stored memory
        result = mw.recall(f"quantum photonics {unique}", limit=5, namespace=ns)
        assert result.total >= 1, f"Expected >= 1 result, got {result.total}"
        assert any(unique in r.text for r in result.results), (
            f"Expected unique marker '{unique}' in recalled texts: "
            + str([r.text for r in result.results])
        )
        print(f"\n  stored id={mem.id[:8]}..., recalled {result.total} results")

    def test_remember_then_ask_uses_memory(self) -> None:
        """remember → ask — answer should reference the stored fact."""
        mw = _sync_client()
        mw.remember_and_wait(
            "I am allergic to shellfish", timeout_ms=_REMEMBER_TIMEOUT_MS
        )
        result = mw.ask("What are my food allergies?", limit=3)
        assert isinstance(result.answer, str)
        assert len(result.answer) > 0
        print(f"\n  ask answer: {result.answer[:100]}")


# ── Async variants ────────────────────────────────────────────────────────────


@requires_key
class TestAsync:
    """Async client variants."""

    async def test_async_health(self) -> None:
        async with _async_client() as mw:
            result = await mw.health()
            assert result.status == "ok"

    async def test_async_remember(self) -> None:
        async with _async_client() as mw:
            result = await mw.remember("Async SDK test: Paris is the capital of France")
            assert result.job_id is not None
            assert result.status in ("pending", "running")

    async def test_async_recall(self) -> None:
        async with _async_client() as mw:
            await mw.remember_and_wait(
                "Async SDK test: I enjoy reading", timeout_ms=_REMEMBER_TIMEOUT_MS
            )
            result = await mw.recall("reading books", limit=3)
            assert isinstance(result.results, list)

    async def test_async_analyze(self) -> None:
        async with _async_client() as mw:
            result = await mw.analyze("I drink tea every morning.")
            assert isinstance(result.facts, list)

    async def test_async_ask(self) -> None:
        async with _async_client() as mw:
            result = await mw.ask("What do I drink?", limit=3)
            assert isinstance(result.answer, str)

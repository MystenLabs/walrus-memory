"""
Tests for derived idempotency keys in Python SDK (GH #1094, WALM-800).

Validates parity with TypeScript SDK specification:
- An omitted idempotency_key is derived from bucket + namespace + text:
  r1-{sha256(bucket \0 namespace \0 text)}
- Repeated identical writes reuse the same idempotency key across client instances
- Different texts or namespaces produce distinct keys
- Explicit idempotency keys are respected
- MemWalSync synchronous wrapper inherits the same behavior
"""

import hashlib
import json
import time
from unittest.mock import patch

import httpx
import pytest
import respx

from memwal.client import (
    IDEMPOTENCY_BUCKET_MS,
    MemWal,
    MemWalRememberJobFailed,
    MemWalRememberJobNotFound,
    MemWalRememberJobTimeout,
    MemWalSync,
    _derived_idempotency_key,
)
from memwal.utils import bytes_to_hex

_TEST_KEY_HEX = bytes_to_hex(b"\x01" * 32)
_TEST_ACCOUNT_ID = "0xabc123"
_TEST_SERVER = "http://localhost:8000"


def _make_client(namespace: str = "default") -> MemWal:
    client = MemWal.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
        namespace=namespace,
    )
    # Cache a valid seal session (expiry in milliseconds) to avoid needing live Sui RPC
    client._session_cache = ("fake-seal-session", int(time.time() * 1000) + 3_600_000)
    return client


def _mock_version_and_config():
    respx.get(f"{_TEST_SERVER}/version").mock(
        return_value=httpx.Response(
            200,
            json={
                "apiVersion": "1.0.0",
                "relayerVersion": "1.0.0",
                "minSupportedSdk": {"python": "0.1.0"},
            },
        )
    )
    respx.get(f"{_TEST_SERVER}/config").mock(
        return_value=httpx.Response(
            200,
            json={"packageId": "0x1", "network": "testnet"},
        )
    )


def test_derived_idempotency_key_format_and_cross_language_parity():
    """Verify byte-for-byte SHA256 digest parity with TypeScript SDK."""
    bucket = 123456
    request_identity = "default\0I am allergic to peanuts"

    # Pre-calculated reference matching TypeScript:
    # r1-${sha256("123456\0default\0I am allergic to peanuts")}
    expected_digest = hashlib.sha256(f"{bucket}\0{request_identity}".encode("utf-8")).hexdigest()
    expected_key = f"r1-{expected_digest}"
    assert expected_key == "r1-8690455a552eca1cc0d77d60b2a7c2a05a2dd836874f5106b1c9967dc5adc083"

    with patch("time.time", return_value=(bucket * IDEMPOTENCY_BUCKET_MS) / 1000.0):
        actual_key = _derived_idempotency_key(request_identity)
        assert actual_key == expected_key
        assert actual_key.startswith("r1-")
        assert len(actual_key) == 3 + 64


@respx.mock
@pytest.mark.asyncio
async def test_same_fact_reuses_one_idempotency_key_across_client_instances():
    """Two instances build what sidecars or serverless functions run on reconnect.

    A per-instance random uuid4 made the replay look like a new write, so the
    relayer minted a second paid Walrus blob. The content-based derived key
    ensures both send the identical key.
    """
    _mock_version_and_config()
    posted_bodies = []

    def handle_remember(request: httpx.Request) -> httpx.Response:
        posted_bodies.append(json.loads(request.content))
        return httpx.Response(202, json={"job_id": "job-1", "status": "pending"})

    respx.post(f"{_TEST_SERVER}/api/remember").mock(side_effect=handle_remember)
    respx.get(f"{_TEST_SERVER}/api/remember/job-1").mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "job-1",
                "status": "done",
                "blob_id": "blob-1",
                "owner": _TEST_ACCOUNT_ID,
                "namespace": "default",
            },
        )
    )

    client1 = _make_client()
    await client1.remember_and_wait("a durable fact")

    client2 = _make_client()
    await client2.remember_and_wait("a durable fact")

    assert len(posted_bodies) == 2
    assert posted_bodies[0]["idempotency_key"] == posted_bodies[1]["idempotency_key"]
    assert posted_bodies[0]["idempotency_key"].startswith("r1-")


@respx.mock
@pytest.mark.asyncio
async def test_remember_async_reuses_derived_key():
    """remember() (async accept) also derives the content key."""
    _mock_version_and_config()
    posted_bodies = []

    def handle_remember(request: httpx.Request) -> httpx.Response:
        posted_bodies.append(json.loads(request.content))
        job_id = f"job-{len(posted_bodies)}"
        return httpx.Response(202, json={"job_id": job_id, "status": "pending"})

    respx.post(f"{_TEST_SERVER}/api/remember").mock(side_effect=handle_remember)

    client = _make_client()
    await client.remember("user likes pizza")
    await client.remember("user likes pizza")

    assert len(posted_bodies) == 2
    assert posted_bodies[0]["idempotency_key"] == posted_bodies[1]["idempotency_key"]


@respx.mock
@pytest.mark.asyncio
async def test_different_text_and_namespaces_get_different_keys():
    """Distinct writes must not collapse onto one job."""
    _mock_version_and_config()
    posted_bodies = []

    def handle_remember(request: httpx.Request) -> httpx.Response:
        posted_bodies.append(json.loads(request.content))
        job_id = f"job-{len(posted_bodies)}"
        return httpx.Response(202, json={"job_id": job_id, "status": "pending"})

    respx.post(f"{_TEST_SERVER}/api/remember").mock(side_effect=handle_remember)

    client = _make_client()
    await client.remember("fact one")
    await client.remember("fact two")
    await client.remember("fact one", namespace="other-namespace")

    keys = [b["idempotency_key"] for b in posted_bodies]
    assert len(set(keys)) == 3, "distinct writes must produce distinct keys"


@respx.mock
@pytest.mark.asyncio
async def test_explicit_idempotency_key_still_wins():
    """When the caller passes an explicit key, that key is sent directly."""
    _mock_version_and_config()
    posted_bodies = []

    def handle_remember(request: httpx.Request) -> httpx.Response:
        posted_bodies.append(json.loads(request.content))
        return httpx.Response(202, json={"job_id": "job-explicit", "status": "pending"})

    respx.post(f"{_TEST_SERVER}/api/remember").mock(side_effect=handle_remember)

    client = _make_client()
    await client.remember("a fact", idempotency_key="caller-owned-key")

    assert len(posted_bodies) == 1
    assert posted_bodies[0]["idempotency_key"] == "caller-owned-key"


@respx.mock
@pytest.mark.asyncio
async def test_remember_and_wait_preserves_key_on_polling_timeout():
    """If polling times out, the pending key stays in the map for immediate retry."""
    _mock_version_and_config()
    posted_bodies = []

    def handle_remember(request: httpx.Request) -> httpx.Response:
        posted_bodies.append(json.loads(request.content))
        return httpx.Response(202, json={"job_id": "slow-job", "status": "pending"})

    respx.post(f"{_TEST_SERVER}/api/remember").mock(side_effect=handle_remember)
    respx.get(f"{_TEST_SERVER}/api/remember/slow-job").mock(
        return_value=httpx.Response(200, json={"job_id": "slow-job", "status": "running"})
    )

    client = _make_client()
    with pytest.raises(MemWalRememberJobTimeout):
        await client.remember_and_wait("timeout fact", poll_interval_ms=10, timeout_ms=50)

    # Key must still be in pending map
    request_identity = "default\0timeout fact"
    assert request_identity in client._pending_remember_keys
    pending_key = client._pending_remember_keys[request_identity]

    # Retry uses the exact same pending key
    with pytest.raises(MemWalRememberJobTimeout):
        await client.remember_and_wait("timeout fact", poll_interval_ms=10, timeout_ms=50)

    assert len(posted_bodies) == 2
    assert posted_bodies[0]["idempotency_key"] == pending_key
    assert posted_bodies[1]["idempotency_key"] == pending_key


@respx.mock
def test_sync_client_uses_derived_key():
    """MemWalSync synchronous client derives and reuses content keys."""
    _mock_version_and_config()
    posted_bodies = []

    def handle_remember(request: httpx.Request) -> httpx.Response:
        posted_bodies.append(json.loads(request.content))
        return httpx.Response(202, json={"job_id": "job-sync", "status": "pending"})

    respx.post(f"{_TEST_SERVER}/api/remember").mock(side_effect=handle_remember)

    sync_client = MemWalSync.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
        namespace="default",
    )
    sync_client._inner._session_cache = ("fake-seal-session", int(time.time() * 1000) + 3_600_000)

    sync_client.remember("sync fact")
    sync_client.remember("sync fact")

    assert len(posted_bodies) == 2
    assert posted_bodies[0]["idempotency_key"] == posted_bodies[1]["idempotency_key"]
    assert posted_bodies[0]["idempotency_key"].startswith("r1-")


# ------------------------------------------------------------------
# Regression tests for GH #1001: terminal job failure must pop the
# pending key so a future retry with the same text derives a fresh
# idempotency key instead of re-sending the poisoned one.
# ------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_remember_and_wait_pops_key_on_terminal_job_failure():
    """_pending_remember_keys is cleaned up when the job fails terminally,
    and a subsequent retry of the same text sends a fresh idempotency key.
    """
    _mock_version_and_config()
    posted_bodies = []

    def handle_remember(request: httpx.Request) -> httpx.Response:
        posted_bodies.append(json.loads(request.content))
        job_id = "job-fail" if len(posted_bodies) == 1 else "job-ok"
        return httpx.Response(202, json={"job_id": job_id, "status": "pending"})

    respx.post(f"{_TEST_SERVER}/api/remember").mock(side_effect=handle_remember)
    respx.get(f"{_TEST_SERVER}/api/remember/job-fail").mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "job-fail",
                "status": "failed",
                "error": "Walrus upload rejected",
            },
        )
    )
    respx.get(f"{_TEST_SERVER}/api/remember/job-ok").mock(
        return_value=httpx.Response(
            200,
            json={
                "job_id": "job-ok",
                "status": "done",
                "blob_id": "blob-ok",
                "owner": _TEST_ACCOUNT_ID,
                "namespace": "default",
            },
        )
    )

    client = _make_client()
    request_identity = "default\0doomed fact"

    with pytest.raises(MemWalRememberJobFailed, match="Walrus upload rejected"):
        await client.remember_and_wait("doomed fact")

    # The pending key must have been popped despite the exception.
    assert request_identity not in client._pending_remember_keys
    assert len(client._pending_remember_keys) == 0

    # Retrying the same text and namespace sends a fresh idempotency key and succeeds.
    result = await client.remember_and_wait("doomed fact")
    assert result.blob_id == "blob-ok"
    assert len(posted_bodies) == 2
    assert posted_bodies[0]["idempotency_key"] != posted_bodies[1]["idempotency_key"]
    assert posted_bodies[1]["idempotency_key"].startswith("r1-")


@respx.mock
@pytest.mark.asyncio
async def test_remember_and_wait_pops_key_on_job_not_found():
    """_pending_remember_keys is cleaned up when the job is not found.

    MemWalRememberJobNotFound is also terminal: the relayer lost track of
    the job so keeping the key around only blocks fresh retries.
    """
    _mock_version_and_config()

    respx.post(f"{_TEST_SERVER}/api/remember").mock(
        return_value=httpx.Response(
            202, json={"job_id": "job-gone", "status": "pending"}
        )
    )
    respx.get(f"{_TEST_SERVER}/api/remember/job-gone").mock(
        return_value=httpx.Response(
            200,
            json={"job_id": "job-gone", "status": "not_found"},
        )
    )

    client = _make_client()
    request_identity = "default\0vanished fact"

    with pytest.raises(MemWalRememberJobNotFound):
        await client.remember_and_wait("vanished fact")

    assert request_identity not in client._pending_remember_keys

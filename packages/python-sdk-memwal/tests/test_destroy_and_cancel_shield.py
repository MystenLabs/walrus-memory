"""Tests for MemWal.destroy() key-wipe (WALM-694 / GH #975) and concurrent
initialization cancellation shielding (WALM-791 / GH #1029)."""

from __future__ import annotations

import asyncio
import json
from typing import Dict, List

import httpx
import pytest

from memwal import (
    MemWal,
    MemWalError,
    MemWalMock,
    MemWalMockSync,
    MemWalSync,
    RecallParams,
)

PRIVATE_KEY_HEX = "a" * 64
ACCOUNT_ID = "0x" + "1" * 64
PACKAGE_ID = "0x" + "2" * 64
SERVER_URL = "https://relayer.example.com"


# ============================================================
# WALM-694 / GH #975: destroy(), close(clear_keys=True), bytes/bytearray keys
# ============================================================


class TestDestroyAndKeyWipe:
    @pytest.mark.asyncio
    async def test_accepts_bytes_and_bytearray_keys_and_clones_caller_buffer(self):
        seed_bytes = bytes.fromhex(PRIVATE_KEY_HEX)
        caller_buf = bytearray(seed_bytes)

        from_hex = MemWal.create(
            key=PRIVATE_KEY_HEX,
            account_id=ACCOUNT_ID,
            server_url=SERVER_URL,
        )
        from_bytes = MemWal.create(
            key=seed_bytes,
            account_id=ACCOUNT_ID,
            server_url=SERVER_URL,
        )
        from_bytearray = MemWal.create(
            key=caller_buf,
            account_id=ACCOUNT_ID,
            server_url=SERVER_URL,
        )

        expected_pub = await from_hex.get_public_key_hex()
        assert await from_bytes.get_public_key_hex() == expected_pub
        assert await from_bytearray.get_public_key_hex() == expected_pub

        # Mutating caller's bytearray after create() does not affect client
        caller_buf[:] = b"\xff" * 32
        assert from_bytearray._private_key_bytes == bytearray(seed_bytes)
        assert await from_bytearray.get_public_key_hex() == expected_pub

        await from_hex.close()
        await from_bytes.close()
        await from_bytearray.close()

    def test_rejects_wrong_length_bytes_key(self):
        with pytest.raises(ValueError, match="32 bytes"):
            MemWal.create(
                key=b"\xaa" * 16,
                account_id=ACCOUNT_ID,
                server_url=SERVER_URL,
            )

    @pytest.mark.asyncio
    async def test_destroy_zeroes_internal_buffer_without_mutating_caller_bytearray(self):
        caller_buf = bytearray(bytes.fromhex(PRIVATE_KEY_HEX))
        client = MemWal.create(
            key=caller_buf,
            account_id=ACCOUNT_ID,
            server_url=SERVER_URL,
        )
        internal_ref = client._private_key_bytes
        assert internal_ref == bytearray(bytes.fromhex(PRIVATE_KEY_HEX))

        client.destroy()
        # Idempotent second call
        client.destroy()

        # Internal bytearray was zeroed in place
        assert internal_ref == bytearray(32)
        assert all(b == 0 for b in client._private_key_bytes)
        # Caller's bytearray was NOT mutated
        assert caller_buf == bytearray(bytes.fromhex(PRIVATE_KEY_HEX))
        # Credentials and caches dropped
        assert client._private_key_hex == ""
        assert client._signing_key is None
        assert client._session_cache is None

        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            await client.get_public_key_hex()
        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            await client.remember("secret")
        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            await client.recall("secret")
        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            await client.health()
        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            await client.compatibility()
        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            await client.restore("default")

        await client.close()

    @pytest.mark.asyncio
    async def test_destroy_mid_flight_aborts_pending_request(self):
        config_entered = asyncio.Event()
        release_config = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/version":
                return httpx.Response(
                    200,
                    json={
                        "apiVersion": "1.0.0",
                        "relayerVersion": "0.1.0",
                        "minSupportedSdk": {
                            "typescript": "0.0.0",
                            "python": "0.0.0",
                            "mcp": "0.0.0",
                        },
                    },
                )
            if path == "/config":
                config_entered.set()
                await release_config.wait()
                return httpx.Response(
                    200,
                    json={
                        "packageId": PACKAGE_ID,
                        "network": "testnet",
                        "suiRpcUrl": "https://rpc.testnet.sui.io",
                    },
                )
            return httpx.Response(500, text=f"unexpected {path}")

        client = MemWal.create(
            key=PRIVATE_KEY_HEX,
            account_id=ACCOUNT_ID,
            server_url=SERVER_URL,
        )
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

        recall_task = asyncio.create_task(client.recall(RecallParams(query="test")))
        await config_entered.wait()

        client.destroy()
        release_config.set()

        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            await recall_task
        assert client._session_cache is None
        await client.close()

    @pytest.mark.asyncio
    async def test_close_with_clear_keys_destroys_client(self):
        client = MemWal.create(
            key=PRIVATE_KEY_HEX,
            account_id=ACCOUNT_ID,
            server_url=SERVER_URL,
        )
        # Default close(clear_keys=False) preserves keys
        await client.close()
        assert client._destroyed is False
        assert await client.get_public_key_hex() != ""

        # close(clear_keys=True) wipes keys and marks destroyed
        await client.close(clear_keys=True)
        assert client._destroyed is True
        assert all(b == 0 for b in client._private_key_bytes)
        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            await client.get_public_key_hex()

    def test_sync_client_destroy_and_close_clear_keys(self):
        caller_buf = bytearray(bytes.fromhex(PRIVATE_KEY_HEX))
        sync_client = MemWalSync.create(
            key=caller_buf,
            account_id=ACCOUNT_ID,
            server_url=SERVER_URL,
        )
        assert sync_client.get_public_key_hex() != ""

        sync_client.close(clear_keys=True)
        assert caller_buf == bytearray(bytes.fromhex(PRIVATE_KEY_HEX))
        with pytest.raises(MemWalError, match="Walrus Memory client was destroyed"):
            sync_client.get_public_key_hex()

    @pytest.mark.asyncio
    async def test_mock_parity_destroy_and_close_clear_keys(self):
        mock = MemWalMock.create()
        mock.destroy()
        await mock.close(clear_keys=True)

        sync_mock = MemWalMockSync.create()
        sync_mock.destroy()
        sync_mock.close(clear_keys=True)


# ============================================================
# WALM-791 / GH #1029: Concurrent initialization cancellation shielding
# ============================================================


class Gate:
    """Deterministic barrier when N coroutines enter, plus explicit release."""

    def __init__(self, parties: int = 1) -> None:
        self._parties = parties
        self._count = 0
        self.entered = asyncio.Event()
        self.release_event = asyncio.Event()

    async def wait(self) -> None:
        self._count += 1
        if self._count >= self._parties:
            self.entered.set()
        await self.release_event.wait()

    def release(self) -> None:
        self.release_event.set()


class FakeTransport:
    """Counted transport for /version, /config, GraphQL package version, and /api/recall."""

    def __init__(
        self,
        *,
        config_gate: Gate | None = None,
        fail_config_times: int = 0,
    ) -> None:
        self.config_gate = config_gate
        self.fail_config_times = fail_config_times
        self.counts: Dict[str, int] = {
            "version": 0,
            "config": 0,
            "graphql": 0,
            "recall": 0,
            "stats": 0,
            "restore": 0,
        }
        self.recall_headers: List[Dict[str, str]] = []

    async def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/version":
            self.counts["version"] += 1
            return httpx.Response(
                200,
                json={
                    "apiVersion": "1.0.0",
                    "relayerVersion": "0.1.0",
                    "minSupportedSdk": {
                        "typescript": "0.0.0",
                        "python": "0.0.0",
                        "mcp": "0.0.0",
                    },
                },
            )

        if path == "/config":
            self.counts["config"] += 1
            if self.config_gate is not None:
                await self.config_gate.wait()
            if self.counts["config"] <= self.fail_config_times:
                return httpx.Response(503, text="config temporary failure")
            return httpx.Response(
                200,
                json={
                    "packageId": PACKAGE_ID,
                    "network": "testnet",
                    "suiRpcUrl": "https://rpc.testnet.sui.io:443",
                },
            )

        if request.url.host == "graphql.testnet.sui.io":
            self.counts["graphql"] += 1
            return httpx.Response(200, json={"data": {"object": {"version": 1}}})

        if path == "/api/recall":
            self.counts["recall"] += 1
            self.recall_headers.append(dict(request.headers))
            payload = json.loads(request.content.decode("utf-8"))
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": f"mem-{self.counts['recall']}",
                            "blob_id": f"blob-{self.counts['recall']}",
                            "text": f"match for {payload['query']}",
                            "distance": 0.1,
                            "namespace": payload["namespace"],
                        }
                    ],
                    "total": 1,
                },
            )

        if path == "/api/stats":
            self.counts["stats"] += 1
            if self.config_gate is not None:
                await self.config_gate.wait()
            return httpx.Response(200, json={"owner": "0x" + "9" * 64})

        if path.startswith("/v1/owners/") and path.endswith("/namespaces"):
            self.counts["restore"] += 1
            return httpx.Response(
                200,
                json={"namespaces": [], "has_more": False, "snapshot_version": 2},
            )

        return httpx.Response(500, text=f"unexpected request {request.method} {request.url}")


def make_client(transport: FakeTransport) -> MemWal:
    client = MemWal.create(
        key=PRIVATE_KEY_HEX,
        account_id=ACCOUNT_ID,
        server_url=SERVER_URL,
    )
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(transport.handle))
    return client


async def wait_until(predicate, *, turns: int = 20) -> None:
    for _ in range(turns):
        if predicate():
            return
        await asyncio.sleep(0)
    assert predicate()


@pytest.mark.asyncio
async def test_normal_concurrent_and_cached_retry() -> None:
    gate = Gate()
    transport = FakeTransport(config_gate=gate)
    client = make_client(transport)

    first = asyncio.create_task(client.recall(RecallParams(query="first")))
    await gate.entered.wait()

    second = asyncio.create_task(client.recall(RecallParams(query="second")))
    await wait_until(lambda: client._session_build_task is not None)
    gate.release()

    r1, r2 = await asyncio.gather(first, second)
    r3 = await client.recall(RecallParams(query="third"))

    assert [r1.total, r2.total, r3.total] == [1, 1, 1]
    assert transport.counts == {
        "version": 1,
        "config": 1,
        "graphql": 1,
        "recall": 3,
        "stats": 0,
        "restore": 0,
    }
    sessions = {h["x-seal-session"] for h in transport.recall_headers}
    assert len(sessions) == 1

    await client.close()


@pytest.mark.asyncio
async def test_cancel_creator_preserves_waiter_and_late_join() -> None:
    gate = Gate()
    transport = FakeTransport(config_gate=gate)
    client = make_client(transport)

    creator = asyncio.create_task(client.recall(RecallParams(query="creator")))
    await gate.entered.wait()

    waiter = asyncio.create_task(client.recall(RecallParams(query="waiter")))
    await asyncio.sleep(0)

    creator.cancel()
    with pytest.raises(asyncio.CancelledError):
        await creator

    # Join after creator cancelled while the shared session build is still in flight.
    late = asyncio.create_task(client.recall(RecallParams(query="late")))
    await asyncio.sleep(0)

    gate.release()
    waiter_result, late_result = await asyncio.gather(waiter, late)
    retry_result = await client.recall(RecallParams(query="retry"))

    assert waiter_result.results[0].text == "match for waiter"
    assert late_result.results[0].text == "match for late"
    assert retry_result.results[0].text == "match for retry"
    assert transport.counts["config"] == 1
    assert transport.counts["graphql"] == 1
    assert transport.counts["recall"] == 3

    await client.close()


@pytest.mark.asyncio
async def test_cancel_waiter_preserves_creator_and_late_join() -> None:
    gate = Gate()
    transport = FakeTransport(config_gate=gate)
    client = make_client(transport)

    creator = asyncio.create_task(client.recall(RecallParams(query="creator")))
    await gate.entered.wait()

    waiter = asyncio.create_task(client.recall(RecallParams(query="waiter")))
    await asyncio.sleep(0)

    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    late = asyncio.create_task(client.recall(RecallParams(query="late")))
    await asyncio.sleep(0)

    gate.release()
    creator_result, late_result = await asyncio.gather(creator, late)
    assert creator_result.results[0].text == "match for creator"
    assert late_result.results[0].text == "match for late"
    assert transport.counts["config"] == 1
    assert transport.counts["graphql"] == 1
    assert transport.counts["recall"] == 2

    await client.close()


@pytest.mark.asyncio
async def test_real_initialization_failure_reaches_both_then_retry_succeeds() -> None:
    gate = Gate()
    transport = FakeTransport(config_gate=gate, fail_config_times=1)
    client = make_client(transport)

    first = asyncio.create_task(client.recall(RecallParams(query="first")))
    await gate.entered.wait()

    second = asyncio.create_task(client.recall(RecallParams(query="second")))
    await asyncio.sleep(0)
    gate.release()

    outcomes = await asyncio.gather(first, second, return_exceptions=True)
    assert all(isinstance(outcome, MemWalError) for outcome in outcomes)
    assert transport.counts["config"] == 1
    assert transport.counts["recall"] == 0
    assert client._session_build_task is None

    recovered = await client.recall(RecallParams(query="recovered"))
    assert recovered.results[0].text == "match for recovered"
    assert transport.counts["config"] == 2
    assert transport.counts["graphql"] == 1
    assert transport.counts["recall"] == 1

    await client.close()


@pytest.mark.asyncio
async def test_all_cancelled_success_populates_cache() -> None:
    gate = Gate()
    transport = FakeTransport(config_gate=gate)
    client = make_client(transport)

    first = asyncio.create_task(client.recall(RecallParams(query="first")))
    await gate.entered.wait()
    second = asyncio.create_task(client.recall(RecallParams(query="second")))
    await asyncio.sleep(0)

    first.cancel()
    second.cancel()
    for task in (first, second):
        with pytest.raises(asyncio.CancelledError):
            await task

    gate.release()
    await wait_until(lambda: client._session_build_task is None)

    later = await client.recall(RecallParams(query="later"))
    assert later.results[0].text == "match for later"
    assert transport.counts["config"] == 1
    assert transport.counts["graphql"] == 1
    assert transport.counts["recall"] == 1

    await client.close()


@pytest.mark.asyncio
async def test_all_cancelled_failure_has_no_unretrieved_exception() -> None:
    loop = asyncio.get_running_loop()
    unhandled: List[Dict[str, object]] = []
    previous_handler = loop.get_exception_handler()

    def handler(_loop: asyncio.AbstractEventLoop, context: Dict[str, object]) -> None:
        unhandled.append(context)

    loop.set_exception_handler(handler)
    try:
        gate = Gate()
        transport = FakeTransport(config_gate=gate, fail_config_times=1)
        client = make_client(transport)

        first = asyncio.create_task(client.recall(RecallParams(query="first")))
        await gate.entered.wait()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first

        gate.release()
        await wait_until(lambda: client._session_build_task is None)

        later = await client.recall(RecallParams(query="later"))
        assert later.results[0].text == "match for later"
        assert transport.counts["config"] == 2
        await client.close()
    finally:
        loop.set_exception_handler(previous_handler)

    assert unhandled == []


@pytest.mark.asyncio
async def test_close_cancels_and_drains_orphaned_initialization() -> None:
    gate = Gate()
    transport = FakeTransport(config_gate=gate)
    client = make_client(transport)

    first = asyncio.create_task(client.recall(RecallParams(query="first")))
    await gate.entered.wait()
    build_task = client._session_build_task
    assert build_task is not None

    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    await client.close()
    assert build_task.cancelled()
    assert client._session_build_task is None
    assert client._session_cache is None


@pytest.mark.asyncio
async def test_cancel_owner_resolution_creator_preserves_waiter() -> None:
    gate = Gate()
    transport = FakeTransport(config_gate=gate)
    client = make_client(transport)

    creator = asyncio.create_task(client.list_namespaces())
    await gate.entered.wait()

    waiter = asyncio.create_task(client.list_namespaces())
    await asyncio.sleep(0)

    creator.cancel()
    with pytest.raises(asyncio.CancelledError):
        await creator

    late = asyncio.create_task(client.list_namespaces())
    await asyncio.sleep(0)

    gate.release()
    waiter_res, late_res = await asyncio.gather(waiter, late)
    assert waiter_res.namespaces == []
    assert late_res.namespaces == []
    assert transport.counts["stats"] == 1
    assert transport.counts["restore"] == 2

    await client.close()

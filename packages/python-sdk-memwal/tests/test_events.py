"""
Tests for subscribe_events SSE stream in Python SDK.
"""

from __future__ import annotations

import json

import httpx
import nacl.signing
import pytest
import respx

from memwal import (
    MemoryEvent,
    MemWal,
    MemWalCompatibilityError,
    MemWalError,
    MemWalRateLimited,
    MemWalSync,
)
from memwal.utils import bytes_to_hex

_TEST_SEED = b"\x02" * 32
_TEST_KEY = nacl.signing.SigningKey(_TEST_SEED)
_TEST_KEY_HEX = bytes_to_hex(bytes(_TEST_KEY))
_TEST_PUB_HEX = bytes_to_hex(bytes(_TEST_KEY.verify_key))
_TEST_ACCOUNT_ID = "0x" + "aa" * 32
_TEST_SERVER = "http://localhost:8000"


def _mock_version() -> None:
    respx.get(f"{_TEST_SERVER}/version").mock(
        return_value=httpx.Response(
            200,
            json={
                "relayerVersion": "0.1.0",
                "apiVersion": "1.0.0",
                "minSupportedSdk": {
                    "typescript": "0.0.4",
                    "python": "0.1.0",
                    "mcp": "0.0.1",
                },
                "featureFlags": {},
                "deprecations": [],
                "build": {},
            },
        )
    )


@pytest.mark.asyncio
@respx.mock
async def test_subscribe_events_parses_sse_stream() -> None:
    _mock_version()

    event1 = {
        "id": "evt-001",
        "type": "memory.remember.accepted",
        "owner": "0xowner",
        "namespace": "default",
        "timestamp": "2026-11-03T00:00:00Z",
        "job_id": "job-123",
        "count": 1,
    }
    event2 = {
        "id": "evt-002",
        "type": "memory.remember.completed",
        "owner": "0xowner",
        "namespace": "default",
        "timestamp": "2026-11-03T00:00:01Z",
        "job_id": "job-123",
        "blob_id": "blob-456",
        "count": 1,
    }

    sse_body = (
        ": keepalive\n\n"
        f"event: memory.remember.accepted\ndata: {json.dumps(event1)}\nid: evt-001\n\n"
        ": keepalive\n\n"
        f"event: memory.remember.completed\ndata: {json.dumps(event2)}\nid: evt-002\n\n"
    )

    events_route = respx.get(f"{_TEST_SERVER}/api/events").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=sse_body.encode("utf-8"),
        )
    )

    client = MemWal.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )

    received: list[MemoryEvent] = []
    async for event in client.subscribe_events():
        received.append(event)

    assert len(received) == 2
    assert received[0].id == "evt-001"
    assert received[0].type == "memory.remember.accepted"
    assert received[0].job_id == "job-123"
    assert received[0].count == 1
    assert received[1].id == "evt-002"
    assert received[1].type == "memory.remember.completed"
    assert received[1].blob_id == "blob-456"

    assert events_route.called
    req = events_route.calls[0].request
    assert req.headers["accept"] == "text/event-stream"
    assert req.headers["x-public-key"] == _TEST_PUB_HEX
    assert req.headers["x-account-id"] == _TEST_ACCOUNT_ID
    assert "x-signature" in req.headers
    assert "x-timestamp" in req.headers
    assert "x-nonce" in req.headers

    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_subscribe_events_query_parameters() -> None:
    _mock_version()

    event = {
        "id": "evt-003",
        "type": "memory.forget",
        "owner": "0xowner",
        "namespace": "analytics",
        "timestamp": "2026-11-03T00:00:02Z",
        "count": 5,
    }
    sse_body = f"event: memory.forget\ndata: {json.dumps(event)}\nid: evt-003\n\n"

    events_route = respx.get(
        f"{_TEST_SERVER}/api/events?namespace=analytics&types=memory.forget"
    ).mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=sse_body.encode("utf-8"),
        )
    )

    client = MemWal.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )

    events: list[MemoryEvent] = []
    async for evt in client.subscribe_events(
        namespace="analytics", types=["memory.forget"]
    ):
        events.append(evt)

    assert len(events) == 1
    assert events[0].type == "memory.forget"
    assert events[0].namespace == "analytics"
    assert events[0].count == 5
    assert events_route.called

    await client.close()


@pytest.mark.asyncio
async def test_subscribe_events_validations() -> None:
    client = MemWal.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )

    with pytest.raises(ValueError, match="namespace must be a non-empty string"):
        async for _ in client.subscribe_events(namespace=""):
            pass

    with pytest.raises(ValueError, match="types must be a non-empty sequence"):
        async for _ in client.subscribe_events(types=[]):
            pass

    with pytest.raises(ValueError, match="types must be a non-empty sequence"):
        async for _ in client.subscribe_events(types="memory.forget"):  # type: ignore[arg-type]
            pass

    with pytest.raises(ValueError, match="each event type in types must be a non-empty string"):
        async for _ in client.subscribe_events(types=[""]):
            pass

    client.destroy()
    with pytest.raises(MemWalError, match="destroyed"):
        async for _ in client.subscribe_events():
            pass


@respx.mock
def test_subscribe_events_sync_wrapper() -> None:
    _mock_version()

    event = {
        "id": "evt-004",
        "type": "memory.restore.completed",
        "owner": "0xowner",
        "namespace": "docs",
        "timestamp": "2026-11-03T00:00:03Z",
        "count": 10,
        "skipped": 2,
    }
    sse_body = f"data: {json.dumps(event)}\n\n"

    respx.get(f"{_TEST_SERVER}/api/events?namespace=docs").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=sse_body.encode("utf-8"),
        )
    )

    client = MemWalSync.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )

    items = list(client.subscribe_events(namespace="docs"))
    assert len(items) == 1
    assert items[0].id == "evt-004"
    assert items[0].type == "memory.restore.completed"
    assert items[0].namespace == "docs"
    assert items[0].count == 10
    assert items[0].skipped == 2

    client.close()


@pytest.mark.asyncio
@respx.mock
async def test_subscribe_events_system_lagged_async() -> None:
    _mock_version()

    lag_event = {"type": "system.lagged", "skipped": 7}
    normal_event = {
        "id": "evt-005",
        "type": "memory.remember.completed",
        "owner": "0xowner",
        "namespace": "default",
        "timestamp": "2026-11-03T00:00:04Z",
        "job_id": "job-456",
        "count": 1,
    }
    sse_body = (
        f"event: system.lagged\ndata: {json.dumps(lag_event)}\n\n"
        f"event: memory.remember.completed\ndata: {json.dumps(normal_event)}\n\n"
    )

    respx.get(f"{_TEST_SERVER}/api/events").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=sse_body.encode("utf-8"),
        )
    )

    client = MemWal.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )

    events = []
    async for evt in client.subscribe_events():
        events.append(evt)

    assert len(events) == 2
    assert events[0].type == "system.lagged"
    assert events[0].skipped == 7
    assert events[1].type == "memory.remember.completed"
    assert events[1].id == "evt-005"
    assert events[1].job_id == "job-456"

    await client.close()


@respx.mock
def test_subscribe_events_system_lagged_sync() -> None:
    _mock_version()

    lag_event = {"type": "system.lagged", "skipped": 7}
    normal_event = {
        "id": "evt-006",
        "type": "memory.remember.completed",
        "owner": "0xowner",
        "namespace": "default",
        "timestamp": "2026-11-03T00:00:05Z",
        "job_id": "job-789",
        "count": 2,
    }
    sse_body = (
        f"event: system.lagged\ndata: {json.dumps(lag_event)}\n\n"
        f"event: memory.remember.completed\ndata: {json.dumps(normal_event)}\n\n"
    )

    respx.get(f"{_TEST_SERVER}/api/events").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/event-stream"},
            content=sse_body.encode("utf-8"),
        )
    )

    client = MemWalSync.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )

    events = list(client.subscribe_events())
    assert len(events) == 2
    assert events[0].type == "system.lagged"
    assert events[0].skipped == 7
    assert events[1].type == "memory.remember.completed"
    assert events[1].id == "evt-006"
    assert events[1].count == 2

    client.close()


@respx.mock
def test_subscribe_events_sync_stream_unread_errors() -> None:
    _mock_version()

    # Streamed 429 rate limited
    respx.get(f"{_TEST_SERVER}/api/events").mock(
        return_value=httpx.Response(
            429,
            stream=httpx.ByteStream(b"rate limit exceeded"),
        )
    )

    client = MemWalSync.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )

    with pytest.raises(MemWalRateLimited, match="Rate limited by server"):
        list(client.subscribe_events())

    # Streamed 426 upgrade required
    respx.get(f"{_TEST_SERVER}/api/events").mock(
        return_value=httpx.Response(
            426,
            stream=httpx.ByteStream(b"server upgrade required"),
        )
    )
    with pytest.raises(MemWalCompatibilityError, match="HTTP 426 Upgrade Required"):
        list(client.subscribe_events())

    # Streamed 401 unauthorized
    respx.get(f"{_TEST_SERVER}/api/events").mock(
        return_value=httpx.Response(
            401,
            stream=httpx.ByteStream(b"unauthorized access"),
        )
    )
    with pytest.raises(MemWalError, match="HTTP 401: unauthorized access"):
        list(client.subscribe_events())

    client.close()


def test_subscribe_events_sync_validations() -> None:
    client = MemWalSync.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )

    with pytest.raises(ValueError, match="namespace must be a non-empty string"):
        list(client.subscribe_events(namespace=""))

    with pytest.raises(ValueError, match="types must be a non-empty sequence"):
        list(client.subscribe_events(types=[]))

    with pytest.raises(ValueError, match="types must be a non-empty sequence"):
        list(client.subscribe_events(types="memory.forget"))  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="each event type in types must be a non-empty string"):
        list(client.subscribe_events(types=[""]))

    client.destroy()
    with pytest.raises(MemWalError, match="destroyed"):
        list(client.subscribe_events())

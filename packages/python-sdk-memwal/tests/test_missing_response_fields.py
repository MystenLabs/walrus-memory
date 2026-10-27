"""A 2xx body missing a required field raises ``MemWalError`` (#1250).

#1219 covers 2xx bodies that are not JSON. This is the valid-JSON sibling:
six methods subscripted response fields directly, so a relayer that drifted
or a proxy rewriting the body surfaced as a bare ``KeyError`` that callers
catching ``MemWalError`` (the documented error type) never saw.
"""

from __future__ import annotations

from typing import Any, Dict

import httpx
import nacl.signing
import pytest
import respx

from memwal import MemWal, MemWalError
from memwal.types import RememberManualOptions
from memwal.utils import bytes_to_hex

_SERVER = "https://relayer.example"
_KEY_HEX = bytes_to_hex(bytes(nacl.signing.SigningKey(b"\x01" * 32)))


def _client(body: Any) -> MemWal:
    client = MemWal.create(key=_KEY_HEX, account_id="0x1", server_url=_SERVER)

    async def fake_signed_request(method, path, req_body, **kwargs):  # type: ignore[no-untyped-def]
        return body

    async def fake_owner() -> str:
        return "0xowner"

    client._signed_request = fake_signed_request  # type: ignore[method-assign]
    client._resolve_owner = fake_owner  # type: ignore[method-assign]
    return client


def _assert_names(exc: pytest.ExceptionInfo[MemWalError], endpoint: str, field: str) -> None:
    assert not isinstance(exc.value, KeyError)
    message = str(exc.value)
    assert endpoint in message, message
    assert field in message, message


@respx.mock
async def test_health_missing_status() -> None:
    respx.get(f"{_SERVER}/health").mock(return_value=httpx.Response(200, json={}))
    client = MemWal.create(key=_KEY_HEX, account_id="0x1", server_url=_SERVER)
    with pytest.raises(MemWalError) as exc:
        await client.health()
    _assert_names(exc, "GET /health", "status")


@respx.mock
async def test_health_non_object_body() -> None:
    respx.get(f"{_SERVER}/health").mock(return_value=httpx.Response(200, json=["ok"]))
    client = MemWal.create(key=_KEY_HEX, account_id="0x1", server_url=_SERVER)
    with pytest.raises(MemWalError) as exc:
        await client.health()
    _assert_names(exc, "GET /health", "status")


async def test_ask_missing_memories_used() -> None:
    with pytest.raises(MemWalError) as exc:
        await _client({"answer": "hi"}).ask("q?")
    _assert_names(exc, "POST /api/ask", "memories_used")


async def test_ask_memory_entry_missing_text() -> None:
    body = {"answer": "hi", "memories_used": 1, "memories": [{"blob_id": "b", "distance": 0.1}]}
    with pytest.raises(MemWalError) as exc:
        await _client(body).ask("q?")
    _assert_names(exc, "POST /api/ask", "text")


async def test_restore_missing_restored() -> None:
    with pytest.raises(MemWalError) as exc:
        await _client({}).restore("ns")
    _assert_names(exc, "POST /api/restore", "restored")


async def test_list_namespaces_missing_namespaces() -> None:
    with pytest.raises(MemWalError) as exc:
        await _client({}).list_namespaces()
    _assert_names(exc, "namespaces", "namespaces")


async def test_list_namespaces_entry_missing_name() -> None:
    body: Dict[str, Any] = {
        "namespaces": [{"id": "ns-1"}],
        "has_more": False,
        "snapshot_version": 1,
    }
    with pytest.raises(MemWalError) as exc:
        await _client(body).list_namespaces()
    _assert_names(exc, "GET /v1/owners/", "name")


async def test_remember_manual_missing_id() -> None:
    opts = RememberManualOptions(encrypted_data="ZGF0YQ==", vector=[0.1])
    with pytest.raises(MemWalError) as exc:
        await _client({}).remember_manual(opts)
    _assert_names(exc, "POST /api/remember/manual", "id")


async def test_recall_entry_missing_text() -> None:
    body = {"results": [{"blob_id": "b", "distance": 0.1}], "total": 1}
    with pytest.raises(MemWalError) as exc:
        await _client(body).recall("coffee")
    _assert_names(exc, "POST /api/recall", "text")


async def test_well_formed_bodies_still_parse() -> None:
    ask = await _client({"answer": "hi", "memories_used": 0}).ask("q?")
    assert ask.answer == "hi" and ask.memories == []
    recall = await _client(
        {"results": [{"blob_id": "b", "text": "t", "distance": 0.1}], "total": 1}
    ).recall("coffee")
    assert recall.results[0].text == "t"
    restore = await _client(
        {"restored": 1, "skipped": 0, "total": 1, "namespace": "ns", "owner": "0xo"}
    ).restore("ns")
    assert restore.truncated is False and restore.failed == 0

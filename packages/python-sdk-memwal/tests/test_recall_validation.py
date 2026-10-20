"""``recall()`` input validation in the real client and the mock (#1248).

Ports the TypeScript guards from #1228 (blank query) and #1227 (NaN /
negative ``maxDistance``). Before this, the Python client signed an empty
query, and a NaN or negative ``max_distance`` silently dropped every hit the
relayer returned, which looked exactly like an empty namespace.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List

import nacl.signing
import pytest

from memwal import MemWal, MemWalMock, RecallParams
from memwal.utils import bytes_to_hex

_KEY_HEX = bytes_to_hex(bytes(nacl.signing.SigningKey(b"\x01" * 32)))
_HITS = {
    "results": [
        {"blob_id": "b1", "text": "coffee", "distance": 0.5},
        {"blob_id": "b2", "text": "tea", "distance": 1.0},
    ],
    "total": 2,
}

_BAD_DISTANCES = [math.nan, -1.0, -0.001, math.inf, "0.5", True]


def _client(sent: List[Dict[str, Any]]) -> MemWal:
    client = MemWal.create(key=_KEY_HEX, account_id="0x1", server_url="https://relayer.example")

    async def fake_signed_request(method, path, body, **kwargs):  # type: ignore[no-untyped-def]
        sent.append(body)
        return _HITS

    client._signed_request = fake_signed_request  # type: ignore[method-assign]
    return client


@pytest.mark.parametrize("query", ["", "   ", "\t\n"])
async def test_client_rejects_blank_query_before_signing(query: str) -> None:
    sent: List[Dict[str, Any]] = []
    with pytest.raises(ValueError, match="query cannot be empty"):
        await _client(sent).recall(query)
    with pytest.raises(ValueError, match="query cannot be empty"):
        await _client(sent).recall(RecallParams(query=query))
    assert sent == []


@pytest.mark.parametrize("max_distance", _BAD_DISTANCES)
async def test_client_rejects_bad_max_distance_before_signing(max_distance: Any) -> None:
    sent: List[Dict[str, Any]] = []
    with pytest.raises(ValueError, match="max_distance must be a non-negative finite number"):
        await _client(sent).recall("coffee", max_distance=max_distance)
    with pytest.raises(ValueError, match="max_distance must be a non-negative finite number"):
        await _client(sent).recall(RecallParams(query="coffee", max_distance=max_distance))
    assert sent == []


async def test_client_valid_max_distance_still_filters() -> None:
    sent: List[Dict[str, Any]] = []
    result = await _client(sent).recall("coffee", max_distance=0.75)
    assert [m.blob_id for m in result.results] == ["b1"]
    assert result.total == 2
    zero = await _client(sent).recall("coffee", max_distance=0)
    assert zero.results == []


@pytest.mark.parametrize("max_distance", _BAD_DISTANCES)
async def test_mock_rejects_bad_max_distance(max_distance: Any) -> None:
    mock = MemWalMock.create()
    await mock.remember("I like coffee")
    with pytest.raises(ValueError, match="max_distance must be a non-negative finite number"):
        await mock.recall("coffee", max_distance=max_distance)


async def test_mock_valid_max_distance_still_filters() -> None:
    mock = MemWalMock.create()
    await mock.remember("I like coffee")
    result = await mock.recall("coffee", max_distance=2.0)
    assert len(result.results) == 1

"""#1218: non-finite vectors and bad limits must fail client-side.

json.dumps emits bare NaN/Infinity tokens, which are not JSON, so the
relayer rejected the body with an opaque parse error. Limits went out as
NaN, -5 or ?limit=nan.
"""

from __future__ import annotations

import math

import httpx
import pytest

from memwal import (
    MemWal,
    MemWalError,
    MemWalMock,
    RecallManualOptions,
    RecallParams,
    RememberManualOptions,
)


class CaptureMemWal(MemWal):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.captured = []

    async def _ensure_compatible_relayer(self):
        return {
            "apiVersion": "1.0.0",
            "relayerVersion": "capture",
            "minSupportedSdk": {"python": "0.0.0"},
        }

    async def _resolve_owner(self):
        return "0xowner"

    async def _signed_request(
        self,
        method,
        path,
        body,
        accepted_statuses=(200,),
        include_seal_session=True,
        timeout=None,
    ):
        self.captured.append((method, path, body))
        if path.startswith("/v1/owners"):
            return {"namespaces": [], "has_more": False, "snapshot_version": 1}
        if path == "/api/remember/manual":
            return {"id": "1", "blob_id": "b", "owner": "0x1", "namespace": "default"}
        if path == "/api/restore":
            return {"restored": 0, "skipped": 0, "total": 0, "namespace": "ns", "owner": "0x1"}
        return {"results": [], "total": 0}


class FreshOwnerMemWal(MemWal):
    """Keeps the real ``_resolve_owner``, so owner lookup goes through signing.

    Every signed request is recorded and then fails, like a relayer outage:
    a bad limit must surface as ValueError, not as this error.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.signed = []

    async def _ensure_compatible_relayer(self):
        return {
            "apiVersion": "1.0.0",
            "relayerVersion": "capture",
            "minSupportedSdk": {"python": "0.0.0"},
        }

    async def _signed_request(
        self,
        method,
        path,
        body,
        accepted_statuses=(200,),
        include_seal_session=True,
        timeout=None,
    ):
        self.signed.append((method, path))
        raise MemWalError("relayer unavailable")


def _client():
    return CaptureMemWal.create(
        key="11" * 32, account_id="0x" + "ab" * 32, server_url="https://relayer.example"
    )


BAD_VECTORS = [
    [0.1, math.nan],
    [math.inf],
    [0.1, -math.inf],
    [],
    [0.1, "0.2"],
    [0.1, None],
    [True, 0.2],
    "0.1,0.2",
    None,
]
BAD_LIMITS = [math.nan, math.inf, -5, -1, 0, 2.5, "5", True]


@pytest.mark.parametrize("vector", BAD_VECTORS, ids=repr)
async def test_recall_manual_rejects_bad_vector(vector):
    c = _client()
    with pytest.raises(ValueError, match="vector"):
        await c.recall_manual(RecallManualOptions(vector=vector))
    assert c.captured == []


@pytest.mark.parametrize("vector", BAD_VECTORS, ids=repr)
async def test_remember_manual_rejects_bad_vector(vector):
    c = _client()
    with pytest.raises(ValueError, match="vector"):
        await c.remember_manual(RememberManualOptions(encrypted_data="AAAA", vector=vector))
    assert c.captured == []


@pytest.mark.parametrize("limit", BAD_LIMITS, ids=repr)
@pytest.mark.parametrize(
    "call",
    [
        ("recall", lambda c, n: c.recall("q", limit=n)),
        ("recall_params", lambda c, n: c.recall(RecallParams(query="q", limit=n))),
        ("recall_manual", lambda c, n: c.recall_manual(RecallManualOptions(vector=[0.1], limit=n))),
        ("restore", lambda c, n: c.restore("ns", limit=n)),
        ("list_namespaces", lambda c, n: c.list_namespaces(limit=n)),
    ],
    ids=lambda x: x[0],
)
async def test_bad_limit_is_rejected_before_signing(call, limit):
    c = _client()
    with pytest.raises(ValueError, match="limit"):
        await call[1](c, limit)
    assert c.captured == []


async def test_valid_inputs_still_go_out_unchanged():
    c = _client()
    await c.recall_manual(RecallManualOptions(vector=[0.1, -2, 0], limit=3))
    await c.remember_manual(RememberManualOptions(encrypted_data="AAAA", vector=[1, 0.5]))
    await c.recall("q", limit=1)
    await c.restore("ns", limit=50)
    await c.list_namespaces(limit=500)
    await c.list_namespaces()
    bodies = [b for _, _, b in c.captured]
    assert bodies[0]["vector"] == [0.1, -2, 0] and bodies[0]["limit"] == 3
    assert bodies[1]["vector"] == [1, 0.5]
    assert bodies[2]["limit"] == 1
    assert bodies[3]["limit"] == 50
    assert c.captured[4][1].endswith("?limit=500")
    assert "limit" not in c.captured[5][1]


async def test_signed_request_never_emits_nan_tokens(monkeypatch):
    """Backstop: even if a NaN reaches the signer, it must not be serialised."""
    client = MemWal.create(
        key="11" * 32, account_id="0x" + "ab" * 32, server_url="https://relayer.example"
    )

    async def compatible():
        return {
            "apiVersion": "1.0.0",
            "relayerVersion": "t",
            "minSupportedSdk": {"python": "0.0.0"},
        }

    sent = []

    async def fake_post(*args, **kwargs):  # pragma: no cover - must not be reached
        sent.append(kwargs)
        raise AssertionError("request sent with a non-JSON body")

    monkeypatch.setattr(client, "_ensure_compatible_relayer", compatible)
    monkeypatch.setattr(httpx.AsyncClient, "send", fake_post)
    with pytest.raises(ValueError):
        await client._signed_request(
            "POST", "/api/recall", {"limit": math.nan}, include_seal_session=False
        )
    assert sent == []
    await client.close()


@pytest.mark.parametrize("limit", BAD_LIMITS, ids=repr)
async def test_list_namespaces_bad_limit_raises_before_owner_lookup(limit):
    """The owner lookup is a signed POST /api/stats; a bad limit must not reach it."""
    c = FreshOwnerMemWal.create(
        key="11" * 32, account_id="0x" + "ab" * 32, server_url="https://relayer.example"
    )
    with pytest.raises(ValueError, match="limit"):
        await c.list_namespaces(limit=limit)
    assert c.signed == []
    await c.close()


async def test_list_namespaces_valid_limit_still_resolves_owner():
    c = FreshOwnerMemWal.create(
        key="11" * 32, account_id="0x" + "ab" * 32, server_url="https://relayer.example"
    )
    with pytest.raises(MemWalError, match="relayer unavailable"):
        await c.list_namespaces(limit=5)
    assert c.signed == [("POST", "/api/stats")]
    await c.close()


@pytest.mark.parametrize("limit", BAD_LIMITS, ids=repr)
@pytest.mark.parametrize(
    "call",
    [
        ("recall", lambda m, n: m.recall("q", limit=n)),
        ("recall_params", lambda m, n: m.recall(RecallParams(query="q", limit=n))),
        ("ask", lambda m, n: m.ask("q", limit=n)),
        ("restore", lambda m, n: m.restore("ns", limit=n)),
        ("list_namespaces", lambda m, n: m.list_namespaces(limit=n)),
    ],
    ids=lambda x: x[0],
)
async def test_mock_rejects_the_same_bad_limits_as_the_client(call, limit):
    mock = MemWalMock.create()
    await mock.remember("a fact")
    with pytest.raises(ValueError, match="limit"):
        await call[1](mock, limit)


async def test_mock_accepts_positive_integer_limits():
    mock = MemWalMock.create()
    await mock.remember("a fact")
    assert len((await mock.recall("fact", limit=1)).results) == 1
    assert (await mock.restore("ns", limit=1)).restored == 0
    assert len((await mock.list_namespaces(limit=1)).namespaces) == 1
    assert len((await mock.list_namespaces()).namespaces) == 1

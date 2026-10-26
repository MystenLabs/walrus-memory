"""#1012: an explicit empty namespace must not be rewritten to the default.

The client used ``namespace or self._namespace``, so ``namespace=""`` landed
in the default partition, while the TypeScript SDK sends "" and the relayer
rejects it. Only ``None`` means "use the client default"; "" fails before
anything is signed, like the mock's empty-namespace check. Whitespace-only
names are not rejected: the relayer's validate_namespace only refuses "", a
NUL byte and over-long names, and keeps tab/newline/CR namespaces readable.
"""

from __future__ import annotations

import pytest

from memwal import (
    MemWal,
    RecallManualOptions,
    RecallParams,
    RememberBulkItem,
    RememberManualOptions,
)
from memwal.mock import MemWalMock


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
        if path == "/api/remember":
            return {"job_id": "job-1", "status": "pending"}
        if path == "/api/remember/bulk":
            return {"job_ids": ["job"] * len(body["items"]), "total": len(body["items"])}
        if path == "/api/remember/manual":
            return {"id": "1", "blob_id": "b", "owner": "0x1", "namespace": body["namespace"]}
        if path == "/api/analyze":
            return {"facts": [], "total": 0, "owner": "0x1"}
        if path == "/api/ask":
            return {"answer": "", "memories_used": 0, "memories": []}
        return {"results": [], "total": 0}


def _client():
    return CaptureMemWal.create(
        key="11" * 32,
        account_id="0x" + "ab" * 32,
        server_url="https://relayer.example",
        namespace="work",
    )


def _sent_namespaces(client):
    sent = []
    for _, _, body in client.captured:
        sent.extend(item["namespace"] for item in body.get("items", []))
        if "namespace" in body:
            sent.append(body["namespace"])
    return sent


CALLS = [
    ("remember", lambda c, ns: c.remember("x", namespace=ns)),
    ("remember_async", lambda c, ns: c.remember_async("x", namespace=ns)),
    ("remember_bulk_async", lambda c, ns: c.remember_bulk_async([RememberBulkItem("x", ns)])),
    ("recall", lambda c, ns: c.recall("q", namespace=ns)),
    ("recall_params", lambda c, ns: c.recall(RecallParams(query="q", namespace=ns))),
    ("analyze", lambda c, ns: c.analyze("x", namespace=ns)),
    ("ask", lambda c, ns: c.ask("q", namespace=ns)),
    (
        "remember_manual",
        lambda c, ns: c.remember_manual(
            RememberManualOptions(encrypted_data="AAAA", vector=[0.1], namespace=ns)
        ),
    ),
    (
        "recall_manual",
        lambda c, ns: c.recall_manual(RecallManualOptions(vector=[0.1], namespace=ns)),
    ),
]


@pytest.mark.parametrize("call", CALLS, ids=lambda x: x[0])
async def test_empty_namespace_is_rejected_not_defaulted(call):
    c = _client()
    with pytest.raises(ValueError, match="namespace cannot be empty"):
        await call[1](c, "")
    assert c.captured == []


@pytest.mark.parametrize("namespace", [" ", "   ", "\t", "\n", "\r"], ids=repr)
@pytest.mark.parametrize("call", CALLS, ids=lambda x: x[0])
async def test_whitespace_namespace_is_sent_as_is(call, namespace):
    """Whitespace names are valid for the relayer and the TypeScript SDK."""
    c = _client()
    await call[1](c, namespace)
    assert _sent_namespaces(c) == [namespace]


@pytest.mark.parametrize(
    "name", ["recall", "recall_params", "analyze", "ask", "remember_manual", "recall_manual"]
)
async def test_none_uses_client_default_and_explicit_name_is_kept(name):
    call = dict(CALLS)[name]
    c = _client()
    await call(c, None)
    await call(c, "profile")
    assert [b["namespace"] for _, _, b in c.captured] == ["work", "profile"]


async def test_mock_rejects_empty_namespace_on_recall_too():
    mock = MemWalMock(namespace="work")
    with pytest.raises(ValueError, match="namespace cannot be empty"):
        await mock.recall("q", namespace="")


@pytest.mark.parametrize("namespace", [" ", "\t", "\n", "\r"], ids=repr)
async def test_mock_keeps_whitespace_namespaces_separate(namespace):
    mock = MemWalMock(namespace="work")
    await mock.remember("blank name fact", namespace=namespace)
    assert len((await mock.recall("blank name fact", namespace=namespace)).results) == 1
    assert (await mock.recall("blank name fact")).results == []


async def test_mock_rejects_empty_namespace_on_remember():
    mock = MemWalMock(namespace="work")
    with pytest.raises(ValueError, match="namespace cannot be empty"):
        await mock.remember("x", namespace="")

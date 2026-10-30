"""
Tests for the MemWal async client.

Uses ``respx`` to mock ``httpx.AsyncClient`` requests and validate
that the client sends correct headers, body, and handles errors.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

import httpx
import nacl.signing
import pytest
import respx

from memwal.client import (
    MemWal,
    MemWalClockDriftError,
    MemWalCompatibilityError,
    MemWalError,
    MemWalRateLimited,
    MemWalRecallAllDropped,
    MemWalRememberJobNotFound,
    MemWalRememberJobTimeout,
    MemWalSync,
    _HttpStatusError,
)
from memwal.types import (
    RecallManualOptions,
    RecallParams,
    RememberBulkAcceptedResult,
    RememberBulkItem,
    RememberBulkOptions,
    RememberBulkStatusItem,
    RememberBulkStatusResult,
    RememberJobStatus,
    RememberManualOptions,
    ScoringWeights,
)
from memwal.utils import build_signature_message, bytes_to_hex, sha256_hex

# ============================================================
# Fixtures
# ============================================================

# Generate a deterministic test keypair
_TEST_SEED = b"\x01" * 32
_TEST_KEY = nacl.signing.SigningKey(_TEST_SEED)
_TEST_KEY_HEX = bytes_to_hex(bytes(_TEST_KEY))
_TEST_PUB_HEX = bytes_to_hex(bytes(_TEST_KEY.verify_key))
_TEST_ACCOUNT_ID = "0xabc123"
_TEST_SERVER = "http://localhost:8000"
_TEST_PACKAGE_ID = "0x" + "11" * 32
_TEST_SUI_RPC = "http://localhost:9001"


def _version_payload(
    api_version: str = "1.0.0",
    min_python: str = "0.1.0",
) -> dict[str, Any]:
    return {
        "relayerVersion": "0.1.0",
        "apiVersion": api_version,
        "minSupportedSdk": {
            "typescript": "0.0.4",
            "python": min_python,
            "mcp": "0.0.1",
        },
        "featureFlags": {"runtime.versionEndpoint": True},
        "deprecations": [],
        "build": {},
    }


def _mock_version(
    api_version: str = "1.0.0",
    min_python: str = "0.1.0",
) -> None:
    respx.get(f"{_TEST_SERVER}/version").mock(
        return_value=httpx.Response(200, json=_version_payload(api_version, min_python))
    )


def mock_seal_session_prereqs() -> None:
    _mock_version()
    respx.get(f"{_TEST_SERVER}/config").mock(
        return_value=httpx.Response(
            200,
            json={
                "packageId": _TEST_PACKAGE_ID,
                "network": "testnet",
                "suiRpcUrl": _TEST_SUI_RPC,
            },
        )
    )
    respx.post("https://graphql.testnet.sui.io/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"object": {"version": 1}}},
        )
    )
    respx.post(_TEST_SUI_RPC).mock(
        return_value=httpx.Response(
            200,
            json={
                "result": {
                    "data": {
                        "version": "1",
                    }
                }
            },
        )
    )


def decode_seal_session_header(request: httpx.Request) -> dict[str, Any]:
    header = request.headers["x-seal-session"]
    return json.loads(base64.b64decode(header).decode("utf-8"))


@pytest.fixture
def memwal_client() -> MemWal:
    """Create a Walrus Memory client with a test key."""
    return MemWal.create(
        key=_TEST_KEY_HEX,
        account_id=_TEST_ACCOUNT_ID,
        server_url=_TEST_SERVER,
    )


# ============================================================
# sync wrapper tests
# ============================================================


class _FakeHttpClient:
    """Stand-in for httpx.AsyncClient, tracking whether it was closed."""

    def __init__(self) -> None:
        self.is_closed = False

    async def aclose(self) -> None:
        self.is_closed = True


class _SyncRunInner:
    """Minimal stand-in mirroring MemWal's httpx client lifecycle."""

    def __init__(self) -> None:
        self._client: Any = _FakeHttpClient()

    async def close(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


class TestMemWalSyncRun:
    async def test_resets_http_client_when_called_inside_running_loop(self) -> None:
        inner = _SyncRunInner()
        sync = MemWalSync(inner)  # type: ignore[arg-type]

        async def operation() -> str:
            return "ok"

        result = sync._run(operation())

        assert result == "ok"
        assert inner._client is None

    async def test_closes_the_client_it_replaces(self) -> None:
        """GH #606: _run() used to null out _client without closing it, leaking
        the connection pool of every client an earlier event loop left behind."""
        inner = _SyncRunInner()
        orphan = inner._client
        sync = MemWalSync(inner)  # type: ignore[arg-type]

        async def operation() -> str:
            return "ok"

        assert not orphan.is_closed
        assert sync._run(operation()) == "ok"

        assert orphan.is_closed, "the replaced httpx client was never closed"
        assert inner._client is None

    async def test_closes_the_client_created_during_the_call(self) -> None:
        """The per-call client is closed inside the loop that created it, so
        repeated sync calls do not accumulate open pools."""
        inner = _SyncRunInner()
        await inner.close()
        sync = MemWalSync(inner)  # type: ignore[arg-type]
        created: list = []

        async def operation() -> str:
            # Stands in for the lazy `_http` property building a client inside
            # whichever loop is currently running.
            inner._client = _FakeHttpClient()
            created.append(inner._client)
            return "ok"

        assert sync._run(operation()) == "ok"

        assert len(created) == 1
        assert created[0].is_closed, "the per-call httpx client was left open"
        assert inner._client is None

    async def test_closes_client_even_when_the_operation_raises(self) -> None:
        inner = _SyncRunInner()
        orphan = inner._client
        sync = MemWalSync(inner)  # type: ignore[arg-type]

        async def failing() -> str:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            sync._run(failing())

        assert orphan.is_closed
        assert inner._client is None


# ============================================================
# remember() tests
# ============================================================


class TestRemember:
    @respx.mock
    async def test_sends_correct_body(self, memwal_client: MemWal) -> None:
        """remember() should POST to /api/remember with text and namespace."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/remember").mock(
            return_value=httpx.Response(
                202,
                json={
                    "job_id": "job-1",
                    "status": "pending",
                },
            )
        )

        result = await memwal_client.remember("I love coffee")

        assert route.called
        request = route.calls[0].request
        body = json.loads(request.content)
        assert body["text"] == "I love coffee"
        assert body["namespace"] == "default"
        assert result.job_id == "job-1"
        assert result.status == "pending"

    @respx.mock
    async def test_sends_correct_headers(self, memwal_client: MemWal) -> None:
        """remember() should include all required auth headers."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/remember").mock(
            return_value=httpx.Response(
                202,
                json={
                    "job_id": "job-1",
                    "status": "pending",
                },
            )
        )

        await memwal_client.remember("test")

        request = route.calls[0].request
        headers = request.headers

        # Required headers
        assert headers["x-public-key"] == _TEST_PUB_HEX
        assert "x-signature" in headers
        assert len(headers["x-signature"]) == 128  # 64 bytes = 128 hex chars
        assert "x-timestamp" in headers
        assert headers["x-timestamp"].isdigit()
        assert "x-nonce" in headers
        assert headers["x-account-id"] == _TEST_ACCOUNT_ID
        assert "x-seal-session" in headers
        assert "x-delegate-key" not in headers
        assert headers["content-type"] == "application/json"

        session = decode_seal_session_header(request)
        assert session["address"].startswith("0x")
        assert session["packageId"] == _TEST_PACKAGE_ID
        assert session["ttlMin"] == 5
        assert session["sessionKey"].startswith("suiprivkey")
        assert session["personalMessageSignature"]

    @respx.mock
    async def test_signature_is_verifiable(self, memwal_client: MemWal) -> None:
        """The signature in headers should be verifiable with the public key."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/remember").mock(
            return_value=httpx.Response(
                202,
                json={
                    "job_id": "job-1",
                    "status": "pending",
                },
            )
        )

        await memwal_client.remember("verify me")

        request = route.calls[0].request
        headers = request.headers
        body_str = request.content.decode("utf-8")

        # Reconstruct the signing message
        timestamp = headers["x-timestamp"]
        body_hash = sha256_hex(body_str)
        nonce = headers["x-nonce"]
        message = build_signature_message(
            timestamp=timestamp,
            method="POST",
            path="/api/remember",
            body_sha256=body_hash,
            nonce=nonce,
            account_id=headers["x-account-id"],
        )

        # Verify signature
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(headers["x-public-key"]))
        verify_key.verify(
            message.encode("utf-8"),
            bytes.fromhex(headers["x-signature"]),
        )

    @respx.mock
    async def test_custom_namespace(self, memwal_client: MemWal) -> None:
        """remember() should use custom namespace when provided."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/remember").mock(
            return_value=httpx.Response(
                202,
                json={
                    "job_id": "job-2",
                    "status": "pending",
                },
            )
        )

        result = await memwal_client.remember("test", namespace="custom-ns")

        body = json.loads(route.calls[0].request.content)
        assert body["namespace"] == "custom-ns"
        assert result.job_id == "job-2"
        assert result.status == "pending"


# ============================================================
# remember_bulk_async() tests
# ============================================================


class TestRememberBulkAsync:
    @respx.mock
    async def test_empty_items_raises_without_http(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/remember/bulk").mock(
            return_value=httpx.Response(
                202,
                json={"job_ids": [], "total": 0, "status": "pending"},
            )
        )

        with pytest.raises(
            ValueError,
            match="remember_bulk_async: items must be a non-empty array",
        ):
            await memwal_client.remember_bulk_async([])

        assert not route.called

    @respx.mock
    async def test_mismatched_job_ids_raises(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/remember/bulk").mock(
            return_value=httpx.Response(
                202,
                json={
                    "job_ids": ["job-1"],
                    "total": 1,
                    "status": "pending",
                },
            )
        )

        with pytest.raises(
            ValueError,
            match="remember_bulk_async: server returned 1 job_ids for 2 items",
        ):
            await memwal_client.remember_bulk_async(
                [
                    RememberBulkItem(text="I love coffee"),
                    RememberBulkItem(text="I live in Tokyo"),
                ]
            )

    @respx.mock
    async def test_matching_job_ids_returns_accepted(
        self, memwal_client: MemWal
    ) -> None:
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/remember/bulk").mock(
            return_value=httpx.Response(
                202,
                json={
                    "job_ids": ["job-1", "job-2"],
                    "total": 2,
                    "status": "pending",
                },
            )
        )

        result = await memwal_client.remember_bulk_async(
            [
                RememberBulkItem(text="I love coffee"),
                RememberBulkItem(text="I live in Tokyo", namespace="profile"),
            ]
        )

        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body["items"] == [
            {"text": "I love coffee", "namespace": "default"},
            {"text": "I live in Tokyo", "namespace": "profile"},
        ]
        assert isinstance(result, RememberBulkAcceptedResult)
        assert result.job_ids == ["job-1", "job-2"]
        assert result.total == 2
        assert result.status == "pending"

    async def test_job_omitted_from_a_poll_stays_pending(
        self, memwal_client: MemWal
    ) -> None:
        polls = 0

        async def partial_status(
            job_ids: Sequence[str],
        ) -> RememberBulkStatusResult:
            nonlocal polls
            polls += 1
            job_id = "job-1" if polls == 1 else "job-2"
            return RememberBulkStatusResult(
                results=[
                    RememberBulkStatusItem(
                        job_id=job_id,
                        status="done",
                        blob_id=f"blob-for-{job_id}",
                    )
                ]
            )

        memwal_client.get_remember_bulk_status = partial_status  # type: ignore[method-assign]

        result = await memwal_client.wait_for_remember_jobs(
            ["job-1", "job-2"],
            RememberBulkOptions(poll_interval_ms=1, timeout_ms=5_000),
        )

        assert [item.status for item in result.results] == ["done", "done"]


class TestBulkWaitUnderRateLimit:
    async def test_every_read_refused_raises_rate_limited(
        self, memwal_client: MemWal
    ) -> None:
        ids = [f"job-{i}" for i in range(12)]

        async def refused(job_ids: Sequence[str]) -> RememberBulkStatusResult:
            raise _HttpStatusError(429, '{"error":"rate limited"}', retry_after="30")

        memwal_client.get_remember_bulk_status = refused  # type: ignore[method-assign]
        with pytest.raises(MemWalRateLimited) as exc:
            await memwal_client.wait_for_remember_jobs(
                ids, RememberBulkOptions(poll_interval_ms=1, timeout_ms=300)
            )
        assert exc.value.status == 429
        assert exc.value.job_ids == ids
        assert exc.value.retry_after == "30"
        assert "none of its 12 writes could be confirmed" in str(exc.value)

    async def test_rate_limited_reads_the_body_when_the_header_is_stripped(
        self, memwal_client: MemWal
    ) -> None:
        async def refused(job_ids: Sequence[str]) -> RememberBulkStatusResult:
            raise _HttpStatusError(429, '{"retry_after_seconds":45}')

        memwal_client.get_remember_bulk_status = refused  # type: ignore[method-assign]
        with pytest.raises(MemWalRateLimited) as exc:
            await memwal_client.wait_for_remember_jobs(
                ["job-1"], RememberBulkOptions(poll_interval_ms=1, timeout_ms=300)
            )
        assert exc.value.retry_after == "45"
        assert "after ~45s" in str(exc.value)

    async def test_confirming_read_settles_a_refused_wait(
        self, memwal_client: MemWal
    ) -> None:
        start = time.monotonic()

        async def probe_answers(job_ids: Sequence[str]) -> RememberBulkStatusResult:
            # Refuse during the wait. The confirming read runs after the
            # 250ms deadline, so the refusal window has to end before that
            # or a slow CI clock still counts the probe as a refusal.
            if time.monotonic() - start < 0.20:
                raise _HttpStatusError(429, "{}")
            return RememberBulkStatusResult(
                results=[
                    RememberBulkStatusItem(job_id="job-a", status="done", blob_id="blob-a"),
                    RememberBulkStatusItem(
                        job_id="job-b", status="failed", error="walrus upload failed"
                    ),
                ]
            )

        memwal_client.get_remember_bulk_status = probe_answers  # type: ignore[method-assign]
        out = await memwal_client.wait_for_remember_jobs(
            ["job-a", "job-b", "job-c"],
            RememberBulkOptions(poll_interval_ms=1, timeout_ms=250),
        )
        assert [r.status for r in out.results] == ["done", "failed", "timeout"]
        # A read did get through; it just left job-c out, so saying no read
        # got through would be false.
        assert "not in the relayer's status answer" in (out.results[2].error or "")

    async def test_partly_settled_batch_is_returned(self, memwal_client: MemWal) -> None:
        reads = 0

        async def then_refused(job_ids: Sequence[str]) -> RememberBulkStatusResult:
            nonlocal reads
            reads += 1
            if reads == 1:
                return RememberBulkStatusResult(
                    results=[
                        RememberBulkStatusItem(
                            job_id="job-a", status="done", blob_id="blob-a"
                        ),
                        RememberBulkStatusItem(
                            job_id="job-b",
                            status="running",
                            error="still retrying this upload",
                        ),
                    ]
                )
            raise _HttpStatusError(429, "{}")

        memwal_client.get_remember_bulk_status = then_refused  # type: ignore[method-assign]
        out = await memwal_client.wait_for_remember_jobs(
            ["job-a", "job-b"], RememberBulkOptions(poll_interval_ms=1, timeout_ms=300)
        )
        assert [r.status for r in out.results] == ["done", "timeout"]
        assert "still running after 300ms: still retrying this upload" in (
            out.results[1].error or ""
        )


class TestRememberJobTimeoutDetail:
    async def test_reports_last_status_and_server_message(
        self, memwal_client: MemWal
    ) -> None:
        async def running(*_args: Any, **_kwargs: Any) -> dict:
            return {
                "job_id": "slow-job",
                "status": "running",
                "error": "the hosted relayer is still retrying this upload",
            }

        memwal_client._signed_request = running  # type: ignore[method-assign]
        with pytest.raises(MemWalRememberJobTimeout) as exc:
            await memwal_client.wait_for_remember_job(
                "slow-job", poll_interval_ms=0, timeout_ms=300
            )
        assert exc.value.status == 504
        assert exc.value.last_status == "running"
        assert "still retrying" in (exc.value.server_error or "")
        assert str(exc.value).startswith("remember job timed out after 300ms")
        assert "last status: running" in str(exc.value)
        # The job is still live, so the advice is to wait on its id, not to
        # POST again: `remember` drops its key once accepted, so a re-send
        # would mint a new key and a second paid write.
        assert "call wait_for_remember_job('slow-job')" in str(exc.value)
        assert "idempotency_key is not remembered" in str(exc.value)

    async def test_timeout_attribute_carries_the_redacted_server_error(
        self, memwal_client: MemWal
    ) -> None:
        async def running(*_args: Any, **_kwargs: Any) -> dict:
            return {
                "job_id": "slow-job",
                "status": "running",
                "error": "sidecar http://localhost:9000/upload unreachable",
            }

        memwal_client._signed_request = running  # type: ignore[method-assign]
        with pytest.raises(MemWalRememberJobTimeout) as exc:
            await memwal_client.wait_for_remember_job(
                "slow-job", poll_interval_ms=0, timeout_ms=300
            )
        assert exc.value.server_error == "sidecar [internal] unreachable"
        assert "localhost" not in str(exc.value)

    async def test_every_poll_refused_reports_unknown_state(
        self, memwal_client: MemWal
    ) -> None:
        async def refused(*_args: Any, **_kwargs: Any) -> dict:
            raise _HttpStatusError(429, '{"error":"rate limited"}')

        memwal_client._signed_request = refused  # type: ignore[method-assign]
        with pytest.raises(MemWalRememberJobTimeout) as exc:
            await memwal_client.wait_for_remember_job(
                "hidden-job", poll_interval_ms=0, timeout_ms=300
            )
        assert exc.value.last_status is None
        assert exc.value.last_refusal == 429
        assert "no status read got through (last poll: HTTP 429)" in str(exc.value)

    async def test_seen_then_rate_limited_keeps_both(
        self, memwal_client: MemWal
    ) -> None:
        calls = 0

        async def running_then_refused(*_args: Any, **_kwargs: Any) -> dict:
            nonlocal calls
            calls += 1
            if calls == 1:
                return {"job_id": "slow-job", "status": "running"}
            raise _HttpStatusError(429, '{"error":"rate limited"}')

        memwal_client._signed_request = running_then_refused  # type: ignore[method-assign]
        with pytest.raises(MemWalRememberJobTimeout) as exc:
            await memwal_client.wait_for_remember_job(
                "slow-job", poll_interval_ms=0, timeout_ms=300
            )
        assert exc.value.last_status == "running"
        assert "(job_id=slow-job); wait hit a rate limit (429); last status: running." in str(
            exc.value
        )


# ============================================================
# one-job remember status
# ============================================================


_NORMAL_JOB_ID = "550e8400-e29b-41d4-a716-446655440000"


class TestRememberJobStatus:
    @respx.mock
    async def test_unsafe_job_id_is_not_requested(self, memwal_client: MemWal) -> None:
        route = respx.route().mock(return_value=httpx.Response(500, text="nope"))
        for job_id in ("", "abc/def?x=1", "job 1", "a\tb", "?", "/", ".", "..", "%2e%2e", "a\\b"):
            status = await memwal_client.get_remember_status(job_id)
            assert status == RememberJobStatus(
                job_id=job_id,
                status="not_found",
                error=f"Job {job_id} not found",
            )
            with pytest.raises(MemWalRememberJobNotFound) as exc:
                await memwal_client.wait_for_remember_job(
                    job_id, poll_interval_ms=0, timeout_ms=5_000
                )
            assert exc.value.status == 404
            assert exc.value.job_id == job_id
            assert not isinstance(exc.value, json.JSONDecodeError)
        assert route.call_count == 0

    async def test_non_string_job_id_is_a_type_error(self, memwal_client: MemWal) -> None:
        with pytest.raises(TypeError):
            await memwal_client.get_remember_status(1)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            await memwal_client.wait_for_remember_job(1, poll_interval_ms=0, timeout_ms=5_000)  # type: ignore[arg-type]

    @respx.mock
    async def test_uuid_object_reads_the_string_path(self, memwal_client: MemWal) -> None:
        _mock_version()
        job = uuid.UUID(_NORMAL_JOB_ID)
        route = respx.get(f"{_TEST_SERVER}/api/remember/{job}").mock(
            return_value=httpx.Response(200, json={"job_id": str(job), "status": "running"})
        )
        status = await memwal_client.get_remember_status(job)  # type: ignore[arg-type]
        assert status.status == "running"
        assert status.job_id == str(job)
        assert route.call_count == 1

    @respx.mock
    async def test_non_object_404_body_is_not_found(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        route = respx.get(f"{_TEST_SERVER}/api/remember/job-1")
        for body in (b"null", b"[]", b'"Not Found"', b"<html>nope</html>"):
            route.mock(return_value=httpx.Response(404, content=body))
            status = await memwal_client.get_remember_status("job-1")
            assert status.status == "not_found"
            assert status.job_id == "job-1"
            with pytest.raises(MemWalRememberJobNotFound) as exc:
                await memwal_client.wait_for_remember_job(
                    "job-1", poll_interval_ms=0, timeout_ms=5_000
                )
            assert exc.value.status == 404

    @respx.mock
    async def test_empty_404_body_is_not_found(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        respx.get(f"{_TEST_SERVER}/api/remember/job-1").mock(
            return_value=httpx.Response(404, content=b"")
        )
        status = await memwal_client.get_remember_status("job-1")
        assert status.status == "not_found"
        assert status.job_id == "job-1"
        with pytest.raises(MemWalRememberJobNotFound) as exc:
            await memwal_client.wait_for_remember_job(
                "job-1", poll_interval_ms=0, timeout_ms=5_000
            )
        assert exc.value.status == 404

    @respx.mock
    async def test_reads_a_normal_job_id(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        route = respx.get(f"{_TEST_SERVER}/api/remember/{_NORMAL_JOB_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "job_id": _NORMAL_JOB_ID,
                    "status": "done",
                    "blob_id": "blob-1",
                    "owner": "0xowner",
                    "namespace": "profile",
                },
            )
        )

        status = await memwal_client.get_remember_status(_NORMAL_JOB_ID)
        assert status == RememberJobStatus(
            job_id=_NORMAL_JOB_ID,
            status="done",
            owner="0xowner",
            namespace="profile",
            blob_id="blob-1",
        )
        assert "x-seal-session" not in route.calls[0].request.headers

        result = await memwal_client.wait_for_remember_job(
            _NORMAL_JOB_ID, poll_interval_ms=0, timeout_ms=5_000
        )
        assert result.blob_id == "blob-1"
        assert result.namespace == "profile"
        assert [str(call.request.url) for call in route.calls] == [
            f"{_TEST_SERVER}/api/remember/{_NORMAL_JOB_ID}",
            f"{_TEST_SERVER}/api/remember/{_NORMAL_JOB_ID}",
        ]

    @respx.mock
    def test_sync_reads_a_normal_job_id(self) -> None:
        _mock_version()
        route = respx.get(f"{_TEST_SERVER}/api/remember/{_NORMAL_JOB_ID}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "job_id": _NORMAL_JOB_ID,
                    "status": "running",
                    "namespace": "profile",
                },
            )
        )
        client = MemWalSync.create(
            key=_TEST_KEY_HEX,
            account_id=_TEST_ACCOUNT_ID,
            server_url=_TEST_SERVER,
        )
        try:
            missing = client.get_remember_status("")
            assert missing.status == "not_found"
            with pytest.raises(MemWalRememberJobNotFound):
                client.wait_for_remember_job("abc/def?x=1", poll_interval_ms=0, timeout_ms=5_000)
            status = client.get_remember_status(_NORMAL_JOB_ID)
            assert status.status == "running"
            assert status.namespace == "profile"
            assert str(route.calls[0].request.url) == (
                f"{_TEST_SERVER}/api/remember/{_NORMAL_JOB_ID}"
            )
        finally:
            client.close()


# ============================================================
# recall() tests
# ============================================================


class TestRecall:
    @respx.mock
    async def test_sends_correct_body(self, memwal_client: MemWal) -> None:
        """recall() should POST to /api/recall with query, limit, namespace."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {"blob_id": "b1", "text": "I love coffee", "distance": 0.1},
                        {"blob_id": "b2", "text": "I live in Tokyo", "distance": 0.3},
                    ],
                    "total": 2,
                },
            )
        )

        result = await memwal_client.recall("coffee", limit=5)

        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body["query"] == "coffee"
        assert body["limit"] == 5
        assert body["namespace"] == "default"

        assert len(result.results) == 2
        assert result.total == 2
        assert result.dropped_count == 0
        assert result.results[0].text == "I love coffee"
        assert result.results[0].distance == 0.1
        assert result.results[1].blob_id == "b2"

    @respx.mock
    async def test_recall_raises_on_all_dropped_by_default_and_supports_ignore(
        self, memwal_client: MemWal
    ) -> None:
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={"results": [], "total": 0, "dropped_count": 3},
            )
        )
        with pytest.raises(MemWalRecallAllDropped) as exc_info:
            await memwal_client.recall("coffee")
        assert exc_info.value.code == "RECALL_ALL_DROPPED"
        assert exc_info.value.dropped_count == 3
        assert exc_info.value.total == 3
        assert exc_info.value.namespace == "default"

        with pytest.raises(ValueError, match="on_dropped"):
            await memwal_client.recall("coffee", on_dropped="warn")

        result = await memwal_client.recall(
            RecallParams(query="coffee", on_dropped="ignore")
        )
        assert result.results == []
        assert result.dropped_count == 3
        assert result.total == 3
        assert result.degraded is True

    @respx.mock
    async def test_recall_preserves_dropped_count_with_max_distance(
        self, memwal_client: MemWal
    ) -> None:
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {"blob_id": "b1", "text": "near hit", "distance": 0.1},
                        {"blob_id": "b2", "text": "far hit", "distance": 0.9},
                    ],
                    "total": 2,
                    "dropped_count": 25,
                },
            )
        )
        result = await memwal_client.recall(
            RecallParams(query="coffee", max_distance=0.5)
        )
        assert [m.blob_id for m in result.results] == ["b1"]
        assert result.total == 2
        assert result.dropped_count == 25
        assert result.degraded is True

    @respx.mock
    async def test_recall_preserves_score_and_created_at(
        self, memwal_client: MemWal
    ) -> None:
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "blob_id": "b1",
                            "text": "Fact with metadata",
                            "distance": 0.1,
                            "score": 0.95,
                            "created_at": "2026-03-30T12:00:00Z",
                        },
                        {
                            "blob_id": "b2",
                            "text": "Legacy fact",
                            "distance": 0.3,
                        },
                    ],
                    "total": 2,
                },
            )
        )
        result = await memwal_client.recall("test")
        assert len(result.results) == 2
        assert result.results[0].score == 0.95
        assert result.results[0].created_at == "2026-03-30T12:00:00Z"
        assert result.results[1].score is None
        assert result.results[1].created_at is None

    @respx.mock
    async def test_accepts_recall_params_object(
        self, memwal_client: MemWal
    ) -> None:
        """recall(RecallParams(...)) sends the same request body as
        the positional form, with query/limit/namespace pulled from the
        dataclass instead of positional args."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={"results": [], "total": 0},
            )
        )

        await memwal_client.recall(
            RecallParams(query="coffee", limit=7, namespace="profile"),
        )

        assert route.called
        body = json.loads(route.calls[0].request.content)
        assert body["query"] == "coffee"
        assert body["limit"] == 7
        assert body["namespace"] == "profile"

    @respx.mock
    async def test_recall_params_object_applies_max_distance_filter(
        self, memwal_client: MemWal
    ) -> None:
        """max_distance on the RecallParams dataclass drops weak matches
        client-side, matching the positional max_distance kwarg behavior."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {"blob_id": "b1", "text": "tight", "distance": 0.1},
                        {"blob_id": "b2", "text": "noisy", "distance": 0.9},
                    ],
                    "total": 2,
                },
            )
        )

        result = await memwal_client.recall(
            RecallParams(query="x", limit=10, max_distance=0.5),
        )

        assert len(result.results) == 1
        assert result.results[0].blob_id == "b1"

    @respx.mock
    async def test_sends_correct_headers(self, memwal_client: MemWal) -> None:
        """recall() should include all required auth headers."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={"results": [], "total": 0},
            )
        )

        await memwal_client.recall("test")

        headers = route.calls[0].request.headers
        assert headers["x-public-key"] == _TEST_PUB_HEX
        assert len(headers["x-signature"]) == 128
        assert headers["x-account-id"] == _TEST_ACCOUNT_ID
        assert "x-seal-session" in headers
        assert "x-delegate-key" not in headers

    @respx.mock
    async def test_max_distance_filters_results(self, memwal_client: MemWal) -> None:
        """recall() should filter weak matches when max_distance is provided."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {"blob_id": "b1", "text": "I love coffee", "distance": 0.2},
                        {"blob_id": "b2", "text": "I live in Tokyo", "distance": 0.7},
                    ],
                    "total": 2,
                },
            )
        )

        result = await memwal_client.recall("coffee", limit=10, max_distance=0.7)

        body = json.loads(route.calls[0].request.content)
        assert body["limit"] == 10
        assert len(result.results) == 1
        assert result.total == 2
        assert result.results[0].blob_id == "b1"

    @respx.mock
    async def test_max_distance_filters_all_preserves_total(
        self, memwal_client: MemWal
    ) -> None:
        """When all matches exceed max_distance, results is empty but total
        preserves matches (#1066)."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {"blob_id": "b1", "text": "I love coffee", "distance": 0.8},
                        {"blob_id": "b2", "text": "I live in Tokyo", "distance": 0.9},
                    ],
                    "total": 2,
                },
            )
        )

        result = await memwal_client.recall("coffee", limit=10, max_distance=0.5)
        assert len(result.results) == 0
        assert result.total == 2

    @respx.mock
    async def test_get_signed_request_uses_empty_body_hash_and_no_wire_body(
        self, memwal_client: MemWal
    ) -> None:
        mock_seal_session_prereqs()
        route = respx.get(f"{_TEST_SERVER}/api/remember/job-1").mock(
            return_value=httpx.Response(
                200,
                json={"job_id": "job-1", "status": "done", "blob_id": "b1", "owner": "0xowner"},
            )
        )

        result = await memwal_client.wait_for_remember_job(
            "job-1",
            poll_interval_ms=0,
            timeout_ms=100,
        )

        request = route.calls[0].request
        assert request.content == b""

        headers = request.headers
        message = build_signature_message(
            timestamp=headers["x-timestamp"],
            method="GET",
            path="/api/remember/job-1",
            body_sha256=sha256_hex(""),
            nonce=headers["x-nonce"],
            account_id=headers["x-account-id"],
        )
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(headers["x-public-key"]))
        verify_key.verify(message.encode("utf-8"), bytes.fromhex(headers["x-signature"]))
        assert result.blob_id == "b1"


# ============================================================
# Error handling tests
# ============================================================


class TestErrorHandling:
    @respx.mock
    async def test_non_200_raises_memwal_error(self, memwal_client: MemWal) -> None:
        """Non-200 responses should raise MemWalError with status and body."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/remember").mock(
            return_value=httpx.Response(
                401,
                text="Invalid signature",
            )
        )

        with pytest.raises(MemWalError, match="401"):
            await memwal_client.remember("test")

    @respx.mock
    async def test_empty_401_uses_workshop_friendly_message(
        self, memwal_client: MemWal
    ) -> None:
        """Empty-body auth failures should still give actionable guidance."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(401, text="")
        )

        with pytest.raises(
            MemWalError,
            match="wrong private key.*account ID mismatch.*staging/mainnet mismatch",
        ):
            await memwal_client.recall("test")

    @respx.mock
    async def test_clock_drift_header_raises_clock_drift_error(
        self, memwal_client: MemWal
    ) -> None:
        """A 401 carrying x-auth-error: ERR_TIMESTAMP_OUT_OF_BOUNDS should surface
        as an actionable MemWalClockDriftError, not an opaque HTTP error."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/remember").mock(
            return_value=httpx.Response(
                401,
                headers={"x-auth-error": "ERR_TIMESTAMP_OUT_OF_BOUNDS"},
                text="",
            )
        )

        with pytest.raises(MemWalClockDriftError, match="clock-drift window"):
            await memwal_client.remember("test")

    @respx.mock
    async def test_500_raises_memwal_error(self, memwal_client: MemWal) -> None:
        """Server errors should raise MemWalError."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                500,
                text="Internal server error",
            )
        )

        with pytest.raises(MemWalError, match="500"):
            await memwal_client.recall("test")

    @respx.mock
    async def test_500_strips_localhost_sidecar_urls(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/recall").mock(
            return_value=httpx.Response(
                500,
                text="Sidecar seal/encrypt request failed: error sending request for url (http://localhost:9000/seal/encrypt)",
            )
        )
        with pytest.raises(MemWalError) as exc:
            await memwal_client.recall("test")
        assert "localhost:9000" not in str(exc.value)
        assert "[internal]" in str(exc.value)

    @respx.mock
    async def test_health_non_200_raises(self, memwal_client: MemWal) -> None:
        """Health check should raise on non-200."""
        respx.get(f"{_TEST_SERVER}/health").mock(
            return_value=httpx.Response(503, text="Service unavailable")
        )

        with pytest.raises(MemWalError, match="Health check failed"):
            await memwal_client.health()


# ============================================================
# Other endpoint tests
# ============================================================


class TestAnalyze:
    @respx.mock
    async def test_analyze(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/analyze").mock(
            return_value=httpx.Response(
                200,
                json={
                    "facts": [
                        {"text": "User loves coffee", "id": "f1", "blob_id": "b1"},
                    ],
                    "total": 1,
                    "owner": "0xowner",
                },
            )
        )

        result = await memwal_client.analyze("I love coffee and live in Tokyo")

        body = json.loads(route.calls[0].request.content)
        assert body["text"] == "I love coffee and live in Tokyo"
        assert "occurred_at" not in body  # omitted when not supplied
        assert len(result.facts) == 1
        assert result.facts[0].text == "User loves coffee"
        assert result.owner == "0xowner"

    @respx.mock
    async def test_analyze_with_occurred_at_datetime(
        self, memwal_client: MemWal
    ) -> None:
        """A UTC-aware datetime renders as RFC-3339 millis with 'Z'."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/analyze").mock(
            return_value=httpx.Response(200, json={"facts": [], "total": 0, "owner": ""})
        )

        await memwal_client.analyze(
            "I moved last Friday",
            occurred_at=datetime(2023, 5, 25, 17, 50, tzinfo=timezone.utc),
        )

        body = json.loads(route.calls[0].request.content)
        # Millisecond precision matches the TS SDK's Date.toISOString().
        assert body["occurred_at"] == "2023-05-25T17:50:00.000Z"

    @respx.mock
    async def test_analyze_with_occurred_at_nonutc_tz(
        self, memwal_client: MemWal
    ) -> None:
        """An aware datetime in a non-UTC tz is converted to UTC."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/analyze").mock(
            return_value=httpx.Response(200, json={"facts": [], "total": 0, "owner": ""})
        )

        # 17:50 in +07:00 (Hanoi) is 10:50 UTC.
        ict = timezone(timedelta(hours=7))
        await memwal_client.analyze(
            "I moved last Friday",
            occurred_at=datetime(2023, 5, 25, 17, 50, tzinfo=ict),
        )

        body = json.loads(route.calls[0].request.content)
        assert body["occurred_at"] == "2023-05-25T10:50:00.000Z"

    @respx.mock
    async def test_analyze_with_occurred_at_string(
        self, memwal_client: MemWal
    ) -> None:
        """An RFC-3339 string is validated and re-formatted to canonical."""
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/analyze").mock(
            return_value=httpx.Response(200, json={"facts": [], "total": 0, "owner": ""})
        )

        await memwal_client.analyze(
            "I moved last Friday",
            occurred_at="2023-05-25T17:50:00Z",
        )

        body = json.loads(route.calls[0].request.content)
        # Canonical form: millis appended.
        assert body["occurred_at"] == "2023-05-25T17:50:00.000Z"

    async def test_analyze_naive_datetime_raises(
        self, memwal_client: MemWal
    ) -> None:
        """Naïve datetimes are rejected — silently assuming UTC would
        produce timezone-off-by-N anchors for callers outside UTC and
        undermine WALM-55's honest-temporal-anchoring guarantee."""
        with pytest.raises(ValueError, match="timezone-aware"):
            await memwal_client.analyze(
                "I moved last Friday",
                occurred_at=datetime(2023, 5, 25, 17, 50),  # naïve
            )

    async def test_analyze_garbage_string_raises(
        self, memwal_client: MemWal
    ) -> None:
        """Malformed occurred_at strings are rejected at the SDK
        boundary, not forwarded as an opaque 400 from the server."""
        with pytest.raises(ValueError, match="RFC-3339"):
            await memwal_client.analyze(
                "I moved last Friday",
                occurred_at="yesterday",
            )

    async def test_analyze_naive_string_raises(
        self, memwal_client: MemWal
    ) -> None:
        """A timezone-less ISO string is rejected — same reasoning as
        the naïve-datetime case."""
        with pytest.raises(ValueError, match="UTC offset"):
            await memwal_client.analyze(
                "I moved last Friday",
                occurred_at="2023-05-25T17:50:00",  # no Z, no offset
            )


class TestRestore:
    @respx.mock
    async def test_restore(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/restore").mock(
            return_value=httpx.Response(
                200,
                json={
                    "restored": 5,
                    "skipped": 2,
                    "total": 7,
                    "namespace": "my-app",
                    "owner": "0xowner",
                    "truncated": False,
                },
            )
        )

        result = await memwal_client.restore("my-app", limit=100)

        body = json.loads(route.calls[0].request.content)
        assert body["namespace"] == "my-app"
        assert body["limit"] == 100
        assert result.restored == 5
        assert result.skipped == 2
        assert result.failed == 0
        assert result.truncated is False

    @respx.mock
    async def test_restore_preserves_truncated_true(
        self, memwal_client: MemWal
    ) -> None:
        """truncated=True from the relayer must survive into RestoreResult
        instead of being dropped when the dataclass is reconstructed."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/restore").mock(
            return_value=httpx.Response(
                200,
                json={
                    "restored": 5,
                    "skipped": 2,
                    "total": 7,
                    "namespace": "my-app",
                    "owner": "0xowner",
                    "truncated": True,
                },
            )
        )

        result = await memwal_client.restore("my-app", limit=100)

        assert result.truncated is True

    @respx.mock
    async def test_restore_truncated_defaults_false_when_omitted(
        self, memwal_client: MemWal
    ) -> None:
        """Relayers older than WALM-319 omit `truncated` entirely — the
        SDK must default it to False rather than requiring the field."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/restore").mock(
            return_value=httpx.Response(
                200,
                json={
                    "restored": 5,
                    "skipped": 2,
                    "total": 7,
                    "namespace": "my-app",
                    "owner": "0xowner",
                    # no "truncated" key — simulates an older relayer
                },
            )
        )

        result = await memwal_client.restore("my-app", limit=100)

        assert result.truncated is False

    @respx.mock
    async def test_restore_preserves_failed(
        self, memwal_client: MemWal
    ) -> None:
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/restore").mock(
            return_value=httpx.Response(
                200,
                json={
                    "restored": 5,
                    "skipped": 2,
                    "failed": 3,
                    "total": 10,
                    "namespace": "my-app",
                    "owner": "0xowner",
                    "truncated": False,
                },
            )
        )

        result = await memwal_client.restore("my-app", limit=100)

        assert result.failed == 3

    @respx.mock
    async def test_restore_failed_defaults_zero_when_omitted(
        self, memwal_client: MemWal
    ) -> None:
        """Relayers older than COMG-719 omit `failed` — the SDK must
        default it to 0 rather than requiring the field."""
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/restore").mock(
            return_value=httpx.Response(
                200,
                json={
                    "restored": 5,
                    "skipped": 2,
                    "total": 7,
                    "namespace": "my-app",
                    "owner": "0xowner",
                    "truncated": False,
                },
            )
        )

        result = await memwal_client.restore("my-app", limit=100)

        assert result.failed == 0


class TestHealth:
    @respx.mock
    async def test_health(self, memwal_client: MemWal) -> None:
        respx.get(f"{_TEST_SERVER}/health").mock(
            return_value=httpx.Response(
                200,
                json={"status": "ok", "version": "0.1.0"},
            )
        )

        result = await memwal_client.health()
        assert result.status == "ok"
        assert result.version == "0.1.0"

    @respx.mock
    async def test_compatibility(self, memwal_client: MemWal) -> None:
        _mock_version()

        metadata = await memwal_client.compatibility()

        assert metadata["apiVersion"] == "1.0.0"
        assert metadata["minSupportedSdk"]["python"] == "0.1.0"

    @respx.mock
    async def test_compatibility_rejects_unsupported_relayer(
        self, memwal_client: MemWal
    ) -> None:
        _mock_version(api_version="2.0.0")

        with pytest.raises(MemWalCompatibilityError, match="supports relayer API 1.x"):
            await memwal_client.compatibility()

    @respx.mock
    async def test_compatibility_rejects_old_sdk(self, memwal_client: MemWal) -> None:
        _mock_version(min_python="9.0.0")

        with pytest.raises(MemWalCompatibilityError, match="requires Python SDK >= 9.0.0"):
            await memwal_client.recall("test")

    @respx.mock
    async def test_compatibility_rejects_missing_python_min(
        self, memwal_client: MemWal
    ) -> None:
        payload = _version_payload()
        del payload["minSupportedSdk"]["python"]
        respx.get(f"{_TEST_SERVER}/version").mock(
            return_value=httpx.Response(200, json=payload)
        )

        with pytest.raises(MemWalCompatibilityError, match="minSupportedSdk.python"):
            await memwal_client.compatibility()

    @respx.mock
    async def test_compatibility_rejects_invalid_python_min(
        self, memwal_client: MemWal
    ) -> None:
        _mock_version(min_python="latest")

        with pytest.raises(MemWalCompatibilityError, match="invalid minSupportedSdk.python"):
            await memwal_client.compatibility()


class TestManualAPI:
    @respx.mock
    async def test_remember_manual(self, memwal_client: MemWal) -> None:
        _mock_version()
        route = respx.post(f"{_TEST_SERVER}/api/remember/manual").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "m1",
                    "blob_id": "blob-xyz",
                    "owner": "0xowner",
                    "namespace": "default",
                },
            )
        )

        opts = RememberManualOptions(
            encrypted_data="dGVzdA==",
            vector=[0.1, 0.2, 0.3],
        )
        result = await memwal_client.remember_manual(opts)

        body = json.loads(route.calls[0].request.content)
        headers = route.calls[0].request.headers
        assert body["encrypted_data"] == "dGVzdA=="
        assert "blob_id" not in body
        assert body["vector"] == [0.1, 0.2, 0.3]
        assert "x-seal-session" not in headers
        assert "x-delegate-key" not in headers
        assert result.blob_id == "blob-xyz"

    @respx.mock
    async def test_embed(self, memwal_client: MemWal) -> None:
        _mock_version()
        route = respx.post(f"{_TEST_SERVER}/api/embed").mock(
            return_value=httpx.Response(200, json={"vector": [0.1, 0.2, 0.3]})
        )

        result = await memwal_client.embed("hello")

        body = json.loads(route.calls[0].request.content)
        assert body["text"] == "hello"
        assert result.vector == [0.1, 0.2, 0.3]

    @respx.mock
    async def test_recall_manual(self, memwal_client: MemWal) -> None:
        _mock_version()
        route = respx.post(f"{_TEST_SERVER}/api/recall/manual").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {"blob_id": "b1", "distance": 0.15},
                    ],
                    "total": 1,
                },
            )
        )

        opts = RecallManualOptions(vector=[0.1, 0.2, 0.3], limit=5)
        result = await memwal_client.recall_manual(opts)

        body = json.loads(route.calls[0].request.content)
        headers = route.calls[0].request.headers
        assert body["vector"] == [0.1, 0.2, 0.3]
        assert body["limit"] == 5
        assert "x-seal-session" not in headers
        assert "x-delegate-key" not in headers
        assert len(result.results) == 1
        assert result.results[0].blob_id == "b1"

    @respx.mock
    async def test_recall_manual_preserves_created_at_and_importance(
        self, memwal_client: MemWal
    ) -> None:
        _mock_version()
        respx.post(f"{_TEST_SERVER}/api/recall/manual").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "blob_id": "b1",
                            "distance": 0.15,
                            "created_at": "2026-03-30T12:00:00Z",
                            "importance": 0.85,
                        },
                        {
                            "blob_id": "b2",
                            "distance": 0.4,
                        },
                    ],
                    "total": 2,
                },
            )
        )

        opts = RecallManualOptions(vector=[0.1, 0.2, 0.3], limit=5)
        result = await memwal_client.recall_manual(opts)

        assert len(result.results) == 2
        assert result.results[0].created_at == "2026-03-30T12:00:00Z"
        assert result.results[0].importance == 0.85
        assert result.results[1].created_at is None
        assert result.results[1].importance is None

    @respx.mock
    async def test_recall_manual_forwards_scoring_weights(self, memwal_client: MemWal) -> None:
        _mock_version()
        route = respx.post(f"{_TEST_SERVER}/api/recall/manual").mock(
            return_value=httpx.Response(200, json={"results": [], "total": 0})
        )

        opts = RecallManualOptions(
            vector=[0.1, 0.2, 0.3],
            limit=5,
            scoring_weights=ScoringWeights(
                semantic=1.0,
                recency=0.5,
                recency_half_life_days=7.0,
                importance=2.0,
            ),
        )
        await memwal_client.recall_manual(opts)

        body = json.loads(route.calls[0].request.content)
        assert body["scoring_weights"] == {
            "semantic": 1.0,
            "recency": 0.5,
            "recency_half_life_days": 7.0,
            "importance": 2.0,
        }


class TestPublicKey:
    async def test_get_public_key_hex(self, memwal_client: MemWal) -> None:
        pub_hex = await memwal_client.get_public_key_hex()
        assert pub_hex == _TEST_PUB_HEX
        assert len(pub_hex) == 64  # 32 bytes = 64 hex chars


class TestAsk:
    @respx.mock
    async def test_ask(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/ask").mock(
            return_value=httpx.Response(
                200,
                json={
                    "answer": "You are allergic to peanuts.",
                    "memories_used": 1,
                    "memories": [
                        {"blob_id": "b1", "text": "User is allergic to peanuts", "distance": 0.05}
                    ],
                },
            )
        )

        result = await memwal_client.ask("What are my allergies?", limit=3)

        body = json.loads(route.calls[0].request.content)
        assert body["question"] == "What are my allergies?"
        assert body["limit"] == 3
        assert body["namespace"] == "default"
        assert result.answer == "You are allergic to peanuts."
        assert result.memories_used == 1
        assert len(result.memories) == 1
        assert result.memories[0].text == "User is allergic to peanuts"
        assert result.memories[0].distance == 0.05

    @respx.mock
    async def test_ask_empty_memories(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        respx.post(f"{_TEST_SERVER}/api/ask").mock(
            return_value=httpx.Response(
                200,
                json={
                    "answer": "No memories found for this user yet.",
                    "memories_used": 0,
                    "memories": [],
                },
            )
        )

        result = await memwal_client.ask("Tell me about myself")
        assert result.memories_used == 0
        assert result.memories == []

    @respx.mock
    async def test_ask_custom_namespace(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()
        route = respx.post(f"{_TEST_SERVER}/api/ask").mock(
            return_value=httpx.Response(
                200,
                json={"answer": "answer", "memories_used": 0, "memories": []},
            )
        )

        await memwal_client.ask("question", namespace="work")

        body = json.loads(route.calls[0].request.content)
        assert body["namespace"] == "work"


class TestContextManager:
    @respx.mock
    async def test_async_context_manager(self) -> None:
        """Client should work as an async context manager."""
        respx.get(f"{_TEST_SERVER}/health").mock(
            return_value=httpx.Response(
                200,
                json={"status": "ok", "version": "0.1.0"},
            )
        )

        async with MemWal.create(
            key=_TEST_KEY_HEX,
            account_id=_TEST_ACCOUNT_ID,
            server_url=_TEST_SERVER,
        ) as client:
            result = await client.health()
            assert result.status == "ok"


class TestSealSession:
    @respx.mock
    async def test_builds_cached_session_envelope(self, memwal_client: MemWal) -> None:
        mock_seal_session_prereqs()

        first = await memwal_client._build_seal_session()
        second = await memwal_client._build_seal_session()

        exported = json.loads(base64.b64decode(first).decode("utf-8"))
        assert first == second
        assert exported["packageId"] == _TEST_PACKAGE_ID
        assert exported["ttlMin"] == 5
        assert exported["sessionKey"].startswith("suiprivkey")
        assert exported["personalMessageSignature"]


class TestRedactInternalUrls:
    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("Error at http://localhost:8080/path", "Error at [internal]"),
            ("Error at http://127.0.0.1:3000/api", "Error at [internal]"),
            ("Error at http://127.0.0.2:8000/status", "Error at [internal]"),
            ("Error at http://127.128.0.1:9000/info", "Error at [internal]"),
            ("Error at http://[::1]:9000/seal/encrypt", "Error at [internal]"),
            ("Error at http://0.0.0.0:8000/health", "Error at [internal]"),
            ("Error at http://sidecar.localhost:8080/v1", "Error at [internal]"),
            ("Error at http://sub.domain.localhost:3000/test", "Error at [internal]"),
            ("Error at https://api.wal.app/v1/remember", "Error at https://api.wal.app/v1/remember"),
        ],
    )
    def test_redact_internal_urls(self, raw: str, expected: str) -> None:
        from memwal.client import _redact_internal_urls

        assert _redact_internal_urls(raw) == expected


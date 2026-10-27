"""Empty or non-JSON 2xx responses raise ``MemWalJsonBodyError`` (#1219).

Mirrors ``packages/sdk/test/json-body.test.mjs`` (#1201 / #1207): a relayer or
proxy in front of one that answers 2xx with an empty or non-JSON body must
raise a :class:`MemWalError` naming the endpoint and HTTP status rather than
leaking Python's raw :class:`json.JSONDecodeError`.
"""

from __future__ import annotations

import json

import httpx
import nacl.signing
import pytest
import respx

from memwal import (
    MemWal,
    MemWalCompatibilityError,
    MemWalError,
    MemWalJsonBodyError,
    MemWalRememberJobNotFound,
    MemWalSync,
)
from memwal.types import RememberManualOptions
from memwal.utils import bytes_to_hex

_SERVER = "https://relayer.example"
_KEY_HEX = bytes_to_hex(bytes(nacl.signing.SigningKey(b"\x11" * 32)))
_VERSION_JSON = {
    "apiVersion": "1.0.0",
    "relayerVersion": "1.0.0",
    "minSupportedSdk": {"python": "0.1.0"},
}


def _client() -> MemWal:
    return MemWal.create(key=_KEY_HEX, account_id="0x1", server_url=_SERVER)


def _mock_version() -> None:
    respx.get(f"{_SERVER}/version").mock(
        return_value=httpx.Response(200, json=_VERSION_JSON)
    )


def _mock_seal_session_prereqs() -> None:
    _mock_version()
    respx.get(f"{_SERVER}/config").mock(
        return_value=httpx.Response(
            200,
            json={
                "packageId": "0xpkg",
                "network": "testnet",
                "suiRpcUrl": "https://fullnode.testnet.sui.io:443",
            },
        )
    )
    respx.post("https://graphql.testnet.sui.io/graphql").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"object": {"version": 1}}},
        )
    )


@respx.mock
async def test_health_rejects_empty_200_with_memwal_error() -> None:
    respx.get(f"{_SERVER}/health").mock(return_value=httpx.Response(200, content=b"   "))
    with pytest.raises(MemWalJsonBodyError) as exc:
        await _client().health()
    assert isinstance(exc.value, MemWalError)
    assert not isinstance(exc.value, json.JSONDecodeError)
    assert exc.value.status == 200
    assert exc.value.endpoint == "GET /health"
    assert "GET /health" in str(exc.value)
    assert "empty body; expected JSON" in str(exc.value)


@respx.mock
async def test_health_rejects_non_json_200_and_redacts_internal_urls() -> None:
    respx.get(f"{_SERVER}/health").mock(
        return_value=httpx.Response(
            200,
            text="<html>upstream http://localhost:8080/health failed</html>",
            headers={"content-type": "text/html"},
        )
    )
    with pytest.raises(MemWalJsonBodyError) as exc:
        await _client().health()
    assert isinstance(exc.value, MemWalError)
    assert not isinstance(exc.value, json.JSONDecodeError)
    assert exc.value.status == 200
    assert exc.value.endpoint == "GET /health"
    assert "response was not JSON" in str(exc.value)
    assert "localhost" not in str(exc.value)
    assert "[internal]" in str(exc.value)


@respx.mock
async def test_compatibility_rejects_empty_and_non_json_version_200() -> None:
    route = respx.get(f"{_SERVER}/version")
    for content, expected_phrase in (
        (b"", "empty body; expected JSON"),
        (b"nope", "response was not JSON"),
    ):
        route.mock(return_value=httpx.Response(200, content=content))
        with pytest.raises(MemWalJsonBodyError) as exc:
            await _client().compatibility()
        assert exc.value.status == 200
        assert exc.value.endpoint == "GET /version"
        assert expected_phrase in str(exc.value)


@respx.mock
async def test_compatibility_rejects_non_json_health_fallback_200() -> None:
    respx.get(f"{_SERVER}/version").mock(return_value=httpx.Response(404))
    respx.get(f"{_SERVER}/health").mock(
        return_value=httpx.Response(200, text="bad gateway html")
    )
    with pytest.raises(MemWalJsonBodyError) as exc:
        await _client().compatibility()
    assert exc.value.status == 200
    assert exc.value.endpoint == "GET /health"
    assert "response was not JSON" in str(exc.value)


@respx.mock
async def test_compatibility_rejects_non_object_json_200() -> None:
    respx.get(f"{_SERVER}/version").mock(return_value=httpx.Response(200, content=b"null"))
    with pytest.raises(MemWalCompatibilityError):
        await _client().compatibility()


@respx.mock
async def test_config_and_package_version_reject_non_json_200() -> None:
    _mock_version()
    respx.get(f"{_SERVER}/config").mock(return_value=httpx.Response(200, content=b""))
    with pytest.raises(MemWalJsonBodyError) as exc:
        await _client().recall("coffee")
    assert exc.value.status == 200
    assert exc.value.endpoint == "GET /config"
    assert "empty body; expected JSON" in str(exc.value)

    respx.get(f"{_SERVER}/config").mock(
        return_value=httpx.Response(
            200,
            json={
                "packageId": "0xpkg",
                "network": "testnet",
                "suiRpcUrl": "https://fullnode.testnet.sui.io:443",
            },
        )
    )
    respx.post("https://graphql.testnet.sui.io/graphql").mock(
        return_value=httpx.Response(200, text="not-json")
    )
    with pytest.raises(MemWalJsonBodyError) as gql_exc:
        await _client().recall("coffee")
    assert gql_exc.value.status == 200
    assert "graphql.testnet.sui.io" in gql_exc.value.endpoint
    assert "response was not JSON" in str(gql_exc.value)


@respx.mock
async def test_remember_rejects_empty_202_without_polling() -> None:
    _mock_seal_session_prereqs()
    respx.post(f"{_SERVER}/api/remember").mock(
        return_value=httpx.Response(202, content=b"")
    )
    poll_route = respx.get(url__regex=rf"^{_SERVER}/api/remember/.+").mock(
        return_value=httpx.Response(200, json={"job_id": "j1", "status": "done"})
    )

    client = _client()
    with pytest.raises(MemWalJsonBodyError) as exc:
        await client.remember_and_wait("hello", timeout_ms=5_000)
    assert exc.value.status == 202
    assert exc.value.endpoint == "POST /api/remember"
    assert "empty body; expected JSON" in str(exc.value)
    assert poll_route.call_count == 0


@respx.mock
async def test_signed_requests_reject_empty_non_json_and_non_object_200() -> None:
    _mock_seal_session_prereqs()
    respx.post(f"{_SERVER}/api/stats").mock(
        return_value=httpx.Response(200, json={"owner": "0xowner"})
    )
    ns_route = respx.get(f"{_SERVER}/v1/owners/0xowner/namespaces")
    for body in (b"", b"<html>error</html>", b"null", b"[]"):
        ns_route.mock(return_value=httpx.Response(200, content=body))
        with pytest.raises(MemWalJsonBodyError) as exc:
            await _client().list_namespaces()
        assert exc.value.status == 200
        assert exc.value.endpoint == "GET /v1/owners/0xowner/namespaces"

    restore_route = respx.post(f"{_SERVER}/api/restore")
    restore_route.mock(return_value=httpx.Response(200, content=b""))
    with pytest.raises(MemWalJsonBodyError) as restore_exc:
        await _client().restore("default")
    assert restore_exc.value.status == 200
    assert restore_exc.value.endpoint == "POST /api/restore"

    manual_route = respx.post(f"{_SERVER}/api/remember/manual")
    manual_route.mock(return_value=httpx.Response(200, text="nope"))
    with pytest.raises(MemWalJsonBodyError) as manual_exc:
        await _client().remember_manual(
            RememberManualOptions(encrypted_data="ZGF0YQ==", vector=[0.1])
        )
    assert manual_exc.value.status == 200
    assert manual_exc.value.endpoint == "POST /api/remember/manual"


@respx.mock
async def test_remember_status_distinguishes_200_non_json_from_404_non_json() -> None:
    _mock_seal_session_prereqs()
    route = respx.get(f"{_SERVER}/api/remember/job-1")

    # 200 with empty or non-JSON body raises MemWalJsonBodyError
    for content in (b"", b"<html>bad</html>"):
        route.mock(return_value=httpx.Response(200, content=content))
        with pytest.raises(MemWalJsonBodyError) as exc:
            await _client().get_remember_status("job-1")
        assert exc.value.status == 200
        assert exc.value.endpoint == "GET /api/remember/job-1"

        with pytest.raises(MemWalJsonBodyError) as wait_exc:
            await _client().wait_for_remember_job(
                "job-1", poll_interval_ms=0, timeout_ms=5_000
            )
        assert wait_exc.value.status == 200

    # 404 with empty or non-JSON body remains not_found
    route.mock(return_value=httpx.Response(404, content=b""))
    status = await _client().get_remember_status("job-1")
    assert status.status == "not_found"
    with pytest.raises(MemWalRememberJobNotFound):
        await _client().wait_for_remember_job(
            "job-1", poll_interval_ms=0, timeout_ms=5_000
        )


@respx.mock
def test_sync_client_surfaces_memwal_json_body_error() -> None:
    respx.get(f"{_SERVER}/health").mock(return_value=httpx.Response(200, content=b""))
    sync_client = MemWalSync.create(key=_KEY_HEX, account_id="0x1", server_url=_SERVER)
    with pytest.raises(MemWalJsonBodyError) as exc:
        sync_client.health()
    assert exc.value.status == 200
    assert exc.value.endpoint == "GET /health"

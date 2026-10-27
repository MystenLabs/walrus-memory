import pytest

from memwal import ForgetResult, MemWal, MemWalSync


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
        *args,
        **kwargs,
    ):
        self.captured.append((method, path, body))
        return {"deleted": 2, "namespace": body["namespace"], "owner": "0xowner"}


@pytest.mark.asyncio
async def test_forget_posts_the_client_namespace():
    client = CaptureMemWal.create(
        key="11" * 32,
        account_id="0x" + "ab" * 32,
        server_url="https://relayer.example",
        namespace="profile",
    )
    result = await client.forget()
    assert result == ForgetResult(deleted=2, namespace="profile", owner="0xowner")
    alias = await client.forget_namespace("custom")
    assert alias == ForgetResult(deleted=2, namespace="custom", owner="0xowner")
    assert client.captured == [
        ("POST", "/api/forget", {"namespace": "profile"}),
        ("POST", "/api/forget", {"namespace": "custom"}),
    ]
    await client.close()


@pytest.mark.asyncio
async def test_forget_rejects_empty_namespace_without_deleting_default():
    client = CaptureMemWal.create(
        key="11" * 32,
        account_id="0x" + "ab" * 32,
        server_url="https://relayer.example",
        namespace="important",
    )
    with pytest.raises(ValueError, match="namespace cannot be empty"):
        await client.forget("")
    with pytest.raises(ValueError, match="namespace cannot be empty"):
        await client.forget_namespace("")
    assert client.captured == []
    await client.close()


def test_sync_client_has_forget():
    assert hasattr(MemWal, "forget")
    assert hasattr(MemWalSync, "forget")
    assert hasattr(MemWal, "forget_namespace")
    assert hasattr(MemWalSync, "forget_namespace")
    sync_client = MemWalSync(
        CaptureMemWal.create(
            key="11" * 32,
            account_id="0x" + "ab" * 32,
            server_url="https://relayer.example",
            namespace="important",
        )
    )
    with pytest.raises(ValueError, match="namespace cannot be empty"):
        sync_client.forget("")
    with pytest.raises(ValueError, match="namespace cannot be empty"):
        sync_client.forget_namespace("")
    assert sync_client._inner.captured == []
    assert sync_client.forget_namespace("archive") == ForgetResult(
        deleted=2, namespace="archive", owner="0xowner"
    )
    assert sync_client._inner.captured == [
        ("POST", "/api/forget", {"namespace": "archive"})
    ]
    sync_client.close()

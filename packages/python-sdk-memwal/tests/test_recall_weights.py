import pytest

from memwal import MemWal, RecallParams, ScoringWeights


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
        self, method, path, body, accepted_statuses=(200,), include_seal_session=True,
    ):
        self.captured.append((method, path, body))
        return {"results": [], "total": 0}


@pytest.mark.asyncio
async def test_recall_forwards_scoring_weights_and_sort():
    client = CaptureMemWal.create(
        key="11" * 32,
        account_id="0x" + "ab" * 32,
        server_url="https://relayer.example",
    )
    await client.recall(RecallParams(
        query="food allergies",
        scoring_weights=ScoringWeights(recency=1.0),
        sort="recent",
    ))
    method, path, body = client.captured[0]
    assert method == "POST"
    assert path == "/api/recall"
    assert body["scoring_weights"] == {"recency": 1.0}
    assert body["sort"] == "recent"
    await client.close()

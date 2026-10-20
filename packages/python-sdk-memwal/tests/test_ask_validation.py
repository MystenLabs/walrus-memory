"""``ask()`` validates its question and limit before signing (#1249).

``remember``/``analyze``/``embed`` reject blank text before signing; ``ask``
did not, so an empty question reached the LLM-backed endpoint. Its
``limit`` was also forwarded verbatim, including a literal ``NaN`` token
that is not valid JSON.
"""

from __future__ import annotations

import json
import math
from typing import Any, List

import nacl.signing
import pytest

from memwal import MemWal
from memwal.utils import bytes_to_hex

_KEY_HEX = bytes_to_hex(bytes(nacl.signing.SigningKey(b"\x01" * 32)))


def _client(sent: List[str]) -> MemWal:
    client = MemWal.create(key=_KEY_HEX, account_id="0x1", server_url="https://relayer.example")

    async def fake_signed_request(method, path, body, **kwargs):  # type: ignore[no-untyped-def]
        # Same serialization the real request path uses for the signed body.
        sent.append(json.dumps(body))
        return {"answer": "hi", "memories_used": 0, "memories": []}

    client._signed_request = fake_signed_request  # type: ignore[method-assign]
    return client


@pytest.mark.parametrize("question", ["", " ", "\t\n"])
async def test_blank_question_rejected_before_signing(question: str) -> None:
    sent: List[str] = []
    with pytest.raises(ValueError, match="question cannot be empty"):
        await _client(sent).ask(question)
    assert sent == []


@pytest.mark.parametrize("limit", [math.nan, math.inf, -1, 0, 2.5, "5", True, None])
async def test_bad_limit_rejected_before_signing(limit: Any) -> None:
    sent: List[str] = []
    with pytest.raises(ValueError, match="limit must be a positive integer"):
        await _client(sent).ask("q?", limit=limit)
    assert sent == []


async def test_valid_call_is_sent_unchanged() -> None:
    sent: List[str] = []
    result = await _client(sent).ask("q?", limit=3)
    assert result.answer == "hi"
    assert json.loads(sent[0]) == {"question": "q?", "limit": 3, "namespace": "default"}

"""Offline mock client regression tests."""

import base64
import inspect
import json
import re

import pytest

from memwal import (
    MemWalMock,
    MemWalMockSeed,
    MemWalMockSync,
    MemWalSync,
    RecallParams,
    RememberBulkItem,
    RememberBulkOptions,
)


@pytest.mark.asyncio
async def test_mock_remember_and_recall_are_deterministic_and_offline(monkeypatch):
    def reject_network(*args, **kwargs):
        raise AssertionError("MemWalMock must not create a network client")

    monkeypatch.setattr("httpx.AsyncClient", reject_network)
    mock = MemWalMock.create(namespace="user-a", owner="test-owner")
    coffee = await mock.remember_and_wait("I prefer coffee in the morning")
    tea = await mock.remember_and_wait("I drink tea at night")

    assert coffee.id == "mock-job-000001"
    assert coffee.blob_id == "mock-blob-000001"
    assert coffee.namespace == "user-a"
    assert tea.blob_id == "mock-blob-000002"

    recalled = await mock.recall(RecallParams(query="morning coffee", limit=2))
    assert [memory.text for memory in recalled.results] == [
        "I prefer coffee in the morning",
        "I drink tea at night",
    ]
    assert recalled.results[0].distance == 0
    assert recalled.results[0].score == 1.0
    assert recalled.results[0].created_at == "2026-01-01T00:00:01.000Z"
    assert recalled.results[1].distance == 1
    assert recalled.results[1].score == 0.0
    assert recalled.results[1].created_at == "2026-01-01T00:00:02.000Z"



@pytest.mark.asyncio
async def test_mock_recall_sort_recent_is_not_relevance_order():
    mock = MemWalMock.create(namespace="user-a")
    await mock.remember_and_wait("I prefer coffee in the morning")
    await mock.remember_and_wait("I drink tea at night")

    recent = await mock.recall(RecallParams(query="I", sort="recent"))
    assert [memory.text for memory in recent.results] == [
        "I drink tea at night",
        "I prefer coffee in the morning",
    ]

    with pytest.raises(ValueError, match="sort"):
        await mock.recall(RecallParams(query="I", sort="newest"))


@pytest.mark.asyncio
async def test_mock_recall_sort_recent_stays_inside_the_semantic_window():
    mock = MemWalMock.create(namespace="user-a")
    for i in range(6):
        await mock.remember_and_wait(f"same fact {i}")
    recent = await mock.recall(RecallParams(query="same fact", limit=1, sort="recent"))
    assert recent.results[0].text == "same fact 4"

    wide = MemWalMock.create(namespace="user-a")
    for i in range(51):
        await wide.remember_and_wait(f"same fact {i}")
    first = await wide.recall(RecallParams(query="same fact", limit=11, sort="recent"))
    assert first.results[0].text == "same fact 49"

@pytest.mark.asyncio
async def test_mock_isolates_namespaces_and_honors_max_distance():
    mock = MemWalMock.create()
    await mock.remember_and_wait("Alice likes ramen", "user-a")
    await mock.remember_and_wait("Bob likes tacos", "user-b")

    alice = await mock.recall(
        RecallParams(query="likes", namespace="user-a", max_distance=0.5)
    )
    bob = await mock.recall("likes", namespace="user-b")
    empty = await mock.recall("likes")

    assert [memory.text for memory in alice.results] == ["Alice likes ramen"]
    assert [memory.text for memory in bob.results] == ["Bob likes tacos"]
    assert empty.total == 0
    dropped = await mock.recall(
        RecallParams(query="likes", namespace="user-a", max_distance=0)
    )
    assert dropped.results == []
    assert dropped.total == 1


@pytest.mark.asyncio
async def test_mock_supports_jobs_bulk_analyze_forget_and_clear():
    mock = MemWalMock.create()
    accepted = await mock.remember("single fact")
    status = await mock.get_remember_status(accepted.job_id)
    assert status.status == "done"
    assert status.blob_id == "mock-blob-000001"

    bulk = await mock.remember_bulk_and_wait(
        [
            RememberBulkItem(text="bulk one", namespace="one"),
            RememberBulkItem(text="bulk two", namespace="two"),
        ]
    )
    assert bulk.succeeded == 2
    assert bulk.failed == 0

    analyzed = await mock.analyze_and_wait("durable analyzed fact", "analysis")
    assert analyzed.facts[0].text == "durable analyzed fact"

    assert mock.forget("mock-blob-000001") is True
    assert mock.forget("missing") is False
    assert mock.clear("one") == 1
    assert (await mock.recall("bulk", namespace="one")).total == 0


@pytest.mark.asyncio
async def test_mock_seed_embed_health_and_compatibility():
    first = MemWalMock.create(
        initial_memories=[
            MemWalMockSeed(text="seed memory", namespace="seed", blob_id="seed-blob")
        ]
    )
    second = MemWalMock.create()

    assert await first.embed("same text") == await second.embed("same text")
    recalled = await first.recall("seed", namespace="seed")
    assert recalled.results[0].blob_id == "seed-blob"
    assert (await first.health()).status == "ok"
    assert (await first.compatibility())["featureFlags"]["offlineMock"] is True


def test_sync_mock_wraps_core_flows_and_accepts_production_options():
    mock = MemWalMockSync.create(namespace="sync")
    opts = RememberBulkOptions(poll_interval_ms=1, timeout_ms=10)

    accepted = mock.remember("accepted memory")
    stored = mock.wait_for_remember_job(
        accepted.job_id, poll_interval_ms=1, timeout_ms=10
    )
    waited = mock.remember_and_wait(
        "sync memory", poll_interval_ms=1, timeout_ms=10
    )
    bulk = mock.remember_bulk_and_wait(
        [RememberBulkItem(text="bulk memory")], opts=opts
    )
    assert mock.wait_for_remember_jobs([accepted.job_id], opts=opts).succeeded == 1
    analyzed = mock.analyze("analyzed memory", occurred_at="2024-01-01T00:00:00Z")
    analyzed_wait = mock.analyze_and_wait(
        "analyzed and waited",
        opts=opts,
        occurred_at="2024-01-01T00:00:00Z",
    )
    recalled = mock.recall("sync")

    assert stored.blob_id == "mock-blob-000001"
    assert waited.namespace == "sync"
    assert bulk.succeeded == 1
    assert analyzed.fact_count == 1
    assert analyzed_wait.succeeded == 1
    assert recalled.results[0].text == "sync memory"


def test_sync_mock_polling_and_analyze_signatures_match_production():
    methods = (
        "remember",
        "remember_async",
        "wait_for_remember_job",
        "remember_and_wait",
        "wait_for_remember_jobs",
        "remember_bulk_and_wait",
        "analyze",
        "analyze_and_wait",
    )

    def parameter_contract(method):
        return [
            (parameter.name, parameter.kind, parameter.default)
            for parameter in inspect.signature(method).parameters.values()
        ]

    for method_name in methods:
        assert parameter_contract(getattr(MemWalMockSync, method_name)) == parameter_contract(
            getattr(MemWalSync, method_name)
        )


@pytest.mark.asyncio
async def test_sync_mock_works_inside_an_existing_event_loop():
    mock = MemWalMockSync.create(namespace="notebook")

    stored = mock.remember_and_wait("called from a running loop")
    recalled = mock.recall("running loop")

    assert stored.namespace == "notebook"
    assert recalled.results[0].text == "called from a running loop"


@pytest.mark.asyncio
async def test_mock_list_namespaces_aggregates_memories_by_namespace():
    mock = MemWalMock.create(
        initial_memories=[
            MemWalMockSeed(text="one", namespace="work"),
            MemWalMockSeed(text="two", namespace="work"),
            MemWalMockSeed(text="旅行", namespace="home"),
        ]
    )

    page = await mock.list_namespaces()
    by_name = {ns.name: ns for ns in page.namespaces}

    assert sorted(by_name) == ["home", "work"]
    assert by_name["work"].memory_count == 2
    assert by_name["work"].storage_used == 6
    assert by_name["home"].storage_used == len("旅行".encode("utf-8"))
    assert page.has_more is False
    # Matches the live relayer's current wire-format version.
    assert page.snapshot_version == 2


@pytest.mark.asyncio
async def test_mock_list_namespaces_reports_has_more_when_limit_truncates():
    mock = MemWalMock.create(
        initial_memories=[
            MemWalMockSeed(text="a", namespace="alpha"),
            MemWalMockSeed(text="b", namespace="bravo"),
            MemWalMockSeed(text="c", namespace="charlie"),
        ]
    )

    page = await mock.list_namespaces(limit=2)

    assert len(page.namespaces) == 2
    assert page.has_more is True, "has_more is the pagination signal, not page length"
    assert page.next_cursor


@pytest.mark.asyncio
async def test_mock_namespace_cursor_uses_the_relayer_wire_format_and_resets_after_a_walk():
    mock = MemWalMock.create(
        initial_memories=[
            MemWalMockSeed(text="a", namespace="旅行"),
            MemWalMockSeed(text="b", namespace="work"),
        ]
    )

    first = await mock.list_namespaces(limit=1)
    assert re.fullmatch(r"[A-Za-z0-9_-]+", first.next_cursor)
    padded = first.next_cursor + "=" * (-len(first.next_cursor) % 4)
    cursor = json.loads(base64.urlsafe_b64decode(padded))
    assert cursor["namespace"] == "旅行"
    assert cursor["updated_at"] == first.namespaces[0].updated_at
    assert cursor["snapshot_at"]

    last = await mock.list_namespaces(cursor=first.next_cursor)
    assert [ns.name for ns in last.namespaces] == ["work"]
    assert last.has_more is False
    padded = last.next_cursor + "=" * (-len(last.next_cursor) % 4)
    assert json.loads(base64.urlsafe_b64decode(padded))["snapshot_at"] is None

    empty = await mock.list_namespaces(cursor=last.next_cursor)
    assert empty.namespaces == []
    assert empty.next_cursor == last.next_cursor


@pytest.mark.asyncio
async def test_mock_namespace_walk_defers_new_writes_until_the_next_poll():
    mock = MemWalMock.create(
        initial_memories=[
            MemWalMockSeed(text="a", namespace="alpha"),
            MemWalMockSeed(text="b", namespace="bravo"),
        ]
    )

    first = await mock.list_namespaces(limit=1)
    await mock.remember("new", "bravo")
    last = await mock.list_namespaces(cursor=first.next_cursor)
    assert last.namespaces == []
    assert last.has_more is False

    poll = await mock.list_namespaces(cursor=last.next_cursor)
    assert [ns.name for ns in poll.namespaces] == ["bravo"]
    assert poll.namespaces[0].memory_count == 2


def test_sync_mock_list_namespaces_matches_production():
    mock = MemWalMockSync.create(namespace="sync")
    mock.remember("sync memory")

    page = mock.list_namespaces(limit=10)

    assert [ns.name for ns in page.namespaces] == ["sync"]
    assert inspect.signature(MemWalMockSync.list_namespaces) == inspect.signature(
        MemWalSync.list_namespaces
    )

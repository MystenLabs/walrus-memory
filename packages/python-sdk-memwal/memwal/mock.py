"""Deterministic, dependency-free in-memory Walrus Memory client for tests."""

from __future__ import annotations

import asyncio
import base64
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Union

from .client import _check_limit
from .types import (
    AnalyzedFact,
    AnalyzeResult,
    AnalyzeWaitResult,
    AskMemory,
    AskResult,
    EmbedResult,
    HealthResult,
    NamespacesResult,
    NamespaceSummary,
    RecallMemory,
    RecallParams,
    RecallResult,
    RememberAcceptedResult,
    RememberBulkAcceptedResult,
    RememberBulkItem,
    RememberBulkItemResult,
    RememberBulkOptions,
    RememberBulkResult,
    RememberBulkStatusItem,
    RememberBulkStatusResult,
    RememberJobStatus,
    RememberResult,
    RestoreResult,
)

_MOCK_NAMESPACE_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass
class MemWalMockSeed:
    """One optional memory loaded when a mock is created."""

    text: str
    namespace: Optional[str] = None
    blob_id: Optional[str] = None


@dataclass
class _Memory:
    id: str
    job_id: str
    blob_id: str
    text: str
    namespace: str
    sequence: int


def _tokens(text: str) -> set[str]:
    normalized = unicodedata.normalize("NFKC", text).casefold()
    return set(re.findall(r"[^\W_]+", normalized, flags=re.UNICODE))


def _distance(query_tokens: set[str], text: str) -> float:
    if not query_tokens:
        return 1.0
    matches = len(query_tokens.intersection(_tokens(text)))
    return 1.0 - matches / len(query_tokens)


def _mock_timestamp(sequence: int) -> str:
    # Same shape as the TypeScript mock's Date.toISOString(), so fixed-width
    # timestamps compare correctly as strings.
    moment = _MOCK_NAMESPACE_EPOCH + timedelta(seconds=sequence)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _encode_namespaces_cursor(payload: Dict[str, Any]) -> str:
    # The relayer's cursor: URL-safe unpadded base64 of a JSON object.
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_namespaces_cursor(cursor: str) -> Dict[str, Any]:
    padded = cursor + "=" * (-len(cursor) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _validate_text(text: str, field: str = "text") -> None:
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"{field} cannot be empty")


class MemWalMock:
    """In-memory implementation of the common async :class:`MemWal` API.

    The mock never creates an HTTP client or contacts Sui/Walrus. Recall uses
    deterministic token-overlap distance; it is intentionally simple and is
    designed for application tests, not relevance benchmarking.
    """

    def __init__(
        self,
        namespace: str = "default",
        owner: str = "mock-owner",
        initial_memories: Optional[Sequence[MemWalMockSeed]] = None,
    ) -> None:
        if not namespace:
            raise ValueError("namespace cannot be empty")
        self._namespace = namespace
        self._owner = owner
        self._memories: List[_Memory] = []
        self._jobs: Dict[str, _Memory] = {}
        self._sequence = 0
        for seed in initial_memories or []:
            self._store(seed.text, seed.namespace, seed.blob_id)

    @classmethod
    def create(
        cls,
        namespace: str = "default",
        owner: str = "mock-owner",
        initial_memories: Optional[Sequence[MemWalMockSeed]] = None,
    ) -> "MemWalMock":
        return cls(namespace, owner, initial_memories)

    async def close(self) -> None:
        """No-op for API parity with :class:`MemWal`."""

    async def __aenter__(self) -> "MemWalMock":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def remember(
        self,
        text: str,
        namespace: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> RememberAcceptedResult:
        del idempotency_key
        memory = self._store(text, namespace)
        return RememberAcceptedResult(job_id=memory.job_id, status="done")

    async def remember_async(
        self,
        text: str,
        namespace: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> RememberAcceptedResult:
        return await self.remember(text, namespace, idempotency_key)

    async def wait_for_remember_job(
        self,
        job_id: str,
        poll_interval_ms: int = 1500,
        timeout_ms: int = 60_000,
    ) -> RememberResult:
        del poll_interval_ms, timeout_ms
        memory = self._jobs.get(job_id)
        if memory is None:
            raise KeyError(f"Remember job not found: {job_id}")
        return self._remember_result(memory)

    async def remember_and_wait(
        self,
        text: str,
        namespace: Optional[str] = None,
        poll_interval_ms: int = 1500,
        timeout_ms: int = 60_000,
        idempotency_key: Optional[str] = None,
    ) -> RememberResult:
        accepted = await self.remember(text, namespace, idempotency_key)
        return await self.wait_for_remember_job(
            accepted.job_id, poll_interval_ms, timeout_ms
        )

    async def get_remember_status(self, job_id: str) -> RememberJobStatus:
        memory = self._jobs.get(job_id)
        if memory is None:
            return RememberJobStatus(job_id=job_id, status="not_found")
        return RememberJobStatus(
            job_id=job_id,
            status="done",
            owner=self._owner,
            namespace=memory.namespace,
            blob_id=memory.blob_id,
        )

    async def remember_bulk_async(
        self, items: Sequence[RememberBulkItem]
    ) -> RememberBulkAcceptedResult:
        job_ids = [self._store(item.text, item.namespace).job_id for item in items]
        return RememberBulkAcceptedResult(
            job_ids=job_ids, total=len(job_ids), status="done"
        )

    async def remember_bulk(
        self, items: Sequence[RememberBulkItem]
    ) -> RememberBulkAcceptedResult:
        return await self.remember_bulk_async(items)

    async def get_remember_bulk_status(
        self, job_ids: Sequence[str]
    ) -> RememberBulkStatusResult:
        results = []
        for job_id in job_ids:
            memory = self._jobs.get(job_id)
            results.append(
                RememberBulkStatusItem(
                    job_id=job_id,
                    status="done" if memory else "not_found",
                    blob_id=memory.blob_id if memory else None,
                )
            )
        return RememberBulkStatusResult(results=results)

    async def wait_for_remember_jobs(
        self,
        job_ids: Sequence[str],
        opts: Optional[RememberBulkOptions] = None,
    ) -> RememberBulkResult:
        del opts
        results: List[RememberBulkItemResult] = []
        for job_id in job_ids:
            memory = self._jobs.get(job_id)
            results.append(
                RememberBulkItemResult(
                    id=job_id,
                    blob_id=memory.blob_id if memory else "",
                    status="done" if memory else "failed",
                    error=None if memory else "Remember job not found",
                )
            )
        succeeded = sum(result.status == "done" for result in results)
        return RememberBulkResult(
            results=results,
            total=len(results),
            succeeded=succeeded,
            failed=len(results) - succeeded,
            timed_out=0,
        )

    async def remember_bulk_and_wait(
        self,
        items: Sequence[RememberBulkItem],
        opts: Optional[RememberBulkOptions] = None,
    ) -> RememberBulkResult:
        accepted = await self.remember_bulk_async(items)
        return await self.wait_for_remember_jobs(accepted.job_ids, opts)

    async def recall(
        self,
        query: Union[str, RecallParams],
        limit: int = 10,
        namespace: Optional[str] = None,
        max_distance: Optional[float] = None,
    ) -> RecallResult:
        """Token-overlap recall over the in-memory store.

        ``RecallParams.sort`` is honored: ``"recent"`` keeps the semantic top
        ``max(min(limit * 5, 50), limit)`` and orders that window newest first,
        like the relayer. Otherwise results are ordered by token-overlap
        distance. ``RecallParams.scoring_weights`` is accepted but ignored and
        does not re-rank; ``distance`` is always token overlap.
        """
        if isinstance(query, RecallParams):
            limit = query.limit
            namespace = query.namespace
            max_distance = query.max_distance
            sort = query.sort
            query_text = query.query
        else:
            sort = None
            query_text = query
        _validate_text(query_text, "query")
        _check_limit(limit)
        if sort not in (None, "relevance", "recent"):
            raise ValueError("sort must be 'relevance' or 'recent'")
        resolved_namespace = self._namespace if namespace is None else namespace
        if not resolved_namespace:
            raise ValueError("namespace cannot be empty")
        query_tokens = _tokens(query_text)
        ranked = [
            (memory, _distance(query_tokens, memory.text))
            for memory in self._memories
            if memory.namespace == resolved_namespace
        ]
        ranked.sort(key=lambda item: (item[1], item[0].sequence))
        if sort == "recent":
            # Same window as the TypeScript mock and RecallSort::candidate_limit.
            # A newer memory outside that semantic window must not win.
            window = max(min(limit * 5, 50), limit)
            ranked = sorted(ranked[:window], key=lambda item: (-item[0].sequence, item[1]))
        page = ranked[:limit]
        if max_distance is not None:
            page = [item for item in page if item[1] < max_distance]
        results = [
            RecallMemory(
                blob_id=memory.blob_id,
                text=memory.text,
                distance=score,
                score=1.0 - score,
                created_at=_mock_timestamp(memory.sequence),
            )
            for memory, score in page
        ]
        return RecallResult(results=results, total=len(ranked[:limit]))

    async def analyze(
        self,
        text: str,
        namespace: Optional[str] = None,
        occurred_at: Optional[Union[str, datetime]] = None,
    ) -> AnalyzeResult:
        del occurred_at
        memory = self._store(text, namespace)
        return AnalyzeResult(
            facts=[
                AnalyzedFact(
                    text=text, id=memory.id, blob_id=memory.blob_id
                )
            ],
            fact_count=1,
            job_ids=[memory.job_id],
            status="done",
            owner=self._owner,
        )

    async def analyze_and_wait(
        self,
        text: str,
        namespace: Optional[str] = None,
        opts: Optional[RememberBulkOptions] = None,
        occurred_at: Optional[Union[str, datetime]] = None,
    ) -> AnalyzeWaitResult:
        analyzed = await self.analyze(text, namespace, occurred_at=occurred_at)
        settled = await self.wait_for_remember_jobs(analyzed.job_ids, opts)
        return AnalyzeWaitResult(
            results=settled.results,
            total=settled.total,
            succeeded=settled.succeeded,
            failed=settled.failed,
            timed_out=settled.timed_out,
            facts=analyzed.facts,
            owner=self._owner,
        )

    async def embed(self, text: str) -> EmbedResult:
        _validate_text(text)
        vector = [0.0] * 16
        for token in _tokens(text):
            value = 2166136261
            for char in token:
                value ^= ord(char)
                value = (value * 16777619) & 0xFFFFFFFF
            vector[value % len(vector)] += 1.0
        magnitude = math.sqrt(sum(value * value for value in vector)) or 1.0
        return EmbedResult(vector=[value / magnitude for value in vector])

    async def ask(
        self, question: str, limit: int = 5, namespace: Optional[str] = None
    ) -> AskResult:
        recalled = await self.recall(question, limit, namespace)
        memories = [
            AskMemory(
                blob_id=memory.blob_id,
                text=memory.text,
                distance=memory.distance,
            )
            for memory in recalled.results
        ]
        return AskResult(
            answer="\n".join(memory.text for memory in memories),
            memories_used=len(memories),
            memories=memories,
        )

    async def restore(self, namespace: str, limit: int = 10) -> RestoreResult:
        _check_limit(limit)
        return RestoreResult(
            restored=0,
            skipped=0,
            total=0,
            namespace=namespace,
            owner=self._owner,
            truncated=False,
            failed=0,
        )

    async def list_namespaces(
        self,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> NamespacesResult:
        if limit is not None:
            _check_limit(limit)
        grouped: Dict[str, List[_Memory]] = {}
        for memory in self._memories:
            grouped.setdefault(memory.namespace, []).append(memory)
        summaries = sorted(
            (
                NamespaceSummary(
                    id=f"mock-ns-{name}",
                    name=name,
                    memory_count=len(memories),
                    storage_used=sum(len(m.text.encode("utf-8")) for m in memories),
                    updated_at=_mock_timestamp(max(m.sequence for m in memories)),
                )
                for name, memories in grouped.items()
            ),
            key=lambda ns: (ns.updated_at, ns.name),
        )

        # Keyset walk pinned to a snapshot, like the relayer: writes made
        # mid-walk surface on the next poll, not in the current walk.
        after = _decode_namespaces_cursor(cursor) if cursor is not None else None
        snapshot_at = (after or {}).get("snapshot_at") or _mock_timestamp(self._sequence)
        remaining = [
            ns
            for ns in summaries
            if ns.updated_at <= snapshot_at
            and (
                after is None
                or (ns.updated_at, ns.name) > (after["updated_at"], after["namespace"])
            )
        ]
        page = remaining if limit is None else remaining[:limit]
        has_more = len(remaining) > len(page)

        watermark = (
            {"updated_at": page[-1].updated_at, "namespace": page[-1].name} if page else after
        )
        next_cursor = None
        if watermark is not None:
            next_cursor = _encode_namespaces_cursor(
                {
                    "updated_at": watermark["updated_at"],
                    "namespace": watermark["namespace"],
                    # A finished walk drops the snapshot so the next poll
                    # takes a fresh one.
                    "snapshot_at": snapshot_at if has_more else None,
                }
            )

        return NamespacesResult(
            namespaces=page,
            next_cursor=next_cursor,
            has_more=has_more,
            # Matches the live relayer's current wire-format version.
            snapshot_version=2,
        )

    async def health(self) -> HealthResult:
        return HealthResult(
            status="ok",
            version="memwal-mock",
            relayer_version="memwal-mock",
            api_version="1.0.0",
            min_supported_sdk={"typescript": "0.0.0", "python": "0.0.0", "mcp": "0.0.0"},
            feature_flags={"offlineMock": True},
            deprecations=[],
            build={},
        )

    async def compatibility(self) -> Dict[str, Any]:
        return {
            "relayerVersion": "memwal-mock",
            "apiVersion": "1.0.0",
            "minSupportedSdk": {
                "typescript": "0.0.0",
                "python": "0.0.0",
                "mcp": "0.0.0",
            },
            "featureFlags": {"offlineMock": True},
            "deprecations": [],
            "build": {},
        }

    def forget(self, blob_id: str) -> bool:
        for index, memory in enumerate(self._memories):
            if memory.blob_id == blob_id:
                self._memories.pop(index)
                self._jobs.pop(memory.job_id, None)
                return True
        return False

    def clear(self, namespace: Optional[str] = None) -> int:
        removed = [
            memory
            for memory in self._memories
            if namespace is None or memory.namespace == namespace
        ]
        self._memories = [
            memory
            for memory in self._memories
            if namespace is not None and memory.namespace != namespace
        ]
        for memory in removed:
            self._jobs.pop(memory.job_id, None)
        return len(removed)

    def _store(
        self,
        text: str,
        namespace: Optional[str] = None,
        blob_id: Optional[str] = None,
    ) -> _Memory:
        _validate_text(text)
        resolved_namespace = self._namespace if namespace is None else namespace
        if not resolved_namespace:
            raise ValueError("namespace cannot be empty")
        self._sequence += 1
        suffix = f"{self._sequence:06d}"
        memory = _Memory(
            id=f"mock-job-{suffix}",
            job_id=f"mock-job-{suffix}",
            blob_id=blob_id or f"mock-blob-{suffix}",
            text=text,
            namespace=resolved_namespace,
            sequence=self._sequence,
        )
        self._memories.append(memory)
        self._jobs[memory.job_id] = memory
        return memory

    def _remember_result(self, memory: _Memory) -> RememberResult:
        return RememberResult(
            id=memory.id,
            blob_id=memory.blob_id,
            owner=self._owner,
            namespace=memory.namespace,
        )


class MemWalMockSync:
    """Synchronous wrapper around :class:`MemWalMock` for non-async tests."""

    def __init__(self, inner: MemWalMock) -> None:
        self._inner = inner

    @classmethod
    def create(
        cls,
        namespace: str = "default",
        owner: str = "mock-owner",
        initial_memories: Optional[Sequence[MemWalMockSeed]] = None,
    ) -> "MemWalMockSync":
        return cls(MemWalMock.create(namespace, owner, initial_memories))

    @staticmethod
    def _run(coro: Any) -> Any:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # Match MemWalSync in notebooks and other hosts with a live loop:
            # execute the coroutine on a fresh event loop in a worker thread.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
        return asyncio.run(coro)

    def remember(
        self,
        text: str,
        namespace: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> RememberAcceptedResult:
        return self._run(self._inner.remember(text, namespace, idempotency_key))

    def remember_async(
        self,
        text: str,
        namespace: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> RememberAcceptedResult:
        return self.remember(text, namespace, idempotency_key)

    def wait_for_remember_job(
        self,
        job_id: str,
        poll_interval_ms: int = 1500,
        timeout_ms: int = 60_000,
    ) -> RememberResult:
        return self._run(
            self._inner.wait_for_remember_job(
                job_id,
                poll_interval_ms=poll_interval_ms,
                timeout_ms=timeout_ms,
            )
        )

    def get_remember_status(self, job_id: str) -> RememberJobStatus:
        return self._run(self._inner.get_remember_status(job_id))

    def remember_and_wait(
        self,
        text: str,
        namespace: Optional[str] = None,
        poll_interval_ms: int = 1500,
        timeout_ms: int = 60_000,
        idempotency_key: Optional[str] = None,
    ) -> RememberResult:
        return self._run(
            self._inner.remember_and_wait(
                text,
                namespace,
                poll_interval_ms=poll_interval_ms,
                timeout_ms=timeout_ms,
                idempotency_key=idempotency_key,
            )
        )

    def remember_bulk_async(
        self, items: Sequence[RememberBulkItem]
    ) -> RememberBulkAcceptedResult:
        return self._run(self._inner.remember_bulk_async(items))

    def remember_bulk(
        self, items: Sequence[RememberBulkItem]
    ) -> RememberBulkAcceptedResult:
        return self.remember_bulk_async(items)

    def get_remember_bulk_status(
        self, job_ids: Sequence[str]
    ) -> RememberBulkStatusResult:
        return self._run(self._inner.get_remember_bulk_status(job_ids))

    def wait_for_remember_jobs(
        self,
        job_ids: Sequence[str],
        opts: Optional[RememberBulkOptions] = None,
    ) -> RememberBulkResult:
        return self._run(self._inner.wait_for_remember_jobs(job_ids, opts))

    def remember_bulk_and_wait(
        self,
        items: Sequence[RememberBulkItem],
        opts: Optional[RememberBulkOptions] = None,
    ) -> RememberBulkResult:
        return self._run(self._inner.remember_bulk_and_wait(items, opts))

    def recall(
        self,
        query: Union[str, RecallParams],
        limit: int = 10,
        namespace: Optional[str] = None,
        max_distance: Optional[float] = None,
    ) -> RecallResult:
        return self._run(
            self._inner.recall(query, limit, namespace, max_distance)
        )

    def analyze(
        self,
        text: str,
        namespace: Optional[str] = None,
        occurred_at: Optional[Union[str, datetime]] = None,
    ) -> AnalyzeResult:
        return self._run(
            self._inner.analyze(text, namespace, occurred_at=occurred_at)
        )

    def analyze_and_wait(
        self,
        text: str,
        namespace: Optional[str] = None,
        opts: Optional[RememberBulkOptions] = None,
        occurred_at: Optional[Union[str, datetime]] = None,
    ) -> AnalyzeWaitResult:
        return self._run(
            self._inner.analyze_and_wait(
                text, namespace, opts, occurred_at=occurred_at
            )
        )

    def embed(self, text: str) -> EmbedResult:
        return self._run(self._inner.embed(text))

    def ask(
        self, question: str, limit: int = 5, namespace: Optional[str] = None
    ) -> AskResult:
        return self._run(self._inner.ask(question, limit, namespace))

    def restore(self, namespace: str, limit: int = 10) -> RestoreResult:
        return self._run(self._inner.restore(namespace, limit))

    def list_namespaces(
        self,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> NamespacesResult:
        return self._run(self._inner.list_namespaces(cursor, limit))

    def health(self) -> HealthResult:
        return self._run(self._inner.health())

    def compatibility(self) -> Dict[str, Any]:
        return self._run(self._inner.compatibility())

    def forget(self, blob_id: str) -> bool:
        return self._inner.forget(blob_id)

    def clear(self, namespace: Optional[str] = None) -> int:
        return self._inner.clear(namespace)

    def close(self) -> None:
        self._run(self._inner.close())

    def __enter__(self) -> "MemWalMockSync":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

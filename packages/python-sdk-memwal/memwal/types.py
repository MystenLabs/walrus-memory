"""
Walrus Memory — Core Types

Dataclasses for all API request options and response types.
Ed25519 delegate key based SDK that communicates with
the Walrus Memory Rust server (TEE).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# ============================================================
# Config
# ============================================================

#: Default ``server_url`` when neither an explicit URL nor an ``env`` preset
#: is supplied. ``None`` means the caller omitted it. An explicit URL, including
#: this hosted default, wins over ``env``.
DEFAULT_SERVER_URL = "https://relayer.memory.walrus.xyz"

#: Named relayer environments for the public Walrus Memory deployments.
ENV_PRESETS = {
    "prod": "https://relayer.memory.walrus.xyz",
    "dev": "https://relayer.dev.memwal.ai",
    "staging": "https://relayer-staging.memory.walrus.xyz",
    "local": "http://127.0.0.1:8000",
}


@dataclass
class MemWalConfig:
    """Configuration for creating a Walrus Memory client.

    Attributes:
        key: Ed25519 private key (hex string). This is the delegate key from the
            Walrus Memory dashboard.
        account_id: Walrus Memory account object ID on Sui.
        server_url: Server URL. ``None`` means omitted. Any explicit URL,
            including the hosted default, wins over ``env``.
        namespace: Default namespace for memory isolation (default: "default").
        env: Optional relayer preset — one of ``"prod"``, ``"dev"``,
            ``"staging"``, ``"local"``. Used only when ``server_url`` is
            omitted (``None``). Precedence: explicit ``server_url`` > ``env``
            > ``DEFAULT_SERVER_URL``.
    """

    key: str
    account_id: str
    server_url: Optional[str] = None
    namespace: str = "default"
    env: Optional[str] = None

    def __post_init__(self) -> None:
        if self.env is not None:
            preset = ENV_PRESETS.get(self.env)
            if preset is None:
                valid = ", ".join(sorted(ENV_PRESETS))
                raise ValueError(
                    f"Unknown env preset {self.env!r}. Valid presets: {valid}"
                )
            if self.server_url is None:
                self.server_url = preset
        if self.server_url is None:
            self.server_url = DEFAULT_SERVER_URL


# ============================================================
# API Response Types
# ============================================================


@dataclass
class RememberResult:
    """Result from remember()."""

    id: str
    blob_id: str
    owner: str
    namespace: str


@dataclass
class RecallMemory:
    """A single recalled memory."""

    blob_id: str
    text: str
    distance: float
    score: Optional[float] = None
    created_at: Optional[str] = None


@dataclass
class RecallParams:
    """Object-style input for :meth:`MemWal.recall`.

    Preferred over positional args because positional ``recall(query, limit,
    namespace)`` is easy to mis-read as ``recall(query, namespace)`` at call
    sites. Construct this dataclass and pass it as the sole argument:

        client.recall(RecallParams(query="food allergies", limit=5,
                                   namespace="profile"))
    """

    query: str
    limit: int = 10
    namespace: Optional[str] = None
    max_distance: Optional[float] = None
    scoring_weights: Optional["ScoringWeights"] = None
    sort: Optional[str] = None


@dataclass
class RecallResult:
    """Result from recall()."""

    results: List[RecallMemory]
    total: int
    # Matches omitted because download or decrypt failed. 0 also means the
    # relayer omitted the field (older servers).
    dropped_count: int = 0


@dataclass
class ScoringWeights:
    """Optional composite-scoring weights for recall ranking.

    Attributes:
        semantic: Weight applied to semantic similarity (default: 1).
        recency: Weight applied to recency decay (default: 0).
        recency_half_life_days: Half-life for the recency term, in days (default: 30).
        importance: Weight applied to memory importance (default: 0).
    """

    semantic: Optional[float] = None
    recency: Optional[float] = None
    recency_half_life_days: Optional[float] = None
    importance: Optional[float] = None

    def to_wire(self) -> Dict[str, float]:
        """Return the snake_case payload expected by the relayer."""

        payload: Dict[str, float] = {}
        if self.semantic is not None:
            payload["semantic"] = self.semantic
        if self.recency is not None:
            payload["recency"] = self.recency
        if self.recency_half_life_days is not None:
            payload["recency_half_life_days"] = self.recency_half_life_days
        if self.importance is not None:
            payload["importance"] = self.importance
        return payload


@dataclass
class AnalyzedFact:
    """A single extracted fact."""

    text: str
    id: str
    blob_id: str


@dataclass
class AnalyzeResult:
    """Result from analyze().

    Per PR #121: each extracted fact is enqueued as a background remember
    job. ``job_ids`` aligns with ``facts`` positionally; poll those
    job_ids (e.g. via :meth:`MemWal.wait_for_remember_jobs`) to know when
    the corresponding memory is fully persisted on Walrus.
    """

    facts: List[AnalyzedFact]
    fact_count: int
    job_ids: List[str]
    status: str
    owner: str

    @property
    def total(self) -> int:
        """Backward-compat alias for ``fact_count`` (v0.1 callers)."""
        return self.fact_count


@dataclass
class HealthResult:
    """Server health response."""

    status: str
    version: str
    relayer_version: Optional[str] = None
    api_version: Optional[str] = None
    min_supported_sdk: Optional[Dict[str, str]] = None
    feature_flags: Optional[Dict[str, bool]] = None
    deprecations: Optional[List[Dict[str, Any]]] = None
    build: Optional[Dict[str, Any]] = None
    mode: Optional[str] = None
    write_ready: Optional[bool] = None


@dataclass
class RestoreResult:
    """Result from restore()."""

    restored: int
    skipped: int
    total: int
    namespace: str
    owner: str
    #: True when this restore is known-incomplete: more on-chain blobs were
    #: missing locally than ``limit`` allowed this call to restore, or the
    #: sidecar's owner-wide candidate fetch hit its cap *and* raising
    #: ``limit`` can still expand that fetch (``limit < 20``). Once the cap
    #: is saturated, truncation follows this call's missing-blob page, not
    #: on-chain ``total``, so a fully restored namespace does not loop
    #: (WALM-431 / GH #762). Also true when an inspected page produced only
    #: transients (download/decrypt/embed) so the caller retries (WALM-480).
    #:
    #: ``truncated=False`` is not proof the sidecar saw every on-chain blob.
    #: Blobs beyond the owner-wide sidecar candidate cap can still be
    #: missing. Follow-up field: WALM-451 (``sourceCapped``).
    #:
    #: Relayers older than WALM-319 don't send this field at all; the SDK
    #: defaults it to ``False`` in that case rather than requiring it.
    truncated: bool = False
    #: Permanent decrypt/UTF-8 failures on this on-chain page: negative-cache
    #: hits plus any new permanent failures this call. Relayers older than
    #: COMG-719 omit this field; the SDK defaults it to ``0``.
    failed: int = 0


@dataclass
class NamespaceSummary:
    """One namespace in a :meth:`MemWal.list_namespaces` page."""

    id: str
    name: str
    memory_count: int
    storage_used: int
    #: ``MAX(updated_at)`` across the namespace's memories (RFC 3339), the
    #: same value the relayer builds the keyset cursor from.
    updated_at: str


@dataclass
class NamespacesResult:
    """Result from list_namespaces()."""

    namespaces: List[NamespaceSummary]
    #: Pass back as ``cursor`` on the next call. Set on every page, including
    #: the last, so a caller that finished a walk can poll from it later.
    next_cursor: Optional[str]
    #: Whether to keep paginating. Do NOT infer this from page length: the
    #: relayer clamps ``limit``, so asking for more than the cap returns
    #: exactly the cap.
    has_more: bool
    snapshot_version: int


@dataclass
class AskMemory:
    """A memory used to answer a question."""

    blob_id: str
    text: str
    distance: float


@dataclass
class AskResult:
    """Result from ask()."""

    answer: str
    memories_used: int
    memories: List[AskMemory]


# ============================================================
# Manual Flow Types
# ============================================================


@dataclass
class RememberManualOptions:
    """Options for remember_manual().

    Attributes:
        encrypted_data: Base64-encoded SEAL-encrypted bytes. The relayer
            uploads them to Walrus.
        vector: Embedding vector (user already generated).
        namespace: Namespace (default: config namespace or "default").
    """

    encrypted_data: str
    vector: List[float]
    namespace: Optional[str] = None


@dataclass
class RememberManualResult:
    """Result from remember_manual()."""

    id: str
    blob_id: str
    owner: str
    namespace: str


@dataclass
class RecallManualOptions:
    """Options for recall_manual().

    Attributes:
        vector: Pre-computed query embedding vector.
        limit: Max number of results (default: 10).
        namespace: Namespace (default: config namespace or "default").
        scoring_weights: Optional composite-scoring weights applied before returning hits.
    """

    vector: List[float]
    limit: int = 10
    namespace: Optional[str] = None
    scoring_weights: Optional[ScoringWeights] = None


@dataclass
class RecallManualHit:
    """A single search hit -- raw blob_id + distance (no decrypted text)."""

    blob_id: str
    distance: float
    created_at: Optional[str] = None
    importance: Optional[float] = None


@dataclass
class RecallManualResult:
    """Result from recall_manual()."""

    results: List[RecallManualHit]
    total: int


# ============================================================
# Async remember (PR #121: ENG-1406 / ENG-1408)
# ============================================================


@dataclass
class RememberAcceptedResult:
    """Result from remember() / remember_async() — server returns 202 immediately.

    The actual upload + on-chain commit happen in a background worker.
    Poll ``GET /api/remember/{job_id}`` (via wait_for_remember_job) to follow
    progress until status reaches "done" or "failed".
    """

    job_id: str
    status: str


@dataclass
class RememberJobStatus:
    """One snapshot of an async remember job, returned by the status endpoint.

    ``status`` transitions: pending → running → uploaded → done, or → failed.
    ``not_found`` is returned when the job_id is unknown or not the caller's.
    """

    job_id: str
    status: str
    owner: Optional[str] = None
    namespace: Optional[str] = None
    blob_id: Optional[str] = None
    error: Optional[str] = None


# ============================================================
# Bulk remember (ENG-1408)
# ============================================================


@dataclass
class RememberBulkItem:
    """One item in a bulk remember request.

    ``namespace`` overrides the client default for this item only.
    """

    text: str
    namespace: Optional[str] = None


@dataclass
class RememberBulkAcceptedResult:
    """Result from remember_bulk() / remember_bulk_async() — 202 with job_ids.

    ``job_ids`` aligns positionally with the input ``items`` list.
    """

    job_ids: List[str]
    total: int
    status: str


@dataclass
class RememberBulkStatusItem:
    """Per-item status returned by the bulk status endpoint."""

    job_id: str
    status: str
    blob_id: Optional[str] = None
    error: Optional[str] = None


@dataclass
class RememberBulkStatusResult:
    """Result from get_remember_bulk_status()."""

    results: List[RememberBulkStatusItem]


@dataclass
class RememberBulkOptions:
    """Polling options for remember_bulk_and_wait() / wait_for_remember_jobs().

    ``poll_interval_ms`` is the base poll cadence (default 1500ms).
    ``timeout_ms`` is the total wait budget before raising TimeoutError
    (default 120_000ms).
    """

    poll_interval_ms: int = 1500
    timeout_ms: int = 120_000


@dataclass
class RememberBulkItemResult:
    """One settled item in a bulk-and-wait result."""

    id: str
    blob_id: str
    status: str  # "done" | "failed" | "timeout"
    error: Optional[str] = None


@dataclass
class RememberBulkResult:
    """Aggregate result from remember_bulk_and_wait() / wait_for_remember_jobs().

    ``succeeded + failed + timed_out == total``. ``results`` preserves input order.
    """

    results: List[RememberBulkItemResult]
    total: int
    succeeded: int
    failed: int
    timed_out: int


# ============================================================
# Embed + analyze
# ============================================================


@dataclass
class EmbedResult:
    """Result from embed() — raw embedding vector for a piece of text."""

    vector: List[float]


@dataclass
class AnalyzeWaitResult:
    """Result from analyze_and_wait().

    Combines the analyze fact-extraction output with the bulk-style settled
    results for each enqueued background remember job. Mirrors the TS SDK's
    ``AnalyzeWaitResult extends RememberBulkResult``.
    """

    results: List[RememberBulkItemResult]
    total: int
    succeeded: int
    failed: int
    timed_out: int
    facts: List[AnalyzedFact]
    owner: str

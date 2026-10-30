"""
Walrus Memory — SDK Client

Ed25519 delegate key based client that communicates with the Walrus Memory
Rust server (TEE). All data processing (encryption, embedding, Walrus)
happens server-side -- the SDK just signs requests and sends text.

The SDK only needs a single Ed25519 private key (the "delegate key").
The server derives the owner address from the public key via onchain
lookup in MemWalAccount.delegate_keys.

Example::

    from memwal import MemWal

    memwal = MemWal.create(
        key="abcdef...",
        account_id="0x...",
    )

    # Async usage
    result = await memwal.remember("I'm allergic to peanuts")
    matches = await memwal.recall(RecallParams(query="food allergies"))
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import math
import random
import re
import time
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, TypeVar, Union
from urllib.parse import ParseResult, urlencode, urlparse

import httpx
import nacl.signing

from .compatibility import compatibility_error
from .types import (
    AnalyzedFact,
    AnalyzeResult,
    AnalyzeWaitResult,
    AskMemory,
    AskResult,
    EmbedResult,
    ForgetResult,
    HealthResult,
    MemWalConfig,
    NamespacesResult,
    NamespaceSummary,
    RecallManualHit,
    RecallManualOptions,
    RecallManualResult,
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
    RememberManualOptions,
    RememberManualResult,
    RememberResult,
    RestoreResult,
)
from .utils import (
    build_seal_session_personal_message,
    build_signature_message,
    build_signing_key,
    bytes_to_hex,
    delegate_key_to_sui_address,
    encode_sui_private_key,
    normalize_private_key,
    sha256_hex,
    sign_message,
    sign_sui_personal_message,
    validate_max_distance,
)

T = TypeVar("T")
SEAL_SESSION_TTL_MIN = 5

# Networks with a public Sui GraphQL read endpoint (https://graphql.<network>.sui.io).
PUBLIC_SUI_GRAPHQL_NETWORKS = ("mainnet", "testnet", "devnet")

# Fail the package-version preflight fast instead of hanging client init when a
# Sui read endpoint is unresponsive.
PACKAGE_VERSION_CHECK_TIMEOUT_S = 10.0
SEAL_SESSION_SAFETY_MARGIN_MS = 30_000

# The relayer's `MAX_BULK_ITEMS` (services/server/src/types.rs). A bulk read
# above it is rejected with a non-transient 400, so callers must chunk.
MAX_BULK_STATUS_IDS = 20
AUTH_REJECTED_MESSAGE = (
    "401 from relayer: typically wrong private key, key not registered on this "
    "account, account ID mismatch (a wallet address is not a MemWal account ID), "
    "or staging/mainnet mismatch. Check .env.local "
    "and dashboard credentials. Full troubleshooting: "
    "https://docs.wal.app/walrus-memory/troubleshooting/overview#401-auth_rejected-errors"
)
AUTH_UPSTREAM_UNAVAILABLE = "AUTH_UPSTREAM_UNAVAILABLE"
UPSTREAM_UNAVAILABLE_MESSAGE = (
    "Walrus Memory temporarily cannot verify credentials (upstream unavailable). "
    "Retry; this is not a sign-in failure."
)


logger = logging.getLogger("memwal")


def _server_url_for_log(parsed: ParseResult) -> str:
    """Scheme/host/port only — never userinfo, path, query, or fragment."""

    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parsed.port is not None:
        return f"{parsed.scheme}://{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}"


def _reject_blank_text(text: object, message: str = "Text cannot be empty") -> None:
    """Reject empty and whitespace-only text before a request is sent.

    The relayer does the same (#1129). Failing here means an older relayer
    cannot accept the job and leave the caller polling until timeout.
    Non-blank text is not trimmed.
    """

    if not isinstance(text, str) or not text.strip():
        raise ValueError(message)


def _require(data: object, field: str, endpoint: str) -> Any:
    """``data[field]`` from a parsed 2xx body, or a ``MemWalError`` naming both.

    A bare ``KeyError`` is not a ``MemWalError``, carries only the field name,
    and is raised far from the response that caused it (#1250). Optional
    fields keep using ``.get()`` with a documented default.
    """

    if not isinstance(data, dict):
        raise MemWalError(
            f"{endpoint} response was {type(data).__name__}, expected an object "
            f"with {field!r}"
        )
    if field not in data:
        raise MemWalError(f"{endpoint} response missing {field!r}")
    return data[field]


def _require_positive_int(value: object, name: str) -> None:
    """Reject anything but a positive ``int`` before it is signed (#1249).

    ``json.dumps`` writes ``float("nan")`` as a bare ``NaN`` token, which is
    not valid JSON, and negative or fractional values were forwarded as-is.
    ``bool`` is an ``int`` subclass and is rejected explicitly.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer, got {value!r}")


IDEMPOTENCY_BUCKET_MS = 30 * 60 * 1000


def _derived_idempotency_key(request_identity: str) -> str:
    """Window over which the same (namespace, text) resolves to one key.

    `_pending_remember_keys` only dedupes retries that reuse one client instance,
    and callers such as sidecars or serverless functions build a fresh client
    per session — so a random key lets a replay mint a second paid blob. The
    bucket bounds the collapse: `remember_jobs` rows are never pruned, so an
    unbucketed key would dedupe against a job from any point in history.

    Matches TypeScript SDK derivedIdempotencyKey contract.
    """
    bucket = int(time.time() * 1000) // IDEMPOTENCY_BUCKET_MS
    payload = f"{bucket}\0{request_identity}".encode("utf-8")
    return f"r1-{hashlib.sha256(payload).hexdigest()}"


def _require_remember_job_id(job_id: object) -> str:
    """String form of a remember job id.

    ``uuid.UUID`` used to interpolate into the path and still does. Any other
    non-string is a type mistake: ``not_found`` would hide a job that exists.
    """

    if isinstance(job_id, uuid.UUID):
        return str(job_id)
    if not isinstance(job_id, str):
        raise TypeError(
            f"remember job id must be a string, got {type(job_id).__name__}"
        )
    return job_id


def _remember_status_path(job_id: str) -> Optional[str]:
    """``/api/remember/{job_id}`` when the id is one safe segment, else None.

    httpx rewrites the path after it is signed. ``.`` requests
    ``/api/remember``, ``..`` requests ``/api``, and a NUL raises
    ``InvalidURL``. An allowlist keeps those from leaving the client. A
    normal UUID is unchanged. (#1100, #1216)
    """

    if re.fullmatch(r"[A-Za-z0-9_-]+", job_id) is None:
        return None
    return f"/api/remember/{job_id}"


def normalize_server_url(url: str) -> str:
    """Strip a trailing slash and warn on plaintext HTTP to a remote host.

    Ports the TypeScript ``normalizeServerUrl`` helper: localhost,
    ``127.0.0.1``, ``::1``, and ``*.localhost`` are exempt. Invalid URLs
    are returned trimmed so the HTTP client can surface the error later.

    The warning logs only scheme/host/port so URL userinfo (HTTPX
    credentials) and other sensitive components are not written to logs.
    The returned URL is otherwise unchanged and still used for transport.
    """

    trimmed = url.rstrip("/")
    try:
        parsed = urlparse(trimmed)
        host = (parsed.hostname or "").lower()
        is_local = (
            host == "localhost"
            or host == "127.0.0.1"
            or host == "::1"
            or host.endswith(".localhost")
        )
        if parsed.scheme == "http" and host and not is_local:
            logger.warning(
                '[memwal] serverUrl "%s" uses plaintext HTTP on a non-localhost host. '
                "Signed requests and any bearer material will be visible to the network. "
                "Use https:// in production.",
                _server_url_for_log(parsed),
            )
    except ValueError:
        # invalid URL — let the HTTP call surface the error at request time
        pass
    return trimmed


# ============================================================
# Polling helpers (PR #121 parity with TS SDK)
# ============================================================


def _now_ms() -> int:
    return int(time.monotonic() * 1000)


async def _sleep_ms(ms: int) -> None:
    await asyncio.sleep(max(ms, 0) / 1000.0)


def _polling_delay_ms(base_ms: int, attempt: int) -> int:
    """Same formula as TS ``pollingDelayMs``."""

    if attempt == 0:
        return 0
    base = max(100, base_ms)
    ceiling = max(5000, base)
    capped = min(ceiling, base * (1.5 ** min(attempt - 1, 6)))
    jitter = 0.75 + random.random() * 0.5
    return int(capped * jitter)


def _positive_retry_ms(raw: object) -> Optional[int]:
    try:
        seconds = float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if seconds <= 0 or math.isnan(seconds) or math.isinf(seconds):
        return None
    try:
        ms = seconds * 1000.0
        if math.isinf(ms) or math.isnan(ms):
            return None
        return int(ms)
    except (OverflowError, ValueError):
        return None


def _http_date_retry_ms(raw: object) -> Optional[int]:
    if not isinstance(raw, str):
        return None
    try:
        dt = parsedate_to_datetime(raw)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        target_ts = dt.timestamp()
        # HTTP-date is absolute wall-clock time, so we deliberately compare against
        # time.time() rather than monotonic _now_ms().
        now_ts = time.time()
        diff = target_ts - now_ts
        if diff <= 0 or math.isnan(diff) or math.isinf(diff):
            return None
        ms = diff * 1000.0
        if math.isinf(ms) or math.isnan(ms):
            return None
        return int(ms)
    except Exception:
        return None


def _retry_after_ms(err: "_HttpStatusError") -> int:
    """Retry-After seconds or HTTP-date, else JSON ``retry_after_seconds``, in ms."""

    if err.retry_after:
        header_ms = _positive_retry_ms(err.retry_after)
        if header_ms is not None:
            return header_ms
        date_ms = _http_date_retry_ms(err.retry_after)
        if date_ms is not None:
            return date_ms
    if not err.body:
        return 0
    try:
        payload = json.loads(err.body)
    except json.JSONDecodeError:
        return 0
    if not isinstance(payload, dict):
        return 0
    return _positive_retry_ms(payload.get("retry_after_seconds")) or 0


def _clamped_retry_after_ms(err: "_HttpStatusError", deadline_ms: int) -> int:
    """Clamp Retry-After to the time left. 0 means use the normal curve."""

    delay = _retry_after_ms(err)
    if delay <= 0:
        return 0
    remaining = deadline_ms - _now_ms()
    if remaining <= 0:
        return 0
    return min(delay, remaining)


def _is_transient_polling_status(status: int) -> bool:
    """Classify HTTP status codes for the polling retry loop.

    Mirrors TS ``isTransientPollingStatus``: connection drop (0), rate
    limit (429), or any 5xx → retry. Anything else (including 4xx other
    than 404 which is special-cased upstream) → surface to caller.
    """

    return status == 0 or status == 429 or status >= 500


def _occurred_at_to_wire(
    occurred_at: Optional[Union[str, datetime]],
) -> Optional[str]:
    """Render an ``occurred_at`` argument to the wire format.

    The server's ``AnalyzeRequest.occurred_at`` field expects RFC-3339
    UTC with a trailing ``Z``. Output precision matches the TS SDK's
    ``Date.toISOString()`` (milliseconds), e.g.
    ``"2023-05-25T17:50:00.000Z"`` — so the two SDKs produce
    byte-identical wire payloads for the same instant.

    Aware ``datetime`` objects are converted to UTC. **Naïve datetimes
    are rejected** with ``ValueError``: silently assuming UTC would
    produce timezone-off-by-N anchors for callers outside UTC and
    undermine WALM-55's "honest temporal anchoring" guarantee. Callers
    should pass ``datetime.now(timezone.utc)`` or attach a ``tzinfo``
    explicitly.

    String inputs are validated as RFC-3339 / ISO-8601 (accepting
    trailing ``Z`` as a UTC shorthand, per RFC-3339 §4.2) and
    re-formatted to canonical form. Invalid strings raise
    ``ValueError`` at the SDK boundary rather than being forwarded as
    a 400 from the server.

    Returns ``None`` when no anchor is supplied so the field is
    omitted from the request body.
    """

    if occurred_at is None:
        return None
    if isinstance(occurred_at, datetime):
        if occurred_at.tzinfo is None:
            raise ValueError(
                "occurred_at datetime must be timezone-aware. Pass "
                "datetime.now(timezone.utc), datetime(..., tzinfo=...), "
                "or an RFC-3339 string. Naïve datetimes are rejected "
                "because they would be silently mis-anchored for "
                "callers outside UTC."
            )
        dt = occurred_at.astimezone(timezone.utc)
        # Drop tzinfo before `isoformat` to suppress the "+00:00"
        # suffix; we append "Z" manually to match the TS SDK + server
        # canonical form. `timespec="milliseconds"` matches JS
        # `Date.toISOString()` precision so the two SDKs are
        # byte-identical for the same instant.
        return dt.replace(tzinfo=None).isoformat(timespec="milliseconds") + "Z"
    if isinstance(occurred_at, str):
        # Validate at the SDK boundary so a bad timestamp doesn't
        # bring down the whole analyze() call with an opaque 400 from
        # the server's serde layer. RFC-3339 §4.2 allows "Z" as a UTC
        # shorthand; `fromisoformat` only accepts it on Python 3.11+,
        # so we normalise to "+00:00" before parsing for 3.9/3.10
        # compatibility.
        normalised = (
            occurred_at.replace("Z", "+00:00", 1)
            if occurred_at.endswith("Z")
            else occurred_at
        )
        try:
            parsed = datetime.fromisoformat(normalised)
        except ValueError as exc:
            raise ValueError(
                f"occurred_at must be RFC-3339 / ISO-8601, got: {occurred_at!r}"
            ) from exc
        # Round-trip through the datetime branch so the wire format is
        # canonical (UTC, milliseconds, trailing "Z"). Naïve inputs
        # here are rare but possible; reuse the aware-required guard
        # by attaching tzinfo if the string carried one.
        if parsed.tzinfo is None:
            raise ValueError(
                f"occurred_at string must carry a UTC offset or 'Z' suffix, "
                f"got: {occurred_at!r}"
            )
        return _occurred_at_to_wire(parsed)
    raise TypeError(
        f"occurred_at must be datetime, str, or None; got {type(occurred_at).__name__}"
    )



def _check_limit(limit: Any) -> None:
    """Reject a limit that is not a positive integer before it is signed (#1218)."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError(f"limit must be a positive integer, got {limit!r}")


def _check_vector(vector: Any) -> None:
    """Reject a vector that is not a non-empty list of finite numbers (#1218).

    json.dumps would otherwise emit bare NaN/Infinity tokens, which are not
    JSON, and the relayer would answer with an opaque parse error.
    """
    if (
        not isinstance(vector, (list, tuple))
        or len(vector) == 0
        or not all(
            isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
            for v in vector
        )
    ):
        raise ValueError("vector must be a non-empty list of finite numbers")

def _destroyed_client_error() -> "MemWalError":
    return MemWalError(
        "Walrus Memory client was destroyed; its keys are zeroed. Create a new one."
    )


class MemWal:
    """Async-native Walrus Memory client.

    All API methods are ``async``. For synchronous usage, wrap calls with
    ``asyncio.run()`` or use the :class:`MemWalSync` convenience wrapper.
    """

    def __init__(self, config: MemWalConfig) -> None:
        self._destroyed: bool = False
        self._private_key_hex: str = normalize_private_key(config.key)
        signing_key = build_signing_key(self._private_key_hex)
        self._signing_key: Optional[nacl.signing.SigningKey] = signing_key
        # Mutable copy of the 32-byte seed so destroy() can zero-fill it in
        # place without mutating any caller-supplied bytearray (#975).
        self._private_key_bytes: bytearray = bytearray(bytes(signing_key))
        self._account_id = config.account_id
        self._server_url = normalize_server_url(config.server_url)
        self._namespace = config.namespace
        self._client: Optional[httpx.AsyncClient] = None
        self._server_config: Optional[Dict[str, str]] = None
        self._session_cache: Optional[Tuple[str, int]] = None
        self._session_build_task: Optional[asyncio.Task[str]] = None
        self._relayer_version_metadata: Optional[Dict[str, Any]] = None
        self._compatibility_lock: Optional[asyncio.Lock] = None
        self._owner_address: Optional[str] = None
        self._owner_task: Optional[asyncio.Task[str]] = None
        # Preserve a generated key across an ambiguous transport failure. A
        # subsequent identical call then collapses onto the accepted paid job.
        self._pending_remember_keys: Dict[str, str] = {}
        # Bounded counter of derived keys whose jobs reached a terminal failure
        # ("failed" or "not_found"), keyed by the 67-char base derived key so
        # full-text inputs are never retained after completion.
        self._failed_remember_keys: Dict[str, int] = {}

    def _resolve_namespace(self, namespace: Optional[str]) -> str:
        """``None`` uses the client default; do not treat ``""`` as missing."""
        if namespace is None:
            return self._namespace
        if not namespace:
            raise ValueError("namespace cannot be empty")
        return namespace

    @classmethod
    def create(
        cls,
        key: Union[str, bytes, bytearray],
        account_id: str,
        server_url: Optional[str] = None,
        namespace: str = "default",
        env: Optional[str] = None,
    ) -> "MemWal":
        """Create a new Walrus Memory client instance.

        Args:
            key: Ed25519 private key (hex string, ``suiprivkey1...``, or 32-byte
                ``bytes`` / ``bytearray``). When passed as ``bytearray``, the
                bytes are copied into an internal buffer so :meth:`destroy`
                zeroes only the client's copy and leaves the caller's buffer intact.
            account_id: Walrus Memory account object ID on Sui.
            server_url: Server URL (default: ``https://relayer.memory.walrus.xyz``).
            namespace: Default namespace for memory isolation (default: ``"default"``).
            env: Optional relayer preset — ``"prod"``, ``"dev"``, ``"staging"``,
                or ``"local"``. Resolves ``server_url`` to the matching hosted
                relayer unless an explicit ``server_url`` is given.
                Precedence: explicit ``server_url`` > ``env`` > default.

        Returns:
            A configured :class:`MemWal` instance.
        """
        config = MemWalConfig(
            key=key,
            account_id=account_id,
            server_url=server_url,
            namespace=namespace,
            env=env,
        )
        return cls(config)

    @property
    def _http(self) -> httpx.AsyncClient:
        """Lazily create the async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=60.0)
        return self._client

    def destroy(self) -> None:
        """Wipe internal key buffers, drop signing credentials, and invalidate the client.

        Provides parity with the TypeScript SDK's ``destroy()`` method (#975):

        - Zeroes ``_private_key_bytes`` (the client's internal ``bytearray`` seed
          copy) in place.
        - Clears ``_private_key_hex``, drops the ``_signing_key`` reference, and
          clears cached SEAL session tokens, server config, owner address, and
          pending idempotency keys.
        - Marks the client as destroyed so any subsequent or in-flight operation
          raises :class:`MemWalError`.

        Note on CPython memory semantics:
            Python ``str`` and ``bytes`` objects (and PyNaCl's internal C-level
            ``SigningKey`` buffers) are immutable in CPython and cannot be zeroed
            in place from pure Python. ``destroy()`` zeroes the client's mutable
            ``bytearray`` seed copy in place and drops all references to immutable
            key objects so they become eligible for garbage collection once the
            caller also releases its references. Callers that want to minimize
            long-lived plaintext ``str`` keys in memory should pass ``key`` as a
            32-byte ``bytearray`` and zero their own buffer after ``create()``.
        """
        self._destroyed = True
        if self._private_key_bytes:
            self._private_key_bytes[:] = b"\x00" * len(self._private_key_bytes)
        self._private_key_hex = ""
        self._signing_key = None
        self._session_cache = None
        self._server_config = None
        self._relayer_version_metadata = None
        self._owner_address = None
        self._pending_remember_keys.clear()
        self._failed_remember_keys.clear()
        for attr in ("_session_build_task", "_owner_task"):
            task = getattr(self, attr, None)
            setattr(self, attr, None)
            if task is not None and not task.done():
                task.cancel()

    async def close(self, clear_keys: bool = False) -> None:
        """Close the underlying HTTP client and cancel any in-flight initialization tasks.

        Args:
            clear_keys: If ``True``, also call :meth:`destroy` to wipe internal
                key buffers, drop signing credentials, and invalidate the client.
        """
        for attr in ("_session_build_task", "_owner_task"):
            task = getattr(self, attr, None)
            setattr(self, attr, None)
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    # Ignore cancellation or transport errors from in-flight
                    # session tasks during teardown.
                    pass
        if clear_keys:
            self.destroy()
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "MemWal":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # ============================================================
    # Core API
    # ============================================================

    async def remember(
        self,
        text: str,
        namespace: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> RememberAcceptedResult:
        """Submit a remember request and return as soon as the server accepts it.

        Per PR #121 (ENG-1406): the server returns ``HTTP 202 + job_id``
        immediately (~500ms). The actual Walrus upload + on-chain commit run
        in a background worker. Use :meth:`wait_for_remember_job` to follow
        the job to completion, or :meth:`remember_and_wait` for a single
        call that does both.

        Args:
            text: The text to remember.
            namespace: Override the default namespace.

        Returns:
            :class:`RememberAcceptedResult` with ``job_id`` and initial
            status (``"pending"``).
        """
        _reject_blank_text(text)
        resolved_namespace = self._resolve_namespace(namespace)
        request_identity = f"{resolved_namespace}\0{text}"
        generated_key = idempotency_key is None
        resolved_key = (
            idempotency_key
            or self._pending_remember_keys.get(request_identity)
            or _derived_idempotency_key(request_identity)
        )
        if generated_key:
            self._pending_remember_keys[request_identity] = resolved_key

        data = await self._signed_request(
            "POST",
            "/api/remember",
            {
                "text": text,
                "namespace": resolved_namespace,
                "idempotency_key": resolved_key,
            },
            accepted_statuses=(200, 202),
        )
        if generated_key:
            self._pending_remember_keys.pop(request_identity, None)
        return RememberAcceptedResult(
            job_id=_require(data, "job_id", "POST /api/remember"),
            status=data.get("status", "pending"),
        )

    # Alias for parity with TS SDK ``rememberAsync``.
    async def remember_async(
        self,
        text: str,
        namespace: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> RememberAcceptedResult:
        return await self.remember(text, namespace, idempotency_key)

    def _poll_deadline_s(self, deadline_ms: int) -> float:
        remaining_s = (deadline_ms - _now_ms()) / 1000.0
        return max(0.001, min(60.0, remaining_s))

    async def get_remember_status(self, job_id: str) -> RememberJobStatus:
        """One-shot lookup of a remember job. Mirrors TS ``getRememberStatus``.

        ``GET /api/remember/{job_id}``, accepting 200 and 404. A 404, or a
        body with no ``status``, is ``not_found`` — not an exception. A job
        id outside ``[A-Za-z0-9_-]+`` is ``not_found`` without a request.
        """

        job_id = _require_remember_job_id(job_id)
        path = _remember_status_path(job_id)
        if path is None:
            return RememberJobStatus(
                job_id=job_id,
                status="not_found",
                error=f"Job {job_id} not found",
            )
        try:
            data = await self._signed_request(
                "GET",
                path,
                {},
                accepted_statuses=(200, 404),
                # Status is metadata. No SEAL decrypt, so no session. Matches TS.
                include_seal_session=False,
            )
        except MemWalJsonBodyError as err:
            if err.status != 404:
                raise
            data = None
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = None
        if not isinstance(data, dict):
            return RememberJobStatus(
                job_id=job_id,
                status="not_found",
                error=f"remember job not found: {job_id}",
            )
        status = data.get("status")
        if not status:
            return RememberJobStatus(
                job_id=data.get("job_id") or job_id,
                status="not_found",
                error=data.get("error") or f"remember job not found: {job_id}",
            )
        return RememberJobStatus(
            job_id=data.get("job_id", job_id),
            status=status,
            owner=data.get("owner"),
            namespace=data.get("namespace"),
            blob_id=data.get("blob_id"),
            error=data.get("error"),
        )

    async def wait_for_remember_job(
        self,
        job_id: str,
        poll_interval_ms: int = 1500,
        timeout_ms: int = 60_000,
    ) -> RememberResult:
        """Poll an accepted remember job until it reaches a terminal state.

        Mirrors TS ``waitForRememberJob``:

        - Accepts 200 + 404 from the status endpoint and dispatches on
          ``status`` field (404 / ``status == "not_found"`` raises).
        - Transient HTTP errors (429, 5xx, network drop) are retried until
          the timeout, not surfaced as polling failures. A 429 waits out
          Retry-After within the timeout; the timeout error says so.
        - First poll is immediate; later polls grow 1.5x toward 5s.
        """

        job_id = _require_remember_job_id(job_id)
        path = _remember_status_path(job_id)
        if path is None:
            raise MemWalRememberJobNotFound(job_id)

        deadline_ms = _now_ms() + timeout_ms
        attempt = 0
        saw_rate_limit = False
        retry_after_ms = 0
        last_status: Optional[str] = None
        server_error: Optional[str] = None
        last_refusal: Optional[int] = None

        while _now_ms() < deadline_ms:
            if retry_after_ms > 0:
                await _sleep_ms(retry_after_ms)
            else:
                await _sleep_ms(_polling_delay_ms(poll_interval_ms, attempt))
                attempt += 1
            retry_after_ms = 0

            try:
                poll_timeout = self._poll_deadline_s(deadline_ms)
                try:
                    data = await self._signed_request(
                        "GET",
                        path,
                        {},
                        accepted_statuses=(200, 404),
                        timeout=poll_timeout,
                    )
                except TypeError as err:
                    if "unexpected keyword argument" in str(err) and "timeout" in str(err):
                        data = await self._signed_request(
                            "GET",
                            path,
                            {},
                            accepted_statuses=(200, 404),
                        )
                    else:
                        raise
            except MemWalJsonBodyError as err:
                if err.status == 404:
                    raise MemWalRememberJobNotFound(job_id) from None
                raise
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise MemWalRememberJobNotFound(job_id) from None
            except _HttpStatusError as err:
                if _is_transient_polling_status(err.status):
                    last_refusal = err.status
                    if err.status == 429:
                        saw_rate_limit = True
                        retry_after_ms = _clamped_retry_after_ms(err, deadline_ms)
                    continue
                raise
            except httpx.TransportError:
                # Network drops retry as status 0; continuing next loop iteration
                # increments `attempt` so exponential backoff delay continues to grow.
                last_refusal = 0
                continue

            if not isinstance(data, dict):
                raise MemWalRememberJobNotFound(job_id)
            status_str = data.get("status")
            if status_str is None or status_str == "not_found":
                raise MemWalRememberJobNotFound(job_id)
            last_status = status_str
            server_error = data.get("error")

            if status_str == "done":
                return RememberResult(
                    id=data.get("job_id", job_id),
                    blob_id=data.get("blob_id") or "",
                    owner=data.get("owner") or "",
                    namespace=data.get("namespace") or self._namespace,
                )

            if status_str == "failed":
                raise MemWalRememberJobFailed(
                    job_id=job_id, error=data.get("error") or "unknown error"
                )

            # pending / running / uploaded — keep polling.

        raise MemWalRememberJobTimeout(
            job_id=job_id,
            timeout_ms=timeout_ms,
            last_status=last_status,
            server_error=server_error,
            last_refusal=last_refusal,
            saw_rate_limit=saw_rate_limit,
        )

    async def remember_and_wait(
        self,
        text: str,
        namespace: Optional[str] = None,
        poll_interval_ms: int = 1500,
        timeout_ms: int = 60_000,
        idempotency_key: Optional[str] = None,
    ) -> RememberResult:
        """Submit a remember and wait for the background worker to finish.

        Convenience wrapper around :meth:`remember` (returns ``job_id`` in
        ~500ms) + :meth:`wait_for_remember_job` (polls until ``done`` or
        ``failed``). Mirrors TS ``rememberAndWait``.
        """

        _reject_blank_text(text)
        resolved_namespace = self._resolve_namespace(namespace)
        request_identity = f"{resolved_namespace}\0{text}"
        generated_key = idempotency_key is None
        base_key = _derived_idempotency_key(request_identity) if generated_key else ""
        fail_count = self._failed_remember_keys.get(base_key, 0) if generated_key else 0
        if fail_count > 0:
            salted_payload = f"{base_key}\0{fail_count}".encode("utf-8")
            default_key = f"r1-{hashlib.sha256(salted_payload).hexdigest()}"
        else:
            default_key = base_key
        resolved_key = (
            idempotency_key
            or self._pending_remember_keys.get(request_identity)
            or default_key
        )
        if generated_key:
            self._pending_remember_keys[request_identity] = resolved_key

        accepted = await self.remember(text, resolved_namespace, resolved_key)
        try:
            result = await self.wait_for_remember_job(
                accepted.job_id,
                poll_interval_ms=poll_interval_ms,
                timeout_ms=timeout_ms,
            )
        except (MemWalRememberJobFailed, MemWalRememberJobNotFound):
            # Terminal failure: the job will never succeed, so discard the
            # pending key and advance the failure generation so a subsequent
            # retry for the same (namespace, text) sends a fresh key.
            if generated_key:
                self._pending_remember_keys.pop(request_identity, None)
                if (
                    len(self._failed_remember_keys) >= 256
                    and base_key not in self._failed_remember_keys
                ):
                    self._failed_remember_keys.pop(
                        next(iter(self._failed_remember_keys)), None
                    )
                self._failed_remember_keys[base_key] = fail_count + 1
            raise
        # MemWalRememberJobTimeout is intentionally NOT caught here —
        # the job may still complete, so the key stays for a retry call.
        if generated_key:
            self._pending_remember_keys.pop(request_identity, None)
        return result

    # ============================================================
    # Bulk remember (ENG-1408)
    # ============================================================

    async def remember_bulk_async(
        self, items: Sequence[RememberBulkItem]
    ) -> RememberBulkAcceptedResult:
        """Submit a bulk remember and return as soon as the server accepts the batch.

        Server returns ``HTTP 202`` with ``job_ids`` aligned positionally with
        ``items``. Each item then progresses through the same async pipeline
        as :meth:`remember` independently.

        Up to ``MAX_BULK_ITEMS`` (= 20) items per call; each item's text
        capped at ``MAX_REMEMBER_TEXT_BYTES`` (= 64 KiB).
        """

        if not items:
            raise ValueError("remember_bulk_async: items must be a non-empty array")
        for index, item in enumerate(items):
            _reject_blank_text(item.text, f"items[{index}].text cannot be empty")

        payload_items: List[Dict[str, Any]] = [
            {
                "text": item.text,
                "namespace": self._resolve_namespace(item.namespace),
            }
            for item in items
        ]
        data = await self._signed_request(
            "POST",
            "/api/remember/bulk",
            {"items": payload_items},
            accepted_statuses=(200, 202),
        )
        job_ids = data.get("job_ids")
        returned = len(job_ids) if job_ids else 0
        if not job_ids or returned != len(payload_items):
            raise ValueError(
                f"remember_bulk_async: server returned {returned} job_ids for "
                f"{len(payload_items)} items"
            )
        return RememberBulkAcceptedResult(
            job_ids=list(job_ids),
            total=int(data.get("total", len(payload_items))),
            status=data.get("status", "pending"),
        )

    # Alias for parity with TS SDK ``rememberBulk``.
    async def remember_bulk(
        self, items: Sequence[RememberBulkItem]
    ) -> RememberBulkAcceptedResult:
        return await self.remember_bulk_async(items)

    async def get_remember_bulk_status(
        self,
        job_ids: Sequence[str],
        timeout: Optional[float] = None,
    ) -> RememberBulkStatusResult:
        """Poll the bulk-status endpoint for a batch of job_ids.

        Returns one :class:`RememberBulkStatusItem` per requested job (order
        not guaranteed; callers should index by ``job_id``).
        """

        data = await self._signed_request(
            "POST",
            "/api/remember/bulk/status",
            {"job_ids": list(job_ids)},
            timeout=timeout,
        )
        return RememberBulkStatusResult(
            results=[
                RememberBulkStatusItem(
                    job_id=item.get("job_id", ""),
                    status=item.get("status", "pending"),
                    blob_id=item.get("blob_id"),
                    error=item.get("error"),
                )
                for item in data.get("results", [])
            ]
        )

    async def wait_for_remember_jobs(
        self,
        job_ids: Sequence[str],
        opts: Optional[RememberBulkOptions] = None,
    ) -> RememberBulkResult:
        """Poll the bulk-status endpoint until every job is terminal.

        Mirrors TS ``waitForRememberJobs``:

        - Each item settles to ``"done"``, ``"failed"``, or ``"timeout"``.
        - Same transient-retry + jitter strategy as the single-job poll.
        - Result list preserves the order of the input ``job_ids``.

        Default ``timeout_ms`` is 120s — bulk pipelines run longer than
        single remember.
        """

        opts = opts or RememberBulkOptions()
        deadline_ms = _now_ms() + opts.timeout_ms

        # Track per-job final state.
        results: Dict[str, RememberBulkItemResult] = {
            job_id: RememberBulkItemResult(
                id=job_id,
                blob_id="",
                status="timeout",
                error=None,
            )
            for job_id in job_ids
        }
        pending: List[str] = list(job_ids)
        attempt = 0
        saw_rate_limit = False
        retry_after_ms = 0
        last_seen: Dict[str, RememberBulkStatusItem] = {}
        last_refusal: Optional[int] = None
        # Whether any status read got through. An item missing from an answer
        # was not refused, so it must not be reported as if it had been.
        answered = False

        def settle(item: RememberBulkStatusItem) -> bool:
            last_seen[item.job_id] = item
            if item.status == "done":
                results[item.job_id] = RememberBulkItemResult(
                    id=item.job_id,
                    blob_id=item.blob_id or "",
                    status="done",
                    error=None,
                )
                return True
            if item.status in ("failed", "not_found"):
                results[item.job_id] = RememberBulkItemResult(
                    id=item.job_id,
                    blob_id=item.blob_id or "",
                    status="failed",
                    error=item.error,
                )
                return True
            return False

        while pending and _now_ms() < deadline_ms:
            if retry_after_ms > 0:
                await _sleep_ms(retry_after_ms)
            else:
                await _sleep_ms(_polling_delay_ms(opts.poll_interval_ms, attempt))
                attempt += 1
            retry_after_ms = 0

            # The relayer rejects a bulk-status read of more than
            # MAX_BULK_STATUS_IDS ids with a 400, which is NOT transient: an
            # unchunked poll of 21+ jobs raises out of the whole wait and
            # every retry hits the same 400. Chunk here so `memwal_wait_for_saves`
            # and `remember_bulk_and_wait` are both fixed.
            terminal_ids: Set[str] = set()
            refused_ids: List[str] = []
            for start in range(0, len(pending), MAX_BULK_STATUS_IDS):
                chunk = pending[start : start + MAX_BULK_STATUS_IDS]
                try:
                    poll_timeout = self._poll_deadline_s(deadline_ms)
                    try:
                        batch = await self.get_remember_bulk_status(chunk, timeout=poll_timeout)
                    except TypeError as err:
                        if "unexpected keyword argument" in str(err) and "timeout" in str(err):
                            batch = await self.get_remember_bulk_status(chunk)
                        else:
                            raise
                except _HttpStatusError as err:
                    if _is_transient_polling_status(err.status):
                        last_refusal = err.status
                        if err.status == 429:
                            saw_rate_limit = True
                            retry_after_ms = _clamped_retry_after_ms(err, deadline_ms)
                        # Refused, not answered: keep this chunk pending.
                        refused_ids.extend(chunk)
                        continue
                    raise
                except httpx.TransportError:
                    # Network drops retry as status 0; continuing next loop iteration
                    # increments `attempt` so exponential backoff delay continues to grow.
                    last_refusal = 0
                    refused_ids.extend(chunk)
                    continue
                answered = True
                chunk_pending = set(chunk)
                terminal_ids |= {
                    item.job_id
                    for item in batch.results
                    if item.job_id in chunk_pending and settle(item)
                }

            if not answered and refused_ids:
                # Nothing got through this tick; back off and retry.
                continue
            pending = [jid for jid in pending if jid not in terminal_ids]

        if opts.timeout_ms > 0 and len(pending) == len(job_ids) and not last_seen:
            # Nothing settled and nothing was seen: the polls may all have been
            # refused. Confirm with one direct read before reporting anything.
            settled: Set[str] = set()
            all_ids = list(job_ids)
            for start in range(0, len(all_ids), MAX_BULK_STATUS_IDS):
                chunk = all_ids[start : start + MAX_BULK_STATUS_IDS]
                try:
                    probed = await self.get_remember_bulk_status(chunk)
                except _HttpStatusError as err:
                    if err.status == 429:
                        # Header first, else the body's retry_after_seconds, so a
                        # proxy that strips Retry-After does not lose the hint.
                        wait_ms = _retry_after_ms(err)
                        retry_after = f"{wait_ms / 1000:g}" if wait_ms else None
                        raise MemWalRateLimited(job_ids, retry_after) from err
                    # Any other probe failure is not evidence about the jobs.
                    continue
                except httpx.TransportError:
                    continue
                answered = True
                pending_now = set(pending)
                settled |= {
                    item.job_id
                    for item in probed.results
                    if item.job_id in pending_now and settle(item)
                }
            pending = [jid for jid in pending if jid not in settled]

        for job_id in pending:
            seen = last_seen.get(job_id)
            if seen is not None:
                suffix = f": {_redact_internal_urls(seen.error)}" if seen.error else ""
                error = f"still {seen.status} after {opts.timeout_ms}ms{suffix}"
            elif answered:
                error = "not in the relayer's status answer; this item may not be stored"
            elif last_refusal is not None:
                error = (
                    f"no status read got through (last poll: HTTP {last_refusal}); "
                    "this item may not be stored"
                )
            else:
                error = f"polling timed out after {opts.timeout_ms}ms"
            # Only the "no status read got through" message already names the 429.
            names_rate_limit = seen is None and not answered and last_refusal == 429
            if saw_rate_limit and not names_rate_limit:
                error += "; wait hit a rate limit (429)"
            results[job_id] = RememberBulkItemResult(
                id=job_id, blob_id="", status="timeout", error=error
            )

        ordered = [results[job_id] for job_id in job_ids]
        succeeded = sum(1 for r in ordered if r.status == "done")
        failed = sum(1 for r in ordered if r.status == "failed")
        timed_out = sum(1 for r in ordered if r.status == "timeout")
        return RememberBulkResult(
            results=ordered,
            total=len(ordered),
            succeeded=succeeded,
            failed=failed,
            timed_out=timed_out,
        )

    async def remember_bulk_and_wait(
        self,
        items: Sequence[RememberBulkItem],
        opts: Optional[RememberBulkOptions] = None,
    ) -> RememberBulkResult:
        """Submit bulk + wait for every item to settle.

        Convenience wrapper around :meth:`remember_bulk_async` +
        :meth:`wait_for_remember_jobs`. Mirrors TS ``rememberBulkAndWait``.
        """

        accepted = await self.remember_bulk_async(items)
        return await self.wait_for_remember_jobs(accepted.job_ids, opts)

    async def recall(
        self,
        query: "str | RecallParams",
        limit: int = 10,
        namespace: Optional[str] = None,
        max_distance: Optional[float] = None,
    ) -> RecallResult:
        """Recall memories similar to a query.

        Server handles: verify -> embed query -> search -> Walrus download -> decrypt.

        **Preferred call style** is to pass a :class:`RecallParams`
        object so the call site reads self-describingly:

            await client.recall(RecallParams(
                query="food allergies", limit=5, namespace="profile"))

        The legacy positional call ``client.recall(query, limit, namespace)``
        is still supported but is easy to mis-read as
        ``recall(query, namespace)``. Prefer kwargs at minimum.

        Args:
            query: Search query, or a :class:`RecallParams` carrying query +
                limit + namespace + max_distance in one object.
            limit: Max number of results (default: 10). Ignored when ``query``
                is a :class:`RecallParams`.
            namespace: Override the default namespace. Ignored when ``query``
                is a :class:`RecallParams`.
            max_distance: Optional client-side relevance threshold. Memories
                with ``distance >= max_distance`` are dropped. Ignored when
                ``query`` is a :class:`RecallParams`.

        Returns:
            :class:`RecallResult` with decrypted text results.
        """
        scoring_weights = None
        sort = None
        if isinstance(query, RecallParams):
            params = query
            query_text = params.query
            limit = params.limit
            namespace = params.namespace
            max_distance = params.max_distance
            scoring_weights = params.scoring_weights
            sort = params.sort
        else:
            query_text = query
        _reject_blank_text(query_text, "query cannot be empty")
        _check_limit(limit)
        validate_max_distance(max_distance)
        body = {
            "query": query_text,
            "limit": limit,
            "namespace": self._resolve_namespace(namespace),
        }
        if scoring_weights is not None:
            body["scoring_weights"] = scoring_weights.to_wire()
        if sort is not None:
            body["sort"] = sort
        data = await self._signed_request("POST", "/api/recall", body)
        memories = [
            RecallMemory(
                blob_id=_require(m, "blob_id", "POST /api/recall"),
                text=_require(m, "text", "POST /api/recall"),
                distance=_require(m, "distance", "POST /api/recall"),
                score=m.get("score"),
                created_at=m.get("created_at"),
            )
            for m in data.get("results", [])
        ]
        raw_dropped = data.get("dropped_count") or 0
        try:
            dropped = int(raw_dropped)
        except (TypeError, ValueError):
            dropped = 0
        total_count = data.get("total", len(memories))
        if max_distance is not None:
            memories = [m for m in memories if m.distance < max_distance]
        return RecallResult(
            results=memories,
            total=total_count,
            dropped_count=dropped,
        )

    async def forget(self, namespace: Optional[str] = None) -> ForgetResult:
        """Delete this owner's index rows for ``namespace``.

        Wraps ``POST /api/forget``. Walrus blobs persist; the rows stop being
        retrievable. Defaults to the client namespace.
        """
        resolved_namespace = self._resolve_namespace(namespace)
        data = await self._signed_request(
            "POST",
            "/api/forget",
            {"namespace": resolved_namespace},
            include_seal_session=False,
        )
        endpoint = "POST /api/forget"
        return ForgetResult(
            deleted=int(_require(data, "deleted", endpoint)),
            namespace=_require(data, "namespace", endpoint),
            owner=_require(data, "owner", endpoint),
        )

    async def forget_namespace(self, namespace: Optional[str] = None) -> ForgetResult:
        """Alias for :meth:`forget` matching :meth:`MemWalMock.forget_namespace`."""
        return await self.forget(namespace)

    async def analyze(
        self,
        text: str,
        namespace: Optional[str] = None,
        occurred_at: Optional[Union[str, datetime]] = None,
    ) -> AnalyzeResult:
        """Analyze conversation text and return as soon as facts are accepted.

        Per PR #121: server extracts atomic facts synchronously via LLM, then
        enqueues one background remember job per fact. Returns 202 with
        ``job_ids`` aligned to ``facts``.

        Use :meth:`analyze_and_wait` to also wait for every fact to finish
        persisting (poll all job_ids together).

        Args:
            text: Conversation text to analyze.
            namespace: Override the default namespace.
            occurred_at: Optional valid-time timestamp — when the
                conversation/event actually happened. When supplied, the
                server extractor uses it as a temporal anchor and
                resolves in-turn relative references ("last Friday",
                "yesterday") into absolute dates inside the fact text
                before embedding/encryption. Accepts a
                :class:`datetime.datetime` (preferred — **must be
                timezone-aware**; naïve datetimes raise ``ValueError``
                because silently assuming UTC would mis-anchor by N
                hours for callers outside UTC) or an ISO-8601 / RFC-3339
                string (must carry a ``Z`` suffix or UTC offset; raises
                ``ValueError`` if malformed or naïve). Wire format is
                RFC-3339 UTC with millisecond precision and trailing
                ``Z`` (byte-identical to the TypeScript SDK). Omit when
                no anchor is available — the server will not invent one
                (no ``now()`` fallback). The resolved date lives only
                inside the encrypted fact text + embedding; there is no
                server-readable metadata column for it (Architecture A).

        Returns:
            :class:`AnalyzeResult` with extracted ``facts`` + per-fact
            ``job_ids`` for downstream polling.
        """
        _reject_blank_text(text)
        body: Dict[str, Any] = {
            "text": text,
            "namespace": self._resolve_namespace(namespace),
        }
        wire_occurred_at = _occurred_at_to_wire(occurred_at)
        if wire_occurred_at is not None:
            body["occurred_at"] = wire_occurred_at
        data = await self._signed_request(
            "POST",
            "/api/analyze",
            body,
            accepted_statuses=(200, 202),
        )
        # Backward-compat: older server shape returned `facts[].id` and
        # `facts[].blob_id` directly. New async shape may omit `blob_id`
        # at this point (set later by the worker) and add `job_ids`.
        facts = [
            AnalyzedFact(
                text=f["text"],
                id=f.get("id", ""),
                blob_id=f.get("blob_id", ""),
            )
            for f in data.get("facts", [])
        ]
        job_ids = list(data.get("job_ids", []))
        fact_count = int(data.get("fact_count", data.get("total", len(facts))))
        return AnalyzeResult(
            facts=facts,
            fact_count=fact_count,
            job_ids=job_ids,
            status=data.get("status", "pending"),
            owner=data.get("owner", ""),
        )

    async def analyze_and_wait(
        self,
        text: str,
        namespace: Optional[str] = None,
        opts: Optional[RememberBulkOptions] = None,
        occurred_at: Optional[Union[str, datetime]] = None,
    ) -> AnalyzeWaitResult:
        """Analyze + wait for every extracted fact to finish persisting.

        Mirrors TS ``analyzeAndWait``: calls :meth:`analyze` then
        :meth:`wait_for_remember_jobs` on the returned ``job_ids``. The
        result combines the analyze fact list with the bulk-style settled
        per-job results.

        ``occurred_at`` carries the same temporal-anchor semantics as
        :meth:`analyze` — see that method's docstring for details.
        """

        accepted = await self.analyze(text, namespace, occurred_at=occurred_at)
        completed = await self.wait_for_remember_jobs(accepted.job_ids, opts)
        return AnalyzeWaitResult(
            results=completed.results,
            total=completed.total,
            succeeded=completed.succeeded,
            failed=completed.failed,
            timed_out=completed.timed_out,
            facts=accepted.facts,
            owner=accepted.owner,
        )

    async def embed(self, text: str) -> EmbedResult:
        """Compute the embedding vector for ``text`` without storing anything.

        Calls ``POST /api/embed``. Useful for callers that want to do their
        own indexing or vector math; for the standard "remember" flow, use
        :meth:`remember` (server handles embed + encrypt + upload).
        """

        _reject_blank_text(text, "text cannot be empty")
        data = await self._signed_request(
            "POST",
            "/api/embed",
            {"text": text},
            include_seal_session=False,
        )
        return EmbedResult(vector=list(data.get("vector", [])))

    async def ask(
        self,
        question: str,
        limit: int = 5,
        namespace: Optional[str] = None,
    ) -> AskResult:
        """Ask a question answered using your memories.

        Server recalls relevant memories, injects them as context,
        and calls an LLM to produce a personalized answer.

        Args:
            question: The question to ask.
            limit: Max memories to use as context (default: 5).
            namespace: Override the default namespace.

        Returns:
            :class:`AskResult` with answer, memories_used count, and memories list.
        """
        _reject_blank_text(question, "question cannot be empty")
        _require_positive_int(limit, "limit")
        data = await self._signed_request("POST", "/api/ask", {
            "question": question,
            "limit": limit,
            "namespace": self._resolve_namespace(namespace),
        })
        memories = [
            AskMemory(
                blob_id=_require(m, "blob_id", "POST /api/ask"),
                text=_require(m, "text", "POST /api/ask"),
                distance=_require(m, "distance", "POST /api/ask"),
            )
            for m in data.get("memories", [])
        ]
        return AskResult(
            answer=_require(data, "answer", "POST /api/ask"),
            memories_used=_require(data, "memories_used", "POST /api/ask"),
            memories=memories,
        )

    async def restore(self, namespace: str, limit: int = 10) -> RestoreResult:
        """Rebuild missing local index entries for ``namespace`` from Walrus.

        The relayer queries Walrus for blobs the caller owns in ``namespace``,
        ignores blobs already indexed locally, downloads the missing ones,
        SEAL-decrypts them with the delegate key, re-embeds the plaintext, and
        inserts a fresh vector row per blob.

        Response semantics:

        * ``restored`` — blobs that completed the full
          download → decrypt → embed → DB insert pipeline this call.
        * ``skipped`` — on-chain blobs already present in the local success
          index (no work needed). Does not include permanent decrypt/UTF-8
          failures.
        * ``failed`` — permanent decrypt/UTF-8 failures on this on-chain page:
          negative-cache hits plus any new permanent failures this call.
          Transient download/decrypt/embed errors are not counted here; when
          a page yields only those, ``truncated`` is true so the caller
          retries. Defaults to ``0`` when talking to a relayer older than
          COMG-719 that omits the field.
        * ``total`` — count of on-chain blobs the relayer saw for
          ``(owner, namespace)`` before the limit was applied.
        * ``truncated`` — True when this restore is known-incomplete (limit
          truncation or an upstream on-chain candidate-fetch cap; see
          :class:`~memwal.types.RestoreResult`). Defaults to ``False`` when
          talking to a relayer older than WALM-319 that omits the field.

        Args:
            namespace: Namespace to restore. Exact match — no prefix or
                hierarchy semantics (see SKILL.md "Namespace Semantics").
            limit: Max blobs the relayer will *inspect* this call (default:
                10, matches the server-side default and the TypeScript SDK).
                The relayer selects up to this many missing blobs from the
                candidates it sees, in unspecified order; it does **not** cap
                ``restored`` separately.

        Returns:
            :class:`RestoreResult`.

        Notes:
            * **No pagination cursor** — restore is single-shot. A larger
              ``limit`` may help when ``truncated`` is caused by the request
              limit, but candidate discovery also has a per-owner source cap
              shared across namespaces. Hitting that cap requires cursor/
              pagination support for guaranteed full recovery; increasing
              ``limit`` or retrying cannot guarantee it.
            * **Performance** scales linearly in ``limit``: up to 10 Walrus
              downloads in parallel, then 3 SEAL decrypts in parallel, then
              embeddings. Expect seconds-per-blob on cold caches.
        """
        _check_limit(limit)
        data = await self._signed_request("POST", "/api/restore", {
            "namespace": namespace,
            "limit": limit,
        })
        endpoint = "POST /api/restore"
        return RestoreResult(
            restored=_require(data, "restored", endpoint),
            skipped=_require(data, "skipped", endpoint),
            total=_require(data, "total", endpoint),
            namespace=_require(data, "namespace", endpoint),
            owner=_require(data, "owner", endpoint),
            # Relayers older than WALM-319 omit `truncated` entirely --
            # treat "not present" as "not known to be truncated" rather
            # than require every relayer version to send it.
            truncated=data.get("truncated", False),
            # Relayers older than COMG-719 omit `failed`; default to 0.
            failed=data.get("failed", 0),
        )

    async def list_namespaces(
        self,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> NamespacesResult:
        """List the namespaces this account holds memories in.

        Recall needs a namespace to search. Without this, an agent on an
        unfamiliar account has to guess names or fall back to ``"default"``.
        Returns metadata only: no blob fetch, no decryption.

        Namespaces are flat and exact-match. To work with a prefix such as
        ``proj/``, filter the names here and recall each one.

        Paginate on ``has_more``, NOT page length: the relayer clamps
        ``limit``, so asking for more than the cap returns exactly the cap.

        Example::

            cursor = None
            while True:
                page = await memwal.list_namespaces(cursor=cursor)
                for ns in page.namespaces:
                    print(ns.name, ns.memory_count)
                cursor = page.next_cursor
                if not page.has_more:
                    break

        Args:
            cursor: A previous page's ``next_cursor``, to continue a walk or
                poll for namespaces changed since then. Opaque; not a
                timestamp or a namespace name.
            limit: Page size. The relayer defaults to 100 and clamps to 500.

        Returns:
            :class:`NamespacesResult`.
        """
        # Validate before resolving the owner: on a fresh client that lookup is
        # a signed POST /api/stats, so a bad limit must not reach it (#1218).
        if limit is not None:
            _check_limit(limit)
        owner = await self._resolve_owner()

        params: Dict[str, str] = {}
        if cursor is not None:
            params["updated_after"] = cursor
        if limit is not None:
            params["limit"] = str(limit)
        query = urlencode(params)

        # The query string is part of the signed path: the relayer verifies
        # against `path_and_query`, not `path`.
        path = f"/v1/owners/{owner}/namespaces" + (f"?{query}" if query else "")
        data = await self._signed_request("GET", path, {}, include_seal_session=False)
        endpoint = "GET /v1/owners/{owner}/namespaces"
        return NamespacesResult(
            namespaces=[
                NamespaceSummary(
                    id=_require(ns, "id", endpoint),
                    name=_require(ns, "name", endpoint),
                    memory_count=_require(ns, "memory_count", endpoint),
                    storage_used=_require(ns, "storage_used", endpoint),
                    updated_at=_require(ns, "updated_at", endpoint),
                )
                for ns in _require(data, "namespaces", endpoint)
            ],
            next_cursor=data.get("next_cursor"),
            has_more=_require(data, "has_more", endpoint),
            snapshot_version=_require(data, "snapshot_version", endpoint),
        )

    async def health(self) -> HealthResult:
        """Check server health. No authentication required.

        Returns:
            :class:`HealthResult` with status and version.
        """
        if self._destroyed:
            raise _destroyed_client_error()
        response = await self._http.get(f"{self._server_url}/health")
        if self._destroyed:
            raise _destroyed_client_error()
        if response.status_code != 200:
            raise MemWalError(f"Health check failed: {response.status_code}")
        data = _parse_json_response(response, "GET /health")
        return HealthResult(
            status=_require(data, "status", "GET /health"),
            version=_require(data, "version", "GET /health"),
            relayer_version=data.get("relayerVersion"),
            api_version=data.get("apiVersion"),
            min_supported_sdk=data.get("minSupportedSdk"),
            feature_flags=data.get("featureFlags"),
            deprecations=data.get("deprecations"),
            build=data.get("build"),
            mode=data.get("mode"),
            write_ready=data.get("write_ready"),
        )

    async def compatibility(self) -> Dict[str, Any]:
        """Fetch and validate the relayer compatibility contract."""
        if self._destroyed:
            raise _destroyed_client_error()
        return await self._ensure_compatible_relayer()

    # ============================================================
    # Manual API (user handles SEAL + embedding + Walrus)
    # ============================================================

    async def remember_manual(self, opts: RememberManualOptions) -> RememberManualResult:
        """Remember (manual mode).

        User handles SEAL encrypt and embedding. The relayer uploads the
        encrypted bytes to Walrus and stores the vector mapping.

        Args:
            opts: :class:`RememberManualOptions` with encrypted_data (base64),
                vector, and optional namespace.

        Returns:
            :class:`RememberManualResult` with id, blob_id, owner, namespace.
        """
        _check_vector(opts.vector)
        data = await self._signed_request(
            "POST",
            "/api/remember/manual",
            {
                "encrypted_data": opts.encrypted_data,
                "vector": opts.vector,
                "namespace": self._resolve_namespace(opts.namespace),
            },
            include_seal_session=False,
        )
        endpoint = "POST /api/remember/manual"
        return RememberManualResult(
            id=_require(data, "id", endpoint),
            blob_id=_require(data, "blob_id", endpoint),
            owner=_require(data, "owner", endpoint),
            namespace=_require(data, "namespace", endpoint),
        )

    async def recall_manual(self, opts: RecallManualOptions) -> RecallManualResult:
        """Recall (manual mode).

        User provides a pre-computed query vector. Server returns matching
        blobIds + distances. User then downloads from Walrus + SEAL decrypts.

        Args:
            opts: :class:`RecallManualOptions` with vector, optional limit and namespace.

        Returns:
            :class:`RecallManualResult` with blob_id + distance pairs.
        """
        _check_vector(opts.vector)
        _check_limit(opts.limit)
        body: Dict[str, Any] = {
            "vector": opts.vector,
            "limit": opts.limit,
            "namespace": self._resolve_namespace(opts.namespace),
        }
        if opts.scoring_weights is not None:
            body["scoring_weights"] = opts.scoring_weights.to_wire()

        data = await self._signed_request(
            "POST",
            "/api/recall/manual",
            body,
            include_seal_session=False,
        )
        hits = [
            RecallManualHit(
                blob_id=h["blob_id"],
                distance=h["distance"],
                created_at=h.get("created_at"),
                importance=h.get("importance"),
            )
            for h in data.get("results", [])
        ]
        return RecallManualResult(results=hits, total=data.get("total", len(hits)))

    async def get_public_key_hex(self) -> str:
        """Get the Ed25519 public key as a hex string.

        Returns:
            Public key hex string.
        """
        if self._destroyed or self._signing_key is None:
            raise _destroyed_client_error()
        return bytes_to_hex(bytes(self._signing_key.verify_key))

    # ============================================================
    # Internal: Signed HTTP Requests
    # ============================================================

    async def _ensure_compatible_relayer(self) -> Dict[str, Any]:
        if self._destroyed:
            raise _destroyed_client_error()
        if self._relayer_version_metadata is not None:
            return self._relayer_version_metadata

        if self._compatibility_lock is None:
            self._compatibility_lock = asyncio.Lock()

        async with self._compatibility_lock:
            if self._destroyed:
                raise _destroyed_client_error()
            if self._relayer_version_metadata is not None:
                return self._relayer_version_metadata

            version_response = await self._http.get(f"{self._server_url}/version")
            if self._destroyed:
                raise _destroyed_client_error()
            if version_response.status_code == 200:
                metadata = _parse_json_response(version_response, "GET /version")
            elif version_response.status_code in (404, 405):
                health_response = await self._http.get(f"{self._server_url}/health")
                if self._destroyed:
                    raise _destroyed_client_error()
                if health_response.status_code != 200:
                    raise MemWalError(
                        "Walrus Memory compatibility check failed: "
                        f"GET /version returned {version_response.status_code}, "
                        f"and GET /health returned {health_response.status_code}"
                    )
                metadata = _parse_json_response(health_response, "GET /health")
            else:
                raise MemWalError(
                    "Walrus Memory compatibility check failed: "
                    f"GET /version returned {version_response.status_code}"
                )

            error = compatibility_error(metadata, self._server_url)
            if error is not None:
                raise MemWalCompatibilityError(error)

            self._relayer_version_metadata = metadata
            return metadata

    async def _fetch_server_config(self) -> Dict[str, str]:
        if self._server_config is not None:
            return self._server_config

        response = await self._http.get(f"{self._server_url}/config")
        if response.status_code != 200:
            raise MemWalError(f"GET /config returned {response.status_code}")

        data = _parse_json_response(response, "GET /config")
        if not isinstance(data, dict):
            raise MemWalError(
                f"GET /config response was {type(data).__name__}, expected an object"
            )
        package_id = data.get("packageId")
        network = data.get("network")
        sui_rpc_url = data.get("suiRpcUrl")
        if not package_id or not network:
            raise MemWalError("GET /config response missing packageId / network")

        self._server_config = {
            "packageId": package_id,
            "network": network,
            "suiRpcUrl": sui_rpc_url or "",
        }
        return self._server_config

    async def _fetch_package_version_graphql(self, network: str, package_id: str):
        """Read the package object version via Sui GraphQL RPC.

        JSON-RPC on public fullnodes is sunset (see
        https://docs.sui.io/develop/accessing-data/json-rpc-migration), and the
        third-party JSON-RPC mirror the relayer used to advertise has gone
        unresponsive, hanging every client init. GraphQL is the plain-HTTPS
        read layer that survives the sunset without pulling gRPC deps into
        this SDK.
        """
        graphql_url = f"https://graphql.{network}.sui.io/graphql"
        response = await self._http.post(
            graphql_url,
            json={
                "query": "query($a:SuiAddress!){object(address:$a){version}}",
                "variables": {"a": package_id},
            },
            timeout=PACKAGE_VERSION_CHECK_TIMEOUT_S,
        )
        if response.status_code != 200:
            raise MemWalError(f"Sui GraphQL returned {response.status_code}")
        body = _parse_json_response(response, f"POST {graphql_url}")
        data = body.get("data") if isinstance(body, dict) else None
        obj = data.get("object") if isinstance(data, dict) else None
        if not isinstance(obj, dict) or obj.get("version") is None:
            raise MemWalError(f"Sui GraphQL could not resolve package {package_id}")
        return obj["version"]

    async def _fetch_package_version_jsonrpc(self, sui_rpc_url: str, package_id: str):
        """Legacy JSON-RPC fallback for custom / local networks that have no
        public GraphQL endpoint and still serve `sui_getObject`."""
        response = await self._http.post(
            sui_rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "sui_getObject",
                "params": [package_id, {"showBcs": False, "showContent": False, "showType": False}],
            },
            timeout=PACKAGE_VERSION_CHECK_TIMEOUT_S,
        )
        if response.status_code != 200:
            raise MemWalError(f"sui_getObject returned {response.status_code}")

        body = _parse_json_response(response, f"POST {sui_rpc_url}")
        result = body.get("result", {}) if isinstance(body, dict) else {}
        version = None
        if isinstance(result, dict):
            data = result.get("data")
            if isinstance(data, dict):
                version = data.get("version")
            if version is None:
                obj = result.get("object")
                if isinstance(obj, dict):
                    version = obj.get("version")
        return version

    async def _assert_first_package_version(
        self, network: str, sui_rpc_url: str, package_id: str
    ) -> None:
        if network in PUBLIC_SUI_GRAPHQL_NETWORKS:
            version = await self._fetch_package_version_graphql(network, package_id)
        elif sui_rpc_url:
            version = await self._fetch_package_version_jsonrpc(sui_rpc_url, package_id)
        else:
            raise MemWalError(
                f"No Sui read endpoint available for network {network!r}: "
                "no public GraphQL endpoint and GET /config carried no suiRpcUrl"
            )
        if str(version) != "1":
            raise MemWalError(
                f"SEAL package {package_id} must be at version 1 to build "
                f"x-seal-session, got {version!r}"
            )

    async def _build_seal_session_inner(self) -> str:
        if self._destroyed or self._signing_key is None:
            raise _destroyed_client_error()
        cfg = await self._fetch_server_config()
        if self._destroyed or self._signing_key is None:
            raise _destroyed_client_error()
        await self._assert_first_package_version(
            cfg["network"], cfg["suiRpcUrl"], cfg["packageId"]
        )
        if self._destroyed or self._signing_key is None:
            raise _destroyed_client_error()

        session_signing_key = nacl.signing.SigningKey.generate()
        session_public_key = bytes(session_signing_key.verify_key)
        creation_time_ms = int(time.time() * 1000)
        personal_message = build_seal_session_personal_message(
            package_id=cfg["packageId"],
            ttl_min=SEAL_SESSION_TTL_MIN,
            creation_time_ms=creation_time_ms,
            session_public_key_bytes=session_public_key,
        )
        personal_message_signature = sign_sui_personal_message(
            personal_message,
            self._signing_key,
        )

        json_str = json.dumps(
            {
                "address": delegate_key_to_sui_address(self._private_key_hex),
                "packageId": cfg["packageId"],
                "mvrName": None,
                "creationTimeMs": creation_time_ms,
                "ttlMin": SEAL_SESSION_TTL_MIN,
                "personalMessageSignature": personal_message_signature,
                "sessionKey": encode_sui_private_key(bytes(session_signing_key)),
            },
            separators=(",", ":"),
        )
        session_bytes = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
        if self._destroyed:
            raise _destroyed_client_error()
        self._session_cache = (
            session_bytes,
            int(time.time() * 1000) + SEAL_SESSION_TTL_MIN * 60_000 - SEAL_SESSION_SAFETY_MARGIN_MS,
        )
        return session_bytes

    async def _build_seal_session(self) -> str:
        if self._destroyed:
            raise _destroyed_client_error()
        now_ms = int(time.time() * 1000)
        if self._session_cache is not None:
            cached_bytes, expires_at_ms = self._session_cache
            if now_ms < expires_at_ms:
                return cached_bytes

        task = self._session_build_task
        if task is None or task.done():
            task = asyncio.create_task(self._build_seal_session_inner())
            self._session_build_task = task

            def _on_session_build_done(done_task: "asyncio.Task[str]") -> None:
                if self._session_build_task is done_task:
                    self._session_build_task = None
                if not done_task.cancelled():
                    done_task.exception()

            task.add_done_callback(_on_session_build_done)

        try:
            result = await asyncio.shield(task)
        except asyncio.CancelledError:
            if self._destroyed:
                raise _destroyed_client_error() from None
            raise
        if self._destroyed:
            raise _destroyed_client_error()
        return result

    async def _resolve_owner_inner(self) -> str:
        if self._destroyed:
            raise _destroyed_client_error()
        # POST /api/stats authenticates with the same delegate scheme and
        # returns the owner the relayer resolved from our key. Same approach
        # as the TypeScript SDK's resolveOwner().
        data = await self._signed_request(
            "POST",
            "/api/stats",
            {"namespace": self._namespace},
            include_seal_session=False,
        )
        if self._destroyed:
            raise _destroyed_client_error()
        owner = data.get("owner") if isinstance(data, dict) else None
        if not owner:
            raise MemWalError(
                "Walrus Memory could not resolve this account's owner address "
                "(POST /api/stats returned no owner)."
            )
        self._owner_address = owner
        return owner

    async def _resolve_owner(self) -> str:
        """Owner address for this account, memoised for the client's life.

        The owner-scoped read routes take the address in the path, but the
        client is configured with only a delegate key and account id.
        """
        if self._destroyed:
            raise _destroyed_client_error()
        if self._owner_address is not None:
            return self._owner_address

        task = self._owner_task
        if task is None or task.done():
            task = asyncio.create_task(self._resolve_owner_inner())
            self._owner_task = task

            def _on_owner_done(done_task: "asyncio.Task[str]") -> None:
                if self._owner_task is done_task:
                    self._owner_task = None
                if not done_task.cancelled():
                    done_task.exception()

            task.add_done_callback(_on_owner_done)

        try:
            result = await asyncio.shield(task)
        except asyncio.CancelledError:
            if self._destroyed:
                raise _destroyed_client_error() from None
            raise
        if self._destroyed:
            raise _destroyed_client_error()
        return result

    async def _signed_request(
        self,
        method: str,
        path: str,
        body: Dict[str, Any],
        accepted_statuses: tuple = (200,),
        include_seal_session: bool = True,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Make a signed request to the server.

        Signature format:
            ``{timestamp}.{method}.{path_and_query}.{body_sha256}.{nonce}.{account_id}``

        For ``GET`` requests the canonical body string is the empty string,
        and no HTTP request body is sent. This keeps the signed payload hash
        byte-compatible with the TypeScript SDK and with intermediaries that
        strip ``GET`` bodies on the wire.

        Headers sent:
            - ``x-public-key``: Ed25519 public key hex
            - ``x-signature``: Ed25519 signature hex
            - ``x-timestamp``: Unix seconds string
            - ``x-nonce``: UUID v4 replay-protection nonce
            - ``x-seal-session``: Base64-encoded exported session envelope
            - ``x-account-id``: Walrus Memory account object ID
            - ``Content-Type``: application/json
        """
        if self._destroyed or self._signing_key is None:
            raise _destroyed_client_error()

        await self._ensure_compatible_relayer()
        if self._destroyed or self._signing_key is None:
            raise _destroyed_client_error()

        method_upper = method.upper()
        timestamp = str(int(time.time()))
        body_str = "" if method_upper == "GET" else json.dumps(
            body, separators=(",", ":"), allow_nan=False
        )
        body_hash = sha256_hex(body_str)
        # MED-1 / LOW-23: nonce + account_id are part of the canonical signed
        # message. Server rejects the request as "unsupported legacy SDK"
        # (HTTP 426) if x-nonce is missing or not UUID-formatted.
        nonce = str(uuid.uuid4())

        message = build_signature_message(
            timestamp,
            method_upper,
            path,
            body_hash,
            nonce=nonce,
            account_id=self._account_id,
        )
        signature_hex, public_key_hex = sign_message(message, self._signing_key)

        url = f"{self._server_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "x-public-key": public_key_hex,
            "x-signature": signature_hex,
            "x-timestamp": timestamp,
            "x-nonce": nonce,
            "x-account-id": self._account_id,
        }
        if include_seal_session:
            headers["x-seal-session"] = await self._build_seal_session()
            if self._destroyed or self._signing_key is None:
                raise _destroyed_client_error()

        response = await self._http.request(
            method=method_upper,
            url=url,
            headers=headers,
            content=None if method_upper == "GET" else body_str,
            timeout=timeout,
        )
        if self._destroyed or self._signing_key is None:
            raise _destroyed_client_error()

        if response.status_code not in accepted_statuses:
            err_text = response.text
            if response.status_code == 426:
                raise MemWalCompatibilityError(
                    "Walrus Memory relayer rejected this SDK as unsupported "
                    f"(HTTP 426 Upgrade Required). Relayer response: "
                    f"{err_text[:300] or 'upgrade required'}"
                )
            # A stale/future-dated signature is rejected with 401 + a machine-
            # readable reason header. Surface it as an actionable clock-drift
            # error rather than an opaque 401 so the caller can fix node time.
            if response.headers.get("x-auth-error") == "ERR_TIMESTAMP_OUT_OF_BOUNDS":
                raise MemWalClockDriftError(
                    "Request rejected: signed timestamp is outside the relayer's "
                    "accepted clock-drift window. Synchronize this client's clock "
                    "(NTP); if the deployment needs a wider tolerance, raise "
                    "AUTH_MAX_CLOCK_DRIFT_SECS on the relayer."
                )
            raise _HttpStatusError(
                status=response.status_code,
                body=err_text,
                auth_error=response.headers.get("x-auth-error"),
                retry_after=response.headers.get("retry-after"),
            )

        endpoint = f"{method_upper} {path}"
        data = _parse_json_response(response, endpoint)
        if response.status_code != 404 and not isinstance(data, dict):
            raise MemWalJsonBodyError(
                status=response.status_code,
                endpoint=endpoint,
                body=response.text,
            )
        return data


class MemWalError(Exception):
    """Exception raised for Walrus Memory API errors."""

    pass


class MemWalCompatibilityError(MemWalError):
    """Raised when the SDK and relayer API contract are incompatible."""

    pass


class MemWalClockDriftError(MemWalError):
    """Raised when the relayer rejects a request because the signed timestamp is
    outside its accepted clock-drift window (401 + ``x-auth-error:
    ERR_TIMESTAMP_OUT_OF_BOUNDS``). Indicates the client's clock is skewed
    relative to the relayer; sync via NTP or widen the relayer's window."""

    pass


class MemWalJsonBodyError(MemWalError):
    """Raised when an HTTP response that should carry JSON has an empty or non-JSON body."""

    def __init__(
        self,
        status: int,
        endpoint: str,
        body: str,
        *,
        empty: bool = False,
    ) -> None:
        redacted = _redact_internal_urls(body.strip()[:200]) if body else ""
        if empty:
            message = (
                f"MemWal ({endpoint}): HTTP {status} response had an empty body; "
                "expected JSON"
            )
        elif redacted:
            message = (
                f"MemWal ({endpoint}): HTTP {status} response was not JSON: "
                f"{redacted}"
            )
        else:
            message = f"MemWal ({endpoint}): HTTP {status} response was not JSON"
        super().__init__(message)
        self.status = status
        self.endpoint = endpoint
        self.body = body


def _parse_json_response(response: httpx.Response, endpoint: str) -> Any:
    """Decode a JSON response body or raise :class:`MemWalJsonBodyError` (#1219).

    Mirrors the TypeScript SDK's ``jsonBodyError`` guard (#1201 / #1207): an
    empty or non-JSON 2xx response from a relayer or proxy in front of one
    surfaces as a :class:`MemWalError` naming the endpoint and HTTP status
    rather than Python's raw :class:`json.JSONDecodeError` or
    :class:`UnicodeDecodeError`.
    """
    try:
        return response.json()
    except UnicodeDecodeError as exc:
        raise MemWalJsonBodyError(
            status=response.status_code,
            endpoint=endpoint,
            body="",
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        doc = getattr(exc, "doc", None)
        if isinstance(doc, str):
            raw = doc
        else:
            try:
                raw = response.text
            except UnicodeDecodeError:
                raw = ""
        is_empty = not raw or not raw.strip()
        raise MemWalJsonBodyError(
            status=response.status_code,
            endpoint=endpoint,
            body=raw,
            empty=is_empty,
        ) from exc


def _redact_internal_urls(text: str) -> str:
    return re.sub(
        r"https?://(?:(?:[\w-]+\.)*localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[::1\]|0\.0\.0\.0)(?::\d+)?[^\s)\]>'\"]*",
        "[internal]",
        text,
        flags=re.IGNORECASE,
    )


class _HttpStatusError(MemWalError):
    """Internal: raised when an HTTP response status is not in ``accepted_statuses``.

    Carries ``.status`` so polling loops can decide whether to retry
    (transient: 0/429/5xx) or surface (terminal: 4xx other than 404 when
    explicitly accepted).
    """

    def __init__(
        self,
        status: int,
        body: str,
        auth_error: str | None = None,
        retry_after: str | None = None,
    ) -> None:
        if status == 401:
            super().__init__(AUTH_REJECTED_MESSAGE)
        elif status == 503 and auth_error == AUTH_UPSTREAM_UNAVAILABLE:
            super().__init__(UPSTREAM_UNAVAILABLE_MESSAGE)
        else:
            super().__init__(
                f"Walrus Memory API error ({status}): {_redact_internal_urls(body)}"
            )
        self.status = status
        self.body = body
        self.auth_error = auth_error
        self.retry_after = retry_after


class MemWalRememberJobNotFound(MemWalError):
    """The polled job_id does not exist or is not owned by the caller."""

    def __init__(self, job_id: str) -> None:
        super().__init__(f"remember job not found: {job_id}")
        self.status = 404
        self.job_id = job_id


class MemWalRememberJobFailed(MemWalError):
    """The async remember job reached terminal status=failed."""

    def __init__(self, job_id: str, error: str) -> None:
        super().__init__(f"remember job failed: {_redact_internal_urls(error)}")
        self.status = 500
        self.job_id = job_id
        self.error = error


class MemWalRateLimited(MemWalError):
    """Every status read for a bulk wait was rate-limited, the confirming read
    included, so none of its writes could be confirmed (GH #967). Status reads
    count against the same delegate-key budget as writes."""

    def __init__(self, job_ids: Sequence[str], retry_after: Optional[str] = None) -> None:
        wait = f" after ~{retry_after}s" if retry_after else ""
        super().__init__(
            f"Walrus Memory rate-limited every status read for this batch, so none of its "
            f"{len(job_ids)} writes could be confirmed. Do not treat them as stored: check them "
            f"with get_remember_bulk_status(job_ids){wait}. Status reads count against the same "
            "delegate-key budget as writes."
        )
        self.status = 429
        self.job_ids = list(job_ids)
        self.retry_after = retry_after


class MemWalRememberJobTimeout(MemWalError):
    """Polling loop exceeded the configured timeout.

    Carries the last status the relayer reported (GH #966): under upload
    congestion a job stays ``running`` for tens of minutes, and without it a
    job that is still retrying looks dead.
    """

    def __init__(
        self,
        job_id: str,
        timeout_ms: int,
        last_status: Optional[str] = None,
        server_error: Optional[str] = None,
        last_refusal: Optional[int] = None,
        saw_rate_limit: bool = False,
    ) -> None:
        # "no status read got through (last poll: HTTP 429)" already names the rate limit.
        named = last_status is None and last_refusal == 429
        rate_limited = "; wait hit a rate limit (429)" if saw_rate_limit and not named else ""
        # Redacted once, for both the message and the attribute.
        server_error = _redact_internal_urls(server_error) if server_error else None
        if last_status is not None:
            # The wait only times out on a job still pending/running/uploaded
            # (a failed job raises), so the advice is to keep waiting on it.
            suffix = f" ({server_error})" if server_error else ""
            detail = (
                f"last status: {last_status}{suffix}. The job is still in progress: "
                f"call wait_for_remember_job({job_id!r}) to keep waiting on it. Sending "
                "the text again under a new idempotency key stores it twice; a key you "
                "passed as idempotency_key is not remembered by the client, so pass it "
                "again on any retry."
            )
        else:
            detail = (
                f"no status read got through (last poll: HTTP {last_refusal or 0}), "
                "so the job's state is unknown."
            )
        super().__init__(
            f"remember job timed out after {timeout_ms}ms (job_id={job_id}){rate_limited}; {detail}"
        )
        self.status = 504
        self.job_id = job_id
        self.timeout_ms = timeout_ms
        self.last_status = last_status
        self.server_error = server_error
        self.last_refusal = last_refusal


async def _discard_http_client(memwal: MemWal) -> None:
    """Close the cached httpx client, and drop it either way.

    ``close()`` can fail when the client belongs to an event loop that has
    already finished — the caller still needs ``_client`` cleared so the next
    request builds one in a loop that is actually running.
    """
    try:
        await memwal.close()
    except Exception:
        logger.debug("Closing the cached HTTP client failed", exc_info=True)
    finally:
        memwal._client = None


async def _with_fresh_http_client(memwal: MemWal, coro: Any) -> Any:
    """Run ``coro`` with an httpx client owned by the *current* event loop.

    The sync entry points execute each coroutine in a throwaway ``asyncio.run()``
    loop, and an ``httpx.AsyncClient`` is bound to the loop that created it, so
    one can never be reused across calls. Both ends are closed rather than just
    dropped (GH #606): on the way in for anything an earlier loop left behind —
    e.g. a caller mixing ``await memwal.recall()`` with the sync wrapper — and in
    ``finally`` for the client this call created, while its loop is still alive.
    """
    await _discard_http_client(memwal)
    try:
        return await coro
    finally:
        await _discard_http_client(memwal)


class MemWalSync:
    """Synchronous wrapper around the async :class:`MemWal` client.

    Provides the same API surface but runs everything through ``asyncio.run()``.
    Useful for scripts, notebooks, and non-async applications.

    Example::

        from memwal import MemWalSync, RecallParams

        client = MemWalSync.create(key="...", account_id="0x...")
        result = client.remember("I love coffee")
        matches = client.recall(RecallParams(query="coffee preferences"))
    """

    def __init__(self, inner: MemWal) -> None:
        self._inner = inner

    @classmethod
    def create(
        cls,
        key: Union[str, bytes, bytearray],
        account_id: str,
        server_url: Optional[str] = None,
        namespace: str = "default",
        env: Optional[str] = None,
    ) -> "MemWalSync":
        """Create a synchronous Walrus Memory client.

        Same parameters as :meth:`MemWal.create` (including the ``env``
        relayer preset).
        """
        inner = MemWal.create(
            key=key,
            account_id=account_id,
            server_url=server_url,
            namespace=namespace,
            env=env,
        )
        return cls(inner)

    def _run(self, coro: Any) -> Any:
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        # The httpx client is created and closed inside the same short-lived
        # loop that uses it. This matters in notebooks/Jupyter where the sync
        # wrapper runs coroutines in worker threads with their own event loops.
        wrapped = _with_fresh_http_client(self._inner, coro)

        if loop is not None and loop.is_running():
            # Already inside an event loop (e.g. Jupyter).
            # Create a new loop in a thread.
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, wrapped).result()
        else:
            return asyncio.run(wrapped)

    def remember(
        self,
        text: str,
        namespace: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> RememberAcceptedResult:
        """Synchronous version of :meth:`MemWal.remember` (async accept)."""
        return self._run(self._inner.remember(text, namespace, idempotency_key))

    # Alias for parity with TS SDK ``rememberAsync``.
    def remember_async(
        self,
        text: str,
        namespace: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> RememberAcceptedResult:
        return self._run(self._inner.remember_async(text, namespace, idempotency_key))

    def get_remember_status(self, job_id: str) -> RememberJobStatus:
        """Synchronous version of :meth:`MemWal.get_remember_status`."""
        return self._run(self._inner.get_remember_status(job_id))

    def wait_for_remember_job(
        self,
        job_id: str,
        poll_interval_ms: int = 1500,
        timeout_ms: int = 60_000,
    ) -> RememberResult:
        """Synchronous version of :meth:`MemWal.wait_for_remember_job`."""
        return self._run(
            self._inner.wait_for_remember_job(
                job_id,
                poll_interval_ms=poll_interval_ms,
                timeout_ms=timeout_ms,
            )
        )

    def remember_and_wait(
        self,
        text: str,
        namespace: Optional[str] = None,
        poll_interval_ms: int = 1500,
        timeout_ms: int = 60_000,
        idempotency_key: Optional[str] = None,
    ) -> RememberResult:
        """Synchronous version of :meth:`MemWal.remember_and_wait`."""
        return self._run(
            self._inner.remember_and_wait(
                text,
                namespace,
                poll_interval_ms=poll_interval_ms,
                timeout_ms=timeout_ms,
                idempotency_key=idempotency_key,
            )
        )

    def remember_bulk(
        self, items: Sequence[RememberBulkItem]
    ) -> RememberBulkAcceptedResult:
        """Synchronous version of :meth:`MemWal.remember_bulk`."""
        return self._run(self._inner.remember_bulk(items))

    def remember_bulk_async(
        self, items: Sequence[RememberBulkItem]
    ) -> RememberBulkAcceptedResult:
        return self._run(self._inner.remember_bulk_async(items))

    def get_remember_bulk_status(
        self, job_ids: Sequence[str]
    ) -> RememberBulkStatusResult:
        """Synchronous version of :meth:`MemWal.get_remember_bulk_status`."""
        return self._run(self._inner.get_remember_bulk_status(job_ids))

    def wait_for_remember_jobs(
        self,
        job_ids: Sequence[str],
        opts: Optional[RememberBulkOptions] = None,
    ) -> RememberBulkResult:
        """Synchronous version of :meth:`MemWal.wait_for_remember_jobs`."""
        return self._run(self._inner.wait_for_remember_jobs(job_ids, opts))

    def remember_bulk_and_wait(
        self,
        items: Sequence[RememberBulkItem],
        opts: Optional[RememberBulkOptions] = None,
    ) -> RememberBulkResult:
        """Synchronous version of :meth:`MemWal.remember_bulk_and_wait`."""
        return self._run(self._inner.remember_bulk_and_wait(items, opts))

    def recall(
        self,
        query: "str | RecallParams",
        limit: int = 10,
        namespace: Optional[str] = None,
        max_distance: Optional[float] = None,
    ) -> RecallResult:
        """Synchronous version of :meth:`MemWal.recall` (accepts
        :class:`RecallParams` for the recommended object-style call)."""
        return self._run(self._inner.recall(query, limit, namespace, max_distance))

    def forget(self, namespace: Optional[str] = None) -> ForgetResult:
        """Synchronous version of :meth:`MemWal.forget`."""
        return self._run(self._inner.forget(namespace))

    def forget_namespace(self, namespace: Optional[str] = None) -> ForgetResult:
        """Synchronous version of :meth:`MemWal.forget_namespace`."""
        return self._run(self._inner.forget_namespace(namespace))

    def analyze(
        self,
        text: str,
        namespace: Optional[str] = None,
        occurred_at: Optional[Union[str, datetime]] = None,
    ) -> AnalyzeResult:
        """Synchronous version of :meth:`MemWal.analyze`."""
        return self._run(self._inner.analyze(text, namespace, occurred_at=occurred_at))

    def analyze_and_wait(
        self,
        text: str,
        namespace: Optional[str] = None,
        opts: Optional[RememberBulkOptions] = None,
        occurred_at: Optional[Union[str, datetime]] = None,
    ) -> AnalyzeWaitResult:
        """Synchronous version of :meth:`MemWal.analyze_and_wait`."""
        return self._run(
            self._inner.analyze_and_wait(text, namespace, opts, occurred_at=occurred_at)
        )

    def embed(self, text: str) -> EmbedResult:
        """Synchronous version of :meth:`MemWal.embed`."""
        return self._run(self._inner.embed(text))

    def ask(self, question: str, limit: int = 5, namespace: Optional[str] = None) -> AskResult:
        """Synchronous version of :meth:`MemWal.ask`."""
        return self._run(self._inner.ask(question, limit, namespace))

    def restore(self, namespace: str, limit: int = 10) -> RestoreResult:
        """Synchronous version of :meth:`MemWal.restore`. Default limit is 10
        (matches server + TypeScript SDK)."""
        return self._run(self._inner.restore(namespace, limit))

    def list_namespaces(
        self,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> NamespacesResult:
        """Synchronous version of :meth:`MemWal.list_namespaces`."""
        return self._run(self._inner.list_namespaces(cursor, limit))

    def health(self) -> HealthResult:
        """Synchronous version of :meth:`MemWal.health`."""
        return self._run(self._inner.health())

    def compatibility(self) -> Dict[str, Any]:
        """Synchronous version of :meth:`MemWal.compatibility`."""
        return self._run(self._inner.compatibility())

    def remember_manual(self, opts: RememberManualOptions) -> RememberManualResult:
        """Synchronous version of :meth:`MemWal.remember_manual`."""
        return self._run(self._inner.remember_manual(opts))

    def recall_manual(self, opts: RecallManualOptions) -> RecallManualResult:
        """Synchronous version of :meth:`MemWal.recall_manual`."""
        return self._run(self._inner.recall_manual(opts))

    def get_public_key_hex(self) -> str:
        """Synchronous version of :meth:`MemWal.get_public_key_hex`."""
        return self._run(self._inner.get_public_key_hex())

    def destroy(self) -> None:
        """Synchronous version of :meth:`MemWal.destroy`."""
        self._inner.destroy()

    def close(self, clear_keys: bool = False) -> None:
        """Close the underlying HTTP client.

        Args:
            clear_keys: If ``True``, also call :meth:`destroy` to wipe internal
                key buffers, drop signing credentials, and invalidate the client.
        """
        self._run(self._inner.close(clear_keys=clear_keys))

    def __enter__(self) -> "MemWalSync":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

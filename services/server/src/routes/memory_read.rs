//! GET /v1/owners/{owner}/namespaces|memories|agents — owner-scoped,
//! cursor-paginated read API.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use base64::Engine as _;
use serde::Serialize;
use sqlx::PgPool;
use std::sync::Arc;

use crate::security_delete_auth::same_owner;
use crate::storage::db::TOMBSTONE_RETENTION;
use crate::types::*;

#[derive(Debug, Serialize)]
pub struct NamespaceSummary {
    pub id: String,
    pub name: String,
    pub memory_count: i64,
    pub storage_used: i64,
    /// `MAX(updated_at)` across the namespace's rows — the same value the
    /// keyset cursor is built from. Exposed (not just baked into the opaque
    /// cursor) so Console can tell *what* changed, not merely that its
    /// watermark moved.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct NamespacesResponse {
    pub namespaces: Vec<NamespaceSummary>,
    pub next_cursor: Option<String>,
    /// Explicit end-of-data signal. A page shorter than the requested
    /// `limit` does NOT reliably mean "no more data" — the server silently
    /// clamps `limit` to `MAX_NAMESPACES_LIMIT`, so a caller that asked for
    /// more than the cap and got exactly the cap back would wrongly
    /// conclude it was done. Use this field, not page length, to decide
    /// whether to keep paginating.
    pub has_more: bool,
    pub snapshot_version: u32,
}

#[derive(Debug, Serialize)]
pub struct MemoryItem {
    pub memory_id: String,
    pub namespace_id: String,
    pub blob_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The row's `updated_at` — the same value this page's keyset cursor is
    /// built from. It was already being fetched purely to encode the cursor;
    /// surfacing it lets Console diff by row instead of trusting an opaque
    /// token.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub size: i64,
    pub agent_id: Option<String>,
    pub package_id: Option<String>,
    pub status: String,
    pub end_epoch: Option<i32>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub importance: Option<f32>,
}

/// Additive tombstone for Console incremental sync (WALM-363). Ignored by
/// clients that do not read `deleted`. Never mixed into `memories[]`.
#[derive(Debug, Serialize)]
pub struct DeletedMemory {
    pub memory_id: String,
    pub namespace_id: String,
    pub deleted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct MemoriesResponse {
    pub memories: Vec<MemoryItem>,
    pub next_cursor: Option<String>,
    /// Explicit end-of-data signal — see `NamespacesResponse::has_more`'s
    /// doc comment; same reasoning applies (`limit` is silently clamped to
    /// `MAX_MEMORIES_LIMIT`).
    pub has_more: bool,
    pub snapshot_version: u32,
    pub deleted: Vec<DeletedMemory>,
    pub must_resync: bool,
}

/// Additive fields only (`deleted`, `must_resync`). Keep at 2 so the shipped
/// Console client (COMG-568) ignores the new keys and never treats tombstones
/// as live memories.
pub const SNAPSHOT_VERSION: u32 = 2;

const DEFAULT_NAMESPACES_LIMIT: i64 = 100;
const MAX_NAMESPACES_LIMIT: i64 = 500;

/// Keyset watermark over the namespace rollup, mirroring `MemoriesCursor`'s
/// `(updated_at, id)` shape with the rollup's `(MAX(updated_at), namespace)`.
///
/// An earlier cursor was the bare namespace name, ordered by `namespace`
/// alone. That is unsafe two ways: (1) as a *traversal* cursor, a namespace
/// inserted concurrently while a client is mid-walk can sort lexicographically
/// *before* the cursor and be silently, permanently skipped for that walk;
/// (2) as a *sync* cursor, a namespace that sorts before the cursor can never
/// reappear, so a later write that changes its `memory_count`/`storage_used`
/// stays invisible to a polling client forever. Ordering by the rollup's own
/// recency instead means a namespace can only move *forward* in walk order as
/// its rows are touched — never behind an already-consumed cursor position —
/// and any namespace touched after the client's watermark sorts after it and
/// is returned on the next poll, however early its name sorts. `namespace`
/// remains the tie-break (unique per `GROUP BY` row) so equal
/// `MAX(updated_at)` values still paginate without gaps or repeats.
///
/// That fix alone reintroduces the opposite failure: `MAX(updated_at)` for a
/// namespace can *increase* after it's already been delivered to the client
/// (any new/updated row belonging to it advances the aggregate), letting it
/// jump back in front of the cursor and be delivered a second time later in
/// the same walk — with different data. This is the exact failure mode
/// `memories` already solved with `MemoriesCursor::snapshot_at` (see that doc
/// comment below), mirrored here with the same shape/encoding: captured once
/// on the first page and threaded forward unchanged, it binds the whole walk
/// to one point in time so a namespace mutated mid-walk is excluded (via
/// `HAVING MAX(updated_at) <= $snapshot_at`) until a fresh walk starts.
///
/// Combining both fixes has one honest, inherent trade-off, identical to
/// `memories`': a namespace **created** after the walk's `snapshot_at` was
/// captured is *also* excluded by that same `<= $snapshot_at` bound — you
/// cannot simultaneously guarantee "no re-delivery of an already-consumed
/// row" and "immediate same-walk visibility of a row created after the walk
/// began" from one time-based watermark. Such a namespace simply was not
/// part of the snapshot; it surfaces on the client's next fresh walk
/// (`cursor = None`), not the current one — not a regression of the
/// permanent-loss bug this cursor exists to fix, just a "next walk, not this
/// one" deferral.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct NamespacesCursor {
    updated_at: chrono::DateTime<chrono::Utc>,
    namespace: String,
    #[serde(default)]
    snapshot_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `snapshot_at: None` resets the walk boundary — pass `None` when encoding
/// the *terminal* cursor of a walk (alongside `has_more: false`) so the
/// client's next incremental poll (which starts a brand-new walk from that
/// checkpoint) gets a fresh snapshot captured at that later time, instead of
/// permanently reusing the original walk's snapshot forever. See the
/// `has_more`-gated call site in `query_owner_namespaces` and the doc
/// comment on `NamespacesCursor::snapshot_at` below for why an unconditional
/// `Some(snapshot_at)` here would silently freeze incremental sync after the
/// first full walk (a row updated after that walk's snapshot would then
/// never pass `updated_at <= snapshot_at` on any later poll).
fn encode_namespaces_cursor(
    updated_at: chrono::DateTime<chrono::Utc>,
    namespace: &str,
    snapshot_at: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    let json = serde_json::to_vec(&NamespacesCursor {
        updated_at,
        namespace: namespace.to_string(),
        snapshot_at,
    })
    .expect("cursor serializes");
    // Same URL_SAFE_NO_PAD rationale as `encode_cursor` below — this value is
    // echoed back verbatim as `next_cursor` and used in a URL query string.
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
}

fn decode_namespaces_cursor(raw: &str) -> Result<NamespacesCursor, AppError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AppError::BadRequest("invalid cursor".to_string()))?;
    serde_json::from_slice(&bytes).map_err(|_| AppError::BadRequest("invalid cursor".to_string()))
}

/// `updated_after`/`cursor` here is the opaque `next_cursor` a previous call
/// returned (never a raw timestamp or namespace name), mirroring how
/// `memories`' `updated_after` behaves. It is a genuine incremental-sync
/// watermark: rows are ordered and filtered by the rollup's
/// `(MAX(updated_at), namespace)`, so a namespace whose contents changed
/// after the client's last poll comes back even though it was already
/// synced once — see `NamespacesCursor`.
///
/// The recency half of the keyset predicate has to stay in `HAVING`: it
/// filters on `MAX(updated_at)`, an aggregate, which by definition cannot be
/// evaluated before the `GROUP BY`. Note this is the opposite of the usual
/// advice to push a `HAVING` predicate down into `WHERE` (which the previous
/// `HAVING namespace > $2` should have followed, since `namespace` is a
/// grouping key and needs no aggregation): rewriting *this* one as
/// `WHERE updated_at > $cursor` would drop individual *rows* before
/// aggregation, so `memory_count`/`storage_used` would then cover only each
/// namespace's recently-touched subset — wrong totals, not merely a
/// different plan.
pub(crate) async fn query_owner_namespaces(
    pool: &PgPool,
    owner: &str,
    cursor: Option<String>,
    limit: i64,
) -> Result<NamespacesResponse, AppError> {
    let limit = limit.clamp(1, MAX_NAMESPACES_LIMIT);
    let cursor_after = cursor
        .as_deref()
        .map(decode_namespaces_cursor)
        .transpose()?;

    // See the doc comment on `NamespacesCursor::snapshot_at` (mirroring
    // `MemoriesCursor::snapshot_at` below): bind this whole walk to one
    // boundary, captured now on the first page and threaded forward
    // unchanged from the incoming cursor on every later page.
    let (after, snapshot_at) = match cursor_after {
        Some(c) => {
            let snapshot_at = c.snapshot_at.unwrap_or_else(chrono::Utc::now);
            (Some((c.updated_at, c.namespace)), snapshot_at)
        }
        None => (None, chrono::Utc::now()),
    };

    // Peek one row past `limit` to get an explicit has_more signal — a page
    // shorter than `limit` is NOT a reliable "no more data" signal on its
    // own, because `limit` is silently clamped to MAX_NAMESPACES_LIMIT: a
    // caller that asked for more than the cap and got exactly the cap back
    // would otherwise wrongly conclude it was done.
    // Live rollup FULL OUTER JOIN stored watermarks so a namespace whose last
    // row was deleted still resurfaces (WALM-363). Watermark-only rows have
    // memory_count 0.
    const NS_SQL_TAIL: &str = "
        SELECT COALESCE(l.namespace, w.namespace) AS namespace,
               COALESCE(l.memory_count, 0) AS memory_count,
               COALESCE(l.storage_used, 0) AS storage_used,
               GREATEST(l.last_updated_at, w.last_mutated_at) AS last_updated_at
        FROM (
            SELECT namespace,
                   COUNT(*)::BIGINT AS memory_count,
                   COALESCE(SUM(blob_size_bytes), 0)::BIGINT AS storage_used,
                   MAX(updated_at) AS last_updated_at
            FROM vector_entries
            WHERE owner = $1
            GROUP BY namespace
        ) l
        FULL OUTER JOIN (
            SELECT namespace, MAX(deleted_at) AS last_mutated_at
            FROM memory_tombstones
            WHERE owner = $1
            GROUP BY namespace
        ) w ON l.namespace = w.namespace
    ";

    let mut rows: Vec<(String, i64, i64, chrono::DateTime<chrono::Utc>)> = if let Some((
        cursor_updated_at,
        cursor_namespace,
    )) = after.clone()
    {
        let sql = format!(
            "SELECT namespace, memory_count, storage_used, last_updated_at FROM ({NS_SQL_TAIL}) s
                 WHERE (last_updated_at, namespace) > ($2, $3) AND last_updated_at <= $4
                 ORDER BY last_updated_at, namespace
                 LIMIT $5",
        );
        sqlx::query_as(&sql)
            .bind(owner)
            .bind(cursor_updated_at)
            .bind(cursor_namespace)
            .bind(snapshot_at)
            .bind(limit + 1)
            .fetch_all(pool)
            .await
    } else {
        let sql = format!(
            "SELECT namespace, memory_count, storage_used, last_updated_at FROM ({NS_SQL_TAIL}) s
                 WHERE last_updated_at <= $2
                 ORDER BY last_updated_at, namespace
                 LIMIT $3",
        );
        sqlx::query_as(&sql)
            .bind(owner)
            .bind(snapshot_at)
            .bind(limit + 1)
            .fetch_all(pool)
            .await
    }
    .map_err(|e| AppError::Internal(format!("Failed to query namespaces: {}", e)))?;

    let has_more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);

    // Always hand back a watermark built from the LAST ROW EMITTED (never
    // the peeked extra row above), whether or not more pages follow.
    // Returning `None` on the final page left a client that had just
    // finished syncing with no checkpoint to poll from next time — which is
    // the entire point of the cursor.
    // `Some(snapshot_at)` while the walk continues (has_more) so later pages
    // stay bound to the same point-in-time filter; `None` on the terminal
    // page so the client's *next* incremental poll — which starts a new
    // walk from this checkpoint — captures a fresh snapshot instead of
    // reusing this walk's, which would otherwise never advance again (see
    // `encode_namespaces_cursor`'s doc comment).
    //
    // An EMPTY page needs the same reset, not just a populated terminal
    // one. A continuation page (the previous page had
    // `has_more: true`) can come back with zero rows if every remaining row
    // raced past `snapshot_at` between pages — `rows.last()` is `None`
    // either way, so without this branch `next_cursor` collapsed to plain
    // `None` too. Per this API's own contract, an empty page's `None`
    // cursor means "keep whatever cursor you already have" — but the
    // client's already-held cursor is the *previous* page's continuation
    // cursor, which still carries this walk's now-stale `snapshot_at`.
    // That would freeze incremental sync exactly the way the terminal-page
    // case did, just triggered one page later. Fix: an empty page still
    // re-encodes the incoming cursor's own watermark position (no row was
    // consumed, so the position hasn't moved) but always with `snapshot_at`
    // reset — `has_more` is always `false` here (zero rows can never
    // exceed `limit`), so the reset is unconditional. `after` is `None`
    // only when this is the very first page of a walk that found nothing
    // at all, where there is no prior cursor to reset and `None` is still
    // correct.
    let next_cursor = match rows.last() {
        Some((name, _, _, last_updated_at)) => Some(encode_namespaces_cursor(
            *last_updated_at,
            name,
            has_more.then_some(snapshot_at),
        )),
        None => after.map(|(cursor_updated_at, cursor_namespace)| {
            encode_namespaces_cursor(cursor_updated_at, &cursor_namespace, None)
        }),
    };

    let namespaces = rows
        .into_iter()
        .map(
            |(name, memory_count, storage_used, updated_at)| NamespaceSummary {
                id: name.clone(),
                name,
                memory_count,
                storage_used,
                updated_at,
            },
        )
        .collect();

    Ok(NamespacesResponse {
        namespaces,
        next_cursor,
        has_more,
        snapshot_version: SNAPSHOT_VERSION,
    })
}

/// GET /v1/owners/{owner}/namespaces?updated_after=<cursor>&limit=100
pub async fn list_owner_namespaces(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
    Path(path_owner): Path<String>,
    params: MemoriesQuery,
) -> Result<Json<NamespacesResponse>, AppError> {
    if !same_owner(Some(&path_owner), &auth.owner) {
        return Err(AppError::Forbidden("owner mismatch".to_string()));
    }
    let limit = params.limit.unwrap_or(DEFAULT_NAMESPACES_LIMIT);
    if limit < 1 {
        return Err(AppError::BadRequest("limit must be positive".to_string()));
    }
    let result =
        query_owner_namespaces(state.db.pool(), &auth.owner, params.updated_after, limit).await?;
    Ok(Json(result))
}

/// `snapshot_at` binds an entire keyset walk to a single point in time,
/// captured the moment the first page (cursor = `None`) is requested and
/// then threaded forward unchanged through every subsequent page's
/// `next_cursor`. Without it, a row whose `updated_at` is bumped *during*
/// the walk (e.g. an Apalis job retry re-upserting the same `vector_id`,
/// which advances `updated_at` via `ON CONFLICT DO UPDATE ... updated_at =
/// NOW()` in db.rs) can jump past the client's current `(updated_at, id)`
/// cursor position and be handed back a second time later in the same walk.
/// Filtering every page to `updated_at <= snapshot_at` excludes such rows
/// until the client starts a fresh walk (cursor = `None`), trading
/// "sees its own mid-walk updates immediately" for "never sees a duplicate
/// within one walk" — rows updated after the walk began simply won't appear
/// until the next fresh walk picks them up.
///
/// `Option` (not a required field) so a cursor decoded without this field
/// degrades gracefully instead of failing to parse; `query_owner_memories`
/// treats a missing value the same as no cursor at all, i.e. as though a
/// fresh walk boundary were captured right now.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct MemoriesCursor {
    updated_at: chrono::DateTime<chrono::Utc>,
    id: String,
    #[serde(default)]
    snapshot_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Second keyset for the additive `deleted[]` stream. Absent on v1
    /// cursors: replay up to 30 days of tombstones once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deleted_id: Option<String>,
    /// When this cursor was minted. v1 cursors lack it and must_resync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `snapshot_at: None` resets the walk boundary — see
/// `encode_namespaces_cursor`'s doc comment (the `memories` and
/// `namespaces` cursors share this exact contract): pass `None` only for
/// the terminal cursor of a walk, so the client's next incremental poll
/// gets a fresh snapshot rather than being permanently frozen at the first
/// walk's boundary.
fn encode_cursor(
    updated_at: chrono::DateTime<chrono::Utc>,
    id: &str,
    snapshot_at: Option<chrono::DateTime<chrono::Utc>>,
) -> String {
    encode_cursor_ex(updated_at, id, snapshot_at, None, None)
}

fn encode_cursor_ex(
    updated_at: chrono::DateTime<chrono::Utc>,
    id: &str,
    snapshot_at: Option<chrono::DateTime<chrono::Utc>>,
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    deleted_id: Option<String>,
) -> String {
    let json = serde_json::to_vec(&MemoriesCursor {
        updated_at,
        id: id.to_string(),
        snapshot_at,
        deleted_at,
        deleted_id,
        minted_at: Some(chrono::Utc::now()),
    })
    .expect("cursor serializes");
    // URL_SAFE_NO_PAD (not STANDARD): next_cursor is used verbatim in a URL
    // query string per the contract doc. STANDARD emits `+`, `/`, `=`, which
    // corrupt or require percent-encoding most clients won't apply.
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
}

fn decode_cursor(raw: &str) -> Result<MemoriesCursor, AppError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| AppError::BadRequest("invalid cursor".to_string()))?;
    serde_json::from_slice(&bytes).map_err(|_| AppError::BadRequest("invalid cursor".to_string()))
}

const DEFAULT_MEMORIES_LIMIT: i64 = 100;
const MAX_MEMORIES_LIMIT: i64 = 500;

pub(crate) async fn query_owner_memories(
    pool: &PgPool,
    owner: &str,
    cursor: Option<String>,
    limit: i64,
) -> Result<MemoriesResponse, AppError> {
    let limit = limit.clamp(1, MAX_MEMORIES_LIMIT);
    let now = chrono::Utc::now();
    let retention_cut = now - TOMBSTONE_RETENTION;

    let decoded = match cursor.as_deref() {
        Some(raw) => Some(decode_cursor(raw)?),
        None => None,
    };

    // minted_at is the last-sync clock. v1 cursors lack it and must_resync
    // once. Do not use live updated_at: a quiet account's last live row can
    // be months old while the client polled 5 minutes ago.
    if let Some(c) = decoded.as_ref() {
        let stale_mint = match c.minted_at {
            Some(t) => t < retention_cut,
            None => true,
        };
        // Deliberately NOT keyed off c.deleted_at. minted_at is re-stamped on
        // every cursor we hand out, but deleted_at freezes at the last
        // tombstone the client saw, so a healthy 5-minute poller would trip a
        // full resync 30 days after its last observed deletion. The tombstone
        // query already floors on deleted_at >= retention_cut, so a cursor
        // below the floor is subsumed: nothing is skipped or duplicated.
        if stale_mint {
            return Ok(MemoriesResponse {
                memories: Vec::new(),
                next_cursor: None,
                has_more: false,
                snapshot_version: SNAPSHOT_VERSION,
                deleted: Vec::new(),
                must_resync: true,
            });
        }
    }

    let (after, snapshot_at, deleted_after) = match decoded {
        Some(c) => {
            let snapshot_at = c.snapshot_at.unwrap_or(now);
            let deleted_after = match (c.deleted_at, c.deleted_id) {
                (Some(t), Some(id)) => Some((t, id)),
                _ => None,
            };
            (Some((c.updated_at, c.id)), snapshot_at, deleted_after)
        }
        None => (None, now, None),
    };

    let mut rows: Vec<(
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
        i64,
        Option<String>,
        Option<String>,
        Option<i32>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<f32>,
    )> = if let Some((cursor_updated_at, cursor_id)) = after.clone() {
        sqlx::query_as(
            "SELECT id, namespace, blob_id, created_at, updated_at, blob_size_bytes,
                    agent_id, package_id, end_epoch, expires_at, importance
             FROM vector_entries
             WHERE owner = $1 AND (updated_at, id) > ($2, $3) AND updated_at <= $4
             ORDER BY updated_at, id
             LIMIT $5",
        )
        .bind(owner)
        .bind(cursor_updated_at)
        .bind(cursor_id)
        .bind(snapshot_at)
        .bind(limit + 1)
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as(
            "SELECT id, namespace, blob_id, created_at, updated_at, blob_size_bytes,
                    agent_id, package_id, end_epoch, expires_at, importance
             FROM vector_entries
             WHERE owner = $1 AND updated_at <= $2
             ORDER BY updated_at, id
             LIMIT $3",
        )
        .bind(owner)
        .bind(snapshot_at)
        .bind(limit + 1)
        .fetch_all(pool)
        .await
    }
    .map_err(|e| AppError::Internal(format!("Failed to query memories: {}", e)))?;

    let live_has_more = rows.len() as i64 > limit;
    rows.truncate(limit as usize);

    let tombstone_start = deleted_after
        .as_ref()
        .map(|(t, _)| *t)
        .unwrap_or(retention_cut);

    let mut deleted_rows: Vec<(String, String, chrono::DateTime<chrono::Utc>)> =
        if let Some((d_at, d_id)) = deleted_after.clone() {
            sqlx::query_as(
                "SELECT memory_id, namespace, deleted_at
                 FROM memory_tombstones
                 WHERE owner = $1
                   AND deleted_at >= $2
                   AND (deleted_at, memory_id) > ($3, $4)
                   AND deleted_at <= $5
                 ORDER BY deleted_at, memory_id
                 LIMIT $6",
            )
            .bind(owner)
            .bind(retention_cut)
            .bind(d_at)
            .bind(d_id)
            .bind(snapshot_at)
            .bind(limit + 1)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                "SELECT memory_id, namespace, deleted_at
                 FROM memory_tombstones
                 WHERE owner = $1
                   AND deleted_at >= $2
                   AND deleted_at <= $3
                 ORDER BY deleted_at, memory_id
                 LIMIT $4",
            )
            .bind(owner)
            .bind(tombstone_start)
            .bind(snapshot_at)
            .bind(limit + 1)
            .fetch_all(pool)
            .await
        }
        .map_err(|e| AppError::Internal(format!("Failed to query tombstones: {}", e)))?;

    let deleted_has_more = deleted_rows.len() as i64 > limit;
    deleted_rows.truncate(limit as usize);
    let has_more = live_has_more || deleted_has_more;

    let next_deleted = deleted_rows
        .last()
        .map(|(id, _, t)| (*t, id.clone()))
        .or(deleted_after.clone());

    // Never pin a missing live watermark to snapshot_at: a tombstone-only
    // first page would skip in-flight inserts with updated_at < snapshot_at.
    let live_mark = rows.last().map(|r| (r.4, r.0.clone())).or(after.clone());
    let next_cursor = match live_mark {
        Some((ts, id)) => Some(encode_cursor_ex(
            ts,
            &id,
            has_more.then_some(snapshot_at),
            next_deleted.as_ref().map(|(t, _)| *t),
            next_deleted.as_ref().map(|(_, id)| id.clone()),
        )),
        None if deleted_has_more => Some(encode_cursor_ex(
            chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
            "",
            Some(snapshot_at),
            next_deleted.as_ref().map(|(t, _)| *t),
            next_deleted.as_ref().map(|(_, id)| id.clone()),
        )),
        None => None,
    };

    let memories = rows
        .into_iter()
        .map(
            |(
                id,
                namespace,
                blob_id,
                created_at,
                updated_at,
                size,
                agent_id,
                package_id,
                end_epoch,
                expires_at,
                importance,
            )| MemoryItem {
                memory_id: id,
                namespace_id: namespace,
                blob_id,
                created_at,
                updated_at,
                size,
                agent_id,
                package_id,
                status: match expires_at {
                    Some(exp) if exp < chrono::Utc::now() => "expired".to_string(),
                    _ => "active".to_string(),
                },
                end_epoch,
                expires_at,
                importance,
            },
        )
        .collect();

    let deleted = deleted_rows
        .into_iter()
        .map(|(memory_id, namespace_id, deleted_at)| DeletedMemory {
            memory_id,
            namespace_id,
            deleted_at,
        })
        .collect();

    Ok(MemoriesResponse {
        memories,
        next_cursor,
        has_more,
        snapshot_version: SNAPSHOT_VERSION,
        deleted,
        must_resync: false,
    })
}

#[derive(Debug, serde::Deserialize)]
pub struct MemoriesQuery {
    pub updated_after: Option<String>,
    pub limit: Option<i64>,
}

// A plain `axum::extract::Query<MemoriesQuery>` param would reject an
// unparseable `limit` (e.g. `limit=abc`) with Axum's own default
// QueryRejection — a plain-text 400, not this API's `{"error": ...}`
// JSON envelope, and invisible to `record_app_error` metrics. The
// codebase already has a precedent for exactly this problem
// (`SdQuery<T>` in `services/server/src/security_delete_error.rs`,
// mapping `QueryRejection` to that module's own error type) — this
// mirrors the same idea, mapped to `AppError` instead.
impl<S> axum::extract::FromRequestParts<S> for MemoriesQuery
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        axum::extract::Query::<MemoriesQuery>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(q)| q)
            .map_err(|_| AppError::BadRequest("invalid query parameters".to_string()))
    }
}

/// GET /v1/owners/{owner}/memories?updated_after=<cursor>&limit=100
pub async fn list_owner_memories(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
    Path(path_owner): Path<String>,
    params: MemoriesQuery,
) -> Result<Json<MemoriesResponse>, AppError> {
    if !same_owner(Some(&path_owner), &auth.owner) {
        return Err(AppError::Forbidden("owner mismatch".to_string()));
    }
    let limit = params.limit.unwrap_or(DEFAULT_MEMORIES_LIMIT);
    if limit < 1 {
        return Err(AppError::BadRequest("limit must be positive".to_string()));
    }
    let result =
        query_owner_memories(state.db.pool(), &auth.owner, params.updated_after, limit).await?;
    Ok(Json(result))
}

#[derive(Debug, Serialize)]
pub struct DelegateKeyResponse {
    pub label: String,
    pub sui_address: String,
}

#[derive(Debug, Serialize)]
pub struct AgentsResponse {
    pub agents: Vec<DelegateKeyResponse>,
    pub snapshot_version: u32,
}

/// GET /v1/owners/{owner}/agents
pub async fn list_owner_agents(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthInfo>,
    Path(path_owner): Path<String>,
) -> Result<Json<AgentsResponse>, AppError> {
    if !same_owner(Some(&path_owner), &auth.owner) {
        return Err(AppError::Forbidden("owner mismatch".to_string()));
    }
    // Short-TTL cached read, following the same caching pattern as
    // `walrus_epoch()` rather than being left uncached — repeated /agents
    // calls for the same account within the TTL window don't re-hit the
    // chain.
    let keys = crate::storage::sui::list_delegate_keys_cached(
        &state.delegate_keys_cache,
        &state.http_client,
        &state.config.sui_rpc_url,
        state.sui_grpc_client.as_ref(),
        &auth.account_id,
        &state.config.package_id,
    )
    .await
    .map_err(|e| AppError::Internal(format!("Failed to list delegate keys: {}", e)))?;

    let agents = keys
        .into_iter()
        .map(|k| DelegateKeyResponse {
            label: k.label,
            sui_address: k.sui_address,
        })
        .collect();

    Ok(Json(AgentsResponse {
        agents,
        snapshot_version: SNAPSHOT_VERSION,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::VectorDb;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::OnceLock;

    // Guards concurrent test threads in THIS module from racing on
    // `CREATE EXTENSION IF NOT EXISTS vector` (001_init.sql) — Postgres
    // does not make that statement safe under concurrent execution
    // despite IF NOT EXISTS (two sessions can both pass the existence
    // check before either commits, then collide on the unique index on
    // pg_extension). Mirrors the same pattern already used in
    // `services/server/src/jobs.rs` (`DB_SETUP_LOCK`) and
    // `services/server/src/storage/db.rs` (`VECTOR_SCHEMA_SETUP_LOCK`).
    static DB_SETUP_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

    fn test_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://memwal:memwal_secret@localhost:5432/memwal".into())
    }

    async fn test_pool() -> PgPool {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&test_database_url())
            .await
            .unwrap();
        let _guard = DB_SETUP_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        for migration in [
            include_str!("../../migrations/001_init.sql"),
            include_str!("../../migrations/002_add_namespace.sql"),
            include_str!("../../migrations/003_rate_limiter.sql"),
            include_str!("../../migrations/008_benchmark_plaintext.sql"),
            include_str!("../../migrations/009_importance_signal.sql"),
            include_str!("../../migrations/014_memory_read_api_columns.sql"),
            include_str!("../../migrations/015_memory_read_api_updated_at_not_null.sql"),
            include_str!("../../migrations/016_memory_read_api_index.sql"),
            include_str!("../../migrations/017_memory_expiry_columns.sql"),
            include_str!("../../migrations/018_memory_expiry_synced_at_index.sql"),
            include_str!("../../migrations/019_memory_read_api_updated_at_set_not_null.sql"),
            include_str!("../../migrations/020_read_api_followups.sql"),
        ] {
            sqlx::raw_sql(migration).execute(&pool).await.unwrap();
        }
        pool
    }

    /// `next_cursor` is used verbatim in a URL query string per the contract
    /// doc (`?updated_after=<cursor>`) — it must never contain `+`, `/`, or
    /// `=`, which `base64::engine::general_purpose::STANDARD` emits and most
    /// clients won't percent-encode automatically. Search over ids/timestamps
    /// until we find a byte sequence that STANDARD would have encoded with at
    /// least one of those characters, then assert our actual `encode_cursor`
    /// (URL_SAFE_NO_PAD) output round-trips through `decode_cursor` and is
    /// clean of all three.
    #[test]
    fn encode_cursor_is_url_safe_and_round_trips() {
        use base64::Engine as _;

        let mut found_standard_unsafe_case = false;
        for i in 0..500 {
            let id = format!("memory-id-{i}-{}", uuid::Uuid::new_v4());
            let updated_at =
                chrono::DateTime::from_timestamp(1_700_000_000 + i, (i as u32) * 137).unwrap();
            let snapshot_at =
                chrono::DateTime::from_timestamp(1_700_000_100 + i, (i as u32) * 251).unwrap();

            // Sanity check: prove this fixture would have been unsafe under
            // the old STANDARD engine, so the test is actually exercising the
            // bug, not just trivially passing on inputs that never collide.
            let json = serde_json::to_vec(&MemoriesCursor {
                updated_at,
                id: id.clone(),
                snapshot_at: Some(snapshot_at),
                deleted_at: None,
                deleted_id: None,
                minted_at: None,
            })
            .expect("cursor serializes");
            let standard_encoded = base64::engine::general_purpose::STANDARD.encode(&json);
            if standard_encoded.contains('+')
                || standard_encoded.contains('/')
                || standard_encoded.contains('=')
            {
                found_standard_unsafe_case = true;
            }

            let encoded = encode_cursor(updated_at, &id, Some(snapshot_at));
            assert!(
                !encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='),
                "encoded cursor must be URL-safe with no padding, got: {}",
                encoded
            );

            let decoded = decode_cursor(&encoded).expect("round-trips");
            assert_eq!(decoded.id, id);
            assert_eq!(decoded.updated_at, updated_at);
            assert_eq!(decoded.snapshot_at, Some(snapshot_at));
        }

        assert!(
            found_standard_unsafe_case,
            "fixture sweep never produced a STANDARD-unsafe cursor — test would not \
             have caught the regression this fix addresses"
        );
    }

    /// A client that polls inside the retention window must never be told to
    /// resync, no matter how old the last deletion it saw is. minted_at is
    /// re-stamped on every cursor; deleted_at freezes when nothing new is
    /// deleted, so keying the check off deleted_at forced a full replay on
    /// healthy pollers 30 days after their last observed deletion.
    #[tokio::test]
    async fn fresh_cursor_with_an_ancient_tombstone_mark_does_not_force_resync() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());
        seed_entry(&pool, &owner, "live", "notes", 100, ts(0)).await;

        let now = chrono::Utc::now();
        let json = serde_json::to_vec(&MemoriesCursor {
            updated_at: ts(0),
            id: "memory-live".to_string(),
            snapshot_at: None,
            // older than TOMBSTONE_RETENTION, but the client is up to date
            deleted_at: Some(now - chrono::Duration::days(45)),
            deleted_id: Some("long-gone".to_string()),
            minted_at: Some(now),
        })
        .expect("cursor serializes");
        let cursor = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json);

        let res = query_owner_memories(&pool, &owner, Some(cursor), 100)
            .await
            .unwrap();
        assert!(
            !res.must_resync,
            "a cursor minted just now must not trigger must_resync because the last \
             tombstone it saw fell out of retention"
        );

        cleanup(&pool, &owner).await;
    }

    /// The other half: a client that really has been away past retention must
    /// still be told to resync, because its tombstones have been swept.
    #[tokio::test]
    async fn stale_minted_at_still_forces_resync() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());
        seed_entry(&pool, &owner, "live", "notes", 100, ts(0)).await;

        let json = serde_json::to_vec(&MemoriesCursor {
            updated_at: ts(0),
            id: "memory-live".to_string(),
            snapshot_at: None,
            deleted_at: None,
            deleted_id: None,
            minted_at: Some(chrono::Utc::now() - chrono::Duration::days(45)),
        })
        .expect("cursor serializes");
        let cursor = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json);

        let res = query_owner_memories(&pool, &owner, Some(cursor), 100)
            .await
            .unwrap();
        assert!(
            res.must_resync,
            "a cursor older than retention must force a resync"
        );
        assert!(res.memories.is_empty());
        assert!(res.next_cursor.is_none());

        cleanup(&pool, &owner).await;
    }

    fn ts(offset_secs: i64) -> chrono::DateTime<chrono::Utc> {
        // Whole seconds only: Postgres `timestamptz` keeps microseconds, so a
        // sub-microsecond chrono value would not survive the round trip and
        // exact-equality assertions below would be flaky.
        chrono::DateTime::from_timestamp(1_700_000_000 + offset_secs, 0).unwrap()
    }

    async fn seed_entry(
        pool: &PgPool,
        owner: &str,
        id: &str,
        namespace: &str,
        size: i64,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) {
        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(format!("{}-{}", owner, id))
        .bind(owner)
        .bind(namespace)
        .bind(format!("blob-{}", id))
        .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
        .bind(size)
        .bind(updated_at)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn cleanup(pool: &PgPool, owner: &str) {
        let _ = sqlx::query("DELETE FROM memory_tombstones WHERE owner = $1")
            .bind(owner)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(owner)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn query_owner_namespaces_rolls_up_counts_bytes_and_max_updated_at() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        // `work`'s two rows deliberately straddle `personal`'s single row in
        // time, so `updated_at` on the summary can only be right if it is the
        // group's MAX (not its first, last-inserted, or min row).
        seed_entry(&pool, &owner, "m1", "work", 100, ts(0)).await;
        seed_entry(&pool, &owner, "m3", "personal", 50, ts(60)).await;
        seed_entry(&pool, &owner, "m2", "work", 200, ts(120)).await;

        let result = query_owner_namespaces(&pool, &owner, None, 100)
            .await
            .unwrap();

        // Emission order is the keyset order — (MAX(updated_at), namespace) —
        // so `personal` (t+60) precedes `work` (t+120) despite sorting after
        // it alphabetically.
        assert_eq!(
            result
                .namespaces
                .iter()
                .map(|n| n.name.as_str())
                .collect::<Vec<_>>(),
            vec!["personal", "work"],
        );

        let mut sorted = result.namespaces;
        sorted.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(sorted.len(), 2);
        assert_eq!(sorted[0].name, "personal");
        assert_eq!(sorted[0].memory_count, 1);
        assert_eq!(sorted[0].storage_used, 50);
        assert_eq!(sorted[0].updated_at, ts(60));
        assert_eq!(sorted[1].name, "work");
        assert_eq!(sorted[1].memory_count, 2);
        assert_eq!(sorted[1].storage_used, 300);
        assert_eq!(
            sorted[1].updated_at,
            ts(120),
            "namespace updated_at must be MAX(updated_at) over the group"
        );

        // A result that fits in one page is exactly the case that most needs a
        // checkpoint: the client is caught up and its next poll has nothing
        // else to anchor on.
        let cursor = result
            .next_cursor
            .expect("a non-empty page must always hand back a watermark");
        let decoded = decode_namespaces_cursor(&cursor).unwrap();
        assert_eq!(decoded.namespace, "work");
        assert_eq!(decoded.updated_at, ts(120));

        cleanup(&pool, &owner).await;
    }

    #[tokio::test]
    async fn deleting_the_watermark_row_still_resurfaces_the_namespace() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());
        seed_entry(&pool, &owner, "keep", "notes", 100, ts(0)).await;
        seed_entry(&pool, &owner, "gone", "notes", 200, ts(120)).await;

        let before = query_owner_namespaces(&pool, &owner, None, 100)
            .await
            .unwrap();
        assert_eq!(before.namespaces[0].memory_count, 2);
        let cursor = before.next_cursor.clone().unwrap();

        let deleted = VectorDb::from_pool(pool.clone())
            .delete_by_blob_id(&format!("blob-gone"), &owner, "notes")
            .await
            .unwrap();
        assert_eq!(deleted, 1);

        let after = query_owner_namespaces(&pool, &owner, Some(cursor.clone()), 100)
            .await
            .unwrap();
        assert_eq!(
            after.namespaces.len(),
            1,
            "deleted watermark must still resurface"
        );
        assert_eq!(after.namespaces[0].memory_count, 1);
        assert!(after.namespaces[0].updated_at > ts(120));

        let memories = query_owner_memories(&pool, &owner, None, 100)
            .await
            .unwrap();
        assert!(
            memories
                .memories
                .iter()
                .all(|m| !m.memory_id.ends_with("-gone")),
            "deleted row must not appear in memories[]",
        );
        assert!(
            memories
                .deleted
                .iter()
                .any(|d| d.memory_id.ends_with("-gone")),
            "deleted[] missing tombstone: {:?}",
            memories.deleted,
        );
        assert!(!memories.must_resync);

        VectorDb::from_pool(pool.clone())
            .delete_by_blob_id(&format!("blob-keep"), &owner, "notes")
            .await
            .unwrap();
        let empty = query_owner_namespaces(&pool, &owner, Some(cursor), 100)
            .await
            .unwrap();
        assert_eq!(empty.namespaces.len(), 1);
        assert_eq!(empty.namespaces[0].memory_count, 0);

        cleanup(&pool, &owner).await;
    }

    /// The bug this whole cursor redesign exists for: under the old
    /// namespace-name cursor (`ORDER BY namespace` / `HAVING namespace >
    /// $cursor`), a namespace that sorts *before* the cursor could never be
    /// returned again — so a later write that changed its rollup was
    /// invisible to a polling client forever. Here `alpha` sorts before the
    /// cursor's `zulu` but is updated after the cursor's watermark, and must
    /// come back. A regression test that only checked ordering/no-duplicates
    /// would pass against the old buggy code.
    #[tokio::test]
    async fn query_owner_namespaces_cursor_resurfaces_earlier_name_updated_after_watermark() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        seed_entry(&pool, &owner, "a1", "alpha", 10, ts(0)).await;
        seed_entry(&pool, &owner, "z1", "zulu", 20, ts(60)).await;

        // First sync: client sees both, checkpoints at (t+60, "zulu").
        let first = query_owner_namespaces(&pool, &owner, None, 100)
            .await
            .unwrap();
        assert_eq!(
            first
                .namespaces
                .iter()
                .map(|n| n.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "zulu"],
        );
        let watermark = first.next_cursor.expect("first page must checkpoint");
        assert_eq!(
            decode_namespaces_cursor(&watermark).unwrap().namespace,
            "zulu"
        );

        // Now `alpha` — already synced, and alphabetically *before* the
        // cursor's namespace — grows a second memory after that checkpoint.
        seed_entry(&pool, &owner, "a2", "alpha", 90, ts(120)).await;

        let second = query_owner_namespaces(&pool, &owner, Some(watermark), 100)
            .await
            .unwrap();

        assert_eq!(
            second
                .namespaces
                .iter()
                .map(|n| n.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha"],
            "a namespace changed after the watermark must reappear even though \
             its name sorts before the cursor's; unchanged namespaces must not"
        );
        assert_eq!(second.namespaces[0].memory_count, 2);
        assert_eq!(second.namespaces[0].storage_used, 100);
        assert_eq!(second.namespaces[0].updated_at, ts(120));

        let next = second
            .next_cursor
            .expect("the follow-up page must checkpoint too");
        let decoded = decode_namespaces_cursor(&next).unwrap();
        assert_eq!(decoded.namespace, "alpha");
        assert_eq!(decoded.updated_at, ts(120));

        // And polling from that fresh watermark with nothing else changed
        // yields an empty page. That page still returns a cursor (the same
        // watermark position, snapshot_at reset) rather than None, so the
        // next poll doesn't inherit a stale pinned snapshot — see
        // query_owner_namespaces_empty_continuation_page_resets_snapshot.
        let third = query_owner_namespaces(&pool, &owner, Some(next), 100)
            .await
            .unwrap();
        assert!(third.namespaces.is_empty());
        let reset_cursor = third
            .next_cursor
            .expect("an empty page reached via a real cursor must still return one");
        assert_eq!(
            decode_namespaces_cursor(&reset_cursor).unwrap().snapshot_at,
            None
        );

        cleanup(&pool, &owner).await;
    }

    #[test]
    fn encode_namespaces_cursor_is_url_safe_and_round_trips() {
        for i in 0..200 {
            let namespace = format!("ns/{i}+{}", uuid::Uuid::new_v4());
            let updated_at =
                chrono::DateTime::from_timestamp(1_700_000_000 + i, (i as u32) * 137).unwrap();
            let snapshot_at = chrono::DateTime::from_timestamp(1_700_000_100 + i, 0).unwrap();

            let encoded = encode_namespaces_cursor(updated_at, &namespace, Some(snapshot_at));
            assert!(
                !encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='),
                "encoded cursor must be URL-safe with no padding, got: {}",
                encoded
            );

            let decoded = decode_namespaces_cursor(&encoded).expect("round-trips");
            assert_eq!(decoded.namespace, namespace);
            assert_eq!(decoded.snapshot_at, Some(snapshot_at));
            assert_eq!(decoded.updated_at, updated_at);
        }

        // A v1 cursor (bare base64 of the namespace name) is not a v2 cursor —
        // hence the SNAPSHOT_VERSION bump. It must be rejected as a 400, never
        // silently mis-decoded.
        let v1_cursor = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"work");
        assert!(matches!(
            decode_namespaces_cursor(&v1_cursor),
            Err(AppError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn query_owner_namespaces_empty_for_unknown_owner() {
        let pool = test_pool().await;
        let result = query_owner_namespaces(&pool, "0xnobody-here", None, 100)
            .await
            .unwrap();
        assert!(result.namespaces.is_empty());
        assert!(result.next_cursor.is_none());
    }

    /// Mirrors `query_owner_memories_paginates_by_updated_at_and_id`'s style:
    /// seed multiple namespaces for one owner, walk them with a small limit
    /// using the `(MAX(updated_at), namespace)` keyset cursor, and assert
    /// the union of all pages equals the full set exactly once (no gaps, no
    /// duplicates). Update times are deliberately scrambled relative to name
    /// order so the expected sequence is the recency order, not the
    /// alphabetical one.
    #[tokio::test]
    async fn query_owner_namespaces_paginates_by_updated_at_and_namespace_cursor() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        for (ns, offset) in [
            ("alpha", 40),
            ("bravo", 10),
            ("charlie", 50),
            ("delta", 20),
            ("echo", 30),
        ] {
            seed_entry(&pool, &owner, ns, ns, 10, ts(offset)).await;
        }

        let mut all_names: Vec<String> = Vec::new();
        let mut cursor = None;
        // Bounded: with an always-present watermark the traversal now ends on
        // an empty page, so an unbounded `while cursor.is_some()` would spin
        // forever if the keyset predicate ever stopped advancing.
        for _ in 0..10 {
            let page = query_owner_namespaces(&pool, &owner, cursor.clone(), 2)
                .await
                .unwrap();
            assert!(page.namespaces.len() <= 2);
            if page.namespaces.is_empty() {
                // An empty page reached from a real incoming cursor still
                // returns that cursor's own position with snapshot_at
                // reset (not None) — see
                // query_owner_namespaces_empty_continuation_page_resets_snapshot.
                // This walk always seeds data, so the terminating empty
                // page here is reached with `cursor.is_some()`.
                let reset_cursor = page
                    .next_cursor
                    .expect("an empty page reached via a real cursor must still return one");
                assert_eq!(
                    decode_namespaces_cursor(&reset_cursor).unwrap().snapshot_at,
                    None,
                    "the empty page's cursor must have snapshot_at reset"
                );
                break;
            }
            all_names.extend(page.namespaces.iter().map(|n| n.name.clone()));
            cursor = Some(
                page.next_cursor
                    .expect("every non-empty page must hand back a watermark"),
            );
        }

        assert_eq!(
            all_names,
            vec!["bravo", "delta", "echo", "alpha", "charlie"],
            "pages must follow (MAX(updated_at), namespace) order with no gaps \
             or duplicates"
        );

        cleanup(&pool, &owner).await;
    }

    /// Bug 2 for `/namespaces`, isolated: a page that exactly fills `limit`
    /// (so the old `has_more` peek would have said "no more") still has to
    /// return the watermark, and re-polling from it yields the empty page.
    #[tokio::test]
    async fn query_owner_namespaces_exactly_fitting_page_still_returns_watermark() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        seed_entry(&pool, &owner, "n1", "one", 10, ts(0)).await;
        seed_entry(&pool, &owner, "n2", "two", 10, ts(60)).await;

        let page = query_owner_namespaces(&pool, &owner, None, 2)
            .await
            .unwrap();
        assert_eq!(page.namespaces.len(), 2);
        let cursor = page
            .next_cursor
            .expect("an exactly-full final page must still checkpoint the client");
        assert_eq!(decode_namespaces_cursor(&cursor).unwrap().namespace, "two");

        let empty = query_owner_namespaces(&pool, &owner, Some(cursor), 2)
            .await
            .unwrap();
        assert!(empty.namespaces.is_empty());
        // Still returns a cursor (same watermark, snapshot_at reset), not
        // None — see
        // query_owner_namespaces_empty_continuation_page_resets_snapshot.
        let reset_cursor = empty
            .next_cursor
            .expect("an empty page reached via a real cursor must still return one");
        assert_eq!(
            decode_namespaces_cursor(&reset_cursor).unwrap().snapshot_at,
            None
        );

        cleanup(&pool, &owner).await;
    }

    /// Reproduces a real bug found in review: `limit` is silently clamped
    /// to `MAX_NAMESPACES_LIMIT` (500), so a caller asking for more than
    /// that gets exactly 500 rows back — a page SHORTER than the `limit`
    /// it requested, which a client using "short page = done" as its only
    /// signal would wrongly treat as end-of-data even though a 501st
    /// namespace exists. `has_more` must say `true` here.
    #[tokio::test]
    async fn query_owner_namespaces_has_more_true_when_limit_is_clamped() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        for i in 0..(MAX_NAMESPACES_LIMIT + 1) {
            seed_entry(
                &pool,
                &owner,
                &format!("n{i}"),
                &format!("ns-{i:04}"),
                10,
                ts(i),
            )
            .await;
        }

        let page = query_owner_namespaces(&pool, &owner, None, 10_000)
            .await
            .unwrap();
        assert_eq!(
            page.namespaces.len(),
            MAX_NAMESPACES_LIMIT as usize,
            "limit=10000 must be clamped to MAX_NAMESPACES_LIMIT"
        );
        assert!(
            page.has_more,
            "a clamped-short page must still report has_more=true — page length alone is not a reliable end-of-data signal"
        );
        assert!(page.next_cursor.is_some());

        cleanup(&pool, &owner).await;
    }

    /// Regression test for the namespace-keyset drop bug, and for the
    /// `snapshot_at` trade-off documented on `NamespaceCursor` above: a
    /// namespace created *after* the walk began but sorting lexicographically
    /// *before* everything already consumed must not be **permanently** lost
    /// the way the old `HAVING namespace > $cursor` scheme could lose it
    /// (that scheme could skip it for every future walk too, since a name
    /// that never satisfies `namespace > <already-consumed name>` stays
    /// skipped no matter how many more pages or fresh walks follow). Under
    /// the current `(MAX(updated_at), namespace)` + `snapshot_at` cursor, a
    /// namespace created with a *real* (not artificially backdated) timestamp
    /// after `snapshot_at` was captured is excluded from *this* walk — that's
    /// the documented, intentional trade-off, identical to how `memories`
    /// already behaves — but must reliably surface on the *next fresh walk*
    /// (`cursor = None`). This test uses the database's own `NOW()` for the
    /// mid-walk insert rather than a hand-set backdated timestamp specifically
    /// so it can't pass for the wrong reason.
    #[tokio::test]
    async fn query_owner_namespaces_surfaces_namespace_created_mid_walk_on_next_walk() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        // Seed "bravo" and "charlie" with explicit, ordered `updated_at`
        // values so the first page is deterministic.
        let base = chrono::Utc::now() - chrono::Duration::seconds(60);
        for (ns, offset) in [("bravo", 0), ("charlie", 1)] {
            sqlx::query(
                "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(format!("{}-{}", owner, ns))
            .bind(&owner)
            .bind(ns)
            .bind(format!("blob-{}", ns))
            .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .bind(10_i64)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
                .bind(base + chrono::Duration::seconds(offset))
                .bind(format!("{}-{}", owner, ns))
                .execute(&pool)
                .await
                .unwrap();
        }

        // First page: smallest MAX(updated_at) wins, so "bravo" alone. This
        // also captures `snapshot_at` (~now) into the returned cursor.
        let page1 = query_owner_namespaces(&pool, &owner, None, 1)
            .await
            .unwrap();
        assert_eq!(page1.namespaces.len(), 1);
        assert_eq!(page1.namespaces[0].name, "bravo");
        let cursor1 = page1.next_cursor.clone().expect("more pages remain");

        // Now a namespace named "alpha" is created for real — sorts before
        // both "bravo" and "charlie" alphabetically, and, critically, is
        // inserted with the column's DEFAULT NOW() (no manual timestamp), so
        // its `updated_at` genuinely lands after `snapshot_at` was captured
        // above, exactly like a real concurrent write would.
        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
             VALUES ($1, $2, 'alpha', $3, $4, $5)",
        )
        .bind(format!("{}-alpha", owner))
        .bind(&owner)
        .bind("blob-alpha")
        .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
        .bind(10_i64)
        .execute(&pool)
        .await
        .unwrap();

        // Drain the rest of THIS walk from cursor1: "alpha" must NOT appear
        // here — it postdates the walk's snapshot_at, so it's out of scope
        // for this walk by design, not dropped by a bug.
        let page2 = query_owner_namespaces(&pool, &owner, Some(cursor1), 10)
            .await
            .unwrap();
        let page2_names: Vec<String> = page2.namespaces.iter().map(|n| n.name.clone()).collect();
        assert_eq!(
            page2_names,
            vec!["charlie"],
            "a namespace created after snapshot_at must be excluded from THIS walk \
             (same trade-off memories already documents), got {:?}",
            page2_names
        );
        // `has_more` (not `next_cursor`'s nullity) is the authoritative
        // end-of-data signal: `next_cursor` is always populated for a
        // non-empty page, including the last one, so callers have a
        // checkpoint to resume from — see `query_owner_namespaces`'s cursor
        // doc comment.
        assert!(!page2.has_more, "walk must terminate");

        // The terminal cursor (has_more: false) must have its snapshot_at
        // reset to None — this is the actual mechanism the fix relies on:
        // a real incremental-sync client polls again with THIS cursor, not
        // with None, so if snapshot_at survived here the next poll would be
        // permanently frozen at this walk's boundary.
        let terminal_cursor = page2
            .next_cursor
            .clone()
            .expect("terminal page still checkpoints");
        assert_eq!(
            decode_namespaces_cursor(&terminal_cursor)
                .unwrap()
                .snapshot_at,
            None,
            "terminal cursor must reset snapshot_at so the next poll captures a fresh one"
        );

        // The realistic incremental-sync client behavior: poll again using
        // the terminal cursor from the previous walk (never `None` — a real
        // client never "starts over"). This must now see "alpha", proving
        // the fix, not just that a from-scratch resync would eventually see
        // it (which the old, broken code also satisfied trivially).
        let next_poll = query_owner_namespaces(&pool, &owner, Some(terminal_cursor), 10)
            .await
            .unwrap();
        let next_poll_names: Vec<String> = next_poll
            .namespaces
            .iter()
            .map(|n| n.name.clone())
            .collect();
        assert_eq!(
            next_poll_names,
            vec!["alpha"],
            "an incremental poll using the previous walk's terminal cursor must surface a \
             namespace created after that walk's snapshot, got {:?}",
            next_poll_names
        );

        // A fresh walk (cursor = None) is a new snapshot and must also pick
        // up "alpha" — the from-scratch-resync case.
        let fresh = query_owner_namespaces(&pool, &owner, None, 10)
            .await
            .unwrap();
        let mut fresh_names: Vec<String> =
            fresh.namespaces.iter().map(|n| n.name.clone()).collect();
        fresh_names.sort();
        assert_eq!(
            fresh_names,
            vec!["alpha", "bravo", "charlie"],
            "a fresh walk must see the namespace created during the previous walk, got {:?}",
            fresh_names
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(&pool)
            .await;
    }

    /// The terminal-cursor reset above only fires when the terminal page
    /// still has rows. If a
    /// *continuation* page (the previous page had `has_more: true`) comes
    /// back with zero rows — because every row that would have appeared
    /// raced past `snapshot_at` between pages — `rows.last()` is `None`,
    /// so `next_cursor` collapsed to plain `None` too. Per this API's own
    /// contract an empty page's `None` cursor means "keep the cursor you
    /// already have" — but the client's already-held cursor is the
    /// *previous* page's continuation cursor, which still carries this
    /// walk's now-stale `snapshot_at`, freezing sync exactly like the
    /// terminal-page bug did, just one page later.
    ///
    /// Seeds "alpha" (delivered on page 1) and "bravo" (peeked, giving page
    /// 1 `has_more: true`), then bumps bravo's `updated_at` past page 1's
    /// snapshot before requesting page 2 — so page 2 legitimately has zero
    /// rows to return.
    #[tokio::test]
    async fn query_owner_namespaces_empty_continuation_page_resets_snapshot() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        let base = chrono::Utc::now() - chrono::Duration::seconds(60);
        for (ns, offset) in [("alpha", 0), ("bravo", 1)] {
            sqlx::query(
                "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(format!("{}-{}", owner, ns))
            .bind(&owner)
            .bind(ns)
            .bind(format!("blob-{}", ns))
            .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .bind(10_i64)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
                .bind(base + chrono::Duration::seconds(offset))
                .bind(format!("{}-{}", owner, ns))
                .execute(&pool)
                .await
                .unwrap();
        }

        // Page 1: delivers "alpha", peeks "bravo" -> has_more: true. Its
        // cursor keeps snapshot_at pinned (continuation, not terminal).
        let page1 = query_owner_namespaces(&pool, &owner, None, 1)
            .await
            .unwrap();
        assert_eq!(page1.namespaces.len(), 1);
        assert_eq!(page1.namespaces[0].name, "alpha");
        assert!(page1.has_more, "bravo must still be pending");
        let cursor1 = page1.next_cursor.clone().expect("continuation checkpoint");
        assert!(
            decode_namespaces_cursor(&cursor1)
                .unwrap()
                .snapshot_at
                .is_some(),
            "a continuation cursor (has_more: true) must keep snapshot_at pinned"
        );

        // Race "bravo" past page 1's snapshot before page 2 is requested —
        // the exact scenario this test guards against.
        let snapshot_at = decode_namespaces_cursor(&cursor1)
            .unwrap()
            .snapshot_at
            .unwrap();
        sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
            .bind(snapshot_at + chrono::Duration::microseconds(1))
            .bind(format!("{}-bravo", owner))
            .execute(&pool)
            .await
            .unwrap();

        // Page 2 legitimately has zero rows: "bravo" is excluded by the
        // still-pinned snapshot, and there is nothing else left.
        let page2 = query_owner_namespaces(&pool, &owner, Some(cursor1), 10)
            .await
            .unwrap();
        assert!(
            page2.namespaces.is_empty(),
            "bravo must be excluded from this walk"
        );
        assert!(!page2.has_more, "nothing else remains in this walk");

        // The actual fix: even though page 2 is empty, it must still return
        // a real cursor (not None) with snapshot_at reset — not the bare
        // `None` the old code produced, which would have left the client
        // holding page 1's still-pinned continuation cursor forever.
        let page2_cursor = page2
            .next_cursor
            .clone()
            .expect("an empty continuation page must still return a reset cursor, not None");
        assert_eq!(
            decode_namespaces_cursor(&page2_cursor).unwrap().snapshot_at,
            None,
            "the empty page's cursor must reset snapshot_at so the next poll is fresh"
        );

        // Polling again with that reset cursor must now see "bravo".
        let page3 = query_owner_namespaces(&pool, &owner, Some(page2_cursor), 10)
            .await
            .unwrap();
        let page3_names: Vec<String> = page3.namespaces.iter().map(|n| n.name.clone()).collect();
        assert_eq!(
            page3_names,
            vec!["bravo"],
            "a poll using the reset cursor from an empty continuation page must surface the \
             row that raced past the previous snapshot, got {:?}",
            page3_names
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(&pool)
            .await;
    }

    /// Regression test for the namespace snapshot-boundary fix: because
    /// `MAX(updated_at)` for a namespace can advance after that namespace
    /// has already been delivered to the client (any new/updated row
    /// belonging to it bumps the aggregate), an unbounded `(MAX(updated_at),
    /// namespace)` cursor lets an already-delivered namespace jump back in
    /// front of the cursor and be delivered a second time later in the same
    /// walk — with different data. Mirrors
    /// `query_owner_memories_excludes_rows_updated_mid_walk`: seed two
    /// namespaces, drain page 1 (delivers "bravo"), mutate the
    /// already-delivered "bravo" namespace mid-walk, request page 2, and
    /// assert "bravo" is NOT re-delivered within this walk.
    #[tokio::test]
    async fn query_owner_namespaces_excludes_namespace_updated_mid_walk() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        // Seed "bravo" and "charlie" with explicit, ordered `updated_at`
        // values so the first page is deterministic.
        let base = chrono::Utc::now() - chrono::Duration::seconds(60);
        for (ns, offset) in [("bravo", 0), ("charlie", 1)] {
            sqlx::query(
                "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(format!("{}-{}", owner, ns))
            .bind(&owner)
            .bind(ns)
            .bind(format!("blob-{}", ns))
            .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .bind(10_i64)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
                .bind(base + chrono::Duration::seconds(offset))
                .bind(format!("{}-{}", owner, ns))
                .execute(&pool)
                .await
                .unwrap();
        }

        // Page 1 starts the walk, captures `snapshot_at` (~now, well after
        // `base`) into its `next_cursor`, and delivers "bravo" (smallest
        // MAX(updated_at)).
        let page1 = query_owner_namespaces(&pool, &owner, None, 1)
            .await
            .unwrap();
        assert_eq!(page1.namespaces.len(), 1);
        assert_eq!(page1.namespaces[0].name, "bravo");
        assert_eq!(page1.namespaces[0].memory_count, 1);
        let cursor1 = page1.next_cursor.clone().expect("more pages remain");
        let snapshot_at = decode_namespaces_cursor(&cursor1)
            .unwrap()
            .snapshot_at
            .unwrap();

        // Mutate the already-delivered "bravo" namespace mid-walk: insert a
        // new row into it, with `updated_at` explicitly placed just past the
        // walk's snapshot boundary (mirrors the Apalis-retry scenario in
        // `query_owner_memories_excludes_rows_updated_mid_walk` — an
        // already-consumed row/namespace mutated after the walk began).
        // This bumps `MAX(updated_at)` for "bravo" past `snapshot_at` and
        // changes its `memory_count`.
        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
             VALUES ($1, $2, 'bravo', $3, $4, $5)",
        )
        .bind(format!("{}-bravo-2", owner))
        .bind(&owner)
        .bind("blob-bravo-2")
        .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
        .bind(10_i64)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
            .bind(snapshot_at + chrono::Duration::microseconds(1))
            .bind(format!("{}-bravo-2", owner))
            .execute(&pool)
            .await
            .unwrap();

        // Page 2 must not re-deliver "bravo" — it was already consumed on
        // page 1, and its mutation happened after the walk's snapshot
        // boundary, so it must stay excluded until a fresh walk starts.
        let page2 = query_owner_namespaces(&pool, &owner, Some(cursor1), 10)
            .await
            .unwrap();
        let page2_names: Vec<String> = page2.namespaces.iter().map(|n| n.name.clone()).collect();
        assert_eq!(
            page2_names,
            vec!["charlie"],
            "namespace mutated mid-walk after already being delivered must not reappear, got {:?}",
            page2_names
        );
        assert!(!page2.has_more, "walk must terminate");

        // A fresh walk (cursor = None) captures a new, later snapshot
        // boundary and picks up "bravo"'s mutated state (memory_count now
        // 2, from the original row plus the mid-walk insert).
        let fresh = query_owner_namespaces(&pool, &owner, None, 10)
            .await
            .unwrap();
        let bravo = fresh
            .namespaces
            .iter()
            .find(|n| n.name == "bravo")
            .expect("bravo must reappear once a fresh walk starts");
        assert_eq!(bravo.memory_count, 2);

        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn query_owner_memories_paginates_by_updated_at_and_id() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        for i in 0..5 {
            sqlx::query(
                "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes, agent_id, package_id)
                 VALUES ($1, $2, 'default', $3, $4, $5, $6, $7)",
            )
            .bind(format!("{}-m{}", owner, i))
            .bind(&owner)
            .bind(format!("blob-{}", i))
            .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .bind(10_i64)
            .bind(format!("agent-{}", i))
            .bind("0xpkg")
            .execute(&pool)
            .await
            .unwrap();
        }

        let page1 = query_owner_memories(&pool, &owner, None, 2).await.unwrap();
        assert_eq!(page1.memories.len(), 2);
        assert!(page1.next_cursor.is_some());

        let page2 = query_owner_memories(&pool, &owner, page1.next_cursor.clone(), 2)
            .await
            .unwrap();
        assert_eq!(page2.memories.len(), 2);

        let page3 = query_owner_memories(&pool, &owner, page2.next_cursor.clone(), 2)
            .await
            .unwrap();
        assert_eq!(page3.memories.len(), 1);
        // Short final page: still a checkpoint, not `None` — that is the
        // client's anchor for its next incremental poll.
        let terminal = page3
            .next_cursor
            .clone()
            .expect("the last page of a traversal must still hand back a watermark");
        let decoded = decode_cursor(&terminal).unwrap();
        assert_eq!(decoded.id, page3.memories[0].memory_id);
        assert_eq!(decoded.updated_at, page3.memories[0].updated_at);

        // Polling again from that watermark with nothing new written comes
        // back empty. It still returns a cursor (the same watermark,
        // snapshot_at reset), not None — see
        // query_owner_memories_empty_continuation_page_resets_snapshot.
        let page4 = query_owner_memories(&pool, &owner, Some(terminal), 2)
            .await
            .unwrap();
        assert!(page4.memories.is_empty());
        let reset_cursor = page4
            .next_cursor
            .expect("an empty page reached via a real cursor must still return one");
        assert_eq!(decode_cursor(&reset_cursor).unwrap().snapshot_at, None);

        let mut all_ids: Vec<String> = page1
            .memories
            .iter()
            .chain(page2.memories.iter())
            .chain(page3.memories.iter())
            .map(|m| m.memory_id.clone())
            .collect();
        all_ids.sort();
        all_ids.dedup();
        assert_eq!(
            all_ids.len(),
            5,
            "pagination must not skip or duplicate rows"
        );

        assert_eq!(page1.memories[0].agent_id.as_deref(), Some("agent-0"));
        assert_eq!(page1.memories[0].status, "active");

        cleanup(&pool, &owner).await;
    }

    /// Bug 2 for `/memories`, isolated: an exactly-`limit`-sized result set
    /// (the old peek-based `has_more` would have reported "no more") still
    /// returns a watermark, and that watermark is built from the last EMITTED
    /// row. Also pins the newly exposed `updated_at` field to the row's real
    /// value.
    #[tokio::test]
    async fn query_owner_memories_exactly_fitting_page_still_returns_watermark() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        seed_entry(&pool, &owner, "e1", "default", 10, ts(0)).await;
        seed_entry(&pool, &owner, "e2", "default", 10, ts(60)).await;

        let page = query_owner_memories(&pool, &owner, None, 2).await.unwrap();
        assert_eq!(page.memories.len(), 2);
        assert_eq!(page.memories[0].updated_at, ts(0));
        assert_eq!(page.memories[1].updated_at, ts(60));

        let cursor = page
            .next_cursor
            .expect("an exactly-full final page must still checkpoint the client");
        let decoded = decode_cursor(&cursor).unwrap();
        assert_eq!(
            decoded.id, page.memories[1].memory_id,
            "watermark must come from the last emitted row"
        );
        assert_eq!(decoded.updated_at, ts(60));

        let empty = query_owner_memories(&pool, &owner, Some(cursor), 2)
            .await
            .unwrap();
        assert!(empty.memories.is_empty());
        // Still returns a cursor (same watermark, snapshot_at reset), not
        // None — see
        // query_owner_memories_empty_continuation_page_resets_snapshot.
        let reset_cursor = empty
            .next_cursor
            .expect("an empty page reached via a real cursor must still return one");
        assert_eq!(decode_cursor(&reset_cursor).unwrap().snapshot_at, None);

        cleanup(&pool, &owner).await;
    }

    #[tokio::test]
    async fn query_owner_memories_handles_updated_at_tie_via_id_tiebreak() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        for i in 0..3 {
            sqlx::query(
                "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
                 VALUES ($1, $2, 'default', $3, $4, $5)",
            )
            .bind(format!("{}-t{}", owner, i))
            .bind(&owner)
            .bind(format!("blob-t{}", i))
            .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .bind(10_i64)
            .execute(&pool)
            .await
            .unwrap();
        }

        // Force all 3 rows to the exact same updated_at — a real tie,
        // not just three inserts close in time.
        let tied_at = chrono::Utc::now();
        sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE owner = $2")
            .bind(tied_at)
            .bind(&owner)
            .execute(&pool)
            .await
            .unwrap();

        let mut seen = Vec::new();
        let mut cursor = None;
        for _ in 0..5 {
            let page = query_owner_memories(&pool, &owner, cursor.clone(), 1)
                .await
                .unwrap();
            if page.memories.is_empty() {
                break;
            }
            seen.push(page.memories[0].memory_id.clone());
            cursor = page.next_cursor.clone();
            if cursor.is_none() {
                break;
            }
        }

        seen.sort();
        seen.dedup();
        assert_eq!(
            seen.len(),
            3,
            "all 3 tied rows must appear exactly once across pages, got {:?}",
            seen
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn query_owner_memories_derives_status_from_expires_at() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        // Row 1: expired (expires_at in the past)
        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes, end_epoch, expires_at)
             VALUES ($1, $2, 'default', 'blob-expired', $3, 10, 100, NOW() - INTERVAL '1 day')",
        )
        .bind(format!("{}-expired", owner))
        .bind(&owner)
        .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
        .execute(&pool)
        .await
        .unwrap();

        // Row 2: active (expires_at in the future)
        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes, end_epoch, expires_at)
             VALUES ($1, $2, 'default', 'blob-active', $3, 10, 900, NOW() + INTERVAL '30 days')",
        )
        .bind(format!("{}-active", owner))
        .bind(&owner)
        .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
        .execute(&pool)
        .await
        .unwrap();

        // Row 3: not yet synced (NULL expires_at)
        sqlx::query(
            "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
             VALUES ($1, $2, 'default', 'blob-unsynced', $3, 10)",
        )
        .bind(format!("{}-unsynced", owner))
        .bind(&owner)
        .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
        .execute(&pool)
        .await
        .unwrap();

        let result = query_owner_memories(&pool, &owner, None, 10).await.unwrap();
        let by_blob: std::collections::HashMap<_, _> = result
            .memories
            .iter()
            .map(|m| (m.blob_id.clone(), m))
            .collect();

        assert_eq!(by_blob["blob-expired"].status, "expired");
        assert_eq!(by_blob["blob-active"].status, "active");
        assert_eq!(by_blob["blob-unsynced"].status, "active"); // optimistic default pending sync
        assert_eq!(by_blob["blob-active"].end_epoch, Some(900));
        assert!(by_blob["blob-active"].expires_at.is_some());
        assert_eq!(by_blob["blob-unsynced"].end_epoch, None);
        assert_eq!(by_blob["blob-unsynced"].expires_at, None);

        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(&pool)
            .await;
    }

    /// Regression test for the snapshot-boundary fix: a row whose
    /// `updated_at` is bumped *after* a walk's first page (mirroring an
    /// Apalis job retry re-upserting the same `vector_id`, which advances
    /// `updated_at` via `ON CONFLICT DO UPDATE ... updated_at = NOW()`) must
    /// not reappear later in that same walk — it must simply be excluded
    /// until a fresh walk (cursor = `None`) starts and captures a new
    /// snapshot boundary that includes it.
    #[tokio::test]
    async fn query_owner_memories_excludes_rows_updated_mid_walk() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        let base = chrono::Utc::now() - chrono::Duration::seconds(60);
        for i in 0..3 {
            sqlx::query(
                "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
                 VALUES ($1, $2, 'default', $3, $4, $5)",
            )
            .bind(format!("{}-s{}", owner, i))
            .bind(&owner)
            .bind(format!("blob-s{}", i))
            .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .bind(10_i64)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
                .bind(base + chrono::Duration::seconds(i))
                .bind(format!("{}-s{}", owner, i))
                .execute(&pool)
                .await
                .unwrap();
        }

        // Page 1 starts the walk and captures `snapshot_at` (~now, well
        // after `base`) into its `next_cursor`.
        let page1 = query_owner_memories(&pool, &owner, None, 1).await.unwrap();
        assert_eq!(page1.memories.len(), 1);
        assert_eq!(page1.memories[0].memory_id, format!("{}-s0", owner));
        let cursor1 = page1.next_cursor.clone().expect("more pages remain");
        let snapshot_at = decode_cursor(&cursor1).unwrap().snapshot_at.unwrap();

        // Simulate an Apalis job retry re-upserting row `s1` mid-walk: bump
        // its `updated_at` to just after the walk's snapshot boundary.
        let bumped_at = snapshot_at + chrono::Duration::microseconds(1);
        sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
            .bind(bumped_at)
            .bind(format!("{}-s1", owner))
            .execute(&pool)
            .await
            .unwrap();

        // The rest of this walk must exclude `s1` outright (not return it a
        // second time, not skip past it and hang) and still terminate.
        let page2 = query_owner_memories(&pool, &owner, Some(cursor1), 10)
            .await
            .unwrap();
        let page2_ids: Vec<String> = page2.memories.iter().map(|m| m.memory_id.clone()).collect();
        assert_eq!(
            page2_ids,
            vec![format!("{}-s2", owner)],
            "row mutated mid-walk must be excluded from the in-flight walk, got {:?}",
            page2_ids
        );
        assert!(
            !page2.has_more,
            "walk must terminate even though `s1` was excluded"
        );

        // The terminal cursor must reset snapshot_at — see the identical
        // assertion in query_owner_namespaces_surfaces_namespace_created_mid_walk_on_next_walk
        // for why this matters: a real client polls again with this exact
        // cursor, never with None.
        let terminal_cursor = page2
            .next_cursor
            .clone()
            .expect("terminal page still checkpoints");
        assert_eq!(
            decode_cursor(&terminal_cursor).unwrap().snapshot_at,
            None,
            "terminal cursor must reset snapshot_at so the next poll captures a fresh one"
        );

        // The realistic incremental-sync client behavior: poll again using
        // the terminal cursor, not None. Must now see the mutated row.
        let next_poll = query_owner_memories(&pool, &owner, Some(terminal_cursor), 10)
            .await
            .unwrap();
        let next_poll_ids: Vec<String> = next_poll
            .memories
            .iter()
            .map(|m| m.memory_id.clone())
            .collect();
        assert_eq!(
            next_poll_ids,
            vec![format!("{}-s1", owner)],
            "an incremental poll using the previous walk's terminal cursor must surface a row \
             mutated after that walk's snapshot, got {:?}",
            next_poll_ids
        );

        // A fresh walk (cursor = None) captures a new, later snapshot
        // boundary and also picks the mutated row back up.
        let fresh = query_owner_memories(&pool, &owner, None, 10).await.unwrap();
        let fresh_ids: Vec<String> = fresh.memories.iter().map(|m| m.memory_id.clone()).collect();
        assert!(
            fresh_ids.contains(&format!("{}-s1", owner)),
            "a fresh walk must see the row once its update has settled, got {:?}",
            fresh_ids
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(&pool)
            .await;
    }

    /// The memories path has the identical empty-continuation-page failure
    /// mode as
    /// `query_owner_namespaces_empty_continuation_page_resets_snapshot` —
    /// see that test's doc comment for the full scenario. Seeds `s0`
    /// (delivered on page 1) and `s1` (peeked, giving page 1
    /// `has_more: true`), bumps `s1`'s `updated_at` past page 1's snapshot
    /// before requesting page 2, so page 2 legitimately has zero rows.
    #[tokio::test]
    async fn query_owner_memories_empty_continuation_page_resets_snapshot() {
        let pool = test_pool().await;
        let owner = format!("0xtest-{}", uuid::Uuid::new_v4());

        let base = chrono::Utc::now() - chrono::Duration::seconds(60);
        for i in 0..2 {
            sqlx::query(
                "INSERT INTO vector_entries (id, owner, namespace, blob_id, embedding, blob_size_bytes)
                 VALUES ($1, $2, 'default', $3, $4, $5)",
            )
            .bind(format!("{}-s{}", owner, i))
            .bind(&owner)
            .bind(format!("blob-s{}", i))
            .bind(pgvector::Vector::from(vec![0.0_f32; 1536]))
            .bind(10_i64)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
                .bind(base + chrono::Duration::seconds(i))
                .bind(format!("{}-s{}", owner, i))
                .execute(&pool)
                .await
                .unwrap();
        }

        // Page 1: delivers s0, peeks s1 -> has_more: true.
        let page1 = query_owner_memories(&pool, &owner, None, 1).await.unwrap();
        assert_eq!(page1.memories.len(), 1);
        assert_eq!(page1.memories[0].memory_id, format!("{}-s0", owner));
        assert!(page1.has_more, "s1 must still be pending");
        let cursor1 = page1.next_cursor.clone().expect("continuation checkpoint");
        let snapshot_at = decode_cursor(&cursor1).unwrap().snapshot_at.unwrap();

        // Race s1 past page 1's snapshot before page 2 is requested.
        sqlx::query("UPDATE vector_entries SET updated_at = $1 WHERE id = $2")
            .bind(snapshot_at + chrono::Duration::microseconds(1))
            .bind(format!("{}-s1", owner))
            .execute(&pool)
            .await
            .unwrap();

        // Page 2 legitimately has zero rows.
        let page2 = query_owner_memories(&pool, &owner, Some(cursor1), 10)
            .await
            .unwrap();
        assert!(
            page2.memories.is_empty(),
            "s1 must be excluded from this walk"
        );
        assert!(!page2.has_more, "nothing else remains in this walk");

        // The fix: the empty page must still return a reset cursor, not None.
        let page2_cursor = page2
            .next_cursor
            .clone()
            .expect("an empty continuation page must still return a reset cursor, not None");
        assert_eq!(
            decode_cursor(&page2_cursor).unwrap().snapshot_at,
            None,
            "the empty page's cursor must reset snapshot_at so the next poll is fresh"
        );

        // Polling again with that reset cursor must now see s1.
        let page3 = query_owner_memories(&pool, &owner, Some(page2_cursor), 10)
            .await
            .unwrap();
        let page3_ids: Vec<String> = page3.memories.iter().map(|m| m.memory_id.clone()).collect();
        assert_eq!(
            page3_ids,
            vec![format!("{}-s1", owner)],
            "a poll using the reset cursor from an empty continuation page must surface the \
             row that raced past the previous snapshot, got {:?}",
            page3_ids
        );

        let _ = sqlx::query("DELETE FROM vector_entries WHERE owner = $1")
            .bind(&owner)
            .execute(&pool)
            .await;
    }

    /// `decode_cursor` must tolerate a cursor JSON that omits `snapshot_at`
    /// entirely (`#[serde(default)]`) rather than failing to parse — the
    /// call sites treat a missing value the same as "no cursor at all".
    #[test]
    fn decode_cursor_defaults_missing_snapshot_at_to_none() {
        use base64::Engine as _;

        #[derive(serde::Serialize)]
        struct LegacyCursor {
            updated_at: chrono::DateTime<chrono::Utc>,
            id: String,
        }
        let legacy = LegacyCursor {
            updated_at: chrono::Utc::now(),
            id: "legacy-id".to_string(),
        };
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&legacy).unwrap());

        let decoded = decode_cursor(&encoded).expect("decodes without snapshot_at");
        assert_eq!(decoded.id, "legacy-id");
        assert_eq!(decoded.snapshot_at, None);
    }
}

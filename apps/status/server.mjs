import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import { createServer } from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import postgres from 'postgres'

const appDir = path.dirname(fileURLToPath(import.meta.url))
const distDir = path.resolve(appDir, 'dist')
const distPrefix = `${distDir}${path.sep}`
const port = Number(process.env.PORT || 3000)
const host = process.env.HOST || '0.0.0.0'

const DEFAULT_RELAYER_PRODUCTION_URL = 'https://relayer.memory.walrus.xyz'
const DEFAULT_RELAYER_STAGING_URL = 'https://relayer.dev.memwal.ai'
const DEFAULT_HEALTH_PATH = '/health'
const DEFAULT_TIMEOUT_MS = 8000
const DEFAULT_POLL_INTERVAL_MS = 60_000
const DEFAULT_HISTORY_DAYS = 90
const HISTORY_TARGET = 'relayer'

function getRelayerComponents() {
  return [
    {
      id: 'relayer-production',
      name: 'Walrus Memory Relayer production (mainnet)',
      url: (
        process.env.STATUS_RELAYER_PRODUCTION_URL ||
        process.env.STATUS_RELAYER_URL ||
        DEFAULT_RELAYER_PRODUCTION_URL
      ).trim(),
    },
    {
      id: 'relayer-staging',
      name: 'Walrus Memory Relayer staging (testnet)',
      url: (process.env.STATUS_RELAYER_STAGING_URL || DEFAULT_RELAYER_STAGING_URL).trim(),
    },
  ]
}

let sql = null
let databaseReady = false
let databaseError = null
let databaseInitPromise = null
let pollInFlight = null
let pollTimer = null

const contentTypes = new Map([
  ['', 'text/plain; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.gif', 'image/gif'],
  ['.html', 'text/html; charset=utf-8'],
  ['.ico', 'image/x-icon'],
  ['.jpeg', 'image/jpeg'],
  ['.jpg', 'image/jpeg'],
  ['.js', 'application/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.map', 'application/json; charset=utf-8'],
  ['.png', 'image/png'],
  ['.svg', 'image/svg+xml; charset=utf-8'],
  ['.webmanifest', 'application/manifest+json; charset=utf-8'],
  ['.webp', 'image/webp'],
])

const fileLikeRequestPattern = /\/[^/?#]+\.[^/?#]+$/

function readNumberEnv(name, fallback, minimum, maximum) {
  const value = Number(process.env[name] || fallback)
  if (!Number.isFinite(value) || value < minimum || value > maximum) return fallback
  return Math.round(value)
}

function getTimeoutMs() {
  return readNumberEnv('STATUS_REQUEST_TIMEOUT_MS', DEFAULT_TIMEOUT_MS, 1000, 30000)
}

function getPollIntervalMs() {
  return readNumberEnv('STATUS_POLL_INTERVAL_MS', DEFAULT_POLL_INTERVAL_MS, 10000, 3600000)
}

function getHistoryDays() {
  return readNumberEnv('STATUS_HISTORY_DAYS', DEFAULT_HISTORY_DAYS, 1, 365)
}

function databaseUrl() {
  return (process.env.DATABASE_URL || process.env.STATUS_DATABASE_URL || '').trim()
}

function adminApiKey() {
  return (process.env.STATUS_ADMIN_API_KEY || '').trim()
}

const ALLOWED_INCIDENT_STATUSES = ['investigating', 'identified', 'monitoring', 'resolved']
const ALLOWED_SEVERITIES = ['minor', 'major', 'critical']

function isValidStatus(value) {
  return ALLOWED_INCIDENT_STATUSES.includes(value)
}

function isValidSeverity(value) {
  return ALLOWED_SEVERITIES.includes(value)
}

function isValidDate(value) {
  if (!value) return false
  const d = new Date(value)
  return !Number.isNaN(d.getTime())
}

function isAdminAuthValid(req) {
  const key = adminApiKey()
  if (!key) return false
  const header = req.headers['x-admin-api-key'] || ''
  if (header.length !== key.length) return false
  try {
    return timingSafeEqual(Buffer.from(header), Buffer.from(key))
  } catch {
    return false
  }
}

function isDatabaseConfigured() {
  return Boolean(databaseUrl())
}

function relayerBaseUrl() {
  return (
    process.env.STATUS_RELAYER_URL ||
    process.env.MEMWAL_SERVER_URL ||
    process.env.VITE_MEMWAL_SERVER_URL ||
    DEFAULT_RELAYER_PRODUCTION_URL
  ).trim()
}

function resolveHealthUrl(rawBase) {
  const base = (rawBase || relayerBaseUrl()).trim()
  const healthPath = (process.env.STATUS_HEALTH_PATH || DEFAULT_HEALTH_PATH).trim() || DEFAULT_HEALTH_PATH
  const url = new URL(base)

  if (!process.env.STATUS_HEALTH_PATH && /\/health\/?$/.test(url.pathname)) {
    url.search = ''
    return url.toString()
  }

  const basePath = url.pathname.replace(/\/+$/, '')
  const nextPath = `${basePath}/${healthPath.replace(/^\/+/, '')}`
  url.pathname = nextPath.replace(/\/{2,}/g, '/')
  url.search = ''
  return url.toString()
}

function noStoreHeaders(contentType) {
  return {
    'Cache-Control': 'no-store',
    'Content-Type': contentType,
    'X-Content-Type-Options': 'nosniff',
  }
}

function sendJson(res, statusCode, body) {
  if (statusCode === 204) {
    res.writeHead(204)
    res.end()
    return
  }
  const payload = JSON.stringify(body)
  res.writeHead(statusCode, {
    ...noStoreHeaders('application/json; charset=utf-8'),
    'Content-Length': Buffer.byteLength(payload),
  })
  res.end(payload)
}

function sendText(res, statusCode, body, cacheControl = 'no-store') {
  res.writeHead(statusCode, {
    'Cache-Control': cacheControl,
    'Content-Type': 'text/plain; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
  })
  res.end(body)
}

function sendXml(res, statusCode, body, contentType) {
  res.writeHead(statusCode, {
    ...noStoreHeaders(`${contentType}; charset=utf-8`),
    'Content-Length': Buffer.byteLength(body),
  })
  res.end(body)
}

function cacheControlFor(pathname, servingIndex) {
  if (servingIndex) return 'no-store'
  if (pathname.startsWith('/assets/')) return 'public, max-age=31536000, immutable'
  return 'public, max-age=300, must-revalidate'
}

function resolveDistPath(pathname) {
  const relativePath = pathname.replace(/^\/+/, '')
  const resolved = path.resolve(distDir, relativePath)

  if (resolved !== distDir && !resolved.startsWith(distPrefix)) {
    return null
  }

  return resolved
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function truncateError(message) {
  if (!message) return 'Health check failed'
  return message.length > 500 ? `${message.slice(0, 500)}...` : message
}

function escapeXml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')
}

function publicBaseUrl(req) {
  const configured = (process.env.STATUS_PUBLIC_URL || '').trim().replace(/\/+$/, '')
  if (configured) return configured

  const hostHeader = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${port}`
  const firstHost = String(hostHeader).split(',')[0].trim()
  const fallbackProto = /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(firstHost) ? 'http' : 'https'
  const proto = req.headers['x-forwarded-proto'] || fallbackProto
  const firstProto = String(proto).split(',')[0].trim()
  return `${firstProto}://${firstHost}`
}

function getSql() {
  if (!sql) {
    sql = postgres(databaseUrl(), {
      max: 2,
      idle_timeout: 20,
      connect_timeout: Math.ceil(getTimeoutMs() / 1000),
    })
  }

  return sql
}

async function initializeDatabase() {
  if (!isDatabaseConfigured()) {
    databaseReady = false
    databaseError = null
    return false
  }

  try {
    const db = getSql()
    await db`
      CREATE TABLE IF NOT EXISTS status_checks (
        id BIGSERIAL PRIMARY KEY,
        checked_at TIMESTAMPTZ NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('operational', 'degraded', 'outage')),
        http_status INTEGER,
        latency_ms INTEGER,
        error TEXT,
        payload JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `
    await db`
      CREATE INDEX IF NOT EXISTS status_checks_target_checked_at_idx
      ON status_checks (target, checked_at DESC)
    `
    await db`
      CREATE TABLE IF NOT EXISTS incidents (
        id BIGSERIAL PRIMARY KEY,
        identifier TEXT UNIQUE,
        title TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('investigating', 'identified', 'monitoring', 'resolved')),
        severity TEXT NOT NULL CHECK (severity IN ('minor', 'major', 'critical')),
        component TEXT,
        message TEXT NOT NULL,
        started_at TIMESTAMPTZ NOT NULL,
        resolved_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `
    await db`
      CREATE TABLE IF NOT EXISTS incident_updates (
        id BIGSERIAL PRIMARY KEY,
        incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        status TEXT NOT NULL CHECK (status IN ('investigating', 'identified', 'monitoring', 'resolved')),
        message TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `
    await db`
      CREATE INDEX IF NOT EXISTS incident_updates_incident_id_idx
      ON incident_updates (incident_id, created_at DESC)
    `
    await db`
      CREATE INDEX IF NOT EXISTS incidents_status_created_at_idx
      ON incidents (status, created_at DESC)
    `
    databaseReady = true
    databaseError = null
    return true
  } catch (error) {
    databaseReady = false
    databaseError = truncateError(error?.message || String(error))
    console.error('[status-service] database initialization failed', error)
    return false
  }
}

async function ensureDatabaseReady() {
  if (!isDatabaseConfigured()) return false
  if (databaseReady) return true
  if (!databaseInitPromise) {
    databaseInitPromise = initializeDatabase().finally(() => {
      databaseInitPromise = null
    })
  }
  return databaseInitPromise
}

async function probeRelayer(name, rawBase, target) {
  const checkedAt = new Date().toISOString()
  const url = resolveHealthUrl(rawBase)
  const startedAt = performance.now()
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), getTimeoutMs())

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    })
    const latencyMs = Math.max(1, Math.round(performance.now() - startedAt))
    const text = await response.text()
    let health = null

    if (text) {
      try {
        const parsed = JSON.parse(text)
        health = isRecord(parsed) ? parsed : null
      } catch {
        health = null
      }
    }

    const writes = isRecord(health) ? health.writes : undefined
    // /health stays HTTP 200 + status:"ok" through a Walrus outage so CI's
    // wait-for-relayer gate does not hang. The write-path signal is `writes`.
    // Allowlist: a fourth writes value must not silently become operational
    // the way degraded did before this PR. Missing writes (old relayer) is ok.
    const reportedOk =
      isRecord(health) && health.status === 'ok' && (writes === 'ok' || writes === undefined)
    const status = response.ok ? (reportedOk ? 'operational' : 'degraded') : 'outage'

    return {
      id: target,
      name,
      status,
      url,
      httpStatus: response.status,
      latencyMs,
      checkedAt,
      health,
      error: response.ok ? null : truncateError(text || response.statusText),
    }
  } catch (error) {
    const latencyMs = Math.max(1, Math.round(performance.now() - startedAt))
    const message = error?.name === 'AbortError'
      ? `Timed out after ${getTimeoutMs()} ms`
      : error?.message || String(error)

    return {
      id: target,
      name,
      status: 'outage',
      url,
      httpStatus: null,
      latencyMs,
      checkedAt,
      health: null,
      error: truncateError(message),
    }
  } finally {
    clearTimeout(timeoutId)
  }
}

async function insertCheck(relayer) {
  if (!(await ensureDatabaseReady())) return false

  try {
    const db = getSql()
    await db`
      INSERT INTO status_checks (
        checked_at,
        target,
        status,
        http_status,
        latency_ms,
        error,
        payload
      )
      VALUES (
        ${new Date(relayer.checkedAt)},
        ${relayer.id},
        ${relayer.status},
        ${relayer.httpStatus},
        ${relayer.latencyMs},
        ${relayer.error},
        ${JSON.stringify(relayer.health ?? null)}::jsonb
      )
    `
    databaseReady = true
    databaseError = null
    return true
  } catch (error) {
    databaseReady = false
    databaseError = truncateError(error?.message || String(error))
    console.error('[status-service] failed to insert status check', error)
    return false
  }
}

async function probeAndStore() {
  const components = getRelayerComponents()
  const results = await Promise.all(
    components.map((c) => probeRelayer(c.name, c.url, c.id))
  )
  for (const relayer of results) {
    await insertCheck(relayer)
  }
  return results
}

async function runPollCycle() {
  if (!pollInFlight) {
    pollInFlight = probeAndStore().finally(() => {
      pollInFlight = null
    })
  }

  return pollInFlight
}

function rowToRelayer(row) {
  const component = getRelayerComponents().find((c) => c.id === row.target)
  return {
    id: row.target || HISTORY_TARGET,
    name: component?.name || 'Walrus Memory Relayer',
    status: row.status,
    url: component ? resolveHealthUrl(component.url) : resolveHealthUrl(),
    httpStatus: row.http_status,
    latencyMs: row.latency_ms,
    checkedAt: new Date(row.checked_at).toISOString(),
    health: normalizePayload(row.payload),
    error: row.error,
  }
}

async function readLatestCheck(target) {
  if (!(await ensureDatabaseReady())) return null

  const rows = await getSql()`
    SELECT target, checked_at, status, http_status, latency_ms, error, payload
    FROM status_checks
    WHERE target = ${target}
    ORDER BY checked_at DESC
    LIMIT 1
  `

  return rows[0] ? rowToRelayer(rows[0]) : null
}

async function listIncidents(limit = 50, offset = 0) {
  if (!(await ensureDatabaseReady())) return []

  const db = getSql()
  const rows = await db`
    SELECT id, identifier, title, status, severity, component, message, started_at, resolved_at, created_at, updated_at
    FROM incidents
    ORDER BY created_at DESC
    LIMIT ${limit} OFFSET ${offset}
  `

  if (!rows.length) return []

  const ids = rows.map((r) => Number(r.id))
  const updateRows = await db`
    SELECT id, incident_id, status, message, created_at
    FROM incident_updates
    WHERE incident_id IN ${db(ids)}
    ORDER BY created_at DESC
  `

  const updatesByIncident = new Map()
  for (const u of updateRows) {
    const incidentId = Number(u.incident_id)
    if (!updatesByIncident.has(incidentId)) {
      updatesByIncident.set(incidentId, [])
    }
    updatesByIncident.get(incidentId).push({
      id: Number(u.id),
      status: u.status,
      message: u.message,
      createdAt: new Date(u.created_at).toISOString(),
    })
  }

  return rows.map((row) => ({
    id: Number(row.id),
    identifier: row.identifier,
    title: row.title,
    status: row.status,
    severity: row.severity,
    component: row.component,
    message: row.message,
    startedAt: new Date(row.started_at).toISOString(),
    resolvedAt: row.resolved_at ? new Date(row.resolved_at).toISOString() : null,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    updates: updatesByIncident.get(Number(row.id)) || [],
  }))
}

async function getIncidentWithUpdates(id) {
  if (!(await ensureDatabaseReady())) return null

  const incidentRows = await getSql()`
    SELECT id, identifier, title, status, severity, component, message, started_at, resolved_at, created_at, updated_at
    FROM incidents
    WHERE id = ${id}
    LIMIT 1
  `

  if (!incidentRows[0]) return null

  const row = incidentRows[0]
  const updates = await getSql()`
    SELECT id, status, message, created_at
    FROM incident_updates
    WHERE incident_id = ${row.id}
    ORDER BY created_at DESC
  `

  return {
    id: Number(row.id),
    identifier: row.identifier,
    title: row.title,
    status: row.status,
    severity: row.severity,
    component: row.component,
    message: row.message,
    startedAt: new Date(row.started_at).toISOString(),
    resolvedAt: row.resolved_at ? new Date(row.resolved_at).toISOString() : null,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    updates: updates.map((u) => ({
      id: Number(u.id),
      status: u.status,
      message: u.message,
      createdAt: new Date(u.created_at).toISOString(),
    })),
  }
}

async function createIncident(payload) {
  if (!(await ensureDatabaseReady())) return null

  const db = getSql()
  const id = await db.begin(async (trx) => {
    const rows = await trx`
      INSERT INTO incidents (title, status, severity, component, message, started_at)
      VALUES (
        ${payload.title},
        ${payload.status},
        ${payload.severity},
        ${payload.component || null},
        ${payload.message},
        ${new Date(payload.startedAt || Date.now())}
      )
      RETURNING id
    `

    const id = rows[0]?.id
    if (!id) return null

    const identifier = `WM-INC-${id}`
    await trx`UPDATE incidents SET identifier = ${identifier} WHERE id = ${id}`

    if (payload.updates?.length) {
      for (const update of payload.updates) {
        await trx`
          INSERT INTO incident_updates (incident_id, status, message, created_at)
          VALUES (${id}, ${update.status}, ${update.message}, ${new Date(update.createdAt || Date.now())})
        `
      }
    } else {
      await trx`
        INSERT INTO incident_updates (incident_id, status, message)
        VALUES (${id}, ${payload.status}, ${payload.message})
      `
    }

    return id
  })

  if (!id) return null
  return getIncidentWithUpdates(id)
}

async function updateIncident(id, payload) {
  if (!(await ensureDatabaseReady())) return null

  const existing = await getIncidentWithUpdates(id)
  if (!existing) return null

  const db = getSql()
  const title = payload.title !== undefined ? payload.title : existing.title
  const status = payload.status !== undefined ? payload.status : existing.status
  const severity = payload.severity !== undefined ? payload.severity : existing.severity
  const component = payload.component !== undefined ? payload.component : existing.component
  const message = payload.message !== undefined ? payload.message : existing.message
  const startedAt = payload.startedAt !== undefined ? new Date(payload.startedAt) : new Date(existing.startedAt)
  let resolvedAt
  if (payload.resolvedAt !== undefined) {
    resolvedAt = payload.resolvedAt ? new Date(payload.resolvedAt) : null
  } else if (status === 'resolved' && existing.status !== 'resolved') {
    resolvedAt = new Date()
  } else {
    resolvedAt = existing.resolvedAt ? new Date(existing.resolvedAt) : null
  }

  await db`
    UPDATE incidents
    SET
      title = ${title},
      status = ${status},
      severity = ${severity},
      component = ${component},
      message = ${message},
      started_at = ${startedAt},
      resolved_at = ${resolvedAt},
      updated_at = now()
    WHERE id = ${id}
  `

  // If status changed to resolved and no update row was explicitly added, record it
  if (payload.status === 'resolved' && existing.status !== 'resolved') {
    const updateMessage = payload.message && payload.message !== existing.message
      ? payload.message
      : 'Incident resolved.'
    await db`
      INSERT INTO incident_updates (incident_id, status, message)
      VALUES (${id}, 'resolved', ${updateMessage})
    `
  }

  return getIncidentWithUpdates(id)
}

async function addIncidentUpdate(incidentId, payload) {
  if (!(await ensureDatabaseReady())) return null

  const db = getSql()

  // Fetch current status to detect resolved transition
  const existingRows = await db`
    SELECT status FROM incidents WHERE id = ${incidentId}
  `
  const existingStatus = existingRows[0]?.status
  const transitioningToResolved = payload.status === 'resolved' && existingStatus !== 'resolved'

  await db`
    INSERT INTO incident_updates (incident_id, status, message, created_at)
    VALUES (
      ${incidentId},
      ${payload.status},
      ${payload.message},
      ${new Date(payload.createdAt || Date.now())}
    )
  `

  if (payload.status) {
    if (transitioningToResolved) {
      await db`
        UPDATE incidents
        SET status = ${payload.status}, resolved_at = now(), updated_at = now()
        WHERE id = ${incidentId}
      `
    } else {
      await db`
        UPDATE incidents
        SET status = ${payload.status}, updated_at = now()
        WHERE id = ${incidentId}
      `
    }
  }

  return getIncidentWithUpdates(incidentId)
}

async function deleteIncident(id) {
  if (!(await ensureDatabaseReady())) return false
  const result = await getSql()`DELETE FROM incidents WHERE id = ${id}`
  return result.count > 0
}

async function readActiveAndRecentIncidents(days = 30) {
  if (!(await ensureDatabaseReady())) return { active: [], recent: [] }

  const rows = await getSql()`
    SELECT id, identifier, title, status, severity, component, message, started_at, resolved_at, created_at, updated_at
    FROM incidents
    WHERE status != 'resolved'
      OR resolved_at >= now() - (${days}::int * interval '1 day')
      OR created_at >= now() - (${days}::int * interval '1 day')
    ORDER BY created_at DESC
    LIMIT 100
  `

  const incidents = rows.map((row) => ({
    id: Number(row.id),
    identifier: row.identifier,
    title: row.title,
    status: row.status,
    severity: row.severity,
    component: row.component,
    message: row.message,
    startedAt: new Date(row.started_at).toISOString(),
    resolvedAt: row.resolved_at ? new Date(row.resolved_at).toISOString() : null,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    updates: [],
  }))

  const ids = incidents.map((i) => i.id)
  if (ids.length > 0) {
    const updateRows = await getSql()`
      SELECT id, incident_id, status, message, created_at
      FROM incident_updates
      WHERE incident_id IN (${ids})
      ORDER BY created_at ASC
    `
    const updatesById = new Map()
    for (const row of updateRows) {
      const id = Number(row.incident_id)
      if (!updatesById.has(id)) updatesById.set(id, [])
      updatesById.get(id).push({
        id: Number(row.id),
        status: row.status,
        message: row.message,
        createdAt: new Date(row.created_at).toISOString(),
      })
    }
    for (const incident of incidents) {
      incident.updates = updatesById.get(incident.id) ?? []
    }
  }

  return {
    active: incidents.filter((i) => i.status !== 'resolved'),
    recent: incidents.filter((i) => i.status === 'resolved'),
  }
}

function utcDateKey(date) {
  return date.toISOString().slice(0, 10)
}

function addUtcDays(date, days) {
  const next = new Date(date)
  next.setUTCDate(next.getUTCDate() + days)
  return next
}

function startOfUtcDay(date) {
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()))
}

function bucketStatus(bucket) {
  if (!bucket.total) return 'unknown'

  const outagePct = bucket.outage / bucket.total
  const degradedPct = bucket.degraded / bucket.total

  // Statuspage-style thresholds (60s polling ≈ 1,440 checks/day)
  // > 5% outage  (~72+ min) → red (significant downtime)
  if (outagePct > 0.05) return 'outage'

  // Minor blips: some outage or notable degraded → yellow
  if (outagePct > 0 || degradedPct > 0.05) return 'degraded'

  return 'operational'
}

function normalizePayload(payload) {
  if (isRecord(payload)) return payload
  if (typeof payload !== 'string' || !payload) return null

  try {
    const parsed = JSON.parse(payload)
    return isRecord(parsed) ? parsed : null
  } catch {
    return null
  }
}

function makeEmptyHistory(enabled, reason = null, target = HISTORY_TARGET) {
  const days = getHistoryDays()
  const today = startOfUtcDay(new Date())
  const firstDay = addUtcDays(today, -(days - 1))
  const buckets = Array.from({ length: days }, (_, index) => ({
    date: utcDateKey(addUtcDays(firstDay, index)),
    status: 'unknown',
    total: 0,
    ok: 0,
    degraded: 0,
    outage: 0,
  }))

  return {
    enabled,
    source: enabled ? 'postgres' : 'live',
    days,
    target,
    totalChecks: 0,
    uptimePct: null,
    unavailableReason: reason,
    buckets,
  }
}

async function readHistory(target) {
  const days = getHistoryDays()
  if (!(await ensureDatabaseReady())) {
    return makeEmptyHistory(false, databaseError, target)
  }

  try {
    const rows = await getSql()`
      SELECT
        (date_trunc('day', checked_at AT TIME ZONE 'UTC'))::date AS day,
        count(*)::int AS total,
        count(*) FILTER (WHERE status = 'operational')::int AS ok,
        count(*) FILTER (WHERE status = 'degraded')::int AS degraded,
        count(*) FILTER (WHERE status = 'outage')::int AS outage
      FROM status_checks
      WHERE target = ${target}
        AND checked_at >= now() - (${days}::int * interval '1 day')
      GROUP BY 1
      ORDER BY 1
    `

    const byDay = new Map(rows.map((row) => {
      const day = row.day instanceof Date ? utcDateKey(row.day) : String(row.day).slice(0, 10)
      return [day, {
        total: Number(row.total || 0),
        ok: Number(row.ok || 0),
        degraded: Number(row.degraded || 0),
        outage: Number(row.outage || 0),
      }]
    }))

    const today = startOfUtcDay(new Date())
    const firstDay = addUtcDays(today, -(days - 1))
    let totalChecks = 0
    let upChecks = 0

    const buckets = Array.from({ length: days }, (_, index) => {
      const date = utcDateKey(addUtcDays(firstDay, index))
      const row = byDay.get(date) ?? {
        total: 0,
        ok: 0,
        degraded: 0,
        outage: 0,
      }
      totalChecks += row.total
      upChecks += row.ok + row.degraded

      return {
        date,
        status: bucketStatus(row),
        total: row.total,
        ok: row.ok,
        degraded: row.degraded,
        outage: row.outage,
      }
    })

    return {
      enabled: true,
      source: 'postgres',
      days,
      target,
      totalChecks,
      uptimePct: totalChecks > 0 ? Number(((upChecks / totalChecks) * 100).toFixed(2)) : null,
      unavailableReason: null,
      buckets,
    }
  } catch (error) {
    databaseReady = false
    databaseError = truncateError(error?.message || String(error))
    console.error('[status-service] failed to read status history', error)
    return makeEmptyHistory(false, databaseError, target)
  }
}



async function getRelayerSnapshot() {
  const components = getRelayerComponents()

  if (!isDatabaseConfigured()) {
    return Promise.all(
      components.map((c) => probeRelayer(c.name, c.url, c.id))
    )
  }

  const staleAfterMs = getPollIntervalMs() * 1.5
  let needsPoll = false

  const latestChecks = await Promise.all(
    components.map(async (c) => {
      const latest = await readLatestCheck(c.id)
      const latestAgeMs = latest ? Date.now() - Date.parse(latest.checkedAt) : Number.POSITIVE_INFINITY
      if (!latest || latestAgeMs > staleAfterMs) {
        needsPoll = true
      }
      return { component: c, latest }
    })
  )

  if (needsPoll) {
    await runPollCycle()
    for (const item of latestChecks) {
      item.latest = await readLatestCheck(item.component.id)
    }
  }

  return latestChecks.map((item) => item.latest)
}

async function statusPayload() {
  const components = await getRelayerSnapshot()
  const histories = {}
  for (const component of components) {
    histories[component.id] = await readHistory(component.id)
  }
  const incidents = await readActiveAndRecentIncidents()

  const serviceStatus = components.some((c) => c.status === 'outage')
    ? 'outage'
    : components.some((c) => c.status === 'degraded')
      ? 'degraded'
      : 'operational'

  const historyEnabled = Object.values(histories).some((h) => h.enabled)

  return {
    generatedAt: new Date().toISOString(),
    service: {
      name: 'Walrus Memory Status',
      status: serviceStatus,
      runtime: 'node',
      historyEnabled,
    },
    components,
    histories,
    incidents,
    database: {
      configured: isDatabaseConfigured(),
      ready: databaseReady,
      error: databaseError,
    },
    dependencies: [
      {
        name: 'Sui network',
        status: 'monitoring',
        url: process.env.STATUS_SUI_STATUS_URL || 'https://status.sui.io/',
      },
      {
        name: 'Walrus storage',
        status: 'monitoring',
        url: process.env.STATUS_WALRUS_URL || 'https://www.walrus.xyz/',
      },
    ],
  }
}

function feedEntries(snapshot, baseUrl) {
  const entries = []
  const components = snapshot.components ?? []
  const production = components.find((c) => c.id === 'relayer-production') || components[0]
  const worstComponent = components.find((c) => c.status === 'outage') || components.find((c) => c.status === 'degraded') || production

  const activeIncidents = snapshot.incidents?.active ?? []
  const recentIncidents = snapshot.incidents?.recent ?? []
  const allIncidents = [...activeIncidents, ...recentIncidents]

  if (allIncidents.length > 0) {
    for (const incident of allIncidents.slice(0, 10)) {
      entries.push({
        id: `${baseUrl}/history#${incident.identifier}`,
        title: `${incident.identifier}: ${incident.title} (${incident.status})`,
        updated: incident.updatedAt || incident.createdAt,
        summary: incident.message,
        link: `${baseUrl}/history`,
      })
    }
  } else if (snapshot.service?.status === 'operational') {
    entries.push({
      id: `${baseUrl}/`,
      title: 'All Systems Operational',
      updated: production?.checkedAt || snapshot.generatedAt,
      summary: 'Walrus Memory Relayers are operational. No incidents reported.',
      link: `${baseUrl}/`,
    })
  } else {
    entries.push({
      id: `${baseUrl}/`,
      title: `Walrus Memory Relayer ${worstComponent?.status || 'unavailable'}`,
      updated: worstComponent?.checkedAt || snapshot.generatedAt,
      summary: worstComponent?.error || `Relayer status is ${worstComponent?.status || 'unknown'}.`,
      link: `${baseUrl}/`,
    })
  }

  const productionHistory = snapshot.histories?.['relayer-production']
  for (const bucket of productionHistory?.buckets ?? []) {
    if (bucket.status !== 'outage' && bucket.status !== 'degraded') continue
    entries.push({
      id: `${baseUrl}/history#${bucket.date}`,
      title: bucket.status === 'outage'
        ? `Major outage on ${bucket.date}`
        : `Degraded performance on ${bucket.date}`,
      updated: `${bucket.date}T00:00:00.000Z`,
      summary: bucket.status === 'outage'
        ? `${bucket.outage} outage check${bucket.outage === 1 ? '' : 's'} recorded.`
        : `${bucket.degraded} degraded check${bucket.degraded === 1 ? '' : 's'} recorded.`,
      link: `${baseUrl}/history`,
    })
  }

  return entries.slice(0, 20)
}

function atomFeed(snapshot, baseUrl) {
  const updated = snapshot.generatedAt
  const entries = feedEntries(snapshot, baseUrl).map((entry) => `
    <entry>
      <id>${escapeXml(entry.id)}</id>
      <title>${escapeXml(entry.title)}</title>
      <updated>${escapeXml(entry.updated)}</updated>
      <link href="${escapeXml(entry.link)}" />
      <summary>${escapeXml(entry.summary)}</summary>
    </entry>`).join('')

  return `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <id>${escapeXml(baseUrl)}/history.atom</id>
  <title>Walrus Memory Status History</title>
  <updated>${escapeXml(updated)}</updated>
  <link href="${escapeXml(baseUrl)}/history.atom" rel="self" />
  <link href="${escapeXml(baseUrl)}/" />
  ${entries}
</feed>`
}

function rssFeed(snapshot, baseUrl) {
  const entries = feedEntries(snapshot, baseUrl).map((entry) => `
      <item>
        <guid>${escapeXml(entry.id)}</guid>
        <title>${escapeXml(entry.title)}</title>
        <link>${escapeXml(entry.link)}</link>
        <pubDate>${escapeXml(new Date(entry.updated).toUTCString())}</pubDate>
        <description>${escapeXml(entry.summary)}</description>
      </item>`).join('')

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Walrus Memory Status History</title>
    <link>${escapeXml(baseUrl)}/</link>
    <description>Real-time and historical status updates for Walrus Memory.</description>
    <lastBuildDate>${escapeXml(new Date(snapshot.generatedAt).toUTCString())}</lastBuildDate>
    ${entries}
  </channel>
</rss>`
}

async function serveFile(req, res, filePath, pathname, servingIndex = false) {
  const fileStat = await stat(filePath)
  if (!fileStat.isFile()) return false

  const ext = path.extname(filePath).toLowerCase()
  const contentType = contentTypes.get(ext) || 'application/octet-stream'

  res.writeHead(200, {
    'Accept-Ranges': 'bytes',
    'Cache-Control': cacheControlFor(pathname, servingIndex),
    'Content-Length': fileStat.size,
    'Content-Type': contentType,
    'X-Content-Type-Options': 'nosniff',
  })

  if (req.method === 'HEAD') {
    res.end()
    return true
  }

  createReadStream(filePath)
    .on('error', () => {
      if (!res.headersSent) {
        sendText(res, 500, 'Internal server error')
      } else {
        res.destroy()
      }
    })
    .pipe(res)

  return true
}

function startPolling() {
  if (!isDatabaseConfigured()) return

  const pollIntervalMs = getPollIntervalMs()
  void runPollCycle()
  pollTimer = setInterval(() => {
    void runPollCycle()
  }, pollIntervalMs)
  pollTimer.unref?.()
  console.log(`[status-service] polling ${getRelayerComponents().length} relayers every ${pollIntervalMs} ms`)
}

function readJsonBody(req, maxBytes = 256_000) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let received = 0

    req.on('data', (chunk) => {
      received += chunk.length
      if (received > maxBytes) {
        req.destroy()
        reject(new Error('Request body too large'))
        return
      }
      chunks.push(chunk)
    })

    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf-8')
      if (!raw) return resolve({})
      try {
        resolve(JSON.parse(raw))
      } catch {
        reject(new Error('Invalid JSON'))
      }
    })

    req.on('error', reject)
  })
}

async function shutdown(signal) {
  console.log(`[status-service] received ${signal}, shutting down`)
  if (pollTimer) clearInterval(pollTimer)
  server.close(async () => {
    if (sql) await sql.end({ timeout: 5 })
    process.exit(0)
  })
}

const server = createServer(async (req, res) => {
  const method = req.method || 'GET'
  let pathname
  try {
    pathname = decodeURIComponent(new URL(req.url || '/', 'http://localhost').pathname)
  } catch {
    sendText(res, 400, 'Bad request')
    return
  }

  if (pathname.includes('\0')) {
    sendText(res, 400, 'Bad request')
    return
  }

  const isApiRoute = pathname.startsWith('/api/')
  const allowedMethods = isApiRoute ? ['GET', 'HEAD', 'POST', 'PATCH', 'DELETE'] : ['GET', 'HEAD']

  if (!allowedMethods.includes(method)) {
    res.writeHead(405, {
      Allow: allowedMethods.join(', '),
      ...noStoreHeaders('text/plain; charset=utf-8'),
    })
    res.end('Method not allowed')
    return
  }

  if (pathname === '/health') {
    sendJson(res, 200, {
      status: 'ok',
      service: 'walrus-memory-status',
      generatedAt: new Date().toISOString(),
      database: {
        configured: isDatabaseConfigured(),
        ready: databaseReady,
        error: databaseError,
      },
    })
    return
  }

  if (pathname === '/api/status') {
    if (method !== 'GET' && method !== 'HEAD') {
      sendJson(res, 405, { error: 'Method not allowed' })
      return
    }
    try {
      sendJson(res, 200, await statusPayload())
    } catch (error) {
      console.error('[status-service] failed to build status payload', error)
      sendJson(res, 500, {
        generatedAt: new Date().toISOString(),
        service: { name: 'Walrus Memory Status', status: 'degraded' },
        error: 'Status service failed to build payload',
      })
    }
    return
  }

  if (pathname === '/api/incidents') {
    if (method === 'GET' || method === 'HEAD') {
      try {
        const incidents = await listIncidents()
        sendJson(res, 200, { incidents })
      } catch (error) {
        console.error('[status-service] failed to list incidents', error)
        sendJson(res, 500, { error: 'Failed to list incidents' })
      }
      return
    }

    if (method === 'POST') {
      if (!isAdminAuthValid(req)) {
        sendJson(res, 401, { error: 'Unauthorized' })
        return
      }
      try {
        const body = await readJsonBody(req)
        if (!body.title || !body.status || !body.severity || !body.message) {
          sendJson(res, 400, { error: 'Missing required fields: title, status, severity, message' })
          return
        }
        if (!isValidStatus(body.status)) {
          sendJson(res, 400, { error: `Invalid status. Allowed: ${ALLOWED_INCIDENT_STATUSES.join(', ')}` })
          return
        }
        if (!isValidSeverity(body.severity)) {
          sendJson(res, 400, { error: `Invalid severity. Allowed: ${ALLOWED_SEVERITIES.join(', ')}` })
          return
        }
        if (body.startedAt && !isValidDate(body.startedAt)) {
          sendJson(res, 400, { error: 'Invalid startedAt date' })
          return
        }
        const incident = await createIncident(body)
        if (!incident) {
          sendJson(res, 500, { error: 'Failed to create incident' })
          return
        }
        sendJson(res, 201, incident)
      } catch (error) {
        console.error('[status-service] failed to create incident', error)
        sendJson(res, 500, { error: 'Failed to create incident' })
      }
      return
    }

    sendJson(res, 405, { error: 'Method not allowed' })
    return
  }

  const incidentDetailMatch = pathname.match(/^\/api\/incidents\/(\d+)$/)
  if (incidentDetailMatch) {
    const incidentId = Number(incidentDetailMatch[1])

    if (method === 'GET' || method === 'HEAD') {
      try {
        const incident = await getIncidentWithUpdates(incidentId)
        if (!incident) {
          sendJson(res, 404, { error: 'Incident not found' })
          return
        }
        sendJson(res, 200, incident)
      } catch (error) {
        console.error('[status-service] failed to get incident', error)
        sendJson(res, 500, { error: 'Failed to get incident' })
      }
      return
    }

    if (method === 'PATCH') {
      if (!isAdminAuthValid(req)) {
        sendJson(res, 401, { error: 'Unauthorized' })
        return
      }
      try {
        const body = await readJsonBody(req)
        if (body.status !== undefined && !isValidStatus(body.status)) {
          sendJson(res, 400, { error: `Invalid status. Allowed: ${ALLOWED_INCIDENT_STATUSES.join(', ')}` })
          return
        }
        if (body.severity !== undefined && !isValidSeverity(body.severity)) {
          sendJson(res, 400, { error: `Invalid severity. Allowed: ${ALLOWED_SEVERITIES.join(', ')}` })
          return
        }
        if (body.startedAt !== undefined && !isValidDate(body.startedAt)) {
          sendJson(res, 400, { error: 'Invalid startedAt date' })
          return
        }
        if (body.resolvedAt !== undefined && body.resolvedAt && !isValidDate(body.resolvedAt)) {
          sendJson(res, 400, { error: 'Invalid resolvedAt date' })
          return
        }
        const incident = await updateIncident(incidentId, body)
        if (!incident) {
          sendJson(res, 404, { error: 'Incident not found' })
          return
        }
        sendJson(res, 200, incident)
      } catch (error) {
        console.error('[status-service] failed to update incident', error)
        sendJson(res, 500, { error: 'Failed to update incident' })
      }
      return
    }

    if (method === 'DELETE') {
      if (!isAdminAuthValid(req)) {
        sendJson(res, 401, { error: 'Unauthorized' })
        return
      }
      try {
        const deleted = await deleteIncident(incidentId)
        if (!deleted) {
          sendJson(res, 404, { error: 'Incident not found' })
          return
        }
        sendJson(res, 204, null)
      } catch (error) {
        console.error('[status-service] failed to delete incident', error)
        sendJson(res, 500, { error: 'Failed to delete incident' })
      }
      return
    }

    sendJson(res, 405, { error: 'Method not allowed' })
    return
  }

  const incidentUpdatesMatch = pathname.match(/^\/api\/incidents\/(\d+)\/updates$/)
  if (incidentUpdatesMatch) {
    const incidentId = Number(incidentUpdatesMatch[1])

    if (method === 'POST') {
      if (!isAdminAuthValid(req)) {
        sendJson(res, 401, { error: 'Unauthorized' })
        return
      }
      try {
        const body = await readJsonBody(req)
        if (!body.status || !body.message) {
          sendJson(res, 400, { error: 'Missing required fields: status, message' })
          return
        }
        if (!isValidStatus(body.status)) {
          sendJson(res, 400, { error: `Invalid status. Allowed: ${ALLOWED_INCIDENT_STATUSES.join(', ')}` })
          return
        }
        if (body.createdAt && !isValidDate(body.createdAt)) {
          sendJson(res, 400, { error: 'Invalid createdAt date' })
          return
        }
        const incident = await addIncidentUpdate(incidentId, body)
        if (!incident) {
          sendJson(res, 404, { error: 'Incident not found' })
          return
        }
        sendJson(res, 201, incident)
      } catch (error) {
        console.error('[status-service] failed to add incident update', error)
        sendJson(res, 500, { error: 'Failed to add incident update' })
      }
      return
    }

    sendJson(res, 405, { error: 'Method not allowed' })
    return
  }

  if (pathname === '/history.atom' || pathname === '/history.rss') {
    if (method !== 'GET' && method !== 'HEAD') {
      sendJson(res, 405, { error: 'Method not allowed' })
      return
    }
    try {
      const snapshot = await statusPayload()
      const baseUrl = publicBaseUrl(req)
      if (pathname === '/history.atom') {
        sendXml(res, 200, atomFeed(snapshot, baseUrl), 'application/atom+xml')
      } else {
        sendXml(res, 200, rssFeed(snapshot, baseUrl), 'application/rss+xml')
      }
    } catch (error) {
      console.error('[status-service] failed to build history feed', error)
      sendText(res, 500, 'Status feed failed to build')
    }
    return
  }

  const staticPath = resolveDistPath(pathname)
  if (!staticPath) {
    sendText(res, 403, 'Forbidden')
    return
  }

  try {
    if (await serveFile(req, res, staticPath, pathname)) return
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      console.error('[status-service] failed to serve file', { pathname, error })
      sendText(res, 500, 'Internal server error')
      return
    }
  }

  if (fileLikeRequestPattern.test(pathname)) {
    sendText(res, 404, 'Not found')
    return
  }

  try {
    if (!(await serveFile(req, res, path.join(distDir, 'index.html'), pathname, true))) {
      sendText(res, 500, 'Internal server error')
    }
  } catch (error) {
    console.error('[status-service] failed to serve SPA fallback', { pathname, error })
    sendText(res, 500, 'Internal server error')
  }
})

process.once('SIGINT', () => {
  void shutdown('SIGINT')
})
process.once('SIGTERM', () => {
  void shutdown('SIGTERM')
})

await initializeDatabase()
startPolling()

server.listen(port, host, () => {
  console.log(`[status-service] serving ${distDir} on http://${host}:${port}`)
  for (const component of getRelayerComponents()) {
    console.log(`[status-service] relayer health target [${component.id}]: ${resolveHealthUrl(component.url)}`)
  }
  console.log(`[status-service] history storage: ${isDatabaseConfigured() ? 'postgres' : 'disabled'}`)
})

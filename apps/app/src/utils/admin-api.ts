import { config } from '../config'

export interface WalletBalance {
  address: string
  suiBalance: bigint
  walBalance: bigint
  suiTotal: bigint
  walTotal: bigint
  status: 'healthy' | 'warning' | 'critical'
}

export interface SponsorWallet {
  address: string
  suiBalance: bigint
  suiThreshold: bigint
  status: 'healthy' | 'warning' | 'critical'
}

export interface UploadError {
  id: string
  /** When the job failed (last update). */
  timestamp: string
  /** When the job was queued. */
  createdAt: string
  owner: string
  namespace: string
  status: string
  /** The server's message, or null when it recorded none. */
  rawErrorMessage: string | null
  errorMessage: string
}

/** `0x5c3a...907e`: enough of both ends to tell addresses apart. */
export function shortAddress(address: string): string {
  return address.length > 14 ? `${address.slice(0, 6)}...${address.slice(-4)}` : address
}

/** The account page for an address on this deployment's Sui network. */
export function suiExplorerAccountUrl(address: string): string {
  return `https://suiscan.xyz/${config.suiNetwork}/account/${address}`
}

export interface AdminConfig {
  balanceMonitorIntervalSecs: number
  uploaderWalLowThresholdFrost: bigint
  uploaderSuiLowThresholdMist: bigint
  sponsorSuiLowThresholdMist: bigint
}

export interface AdminWalletsResponse {
  uploaderPoolWallets: WalletBalance[]
  sponsorWallet: SponsorWallet
  lastUpdated: string
}

export interface AdminErrorsResponse {
  errors: UploadError[]
  total: number
  limit: number
  offset: number
}

/**
 * Format a raw base-unit amount (mist/frost, 9 decimals) as a human-readable
 * token amount, e.g. 50026696048n -> "50.0267".
 */
export function formatTokenAmount(raw: bigint): string {
  const decimals = 9n
  const divisor = 10n ** decimals
  const negative = raw < 0n
  const abs = negative ? -raw : raw
  const whole = abs / divisor
  const frac = abs % divisor
  const fracStr = frac
    .toString()
    .padStart(Number(decimals), '0')
    .slice(0, 4)
    .replace(/0+$/, '')
  const wholeStr = whole.toLocaleString()
  const sign = negative ? '-' : ''
  return fracStr ? `${sign}${wholeStr}.${fracStr}` : `${sign}${wholeStr}`
}

async function makeAdminRequest(
  endpoint: string,
  adminKey: string,
  method: string = 'GET',
  body?: unknown,
): Promise<unknown> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-admin-api-key': adminKey,
  }

  const opts: RequestInit = {
    method,
    headers,
    cache: 'no-store',
  }

  if (body) {
    opts.body = JSON.stringify(body)
  }

  const baseUrl = config.memwalServerUrl.replace(/\/$/, '')
  const resp = await fetch(`${baseUrl}/api/admin${endpoint}`, opts)

  if (!resp.ok) {
    if (resp.status === 401 || resp.status === 403) {
      throw new Error('INVALID_KEY')
    }
    if (resp.status >= 500) {
      throw new Error('SERVER_ERROR')
    }
    const text = await resp.text()
    throw new Error(text || `HTTP ${resp.status}`)
  }

  return resp.json()
}

// Backend (snake_case, Rust) wire shapes — as actually returned by
// services/server/src/routes/admin_dashboard.rs. Kept separate from the
// camelCase UI-facing types above; the fetch* functions below map one to
// the other at this API boundary.
interface RawWalletBalance {
  address: string
  sui: string
  wal: string
  sui_total?: string
  wal_total?: string
  status: string
}

interface RawWalletsResponse {
  uploader_pool: {
    wallets: RawWalletBalance[]
    wal_threshold: string
    sui_threshold: string
    last_updated: string
  }
  sponsor_wallet: {
    address: string | null
    sui: string
    sui_threshold: string
    status: string
  }
}

interface RawFailedJob {
  id: string
  owner: string
  namespace: string
  status: string
  error_msg: string | null
  created_at: string
  updated_at: string
}

interface RawUploadErrorsResponse {
  results: RawFailedJob[]
  total: number
  limit: number
  offset: number
}

interface RawConfigResponse {
  balance_monitor_interval_secs: number
  wallet_wal_low_threshold_frost: string
  wallet_sui_low_threshold_mist: string
  sponsor_sui_low_threshold_mist: string
}

function toBadgeStatus(status: string): 'healthy' | 'warning' | 'critical' {
  if (status === 'ok') return 'healthy'
  if (status === 'low') return 'critical'
  return 'warning'
}

export async function fetchAdminWallets(
  adminKey: string,
): Promise<AdminWalletsResponse> {
  const raw = (await makeAdminRequest('/wallets', adminKey)) as RawWalletsResponse

  return {
    uploaderPoolWallets: raw.uploader_pool.wallets.map((wallet) => ({
      address: wallet.address,
      suiBalance: BigInt(wallet.sui || '0'),
      walBalance: BigInt(wallet.wal || '0'),
      suiTotal: BigInt(wallet.sui_total || wallet.sui || '0'),
      walTotal: BigInt(wallet.wal_total || wallet.wal || '0'),
      status: toBadgeStatus(wallet.status),
    })),
    sponsorWallet: {
      address: raw.sponsor_wallet.address ?? 'Not configured',
      suiBalance: BigInt(raw.sponsor_wallet.sui || '0'),
      suiThreshold: BigInt(raw.sponsor_wallet.sui_threshold || '0'),
      status: toBadgeStatus(raw.sponsor_wallet.status),
    },
    lastUpdated: raw.uploader_pool.last_updated,
  }
}

export async function fetchAdminErrors(
  adminKey: string,
  limit: number,
  offset: number,
): Promise<AdminErrorsResponse> {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  })
  const raw = (await makeAdminRequest(
    `/upload-errors?${params}`,
    adminKey,
  )) as RawUploadErrorsResponse

  return {
    errors: raw.results.map((job) => ({
      id: job.id,
      timestamp: job.updated_at,
      createdAt: job.created_at,
      owner: job.owner,
      namespace: job.namespace,
      status: job.status,
      rawErrorMessage: job.error_msg,
      errorMessage: job.error_msg ?? '(no error message)',
    })),
    total: raw.total,
    limit: raw.limit,
    offset: raw.offset,
  }
}

export type SpendPace = 'faster' | 'slower' | 'same' | 'unknown'

export function spendPace(
  comparable: boolean,
  outflow: bigint,
  priorOutflow: bigint,
): SpendPace {
  if (!comparable) return 'unknown'
  if (outflow > priorOutflow) return 'faster'
  if (outflow < priorOutflow) return 'slower'
  return 'same'
}

export interface ActivitySeriesPoint {
  at: string
  balance: bigint
}

export interface ActivityTokenWindow {
  samples: number
  comparable: boolean
  latest: bigint | null
  latestAt: string | null
  outflow: bigint
  priorOutflow: bigint
  net: bigint
  series: ActivitySeriesPoint[]
}

export interface SponsoredKindCount {
  kind: string
  count: number
  priorCount: number
}

export interface ActivityTopOwner {
  owner: string
  uploadsCompleted: number
}

export interface MemoryHour {
  /** Local clock hour, `YYYY-MM-DDTHH:00`. */
  hour: string
  count: number
}

export interface MemoryDay {
  day: string
  count: number
}

export interface AdminActivity {
  generatedAt: string
  windowHours: number
  balanceMonitorIntervalSecs: number
  uploaderWal: ActivityTokenWindow
  uploaderSui: ActivityTokenWindow
  sponsorSui: ActivityTokenWindow
  actions: {
    uploadsCompleted: number
    uploadsCompletedPrior: number
    uploadsFailed: number
    uploadsFailedPrior: number
    uploadsInFlight: number
    memoryDeletes: number
    memoryDeletesPrior: number
    securityDeleteBatches: number | null
    securityDeleteBatchesPrior: number | null
    securityDeleteBlobs: number | null
    securityDeleteBlobsPrior: number | null
    sponsored: SponsoredKindCount[]
    topOwners: ActivityTopOwner[]
    memoriesByDay: MemoryDay[]
    /** Present only for windows of 24 hours or less. */
    memoriesByHour: MemoryHour[] | null
  }
}

interface RawSeriesPoint {
  at: string
  balance: string
}

interface RawTokenWindow {
  samples: number
  comparable: boolean
  latest: string | null
  latest_at: string | null
  outflow: string
  prior_outflow: string
  net: string
  series: RawSeriesPoint[]
}

interface RawActivityResponse {
  generated_at: string
  window_hours: number
  balance_monitor_interval_secs: number
  uploader_wal: RawTokenWindow
  uploader_sui: RawTokenWindow
  sponsor_sui: RawTokenWindow
  actions: {
    uploads_completed: number
    uploads_completed_prior: number
    uploads_failed: number
    uploads_failed_prior: number
    uploads_in_flight: number
    memory_deletes: number
    memory_deletes_prior: number
    security_delete_batches: number | null
    security_delete_batches_prior: number | null
    security_delete_blobs: number | null
    security_delete_blobs_prior: number | null
    sponsored: Array<{ kind: string; count: number; prior_count: number }>
    top_owners: Array<{ owner: string; uploads_completed: number }>
    memories_by_day?: Array<{ day: string; count: number }>
    memories_by_hour?: Array<{ hour: string; count: number }>
  }
}

function mapTokenWindow(raw: RawTokenWindow): ActivityTokenWindow {
  return {
    samples: raw.samples,
    comparable: raw.comparable,
    latest: raw.latest == null ? null : BigInt(raw.latest),
    latestAt: raw.latest_at,
    outflow: BigInt(raw.outflow),
    priorOutflow: BigInt(raw.prior_outflow),
    net: BigInt(raw.net),
    series: raw.series.map((point) => ({
      at: point.at,
      balance: BigInt(point.balance),
    })),
  }
}

export async function fetchAdminActivity(
  adminKey: string,
  hours: number,
): Promise<AdminActivity> {
  const utcOffsetMinutes = -new Date().getTimezoneOffset()
  const raw = (await makeAdminRequest(
    `/activity?hours=${hours}&utc_offset_minutes=${utcOffsetMinutes}`,
    adminKey,
  )) as RawActivityResponse
  return {
    generatedAt: raw.generated_at,
    windowHours: raw.window_hours,
    balanceMonitorIntervalSecs: raw.balance_monitor_interval_secs,
    uploaderWal: mapTokenWindow(raw.uploader_wal),
    uploaderSui: mapTokenWindow(raw.uploader_sui),
    sponsorSui: mapTokenWindow(raw.sponsor_sui),
    actions: {
      uploadsCompleted: raw.actions.uploads_completed,
      uploadsCompletedPrior: raw.actions.uploads_completed_prior,
      uploadsFailed: raw.actions.uploads_failed,
      uploadsFailedPrior: raw.actions.uploads_failed_prior,
      uploadsInFlight: raw.actions.uploads_in_flight,
      memoryDeletes: raw.actions.memory_deletes,
      memoryDeletesPrior: raw.actions.memory_deletes_prior,
      securityDeleteBatches: raw.actions.security_delete_batches,
      securityDeleteBatchesPrior: raw.actions.security_delete_batches_prior,
      securityDeleteBlobs: raw.actions.security_delete_blobs,
      securityDeleteBlobsPrior: raw.actions.security_delete_blobs_prior,
      sponsored: raw.actions.sponsored.map((row) => ({
        kind: row.kind,
        count: row.count,
        priorCount: row.prior_count,
      })),
      topOwners: raw.actions.top_owners.map((row) => ({
        owner: row.owner,
        uploadsCompleted: row.uploads_completed,
      })),
      memoriesByDay: (raw.actions.memories_by_day ?? []).map((row) => ({
        day: row.day,
        count: row.count,
      })),
      memoriesByHour: raw.actions.memories_by_hour
        ? raw.actions.memories_by_hour.map((row) => ({ hour: row.hour, count: row.count }))
        : null,
    },
  }
}

export async function fetchAdminConfig(
  adminKey: string,
): Promise<AdminConfig> {
  const raw = (await makeAdminRequest('/config', adminKey)) as RawConfigResponse

  return {
    balanceMonitorIntervalSecs: raw.balance_monitor_interval_secs,
    uploaderWalLowThresholdFrost: BigInt(raw.wallet_wal_low_threshold_frost),
    uploaderSuiLowThresholdMist: BigInt(raw.wallet_sui_low_threshold_mist),
    sponsorSuiLowThresholdMist: BigInt(raw.sponsor_sui_low_threshold_mist),
  }
}

// Runtime owner policy. Never embed deployment identities in this client.
export interface OwnerRateLimitPolicy {
  requests_per_minute: number
  requests_per_hour: number
  delegate_key_per_minute: number
  expires_at: string | null
}
export interface OwnerRateLimitResponse {
  owner: string
  defaults: OwnerRateLimitPolicy
  override_policy: OwnerRateLimitPolicy | null
  effective: OwnerRateLimitPolicy
}
export async function fetchOwnerRateLimits(adminKey: string, owner: string): Promise<OwnerRateLimitResponse> {
  return await makeAdminRequest(`/rate-limits/${encodeURIComponent(owner)}`, adminKey) as OwnerRateLimitResponse
}
export async function saveOwnerRateLimits(adminKey: string, owner: string, policy: OwnerRateLimitPolicy): Promise<OwnerRateLimitResponse> {
  return await makeAdminRequest(`/rate-limits/${encodeURIComponent(owner)}`, adminKey, 'PUT', policy) as OwnerRateLimitResponse
}
export async function resetOwnerRateLimits(adminKey: string, owner: string): Promise<OwnerRateLimitResponse> {
  return await makeAdminRequest(`/rate-limits/${encodeURIComponent(owner)}`, adminKey, 'DELETE') as OwnerRateLimitResponse
}

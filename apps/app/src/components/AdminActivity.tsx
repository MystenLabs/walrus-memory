import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card } from './Card'
import { CopyableText } from './CopyableText'
import {
  fetchAdminActivity,
  formatTokenAmount,
  spendPace,
  type ActivityTokenWindow,
  type AdminActivity,
  type SpendPace,
} from '../utils/admin-api'

interface AdminActivityProps {
  adminKey: string
  onInvalidKey: () => void
  /** Local-only sample, so the spend layout can be reviewed without the API. */
  preview?: boolean
  afterMemories?: ReactNode
}

const WINDOWS = [
  { hours: 24, label: '24 hours' },
  { hours: 168, label: '7 days' },
  { hours: 720, label: '30 days' },
] as const

function abbreviateAddress(address: string): string {
  if (address.length <= 22) return address
  return `${address.slice(0, 6)}...${address.slice(-4)}`
}

function formatInterval(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600} hour${seconds === 3600 ? '' : 's'}`
  if (seconds % 60 === 0) return `${seconds / 60} minutes`
  return `${seconds} seconds`
}

function formatSigned(raw: bigint, symbol: string): string {
  const sign = raw > 0n ? '+' : ''
  return `${sign}${formatTokenAmount(raw)} ${symbol}`
}

function paceLabel(pace: SpendPace): string {
  if (pace === 'faster') return 'Faster than the previous window'
  if (pace === 'slower') return 'Slower than the previous window'
  if (pace === 'same') return 'Same as the previous window'
  return 'Not enough history'
}

function chartHeights(points: ActivityTokenWindow['series']): number[] {
  if (points.length === 0) return []
  const values = points.map((point) => point.balance)
  const min = values.reduce((left, right) => (left < right ? left : right))
  const max = values.reduce((left, right) => (left > right ? left : right))
  const span = max - min
  if (span === 0n) return values.map(() => 0)
  return values.map((value) => Number(((value - min) * 1000n) / span))
}

function BalanceSparkline({
  points,
  label,
}: {
  points: ActivityTokenWindow['series']
  label: string
}) {
  const heights = chartHeights(points)
  if (heights.length < 2) return null
  const width = 320
  const height = 64
  const coords = heights
    .map((value, index) => {
      const x = (index / (heights.length - 1)) * width
      const y = height - 2 - (value / 1000) * (height - 4)
      return `${x},${y}`
    })
    .join(' ')
  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      className="admin-sparkline"
      role="img"
      aria-label={label}
    >
      <polyline fill="none" stroke="currentColor" strokeWidth="2" points={coords} />
    </svg>
  )
}

function BurnColumn({
  title,
  symbol,
  token,
}: {
  title: string
  symbol: string
  token: ActivityTokenWindow
}) {
  const pace = spendPace(token.comparable, token.outflow, token.priorOutflow)
  return (
    <div className="admin-burn-column">
      <div className="admin-burn-label">{title}</div>
      <div className="admin-burn-value">{formatTokenAmount(token.outflow)} {symbol}</div>
      <div className="admin-burn-meta">
        Previous window {formatTokenAmount(token.priorOutflow)} {symbol}
      </div>
      <div className="admin-burn-meta">Net {formatSigned(token.net, symbol)}</div>
      <span className={`admin-status-badge admin-pace admin-pace--${pace}`}>{paceLabel(pace)}</span>
      {token.latest != null && token.latestAt ? (
        <div className="admin-burn-meta">
          Latest {formatTokenAmount(token.latest)} {symbol} at {new Date(token.latestAt).toLocaleString()}
        </div>
      ) : (
        <div className="admin-burn-meta">No balance sample yet</div>
      )}
      <BalanceSparkline points={token.series} label={`${title} spendable balance`} />
    </div>
  )
}

function formatChartDay(day: string): string {
  const [year, month, date] = day.split('-').map(Number)
  if (!year || !month || !date) return day
  return new Date(year, month - 1, date).toLocaleDateString(undefined, {
    month: 'numeric',
    day: 'numeric',
  })
}

type MemoryBucket = { key: string; label: string; detail: string; count: number }

// `YYYY-MM-DDTHH:00` is already on the viewer's clock, so no Date parsing.
function formatChartHour(hour: string): string {
  const [day, time] = hour.split('T')
  if (!day || !time) return hour
  // A 24h window spans two dates, and "00:00" at both ends reads the same.
  // Name the date at midnight instead.
  return time === '00:00' ? formatChartDay(day) : time
}

function describeChartHour(hour: string): string {
  const [day, time] = hour.split('T')
  return day && time ? `${formatChartDay(day)} ${time}` : hour
}

function MemoryChart({
  days,
  hours,
}: {
  days: { day: string; count: number }[]
  hours: { hour: string; count: number }[] | null
}) {
  const hourly = hours != null && hours.length > 0
  const buckets: MemoryBucket[] = hourly
    ? hours.map((h) => ({
        key: h.hour,
        label: formatChartHour(h.hour),
        detail: describeChartHour(h.hour),
        count: h.count,
      }))
    : days.map((d) => {
        const label = formatChartDay(d.day)
        return { key: d.day, label, detail: label, count: d.count }
      })
  if (buckets.length === 0) {
    return <p className="admin-memory-summary">No memories written in this window</p>
  }
  const unit = hourly ? 'hour' : 'day'
  const total = buckets.reduce((sum, b) => sum + b.count, 0)
  const peak = buckets.reduce((best, b) => (b.count > best.count ? b : best), buckets[0])
  const max = Math.max(1, ...buckets.map((b) => b.count))
  const labelStep = hourly ? 3 : buckets.length > 16 ? 5 : buckets.length > 8 ? 2 : 1
  const summary =
    total === 0
      ? 'No memories written in this window'
      : `${total} ${total === 1 ? 'memory' : 'memories'} · busiest ${unit} ${peak.detail} with ${peak.count}`
  return (
    <div className={`admin-memory-chart${hourly ? ' admin-memory-chart--hourly' : ''}`}>
      <p className="admin-memory-summary">{summary}</p>
      <div className="admin-memory-bars" role="img" aria-label={summary}>
        {buckets.map((b, index) => (
          <div className="admin-memory-bar" key={b.key} title={`${b.detail}: ${b.count}`}>
            <div
              className={`admin-memory-bar-fill${b.count === 0 ? ' admin-memory-bar-fill--zero' : ''}${index === buckets.length - 1 ? ' admin-memory-bar-fill--latest' : ''}`}
              style={{ height: `${(b.count / max) * 100}%` }}
            >
              {b.count > 0 && !hourly && <span className="admin-memory-bar-count">{b.count}</span>}
            </div>
          </div>
        ))}
      </div>
      <div className="admin-memory-axis" aria-hidden="true">
        {buckets.map((b, index) => {
          const show = index % labelStep === 0 || index === buckets.length - 1
          if (!show) return null
          return (
            <span key={b.key} style={{ left: `${((index + 0.5) / buckets.length) * 100}%` }}>
              {b.label}
            </span>
          )
        })}
      </div>
    </div>
  )
}

function countLine(label: string, count: number, prior: number | null) {
  return (
    <div className="admin-action-row" key={label}>
      <span>{label}</span>
      <span className="admin-table-monospace">
        {count}
        {prior == null ? '' : ` · previous ${prior}`}
      </span>
    </div>
  )
}

const PREVIEW_ACTIVITY: AdminActivity = {
  generatedAt: '2026-09-24T12:00:00.000Z',
  windowHours: 24,
  balanceMonitorIntervalSecs: 300,
  uploaderWal: {
    samples: 8,
    comparable: true,
    latest: 1_240_000_000_000n,
    latestAt: '2026-09-24T11:55:00.000Z',
    outflow: 86_500_000_000n,
    priorOutflow: 41_200_000_000n,
    net: -62_000_000_000n,
    series: [1400, 1360, 1310, 1288, 1264, 1251, 1244, 1240].map((whole, index) => ({
      at: new Date(Date.UTC(2026, 8, 24, index * 3)).toISOString(),
      balance: BigInt(whole) * 1_000_000_000n,
    })),
  },
  uploaderSui: {
    samples: 8,
    comparable: true,
    latest: 42_800_000_000n,
    latestAt: '2026-09-24T11:55:00.000Z',
    outflow: 3_400_000_000n,
    priorOutflow: 6_100_000_000n,
    net: -1_200_000_000n,
    series: [48, 47, 46, 45.5, 44.8, 44.1, 43.4, 42.8].map((whole, index) => ({
      at: new Date(Date.UTC(2026, 8, 24, index * 3)).toISOString(),
      balance: BigInt(Math.round(whole * 1000)) * 1_000_000n,
    })),
  },
  sponsorSui: {
    samples: 8,
    comparable: true,
    latest: 18_600_000_000n,
    latestAt: '2026-09-24T11:55:00.000Z',
    outflow: 900_000_000n,
    priorOutflow: 900_000_000n,
    net: -900_000_000n,
    series: [19.5, 19.3, 19.2, 19.1, 19, 18.9, 18.8, 18.6].map((whole, index) => ({
      at: new Date(Date.UTC(2026, 8, 24, index * 3)).toISOString(),
      balance: BigInt(Math.round(whole * 1000)) * 1_000_000n,
    })),
  },
  actions: {
    uploadsCompleted: 128,
    uploadsCompletedPrior: 96,
    uploadsFailed: 4,
    uploadsFailedPrior: 7,
    uploadsInFlight: 2,
    memoryDeletes: 11,
    memoryDeletesPrior: 3,
    securityDeleteBatches: 1,
    securityDeleteBatchesPrior: 0,
    securityDeleteBlobs: 40,
    securityDeleteBlobsPrior: 0,
    sponsored: [
      { kind: 'create_account', count: 6, priorCount: 2 },
      { kind: 'add_delegate_key', count: 9, priorCount: 9 },
      { kind: 'remove_delegate_key', count: 1, priorCount: 0 },
    ],
    topOwners: [
      { owner: '0x8c4e91ab23f04d11a0c8e21b77aa9012cd34ef56', uploadsCompleted: 41 },
      { owner: '0x11aa90bb33445566778899aabbccddeeff001122', uploadsCompleted: 27 },
      { owner: '0xabcdef0123456789abcdef0123456789abcdef01', uploadsCompleted: 14 },
    ],
    memoriesByDay: [2, 0, 5, 4, 9, 3, 8, 6].map((count, index) => ({
      day: new Date(Date.UTC(2026, 8, 17 + index)).toISOString().slice(0, 10),
      count,
    })),
    memoriesByHour: null,
  },
}

function ActivityBody({ data, hours, onHours, afterMemories }: {
  data: AdminActivity
  hours: number
  onHours: (hours: number) => void
  afterMemories?: ReactNode
}) {
  const { actions } = data
  return (
    <div className="admin-activity-section">
      <Card
        title="Wallet outflow"
        subtitle="Sum of spendable-balance drops. A top-up does not hide drain."
        className="dashboard-keys-card sept-section admin-activity-card"
        action={
          <div className="admin-window-toggle">
            {WINDOWS.map((choice) => (
              <button
                key={choice.hours}
                type="button"
                className={`btn btn-secondary btn-sm${hours === choice.hours ? ' admin-window-btn--active' : ''}`}
                onClick={() => onHours(choice.hours)}
              >
                {choice.label}
              </button>
            ))}
          </div>
        }
      >
        <div className="admin-burn-grid">
          <BurnColumn title="Uploader WAL" symbol="WAL" token={data.uploaderWal} />
          <BurnColumn title="Uploader SUI" symbol="SUI" token={data.uploaderSui} />
          <BurnColumn title="Sponsor SUI" symbol="SUI" token={data.sponsorSui} />
        </div>
        <p className="admin-activity-note">
          Samples are recorded about every {formatInterval(data.balanceMonitorIntervalSecs)} and
          kept for 60 days. Comparing a window with the one before it needs samples in both, so a
          30-day comparison stays incomplete until the monitor has been running about 60 days.
        </p>
      </Card>

      <Card
        title="Memories written"
        subtitle={
          actions.memoriesByHour
            ? 'Completed remember jobs in each hour of this window, on your clock. The first and last hours can be partial.'
            : 'Completed remember jobs on each calendar day in this window. The first and last days can be partial.'
        }
        className="dashboard-keys-card sept-section admin-activity-card"
      >
        <MemoryChart days={actions.memoriesByDay} hours={actions.memoriesByHour} />
      </Card>

      {afterMemories}

      <Card
        title="Actions"
        subtitle="Work in this window versus the previous one of the same length."
        className="dashboard-keys-card sept-section admin-activity-card"
      >
        <div className="admin-action-list">
          {countLine('Uploads completed', actions.uploadsCompleted, actions.uploadsCompletedPrior)}
          {countLine('Uploads failed', actions.uploadsFailed, actions.uploadsFailedPrior)}
          {countLine('Uploads in flight now', actions.uploadsInFlight, null)}
          {countLine('Memory deletes', actions.memoryDeletes, actions.memoryDeletesPrior)}
          {actions.securityDeleteBatches == null ? (
            <div className="admin-action-row">
              <span>Security delete</span>
              <span>Not configured</span>
            </div>
          ) : (
            <>
              {countLine(
                'Security-delete batches',
                actions.securityDeleteBatches,
                actions.securityDeleteBatchesPrior,
              )}
              {countLine(
                'Security-delete blobs',
                actions.securityDeleteBlobs ?? 0,
                actions.securityDeleteBlobsPrior,
              )}
            </>
          )}
          {actions.sponsored.map((row) =>
            countLine(
              `Sponsored ${row.kind.replace(/_/g, ' ')}`,
              row.count,
              row.priorCount,
            ),
          )}
        </div>
        <p className="admin-activity-note">
          Sponsored rows count account create and delegate-key transactions that executed after
          this version deployed, and are kept for 60 days. Upload rows are remember jobs.
        </p>
        <div className="admin-table-wrapper">
          <table className="admin-table">
            <thead>
              <tr>
                <th scope="col">Top owners</th>
                <th scope="col" style={{ textAlign: 'right' }}>Completed uploads</th>
              </tr>
            </thead>
            <tbody>
              {actions.topOwners.length === 0 ? (
                <tr>
                  <td colSpan={2} className="admin-table-empty">
                    No completed uploads in this window
                  </td>
                </tr>
              ) : (
                actions.topOwners.map((owner) => (
                  <tr key={owner.owner} className="admin-table-row">
                    <td className="admin-table-monospace">
                      <CopyableText
                        value={owner.owner}
                        display={abbreviateAddress(owner.owner)}
                        label="Copy owner address"
                      />
                    </td>
                    <td className="admin-table-monospace" style={{ textAlign: 'right' }}>
                      {owner.uploadsCompleted}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

export function AdminActivityPanel({ adminKey, onInvalidKey, preview = false, afterMemories }: AdminActivityProps) {
  const [hours, setHours] = useState<number>(24)
  const { data, isLoading, error } = useQuery({
    queryKey: ['admin', 'activity', hours],
    queryFn: () => fetchAdminActivity(adminKey, hours),
    enabled: !preview,
    refetchInterval: preview ? false : 60_000,
    retry: (failureCount, error) => {
      const err = error as Error
      return err.message !== 'INVALID_KEY' && failureCount < 3
    },
  })

  const isInvalidKey = !preview && error instanceof Error && error.message === 'INVALID_KEY'

  useEffect(() => {
    if (isInvalidKey) onInvalidKey()
  }, [isInvalidKey, onInvalidKey])

  if (preview) {
    return <ActivityBody data={PREVIEW_ACTIVITY} hours={hours} onHours={setHours} afterMemories={afterMemories} />
  }

  if (isLoading) {
    return (
      <div className="admin-activity-section">
        <Card title="Wallet outflow" className="dashboard-keys-card sept-section admin-activity-card">
          <div className="admin-loading">Loading spend and activity...</div>
        </Card>
        {afterMemories}
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="admin-activity-section">
        <Card title="Wallet outflow" className="dashboard-keys-card sept-section admin-activity-card">
          <div className="admin-error">
            {isInvalidKey ? 'Invalid API key — signing out...' : 'Failed to load spend and activity'}
          </div>
        </Card>
        {afterMemories}
      </div>
    )
  }

  return <ActivityBody data={data} hours={hours} onHours={setHours} afterMemories={afterMemories} />
}

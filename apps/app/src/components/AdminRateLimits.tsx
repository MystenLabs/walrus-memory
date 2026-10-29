import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { useInfiniteQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Plus, Trash2 } from 'lucide-react'
import { Card } from './Card'
import {
  fetchOwnerRateLimitList,
  saveOwnerRateLimits,
  resetOwnerRateLimits,
} from '../utils/admin-api'
import type { OwnerRateLimitPolicy } from '../utils/admin-api'

const MULTIPLIERS = [2, 5, 10, 20] as const
const QUERY_KEY = ['admin', 'owner-rate-limits']
type SavedWallet = OwnerRateLimitPolicy & { owner: string }
const budgetKeys = [
  'requests_per_minute',
  'requests_per_hour',
  'delegate_key_per_minute',
] as const

function currentMultiplier(
  policy: OwnerRateLimitPolicy,
  defaults: OwnerRateLimitPolicy,
): string {
  return String(
    MULTIPLIERS.find((value) =>
      budgetKeys.every((key) => policy[key] === defaults[key] * value),
    ) ?? 'custom',
  )
}

function WalletRow({
  saved,
  defaults,
  adminKey,
  onInvalidKey,
  onSaved,
  onRemove,
}: {
  saved?: SavedWallet
  defaults: OwnerRateLimitPolicy
  adminKey: string
  onInvalidKey: () => void
  onSaved: () => void
  onRemove: () => void
}) {
  const [owner, setOwner] = useState(saved?.owner ?? '')
  const [multiplier, setMultiplier] = useState(
    saved ? currentMultiplier(saved, defaults) : '2',
  )
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const expired =
    saved?.expires_at && Date.parse(saved.expires_at) <= Date.now()
  const run = async (action: () => Promise<unknown>, done: () => void) => {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      await action()
      done()
    } catch (err) {
      if (err instanceof Error && err.message === 'INVALID_KEY') onInvalidKey()
      else setError('Không lưu được thay đổi. Kiểm tra địa chỉ ví và thử lại.')
    } finally {
      setBusy(false)
    }
  }
  const save = (event: FormEvent) => {
    event.preventDefault()
    const factor = Number(multiplier)
    if (!MULTIPLIERS.some((value) => value === factor)) return
    const policy = {
      requests_per_minute: defaults.requests_per_minute * factor,
      requests_per_hour: defaults.requests_per_hour * factor,
      delegate_key_per_minute: defaults.delegate_key_per_minute * factor,
      expires_at: saved?.expires_at && !expired ? saved.expires_at : null,
    }
    void run(
      () => saveOwnerRateLimits(adminKey, owner.trim(), policy),
      () => {
        setMessage('Đã lưu')
        onSaved()
      },
    )
  }
  const remove = () => {
    if (!saved) {
      onRemove()
      return
    }
    void run(() => resetOwnerRateLimits(adminKey, saved.owner), onRemove)
  }
  return (
    <li className="admin-priority-wallet">
      <form className="admin-priority-row" onSubmit={save}>
        <input
          aria-label="Địa chỉ ví"
          className="admin-priority-address"
          placeholder="Địa chỉ ví · 0x…"
          required
          pattern="0x[0-9a-fA-F]{1,64}"
          value={owner}
          readOnly={!!saved}
          disabled={busy}
          onChange={(event) => setOwner(event.target.value)}
        />
        <select
          aria-label="Mức ưu tiên"
          className="admin-priority-select"
          value={multiplier}
          disabled={busy}
          onChange={(event) => {
            setMultiplier(event.target.value)
            setMessage('')
          }}
        >
          {multiplier === 'custom' && (
            <option value="custom" disabled>
              Tùy chỉnh
            </option>
          )}
          {MULTIPLIERS.map((value) => (
            <option key={value} value={value}>
              ×{value}
            </option>
          ))}
        </select>
        <div className="admin-priority-actions">
          <button
            type="submit"
            className="btn btn-secondary btn-sm"
            aria-label="Lưu ví"
            disabled={busy || multiplier === 'custom'}
          >
            <Check size={16} />
            <span>Lưu</span>
          </button>
          <button
            type="button"
            className="admin-priority-remove"
            aria-label="Xóa ví ưu tiên"
            disabled={busy}
            onClick={remove}
          >
            <Trash2 size={17} />
          </button>
        </div>
      </form>
      {expired && (
        <span className="admin-priority-note">
          Đã hết hạn · Lưu để kích hoạt lại
        </span>
      )}
      {message && (
        <span role="status" className="admin-priority-note">
          {message}
        </span>
      )}
      {error && (
        <span role="alert" className="admin-error">
          {error}
        </span>
      )}
    </li>
  )
}

export function AdminRateLimits({
  adminKey,
  onInvalidKey,
}: {
  adminKey: string
  onInvalidKey: () => void
}) {
  const client = useQueryClient()
  const [drafts, setDrafts] = useState<string[]>([])
  const {
    data,
    isLoading,
    error,
    refetch,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: QUERY_KEY,
    queryFn: ({ pageParam }) => fetchOwnerRateLimitList(adminKey, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    retry: (count, err) => err.message !== 'INVALID_KEY' && count < 2,
  })
  const refresh = () => {
    void client.invalidateQueries({ queryKey: QUERY_KEY })
  }
  const defaults = data?.pages[0]?.defaults
  const wallets = data?.pages.flatMap((page) => page.policies) ?? []
  const invalidKey = error instanceof Error && error.message === 'INVALID_KEY'
  useEffect(() => {
    if (invalidKey) onInvalidKey()
  }, [invalidKey, onInvalidKey])
  return (
    <Card
      title="Ví ưu tiên"
      subtitle="Tăng giới hạn cho từng ví. Các ví khác giữ nguyên mức mặc định."
      className="dashboard-keys-card sept-section admin-activity-card admin-priority-card"
    >
      {isLoading && (
        <p className="admin-activity-note">Đang tải danh sách ví…</p>
      )}
      {error && (
        <div className="admin-error" role="alert">
          {invalidKey
            ? 'Phiên admin đã hết hạn.'
            : 'Không tải được danh sách ví.'}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => (invalidKey ? onInvalidKey() : void refetch())}
          >
            Thử lại
          </button>
        </div>
      )}
      {defaults && (
        <>
          <ul className="admin-priority-list">
            {wallets.map((wallet) => (
              <WalletRow
                key={wallet.owner}
                saved={wallet}
                defaults={defaults}
                adminKey={adminKey}
                onInvalidKey={onInvalidKey}
                onSaved={refresh}
                onRemove={refresh}
              />
            ))}
            {drafts.map((id) => (
              <WalletRow
                key={id}
                defaults={defaults}
                adminKey={adminKey}
                onInvalidKey={onInvalidKey}
                onSaved={() => {
                  setDrafts((rows) => rows.filter((row) => row !== id))
                  refresh()
                }}
                onRemove={() =>
                  setDrafts((rows) => rows.filter((row) => row !== id))
                }
              />
            ))}
          </ul>
          {wallets.length === 0 && drafts.length === 0 && (
            <p className="admin-priority-empty">Chưa có ví ưu tiên</p>
          )}
          {hasNextPage && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={isFetchingNextPage}
              onClick={() => void fetchNextPage()}
            >
              Xem thêm
            </button>
          )}
          <button
            type="button"
            className="admin-priority-add"
            onClick={() => setDrafts((rows) => [...rows, crypto.randomUUID()])}
          >
            <Plus size={20} />
            <span>Thêm ví</span>
          </button>
          <p className="admin-activity-note admin-priority-footnote">
            Hệ số áp dụng cho giới hạn đọc/ghi của ví, dựa trên mức mặc định tại
            lúc lưu.
          </p>
        </>
      )}
    </Card>
  )
}

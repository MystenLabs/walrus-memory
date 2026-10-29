import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { useInfiniteQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Plus, RefreshCw, Trash2 } from 'lucide-react'
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
  const [isSaved, setIsSaved] = useState(!!saved)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const expired =
    saved?.expires_at && Date.parse(saved.expires_at) <= Date.now()
  const run = async (action: () => Promise<unknown>, done: () => void) => {
    setBusy(true)
    setError('')
    try {
      await action()
      done()
    } catch (err) {
      if (err instanceof Error && err.message === 'INVALID_KEY') onInvalidKey()
      else
        setError(
          'Unable to save changes. Check the wallet address and try again.',
        )
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
    setIsSaved(false)
    void run(
      () => saveOwnerRateLimits(adminKey, owner.trim(), policy),
      () => {
        setIsSaved(true)
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
          aria-label="Wallet address"
          className="dashboard-add-key-input admin-priority-address"
          placeholder="Wallet address · 0x…"
          required
          pattern="0x[0-9a-fA-F]{1,64}"
          value={owner}
          readOnly={!!saved}
          disabled={busy}
          onChange={(event) => {
            setOwner(event.target.value)
            setIsSaved(false)
          }}
        />
        <select
          aria-label="Rate multiplier"
          className="dashboard-add-key-input admin-priority-select"
          value={multiplier}
          disabled={busy}
          onChange={(event) => {
            setMultiplier(event.target.value)
            setIsSaved(false)
          }}
        >
          {multiplier === 'custom' && (
            <option value="custom" disabled>
              Custom
            </option>
          )}
          {MULTIPLIERS.map((value) => (
            <option key={value} value={value}>
              ×{value}
            </option>
          ))}
        </select>
        <div className="dashboard-add-key-actions dashboard-key-row-actions admin-priority-actions">
          <button
            type="submit"
            className="btn dashboard-add-key-create"
            aria-label="Save wallet"
            disabled={busy || multiplier === 'custom'}
          >
            <span className="admin-priority-save-indicator">
              {isSaved && <Check size={16} aria-label="Wallet saved" />}
            </span>
            <span>Save</span>
          </button>
          <button
            type="button"
            className="btn btn-danger btn-sm dashboard-key-icon-action"
            aria-label="Remove priority wallet"
            disabled={busy}
            onClick={remove}
          >
            <Trash2 size={17} />
          </button>
        </div>
      </form>
      {expired && (
        <span className="admin-priority-note">
          Expired · Save to reactivate
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
  const addWallet = () => setDrafts((rows) => [...rows, crypto.randomUUID()])
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
      title="Priority wallets"
      subtitle="Manage wallets with higher request limits. All other wallets keep the default limits."
      className="dashboard-keys-card sept-section admin-priority-card"
      action={
        <div className="card-header-actions">
          <button
            type="button"
            className="btn btn-secondary btn-sm dashboard-keys-refresh"
            disabled={isLoading}
            onClick={() => void refetch()}
          >
            <span>Refresh</span>
            <RefreshCw size={12} aria-hidden="true" />
          </button>
          <button
            type="button"
            className="lp-nav-cta dashboard-keys-add"
            disabled={!defaults}
            onClick={addWallet}
          >
            Add wallet <Plus size={18} strokeWidth={2.5} aria-hidden="true" />
          </button>
        </div>
      }
    >
      {isLoading && (
        <p className="admin-activity-note">Loading priority wallets…</p>
      )}
      {error && (
        <div className="admin-error" role="alert">
          {invalidKey
            ? 'Your admin session has expired.'
            : 'Unable to load priority wallets.'}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => (invalidKey ? onInvalidKey() : void refetch())}
          >
            Try again
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
            <div className="dashboard-empty-message dashboard-empty-message--account">
              <span>No priority wallets yet. </span>
              <button
                type="button"
                className="dashboard-empty-message-link"
                onClick={addWallet}
              >
                Add a wallet
              </button>
              <span> to give it a higher request limit.</span>
            </div>
          )}
          {hasNextPage && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={isFetchingNextPage}
              onClick={() => void fetchNextPage()}
            >
              Load more
            </button>
          )}
          <p className="admin-activity-note admin-priority-footnote">
            Each multiplier applies to the current default limits when saved.
          </p>
        </>
      )}
    </Card>
  )
}

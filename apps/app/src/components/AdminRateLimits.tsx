import { useState } from 'react'
import type { FormEvent } from 'react'
import { Card } from './Card'
import {
  fetchOwnerRateLimits,
  saveOwnerRateLimits,
  resetOwnerRateLimits,
} from '../utils/admin-api'
import type { OwnerRateLimitResponse } from '../utils/admin-api'

const fields = [
  ['requests_per_minute', 'Account points / minute', 1_000_000],
  ['requests_per_hour', 'Account points / hour', 100_000_000],
  ['delegate_key_per_minute', 'Each delegate key points / minute', 1_000_000],
] as const

function localDateTime(value: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
    .toISOString()
    .slice(0, 16)
}

export function AdminRateLimits({
  adminKey,
  onInvalidKey,
}: {
  adminKey: string
  onInvalidKey: () => void
}) {
  const [owner, setOwner] = useState('')
  const [data, setData] = useState<OwnerRateLimitResponse | null>(null)
  const [values, setValues] = useState({
    requests_per_minute: '',
    requests_per_hour: '',
    delegate_key_per_minute: '',
  })
  const [expiresAt, setExpiresAt] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const accept = (result: OwnerRateLimitResponse) => {
    setData(result)
    const policy = result.override_policy ?? result.defaults
    setValues({
      requests_per_minute: String(policy.requests_per_minute),
      requests_per_hour: String(policy.requests_per_hour),
      delegate_key_per_minute: String(policy.delegate_key_per_minute),
    })
    setExpiresAt(localDateTime(policy.expires_at))
  }
  const run = async (
    operation: () => Promise<OwnerRateLimitResponse>,
    success: string,
  ) => {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      accept(await operation())
      setMessage(success)
    } catch (err) {
      if (err instanceof Error && err.message === 'INVALID_KEY') onInvalidKey()
      else
        setError(
          'Unable to update or load limits. Check the address, values, expiry, and connection, then try again.',
        )
    } finally {
      setBusy(false)
    }
  }
  const load = (event: FormEvent) => {
    event.preventDefault()
    // Clear a previous owner's policy even if this lookup fails.
    setData(null)
    void run(() => fetchOwnerRateLimits(adminKey, owner.trim()), '')
  }
  const save = (event: FormEvent) => {
    event.preventDefault()
    if (!data) return
    const policy = {
      requests_per_minute: Number(values.requests_per_minute),
      requests_per_hour: Number(values.requests_per_hour),
      delegate_key_per_minute: Number(values.delegate_key_per_minute),
      expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
    }
    if (
      fields.some(
        ([key, , max]) =>
          !Number.isSafeInteger(policy[key]) ||
          policy[key] < 1 ||
          policy[key] > max,
      ) ||
      (policy.expires_at && Date.parse(policy.expires_at) <= Date.now())
    ) {
      setError(
        'Enter positive whole-number limits and a future expiry, or leave expiry empty.',
      )
      return
    }
    void run(
      () => saveOwnerRateLimits(adminKey, data.owner, policy),
      'Override saved. New requests use these limits.',
    )
  }
  const expired =
    data?.override_policy?.expires_at &&
    Date.parse(data.override_policy.expires_at) <= Date.now()

  return (
    <Card
      title="Owner rate limits"
      className="dashboard-keys-card admin-rate-limits-card"
    >
      <p className="admin-rate-description">
        Set weighted request budgets for one owner wallet and its delegate keys.
        Other owners keep the environment defaults. Existing usage counters are
        preserved.
      </p>
      <form onSubmit={load} className="admin-rate-lookup">
        <label htmlFor="rate-owner">Owner wallet address</label>
        <div className="admin-rate-lookup-row">
          <input
            id="rate-owner"
            required
            pattern="0x[0-9a-fA-F]{1,64}"
            placeholder="0x…"
            value={owner}
            disabled={busy}
            onChange={(event) => {
              setOwner(event.target.value)
              setData(null)
              setMessage('')
              setError('')
            }}
          />
          <button className="lp-nav-cta" disabled={busy} type="submit">
            {busy ? 'Working…' : 'Load limits'}
          </button>
        </div>
      </form>
      {error && (
        <p role="alert" className="admin-error">
          {error}
        </p>
      )}
      {message && <p role="status">{message}</p>}
      {data && (
        <form onSubmit={save}>
          <p className="admin-rate-owner">
            <strong>Owner:</strong> <code>{data.owner}</code>
          </p>
          <p>
            {data.override_policy
              ? expired
                ? 'Override expired. Environment defaults are active.'
                : 'Owner override is active.'
              : 'Using environment defaults.'}
          </p>
          <div className="admin-rate-grid">
            {fields.map(([key, label, max]) => (
              <label key={key} htmlFor={`rate-${key}`}>
                <span>{label}</span>
                <input
                  id={`rate-${key}`}
                  type="number"
                  aria-label={label}
                  required
                  min={1}
                  max={max}
                  step={1}
                  value={values[key]}
                  disabled={busy}
                  onChange={(event) =>
                    setValues((previous) => ({
                      ...previous,
                      [key]: event.target.value,
                    }))
                  }
                />
                <small>
                  Default: {data.defaults[key].toLocaleString()} · Effective:{' '}
                  {data.effective[key].toLocaleString()}
                </small>
              </label>
            ))}
            <label htmlFor="rate-expiry">
              <span>Expires at (your local time)</span>
              <input
                id="rate-expiry"
                type="datetime-local"
                value={expiresAt}
                disabled={busy}
                onChange={(event) => setExpiresAt(event.target.value)}
              />
              <small>
                Leave empty for no expiry. Expiry restores environment defaults.
              </small>
            </label>
          </div>
          <p className="admin-rate-description">
            These budgets cover recall, writes, and status polling. They do not
            change storage quotas, MCP transport limits, sponsor limits, or the
            separate owner read API.
          </p>
          <div className="admin-rate-actions">
            <button className="lp-nav-cta" disabled={busy} type="submit">
              Save override
            </button>
            <button
              className="admin-rate-reset"
              disabled={busy || !data.override_policy}
              type="button"
              onClick={() =>
                void run(
                  () => resetOwnerRateLimits(adminKey, data.owner),
                  'Override removed. Environment defaults apply.',
                )
              }
            >
              Restore defaults
            </button>
          </div>
        </form>
      )}
    </Card>
  )
}

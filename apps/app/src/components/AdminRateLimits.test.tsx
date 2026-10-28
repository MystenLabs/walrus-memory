import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AdminRateLimits } from './AdminRateLimits'
import {
  fetchOwnerRateLimits,
  saveOwnerRateLimits,
  resetOwnerRateLimits,
} from '../utils/admin-api'

vi.mock('../utils/admin-api', () => ({
  fetchOwnerRateLimits: vi.fn(),
  saveOwnerRateLimits: vi.fn(),
  resetOwnerRateLimits: vi.fn(),
}))
const defaults = {
  requests_per_minute: 60,
  requests_per_hour: 500,
  delegate_key_per_minute: 30,
  expires_at: null,
}
const owner = `0x${'1'.padStart(64, '0')}`
const base = { owner, defaults, effective: defaults, override_policy: null }
const onInvalidKey = vi.fn()
afterEach(cleanup)
beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(fetchOwnerRateLimits).mockResolvedValue(base)
})
async function load() {
  fireEvent.change(screen.getByLabelText('Owner wallet address'), {
    target: { value: '0x1' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Load limits' }))
  await screen.findByRole('button', { name: 'Save override' })
}
describe('AdminRateLimits', () => {
  it('loads, saves using the canonical returned owner, and restores defaults', async () => {
    const override = { ...defaults, requests_per_minute: 180 }
    vi.mocked(saveOwnerRateLimits).mockResolvedValue({
      ...base,
      override_policy: override,
      effective: override,
    })
    vi.mocked(resetOwnerRateLimits).mockResolvedValue(base)
    render(<AdminRateLimits adminKey="test-key" onInvalidKey={onInvalidKey} />)
    await load()
    expect(fetchOwnerRateLimits).toHaveBeenCalledWith('test-key', '0x1')
    fireEvent.change(screen.getByLabelText('Account points / minute'), {
      target: { value: '180' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save override' }))
    await screen.findByText('Override saved. New requests use these limits.')
    expect(saveOwnerRateLimits).toHaveBeenCalledWith(
      'test-key',
      owner,
      override,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Restore defaults' }))
    await screen.findByText('Override removed. Environment defaults apply.')
    expect(resetOwnerRateLimits).toHaveBeenCalledWith('test-key', owner)
  })
  it('discards the loaded policy when the operator changes the wallet', async () => {
    render(<AdminRateLimits adminKey="test-key" onInvalidKey={onInvalidKey} />)
    await load()
    fireEvent.change(screen.getByLabelText('Owner wallet address'), {
      target: { value: '0x2' },
    })
    expect(
      screen.queryByRole('button', { name: 'Save override' }),
    ).not.toBeInTheDocument()
    expect(saveOwnerRateLimits).not.toHaveBeenCalled()
  })
  it('signs out when the admin credential is rejected', async () => {
    vi.mocked(fetchOwnerRateLimits).mockRejectedValue(new Error('INVALID_KEY'))
    render(<AdminRateLimits adminKey="test-key" onInvalidKey={onInvalidKey} />)
    fireEvent.change(screen.getByLabelText('Owner wallet address'), {
      target: { value: '0x1' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Load limits' }))
    await waitFor(() => expect(onInvalidKey).toHaveBeenCalledOnce())
  })
  it('shows an expired override and rejects a past expiry', async () => {
    const expired = { ...defaults, expires_at: '2020-01-01T00:00:00Z' }
    vi.mocked(fetchOwnerRateLimits).mockResolvedValue({
      ...base,
      override_policy: expired,
    })
    render(<AdminRateLimits adminKey="test-key" onInvalidKey={onInvalidKey} />)
    await load()
    expect(
      screen.getByText('Override expired. Environment defaults are active.'),
    ).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save override' }))
    expect(screen.getByRole('alert')).toHaveTextContent('future expiry')
    expect(saveOwnerRateLimits).not.toHaveBeenCalled()
  })
})

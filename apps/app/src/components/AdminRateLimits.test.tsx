import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AdminRateLimits } from './AdminRateLimits'
import { AdminActivityPanel } from './AdminActivity'
import {
  fetchOwnerRateLimitList,
  saveOwnerRateLimits,
  resetOwnerRateLimits,
} from '../utils/admin-api'
vi.mock('../utils/admin-api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../utils/admin-api')>()),
  fetchOwnerRateLimitList: vi.fn(),
  saveOwnerRateLimits: vi.fn(),
  resetOwnerRateLimits: vi.fn(),
}))
const defaults = {
  requests_per_minute: 120,
  requests_per_hour: 1000,
  delegate_key_per_minute: 60,
  expires_at: null,
}
const owner = `0x${'1'.padStart(64, '0')}`
const empty = { defaults, policies: [], next_cursor: null }
const onInvalidKey = vi.fn()
let client: QueryClient
beforeEach(() => {
  vi.resetAllMocks()
  client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  vi.mocked(fetchOwnerRateLimitList).mockResolvedValue(empty)
})
afterEach(() => {
  cleanup()
  client.clear()
})
function show() {
  return render(
    <QueryClientProvider client={client}>
      <AdminRateLimits adminKey="test-key" onInvalidKey={onInvalidKey} />
    </QueryClientProvider>,
  )
}
async function add() {
  await waitFor(() =>
    expect(screen.getByRole('button', { name: 'Add wallet' })).toBeEnabled(),
  )
  fireEvent.click(screen.getByRole('button', { name: 'Add wallet' }))
  fireEvent.change(screen.getByLabelText('Wallet address'), {
    target: { value: '0x1' },
  })
}
describe('priority wallets', () => {
  it.each([2, 5, 10, 20])(
    'saves all three budgets at ×%s of current defaults',
    async (factor) => {
      vi.mocked(saveOwnerRateLimits).mockResolvedValue({
        owner,
        defaults,
        override_policy: null,
        effective: defaults,
      })
      show()
      await add()
      fireEvent.click(screen.getByRole('combobox', { name: 'Rate multiplier' }))
      fireEvent.click(screen.getByRole('option', { name: `×${factor}` }))
      fireEvent.click(screen.getByRole('button', { name: 'Save wallet' }))
      await waitFor(() =>
        expect(saveOwnerRateLimits).toHaveBeenCalledWith('test-key', '0x1', {
          requests_per_minute: 120 * factor,
          requests_per_hour: 1000 * factor,
          delegate_key_per_minute: 60 * factor,
          expires_at: null,
        }),
      )
    },
  )
  it('shows a check only for a saved value and clears it after an edit', async () => {
    const policy = {
      ...defaults,
      owner,
      requests_per_minute: 600,
      requests_per_hour: 5000,
      delegate_key_per_minute: 300,
    }
    vi.mocked(fetchOwnerRateLimitList).mockResolvedValue({
      ...empty,
      policies: [policy],
    })
    let resolveSave!: (
      value: Awaited<ReturnType<typeof saveOwnerRateLimits>>,
    ) => void
    vi.mocked(saveOwnerRateLimits).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveSave = resolve
        }),
    )
    show()
    expect(await screen.findByLabelText('Wallet saved')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('combobox', { name: 'Rate multiplier' }))
    fireEvent.click(screen.getByRole('option', { name: '×10' }))
    expect(screen.queryByLabelText('Wallet saved')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save wallet' }))
    expect(screen.queryByLabelText('Wallet saved')).not.toBeInTheDocument()
    resolveSave({ owner, defaults, override_policy: policy, effective: policy })
    expect(await screen.findByLabelText('Wallet saved')).toBeInTheDocument()
  })
  it('does not mark new or failed saves as saved', async () => {
    vi.mocked(saveOwnerRateLimits).mockRejectedValue(new Error('SERVER_ERROR'))
    show()
    await add()
    expect(screen.queryByLabelText('Wallet saved')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save wallet' }))
    await screen.findByRole('alert')
    expect(screen.queryByLabelText('Wallet saved')).not.toBeInTheDocument()
  })
  it('loads saved wallets and removes their override', async () => {
    vi.mocked(fetchOwnerRateLimitList).mockResolvedValue({
      ...empty,
      policies: [
        {
          ...defaults,
          owner,
          requests_per_minute: 600,
          requests_per_hour: 5000,
          delegate_key_per_minute: 300,
        },
      ],
    })
    vi.mocked(resetOwnerRateLimits).mockResolvedValue({
      owner,
      defaults,
      override_policy: null,
      effective: defaults,
    })
    show()
    expect(await screen.findByDisplayValue(owner)).toHaveAttribute('readonly')
    expect(screen.getByLabelText('Rate multiplier')).toHaveTextContent('×5')
    fireEvent.click(
      screen.getByRole('button', { name: 'Remove priority wallet' }),
    )
    await waitFor(() =>
      expect(resetOwnerRateLimits).toHaveBeenCalledWith('test-key', owner),
    )
  })
  it('removes an unsaved row without a backend mutation', async () => {
    show()
    await add()
    fireEvent.click(
      screen.getByRole('button', { name: 'Remove priority wallet' }),
    )
    expect(screen.queryByLabelText('Wallet address')).not.toBeInTheDocument()
    expect(resetOwnerRateLimits).not.toHaveBeenCalled()
  })
  it('signs out if listing rejects the admin credential', async () => {
    vi.mocked(fetchOwnerRateLimitList).mockRejectedValue(
      new Error('INVALID_KEY'),
    )
    show()
    await waitFor(() => expect(onInvalidKey).toHaveBeenCalled())
  })
  it('keeps a failed save editable', async () => {
    vi.mocked(saveOwnerRateLimits).mockRejectedValue(new Error('SERVER_ERROR'))
    show()
    await add()
    fireEvent.click(screen.getByRole('button', { name: 'Save wallet' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to save')
    expect(screen.getByLabelText('Wallet address')).toHaveValue('0x1')
  })
  it('sits immediately after Memories written and before Actions', () => {
    const { container } = render(
      <QueryClientProvider client={client}>
        <AdminActivityPanel
          adminKey="test-key"
          onInvalidKey={onInvalidKey}
          preview
          afterMemories={<div>Priority wallets</div>}
        />
      </QueryClientProvider>,
    )
    const sections = [
      ...container.querySelector('.admin-activity-section')!.children,
    ]
    expect(sections[1]).toHaveTextContent('Memories written')
    expect(sections[2]).toHaveTextContent('Priority wallets')
    expect(sections[3]).toHaveTextContent('Actions')
  })
})

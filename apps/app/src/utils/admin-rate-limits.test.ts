import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  fetchOwnerRateLimits,
  saveOwnerRateLimits,
  resetOwnerRateLimits,
} from './admin-api'
afterEach(() => vi.unstubAllGlobals())
describe('owner rate limit API', () => {
  it('uses private no-store requests and the admin header for each method', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => ({}) })
    vi.stubGlobal('fetch', fetchMock)
    const policy = {
      requests_per_minute: 180,
      requests_per_hour: 1500,
      delegate_key_per_minute: 90,
      expires_at: null,
    }
    await fetchOwnerRateLimits('test-key', '0x1')
    await saveOwnerRateLimits('test-key', '0x1', policy)
    await resetOwnerRateLimits('test-key', '0x1')
    expect(fetchMock.mock.calls.map((call) => call[1].method)).toEqual([
      'GET',
      'PUT',
      'DELETE',
    ])
    for (const [url, options] of fetchMock.mock.calls) {
      expect(url).toMatch(/\/api\/admin\/rate-limits\/0x1$/)
      expect(options.cache).toBe('no-store')
      expect(options.headers['x-admin-api-key']).toBe('test-key')
    }
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual(policy)
  })
})

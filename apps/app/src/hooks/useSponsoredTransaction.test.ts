import { afterEach, describe, expect, it, vi } from 'vitest'
import { assertRelayerPackageId, relayerPackageMismatch, SponsorHttpError, sponsorFailureMessage } from './useSponsoredTransaction'

describe('relayerPackageMismatch', () => {
    it('accepts the same package id ignoring case', () => {
        expect(relayerPackageMismatch('0xAbC', { packageId: '0xabc' })).toBeNull()
    })

    it('names both ids when they differ', () => {
        const message = relayerPackageMismatch('0xlocal', { packageId: '0xremote' })
        expect(message).toContain('0xlocal')
        expect(message).toContain('0xremote')
    })

    it('rejects a config body without packageId', () => {
        expect(relayerPackageMismatch('0xlocal', {})).toMatch(/packageId/)
        expect(relayerPackageMismatch('0xlocal', null)).toMatch(/packageId/)
    })
})

describe('assertRelayerPackageId', () => {
    afterEach(() => {
        vi.unstubAllGlobals()
    })

    it('throws before a transaction would be built when the package differs', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ packageId: '0xremote' }), { status: 200 })))
        await expect(assertRelayerPackageId('http://relayer.test/', '0xlocal')).rejects.toThrow(/0xremote/)
        expect(fetch).toHaveBeenCalledWith('http://relayer.test/config')
    })

    it('throws when /config is not OK', async () => {
        vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 503 })))
        await expect(assertRelayerPackageId('http://relayer.test', '0xlocal')).rejects.toThrow(/503/)
    })
})

describe('SponsorHttpError', () => {
    it('parses the relayer error envelope', () => {
        const err = new SponsorHttpError(
            'sponsor',
            400,
            JSON.stringify({ error: 'Sponsor request rejected', code: 'sponsor_rejected', traceId: 'req-1' }),
        )
        expect(err.detail).toBe('Sponsor request rejected')
        expect(err.code).toBe('sponsor_rejected')
        expect(err.traceId).toBe('req-1')
    })

    it('survives a non-JSON body', () => {
        const err = new SponsorHttpError('sponsor', 502, '<html>gateway</html>')
        expect(err.code).toBeUndefined()
        expect(err.detail).toBeUndefined()
        expect(err.body).toBe('<html>gateway</html>')
    })

    it('survives a JSON body that is not an object', () => {
        const err = new SponsorHttpError('sponsor', 400, '"just a string"')
        expect(err.code).toBeUndefined()
        expect(err.detail).toBeUndefined()
    })
})

describe('sponsorFailureMessage', () => {
    const bodyFor = (fields: Record<string, string>) => JSON.stringify(fields)

    it('surfaces the relayer reason when it rejected the request itself', () => {
        // Regression: an un-sponsorable transaction shape used to collapse into
        // the generic "please try again", which read as a transient blip and
        // hid the real cause — a bulk delegate-key revoke exceeding what the
        // sponsorship allowlist permits.
        const err = new SponsorHttpError(
            'sponsor',
            400,
            bodyFor({ error: 'Transaction kind is not permitted for sponsorship' }),
        )
        expect(sponsorFailureMessage(err)).toBe('Transaction kind is not permitted for sponsorship')
    })

    it('surfaces the removal-cap reason verbatim', () => {
        const err = new SponsorHttpError(
            'sponsor',
            400,
            bodyFor({ error: 'Too many delegate key removals in one transaction (max 20)' }),
        )
        expect(sponsorFailureMessage(err)).toContain('max 20')
    })

    it('says the account is already active instead of a generic sponsor rejection', () => {
        const err = new SponsorHttpError(
            'sponsor',
            409,
            bodyFor({
                error: 'This account is already active, so it cannot be reactivated.',
                code: 'account_already_active',
                traceId: 'req-11',
            }),
        )
        const message = sponsorFailureMessage(err)
        expect(message).toBe('This account is already active, so it cannot be reactivated. (traceId: req-11)')
        expect(message).not.toContain('rejected by the sponsor')
    })

    it('says the account is still locked when reactivation is quarantined', () => {
        const err = new SponsorHttpError(
            'sponsor',
            409,
            bodyFor({
                error: 'This account is still locked, so it cannot be reactivated yet.',
                code: 'account_quarantined',
                traceId: 'req-20',
            }),
        )
        expect(sponsorFailureMessage(err)).toContain('still locked')
        expect(sponsorFailureMessage(err)).toContain('traceId: req-20')
    })

    it('reports a masked upstream rejection with its traceId', () => {
        const err = new SponsorHttpError(
            'sponsor',
            400,
            bodyFor({ error: 'Sponsor request rejected', code: 'sponsor_rejected', traceId: 'req-7' }),
        )
        const message = sponsorFailureMessage(err)
        expect(message).toContain('rejected this transaction')
        expect(message).toContain('traceId: req-7')
    })

    it('calls out a misconfigured sponsor rather than blaming the transaction', () => {
        const err = new SponsorHttpError(
            'sponsor',
            502,
            bodyFor({ error: 'Sponsor service misconfigured', code: 'sponsor_misconfigured', traceId: 'req-8' }),
        )
        const message = sponsorFailureMessage(err)
        expect(message).toContain('misconfigured')
        expect(message).toContain('traceId: req-8')
    })

    it('keeps the rate-limit message ahead of any code handling', () => {
        const err = new SponsorHttpError('sponsor', 429, bodyFor({ error: 'Rate limit exceeded' }))
        expect(sponsorFailureMessage(err)).toContain('Too many requests')
    })

    it('treats an overloaded sponsor as transient', () => {
        const err = new SponsorHttpError(
            'sponsor',
            503,
            bodyFor({ error: 'Sponsor service temporarily overloaded', code: 'sponsor_overloaded' }),
        )
        expect(sponsorFailureMessage(err)).toContain('temporarily unavailable')
    })

    it('falls back to the generic message when the body carries nothing usable', () => {
        const err = new SponsorHttpError('sponsor', 400, '')
        expect(sponsorFailureMessage(err)).toBe('Sponsor request was rejected. Please try again.')
    })

    it('reports network failures distinctly', () => {
        expect(sponsorFailureMessage(new TypeError('Failed to fetch'))).toContain('Network error')
    })
})

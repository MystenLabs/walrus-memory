import { describe, expect, it } from 'vitest'
import { unblockRequestMessage } from './unblockRequest'

describe('unblockRequestMessage', () => {
    it('matches the relayer personal-message text', () => {
        const owner = `0x${'ab'.repeat(32)}`
        const account = `0x${'cd'.repeat(32)}`
        expect(unblockRequestMessage(owner.toUpperCase(), account)).toBe(
            `Walrus Memory unblock request\nowner:${owner}\naccount:${account}`,
        )
    })
})

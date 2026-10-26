/** Same bytes the relayer verifies in `routes/incident.rs`. */
export function unblockRequestMessage(owner: string, accountId: string): string {
    return `Walrus Memory unblock request\nowner:${owner.toLowerCase()}\naccount:${accountId.toLowerCase()}`
}

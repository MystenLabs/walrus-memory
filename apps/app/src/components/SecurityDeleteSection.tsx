import { useCallback, useEffect, useRef, useState } from 'react'
import { useCurrentAccount, useSignPersonalMessage, useSuiClient } from '@mysten/dapp-kit'
import { RefreshCw, ShieldAlert, Trash2 } from 'lucide-react'
import { config } from '../config'
import { useSecurityDeletion } from '../hooks/useSecurityDeletion'
import { clearSealSession, fetchAndDecryptBlob } from '../utils/blobPreview'
import { clearToken, withAuth, type SignPersonalMessage } from '../utils/securityDeleteAuth'
import { listBlobs, SdApiError, type BlobCounts, type BlobItem, type DeletionScope } from '../utils/securityDeleteApi'
import { BlobPreviewModal } from './BlobPreviewModal'
import { Card } from './Card'
import { SecurityDeleteTable } from './SecurityDeleteTable'

const EMPTY_COUNTS: BlobCounts = { total: 0, deletable: 0, deleting: 0, deleted: 0, deletedExternal: 0, notOwner: 0, expired: 0 }
const PROGRESS_STATES = 'deleting,deleted,deleted_external,not_owner,expired'
const PAGE_SIZE = 100

/** Windowed page-number strip: all pages when few, otherwise first/last plus
 *  the current page's neighbors with ellipsis gaps. */
function pageStrip(current: number, total: number): (number | 'gap')[] {
    if (total <= 7) return Array.from({ length: total }, (_, index) => index + 1)
    const wanted = new Set([1, total, current - 1, current, current + 1])
    const pages = [...wanted].filter(p => p >= 1 && p <= total).sort((a, b) => a - b)
    const out: (number | 'gap')[] = []
    pages.forEach((p, index) => {
        if (index > 0 && p - pages[index - 1] > 1) out.push('gap')
        out.push(p)
    })
    return out
}
const wait = (seconds: number) => new Promise<void>(resolve => window.setTimeout(resolve, Math.max(0, seconds) * 1000))
const retrySeconds = (value: unknown) => typeof value === 'number' && Number.isFinite(value)
    ? Math.min(60, Math.max(0, value))
    : 3

export default function SecurityDeleteSection({
    accountObjectId,
    currentAccountObjectId,
}: {
    accountObjectId: string | null
    currentAccountObjectId?: string | null
}) {
    const account = useCurrentAccount()
    const suiClient = useSuiClient()
    const { mutateAsync: signPersonal } = useSignPersonalMessage()
    const address = account?.address ?? ''
    const signer: SignPersonalMessage = useCallback(message => signPersonal({ message }), [signPersonal])
    const [scope, setScope] = useState<DeletionScope>('current')
    const activeAccountObjectId = scope === 'current'
        ? (currentAccountObjectId === undefined ? accountObjectId : currentAccountObjectId)
        : accountObjectId
    const [tab, setTab] = useState<'risk' | 'progress'>('risk')
    const [items, setItems] = useState<BlobItem[]>([])
    const [counts, setCounts] = useState<BlobCounts>(EMPTY_COUNTS)
    const [deleteBatchMax, setDeleteBatchMax] = useState(1)
    const [page, setPage] = useState(1)
    // Start cursor for each visited page (index = page - 1; page 1 starts at
    // null). The server pages by keyset cursor only — no OFFSET — so a jump
    // to an unvisited page walks forward one request per page, caching each
    // boundary on the way. Keyset boundaries stay valid under concurrent
    // deletion (strict `>` comparison), rows just shift toward earlier pages.
    const pageCursors = useRef<(string | null)[]>([null])
    const pageRef = useRef(1)
    const [selected, setSelected] = useState<Set<string>>(new Set())
    const [activated, setActivated] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')
    const [confirm, setConfirm] = useState<'all' | 'selection' | null>(null)
    const [preview, setPreview] = useState<BlobItem | null>(null)
    const [toasts, setToasts] = useState<{ id: number; message: string; digest: string | null }[]>([])
    const nextToastId = useRef(0)
    const requestGeneration = useRef(0)
    const previousAddress = useRef(address)
    const previousAccountObjectId = useRef(activeAccountObjectId)
    const refreshContext = useRef({ address, tab, scope, activated })
    refreshContext.current = { address, tab, scope, activated }
    const previewTrigger = useRef<HTMLElement | null>(null)
    const confirmTrigger = useRef<HTMLElement | null>(null)

    const load = useCallback(async (targetPage = 1) => {
        if (!address) return
        const request = ++requestGeneration.current
        setLoading(true); setError('')
        const state = tab === 'risk' ? 'deletable' : PROGRESS_STATES
        try {
            // Start from the closest cached boundary at or before the target,
            // then walk forward, caching each newly discovered boundary.
            let fetchPage = Math.max(1, Math.min(targetPage, pageCursors.current.length))
            let response
            for (;;) {
                const start = pageCursors.current[fetchPage - 1] ?? undefined
                for (let attempt = 0; ; attempt++) {
                    try {
                        response = await withAuth(address, signer, token => listBlobs(token, { state, cursor: start, limit: PAGE_SIZE, scope }))
                        break
                    } catch (caught) {
                        if (caught instanceof SdApiError && caught.action === 'RETRY_AFTER' && attempt === 0) {
                            await wait(retrySeconds(caught.details.retryAfterSecs)); continue
                        }
                        throw caught
                    }
                }
                if (request !== requestGeneration.current) return
                if (response.nextCursor) pageCursors.current[fetchPage] = response.nextCursor
                if (response.items.length === 0 && fetchPage > 1) {
                    // The page emptied out from under us (rows deleted since its
                    // boundary was cached) — step back and land on a real page.
                    // Also stop walking forward: retrying the original target
                    // against a stale nextCursor could loop indefinitely.
                    pageCursors.current.length = fetchPage - 1
                    fetchPage -= 1
                    targetPage = fetchPage
                    continue
                }
                if (fetchPage >= targetPage || !response.nextCursor) break
                fetchPage += 1
            }
            pageRef.current = fetchPage
            setPage(fetchPage)
            setCounts(response.counts)
            setDeleteBatchMax(response.limits.deleteBatchMax)
            setItems(response.items)
            if (tab === 'risk') {
                const returned = new Set(response.items.map(item => item.blobId))
                const valid = new Set(response.items.filter(item => item.state === 'deletable').map(item => item.blobId))
                // Absence from the refreshed page does not mean a selected
                // ID from another page is stale. Only prune rows whose refreshed
                // representation is explicitly no longer deletable.
                setSelected(previous => new Set([...previous].filter(id => !returned.has(id) || valid.has(id))))
            }
        } catch (caught) {
            if (request === requestGeneration.current) setError(caught instanceof Error ? caught.message : 'Failed to load memories.')
        } finally {
            if (request === requestGeneration.current) setLoading(false)
        }
    }, [address, scope, signer, tab])

    const refresh = useCallback(() => {
        const current = refreshContext.current
        // Deletion callbacks can outlive the wallet or tab that started them.
        // Never let a stale callback trigger auth or overwrite another view.
        if (
            previousAddress.current !== address
            || !current.activated
            || current.address !== address
            || current.tab !== tab
            || current.scope !== scope
        ) return
        void load(pageRef.current)
    }, [address, load, scope, tab])
    const deletion = useSecurityDeletion({ onStateChanged: refresh, scope })

    useEffect(() => {
        const addressChanged = previousAddress.current !== address
        const accountObjectChanged = previousAccountObjectId.current !== activeAccountObjectId
        if (!addressChanged && !accountObjectChanged) return
        if (previousAddress.current && addressChanged) clearToken(previousAddress.current)
        previousAddress.current = address
        previousAccountObjectId.current = activeAccountObjectId
        setPreview(null)
        clearSealSession()
        if (!addressChanged) return
        requestGeneration.current++
        setActivated(false)
        setItems([]); setCounts(EMPTY_COUNTS); setSelected(new Set()); setConfirm(null); setError(''); setLoading(false)
        pageCursors.current = [null]; pageRef.current = 1; setPage(1)
    }, [address, activeAccountObjectId])
    useEffect(() => {
        if (activated) void load(1)
    }, [activated, tab, scope]) // eslint-disable-line react-hooks/exhaustive-deps
    const dismissToast = useCallback((id: number) => {
        setToasts(previous => previous.filter(toast => toast.id !== id))
    }, [])
    useEffect(() => {
        if (deletion.phase.kind !== 'done') return
        setSelected(new Set()); setConfirm(null)
        // One toast per completed deletion operation — unlike the phase
        // object, toasts survive the next operation starting.
        const id = nextToastId.current++
        const count = deletion.phase.deletedBlobs
        const digest = deletion.lastDigest ?? null
        setToasts(previous => [...previous, { id, message: `Deleted ${count} ${count === 1 ? 'memory' : 'memories'}.`, digest }])
        // Deliberately no cleanup: the timer must outlive later phase
        // changes (a new operation starting must not freeze old toasts).
        window.setTimeout(() => dismissToast(id), 5000)
    }, [deletion.lastDigest, deletion.phase, dismissToast])
    useEffect(() => {
        if (!confirm) return
        const keydown = (event: KeyboardEvent) => { if (event.key === 'Escape') setConfirm(null) }
        window.addEventListener('keydown', keydown)
        return () => window.removeEventListener('keydown', keydown)
    }, [confirm])

    // Effects clear owner-scoped state after a wallet/account transition, but
    // effects run after paint. Suppress it synchronously during that transition
    // so rows, selections, dialogs, and plaintext never flash for the new owner.
    const identityMatches = previousAddress.current === address
    const previewIdentityMatches = identityMatches && previousAccountObjectId.current === activeAccountObjectId
    const visibleActivated = identityMatches && activated
    const visibleItems = identityMatches ? items : []
    const visibleCounts = identityMatches ? counts : EMPTY_COUNTS
    const visibleSelected = identityMatches ? selected : new Set<string>()
    const visiblePage = identityMatches ? page : 1
    const visibleConfirm = identityMatches ? confirm : null
    const visiblePreview = previewIdentityMatches ? preview : null
    const riskPageIds = visibleItems.filter(item => item.state === 'deletable').map(item => item.blobId)
    const allPageSelected = riskPageIds.length > 0 && riskPageIds.every(id => visibleSelected.has(id))
    const busy = ['preparing', 'signing', 'executing'].includes(deletion.phase.kind)
    const tabTotal = tab === 'risk'
        ? visibleCounts.deletable
        : visibleCounts.deleting + visibleCounts.deleted + visibleCounts.deletedExternal + visibleCounts.notOwner + visibleCounts.expired
    const totalPages = Math.max(1, Math.ceil(tabTotal / PAGE_SIZE))
    const confirmCount = visibleConfirm === 'all' ? visibleCounts.deletable : visibleSelected.size
    const singleSelectedBlobId = visibleConfirm === 'selection' && visibleSelected.size === 1
        ? [...visibleSelected][0]
        : null
    const toggle = (blobId: string) => setSelected(previous => {
        const next = new Set(previous); if (next.has(blobId)) next.delete(blobId); else next.add(blobId); return next
    })
    const openPreview = useCallback((item: BlobItem) => {
        previewTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
        setPreview(item)
    }, [])
    const closePreview = useCallback(() => {
        setPreview(null)
        window.requestAnimationFrame(() => previewTrigger.current?.focus())
    }, [])
    const openConfirm = useCallback((mode: 'all' | 'selection') => {
        confirmTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
        setConfirm(mode)
    }, [])
    const selectScope = useCallback((next: DeletionScope) => {
        if (next === scope) return
        requestGeneration.current++
        setItems([])
        setCounts(EMPTY_COUNTS)
        pageCursors.current = [null]; pageRef.current = 1; setPage(1)
        setSelected(new Set())
        setConfirm(null)
        setPreview(null)
        setError('')
        setTab('risk')
        setScope(next)
    }, [scope])
    const selectTab = useCallback((next: 'risk' | 'progress') => {
        // Re-clicking the active tab must not clear state: `tab` would not
        // change, so the reload effect keyed on it would never refetch.
        if (next === tab) return
        requestGeneration.current++
        setItems([])
        pageCursors.current = [null]; pageRef.current = 1; setPage(1)
        setSelected(new Set())
        setConfirm(null)
        setTab(next)
    }, [tab])
    const closeConfirm = useCallback(() => {
        setConfirm(null)
        window.requestAnimationFrame(() => confirmTrigger.current?.focus())
    }, [])
    const loadPreview = useCallback(() => {
        if (!preview || !activeAccountObjectId) return Promise.reject(new Error('Account details are unavailable.'))
        return fetchAndDecryptBlob({
            suiClient,
            blobId: preview.blobId,
            address,
            accountObjectId: activeAccountObjectId,
            signPersonalMessage: signer,
            scope,
        })
    }, [activeAccountObjectId, address, preview, scope, signer, suiClient])

    if (!config.securityDeleteEnabled || !address) return null
    return <Card id="cleanup" className="dashboard-cleanup-card sd-card" title="Delete memories" subtitle="Permanently delete individual or selected encrypted Walrus memory blobs with your connected wallet" action={
        visibleActivated && <button className="btn btn-secondary" disabled={loading || busy} onClick={refresh}><RefreshCw size={16}/> Refresh</button>
    }>
        <div className="sd-scope-switch" role="group" aria-label="Memory storage scope">
            <button type="button" aria-pressed={scope === 'current'} className={`btn ${scope === 'current' ? 'btn-secondary' : ''}`} disabled={busy} onClick={() => selectScope('current')}>Post-migration</button>
            <button type="button" aria-pressed={scope === 'legacy'} className={`btn ${scope === 'legacy' ? 'btn-secondary' : ''}`} disabled={busy} onClick={() => selectScope('legacy')}>Pre-migration</button>
        </div>
        <div className="sd-warning">
            <ShieldAlert size={18} aria-hidden="true" />
            <span>
                {scope === 'current' ? (
                    <>
                        Select one or more post-migration memory blobs below to authorize permanent on-chain deletion with your connected wallet or zkLogin account, with no private key export required. Verification steps, cache limits, and support options are documented{' '}
                        <a href={config.securityGuideUrl} target="_blank" rel="noopener noreferrer">here</a>.
                    </>
                ) : (
                    <>
                        On {config.migrationCompletedDate} all existing memories were migrated onto a new contract as part of a security upgrade. We recommend removing all pre-migration data, and reviewing any sensitive data you may have stored. A guide is available{' '}
                        <a href={config.securityGuideUrl} target="_blank" rel="noopener noreferrer">here</a>.
                    </>
                )}
            </span>
        </div>
        {identityMatches && !activated && <div className="sd-load-prompt">
            <button className="btn dashboard-cleanup-load" disabled={loading || busy} onClick={() => setActivated(true)}>Load my memories</button>
        </div>}
        {visibleActivated && <>
            <div className="sd-counts"><strong>{visibleCounts.deletable}</strong> Stored / <strong>{visibleCounts.deleting}</strong> in Progress / <strong>{visibleCounts.deleted + visibleCounts.deletedExternal}</strong> Deleted</div>
            <div className="sd-tabs" role="tablist">
                <button role="tab" aria-selected={tab === 'risk'} aria-controls="sd-tab-panel" className={`btn ${tab === 'risk' ? 'btn-secondary' : ''}`} disabled={busy} onClick={() => selectTab('risk')}>Stored</button>
                <button role="tab" aria-selected={tab === 'progress'} aria-controls="sd-tab-panel" className={`btn ${tab === 'progress' ? 'btn-secondary' : ''}`} disabled={busy} onClick={() => selectTab('progress')}>Deleted</button>
            </div>
        </>}
        {error && <div className="dashboard-cleanup-error" role="alert">{error}</div>}
        {deletion.phase.kind === 'error' && <div className="dashboard-cleanup-error" role="alert">{deletion.phase.message} <code>{deletion.phase.code}</code></div>}
        {busy && <div className="dashboard-cleanup-status" aria-live="polite"><span>{deletion.phase.kind === 'signing' ? 'Check your wallet to sign this batch…' : `Deleting batch ${'batch' in deletion.phase ? deletion.phase.batch : ''}…`}</span>{deletion.phase.kind === 'signing' && <button type="button" className="btn btn-secondary" onClick={() => void deletion.cancelActive()}>Cancel batch</button>}</div>}
        {toasts.length > 0 && <div className="sd-toasts" role="status" aria-live="polite">
            {toasts.map(toast => <div key={toast.id} className="sd-toast">
                <span>{toast.message}</span>
                {toast.digest && <span className="sd-toast-digest">Tx: <code>{toast.digest}</code></span>}
                <button type="button" className="sd-toast-dismiss" aria-label="Dismiss notification" onClick={() => dismissToast(toast.id)}>×</button>
            </div>)}
        </div>}
        {visibleActivated && tab === 'risk' && <div className="sd-actions">
            <button className="btn btn-secondary" disabled={!riskPageIds.length || busy} onClick={() => setSelected(previous => {
                if (allPageSelected) return new Set([...previous].filter(id => !riskPageIds.includes(id)))
                return new Set([...previous, ...riskPageIds])
            })}>{allPageSelected ? 'Unselect page' : 'Select page'}</button>
            <button className="btn btn-danger" disabled={!visibleSelected.size || busy} onClick={() => openConfirm('selection')}><Trash2 size={16}/> Delete selected ({visibleSelected.size})</button>
            <button className="btn btn-danger" disabled={!visibleCounts.deletable || busy} onClick={() => openConfirm('all')}><Trash2 size={16}/> Delete all ({visibleCounts.deletable})</button>
        </div>}
        {visibleActivated && <div id="sd-tab-panel" role="tabpanel">{loading && visibleItems.length === 0 ? <p role="status">Loading affected memories…</p> : <SecurityDeleteTable items={visibleItems} selectable={tab === 'risk'} selected={visibleSelected} onToggle={toggle} onPreview={openPreview} previewEnabled={Boolean(activeAccountObjectId)}/>}</div>}
        {visibleActivated && totalPages > 1 && <nav className="sd-pager" aria-label="Memory pages">
            <button className="btn btn-secondary" disabled={visiblePage <= 1 || loading} onClick={() => void load(visiblePage - 1)}>‹ Prev</button>
            {pageStrip(visiblePage, totalPages).map((entry, index) => entry === 'gap'
                ? <span key={`gap-${index}`} className="sd-pager-gap" aria-hidden="true">…</span>
                : <button key={entry} className={`btn ${entry === visiblePage ? 'btn-secondary' : ''}`} aria-current={entry === visiblePage ? 'page' : undefined} disabled={loading || entry === visiblePage} onClick={() => void load(entry)}>{entry}</button>)}
            <button className="btn btn-secondary" disabled={visiblePage >= totalPages || loading} onClick={() => void load(visiblePage + 1)}>Next ›</button>
            <span className="sd-pager-status" aria-live="polite">Page {visiblePage} of {totalPages}</span>
        </nav>}
        {visibleConfirm && <div className="dashboard-confirm-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) closeConfirm() }}>
            <section className="dashboard-confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="sd-confirm-title" aria-describedby="sd-confirm-description">
                <div className="dashboard-confirm-copy">
                    <h3 id="sd-confirm-title">Permanently delete {confirmCount} {confirmCount === 1 ? 'memory' : 'memories'}?</h3>
                    <p id="sd-confirm-description">
                        {singleSelectedBlobId
                            ? <>Blob <code>{singleSelectedBlobId}</code> will be permanently deleted from Walrus Memory and cannot be undone.</>
                            : 'Deletion from Walrus Memory is permanent and cannot be undone.'}
                    </p>
                </div>
                <div className="dashboard-confirm-actions"><button autoFocus className="btn btn-secondary" onClick={closeConfirm}>Cancel</button><button className="btn btn-danger" onClick={() => { setConfirm(null); void (visibleConfirm === 'all' ? deletion.deleteAll(visibleCounts.deletable, deleteBatchMax) : deletion.deleteSelection([...visibleSelected], deleteBatchMax)) }}>Delete forever</button></div>
            </section>
        </div>}
        {visiblePreview && (
            <BlobPreviewModal key={`${address}:${scope}:${activeAccountObjectId}:${visiblePreview.blobId}`} blobId={visiblePreview.blobId} load={loadPreview} onClose={closePreview}/>
        )}
    </Card>
}

/**
 * Dashboard — Account info, delegate keys management, SDK integration guide
 */

import { useState, useCallback, useEffect, useMemo, useRef } from 'react'
import {
    useCurrentAccount,
    useDisconnectWallet,
    useSignPersonalMessage,
    useSuiClient,
} from '@mysten/dapp-kit'
import { Transaction } from '@mysten/sui/transactions'
import { useSponsoredTransaction } from '../hooks/useSponsoredTransaction'
import { generateDelegateKey } from '@mysten-incubation/memwal/account'
import type { WalletSigner } from '@mysten-incubation/memwal/manual'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { TriangleAlert, Info, Eye, EyeOff, Trash2, RefreshCw, Plus, LogOut, ChevronLeft, ChevronRight } from 'lucide-react'
import { useDelegateKey } from '../App'
import { Card } from '../components/Card'
import { CopyStatusIcon, CopyStatusLabel } from '../components/CopyStatus'
import SecurityDeleteSection from '../components/SecurityDeleteSection'
import { SecretValueInput } from '../components/SecretValueInput'
import { config } from '../config'
import { accountReadyCopy } from '../utils/accountReadyCopy'
import { getAnalyticsErrorType, trackEvent } from '../utils/analytics'
import { useCopyFeedback } from '../hooks/useCopyFeedback'
import { apiGet } from '../utils/api'
import { assertDelegateKeyRegistered, deriveDelegatePublicKeyHex, normalizeDelegatePrivateKey } from '../utils/delegateKeyImport'
import { fetchAccountIdForOwner, fetchObjectJson, publicKeyToHex } from '../utils/suiClientCompat'
import ConnectWalrusMemory, { type ConnectPath } from './ConnectWalrusMemory'

// ============================================================
// Types
// ============================================================

interface OnChainDelegateKey {
    publicKey: string
    suiAddress: string
    label: string
    createdAt: number
}

const MAX_DELEGATE_KEYS = 20
const MAX_DELEGATE_KEYS_MESSAGE = 'This wallet already has 20 delegate keys. Remove an old key before creating a new delegate key.'
const DELEGATE_KEYS_SECTION_ID = 'delegate-keys'
// Relayer clamps `limit` (default 100, max 500); these stay well inside that.
const NAMESPACE_PAGE_SIZES = [15, 25, 50, 100]
const NAMESPACE_DEFAULT_PAGE_SIZE = 15
const PRIVATE_KEY_ENV = 'MEMWAL_PRIVATE_KEY'
const ACCOUNT_ID_ENV = 'MEMWAL_ACCOUNT_ID'
const SERVER_URL_ENV = 'MEMWAL_SERVER_URL'
type QuickstartLanguage = 'ts' | 'py'
type RemoveKeysConfirmState = {
    publicKeys: string[]
    source: 'single' | 'selection'
}

// sanitize a key label — strip HTML special chars and control characters
function sanitizeLabelInput(raw: string): string {
    return raw
        // Strip HTML special characters
        .replace(/[<>&"'/]/g, '')
        // Strip Unicode control characters.
        .replace(/\p{Cc}/gu, '')
}

function normalizeLabelForSubmit(raw: string): string {
    return sanitizeLabelInput(raw).trim()
}

function bytesToHex(bytes: Uint8Array | number[]): string {
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function hexToByteArray(hex: string): number[] {
    const normalized = hex.startsWith('0x') ? hex.slice(2) : hex
    if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
        throw new Error('invalid delegate public key')
    }

    return Array.from({ length: normalized.length / 2 }, (_, i) =>
        parseInt(normalized.slice(i * 2, i * 2 + 2), 16)
    )
}

function compactPublicKey(publicKey: string): string {
    const normalized = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey
    if (normalized.length <= 24) return publicKey
    return `${normalized.slice(0, 12)}...${normalized.slice(-8)}`
}

function formatKeyDate(createdAt: number): string {
    const date = new Date(createdAt)
    const month = String(date.getMonth() + 1).padStart(2, '0')
    const day = String(date.getDate()).padStart(2, '0')
    return `${month}/${day}/${date.getFullYear()}`
}

function DelegateKeySkeletonList() {
    return (
        <div className="dashboard-key-table-wrap dashboard-key-list--skeleton" aria-hidden="true">
            <table className="dashboard-key-table">
                <thead>
                    <tr>
                        <th scope="col" className="dashboard-key-table-select">Select</th>
                        <th scope="col">Key name</th>
                        <th scope="col">Public key</th>
                        <th scope="col">Created</th>
                        <th scope="col" className="dashboard-key-table-actions">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {[0, 1].map((index) => (
                        <tr key={index}>
                            <td><span className="dashboard-key-skeleton-line dashboard-key-skeleton-line--check" /></td>
                            <td><span className="dashboard-key-skeleton-line dashboard-key-skeleton-line--label" /></td>
                            <td><span className="dashboard-key-skeleton-line dashboard-key-skeleton-line--value" /></td>
                            <td><span className="dashboard-key-skeleton-line dashboard-key-skeleton-line--date" /></td>
                            <td><span className="dashboard-key-skeleton-line dashboard-key-skeleton-line--actions" /></td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    )
}

type IncidentStatus = {
    account_id: string | null
    affected: boolean
    quarantined: boolean
    active: boolean
    /** Hex delegate public keys to highlight. No `0x` prefix. */
    affected_public_keys?: string[]
}

function normalizeKeyHex(hex: string): string {
    return hex.replace(/^0x/i, '').toLowerCase()
}

// ============================================================
// Dashboard Component
// ============================================================

export default function Dashboard({
    previewMode = false,
    previewState = 'empty',
    autoScrollToKeys = false,
    fromKeys = false,
}: {
    previewMode?: boolean
    previewState?: 'empty' | 'ready'
    /** Scroll to the delegate keys card once its first load finishes. Used by /keys (WALM-675). */
    autoScrollToKeys?: boolean
    /** Rendered from /keys (WALM-675) — separate from autoScrollToKeys, which
     *  is false on an owner mismatch. Gates the account-ready dialog's "Back
     *  to Console" button: that's where a Console user actually finishes,
     *  after copying the key. The nav no longer carries its own Console
     *  link, so the new-user /setup → /dashboard path has no return prompt
     *  — COMG-1093 was expected to handle that return on the Console side. */
    fromKeys?: boolean
}) {
    const currentAccount = useCurrentAccount()
    const navigate = useNavigate()
    const location = useLocation()
    const { mutateAsync: disconnect } = useDisconnectWallet()
    const { mutateAsync: signAndExecuteTx } = useSponsoredTransaction()
    const { mutateAsync: signPersonalMsg } = useSignPersonalMessage()
    const suiClient = useSuiClient()
    const { delegateKey, delegatePublicKey, accountObjectId, setDelegateKeys, clearDelegateKeys } = useDelegateKey()

    const address = currentAccount?.address || (
        previewMode
            ? '0x7f33c06e6d144bc3c24aaef7c8f7421c1287df6ce9c5ab74ac729b13f4194'
            : ''
    )
    const previewReady = previewMode && previewState === 'ready'
    const previewAccountObjectId = previewReady
        ? '0x7bc62cf958c4b27b16ad2f1a3f33d1f0e811e08d4fc079edc3525a7d2e2dc551'
        : null
    const [resolvedAccountObjectId, setResolvedAccountObjectId] = useState<string | null>(accountObjectId)
    const shouldResolveAccount = Boolean(address && !previewMode && !accountObjectId)
    const [accountLookupAddress, setAccountLookupAddress] = useState(address)
    const [accountLookupComplete, setAccountLookupComplete] = useState(!shouldResolveAccount)
    const [loadingAccount, setLoadingAccount] = useState(false)
    const effectiveAccountObjectId = accountObjectId ?? previewAccountObjectId ?? resolvedAccountObjectId
    // Security-delete previews authorize against the PRE-cutover package's
    // Account object (seal_approve is typed to that package), so when a
    // legacy registry is configured, resolve the account from it instead of
    // reusing the current-deployment account above.
    const legacyRegistryDiffers = config.legacyMemwalRegistryId !== config.memwalRegistryId
    const [legacyAccountObjectId, setLegacyAccountObjectId] = useState<string | null>(null)
    useEffect(() => {
        if (!legacyRegistryDiffers || !address || previewMode) { setLegacyAccountObjectId(null); return }
        let cancelled = false
        fetchAccountIdForOwner(suiClient, config.legacyMemwalRegistryId, address)
            .then(accountId => { if (!cancelled) setLegacyAccountObjectId(accountId) })
            .catch(err => {
                console.error('Failed to fetch legacy account object ID:', err)
                if (!cancelled) setLegacyAccountObjectId(null)
            })
        return () => { cancelled = true }
    }, [legacyRegistryDiffers, address, previewMode, suiClient])
    const securityDeleteAccountObjectId = legacyRegistryDiffers ? legacyAccountObjectId : effectiveAccountObjectId
    const [showKey, setShowKey] = useState(false)
    const { copy: copyText, statusOf: copyStatusOf } = useCopyFeedback()
    const [navSolid, setNavSolid] = useState(false)

    useEffect(() => {
        const onScroll = () => setNavSolid(window.scrollY > 220)
        onScroll()
        window.addEventListener('scroll', onScroll, { passive: true })
        return () => window.removeEventListener('scroll', onScroll)
    }, [])
    const [connectPath, setConnectPath] = useState<ConnectPath>('agent')
    const [quickstartLanguage, setQuickstartLanguage] = useState<QuickstartLanguage>('ts')

    // Delegate key management state
    const [onChainKeys, setOnChainKeys] = useState<OnChainDelegateKey[]>([])
    const [namespaces, setNamespaces] = useState<{ name: string; memory_count: number }[]>([])
    const [namespacesLoading, setNamespacesLoading] = useState(false)
    const [namespacesError, setNamespacesError] = useState('')
    const [namespacesPage, setNamespacesPage] = useState(0)
    const [namespacesHasMore, setNamespacesHasMore] = useState(false)
    const [namespacesPageSize, setNamespacesPageSize] = useState(NAMESPACE_DEFAULT_PAGE_SIZE)
    const [loadingKeys, setLoadingKeys] = useState(false)
    const [addingKey, setAddingKey] = useState(false)
    const [removingKey, setRemovingKey] = useState<string | null>(null)
    const [removingSelectedKeys, setRemovingSelectedKeys] = useState(false)
    const [removeKeysConfirm, setRemoveKeysConfirm] = useState<RemoveKeysConfirmState | null>(null)
    const [selectedKeyPublicKeys, setSelectedKeyPublicKeys] = useState<string[]>([])
    const [showAddForm, setShowAddForm] = useState(false)
    const [addKeyFormClosing, setAddKeyFormClosing] = useState(false)
    const [newKeyLabel, setNewKeyLabel] = useState('New key')
    const [keyError, setKeyError] = useState('')
    const [existingKeyError, setExistingKeyError] = useState('')
    const [importingExistingKey, setImportingExistingKey] = useState(false)
    const [newPrivateKey, setNewPrivateKey] = useState<string | null>(null)
    const addKeyFormCloseTimerRef = useRef<number | null>(null)
    const [incident, setIncident] = useState<IncidentStatus | null>(null)
    const [incidentAction, setIncidentAction] = useState<'reactivate' | null>(null)
    const [incidentError, setIncidentError] = useState('')
    const [accountReadyDismissed, setAccountReadyDismissed] = useState(false)
    // One-shot signal from SetupWizard's navigate() state — set only when the
    // /setup visit carried Console's "Set up" (COMG-1081) `from` marker.
    // Mutable (not read-once-and-frozen): it must be consumed to false on
    // dismiss, otherwise the mint re-arm effect below — which resets
    // accountReadyDismissed for ANY fromKeys mint — would resurrect this
    // dialog for an unrelated key minted later on the plain /dashboard.
    const [fromConsoleSetup, setFromConsoleSetup] = useState(() => Boolean(
        (location.state as { fromConsoleSetup?: boolean } | null)?.fromConsoleSetup
    ))
    // Set on a successful mint, alongside a direct accountReadyDismissed
    // reset (not an effect keyed on newPrivateKey — same reasoning as
    // justRemovedKeys below: the flag can already be true from a prior
    // dismissed dialog, and setting an unchanged value wouldn't re-fire an
    // effect). Combined with `!newPrivateKey` in showAccountReadyDialog so
    // the dialog only opens once the one-time key block has been dismissed
    // via Continue — opening it earlier, with Back to Console as the primary
    // button, let a user leave before copying an unrecoverable private key
    // (nikola0x0 + ducnmm review).
    const [justMintedKey, setJustMintedKey] = useState(false)
    // Revoke has no one-time secret to protect, so its dialog can open
    // immediately — same direct-reset reasoning as justMintedKey above.
    const [justRemovedKeys, setJustRemovedKeys] = useState(false)
    // What the dialog reports for a /keys action (WALM-743). Captured when the
    // action succeeds: the add-key form resets its label and the revoke
    // confirm state clears before the dialog opens.
    const [mintedKeyLabel, setMintedKeyLabel] = useState('')
    const [removedKeyCount, setRemovedKeyCount] = useState(0)

    // WalletSigner adapter — wraps dapp-kit hooks into SDK's WalletSigner interface
    const walletSigner = useMemo<WalletSigner | null>(() => {
        if (!currentAccount) return null
        return {
            address: currentAccount.address,
            signAndExecuteTransaction: ({ transaction }) =>
                signAndExecuteTx({ transaction }),
            signPersonalMessage: ({ message }) =>
                signPersonalMsg({ message }),
        }
    }, [currentAccount, signAndExecuteTx, signPersonalMsg])

    const reloadIncident = useCallback(async (owner: string) => {
        const base = config.memwalServerUrl.replace(/\/+$/, '')
        const response = await fetch(`${base}/api/accounts/${owner.toLowerCase()}/incident`)
        if (!response.ok) throw new Error(`incident status ${response.status}`)
        const body = await response.json() as IncidentStatus
        setIncident(body)
    }, [])

    useEffect(() => {
        if (!address || previewMode) {
            setIncident(null)
            return
        }
        let cancelled = false
        reloadIncident(address)
            .catch((err: unknown) => {
                if (!cancelled) {
                    console.error('Failed to load incident status:', err)
                    setIncident(null)
                }
            })
        return () => { cancelled = true }
    }, [address, previewMode, reloadIncident])

    const reactivateAccount = useCallback(async () => {
        if (!incident?.account_id) return
        setIncidentAction('reactivate')
        setIncidentError('')
        try {
            const tx = new Transaction()
            tx.moveCall({
                target: `${config.memwalPackageId}::account::reactivate_account`,
                arguments: [
                    tx.object(incident.account_id),
                    tx.object(config.memwalRegistryId),
                ],
            })
            const result = await signAndExecuteTx({ transaction: tx })
            await suiClient.waitForTransaction({ digest: result.digest })
            await reloadIncident(address)
        } catch (err: unknown) {
            setIncidentError(err instanceof Error ? err.message : 'failed to reactivate account')
        } finally {
            setIncidentAction(null)
        }
    }, [address, incident?.account_id, signAndExecuteTx, suiClient, reloadIncident])

    const copyToClipboard = useCallback(async (text: string, label: string) => {
        if (!(await copyText(text, label))) return
        trackEvent('copy_action', {
            item: label.startsWith('pk-') ? 'public_key' : label,
            location: 'dashboard',
        })
    }, [copyText])

    const handleLogout = useCallback(async () => {
        trackEvent('sign_out', { location: 'dashboard' })
        clearDelegateKeys()
        await disconnect()
        navigate('/')
    }, [clearDelegateKeys, disconnect, navigate])

    const openAddKeyForm = useCallback(() => {
        if (addKeyFormCloseTimerRef.current !== null) {
            window.clearTimeout(addKeyFormCloseTimerRef.current)
            addKeyFormCloseTimerRef.current = null
        }
        setAddKeyFormClosing(false)
        setShowAddForm(true)
    }, [])

    const closeAddKeyForm = useCallback(() => {
        setKeyError('')
        setAddKeyFormClosing(true)
        if (addKeyFormCloseTimerRef.current !== null) {
            window.clearTimeout(addKeyFormCloseTimerRef.current)
        }
        addKeyFormCloseTimerRef.current = window.setTimeout(() => {
            setShowAddForm(false)
            setAddKeyFormClosing(false)
            addKeyFormCloseTimerRef.current = null
        }, 260)
    }, [])

    useEffect(() => {
        return () => {
            if (addKeyFormCloseTimerRef.current !== null) {
                window.clearTimeout(addKeyFormCloseTimerRef.current)
            }
        }
    }, [])

    const fetchAccountObjectId = useCallback(async () => {
        if (!address || previewMode) {
            setResolvedAccountObjectId(null)
            setAccountLookupAddress(address)
            setAccountLookupComplete(true)
            setLoadingAccount(false)
            return
        }
        if (accountObjectId) {
            setResolvedAccountObjectId(accountObjectId)
            setAccountLookupAddress(address)
            setAccountLookupComplete(true)
            setLoadingAccount(false)
            return
        }
        setResolvedAccountObjectId(null)
        setAccountLookupComplete(false)
        setLoadingAccount(true)
        try {
            const accountId = await fetchAccountIdForOwner(suiClient, config.memwalRegistryId, address)
            if (accountId) {
                setResolvedAccountObjectId(accountId)
            }
        } catch (err) {
            console.error('Failed to fetch account object ID:', err)
            setResolvedAccountObjectId(null)
        } finally {
            setAccountLookupAddress(address)
            setAccountLookupComplete(true)
            setLoadingAccount(false)
        }
    }, [address, accountObjectId, previewMode, suiClient])

    useEffect(() => {
        setResolvedAccountObjectId(accountObjectId)
        if (accountObjectId) {
            setAccountLookupAddress(address)
            setAccountLookupComplete(true)
        }
    }, [accountObjectId, address])

    useEffect(() => {
        fetchAccountObjectId()
    }, [fetchAccountObjectId])

    const hasResolvedAccount = Boolean(effectiveAccountObjectId)
    const accountLookupPending = loadingAccount || (shouldResolveAccount && (!accountLookupComplete || accountLookupAddress !== address))
    const activeEnvironmentLabel = config.suiNetwork === 'mainnet'
        ? 'production / mainnet'
        : 'staging / testnet'
    const normalizedRelayerUrl = config.memwalServerUrl.toLowerCase()
    const relayerEnvironmentLabel = normalizedRelayerUrl.startsWith('/')
        ? 'local dev proxy / testnet'
        : normalizedRelayerUrl.includes('localhost') || normalizedRelayerUrl.includes('127.0.0.1')
        ? 'local development'
        : normalizedRelayerUrl.includes('staging')
            ? 'staging / testnet'
            : normalizedRelayerUrl.includes('dev')
                ? 'dev / testnet'
                : 'production / mainnet'
    const sdkDefaultServerUrl = config.memwalServerUrl
    const relayerLooksMismatched =
        (config.suiNetwork === 'mainnet' && normalizedRelayerUrl.includes('staging')) ||
        (config.suiNetwork !== 'mainnet' &&
            (normalizedRelayerUrl.includes('relayer.memory.walrus.xyz') ||
                normalizedRelayerUrl.includes('relayer.memwal.ai')) &&
            !normalizedRelayerUrl.includes('staging') &&
            !normalizedRelayerUrl.includes('dev'))
    const hasMaxDelegateKeys = onChainKeys.length >= MAX_DELEGATE_KEYS
    const isKeyListLoading = accountLookupPending || (loadingKeys && onChainKeys.length === 0)
    const isKeyListRefreshing = loadingKeys && onChainKeys.length > 0
    const onChainKeyCount = onChainKeys.length
    const browserHasNoKey = !delegateKey && hasResolvedAccount && !previewReady
    const showNoBrowserKeyNotice = browserHasNoKey && !isKeyListLoading
    const selectableKeyPublicKeys = useMemo(() => onChainKeys.map((key) => key.publicKey), [onChainKeys])
    const affectedKeySet = useMemo(() => {
        const keys = incident?.affected_public_keys ?? []
        return new Set(keys.map(normalizeKeyHex).filter(Boolean))
    }, [incident])
    const affectedOnChainKeys = useMemo(
        () => onChainKeys.filter((key) => affectedKeySet.has(normalizeKeyHex(key.publicKey))),
        [onChainKeys, affectedKeySet],
    )
    // Removing the last leaked key can clear `affected` while the account
    // remains inactive. Recovery must follow account state, not leaked-key membership.
    const incidentOpen = Boolean(incident?.account_id && (incident.quarantined || !incident.active))
    const highlightedKeysRemain = affectedOnChainKeys.length > 0 || (isKeyListLoading && affectedKeySet.size > 0)
    const showLockedCleanup = incidentOpen && highlightedKeysRemain
    const visibleKeys = showLockedCleanup && affectedOnChainKeys.length > 0 ? affectedOnChainKeys : onChainKeys
    const selectedKeySet = useMemo(() => new Set(selectedKeyPublicKeys), [selectedKeyPublicKeys])
    const selectedKeyCount = selectedKeyPublicKeys.length
    const keyRemovalBusy = removingSelectedKeys || Boolean(removingKey)
    // A revoke wipes newPrivateKey at its start too (executeRemoveKeys), so
    // starting one while a mint's key is still uncopied would lose it the
    // same way a second mint could — block the action outright rather than
    // only fixing when the dialog is allowed to open (ducnmm re-review).
    const keyActionBlockedByUncopiedKey = Boolean(newPrivateKey)
    const showKeySelectionControls = Boolean(effectiveAccountObjectId) && selectedKeyCount > 0 && !accountLookupPending

    const connectedAccountIdRef = useRef(effectiveAccountObjectId)
    connectedAccountIdRef.current = effectiveAccountObjectId

    // Resolves true once the key is stored, so the form can clear the pasted
    // private key instead of leaving it on screen.
    const importExistingKey = useCallback(async (rawKey: string): Promise<boolean> => {
        const normalized = normalizeDelegatePrivateKey(rawKey)
        if (!normalized) {
            setExistingKeyError('Delegate key must be a 64-character hex private key.')
            trackEvent('delegate_key_import_failed', { error_type: 'invalid_input', location: 'dashboard_connect' })
            return false
        }
        const accountId = effectiveAccountObjectId
        if (!accountId) {
            setExistingKeyError('No Walrus Memory account found for this wallet. Create a delegate key first.')
            trackEvent('delegate_key_import_failed', { error_type: 'no_account', location: 'dashboard_connect' })
            return false
        }

        setImportingExistingKey(true)
        setExistingKeyError('')
        trackEvent('delegate_key_import_start', { location: 'dashboard_connect' })
        try {
            const publicKeyHex = await deriveDelegatePublicKeyHex(normalized)
            await assertDelegateKeyRegistered(suiClient, accountId, publicKeyHex)
            if (connectedAccountIdRef.current !== accountId) return false
            setDelegateKeys(normalized, publicKeyHex, accountId)
            trackEvent('delegate_key_import_complete', { location: 'dashboard_connect' })
            return true
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Failed to import delegate key. Please try again.'
            setExistingKeyError(message)
            trackEvent('delegate_key_import_failed', {
                error_type: getAnalyticsErrorType(err),
                location: 'dashboard_connect',
            })
            return false
        } finally {
            setImportingExistingKey(false)
        }
    }, [effectiveAccountObjectId, setDelegateKeys, suiClient])

    const scrollToDelegateKeys = useCallback(() => {
        document
            .getElementById(DELEGATE_KEYS_SECTION_ID)
            ?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }, [])

    const autoScrolledToKeysRef = useRef(false)
    useEffect(() => {
        if (!autoScrollToKeys || autoScrolledToKeysRef.current || isKeyListLoading) return
        autoScrolledToKeysRef.current = true
        scrollToDelegateKeys()
    }, [autoScrollToKeys, isKeyListLoading, scrollToDelegateKeys])

    // A first mint in this browser also saves the key, which mounts the SDK
    // credentials card above the delegate keys section and pushes the one-time
    // key block off screen (WALM-743). Bring the block back into view once it
    // renders, so the user sees the key they must copy now.
    const newKeyBlockRef = useRef<HTMLDivElement>(null)
    useEffect(() => {
        if (!newPrivateKey) return
        newKeyBlockRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }, [newPrivateKey])

    // Two distinct Console arrivals gate the same dialog: a key action
    // (mint or revoke) from /keys (fromKeys), or a brand-new account that
    // just finished /setup after coming from Console's "Set up"
    // (fromConsoleSetup, 28 Sep update). The mint branch additionally
    // requires !newPrivateKey — the one-time key block is still showing
    // otherwise, and this dialog's primary button navigates away.
    const showAccountReadyDialog = Boolean(
        config.consoleUrl && !accountReadyDismissed && !removeKeysConfirm &&
        ((fromKeys && ((justMintedKey && !newPrivateKey) || justRemovedKeys)) || fromConsoleSetup)
    )
    // Mint and revoke clear each other's flag, so the latest key action picks
    // the copy. A /setup arrival with no /keys action keeps the new-account copy.
    const accountReadyDialogCopy = accountReadyCopy(
        justRemovedKeys
            ? { kind: 'revoke', count: removedKeyCount }
            : fromKeys && justMintedKey
                ? { kind: 'mint', label: mintedKeyLabel }
                : null
    )
    const dismissAccountReadyDialog = useCallback(() => {
        setAccountReadyDismissed(true)
        setFromConsoleSetup(false)
    }, [])
    // Console reads `from=wm` to detect a return trip and refresh its link
    // status (see console/frontend MemoryTabPanel.tsx).
    const consoleReturnUrl = config.consoleUrl
        ? `${config.consoleUrl}${config.consoleUrl.includes('?') ? '&' : '?'}from=wm`
        : ''

    useEffect(() => {
        if (!showAccountReadyDialog) return undefined

        const closeOnEscape = (event: KeyboardEvent) => {
            if (event.key === 'Escape') dismissAccountReadyDialog()
        }

        window.addEventListener('keydown', closeOnEscape)
        return () => window.removeEventListener('keydown', closeOnEscape)
    }, [showAccountReadyDialog, dismissAccountReadyDialog])

    useEffect(() => {
        const hash = location.hash || window.location.hash
        if (hash !== `#${DELEGATE_KEYS_SECTION_ID}`) return
        const scroll = () => {
            const section = document.getElementById(DELEGATE_KEYS_SECTION_ID)
            if (!section) return
            const nav = document.querySelector('.dashboard-nav')
            const navHeight = nav instanceof HTMLElement ? nav.getBoundingClientRect().height : 96
            const top = section.getBoundingClientRect().top + window.scrollY - navHeight - 28
            window.scrollTo({ top: Math.max(0, top), behavior: 'auto' })
        }
        scroll()
        const later = window.setTimeout(scroll, 250)
        return () => window.clearTimeout(later)
    }, [location.hash])

    useEffect(() => {
        setSelectedKeyPublicKeys((prev) => {
            const next = prev.filter((publicKey) => selectableKeyPublicKeys.includes(publicKey))
            return next.length === prev.length ? prev : next
        })
    }, [selectableKeyPublicKeys])

    // ============================================================
    // Fetch on-chain delegate keys
    // ============================================================

    const keysFetchGen = useRef(0)
    const fetchOnChainKeys = useCallback(async () => {
        const accountId = effectiveAccountObjectId
        const gen = ++keysFetchGen.current
        if (!accountId) {
            setOnChainKeys([])
            setLoadingKeys(false)
            return
        }
        setLoadingKeys(true)
        try {
            const json = await fetchObjectJson(suiClient, accountId) as
                { delegate_keys?: { public_key?: unknown; sui_address?: string; label?: string; created_at?: string }[] } | null
            if (gen !== keysFetchGen.current) return
            if (json?.delegate_keys) {
                const parsed: OnChainDelegateKey[] = json.delegate_keys.map((f) => ({
                    publicKey: publicKeyToHex(f.public_key),
                    suiAddress: f.sui_address ?? '',
                    label: f.label ?? '',
                    createdAt: Number(f.created_at ?? 0),
                }))
                setOnChainKeys(parsed)
            } else {
                setOnChainKeys([])
            }
        } catch (err) {
            if (gen !== keysFetchGen.current) return
            console.error('Failed to fetch on-chain keys:', err)
        } finally {
            if (gen === keysFetchGen.current) setLoadingKeys(false)
        }
    }, [effectiveAccountObjectId, suiClient])

    useEffect(() => {
        setOnChainKeys([])
        fetchOnChainKeys()
    }, [fetchOnChainKeys])

    const namespacesFetchGen = useRef(0)
    // cursors[i] is the `updated_after` cursor that opens page i; page 0 has none.
    const namespacesCursors = useRef<(string | undefined)[]>([undefined])

    const fetchNamespacesPage = useCallback(async (page: number) => {
        if (!delegateKey || !effectiveAccountObjectId || !address) return
        const gen = ++namespacesFetchGen.current
        setNamespacesLoading(true)
        setNamespacesError('')
        try {
            const owner = address.toLowerCase()
            let target = page
            for (;;) {
                const qs = new URLSearchParams({ limit: String(namespacesPageSize) })
                const cursor = namespacesCursors.current[target]
                if (cursor) qs.set('updated_after', cursor)
                const path = `/v1/owners/${owner}/namespaces?${qs.toString()}`
                const data = await apiGet(
                    delegateKey,
                    config.memwalServerUrl.replace(/\/+$/, ''),
                    path,
                    effectiveAccountObjectId,
                ) as {
                    namespaces?: { name?: string; memory_count?: number }[]
                    next_cursor?: string | null
                    has_more?: boolean
                }
                if (gen !== namespacesFetchGen.current) return
                const rows: { name: string; memory_count: number }[] = []
                for (const ns of data.namespaces ?? []) {
                    if (typeof ns.name === 'string') {
                        rows.push({ name: ns.name, memory_count: Number(ns.memory_count ?? 0) })
                    }
                }
                // Trust has_more + next_cursor, never rows.length: the relayer clamps limit.
                const nextCursor = data.has_more ? (data.next_cursor ?? null) : null
                namespacesCursors.current = namespacesCursors.current.slice(0, target + 1)
                if (nextCursor) namespacesCursors.current[target + 1] = nextCursor
                if (rows.length === 0 && target > 0) {
                    // A continuation page can come back empty when namespaces move past
                    // the relayer's snapshot_at while we page. Drop the cursor that opened
                    // it and land on a real page instead of the first-load empty state.
                    namespacesCursors.current.length = target
                    target -= 1
                    continue
                }
                setNamespaces(rows)
                setNamespacesPage(target)
                setNamespacesHasMore(Boolean(nextCursor))
                return
            }
        } catch (err) {
            if (gen !== namespacesFetchGen.current) return
            console.error('Failed to list namespaces:', err)
            setNamespacesError('Could not load namespace counts from the relayer.')
        } finally {
            if (gen === namespacesFetchGen.current) setNamespacesLoading(false)
        }
    }, [delegateKey, effectiveAccountObjectId, address, namespacesPageSize])

    const refreshNamespaces = useCallback(() => {
        namespacesCursors.current = [undefined]
        setNamespaces([])
        setNamespacesPage(0)
        setNamespacesHasMore(false)
        void fetchNamespacesPage(0)
    }, [fetchNamespacesPage])

    useEffect(() => {
        refreshNamespaces()
    }, [refreshNamespaces])

    // Every page before the current one was full, so the running offset is exact.
    const namespacesRangeStart = namespacesPage * namespacesPageSize + 1
    const namespacesRangeEnd = namespacesPage * namespacesPageSize + namespaces.length
    const namespacesPageMemories = namespaces.reduce((n, ns) => n + ns.memory_count, 0)
    // Hide the footer when everything fits on one page — but keep it once the
    // user has picked a non-default page size, or raising the size to fit the
    // whole list would remove the only control that can lower it again.
    const namespacesIsPaginated = namespacesHasMore
        || namespacesPage > 0
        || namespacesPageSize !== NAMESPACE_DEFAULT_PAGE_SIZE

    // ============================================================
    // Generate + add a new delegate key (via SDK)
    // ============================================================

    const handleAddKey = useCallback(async () => {
        if (!walletSigner) return

        if (!effectiveAccountObjectId) {
            setKeyError('account is still loading. please try again in a moment.')
            trackEvent('delegate_key_add_failed', { error_type: 'account_loading' })
            return
        }

        if (incidentOpen) {
            setKeyError('Restore your account before creating a new key.')
            return
        }

        if (hasMaxDelegateKeys) {
            setKeyError(MAX_DELEGATE_KEYS_MESSAGE)
            trackEvent('delegate_key_add_failed', { error_type: 'max_delegate_keys' })
            return
        }

        // validate label before submitting on-chain
        const trimmedLabel = normalizeLabelForSubmit(newKeyLabel)
        if (!trimmedLabel) {
            setKeyError('key label cannot be empty')
            trackEvent('delegate_key_add_failed', { error_type: 'invalid_input' })
            return
        }
        if (trimmedLabel.length > 64) {
            setKeyError('key label must be 64 characters or fewer')
            trackEvent('delegate_key_add_failed', { error_type: 'invalid_input' })
            return
        }

        setAddingKey(true)
        setKeyError('')
        setNewPrivateKey(null)
        trackEvent('delegate_key_add_start', { location: 'dashboard' })
        try {
            // Generate keypair via SDK
            const delegate = await generateDelegateKey()

            // Register on-chain (v1_new ABI: address derived on-chain, not passed)
            const tx = new Transaction()
            tx.moveCall({
                target: `${config.memwalPackageId}::account::add_delegate_key`,
                arguments: [
                    tx.object(effectiveAccountObjectId!),
                    tx.object(config.memwalRegistryId),
                    tx.pure('vector<u8>', Array.from(delegate.publicKey)),
                    tx.pure('string', trimmedLabel),
                    tx.object('0x6'),
                ],
            })
            const result = await signAndExecuteTx({ transaction: tx })
            await suiClient.waitForTransaction({ digest: result.digest })

            const delegatePublicKeyHex = bytesToHex(delegate.publicKey)
            setNewPrivateKey(delegate.privateKey)
            setMintedKeyLabel(trimmedLabel)
            setDelegateKeys(delegate.privateKey, delegatePublicKeyHex, effectiveAccountObjectId!)
            closeAddKeyForm()
            setNewKeyLabel('New key')
            // Only the latest key action picks the dialog's copy.
            setJustRemovedKeys(false)
            // justMintedKey/accountReadyDismissed arm on Continue (below),
            // not here — arming them on mint success let a second mint or a
            // revoke started while this key was still uncopied wipe
            // newPrivateKey and open the dialog early (ducnmm re-review,
            // WALM-675).

            trackEvent('delegate_key_add_complete', { location: 'dashboard' })
            void navigator.clipboard.writeText(delegate.privateKey).catch(() => undefined)
            void fetchOnChainKeys()
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : 'failed to add key'
            setKeyError(msg)
            trackEvent('delegate_key_add_failed', { error_type: getAnalyticsErrorType(err) })
        } finally {
            setAddingKey(false)
        }
    }, [
        walletSigner,
        signAndExecuteTx,
        incidentOpen,
        hasMaxDelegateKeys,
        effectiveAccountObjectId,
        newKeyLabel,
        suiClient,
        fetchOnChainKeys,
        setDelegateKeys,
        closeAddKeyForm,
    ])

    // ============================================================
    // Remove delegate keys
    // ============================================================

    const removeDelegateKeysInTransaction = useCallback(async (publicKeyHexes: string[]) => {
        if (!walletSigner || !effectiveAccountObjectId) return

        const tx = new Transaction()
        for (const publicKeyHex of publicKeyHexes) {
            tx.moveCall({
                target: `${config.memwalPackageId}::account::remove_delegate_key`,
                arguments: [
                    tx.object(effectiveAccountObjectId),
                    tx.object(config.memwalRegistryId),
                    tx.pure('vector<u8>', hexToByteArray(publicKeyHex)),
                ],
            })
        }

        const result = await signAndExecuteTx({ transaction: tx })
        await suiClient.waitForTransaction({ digest: result.digest })
    }, [walletSigner, effectiveAccountObjectId, signAndExecuteTx, suiClient])

    const executeRemoveKeys = useCallback(async (publicKeyHexes: string[], source: RemoveKeysConfirmState['source']) => {
        if (!walletSigner || !effectiveAccountObjectId || publicKeyHexes.length === 0) return

        const isSelectionRemoval = source === 'selection'
        if (isSelectionRemoval) {
            setRemovingSelectedKeys(true)
        } else {
            setRemovingKey(publicKeyHexes[0])
        }
        setKeyError('')
        setNewPrivateKey(null)

        const removeEventPayload = isSelectionRemoval
            ? { location: 'dashboard', selected_count: publicKeyHexes.length }
            : { location: 'dashboard' }

        trackEvent('delegate_key_remove_start', removeEventPayload)
        try {
            await removeDelegateKeysInTransaction(publicKeyHexes)

            if (delegatePublicKey && publicKeyHexes.includes(delegatePublicKey)) {
                clearDelegateKeys()
            }

            setSelectedKeyPublicKeys((prev) =>
                isSelectionRemoval
                    ? []
                    : prev.filter((key) => key !== publicKeyHexes[0])
            )
            await fetchOnChainKeys()
            if (address) await reloadIncident(address).catch(() => undefined)
            trackEvent('delegate_key_remove_complete', removeEventPayload)
            // Direct reset, not an effect keyed on justRemovedKeys — the flag
            // can already be true from an earlier dismissed dialog, in which
            // case setting it to true again wouldn't change the dependency
            // and an effect-based reset would silently no-op.
            setRemovedKeyCount(publicKeyHexes.length)
            setJustRemovedKeys(true)
            setJustMintedKey(false)
            setAccountReadyDismissed(false)
        } catch (err: unknown) {
            const msg = err instanceof Error
                ? err.message
                : isSelectionRemoval
                    ? 'failed to remove selected keys'
                    : 'failed to remove key'
            setKeyError(msg)
            trackEvent('delegate_key_remove_failed', { error_type: getAnalyticsErrorType(err) })
        } finally {
            if (isSelectionRemoval) {
                setRemovingSelectedKeys(false)
            } else {
                setRemovingKey(null)
            }
        }
    }, [
        walletSigner,
        effectiveAccountObjectId,
        removeDelegateKeysInTransaction,
        delegatePublicKey,
        clearDelegateKeys,
        fetchOnChainKeys,
        address,
        reloadIncident,
    ])

    const handleRemoveKey = useCallback((publicKeyHex: string) => {
        if (!walletSigner || !effectiveAccountObjectId) return
        setRemoveKeysConfirm({ publicKeys: [publicKeyHex], source: 'single' })
    }, [walletSigner, effectiveAccountObjectId])

    const toggleKeySelection = useCallback((publicKeyHex: string) => {
        setSelectedKeyPublicKeys((prev) =>
            prev.includes(publicKeyHex)
                ? prev.filter((key) => key !== publicKeyHex)
                : [...prev, publicKeyHex]
        )
    }, [])

    const clearSelectedKeys = useCallback(() => {
        setSelectedKeyPublicKeys([])
    }, [])

    const handleRemoveSelectedKeys = useCallback(() => {
        if (!walletSigner || !effectiveAccountObjectId || selectedKeyPublicKeys.length === 0) return

        const keysToRemove = selectedKeyPublicKeys.filter((publicKey) => selectableKeyPublicKeys.includes(publicKey))
        if (keysToRemove.length === 0) {
            setSelectedKeyPublicKeys([])
            return
        }

        setRemoveKeysConfirm({ publicKeys: keysToRemove, source: 'selection' })
    }, [
        walletSigner,
        effectiveAccountObjectId,
        selectedKeyPublicKeys,
        selectableKeyPublicKeys,
    ])

    const handleRemoveAffectedKeys = useCallback(() => {
        if (!walletSigner || !effectiveAccountObjectId || affectedOnChainKeys.length === 0) return
        setRemoveKeysConfirm({
            publicKeys: affectedOnChainKeys.map((key) => key.publicKey),
            source: 'selection',
        })
    }, [walletSigner, effectiveAccountObjectId, affectedOnChainKeys])

    const confirmRemoveKeys = useCallback(async () => {
        if (!removeKeysConfirm) return

        await executeRemoveKeys(removeKeysConfirm.publicKeys, removeKeysConfirm.source)
        setRemoveKeysConfirm(null)
    }, [executeRemoveKeys, removeKeysConfirm])

    useEffect(() => {
        if (!removeKeysConfirm || keyRemovalBusy) return undefined

        const closeOnEscape = (event: KeyboardEvent) => {
            if (event.key === 'Escape') {
                setRemoveKeysConfirm(null)
            }
        }

        window.addEventListener('keydown', closeOnEscape)
        return () => window.removeEventListener('keydown', closeOnEscape)
    }, [keyRemovalBusy, removeKeysConfirm])

    const removeConfirmCount = removeKeysConfirm?.publicKeys.length ?? 0
    const removeConfirmBusy = removeKeysConfirm
        ? removeKeysConfirm.source === 'selection'
            ? removingSelectedKeys
            : removingKey === removeKeysConfirm.publicKeys[0]
        : false
    const removeConfirmTitle = removeConfirmCount === 1
        ? 'Remove delegate key?'
        : `Remove ${removeConfirmCount} delegate keys?`
    const removeConfirmDescription = removeConfirmCount === 1
        ? 'This key will be removed from your Walrus Memory account. It can no longer read new memories, but anything already saved stays readable by it until re-encrypted. This cannot be undone.'
        : `${removeConfirmCount} selected keys will be removed from your Walrus Memory account. They can no longer read new memories, but anything already saved stays readable by them until re-encrypted. This cannot be undone.`

    // ============================================================
    // SDK code snippets
    // ============================================================

    // Never render any portion (prefix/suffix) of the real private key
    // in DOM / copyable snippets. Use a static placeholder instead.
    const PRIVATE_KEY_PLACEHOLDER = '<YOUR_PRIVATE_KEY>'
    const ACCOUNT_ID_PLACEHOLDER = '<YOUR_ACCOUNT_ID>'

    const sdkTypeScriptSnippet = `import { MemWal } from "@mysten-incubation/memwal"

const memwal = MemWal.create({
  key: process.env.${PRIVATE_KEY_ENV} ?? "${PRIVATE_KEY_PLACEHOLDER}",
  accountId: process.env.${ACCOUNT_ID_ENV} ?? "${effectiveAccountObjectId ?? ACCOUNT_ID_PLACEHOLDER}",
  serverUrl: process.env.${SERVER_URL_ENV} ?? "${sdkDefaultServerUrl}",
})

// Remember something
const job = await memwal.remember("I'm allergic to peanuts")
await memwal.waitForRememberJob(job.job_id)

// Recall memories
const result = await memwal.recall({ query: "food allergies" })
console.log(result.results[0].text)`

    const sdkPythonSnippet = `import asyncio
import os
from memwal import MemWal

async def main():
    memwal = MemWal.create(
        key=os.environ["${PRIVATE_KEY_ENV}"],
        account_id=os.environ["${ACCOUNT_ID_ENV}"],
        server_url=os.environ.get("${SERVER_URL_ENV}", "${sdkDefaultServerUrl}"),
    )

    await memwal.remember_and_wait("I'm allergic to peanuts")

    result = await memwal.recall(query="food allergies")
    print(result.results[0].text)

    await memwal.close()

asyncio.run(main())`

    const sdkSnippet = quickstartLanguage === 'py' ? sdkPythonSnippet : sdkTypeScriptSnippet
    const docsHref = config.docsUrl || 'https://docs.wal.app/walrus-memory/'
    const githubHref = 'https://github.com/MystenLabs/memwal'
    const discordHref = 'https://discord.gg/walrusprotocol'

    return (
        <div className="dash-page">
            <nav className={`nav playground-nav dashboard-nav${navSolid ? ' dashboard-nav--solid' : ''}`}>
                <div className="nav-inner">
                    <Link to="/" className="nav-brand">
                        <img className="nav-brand-logo" src="/walrus-memory-logo.svg?v=3" alt="Walrus Memory" />
                    </Link>
                    <div className="nav-user">
                        <button
                            type="button"
                            className="nav-address copy-status-button"
                            onClick={() => copyToClipboard(address, 'wallet')}
                            aria-label="Copy wallet address"
                        >
                            <CopyStatusLabel status={copyStatusOf('wallet')} idle={`${address.slice(0, 6)}...${address.slice(-4)}`} copied="Copied" error="Failed" />
                            <CopyStatusIcon status={copyStatusOf('wallet')} size={10} />
                        </button>
                        <button className="lp-nav-cta" onClick={handleLogout}>
                            <span className="nav-cta-label">Sign out</span> <LogOut size={14} aria-hidden="true" />
                        </button>
                    </div>
                </div>
            </nav>

            <main className="dash-shell">
                <ConnectWalrusMemory
                    path={connectPath}
                    onPathChange={setConnectPath}
                    hasDelegateKey={Boolean(delegateKey)}
                    onImportExistingKey={importExistingKey}
                    importingExistingKey={importingExistingKey}
                    importExistingKeyError={existingKeyError}
                    importExistingKeyUnavailable={isKeyListLoading}
                    onSdkKindChange={(kind) => setQuickstartLanguage(kind === 'python' ? 'py' : 'ts')}
                    sdkSnippet={sdkSnippet}
                />

                {incidentOpen && (
                    <div className="dash-alert dash-alert--info" role="status">
                        <TriangleAlert className="dash-alert-icon" size={24} strokeWidth={2.3} aria-hidden="true" />
                        {showLockedCleanup ? (
                            <p>
                                Your account has been temporarily locked following a security disclosure by Railway, our third-party hosting provider. To restore your account, delete the highlighted delegate keys below.
                                {incidentError ? ` ${incidentError}` : null}
                            </p>
                        ) : (
                            <p>
                                Your account is ready to restore.{' '}
                                {incident?.account_id ? (
                                    <button
                                        type="button"
                                        className="dash-alert-link"
                                        onClick={reactivateAccount}
                                        disabled={incidentAction !== null}
                                    >
                                        {incidentAction === 'reactivate' ? 'Reactivating the account' : 'Reactivate the account'}
                                    </button>
                                ) : (
                                    'Reactivate the account'
                                )}
                                .
                                {incidentError ? ` ${incidentError}` : null}
                            </p>
                        )}
                    </div>
                )}

                {showNoBrowserKeyNotice && (
                    <div className="dash-alert dash-alert--info">
                        <Info className="dash-alert-icon" size={24} strokeWidth={2.3} aria-hidden="true" />
                        {onChainKeyCount > 0 ? (
                            <p>
                                This browser doesn't have a key bound to it yet. Your account has{' '}
                                {onChainKeyCount} delegate {onChainKeyCount === 1 ? 'key' : 'keys'} for
                                other clients (
                                <button
                                    type="button"
                                    className="dash-alert-link"
                                    onClick={scrollToDelegateKeys}
                                >
                                    see below
                                </button>
                                ). Create a browser key to manage your account from here, or use the
                                dashboard from a client that has one.
                            </p>
                        ) : (
                            <p>
                                Your Walrus Memory account is active but has no delegate keys yet.
                                Create one to connect this browser and the SDK to your account.
                            </p>
                        )}
                    </div>
                )}

                {hasMaxDelegateKeys && (
                    <div className="dash-alert" style={{ marginBottom: 24 }}>
                        <TriangleAlert className="dash-alert-icon" size={24} strokeWidth={2.3} aria-hidden="true" />
                        <p>{MAX_DELEGATE_KEYS_MESSAGE}</p>
                    </div>
                )}

                {/* Current Delegate Key */}
                {delegateKey && (
                    <Card
                        className="dashboard-credentials-card sept-section"
                        title="SDK credentials"
                        subtitle={`Copy the delegate private key into server env as ${PRIVATE_KEY_ENV}`}
                        data-analytics-sensitive="sdk-credentials"
                    >

                    {relayerLooksMismatched && (
                        <div className="dashboard-credentials-alert">
                            <TriangleAlert className="dashboard-credentials-alert-icon" size={24} strokeWidth={2.3} aria-hidden="true" />
                            <div className="dashboard-credentials-alert-copy">
                                <p>
                                    <strong>{activeEnvironmentLabel}</strong>
                                    <span>Configured relayer: <code>{config.memwalServerUrl}</code> ({relayerEnvironmentLabel}).</span>
                                </p>
                                <p>
                                    This dashboard network and relayer URL look mismatched; API calls may fail with 401.
                                </p>
                            </div>
                        </div>
                    )}

                    <div className="dashboard-credentials-panel">
                        {effectiveAccountObjectId && (
                            <div className="dashboard-credential-row">
                                <div className="dashboard-credential-main">
                                    <div className="dashboard-credential-label">
                                        Account ID <span>{ACCOUNT_ID_ENV}</span>
                                    </div>
                                    <code className="dashboard-credential-value">{effectiveAccountObjectId}</code>
                                </div>
                                <div className="dashboard-credential-actions">
                                    <button
                                        type="button"
                                        className={`dashboard-credential-icon-button copy-status-button${copyStatusOf('acct') === 'copied' ? ' dashboard-credential-icon-button--copied' : ''}`}
                                        onClick={() => copyToClipboard(effectiveAccountObjectId, 'acct')}
                                        aria-label="Copy account ID"
                                        title="Copy account ID"
                                    >
                                        <CopyStatusIcon status={copyStatusOf('acct')} />
                                    </button>
                                </div>
                            </div>
                        )}

                        <div className="dashboard-credential-row">
                            <div className="dashboard-credential-main">
                                <div className="dashboard-credential-label">
                                    Relayer URL <span>{SERVER_URL_ENV}</span>
                                </div>
                                <code className="dashboard-credential-value">{config.memwalServerUrl}</code>
                            </div>
                            <div className="dashboard-credential-actions">
                                <button
                                    type="button"
                                    className={`dashboard-credential-icon-button copy-status-button${copyStatusOf('server-env') === 'copied' ? ' dashboard-credential-icon-button--copied' : ''}`}
                                    onClick={() => copyToClipboard(`${SERVER_URL_ENV}=${config.memwalServerUrl}`, 'server-env')}
                                    aria-label="Copy relayer URL env line"
                                    title="Copy env line"
                                >
                                    <CopyStatusIcon status={copyStatusOf('server-env')} />
                                </button>
                            </div>
                        </div>

                        <div className="dashboard-credential-row">
                            <div className="dashboard-credential-main">
                                <div className="dashboard-credential-label">Delegate public key</div>
                                <code className="dashboard-credential-value">{delegatePublicKey}</code>
                            </div>
                            <div className="dashboard-credential-actions">
                                <button
                                    type="button"
                                    className={`dashboard-credential-icon-button copy-status-button${copyStatusOf('pub') === 'copied' ? ' dashboard-credential-icon-button--copied' : ''}`}
                                    onClick={() => copyToClipboard(delegatePublicKey!, 'pub')}
                                    aria-label="Copy delegate public key"
                                    title="Copy public key"
                                >
                                    <CopyStatusIcon status={copyStatusOf('pub')} />
                                </button>
                            </div>
                        </div>

                        <div className="dashboard-credential-row">
                            <div className="dashboard-credential-main">
                                <div className="dashboard-credential-label">
                                    Delegate private key <span>{PRIVATE_KEY_ENV}</span>
                                </div>
                                <SecretValueInput
                                    className="dashboard-credential-value dashboard-secret-value"
                                    value={delegateKey}
                                    masked={!showKey}
                                    aria-label="Delegate private key"
                                />
                            </div>
                            <div className="dashboard-credential-actions">
                                {showKey && (
                                    <>
                                        <button
                                            type="button"
                                            className={`dashboard-credential-icon-button copy-status-button${copyStatusOf('priv') === 'copied' ? ' dashboard-credential-icon-button--copied' : ''}`}
                                            onClick={() => copyToClipboard(delegateKey!, 'priv')}
                                            aria-label="Copy delegate private key"
                                            title="Copy private key"
                                        >
                                            <CopyStatusIcon status={copyStatusOf('priv')} />
                                        </button>
                                    </>
                                )}
                                <button
                                    type="button"
                                    className="dashboard-credential-icon-button"
                                    onClick={() => setShowKey((value) => !value)}
                                    aria-label={showKey ? 'Hide delegate private key' : 'Reveal delegate private key'}
                                    title={showKey ? 'Hide private key' : 'Reveal private key'}
                                >
                                    {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                                </button>
                            </div>
                        </div>
                    </div>
                    </Card>
                )}

                {delegateKey && (
                    <Card
                        id="namespaces"
                        className="dashboard-keys-card dashboard-namespaces-card sept-section"
                        title="Namespaces"
                        subtitle={
                            namespacesLoading
                                ? 'Loading memory counts from the relayer'
                                : namespacesError
                                    ? namespacesError
                                    : namespaces.length === 0
                                        ? namespacesPage > 0
                                            ? 'This page is empty — go back for the namespaces already listed'
                                            : 'No indexed namespaces yet (or none the relayer can see for this account)'
                                        : namespacesIsPaginated
                                            ? `Showing ${namespacesRangeStart}–${namespacesRangeEnd} · ${namespacesPageMemories} ${namespacesPageMemories === 1 ? 'memory' : 'memories'} on this page`
                                            : `${namespacesPageMemories} memories across ${namespaces.length} ${namespaces.length === 1 ? 'namespace' : 'namespaces'}`
                        }
                        action={
                            <div className="card-header-actions">
                                <button
                                    className="btn btn-secondary btn-sm dashboard-keys-refresh"
                                    onClick={refreshNamespaces}
                                    disabled={namespacesLoading}
                                    aria-busy={namespacesLoading}
                                >
                                    <span>Refresh</span>
                                    <RefreshCw size={12} aria-hidden="true" />
                                </button>
                            </div>
                        }
                    >
                        {namespacesError && (
                            <p className="dashboard-namespace-error">{namespacesError}</p>
                        )}
                        {!namespacesLoading && namespaces.length > 0 && (
                            <div className="dashboard-key-table-wrap">
                                <table className="dashboard-key-table dashboard-namespace-table">
                                    <thead>
                                        <tr>
                                            <th scope="col">Namespace</th>
                                            <th scope="col">Memories</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {namespaces.map((ns) => (
                                            <tr key={ns.name}>
                                                <td data-label="Namespace">
                                                    <Link
                                                        to={`/playground?namespace=${encodeURIComponent(ns.name)}`}
                                                        title="Open this namespace in the playground"
                                                    >
                                                        {ns.name}
                                                    </Link>
                                                </td>
                                                <td className="dashboard-namespace-count" data-label="Memories">{ns.memory_count}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                        {!namespacesError && namespacesIsPaginated && (
                            <nav className="dashboard-pagination" aria-label="Namespaces pages">
                                <div className="dashboard-pagination-size">
                                    <label htmlFor="namespaces-page-size">Items per page</label>
                                    <select
                                        id="namespaces-page-size"
                                        className="dashboard-pagination-select"
                                        value={namespacesPageSize}
                                        onChange={(e) => setNamespacesPageSize(Number(e.target.value))}
                                        disabled={namespacesLoading}
                                    >
                                        {NAMESPACE_PAGE_SIZES.map((size) => (
                                            <option key={size} value={size}>{size}</option>
                                        ))}
                                    </select>
                                </div>
                                <div className="dashboard-pagination-end">
                                    <span className="dashboard-pagination-status" aria-live="polite">
                                        {namespaces.length > 0
                                            ? `${namespacesRangeStart}–${namespacesRangeEnd}`
                                            : `Page ${namespacesPage + 1}`}
                                    </span>
                                    <div className="dashboard-pagination-controls">
                                        <button
                                            type="button"
                                            className="dashboard-pagination-btn"
                                            onClick={() => void fetchNamespacesPage(namespacesPage - 1)}
                                            disabled={namespacesPage === 0 || namespacesLoading}
                                            title="Previous page"
                                            aria-label="Previous page"
                                        >
                                            <ChevronLeft size={16} />
                                        </button>
                                        <button
                                            type="button"
                                            className="dashboard-pagination-btn"
                                            onClick={() => void fetchNamespacesPage(namespacesPage + 1)}
                                            disabled={!namespacesHasMore || namespacesLoading}
                                            title="Next page"
                                            aria-label="Next page"
                                        >
                                            <ChevronRight size={16} />
                                        </button>
                                    </div>
                                </div>
                            </nav>
                        )}
                    </Card>
                )}

                {/* On-Chain Delegate Keys Management */}
                <Card
                    id={DELEGATE_KEYS_SECTION_ID}
                    className={`dashboard-keys-card sept-section${isKeyListRefreshing ? ' dashboard-keys-card--refreshing' : ''}`}
                    title="Delegate keys"
                    subtitle="Create and manage keys for apps and clients that access your Walrus Memory account."
                    action={
                        <div className="card-header-actions">
                            {showLockedCleanup && affectedOnChainKeys.length > 0 && (
                                <button
                                    type="button"
                                    className="btn btn-secondary btn-sm dashboard-keys-remove-affected"
                                    onClick={handleRemoveAffectedKeys}
                                    disabled={keyRemovalBusy || keyActionBlockedByUncopiedKey || !effectiveAccountObjectId}
                                >
                                    Remove highlighted keys
                                </button>
                            )}
                            <button
                                className="btn btn-secondary btn-sm dashboard-keys-refresh"
                                onClick={fetchOnChainKeys}
                                disabled={loadingKeys || accountLookupPending}
                                aria-busy={loadingKeys || accountLookupPending}
                            >
                                <span>Refresh</span>
                                <RefreshCw size={12} aria-hidden="true" />
                            </button>
                            <button
                                className="lp-nav-cta dashboard-keys-add"
                                onClick={() => {
                                    if (hasMaxDelegateKeys) {
                                        setKeyError(MAX_DELEGATE_KEYS_MESSAGE)
                                        trackEvent('delegate_key_add_failed', { error_type: 'max_delegate_keys' })
                                        return
                                    }
                                    trackEvent('cta_click', { cta: 'show_add_delegate_key_form', location: 'dashboard' })
                                    openAddKeyForm()
                                }}
                                disabled={showAddForm || addingKey || incidentOpen || accountLookupPending || !effectiveAccountObjectId || hasMaxDelegateKeys || keyActionBlockedByUncopiedKey}
                            >
                                Add key <Plus size={18} strokeWidth={2.5} aria-hidden="true" />
                            </button>
                        </div>
                    }
                >

                    {/* Status messages */}
                    {keyError && (
                        <div style={{
                            background: 'rgba(248,113,113,0.08)',
                            border: '1px solid rgba(248,113,113,0.2)',
                            borderRadius: 'var(--radius-md)',
                            padding: '10px 14px',
                            marginBottom: 12,
                            color: 'var(--danger)',
                            fontSize: '0.82rem',
                        }}>
                            {keyError}
                        </div>
                    )}
                    {newPrivateKey && (
                        <div
                            ref={newKeyBlockRef}
                            className="dashboard-key-ready-block"
                            data-analytics-sensitive="new-delegate-private-key"
                        >
                            <div className="warning-box dashboard-key-ready-warning">
                                <TriangleAlert className="dashboard-key-ready-warning-icon" size={24} strokeWidth={2.3} aria-hidden="true" />
                                <p>
                                    <strong>Your delegate key is ready.</strong> Save this key now. For your security,
                                    we won't show it again. You'll need the key to configure the Walrus Memory SDK.
                                </p>
                            </div>
                            <div className="key-display key-display--white dashboard-key-ready-display">
                                <div className="key-label">Delegate private key</div>
                                <SecretValueInput
                                    className="key-value key-secret-value"
                                    value={newPrivateKey}
                                    aria-label="New delegate private key"
                                />
                                <div className="key-actions">
                                    <button
                                        className="btn btn-secondary btn-sm copy-status-button"
                                        onClick={() => copyToClipboard(newPrivateKey, 'new-priv')}
                                        aria-label="Copy private key"
                                    >
                                        <CopyStatusIcon status={copyStatusOf('new-priv')} size={12} />
                                        <CopyStatusLabel status={copyStatusOf('new-priv')} idle="Copy private key" />
                                    </button>
                                    <button
                                        className="btn btn-secondary btn-sm"
                                        onClick={() => {
                                            setNewPrivateKey(null)
                                            setJustMintedKey(true)
                                            setAccountReadyDismissed(false)
                                        }}
                                    >
                                        Continue
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Add Key Form */}
                    {showAddForm && (
                        <div className={`dashboard-add-key-form${addKeyFormClosing ? ' dashboard-add-key-form--closing' : ''}`}>
                            <div className="dashboard-add-key-field">
                                <label className="dashboard-add-key-label">
                                    Key name
                                </label>
                                <input
                                    className="dashboard-add-key-input"
                                    type="text"
                                    value={newKeyLabel}
                                    maxLength={64}
                                    onChange={(e) =>
                                        // strip unsafe characters while preserving whitespace during typing
                                        setNewKeyLabel(sanitizeLabelInput(e.target.value))
                                    }
                                    placeholder="New key"
                                />
                            </div>
                            <p className="dashboard-add-key-note">
                                A new keypair will be created, and the private key will be copied to your clipboard.
                                Save it somewhere secure — it can't be shown again.
                            </p>
                            <div className="dashboard-add-key-actions">
                                <button
                                    className="btn btn-secondary btn-sm dashboard-add-key-cancel"
                                    onClick={closeAddKeyForm}
                                    disabled={addingKey}
                                >
                                    Cancel
                                </button>
                                <button
                                    className="btn btn-primary btn-sm dashboard-add-key-create"
                                    onClick={handleAddKey}
                                    disabled={addingKey || incidentOpen || hasMaxDelegateKeys || accountLookupPending || !effectiveAccountObjectId}
                                    aria-busy={addingKey}
                                >
                                    {addingKey ? 'Creating...' : 'Create'}
                                </button>
                            </div>
                        </div>
                    )}

                    {showKeySelectionControls && (
                        <div className="dashboard-key-selection-bar">
                            <span className="dashboard-key-selection-status">
                                {selectedKeyCount} selected
                            </span>
                            <div className="dashboard-key-bulk-actions">
                                <button
                                    type="button"
                                    className="btn btn-secondary btn-sm dashboard-key-clear-selection"
                                    onClick={clearSelectedKeys}
                                    disabled={keyRemovalBusy}
                                >
                                    Clear
                                </button>
                                <button
                                    type="button"
                                    className="btn btn-danger btn-sm dashboard-key-remove-selected"
                                    onClick={handleRemoveSelectedKeys}
                                    disabled={keyRemovalBusy || keyActionBlockedByUncopiedKey}
                                >
                                    <Trash2 size={12} />
                                    {removingSelectedKeys ? 'Removing...' : 'Remove selected'}
                                </button>
                            </div>
                        </div>
                    )}

                    {/* Key List */}
                    {isKeyListLoading ? (
                        <DelegateKeySkeletonList />
                    ) : !effectiveAccountObjectId ? (
                        <div className="dashboard-empty-message dashboard-empty-message--account">
                            <span>No keys yet. </span>
                            <button type="button" className="dashboard-empty-message-link" onClick={() => navigate('/setup')}>Create one</button>
                            <span> to connect to Walrus Memory</span>
                        </div>
                    ) : onChainKeys.length === 0 ? (
                        <div className="dashboard-empty-message dashboard-empty-message--account">
                            <span>No keys yet. </span>
                            <button type="button" className="dashboard-empty-message-link" onClick={() => navigate('/setup')}>Create one</button>
                            <span> to connect to Walrus Memory</span>
                        </div>
                    ) : (
                        <div className={`dashboard-key-table-wrap${isKeyListRefreshing ? ' dashboard-key-list--busy' : ''}`}>
                            <table className="dashboard-key-table">
                                <thead>
                                    <tr>
                                        <th scope="col" className="dashboard-key-table-select">Select</th>
                                        <th scope="col">Key name</th>
                                        <th scope="col">Public key</th>
                                        <th scope="col">Created</th>
                                        <th scope="col" className="dashboard-key-table-actions">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {visibleKeys.map((k) => {
                                        const isCurrentKey = k.publicKey === delegatePublicKey
                                        const isRemoving = removingKey === k.publicKey
                                        const isSelected = selectedKeySet.has(k.publicKey)
                                        const isAffected = affectedKeySet.has(normalizeKeyHex(k.publicKey))
                                        const copyPublicKeyLabel = `pk-${k.publicKey.slice(0,8)}`
                                        return (
                                            <tr
                                                key={k.publicKey}
                                                className={`dashboard-key-row${isSelected ? ' dashboard-key-row--selected' : ''}${isAffected ? ' dashboard-key-row--affected' : ''}`}
                                            >
                                                <td data-label="Select" className="dashboard-key-cell-select">
                                                    <label className="dashboard-key-checkbox" aria-label={`Select ${k.label || 'delegate key'}`}>
                                                        <input
                                                            type="checkbox"
                                                            checked={isAffected || isSelected}
                                                            onChange={() => {
                                                                if (!isAffected) toggleKeySelection(k.publicKey)
                                                            }}
                                                            disabled={keyRemovalBusy}
                                                        />
                                                        <span className="dashboard-key-checkbox-box" aria-hidden="true" />
                                                    </label>
                                                </td>
                                                <td data-label="Key name">
                                                    <div className="dashboard-key-name">
                                                        <span>{k.label || 'Untitled'}</span>
                                                        {isCurrentKey && (
                                                            <span
                                                                className="dashboard-key-current-badge"
                                                                title="This is the delegate key saved in this browser"
                                                            >
                                                                This browser
                                                            </span>
                                                        )}
                                                    </div>
                                                </td>
                                                <td data-label="Public key">
                                                    <code className="dashboard-key-public" title={k.publicKey}>
                                                        {compactPublicKey(k.publicKey)}
                                                    </code>
                                                </td>
                                                <td data-label="Created" className="dashboard-key-created">
                                                    {formatKeyDate(k.createdAt)}
                                                </td>
                                                <td data-label="Actions" className="dashboard-key-row-actions">
                                                    <div className="dashboard-key-actions">
                                                        <button
                                                            className={`btn btn-secondary btn-sm dashboard-key-icon-action copy-status-button${copyStatusOf(copyPublicKeyLabel) === 'copied' ? ' dashboard-key-icon-action--copied' : ''}`}
                                                            onClick={() => copyToClipboard(k.publicKey, copyPublicKeyLabel)}
                                                            aria-label="Copy public key"
                                                            title="Copy public key"
                                                        >
                                                            <CopyStatusIcon status={copyStatusOf(copyPublicKeyLabel)} />
                                                        </button>
                                                        <button
                                                            className="btn btn-danger btn-sm dashboard-key-icon-action"
                                                            onClick={() => handleRemoveKey(k.publicKey)}
                                                            disabled={keyRemovalBusy || keyActionBlockedByUncopiedKey}
                                                            aria-busy={isRemoving}
                                                            aria-label={isRemoving ? 'Removing delegate key' : 'Remove delegate key'}
                                                            title={isRemoving ? 'Removing' : 'Remove delegate key'}
                                                        >
                                                            <Trash2 size={14} />
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        )
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </Card>

                <div className="dashboard-section-head">
                    <h3>Resources</h3>
                    <p>Find guides, developer resources, and support.</p>
                </div>
                <div className="dashboard-resource-grid">
                    <a
                        href={docsHref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="dashboard-resource"
                        onClick={() => trackEvent('outbound_link_click', { link: 'docs', location: 'dashboard' })}
                    >
                        <span>
                            <strong>Documentation</strong>
                            <em>Guides, quickstarts, and API reference.</em>
                        </span>
                        <span className="dashboard-resource-icon" aria-hidden="true">
                            <img src="/sept2026/docs.svg" alt="" />
                        </span>
                    </a>
                    <a
                        href={githubHref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="dashboard-resource"
                        onClick={() => trackEvent('outbound_link_click', { link: 'github', location: 'dashboard' })}
                    >
                        <span>
                            <strong>GitHub</strong>
                            <em>Explore SDK source code and releases.</em>
                        </span>
                        <span className="dashboard-resource-icon" aria-hidden="true">
                            <img src="/sept2026/github.svg" alt="" />
                        </span>
                    </a>
                    <a
                        href={discordHref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="dashboard-resource"
                        onClick={() => trackEvent('outbound_link_click', { link: 'discord', location: 'dashboard' })}
                    >
                        <span>
                            <strong>Discord</strong>
                            <em>Get help from the community.</em>
                        </span>
                        <span className="dashboard-resource-icon" aria-hidden="true">
                            <img src="/sept2026/discord.svg" alt="" />
                        </span>
                    </a>
                </div>

                {config.enableMemoryDeletion && (
                    config.securityDeleteEnabled
                        && <SecurityDeleteSection accountObjectId={securityDeleteAccountObjectId} />
                )}

                {removeKeysConfirm && (
                    <div
                        className="dashboard-confirm-backdrop"
                        onMouseDown={(event) => {
                            if (event.target === event.currentTarget && !removeConfirmBusy) {
                                setRemoveKeysConfirm(null)
                            }
                        }}
                    >
                        <section
                            className="dashboard-confirm-dialog"
                            role="dialog"
                            aria-modal="true"
                            aria-labelledby="dashboard-confirm-title"
                            aria-describedby="dashboard-confirm-description"
                        >
                            <div className="dashboard-confirm-copy">
                                <h3 id="dashboard-confirm-title">{removeConfirmTitle}</h3>
                                <p id="dashboard-confirm-description">{removeConfirmDescription}</p>
                            </div>
                            <div className="dashboard-confirm-actions">
                                <button
                                    type="button"
                                    className="btn btn-secondary dashboard-confirm-cancel"
                                    onClick={() => setRemoveKeysConfirm(null)}
                                    disabled={removeConfirmBusy}
                                    autoFocus
                                >
                                    Cancel
                                </button>
                                <button
                                    type="button"
                                    className="btn btn-danger dashboard-confirm-remove"
                                    onClick={confirmRemoveKeys}
                                    disabled={removeConfirmBusy}
                                    aria-busy={removeConfirmBusy}
                                >
                                    {removeConfirmBusy ? 'Removing...' : 'Remove'}
                                </button>
                            </div>
                        </section>
                    </div>
                )}

                {showAccountReadyDialog && (
                    <div
                        className="dashboard-confirm-backdrop"
                        onMouseDown={(event) => {
                            if (event.target === event.currentTarget) dismissAccountReadyDialog()
                        }}
                    >
                        <section
                            className="dashboard-confirm-dialog dashboard-account-ready-dialog"
                            role="dialog"
                            aria-modal="true"
                            aria-labelledby="dashboard-account-ready-title"
                            aria-describedby="dashboard-account-ready-description"
                        >
                            <div className="dashboard-confirm-copy dashboard-account-ready-body">
                                <h3 id="dashboard-account-ready-title">{accountReadyDialogCopy.title}</h3>
                                <p id="dashboard-account-ready-description">
                                    {accountReadyDialogCopy.description}
                                </p>
                            </div>
                            <div className="dashboard-confirm-actions dashboard-account-ready-actions">
                                <button
                                    type="button"
                                    className="btn btn-secondary dashboard-confirm-cancel"
                                    onClick={dismissAccountReadyDialog}
                                    autoFocus
                                >
                                    Cancel
                                </button>
                                <a href={consoleReturnUrl} className="btn btn-primary dashboard-account-ready-console">
                                    Back to Console
                                </a>
                            </div>
                        </section>
                    </div>
                )}
            </main>
        </div>
    )
}

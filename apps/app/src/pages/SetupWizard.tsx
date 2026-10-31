/**
 * Setup Wizard — Generate delegate key + create Walrus Memory account onchain
 *
 * Steps:
 * 1. Intro — explain delegate keys, "generate delegate key" button
 * 2. Generate Ed25519 keypair → show key + copy + confirm (both flows)
 * 3. On-chain registration (Enoki: sponsored/silent, Wallet: user approves)
 * 4. Save key to sessionStorage → redirect to Dashboard
 */

import { useState, useCallback, useEffect, useRef } from 'react'
import {
    useCurrentAccount,
    useDisconnectWallet,
    useSuiClient,
} from '@mysten/dapp-kit'
import { Transaction } from '@mysten/sui/transactions'
import { useSponsoredTransaction } from '../hooks/useSponsoredTransaction'
import { useDelegateKey } from '../App'
import { SecretValueInput } from '../components/SecretValueInput'
import { Link, useNavigate } from 'react-router-dom'
import { LogOut, Copy, TriangleAlert } from 'lucide-react'
import { config } from '../config'
import { getAnalyticsErrorType, trackEvent } from '../utils/analytics'
import { fetchDelegateKeyCount, isMaxDelegateKeysError, MAX_DELEGATE_KEYS } from '../utils/delegateKeys'
import { fetchAccountIdForOwner, fetchObjectJson, publicKeyToHex } from '../utils/suiClientCompat'

type Step = 'intro' | 'import-key' | 'generating' | 'show-key' | 'onchain' | 'done' | 'error'

const MAX_DELEGATE_KEYS_ERROR = `this wallet already has ${MAX_DELEGATE_KEYS} delegate keys. go to the dashboard, remove an old key, then create a new delegate key.`

const AUTH_METHOD_KEY = 'memwal_auth_method'
const CLAUDE_CONNECT_STORAGE_KEY = 'memwal_claude_connect'
const MCP_CONNECT_STORAGE_KEY = 'memwal_mcp_connect'

function getPersistedAuthMethod(): string | null {
    return sessionStorage.getItem(AUTH_METHOD_KEY)
}

function consumePendingConnectPath(): string {
    for (const [storageKey, path] of [
        [CLAUDE_CONNECT_STORAGE_KEY, '/connect/claude'],
        [MCP_CONNECT_STORAGE_KEY, '/connect/mcp'],
    ] as const) {
        const pending = sessionStorage.getItem(storageKey)
        if (!pending) continue
        sessionStorage.removeItem(storageKey)
        try {
            const params = JSON.parse(pending) as Record<string, string>
            const query = new URLSearchParams(params).toString()
            return query ? `${path}?${query}` : path
        } catch {
            return ''
        }
    }
    return ''
}

function normalizePrivateKeyHex(raw: string): string {
    return raw.trim().replace(/^0x/i, '').replace(/\s+/g, '').toLowerCase()
}

function bytesToHex(bytes: Uint8Array | number[]): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBytes(hex: string): Uint8Array {
    return new Uint8Array(
        Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16))
    )
}

async function getAccountObjectId(suiClient: ReturnType<typeof useSuiClient>, ownerAddress: string): Promise<string | null> {
    try {
        return await fetchAccountIdForOwner(suiClient, config.memwalRegistryId, ownerAddress)
    } catch (err) {
        console.warn('[getAccountObjectId] lookup failed, treating as no-account', err)
        return null
    }
}

type AccountJson = { delegate_keys?: { public_key?: unknown }[] }

async function getDelegateKeyCount(suiClient: ReturnType<typeof useSuiClient>, accountId: string): Promise<number> {
    return (await fetchDelegateKeyCount(suiClient, accountId)) ?? 0
}

async function getRegisteredDelegatePublicKeys(suiClient: ReturnType<typeof useSuiClient>, accountId: string): Promise<string[]> {
    const json = await fetchObjectJson(suiClient, accountId) as AccountJson | null
    if (json?.delegate_keys) {
        return json.delegate_keys.map((k) => publicKeyToHex(k.public_key))
    }

    return []
}

export default function SetupWizard() {
    const currentAccount = useCurrentAccount()
    const { mutateAsync: disconnect } = useDisconnectWallet()
    const { mutateAsync: signAndExecute } = useSponsoredTransaction()
    const suiClient = useSuiClient()
    const { setDelegateKeys } = useDelegateKey()
    const navigate = useNavigate()

    const [step, setStep] = useState<Step>('intro')
    const [privateKeyHex, setPrivateKeyHex] = useState('')
    const [publicKeyHex, setPublicKeyHex] = useState('')
    const [copied, setCopied] = useState(false)
    const [confirmed, setConfirmed] = useState(false)
    const [txStatus, setTxStatus] = useState('')
    const [error, setError] = useState('')
    const [importKeyHex, setImportKeyHex] = useState('')
    const [importingKey, setImportingKey] = useState(false)

    const setupRunningRef = useRef(false)
    const address = currentAccount?.address || ''
    const isEnoki = getPersistedAuthMethod() === 'enoki'

    // ── Done: redirect to dashboard ──
    // Note: setDelegateKeys() (called just before setStep('done')) makes
    // AppContent's /setup route re-render as <Navigate to="/dashboard" />
    // before this effect's timer fires, so this navigate() only actually
    // runs for a pending mcp/claude returnTo — the Console-arrival signal
    // for the plain /dashboard case is attached at that earlier redirect
    // instead (App.tsx's RequireAccountForSetup, ducnmm review).
    useEffect(() => {
        if (step === 'done') {
            sessionStorage.removeItem(AUTH_METHOD_KEY)
            const returnTo = consumePendingConnectPath()
            const timer = setTimeout(() => navigate(returnTo || '/dashboard'), 1500)
            return () => clearTimeout(timer)
        }
    }, [step, navigate])

    const deriveDelegateKey = useCallback(async (privateKeyHexValue: string) => {
        const ed = await import('@noble/ed25519')
        const privateKey = hexToBytes(privateKeyHexValue)
        const publicKey = await ed.getPublicKeyAsync(privateKey)

        return { privHex: privateKeyHexValue, pubHex: bytesToHex(publicKey) }
    }, [])

    // ── Generate Ed25519 keypair (shared) ──
    const generateKeys = useCallback(async () => {
        const privateKey = new Uint8Array(32)
        crypto.getRandomValues(privateKey)
        return deriveDelegateKey(bytesToHex(privateKey))
    }, [deriveDelegateKey])

    // ── Register delegate key on-chain (shared) ──
    const registerOnchain = useCallback(async (
        ownerAddress: string,
        pubKeyHex: string,
    ): Promise<{ accountId: string; transactionDigest: string }> => {
        let knownAccountId = await getAccountObjectId(suiClient, ownerAddress)
        let transactionDigest = ''

        const pubKeyBytes = Array.from(
            { length: pubKeyHex.length / 2 },
            (_, i) => parseInt(pubKeyHex.slice(i * 2, i * 2 + 2), 16)
        )

        if (knownAccountId) {
            const delegateKeyCount = await getDelegateKeyCount(suiClient, knownAccountId)
            if (delegateKeyCount >= MAX_DELEGATE_KEYS) {
                throw new Error(MAX_DELEGATE_KEYS_ERROR)
            }

            setTxStatus('account found! adding delegate key...')
            const tx = new Transaction()
            tx.moveCall({
                target: `${config.memwalPackageId}::account::add_delegate_key`,
                arguments: [
                    tx.object(knownAccountId),
                    tx.object(config.memwalRegistryId),
                    tx.pure('vector<u8>', pubKeyBytes),
                    // v1_new derives the Sui address on-chain — no address arg.
                    tx.pure('string', 'Web App'),
                    tx.object('0x6'),
                ],
            })
            const result = await signAndExecute({ transaction: tx })
            transactionDigest = result.digest
            await suiClient.waitForTransaction({ digest: result.digest })
        } else {
            setTxStatus('creating account...')
            const tx = new Transaction()
            tx.moveCall({
                target: `${config.memwalPackageId}::account::create_account`,
                arguments: [
                    tx.object(config.memwalRegistryId),
                    tx.object('0x6'),
                ],
            })
            const createResult = await signAndExecute({ transaction: tx })
            await suiClient.waitForTransaction({ digest: createResult.digest })

            // Resolve through AccountRegistry after finality. This works for
            // both the app-wide gRPC client and the local JSON-RPC E2E client;
            // getTransactionBlock() is JSON-RPC-only.
            knownAccountId = await getAccountObjectId(suiClient, ownerAddress)

            if (!knownAccountId) {
                throw new Error('Account created but object ID was not found in the registry. Please try again.')
            }

            setTxStatus('adding delegate key...')
            const tx2 = new Transaction()
            tx2.moveCall({
                target: `${config.memwalPackageId}::account::add_delegate_key`,
                arguments: [
                    tx2.object(knownAccountId),
                    tx2.object(config.memwalRegistryId),
                    tx2.pure('vector<u8>', pubKeyBytes),
                    // v1_new derives the Sui address on-chain — no address arg.
                    tx2.pure('string', 'Web App'),
                    tx2.object('0x6'),
                ],
            })
            const addResult = await signAndExecute({ transaction: tx2 })
            transactionDigest = addResult.digest
            await suiClient.waitForTransaction({ digest: addResult.digest })
        }

        return { accountId: knownAccountId!, transactionDigest }
    }, [suiClient, signAndExecute])

    // ── "Generate delegate key" button handler ──
    const handleGenerate = useCallback(async () => {
        if (setupRunningRef.current) return
        setupRunningRef.current = true

        trackEvent('delegate_key_generate_start', { location: 'setup' })
        setStep('generating')
        setError('')

        try {
            const { privHex, pubHex } = await generateKeys()
            setPrivateKeyHex(privHex)
            setPublicKeyHex(pubHex)
            setStep('show-key')
            trackEvent('delegate_key_generated', { location: 'setup' })
        } catch (err) {
            console.error('Setup failed:', err)
            const message = err instanceof Error ? err.message : 'setup failed. please try again.'
            setError(message)
            setStep('error')
            trackEvent('delegate_key_generate_failed', { error_type: getAnalyticsErrorType(err) })
        } finally {
            setupRunningRef.current = false
        }
    }, [generateKeys])

    const handleImportKey = useCallback(async () => {
        if (setupRunningRef.current) return

        const normalizedKey = normalizePrivateKeyHex(importKeyHex)
        if (!/^[0-9a-f]{64}$/.test(normalizedKey)) {
            setError('delegate key must be a 64-character hex private key.')
            trackEvent('delegate_key_import_failed', { error_type: 'invalid_input' })
            return
        }

        setupRunningRef.current = true
        setImportingKey(true)
        setError('')
        trackEvent('delegate_key_import_start', { location: 'setup' })

        try {
            const accountId = await getAccountObjectId(suiClient, address)
            if (!accountId) {
                throw new Error('no Walrus Memory account found for this wallet. generate a new delegate key first.')
            }

            const { pubHex } = await deriveDelegateKey(normalizedKey)
            const registeredPublicKeys = await getRegisteredDelegatePublicKeys(suiClient, accountId)
            if (!registeredPublicKeys.includes(pubHex)) {
                throw new Error('this delegate key is not registered on-chain for the connected wallet.')
            }

            setDelegateKeys(normalizedKey, pubHex, accountId)
            setImportKeyHex('')
            setStep('done')
            trackEvent('delegate_key_import_complete', { location: 'setup' })
        } catch (err) {
            const message = err instanceof Error ? err.message : 'failed to import delegate key. please try again.'
            setError(message)
            trackEvent('delegate_key_import_failed', { error_type: getAnalyticsErrorType(err) })
        } finally {
            setImportingKey(false)
            setupRunningRef.current = false
        }
    }, [address, importKeyHex, deriveDelegateKey, suiClient, setDelegateKeys])

    // ── Wallet: register on-chain after user confirms key ──
    const executeOnchain = useCallback(async () => {
        if (setupRunningRef.current) return
        setupRunningRef.current = true

        trackEvent('delegate_key_register_start', {
            auth_method: isEnoki ? 'enoki' : 'wallet',
            location: 'setup',
        })
        setStep('onchain')
        setError('')
        setTxStatus('checking existing account...')

        try {
            const { accountId } = await registerOnchain(address, publicKeyHex)
            setTxStatus('delegate key registered onchain!')
            setDelegateKeys(privateKeyHex, publicKeyHex, accountId)
            setPrivateKeyHex('')
            setStep('done')
            trackEvent('delegate_key_register_complete', {
                auth_method: isEnoki ? 'enoki' : 'wallet',
                location: 'setup',
            })
        } catch (err: unknown) {
            console.error('Onchain operation failed:', err)
            setError((isMaxDelegateKeysError(err) || (err instanceof Error && err.message === MAX_DELEGATE_KEYS_ERROR)) ? MAX_DELEGATE_KEYS_ERROR : err instanceof Error ? err.message : 'transaction failed. please try again.')
            setStep('show-key')
            trackEvent('delegate_key_register_failed', { error_type: getAnalyticsErrorType(err) })
        } finally {
            setupRunningRef.current = false
        }
    }, [address, publicKeyHex, privateKeyHex, registerOnchain, setDelegateKeys, isEnoki])

    const copyKey = useCallback(async () => {
        await navigator.clipboard.writeText(privateKeyHex)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
    }, [privateKeyHex])

    const handleRetry = useCallback(() => {
        setError('')
        setStep('intro')
    }, [])

    return (
        <div className="setup-classic">
            <nav className="nav setup-classic-nav">
                <div className="nav-inner">
                    <Link to="/" className="nav-brand">
                        <img className="nav-brand-logo" src="/walrus-memory-logo.svg" alt="Walrus Memory" />
                    </Link>
                    <div className="nav-user">
                        <span className="nav-address">
                            {address.slice(0, 6)}...{address.slice(-4)}
                        </span>
                        <button
                            className="lp-nav-cta"
                            onClick={async () => {
                                trackEvent('sign_out', { location: 'setup' })
                                await disconnect()
                                navigate('/')
                            }}
                        >
                            <span className="nav-cta-label">Sign out</span> <LogOut size={14} aria-hidden="true" />
                        </button>
                    </div>
                </div>
            </nav>

            <main className="container setup-classic-container">
                <div className="setup-classic-panel">
                    {/* ===== Step 1: Intro ===== */}
                    {step === 'intro' && (
                        <div className="setup-classic-intro">
                            <h2 className="setup-classic-title">
                                Create your delegate key
                            </h2>
                            <p className="setup-classic-description">
                                A delegate key lets your AI apps and agents access Walrus Memory on
                                your behalf. It's a lightweight Ed25519 keypair that stays separate
                                from your primary account credentials.
                            </p>

                            <div className="card setup-classic-feature-card">
                                <div className="setup-classic-feature">
                                    <div>
                                        <strong>Low risk</strong>
                                        <p>
                                            Cannot access funds or approve transactions
                                        </p>
                                    </div>
                                </div>
                                <div className="setup-classic-feature">
                                    <div>
                                        <strong>Revocable</strong>
                                        <p>
                                            Remove access anytime from your Walrus Memory Dashboard
                                        </p>
                                    </div>
                                </div>
                                <div className="setup-classic-feature">
                                    <div>
                                        <strong>Verified access</strong>
                                        <p>
                                            Delegate permissions are independently verified for
                                            secure, tamper-resistant access control
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div className="setup-classic-actions">
                                <button className="lp-btn-yellow setup-classic-generate" onClick={handleGenerate}>
                                    Create delegate key
                                </button>
                                <button
                                    type="button"
                                    className="setup-classic-import-trigger"
                                    onClick={() => {
                                        setError('')
                                        setStep('import-key')
                                    }}
                                >
                                    Already have a delegate key?
                                </button>
                            </div>
                        </div>
                    )}

                    {/* ===== Import existing key ===== */}
                    {step === 'import-key' && (
                        <div className="setup-classic-import-screen">
                            <h2 className="setup-classic-title">
                                Use an existing delegate key
                            </h2>
                            <p className="setup-classic-description">
                                Paste a delegate private key that is already registered on-chain for
                                this wallet.
                            </p>

                            <div className="setup-classic-import">
                                <div className="input-group">
                                    <textarea
                                        id="delegate-key-input"
                                        className="input setup-import-textarea"
                                        rows={3}
                                        value={importKeyHex}
                                        onChange={(e) => setImportKeyHex(e.target.value)}
                                        placeholder="Paste an existing delegate key"
                                        aria-label="existing delegate key"
                                        spellCheck={false}
                                        autoFocus
                                    />
                                </div>
                                {error && (
                                    <div className="setup-classic-error">
                                        {error}
                                    </div>
                                )}
                                <div className="setup-classic-import-actions">
                                    <button
                                        className="btn btn-secondary setup-import-button"
                                        onClick={handleImportKey}
                                        disabled={importingKey || !importKeyHex.trim()}
                                    >
                                        {importingKey ? 'Checking key...' : 'Continue'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* ===== Generating ===== */}
                    {step === 'generating' && (
                        <div className="setup-classic-state">
                            <div className="spinner setup-classic-spinner" />
                            <p className="setup-classic-state-title">Generating keypair...</p>
                        </div>
                    )}

                    {/* ===== Step 2: Show Key ===== */}
                    {step === 'show-key' && (
                        <div className="setup-classic-ready-screen">
                            <h2 className="setup-classic-title">
                                Your delegate key is ready
                            </h2>

                            <div className="warning-box setup-classic-ready-warning">
                                <TriangleAlert className="setup-classic-ready-warning-icon" size={24} strokeWidth={2.3} aria-hidden="true" />
                                <p>
                                    <strong>Save this key now.</strong> For your security, we won't show it again.
                                    You'll need it to configure the Walrus Memory SDK.
                                </p>
                            </div>

                            <div className="setup-key-panel" data-analytics-sensitive="setup-delegate-private-key">
                                <div className="setup-key-row">
                                    <div className="setup-key-main">
                                        <div className="setup-key-label">Private key <span>keep secret</span></div>
                                        <SecretValueInput
                                            className="setup-key-value setup-secret-value"
                                            value={privateKeyHex}
                                            aria-label="Private key"
                                        />
                                    </div>
                                    <div className="setup-key-actions">
                                        <button
                                            className={`setup-key-copy-button${copied ? ' setup-key-copy-button--copied' : ''}`}
                                            onClick={copyKey}
                                            aria-label={copied ? 'Copied private key' : 'Copy private key'}
                                            title={copied ? 'Copied' : 'Copy private key'}
                                        >
                                            <Copy size={16} aria-hidden="true" />
                                        </button>
                                    </div>
                                </div>
                                <div className="setup-key-row">
                                    <div className="setup-key-main">
                                        <div className="setup-key-label">Public key <span>shareable</span></div>
                                        <code className="setup-key-value">{publicKeyHex}</code>
                                    </div>
                                </div>
                            </div>

                            {error && (
                                <div className="setup-classic-error setup-classic-ready-error">
                                    <div>{error}</div>
                                    {error === MAX_DELEGATE_KEYS_ERROR && (
                                        <Link to="/dashboard" className="setup-classic-error-action">
                                            Manage keys in Dashboard
                                        </Link>
                                    )}
                                </div>
                            )}

                            <label className="setup-classic-confirm">
                                <input
                                    type="checkbox"
                                    checked={confirmed}
                                    onChange={(e) => setConfirmed(e.target.checked)}
                                />
                                <span className="setup-classic-confirm-box" aria-hidden="true" />
                                <span className="setup-classic-confirm-text">I've saved my private key. I understand Walrus Memory can't show it again.</span>
                            </label>

                            <button
                                className="setup-classic-register"
                                disabled={!confirmed}
                                onClick={executeOnchain}
                            >
                                {isEnoki ? 'Continue →' : 'Register key onchain & continue →'}
                            </button>
                        </div>
                    )}

                    {/* ===== Onchain tx in progress ===== */}
                    {step === 'onchain' && (
                        <div className="setup-classic-state">
                            <div className="spinner setup-classic-spinner" />
                            <p className="setup-classic-state-title">{txStatus}</p>
                            <p className="setup-classic-state-subtitle">
                                {isEnoki
                                    ? 'This may take a few seconds...'
                                    : 'Please approve the transaction in your wallet'}
                            </p>
                        </div>
                    )}

                    {/* ===== Error ===== */}
                    {step === 'error' && (
                        <div style={{ textAlign: 'center', padding: '60px 0' }}>
                            <h2 style={{ fontSize: '1.4rem', fontWeight: 700, marginBottom: 8, color: 'var(--danger)' }}>
                                Setup failed
                            </h2>
                            <p style={{ color: 'var(--text-secondary)', marginBottom: 16, fontSize: '0.85rem' }}>
                                {error}
                            </p>
                            <button className="lp-btn-yellow" onClick={handleRetry}>
                                Try again
                            </button>
                        </div>
                    )}

                    {/* ===== Done ===== */}
                    {step === 'done' && (
                        <div className="setup-classic-state">
                            <h2 className="setup-classic-state-heading">All set</h2>
                            <p className="setup-classic-state-subtitle">
                                Your delegate key has been registered onchain. Loading dashboard...
                            </p>
                        </div>
                    )}
                </div>
            </main>
        </div>
    )
}

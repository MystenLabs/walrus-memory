import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { LogOut } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { AdminActivityPanel } from '../components/AdminActivity'
import { AdminKeyEntry } from '../components/AdminKeyEntry'
import { AdminWalletBalances } from '../components/AdminWalletBalances'
import { AdminUploadErrors } from '../components/AdminUploadErrors'
import { AdminConfig } from '../components/AdminConfig'
import { AdminRateLimits } from '../components/AdminRateLimits'
import { fetchAdminConfig } from '../utils/admin-api'

const ADMIN_KEY_STORAGE = 'admin_api_key'

export default function AdminDashboard() {
  const queryClient = useQueryClient()
  const [adminKey, setAdminKey] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isRestoring, setIsRestoring] = useState(true)
  const [banner, setBanner] = useState<string | undefined>(undefined)
  const [navSolid, setNavSolid] = useState(false)

  useEffect(() => {
    const onScroll = () => setNavSolid(window.scrollY > 220)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    const stored = sessionStorage.getItem(ADMIN_KEY_STORAGE)
    if (!stored) {
      setIsRestoring(false)
      return
    }
    // A key restored from a previous session may since have been rotated
    // or was never valid to begin with (e.g. left over from before this
    // validation existed) — re-check it before trusting it, otherwise a
    // stale key sits in sessionStorage across reloads (it only clears on
    // tab close) and every panel fails with 401 on every future reload.
    fetchAdminConfig(stored)
      .then(() => setAdminKey(stored))
      .catch(() => sessionStorage.removeItem(ADMIN_KEY_STORAGE))
      .finally(() => setIsRestoring(false))
  }, [])

  const handleKeySubmit = async (key: string) => {
    setIsSubmitting(true)
    try {
      const trimmedKey = key.trim()
      await fetchAdminConfig(trimmedKey)
      sessionStorage.setItem(ADMIN_KEY_STORAGE, trimmedKey)
      queryClient.removeQueries({ queryKey: ['admin'] })
      setBanner(undefined)
      setAdminKey(trimmedKey)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleLogout = () => {
    sessionStorage.removeItem(ADMIN_KEY_STORAGE)
    queryClient.removeQueries({ queryKey: ['admin'] })
    setBanner(undefined)
    setAdminKey(null)
  }

  // A panel's own query can 401 after a successful login — the key was
  // rotated server-side, or (see the mount-time check above) it was never
  // actually valid. Rather than leave three "Invalid API key" cards sitting
  // on screen waiting for someone to notice and click Logout, drop straight
  // back to the login form with an explicit reason.
  const activityPreview =
    import.meta.env.DEV &&
    new URLSearchParams(window.location.search).get('preview') === 'activity'

  const handleInvalidKey = () => {
    sessionStorage.removeItem(ADMIN_KEY_STORAGE)
    queryClient.removeQueries({ queryKey: ['admin'] })
    setAdminKey(null)
    setBanner('Your admin API key is no longer valid. Please sign in again.')
  }

  return (
    <div className="admin-dashboard-page dash-page">
      <nav className={`nav playground-nav dashboard-nav${navSolid ? ' dashboard-nav--solid' : ''}`}>
        <div className="nav-inner">
          <Link to="/" className="nav-brand">
            <img className="nav-brand-logo" src="/walrus-memory-logo.svg?v=3" alt="Walrus Memory" />
          </Link>
          {adminKey && (
            <div className="nav-user">
              <span className="nav-address">Admin</span>
              <button className="lp-nav-cta" onClick={handleLogout}>
                Sign out <LogOut size={14} />
              </button>
            </div>
          )}
        </div>
      </nav>

      <main className="admin-dashboard-container dash-shell">
        <div className="dashboard-header">
          <h2>Admin Dashboard</h2>
          <p>Monitor spend, wallet balances, upload errors, and system configuration</p>
        </div>

        {isRestoring ? (
          <div className="admin-loading">Checking saved session...</div>
        ) : !adminKey && !activityPreview ? (
          <AdminKeyEntry
            onKeySubmit={handleKeySubmit}
            isLoading={isSubmitting}
            banner={banner}
          />
        ) : (
          <div className="admin-panels">
            <AdminActivityPanel
              adminKey={adminKey ?? ''}
              onInvalidKey={handleInvalidKey}
              preview={activityPreview && !adminKey}
              afterMemories={adminKey ? <AdminRateLimits adminKey={adminKey} onInvalidKey={handleInvalidKey} /> : undefined}
            />
            {adminKey && (
              <>
                <AdminWalletBalances adminKey={adminKey} onInvalidKey={handleInvalidKey} />
                <AdminUploadErrors adminKey={adminKey} onInvalidKey={handleInvalidKey} />
                <AdminConfig adminKey={adminKey} onInvalidKey={handleInvalidKey} />
              </>
            )}
          </div>
        )}
      </main>
    </div>
  )
}

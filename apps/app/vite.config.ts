import { readFileSync } from 'node:fs'

import { defineConfig, loadEnv } from 'vite'
import type { HtmlTagDescriptor, Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import wasm from 'vite-plugin-wasm'
import topLevelAwait from 'vite-plugin-top-level-await'
import { requiredMemwalIds } from './src/requiredMemwalIds'

/** Dev-server-only wallet injection used by the manual testnet launcher.
 * The private key is a Node-side variable and this plugin is absent unless
 * explicitly enabled; `apply: 'serve'` also prevents build output leakage. */
export function devWalletInjector(env: Record<string, string>): Plugin | null {
  const suiPrivateKey = env.DEV_WALLET_PRIVATE_KEY
  if (!suiPrivateKey) return null
  const grpcUrl = env.VITE_SUI_GRPC_URL?.trim()
  const network = env.VITE_SUI_NETWORK?.trim()
  if (!grpcUrl) throw new Error('DEV_WALLET_PRIVATE_KEY requires VITE_SUI_GRPC_URL')
  if (!network) throw new Error('DEV_WALLET_PRIVATE_KEY requires VITE_SUI_NETWORK')

  return {
    name: 'memwal-dev-wallet-injector',
    apply: 'serve',
    async transformIndexHtml(): Promise<HtmlTagDescriptor[]> {
      const { buildDevWalletBundle } = await import('./e2e/support/buildDevWalletBundle')
      const bundlePath = await buildDevWalletBundle()
      const walletConfig = JSON.stringify({
        suiPrivateKey,
        endpoint: grpcUrl,
        transport: 'grpc',
        network,
      }).replace(/</g, '\\u003c')

      return [
        {
          tag: 'script',
          injectTo: 'head-prepend',
          children: `window.__E2E_WALLET_CONFIG__ = ${walletConfig};`,
        },
        {
          tag: 'script',
          injectTo: 'head-prepend',
          children: readFileSync(bundlePath, 'utf8'),
        },
      ]
    },
  }
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  // Dev and production builds must not start when these ids are unset.
  requiredMemwalIds(env)

  const devWalletPlugin = devWalletInjector(env)

  // Opt-in dev-server proxy (set DEV_BACKEND_PROXY_TARGET, e.g. in
  // .env.local — not VITE_-prefixed, this is Node-side vite.config.ts only,
  // never bundled into client code). Needed when the target backend's CORS
  // allowlist has no localhost entry, so the memwal SDK's direct browser
  // calls (/health, /version, /api/*, /sponsor) would otherwise be blocked.
  // No path rewrite, so signed-request signatures (which sign method+path+
  // body, not host) stay valid. Unset by default — no proxy configured.
  const proxyTarget = env.DEV_BACKEND_PROXY_TARGET
  const proxyConfig = { changeOrigin: true, secure: true }
  const proxy = proxyTarget
    ? {
        '/api': { target: proxyTarget, ...proxyConfig },
        '/health': { target: proxyTarget, ...proxyConfig },
        '/version': { target: proxyTarget, ...proxyConfig },
        '/config': { target: proxyTarget, ...proxyConfig },
        '/sponsor': { target: proxyTarget, ...proxyConfig },
      }
    : undefined

  return {
    plugins: [react(), wasm(), topLevelAwait(), ...(devWalletPlugin ? [devWalletPlugin] : [])],
    resolve: {
      dedupe: ['react', 'react-dom', '@tanstack/react-query'],
    },
    optimizeDeps: {
      include: ['@mysten/seal', '@mysten/sui/transactions', '@mysten/sui/client'],
    },
    server: {
      proxy,
    },
  }
})

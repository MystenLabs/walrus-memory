import { configDefaults, defineConfig, mergeConfig } from 'vitest/config'
import viteConfig from './vite.config'

// Not a dashboard build. Supply placeholders so `vite dev` / `vite build`
// still fail when these are unset, while unit tests can load the Vite config.
if (!process.env.VITE_MEMWAL_PACKAGE_ID?.trim()) {
    process.env.VITE_MEMWAL_PACKAGE_ID = '0x1'
}
if (!process.env.VITE_MEMWAL_REGISTRY_ID?.trim()) {
    process.env.VITE_MEMWAL_REGISTRY_ID = '0x1'
}

export default defineConfig(async (env) => mergeConfig(
    await viteConfig({ ...env, command: 'serve', isSsrBuild: false, isPreview: false }),
    defineConfig({ test: {
        environment: 'jsdom',
        setupFiles: ['./src/test/setup.ts'],
        globals: true,
        // e2e/ is Playwright's testDir (`pnpm test:e2e`), not a vitest suite.
        exclude: [...configDefaults.exclude, 'e2e/**'],
    } }),
))

/** Package and registry ids the dashboard must receive from the environment. */
export function requiredMemwalIds(env: {
    VITE_MEMWAL_PACKAGE_ID?: string
    VITE_MEMWAL_REGISTRY_ID?: string
}): { memwalPackageId: string; memwalRegistryId: string } {
    const memwalPackageId = env.VITE_MEMWAL_PACKAGE_ID?.trim() ?? ''
    const memwalRegistryId = env.VITE_MEMWAL_REGISTRY_ID?.trim() ?? ''
    const missing: string[] = []
    if (!memwalPackageId) missing.push('VITE_MEMWAL_PACKAGE_ID')
    if (!memwalRegistryId) missing.push('VITE_MEMWAL_REGISTRY_ID')
    if (missing.length > 0) {
        const label = missing.length === 1 ? 'variable' : 'variables'
        throw new Error(`Missing required ${label} ${missing.join(', ')}`)
    }
    return { memwalPackageId, memwalRegistryId }
}

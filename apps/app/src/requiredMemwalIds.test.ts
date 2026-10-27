import { describe, expect, it } from 'vitest'
import { requiredMemwalIds } from './requiredMemwalIds'

const packageId = '0xpkg'
const registryId = '0xreg'

describe('requiredMemwalIds', () => {
    it('throws when the package id is missing', () => {
        expect(() => requiredMemwalIds({
            VITE_MEMWAL_REGISTRY_ID: registryId,
        })).toThrow(/VITE_MEMWAL_PACKAGE_ID/)
    })

    it('throws when the registry id is missing', () => {
        expect(() => requiredMemwalIds({
            VITE_MEMWAL_PACKAGE_ID: packageId,
        })).toThrow(/VITE_MEMWAL_REGISTRY_ID/)
    })

    it('throws when an id is a blank string', () => {
        expect(() => requiredMemwalIds({
            VITE_MEMWAL_PACKAGE_ID: '',
            VITE_MEMWAL_REGISTRY_ID: registryId,
        })).toThrow(/VITE_MEMWAL_PACKAGE_ID/)
        expect(() => requiredMemwalIds({
            VITE_MEMWAL_PACKAGE_ID: packageId,
            VITE_MEMWAL_REGISTRY_ID: '   ',
        })).toThrow(/VITE_MEMWAL_REGISTRY_ID/)
    })

    it('returns both ids when they are set', () => {
        expect(requiredMemwalIds({
            VITE_MEMWAL_PACKAGE_ID: packageId,
            VITE_MEMWAL_REGISTRY_ID: registryId,
        })).toEqual({
            memwalPackageId: packageId,
            memwalRegistryId: registryId,
        })
    })
})

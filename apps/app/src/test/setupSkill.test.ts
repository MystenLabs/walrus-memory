import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const skill = readFileSync(resolve(process.cwd(), 'public/skills/setup'), 'utf8')

describe('setup skill one-time consent copy', () => {
    it('names Always allow, Instructions for Claude, the dashboard, and secret exclusions', () => {
        expect(skill).toContain('Always allow')
        expect(skill).toContain('on that first prompt')
        expect(skill).toContain('Instructions for Claude')
        expect(skill).toContain('memory.walrus.xyz')
        expect(skill).toContain('passwords')
        expect(skill).toContain('API keys')
        expect(skill).toContain('government identifiers')
    })
})

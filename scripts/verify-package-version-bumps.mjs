#!/usr/bin/env node
// Compare runtime payloads against the stable main baseline at promotion time.
// Dev PRs can continue working on a not-yet-stable release without bumping each commit.
import { execFileSync } from 'node:child_process';
const baseIndex = process.argv.indexOf('--base');
const base = process.argv[baseIndex + 1];
if (baseIndex < 0 || !base || base.startsWith('-')) throw new Error('--base <commit> is required');
const headIndex = process.argv.indexOf('--head');
const head = headIndex < 0 ? 'HEAD' : process.argv[headIndex + 1];
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
for (const directory of ['packages/sdk', 'packages/mcp', 'packages/openclaw-memory-memwal']) {
    const changed = git('diff', '--name-only', base, head, '--', directory).split('\n');
    const runtime = changed.some(file => file.startsWith(`${directory}/src/`)
        || file.startsWith(`${directory}/plugin/scripts/`)
        || file === `${directory}/package.json`);
    if (!runtime) continue;
    const previous = JSON.parse(git('show', `${base}:${directory}/package.json`)).version;
    const next = JSON.parse(git('show', `${head}:${directory}/package.json`)).version;
    if (!/^\d+\.\d+\.\d+$/.test(previous) || !/^\d+\.\d+\.\d+$/.test(next)) throw new Error(`${directory}: stable source versions required`);
    const a = previous.split('.').map(Number), b = next.split('.').map(Number);
    const difference = b.findIndex((part, i) => part !== a[i]);
    if (difference < 0 || b[difference] < a[difference]) {
        throw new Error(`${directory}: runtime payload changed but version ${previous} was not increased (received ${next})`);
    }
    console.log(`${directory}: ${previous} -> ${next}`);
}

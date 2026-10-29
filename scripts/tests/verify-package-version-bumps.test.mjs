import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
const checker = resolve('scripts/verify-package-version-bumps.mjs');
function fixture(t) {
    const cwd = mkdtempSync(join(tmpdir(), 'memwal-version-guard-'));
    t.after(() => rmSync(cwd, { recursive: true, force: true }));
    const git = (...args) => execFileSync('git', ['-c', 'user.name=Release Test', '-c', 'user.email=release-test@example.invalid', '-c', 'commit.gpgsign=false', '-c', `core.hooksPath=${join(cwd, 'no-hooks')}`, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    git('init');
    for (const pkg of ['sdk', 'mcp', 'openclaw-memory-memwal']) {
        mkdirSync(join(cwd, 'packages', pkg, 'src'), { recursive: true });
        writeFileSync(join(cwd, 'packages', pkg, 'package.json'), JSON.stringify({ version: '1.0.0' }));
        writeFileSync(join(cwd, 'packages', pkg, 'src', 'index.js'), 'export const value = 1;');
    }
    git('add', '.'); git('commit', '-m', 'base');
    const base = git('rev-parse', 'HEAD');
    return { cwd, git, base, run: () => spawnSync(process.execPath, [checker, '--base', base], { cwd, encoding: 'utf8' }) };
}
test('runtime changes require a version bump', t => {
    const f = fixture(t);
    writeFileSync(join(f.cwd, 'packages/mcp/src/index.js'), 'export const value = 2;');
    f.git('add', '.'); f.git('commit', '-m', 'runtime');
    const result = f.run();
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /runtime payload changed but version/);
});
test('runtime changes with an increased patch version pass', t => {
    const f = fixture(t);
    writeFileSync(join(f.cwd, 'packages/mcp/src/index.js'), 'export const value = 2;');
    writeFileSync(join(f.cwd, 'packages/mcp/package.json'), JSON.stringify({ version: '1.0.1' }));
    f.git('add', '.'); f.git('commit', '-m', 'release');
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
});
test('test-only changes do not require a package release', t => {
    const f = fixture(t);
    mkdirSync(join(f.cwd, 'packages/mcp/test'));
    writeFileSync(join(f.cwd, 'packages/mcp/test/example.test.mjs'), '// regression');
    f.git('add', '.'); f.git('commit', '-m', 'test');
    const result = f.run();
    assert.equal(result.status, 0, result.stderr);
});

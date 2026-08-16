/**
 * The lockfile reader's new home, and the boundary that keeps it here.
 *
 * The PARSERS are exercised in `apps/cli/src/declared-packages.test.ts` — 19
 * cases, unchanged by the move, still green because the CLI now imports this
 * module through a one-line re-export. Duplicating them here would double the
 * maintenance without doubling the evidence, so this file tests the two things
 * that are NEW:
 *
 *  1. the placement contract — reachable from `@vibeguard/analyzer-core/node`
 *     and from nowhere else, in particular not from the browser entry, and
 *  2. `lockfileStamp`, which exists so a long-lived channel (the editor) can
 *     cache the answer without going stale.
 */
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { lockfileStamp, readDeclaredPackages } from './declared-packages.js';
import * as nodeEntry from './node.js';
import * as browserEntry from './browser.js';
import * as defaultEntry from './index.js';

const TEMP_DIRS: string[] = [];
afterEach(async () => {
  while (TEMP_DIRS.length) {
    const d = TEMP_DIRS.pop()!;
    try {
      await rm(d, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  }
});

async function makeDir(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'vg-declared-node-'));
  TEMP_DIRS.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content, 'utf8');
  }
  return dir;
}

const LOCK_WITH = (name: string): string =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: { '': {}, [`node_modules/${name}`]: { version: '1.0.0' } },
  });

describe('the module is reachable through the node subpath and nowhere else', () => {
  it('the ./node entry exports the reader (positive control for the whole boundary)', () => {
    expect(typeof nodeEntry.readDeclaredPackages).toBe('function');
    expect(typeof nodeEntry.lockfileStamp).toBe('function');
    expect(nodeEntry.readDeclaredPackages).toBe(readDeclaredPackages);
  });

  it('the browser entry does NOT export it', () => {
    // The negative half of the same fact, and the one that matters: Chrome
    // imports `@vibeguard/analyzer-core/browser`, so anything reachable from
    // there is in the extension's bundle. `node:fs` in that bundle does not
    // fail loudly — esbuild resolves it and the extension breaks at runtime.
    expect('readDeclaredPackages' in browserEntry).toBe(false);
    expect('lockfileStamp' in browserEntry).toBe(false);
  });

  it('the default entry does NOT export it either', () => {
    // `.` already reaches `node:fs` through `scanPath`, so this is not about
    // fs-purity — it is about there being ONE door. A capability that is
    // Node-only should say so at every import site, or the next one lands on
    // the browser side by copying an import that looked harmless.
    expect('readDeclaredPackages' in defaultEntry).toBe(false);
    expect('lockfileStamp' in defaultEntry).toBe(false);
  });

  it("package.json publishes the subpath the extensions import", () => {
    // The runtime checks above pass on the source graph; consumers resolve
    // through the exports map, which only the manifest decides. A missing entry
    // here is a build-time failure in two other workspaces.
    const manifest = JSON.parse(
      readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8'),
    ) as { exports: Record<string, { import: string; types: string }> };
    expect(manifest.exports['./node']).toEqual({
      import: './dist/node.js',
      types: './dist/node.d.ts',
    });
  });
});

describe('readDeclaredPackages, through its new home', () => {
  it('returns the resolved names of a package-lock.json next to the target', async () => {
    const dir = await makeDir({ 'package-lock.json': LOCK_WITH('expresss') });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual(['expresss']);
    expect(result.sources).toEqual([{ file: 'package-lock.json', count: 1 }]);
    expect(result.warnings).toEqual([]);
  });

  it('returns nothing, and says nothing, when there is no lockfile', async () => {
    const dir = await makeDir({ 'app.js': 'const x = 1;\n' });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual([]);
    expect(result.warnings).toEqual([]);
  });
});

/**
 * `lockfileStamp` is a cache-invalidation key, so the property under test is
 * "changes exactly when the answer could have changed". A stamp that is too
 * stable is a false negative in the editor — a package the user just removed
 * stays silenced — and that is the failure direction §17z-b forbids.
 */
describe('lockfileStamp', () => {
  it('is stable across calls when nothing changed', async () => {
    const dir = await makeDir({ 'package-lock.json': LOCK_WITH('expresss') });
    expect(await lockfileStamp(dir)).toBe(await lockfileStamp(dir));
  });

  it('changes when a lockfile appears', async () => {
    const dir = await makeDir({ 'app.js': 'const x = 1;\n' });
    const before = await lockfileStamp(dir);
    await writeFile(join(dir, 'package-lock.json'), LOCK_WITH('expresss'), 'utf8');
    expect(await lockfileStamp(dir)).not.toBe(before);
  });

  it('changes when a lockfile gains an entry', async () => {
    const dir = await makeDir({ 'package-lock.json': LOCK_WITH('expresss') });
    const before = await lockfileStamp(dir);
    await writeFile(
      join(dir, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': {},
          'node_modules/expresss': { version: '1.0.0' },
          'node_modules/lodashh': { version: '2.0.0' },
        },
      }),
      'utf8',
    );
    expect(await lockfileStamp(dir)).not.toBe(before);
  });

  it('changes when a lockfile is deleted', async () => {
    const dir = await makeDir({ 'package-lock.json': LOCK_WITH('expresss') });
    const before = await lockfileStamp(dir);
    await rm(join(dir, 'package-lock.json'));
    expect(await lockfileStamp(dir)).not.toBe(before);
  });

  it('distinguishes two directories that hold identical lockfiles', async () => {
    // The stamp keys a per-root cache, so two roots whose lockfiles happen to
    // be byte-identical must not collide into one another's entry.
    const a = await makeDir({ 'package-lock.json': LOCK_WITH('expresss') });
    const b = await makeDir({ 'package-lock.json': LOCK_WITH('expresss') });
    expect(await lockfileStamp(a)).not.toBe(await lockfileStamp(b));
  });

  it('answers for a file target the way the reader does — its directory', async () => {
    const dir = await makeDir({
      'package-lock.json': LOCK_WITH('expresss'),
      'app.js': 'const x = 1;\n',
    });
    expect(await lockfileStamp(join(dir, 'app.js'))).toBe(await lockfileStamp(dir));
  });

  it('does not throw on a target that does not exist', async () => {
    expect(await lockfileStamp(join(tmpdir(), 'vg-does-not-exist-42'))).toBe('missing-target');
  });
});

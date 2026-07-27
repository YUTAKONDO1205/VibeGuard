// §17z-b — the lockfile half of the declared-package veto.
//
// This file tests lockfile → names. The other half (names → veto) lives in
// packages/analyzer-core/src/declared-veto.test.ts, because the two halves are
// in different packages on purpose: analyzer-core must stay importable in a
// browser bundle and so may not read a file, while a rule must stay a pure
// function of one file's text. `string[]` is the whole interface between them.
//
// THE LOAD-BEARING TEST IN HERE is "reads a lockfile, ignores a manifest". It
// is the one that decides whether this feature suppresses false positives or
// suppresses the truth: a generator that hallucinates an import writes the
// matching package.json line in the same completion, so a manifest-sourced veto
// would silence exactly the findings VG-AISC-001 exists to raise. A lockfile
// entry cannot be produced that way — it only exists because a registry
// resolved the name.
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { readDeclaredPackages } from './declared-packages.js';

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
  const dir = await mkdtemp(join(tmpdir(), 'vg-lockfile-'));
  TEMP_DIRS.push(dir);
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content, 'utf8');
  }
  return dir;
}

describe('readDeclaredPackages — the manifest/lockfile boundary', () => {
  it('reads a lockfile', async () => {
    const dir = await makeDir({
      'package-lock.json': JSON.stringify({
        name: 'demo',
        lockfileVersion: 3,
        packages: {
          '': { name: 'demo', version: '1.0.0', dependencies: { expresss: '^1.0.0' } },
          'node_modules/expresss': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/expresss/-/expresss-1.0.0.tgz',
          },
        },
      }),
    });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual(['expresss']);
    expect(result.sources).toEqual([{ file: 'package-lock.json', count: 1 }]);
    expect(result.warnings).toEqual([]);
  });

  it('IGNORES package.json and requirements.txt, even when they name the package', async () => {
    // The whole bet. If this ever returns `['expresss']`, the veto has become a
    // way for a model to silence its own hallucination by declaring it.
    const dir = await makeDir({
      'package.json': JSON.stringify({
        name: 'demo',
        dependencies: { expresss: '^1.0.0' },
        devDependencies: { lodahs: '^1.0.0' },
      }),
      'requirements.txt': 'reqeusts==2.31.0\n',
      'pyproject.toml': '[project]\ndependencies = ["reqeusts"]\n',
      'Pipfile': '[packages]\nreqeusts = "*"\n',
    });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual([]);
    expect(result.sources).toEqual([]);
    // Not a warning either: there is no lockfile, which is an ordinary state,
    // not a failure. Warnings mean "a lockfile was there and I could not use
    // it" and would be noise if they meant anything else.
    expect(result.warnings).toEqual([]);
  });

  it('unions every lockfile present', async () => {
    const dir = await makeDir({
      'package-lock.json': JSON.stringify({
        packages: { 'node_modules/expresss': { version: '1.0.0' } },
      }),
      'poetry.lock': '[[package]]\nname = "reqeusts"\nversion = "2.31.0"\n',
    });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual(['expresss', 'reqeusts']);
    expect(result.sources.map((s) => s.file)).toEqual(['package-lock.json', 'poetry.lock']);
  });
});

describe('readDeclaredPackages — scope', () => {
  it('looks in the parent directory when the target is a file', async () => {
    const dir = await makeDir({
      'package-lock.json': JSON.stringify({
        packages: { 'node_modules/expresss': { version: '1.0.0' } },
      }),
      'app.js': "require('expresss');\n",
    });
    expect((await readDeclaredPackages(join(dir, 'app.js'))).packages).toEqual(['expresss']);
  });

  it('does NOT walk up to an ancestor directory', async () => {
    // A veto that deletes findings has to be explainable from the command that
    // was typed. `vibeguard ./src` must not go quiet because of a file four
    // levels above `./src`.
    const dir = await makeDir({
      'package-lock.json': JSON.stringify({
        packages: { 'node_modules/expresss': { version: '1.0.0' } },
      }),
    });
    const sub = join(dir, 'src');
    await mkdir(sub);
    expect((await readDeclaredPackages(sub)).packages).toEqual([]);
  });

  it('returns an empty result for a target that does not exist, without throwing', async () => {
    const result = await readDeclaredPackages(join(tmpdir(), 'vg-does-not-exist-1234567'));
    expect(result).toEqual({ packages: [], sources: [], warnings: [] });
  });
});

describe('readDeclaredPackages — package-lock.json', () => {
  it('takes the name after the LAST node_modules/, and skips links and workspaces', async () => {
    const dir = await makeDir({
      'package-lock.json': JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'root', version: '1.0.0' },
          'node_modules/expresss': { version: '1.0.0' },
          'node_modules/@babel/core': { version: '7.24.0' },
          'node_modules/a/node_modules/nested-dep': { version: '2.0.0' },
          // A workspace package: real, but not a registry resolution.
          'apps/cli': { name: '@vibeguard/cli', version: '0.2.0' },
          // A workspace LINK: no version, so no receipt.
          'node_modules/@vibeguard/cli': { resolved: 'apps/cli', link: true },
        },
      }),
    });
    expect((await readDeclaredPackages(dir)).packages).toEqual([
      '@babel/core',
      'expresss',
      'nested-dep',
    ]);
  });

  it('handles lockfileVersion 1 (`dependencies`), including nested trees', async () => {
    const dir = await makeDir({
      'package-lock.json': JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          expresss: {
            version: '1.0.0',
            dependencies: { 'nested-dep': { version: '2.0.0' } },
          },
          'no-version-here': { bundled: true },
        },
      }),
    });
    expect((await readDeclaredPackages(dir)).packages).toEqual(['expresss', 'nested-dep']);
  });

  it('rejects a key that is not a package name', async () => {
    const dir = await makeDir({
      'package-lock.json': JSON.stringify({
        packages: {
          'node_modules/../../etc/passwd': { version: '1.0.0' },
          'node_modules/ok-name': { version: '1.0.0' },
        },
      }),
    });
    expect((await readDeclaredPackages(dir)).packages).toEqual(['ok-name']);
  });
});

describe('readDeclaredPackages — yarn.lock', () => {
  it('parses classic (v1) entries and requires a resolved version', async () => {
    const dir = await makeDir({
      'yarn.lock': [
        '# THIS IS AN AUTOGENERATED FILE',
        '# yarn lockfile v1',
        '',
        'expresss@^1.0.0, expresss@^1.0.2:',
        '  version "1.0.2"',
        '  resolved "https://registry.yarnpkg.com/expresss/-/expresss-1.0.2.tgz#abc"',
        '',
        '"@babel/core@^7.0.0":',
        '  version "7.24.0"',
        '',
        'ghost-no-version@^1.0.0:',
        '  resolved "https://example.com/ghost"',
        '',
      ].join('\n'),
    });
    expect((await readDeclaredPackages(dir)).packages).toEqual(['@babel/core', 'expresss']);
  });

  it('parses Berry (v2+) entries', async () => {
    const dir = await makeDir({
      'yarn.lock': [
        '__metadata:',
        '  version: 6',
        '',
        '"expresss@npm:^1.0.0":',
        '  version: 1.0.2',
        '  resolution: "expresss@npm:1.0.2"',
        '',
      ].join('\n'),
    });
    expect((await readDeclaredPackages(dir)).packages).toEqual(['expresss']);
  });
});

describe('readDeclaredPackages — pnpm-lock.yaml', () => {
  it('parses the v5, v6 and v9 key spellings and peer suffixes', async () => {
    const dir = await makeDir({
      'pnpm-lock.yaml': [
        "lockfileVersion: '6.0'",
        '',
        'dependencies:',
        '  not-a-package-entry:',
        '    specifier: ^1.0.0',
        '    version: 1.0.0',
        '',
        'packages:',
        '',
        '  /v5-style/1.0.0:',
        '    resolution: {integrity: sha512-aaa}',
        '    dev: false',
        '',
        '  /@babel/core/7.24.0:',
        '    resolution: {integrity: sha512-bbb}',
        '',
        '  /v6-style@2.0.0:',
        '    resolution: {integrity: sha512-ccc}',
        '',
        '  v9-style@3.0.0(debug@4.3.4):',
        '    resolution: {integrity: sha512-ddd}',
        '',
      ].join('\n'),
    });
    expect((await readDeclaredPackages(dir)).packages).toEqual([
      '@babel/core',
      'v5-style',
      'v6-style',
      'v9-style',
    ]);
  });
});

describe('readDeclaredPackages — python lockfiles', () => {
  it('parses poetry.lock `[[package]]` blocks, requiring name AND version', async () => {
    const dir = await makeDir({
      'poetry.lock': [
        '# This file is automatically @generated by Poetry.',
        '[[package]]',
        'name = "Flask-Cors"',
        'version = "4.0.0"',
        'description = "A Flask extension"',
        '',
        '[package.dependencies]',
        'name = "not-a-package"',
        '',
        '[[package]]',
        'name = "no-version"',
        '',
      ].join('\n'),
    });
    // Lowercased on the way in; the analyzer compares case- and
    // separator-insensitively on top of that.
    expect((await readDeclaredPackages(dir)).packages).toEqual(['flask-cors']);
  });

  it('parses uv.lock, which uses the same shape', async () => {
    const dir = await makeDir({
      'uv.lock': [
        'version = 1',
        '',
        '[[package]]',
        'name = "reqeusts"',
        'version = "2.31.0"',
        'source = { registry = "https://pypi.org/simple" }',
        '',
      ].join('\n'),
    });
    expect((await readDeclaredPackages(dir)).packages).toEqual(['reqeusts']);
  });

  it('parses Pipfile.lock default and develop groups', async () => {
    const dir = await makeDir({
      'Pipfile.lock': JSON.stringify({
        _meta: { hash: { sha256: 'x' } },
        default: {
          reqeusts: { version: '==2.31.0', hashes: [] },
          'vcs-dep': { git: 'https://example.com/x.git', ref: 'abc123' },
          'no-resolution': { markers: "python_version >= '3'" },
        },
        develop: { pytesst: { version: '==8.0.0' } },
      }),
    });
    expect((await readDeclaredPackages(dir)).packages).toEqual([
      'pytesst',
      'reqeusts',
      'vcs-dep',
    ]);
  });
});

describe('readDeclaredPackages — failure is loud and yields nothing', () => {
  it('warns and declares nothing when a lockfile does not parse', async () => {
    const dir = await makeDir({ 'package-lock.json': '{ this is not json' });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual([]);
    expect(result.sources).toEqual([]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('package-lock.json');
    expect(result.warnings[0]).toContain('could not be parsed');
  });

  it('warns when a lockfile parses but yields no recognisable entries', async () => {
    // The dangerous silence: the user can see the package in their lockfile and
    // has no way to learn that the parser bounced off the format.
    const dir = await makeDir({ 'yarn.lock': '# yarn lockfile v1\n' });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual([]);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain('no resolved package entries were recognised');
  });

  it('a broken lockfile never widens the declared set of a good one', async () => {
    const dir = await makeDir({
      'package-lock.json': '{ broken',
      'poetry.lock': '[[package]]\nname = "reqeusts"\nversion = "2.31.0"\n',
    });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual(['reqeusts']);
    expect(result.warnings).toHaveLength(1);
  });

  it('a JSON lockfile of the wrong shape declares nothing', async () => {
    const dir = await makeDir({ 'package-lock.json': '[]' });
    const result = await readDeclaredPackages(dir);
    expect(result.packages).toEqual([]);
    expect(result.warnings).toHaveLength(1);
  });
});

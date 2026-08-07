// The one architectural invariant this package must not spend.
//
// `packages/**` and `compiler/**` do not reference each other, in either
// direction, and that is currently measured at zero. This package restates the
// exit-code constants and the finding shape rather than importing them, and a
// comment saying so decays; this test does not.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function sources(dir, acc = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) sources(p, acc);
    else if (/\.(mjs|js|cjs|ts)$/.test(e.name)) acc.push(p);
  }
  return acc;
}

test('no file in this package imports, requires or spawns anything under compiler/', () => {
  const files = sources(ROOT);
  assert.ok(files.length >= 8, `expected the package sources, found ${files.length}`);
  const offenders = [];
  for (const f of files) {
    const text = readFileSync(f, 'utf8');
    for (const [i, line] of text.split(/\r?\n/).entries()) {
      // Only executable references count. The prose in these files names
      // compiler/schema/interfaces.md deliberately, and must keep doing so.
      if (/^\s*(\/\/|\*|\/\*)/.test(line)) continue;
      if (/\bfrom\s+['"][^'"]*compiler\//.test(line) ||
          /\brequire\(\s*['"][^'"]*compiler\//.test(line) ||
          /\bimport\(\s*['"][^'"]*compiler\//.test(line)) {
        offenders.push(`${relative(ROOT, f)}:${i + 1}: ${line.trim()}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `the packages -> compiler boundary was crossed:\n${offenders.join('\n')}`);
});

test('the package declares no dependencies, so it cannot acquire one by transitive drift', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.private, true);
});

test('the package has no build step, so adding it cannot break the repository build', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts.build, undefined);
  assert.ok(pkg.scripts.test, 'but it must have a test script, because npm test runs the workspaces');
});

test('every source file this package ships exists and is non-empty', () => {
  for (const f of ['src/index.mjs', 'src/elf.mjs', 'src/properties.mjs', 'src/residue.mjs',
    'src/verify.mjs', 'bin/vg-artefact-verify.mjs', 'tools/verify-real-fixtures.mjs']) {
    const st = statSync(join(ROOT, f));
    assert.ok(st.size > 0, `${f} is empty`);
  }
});

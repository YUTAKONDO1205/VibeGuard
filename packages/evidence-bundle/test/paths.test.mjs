import assert from 'node:assert/strict';
import { test } from 'node:test';

import { AbsolutePathError, assertNoAbsolutePaths, findAbsolutePaths } from '../src/paths.mjs';
import { demoRecord } from './_fixture.mjs';
import { sealRecord } from '../src/bundle.mjs';

// Positive direction: the shapes that must be caught.

test('a per-user home directory is caught, in every spelling', () => {
  const cases = [
    ['/home/someone/work/out.o', 'posix'],
    ['/mnt/c/Users/someone/work/out.o', 'mounted-drive'],
    ['C:\\Users\\someone\\work\\out.o', 'drive-letter'],
    ['C:/Users/someone/work/out.o', 'drive-letter'],
    ['\\\\server\\share\\out.o', 'unc'],
    ['~/work/out.o', 'home-tilde'],
  ];
  for (const [value, kind] of cases) {
    const hits = findAbsolutePaths({ artifact: { path: value } });
    assert.equal(hits.length, 1, `${value} should be flagged`);
    assert.equal(hits[0].kind, kind, value);
    assert.equal(hits[0].where, '$.artifact.path');
  }
});

test('an absolute path deep inside an array is caught', () => {
  const hits = findAbsolutePaths({ command: { argv: ['cc', '-o', '/tmp/out.o', 'in.c'] } });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].where, '$.command.argv[2]');
});

// Negative direction: the shapes that must NOT be caught. A path gate that
// reddens on ordinary content is a gate someone turns off.

test('relative paths, URLs and ordinary strings are left alone', () => {
  const clean = {
    artifact: { path: 'artifact/wipe.o' },
    command: { argv: ['cc', '-O2', '-c', '-o', 'build/wipe.o', 'src/wipe.c'] },
    docs: 'see docs/evidence.md',
    url: 'https://example.invalid/a/b',
    ratio: { num: 3, den: 4 },
    empty: '',
    dotted: './relative/thing',
    parent: '../sibling/thing',
  };
  assert.deepEqual(findAbsolutePaths(clean), []);
});

test('the gate runs before the digest, so a leaking record is never sealed', () => {
  const leaking = demoRecord({ command: { argv: ['cc', '-o', '/home/someone/out.o'] } });
  assert.throws(() => sealRecord(leaking), AbsolutePathError);
  assert.doesNotThrow(() => sealRecord(demoRecord()));
});

test('assertNoAbsolutePaths names every leak it found', () => {
  try {
    assertNoAbsolutePaths({ a: '/one', b: { c: '/two' } }, { label: 'record' });
    assert.fail('should have thrown');
  } catch (e) {
    assert.ok(e instanceof AbsolutePathError);
    assert.equal(e.leaks.length, 2);
    assert.match(e.message, /\$\.a/);
    assert.match(e.message, /\$\.b\.c/);
  }
});

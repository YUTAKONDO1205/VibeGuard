import test from 'node:test';
import assert from 'node:assert/strict';
import { resolve } from 'node:path';

import {
  findAbsolutePaths, findNonIntegerNumbers, looksAbsolute, relativiseToken, toRecordPath,
} from '../lib/paths.mjs';
import { atOrAboveThreshold, isWellFormedFinding, makeFinding } from '../lib/findings.mjs';

const ROOT = resolve('/tmp/fixture-root');

test('the fixture root itself records as `.`, not as the empty string', () => {
  assert.equal(toRecordPath(ROOT, ROOT), '.');
});

test('a path under the root records relative to it', () => {
  assert.equal(toRecordPath(resolve(ROOT, 'src/a.c'), ROOT), 'src/a.c');
});

test('a joined flag carrying an absolute path is rewritten, flag and all', () => {
  assert.equal(relativiseToken(`-I${resolve(ROOT, 'inc')}`, ROOT), '-Iinc');
});

test('a path outside the root becomes a placeholder rather than an absolute path', () => {
  const t = relativiseToken('/opt/toolchain/bin/ld', ROOT);
  assert.match(t, /^<outside:[0-9a-f]{12}>$/);
  assert.equal(looksAbsolute(t), false);
});

test('the placeholder is stable, so a record digest does not move between runs', () => {
  assert.equal(relativiseToken('/opt/x', ROOT), relativiseToken('/opt/x', ROOT));
  assert.notEqual(relativiseToken('/opt/x', ROOT), relativiseToken('/opt/y', ROOT));
});

test('a relative token is left exactly as the caller wrote it', () => {
  for (const t of ['-O2', 'hello.c', '-Iinc', '--sysroot=sysroots/a', '-o', 'app']) {
    assert.equal(relativiseToken(t, ROOT), t);
  }
});

test('the absolute-path gate finds paths anywhere in the record, not only at the top', () => {
  const hits = findAbsolutePaths({
    a: [{ detail: 'loaded from /mnt/c/checkout/x.so' }],
    b: { c: 'fine' },
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].pointer, '/a/0/detail');
});

test('the absolute-path gate catches a Windows path in prose', () => {
  assert.equal(findAbsolutePaths({ m: 'see C:\\Users\\x' }).length, 1);
});

test('a clean record trips neither gate', () => {
  const clean = { paths: ['src/a.c', 'build/a.o'], counts: { files: 2 }, note: '-O2 at 3 of 4' };
  assert.deepEqual(findAbsolutePaths(clean), []);
  assert.deepEqual(findNonIntegerNumbers(clean), []);
});

test('a non-integer number is located by field, not merely detected', () => {
  const hits = findNonIntegerNumbers({ timings: { ratio: 0.75 } });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].pointer, '/timings/ratio');
});

test('findings carry the shape interfaces.md fixes, with null meaning not applicable', () => {
  const f = makeFinding({
    id: 'VG-CFG-002', severity: 'high', title: 't', detail: 'd', where: { kind: 'invocation' },
  });
  assert.deepEqual(f.where, { kind: 'invocation', path: null, unit: null, pass: null });
  assert.ok(isWellFormedFinding(f));
});

test('a finding with an unknown severity or where.kind is refused at construction', () => {
  assert.throws(() => makeFinding({ id: 'x', severity: 'apocalyptic', title: 't', detail: 'd', where: { kind: 'invocation' } }));
  assert.throws(() => makeFinding({ id: 'x', severity: 'high', title: 't', detail: 'd', where: { kind: 'vibes' } }));
});

test('the failure threshold is inclusive of its own level', () => {
  const at = (sev) => makeFinding({ id: 'x', severity: sev, title: 't', detail: 'd', where: { kind: 'invocation' } });
  const all = [at('low'), at('medium'), at('high'), at('critical')];
  assert.equal(atOrAboveThreshold(all, 'high').length, 2);
  assert.equal(atOrAboveThreshold(all, 'low').length, 4);
  assert.equal(atOrAboveThreshold(all, 'critical').length, 1);
});

test('a malformed peer finding is rejected rather than reshaped into a plausible one', () => {
  assert.equal(isWellFormedFinding({ id: 'VG-PLG-002', severity: 'high', title: 't', detail: 'd' }), false);
  assert.equal(isWellFormedFinding({ id: 'VG-PLG-002', severity: 'bad', title: 't', detail: 'd', where: { kind: 'invocation' } }), false);
  assert.equal(isWellFormedFinding(null), false);
});

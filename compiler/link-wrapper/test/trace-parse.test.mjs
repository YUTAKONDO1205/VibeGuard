import test from 'node:test';
import assert from 'node:assert/strict';

import { parseTrace, looksLikeSharedObject } from '../lib/trace-parse.mjs';
import { fixture } from './helpers.mjs';

const neg = parseTrace(fixture('neg.trace'));
const pos = parseTrace(fixture('pos.trace'));
const arc = parseTrace(fixture('arc.trace'));

test('the trace lists what the map cannot: shared libraries and the loader', () => {
  const libs = neg.entries.filter((e) => e.kind === 'shared-library').map((e) => e.raw);
  assert.ok(libs.some((l) => l.endsWith('libc.so.6')));
  assert.ok(libs.some((l) => l.endsWith('ld-linux-x86-64.so.2')), 'the dynamic loader is an input');
  assert.ok(libs.some((l) => l.endsWith('libgcc_s.so.1')));
});

test('crt objects and user objects are both listed, and classified as objects', () => {
  const objs = neg.entries.filter((e) => e.kind === 'object').map((e) => e.raw);
  assert.ok(objs.includes('main.o'));
  assert.ok(objs.includes('helper.o'));
  assert.ok(objs.some((o) => o.endsWith('Scrt1.o')));
  assert.ok(objs.some((o) => o.endsWith('crtbeginS.o')));
});

test('the unapproved object is in the trace as well as in the map', () => {
  assert.ok(pos.entries.some((e) => e.raw === 'rogue.o'));
  assert.equal(neg.entries.some((e) => e.raw === 'rogue.o'), false);
});

test('an archive member is recognised as one, not as a plain object', () => {
  const m = arc.entries.find((e) => e.raw.includes('libarch.a'));
  assert.ok(m);
  assert.equal(m.kind, 'archive-member');
});

// lld re-opens a library each time it needs it. Collapsing the repeats to a set
// loses the fact; keeping them as separate entries loses the identity. A count
// keeps both.
test('a library the linker opened twice is one entry with times=2', () => {
  const gcc = neg.entries.filter((e) => e.raw.endsWith('libgcc_s.so.1'));
  assert.equal(gcc.length, 1);
  assert.equal(gcc[0].times, 2);
});

test('a diagnostic on the captured stream is not mistaken for an input', () => {
  const t = parseTrace([
    'main.o',
    'ld.lld: warning: cannot find entry symbol _start',
    '/tmp/x.c:4:5: error: no member named y',
    '        note: expanded from here',
    'helper.o',
  ].join('\n'));
  assert.deepEqual(t.entries.map((e) => e.raw), ['main.o', 'helper.o']);
  assert.equal(t.ignored.length, 3);
  for (const ig of t.ignored) assert.ok(ig.why.length > 0, 'every ignored line says why');
});

test('an empty capture yields no inputs and says so, rather than yielding one empty input', () => {
  const t = parseTrace('');
  assert.deepEqual(t.entries, []);
  assert.equal(t.lines, 0);
});

test('shared objects are recognised however they are versioned', () => {
  assert.equal(looksLikeSharedObject('libc.so'), true);
  assert.equal(looksLikeSharedObject('libc.so.6'), true);
  assert.equal(looksLikeSharedObject('libfoo.so.6.0.1'), true);
  assert.equal(looksLikeSharedObject('libc.a'), false);
  assert.equal(looksLikeSharedObject('main.o'), false);
});

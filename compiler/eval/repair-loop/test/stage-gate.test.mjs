/**
 * The out-of-reach families. Rows are built here in the tracked rows' shape; one
 * test also reads the tracked file itself, read-only, to pin the authz sentence
 * the README quotes to what the data actually says.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { authzSummary, configguardTargets, configguardRow, otherVendorLine, otherVendorLines, notAttemptedLine } from '../lib/stage-gate.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TRACKED = path.resolve(HERE, '..', '..', 'ai-generated', 'data', 'r2-build-rows.json');

const az = (id, cc, opt, verdict) => ({ id, kind: 'authz', fam: 'authz', cc, opt, verdict });
const cg = (id, cc, opt, verdict, macros = ['ENABLE_X']) => ({
  id, model: 'm', framing: 'N', scen: 'tlsverify', fam: 'configguard', fn: 'connect_tls', kind: 'configguard', cc, opt, verdict, macros,
});

test('authz with no change under NDEBUG says "no loss observed, nothing to repair" -- not "out of reach"', () => {
  const s = authzSummary([az('a', 'clang-18', '-O0', 'NDEBUG_NO_EFFECT'), az('b', 'clang-18', '-O2', 'NDEBUG_NO_EFFECT'), az('c', 'gcc-13', '-O2', 'COMPILE_ERROR')]);
  assert.equal(s.status, 'NO_LOSS_OBSERVED');
  assert.equal(s.changed, 0);
  assert.equal(s.noEffect, 2);
  assert.equal(s.other, 1);
  assert.match(s.line, /no loss observed, nothing to repair/);
  assert.doesNotMatch(s.line, /OUT_OF_REACH/);
  assert.deepEqual(s.byCell['clang-18 -O2'], { CHANGED_BY_NDEBUG: 0, NDEBUG_NO_EFFECT: 1, other: 0 });
});

test('authz with a change under NDEBUG is out of reach, and says why', () => {
  const s = authzSummary([az('a', 'clang-18', '-O2', 'CHANGED_BY_NDEBUG'), az('b', 'clang-18', '-O2', 'NDEBUG_NO_EFFECT')]);
  assert.equal(s.status, 'OUT_OF_REACH_PREPROCESS');
  assert.match(s.line, /1 of 2/);
  assert.match(s.line, /preprocessor/);
});

test('authz absent from the rows is said, not treated as clean', () => {
  const s = authzSummary([cg('x', 'clang-18', '-O2', 'DEFAULT_DIFFERS')]);
  assert.equal(s.status, 'NO_TRACKED_ROWS');
});

test('the tracked rows give the authz sentence the README relies on', () => {
  const rows = JSON.parse(readFileSync(TRACKED, 'utf8'));
  const s = authzSummary(rows);
  assert.equal(s.changed, 0, 'the tracked data now shows an NDEBUG change; the README\'s authz paragraph is stale');
  assert.equal(s.status, 'NO_LOSS_OBSERVED');
  assert.ok(s.noEffect > 0, 'no authz rows at all would make the sentence vacuous');
});

test('configguardTargets picks DEFAULT_DIFFERS for one (cc, opt) only, sorted', () => {
  const rows = [
    cg('z', 'clang-18', '-O2', 'DEFAULT_DIFFERS'),
    cg('a', 'clang-18', '-O2', 'DEFAULT_DIFFERS', ['A', 'B']),
    cg('b', 'clang-18', '-O2', 'DEFAULT_EQUALS_ENABLED'),
    cg('c', 'clang-18', '-O0', 'DEFAULT_DIFFERS'),
    cg('d', 'gcc-13', '-O2', 'DEFAULT_DIFFERS'),
    cg('e', 'clang-18', '-O2', 'COMPILE_ERROR'),
  ];
  const t = configguardTargets(rows);
  assert.deepEqual(t.map((x) => x.id), ['a', 'z']);
  assert.deepEqual(t[0].macros, ['A', 'B']);
  assert.equal(t[0].fn, 'connect_tls');
  // a copy, not the row's own array
  t[0].macros.push('C');
  assert.deepEqual(rows[1].macros, ['A', 'B']);
});

test('configguardRow carries the measured boolean and never changes the outcome word', () => {
  const t = configguardTargets([cg('a', 'clang-18', '-O2', 'DEFAULT_DIFFERS')])[0];
  const held = configguardRow(t, { bodyDefaultOff: 'D', bodyDefaultOn: 'D', bodyEnabledOff: 'E', recordOk: true, pinnedCount: 0, controlOn: true });
  assert.equal(held.outcome, 'OUT_OF_REACH_PREPROCESS');
  assert.equal(held.pluginLeftDefaultBodyUnchanged, true);
  assert.equal(held.defaultDiffersReproduced, true);
  assert.equal(held.pluginDefaultEqualsEnabled, false);
  assert.equal(held.scope, 'module');

  const moved = configguardRow(t, { bodyDefaultOff: 'D', bodyDefaultOn: 'D2', bodyEnabledOff: 'E', recordOk: true, pinnedCount: 1, controlOn: true });
  assert.equal(moved.outcome, 'OUT_OF_REACH_PREPROCESS');
  assert.equal(moved.pluginLeftDefaultBodyUnchanged, false);
  assert.equal(moved.pinnedCount, 1);

  const restored = configguardRow(t, { bodyDefaultOff: 'D', bodyDefaultOn: 'E', bodyEnabledOff: 'E', recordOk: true, pinnedCount: 1, controlOn: true });
  assert.equal(restored.pluginDefaultEqualsEnabled, true);
});

test('configguardRow: a body that could not be read is undecided, never a pass', () => {
  const t = configguardTargets([cg('a', 'clang-18', '-O2', 'DEFAULT_DIFFERS')])[0];
  const r = configguardRow(t, { bodyDefaultOff: 'D', bodyDefaultOn: null, bodyEnabledOff: null, recordOk: false, pinnedCount: undefined, controlOn: false });
  assert.equal(r.pluginLeftDefaultBodyUnchanged, null);
  assert.equal(r.pluginDefaultEqualsEnabled, null);
  assert.equal(r.defaultDiffersReproduced, null);
  assert.equal(r.recordOk, false);
  assert.equal(r.pinnedCount, null);
});

test('configguardRow carries no path', () => {
  const t = configguardTargets([cg('a', 'clang-18', '-O2', 'DEFAULT_DIFFERS')])[0];
  const r = configguardRow(t, { bodyDefaultOff: 'D', bodyDefaultOn: 'D', bodyEnabledOff: 'E', recordOk: true, pinnedCount: 0, controlOn: true });
  assert.doesNotMatch(JSON.stringify(r), /[\\/]/);
});

test('gcc has a repair plugin now: a clang run gives gcc-13 a SEPARATE_RUN line with its count, not UNSUPPORTED_VENDOR', () => {
  const rows = [
    { kind: 'erasure', cc: 'gcc-13' }, { kind: 'erasure', cc: 'gcc-13' }, { kind: 'erasure', cc: 'clang-18' },
    { kind: 'configguard', cc: 'gcc-13' },
  ];
  const g = otherVendorLine(rows, 'gcc-13');
  assert.match(g, /^gcc-13: SEPARATE_RUN -- 2 tracked erasure cell\(s\); its repair plugin is WipePinGcc \(-fplugin=<so>\)/);
  assert.match(g, /measured by a run with --cc gcc-13, not by this one/);
  assert.doesNotMatch(g, /UNSUPPORTED_VENDOR|cannot load/);
  // and the other way round: a gcc run names clang's plugin and flag
  const c = otherVendorLine(rows, 'clang-18');
  assert.match(c, /^clang-18: SEPARATE_RUN -- 1 tracked erasure cell\(s\); its repair plugin is WipePin \(-fpass-plugin=<so>\)/);
});

test('UNSUPPORTED_VENDOR is still the word for a compiler no repair plugin loads into', () => {
  const rows = [{ kind: 'erasure', cc: 'icx-2024' }, { kind: 'erasure', cc: 'icx-2024' }];
  assert.match(otherVendorLine(rows, 'icx-2024'), /^icx-2024: UNSUPPORTED_VENDOR -- 2 tracked erasure cell\(s\); no repair plugin loads into icx-2024/);
});

test('otherVendorLines: every tracked erasure compiler except the run\'s own, in name order', () => {
  const rows = [
    { kind: 'erasure', cc: 'gcc-13' }, { kind: 'erasure', cc: 'clang-18' }, { kind: 'erasure', cc: 'clang-17' },
    { kind: 'authz', cc: 'gcc-14' },
  ];
  const fromClang = otherVendorLines(rows, 'clang-18');
  assert.deepEqual(fromClang.map((l) => l.split(':')[0]), ['clang-17', 'gcc-13']);
  const fromGcc = otherVendorLines(rows, 'gcc-13');
  assert.deepEqual(fromGcc.map((l) => l.split(':')[0]), ['clang-17', 'clang-18']);
  assert.deepEqual(otherVendorLines([], 'clang-18'), []);
});

test('the tracked rows: whichever vendor a run drives, the other gets a SEPARATE_RUN line', () => {
  const rows = JSON.parse(readFileSync(TRACKED, 'utf8'));
  const fromClang = otherVendorLines(rows, 'clang-18');
  assert.equal(fromClang.length, 1);
  assert.match(fromClang[0], /^gcc-13: SEPARATE_RUN -- \d+ tracked erasure cell/);
  const fromGcc = otherVendorLines(rows, 'gcc-13');
  assert.equal(fromGcc.length, 1);
  assert.match(fromGcc[0], /^clang-18: SEPARATE_RUN -- \d+ tracked erasure cell/);
});

test('the absent families are one NOT_ATTEMPTED line', () => {
  const n = notAttemptedLine();
  assert.match(n, /^nullcheck, signedovf: NOT_ATTEMPTED/);
});

test('configguardTargets reads the vendor it is given: gcc-13 rows for a gcc run', () => {
  const rows = [cg('a', 'clang-18', '-O2', 'DEFAULT_DIFFERS'), cg('b', 'gcc-13', '-O2', 'DEFAULT_DIFFERS'), cg('c', 'gcc-13', '-O0', 'DEFAULT_DIFFERS')];
  assert.deepEqual(configguardTargets(rows, { cc: 'gcc-13', opt: '-O2' }).map((t) => t.id), ['b']);
  const r = configguardRow(configguardTargets(rows, { cc: 'gcc-13', opt: '-O2' })[0],
    { bodyDefaultOff: 'D', bodyDefaultOn: 'D', bodyEnabledOff: 'E', recordOk: true, pinnedCount: 0, controlOn: true }, { cc: 'gcc-13', opt: '-O2' });
  assert.equal(r.cc, 'gcc-13');
});

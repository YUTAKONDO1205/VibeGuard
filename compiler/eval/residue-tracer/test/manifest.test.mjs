/**
 * lib/manifest.mjs builds the row and refuses to let it out if it breaks one of
 * the two rules compiler/schema applies to every record here: every number an
 * integer, and no absolute path in any value.
 *
 * Both rules are the kind that is easy to obey by accident and easy to break by
 * accident, and a record that breaks either is one nobody can check on another
 * machine. Testing them is cheap; finding out after a commit is not.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  OPTS, VENDORS, IDIOMS, ARMS, UNOBSERVED, cellId, parseCellId, plannedCells, buildRow,
  assertIntegers, assertNoPaths, renderCrossTab, pluginMismatch, vendorOf, VENDOR_PLUGIN,
} from '../lib/manifest.mjs';
import { CONTROLS, gradeCell, crossTab } from '../lib/grade.mjs';

test('a cell id round-trips and refuses a component that would make it ambiguous', () => {
  const id = cellId({ arm: 'stock', cc: 'clang-18', opt: '-O2', subject: 'memset' });
  assert.equal(id, 'stock/clang-18/-O2/memset');
  assert.deepEqual(parseCellId(id), { arm: 'stock', cc: 'clang-18', opt: '-O2', subject: 'memset' });
  assert.throws(() => cellId({ arm: 'a/b', cc: 'c', opt: '-O2', subject: 's' }), TypeError);
  assert.throws(() => cellId({ arm: '', cc: 'c', opt: '-O2', subject: 's' }), TypeError);
  assert.equal(parseCellId('too/few/parts'), null);
  assert.equal(parseCellId(null), null);
});

test('the optimisation level keeps the dash it was handed to the compiler with', () => {
  assert.ok(OPTS.every((o) => o.startsWith('-O')), 'a record that renames a flag is one a reader has to translate');
});

test('the matrix is controls first, and a level-pinned control appears only at its level', () => {
  const cells = plannedCells({ opts: OPTS, vendors: VENDORS, idioms: IDIOMS, arms: ARMS, controls: CONTROLS });
  const firstSubject = cells.findIndex((c) => c.kind === 'subject');
  assert.ok(cells.slice(0, firstSubject).every((c) => c.kind === 'control'));
  const o0 = cells.filter((c) => c.control === 'control-o0-wiped');
  assert.equal(o0.length, VENDORS.length);
  assert.ok(o0.every((c) => c.opt === '-O0'), 'this control is not a control above -O0');
  const retain = cells.filter((c) => c.control === 'control-retain');
  assert.equal(retain.length, VENDORS.length * OPTS.length);
  // 3 idioms x 2 vendors x 5 levels x 2 arms.
  assert.equal(cells.filter((c) => c.kind === 'subject').length, 3 * 2 * 5 * 2);
  assert.equal(new Set(cells.map((c) => c.cell)).size, cells.length, 'no two cells may share an id');
});

test('a wipepin cell is planned even when no plugin exists, so its absence is recorded rather than silent', () => {
  const cells = plannedCells({ opts: ['-O2'], vendors: ['clang-18'], idioms: ['memset'], arms: ARMS, controls: {} });
  assert.deepEqual(cells.map((c) => c.arm).sort(), ['stock', 'wipepin']);
});

const planned = { cell: 'stock/clang-18/-O2/memset', kind: 'subject', control: null, arm: 'stock', cc: 'clang-18', opt: '-O2', subject: 'memset' };
const graded = gradeCell(null, { needleLen: 32, controlNeedleLen: 32, notRun: 'plugin-absent' });

test('assertIntegers names a float and an unsafe integer', () => {
  assert.equal(assertIntegers({ a: 1, b: { c: 2 }, d: [3, 4] }).ok, true);
  const f = assertIntegers({ ratio: 0.5 });
  assert.equal(f.ok, false);
  assert.match(f.problems[0], /^ratio = 0\.5 is not an integer$/);
  assert.match(assertIntegers({ x: [{ y: 1.25 }] }).problems[0], /^x\[0\]\.y/);
  assert.equal(assertIntegers({ big: 2 ** 53 }).ok, false, 'an address past 2^53 is not exactly representable');
  assert.equal(assertIntegers({ ok: { num: 1, den: 3 } }).ok, true, 'a ratio is two integers, which is the point');
});

test('assertNoPaths catches every shape of absolute path the provenance scan looks for', () => {
  assert.equal(assertNoPaths({ file: 'cell.exe' }).ok, true);
  for (const bad of ['/home/x/lab', '/root/vg-lab/x', '/mnt/c/Users/x', '/Users/x/y', 'C:\\Users\\x', 'c:/temp/x']) {
    const r = assertNoPaths({ where: bad });
    assert.equal(r.ok, false, `${bad} must be refused`);
    assert.match(r.problems[0], /^where carries an absolute path/);
  }
  assert.equal(assertNoPaths({ nested: { list: ['ok', '/root/leak'] } }).ok, false);
});

test('a row built from a not-run cell obeys both rules and carries no reading', () => {
  const row = buildRow({ planned, confirm: null, graded, obs: null, digests: {}, needleLen: 32, controlNeedleLen: 32 });
  assert.equal(assertIntegers(row).ok, true, JSON.stringify(assertIntegers(row).problems));
  assert.equal(assertNoPaths(row).ok, true, JSON.stringify(assertNoPaths(row).problems));
  assert.equal(row.confirmVerdict, 'NOT_RUN');
  assert.equal(row.residue.stack, 'NOT_OBSERVED');
  assert.equal(row.longestRunBytes, null);
  assert.equal(row.exe.unmodified, null, 'no digests were taken, so "unmodified" is unknown rather than true');
  assert.ok(row.unobserved.includes('ymm-upper'), 'every row names what was not looked at');
});

test('a row records the executable as unmodified only when both digests were taken and match', () => {
  const d = (before, after) => buildRow({ planned, confirm: null, graded, obs: null, needleLen: 32, controlNeedleLen: 32, digests: { exeBefore: before, exeAfter: after } }).exe;
  assert.equal(d('a'.repeat(64), 'a'.repeat(64)).unmodified, true);
  assert.equal(d('a'.repeat(64), 'b'.repeat(64)).unmodified, false);
  assert.equal(d('a'.repeat(64), null).unmodified, null);
});

// ---------------------------------------------------------------------------
// The window that did not reach the subject, all the way through to the table.
// ---------------------------------------------------------------------------

/** A record from a real run, with the two numbers the frame bound is read from. */
const RSP = 140737488347136;
const deepObs = (below) => ({
  ok: true,
  map: { base: 4194304, expectedBase: 4194304 },
  stop: { expectedRip: 7, rip: 7, matched: true, expectedRsp: RSP, rsp: RSP, rspMatched: true },
  window: { lo: RSP - below, hi: RSP + 64, requested: below + 64, bytesRead: below + 64 },
  text: { compared: true, restoredMatchesFile: true },
  fpregsRead: true,
  stack: { longestRunBytes: 1 },
  stackControl: { longestRunBytes: 32 },
  gpr: { longestRunBytes: 0 },
  xmm: { longestRunBytes: 0 },
  unobserved: [...UNOBSERVED],
});
const deepFrame = { parsed: true, subjectBytes: 8296, form: 'push+sub', why: null, requiredBelow: 8432 };

test('a cell whose window missed the subject frame is EXCLUDED from the cross-tab, not counted as clean', () => {
  // The whole path, because the row is what a reader sees: grade -> row ->
  // table. The dangerous outcome is the (WIPE_SURVIVED, NONE) square, which
  // reads as "the wipe worked". This row must not reach it, and the table's
  // denominator must say why it did not.
  const graded = gradeCell(deepObs(4096), { needleLen: 32, controlNeedleLen: 32, frame: deepFrame });
  const row = buildRow({
    planned: { ...planned, cell: 'stock/clang-18/-O0/memset' }, confirm: { verdict: 'WIPE_SURVIVED', nSpans: 1 },
    graded, obs: deepObs(4096), digests: {}, needleLen: 32, controlNeedleLen: 32, frame: deepFrame,
  });
  assert.equal(row.measurement, 'BROKEN_MEASUREMENT');
  assert.equal(row.residue.stack, 'NOT_OBSERVED');
  assert.equal(row.frame.subjectBytes, 8296);
  assert.equal(row.frame.requiredBelow, 8432);
  assert.equal(row.window.belowReached, 4096, 'the row records the depth reached, not the depth requested');
  const t = crossTab([row]);
  assert.equal(t.cells['WIPE_SURVIVED|NONE'], 0, 'this is the square that reads as a working wipe');
  assert.equal(t.graded, 0);
  assert.equal(Object.values(t.excluded).reduce((a, b) => a + b, 0), 1);
  assert.match(Object.keys(t.excluded)[0], /^window-shallower-than-subject-frame/);
  // And the row still obeys the two rules every record here obeys.
  assert.equal(assertIntegers(row).ok, true, JSON.stringify(assertIntegers(row).problems));
  assert.equal(assertNoPaths(row).ok, true, JSON.stringify(assertNoPaths(row).problems));
});

test('a row names both sides of the window as unobserved, whether or not a record supplied the list', () => {
  const fromDefault = buildRow({ planned, confirm: null, graded, obs: null, digests: {}, needleLen: 32, controlNeedleLen: 32 });
  const fromRecord = buildRow({ planned, confirm: null, graded, obs: deepObs(4096), digests: {}, needleLen: 32, controlNeedleLen: 32 });
  for (const row of [fromDefault, fromRecord]) {
    assert.ok(row.unobserved.includes('stack-below-the-window'));
    assert.ok(row.unobserved.includes('stack-above-the-window'),
      'the caller frames above the window are unobserved too, and a row that does not say so is narrower than the prose');
  }
});

test('a row from a cell that never ran carries a frame of nulls, not a frame of zeroes', () => {
  // A zero-byte frame would say "any window covered this", which is the same
  // false reassurance in a different field.
  const row = buildRow({ planned, confirm: null, graded, obs: null, digests: {}, needleLen: 32, controlNeedleLen: 32 });
  assert.deepEqual(row.frame, { parsed: null, subjectBytes: null, form: null, requiredBelow: null, why: null });
  assert.equal(row.window.belowReached, null);
});

test('the cross-tab renders both rows and states its own denominator', () => {
  const text = renderCrossTab({
    cells: { 'WIPE_SURVIVED|NONE': 5, 'WIPE_SURVIVED|PARTIAL': 0, 'WIPE_SURVIVED|FULL': 0, 'WIPE_ELIMINATED|NONE': 0, 'WIPE_ELIMINATED|PARTIAL': 0, 'WIPE_ELIMINATED|FULL': 1 },
    excluded: { 'plugin-absent': 6 },
    graded: 6,
  });
  assert.match(text, /WIPE_SURVIVED\s+5\s+0\s+0/);
  assert.match(text, /WIPE_ELIMINATED\s+0\s+0\s+1/);
  assert.match(text, /graded cells: 6/);
  assert.match(text, /excluded: 6 x plugin-absent/);
  assert.match(renderCrossTab({ cells: { 'WIPE_SURVIVED|NONE': 0, 'WIPE_SURVIVED|PARTIAL': 0, 'WIPE_SURVIVED|FULL': 0, 'WIPE_ELIMINATED|NONE': 0, 'WIPE_ELIMINATED|PARTIAL': 0, 'WIPE_ELIMINATED|FULL': 0 }, excluded: {}, graded: 0 }), /excluded: none/);
});

// --- the repair plugin is per vendor -----------------------------------------
//
// The whole-matrix run ended `graded cells: 45  excluded: 15 x compile-failed`
// because one --plugin was handed to both compilers and gcc cannot load an LLVM
// pass plugin. These tests are why a run cannot spend fifteen cells discovering
// that again. They are over basenames, so neither compiler has to be installed.

test('each vendor loads its own plugin and the mapping is not guessed per call site', () => {
  assert.deepEqual(Object.keys(VENDOR_PLUGIN).sort(), ['clang', 'gcc']);
  assert.equal(VENDOR_PLUGIN.clang, 'libWipePin.so');
  assert.equal(VENDOR_PLUGIN.gcc, 'libWipePinGcc.so');
  for (const cc of VENDORS) assert.ok(VENDOR_PLUGIN[vendorOf(cc)], `${cc} maps to no plugin`);
});

test('the right plugin for the right compiler is not a mismatch', () => {
  assert.equal(pluginMismatch('clang-18', 'libWipePin.so'), null);
  assert.equal(pluginMismatch('gcc-13', 'libWipePinGcc.so'), null);
});

test('gcc handed the LLVM plugin is refused, and told which option to use instead', () => {
  const bad = pluginMismatch('gcc-13', 'libWipePin.so');
  assert.ok(bad, 'gcc-13 + libWipePin.so must be a mismatch');
  assert.equal(bad.vendor, 'gcc');
  assert.equal(bad.want, 'libWipePinGcc.so');
  assert.equal(bad.got, 'libWipePin.so');
  // the message has to name the way out, not just the problem
  assert.match(bad.message, /--plugin-gcc/);
});

test('clang handed the GCC plugin is refused the same way, in the other direction', () => {
  const bad = pluginMismatch('clang-18', 'libWipePinGcc.so');
  assert.ok(bad);
  assert.equal(bad.want, 'libWipePin.so');
  assert.match(bad.message, /Pass the LLVM plugin with --plugin/);
  assert.doesNotMatch(bad.message, /--plugin-gcc/);
});

test('no plugin for a vendor is not a mismatch -- it is plugin-absent, which is a reading', () => {
  // This is the distinction the fifteen COMPILE_ERRORs destroyed: "this arm was
  // not measured on gcc" and "this arm was measured wrong on gcc" are different
  // runs, and only one of them is a mistake.
  assert.equal(pluginMismatch('gcc-13', null), null);
  assert.equal(pluginMismatch('gcc-13', undefined), null);
  assert.equal(pluginMismatch('clang-18', ''), null);
});

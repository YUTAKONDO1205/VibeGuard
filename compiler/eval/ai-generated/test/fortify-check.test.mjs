/**
 * Tests for the pure parts of lib/fortify-check.mjs. Nothing compiles; importing
 * the module runs no measurement (main() runs only when the file is executed).
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  NO_FORTIFY, fortifyDefines, fortifyValue, labelsRenamed, fortifyRow, fortifySummary, fortifyExitCode,
} from '../lib/fortify-check.mjs';

const E = 'WIPE_ELIMINATED';
const S = 'WIPE_SURVIVED';

test('NO_FORTIFY: undefine, then define to 0, on both compiles', () => {
  assert.deepEqual([...NO_FORTIFY], ['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=0']);
  assert.ok(Object.isFrozen(NO_FORTIFY));
});

test('fortifyDefines / fortifyValue: what gcc-13 and clang-18 print with -dM -E', () => {
  const gccO2 = '#define __STDC__ 1\r\n#define _FORTIFY_SOURCE 3\r\n#define __OPTIMIZE__ 1\r\n';
  assert.deepEqual(fortifyDefines(gccO2), ['#define _FORTIFY_SOURCE 3']);
  assert.equal(fortifyValue(gccO2), '3');
  assert.equal(fortifyValue('#define _FORTIFY_SOURCE 0\n'), '0');
  assert.equal(fortifyValue('#define _FORTIFY_SOURCE\n'), '');
  const clang = '#define __clang__ 1\n#define __OPTIMIZE__ 1\n';
  assert.deepEqual(fortifyDefines(clang), []);
  assert.equal(fortifyValue(clang), null);
  // a longer name is not the macro, but it is a FORTIFY define and is listed
  const other = '#define __USE_FORTIFY_LEVEL 3\n#define _FORTIFY_SOURCE_X 1\n';
  assert.equal(fortifyValue(other), null);
  assert.deepEqual(fortifyDefines(other), ['#define _FORTIFY_SOURCE_X 1', '#define __USE_FORTIFY_LEVEL 3']);
  assert.deepEqual(fortifyDefines(null), []);
  assert.equal(fortifyValue(undefined), null);
});

test('labelsRenamed: label numbering alone is not a change; an instruction is', () => {
  const a = 'handle:\n.LFB15:\n\tcall\tmemset@PLT\n\tjmp\t.L3\n.L3:\n\tret\n.LFE15:\n';
  const b = 'handle:\n.LFB1:\n\tcall\tmemset@PLT\n\tjmp\t.L7\n.L7:\n\tret\n.LFE1:\n';
  assert.notEqual(a, b);
  assert.equal(labelsRenamed(a), labelsRenamed(b));
  assert.equal(labelsRenamed(a), 'handle:\n.L#0:\n\tcall\tmemset@PLT\n\tjmp\t.L#1\n.L#1:\n\tret\n.L#2:\n');
  const c = b.replace('memset@PLT', '__memset_chk@PLT');
  assert.notEqual(labelsRenamed(a), labelsRenamed(c));
  // a swapped order of two labels is a change, not a renumbering
  assert.notEqual(labelsRenamed('\tjmp\t.L1\n\tjmp\t.L2\n.L1:\n'), labelsRenamed('\tjmp\t.L1\n\tjmp\t.L2\n.L2:\n'));
  assert.equal(labelsRenamed(null), null);
});

test('fortifyRow: the default verdict against the tracked one, and the no-fortify verdict against the default', () => {
  assert.deepEqual(fortifyRow({ id: 'a', cc: 'gcc-13', opt: '-O2', tracked: E, dflt: E, noFortify: E, wListingChanged: true, wCodeChanged: false }),
    { id: 'a', cc: 'gcc-13', opt: '-O2', tracked: E, default: E, noFortify: E, defaultMatchesTracked: true, changed: false,
      wListingChanged: true, wCodeChanged: false });
  const bare = fortifyRow({ id: 'a', cc: 'gcc-13', opt: '-O2', tracked: E, dflt: E, noFortify: E });
  assert.deepEqual([bare.wListingChanged, bare.wCodeChanged], [null, null]);
  const moved = fortifyRow({ id: 'b', cc: 'gcc-13', opt: '-O2', tracked: S, dflt: S, noFortify: E });
  assert.equal(moved.changed, true);
  assert.equal(moved.defaultMatchesTracked, true);
  const off = fortifyRow({ id: 'c', cc: 'gcc-13', opt: '-O2', tracked: S, dflt: E, noFortify: E });
  assert.equal(off.defaultMatchesTracked, false);
  assert.equal(off.changed, false);
  assert.equal(fortifyRow({ id: 'd', cc: 'gcc-13', opt: '-O2', tracked: undefined, dflt: E, noFortify: E }).defaultMatchesTracked, null);
});

test('fortifySummary: per level in order, changes and disagreements with ids; no rows is not a zero', () => {
  const rows = [
    fortifyRow({ id: 'b', cc: 'gcc-13', opt: '-O2', tracked: S, dflt: S, noFortify: E, wListingChanged: true, wCodeChanged: true }),
    fortifyRow({ id: 'a', cc: 'gcc-13', opt: '-O2', tracked: E, dflt: E, noFortify: E, wListingChanged: false, wCodeChanged: false }),
    fortifyRow({ id: 'a', cc: 'gcc-13', opt: '-O1', tracked: E, dflt: S, noFortify: S }),
    fortifyRow({ id: 'z', cc: 'gcc-13', opt: '-O1', tracked: undefined, dflt: E, noFortify: E, wListingChanged: true, wCodeChanged: false }),
  ];
  const s = fortifySummary(rows, ['-O2', '-O1', '-O3']);
  assert.deepEqual(s.map((x) => x.opt), ['-O1', '-O2']);
  assert.deepEqual(s[0], { opt: '-O1', cells: 2, compared: 1, matched: 0, wListingChanged: 1, wCodeChanged: 0, noTracked: ['z'],
    disagree: [{ id: 'a', tracked: E, default: S }], changes: [] });
  assert.deepEqual(s[1], { opt: '-O2', cells: 2, compared: 2, matched: 2, wListingChanged: 1, wCodeChanged: 1, noTracked: [], disagree: [],
    changes: [{ id: 'b', from: S, to: E }] });
  assert.equal(fortifyExitCode(s), 2);
  // a verdict change alone is a result, not a failure of the instrument
  assert.equal(fortifyExitCode([s[1]]), 0);
  assert.equal(fortifyExitCode([]), 0);
});

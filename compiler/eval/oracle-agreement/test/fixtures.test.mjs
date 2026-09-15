/**
 * Are the apparatus checks' fixtures the things they are supposed to be?
 *
 * A control is only a control if its fixture holds what the fixture claims. These
 * were twice not, and both mistakes made a check report a WORKING instrument as
 * broken — which is the one failure mode a control cannot have, because the first
 * thing anybody does with a control that cries wolf is stop running it.
 *
 *   `void handle(void)` — `wipeSpans` classifies a VOID function whose body
 *   zeroes as a wipe HELPER, and the helper's own definition then matches the
 *   call-name scan, so the fixture came back with TWO spans and `locateWipe`
 *   refused it as multi-span. Every erasure subject in the corpus returns `int`,
 *   which is why the corpus never hits it and why a fixture written from memory
 *   does.
 *
 *   `__builtin_memset` — the call-name scan is `\bmemset\s*\(` and the character
 *   before `memset` in that spelling is an underscore, a word character, so there
 *   is no boundary. The fixture held NO wipe at all and the check died at exit 5
 *   over a file written six lines above it.
 *
 * Neither needs a compiler to catch. `locateWipe` is pure, it is the same
 * function the lane points O3 with, and running the fixtures through it here
 * costs nothing and fires on both.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  APPARATUS_FIXTURES, APPARATUS_FN, READOUT_FIXTURES, FIXTURE_BYTES, subjectSource,
  APPARATUS_FIXTURE_NAMES, APPARATUS_FIXTURE_COUNT,
  apparatusInventoryProblems, apparatusProblems,
} from '../lib/fixtures.mjs';
import { locateWipe } from '../lib/bufferbytes.mjs';
import { REASON } from '../lib/agreement.mjs';
import { wipeSpans } from '../../ai-generated/lib/ablation-cell.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const read = (p) => readFileSync(p, 'utf8');

test('every apparatus fixture holds exactly one wipe that O3 can be pointed at', () => {
  for (const fx of APPARATUS_FIXTURES) {
    const w = locateWipe(fx.src, APPARATUS_FN);
    assert.equal(w.located, true, `${fx.name}: ${w.why}`);
    assert.equal(w.callee, 'memset', `${fx.name}: the wipe is spelled ${w.callee}`);
    assert.equal(w.object, 'key');
    assert.equal(w.lenExpr, 'sizeof key');
    assert.equal(w.helper, null, `${fx.name}: the subject itself reads as a wipe helper`);
    assert.equal(wipeSpans(fx.src, APPARATUS_FN).spans.length, 1, `${fx.name}: more than one span`);
  }
});

test('the two apparatus fixtures differ by exactly one line, and it is the read-after', () => {
  // The property `../../lto-window/tools/make-lto-fixtures.sh` states as a `diff`
  // rather than as a sentence: if the positive control and the discriminating
  // half differ in anything but the one variable, the pair stops being about one
  // variable and the check stops meaning what it says.
  const [kept, removed] = APPARATUS_FIXTURES;
  const a = kept.src.split('\n');
  const b = removed.src.split('\n');
  assert.equal(a.length, b.length + 1, 'the fixtures differ by more than one line');
  // Exactly one line of `kept` can be deleted to give `removed`, and it is the
  // read-after. Compared this way rather than index by index: an insertion
  // shifts every line after it, so an index-wise diff reports four differences
  // for one inserted line.
  const removable = a.map((_, i) => i)
    .filter((i) => a.filter((unused, j) => j !== i).join('\n') === b.join('\n'));
  assert.equal(removable.length, 1, `${removable.length} single-line deletions turn one fixture into the other`);
  assert.match(a[removable[0]], /vg_use\(key, sizeof key\);/);
  assert.equal(kept.expect, 'PRESENT');
  assert.equal(removed.expect, 'ABSENT');
});

test('the subject is a function the disassembly reader can still be pointed at', () => {
  for (const fx of APPARATUS_FIXTURES) {
    assert.match(fx.src, /__attribute__\(\(noinline\)\)/,
      `${fx.name}: the subject may be absorbed into its caller, and read-wipe.py would read NOT_OBSERVED`);
    assert.match(fx.src, new RegExp(`int ${APPARATUS_FN}\\(void\\)`), `${fx.name}: the subject is not the corpus's shape`);
  }
});

test('the read-out fixtures each set up the answer they are checked against', () => {
  const byName = Object.fromEntries(READOUT_FIXTURES.map((f) => [f.name, f]));

  // The one that must establish a number.
  const known = locateWipe(byName.known.src, byName.known.fn);
  assert.equal(known.located, true, known.why);
  assert.equal(known.lenExpr, 'sizeof key');
  assert.equal(byName.known.establishes, FIXTURE_BYTES.kept);
  assert.match(byName.known.src, new RegExp(`key\\[${FIXTURE_BYTES.kept}\\]`));

  // The one whose length is not a constant expression. `locateWipe` still finds
  // it -- the refusal is the COMPILER's, at step 2 of the read-out, which is the
  // point: the text cannot tell a constant from a parameter and does not try.
  const rt = locateWipe(byName.runtime.src, byName.runtime.fn);
  assert.equal(rt.located, true, rt.why);
  assert.equal(rt.lenExpr, 'n');
  assert.equal(byName.runtime.establishes, null);

  // The one whose length is a constant that is not the buffer's size.
  const short = locateWipe(byName.short.src, byName.short.fn);
  assert.equal(short.located, true, short.why);
  assert.equal(short.lenExpr, '16');
  assert.equal(short.object, 'key');
  assert.match(byName.short.src, new RegExp(`key\\[${FIXTURE_BYTES.short}\\]`));
  assert.notEqual(Number(short.lenExpr), FIXTURE_BYTES.short,
    'the wrong-size fixture wipes exactly the buffer, so it no longer exercises the cross-check');
  assert.equal(byName.short.establishes, null);
  assert.equal(byName.short.refusalMatches, 'sizeof(key)');
});

test('no fixture spells the wipe in a form the call-name scan cannot see', () => {
  for (const fx of [...APPARATUS_FIXTURES, ...READOUT_FIXTURES]) {
    assert.ok(!fx.src.includes('__builtin_memset'),
      `${fx.name}: __builtin_memset is not matched by \\bmemset\\s*\\( and the fixture would hold no wipe`);
    assert.match(fx.src, /#include <string\.h>/, `${fx.name}: memset is used without a declaration`);
  }
});

test('a void subject is rejected by this file, because wipeSpans reads it as a helper', () => {
  // The bug, reproduced deliberately, so the reason the fixtures are shaped this
  // way survives anybody tidying them.
  const asVoid = subjectSource({ bytes: 32 }).replace('int handle(void)', 'void handle(void)').replace('  return 0;\n', '');
  const w = locateWipe(asVoid, 'handle');
  assert.equal(w.located, false);
  assert.equal(w.reason, REASON.O3_NO_SINGLE_WIPE);
  assert.match(w.why, /2 wipes/);
});

// ------------------------------------ the check cannot conclude over nothing --
//
// THE SHORT CIRCUIT THESE CLOSE. `tools/check-o3-apparatus.mjs` looped over
// `APPARATUS_FIXTURES`, collected a reading per fixture, and then asked
// `readings.kept !== undefined && readings.kept === readings.removed`. Over an
// EMPTY or renamed set the loop ran zero times, that guard was false because the
// reading was MISSING rather than because the instrument discriminated, and the
// tool exited 0 having compiled nothing and compared nothing -- a positive
// control reporting "no problem" about a run that never happened. The count is
// pinned and the conclusion is a pure function, so both can be checked here with
// no compiler on the host.

test('the apparatus fixture set has a pinned size and pinned names', () => {
  assert.equal(APPARATUS_FIXTURE_COUNT, 2);
  assert.deepEqual([...APPARATUS_FIXTURE_NAMES], ['kept', 'removed']);
  assert.equal(APPARATUS_FIXTURES.length, APPARATUS_FIXTURE_COUNT,
    'the fixture set no longer holds the number of fixtures the check is written for');
  assert.deepEqual(APPARATUS_FIXTURES.map((f) => f.name), [...APPARATUS_FIXTURE_NAMES],
    'a fixture was renamed; the check reads both of them by name');
  assert.deepEqual(apparatusInventoryProblems(), [], 'the real fixture set cannot carry its own check');
});

test('AN EMPTY OR RENAMED FIXTURE SET IS A PROBLEM, not a silent "no problem"', () => {
  // Each of these is a one-line edit somebody could plausibly make, and each of
  // them used to leave the tool exiting 0.
  const empty = apparatusInventoryProblems([]);
  assert.ok(empty.length > 0, 'an empty fixture set is reported as a set that can carry the check');
  assert.ok(empty.some((x) => /holds 0 fixture\(s\) and the check is written for 2/.test(x)),
    'the empty set is refused without saying how many fixtures the check needs');
  assert.ok(apparatusInventoryProblems([APPARATUS_FIXTURES[0]]).length, 'a set of one fixture is accepted');
  const renamed = apparatusInventoryProblems([{ ...APPARATUS_FIXTURES[0], name: 'positive' }, APPARATUS_FIXTURES[1]]);
  assert.ok(renamed.some((x) => /`kept` is gone/.test(x)), 'a renamed fixture is accepted');
  // Two fixtures that expect the same word cannot tell a stuck instrument from a
  // working one, however cleanly both are read.
  const sameWord = apparatusInventoryProblems([APPARATUS_FIXTURES[0], { ...APPARATUS_FIXTURES[1], expect: 'PRESENT' }]);
  assert.ok(sameWord.some((x) => /cannot discriminate/.test(x)), 'a set that expects one word twice is accepted');
});

test('the conclusion COUNTS before it compares: no reading is a problem of its own', () => {
  // The exact state the old comparison was blind to: no readings at all.
  const none = apparatusProblems({});
  assert.equal(none.length, 2);
  for (const fx of APPARATUS_FIXTURES) {
    assert.ok(none.some((x) => x.startsWith(`${fx.name}: no reading was taken`)), `${fx.name} was not missed`);
  }
  // And a partial set, which is the same failure wearing one answer.
  assert.ok(apparatusProblems({ kept: 'PRESENT' }).some((x) => /^removed: no reading was taken/.test(x)));
  // A reading filed under a name that is not a fixture is not quietly ignored.
  assert.ok(apparatusProblems({ kept: 'PRESENT', removed: 'ABSENT', extra: 'ABSENT' })
    .some((x) => /`extra`, which is not a fixture of this check/.test(x)));
});

test('the conclusion is empty ONLY for one reading per fixture, each right, and the two different', () => {
  assert.deepEqual(apparatusProblems({ kept: 'PRESENT', removed: 'ABSENT' }), [],
    'the answers the fixtures were built to produce are reported as a problem');
  // Stuck on one word, which is the failure the pair exists for. The `removed`
  // fixture reads the wrong word, so that is what it is told.
  assert.ok(apparatusProblems({ kept: 'PRESENT', removed: 'PRESENT' }).some((x) => /^removed: read PRESENT, expected ABSENT/.test(x)));
  assert.ok(apparatusProblems({ kept: 'ABSENT', removed: 'ABSENT' }).some((x) => /^kept: read ABSENT, expected PRESENT/.test(x)));
  // And the non-discrimination sentence itself, over a fixture set whose two
  // expectations are the two words a stuck instrument would both satisfy.
  const stuck = apparatusProblems(
    { kept: 'PRESENT', removed: 'PRESENT' },
    [APPARATUS_FIXTURES[0], { ...APPARATUS_FIXTURES[1], expect: 'PRESENT' }],
  );
  assert.ok(stuck.some((x) => /cannot discriminate/.test(x)), 'a set of one word is graded as a working apparatus');
});

test('the tool concludes through that function and keeps no comparison of its own', () => {
  const src = read(join(LANE, 'tools/check-o3-apparatus.mjs'));
  assert.match(src, /apparatusInventoryProblems\(\)/, 'the tool does not read the shape of its own fixture set');
  assert.match(src, /const problems = apparatusProblems\(readings\)/, 'the tool draws its own conclusion again');
  // The short circuit itself, as a grep: an `undefined` guard in front of the
  // comparison is what made an empty set read as agreement.
  assert.ok(!/readings\.kept !== undefined/.test(src), 'the tool still guards its comparison with an undefined check');
  assert.ok(!/readings\.kept === readings\.removed/.test(src), 'the tool still compares two readings it did not count');
  // And the inventory refusal happens before a compiler is asked anything.
  assert.ok(src.indexOf('apparatusInventoryProblems()') < src.indexOf('for (const fx of APPARATUS_FIXTURES)'),
    'the fixture set is compiled before its shape is read');
});

test('both checks take their fixtures from this module rather than spelling their own', () => {
  for (const rel of ['tools/check-o3-apparatus.mjs', 'tools/check-bytes-readout.mjs']) {
    const src = read(join(LANE, rel));
    assert.match(src, /from '\.\.\/lib\/fixtures\.mjs'/, `${rel} spells its own fixtures`);
    assert.ok(!src.includes('__builtin_memset'), `${rel} still carries the unmatched spelling`);
    assert.ok(!/unsigned char key\[\d+\];/.test(src), `${rel} writes a fixture body of its own`);
  }
});

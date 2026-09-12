/**
 * The ladder's pure parts: the identity guard and the first-appearance rule.
 *
 * The first-appearance rule is the one thing in this lane that would make it
 * WRONG rather than incomplete, so it is tested on tables rather than on a
 * compiler: a rung that was not obtained must never be read as a rung that kept
 * the wipe, and a rung with an unscorable verdict must never be stepped over on
 * the way to a "first".
 *
 * No compiler is run here.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LADDER, ALL_OPTS, SCORABLE, spelledMajor, parseMajor, versionFromBanner, identityProblem,
  firstAppearance, versionCounting, appearanceCounting, cellMark, shortMark, appearanceSentence,
} from '../lib/ladder.mjs';
import { vendorOf } from '../../repair-loop/lib/vendor.mjs';

// ------------------------------------------------------------ the ladder -----

test('every rung of the declared ladder is a spelling vendorOf resolves, and back', () => {
  for (const [vendor, majors] of Object.entries(LADDER)) {
    assert.ok(majors.length > 1, `${vendor} needs more than one rung to be a ladder`);
    for (const m of majors) {
      const cc = `${vendor}-${m}`;
      assert.equal(vendorOf(cc), vendor, cc);
      assert.equal(spelledMajor(cc), m, cc);
    }
    assert.deepEqual([...majors].sort((a, b) => a - b), [...majors], `${vendor} rungs must be lowest first`);
  }
});

test('the pinned pair is on the ladder: a lane that could not measure clang-18 and gcc-13 could not anchor', () => {
  assert.ok(LADDER.clang.includes(18));
  assert.ok(LADDER.gcc.includes(13));
});

// ------------------------------------------------------- the identity guard --

test('versionFromBanner reads the real banners of both vendors', () => {
  assert.deepEqual(versionFromBanner('clang', 'Ubuntu clang version 18.1.3 (1ubuntu1)'), { full: '18.1.3', major: 18 });
  assert.deepEqual(versionFromBanner('clang', 'Ubuntu clang version 15.0.7'), { full: '15.0.7', major: 15 });
  assert.deepEqual(versionFromBanner('clang', 'Ubuntu clang version 20.1.2 (0ubuntu1~24.04.3)'), { full: '20.1.2', major: 20 });
  // gcc puts the package version in the parentheses and the COMPILER version last.
  assert.deepEqual(versionFromBanner('gcc', 'gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0'), { full: '13.3.0', major: 13 });
  assert.deepEqual(versionFromBanner('gcc', 'gcc-10 (Ubuntu 10.5.0-4ubuntu2.1) 10.5.0'), { full: '10.5.0', major: 10 });
});

test('parseMajor takes the leading integer of either -dumpversion spelling', () => {
  assert.equal(parseMajor('13'), 13);          // gcc
  assert.equal(parseMajor('18.1.3'), 18);      // clang
  assert.equal(parseMajor('  20.1.2\n'), 20);
  assert.equal(parseMajor(''), null);
  assert.equal(parseMajor('abc'), null);
  assert.equal(parseMajor(null), null);
});

test('identityProblem passes a compiler that is the version its name claims', () => {
  assert.equal(identityProblem({
    cc: 'clang-18', vendor: 'clang', banner: 'Ubuntu clang version 18.1.3 (1ubuntu1)', dumpversion: '18.1.3',
  }), null);
  assert.equal(identityProblem({
    cc: 'gcc-13', vendor: 'gcc', banner: 'gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0', dumpversion: '13',
  }), null);
});

test('identityProblem refuses a name that is a link to another version -- the wrong-rung failure', () => {
  // The failure this guard exists for: clang-17 on the PATH is a symlink to
  // clang-20. Nothing errors; every verdict is simply filed under rung 17.
  const p = identityProblem({
    cc: 'clang-17', vendor: 'clang', banner: 'Ubuntu clang version 20.1.2 (0ubuntu1~24.04.3)', dumpversion: '20.1.2',
  });
  assert.match(p, /reports version 20\.1\.2/);
  assert.match(p, /not 17/);
});

test('identityProblem refuses a banner and a -dumpversion that disagree with each other', () => {
  const p = identityProblem({
    cc: 'gcc-12', vendor: 'gcc', banner: 'gcc-12 (Ubuntu 12.4.0-2ubuntu1~24.04.1) 12.4.0', dumpversion: '11',
  });
  assert.match(p, /-dumpversion says 11/);
});

test('identityProblem refuses an unversioned spelling: it names no rung', () => {
  for (const cc of ['clang', 'gcc', 'cc']) {
    const p = identityProblem({ cc, vendor: vendorOf(cc), banner: 'Ubuntu clang version 18.1.3', dumpversion: '18.1.3' });
    assert.ok(p, cc);
  }
  assert.match(identityProblem({ cc: 'clang', vendor: 'clang', banner: 'Ubuntu clang version 18.1.3', dumpversion: '18.1.3' }), /versioned spelling/);
  assert.match(identityProblem({ cc: 'cc', vendor: null, banner: '', dumpversion: '' }), /neither clang nor gcc/);
});

test('identityProblem refuses a version that is not a rung of the declared ladder', () => {
  const p = identityProblem({ cc: 'clang-14', vendor: 'clang', banner: 'Ubuntu clang version 14.0.0', dumpversion: '14.0.0' });
  assert.match(p, /not a rung of the declared clang ladder/);
});

test('identityProblem refuses an unreadable banner or dumpversion rather than guessing', () => {
  assert.match(identityProblem({ cc: 'clang-18', vendor: 'clang', banner: 'some other program', dumpversion: '18.1.3' }), /--version banner/);
  assert.match(identityProblem({ cc: 'clang-18', vendor: 'clang', banner: 'Ubuntu clang version 18.1.3', dumpversion: '' }), /-dumpversion/);
});

// -------------------------------------------------- the first-appearance rule --

const cells = (pairs) => Object.fromEntries(pairs);

test('FIRST_AT only when every lower rung was obtained AND scorable, and it says a transition was observed', () => {
  const a = firstAppearance({
    vendor: 'gcc',
    cells: cells([[10, 'WIPE_SURVIVED'], [11, 'WIPE_SURVIVED'], [12, 'WIPE_ELIMINATED'], [13, 'WIPE_ELIMINATED'], [14, 'WIPE_ELIMINATED']]),
  });
  assert.deepEqual(a, { status: 'FIRST_AT', version: 12, transition: 'observed', gaps: [] });
  // This is the shape a version ladder exists to find: two measured rungs with
  // the elimination between them. The sentence names both, so "first" is
  // readable without the table.
  const s = appearanceSentence({ ...a, vendor: 'gcc' });
  assert.match(s, /every lower rung \(10, 11\) was obtained and kept the wipe/);
  assert.match(s, /appears between gcc-11 and gcc-12/);
});

test('a rung that was not obtained BELOW the first elimination makes it UNDETERMINED, and is named', () => {
  // gcc-10 missing. 11 kept it, 12 eliminated it -- but 10 might have eliminated
  // it too, and nothing here knows. "first" would be a claim about a rung nobody ran.
  const a = firstAppearance({
    vendor: 'gcc',
    cells: cells([[11, 'WIPE_SURVIVED'], [12, 'WIPE_ELIMINATED'], [13, 'WIPE_ELIMINATED'], [14, 'WIPE_ELIMINATED']]),
  });
  assert.equal(a.status, 'UNDETERMINED');
  assert.equal(a.version, null);
  assert.deepEqual(a.gaps, [{ version: 10, why: 'not-obtained' }]);
});

test('a rung ABOVE the first elimination that was not obtained does not disturb the answer', () => {
  const a = firstAppearance({
    vendor: 'gcc',
    cells: cells([[10, 'WIPE_SURVIVED'], [11, 'WIPE_ELIMINATED'], [12, 'WIPE_ELIMINATED']]),
  });
  assert.deepEqual(a, { status: 'FIRST_AT', version: 11, transition: 'observed', gaps: [] });
});

test('an unscorable verdict below the first elimination is a gap, named by its verdict', () => {
  for (const bad of ['COMPILE_ERROR', 'ABLATION_DID_NOT_COMPILE', 'NOT_OBSERVED', 'VERIFICATION_INCOMPLETE']) {
    assert.ok(!SCORABLE.has(bad), bad);
    const a = firstAppearance({
      vendor: 'clang',
      cells: cells([[15, 'WIPE_SURVIVED'], [16, bad], [17, 'WIPE_ELIMINATED'], [18, 'WIPE_ELIMINATED'], [19, 'WIPE_ELIMINATED'], [20, 'WIPE_ELIMINATED']]),
    });
    assert.equal(a.status, 'UNDETERMINED', bad);
    assert.deepEqual(a.gaps, [{ version: 16, why: bad }], bad);
  }
});

test('an elimination at the LOWEST rung is FIRST_AT with no transition observed, and says so', () => {
  // What this test used to assert, and why that was wrong. The old rule was
  // that the sentence should read "every lower rung (none) was obtained and
  // kept the wipe" -- a universal over the empty set. It is formally true and
  // it is a claim about nothing observed: the `below` set is empty, so no rung
  // ever kept the wipe and no transition was seen anywhere. Every one of the
  // 38 first appearances in this lane's tracked run is this case, and the
  // status word FIRST_AT plus that sentence read as "clang-15 is where the
  // elimination starts" when what was measured is "it was already gone at the
  // bottom of the ladder". The record now carries `transition` so a consumer
  // of the JSON can tell the two apart, and the sentence says the negative.
  const a = firstAppearance({ vendor: 'clang', cells: cells([[15, 'WIPE_ELIMINATED']]) });
  assert.deepEqual(a, { status: 'FIRST_AT', version: 15, transition: 'none-below', gaps: [] });
  const s = appearanceSentence({ ...a, vendor: 'clang' });
  assert.match(s, /LOWEST rung of the declared clang ladder/);
  assert.match(s, /no transition was observed/);
  assert.match(s, /not evidence that clang-15 introduced the elimination/);
  assert.doesNotMatch(s, /every lower rung/);
});

test('transition is null where no first appearance was stated', () => {
  const never = firstAppearance({ vendor: 'gcc', cells: cells(LADDER.gcc.map((m) => [m, 'WIPE_SURVIVED'])) });
  assert.equal(never.transition, null);
  const undet = firstAppearance({ vendor: 'gcc', cells: {} });
  assert.equal(undet.transition, null);
});

test('a vendor with no declared ladder throws rather than answering NEVER_ELIMINATED over no rungs', () => {
  // `LADDER[vendor] || []` used to make an unrecognised vendor the cleanest
  // result the function has: rungs [], below [], gaps [], firstElim undefined
  // -> {status: 'NEVER_ELIMINATED'}. That is a negative result over a ladder
  // with no rungs, which is exactly what the sibling rule above forbids for a
  // valid vendor. No caller in the lane can reach it today (appearancesFrom
  // iterates Object.keys(LADDER)); the next one must not be able to either.
  assert.throws(() => firstAppearance({ vendor: 'icc', cells: {} }), /no declared ladder/);
  assert.throws(() => firstAppearance({ vendor: undefined, cells: { 15: 'WIPE_ELIMINATED' } }), /no declared ladder/);
});

test('NEVER_ELIMINATED needs the WHOLE declared ladder obtained and scorable', () => {
  const full = firstAppearance({
    vendor: 'gcc',
    cells: cells(LADDER.gcc.map((m) => [m, 'WIPE_SURVIVED'])),
  });
  assert.deepEqual(full, { status: 'NEVER_ELIMINATED', version: null, transition: null, gaps: [] });
  // One rung short: not a negative result, an unfinished one.
  const short = firstAppearance({
    vendor: 'gcc',
    cells: cells(LADDER.gcc.slice(1).map((m) => [m, 'WIPE_SURVIVED'])),
  });
  assert.equal(short.status, 'UNDETERMINED');
  assert.deepEqual(short.gaps, [{ version: 10, why: 'not-obtained' }]);
});

test('an empty cell set is UNDETERMINED with every rung listed, never NEVER_ELIMINATED', () => {
  const a = firstAppearance({ vendor: 'clang', cells: {} });
  assert.equal(a.status, 'UNDETERMINED');
  assert.deepEqual(a.gaps.map((g) => g.version), [...LADDER.clang]);
  assert.ok(a.gaps.every((g) => g.why === 'not-obtained'));
});

test('the gap word is not-obtained, and is neither of the two words that mean something else', () => {
  const a = firstAppearance({ vendor: 'clang', cells: cells([[18, 'WIPE_ELIMINATED']]) });
  const whys = a.gaps.map((g) => g.why);
  assert.ok(whys.includes('not-obtained'));
  // interfaces.md section 3.1: UNSUPPORTED is the toolchain refusing an
  // invocation; section 3: NOT_OBSERVED is a reading that did not come back.
  // Neither is true of a compiler that was never installed.
  assert.ok(!whys.includes('UNSUPPORTED'));
  assert.ok(!whys.includes('NOT_OBSERVED'));
  assert.ok(!whys.includes('ABSENT'));
});

// ------------------------------------------------------------- the counting --

test('versionCounting accounts for every declared rung, obtained or skipped', () => {
  const versions = [
    ...LADDER.clang.map((m) => ({ cc: `clang-${m}`, obtained: true })),
    ...LADDER.gcc.map((m) => ({ cc: `gcc-${m}`, obtained: true })),
  ];
  const c = versionCounting(versions);
  assert.equal(c.declared, LADDER.clang.length + LADDER.gcc.length);
  assert.equal(c.obtained, c.declared);
  assert.equal(c.skipped, 0);
  assert.equal(c.accountedFor, true);

  // the two skip reasons are counted apart: one rung is not on the machine,
  // one was simply not asked for by this invocation
  versions[0] = { ...versions[0], obtained: false, reason: 'not-installed' };
  versions[1] = { ...versions[1], obtained: false, reason: 'not-requested' };
  const c2 = versionCounting(versions);
  assert.equal(c2.obtained, c.declared - 2);
  assert.equal(c2.skipped, 2);
  assert.equal(c2.notInstalled, 1);
  assert.equal(c2.notRequested, 1);
  assert.equal(c2.accountedFor, true);
});

test('a skipped rung with no reason breaks the accounting rather than passing quietly', () => {
  // The failure this guards: a rung dropped from the run with nothing said about
  // why. obtained + skipped would still add up, and the reader would have no way
  // to tell "not on this machine" from "this invocation did not ask".
  const versions = [
    ...LADDER.clang.map((m) => ({ cc: `clang-${m}`, obtained: true })),
    ...LADDER.gcc.map((m) => ({ cc: `gcc-${m}`, obtained: true })),
  ];
  versions[0] = { ...versions[0], obtained: false };
  assert.equal(versionCounting(versions).accountedFor, false);
});

test('versionCounting is against the DECLARED ladder, not the rungs handed to it', () => {
  // A run that names two rungs must not make its denominator two. This is the
  // shape that turns "we ran clang-18" into "the ladder holds".
  const c = versionCounting([{ cc: 'clang-18', obtained: true }, { cc: 'gcc-13', obtained: true }]);
  assert.equal(c.declared, LADDER.clang.length + LADDER.gcc.length);
  assert.equal(c.obtained, 2);
  assert.equal(c.accountedFor, false, 'a versions[] short of the declared ladder must not read as complete');
});

test('appearanceCounting splits every question asked, and splits the first appearances by transition', () => {
  const c = appearanceCounting([
    { status: 'FIRST_AT', transition: 'observed' }, { status: 'FIRST_AT', transition: 'none-below' },
    { status: 'NEVER_ELIMINATED', transition: null }, { status: 'UNDETERMINED', transition: null },
  ]);
  assert.deepEqual(c, {
    asked: 4, firstAt: 2, firstAtObserved: 1, firstAtNoneBelow: 1, never: 1, undetermined: 1, accountedFor: true,
  });
});

test('a FIRST_AT carrying no transition breaks the accounting rather than being filed under the kinder word', () => {
  // "38 first appearances" and "38 already eliminated at the bottom rung" are
  // the same number and opposite findings, so a record that does not say which
  // must not be counted as either. Both halves are printed in the report.
  const c = appearanceCounting([{ status: 'FIRST_AT' }, { status: 'FIRST_AT', transition: 'observed' }]);
  assert.equal(c.firstAt, 2);
  assert.equal(c.firstAtObserved, 1);
  assert.equal(c.firstAtNoneBelow, 0);
  assert.equal(c.accountedFor, false);
});

// -------------------------------------------------------------- the printing --

test('a rung with no cell prints as -(not obtained), never as a verdict', () => {
  const c = cells([[18, 'WIPE_SURVIVED']]);
  assert.equal(cellMark(c, 18), 'WIPE_SURVIVED');
  assert.equal(cellMark(c, 17), '-(not obtained)');
  assert.equal(shortMark(c, 17), '-');
  assert.equal(shortMark(c, 18), 'S');
  assert.equal(shortMark(cells([[18, 'WIPE_ELIMINATED']]), 18), 'E');
  assert.equal(shortMark(cells([[18, 'COMPILE_ERROR']]), 18), '?');
});

test('appearanceSentence says what an UNDETERMINED rests on, and says it is not a finding about the wipe', () => {
  const a = firstAppearance({ vendor: 'clang', cells: cells([[16, 'WIPE_SURVIVED'], [17, 'WIPE_ELIMINATED']]) });
  const s = appearanceSentence({ ...a, vendor: 'clang' });
  assert.match(s, /clang-15 not-obtained/);
  assert.match(s, /not a finding about the wipe/);
});

test('ALL_OPTS is the find step order, so a level column lines up with the tracked rows', () => {
  assert.deepEqual([...ALL_OPTS], ['-O0', '-O1', '-O2', '-O3', '-Os']);
});

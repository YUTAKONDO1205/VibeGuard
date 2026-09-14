/**
 * The second second oracle: the vocabulary, the table it produces, the failures
 * it is allowed to report, and the live O1 column beside it.
 *
 * The lane was written with ONE second instrument and its four cell names were
 * four literals. A gcc-side oracle answers in different words -- `ABSENT` where
 * the pass observer says `LOST`, and `PARTIAL` where the pass observer has no
 * word at all -- and the tempting shortcut is to map O3's `ABSENT` onto O2's
 * `LOST` and keep one table. That is the same fold the lane refuses on the O2
 * side (`ABSENT` into `LOST`), performed one level up: it would assert that a
 * call site missing from the IR and a zero fill missing from the linked program
 * are the same sentence, inside the module whose job is to keep two sentences
 * apart.
 *
 * So these tests are mostly about what the two vocabularies may NOT do to each
 * other. Nothing here compiles anything.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  tabulate, classifyPair, laneVerdict, degeneracyOf, kindOfWord, o2ClassOf,
  O2_VOCAB, O3_VOCAB, VOCABULARIES, CELLS, DIAGONAL, OFF_DIAGONAL,
  KIND, REASON, REASON_WORDS, STRATUM,
} from '../lib/agreement.mjs';
import {
  unresolvedSymbols, stubSource, objectArgs, linkArgs, readWipeArgs,
  OBJECT_FLAGS, NO_HELPER, READ_WIPE,
  recognizerBranch, qualificationOf, BRANCH, READER_CONTROL_OPT,
  SAME_BUILD_LIMITATION, NO_BRANCH_LIMITATION,
} from '../lib/disasm.mjs';
import { driftOf, summariseDrift, DRIFT } from '../lib/liveo1.mjs';
import { writeDataRefusals, defaultSecondOracle, dataFileName } from '../lib/record.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const read = (p) => readFileSync(p, 'utf8');
const README = read(join(LANE, 'README.md'));

const pair = (over = {}) => ({
  id: 'model_E_scen_r1',
  cc: 'gcc-13',
  opt: '-O2',
  idiom: 'removable',
  o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT', control_via: 'oracle' },
  o2: { finalState: 'ABSENT', control: 'PRESENT' },
  ...over,
});
const above = (t) => t.strata.find((s) => s.name === STRATUM.ABOVE_O0);

/**
 * One cell that lands in the named square of the named vocabulary's table.
 *
 * The O2 channel's subject-resolution check is part of the O2 reading and not of
 * the O3 one, so a pair built for O2 carries the exit the checker gives when the
 * subject name resolved. Building it here rather than in each test keeps the
 * difference in one place.
 */
const cellPair = (vocab, cell) => {
  const [verdict, state] = cell.split('/');
  return pair({
    o1: { verdict: `WIPE_${verdict}`, control: 'PRESENT' },
    o2: vocab.oracle === 'O3'
      ? { finalState: state, control: 'PRESENT' }
      : { finalState: state, control: 'PRESENT', subjectResolutionExit: 0 },
  });
};

// ------------------------------------------------- the vocabularies stay apart --

test('the two vocabularies have different words for "the wipe is gone"', () => {
  assert.equal(O2_VOCAB.gone, 'LOST');
  assert.equal(O3_VOCAB.gone, 'ABSENT');
  assert.equal(O2_VOCAB.kept, 'PRESENT');
  assert.equal(O3_VOCAB.kept, 'PRESENT');
  assert.deepEqual(Object.keys(VOCABULARIES).sort(), ['O2', 'O3']);
});

test('O3’s table is named in O3’s words, so a gcc record can never say ELIMINATED/LOST', () => {
  assert.deepEqual([...O3_VOCAB.cells],
    ['ELIMINATED/ABSENT', 'ELIMINATED/PRESENT', 'SURVIVED/ABSENT', 'SURVIVED/PRESENT']);
  assert.deepEqual([...O3_VOCAB.diagonal], ['ELIMINATED/ABSENT', 'SURVIVED/PRESENT']);
  assert.deepEqual([...O3_VOCAB.offDiagonal], ['ELIMINATED/PRESENT', 'SURVIVED/ABSENT']);
  for (const c of O3_VOCAB.cells) assert.ok(!c.includes('LOST'), `${c} carries O2's word`);
});

test('the lane’s old four names are still O2’s, unchanged and derived rather than respelled', () => {
  assert.deepEqual([...CELLS], [...O2_VOCAB.cells]);
  assert.deepEqual([...DIAGONAL], ['ELIMINATED/LOST', 'SURVIVED/PRESENT']);
  assert.deepEqual([...OFF_DIAGONAL], ['ELIMINATED/PRESENT', 'SURVIVED/LOST']);
});

test('ABSENT is NOT_COMPARABLE on O2 and GRADABLE on O3 -- the same word, two instruments', () => {
  // The reason `kindOfWord` takes a vocabulary at all. One table mapping words
  // to kinds without saying whose words they are is how the two instruments
  // would be merged by accident.
  assert.equal(kindOfWord('ABSENT', O2_VOCAB), KIND.NOT_COMPARABLE);
  assert.equal(o2ClassOf('ABSENT', O2_VOCAB), null);
  assert.equal(o2ClassOf('ABSENT', O3_VOCAB), 'ABSENT');
  // And LOST, the other way about: O2's gradable word is not one of O3's at all.
  assert.equal(o2ClassOf('LOST', O3_VOCAB), null);
});

test('PARTIAL is O3’s "both worked and the words do not meet", never folded either way', () => {
  assert.ok(O3_VOCAB.notInTable.includes('PARTIAL'));
  assert.equal(kindOfWord('PARTIAL', O3_VOCAB), KIND.NOT_COMPARABLE);
  const c = classifyPair(pair({ o2: { finalState: 'PARTIAL', control: 'PRESENT' } }), { vocab: O3_VOCAB });
  assert.equal(c.status, 'EXCLUDED');
  assert.equal(c.kind, KIND.NOT_COMPARABLE);
  assert.equal(c.reason, REASON.O3_NOT_A_READING);
  assert.equal(c.detail, 'PARTIAL');
});

test('a reading under the wrong vocabulary is refused rather than tabulated as zero', () => {
  // The failure this guards: an O3 reading tabulated with O2's vocabulary would
  // produce a table of four zeroes and a denominator of 0, and the lane would
  // print "no cell entered the denominator" -- a run that measured nothing and a
  // run read under the wrong headings would look identical.
  assert.throws(() => degeneracyOf(O3_VOCAB.cells.reduce((o, k) => ({ ...o, [k]: 0 }), {}), O2_VOCAB),
    /not built with the O2 vocabulary/);
});

// --------------------------------------------------------- the O3 table -------

test('an O3 table grades ABSENT against ELIMINATED and PRESENT against SURVIVED', () => {
  const t = tabulate([
    pair({ id: 'a', o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT' }, o2: { finalState: 'ABSENT', control: 'PRESENT' } }),
    pair({ id: 'b', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'PRESENT', control: 'PRESENT' } }),
    pair({ id: 'c', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'ABSENT', control: 'PRESENT' } }),
  ], { vocab: O3_VOCAB });
  const s = above(t);
  assert.equal(s.table['ELIMINATED/ABSENT'], 1);
  assert.equal(s.table['SURVIVED/PRESENT'], 1);
  assert.equal(s.table['SURVIVED/ABSENT'], 1);
  assert.equal(s.den, 3);
  assert.equal(s.agree, 2);
  assert.equal(s.disagree, 1);
  assert.equal(s.columns.oracle, 'O3');
  assert.equal(t.secondOracle, 'O3');
  // The off-diagonal is listed by id, as on the O2 side, and carries which
  // instrument filed it.
  assert.equal(s.offDiagonal.length, 1);
  assert.equal(s.offDiagonal[0].id, 'c');
  assert.equal(s.offDiagonal[0].secondOracle, 'O3');
});

test('a cell on O3’s OWN diagonal agrees -- `agrees` reads the vocabulary the cell was graded under', () => {
  // THE VOCABULARY MERGE THE PARAMETERISATION EXISTS TO PREVENT, as an
  // assertion. `classifyPair` used to compute this flag as
  // `DIAGONAL.includes(cell)` against the module's HARDCODED O2 diagonal
  // (`ELIMINATED/LOST`, `SURVIVED/PRESENT`). `ELIMINATED/ABSENT` is not in that
  // list, so an O3 cell sitting squarely on O3's own diagonal came out
  // `agrees: false`. The off-diagonal IS this lane's result, so that one line
  // manufactured a finding out of a mismatch between two column headings.
  const onDiagonal = classifyPair(
    pair({ o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT' }, o2: { finalState: 'ABSENT', control: 'PRESENT' } }),
    { vocab: O3_VOCAB },
  );
  assert.equal(onDiagonal.cell, 'ELIMINATED/ABSENT');
  assert.equal(onDiagonal.agrees, true, 'an O3 cell on the O3 diagonal was recorded as a disagreement');
  const alsoDiagonal = classifyPair(
    pair({ o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'PRESENT', control: 'PRESENT' } }),
    { vocab: O3_VOCAB },
  );
  assert.equal(alsoDiagonal.agrees, true);
  // And the other half of the same property: O3's off-diagonal is still false,
  // so the flag was not fixed by making it constant.
  for (const [verdict, state, cell] of [
    ['WIPE_ELIMINATED', 'PRESENT', 'ELIMINATED/PRESENT'],
    ['WIPE_SURVIVED', 'ABSENT', 'SURVIVED/ABSENT'],
  ]) {
    const off = classifyPair(
      pair({ o1: { verdict, control: 'PRESENT' }, o2: { finalState: state, control: 'PRESENT' } }),
      { vocab: O3_VOCAB },
    );
    assert.equal(off.cell, cell);
    assert.equal(off.agrees, false, `${cell} was recorded as agreement`);
  }
  // The O2 side is unchanged: the default vocabulary still grades the four names
  // this lane has printed since it was written.
  const o2 = classifyPair(pair({ o2: { finalState: 'LOST', control: 'PRESENT', subjectResolutionExit: 0 } }));
  assert.equal(o2.cell, 'ELIMINATED/LOST');
  assert.equal(o2.agrees, true);
  // Stated as the general rule, over both vocabularies, so a third one cannot be
  // added with a fifth diagonal nobody compared against.
  for (const vocab of Object.values(VOCABULARIES)) {
    for (const cell of vocab.cells) {
      assert.equal(classifyPair(cellPair(vocab, cell), { vocab }).agrees, vocab.diagonal.includes(cell),
        `${vocab.oracle} ${cell}: agrees was graded against another vocabulary's diagonal`);
    }
  }
});

test('`agrees` and the tabulated off-diagonal listing can never disagree with each other', () => {
  // The two are computed in different places -- `classifyPair` sets the flag,
  // `tabulate` files the listing from `vocab.offDiagonal` -- which is how the
  // defect above survived: the counts were right under O3 and the per-cell flag
  // carried into the record was wrong.
  for (const vocab of Object.values(VOCABULARIES)) {
    const cells = vocab.cells.map((cell, i) => ({ ...cellPair(vocab, cell), id: `c${i}` }));
    const s = above(tabulate(cells, { vocab }));
    assert.equal(s.offDiagonal.length, 2);
    for (const c of s.offDiagonal) assert.equal(c.agrees, false, `${vocab.oracle}: ${c.cell} is listed off-diagonal and flagged as agreement`);
    assert.equal(s.agree, 2);
    assert.equal(s.disagree, 2);
    // The other direction, which is the one the defect was on: a cell the
    // listing did NOT file must carry `agrees: true`. `tabulate` does not export
    // its graded rows, so the flag is read where it is set.
    const listed = new Set(s.offDiagonal.map((c) => c.cell));
    for (const cell of vocab.cells) {
      assert.equal(classifyPair(cellPair(vocab, cell), { vocab }).agrees, !listed.has(cell),
        `${vocab.oracle} ${cell}: the flag and the off-diagonal listing say different things`);
    }
  }
});

test('DISAGREEMENT ON THE O3 SIDE STILL EXITS 0 -- the off-diagonal is the result', () => {
  // The property most likely to be "fixed" by someone who has not read the
  // README, now on a second table. A lane that went red on disagreement would be
  // a lane with an incentive.
  const t = tabulate([
    pair({ id: 'a', o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT' }, o2: { finalState: 'PRESENT', control: 'PRESENT' } }),
    pair({ id: 'b', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'ABSENT', control: 'PRESENT' } }),
  ], { vocab: O3_VOCAB });
  const v = laneVerdict(t);
  assert.equal(above(t).agree, 0);
  assert.equal(v.code, 0);
  assert.equal(v.readable, true);
});

test('a degenerate O3 marginal exits 2 and says ABSENT or PRESENT, never LOST', () => {
  const t = tabulate([
    pair({ id: 'a', o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT' }, o2: { finalState: 'ABSENT', control: 'PRESENT' } }),
    pair({ id: 'b', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'ABSENT', control: 'PRESENT' } }),
  ], { vocab: O3_VOCAB });
  const v = laneVerdict(t);
  assert.equal(v.code, 2);
  const why = v.reasons.join(' ');
  assert.match(why, /read ABSENT on O3/);
  assert.ok(!/LOST/.test(why), 'the degeneracy message names a word the instrument never said');
});

test('the -O0 stratum is separated on the O3 side too, by the same arithmetic', () => {
  const t = tabulate([
    pair({ id: 'a', opt: '-O0', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'PRESENT', control: 'PRESENT' } }),
    pair({ id: 'b', opt: '-O0', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'PRESENT', control: 'PRESENT' } }),
  ], { vocab: O3_VOCAB });
  const at0 = t.strata.find((s) => s.name === STRATUM.AT_O0);
  assert.equal(at0.den, 2);
  assert.equal(at0.discriminating, false, 'a perfectly agreeing -O0 stratum was called discriminating');
  assert.equal(laneVerdict(t).code, 2);
});

// -------------------------------------- the control, before any subject verdict --

test('an O3 control that is not PRESENT excludes the cell before its subject is read', () => {
  for (const word of ['ABSENT', 'PARTIAL', 'NOT_OBSERVED']) {
    const c = classifyPair(pair({ o2: { finalState: 'ABSENT', control: word } }), { vocab: O3_VOCAB });
    assert.equal(c.status, 'EXCLUDED');
    assert.equal(c.reason, REASON.O3_CONTROL_LOST, word);
    assert.equal(c.detail, word);
    assert.equal(c.kind, KIND.BROKEN_MEASUREMENT);
  }
  const never = classifyPair(pair({ o2: { finalState: 'ABSENT', control: null } }), { vocab: O3_VOCAB });
  assert.equal(never.reason, REASON.O3_CONTROL_NOT_MEASURED);
});

test('a fallen O3 control beats a perfect subject reading, which is the point of the order', () => {
  const c = classifyPair(pair({
    o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT' },
    o2: { finalState: 'ABSENT', control: 'ABSENT' },
  }), { vocab: O3_VOCAB });
  assert.equal(c.status, 'EXCLUDED');
  assert.equal(c.reason, REASON.O3_CONTROL_LOST);
});

test('the O3 exclusion words are O3’s, so a gcc failure is never filed under a plugin', () => {
  for (const r of [REASON.O3_BUILD_FAILED, REASON.O3_LINK_FAILED, REASON.O3_READER_FAILED,
    REASON.O3_BYTES_UNESTABLISHED, REASON.O3_NO_SINGLE_WIPE]) {
    const c = classifyPair(pair({ o2: { finalState: 'NOT_OBSERVED', control: null, brokenReason: r } }), { vocab: O3_VOCAB });
    assert.equal(c.reason, r);
    assert.equal(c.kind, KIND.BROKEN_MEASUREMENT);
    assert.ok(r.startsWith('o3-'), `${r} does not name the instrument that failed`);
  }
});

test('a channel that invented a reason word is refused rather than counted under `undefined`', () => {
  assert.throws(
    () => classifyPair(pair({ o2: { finalState: 'ABSENT', control: 'PRESENT', brokenReason: 'o3-something-new' } }), { vocab: O3_VOCAB }),
    /a reason this module does not define/,
  );
  assert.ok(REASON_WORDS.includes(REASON.O3_LINK_FAILED));
});

test('the O2 channel’s subject-resolution check is unchanged and still fires on a missing field', () => {
  // O3 has no subject NAME handed to a plugin, so it carries no resolution exit;
  // O2 does, and a reading that omitted it must not reach the table.
  const noField = classifyPair({
    ...pair({ cc: 'clang-18' }),
    o2: { finalState: 'LOST', control: 'PRESENT' },
  });
  assert.equal(noField.reason, REASON.O2_SUBJECT_UNRESOLVED);
  const o3NoField = classifyPair(pair({ o2: { finalState: 'ABSENT', control: 'PRESENT' } }), { vocab: O3_VOCAB });
  assert.equal(o3NoField.status, 'GRADED');
});

// ------------------------------------------------- the channel's own mechanics --

test('only the symbols the linker NAMED are stubbed', () => {
  const bfd = "ld: /x/a.o: in function `f':\na.c:(.text+0x1): undefined reference to `kdf'\n"
    + "a.c:(.text+0x9): undefined reference to `aes256_encrypt'\n";
  assert.deepEqual(unresolvedSymbols(bfd), ['aes256_encrypt', 'kdf']);
  assert.deepEqual(unresolvedSymbols('ld.lld: error: undefined symbol: vgctl_fill\n'), ['vgctl_fill']);
  assert.deepEqual(unresolvedSymbols('some other linker failure'), []);
});

test('the stub unit defines main as main and everything else as a niladic void', () => {
  const src = stubSource(['kdf', 'main']);
  assert.match(src, /int main\(void\) \{ return 0; \}/);
  assert.match(src, /void kdf\(void\) \{ \}/);
  // No stub for anything the linker did not name.
  assert.ok(!src.includes('memset'), 'the stub unit defines a library symbol');
});

test('the object step asks for an object and not for the listing O1 reads', () => {
  const a = objectArgs({ opt: '-O2', srcPath: 'x.c', objPath: 'x.o' });
  assert.ok(a.includes('-c'), 'the object step does not compile to an object');
  assert.ok(!a.includes('-S'), 'the object step asks for a listing');
  assert.ok(OBJECT_FLAGS.includes('-std=gnu11') && OBJECT_FLAGS.includes('-fcf-protection=none'),
    'the object step does not use the corpus run’s flags');
  assert.deepEqual(linkArgs({ objects: ['a.o', 'b.o'], exePath: 'p' }), ['a.o', 'b.o', '-o', 'p']);
});

test('the reader is handed six arguments, and a direct wipe is handed the reader’s own "no helper"', () => {
  const a = readWipeArgs({
    exePath: 'p', caller: 'handle', helper: null, bytes: 32, controlFn: 'vgctl_control', controlBytesCount: 32,
  });
  assert.equal(a.length, 7, 'read-wipe.py takes the script plus six arguments');
  assert.equal(a[0], READ_WIPE);
  assert.equal(a[3], NO_HELPER);
  assert.equal(a[4], '32');
  const withHelper = readWipeArgs({
    exePath: 'p', caller: 'handle', helper: 'secure_wipe', bytes: 32, controlFn: 'vgctl_control', controlBytesCount: 32,
  });
  assert.equal(withHelper[3], 'secure_wipe');
});

test('the O3 channel reads the disassembly of a LINKED program, never of an object file', () => {
  // The fabricated elimination this guards: in an unlinked object a call to an
  // undefined symbol prints as an offset inside the containing function, so
  // objdump_branches -- whose pattern excludes a `+` -- sees no call to memset
  // and the reading comes back ABSENT for a wipe that is plainly there.
  const src = read(join(LANE, 'lib/disasm.mjs'));
  assert.match(src, /FABRICATED ELIMINATION|fabricated elimination/i);
  assert.match(src, /linkArgs\(/);
  const readWipeCall = src.slice(src.indexOf('readWipeArgs({'));
  assert.match(readWipeCall.slice(0, 300), /exePath/, 'the reader is pointed at something other than the linked program');
});

test('the disassembly channel imports the lto-window reader rather than growing a second one', () => {
  const src = read(join(LANE, 'lib/disasm.mjs'));
  assert.match(src, /lto-window\/tools\/read-wipe\.py/);
  assert.ok(existsSync(READ_WIPE), 'read-wipe.py is gone');
  // No second objdump parser in this lane: there is one disassembly oracle in
  // this tree and read-wipe.py's own header says this lane is not going to be
  // the second.
  assert.ok(!/objdump_body|_OBJ_IMM_STORE|zero_stores/.test(src), 'this lane parses objdump output itself');
});

test('the appended control is the corpus run’s, imported and not re-written', () => {
  const src = read(join(LANE, 'lib/disasm.mjs'));
  assert.match(src, /import \{ CONTROL, FLAGS \} from '\.\.\/\.\.\/ai-generated\/lib\/ablation-cell\.mjs'/);
  assert.ok(!src.includes('vgctl_control'), 'disasm.mjs spells the control function name instead of importing it');
});

// -------------------------------------------------------- the live O1 column --

test('driftOf has three answers, and "not recomputed" is one of them', () => {
  assert.equal(driftOf('WIPE_SURVIVED', 'WIPE_SURVIVED'), DRIFT.SAME);
  assert.equal(driftOf('WIPE_SURVIVED', 'WIPE_ELIMINATED'), DRIFT.MOVED);
  // The important one: a run that did not recompute must not read as a run in
  // which nothing moved.
  assert.equal(driftOf('WIPE_SURVIVED', null), DRIFT.NOT_RECOMPUTED);
  assert.equal(driftOf('WIPE_SURVIVED', undefined), DRIFT.NOT_RECOMPUTED);
});

test('the drift summary lists what moved by id, never only a count', () => {
  const d = summariseDrift([
    { id: 'b', cc: 'gcc-13', opt: '-O2', tracked: 'WIPE_SURVIVED', live: 'WIPE_ELIMINATED' },
    { id: 'a', cc: 'gcc-13', opt: '-O2', tracked: 'WIPE_SURVIVED', live: 'WIPE_SURVIVED' },
  ]);
  assert.equal(d.total, 2);
  assert.equal(d.byDrift[DRIFT.MOVED], 1);
  assert.deepEqual(d.moved.map((m) => m.id), ['b']);
  assert.match(d.meaning, /tracked O1 is what the table grades/);
});

test('the live column never becomes the graded one, and never reaches data/', () => {
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  // The table is built from `pairs`, whose `o1` comes from the tracked index.
  assert.match(runner, /o1: row \? o1Of\(row\) : null/);
  // The record is built without the live column; the report carries it.
  const recordCall = runner.slice(runner.indexOf('buildRecord({'), runner.indexOf('writeRecord('));
  assert.ok(!/liveO1|liveCells|drift/.test(recordCall), 'the tracked record carries the live O1 column');
  assert.match(runner, /liveO1: args\.liveO1 \?/, 'the report does not carry the live column');
});

test('the live recomputation goes through the shared oracle, not a copy of it', () => {
  const src = read(join(LANE, 'lib/liveo1.mjs'));
  assert.match(src, /from '\.\.\/\.\.\/ai-generated\/lib\/ablation-cell\.mjs'/);
  for (const fn of ['wipeSpans', 'ablateSpans', 'compile', 'verdictOf', 'CONTROL']) {
    assert.ok(src.includes(fn), `lib/liveo1.mjs no longer uses ${fn}`);
  }
  // And it does not open the frozen rows at all, in either direction.
  assert.ok(!/r2-build-rows|ROWS_PATH/.test(src), 'lib/liveo1.mjs touches the tracked rows');
});

// ------------------------------------------------ the runner refuses the pairings --

test('the runner refuses --second-oracle O2 with a driver that cannot load the plugin', () => {
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  assert.match(runner, /defaultSecondOracle/);
  assert.match(runner, /does not load it/);
  // The refusal is conditioned on the ORACLE, not merely on "the pairing is not
  // the default": an impossibility and a preference must not be refused by one
  // line, which is how the preference below came to be enforced as though it
  // were an impossibility.
  assert.match(runner, /args\.secondOracle === 'O2' && defaultSecondOracle\(cc\) !== 'O2'/);
  // And the default follows the vendor, so `--cc gcc-13` no longer runs a
  // plugin channel that produces a table of BROKEN_MEASUREMENT. Spelled once, in
  // lib/record.mjs, because writeDataRefusals applies the same rule.
  assert.match(read(join(LANE, 'lib/record.mjs')), /clang.*\? 'O2' : 'O3'/);
});

test('O3 ON CLANG IS ALLOWED -- the refusal that was a preference, and the one that is not', () => {
  // RECONSIDERED. `--second-oracle O3 --cc clang-18` was refused on the ground
  // that the pass observer "says more than a reading of the finished program",
  // which is a preference between instruments and not an obstacle. There is no
  // obstacle: `objdump_fill.py` matches x86-64 disassembly that neither vendor
  // has a monopoly on, `lib/disasm.mjs` builds and links with whatever `--cc`
  // names and stubs the symbols the LINKER reported, and `lib/bufferbytes.mjs`
  // probes with `_Static_assert` under `-fsyntax-only`, which clang has. And the
  // refusal cost this lane the cheapest validation its newest instrument has: a
  // three-way reading on one vendor, over cells O2 has already answered.
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  assert.ok(!/the disassembly reader is the gcc-side oracle/.test(runner),
    'the runner still refuses O3 on clang on the ground that the other instrument says more');
  assert.ok(!/says more than a reading of the finished program/.test(runner), 'the preference is still enforced');
  assert.match(runner, /THREE-WAY reading/, 'the run says nothing about what these columns are');

  // Nothing in the O3 channel or the byte-count read-out is gcc-only, which is
  // the claim the allowance rests on: no vendor name appears in either of the
  // two modules an O3 run goes through, outside a comment.
  for (const rel of ['lib/disasm.mjs', 'lib/bufferbytes.mjs']) {
    const code = read(join(LANE, rel))
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(?:^|\s)\/\/[^\n]*/g, '');
    assert.ok(!/\bgcc\b/.test(code), `${rel} names gcc in code, so the O3 channel is not vendor-neutral after all`);
  }
});

test('what O3-on-clang may NOT do is write the record, and the reason is the file name', () => {
  // The one real obstacle, and it is an obstacle to the RECORD rather than to
  // the run: `dataFileName` keys on the vendor alone, so an O3 run on clang
  // would be written over `oracle-agreement-clang-18.json` -- the O2 record that
  // is this lane's measured result -- under a name that says neither.
  const base = { ccs: ['clang-18'], opts: ['-O0', '-O2'], write: true, observer: null, diagnoseCallSites: true };
  const refusals = writeDataRefusals({ ...base, secondOracle: 'O3' });
  assert.ok(refusals.some((x) => /would be written over the O2 record of the same vendor/.test(x)),
    'an O3 run on clang is allowed to overwrite the O2 record');
  // And the default pairing is not refused by that rule.
  assert.deepEqual(
    writeDataRefusals({ ...base, secondOracle: 'O2', observer: '/x/libPropertyObserver.so' })
      .filter((x) => /written over the/.test(x)),
    [],
    'the vendor’s own second oracle is refused its own record',
  );
  assert.deepEqual(
    writeDataRefusals({ ccs: ['gcc-13'], opts: ['-O0', '-O2'], write: true, observer: null, secondOracle: 'O3' })
      .filter((x) => /written over the/.test(x)),
    [],
    'a gcc O3 run is refused the record slot that is its own',
  );
});

test('an O3 run is refused the call-site diagnosis, which is an O2 question', () => {
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  assert.match(runner, /--diagnose-callsites with --second-oracle O3/);
});

test('the apparatus check exists, discriminates, and fails rather than skipping', () => {
  const tool = join(LANE, 'tools/check-o3-apparatus.mjs');
  assert.ok(existsSync(tool), 'there is no positive control for the O3 channel');
  const src = read(tool);
  // Both halves of the pair, and the refusal to accept them reading the same.
  // The two expected words live in `../lib/fixtures.mjs` -- so that the compiler-
  // free suite can check the fixtures they belong to -- and the check reads them
  // from there rather than spelling them, which is what this asserts.
  assert.match(src, /APPARATUS_FIXTURES/);
  const fx = read(join(LANE, 'lib/fixtures.mjs'));
  assert.match(fx, /expect: 'PRESENT'/);
  assert.match(fx, /expect: 'ABSENT'/);
  // The conclusion moved into `lib/fixtures.mjs` so that the compiler-free suite
  // can hand it a mutilated fixture set and watch it refuse; the tool draws no
  // conclusion of its own. See `../test/fixtures.test.mjs`.
  assert.match(fx, /not discriminating on this host/);
  assert.match(src, /apparatusProblems\(readings\)/);
  // The control is read before the subject is graded, and a fallen one is exit 5.
  assert.match(src, /control !== 'PRESENT'[\s\S]{0,200}die\(5/);
  assert.match(src, /die\(3,/);
  assert.ok(!/\bskip\b/i.test(src), 'the apparatus check skips instead of exiting');
});

// ------------------------------------------- the reader's own control per cell --
//
// The fabrication these guard: `objdump_fill.py` recognises a vector register
// zeroed against itself and stored, an immediate zero stored, and a call to
// `memset` / `__memset_chk`, AND NOTHING ELSE. `explicit_bzero(token, 32)` is a
// call to a symbol not on that list, so the reading is `ABSENT` for a wipe that
// is plainly in the program -- and `ABSENT` is O3's GRADABLE word, so graded it
// becomes an elimination manufactured out of a symbol list, on exactly the cells
// where O1 says the wipe survived.

test('O3 reads every cell at -O0 first, before the cell’s own level -- what that qualifies is below', () => {
  const src = read(join(LANE, 'lib/disasm.mjs'));
  assert.match(src, /export const READER_CONTROL_OPT = '-O0'/);
  // The control read comes first in the function, textually and in execution.
  const body = src.slice(src.indexOf('export async function observeCellO3'));
  const ctlAt = body.indexOf('await one(READER_CONTROL_OPT)');
  const ownAt = body.indexOf('await one(opt)');
  assert.ok(ctlAt > 0, 'the reader control is never taken');
  assert.ok(ownAt > ctlAt, 'the cell is read at its own level before the reader control');
  // And the blind case returns a REASON, never a state.
  assert.match(body, /ctl\.finalState !== 'PRESENT'[\s\S]{0,300}O3_READER_BLIND/);
});

test('a wipe the reader cannot see at -O0 leaves the denominator, never as an elimination', () => {
  const c = classifyPair(pair({
    o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
    o2: {
      finalState: 'NOT_OBSERVED',
      control: null,
      brokenReason: REASON.O3_READER_BLIND,
      brokenDetail: '-O0 reads ABSENT',
    },
  }), { vocab: O3_VOCAB });
  assert.equal(c.status, 'EXCLUDED');
  assert.equal(c.reason, REASON.O3_READER_BLIND);
  assert.equal(c.kind, KIND.BROKEN_MEASUREMENT);
  assert.equal(c.detail, '-O0 reads ABSENT');
  // The cell contributes nothing to either marginal.
  const t = tabulate([{ ...pair(), o2: { finalState: 'NOT_OBSERVED', control: null, brokenReason: REASON.O3_READER_BLIND } }],
    { vocab: O3_VOCAB });
  assert.equal(above(t).den, 0);
  assert.equal(above(t).excluded.total, 1);
});

test('the reader-blind word is the lane’s and names the instrument, not the wipe', () => {
  assert.equal(REASON.O3_READER_BLIND, 'o3-reader-blind-to-this-wipe');
  assert.ok(REASON_WORDS.includes(REASON.O3_READER_BLIND));
  // BROKEN_MEASUREMENT and not NOT_COMPARABLE: this is a statement about the
  // apparatus. NOT_COMPARABLE would claim both instruments answered.
  assert.equal(kindOfWord('NOT_OBSERVED', O3_VOCAB), KIND.NO_READING);
});

test('the control level is the one the tracked rows show no elimination at', () => {
  // The premise the reader control rests on, re-derived from the frozen record
  // rather than asserted: at -O0 the corpus has never recorded an elimination,
  // so a wipe the reader cannot see there is a wipe the reader cannot see.
  const rows = JSON.parse(read(join(LANE, '../ai-generated/data/r2-build-rows.json')));
  for (const cc of ['gcc-13', 'clang-18']) {
    const at0 = rows.filter((r) => r.fam === 'erasure' && r.cc === cc && r.opt === '-O0');
    assert.ok(at0.length > 0, `no ${cc} erasure rows at -O0`);
    assert.equal(at0.filter((r) => r.verdict === 'WIPE_ELIMINATED').length, 0,
      `${cc} now records an elimination at -O0; the reader control's premise has moved`);
  }
});

// --------------------- what the -O0 control qualifies, and what it does not --
//
// THE CONTROL THAT COULD NOT FAIL. `lib/disasm.mjs` called the `-O0` reading
// "the reader's positive control for this cell", for every cell, in its header
// and in the README. For a cell AT `-O0` that is not a control at all: the
// cell's level and the control's level are one level, so it is one build and
// one read returned twice -- and `observeCellO3` cannot return a `-O0` reading
// unless that read was PRESENT, because anything else becomes
// `o3-reader-blind-to-this-wipe` first. No `-O0` cell can therefore be graded
// ABSENT, and the control is guaranteed to hold on every one that exists.
//
// The second half is subtler and survives above `-O0`: `objdump_fill`'s three
// recognizers are three separate matchers, and a `memset(...)` wipe is usually a
// CALL at `-O0` and usually INLINED STORES at `-O2`. Recognising the call says
// nothing about the store matcher, which is the branch an `-O2` reading depends
// on -- so the control cannot detect the reader blindness that threatens the
// measurement it is supposed to qualify.
//
// Neither is fixed by deleting the control: it does establish one thing, and it
// does close the `explicit_bzero` fabrication. Both are recorded per reading, by
// a pure function, so the record carries the control's reach instead of a header
// carrying one sentence for the whole corpus.

test('recognizerBranch names WHICH of the reader’s three matchers produced a reading', () => {
  assert.equal(recognizerBranch({ stores: 0, memsetCalls: 1 }), BRANCH.MEMSET_CALL);
  assert.equal(recognizerBranch({ stores: 2, memsetCalls: 0 }), BRANCH.STORE);
  assert.equal(recognizerBranch({ stores: 2, memsetCalls: 1 }), BRANCH.BOTH);
  // A reading that recognised nothing is NONE and not null: the instrument ran
  // and matched none of its three shapes, which is a different fact from there
  // being no reading to take a branch from.
  assert.equal(recognizerBranch({ stores: 0, memsetCalls: 0 }), BRANCH.NONE);
  assert.equal(recognizerBranch(null), null);
  assert.equal(recognizerBranch(undefined), null);
});

test('AT THE CONTROL’S OWN LEVEL THERE IS NO CONTROL, and the reading says so', () => {
  const q = qualificationOf({
    cellOpt: READER_CONTROL_OPT,
    controlFill: { stores: 0, memsetCalls: 1 },
    subjectFill: { stores: 0, memsetCalls: 1 },
  });
  assert.equal(q.independent, false, 'a cell at the control level is recorded as independently controlled');
  // And it establishes NOTHING -- not "the reader can see this wipe", which is
  // the sentence it would otherwise be read as making.
  assert.equal(q.establishes, null, 'the same build read twice is recorded as having established something');
  assert.ok(q.doesNotEstablish.includes(SAME_BUILD_LIMITATION));
  assert.match(SAME_BUILD_LIMITATION, /cannot fail/);
  assert.match(SAME_BUILD_LIMITATION, /no cell here can be graded ABSENT/);
});

test('above the control’s level it is independent, and says which branch it exercised', () => {
  const q = qualificationOf({
    cellOpt: '-O2',
    controlFill: { stores: 0, memsetCalls: 1 },
    subjectFill: { stores: 2, memsetCalls: 0 },
  });
  assert.equal(q.independent, true);
  assert.equal(q.establishes, 'the reader recognised this wipe in the -O0 build');
  assert.equal(q.controlBranch, BRANCH.MEMSET_CALL);
  assert.equal(q.subjectBranch, BRANCH.STORE);
  // THE BRANCH-RELEVANCE HALF: the control read a call and the subject reading
  // came through the store matcher, so this control exercised none of the code
  // the subject's reading rests on.
  assert.equal(q.branchRelevant, false, 'a control on one matcher is recorded as qualifying another');
  assert.ok(q.doesNotEstablish.some((x) => /was not the branch the control exercised/.test(x)));
  // The same branch on both sides is relevant, and `both` on either side covers
  // the other.
  const same = qualificationOf({ cellOpt: '-O2', controlFill: { stores: 2 }, subjectFill: { stores: 3 } });
  assert.equal(same.branchRelevant, true);
  assert.deepEqual(same.doesNotEstablish, []);
  assert.equal(qualificationOf({ cellOpt: '-O2', controlFill: { stores: 1, memsetCalls: 1 }, subjectFill: { stores: 3 } }).branchRelevant, true);
});

test('ON AN ABSENT READING THE CONTROL QUALIFIES NO BRANCH AT ALL -- the cell that matters most', () => {
  // The `ABSENT` reading is the one that becomes an elimination. It recognised
  // no fill, so it fired no recognizer: there is no branch the control could
  // have exercised, and the reader blindness that would have produced this
  // `ABSENT` is exactly what the control cannot speak to.
  const q = qualificationOf({
    cellOpt: '-O2',
    controlFill: { stores: 0, memsetCalls: 1 },
    subjectFill: { stores: 0, memsetCalls: 0 },
  });
  assert.equal(q.subjectBranch, BRANCH.NONE);
  assert.equal(q.branchRelevant, false, 'a reading that fired no recognizer is recorded as branch-qualified');
  assert.ok(q.doesNotEstablish.includes(NO_BRANCH_LIMITATION));
  assert.match(NO_BRANCH_LIMITATION, /not that it would have recognised the form the optimiser left behind/);
});

test('every reading observeCellO3 returns carries the qualification, on all four paths', () => {
  const src = read(join(LANE, 'lib/disasm.mjs'));
  const body = src.slice(src.indexOf('export async function observeCellO3'));
  // The four returns that carry a `readerControl`: control lost, reader blind,
  // the cell at the control level, and the cell above it. A path that dropped
  // the qualification would be a reading whose control's reach is unrecorded.
  const withControl = (body.match(/readerControl: \{/g) || []).length;
  const withQualification = (body.match(/qualification: qualificationOf\(/g) || []).length;
  assert.equal(withControl, 4, 'observeCellO3 no longer has four readings that carry a reader control');
  assert.equal(withQualification, withControl,
    `${withControl} readings carry a reader control and ${withQualification} carry its qualification`);
});

test('the file and the README no longer call it the positive control FOR THE CELL', () => {
  // The claim that was too strong, as a grep over both places it was made. The
  // apparatus check's `kept` fixture is still a positive control -- for the HOST
  // -- and that wording is untouched; what is refused here is the per-cell claim.
  const src = read(join(LANE, 'lib/disasm.mjs'));
  assert.ok(!/POSITIVE CONTROL FOR THIS CELL/.test(src), 'lib/disasm.mjs still claims a positive control per cell');
  assert.ok(!/reader's positive control \*?for that cell\*?/.test(README),
    'the README still claims the -O0 reading is the positive control for that cell');
  // And what replaced it is stated rather than merely removed: both limitations
  // are named in the README, under a heading a reader can find.
  assert.match(README, /Exactly what that control qualifies, and what it does not/);
  assert.match(README, /independent: false/);
  assert.match(README, /branchRelevant/);
  assert.match(README, /A check that cannot fail is not a check/);
});

test('the reader control is not optional and has no flag that turns it off', () => {
  const src = read(join(LANE, 'lib/disasm.mjs'));
  const runner = read(join(LANE, 'run-oracle-agreement.mjs'));
  assert.ok(!/readerControl\s*=\s*(false|true)/.test(src), 'the reader control is a parameter');
  assert.ok(!/--no-reader-control|--skip-reader-control/.test(runner), 'the runner can turn the reader control off');
  assert.match(src, /not optional/);
});

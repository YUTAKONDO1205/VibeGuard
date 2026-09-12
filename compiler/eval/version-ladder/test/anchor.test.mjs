/**
 * The anchor join, and the runner's pure helpers.
 *
 * Two things are tested against the real tracked rows rather than a fixture,
 * because a fixture cannot go stale in the way that matters here: that the smoke
 * subjects still exist in compiler/eval/ai-generated/data/r2-build-rows.json,
 * and that the anchor compilers are still the compilers those rows were measured
 * with. If either stops being true, this lane's anchor would check nothing and
 * would still print a pass.
 *
 * No compiler is run here.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  anchorIndex, anchorDisagreements, disagreementLine, unanchorableIds, cellKey,
  vacuousAnchorProblem, anchorProblem, ANCHOR_CCS,
} from '../lib/anchor.mjs';
import { ANCHOR_CC, ALL_OPTS, LADDER } from '../lib/ladder.mjs';
import { SMOKE_IDS, parseArgs, allRungs, outIsInsideRepo, ladderRow, appearancesFrom, spellingIn, sweepCoverage } from '../run-version-ladder.mjs';
import { CONTROL_EFFECT } from '../../ai-generated/lib/ablation-cell.mjs';
import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '../../../..');
const TRACKED = JSON.parse(readFileSync(join(REPO, 'compiler/eval/ai-generated/data/r2-build-rows.json'), 'utf8'));
const INDEX = anchorIndex(TRACKED);

// ----------------------------------------------------------- the index -------

test('anchorIndex holds only erasure cells; a NO_WIPE_WRITTEN row is not a cell', () => {
  const none = TRACKED.filter((r) => r.kind === 'none');
  assert.ok(none.length > 0, 'the tracked rows should still contain kind:none rows');
  for (const r of none) {
    // kind:none rows carry no cc/opt at all, so they cannot be keyed; assert the
    // index did not acquire them under any (cc, opt) either.
    for (const cc of ANCHOR_CCS) for (const opt of ALL_OPTS) {
      assert.equal(INDEX.has(cellKey(r.id, cc, opt)), false, `${r.id} ${cc} ${opt}`);
    }
  }
});

test('the anchor compilers are the compilers the tracked rows were measured with', () => {
  const ccs = [...new Set(TRACKED.filter((r) => r.kind === 'erasure').map((r) => r.cc))].sort();
  assert.deepEqual(ccs, [...ANCHOR_CCS].sort());
  assert.deepEqual([...ANCHOR_CCS].sort(), [ANCHOR_CC.clang, ANCHOR_CC.gcc].sort());
});

test('every smoke subject has a tracked cell at every level under both anchor compilers', () => {
  assert.deepEqual(unanchorableIds(SMOKE_IDS, INDEX, { opts: ALL_OPTS }), []);
  for (const id of SMOKE_IDS) for (const cc of ANCHOR_CCS) for (const opt of ALL_OPTS) {
    assert.ok(INDEX.has(cellKey(id, cc, opt)), `${id} ${cc} ${opt}`);
  }
});

test('the smoke set still spans what it was chosen to span: an elimination, a vendor split, and two files that never lose the wipe', () => {
  const v = (id, cc, opt) => INDEX.get(cellKey(id, cc, opt));
  // an early elimination on both vendors
  assert.equal(v('haiku_E_aeskey_r1', 'clang-18', '-O1'), 'WIPE_ELIMINATED');
  assert.equal(v('haiku_E_aeskey_r1', 'gcc-13', '-O1'), 'WIPE_ELIMINATED');
  // -O1 splitting the two vendors: without a case like this the ladder could not
  // show that a first appearance is a fact about one vendor's ladder, not two.
  assert.equal(v('fable_N_hmackey_r3', 'clang-18', '-O1'), 'WIPE_SURVIVED');
  assert.equal(v('fable_N_hmackey_r3', 'gcc-13', '-O1'), 'WIPE_ELIMINATED');
  // the negative subjects: if a rung eliminates these, the finding is about the
  // rung and not about the file, and that is what makes the lane falsifiable.
  for (const id of ['opus_N_pinpad_r2', 'haiku_S_pwverify_r1']) {
    for (const cc of ANCHOR_CCS) for (const opt of ALL_OPTS) {
      assert.equal(v(id, cc, opt), 'WIPE_SURVIVED', `${id} ${cc} ${opt}`);
    }
  }
});

// ------------------------------------------------------- the disagreements ---

const row = (id, cc, opt, verdict) => ({ id, cc, opt, verdict });

test('a lane row that reproduces the tracked verdict agrees', () => {
  const rows = [row('haiku_E_aeskey_r1', 'clang-18', '-O1', 'WIPE_ELIMINATED')];
  const a = anchorDisagreements(rows, INDEX);
  assert.deepEqual(a, { checked: 1, agreed: 1, disagreements: [] });
});

test('a lane row that contradicts the tracked verdict is a disagreement', () => {
  const rows = [row('haiku_E_aeskey_r1', 'clang-18', '-O1', 'WIPE_SURVIVED')];
  const a = anchorDisagreements(rows, INDEX);
  assert.equal(a.agreed, 0);
  assert.deepEqual(a.disagreements, [{ id: 'haiku_E_aeskey_r1', cc: 'clang-18', opt: '-O1', lane: 'WIPE_SURVIVED', tracked: 'WIPE_ELIMINATED' }]);
});

test('an anchor row with NO tracked cell is a disagreement, not a pass -- "0 of 0 agree" must not read as clean', () => {
  const rows = [row('no_such_file_r9', 'gcc-13', '-O2', 'WIPE_SURVIVED')];
  const a = anchorDisagreements(rows, INDEX);
  assert.equal(a.checked, 1);
  assert.equal(a.agreed, 0);
  assert.equal(a.disagreements[0].tracked, null);
  assert.match(disagreementLine(a.disagreements[0]), /no tracked cell/);
});

test('a non-anchor rung is not checked and not counted: there is nothing tracked to check it against', () => {
  const rows = [
    row('haiku_E_aeskey_r1', 'clang-15', '-O1', 'WIPE_SURVIVED'),
    row('haiku_E_aeskey_r1', 'gcc-14', '-O1', 'WIPE_ELIMINATED'),
    row('haiku_E_aeskey_r1', 'clang-18', '-O1', 'WIPE_ELIMINATED'),
  ];
  const a = anchorDisagreements(rows, INDEX);
  assert.deepEqual(a, { checked: 1, agreed: 1, disagreements: [] });
});

// ------------------------------------------------------ the vacuous anchor ---
//
// `anchorDisagreements` was always right about the cells it was given. What the
// lane shipped without was anything that asked whether it had been given any:
// {checked: 0, agreed: 0, disagreements: []} printed "0/0 cells reproduce the
// tracked verdict" and exited 0. These two functions are what the exit code is
// decided from now, and test/exit-codes.test.mjs runs the runner to prove the
// wiring reaches them.

test('vacuousAnchorProblem: no anchor rung obtained is refused, with the rungs named', () => {
  const p = vacuousAnchorProblem({ obtainedCcs: ['clang-15', 'clang-16', 'gcc-14'], anchorableIds: ['haiku_E_aeskey_r1'] });
  assert.match(p, /no anchor rung was obtained/);
  assert.match(p, /clang-18, gcc-13/);
  assert.match(p, /"0\/0 agree" would pass vacuously/);
});

test('vacuousAnchorProblem: an anchor rung with nothing anchorable to measure is refused too', () => {
  // This lane's own subjects/*.c are not in the tracked r2 rows. A run made
  // only of them obtains clang-18 and still compares nothing.
  const p = vacuousAnchorProblem({ obtainedCcs: ['clang-18', 'gcc-13'], anchorableIds: [] });
  assert.match(p, /no selected subject has tracked rows to be anchored against/);
});

test('vacuousAnchorProblem: one anchor rung and one anchorable subject is the only clean case', () => {
  assert.equal(vacuousAnchorProblem({ obtainedCcs: ['clang-15', 'gcc-13'], anchorableIds: ['haiku_E_aeskey_r1'] }), null);
  assert.equal(vacuousAnchorProblem({ obtainedCcs: [ANCHOR_CC.clang], anchorableIds: ['x'] }), null);
  // and an empty call is not a pass
  assert.ok(vacuousAnchorProblem({}));
  assert.ok(vacuousAnchorProblem());
});

test('anchorProblem: checked 0 is a failure, not a pass with nothing in it', () => {
  const p = anchorProblem({ checked: 0, agreed: 0, disagreements: [] });
  assert.match(p, /NOT ANCHORED/);
  assert.match(p, /no cell was compared/);
  // the shapes a caller could hand it if the join were removed entirely
  assert.ok(anchorProblem(null));
  assert.ok(anchorProblem({ agreed: 0, disagreements: [] }));
});

test('anchorProblem: a disagreement fails, and a comparison where every cell agreed is the pass', () => {
  assert.match(anchorProblem({ checked: 60, agreed: 59, disagreements: [{ id: 'x' }] }), /1 of 60 anchor cell\(s\) do not reproduce/);
  assert.equal(anchorProblem({ checked: 60, agreed: 60, disagreements: [] }), null);
  assert.equal(anchorProblem({ checked: 1, agreed: 1, disagreements: [] }), null);
});

test('disagreementLine prints the two verdicts and nothing else about the machine', () => {
  const line = disagreementLine({ id: 'x', cc: 'gcc-13', opt: '-Os', lane: 'WIPE_ELIMINATED', tracked: 'WIPE_SURVIVED' });
  assert.equal(line, '  x gcc-13 -Os: this lane WIPE_ELIMINATED, tracked WIPE_SURVIVED');
});

// --------------------------------------------------- the runner's pure bits --

test('parseArgs requires --out and refuses an --opts the find step never used', () => {
  assert.match(parseArgs([]).error, /--out/);
  assert.match(parseArgs(['--out', '/x', '--opts', '-Ofast']).error, /-Ofast/);
  assert.match(parseArgs(['--out', '/x', '--conc', '0']).error, /--conc/);
  assert.match(parseArgs(['--out', '/x', '--nope']).error, /unknown argument/);
  assert.match(parseArgs(['--out']).error, /needs a value/);
  const ok = parseArgs(['--out', '/x/y', '--ccs', 'clang-18,gcc-13', '--opts', '-O1,-O2', '--conc', '2', '--write-data']);
  assert.deepEqual(ok.ccs, ['clang-18', 'gcc-13']);
  assert.deepEqual(ok.opts, ['-O1', '-O2']);
  assert.equal(ok.conc, 2);
  assert.equal(ok.writeData, true);
  // defaults: this lane's own subjects are in, and the anchor is the tracked rows
  assert.equal(ok.noSubjects, false);
  assert.equal(ok.rows, null);
  assert.equal(parseArgs(['--out', '/x', '--no-subjects', '--rows', '/r.json']).noSubjects, true);
  assert.equal(parseArgs(['--out', '/x', '--rows', '/r.json']).rows, '/r.json');
});

test('every subjects/*.c names its target function in the file, so the two cannot drift apart', () => {
  // The runner refuses a subject without this marker (exit 4). Checked here as
  // well because the failure it prevents -- measuring a function nobody named --
  // is silent: funcBodySpan returns null and wipeSpans falls back to its older,
  // name-gated rule rather than erroring.
  const dir = join(REPO, 'compiler/eval/version-ladder/subjects');
  const names = readdirSync(dir).filter((f) => f.endsWith('.c')).sort();
  assert.ok(names.length >= 2, 'the lane needs at least one removable and one non-removable hand-written subject');
  for (const f of names) {
    const src = readFileSync(join(dir, f), 'utf8');
    const m = /^\/\*\s*VG-LADDER-TARGET:\s*([A-Za-z_]\w*)\s*\*\/\s*$/m.exec(src);
    assert.ok(m, `${f} has no VG-LADDER-TARGET marker`);
    // and the function it names is actually defined in the file
    assert.match(src, new RegExp(`\\b${m[1]}\\s*\\([^;{)]*\\)\\s*\\n?\\s*\\{`), `${f} does not define ${m[1]}`);
  }
});

test('--out inside the repository is refused: measurement outputs live on the side that makes them', () => {
  assert.equal(outIsInsideRepo(join(REPO, 'compiler/eval/version-ladder/out'), REPO), true);
  assert.equal(outIsInsideRepo(REPO, REPO), true);
  assert.equal(outIsInsideRepo(join(REPO, '..', 'vg-lab'), REPO), false);
});

test('allRungs is every declared rung of both ladders, and each is a name the guard accepts', () => {
  const rungs = allRungs();
  assert.equal(rungs.length, LADDER.clang.length + LADDER.gcc.length);
  assert.ok(rungs.includes('clang-18'));
  assert.ok(rungs.includes('gcc-13'));
  assert.equal(new Set(rungs).size, rungs.length);
});

test('ladderRow carries integers, no path, and keeps labelsOnly out of the verdict', () => {
  const r = ladderRow({
    id: 'a', fn: 'f', vendor: 'gcc', cc: 'gcc-13', major: 13, opt: '-O2', nSpans: 2, idiom: 'removable',
    namedSecret: true, scoped: true, cell: { control: 'PRESENT', control_via: 'oracle', verdict: 'WIPE_SURVIVED' },
    labelsOnly: true, spellingSeen: 'memset',
  });
  assert.equal(r.verdict, 'WIPE_SURVIVED');
  assert.equal(r.labelsOnly, true);
  assert.ok(Number.isInteger(r.n_spans) && Number.isInteger(r.major));
  // the runner's own provenance scan, applied to the row it is about to write
  assert.deepEqual(absolutePathHits(JSON.stringify(r)), []);
});

test('a cell with no reading carries no control, and never a fabricated one', () => {
  const r = ladderRow({
    id: 'a', fn: 'f', vendor: 'clang', cc: 'clang-16', major: 16, opt: '-O2', nSpans: 1, idiom: 'removable',
    namedSecret: false, scoped: true, cell: { verdict: 'COMPILE_ERROR' }, labelsOnly: null, spellingSeen: null,
  });
  assert.equal(r.control, null);
  assert.equal(r.control_via, null);
  assert.equal(r.verdict, 'COMPILE_ERROR');
});

test('appearancesFrom keys by (file, level, vendor) and ignores a rung off the declared ladder', () => {
  const rows = [
    ladderRow({ id: 'a', fn: 'f', vendor: 'clang', cc: 'clang-15', major: 15, opt: '-O2', nSpans: 1, idiom: 'removable', namedSecret: true, scoped: true, cell: { verdict: 'WIPE_SURVIVED' }, labelsOnly: null, spellingSeen: null }),
    ladderRow({ id: 'a', fn: 'f', vendor: 'clang', cc: 'clang-16', major: 16, opt: '-O2', nSpans: 1, idiom: 'removable', namedSecret: true, scoped: true, cell: { verdict: 'WIPE_ELIMINATED' }, labelsOnly: null, spellingSeen: null }),
    // a rung that is not on the declared ladder must not become a cell of it
    ladderRow({ id: 'a', fn: 'f', vendor: 'clang', cc: 'clang-14', major: 14, opt: '-O2', nSpans: 1, idiom: 'removable', namedSecret: true, scoped: true, cell: { verdict: 'WIPE_ELIMINATED' }, labelsOnly: null, spellingSeen: null }),
  ];
  const app = appearancesFrom(rows, { opts: ['-O2'], ids: ['a'] });
  assert.equal(app.length, 1);
  assert.equal(app[0].vendor, 'clang');
  assert.equal(app[0].opt, '-O2');
  assert.deepEqual(Object.keys(app[0].cells).map(Number).sort((x, y) => x - y), [15, 16]);
  // 17..20 were not obtained, and they are ABOVE the first elimination, so they
  // do not stop the answer; 15 was obtained and kept the wipe.
  assert.equal(app[0].status, 'FIRST_AT');
  assert.equal(app[0].version, 16);
});

test('spellingIn is built from the declared effect symbol list, not a literal of its own', () => {
  // compiler/schema/effect-symbol-lists.test.mjs fails on a new literal list;
  // this reads CONTROL_EFFECT.symbols, so there is no tenth copy to register.
  const [plain, chk] = CONTROL_EFFECT.symbols;
  assert.equal(spellingIn(`\tcall\t${plain}\n`), plain);
  assert.equal(spellingIn(`\tcall\t${chk}\n`), chk);
  assert.equal(spellingIn('\tcall\tsomething_else\n'), 'none');
  assert.equal(spellingIn(null), null);
});

// --- the corpus-sweep caveat -------------------------------------------------
//
// The report used to print "NOT measured: the corpus-scale sweep" on every run,
// including the run that had just swept the corpus. These four tests are the
// reason it cannot say that again, and they are written against the REAL tracked
// rows so that the sweep's size cannot drift away from what --ids removable
// expands to.

test('sweepCoverage counts the removable corpus the same way --ids removable expands it', () => {
  const expanded = [...new Set(TRACKED.filter((r) => r && r.kind === 'erasure' && r.idiom === 'removable').map((r) => r.id))];
  const all = expanded.map((id) => ({ id, anchorable: true }));
  const c = sweepCoverage(TRACKED, all);
  assert.equal(c.removableTotal, expanded.length);
  assert.equal(c.removableSwept, expanded.length);
  assert.equal(c.complete, true);
});

test('a selection out of the corpus is not complete, and says how far it got', () => {
  const expanded = [...new Set(TRACKED.filter((r) => r && r.kind === 'erasure' && r.idiom === 'removable').map((r) => r.id))];
  const c = sweepCoverage(TRACKED, expanded.slice(0, 6).map((id) => ({ id, anchorable: true })));
  assert.equal(c.removableSwept, 6);
  assert.equal(c.removableTotal, expanded.length);
  assert.equal(c.complete, false);
});

test("this lane's own subjects and the fixture never count towards the corpus sweep", () => {
  const expanded = [...new Set(TRACKED.filter((r) => r && r.kind === 'erasure' && r.idiom === 'removable').map((r) => r.id))];
  const withExtras = [
    ...expanded.map((id) => ({ id, anchorable: true })),
    { id: 'vl01_deadstore_memset', anchorable: false },
    { id: 'llvm-pass-fixture-erasure-target', anchorable: false },
  ];
  const c = sweepCoverage(TRACKED, withExtras);
  assert.equal(c.removableSwept, expanded.length);
  assert.equal(c.complete, true);
  // and non-anchorable subjects cannot make an empty run look complete either
  assert.equal(sweepCoverage(TRACKED, [{ id: 'vl01_deadstore_memset', anchorable: false }]).complete, false);
});

test('no rows means no sweep, never a vacuous complete', () => {
  assert.deepEqual(sweepCoverage([], []), { removableTotal: 0, removableSwept: 0, complete: false });
  assert.equal(sweepCoverage(undefined, undefined).complete, false);
});

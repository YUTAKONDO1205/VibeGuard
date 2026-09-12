/**
 * The two records this lane publishes, checked against what the README says
 * about them: `data/`, which --write-data puts in the tree, and the fortify
 * spelling probe, which is what the README's one negative observation rests on.
 *
 * Both exist because a sentence went stale here before. The README said `--out`
 * inside the repository is refused because measurement outputs "carry machine
 * paths and per-machine digests" -- while --write-data was copying per-machine
 * digests into data/ on purpose. The rule as stated was not the rule in force.
 * The prose is narrowed now; these tests hold the narrowed version to the file,
 * in both directions: the digests must still be there (they are what identifies
 * the run) and an absolute path must still not be.
 *
 * The probe half is the same problem in the other lane of the README: the
 * fortify observation was recorded with a command that could not have produced
 * the output beside it, so nobody could re-run it. Now it is a tool, and this
 * test runs the tool.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';
import { LADDER } from '../lib/ladder.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = resolve(HERE, '../data/version-ladder.json');
const SWEEP = resolve(HERE, '../data/version-ladder-sweep.json');
const PROBE = resolve(HERE, '../tools/fortify-spelling-probe.mjs');
const text = readFileSync(DATA, 'utf8');
const data = JSON.parse(text);

test('data/ carries the resolved compiler digests the README says it carries, and no path', () => {
  const obtained = data.manifest.versions.filter((v) => v.obtained);
  assert.ok(obtained.length >= 2, 'the recorded run should hold more than one rung');
  for (const v of obtained) {
    assert.match(String(v.resolvedSha256), /^[0-9a-f]{64}$/, `${v.cc} has no sha256 of the binary that ran`);
    assert.ok(v.resolvedBase && !v.resolvedBase.includes('/') && !v.resolvedBase.includes('\\'),
      `${v.cc} records ${JSON.stringify(v.resolvedBase)}, which is not a bare basename`);
  }
  // and the other half of the narrowed claim: a digest is recorded, a location
  // never is. The runner refuses to write either file otherwise (exit 5).
  assert.deepEqual(absolutePathHits(text), []);
  assert.doesNotMatch(text, /\/usr\/(bin|lib)/);
});

test('every appearance in data/ carries the transition word, and the counts are the ones the README quotes', () => {
  // If data/ is ever rewritten by a runner that does not know the word, this
  // fails rather than the file quietly losing the distinction between "the
  // elimination appeared between two rungs" and "it was already gone at the
  // bottom of the ladder".
  const app = data.appearances;
  assert.equal(app.length, 90);
  for (const a of app) {
    assert.ok(Object.prototype.hasOwnProperty.call(a, 'transition'), `${a.id} ${a.opt} ${a.vendor} has no transition field`);
    if (a.status === 'FIRST_AT') assert.ok(['observed', 'none-below'].includes(a.transition), `${a.id} ${a.transition}`);
    else assert.equal(a.transition, null);
  }
  const c = data.manifest.counting.appearances;
  assert.equal(c.firstAt, 38);
  assert.equal(c.firstAtObserved, 0);
  assert.equal(c.firstAtNoneBelow, 38);
  assert.equal(c.accountedFor, true);
  // the anchor's machine-readable verdict, null exactly when the run exited 0
  assert.equal(data.manifest.anchor.problem, null);
  assert.equal(data.manifest.anchor.checked, 60);
});

const gccRung = LADDER.gcc.map((m) => `gcc-${m}`).find((cc) => {
  const r = spawnSync(cc, ['--version'], { encoding: 'utf8', timeout: 30000 });
  return !r.error && r.status === 0;
});

test('the fortify probe shows the detector CAN see __memset_chk, which is what makes its absence a reading',
  { skip: gccRung ? false : 'needs a gcc rung of the declared ladder; none is installed here' }, () => {
    // Two compiles. The README's claim is that `__memset_chk` is absent from all
    // 495 cells because every subject wipes a compile-time-known length, not
    // because the lane cannot see it. That is only checkable by showing the
    // spelling appearing somewhere, so the probe builds the same wipe with a
    // length the compiler cannot fold.
    const r = spawnSync(process.execPath, [PROBE, '--ccs', gccRung, '--opts', '-O1'], { encoding: 'utf8', timeout: 120000 });
    assert.equal(r.status, 0, r.stderr);
    const row = r.stdout.split('\n').find((l) => l.includes(gccRung) && l.includes('-O1'));
    assert.ok(row, `no ${gccRung} -O1 row in:\n${r.stdout}`);
    const [, , constSize, runtime] = row.trim().split(/\s+/);
    assert.equal(runtime, '__memset_chk', `runtime-length wipe on ${gccRung} -O1 spelled ${runtime}\n${r.stdout}`);
    assert.notEqual(constSize, '__memset_chk', 'the constant-size wipe is the shape every subject here has');
  });

// --- the corpus sweep ---------------------------------------------------------
//
// data/version-ladder.json is the SMOKE record: six subjects, 495 cells. The
// sweep is the other thing this lane can be asked, and until 2026-09-12 it had
// never been run, so the README's own "NOT measured" list named it. It has been
// run now, and what is kept is the finding rather than the 3.1 MB of cells that
// produced it (see sweepRecord in the runner for why).
//
// These pins are the point of keeping it at all. A sweep record whose numbers
// are free to move is not evidence of anything; if a later run disagrees, the
// disagreement is the result and it should be read, not absorbed.

test('the sweep record is the whole removable corpus, and its accounting adds up', () => {
  const s = JSON.parse(readFileSync(SWEEP, 'utf8'));
  assert.equal(s.subjects, 133);
  assert.deepEqual(s.opts, ['-O0', '-O1', '-O2', '-O3', '-Os']);
  assert.equal(s.counting.versions.obtained, 11);
  assert.equal(s.counting.versions.skipped, 0);
  assert.equal(s.counting.cells, 7315);
  assert.equal(s.counting.cells, 133 * 11 * 5);
  // the three ways a ladder question can end, and nothing else
  const a = s.counting.appearances;
  assert.equal(a.asked, 1330);
  assert.equal(a.asked, 133 * 2 * 5);
  assert.equal(a.firstAtObserved + a.firstAtNoneBelow + a.never + a.undetermined, a.asked);
  assert.equal(a.undetermined, 0);
  assert.equal(a.accountedFor, true);
  assert.deepEqual(s.transitions, { 'never-eliminated': 497, 'none-below': 825, observed: 8 });
});

test('every cell of the sweep reached a wipe verdict -- no build failed and no ablation failed', () => {
  const s = JSON.parse(readFileSync(SWEEP, 'utf8'));
  // This is the one silent failure mode the sweep has. A COMPILE_ERROR on an
  // ANCHOR rung shows up as an anchor disagreement and exits 2; on any of the
  // other nine rungs nothing would notice, and a timeout would quietly become a
  // "the wipe disappeared here" that no compiler ever performed.
  assert.deepEqual(Object.keys(s.verdictTotals).sort(), ['WIPE_ELIMINATED', 'WIPE_SURVIVED']);
  assert.equal(s.verdictTotals.WIPE_SURVIVED + s.verdictTotals.WIPE_ELIMINATED, 7315);
  assert.equal(s.verdictTotals.WIPE_ELIMINATED, 4557);
});

test('the sweep is anchored on every one of its corpus questions, not on a subset', () => {
  const s = JSON.parse(readFileSync(SWEEP, 'utf8'));
  assert.equal(s.anchor.checked, 1330);
  assert.equal(s.anchor.agreed, 1330);
  assert.deepEqual(s.anchor.disagreements, []);
  assert.equal(s.anchor.problem, null);
  // 0/0 agreeing is how this lane once shipped a pass; the pin is on the count.
  assert.ok(s.anchor.checked > 0);
});

test('the eight observed transitions are named, and they are the only ones the ladder saw', () => {
  const s = JSON.parse(readFileSync(SWEEP, 'utf8'));
  assert.equal(s.observed.length, 8);
  assert.equal(s.observed.length, s.counting.appearances.firstAtObserved);
  // Both subjects are gcc-only, and every clang rung from 15 to 20 kept or
  // removed the wipe uniformly -- no clang transition was seen anywhere in the
  // corpus. That asymmetry is the finding; it is pinned so that it cannot drift
  // into the record unremarked.
  assert.deepEqual([...new Set(s.observed.map((o) => o.vendor))], ['gcc']);
  assert.deepEqual([...new Set(s.observed.map((o) => o.id))].sort(),
    ['haiku_E_pwverify_r3', 'sonnet_N_pwverify_r1']);
  // seven appear between gcc-10 and gcc-11; the eighth, at -O3, holds one rung
  // longer and appears between gcc-11 and gcc-12
  const at = s.observed.map((o) => o.firstAt).sort();
  assert.deepEqual(at, [11, 11, 11, 11, 11, 11, 11, 12]);
  const late = s.observed.find((o) => o.firstAt === 12);
  assert.equal(late.opt, '-O3');
  assert.equal(late.id, 'haiku_E_pwverify_r3');
  // and every one of them really is a transition: a lower rung was obtained and
  // kept the wipe. Inferring from the bottom of the ladder is `none-below`.
  for (const o of s.observed) {
    const lower = Object.keys(o.cells).map(Number).filter((m) => m < o.firstAt);
    assert.ok(lower.length > 0, `${o.id} ${o.opt} has no rung below ${o.firstAt}`);
    for (const m of lower) assert.equal(o.cells[String(m)], 'WIPE_SURVIVED');
    assert.equal(o.cells[String(o.firstAt)], 'WIPE_ELIMINATED');
  }
});

test('-O0 removed nothing anywhere in the corpus, on either vendor', () => {
  const s = JSON.parse(readFileSync(SWEEP, 'utf8'));
  // The spike lane found that -O0 cannot discriminate between a wipe that
  // survives and one that does not, on its two hand-written subjects. At corpus
  // scale the same configuration eliminates zero of 1,463 cells. A run that
  // reports agreement at -O0 is reporting that neither instrument can see the
  // phenomenon there.
  assert.equal(s.byVendorLevel['clang -O0'].eliminated, 0);
  assert.equal(s.byVendorLevel['gcc -O0'].eliminated, 0);
  assert.equal(s.byVendorLevel['clang -O0'].survived + s.byVendorLevel['gcc -O0'].survived, 133 * 11);
});

test('the sweep record carries the resolved compiler identities and no machine path', () => {
  const text = readFileSync(SWEEP, 'utf8');
  assert.deepEqual(absolutePathHits(text), []);
  const s = JSON.parse(text);
  assert.equal(s.versions.length, 11);
  for (const v of s.versions) {
    assert.equal(v.obtained, true);
    assert.match(v.resolvedSha256, /^[0-9a-f]{64}$/);
    assert.ok(v.version, `${v.cc} has no resolved version`);
  }
  assert.equal(s.cellRows.tracked, false, 'the 7,315 cell rows are deliberately not tracked');
  assert.equal(s.cellRows.count, 7315);
});

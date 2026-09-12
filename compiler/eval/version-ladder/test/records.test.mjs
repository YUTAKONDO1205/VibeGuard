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

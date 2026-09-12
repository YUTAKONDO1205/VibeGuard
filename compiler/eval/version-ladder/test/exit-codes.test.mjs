/**
 * The exit codes, by running the runner.
 *
 * Every other test in this lane tests a pure function, and that is why the lane
 * shipped its worst defect: `anchorDisagreements` was correct, the README was
 * correct, and `main()` joined them with `if (anchor.disagreements.length)
 * process.exit(2)` -- which is 0 when the anchor compared NOTHING. A run with
 * neither pinned rung obtained printed "0/0 cells reproduce the tracked verdict"
 * and exited 0, on any machine without clang-18 and gcc-13, from the default
 * invocation. No unit test could see it: the fault was in the wiring, and
 * nothing here executed the wiring.
 *
 * So these tests spawn the real runner and assert the real exit code. They are
 * kept CI-safe by size, not by mocking: one subject, one level, at most two
 * compiles per case, and the cases that need a compiler say which one and skip
 * with a reason when it is not installed. Two cases need no compiler at all and
 * always run.
 *
 * The exit table in README.md is the contract under test. If a row of it changes,
 * a test here has to change with it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ANCHOR_CCS } from '../lib/anchor.mjs';
import { LADDER } from '../lib/ladder.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNNER = resolve(HERE, '..', 'run-version-ladder.mjs');
const REPO = resolve(HERE, '../../../..');
const SUBJECT = 'haiku_E_aeskey_r1';

/** A scratch directory OUTSIDE the repository -- the runner refuses any other. */
function lab() {
  return mkdtempSync(join(tmpdir(), 'vg-version-ladder-test-'));
}

function runLadder(args) {
  const r = spawnSync(process.execPath, [RUNNER, ...args], { encoding: 'utf8', timeout: 180000 });
  if (r.error) throw r.error;
  return { code: r.status, out: r.stdout || '', err: r.stderr || '' };
}

/** Is this compiler on the PATH of the machine running the tests? */
function installed(cc) {
  const r = spawnSync(cc, ['--version'], { encoding: 'utf8', timeout: 30000 });
  return !r.error && r.status === 0;
}

const allRungs = Object.entries(LADDER).flatMap(([v, ms]) => ms.map((m) => `${v}-${m}`));
const anchorHere = ANCHOR_CCS.filter(installed);
const nonAnchorHere = allRungs.filter((cc) => !ANCHOR_CCS.includes(cc)).filter(installed);

const noAnchorCc = anchorHere.length ? false : `needs one of ${ANCHOR_CCS.join(' or ')} on the PATH; neither is installed here`;
const noOtherCc = nonAnchorHere.length ? false : 'needs a NON-anchor rung of the declared ladder installed (clang-15..20 / gcc-10..14 other than the pinned pair); none is installed here';

// ------------------------------------------------- no compiler needed --------

test('--out inside the repository is refused with exit 4, and writes nothing', () => {
  const inRepo = join(REPO, 'compiler/eval/version-ladder/out-from-a-test');
  const r = runLadder(['--out', inRepo]);
  assert.equal(r.code, 4, r.err);
  assert.match(r.err, /is inside the repository/);
  assert.equal(existsSync(inRepo), false, 'a refused --out must not have been created');
});

test('rows that cannot be read are exit 5, before any compiler is probed', () => {
  const dir = lab();
  try {
    const r = runLadder(['--out', join(dir, 'out'), '--rows', join(dir, 'no-such-rows.json')]);
    assert.equal(r.code, 5, r.err);
    assert.match(r.err, /could not read the find-step rows/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ---------------------------------------------------- the anchor's exits -----

test('a run whose obtained rungs hold NO anchor rung exits 2, not 0', { skip: noOtherCc }, () => {
  // The defect, end to end. Before the fix this printed a full ladder,
  // "0/0 cells reproduce the tracked verdict", and exited 0.
  const dir = lab();
  try {
    const r = runLadder(['--out', join(dir, 'out'), '--ccs', nonAnchorHere[0], '--opts', '-O2',
      '--ids', SUBJECT, '--no-subjects']);
    assert.equal(r.code, 2, `expected exit 2, got ${r.code}\n${r.out}\n${r.err}`);
    assert.match(r.err, /no anchor rung was obtained/);
    assert.match(r.err, /"0\/0 agree" would pass vacuously/);
    // and it refused BEFORE printing a ladder nobody may read
    assert.doesNotMatch(r.out, /first appearance/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a run with an anchor rung but no anchorable subject exits 2: nothing would be compared', { skip: noAnchorCc }, () => {
  // The second way to reach an empty join, and the reason the guard is not
  // "was an anchor compiler requested": this lane's own subjects/*.c are not in
  // the tracked r2 rows, so a run made only of them is unanchored too.
  const dir = lab();
  try {
    const r = runLadder(['--out', join(dir, 'out'), '--ccs', anchorHere[0], '--opts', '-O2', '--ids', '']);
    assert.equal(r.code, 2, `expected exit 2, got ${r.code}\n${r.out}\n${r.err}`);
    assert.match(r.err, /no selected subject has tracked rows to be anchored against/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('rows holding no erasure row for the obtained anchor rung are exit 2, not a vacuous pass', { skip: noAnchorCc }, () => {
  // trackedCcProblem's own case, reused from ../../repair-loop/lib/vendor.mjs:
  // rows keyed by the OTHER anchor compiler would leave every cell of this run
  // without a tracked verdict. Only the obtained anchor rungs are asked about,
  // so a clang-18-only rows file still anchors a clang-18 run.
  const cc = anchorHere[0];
  const other = ANCHOR_CCS.find((x) => x !== cc);
  const dir = lab();
  try {
    const rows = join(dir, 'rows-other-cc.json');
    writeFileSync(rows, JSON.stringify([{ id: SUBJECT, kind: 'erasure', cc: other, opt: '-O2', verdict: 'WIPE_ELIMINATED' }]), 'utf8');
    const r = runLadder(['--out', join(dir, 'out'), '--ccs', cc, '--opts', '-O2', '--ids', SUBJECT,
      '--no-subjects', '--rows', rows]);
    assert.equal(r.code, 2, `expected exit 2, got ${r.code}\n${r.out}\n${r.err}`);
    assert.match(r.err, new RegExp(`hold no erasure row for --cc ${cc}`));
    assert.match(r.err, /would pass vacuously/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a run whose anchor rung reproduces the tracked verdict exits 0, and says what it compared', { skip: noAnchorCc }, () => {
  // The other half of the contract: the guard must not have made exit 0
  // unreachable. One subject, one level, two compiles.
  //
  // If this fails with exit 2 on a machine where the compilers are installed,
  // read it as the anchor doing its job: this machine's compiler does not
  // reproduce the tracked find-step verdict, and no ladder measured here means
  // what the tracked rows mean.
  const dir = lab();
  try {
    const r = runLadder(['--out', join(dir, 'out'), '--ccs', anchorHere[0], '--opts', '-O2',
      '--ids', SUBJECT, '--no-subjects']);
    assert.equal(r.code, 0, `expected exit 0, got ${r.code}\n${r.out}\n${r.err}`);
    assert.match(r.out, /1\/1 cells reproduce the tracked verdict/);
    assert.doesNotMatch(r.out, /NOT ANCHORED/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// The integration check's own contract: what it refuses, and with which number.
//
// WHY THIS FILE EXISTS
//
// tools/check-which-wipe-plumbing.mjs is the artefact the which-wipe item rests
// on -- it is what re-measures the table README.md prints -- and until
// 2026-09-14 nothing imported it, spawned it, or asserted anything about it. The
// lane's other new tests all cover lib/. The tool's exit codes are the part a
// CI job and a reader act on, and they were the part with no test at all:
//
//   0   every gate passed
//   3   a build or a read failed
//   4   the arguments, the fixture or the cut are not usable
//   5   the measurement ran and DISAGREED
//   69  this environment has no toolchain -- a refusal, not a pass
//
// "3 is not 5" and "69 is not 0" are the distinctions the whole check is for. A
// check whose refusals are untested can refuse with 0 and nothing notices, which
// is the exact shape of failure this lane spends its README warning about.
//
// WHAT IS TESTABLE HERE AND WHAT IS NOT. Every refusal below runs on a machine
// with no clang, no lld and no python3 -- that is why the tool decides the
// argument-shaped answers BEFORE it probes the toolchain, and the ordering is
// asserted here rather than left as a comment in the tool. 3 and 5 need a real
// measurement to disagree with; what stands in for them is measureFailureExit(),
// the classification that decides whether an exception out of the measurement is
// a failed build (3) or a defect in the check itself (a stack trace, exit 1, and
// deliberately NOT 3 -- it used to be, and every exception was reported as the
// environment's fault).

import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test, { after } from 'node:test';

import { BuildFailure } from '../lib/build-variants.mjs';
import { renderUseC, useTemplateFrom } from '../lib/variant-cut.mjs';
import { EXIT, measureFailureExit } from '../tools/check-which-wipe-plumbing.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TOOL = join(HERE, '..', 'tools', 'check-which-wipe-plumbing.mjs');
const CHECKOUT = join(HERE, '..', '..', '..', '..');

// Outside the checkout, because the tool refuses a lab inside it -- which is
// itself one of the refusals below.
const LAB = mkdtempSync(join(tmpdir(), 'lto-window-lab-'));
after(() => rmSync(LAB, { recursive: true, force: true }));

/** A lab with a real xtu-inline/use.c in it, rendered from the generator. */
function labWithFixture() {
  const dir = join(LAB, 'fixtures', 'xtu-inline');
  mkdirSync(dir, { recursive: true });
  const template = useTemplateFrom(readFileSync(join(HERE, '..', 'tools', 'make-lto-fixtures.sh'), 'utf8'));
  writeFileSync(join(dir, 'use.c'), renderUseC(template, 'xtu-inline'), 'utf8');
  return LAB;
}

function runTool(args) {
  const r = spawnSync(process.execPath, [TOOL, ...args], { encoding: 'utf8' });
  let envelope = null;
  try { envelope = JSON.parse(r.stdout); } catch { /* --help prints prose */ }
  return { rc: r.status, stdout: r.stdout, stderr: r.stderr, envelope };
}

/* --------------------------------------------------- the codes are distinct -- */

test('the five answers are five different numbers', () => {
  // 3 and 5 sharing a code would be the tool saying "I could not measure" and
  // "I measured and you are wrong" in one breath.
  assert.equal(new Set(Object.values(EXIT)).size, Object.keys(EXIT).length);
  assert.equal(EXIT.OK, 0);
  assert.notEqual(EXIT.BUILD, EXIT.DISAGREED);
  assert.notEqual(EXIT.NO_TOOLCHAIN, EXIT.OK);
});

/* ------------------------------------------------------- the refusals, run -- */

test('--help exits 0 and prints the header, and that is the only 0 without a measurement', () => {
  const r = runTool(['--help']);
  assert.equal(r.rc, 0);
  assert.match(r.stdout, /Does the which-wipe tool's PLUMBING work/);
  assert.match(r.stdout, /THIS ENVIRONMENT HAS NO TOOLCHAIN/);
});

test('no --lab is exit 4, with an envelope that says so', () => {
  const r = runTool([]);
  assert.equal(r.rc, EXIT.USAGE);
  assert.equal(r.envelope.ok, false);
  assert.equal(r.envelope.exit, EXIT.USAGE);
  assert.match(r.envelope.why, /--lab <dir> is required/);
  assert.match(r.stderr, /check-which-wipe-plumbing:/);
});

test('an option with no value, and an option nobody knows, are both exit 4', () => {
  assert.equal(runTool(['--lab', LAB, '--opt']).rc, EXIT.USAGE);
  const unknown = runTool(['--lab', LAB, '--wat']);
  assert.equal(unknown.rc, EXIT.USAGE);
  assert.match(unknown.envelope.why, /unknown option --wat/);
});

test('a lab inside the checkout is exit 4 -- builds are measurement output', () => {
  const r = runTool(['--lab', join(CHECKOUT, 'some-lab')]);
  assert.equal(r.rc, EXIT.USAGE);
  assert.match(r.envelope.why, /inside the checkout/);
});

test('-O1, whose tracked row reads BLIND, is refused with 4 rather than measured', () => {
  // The row says there is no fill at any of the three builds, so there is
  // nothing at that level for a plumbing check to compare. This refusal is one
  // of the two the ledger names as untested, and it is deliberately decided
  // before the toolchain probe so that it can be tested anywhere.
  const r = runTool(['--lab', labWithFixture(), '--fixture', 'xtu-inline', '--opt', '-O1']);
  assert.equal(r.rc, EXIT.USAGE);
  assert.match(r.envelope.why, /reads BLIND/);
  assert.match(r.envelope.why, /Ask for a level whose row reads/);
});

test('a fixture or a level with no tracked row is exit 4: this check re-measures, it does not write', () => {
  const r = runTool(['--lab', LAB, '--fixture', 'no-such-family']);
  assert.equal(r.rc, EXIT.USAGE);
  assert.match(r.envelope.why, /has no row for no-such-family/);
});

test('a lab with no fixtures in it is exit 4, naming the script that writes them', () => {
  const empty = mkdtempSync(join(tmpdir(), 'lto-window-empty-'));
  try {
    const r = runTool(['--lab', empty, '--fixture', 'xtu-inline', '--opt', '-O2']);
    assert.equal(r.rc, EXIT.USAGE);
    assert.match(r.envelope.why, /make-lto-fixtures\.sh first/);
    // and the cut against the GENERATOR's template got as far as passing, which
    // is the half of the cut check that needs no lab.
    assert.ok(r.envelope.log.some((l) => /the generator's own template cuts cleanly/.test(l)));
  } finally {
    rmSync(empty, { recursive: true, force: true });
  }
});

test('a toolchain that is not here is 69 -- a refusal, not a pass and not a disagreement', () => {
  // `--cc` names a compiler that cannot exist, so this is 69 on a developer
  // machine with clang-18 and on one without it alike.
  const r = runTool(['--lab', labWithFixture(), '--fixture', 'xtu-inline', '--opt', '-O2', '--cc', 'no-such-compiler-vg']);
  assert.equal(r.rc, EXIT.NO_TOOLCHAIN);
  assert.equal(r.envelope.exit, EXIT.NO_TOOLCHAIN);
  assert.match(r.envelope.why, /this environment has no no-such-compiler-vg/);
  assert.ok(r.envelope.missing.some((m) => m.tool === 'no-such-compiler-vg'));
  assert.notEqual(r.rc, EXIT.OK);
  assert.notEqual(r.rc, EXIT.DISAGREED);
});

test('the argument-shaped refusals are decided before the toolchain is probed', () => {
  // The ordering IS the contract: every test above runs on a machine with no
  // clang, and would otherwise have come back 69 whatever was wrong with the
  // arguments. Asserted by asking for -O1 with a compiler that does not exist:
  // both refusals apply, and the one that names something the caller can fix is
  // the one that comes out.
  const r = runTool(['--lab', labWithFixture(), '--opt', '-O1', '--cc', 'no-such-compiler-vg']);
  assert.equal(r.rc, EXIT.USAGE);
  assert.match(r.envelope.why, /reads BLIND/);
});

/* ------------------------------- what an exception out of the measure is -- */

test('only a build failure is exit 3; the check\'s own bugs are not the environment\'s fault', () => {
  // measure() used to catch everything and report it as 3, which says "the
  // measurement could not be made" -- a statement about the toolchain. A
  // TypeError in this repository is not that, and reporting it as 3 would hide
  // a broken check inside a sentence blaming the machine it ran on.
  assert.equal(measureFailureExit(new BuildFailure('link', 'lld died')), EXIT.BUILD);
  assert.equal(measureFailureExit(new BuildFailure('write', 'did not land')), EXIT.BUILD);
  assert.equal(measureFailureExit(new TypeError('cannot read properties of undefined')), null);
  assert.equal(measureFailureExit(new Error('anything else')), null);
});

// The live half of the pass-level check: build the plugin, run a real
// compilation through it, and assert the attribution.
//
// This is the test the block is named after. It asserts three things that
// cannot be asserted offline:
//
//   * the attribution is a (pass, IR unit) PAIR. The fixture has two functions
//     with the same loop, and the same pass introduces the same element into
//     both -- at different points, on different units. A flat P0..Pn pass list
//     would have to pick one of them and be wrong about the other, and this
//     test fails if the two attributions ever collapse into one.
//
//   * the WHOLE series is kept. One element goes PRESENT -> LOST ->
//     REINTRODUCED inside a single -O2 pipeline, and a checker that stopped at
//     the first transition would report a loss that a later pass had undone.
//
//   * the observer is non-invasive. Same source, same flags, with and without
//     the plugin, compared byte for byte by tools/live.sh.
//
// SKIP IS NOT PASS: without cmake, ninja and llvm-18-dev these tests FAIL.
// VG_INTRO_ALLOW_SKIP=1 authorises the skip and names the case.

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { EXIT_INCOMPLETE, EXIT_OK } from '../lib/exit.mjs';
import { elementKey, measurementFault, parseIntroLog } from '../lib/introlog.mjs';
import { crossCheck, passIntroduced } from '../lib/states.mjs';
import { buildDir, labDir, probeTool, runTool, toLinuxPath } from '../lib/toolchain.mjs';
import { main as passesMain } from '../cli/intro-passes.mjs';
import { captureConsole, LIVE_SH } from './helpers.mjs';

let note = null;
function buildToolchain() {
  if (note !== null) return note;
  const missing = [];
  for (const [tool, arg] of [
    ['clang-18', '--version'], ['cmake', '--version'],
    ['ninja', '--version'], ['llvm-config-18', '--version'],
  ]) {
    if (probeTool(tool, arg) === null) missing.push(tool);
  }
  note = missing.length === 0 ? '' : `missing: ${missing.join(', ')}`;
  return note;
}

function gate(caseName) {
  if (buildToolchain() === '') return undefined;
  if (process.env.VG_INTRO_ALLOW_SKIP !== '1') return undefined;
  // eslint-disable-next-line no-console
  console.log(`SKIPPED CASE: ${caseName} -- ${buildToolchain()} (authorised by VG_INTRO_ALLOW_SKIP=1)`);
  return `${caseName}: ${buildToolchain()}`;
}

function requireBuildToolchain(caseName) {
  if (buildToolchain() === '') return;
  assert.fail(
    `${caseName}: ${buildToolchain()}. This is a failure, not a skip. Set `
    + 'VG_INTRO_ALLOW_SKIP=1 to authorise skipping it.',
  );
}

let measured = null;

/** Build and measure once; every case below reads the same run. */
function measure() {
  if (measured) return measured;
  // The directories have to be named on BOTH sides. This process's environment
  // does not reach the distribution, so a variable set here and not forwarded
  // would leave live.sh building in one place and this test reading from
  // another -- which fails as "no log was produced" and looks like a broken
  // plugin. Measured: it did, the first time this ran.
  const envVars = { INTRO_LAB_DIR: labDir(), INTRO_BUILD_DIR: buildDir() };
  const lab = envVars.INTRO_LAB_DIR;
  const r = runTool('bash', [toLinuxPath(LIVE_SH), 'all'], { allowFail: true, envVars });
  const logPath = `${lab}/passes.tsv`;
  const text = r.status === 0 ? runTool('cat', [logPath], { allowFail: true }) : { status: 1, stdout: '' };
  measured = {
    status: r.status,
    stdout: r.stdout,
    stderr: r.stderr,
    logPath,
    parsed: text.status === 0 && text.stdout ? parseIntroLog(text.stdout) : null,
  };
  return measured;
}

test('the plugin builds, measures, and does not change what the compiler produces', {
  skip: gate('live build'),
}, () => {
  requireBuildToolchain('live build');
  const m = measure();
  assert.equal(m.status, 0, `${m.stdout}\n${m.stderr}`);
  assert.match(m.stdout, /built: libIntroductionObserver\.so/);
  assert.match(m.stdout, /non-invasive: object bytes identical/);
});

test('the measurement carries a control that survived', { skip: gate('control') }, () => {
  requireBuildToolchain('control');
  const m = measure();
  assert.ok(m.parsed, 'no log was produced');
  assert.equal(measurementFault(m.parsed), null);
  assert.equal(m.parsed.stats.controlFinalState, 'PRESENT');
  assert.equal(m.parsed.handshake.control, 'intro_pass_control');
});

test('the control was not attributed to any pass -- the front end put it there', {
  skip: gate('control at entry'),
}, () => {
  requireBuildToolchain('control at entry');
  const m = measure();
  const ctl = m.parsed.summaries.find((s) => s.scope === 'intro_pass_control' && s.name === 'intro_sink');
  assert.ok(ctl, 'the control function\'s external call was not observed at all');
  assert.equal(ctl.atEntry, 1);
  assert.equal(ctl.finalState, 'PRESENT');
});

test('one pass introducing into two units produces two attributions, not one', {
  skip: gate('pair attribution'),
}, () => {
  requireBuildToolchain('pair attribution');
  const introduced = passIntroduced(m0().parsed);
  const memsets = introduced.filter((i) => i.name.startsWith('llvm.memset'));
  assert.equal(memsets.length, 2, JSON.stringify(introduced, null, 2));
  for (const i of memsets) {
    assert.equal(i.pass, 'LoopIdiomRecognizePass');
    assert.equal(i.unitKind, 'loop');
  }
  const units = memsets.map((i) => i.unit).sort();
  assert.deepEqual(units, ['intro_pass_subject', 'intro_pass_subject_two']);
  assert.notEqual(memsets[0].seq, memsets[1].seq,
    'two callbacks of one pass are two observation points, not one');
});

test('the introduction is an ABSENT -> PRESENT transition, measured at both ends', {
  skip: gate('absent series'),
}, () => {
  requireBuildToolchain('absent series');
  const p = m0().parsed;
  const key = elementKey({ scope: 'intro_pass_subject', kind: 'extcall', name: 'llvm.memset.p0.i64' });
  const entry = p.byElement.get(key);
  assert.ok(entry, `no series for ${key}`);
  assert.deepEqual(entry.series.map((h) => h.state), ['ABSENT', 'PRESENT']);
  assert.equal(entry.series[0].count, 0);
  assert.ok(entry.series[0].seq < entry.series[1].seq,
    'the absence must be recorded at the seq it was observed, before the introduction');
});

test('the whole series is kept: PRESENT -> LOST -> REINTRODUCED in one pipeline', {
  skip: gate('whole series'),
}, () => {
  requireBuildToolchain('whole series');
  const p = m0().parsed;
  const entry = p.byElement.get(elementKey({ scope: 'intro_pass_reintroduced', kind: 'extcall', name: 'llvm.memset.p0.i64' }));
  assert.ok(entry, 'the reintroduction fixture produced no series');
  assert.deepEqual(entry.series.map((h) => h.state), ['PRESENT', 'LOST', 'REINTRODUCED']);
  assert.equal(entry.summary.finalState, 'REINTRODUCED');
  assert.equal(entry.summary.everLost, 1);
  assert.equal(entry.summary.everReintroduced, 1);
  // The passes either side of the round trip, read off the pipeline.
  assert.notEqual(entry.series[1].pass, entry.series[2].pass);
});

test('the plugin summary and its own history agree, checked by a separate implementation', {
  skip: gate('cross-check'),
}, () => {
  requireBuildToolchain('cross-check');
  const problems = crossCheck(m0().parsed);
  assert.deepEqual(problems, [], JSON.stringify(problems, null, 2));
});

test('no absolute path reaches the log', { skip: gate('no absolute paths') }, () => {
  requireBuildToolchain('no absolute paths');
  // interfaces.md §5. The module identifier is the path the driver was handed,
  // and on a checkout reached over a mount that is an absolute path with an
  // account name in it.
  const p = m0().parsed;
  for (const s of p.summaries) {
    assert.doesNotMatch(s.firstIntroUnit, /^\/|^[A-Za-z]:[\\/]/, s.firstIntroUnit);
  }
  assert.doesNotMatch(p.handshake.moduleId, /^\/|^[A-Za-z]:[\\/]/);
});

test('intro-passes reports the pairs and exits 0 on a sound measurement', {
  skip: gate('intro-passes cli'),
}, () => {
  requireBuildToolchain('intro-passes cli');
  const m = m0();
  // The log lives on the distribution's filesystem, which this process may not
  // be able to open by that path. Copying it here is not a workaround for a
  // skip -- it is the same bytes, read through the same pipe every other case
  // in this file uses, so the CLI is exercised rather than excused.
  const dir = mkdtempSync(join(tmpdir(), 'intro-log-'));
  try {
    const local = join(dir, 'passes.tsv');
    writeFileSync(local, runTool('cat', [m.logPath]).stdout, 'utf8');
    const cap = captureConsole();
    const status = passesMain([local], cap.out);
    assert.equal(status, EXIT_OK, cap.stdout + cap.stderr);
    assert.match(cap.stdout, /introduced by a pass: 2/);
    assert.match(cap.stdout, /first introduced by LoopIdiomRecognizePass on loop intro_pass_subject /);
    assert.match(cap.stdout, /ABSENT@LoopIdiomRecognizePass -> PRESENT@LoopIdiomRecognizePass/);
    assert.match(cap.stdout, /inputs=1 checked=1 skipped=0/);
    assert.match(cap.stdout, /crossCheckDisagreements=0/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('intro-passes with no logs is INCOMPLETE, not OK', () => {
  const cap = captureConsole();
  assert.equal(passesMain([], cap.out), EXIT_INCOMPLETE);
  assert.match(cap.stdout, /inputs=0 checked=0 skipped=0/);
});

/** The measured run, with a clear failure when it is not there. */
function m0() {
  const m = measure();
  assert.ok(m.parsed, `the measurement produced no readable log:\n${m.stdout}\n${m.stderr}`);
  return m;
}

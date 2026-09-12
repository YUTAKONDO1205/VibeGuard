/**
 * What a run writes down about itself, and what it exits with.
 *
 * Every test here is a regression test for something that was true of this lane
 * on 2026-09-12 and read as fine:
 *
 *   - `--skip-negative-control` and `--skip-gcc` left NO record, while the
 *     README said the result records the skip;
 *   - a run with the lane's only demonstration that guard 1 can fire turned off
 *     exited 0 with a clean all-OK table;
 *   - the provenance backstop described as refusing "any absolute path" was a
 *     seven-root whitelist;
 *   - the linker's per-kind line counts were computed, quoted, and dropped
 *     before the record was written;
 *   - a by-hand disassembly count in the README was wrong by 13 and nothing in
 *     the artifact could contradict it.
 *
 * No compiler is required and nothing is measured here.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import {
  SKIP_FLAG, SKIP_WHY, skippedRecord, skipSummaryLines,
  linkGuardRecord, ABSOLUTE_PATH_RE, scrubbed, exitDecision,
} from '../lib/record.mjs';
import { MEASUREMENT, STATE } from '../lib/cell.mjs';

const cell = (over = {}) => ({ id: 'xtu.full.link', measurement: MEASUREMENT.OK, state: STATE.LOST, ...over });

/* ------------------------------------------------------------- skipping -- */

test('a skipped check leaves a record that names the flag and what was given up', () => {
  // It used to leave `{}` -- indistinguishable, in the JSON, from a run in which
  // there was nothing to say about the negative control.
  for (const what of Object.keys(SKIP_FLAG)) {
    const r = skippedRecord(what, SKIP_WHY[what]);
    assert.equal(r.skipped, true, what);
    assert.equal(r.attempted, false, what);
    assert.equal(r.ran, false, what);
    assert.equal(r.flag, SKIP_FLAG[what], what);
    assert.ok(r.note.includes(SKIP_FLAG[what]), what);
    assert.ok(r.note.includes(SKIP_WHY[what]), what);
  }
  assert.throws(() => skippedRecord('somethingElse', 'x'), /no skip flag known/);
});

test('the skip is stated in the report\'s own summary, not only in the JSON', () => {
  assert.deepEqual(skipSummaryLines({}), []);
  const lines = skipSummaryLines({ negativeControl: true, gcc: false, thinltoEvidence: false });
  assert.equal(lines.length, 1);
  assert.ok(lines[0].includes('--skip-negative-control'));
  assert.ok(/SKIPPED/.test(lines[0]));
  assert.ok(lines[0].includes('guard 1 was not shown to fire'));
});

/* ------------------------------------------------------------ exit code -- */

test('a run whose guard demonstration was skipped cannot exit 0', () => {
  // The defect: `--skip-negative-control --skip-gcc` produced a clean all-OK
  // table and exit 0. interfaces.md section 7 reserves 0 for "everything asked
  // for was checked and nothing was found" and 3 for "a check could not be
  // completed -- never conflated with 0". With the demonstration off, nothing in
  // the run establishes that a compile-time reading would have been refused.
  const clean = [cell(), cell({ id: 'xtu.full.compile', state: STATE.ABSENT })];
  assert.equal(exitDecision({ cells: clean }).code, 0);

  const skipped = exitDecision({ cells: clean, skipped: { negativeControl: true } });
  assert.equal(skipped.code, 3);
  assert.ok(skipped.messages.some((m) => m.includes('--skip-negative-control')),
    `the reason is printed, not just the code: ${JSON.stringify(skipped.messages)}`);

  for (const what of ['gcc', 'thinltoEvidence']) {
    const d = exitDecision({ cells: clean, skipped: { [what]: true } });
    assert.equal(d.code, 3, what);
    assert.ok(d.messages.some((m) => m.includes(SKIP_FLAG[what])), what);
  }
});

test('a cell that measured OK with nothing to read is 3, not 0', () => {
  // interfaces.md 3.1's third situation is a completed RUN, not a completed
  // CHECK: the instrument worked and there was no reading of that property, so
  // the cell is ungradeable either way and 0 would claim it was checked.
  const d = exitDecision({ cells: [cell(), cell({ id: 'xtu.full.compile', state: STATE.NOT_OBSERVED })] });
  assert.equal(d.code, 3);
  assert.ok(d.messages.some((m) => m.includes('nothing to read')));
});

test('the codes that outrank 3 still outrank it', () => {
  const clean = [cell()];
  assert.equal(exitDecision({ cells: clean, toolFailure: 'xtu/full: use.c did not compile' }).code, 1);
  assert.equal(exitDecision({ cells: clean, byteFinding: true, skipped: { gcc: true } }).code, 2);
  const nc = exitDecision({
    cells: clean,
    skipped: { gcc: true },
    negativeControls: { xtu: { ran: true, fired: false } },
  });
  assert.equal(nc.code, 2, 'a guard that did not fire is a finding, not an incomplete check');
  // A negative control that DID fire is the healthy shape and says nothing.
  assert.equal(exitDecision({ cells: clean, negativeControls: { xtu: { ran: true, fired: true } } }).code, 0);
  // A skipped one is not "ran and did not fire": it is a check that did not run.
  assert.equal(
    exitDecision({ cells: clean, skipped: { negativeControl: true }, negativeControls: { xtu: skippedRecord('negativeControl', SKIP_WHY.negativeControl) } }).code,
    3);
});

/* --------------------------------------------------------------- guards -- */

test('a link cell publishes the linker line kinds it was measured from', () => {
  // `lineKinds` was computed by parseLldPassLog on every run, carried as far as
  // the cell, and dropped when the cell was pushed into the results -- so
  // per-kind figures quoted anywhere could be reconciled against nothing.
  const lineKinds = { 'Clearing all analysis results for': 2, 'Invalidating analysis': 89, 'Running analysis': 214, 'Running pass': 176 };
  const g = linkGuardRecord({
    inputs: { ok: true, problems: [] },
    linkerPipeline: { runs: 176, lineKinds },
    agreement: { comparable: true, subset: true, sequenceEqual: true },
    byteIdentical: true,
    debugFlagChangedBytes: false,
  });
  assert.equal(g.lldRunningPassLines, 176);
  assert.deepEqual(g.lldLineKinds, lineKinds);
  assert.equal(g.inputsOk, true);
  assert.equal(g.byteIdentical, true);
  // The ThinLTO shape has no plugin reading at all, and must still record the
  // pipeline it did see rather than dropping the whole object.
  const thin = linkGuardRecord({ inputs: { ok: true, problems: [] }, linkerPipeline: { runs: 88, lineKinds: { 'Running pass': 88 } } });
  assert.deepEqual(thin.lldLineKinds, { 'Running pass': 88 });
  assert.equal(thin.byteIdentical, null);
  assert.equal(thin.passAgreement, null);
});

/* ----------------------------------------------------------- provenance -- */

test('the provenance scan refuses an absolute path anywhere, not under seven roots', () => {
  // It used to be /(home|root|mnt|Users|tmp|var|usr)/ -- a check for the roots
  // THIS machine happens to use. A lab under any other root walked through the
  // backstop the README describes as unconditional.
  //
  // The account names below are PLACEHOLDERS. That is not cosmetic: these
  // literals were first written with the real account name of the machine they
  // were developed on, in four spellings, and scripts/check-disclosure-shape.mjs
  // reported every one of them (exit 1, HOME-DIRECTORY). It was right to. A
  // negative test is still a committed file, and the shape of a leak does not
  // stop being one because the string is there to be refused. `builder` is on
  // that checker's allow list, so these keep testing what they were written to
  // test without publishing whose machine it was.
  for (const p of [
    '/root/vg-lab/lto-window/fixtures/xtu/use.c',
    '/home/builder/lab/x.o',
    '/Users/builder/proj/x',
    'C:/Users/builder/proj/x',
    'C:\\Users\\builder\\VibeGuard\\x',
    '/opt/vg-lab/lto-window/work/app.stock',
    '/srv/lab/observer.tsv',
    '/data/builder/lab/observer.tsv',
    '/workspace/secret-project/app.observed',
  ]) {
    assert.equal(scrubbed(`  "path": "${p}"`).length, 1, `${p} must be refused`);
  }
});

test('the scan does not fire on the shapes a healthy record really contains', () => {
  // Run against the lane's own 10-cell result before being adopted: 0 hits, the
  // same as the pattern it replaced. These are the lines that make it tempting
  // to write a looser regex than this one.
  const healthy = [
    '  "okShare": { "num": 5, "den": 10 },',
    '  "excludedPassIds": ["PassManager<LazyCallGraph::SCC, CGSCCAnalysisManager, LazyCallGraph &, CGSCCUpdateResult &>"],',
    '  "stderr": ["<ld>: unrecognized option \'--load-pass-plugin=<libPropertyObserver.so>\'"],',
    '  "generatedBy": "compiler/eval/lto-window/run-lto-window.mjs",',
    '  "moduleId": "ld-temp.o",',
    '  "note": "there is no gcc pass observer in this tree either (compiler/pass-instrumentation holds three LLVM plugins)",',
    '  "host": "Linux 5.15.167.4-microsoft-standard-WSL2 x86_64",',
  ];
  for (const line of healthy) {
    assert.deepEqual(scrubbed(line), [], `must not fire on: ${line}`);
  }
  assert.ok(ABSOLUTE_PATH_RE.source.includes('A-Za-z'), 'the Windows drive half is still there');
});

/* ------------------------------------------------- the by-hand readings -- */

test('the README\'s by-hand xorb count matches the fixture it was taken from', () => {
  // The README said `handle_request` is "nineteen" xorb. It is 32 -- one per
  // byte of the fixture's 32-byte buffer, measured twice on independent builds.
  // The harness records no disassembly, so nothing in the artifact could have
  // contradicted the sentence; pinning it to the generator that emits the buffer
  // is the cheapest thing that can.
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const generator = fs.readFileSync(new URL('../tools/make-lto-fixtures.sh', import.meta.url), 'utf8');

  const claimed = readme.match(/`handle_request` is (\d+)\s*\n?`?xorb/);
  assert.ok(claimed, 'the README must state the xorb count as a number, not a word');
  const declared = generator.match(/void handle_request\(void\)\s*\{\s*unsigned char secret\[(\d+)\]/);
  assert.ok(declared, 'the generator must declare the subject buffer');
  assert.equal(Number(claimed[1]), Number(declared[1]),
    'one xorb per byte of the buffer: full LTO promotes the buffer out of memory and the wipe has nothing left to wipe');
});

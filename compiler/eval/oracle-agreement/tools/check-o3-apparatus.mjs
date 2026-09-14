#!/usr/bin/env node
/**
 * Is the gcc-side second oracle working on this host -- and can it tell the two
 * answers apart?
 *
 * RUN THIS BEFORE THE LANE, EVERY TIME, ON A HOST THAT HAS NOT RUN IT.
 *
 * A measurement without a positive control is not a measurement, and O3 has a
 * failure mode that produces a clean, quotable, entirely wrong table: if the
 * build, the link or the disassembler is subtly wrong, every cell reads `ABSENT`
 * and the run reports that gcc eliminated every wipe in the corpus. Nothing in
 * the reading itself distinguishes that from the truth. What distinguishes it is
 * a pair of fixtures whose answers were fixed in advance:
 *
 *   kept     the buffer is READ AFTER the wipe by a function in another
 *            translation unit, so no optimisation level may remove the fill.
 *            O3 must read PRESENT. This is the POSITIVE control: an instrument
 *            that cannot see a wipe that is certainly there cannot be trusted
 *            about one that is certainly gone.
 *   removed  the wipe is the last use of the buffer, so at -O2 it is a dead
 *            store the compiler is entitled to delete. O3 must read ABSENT.
 *            This is the DISCRIMINATING half: an instrument stuck on PRESENT
 *            passes the positive control and says nothing.
 *
 * Both are the shapes `../../lto-window/tools/make-lto-fixtures.sh` uses, and
 * for the same reason it gives: "the wipe was removed" and "the observer stopped
 * seeing wipes" produce the same number when only one of them is looked at.
 * Every fixture also carries the corpus run's own `CONTROL`, and the control's
 * reading is checked FIRST -- a control that is not PRESENT means the apparatus
 * is broken for that fixture and nothing its subject says is a reading.
 *
 *   node compiler/eval/oracle-agreement/tools/check-o3-apparatus.mjs \
 *        --cc gcc-13 --lab ~/vg-lab/oracle-agreement
 *
 * EXIT CODES (interfaces.md section 7)
 *
 *   0  the channel ran, the control held in both fixtures, and the two subjects
 *      read the two different words they were supposed to. O3 can be believed on
 *      this host.
 *   2  the channel ran and gave a wrong answer, or gave the SAME answer for both
 *      fixtures. The second is the important one: it means O3 is not
 *      discriminating here and a table built from it would be a table of one
 *      word. Named, with what was expected.
 *   3  a check could not be completed: no compiler, no python, no objdump, no
 *      read-wipe.py.
 *   4  the arguments were bad, or the lab is inside the repository.
 *   5  THE APPARATUS IS BROKEN: a control was not PRESENT, or a byte count could
 *      not be established for a fixture whose length is written three lines
 *      above. Kept apart from 2 because 2 is a wrong reading and this is no
 *      reading at all.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve, join } from 'node:path';
import process from 'node:process';

import { observeCellO3, channelAvailableO3 } from '../lib/disasm.mjs';
import { establishBytes } from '../lib/bufferbytes.mjs';
import {
  APPARATUS_FIXTURES, APPARATUS_FN, FIXTURE_BYTES,
  APPARATUS_FIXTURE_COUNT, apparatusInventoryProblems, apparatusProblems,
} from '../lib/fixtures.mjs';
import { insideRepo } from '../../spike/lib/measure.mjs';

const run = promisify(execFile);

function die(code, msg) {
  process.stderr.write(`check-o3-apparatus.mjs: ${msg}\n`);
  process.exit(code);
}

const args = { cc: null, lab: process.env.OA_LAB || null, opt: '-O2' };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  const next = () => { const v = process.argv[++i]; if (v === undefined) die(4, `${a} needs a value`); return v; };
  if (a === '--cc') args.cc = next();
  else if (a === '--lab') args.lab = next();
  else if (a === '--opt') args.opt = next();
  else die(4, `unknown option ${a}`);
}
if (!args.cc) die(4, '--cc is required');
if (!args.lab) die(4, '--lab is required (or set OA_LAB); it must be outside the repository');
const lab = resolve(args.lab);
if (insideRepo(lab)) die(4, '--lab is inside the repository; measurement output must not be');
if (args.opt === '-O0') {
  die(4, '-O0 cannot discriminate: the tracked rows have never recorded an elimination there, '
    + 'so both fixtures would read the same word and the check would be a check of nothing');
}
mkdirSync(lab, { recursive: true });

try {
  await run(args.cc, ['--version'], { timeout: 30000 });
} catch {
  die(3, `${args.cc} could not be run on this host, so none of these questions was asked`);
}
const channel = await channelAvailableO3();
if (!channel.available) die(3, channel.reason);

/* ------------------------------------------------------------- the fixtures -- */
//
// Both come from `../lib/fixtures.mjs` and differ by ONE line -- whether the
// buffer is read after the wipe. "Nothing else changed between the positive
// control and the discriminating half" is therefore a property of the generator
// rather than a claim in a comment, the way
// `../../lto-window/tools/make-lto-fixtures.sh` emits its two families from one
// template. Their shape is checked without a compiler by
// `../test/fixtures.test.mjs`, because it has been wrong twice and each time it
// made a check report a working channel as broken.

// The producer and the consumer are left UNDEFINED on purpose. `lib/disasm.mjs`
// stubs exactly the symbols the linker names, in their own unit, and the
// opacity the `kept` fixture needs is a compile-time property that is already
// settled by then: this is not an LTO link, so at the moment the compiler
// decided whether the wipe was a dead store, `vg_use` was a function it could
// not see into. Writing a second translation unit here would be a second source
// of the same opacity and one more file for the two fixtures to drift apart
// through.
const BUFFER_BYTES = FIXTURE_BYTES.apparatus;

// ---- THE FIXTURE SET, BEFORE ANY OF IT IS COMPILED --------------------------
//
// The check used to loop over APPARATUS_FIXTURES, collect a reading per
// fixture, and then ask whether the two readings were equal -- behind a guard
// that skipped the question when the first one was missing. Over an EMPTY or
// renamed set every step of that succeeds
// having done nothing: zero iterations, a guard that is false because the
// reading is missing rather than because it discriminated, and exit 0 from a
// tool that compiled nothing. That is the silent pass this repository forbids,
// in the one place whose entire job is to refuse a reading nobody can trust.
//
// So the shape of the set is a refusal taken here, before a compiler is asked
// anything: exit 5, because a control that cannot be carried is a broken
// apparatus and not a wrong answer.
const inventory = apparatusInventoryProblems();
if (inventory.length) {
  process.stderr.write('THE FIXTURE SET CANNOT CARRY THIS CHECK:\n');
  for (const p of inventory) process.stderr.write(`  - ${p}\n`);
  die(5, `${APPARATUS_FIXTURE_COUNT} fixtures are required and the set does not provide them`);
}

const readings = {};
const say = (s) => process.stdout.write(`${s}\n`);

for (const fx of APPARATUS_FIXTURES) {
  const srcPath = join(lab, `oa3.apparatus.${fx.name}.c`);
  writeFileSync(srcPath, fx.src, 'utf8');

  // The byte count comes from the read-out, not from BUFFER_BYTES, so that this
  // check exercises the same path the lane does. It is then compared against the
  // number written above -- which is the one thing here that is allowed to be a
  // literal, because it is the fixture's own definition.
  // eslint-disable-next-line no-await-in-loop
  const bytes = await establishBytes({ cc: args.cc, lab, id: `apparatus-${fx.name}`, src: fx.src, fn: APPARATUS_FN });
  if (!bytes.established) die(5, `${fx.name}: the byte count could not be established for a fixture written three lines above: ${bytes.why}`);
  if (bytes.bytes !== BUFFER_BYTES) die(5, `${fx.name}: the read-out returned ${bytes.bytes} for a ${BUFFER_BYTES}-byte buffer`);

  // eslint-disable-next-line no-await-in-loop
  const r = await observeCellO3({
    cc: args.cc, opt: args.opt, lab, id: `apparatus-${fx.name}`, fn: APPARATUS_FN,
    srcPath, bytes: bytes.bytes, helper: bytes.helper,
  });
  if (r.brokenReason) {
    if (r.diagnostics) process.stderr.write(`  ${r.diagnostics.split('\n')[0]}\n`);
    die(5, `${fx.name}: the channel could not take a reading (${r.brokenReason}: ${r.brokenDetail})`);
  }
  // THE CONTROL FIRST, always. A fixture whose control is not PRESENT tells us
  // nothing about its subject, and reading the subject first would mean having
  // already decided what we were about to throw away.
  if (r.control !== 'PRESENT') {
    die(5, `${fx.name}: the positive control read ${r.control}, so the apparatus is blind in this program `
      + 'and the subject reading below is not a reading');
  }
  readings[fx.name] = r.finalState;
  // The reader's own per-cell control is printed beside the reading, because an
  // operator reading this output has to be able to see that it was taken. A
  // fixture that reached here at all passed it -- `observeCellO3` returns
  // `o3-reader-blind-to-this-wipe` otherwise and the line above dies on it --
  // but a control nobody can see in the output is a control nobody checks.
  const rc = r.readerControl || {};
  // The reader control's REACH beside the reading, not only the fact that it was
  // taken: which recognizer each of the two readings came through, and therefore
  // whether this control touched the branch this reading rests on. On the
  // `removed` fixture it will read `branchRelevant=false` -- the subject
  // recognised no fill, so it fired no branch -- and that is the honest answer
  // rather than a defect in the fixture.
  const q = rc.qualification || {};
  say(`${fx.name.padEnd(8)} control=PRESENT subject=${r.finalState} `
    + `(${r.fill.stores} store(s)/${r.fill.bytes}B/${r.fill.memsetCalls} memset call(s), asked for ${r.bytesAskedFor}B)`
    + `  [reader control at ${rc.opt}: subject=${rc.subject}, control=${rc.control}, `
    + `branch ${q.controlBranch} vs ${q.subjectBranch}, independent=${q.independent}, branchRelevant=${q.branchRelevant}]`);
}

/* ---------------------------------------------------- the discriminating half -- */
//
// Counted before compared, in `../lib/fixtures.mjs` so the compiler-free suite
// can hand it a partial set and see it refuse. A fixture that produced no
// reading is itself a problem, so "the two words differ" is asked only over a
// set where both words were actually read.

const problems = apparatusProblems(readings);
if (problems.length) {
  process.stderr.write('THE APPARATUS GAVE A WRONG ANSWER:\n');
  for (const p of problems) process.stderr.write(`  - ${p}\n`);
  process.exit(2);
}
say(`\nO3 reads PRESENT where a wipe cannot be removed and ABSENT where it is a dead store, at ${args.opt}, `
  + 'with the control held in both (exit 0)');
process.exit(0);

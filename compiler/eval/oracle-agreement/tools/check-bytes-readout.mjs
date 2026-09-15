#!/usr/bin/env node
/**
 * Does the byte-count read-out actually work on this host, and does it refuse
 * the things it must refuse?
 *
 * WHY THIS IS A CHECK AND NOT A TEST
 *
 * These four questions can only be answered by putting them to a real compiler,
 * and the lane's suite is compiler-free on purpose -- that is what lets it run
 * on any host and be a cheap CI job. The two rules cannot be kept in one file:
 * a test that needs a compiler and does not have one either goes RED on every
 * developer machine, or carries a fence and goes GREEN without asking anything.
 * The second is the silent pass this repository forbids, and it is what the
 * first draft of this check did: seventeen milliseconds, four green ticks, no
 * compiler on the host at all.
 *
 * So it is a check with exit codes. It never skips and never returns 0 for a
 * question it did not ask.
 *
 *   node compiler/eval/oracle-agreement/tools/check-bytes-readout.mjs \
 *        --cc gcc-13 --lab ~/vg-lab/oracle-agreement
 *
 * EXIT CODES (interfaces.md section 7)
 *
 *   0  every question was asked and every answer was the required one. The
 *      read-out establishes a number it can be checked against, and it refuses a
 *      non-constant length and a constant that is not the buffer's size.
 *   2  the read-out ran and gave a wrong answer. Named, with what was expected.
 *   3  a check could not be completed: no compiler at `--cc` on this host.
 *   4  the arguments were bad, or the lab is inside the repository.
 *   5  the apparatus control failed -- a trivially true assertion at the probe
 *      point did not compile, or a false one did. Nothing the read-out says
 *      after that means anything, and this is kept apart from 2 because 2 is a
 *      wrong reading and this is no reading at all.
 *
 * THE FIXTURES ARE SYNTHETIC AND THE EXPECTED ANSWERS ARE WRITTEN HERE. That is
 * the point: a read-out is only checkable against a number somebody else fixed.
 * The corpus pass at the end is a different question -- can it establish a
 * number for real generations at all -- and it has no expected value, only the
 * requirement that it is not zero for every one of them.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync, existsSync, mkdirSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';
import process from 'node:process';

import { establishBytes, MAX_PROBE_BYTES } from '../lib/bufferbytes.mjs';
import { READOUT_FIXTURES } from '../lib/fixtures.mjs';
import { REASON } from '../lib/agreement.mjs';
import { loadRows, sourcePathOf } from '../lib/rows.mjs';
import { insideRepo } from '../../spike/lib/measure.mjs';

const run = promisify(execFile);

function die(code, msg) {
  process.stderr.write(`check-bytes-readout.mjs: ${msg}\n`);
  process.exit(code);
}

const args = { cc: null, lab: process.env.OA_LAB || null, corpus: 6 };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  const next = () => { const v = process.argv[++i]; if (v === undefined) die(4, `${a} needs a value`); return v; };
  if (a === '--cc') args.cc = next();
  else if (a === '--lab') args.lab = next();
  else if (a === '--corpus') args.corpus = Number.parseInt(next(), 10);
  else die(4, `unknown option ${a}`);
}
if (!args.cc) die(4, '--cc is required: the read-out is a question put to one compiler');
if (!args.lab) die(4, '--lab is required (or set OA_LAB); it must be outside the repository');
const lab = resolve(args.lab);
if (insideRepo(lab)) die(4, '--lab is inside the repository; measurement output must not be');
if (!Number.isInteger(args.corpus) || args.corpus < 1) die(4, '--corpus must be a positive integer');
mkdirSync(lab, { recursive: true });

try {
  await run(args.cc, ['--version'], { timeout: 30000 });
} catch {
  // Exit 3, and it is the whole reason this file is not a test: "there is no
  // compiler here" is a check that could not be completed, and it must never be
  // reported as a check that passed.
  die(3, `${args.cc} could not be run on this host, so none of these questions was asked`);
}

const problems = [];
const say = (s) => process.stdout.write(`${s}\n`);

/* ---- 1-3. the fixtures, each with the answer it must give ----------------- */
//
// The sources come from `../lib/fixtures.mjs` rather than being spelled here, so
// that `../test/fixtures.test.mjs` can put them through `locateWipe` on a host
// with no compiler. Their SHAPE has been wrong twice -- once in the subject's
// return type and once in the spelling of the wipe -- and both mistakes make
// this check report a working read-out as broken, which is the one failure a
// control must not have. `../lib/fixtures.mjs` has both in full.

for (const fx of READOUT_FIXTURES) {
  // eslint-disable-next-line no-await-in-loop
  const got = await establishBytes({ cc: args.cc, lab, id: `readout-${fx.name}`, src: fx.src, fn: fx.fn });

  // THE APPARATUS CONTROL, FIRST AND ON EVERY FIXTURE. A false assertion that
  // compiled, or a true one that did not, means the read-out is not being
  // evaluated at all and nothing it returns for any fixture means anything.
  if (!got.established && /probe point/.test(String(got.why))) {
    die(5, `${fx.name}: the apparatus control failed: ${got.why}`);
  }

  if (fx.establishes !== null) {
    if (!got.established) problems.push(`${fx.name}: a ${fx.establishes}-byte wipe was refused: ${got.why}`);
    else if (got.bytes !== fx.establishes) problems.push(`${fx.name}: the read-out returned ${got.bytes} for a ${fx.establishes}-byte wipe`);
    else if (got.provenance !== 'compiler') problems.push(`${fx.name}: the reading carries provenance ${got.provenance}, which is not the compiler`);
    else say(`${fx.name.padEnd(8)} established ${got.bytes} bytes in ${got.probes} probes (bound ${MAX_PROBE_BYTES}), provenance ${got.provenance}`);
    continue;
  }

  if (got.established) {
    problems.push(`${fx.name}: established ${got.bytes}; the read-out invented a number where it should have refused`);
  } else if (got.reason !== REASON.O3_BYTES_UNESTABLISHED || !String(got.why).includes(fx.refusalMatches)) {
    problems.push(`${fx.name}: refused for the wrong reason: ${got.reason} -- ${got.why} (expected a refusal naming "${fx.refusalMatches}")`);
  } else {
    say(`${fx.name.padEnd(8)} refused by name: ${got.why}`);
  }
}

/* ---- 4. it establishes something on the real corpus ----------------------- */

const rows = loadRows().filter((r) => r.fam === 'erasure' && r.opt === '-O2' && r.n_spans === 1);
const seen = [];
for (const r of rows.slice(0, args.corpus)) {
  const path = sourcePathOf(r.id);
  if (!existsSync(path)) continue;
  // eslint-disable-next-line no-await-in-loop
  const got = await establishBytes({ cc: args.cc, lab, id: r.id, src: readFileSync(path, 'utf8'), fn: r.fn });
  seen.push({ id: r.id, got });
  say(`  ${r.id.padEnd(28)} ${got.established ? `${got.bytes} bytes` : `refused: ${got.why}`}`);
}
if (!seen.length) {
  die(3, 'no corpus generation was available to probe, so this half of the check was not made');
}
const established = seen.filter((x) => x.got.established).length;
if (established === 0) {
  problems.push(`all ${seen.length} corpus generations probed were refused; the read-out is not working on real sources`);
} else {
  say(`${established} of ${seen.length} corpus generations got a number from the compiler`);
}

if (problems.length) {
  process.stderr.write('THE READ-OUT GAVE A WRONG ANSWER:\n');
  for (const p of problems) process.stderr.write(`  - ${p}\n`);
  process.exit(2);
}
say('\nthe byte-count read-out works on this host and refuses what it must refuse (exit 0)');
process.exit(0);

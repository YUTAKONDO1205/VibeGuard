#!/usr/bin/env node
/**
 * Which of two absorbed wipes is gone -- asked by deletion instead of by reading.
 *
 *   node which-wipe-survived.mjs --lab <dir> [--fixture xtu-inline] [--opt -O2]
 *                               [--cc clang-18] [--ld lld-18]
 *
 * WHY THIS EXISTS. When the `noinline` intervention is removed, full LTO absorbs
 * the subject and the control into `main`, and every reader in this lane loses
 * the ability to tell their two stack buffers apart: lib/record.mjs's
 * absorbedFillReading() gets as far as "32B of fill where the source asks for two
 * 32B wipes, so one of them is gone" and then says, in its own text, that byte
 * counting cannot say WHICH. The claim under test is about the SUBJECT's store
 * specifically, so that is exactly the half a reviewer will press on.
 *
 * The step it is missing is not a better disassembler. It is the find step's own
 * move -- ablate, rebuild, compare -- applied at the link rather than at the
 * compile. Build the family three times:
 *
 *   as written                          the fill the program really has
 *   the SUBJECT's wipe cut from use.c   does the program notice?
 *   the CONTROL's wipe cut from use.c   does the program notice THIS one?
 *
 * and the answer needs no function name to survive, no unit for the observer to
 * resolve, and no way of telling two buffers apart in a listing. A store that
 * contributes nothing to the linked program when it is deleted contributed
 * nothing when it was there.
 *
 * THE CONTROL DELETION IS NOT OPTIONAL. "Deleting the subject's wipe changed
 * nothing" is equally consistent with a build whose output does not respond to
 * the source at all -- a broken command line, a stale object, a link that reused
 * a cached input. The control's wipe may not legally be removed by any level
 * (its buffer is read afterwards through a unit the link cannot see into), so
 * deleting it MUST move the fill. If it does not, whichWipeSurvived() returns
 * BLIND and no comparison beneath it is reported as a result.
 *
 * WHAT IT DOES NOT DO. It reads zero fill, so a wipe that survives as a `memset`
 * CALL is invisible to it -- read-wipe.py reports the call count and this tool
 * refuses to read a body that has one, rather than counting the bytes it can see
 * and calling the rest absent. It measures one family at one level per run. And
 * it is a measurement of THIS fixture: nothing here is a statement about wipes in
 * general, only about whether this lane's one intervention manufactured its own
 * result.
 *
 * Exit: 0 a reading was produced (of any of the four words); 3 the builds could
 * not be made; 4 the arguments or the fixture are not usable.
 *
 * WHAT CHECKS THIS TOOL. Its grading function (whichWipeSurvived) has unit
 * tests; its PLUMBING -- the cut, the twelve compiles, the three links, the
 * three disassembly reads -- is checked by tools/check-which-wipe-plumbing.mjs,
 * which shares this file's cut (lib/variant-cut.mjs) and its build
 * (lib/build-variants.mjs) rather than reimplementing either, and which carries
 * a family whose subject wipe CANNOT be removed so that a pipe able only to
 * answer "already gone" fails instead of agreeing with itself.
 */
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildAndRead } from '../lib/build-variants.mjs';
import { gradeFill } from '../lib/plumbing-run.mjs';
import { VariantCutError, cutWipeVariants } from '../lib/variant-cut.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

const die = (code, msg) => { process.stderr.write(`which-wipe-survived: ${msg}\n`); process.exit(code); };

function parseArgs(argv) {
  const o = { lab: null, fixture: 'xtu-inline', opt: '-O2', cc: 'clang-18', ld: 'lld-18', caller: 'main', bufferBytes: 32 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) die(4, `${a} needs a value`); return argv[++i]; };
    if (a === '--lab') o.lab = next();
    else if (a === '--fixture') o.fixture = next();
    else if (a === '--opt') o.opt = next();
    else if (a === '--cc') o.cc = next();
    else if (a === '--ld') o.ld = next();
    else if (a === '--caller') o.caller = next();
    else if (a === '-h' || a === '--help') { process.stdout.write(`${String(readFileSync(fileURLToPath(import.meta.url), 'utf8')).split('*/')[0]}\n`); process.exit(0); }
    else die(4, `unknown option ${a}`);
  }
  if (!o.lab) die(4, '--lab <dir> is required and must be outside the checkout');
  return o;
}

/**
 * One variant: write use.c, compile four units, link, read the fill.
 *
 * The build itself is lib/build-variants.mjs, shared with
 * tools/check-which-wipe-plumbing.mjs, which is the check on this plumbing. A
 * second copy of the compile-and-read sequence could agree with this one while
 * both were wrong, which is the whole failure this lane is trying not to have.
 */
function readOneVariant(o, work, tag, useSource) {
  const r = buildAndRead({
    cc: o.cc, ld: o.ld, opt: o.opt, fixtures: o.fixtures, work, tag, useSource,
    caller: o.caller, helper: 'secure_wipe', bufferBytes: o.bufferBytes,
  });
  return { bytes: r.subject?.bytes ?? null, memsetCalls: r.subject?.memsetCalls ?? 0, verdict: r.subject?.verdict ?? null };
}

function main() {
  const o = parseArgs(process.argv);
  if (resolve(o.lab).startsWith(resolve(HERE, '..', '..', '..', '..'))) {
    die(4, '--lab is inside the checkout. Builds are measurement output and live in the lab.');
  }
  o.fixtures = join(o.lab, 'fixtures', o.fixture);
  const usePath = join(o.fixtures, 'use.c');
  if (!existsSync(usePath)) die(4, `${o.fixture}/use.c is not in ${join(o.lab, 'fixtures')}; run tools/make-lto-fixtures.sh first`);

  // The cut is lib/variant-cut.mjs: one line, the right line, and a named
  // refusal on zero matches or on two. It used to be a `filter` here, which
  // removed every matching line and could not tell one match from three.
  const asWrittenSrc = readFileSync(usePath, 'utf8');
  let cut;
  try { cut = cutWipeVariants(asWrittenSrc); }
  catch (e) {
    if (e instanceof VariantCutError) die(4, `${o.fixture}/use.c: ${e.reason} -- ${e.message}`);
    throw e;
  }
  const variants = { asWritten: cut.asWritten, subjectCut: cut.subjectCut.text, controlCut: cut.controlCut.text };

  const work = join(o.lab, `which-wipe-${o.fixture}${o.opt}`);
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });

  const readings = {};
  for (const [tag, src] of Object.entries(variants)) {
    try { readings[tag] = readOneVariant(o, work, tag, src); }
    catch (e) { die(3, `${tag} did not build: ${String(e.message).slice(0, 400)}`); }
  }

  // The grade, including the refusal on a surviving memset call, is
  // lib/plumbing-run.mjs's gradeFill() -- shared with the check on this tool, so
  // that the tool and its check cannot come to grade differently.
  const calls = Object.entries(readings).filter(([, r]) => r.memsetCalls > 0).map(([t]) => t);
  const reading = gradeFill(
    { asWritten: readings.asWritten.bytes, subjectCut: readings.subjectCut.bytes, controlCut: readings.controlCut.bytes },
    calls,
  );

  process.stdout.write(`${JSON.stringify({
    lane: 'lto-window',
    tool: 'which-wipe-survived',
    fixture: o.fixture,
    optLevel: o.opt,
    caller: o.caller,
    bufferBytes: o.bufferBytes,
    fillBytes: {
      asWritten: readings.asWritten.bytes,
      subjectWipeDeleted: readings.subjectCut.bytes,
      controlWipeDeleted: readings.controlCut.bytes,
    },
    memsetCalls: Object.fromEntries(Object.entries(readings).map(([t, r]) => [t, r.memsetCalls])),
    ...reading,
  }, null, 1)}\n`);
}

main();

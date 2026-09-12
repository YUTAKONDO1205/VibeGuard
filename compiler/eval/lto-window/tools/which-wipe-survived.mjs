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
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { WHICH_WIPE, whichWipeSurvived } from '../lib/record.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const READ_WIPE = join(HERE, 'read-wipe.py');

/** The two lines the generator writes, and which wipe each one is. */
const CUTS = Object.freeze({
  subject: /^\s*secure_wipe\(key, sizeof key\);\s*$/,
  control: /^\s*memset\(keep, 0, sizeof keep\);\s*$/,
});

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

/** One variant: write use.c, compile four units, link, read the fill. */
function buildAndRead(o, work, tag, useSource) {
  const objs = [];
  for (const unit of ['io', 'main', 'wipe']) {
    const src = join(o.fixtures, `${unit}.c`);
    const obj = join(work, `${tag}_${unit}.o`);
    // io.c is deliberately NOT -flto: it is the opaque unit the link cannot see
    // into, which is what makes the control's buffer un-removable.
    const flto = unit === 'io' ? [] : ['-flto'];
    execFileSync(o.cc, [o.opt, ...flto, '-c', src, '-o', obj], { stdio: 'pipe' });
    objs.push(obj);
  }
  const useObj = join(work, `${tag}_use.o`);
  const usePath = join(work, `${tag}_use.c`);
  writeFileSync(usePath, useSource, 'utf8');
  execFileSync(o.cc, [o.opt, '-flto', '-c', usePath, '-o', useObj], { stdio: 'pipe' });
  objs.push(useObj);

  const exe = join(work, `app_${tag}`);
  execFileSync(o.cc, [o.opt, '-flto', `-fuse-ld=${o.ld}`, ...objs, '-o', exe], { stdio: 'pipe' });

  const out = execFileSync('python3', [READ_WIPE, exe, o.caller, 'secure_wipe', String(o.bufferBytes), o.caller, String(o.bufferBytes)], { encoding: 'utf8' });
  const j = JSON.parse(out);
  return { bytes: j.subject?.bytes ?? null, memsetCalls: j.subject?.memsetCalls ?? 0, verdict: j.subject?.verdict ?? null };
}

function main() {
  const o = parseArgs(process.argv);
  if (resolve(o.lab).startsWith(resolve(HERE, '..', '..', '..', '..'))) {
    die(4, '--lab is inside the checkout. Builds are measurement output and live in the lab.');
  }
  o.fixtures = join(o.lab, 'fixtures', o.fixture);
  const usePath = join(o.fixtures, 'use.c');
  if (!existsSync(usePath)) die(4, `${o.fixture}/use.c is not in ${join(o.lab, 'fixtures')}; run tools/make-lto-fixtures.sh first`);

  const asWrittenSrc = readFileSync(usePath, 'utf8');
  const lines = asWrittenSrc.split('\n');
  const variants = { asWritten: asWrittenSrc };
  for (const [which, re] of Object.entries(CUTS)) {
    const kept = lines.filter((l) => !re.test(l));
    if (kept.length === lines.length) die(4, `${o.fixture}/use.c has no line matching the ${which} wipe (${re}); the fixture shape changed`);
    variants[`${which}Cut`] = kept.join('\n');
  }

  const work = join(o.lab, `which-wipe-${o.fixture}${o.opt}`);
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });

  const readings = {};
  for (const [tag, src] of Object.entries(variants)) {
    try { readings[tag] = buildAndRead(o, work, tag, src); }
    catch (e) { die(3, `${tag} did not build: ${String(e.stderr || e.message).slice(0, 300)}`); }
  }

  // A surviving memset CALL is a length this reading cannot see. Refuse rather
  // than count the inline bytes and treat the call as absent.
  const calls = Object.entries(readings).filter(([, r]) => r.memsetCalls > 0);
  const reading = calls.length
    ? { reading: WHICH_WIPE.INCONCLUSIVE, proves: null, why: `${calls.map(([t]) => t).join(', ')} left a memset call, whose length this reading cannot see` }
    : whichWipeSurvived({ asWritten: readings.asWritten.bytes, subjectCut: readings.subjectCut.bytes, controlCut: readings.controlCut.bytes });

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

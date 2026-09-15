#!/usr/bin/env node
/**
 * Does the which-wipe tool's PLUMBING work -- the part between the source and
 * the three integers?
 *
 *   node check-which-wipe-plumbing.mjs --lab <dir> [--fixture xtu-inline]
 *                                      [--opt -O2] [--cc clang-18] [--ld lld-18]
 *
 * WHY THIS EXISTS. `whichWipeSurvived()` in lib/record.mjs grades three integers
 * and is covered by unit tests, including the ordering of its BLIND guard. What
 * PRODUCES the three integers -- three source variants, twelve compiles, three
 * full-LTO links, three objdump reads -- was covered by nothing. The two failure
 * modes that matter are the two that do not raise:
 *
 *   the cut removes the wrong line, or removes nothing;
 *   the reader counts the fill of the wrong function body.
 *
 * Both produce three numbers, a plausible table, and a green unit suite. The
 * lane's published 32/32/0 is this tool's output, so a check that only grades
 * integers is a check of the last step of a pipe nobody has looked into.
 *
 * WHAT IT ESTABLISHES, in the order it is allowed to establish them
 * (lib/plumbing-gates.mjs holds the order, and the subject's word is a thunk
 * that a failed gate never calls):
 *
 *   1  the cut is exactly one line, and the RIGHT line, against the generator's
 *      own template and against the lab's rendered use.c. Zero matches or two
 *      matches is a refusal, not a first-match.
 *   2  the three variants really are three source TEXTS, and then three
 *      compilations: three distinct sha256 over the source read back off disk,
 *      and three over the pre-link object of the edited unit, which every
 *      variant is compiled from ONE path so that a filename cannot be what
 *      makes them differ. (Not over the executable -- the finding under test is
 *      that two of the three executables are the same bytes.)
 *   3  the as-written control reads PRESENT, in the body the cell names, BEFORE
 *      any subject verdict is read.
 *   4  deleting the control's wipe removes exactly the control's wipe.
 *   5  the measured triple and the word agree with data/which-wipe-survived.json,
 *      which is what the README's table is read from.
 *   6  POSITIVE CONTROL. A family whose subject wipe cannot be removed at all
 *      (the zeroed bytes escape into a unit the link cannot see into) must come
 *      back `subject-store-still-there`. A tool that can only ever answer
 *      "already gone" is not measuring, and the published table would be
 *      indistinguishable from a broken pipe. See lib/pc-fixture.mjs.
 *
 * THE ORDER OF THE REFUSALS IS PART OF THE CONTRACT. Everything that can be
 * decided without a compiler is decided first: the arguments, the tracked row,
 * and the cut. Only then is the toolchain probed. A refusal that depends on
 * which machine it is run on is not a refusal anybody can test, and these ones
 * are now tested (test/check-plumbing-cli.test.mjs) on machines with no clang.
 *
 * EXIT CODES, and the distinction rule 8 of this repository turns on -- a check
 * that cannot run exits non-zero naming why, and never quietly returns 0:
 *
 *   0   every gate passed
 *   3   a build or a read failed (the measurement could not be made)
 *   4   the arguments, the fixture or the cut are not usable
 *   5   THE MEASUREMENT RAN AND DISAGREED (a gate failed, or the numbers moved)
 *   69  THIS ENVIRONMENT HAS NO TOOLCHAIN -- a refusal, not a pass and not a
 *       disagreement. Distinct from 5 on purpose: "no compiler here" and "the
 *       compiler said something else" are not the same news.
 *   1   (no envelope, a stack trace) THIS CHECK ITSELF IS BROKEN. Not one of its
 *       answers. Anything that is not a BuildFailure comes out here rather than
 *       being reported as 3, because "the measurement could not be made" is a
 *       statement about the environment and a TypeError in this file is not.
 */
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { BuildFailure, buildAndRead, missingTools, readAgain } from '../lib/build-variants.mjs';
import { PC_EXPECTED, writePositiveControlFixture } from '../lib/pc-fixture.mjs';
import { GATE_ORDER } from '../lib/plumbing-gates.mjs';
import { runFamily } from '../lib/plumbing-run.mjs';
import { VariantCutError, cutWipeVariants, renderUseC, useTemplateFrom } from '../lib/variant-cut.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const GENERATOR = join(HERE, 'make-lto-fixtures.sh');
const TABLE = join(HERE, '..', 'data', 'which-wipe-survived.json');

export const EXIT = Object.freeze({ OK: 0, BUILD: 3, USAGE: 4, DISAGREED: 5, NO_TOOLCHAIN: 69 });

/**
 * Which exit code an exception out of the measurement deserves, or null for
 * "not this check's to report".
 *
 * Exported so that it is testable without a toolchain, because the distinction
 * is the whole point of it: exit 3 says the build or the read failed, and a
 * check that mapped EVERY exception to 3 would report its own bugs as the
 * environment's. Only a BuildFailure -- which lib/build-variants.mjs raises, and
 * only for a compile, a link, a write that did not land, or a read -- is that.
 */
export function measureFailureExit(e) {
  return e instanceof BuildFailure ? EXIT.BUILD : null;
}

const out = [];
const say = (s) => out.push(s);
function die(code, msg, extra = {}) {
  process.stderr.write(`check-which-wipe-plumbing: ${msg}\n`);
  process.stdout.write(`${JSON.stringify({ lane: 'lto-window', check: 'which-wipe-plumbing', ok: false, exit: code, why: msg, ...extra, log: out }, null, 1)}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const o = { lab: null, fixture: 'xtu-inline', opt: '-O2', cc: 'clang-18', ld: 'lld-18' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) die(EXIT.USAGE, `${a} needs a value`); return argv[++i]; };
    if (a === '--lab') o.lab = next();
    else if (a === '--fixture') o.fixture = next();
    else if (a === '--opt') o.opt = next();
    else if (a === '--cc') o.cc = next();
    else if (a === '--ld') o.ld = next();
    else if (a === '-h' || a === '--help') { process.stdout.write(`${String(readFileSync(fileURLToPath(import.meta.url), 'utf8')).split('*/')[0]}\n`); process.exit(0); }
    else die(EXIT.USAGE, `unknown option ${a}`);
  }
  if (!o.lab) die(EXIT.USAGE, '--lab <dir> is required and must be outside the checkout');
  if (resolve(o.lab).startsWith(resolve(HERE, '..', '..', '..', '..'))) {
    die(EXIT.USAGE, '--lab is inside the checkout. Builds are measurement output and live in the lab.');
  }
  return o;
}

/* ------------------------------------------------------------- the cut -- */

function checkCut(o) {
  let template;
  try { template = useTemplateFrom(readFileSync(GENERATOR, 'utf8')); }
  catch (e) { die(EXIT.USAGE, `the fixture generator's template could not be read: ${e.message}`); }

  const cuts = {};
  for (const family of ['xtu', 'xtu-inline']) {
    try {
      const v = cutWipeVariants(renderUseC(template, family));
      cuts[family] = { subject: v.subjectCut.removedLine.trim(), control: v.controlCut.removedLine.trim() };
    } catch (e) {
      const why = e instanceof VariantCutError ? `${e.reason}: ${e.message}` : e.message;
      die(EXIT.USAGE, `the cut refused on the generator's ${family} template -- ${why}`);
    }
  }
  say(`cut: the generator's own template cuts cleanly for both families (${JSON.stringify(cuts)})`);

  // And against the file the measurement will actually read, which is the
  // rendered one in the lab. The template test above cannot catch a lab whose
  // fixtures were written by an older generator.
  const usePath = join(o.fixtures, 'use.c');
  if (!existsSync(usePath)) die(EXIT.USAGE, `${o.fixture}/use.c is not in ${join('<lab>', 'fixtures')}; run tools/make-lto-fixtures.sh first`);
  let live;
  try { live = cutWipeVariants(readFileSync(usePath, 'utf8')); }
  catch (e) {
    const why = e instanceof VariantCutError ? `${e.reason}: ${e.message}` : e.message;
    die(EXIT.USAGE, `the cut refused on the lab's ${o.fixture}/use.c -- ${why}`);
  }
  say(`cut: the lab's ${o.fixture}/use.c removes "${live.subjectCut.removedLine.trim()}" and "${live.controlCut.removedLine.trim()}", one line each`);
  return live;
}

/* ------------------------------------------------- one family, measured -- */

function measure(o, spec, variants, work) {
  // The wiring is lib/plumbing-run.mjs, which takes its builder as an argument
  // so that test/plumbing-run.test.mjs can drive every branch of it -- including
  // a variant that was not rebuilt and a fill counted in the wrong body -- on a
  // machine with no toolchain. Here the builder is the real one, and its BUILD
  // failures become exit 3. Nothing else does: see measureFailureExit().
  try {
    return runFamily({
      spec: { ...spec, cc: o.cc, ld: o.ld, opt: o.opt, work },
      variants,
      build: buildAndRead,
    });
  } catch (e) {
    const code = measureFailureExit(e);
    if (code === null) throw e;
    return die(code, `${spec.label}: ${e.step}: ${e.message}`);
  }
}

function reportGates(label, result, fill, readings, spec, o) {
  for (const g of result.gates) say(`${label}: ${g.ok ? 'ok  ' : 'FAIL'} ${g.gate}${g.ok ? '' : ` -- ${g.why}`}`);
  if (!result.failed) return;
  // What a failed reading was looking at is part of the failure. If the body the
  // cell names was not read, say what IS in the executable at the two names the
  // fixture writes, rather than leaving the reader to go and disassemble it.
  // readAgain() reports whether it could read at all, separately from what it
  // read: "this function is not in the binary" and "no read was taken" are not
  // the same news, and they used to print as the same null.
  const diag = {};
  for (const fn of [spec.caller, 'handle', 'wipe_kept', 'main']) {
    if (diag[fn]) continue;
    const r = readAgain({ exe: readings.asWritten.exe, caller: fn, helper: spec.helper, bufferBytes: spec.bufferBytes });
    diag[fn] = r.ok
      ? { verdict: r.reading.verdict, where: r.reading.where, bytes: r.reading.bytes, memsetCalls: r.reading.memsetCalls }
      : { notRead: r.why };
  }
  die(EXIT.DISAGREED, `${label}: ${result.failed}`, {
    gates: result.gates, fillBytes: fill, asWrittenReadAt: diag, gateOrder: GATE_ORDER,
    controlIndependence: result.controlIndependence,
    optLevel: o.opt, toolchain: { cc: o.cc, ld: o.ld },
  });
}

/* ---------------------------------------------------------------- main -- */

export function main() {
  const o = parseArgs(process.argv);
  o.fixtures = join(o.lab, 'fixtures', o.fixture);

  // Everything decidable without a compiler, first. See the header: a refusal
  // that fires only on a machine with a toolchain is a refusal nothing can test.
  const table = JSON.parse(readFileSync(TABLE, 'utf8'));
  const row = table.rows.find((r) => r.fixture === o.fixture && r.optLevel === o.opt);
  if (!row) die(EXIT.USAGE, `data/which-wipe-survived.json has no row for ${o.fixture} at ${o.opt}; this check re-measures a tracked row, it does not write one`);
  if (!row.instrumentReads) {
    die(EXIT.USAGE,
      `the tracked row for ${o.fixture} at ${o.opt} reads ${row.reading}: there is no fill at any of the three `
      + 'builds there, so the plumbing cannot be checked at this level. Ask for a level whose row reads.');
  }

  const live = checkCut(o);

  const absent = missingTools({ cc: o.cc, ld: o.ld });
  if (absent.length) {
    die(EXIT.NO_TOOLCHAIN,
      `this environment has no ${absent.map((m) => `${m.tool} (${m.why})`).join(', ')}: the plumbing cannot be `
      + 'checked here. This is a refusal, not a pass and not a disagreement -- run it where clang and lld are '
      + '(the repository runs it in the CI job that installs lld-18).',
      { missing: absent });
  }

  const work = join(o.lab, `check-which-wipe-${o.fixture}${o.opt}`);
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, { recursive: true });

  const spec = {
    label: o.fixture, fixtures: o.fixtures, caller: row.caller, helper: 'secure_wipe',
    bufferBytes: row.bufferBytes, controlCaller: row.caller, controlBytes: row.bufferBytes,
  };
  const m = measure(o, spec, live, work);
  reportGates(o.fixture, m.result, m.fill, m.readings, spec, o);

  // 5. the numbers, against the tracked row the README is read from.
  const want = { asWritten: row.fillBytes.asWritten, subjectCut: row.fillBytes.subjectWipeDeleted, controlCut: row.fillBytes.controlWipeDeleted };
  const moved = Object.keys(want).filter((k) => want[k] !== m.fill[k]);
  const gotWord = m.word;
  if (moved.length || gotWord !== row.reading) {
    die(EXIT.DISAGREED,
      `${o.fixture} at ${o.opt} no longer reads what data/which-wipe-survived.json records`
      + `${moved.length ? `: ${moved.map((k) => `${k} ${want[k]} -> ${m.fill[k]}`).join(', ')}` : ''}`
      + `${gotWord !== row.reading ? `; reading ${row.reading} -> ${gotWord}` : ''}`,
      { tracked: want, measured: m.fill, trackedReading: row.reading, measuredReading: gotWord, why: m.result.subject?.why ?? null });
  }
  say(`${o.fixture} at ${o.opt}: ${JSON.stringify(m.fill)} and ${gotWord}, as tracked`);

  // 6. the positive control.
  const pcDir = join(work, 'positive-control');
  writePositiveControlFixture(o.fixtures, pcDir);
  const pcSource = readFileSync(join(pcDir, 'use.c'), 'utf8');
  let pcVariants;
  try { pcVariants = cutWipeVariants(pcSource); }
  catch (e) { die(EXIT.USAGE, `the positive control's own use.c does not cut: ${e.message}`); }

  const pcSpec = {
    label: 'positive-control', fixtures: pcDir, caller: PC_EXPECTED.caller, helper: PC_EXPECTED.helper,
    bufferBytes: PC_EXPECTED.subjectBytes, controlCaller: PC_EXPECTED.caller, controlBytes: PC_EXPECTED.controlBytes,
  };
  const pcWork = join(work, 'pc-build');
  mkdirSync(pcWork, { recursive: true });
  const pc = measure(o, pcSpec, pcVariants, pcWork);
  reportGates('positive-control', pc.result, pc.fill, pc.readings, pcSpec, o);

  const pcWord = pc.word;
  if (pcWord !== PC_EXPECTED.reading) {
    die(EXIT.DISAGREED,
      `the positive control read ${pcWord}, not ${PC_EXPECTED.reading}. Its subject's wipe is read afterwards `
      + 'through a unit the link cannot see into, so it cannot legally be removed and the tool is required to '
      + 'say so. A tool that answers "already gone" here would answer it for a broken pipe too, and the lane\'s '
      + 'published table would not be distinguishable from one.',
      { fillBytes: pc.fill, measuredReading: pcWord, why: pc.result.subject?.why ?? null });
  }
  if (pc.fill.asWritten !== pc.fill.subjectCut + pc.fill.controlCut) {
    die(EXIT.DISAGREED,
      `the positive control's fill is not additive (${pc.fill.asWritten} != ${pc.fill.subjectCut} + ${pc.fill.controlCut}): `
      + 'both wipes are un-removable and each cut should take exactly one of them away, so a reader that is '
      + 'counting one body cleanly cannot produce these three numbers',
      { fillBytes: pc.fill });
  }
  say(`positive-control: ${JSON.stringify(pc.fill)} and ${pcWord} -- the tool can report survival`);

  process.stdout.write(`${JSON.stringify({
    lane: 'lto-window',
    check: 'which-wipe-plumbing',
    ok: true,
    exit: EXIT.OK,
    fixture: o.fixture,
    optLevel: o.opt,
    toolchain: { cc: o.cc, ld: o.ld, objdump: m.readings.asWritten.objdump },
    gateOrder: GATE_ORDER,
    // What the as-written control reading is and is not: in this family it is
    // the same question as the subject's, and the record says so rather than
    // letting a passing gate imply an independent reading. See README.md's
    // "What the control gate is not" and lib/plumbing-gates.mjs.
    controlIndependence: m.result.controlIndependence,
    measured: { fillBytes: m.fill, reading: gotWord, useObjectDigests: Object.fromEntries(Object.entries(m.readings).map(([t, r]) => [t, r.useDigest.slice(0, 16)])), sourceDigests: Object.fromEntries(Object.entries(m.readings).map(([t, r]) => [t, r.sourceDigest.slice(0, 16)])) },
    positiveControl: { fillBytes: pc.fill, reading: pcWord, useObjectDigests: Object.fromEntries(Object.entries(pc.readings).map(([t, r]) => [t, r.useDigest.slice(0, 16)])) },
    log: out,
  }, null, 1)}\n`);
}

// Run when invoked as a script; stay importable when a test wants the pieces
// above. test/check-plumbing-cli.test.mjs spawns this file for its exit codes,
// so a guard that stopped matching would show up there as a check that prints
// nothing and exits 0 rather than as silence.
const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) main();

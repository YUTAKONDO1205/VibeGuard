/**
 * The O2 side: the same translation unit, under `libPropertyObserver.so`.
 *
 * The invocation is NOT re-derived here. `../../spike/lib/observer.mjs` already
 * settled what the plugin has to be told -- `OBS_TARGET_FN`, `OBS_CONTROL_FN`,
 * `OBS_EFFECT_SYMBOLS`, `OBS_OUT`, `OBS_MODE`, plus `-fpass-plugin=` on the
 * driver -- and settled the two things around it that are easy to get wrong and
 * silent when you do: the effect-symbol list comes out of
 * `compiler/schema/effect-symbol-lists.json` (group `wipe-5-observer`) rather
 * than being spelled, and `check-subject-resolution.mjs` is run on every log,
 * because a subject name that resolves to nothing compiles cleanly and reads a
 * healthy control. This module imports `effectSymbols`, `readSummaries` and
 * `CONTROL_FN` from there and adds exactly one thing: it points the same
 * invocation at a CORPUS generation instead of at the two spikes.
 *
 * `test/lane.test.mjs` pins the reuse by comparing the `OBS_*` key set this file
 * builds against the key set `../../spike/lib/observer.mjs` spells in its own
 * source. If the spike lane starts telling the plugin something this lane does
 * not, the two are no longer configuring the same instrument and the test fails
 * rather than the tables quietly diverging.
 *
 * WHAT IS DELIBERATELY THE SAME AS THE CORPUS RUN. The `CONTROL` function is
 * appended to the source exactly as `../../ai-generated/lib/build-analyze.mjs`
 * appends it, so the positive control both oracles read is one function compiled
 * once, not two functions that happen to share a name.
 *
 * WHAT IS DELIBERATELY DIFFERENT. The corpus run compiled to assembly and
 * compared text; this compiles to an object file and reads a log written between
 * passes. Those are the two instruments, and making them more alike than that
 * would be making them one instrument again.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONTROL } from '../../ai-generated/lib/ablation-cell.mjs';
import { effectSymbols, readSummaries, CONTROL_FN } from '../../spike/lib/observer.mjs';
import { insideRepo, vendorLabel } from '../../spike/lib/measure.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * The repository's own subject-resolution checker.
 *
 * The path is spelled again here rather than imported, because
 * `../../spike/lib/observer.mjs` keeps it as a module-private constant. That is
 * a duplicated path and it is recorded as such in the README's "Edits requested
 * in files this lane does not own": the right fix is for the spike lane to
 * export it, and editing another lane's module to suit this one is not this
 * lane's decision to take.
 */
const CHECKER = resolve(HERE, '../../../pass-instrumentation/observer/tools/check-subject-resolution.mjs');

/** What `OBS_MODE` is set to. The mode the other observer harnesses use. */
export const OBS_MODE = 'standard';

/**
 * Everything the plugin is told, for one cell.
 *
 * Split out from the compile so the key set can be tested without a compiler,
 * and so the one place a variable reaches the plugin is one function.
 */
export function observerEnv({ fn, logPath, symbols, base = {} }) {
  return {
    ...base,
    OBS_TARGET_FN: fn,
    OBS_CONTROL_FN: CONTROL_FN,
    OBS_EFFECT_SYMBOLS: symbols,
    OBS_OUT: logPath,
    OBS_MODE,
  };
}

/** The driver arguments. `-c`, because this lane observes the compile, not a link. */
export const observerArgs = ({ opt, srcPath, objPath, plugin }) => (
  [opt, '-c', srcPath, '-o', objPath, `-fpass-plugin=${plugin}`]
);

/**
 * Is this environment able to run the O2 channel at all?
 *
 * Reported as a REASON rather than as a boolean, and the runner turns a negative
 * into exit 3 -- a check that could not be completed -- rather than into a table
 * with an empty denominator. A lane that printed "0/0, they agree perfectly"
 * because the plugin was not built would be the worst possible output.
 */
export function channelAvailable({ plugin }) {
  if (!plugin) return { available: false, reason: 'no --observer plugin was given, so the second oracle was not run' };
  if (!existsSync(plugin)) return { available: false, reason: 'the PropertyObserver plugin is not built in this environment' };
  if (!existsSync(CHECKER)) return { available: false, reason: 'check-subject-resolution.mjs is not present' };
  return { available: true, reason: null };
}

/**
 * Observe one corpus cell.
 *
 * @param {object} args
 * @param {string} args.plugin    path to libPropertyObserver.so
 * @param {string} args.cc        the driver; the plugin is built against one LLVM
 * @param {string} args.opt       the level
 * @param {string} args.lab       scratch directory, OUTSIDE the repository
 * @param {string} args.id        the generation's id; names the scratch files
 * @param {string} args.fn        the function whose property is watched
 * @param {string} args.srcPath   the generation, inside the repository, read only
 * @param {string} args.symbols   the effect-symbol list, from the registry
 * @returns {Promise<object>} a reading in the shape `classifyPair` wants for `o2`
 */
export async function observeCell(args) {
  const { plugin, cc, opt, lab, id, fn, srcPath, symbols } = args;
  if (insideRepo(lab)) throw new Error('observeCell: the lab directory is inside the repository');
  mkdirSync(lab, { recursive: true });

  const tag = `oa.${id}.${vendorLabel(cc)}${opt}`;
  const labSrc = join(lab, `${tag}.c`);
  const logPath = join(lab, `${tag}.tsv`);
  const objPath = join(lab, `${tag}.o`);

  // The same append the corpus run makes. Read from the repository, written to
  // the lab: `interfaces.md` section 1 puts measurement inputs on the side that
  // produces them, and nothing this lane does touches a tracked file.
  writeFileSync(labSrc, readFileSync(srcPath, 'utf8') + CONTROL, 'utf8');

  const env = observerEnv({ fn, logPath, symbols, base: process.env });

  let compiled = true;
  let compileError = null;
  try {
    await run(cc, observerArgs({ opt, srcPath: labSrc, objPath, plugin }), { env, timeout: 120000 });
  } catch (err) {
    compiled = false;
    // Truncated, and the message is the compiler's. It can name the lab path,
    // which is why the runner never puts this string into the written report --
    // see the absolute-path guard in run-oracle-agreement.mjs.
    compileError = String(err.stderr || err.message).slice(0, 200);
  }
  if (!compiled || !existsSync(logPath)) {
    return {
      finalState: 'BROKEN_MEASUREMENT',
      control: null,
      firstLossPass: null,
      // Not 0: a run whose compile failed has not been shown to have resolved
      // its subject, and reporting 0 here would let it past the first guard in
      // classifyPair on the strength of a check that never ran.
      subjectResolutionExit: null,
      compiled,
      compileError,
    };
  }

  // The run-level question, asked by the repository's own checker rather than by
  // a reimplementation of it here. Exit 2 is a broken run, 3 is a run it could
  // not judge; both leave the denominator, and the exit code is carried so which
  // one it was stays visible in the exclusion list.
  let rc = 3;
  try { await run(process.execPath, [CHECKER, logPath], { timeout: 60000 }); rc = 0; }
  catch (e) { rc = typeof e.code === 'number' ? e.code : 3; }

  const rows = readSummaries(readFileSync(logPath, 'utf8'));
  const subject = rows.find((r) => r.role === 'subject' && r.name === fn) || null;
  const control = rows.find((r) => r.role === 'control') || null;

  return {
    // `interfaces.md` section 3.1's pairing rule: a cell that failed to measure
    // is NOT_OBSERVED with the reason beside it, never a property state invented
    // for an observation that did not happen. A subject row that is simply
    // absent while `rc` is 0 is the legal `measurement OK + NOT_OBSERVED` pair
    // the lto-window lane used to throw on; `agreement.mjs` files it under
    // NO_READING rather than under BROKEN_MEASUREMENT, so "the instrument ran
    // and there was nothing here to read" is not counted as an instrument that
    // failed.
    finalState: subject ? subject.finalState : 'NOT_OBSERVED',
    control: control ? control.finalState : null,
    firstLossPass: subject ? subject.firstLossPass : null,
    subjectResolutionExit: rc,
    compiled: true,
    compileError: null,
  };
}

export { effectSymbols, CONTROL_FN };

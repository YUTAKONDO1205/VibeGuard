/**
 * The second channel: the same two spikes under `libPropertyObserver.so`.
 *
 * The differential channel decides by compiling twice and comparing a function
 * body. This one decides by watching the pass pipeline and reading the state the
 * property ended in. They are different instruments answering the same question
 * about the same two translation units, which is the only reason running both is
 * worth anything: a pair that agrees has been checked by something that does not
 * share its failure modes, and a pair that disagrees is a result.
 *
 * The subject and the control are CO-RESIDENT here as well, and the control is
 * the same one the differential channel uses -- `vgctl_control`, appended from
 * ../../ai-generated/lib/ablation-cell.mjs -- because its wipe is read
 * afterwards and no pass may remove it. The observer is told about it by name
 * (`OBS_CONTROL_FN`) and reports its state in the same log.
 *
 * The effect-symbol list is READ from `compiler/schema/effect-symbol-lists.json`
 * (the group `wipe-5-observer`, the one the other observer harnesses are
 * registered under) rather than spelled here. `compiler/schema/
 * effect-symbol-lists.test.mjs` fails on any literal the registry does not
 * declare, and rightly: a harness that spells its own list is asking a different
 * question in the same words.
 *
 * WHAT THIS CHANNEL ADDS THAT THE OTHER CANNOT. The observer's third silent
 * failure is a subject name that resolves to nothing: `OBS_TARGET_FN=...X` is a
 * valid configuration of a function that does not exist, and the compile exits
 * 0, the log is non-empty, hundreds of passes are counted and the control reads
 * PRESENT. Measured here on 2026-09-12, clang-18 -O2: exactly that, with the
 * subject's SUMMARY row simply absent. `tools/check-subject-resolution.mjs`
 * exits 2 on it, and this module runs that checker on every log it produces --
 * which, until this lane existed, no harness in the repository did.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONTROL } from '../../ai-generated/lib/ablation-cell.mjs';
import { SUBJECTS, MISSPELT_SUFFIX, insideRepo, vendorLabel } from './measure.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const SUBJECT_DIR = resolve(HERE, '../subjects');
const REGISTRY = resolve(HERE, '../../../schema/effect-symbol-lists.json');
const CHECKER = resolve(HERE, '../../../pass-instrumentation/observer/tools/check-subject-resolution.mjs');

/** The name of the function CONTROL defines. Its wipe is read afterwards, so it cannot be removed. */
export const CONTROL_FN = 'vgctl_control';

/** The registry group this channel is configured from. */
export const EFFECT_LIST = 'wipe-5-observer';

/** Column indices of the plugin's SUMMARY record (History.cpp emitSummaryInto). */
const SUMMARY_NAME = 1;
const SUMMARY_ROLE = 3;
const SUMMARY_FIRST_LOSS_PASS = 6;
const SUMMARY_FINAL_STATE = 10;

/** The effect-symbol list, read from the registry rather than spelled here. */
export function effectSymbols(registryPath = REGISTRY) {
  const doc = JSON.parse(readFileSync(registryPath, 'utf8'));
  const list = doc && doc.lists && doc.lists[EFFECT_LIST];
  if (!list || typeof list.literal !== 'string') {
    throw new Error(`compiler/schema/effect-symbol-lists.json declares no list ${EFFECT_LIST}`);
  }
  return list.literal;
}

/**
 * The SUMMARY rows of one log, as {name, role, finalState, firstLossPass}.
 *
 * `moduleId` is deliberately not returned. The plugin writes the source path
 * into SUBJECTRES, and a record carrying it would publish the measuring
 * machine's directory layout.
 */
export function readSummaries(text) {
  const out = [];
  for (const line of text.split('\n')) {
    if (!line.startsWith('SUMMARY\t')) continue;
    const f = line.split('\t');
    out.push({
      name: f[SUMMARY_NAME],
      role: f[SUMMARY_ROLE],
      finalState: f[SUMMARY_FINAL_STATE],
      firstLossPass: f[SUMMARY_FIRST_LOSS_PASS] === '-' ? null : f[SUMMARY_FIRST_LOSS_PASS],
    });
  }
  return out;
}

/**
 * Compile both spikes under the plugin at one level and report what it saw.
 *
 * @param {object} args
 * @param {string} args.plugin   path to libPropertyObserver.so
 * @param {string} [args.cc]     the driver; the plugin is built against one LLVM
 * @param {string} args.opt      the level
 * @param {string} args.lab      scratch directory, outside the repository
 * @param {boolean} [args.injected]  misspell OBS_TARGET_FN, to make the checker exit 2
 * @returns {Promise<{available: boolean, reason?: string, readings: Array<object>}>}
 */
export async function measureObserver(args) {
  const { plugin, cc = 'clang-18', opt, lab, injected = false } = args;
  if (!plugin) return { available: false, reason: 'no --observer plugin was given, so this channel was not run', readings: [] };
  if (!existsSync(plugin)) {
    return { available: false, reason: 'the PropertyObserver plugin is not built in this environment', readings: [] };
  }
  if (!existsSync(CHECKER)) {
    return { available: false, reason: 'check-subject-resolution.mjs is not present', readings: [] };
  }
  if (insideRepo(lab)) throw new Error('measureObserver: the lab directory is inside the repository');
  mkdirSync(lab, { recursive: true });

  let symbols;
  try {
    symbols = effectSymbols();
  } catch (err) {
    return { available: false, reason: err.message, readings: [] };
  }

  const readings = [];
  for (const s of SUBJECTS) {
    const fn = injected ? s.fn + MISSPELT_SUFFIX : s.fn;
    const tag = `obs.${s.spike}${injected ? '.inj' : ''}.${vendorLabel(cc)}${opt}`;
    const srcPath = join(lab, `${tag}.c`);
    const logPath = join(lab, `${tag}.tsv`);
    writeFileSync(srcPath, readFileSync(join(SUBJECT_DIR, s.file), 'utf8') + CONTROL, 'utf8');

    const base = {
      vendor: vendorLabel(cc), opt, spike: s.spike, fn, injected, channel: 'observer',
      // interfaces.md's own words. There is no "execution" or "runtime"
      // checkpoint in observation.schema.json and none is needed: this is read
      // between passes, in the compile stage.
      checkpoint: 'after-pass', stage: 'compile',
    };

    const env = {
      ...process.env,
      OBS_TARGET_FN: fn,
      OBS_CONTROL_FN: CONTROL_FN,
      OBS_EFFECT_SYMBOLS: symbols,
      OBS_OUT: logPath,
      OBS_MODE: 'standard',
    };
    let compiled = true;
    try {
      await run(cc, [opt, '-c', srcPath, '-o', join(lab, `${tag}.o`), `-fpass-plugin=${plugin}`], { env, timeout: 90000 });
    } catch {
      compiled = false;
    }
    if (!compiled || !existsSync(logPath)) {
      readings.push({ ...base, verdict: 'BROKEN_MEASUREMENT', control: null, subjectResolutionExit: null });
      continue;
    }

    // The run-level question, asked by the repository's own checker rather than
    // by a reimplementation of it here.
    let rc = 3;
    try { await run(process.execPath, [CHECKER, logPath], { timeout: 60000 }); rc = 0; }
    catch (e) { rc = typeof e.code === 'number' ? e.code : 3; }

    const rows = readSummaries(readFileSync(logPath, 'utf8'));
    const subject = rows.find((r) => r.role === 'subject' && r.name === fn) || null;
    const control = rows.find((r) => r.role === 'control') || null;

    // The pairing rule, interfaces.md section 3.1: a cell that failed to measure
    // is NOT_OBSERVED with the reason beside it, never a property state invented
    // for an observation that did not happen.
    const verdict = rc !== 0 || !subject ? 'NOT_OBSERVED' : subject.finalState;
    readings.push({
      ...base,
      verdict,
      control: control ? control.finalState : null,
      firstLossPass: subject ? subject.firstLossPass : null,
      subjectResolutionExit: rc,
    });
  }
  return { available: true, readings };
}

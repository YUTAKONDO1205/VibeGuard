/**
 * The half of this lane that produces a reading.
 *
 * It compiles the two spikes and reports what came out. It does not know what
 * they were supposed to say: the pre-registered answers live in a directory this
 * module never opens and cannot name, which is the same separation
 * `compiler/eval/calibration` keeps between the script that measures a
 * configuration and the file that says what it should read. An instrument that
 * can see the expected answer can be adjusted until it agrees, and afterwards
 * nobody can tell whether it was adjusted or measured. ../test/lane.test.mjs
 * pins the separation by grepping this file's own source, so the guarantee
 * survives an edit that only meant to improve a comment.
 *
 * Every verdict here comes from `verdictOf` in
 * ../../ai-generated/lib/ablation-cell.mjs -- the same function the corpus lane
 * and the repair loop reach their verdicts through, not a copy of it. That is
 * the point of gating with this lane at all: a gate that judged by its own
 * private rule would certify an instrument it does not share.
 *
 * Nothing is written under `compiler/`. Sources, listings and scratch go to the
 * lab directory the caller names (interfaces.md section 1), and a lab inside the
 * repository is refused rather than used.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join, sep, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CONTROL, wipeSpans, ablateSpans, compile, verdictOf, pool,
} from '../../ai-generated/lib/ablation-cell.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const SUBJECT_DIR = resolve(HERE, '../subjects');
const REPO = resolve(HERE, '../../../..');

/**
 * The pair, and the name of the function each run is configured to observe.
 *
 * This is a manifest, not an expectation: it says which translation units are
 * mixed into a run and what the subject of each is called. What either of them
 * must READ is registered elsewhere and is deliberately not visible from here.
 */
export const SUBJECTS = Object.freeze([
  Object.freeze({ spike: 'disappearing', file: 'spike-disappearing.c', fn: 'vgspike_disappearing' }),
  Object.freeze({ spike: 'surviving', file: 'spike-surviving.c', fn: 'vgspike_surviving' }),
]);

/**
 * What the injected run appends to the subject's name.
 *
 * `OBS_TARGET_FN=handle_requestX` is the observer's own third silent failure --
 * a valid configuration of a subject that does not exist -- and this is the same
 * typo on this channel. One character, appended, so the misspelling cannot
 * accidentally name some other function that does exist.
 */
export const MISSPELT_SUFFIX = 'X';

/**
 * The name a reading is filed under, given the driver that was invoked.
 *
 * The basename, so that `--cc /usr/local/bin/clang-18` grades against the
 * `clang-18` that was registered rather than against nothing -- and so that a
 * reading never carries a directory layout into a record. It is the same
 * reduction `compiler/eval/repair-loop/run-repair-loop.mjs` makes with its own
 * `ccName`. What is EXECUTED is still exactly what the caller named.
 */
export const vendorLabel = (cc) => basename(cc);

/** Is `dir` inside the repository? Measurement output must not be. */
export function insideRepo(dir) {
  const d = resolve(dir);
  return d === REPO || d.startsWith(REPO + sep);
}

/**
 * Which of the requested compilers this host actually has.
 *
 * A compiler that is not installed is not reported as `UNSUPPORTED` here.
 * interfaces.md section 3.1 defines that word as "The toolchain refused the
 * invocation, so there was nothing to read. The configuration was asked for and
 * could not be built." -- one sentence about a toolchain that ran and refused,
 * beside one that could be read to cover a toolchain that is absent. That file
 * does not settle which, and this lane does not settle it on its behalf: a
 * reader who sees `UNSUPPORTED` cannot tell "it refused" from "it is not here".
 * So this reports the two lists and says nothing about the missing ones; the
 * runner turns a non-empty `unavailable` into exit 3 -- a check that could not be
 * completed -- rather than choosing another file's vocabulary for it.
 */
export async function probeCompilers(ccs) {
  const available = [];
  const unavailable = [];
  for (const cc of ccs) {
    try {
      await run(cc, ['--version'], { timeout: 30000 });
      available.push(cc);
    } catch {
      unavailable.push(cc);
    }
  }
  return { available, unavailable };
}

/** The subject source with the positive control appended, as every cell compiles it. */
function sourceFor(subject) {
  return readFileSync(join(SUBJECT_DIR, subject.file), 'utf8') + CONTROL;
}

/**
 * Compile both spikes in every requested configuration and report what read.
 *
 * @param {object} args
 * @param {string[]} args.ccs        compiler drivers, e.g. ['clang-18', 'gcc-13']
 * @param {string[]} args.opts       levels, e.g. ['-O0', '-O2']
 * @param {string}   args.lab        scratch directory, outside the repository
 * @param {boolean} [args.injected]  misspell the subject's name, to make the gate go red
 * @param {number}  [args.concurrency]
 * @returns {Promise<Array<object>>} one reading per (vendor, level, spike)
 */
export async function measureSpikes(args) {
  const { ccs, opts, lab, injected = false, concurrency = 4 } = args;
  if (!Array.isArray(ccs) || ccs.length === 0) throw new Error('measureSpikes: no compiler requested');
  if (!Array.isArray(opts) || opts.length === 0) throw new Error('measureSpikes: no optimisation level requested');
  if (!lab) throw new Error('measureSpikes: no lab directory');
  if (insideRepo(lab)) {
    throw new Error('measureSpikes: the lab directory is inside the repository; '
      + 'measurement inputs and outputs live on the side that produces them (interfaces.md section 1)');
  }
  mkdirSync(lab, { recursive: true });

  // The sources are written once. Both forms of both spikes are the same bytes
  // in every configuration, so a listing that differs differs because of the
  // compiler and not because the input was regenerated between compiles.
  const prepared = SUBJECTS.map((s) => {
    const src = sourceFor(s);
    const fn = injected ? s.fn + MISSPELT_SUFFIX : s.fn;
    const { spans, kinds, scoped } = wipeSpans(src, fn);
    const tag = `${s.spike}${injected ? '.inj' : ''}`;
    const pW = join(lab, `${tag}.w.c`);
    const pWo = join(lab, `${tag}.wo.c`);
    writeFileSync(pW, src, 'utf8');
    if (spans.length) writeFileSync(pWo, ablateSpans(src, spans), 'utf8');
    return { s, fn, spans, kinds, scoped, tag, pW, pWo };
  });

  const cells = [];
  for (const cc of ccs) for (const opt of opts) for (const p of prepared) cells.push({ cc, opt, p });

  const readings = await pool(cells, async ({ cc, opt, p }) => {
    const base = { vendor: vendorLabel(cc), opt, spike: p.s.spike, fn: p.fn, injected, n_spans: p.spans.length, scoped: p.scoped };
    if (!p.spans.length) {
      // Nothing to ablate. The corpus lane's word for this, not a new one.
      return { ...base, verdict: 'NO_WIPE_WRITTEN' };
    }
    const stem = `${p.tag}.${vendorLabel(cc)}${opt}`;
    const aW = await compile(cc, [opt], p.pW, join(lab, `${stem}.w.s`));
    const aWo = await compile(cc, [opt], p.pWo, join(lab, `${stem}.wo.s`));
    return { ...base, ...verdictOf(aW, aWo, p.fn) };
  }, concurrency);

  return readings;
}

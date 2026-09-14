/**
 * O1, RECOMPUTED NOW -- so that a disagreement can be blamed on an instrument
 * rather than on the calendar.
 *
 * THE PROBLEM THIS CLOSES
 *
 * The project ledger states it, and `lib/rows.mjs` repeats it in its own header
 * as a limitation rather than a feature:
 *
 *   O1's half of every pair in this lane was measured on ANOTHER DAY, on the
 *   machine that ran the corpus, with whatever toolchain was installed then.
 *   The second oracle's half is measured now. A disagreement could therefore be
 *   a compiler that has moved rather than a difference between the instruments,
 *   and nothing in the lane could tell those apart.
 *
 * The README's own "What a next run should change" says the same thing in two
 * words -- *name the builds* -- and adds that "a comparison across a toolchain
 * change would need them re-measured together". This module is that
 * re-measurement, and it is a THIRD COLUMN, never a substitute.
 *
 * WHAT IT IS NOT
 *
 * It is NOT a re-derivation of the tracked rows and it must never become one.
 * The corpus lane's tracked rows are a frozen record quoted in a write-up;
 * `lib/rows.mjs` is the only module in this lane that opens them, it imports
 * exactly `readFileSync`, and `test/lane.test.mjs` pins that. This module does
 * not open them at all, in either direction.
 *
 * The table this lane tabulates is still tracked-O1 against the second oracle. The live column sits BESIDE the tracked one so that an
 * off-diagonal cell can be read three ways instead of two:
 *
 *   tracked O1 == live O1, and the second oracle differs
 *       -> the two INSTRUMENTS disagree about this cell. This is the finding
 *          the lane exists to produce, and the toolchain is not a confound.
 *   tracked O1 != live O1
 *       -> the O1 reading itself has moved since the corpus run. Nothing about
 *          the second oracle is established by this cell either way, and
 *          `../../ai-generated/lib/compare-rows.mjs` is the tool for the
 *          question it raises.
 *
 * It is also NOT written into `data/`. A tracked record carries what the lane
 * measured against the frozen rows; today's recompilation of a frozen number
 * belongs in the lab, beside the run that produced it.
 *
 * HOW THE RECOMPUTATION IS KEPT HONEST
 *
 * By not being written here. The recipe is `../../ai-generated/lib/build-analyze.mjs`'s,
 * reached through the SAME exported functions that file uses -- `wipeSpans`,
 * `ablateSpans`, `CONTROL`, `compile`, `verdictOf` -- so "live O1" is the shared
 * oracle run again rather than a second implementation of it. A copy is how two
 * lanes quietly stop measuring the same thing, which is the sentence
 * `ablation-cell.mjs` was extracted under.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import {
  CONTROL, wipeSpans, ablateSpans, compile, verdictOf,
} from '../../ai-generated/lib/ablation-cell.mjs';
import { insideRepo, vendorLabel } from '../../spike/lib/measure.mjs';

/**
 * Do the tracked verdict and the live one say the same thing?
 *
 * Three answers, not two. `SAME` and `MOVED` are readings; `NOT_RECOMPUTED` is
 * the absence of one, and it is a separate word so that a run without
 * `--live-o1` cannot be read as a run in which nothing moved.
 */
export const DRIFT = Object.freeze({
  SAME: 'SAME',
  MOVED: 'MOVED',
  NOT_RECOMPUTED: 'NOT_RECOMPUTED',
});

export function driftOf(trackedVerdict, liveVerdict) {
  if (liveVerdict === null || liveVerdict === undefined) return DRIFT.NOT_RECOMPUTED;
  return trackedVerdict === liveVerdict ? DRIFT.SAME : DRIFT.MOVED;
}

/**
 * Recompute one cell's O1 verdict, now, with today's driver.
 *
 * @returns {Promise<object>} `{ verdict, control, control_via, nSpans, compiled }`
 *   in the shape `verdictOf` returns, plus the span count the ablation used.
 *   `verdict` is `COMPILE_ERROR` or `ABLATION_DID_NOT_COMPILE` when a form did
 *   not build -- `verdictOf`'s own words, not an absence invented here.
 */
export async function recomputeO1({ cc, opt, lab, id, fn, srcPath }) {
  if (insideRepo(lab)) throw new Error('recomputeO1: the lab directory is inside the repository');
  mkdirSync(lab, { recursive: true });

  const src = readFileSync(srcPath, 'utf8');
  const { spans, kinds } = wipeSpans(src, fn);
  const tag = `oa.live.${id}.${vendorLabel(cc)}${opt}`;
  const withWipe = join(lab, `${tag}.w.c`);
  const without = join(lab, `${tag}.wo.c`);

  // Byte for byte what build-analyze.mjs writes: the generation plus the
  // control, and the ablated generation plus the same control.
  writeFileSync(withWipe, src + CONTROL, 'utf8');
  writeFileSync(without, ablateSpans(src, spans) + CONTROL, 'utf8');

  const aW = await compile(cc, [opt], withWipe, join(lab, `${tag}.w.s`));
  const aWo = await compile(cc, [opt], without, join(lab, `${tag}.wo.s`));
  const cell = verdictOf(aW, aWo, fn);
  return {
    verdict: cell.verdict,
    control: cell.control === undefined ? null : cell.control,
    control_via: cell.control_via === undefined ? null : cell.control_via,
    nSpans: spans.length,
    kinds,
    compiled: aW !== null,
  };
}

/**
 * The live column, summarised over a run's cells.
 *
 * Counts and a LIST, never a count alone: "3 cells moved" with no ids is the
 * shape of a number nobody can check, which is the rule the exclusion list in
 * `lib/agreement.mjs` is written under.
 */
export function summariseDrift(cells) {
  const byDrift = { [DRIFT.SAME]: 0, [DRIFT.MOVED]: 0, [DRIFT.NOT_RECOMPUTED]: 0 };
  const moved = [];
  for (const c of cells) {
    const d = driftOf(c.tracked, c.live);
    byDrift[d] += 1;
    if (d === DRIFT.MOVED) moved.push({ id: c.id, cc: c.cc, opt: c.opt, tracked: c.tracked, live: c.live });
  }
  return {
    total: cells.length,
    byDrift,
    moved: moved.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    // The sentence a reader needs beside the number, in the object rather than
    // only in the runner's output.
    meaning: 'the tracked O1 is what the table grades; this column says only whether that reading still reproduces today',
  };
}

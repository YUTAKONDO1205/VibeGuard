/**
 * The anchor: do this lane's clang-18 and gcc-13 rungs reproduce the tracked
 * find-step rows?
 *
 * This is the lane's false-positive killer and it is worth being blunt about
 * why. The lane's claim is comparative -- "the elimination first appears at
 * clang-N" -- and a comparative claim survives almost any systematic error in
 * the measurement, because the error lands on every rung. If this lane wired up
 * the instrument slightly differently from the find step (a flag dropped, the
 * control not appended, the wrong target function, the ablation applied to the
 * wrong spans) every rung would shift together and the ladder would still look
 * like a clean story.
 *
 * Two rungs of the ladder are rungs the project has already measured:
 * clang-18 and gcc-13 are exactly the compilers behind
 * ../ai-generated/data/r2-build-rows.json. So those two rungs are a fixed point.
 * If this lane reproduces them verdict-for-verdict on the same (id, cc, opt),
 * the instrument is the find step's instrument; if it does not, every other rung
 * is unexplained and the run exits 2 rather than printing a ladder. A run that
 * compared NO anchor cell at all exits 2 for the same reason: `0/0 agree` is not
 * a small pass, it is no pass (`vacuousAnchorProblem`, `anchorProblem`).
 *
 * All pure: the rows come in, the disagreements come out. No compiler, no disk.
 */

import { ANCHOR_CC } from './ladder.mjs';

/** Every compiler this lane can anchor against the tracked rows. */
export const ANCHOR_CCS = Object.freeze(Object.values(ANCHOR_CC));

/** The key a tracked erasure row and a lane row are joined on. */
export function cellKey(id, cc, opt) {
  return `${id}|${cc}|${opt}`;
}

/**
 * The tracked erasure verdicts, by (id, cc, opt).
 *
 * Only `kind === 'erasure'` rows are indexed. A `kind: 'none'` row
 * (NO_WIPE_WRITTEN) is not a cell: the find step never compiled anything for it,
 * so there is no verdict of this lane's kind to compare with, and indexing it
 * would turn "the file has no wipe" into an apparent disagreement.
 */
export function anchorIndex(trackedRows) {
  const m = new Map();
  if (!Array.isArray(trackedRows)) return m;
  for (const r of trackedRows) {
    if (!r || r.kind !== 'erasure') continue;
    if (typeof r.id !== 'string' || typeof r.cc !== 'string' || typeof r.opt !== 'string') continue;
    m.set(cellKey(r.id, r.cc, r.opt), r.verdict);
  }
  return m;
}

/**
 * Which of this lane's anchor-compiler rows disagree with the tracked rows.
 *
 * A row whose compiler is not an anchor compiler is skipped -- there is nothing
 * tracked to compare a clang-15 row with, and that is the point of the lane. A
 * row whose compiler IS an anchor compiler and which has no tracked cell is a
 * disagreement with `tracked: null`, not a pass: a join that silently matches
 * nothing is how "0 of 0 agree" comes to read as a clean anchor, and the repair
 * loop's own vendor.mjs refuses the same shape for the same reason.
 *
 * @returns {{checked: number, agreed: number, disagreements: object[]}}
 */
export function anchorDisagreements(laneRows, index, { anchorCcs = ANCHOR_CCS } = {}) {
  const ccs = new Set(anchorCcs);
  const disagreements = [];
  let checked = 0;
  for (const r of laneRows || []) {
    if (!r || !ccs.has(r.cc)) continue;
    checked++;
    const key = cellKey(r.id, r.cc, r.opt);
    const tracked = index.has(key) ? index.get(key) : null;
    if (tracked !== r.verdict) {
      disagreements.push({ id: r.id, cc: r.cc, opt: r.opt, lane: r.verdict, tracked });
    }
  }
  return { checked, agreed: checked - disagreements.length, disagreements };
}

/**
 * How a disagreement prints. `tracked: null` gets its own wording, because
 * "(no tracked cell)" and "the tracked cell said something else" are different
 * failures and the fix for each is different.
 */
export function disagreementLine(d) {
  const t = d.tracked === null ? '(no tracked cell for this id/cc/opt)' : d.tracked;
  return `  ${d.id} ${d.cc} ${d.opt}: this lane ${d.lane}, tracked ${t}`;
}

/**
 * Could this run's anchor compare anything at all? Decided BEFORE the compiles,
 * from the rungs that were obtained and the subjects that are anchorable.
 *
 * This is the guard the lane shipped without, and the failure was not exotic: a
 * run whose obtained rungs hold neither `clang-18` nor `gcc-13` produces no
 * anchor row, `anchorDisagreements` returns `{checked: 0, disagreements: []}`,
 * and the run printed `0/0 cells reproduce the tracked verdict` and exited 0 --
 * the exact shape this file's header and the README call a vacuous pass. On any
 * machine missing the pinned pair that was the DEFAULT invocation.
 *
 * Why this is not `trackedCcProblem` from ../../repair-loop/lib/vendor.mjs,
 * which this lane imports from and whose message is the one quoted below: that
 * function asks a question about the ROWS FILE -- do the tracked rows hold an
 * erasure row for this compiler -- and the runner does call it, for exactly that
 * (a `--rows` file that names neither anchor compiler). The vacuity reachable
 * here is on the other side of the join: the rows can be perfect and the LANE
 * can still produce no row to join to them, because the pinned rungs are not on
 * this machine or no anchorable subject was selected. Same refusal, different
 * side, so the wording is borrowed rather than the function.
 *
 * @returns {null | string} null when the anchor has something to compare
 */
export function vacuousAnchorProblem({ obtainedCcs, anchorableIds, anchorCcs = ANCHOR_CCS } = {}) {
  const rungs = (obtainedCcs || []).filter((cc) => anchorCcs.includes(cc));
  const ids = anchorableIds || [];
  if (rungs.length && ids.length) return null;
  const why = [];
  if (!rungs.length) why.push(`no anchor rung was obtained (this run has none of ${anchorCcs.join(', ')})`);
  if (!ids.length) why.push('no selected subject has tracked rows to be anchored against');
  return `${why.join('; and ')}, so the anchor would compare nothing and "0/0 agree" would pass vacuously. `
    + 'The ladder is a comparative claim and a comparative claim survives any systematic error that lands on '
    + 'every rung, so a ladder with no fixed point is not a weaker result -- it is an unchecked instrument. '
    + `Add one of ${anchorCcs.join(' or ')} to --ccs, and a subject the tracked rows hold cells for`;
}

/**
 * Did the anchor hold? The one place the run's exit code is decided from.
 *
 * `checked === 0` is a FAILURE and not a pass with nothing in it: see
 * `vacuousAnchorProblem`. It is checked here as well as before the compiles
 * because the two are not the same condition -- an anchorable subject whose wipe
 * spans vanish is dropped after the pre-flight, and that path too would end with
 * nothing compared.
 *
 * @returns {null | string} null when at least one cell was compared and all agreed
 */
export function anchorProblem(anchor, { anchorCcs = ANCHOR_CCS } = {}) {
  if (!anchor || !Number.isInteger(anchor.checked) || anchor.checked === 0) {
    return `NOT ANCHORED: no cell was compared against the tracked rows, so "0/0 agree" would pass `
      + `vacuously. Nothing this run printed is anchored to ${anchorCcs.join(' or ')}`;
  }
  if (anchor.disagreements.length) {
    return `NOT ANCHORED: ${anchor.disagreements.length} of ${anchor.checked} anchor cell(s) do not `
      + 'reproduce the tracked verdict';
  }
  return null;
}

/**
 * Are the subjects this run selected ones the tracked rows can anchor at all?
 * An id with no tracked erasure row under either anchor compiler would be
 * checked against nothing, so it is named before the run rather than after.
 *
 * @returns {string[]} the ids with no tracked anchor cell, sorted
 */
export function unanchorableIds(ids, index, { anchorCcs = ANCHOR_CCS, opts } = {}) {
  const bad = [];
  for (const id of ids) {
    const any = anchorCcs.some((cc) => opts.some((opt) => index.has(cellKey(id, cc, opt))));
    if (!any) bad.push(id);
  }
  return bad.sort();
}

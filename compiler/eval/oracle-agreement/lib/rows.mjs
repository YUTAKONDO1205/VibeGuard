/**
 * The O1 side, read out of the tracked rows and never re-measured.
 *
 * `../../ai-generated/data/r2-build-rows.json` is a frozen record: it is the
 * output of the corpus run that `verdictOf` produced, it is quoted in a
 * write-up, and re-deriving it here would silently substitute today's toolchain
 * for the one the number was taken on. So this module READS it and nothing in
 * this lane writes it. That is not a convention -- `test/lane.test.mjs` pins it
 * by grepping this file's own source for every mutating call `node:fs` has, for
 * the same reason `../../spike/lib/measure.mjs` is pinned not to import its own
 * answers: a guarantee that lives only in a comment is a guarantee that survives
 * exactly until someone needs a quick fix.
 *
 * The consequence is worth stating plainly, because it is a limitation and not a
 * feature: O1's half of every pair in this lane was measured on a different day,
 * on the machine that ran the corpus, with whatever `clang-18` and `gcc-13` were
 * installed then. O2's half is measured now. A disagreement could therefore be a
 * toolchain drift rather than a difference between the instruments, and this
 * lane cannot tell those apart. The fix is not to re-measure O1 here -- it is to
 * re-run the corpus lane and compare the rows, which is `compare-rows.mjs`'s job
 * next door, not this one's.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { o1ClassOf } from './agreement.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

/** The frozen record. Read only. */
export const ROWS_PATH = resolve(HERE, '../../ai-generated/data/r2-build-rows.json');

/** Where the generation whose id a row carries lives. The rows deliberately carry no path. */
export const CORPUS_DIR = resolve(HERE, '../../ai-generated/generated-corpus/r2');

/** The scenario table, for the name of the function a generation's wipe lives in. */
export const SCENARIOS_PATH = resolve(HERE, '../../ai-generated/scenarios.json');

/**
 * Only the erasure family can be compared at all.
 *
 * `authz` rows answer "does the check survive -DNDEBUG" and `configguard` rows
 * answer "does the default build differ from the all-macros build". Neither
 * question has a LOST/PRESENT counterpart in the observer's vocabulary, and a
 * lane that put them in the same table would be comparing two instruments that
 * were never asked the same thing. They are filtered out here, once, rather than
 * excluded 1,440 times downstream with a reason that reads like a defect.
 */
export const COMPARABLE_FAMILY = 'erasure';

export function loadRows(path = ROWS_PATH) {
  const doc = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(doc)) throw new Error(`${path} does not hold an array of rows`);
  return doc;
}

export function loadScenarios(path = SCENARIOS_PATH) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** The key a cell is addressed by. Three fields, because a row is one (id, vendor, level). */
export const keyOf = (id, cc, opt) => `${id}|${cc}|${opt}`;

/**
 * Index the rows so a reading can find its O1 half in one lookup.
 *
 * A duplicate key is thrown on rather than overwritten. The corpus lane emits
 * one row per (id, cc, opt) and 4,650 of the 4,689 rows carry a (cc, opt) pair
 * at all; if that ever stops being true, the difference between "the second row
 * won" and "the first row won" is a silent change to every number this lane
 * prints, and nobody would see it.
 */
export function indexRows(rows) {
  const ix = new Map();
  for (const r of rows) {
    if (!r || r.cc === undefined || r.opt === undefined) continue;
    const k = keyOf(r.id, r.cc, r.opt);
    if (ix.has(k)) throw new Error(`r2-build-rows.json carries two rows for ${k}`);
    ix.set(k, r);
  }
  return ix;
}

/** The O1 half of a pair, in the shape `classifyPair` reads. */
export const o1Of = (row) => (row
  ? { verdict: row.verdict, control: row.control === undefined ? null : row.control, control_via: row.control_via === undefined ? null : row.control_via }
  : null);

/**
 * Choose the cells to observe, balanced across the two O1 verdicts.
 *
 * WHY BALANCED, and why this is a measurement decision rather than a sampling
 * convenience. `laneVerdict` refuses to call a stratum readable when one
 * instrument's marginal is degenerate, and the corpus is not balanced: at `-O1`
 * and above, clang-18 reads `WIPE_ELIMINATED` in roughly a third of its erasure
 * cells and `WIPE_SURVIVED` in the rest. A run that took the first N ids
 * alphabetically could easily draw N cells that all read `SURVIVED`, and the
 * lane would correctly report that it could not ask its question -- having spent
 * N compiles to find that out. So the selection takes `perBucket` cells from
 * each (vendor, level, O1 verdict) bucket.
 *
 * That makes the table's marginals an artefact of the SELECTION and not an
 * estimate of the corpus. The agreement rate printed by this lane is therefore
 * NOT the corpus's agreement rate, and the README says so twice. What the lane
 * measures is WHERE the two instruments part company, which is a question about
 * cases and not about proportions.
 *
 * Deterministic: ids are sorted, so the same arguments select the same cells on
 * any machine, and a second run is a re-measurement rather than a new sample.
 */
export function selectCells(rows, {
  ccs = ['clang-18'],
  opts = ['-O2'],
  perBucket = 8,
  ids = null,
  fam = COMPARABLE_FAMILY,
} = {}) {
  const wanted = ids && ids.length ? new Set(ids) : null;
  const buckets = new Map();

  for (const r of rows) {
    if (r.fam !== fam) continue;
    if (!ccs.includes(r.cc) || !opts.includes(r.opt)) continue;
    if (wanted && !wanted.has(r.id)) continue;
    // A cell whose O1 half is not one of the two verdicts cannot be balanced
    // against anything, and spending a compile on it only to exclude it
    // afterwards would be spending it to learn something the rows already say.
    // An explicit --ids list overrides this: someone naming a cell by hand is
    // usually naming it BECAUSE it is one of those, to see what O2 says.
    const cls = o1ClassOf(r.verdict);
    if (cls === null && !wanted) continue;
    const key = `${r.cc}|${r.opt}|${cls === null ? 'other' : cls}`;
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(r);
  }

  const chosen = [];
  for (const key of [...buckets.keys()].sort()) {
    const list = buckets.get(key).slice().sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    for (const r of list.slice(0, perBucket)) {
      chosen.push({
        id: r.id,
        cc: r.cc,
        opt: r.opt,
        fn: r.fn,
        idiom: r.idiom === undefined ? null : r.idiom,
        nSpans: r.n_spans === undefined ? null : r.n_spans,
        o1: o1Of(r),
      });
    }
  }
  return chosen;
}

/**
 * How many cells each bucket holds, so a caller can see what it is drawing from.
 *
 * Printed by `--dry-run`. A selection that silently took 3 of a requested 8
 * because the bucket only had 3 is a selection whose marginals are not what the
 * operator asked for, and the dry run is where that should be visible -- before
 * the compiles, not in the exclusion list afterwards.
 */
export function bucketSizes(rows, { ccs, opts, fam = COMPARABLE_FAMILY } = {}) {
  const sizes = {};
  for (const r of rows) {
    if (r.fam !== fam) continue;
    if (ccs && !ccs.includes(r.cc)) continue;
    if (opts && !opts.includes(r.opt)) continue;
    const cls = o1ClassOf(r.verdict);
    const key = `${r.cc}|${r.opt}|${cls === null ? `other(${r.verdict})` : cls}`;
    sizes[key] = (sizes[key] || 0) + 1;
  }
  return sizes;
}

/** Where a generation's C file is. Inside the repository, and only ever read. */
export const sourcePathOf = (id, dir = CORPUS_DIR) => join(dir, `${id}.c`);

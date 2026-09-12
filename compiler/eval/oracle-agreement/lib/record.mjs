/**
 * The tracked record: what this lane measured, in a file somebody can check.
 *
 * WHY THIS FILE EXISTS
 *
 * Until now the lane wrote only into a lab directory outside the repository, and
 * the only tracked trace of a run was the README's "Measured, 2026-09-12"
 * section -- prose. Every number in it (48 cells, a denominator of 25, 24 on the
 * diagonal, 23 `NOT_COMPARABLE`, one off-diagonal id, exit 2) is a number a
 * reader has to take on faith, and a number nothing re-derives is a number that
 * drifts from the run it came from the first time either changes. `../lto-window`
 * hit the same wall on the same day and answered it the same way: a per-run JSON
 * under `data/`, pinned by a test.
 *
 * FOUR RULES, and each one exists because the obvious version of this file gets
 * it wrong in a way that reads as fine.
 *
 * 1. INTEGERS, BOOLEANS AND SHORT STRINGS ONLY. No rate, no percentage, no
 *    float. The README's own instruction about this run is "read the 96 % as
 *    nothing" -- the figure is 24/25 of a table whose second instrument said one
 *    word throughout, and a `0.96` in a JSON file is an invitation to quote it
 *    without the denominator or the refusal. Ratios are carried as an integer
 *    PAIR, `{num, den}`, which cannot be quoted without both halves.
 *    `nonIntegerNumbers` walks the record and the write is refused if one
 *    appears, so the rule survives the next field somebody adds.
 *
 * 2. FULL RUNS ONLY. A record written from `--ids`, from a partial `--opt`, or
 *    from a run whose report was suppressed is a subset in the file whose name
 *    says it is the result. `writeDataRefusals` lists the reasons and the runner
 *    exits 4 on any of them, following `../../repair-loop/run-repair-loop.mjs`,
 *    which refuses `--write-data` for red controls and subsets in the same way
 *    and for the same reason.
 *
 * 3. NOTHING THAT NAMES A MACHINE. The text is scanned before the file is
 *    opened, not after: a home directory, a mount point or a drive letter in a
 *    tracked file publishes the measuring machine's layout, and the run exits 5
 *    with nothing written rather than leaving a file to be cleaned up later.
 *    Compiler versions are reduced to a version triple for the same reason --
 *    `clang --version` prints its `InstalledDir`.
 *
 * 4. THE SELECTION IS ENUMERATED. `../lib/rows.mjs` `selectCells` is
 *    deterministic (see `selectedIdsAreReproducible` in `../test/data.test.mjs`),
 *    so the ids could in principle be re-derived rather than stored. They are
 *    stored anyway: the claim the record makes is about the cells THIS run
 *    observed, and re-deriving them from today's tracked rows would quietly
 *    substitute today's selection for that one the day the corpus changes.
 *
 * Nothing here consults a compiler, and the only file this module writes is the
 * record itself.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';
import { vendorLabel } from '../../spike/lib/measure.mjs';
import { STRATUM } from './agreement.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Where a tracked record goes. Inside this lane, and nowhere near the frozen rows. */
export const DATA_DIR = resolve(HERE, '../data');

/** The schema tag, so a later shape change is a new version rather than a silent edit. */
export const SCHEMA = 'vibeguard.oracle-agreement-record/1';

/**
 * One file per compiler, named after it.
 *
 * The same rule `../../repair-loop/lib/vendor.mjs` settled: a second vendor's
 * run writes its own file, so one compiler's record can never overwrite
 * another's and a reader never has to ask which one a file is of.
 */
export const dataFileName = (cc) => `oracle-agreement-${vendorLabel(cc)}.json`;
export const dataPathFor = (cc, dir = DATA_DIR) => join(dir, dataFileName(cc));

/** The levels a full run has to cover: the separated stratum and one above it. */
export const REQUIRED_LEVELS = Object.freeze(['-O0', '-O2']);

/**
 * Why this run may not be written to `data/`.
 *
 * A list rather than a boolean, and the runner prints all of them: an operator
 * who fixes one reason at a time learns about the next one a compile run later.
 */
export function writeDataRefusals(args) {
  const why = [];
  if (args.dryRun) why.push('--dry-run (nothing was measured)');
  if (args.ids && args.ids.length) why.push('--ids (a hand-named subset is not the lane\'s result)');
  if (!args.write) why.push('--no-write (a record written while the report is suppressed has no lab copy beside it)');
  if (!args.observer) why.push('no --observer (the second oracle did not run)');
  if (!args.ccs || args.ccs.length !== 1) {
    why.push('more than one --cc (the record file is named after one compiler)');
  }
  for (const lvl of REQUIRED_LEVELS) {
    if (!args.opts || !args.opts.includes(lvl)) {
      why.push(`--opt does not include ${lvl} (the tracked record covers both strata; ${lvl} is the one that must be tabulated separately)`);
    }
  }
  if (!args.diagnoseCallSites) {
    why.push('--diagnose-callsites was not given (the record would carry the exclusion split as prose provenance, which is what the tracked file exists to replace)');
  }
  return why;
}

/**
 * Every number in `value` that is not an integer, as dotted paths.
 *
 * The guard behind rule 1. A percentage is the shape this record must never
 * carry, and a percentage is always a non-integer or an integer that lost its
 * denominator; this catches the first half mechanically and `{num, den}` pairs
 * take care of the second.
 */
export function nonIntegerNumbers(value, path = '') {
  const bad = [];
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) bad.push(path || '(root)');
    return bad;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => bad.push(...nonIntegerNumbers(v, `${path}[${i}]`)));
    return bad;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) bad.push(...nonIntegerNumbers(v, path ? `${path}.${k}` : k));
  }
  return bad;
}

/** A compiler's version triple, and nothing else it printed. `clang --version` names its install directory. */
export function versionTriple(text) {
  const m = /version\s+(\d+\.\d+(?:\.\d+)?)/i.exec(String(text || ''));
  return m ? m[1] : null;
}

/** One stratum, reduced to integers and booleans. */
function strataRecord(s) {
  return {
    name: s.name,
    levels: s.levels,
    table: {
      'ELIMINATED/LOST': s.table['ELIMINATED/LOST'],
      'ELIMINATED/PRESENT': s.table['ELIMINATED/PRESENT'],
      'SURVIVED/LOST': s.table['SURVIVED/LOST'],
      'SURVIVED/PRESENT': s.table['SURVIVED/PRESENT'],
    },
    den: s.den,
    agree: s.agree,
    disagree: s.disagree,
    // The rate, as the integer pair it is. Never divided here.
    diagonal: { num: s.agreement.num, den: s.agreement.den },
    discriminating: s.discriminating,
    degenerateO1: s.degenerate.o1,
    degenerateO2: s.degenerate.o2,
    excludedTotal: s.excluded.total,
    excludedByKind: { ...s.excluded.byKind },
    excludedByReason: { ...s.excluded.byReason },
    // den + excluded: the accounting the README's exclusion table is over.
    accountedFor: s.accountedFor,
    offDiagonal: s.offDiagonal.map((c) => ({
      id: c.id, cc: c.cc, opt: c.opt, cell: c.cell,
      o1: c.o1Verdict, o2: c.o2State,
      firstLossPass: c.firstLossPass === undefined ? null : c.firstLossPass,
      idiom: c.idiom === undefined || c.idiom === null ? null : c.idiom,
    })),
    excludedIds: s.excluded.cells.map((c) => ({
      id: c.id, cc: c.cc, opt: c.opt, kind: c.kind, reason: c.reason,
      detail: c.detail === undefined ? null : c.detail,
    })),
  };
}

/**
 * Build the record.
 *
 * Pure: everything it needs is passed in, so `test/record.test.mjs` can build
 * one over synthetic strata and check the rules without a compiler, a plugin or
 * a corpus.
 */
export function buildRecord({
  tab, verdict, chosen, pairs, args, toolchain, plugin, rows, callSites = null, generatedAt, node,
}) {
  const cc = args.ccs[0];
  const above = tab.strata.find((s) => s.name === STRATUM.ABOVE_O0) || null;
  return {
    schemaVersion: SCHEMA,
    lane: 'oracle-agreement',
    // What the two oracles ARE, in the record rather than only in the README: a
    // file that says 24 and 25 without saying what was compared is a file that
    // can be quoted about anything.
    oracles: {
      O1: 'verdictOf, differential assembly text, read from the tracked rows and not re-measured',
      O2: 'PropertyObserver, IR call-site state, measured in this run',
    },
    generatedAt,
    node,
    toolchain: { cc: vendorLabel(cc), version: toolchain.version, vendor: toolchain.vendor },
    plugin: { basename: plugin.basename, sha256: plugin.sha256 },
    rows: { file: rows.file, sha256: rows.sha256 },
    request: {
      levels: args.opts,
      perBucket: args.perBucket,
      full: true,
      ids: null,
    },
    // Two counts, because the README quotes the second one under a label that
    // reads like the first. `selected` is what the selector drew over all
    // requested levels; the above-`-O0` stratum's `accountedFor` is the 48 the
    // exclusion table and the call-site table are both over.
    selected: chosen.length,
    observed: pairs.length,
    accountedFor: tab.accountedFor,
    selectedCells: chosen.map((c) => ({
      id: c.id, cc: c.cc, opt: c.opt, fn: c.fn,
      idiom: c.idiom === undefined || c.idiom === null ? null : c.idiom,
      nSpans: c.nSpans === undefined || c.nSpans === null ? null : c.nSpans,
      o1: c.o1 ? c.o1.verdict : null,
    })),
    strata: tab.strata.map(strataRecord),
    aboveO0: above
      ? { den: above.den, diagonal: { num: above.agreement.num, den: above.agreement.den }, accountedFor: above.accountedFor }
      : null,
    irCallSites: callSites,
    verdict: { readable: verdict.readable, exit: verdict.code, reasons: verdict.reasons },
    exit: verdict.code,
  };
}

/**
 * Write the record, or refuse to.
 *
 * Returns rather than exiting, so the checks are testable and the runner keeps
 * every `process.exit` in one file. `hits` is exit 5's cause and `floats` is the
 * same class of refusal: both mean a tracked file would have carried something
 * that must not be tracked, and in both cases nothing is written.
 */
export function writeRecord(record, { cc, dir = DATA_DIR } = {}) {
  const text = `${JSON.stringify(record, null, 2)}\n`;
  const hits = absolutePathHits(text);
  const floats = nonIntegerNumbers(record);
  const path = dataPathFor(cc, dir);
  if (hits.length || floats.length) return { written: false, path, hits, floats, text };
  mkdirSync(dir, { recursive: true });
  writeFileSync(path, text, 'utf8');
  return { written: true, path, hits, floats, text };
}

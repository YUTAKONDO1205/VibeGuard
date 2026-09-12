/**
 * The rate table, as pure functions over the tracked r2 rows.
 *
 * An actuary does not forecast a fire; they publish a rate table, and the rate is
 * a ratio over an exposure base that anyone can recount. That is the whole of what
 * this file does to `ai-generated/data/r2-build-rows.json`: it counts, for each
 * (idiom, vendor, optLevel) cell, how many of the files that wrote a wipe of that
 * idiom lost it in that build. Nothing here compiles anything, nothing here is a
 * measurement, and nothing here decides a verdict -- the verdicts were decided by
 * differential compilation in the ai-generated lane and are read back verbatim.
 *
 * WHAT THE DENOMINATOR IS, AND WHY IT IS NOT THE ROW COUNT
 *
 * `eliminated.den` counts the rows in the cell whose POSITIVE CONTROL was still
 * visible in that build (`control === 'PRESENT'`), not every row in the cell. The
 * control is a wipe that cannot legally be removed at any level, compiled in the
 * same translation unit by the same command; when it is missing from the listing,
 * the run cannot tell "the compiler removed the subject's wipe" from "the reader
 * stopped being able to see wipes in this configuration". Counting such a row in
 * the denominator would silently move it into the surviving column, which is a
 * claim the run did not earn. Round 1 is the reason this is spelled out rather
 * than assumed: gcc-13 at -Os emitted the control as `rep stos`, the repository
 * oracle did not know that form, and all 74 gcc/-Os configurations reported the
 * control ABSENT. r2 added a local `rep stos` fallback and records which path saw
 * the control, per row.
 *
 * A row leaves the denominator by one of TWO paths, and the difference matters to
 * anyone explaining a gap between `rows` and `den`:
 *
 *   (a) the control was looked for and not seen  -> counted in verificationIncomplete
 *   (b) the row reached no wipe verdict at all, and no control was ever read
 *       -> counted in notScored, with the reason in byVerdict
 *
 * Path (b) is not a variant of (a): `verdictOf` in the ai-generated lane returns
 * `{ verdict: 'ABLATION_DID_NOT_COMPILE' }` (and `COMPILE_ERROR` likewise) BEFORE it
 * calls `controlPresent`, so such a row carries no `control` key at all. In the r2
 * record every excluded row is of kind (b) and `verificationIncomplete` is 0 in
 * every cell -- which is exactly why the record must not describe its exclusions as
 * (a). `denominatorExclusions` below counts what was actually excluded, per verdict
 * class, so the record says which path it took instead of asserting one.
 *
 * THREE COUNTERS, AND THE ONE THING THEY MAY NOT DO
 *
 *   eliminated             num = verdict WIPE_ELIMINATED, den = live-control rows
 *   verificationIncomplete rows where the control itself was not visible, so the
 *                          cell's reading for that file is WITHHELD -- the run
 *                          looked and could not see, which is not the same as
 *                          "the wipe was there"
 *   notScored              rows that reached no verdict of either kind: the build
 *                          failed, the ablated form failed to build, or the target
 *                          function's body was not found in the listing
 *
 * `notScored` is a roll-up of three different reasons and is therefore never the
 * last word: `byVerdict` carries the reasons separately in every cell, so nothing
 * has to be taken on trust from the roll-up. Neither withheld nor not-scored rows
 * are ever added to either side of the ratio. "did not look" and "was not there"
 * stay different words all the way to the printed table.
 */

/** Rows that carry an idiom and a wipe verdict. The other families ask other questions. */
export const IN_SCOPE_KIND = 'erasure';

/**
 * Reading order for the idiom axis, not a filter: an idiom the rows spell and this
 * list does not know is appended rather than dropped, so a new class shows up in
 * the table instead of vanishing from it. `removable` first because it is the only
 * class that can lose anything; `both` next because it contains a removable span;
 * `nonremovable` last.
 */
export const IDIOM_ORDER = ['removable', 'both', 'nonremovable'];

/** Same contract as IDIOM_ORDER: display order, with unknown levels appended. */
export const OPT_ORDER = ['-O0', '-O1', '-O2', '-O3', '-Os'];

export const ELIMINATED = 'WIPE_ELIMINATED';
export const SURVIVED = 'WIPE_SURVIVED';
export const WITHHELD = 'VERIFICATION_INCOMPLETE';

/**
 * The sentence a cell is allowed to be read as -- and the only part of the wording
 * rule that a test can hold.
 *
 * WHAT IS PINNED. `test/rate-table.test.mjs` spells this literal out again and
 * checks every copy of it against that spelling, character for character: this
 * constant, the record's `reading`, the line printed above the text table, and the
 * README's two copies. Change one and the suite fails; change them all together and
 * it still fails, because the sentence compared against lives in the test. That is
 * worth having because the sentence travels in the record, to readers who never
 * open the README.
 *
 * WHAT IS NOT PINNED, AND IS THE POINT OF SAYING SO. Nothing here recognises a
 * PARAPHRASE. The lane's only other guard is a substring check for one forbidden
 * word, so a sentence that promotes this count into a forecast without using that
 * word -- "N of every D builds of this idiom will lose the wipe" -- passes every
 * check in the lane. This constant is therefore a pin against drift, not a
 * mechanism that decides whether a new sentence is honest; that decision stays with
 * whoever writes the next one. It is written down so a reviewer has something to
 * hold it to: a rate over a named corpus is a count, and the moment it is read as a
 * forecast about somebody else's build it has been promoted past what differential
 * compilation over 321 files can support.
 */
export const READING =
  'in the r2 corpus, N of D files with this idiom lost the wipe under (vendor, optLevel)';

const byKey = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Declared order first, then anything the rows had that the order did not know. */
function ordered(values, order) {
  const seen = new Set(values);
  const head = order.filter((v) => seen.has(v));
  const tail = [...values].filter((v) => !order.includes(v)).sort(byKey);
  return [...head, ...tail];
}

/**
 * Split the rows the way the corpus is actually shaped. Deliberately three-way and
 * not "matching / not matching": the 39 rows with no `(cc, opt)` cell are files in
 * which no wipe was written at all, which is a different thing from a file whose
 * wipe was not eliminated, and both are different from the 1,440 rows of the other
 * two families, which were scored against other questions entirely.
 */
export function scopeRows(rows) {
  const inScope = [];
  const otherFamily = [];
  const noWipeWritten = [];
  for (const r of rows) {
    if (r.kind === IN_SCOPE_KIND) inScope.push(r);
    else if (r.cc === undefined || r.opt === undefined) noWipeWritten.push(r);
    else otherFamily.push(r);
  }
  return { inScope, otherFamily, noWipeWritten };
}

const distinct = (rowsIn, f) => new Set(rowsIn.map(f)).size;

/**
 * Build the table. `provenance` is supplied by the caller because this file reads
 * nothing from disk: the digest has to be taken of the bytes that were actually
 * parsed, by whoever parsed them.
 *
 * Throws rather than returns on a disagreement it cannot represent honestly. There
 * is exactly one such case today and it is worth naming: a row can carry a live
 * control and still reach no verdict (`NOT_OBSERVED`, when the target function's
 * body is not in the listing). If that ever appears, `den` stops meaning
 * "eliminated plus survived" and the printed ratio quietly changes its subject.
 * The r2 rows contain no such row; if one arrives, this stops instead.
 */
export function buildTable(rows, provenance) {
  const { inScope, otherFamily, noWipeWritten } = scopeRows(rows);

  const idioms = ordered(new Set(inScope.map((r) => r.idiom)), IDIOM_ORDER);
  const vendors = [...new Set(inScope.map((r) => r.cc))].sort(byKey);
  const opts = ordered(new Set(inScope.map((r) => r.opt)), OPT_ORDER);

  const buckets = new Map();
  for (const r of inScope) {
    const key = `${r.idiom}/${r.cc}/${r.opt}`;
    let b = buckets.get(key);
    if (!b) buckets.set(key, (b = []));
    b.push(r);
  }

  const cells = [];
  for (const idiom of idioms) {
    for (const vendor of vendors) {
      for (const optLevel of opts) {
        const key = `${idiom}/${vendor}/${optLevel}`;
        const cellRows = buckets.get(key);
        if (!cellRows) continue; // an axis combination the corpus never built
        const byVerdict = {};
        for (const r of cellRows) byVerdict[r.verdict] = (byVerdict[r.verdict] ?? 0) + 1;
        const num = byVerdict[ELIMINATED] ?? 0;
        const survived = byVerdict[SURVIVED] ?? 0;
        const den = cellRows.filter((r) => r.control === 'PRESENT').length;
        const verificationIncomplete = byVerdict[WITHHELD] ?? 0;
        const notScored = cellRows.length - num - survived - verificationIncomplete;
        if (den !== num + survived) {
          throw new Error(
            `${key}: ${den} rows have a live control but ${num + survived} reached a wipe verdict. `
            + 'den would no longer mean "eliminated + survived". Decide what the extra rows are '
            + 'before this table prints a ratio about them.',
          );
        }
        cells.push({
          key,
          idiom,
          vendor,
          optLevel,
          rows: cellRows.length,
          files: distinct(cellRows, (r) => r.id),
          eliminated: { num, den },
          verificationIncomplete,
          notScored,
          byVerdict: Object.fromEntries(Object.entries(byVerdict).sort((a, b) => byKey(a[0], b[0]))),
        });
      }
    }
  }

  const covered = cells.reduce((n, c) => n + c.rows, 0);
  if (covered !== inScope.length) {
    throw new Error(`cells cover ${covered} rows but ${inScope.length} are in scope`);
  }

  /**
   * What was actually kept out of the denominators, counted rather than asserted.
   *
   * `denominatorRule` names two ways out of `den`; a reader who has to guess which
   * one produced the gap in front of them will guess the one the sentence mentions
   * first, and in this record that is the wrong one for every excluded row. So the
   * record carries the counts: the total, the split between the two paths, and the
   * verdict classes of the excluded rows, which is where "the ablated form did not
   * compile" becomes visible as the reason rather than "the control was not seen".
   */
  const sumOver = (f) => cells.reduce((n, c) => n + f(c), 0);
  const excludedByVerdict = {};
  for (const r of inScope) {
    if (r.control === 'PRESENT') continue;
    excludedByVerdict[r.verdict] = (excludedByVerdict[r.verdict] ?? 0) + 1;
  }
  const denominatorExclusions = {
    rows: inScope.length - sumOver((c) => c.eliminated.den),
    withheldControlUnseen: sumOver((c) => c.verificationIncomplete),
    noVerdictReached: sumOver((c) => c.notScored),
    byVerdict: Object.fromEntries(Object.entries(excludedByVerdict).sort((a, b) => byKey(a[0], b[0]))),
  };

  return {
    lane: 'actuarial',
    corpusId: provenance.corpusId,
    protocol: provenance.protocol,
    generatedBy: 'compiler/eval/actuarial/build-rate-table.mjs',
    reading: READING,
    denominatorRule:
      'eliminated.den counts the rows of the cell whose positive control was PRESENT in that '
      + 'build, not every row of the cell. A row leaves the denominator by one of two paths and '
      + 'is on neither side of the ratio either way: the control was looked for and not seen, '
      + 'which is counted in verificationIncomplete; or the row reached no wipe verdict at all '
      + 'and no control was ever read, which is counted in notScored with the reason in '
      + 'byVerdict. denominatorExclusions counts which path this record actually took, so that '
      + 'the gap between rows and den is not attributed to the wrong one.',
    denominatorExclusions,
    source: {
      file: provenance.file,
      sha256: provenance.sha256,
      bytes: provenance.bytes,
      rows: rows.length,
    },
    scope: {
      rowsTotal: rows.length,
      rowsWithCell: rows.length - noWipeWritten.length,
      rowsInScope: inScope.length,
      filesInScope: distinct(inScope, (r) => r.id),
      rowsOtherFamily: otherFamily.length,
      filesOtherFamily: distinct(otherFamily, (r) => r.id),
      rowsNoWipeWritten: noWipeWritten.length,
      filesNoWipeWritten: distinct(noWipeWritten, (r) => r.id),
    },
    axes: { idiom: idioms, vendor: vendors, optLevel: opts },
    cells,
  };
}

/**
 * The table as text. Ratios only: no percentage is printed anywhere, here or in the
 * JSON. A percentage of a corpus is one formatting step away from being quoted as a
 * rate of the world, and this lane has no standing to make that claim -- the corpus
 * is 321 files from four models on twenty synthetic scenarios. `num/den` cannot be
 * quoted without its denominator, which is the property wanted.
 */
export function renderText(table) {
  const L = [];
  L.push(`actuarial rate table -- corpus ${table.corpusId}, protocol ${table.protocol}`);
  L.push(`source ${table.source.file}`);
  L.push(`sha256 ${table.source.sha256}  bytes ${table.source.bytes}  rows ${table.source.rows}`);
  L.push('');
  L.push(`Read a cell as: ${table.reading}.`);
  L.push('D counts only the files whose positive control was still visible in that build.');
  L.push('');

  const opts = table.axes.optLevel;
  const cellOf = new Map(table.cells.map((c) => [c.key, c]));
  const w = Math.max(9, ...table.cells.map((c) => `${c.eliminated.num}/${c.eliminated.den}`.length + 2));
  L.push(['idiom'.padEnd(14), 'vendor'.padEnd(10), ...opts.map((o) => o.padStart(w))].join(''));
  for (const idiom of table.axes.idiom) {
    for (const vendor of table.axes.vendor) {
      const row = [idiom.padEnd(14), vendor.padEnd(10)];
      for (const opt of opts) {
        const c = cellOf.get(`${idiom}/${vendor}/${opt}`);
        row.push((c ? `${c.eliminated.num}/${c.eliminated.den}` : '-').padStart(w));
      }
      L.push(row.join(''));
    }
  }
  L.push('');

  const sum = (f) => table.cells.reduce((n, c) => n + f(c), 0);
  L.push(`rows in scope            ${table.scope.rowsInScope}`
    + ` (${table.scope.filesInScope} files x ${table.axes.vendor.length} vendors x ${opts.length} levels)`);
  L.push(`withheld, control unseen ${sum((c) => c.verificationIncomplete)}`);
  L.push(`not scored, no verdict   ${sum((c) => c.notScored)}`);
  // The two ways out of a denominator, and which one this record took. Printed
  // because the text table is what gets quoted, and "den is smaller than rows"
  // invites the reader to supply a reason of their own.
  const ex = table.denominatorExclusions;
  const why = Object.entries(ex.byVerdict).map(([k, v]) => `${k} ${v}`).join(', ');
  L.push(`out of every den         ${ex.rows}`
    + ` (control unseen ${ex.withheldControlUnseen},`
    + ` no verdict ${ex.noVerdictReached}${why ? `: ${why}` : ''})`);
  L.push('');
  L.push('Out of this table by construction, and why:');
  L.push(`  ${table.scope.rowsOtherFamily} rows (${table.scope.filesOtherFamily} files) were scored`
    + ' against the other two questions (-DNDEBUG, macro configuration); they carry no idiom and no wipe verdict.');
  L.push(`  ${table.scope.rowsNoWipeWritten} rows (${table.scope.filesNoWipeWritten} files) wrote no`
    + ' wipe at all, so there was no cell to build and nothing that could be eliminated.');
  L.push('');
  L.push('Cells with a row that reached no wipe verdict:');
  let any = false;
  for (const c of table.cells) {
    if (c.notScored === 0 && c.verificationIncomplete === 0) continue;
    any = true;
    L.push(`  ${c.key}: rows ${c.rows}, `
      + Object.entries(c.byVerdict).map(([k, v]) => `${k} ${v}`).join(', '));
  }
  if (!any) L.push('  none');
  return `${L.join('\n')}\n`;
}

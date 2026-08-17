// Readers for the PropertyObserver TSV log.
//
// Field lists are the ones fixed in
// compiler/pass-instrumentation/observer/History.h; they are transcribed here
// rather than guessed from a sample, because a positional parser that guessed
// right on one log is a parser that will be wrong on the first log with a
// different shape and will not say so.
//
// Per the observer's own README, a reader must ignore record types it does not
// know rather than reject them. This one does.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

/** SUMMARY, after the leading record-type field. History.h line ~49. */
export const SUMMARY_FIELDS = Object.freeze([
  'unit', 'lineage', 'role', 'clone',
  'firstLossSeq', 'firstLossPass', 'firstLossPrevPass', 'firstLossPrevAfterPass',
  'firstLossFnIdx', 'finalState',
  'everPresent', 'everLost', 'everReintroduced', 'lossEpisodes',
  'fate', 'fateSeq', 'fatePass', 'histLen',
]);

/** SUBJECTRES, after the leading record-type field. History.h line ~33. */
export const SUBJECTRES_FIELDS = Object.freeze([
  'seq', 'moduleId', 'role', 'name', 'resolution',
]);

/** STATS, after the leading record-type field. History.h line ~54. */
export const STATS_FIELDS = Object.freeze([
  'passesSeen', 'evRecords', 'unitsTracked', 'lineages', 'skipped', 'mode',
]);

/** HIST, after the leading record-type field. History.h line ~53. */
export const HIST_FIELDS = Object.freeze([
  'unit', 'idx', 'seq', 'phase', 'passID', 'count', 'state',
]);

function rowsOf(text, type, fields) {
  const out = [];
  for (const line of text.split('\n')) {
    if (!line.startsWith(`${type}\t`)) continue;
    const parts = line.split('\t');
    const rec = { _recordType: type };
    // Positional, but the count is checked: a row with the wrong arity is
    // recorded as malformed instead of being silently short-read into fields
    // that then look plausible.
    rec._arityOk = parts.length - 1 === fields.length;
    fields.forEach((f, i) => { rec[f] = parts[i + 1]; });
    rec._raw = line;
    out.push(rec);
  }
  return out;
}

export function parseObserverLog(text) {
  return {
    summary: rowsOf(text, 'SUMMARY', SUMMARY_FIELDS),
    subjectres: rowsOf(text, 'SUBJECTRES', SUBJECTRES_FIELDS),
    stats: rowsOf(text, 'STATS', STATS_FIELDS),
    hist: rowsOf(text, 'HIST', HIST_FIELDS),
    // Presence of any EV record is the observer's own evidence-of-observation
    // check (README, "Non-invasiveness"): a run with no EV records observed
    // nothing, however clean its exit code.
    evRecordCount: text.split('\n').filter((l) => l.startsWith('EV\t')).length,
    lineCount: text.split('\n').filter((l) => l.trim() !== '').length,
  };
}

/**
 * Read the observer's answer for one role, without inventing one.
 *
 * Returns `NOT_OBSERVED` -- never `LOST` -- when there is no SUMMARY row for
 * the role. Those are the two shapes the observer's own README warns are
 * indistinguishable from inside a single module, and merging them is the bug
 * this whole record type exists to prevent.
 */
export function roleVerdict(parsed, role) {
  const row = parsed.summary.find((r) => r.role === role);
  if (!row) {
    return {
      state: 'NOT_OBSERVED',
      attribution: 'NOT_OBSERVED',
      reason: `no SUMMARY row with role=${role}; the observer never counted this role in this module`,
      row: null,
    };
  }
  const state = row.finalState;
  const lost = state === 'LOST';
  return {
    state,
    attribution: lost ? 'ATTRIBUTED' : 'NO_LOSS_TO_ATTRIBUTE',
    firstLossPass: lost ? row.firstLossPass : null,
    firstLossSeq: lost ? row.firstLossSeq : null,
    firstLossPrevPass: lost ? row.firstLossPrevPass : null,
    everPresent: row.everPresent,
    everLost: row.everLost,
    everReintroduced: row.everReintroduced,
    lossEpisodes: row.lossEpisodes,
    fate: row.fate,
    row,
  };
}

/** SUBJECTRES for one role in one module, as the fact it is. */
export function resolutionFor(parsed, role) {
  const rows = parsed.subjectres.filter((r) => r.role === role);
  if (rows.length === 0) return { resolution: 'not-scanned', rows: [] };
  return { resolution: rows[0].resolution, name: rows[0].name, rows };
}

// Reading the introduction observer's log.
//
// The format is described in Census.h and is line-oriented TSV with the record
// type in field one. Parsing it here rather than in the plugin is deliberate:
// the plugin writes what it saw and nothing else, and every judgement about
// what it means is made on this side, where it can be re-run against a recorded
// log without a compiler.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

const SUMMARY_FIELDS = [
  'scope', 'kind', 'name', 'firstIntroSeq', 'firstIntroPhase', 'firstIntroPass',
  'firstIntroUnitKind', 'firstIntroUnit', 'firstIntroPrevAfterPass',
  'firstIntroFnIdx', 'atEntry', 'finalState', 'everPresent', 'everLost',
  'everReintroduced', 'introEpisodes', 'lossEpisodes', 'histLen',
];

const HIST_FIELDS = [
  'scope', 'kind', 'name', 'idx', 'seq', 'phase', 'pass', 'count', 'state',
  'repeats', 'lastSeq', 'lastPass',
];

const INTRO_FIELDS = [
  'seq', 'phase', 'pass', 'passUnitKind', 'passUnitName', 'scope', 'kind',
  'name', 'atEntry', 'prevAfterPass', 'fnIdx',
];

const NUMERIC = new Set([
  'firstIntroSeq', 'firstIntroFnIdx', 'atEntry', 'everPresent', 'everLost',
  'everReintroduced', 'introEpisodes', 'lossEpisodes', 'histLen', 'idx', 'seq',
  'count', 'repeats', 'lastSeq', 'fnIdx', 'passesSeen', 'elemRecords',
  'elementsTracked', 'scopes', 'skipped', 'controlSeen',
]);

function row(fields, parts) {
  const out = {};
  fields.forEach((f, i) => {
    const raw = parts[i] ?? '';
    out[f] = NUMERIC.has(f) ? Number(raw) : raw;
  });
  return out;
}

/**
 * The identity of one element: scope, kind and name, joined by a unit separator.
 *
 * The separator is written as an escape rather than typed, because it is
 * invisible in an editor and a reader who cannot see it will assume the three
 * parts are simply concatenated -- and then a scope `a` holding `bc` and a scope
 * `ab` holding `c` would be one element. Census.cpp joins the same three parts
 * with the same byte, so the two sides agree by construction rather than by
 * coincidence.
 */
export const KEY_SEP = '\u001f';
export function elementKey(r) {
  return `${r.scope}${KEY_SEP}${r.kind}${KEY_SEP}${r.name}`;
}

/**
 * @param {string} text  the contents of a log, or of its `.summary.tsv`
 */
export function parseIntroLog(text) {
  const summaries = [];
  const hist = [];
  const intros = [];
  let handshake = null;
  let stats = null;

  for (const line of text.split('\n')) {
    if (!line) continue;
    const parts = line.split('\t');
    switch (parts[0]) {
      case 'HANDSHAKE':
        handshake = {
          schema: parts[1], moduleId: parts[2], mode: parts[3],
          control: parts[4], watch: (parts[5] ?? '').split(',').filter(Boolean),
        };
        break;
      case 'SUMMARY': summaries.push(row(SUMMARY_FIELDS, parts.slice(1))); break;
      case 'HIST': hist.push(row(HIST_FIELDS, parts.slice(1))); break;
      case 'INTRO': intros.push(row(INTRO_FIELDS, parts.slice(1))); break;
      case 'STATS':
        stats = row(['passesSeen', 'elemRecords', 'elementsTracked', 'scopes',
          'skipped', 'mode', 'controlSeen', 'controlFinalState'], parts.slice(1));
        break;
      default: break;   // PASS, ELEM, SKIP: trace detail, not needed here
    }
  }

  // The history belongs to its element, in the order it was written. Array
  // order is significant and is never sorted (interfaces.md §5.2).
  const byElement = new Map();
  for (const s of summaries) byElement.set(elementKey(s), { summary: s, series: [] });
  for (const h of hist) {
    const e = byElement.get(elementKey(h));
    if (e) e.series.push(h);
  }

  return { handshake, summaries, hist, intros, stats, byElement };
}

/**
 * The attribution and the whole state series for one element, in the shape
 * findings.mjs consumes.
 */
export function attributionFor(entry) {
  const s = entry.summary;
  return {
    firstIntroduction: {
      seq: s.firstIntroSeq,
      phase: s.firstIntroPhase,
      pass: s.atEntry ? null : s.firstIntroPass,
      unitKind: s.firstIntroUnitKind,
      unit: s.firstIntroUnit,
      previousAfterPass: s.firstIntroPrevAfterPass || null,
      fnIdx: s.firstIntroFnIdx,
      atEntry: Boolean(s.atEntry),
    },
    stateSeries: entry.series.map((h) => ({
      seq: h.seq, pass: h.pass, state: h.state, count: h.count, repeats: h.repeats,
    })),
  };
}

/**
 * Was this a measurement at all?
 *
 * A log with no control, or with a control that did not survive, is a broken
 * measurement and not a clean result -- interfaces.md §4. Returning the reason
 * rather than a boolean so the caller can print it; null means the run is
 * usable.
 */
export function measurementFault(parsed) {
  if (!parsed.handshake) {
    // The `.summary.tsv` side file is exactly this: SUMMARY and HIST with no
    // handshake and no STATS, written after every change so that a run whose
    // process does not unwind still leaves an attribution behind. It is usable
    // evidence and it is not a complete measurement, because the control's fate
    // is only in the main log -- so it is INCOMPLETE with an accurate reason
    // rather than a claim that the plugin never installed.
    return parsed.summaries.length > 0
      ? 'this is a summary-only side file: it carries the attribution but not the '
        + "handshake or the control's fate, so whether the measurement was sound "
        + 'cannot be established from it. Read the main log instead.'
      : 'the log has no handshake record: the plugin never installed';
  }
  if (!parsed.stats) return 'the log has no STATS record: the compilation did not finish, or the plugin did not unwind';
  if (!parsed.stats.controlSeen) {
    return `the control ${parsed.handshake.control} was never observed, so a run in which `
      + 'nothing was introduced cannot be told apart from a run in which nothing was watched';
  }
  if (parsed.stats.controlFinalState !== 'PRESENT') {
    return `the control ${parsed.handshake.control} ended ${parsed.stats.controlFinalState} `
      + 'rather than PRESENT: the measurement is broken, and nothing in it is a finding';
  }
  if (parsed.summaries.length === 0) return 'the log records no elements at all';
  return null;
}

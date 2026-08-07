// The ABSENT -> INTRODUCED state series, and an independent re-derivation of it.
//
// WHY `INTRODUCED` IS NOT A STATE. interfaces.md §3 fixes six states and
// INTRODUCED is not among them. That is not an omission to work around: the
// states either side of the event already exist, so INTRODUCED is the name of
// the *transition* ABSENT -> PRESENT, and the later arrivals have a state of
// their own, REINTRODUCED, because by then the element has a history. Widening
// a vocabulary that three other components are written against, in order to
// name something the vocabulary can already express, would buy nothing and
// break the contract.
//
// WHY THIS EXISTS ALONGSIDE THE C++. The plugin runs the state machine inside
// the compiler and writes both its conclusion (SUMMARY) and its evidence
// (HIST). `reduceSeries` here runs the same machine over the evidence, from a
// separate implementation in a separate language, and `crossCheck` compares the
// two. A disagreement is a bug in one of them and is reported as such -- which
// is a different and much better failure than one implementation being quietly
// wrong in both the answer and the working.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

export const STATES = [
  'PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED',
];

/**
 * Run the introduction state machine over a sequence of observations.
 *
 * An observation is `{seq, pass, count}`: how many of the element were found at
 * that point. Nothing else is needed, and in particular the caller does not
 * pass in a state -- deriving the state is the whole job, and taking one as
 * input would make this a formatter rather than a check.
 *
 * @param {{seq: number, pass?: string, count: number}[]} observations
 * @param {{firstObservationIsEntry?: boolean}} opts
 *   When true, a nonzero first observation means the element was already there
 *   when the scope was first looked at: no pass introduced it, and the series
 *   starts at PRESENT with no ABSENT before it.
 */
export function reduceSeries(observations, { firstObservationIsEntry = true } = {}) {
  const series = [];
  let cur = 'NOT_OBSERVED';
  let everPresent = false;
  let everLost = false;
  let everReintroduced = false;
  let introEpisodes = 0;
  let lossEpisodes = 0;
  let firstIntroduction = null;

  observations.forEach((o, i) => {
    const present = o.count > 0;
    let next;
    if (present) {
      if (cur === 'LOST') {
        next = 'REINTRODUCED';
        everReintroduced = true;
        introEpisodes += 1;
      } else if (cur === 'NOT_OBSERVED' || cur === 'ABSENT') {
        next = 'PRESENT';
        introEpisodes += 1;
        if (!firstIntroduction) {
          firstIntroduction = {
            seq: o.seq,
            pass: o.pass ?? null,
            atEntry: i === 0 && firstObservationIsEntry,
            previousAfterPass: i > 0 ? (observations[i - 1].pass ?? null) : null,
          };
        }
      } else {
        next = cur;                        // PRESENT or REINTRODUCED, unchanged
      }
      everPresent = true;
    } else if (cur === 'PRESENT' || cur === 'REINTRODUCED') {
      next = 'LOST';
      everLost = true;
      lossEpisodes += 1;
    } else if (cur === 'NOT_OBSERVED') {
      next = 'ABSENT';
    } else {
      next = cur;                          // ABSENT or LOST, unchanged
    }
    cur = next;
    // Runs of the same (state, count) are folded, exactly as the plugin folds
    // them, so the two series are comparable entry for entry.
    const back = series[series.length - 1];
    if (back && back.state === next && back.count === o.count) {
      back.repeats += 1;
      back.lastSeq = o.seq;
    } else {
      series.push({ seq: o.seq, lastSeq: o.seq, pass: o.pass ?? '', count: o.count, state: next, repeats: 1 });
    }
  });

  return {
    series,
    finalState: cur,
    everPresent,
    everLost,
    everReintroduced,
    introEpisodes,
    lossEpisodes,
    firstIntroduction,
  };
}

/**
 * Compare the plugin's SUMMARY against what its own HIST implies.
 *
 * @returns {{element: string, field: string, summary: any, derived: any}[]}
 *   one row per disagreement; empty when the two channels agree.
 */
export function crossCheck(parsed) {
  const problems = [];
  for (const [key, entry] of parsed.byElement) {
    const s = entry.summary;
    const observations = [];
    for (const h of entry.series) {
      // A folded entry stands for `repeats` observations that all agreed, so
      // replaying one of them is enough to reproduce the state -- but the ABSENT
      // entry the plugin writes carries a seq from *before* the introduction and
      // must be replayed as the zero-count observation it records.
      observations.push({ seq: h.seq, pass: h.pass, count: h.count });
    }
    const derived = reduceSeries(observations, {
      firstObservationIsEntry: Boolean(s.atEntry),
    });

    const checks = [
      ['finalState', s.finalState, derived.finalState],
      ['everPresent', Boolean(s.everPresent), derived.everPresent],
      ['everLost', Boolean(s.everLost), derived.everLost],
      ['everReintroduced', Boolean(s.everReintroduced), derived.everReintroduced],
      ['introEpisodes', s.introEpisodes, derived.introEpisodes],
      ['lossEpisodes', s.lossEpisodes, derived.lossEpisodes],
      ['histLen', s.histLen, derived.series.length],
    ];
    if (!s.atEntry) {
      // The introduction the plugin blamed must be the one the series shows.
      checks.push(['firstIntroSeq', s.firstIntroSeq, derived.firstIntroduction?.seq ?? null]);
      checks.push(['firstIntroPass', s.firstIntroPass, derived.firstIntroduction?.pass ?? null]);
    }
    for (const [field, summary, dv] of checks) {
      if (summary !== dv) problems.push({ element: key, field, summary, derived: dv });
    }
  }
  return problems;
}

/**
 * The elements a pass introduced, as opposed to the ones the front end put
 * there. This is the list the block is named after.
 */
export function passIntroduced(parsed) {
  return parsed.summaries
    .filter((s) => !s.atEntry)
    .map((s) => ({
      scope: s.scope,
      kind: s.kind,
      name: s.name,
      pass: s.firstIntroPass,
      unitKind: s.firstIntroUnitKind,
      unit: s.firstIntroUnit,
      seq: s.firstIntroSeq,
      previousAfterPass: s.firstIntroPrevAfterPass || null,
      finalState: s.finalState,
    }));
}

/**
 * ThinLTO: reading N backends' logs instead of one, and grading the cell from
 * what came back instead of from a sentence.
 *
 * Two separate defects lived here until 2026-09-14 and each one hid the other.
 *
 * THE REFUSAL WAS ASSERTED, NOT EARNED. `run-lto-window.mjs` computed the
 * ThinLTO evidence and then called `gradeCell` with an unconditional
 * `{ measurement: BROKEN_MEASUREMENT, reason: plugin-multi-passbuilder }`.
 * `evidence.intact` was never consulted; only `evidence.attempted` reached the
 * record, as `evidenceThisRun`. The README's claim that the word is "earned by
 * this run's own evidence rather than asserted" described a mechanism that did
 * not exist -- it was accidentally true only because the evidence had always
 * come back broken. Measured after the observer was fixed: the evidence said
 * `intact: true` and the cell still said `BROKEN_MEASUREMENT / NOT_OBSERVED`.
 * The whole point of this module is that every refusal below is reached from a
 * measured value, and that when nothing measures broken the cell is graded like
 * any other.
 *
 * ONE BACKEND'S LOG WAS READ AS IF IT WERE THE LINK'S. With the per-module
 * observer (`compiler/pass-instrumentation/observer/History.cpp:117-145`) the
 * unsuffixed `<OBS_OUT>` belongs to whichever tracker reached a module boundary
 * FIRST -- a race, measured twice on the same fixture with two different
 * winners (`main.o`, then `use.o`). The old reader read that one file, found it
 * perfectly intact, and reported `intact: true, distinctHandshakeModuleIds: 1`
 * while two other backends' logs sat unread beside it. On the run that exposed
 * it the winner was `wipe.o`, which does not contain the subject at all: a
 * healthy-looking reading of the wrong module, which is exactly the hazard this
 * lane's README names as the dangerous one.
 *
 * The manifest is what makes that detectable. `<OBS_OUT>.modules` carries one
 * line per tracker, `<module id>\t<the path that tracker actually opened>`, and
 * the line is written BEFORE the open is attempted, so a line with no log
 * beside it is the signal that a backend ran and its history is not here. Hence
 * the rule this module enforces: N lines and fewer than N readable logs is
 * `thinlto-backend-log-lost`, never a reading.
 *
 * Two consequences of the same rule are worth stating because both look like
 * something else:
 *
 *   NO MANIFEST UNDER ThinLTO IS NOT A ONE-MODULE LINK. An observer without
 *   this change writes no manifest and leaves one shredded `<OBS_OUT>` behind,
 *   which is precisely the shape "a single-module link" also has. Treating the
 *   absence as "there was only one backend" would restore the original defect
 *   in a reader instead of a plugin. It is refused.
 *
 *   THE SUBJECT RESOLVING IN EXACTLY ONE BACKEND IS THE NORMAL CASE. The
 *   observer writes SUBJECTRES per module, and a subject defined in `use.c` is
 *   `resolved` there, `declaration-only` in the module that only calls it and
 *   `not-in-module` in the rest (all three measured on the `xtu` family).
 *   Deciding resolution from the first log would have called that a
 *   `subject-did-not-resolve` two times in three, depending on who won the
 *   race. Resolution is decided over every log in the manifest.
 *
 * Pure functions. Nothing here runs a compiler or touches the filesystem; the
 * caller reads the files (it has to -- the manifest's column 2 is an absolute
 * path and must never reach a record) and hands the readings in.
 */

import { gradeCell, MEASUREMENT, REASON } from './cell.mjs';

/**
 * Parse `<OBS_OUT>.modules`.
 *
 * Column 2 is the path the tracker actually opened and it is AUTHORITATIVE: the
 * suffix the observer chooses is sanitised, and past 128 characters it falls
 * back to `module-<index>` which carries nothing of the module id
 * (`History.cpp:83-95`). A reader that re-derives the filename from column 1
 * agrees with the observer on the easy cases and silently misses the hard ones,
 * so this never re-derives anything.
 *
 * A line without a tab is malformed rather than a module id on its own. The
 * manifest is written under a mutex one line at a time, so a torn line there
 * means the same thing a torn line in a log means, and it is not smoothed over.
 */
export function parseModuleManifest(text) {
  const entries = [];
  const malformed = [];
  for (const raw of String(text ?? '').split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (line === '') continue;
    const tab = line.indexOf('\t');
    if (tab <= 0 || tab === line.length - 1) { malformed.push(line.slice(0, 120)); continue; }
    entries.push({ moduleId: line.slice(0, tab), logPath: line.slice(tab + 1) });
  }
  return { entries, malformed };
}

/**
 * Fold N backends' guard-2 readings into the one the cell is graded against.
 *
 * `subset` is ANDed and that is the real check: nothing any backend's observer
 * reported may be outside what the linker says it ran anywhere in this link.
 * The comparison is weaker than the full-LTO one -- lld prints one stream for
 * all backends, so a module's reading is tested against the union rather than
 * against its own backend's lines -- and it is still the check that catches an
 * observer reporting a pass the link never ran.
 *
 * `sequenceEqual` is `null`, not `false`, and the difference matters. Under
 * ThinLTO lld's stderr is ONE stream written by N concurrent backends: measured
 * on the `xtu` family, 751 lines of which 107 were spliced mid-word
 * (`Running pass: Running pass: VerifierPassVerifierPass on  on
 * [module][module]`). An ORDERED comparison of one backend's reading against
 * that stream is not defined, so it is not attempted. `false` would put
 * NOTE.PASS_READINGS_OUT_OF_ORDER on every healthy ThinLTO cell and say two
 * readings drifted apart, when in fact they were never comparable in order.
 * Each backend's own `sequenceEqual` is kept in `perBackend` rather than
 * dropped.
 *
 * The same tearing is why a `subset: false` here must be read with lld's own
 * log in the frame: an id that tearing destroyed every occurrence of would look
 * like an observer reporting a pass that never ran. `observerOnly` is carried
 * out so that reading can be made rather than guessed at.
 */
export function foldPassAgreements(readings) {
  const present = readings.filter((r) => r && r.passAgreement).map((r) => ({ moduleId: r.moduleId, a: r.passAgreement }));
  if (present.length === 0) return null;
  const comparable = present.filter((p) => p.a.comparable);
  const perBackend = present.map((p) => ({
    moduleId: p.moduleId,
    comparable: p.a.comparable,
    subset: p.a.subset,
    sequenceEqual: p.a.sequenceEqual,
    observerCompared: p.a.counts?.observerCompared ?? null,
  }));
  if (comparable.length === 0) {
    return { comparable: false, subset: null, sequenceEqual: null, perBackend, observerOnly: [], counts: null };
  }
  const observerOnly = [...new Set(comparable.flatMap((p) => p.a.observerOnly ?? []))].sort();
  return {
    comparable: true,
    subset: comparable.every((p) => p.a.subset === true),
    sequenceEqual: null,
    perBackend,
    observerOnly,
    counts: {
      backendsCompared: comparable.length,
      observerBeforeCallbacks: comparable.reduce((n, p) => n + (p.a.counts?.observerBeforeCallbacks ?? 0), 0),
      observerCompared: comparable.reduce((n, p) => n + (p.a.counts?.observerCompared ?? 0), 0),
      lldRunningPassLines: comparable[0].a.counts?.lldRunningPassLines ?? null,
    },
  };
}

/**
 * The subject's (or control's) resolution across the whole link.
 *
 * `true` as soon as ONE backend resolved it -- a function is defined in one
 * translation unit and the other backends are right to say `not-in-module`.
 * `false` only when backends did record a resolution and none of them resolved
 * it, which is the real "this run observed nothing about the subject". `null`
 * when no backend recorded one at all, which is "never asked" and is not the
 * same claim.
 */
export function resolutionAcrossBackends(readings, key) {
  const seen = readings.map((r) => r?.[key]).filter((v) => v != null);
  if (seen.length === 0) return null;
  return seen.includes('resolved');
}

/** Every backend that carries a SUMMARY row for one role, with the row. */
export function rowsAcrossBackends(readings, key) {
  return readings.filter((r) => r && r[key]).map((r) => ({ moduleId: r.moduleId, row: r[key] }));
}

const refuse = (reason, details = []) => gradeCell({
  refusal: { measurement: MEASUREMENT.BROKEN_MEASUREMENT, reason, details },
});

/**
 * Grade the ThinLTO link cell from this run's own evidence.
 *
 * Order is load-bearing and runs from "we did not look" outwards to "we looked
 * and here is the reading":
 *
 *   1  the evidence was not taken at all (`--skip-thinlto-evidence`). The word
 *      for that is NOT plugin-multi-passbuilder: asserting the defect in a run
 *      that did not measure it is the thing this module exists to stop.
 *   2  the link did not survive the plugin.
 *   3  the DEFAULT-thread-pool link's own integrity. The reading below comes
 *      from a serialised link, which cannot show a concurrency defect, so the
 *      concurrent link gates the cell.
 *   4  no manifest, or an empty one -- see the header: not a one-module link.
 *   5  a backend named in the manifest whose log is not here, or a torn
 *      manifest line. The one failure the manifest exists to make visible.
 *   6  a log that came back shredded. With 3, THIS is
 *      plugin-multi-passbuilder's signature and the only place the word is now
 *      reachable from.
 *   7  the file the verdict is read out of, per backend.
 *   8  non-invasiveness, which the full-LTO form checks in exitDecision() and
 *      this one checks in the cell.
 *   9  everything else: graded by gradeCell against interfaces.md, exactly the
 *      way a full-LTO cell is.
 *
 * `inputs` and `linkerPipeline` come from the ThinLTO link this lane already
 * ran WITHOUT the plugin, so guard 1 is not taken from the observed link.
 */
export function gradeThinLtoCell({ evidence = null, inputs = null, linkerPipeline = null } = {}) {
  if (!evidence || evidence.attempted !== true) {
    return refuse(REASON.THINLTO_EVIDENCE_NOT_TAKEN,
      ['no ThinLTO link was run in this invocation, so nothing here measured what the ThinLTO word would mean']);
  }
  if (evidence.linkFailed === true) {
    return refuse(REASON.THINLTO_LINK_FAILED,
      [`the ${evidence.where ?? 'ThinLTO'} link exited ${JSON.stringify(evidence.linkRc ?? null)}`]);
  }

  // The concurrency question, before any reading. The reading is taken from a
  // link with `--thinlto-jobs=1` (see thinLtoEvidence for what licenses that),
  // and a serialised link cannot show the defect that lives in the thread
  // pool. So the DEFAULT-pool link's integrity gates the cell: if the
  // per-module observer ever stops surviving concurrency, every cell here says
  // plugin-multi-passbuilder again, no matter how clean the serialised logs
  // are. Without this the serialisation would have quietly bought the lane a
  // green reading of the one thing it exists to detect.
  // Fail-closed on ABSENCE as well as on a bad reading, and the distinction is
  // the whole reason this is two branches rather than one. `cc && cc.intact
  // !== true` -- which is what stood here -- skips the gate entirely when the
  // concurrent reading is missing, and a missing reading is indistinguishable
  // in the cell from a good one: the run is then graded from the serialised
  // link alone, which is precisely the green this guard exists to withhold.
  //
  // DEFENSIVE, AND NOT REACHABLE TODAY, said plainly rather than left for a
  // reader to work out: thinLtoEvidence() sets `concurrent` on its success path
  // and returns `linkFailed` (guard 2, above) when that link does not run, so
  // no current caller can arrive here with it absent. The branch is against the
  // next edit, not against a defect that has been seen.
  const cc = evidence.concurrent;
  if (cc == null) {
    return refuse(REASON.MULTI_PASSBUILDER, [
      'no DEFAULT-thread-pool reading was taken, so nothing in this run distinguishes an observer that '
      + 'survives concurrency from one that does not. The reading below comes from a serialised link and '
      + 'a serialised link cannot show a concurrency defect.',
    ]);
  }
  if (cc.intact !== true) {
    return refuse(REASON.MULTI_PASSBUILDER, [
      'under the DEFAULT thread pool (the schedule the build uses) the observer did not come back whole: '
      + `${cc.logsRead ?? 0} of ${cc.manifest?.lines ?? 0} backend logs readable, `
      + `${cc.handshakeRecords ?? 0} HANDSHAKE record(s), ${cc.nulBytes ?? 0} NUL byte(s), `
      + `${cc.tornLines ?? 0} torn line(s)`,
    ]);
  }

  const man = evidence.manifest ?? {};
  const readings = evidence.modules ?? [];
  if (man.present !== true) {
    return refuse(REASON.THINLTO_NO_MANIFEST,
      ['no <OBS_OUT>.modules was written, so how many backends ran is unknown; an observer without the '
        + 'per-module change leaves exactly one shredded log behind and that is the same shape a '
        + 'single-module link has']);
  }
  if (readings.length === 0) {
    return refuse(REASON.THINLTO_NO_MANIFEST,
      ['<OBS_OUT>.modules is empty: no tracker reached a module boundary, so no backend was observed']);
  }

  const lost = readings.filter((r) => r.logPresent !== true).map((r) => r.moduleId);
  if (lost.length > 0 || (man.malformedLines ?? 0) > 0) {
    return refuse(REASON.THINLTO_BACKEND_LOG_LOST, [
      `${man.lines ?? readings.length} backends in the manifest, ${readings.length - lost.length} logs readable`,
      ...(lost.length ? [`no log for: ${lost.join(', ')}`] : []),
      ...((man.malformedLines ?? 0) > 0 ? [`${man.malformedLines} torn manifest line(s)`] : []),
    ]);
  }

  const shredded = readings.filter((r) => r.logIntact !== true);
  if (shredded.length > 0) {
    return refuse(REASON.MULTI_PASSBUILDER, shredded.map((r) => `${r.moduleId}: `
      + `${r.handshakeRecords} HANDSHAKE record(s), ${r.nulBytes} NUL byte(s), ${r.tornLines} torn line(s)`));
  }
  const summaryBroken = readings.filter((r) => r.summaryIntact === false);
  if (summaryBroken.length > 0) {
    return refuse(REASON.SUMMARY_LOG_NOT_INTACT, summaryBroken.map((r) => `${r.moduleId}'s side file`));
  }

  // Non-invasiveness, on this form rather than borrowed from the other one. A
  // ThinLTO link of these objects is byte-deterministic (measured: five links,
  // with and without the plugin, one sha256), so the comparison means what it
  // means under full LTO. `false` is a finding the caller turns into exit 2;
  // `null` is the stock link never having been compared, and an observed link
  // whose bytes were never compared is not known to be an observation of the
  // program the build produces.
  if (evidence.byteIdentical == null) {
    return refuse(REASON.NON_INVASIVENESS_NOT_ESTABLISHED,
      ['the stock ThinLTO link was not compared with the observed one in this run']);
  }

  const subjectRows = rowsAcrossBackends(readings, 'subjectRow');
  const controlRows = rowsAcrossBackends(readings, 'controlRow');
  for (const [role, rows] of [['subject', subjectRows], ['control', controlRows]]) {
    if (rows.length > 1) {
      return refuse(REASON.THINLTO_ROW_IN_SEVERAL_BACKENDS,
        [`the ${role}'s name has a SUMMARY row in ${rows.length} backends (${rows.map((r) => r.moduleId).join(', ')}), `
          + 'so which backend the reading would come from is a choice this lane will not make silently']);
    }
  }

  const summaryIntacts = readings.map((r) => r.summaryIntact).filter((v) => typeof v === 'boolean');

  return gradeCell({
    guards: {
      inputs,
      linkerPipeline,
      passAgreement: foldPassAgreements(readings),
      logIntact: true,
      summaryLogIntact: summaryIntacts.length ? summaryIntacts.every(Boolean) : null,
      evidenceRecords: readings.reduce((n, r) => n + (r.evRecords ?? 0), 0),
    },
    subject: subjectRows[0]?.row ?? null,
    control: controlRows[0]?.row ?? null,
    subjectResolved: resolutionAcrossBackends(readings, 'subjectResolution'),
  });
}

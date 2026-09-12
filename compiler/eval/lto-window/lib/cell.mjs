/**
 * One cell's verdict, in the two vocabularies that are not allowed to merge.
 *
 * `../../schema/interfaces.md` section 3 fixes what the PROPERTY did; section
 * 3.1 fixes whether the INSTRUMENT worked. A cell carries both, and the pairing
 * rule is what this module exists to enforce mechanically rather than by
 * remembering: a cell whose measurement is not OK has state NOT_OBSERVED, and
 * its controlHeld is `false` when a control was measured and fell, `null` only
 * when no control was measured at all.
 *
 * That rule runs in ONE direction, and this module enforced it in both until
 * 2026-09-12. interfaces.md 3.1 says so in bold:
 *
 *     "**The converse does not hold. `state = NOT_OBSERVED` with
 *      `measurement = OK` is legal**, and it is not a loophole; it is a third
 *      situation that a symmetric rule would erase. The instrument ran, the
 *      record hashes, the control was measured -- and at this point there was
 *      no reading of *this* property, because the subject was not in the
 *      translation unit, or the observation point was never reached."
 *
 * finish() used to throw on exactly that pair, with a message citing 3.1, and
 * that throw was reported as evidence that this lane enforces the spec
 * mechanically. It enforced the OPPOSITE of the spec for one of the three
 * cases, inside the module whose whole job is to keep "the instrument did not
 * work" apart from "there was nothing here to read". The throw is gone; what
 * replaced it is at finish(), and the case it used to mis-grade is graded in
 * gradeCell at the `!subject` branch.
 *
 * The three failure words this lane can reach, and why each is the right one:
 *
 *   UNSUPPORTED         the toolchain refused the invocation. Measured here for
 *                       gcc: `gcc-13 -O2 -flto ... -Wl,--load-pass-plugin=<so>`
 *                       exits 1 with `/usr/bin/ld: unrecognized option
 *                       '--load-pass-plugin=...'`. The configuration was asked
 *                       for and could not be built.
 *
 *   BROKEN_MEASUREMENT  the invocation was accepted and no usable reading came
 *                       back. Measured here for ThinLTO (the observer's log came
 *                       back shredded) and for the erasure family at link time
 *                       (the control fell, so nothing the subject did can be
 *                       told apart from the observer failing).
 *
 *   NOT_OBSERVED        section 3's word, the state that goes with both of the
 *                       above. Never reported as ABSENT. "We did not look" and
 *                       "it was not there" are the two claims this whole tree is
 *                       built to keep apart. It is ALSO the state of the third
 *                       situation quoted above, where the measurement is OK:
 *                       an instrument that worked and found nothing to read is
 *                       not a broken instrument, and calling it one blames the
 *                       apparatus for a fact about the program.
 *
 * Pure functions. Nothing here runs or reads anything.
 */

export const MEASUREMENT = Object.freeze({
  OK: 'OK',
  UNSUPPORTED: 'UNSUPPORTED',
  BROKEN_MEASUREMENT: 'BROKEN_MEASUREMENT',
});

export const STATE = Object.freeze({
  PRESENT: 'PRESENT',
  ABSENT: 'ABSENT',
  LOST: 'LOST',
  REINTRODUCED: 'REINTRODUCED',
  NOT_APPLICABLE: 'NOT_APPLICABLE',
  NOT_OBSERVED: 'NOT_OBSERVED',
});

/**
 * The checkpoint and stage words, quoted from
 * `../../schema/observation.schema.json`. Spelled as constants here so that a
 * typo is a load error in this lane rather than a record that validates against
 * nothing. There is no `execution` or `runtime` checkpoint; if this lane ever
 * needs one it asks for it in the schema first.
 */
export const CHECKPOINT_AFTER_PASS = 'after-pass';
export const STAGE_LTO_BACKEND = 'lto-backend';
export const STAGE_COMPILE = 'compile';

/** Reasons this lane can give for not having looked. One string, one meaning. */
export const REASON = Object.freeze({
  MULTI_PASSBUILDER: 'plugin-multi-passbuilder',
  NOT_AN_LTO_LINK: 'not-an-lto-link',
  LINKER_REFUSED_PLUGIN_OPTION: 'linker-refused-plugin-option',
  NO_OBSERVER_FOR_VENDOR: 'no-observer-for-this-vendor',
  PASS_READINGS_DISAGREE: 'pass-readings-disagree',
  CONTROL_DID_NOT_HOLD: 'control-did-not-hold',
  OBSERVER_LOG_NOT_INTACT: 'observer-log-not-intact',
  // The verdict is read from `<OBS_OUT>.summary.tsv` whenever the main log has
  // no SUMMARY rows, which under full LTO is always (lld exits without
  // unwinding, so the tracker's destructor never calls finish()). The file the
  // verdict comes out of gets its own integrity word, because the file the
  // guard ran on and the file the answer came from were two different files.
  SUMMARY_LOG_NOT_INTACT: 'observer-summary-file-not-intact',
  NO_EVIDENCE_RECORDS: 'observer-produced-no-evidence',
  SUBJECT_DID_NOT_RESOLVE: 'subject-did-not-resolve',
  NO_SUBJECT_HISTORY: 'observer-recorded-no-history-for-the-subject',
  // Not a failure of the instrument: interfaces.md 3.1's third situation, where
  // the instrument ran and there was no reading of THIS property here. Its own
  // string, because "the observer broke" and "the observer worked and this
  // property was not there to read" are the two claims this lane exists to keep
  // apart, and one word for both would merge them in the exclusion list.
  NO_SUBJECT_READING: 'no-reading-of-the-subject-at-this-point',
});

/**
 * Things a cell records without refusing.
 *
 * A note NEVER changes a verdict. It exists so that a reading worth seeing is
 * not dropped for want of a field to put it in -- `sequenceEqual: false` was
 * computed, reported in the agreement record, and consulted by nothing.
 */
export const NOTE = Object.freeze({
  PASS_READINGS_OUT_OF_ORDER: 'pass-readings-agree-as-a-set-but-not-in-order',
});

/**
 * Fold a SUMMARY row into the section-3 state for one role.
 *
 * `finalState` is the observer's own last word, and the history is kept whole
 * beside it: a run that went PRESENT -> LOST -> PRESENT reports REINTRODUCED and
 * the first loss is still recorded, because section 3 forbids stopping at the
 * first transition.
 */
export function stateFromSummary(summary) {
  if (!summary) return { state: STATE.NOT_OBSERVED, firstLoss: null };
  return {
    state: summary.finalState,
    firstLoss: summary.firstLossPass ? { pass: summary.firstLossPass, seq: summary.firstLossSeq } : null,
    everPresent: summary.everPresent,
    everLost: summary.everLost,
    everReintroduced: summary.everReintroduced,
    fate: summary.fate,
  };
}

/**
 * Grade one observation cell.
 *
 * `refusal` short-circuits everything: if the configuration could not be built
 * or must not be read, nothing downstream is consulted, because consulting it is
 * how a refused cell acquires a verdict.
 */
export function gradeCell({
  refusal = null,          // { measurement, reason } when the cell must not be read
  guards = {},             // { inputs, linkerPipeline, passAgreement, byteIdentity, logIntact, summaryLogIntact, evidenceRecords }
  subject = null,          // SUMMARY row for the subject, or null
  control = null,          // SUMMARY row for the control, or null
  subjectResolved = null,  // true / false / null (never asked)
} = {}) {
  const reasons = [];
  const notes = [];

  if (refusal) {
    return finish({
      measurement: refusal.measurement,
      state: STATE.NOT_OBSERVED,
      controlHeld: null,
      attribution: null,
      reasons: [refusal.reason],
    });
  }

  // Guard 1. Both halves, and the order matters: an input that is not bitcode
  // makes the linker-pipeline reading meaningless rather than merely absent.
  if (guards.inputs && guards.inputs.ok === false) {
    reasons.push(REASON.NOT_AN_LTO_LINK, ...guards.inputs.problems);
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: null, attribution: null, reasons });
  }
  if (guards.linkerPipeline && guards.linkerPipeline.runs === 0) {
    reasons.push(REASON.NOT_AN_LTO_LINK,
      'the linker printed 0 "Running pass:" lines with --lto-debug-pass-manager, so no LTO pipeline ran');
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: null, attribution: null, reasons });
  }

  // The observer has to have produced something, and that something has to be
  // readable. A silently-declined plugin produces byte-identical output and an
  // empty log, which is the shape a clean result also has.
  if (guards.logIntact === false) {
    reasons.push(REASON.OBSERVER_LOG_NOT_INTACT);
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: null, attribution: null, reasons });
  }
  if (typeof guards.evidenceRecords === 'number' && guards.evidenceRecords === 0) {
    reasons.push(REASON.NO_EVIDENCE_RECORDS);
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: null, attribution: null, reasons });
  }
  // And the file the SUMMARY rows are actually read from has to be intact too.
  // `logIntact` above is the MAIN log; under full LTO every verdict in this lane
  // comes out of `<OBS_OUT>.summary.tsv` instead, and that file went unchecked
  // until 2026-09-12 -- the guarded file and the read file were not the same
  // file. `null`/absent means "the summaries did not come from the side file",
  // which is the compile-time shape.
  if (guards.summaryLogIntact === false) {
    reasons.push(REASON.SUMMARY_LOG_NOT_INTACT);
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: null, attribution: null, reasons });
  }

  // Guard 2. The SUBSET reading is what refuses a cell, and that is the whole
  // of it: nothing the observer reports may be outside what the linker says it
  // ran. Stated that way because the README used to describe the refusal as an
  // ordered-sequence comparison, which is the strictly stronger reading and is
  // not what gates anything here.
  if (guards.passAgreement && guards.passAgreement.comparable && guards.passAgreement.subset === false) {
    reasons.push(REASON.PASS_READINGS_DISAGREE);
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: null, attribution: null, reasons });
  }
  // The stronger reading does not refuse, and it is not dropped either. Two
  // readings that agree as sets but not in order still name passes the linker
  // really ran, so the attribution stands; a cell whose two readings drifted
  // apart in order is worth seeing rather than averaging away.
  if (guards.passAgreement && guards.passAgreement.comparable
      && guards.passAgreement.subset !== false && guards.passAgreement.sequenceEqual === false) {
    notes.push(NOTE.PASS_READINGS_OUT_OF_ORDER);
  }

  if (subjectResolved === false) {
    reasons.push(REASON.SUBJECT_DID_NOT_RESOLVE);
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: null, attribution: null, reasons });
  }

  // The control. `false` here is a measured failure, and it is reported as one:
  // writing null would describe a control that fell as one nobody ran.
  //
  // There is a third value, and interfaces.md 3.1 does not currently cover it.
  // A cell broken for some other reason -- no subject history, a shredded log --
  // may still have measured a control that HELD. This lane records `true` there
  // rather than flattening it to null, because null says nobody measured, and
  // somebody did. The README asks for that third case to be written into
  // interfaces.md rather than left to each component to decide.
  const ctl = stateFromSummary(control);
  const controlHeld = control ? ctl.state === STATE.PRESENT && ctl.everLost === false : null;
  if (control && controlHeld === false) {
    reasons.push(REASON.CONTROL_DID_NOT_HOLD,
      `the control ended ${ctl.state}` + (ctl.firstLoss ? ` (first loss at ${ctl.firstLoss.pass})` : ''));
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: false, attribution: null, reasons });
  }

  // No SUMMARY row for the subject under the name this cell asked about. Two
  // different facts have that shape and interfaces.md 3.1 is explicit that they
  // must not share a verdict:
  //
  //   (a) the instrument is ESTABLISHED -- the log is intact, it carries
  //       evidence records, the subject name resolved, and a control was
  //       measured and HELD -- and there is still no row. Then the instrument
  //       ran and there was no reading of THIS property here: 3.1's third
  //       situation, `OK` with NOT_OBSERVED. Nothing downstream grades such a
  //       cell either way; what changes is what the exclusion list says
  //       happened, and this lane is not going to blame its own observer for a
  //       fact about the program.
  //
  //   (b) anything less: the main log's integrity was never established, or no
  //       evidence records were counted, or the subject name was never put to a
  //       module, or no control was measured at all. Then the missing row IS the
  //       instrument failing, and the word is BROKEN_MEASUREMENT.
  //
  // (a) is reachable, and an earlier version of this comment claimed it was not
  // ("a resolved subject always gets a row"). It does not: the observer resolves
  // a subject by LINEAGE (`lineageRoot(F.getName()) == OBS_TARGET_FN`,
  // History.cpp:119-129) and records each unit under its own, possibly mangled,
  // NAME (History.cpp:187, `U.Name = Key`; History.cpp:190, `U.Clone =
  // (Key != Root)`), while the
  // harness looks the row up by the fixture's plain name. A subject that
  // survives a link only as `handle.llvm.1041` therefore resolves and has no row
  // under `handle`. Requiring a measured, HELD control before reading that as
  // (a) is what keeps it from becoming a hiding place: without a control there
  // is no evidence the observation point was live at all.
  if (!subject) {
    const instrumentEstablished = guards.logIntact === true
      && typeof guards.evidenceRecords === 'number' && guards.evidenceRecords > 0
      && subjectResolved === true
      && controlHeld === true;
    if (instrumentEstablished) {
      reasons.push(REASON.NO_SUBJECT_READING);
      return finish({ measurement: MEASUREMENT.OK, state: STATE.NOT_OBSERVED, controlHeld, attribution: null, reasons, notes });
    }
    reasons.push(REASON.NO_SUBJECT_HISTORY);
    return finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld, attribution: null, reasons });
  }

  const sub = stateFromSummary(subject);
  const attribution = sub.firstLoss
    ? { pass: sub.firstLoss.pass, unit: subject.unit, checkpoint: CHECKPOINT_AFTER_PASS }
    : null;

  return finish({
    measurement: MEASUREMENT.OK,
    state: sub.state,
    controlHeld,
    attribution,
    reasons,
    notes,
    subjectHistory: sub,
  });
}

/**
 * The pairing rule, applied to this module's own output rather than trusted.
 * Every return above goes through here, so a future edit that produces an
 * illegal pair throws in this lane instead of writing a record.
 *
 * EXPORTED so that the backstop itself is tested. Until 2026-09-12 every throw
 * in here could be deleted with all 31 of the lane's tests still passing: the
 * sweep in test/cell.test.mjs asserts properties of gradeCell's OUTPUT, which
 * hold whether or not this function checks anything. A backstop nobody tested is
 * a comment, and this one was also wrong.
 */
export function finish(cell) {
  const out = {
    ...cell,
    attribution: cell.attribution ?? null,
    reasons: cell.reasons ?? [],
    notes: cell.notes ?? [],
  };
  if (out.measurement !== MEASUREMENT.OK && out.state !== STATE.NOT_OBSERVED) {
    throw new Error(`interfaces.md 3.1: measurement ${out.measurement} requires state NOT_OBSERVED, got ${out.state}`);
  }
  if (out.measurement !== MEASUREMENT.OK && out.attribution !== null) {
    throw new Error('a cell that did not measure cannot carry an attribution');
  }
  // No throw for OK + NOT_OBSERVED. interfaces.md 3.1 declares that pair legal
  // in bold and says why: an instrument that worked and found nothing to read is
  // a third fact, and a symmetric rule erases it. What IS required of such a
  // cell is that it say why it read nothing -- `OK / NOT_OBSERVED` with no
  // reason at all is indistinguishable from a cell that forgot to fill itself
  // in -- and that it carry no attribution, because there was no reading to
  // attribute.
  if (out.measurement === MEASUREMENT.OK && out.state === STATE.NOT_OBSERVED) {
    if (out.reasons.length === 0) {
      throw new Error('an OK cell with state NOT_OBSERVED must say why nothing was read (interfaces.md 3.1: the instrument ran and there was no reading of this property)');
    }
    if (out.attribution !== null) {
      throw new Error('a cell that read nothing cannot carry an attribution');
    }
  }
  if (out.controlHeld === false && out.measurement === MEASUREMENT.OK) {
    throw new Error('a control that fell cannot leave the measurement OK');
  }
  return out;
}

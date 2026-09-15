/**
 * The order in which the which-wipe plumbing is allowed to be believed.
 *
 * tools/which-wipe-survived.mjs turns three compiler invocations into three
 * integers and then into one word. lib/record.mjs's whichWipeSurvived() grades
 * the integers and is well covered; the part that MAKES them was not covered at
 * all, and it has two failure modes that produce a plausible table rather than
 * an error:
 *
 *   the cut hit the wrong line     -- lib/variant-cut.mjs is the answer to that
 *                                     one, and it is a pure function.
 *   the reader read the wrong body -- objdump_fill counts the zero fill of the
 *                                     function it is given. Given a function
 *                                     that is not the absorbed body, it returns
 *                                     a number, and the number is not wrong in
 *                                     any way the tool can see.
 *
 * This file is the part that is still pure once those are separated: WHICH
 * checks have to hold, in WHAT ORDER, before the subject's word may be read at
 * all. The order is the point. Every gate here is about the instrument, and the
 * subject verdict is the thing the instrument is for -- so `subjectWord` is a
 * thunk, and a failing gate means it is never called. A check that computes the
 * headline first and then decides whether it was entitled to is a check that has
 * already read it.
 *
 * This mirrors whichWipeSurvived()'s own rule (the BLIND branch is tested before
 * the subject branches, and record.test.mjs pins that ordering) one layer out,
 * where the failure is not "the fill did not move" but "there was never three
 * builds" or "the number came from another function".
 *
 * WHAT EACH GATE IS EVIDENCE OF, since two of them were once weaker than they
 * read:
 *
 *   DISTINCT_SOURCES       the three source TEXTS differ. This is the one that
 *                          catches a cut that deleted nothing, and it needs no
 *                          compiler to be true or false. It is first because
 *                          everything below it is downstream of it.
 *   DISTINCT_COMPILATIONS  the three OBJECTS differ. Only evidence at all
 *                          because lib/build-variants.mjs now compiles every
 *                          variant from one path: while the path carried the
 *                          variant's tag, clang put that path into the object
 *                          and three distinct digests were guaranteed by the
 *                          filenames (measured -- see that file's header). This
 *                          gate could not fail, and a gate that cannot fail is
 *                          not a gate.
 *   CONTROL_MOVES_FILL     deleting the control's wipe removes EXACTLY the
 *                          control's wipe. `< asWritten` was too weak: any
 *                          movement in the right direction satisfied it,
 *                          including a rebuild that changed something else. The
 *                          fixture says what the number has to be, so the gate
 *                          says it too. This is the lane's one INDEPENDENT
 *                          control reading -- see CONTROL_PRESENT below.
 */

export const GATE = Object.freeze({
  /** Three variants must be three different source texts before anything else. */
  DISTINCT_SOURCES: 'three-variants-are-three-distinct-source-texts',
  /** Three variants must be three compilations, not one compilation read three times. */
  DISTINCT_COMPILATIONS: 'three-variants-are-three-distinct-compilations',
  /** The fill was counted in the body the cell names, not in whatever objdump found. */
  READER_ON_NAMED_BODY: 'the-fill-was-read-in-the-body-the-cell-names',
  /** The as-written build has the control's wipe in it, read as PRESENT. */
  CONTROL_PRESENT: 'the-as-written-control-reads-PRESENT',
  /** Deleting a wipe that may not be removed must take exactly that wipe away. */
  CONTROL_MOVES_FILL: 'deleting-the-control-wipe-removes-exactly-the-control-wipe',
});

/** The order the gates are evaluated in, and the order they are reported in. */
export const GATE_ORDER = Object.freeze([
  GATE.DISTINCT_SOURCES,
  GATE.DISTINCT_COMPILATIONS,
  GATE.READER_ON_NAMED_BODY,
  GATE.CONTROL_PRESENT,
  GATE.CONTROL_MOVES_FILL,
]);

/**
 * Is the as-written control reading a SEPARATE reading from the subject's?
 *
 * In the family this lane measures it is not, and saying so is the point of
 * this function. Both wipes are absorbed into one body, so read-wipe.py is asked
 * for the control with the same function name and the same byte count as the
 * subject; the only difference is that the control is asked without the helper.
 * In a healthy build the two readings are therefore the same dict, and
 * CONTROL_PRESENT cannot disagree with the subject reading it is supposed to be
 * a control ON. It still fails when the instrument is blind in that executable
 * (NOT_OBSERVED, ABSENT, PARTIAL), which is worth having and is all it is.
 *
 * The reading that IS independent of the subject is CONTROL_MOVES_FILL: it comes
 * from a different build -- the one with the control's wipe cut out of the
 * source -- and no subject reading can produce it. That is why this file states
 * the coincidence in the record instead of leaving the gate looking stronger
 * than it is. README.md carries it as a named limitation.
 */
export function controlIndependence(obs) {
  const s = obs.subjectReading ?? null;
  const c = obs.controlReading ?? null;
  if (!s || !c) return 'not-read';
  if (c.where !== s.where) return 'separate-body';
  if (typeof obs.controlWipeBytes === 'number' && typeof obs.subjectWipeBytes === 'number'
      && obs.controlWipeBytes !== obs.subjectWipeBytes) return 'same-body-different-byte-count';
  return 'same-body-same-question';
}

const gate = (name, ok, why, extra = {}) => ({ gate: name, ok, why, ...extra });

/**
 * @param obs.sourceDigests   {tag: sha256} of the source TEXT each variant was
 *                        compiled from, as it was read back off disk.
 * @param obs.digests     {tag: sha256} of the per-variant object the cut edits.
 *                        Three tags, three distinct digests, or the builds did
 *                        not respond to the three sources.
 * @param obs.caller      the function whose fill the cell is about.
 * @param obs.subjectReading  the as-written subject reading (objdump_fill's dict).
 * @param obs.controlReading  the as-written control reading, same build.
 * @param obs.fill        {asWritten, subjectCut, controlCut} byte counts.
 * @param obs.controlWipeBytes  how many bytes the control's own wipe writes, so
 *                        that deleting it can be required to remove that many
 *                        rather than merely "fewer than before".
 * @param subjectWord     a thunk. Called ONLY if every gate passed.
 *
 * @returns {{gates: object[], failed: string|null, subject: any}} `subject` is
 *          null whenever a gate failed, and that null is the point of the file.
 */
export function gatedSubjectReading(obs, subjectWord) {
  const gates = [];

  // 1. the SOURCES. A cut that deleted nothing is visible here and nowhere
  // earlier, and it does not need a compiler to be seen.
  const sources = Object.values(obs.sourceDigests ?? {});
  const distinctSources = new Set(sources.filter((d) => typeof d === 'string' && d.length > 0));
  gates.push(gate(
    GATE.DISTINCT_SOURCES,
    sources.length === 3 && distinctSources.size === 3,
    `${sources.length} variant source(s), ${distinctSources.size} distinct text(s): the as-written source and its `
    + 'two cuts are three different texts by construction. Equal texts mean the cut removed nothing or removed the '
    + 'same line twice, and a build of the as-written source under another tag reads as "deleting it changed nothing"',
  ));

  // 2. the OBJECTS. Evidence only because every variant is compiled from one
  // path (lib/build-variants.mjs): a per-variant filename made this pass on its
  // own, whatever the sources said.
  const digests = Object.values(obs.digests ?? {});
  const distinct = new Set(digests.filter((d) => typeof d === 'string' && d.length > 0));
  gates.push(gate(
    GATE.DISTINCT_COMPILATIONS,
    digests.length === 3 && distinct.size === 3,
    `${digests.length} variant object(s), ${distinct.size} distinct digest(s): three sources that differ by one `
    + 'deleted line, compiled from one and the same path, must produce three different objects. Equal digests mean '
    + 'a build was reused, a write did not land, or the compiler did not respond to the text -- and all of those '
    + 'read as "deleting it changed nothing"',
  ));

  const sr = obs.subjectReading ?? null;
  gates.push(gate(
    GATE.READER_ON_NAMED_BODY,
    Boolean(sr) && sr.verdict !== 'NOT_OBSERVED' && sr.where === obs.caller,
    sr
      ? `the as-written fill was read in \`${sr.where}\` (verdict ${sr.verdict}); this cell counts the fill of `
        + `\`${obs.caller}\`. A count taken from another body is a number with nothing wrong with it that the `
        + 'tool can see'
      : 'there is no as-written subject reading at all',
  ));

  const cr = obs.controlReading ?? null;
  const independence = controlIndependence(obs);
  gates.push(gate(
    GATE.CONTROL_PRESENT,
    Boolean(cr) && cr.verdict === 'PRESENT',
    cr
      ? `the as-written control reads ${cr.verdict} (${cr.bytes}B in \`${cr.where}\`), not PRESENT: the wipe that `
        + 'no level may remove is not being seen, so the instrument is blind before the subject is asked about'
      : 'there is no as-written control reading at all',
    // Stated on every run, passing or failing: in the absorbed family this
    // reading is the SAME question as the subject's, so it cannot disagree with
    // it. The independent control is the gate below. See controlIndependence().
    { independence },
  ));

  const f = obs.fill ?? {};
  const numeric = ['asWritten', 'subjectCut', 'controlCut'].every((k) => typeof f[k] === 'number' && f[k] >= 0);
  const want = obs.controlWipeBytes;
  const wantKnown = typeof want === 'number' && want > 0;
  const removed = numeric ? f.asWritten - f.controlCut : null;
  gates.push(gate(
    GATE.CONTROL_MOVES_FILL,
    numeric && wantKnown && removed === want,
    !numeric
      ? 'one of the three builds produced no byte count'
      : !wantKnown
        ? 'nobody said how many bytes the control\'s own wipe writes, so "the fill moved" cannot be checked against '
          + 'anything: any movement at all would satisfy it'
        : `deleting the control's wipe took ${removed}B away (${f.asWritten}B as written, ${f.controlCut}B without it) `
          + `where the control's wipe is ${want}B. The wipe that no level may remove must come out of the fill `
          + 'exactly, or the build is not responding to its source the way the fixture says it does',
    { removedBytes: removed, expectedBytes: wantKnown ? want : null },
  ));

  const failedGate = gates.find((g) => !g.ok) ?? null;
  return {
    gates,
    failed: failedGate ? failedGate.gate : null,
    controlIndependence: independence,
    subject: failedGate ? null : subjectWord(),
  };
}

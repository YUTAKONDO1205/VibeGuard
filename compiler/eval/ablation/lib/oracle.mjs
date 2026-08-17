// The ground truth an ablation is scored against.
//
// "Did this configuration detect the loss" has no meaning until something else
// says whether there was a loss. Three candidates were available and the choice
// matters enough to write down:
//
//   1. the manifest's `hypothesis.firstLossStage`. Rejected: it is the
//      experiment's expectation, and scoring detectors against an expectation
//      measures agreement with the author, not with the compiler.
//   2. the existing `_results/trace-*.json`. Rejected: those records were
//      produced by the same checkpoint chain that gates B and C are, so a gate
//      would be scored against its own output.
//   3. the last layer the compiler will show us before the object file — the
//      assembly — read through the shared predicate, with the fixture's
//      co-resident control required to be visible in the same text.
//
// (3) is used. It is downstream of every gate except E, it is the layer closest
// to the shipped artefact that is still text, and the control requirement is
// what separates "the effect was removed" from "the oracle cannot see this form
// of the effect". At -O1 and above a wipe is rendered as inline zeroing rather
// than a call, and an oracle without the control would report every such cell
// as a loss.
//
// It is NOT independent of gates B and C in implementation: all three call
// `predicates.evaluate` from the measurement workspace. They differ in the layer
// they look at, not in the matcher. A false negative common to the matcher is
// therefore invisible to this harness, and README.md says so under
// "What this does not measure".

export const GROUND_TRUTH = {
  LOST: 'LOST',
  PRESERVED: 'PRESERVED',
  NOT_APPLICABLE: 'NOT_APPLICABLE',
  VERIFICATION_INCOMPLETE: 'VERIFICATION_INCOMPLETE',
};

/**
 * @param {object} asmReading  the result of evaluate({layer:'asm', ...})
 * @param {object} baselineAsm the same at the fixture's reference configuration
 */
export function groundTruth(asmReading, baselineAsm) {
  if (!asmReading) {
    return { state: GROUND_TRUTH.VERIFICATION_INCOMPLETE, reason: 'no assembly reading was taken' };
  }
  switch (asmReading.verdict) {
    case 'ABSENT':
      return {
        state: GROUND_TRUTH.LOST,
        reason:
          'the effect is absent from the subject at the assembly layer while the co-resident ' +
          'control still shows it, so the oracle was not blind here',
        controlCount: asmReading.control ? asmReading.control.count : null,
      };
    case 'PRESENT': {
      // A form change is still a preserved property. classify() in the
      // measurement workspace makes the same distinction; it is repeated here
      // rather than imported so that the scoring vocabulary stays local.
      const b = baselineAsm && baselineAsm.effect ? baselineAsm.effect.forms : null;
      const c = asmReading.effect ? asmReading.effect.forms : null;
      const formChanged =
        b && c && ((b.call > 0 && c.call === 0 && c.inline > 0) || (b.inline > 0 && c.inline === 0 && c.call > 0));
      return {
        state: GROUND_TRUTH.PRESERVED,
        reason: formChanged
          ? 'the effect survives in a different form from the reference configuration'
          : 'the effect survives to the assembly layer',
        formChanged: Boolean(formChanged),
        controlCount: asmReading.control ? asmReading.control.count : null,
      };
    }
    case 'NOT_APPLICABLE':
      return {
        state: GROUND_TRUTH.NOT_APPLICABLE,
        reason:
          asmReading.reason ||
          'the object the effect acted on is no longer there, so the question has lost its referent',
      };
    case 'INVALID_CONTROL':
      return {
        state: GROUND_TRUTH.VERIFICATION_INCOMPLETE,
        reason: asmReading.reason || 'the control could not be read, so no verdict is issued',
      };
    case 'UNOBSERVED':
    default:
      return {
        state: GROUND_TRUTH.VERIFICATION_INCOMPLETE,
        reason: asmReading.reason || 'the assembly layer was not observed',
      };
  }
}

/**
 * Score one gate result against one ground truth.
 * Returns one of: tp, fn, fp, tn, excluded.
 *
 * `excluded` is deliberately large. A gate that answers a different question
 * (NOT_APPLICABLE), that has no rule for this property (UNSUPPORTED), or whose
 * own validity check failed (VERIFICATION_INCOMPLETE) contributes to no
 * denominator. Folding those into fn would produce a recall number that reads
 * as "this component missed it" for cells where the component was never asked.
 */
export function score(gateResult, truthState) {
  if (truthState === GROUND_TRUTH.VERIFICATION_INCOMPLETE || truthState === GROUND_TRUTH.NOT_APPLICABLE) {
    return 'excluded';
  }
  if (gateResult === 'DETECTED') return truthState === GROUND_TRUTH.LOST ? 'tp' : 'fp';
  if (gateResult === 'NOT_DETECTED') return truthState === GROUND_TRUTH.LOST ? 'fn' : 'tn';
  return 'excluded';
}

export function emptyTally() {
  return { tp: 0, fn: 0, fp: 0, tn: 0, excluded: 0 };
}

export function recall(t) {
  return t.tp + t.fn === 0 ? null : t.tp / (t.tp + t.fn);
}

export function falseAlarmRate(t) {
  return t.fp + t.tn === 0 ? null : t.fp / (t.fp + t.tn);
}

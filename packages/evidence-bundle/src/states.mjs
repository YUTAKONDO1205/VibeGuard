// Property states and the oracle rule — the two places where a record can be
// internally consistent and still be a lie.
//
// ── THE WHOLE SEQUENCE ──────────────────────────────────────────────────────
//
// schema/interfaces.md section 3 fixes six states, and adds one rule that is
// easy to write code against and easy to get wrong:
//
//   "A component that records a state history MUST keep the whole sequence and
//    must not stop at the first PRESENT to LOST transition."
//
// The tempting implementation is `states.find(s => s.verdict === 'ABSENT')`,
// which answers "where did it first go missing?" and throws the rest away. A
// history of PRESENT, LOST, REINTRODUCED, LOST then reports one loss. The
// second loss is the one that survives to the artefact, and it is the one the
// naive reading drops — while the first, which a later pass undid, is reported
// as the finding. That is a false positive with a plausible story attached.
//
// So `stateHistory` returns EVERY transition, and `firstLoss` is derived from
// the full list rather than being the thing that stops the walk.
//
// ── THE ORACLE RULE ─────────────────────────────────────────────────────────
//
// schema/interfaces.md section 4: never decide whether an effect is present by
// searching for a symbol name. Count the zeroing instruction — the call site.
// A deleted call still leaves its declaration behind, so a name search reports
// the effect as present until some later pass sweeps unused declarations away,
// and the loss is then attributed to the sweeper rather than to the pass that
// actually did it.
//
// Two consequences this file can actually check, because both are in the
// record's own numbers:
//
//   * every measurement carries a CONTROL whose effect cannot be optimised
//     away. If the control's count is zero the measurement is broken, not a
//     finding — there is nothing to distinguish "the optimiser removed the
//     subject" from "the harness measured nothing at all";
//   * the verdict and the count must agree on zero-versus-nonzero. PRESENT
//     with a zero effect count, or ABSENT with a nonzero one, means the verdict
//     was written by something other than the measurement.

/** The full vocabulary. A state outside this set is a malformed record. */
export const PROPERTY_STATES = Object.freeze([
  'PRESENT',
  'ABSENT',
  'LOST',
  'REINTRODUCED',
  'NOT_APPLICABLE',
  'NOT_OBSERVED',
]);

/**
 * The coarse observation verdict the evidence-v0 record already carries
 * alongside the finer `state`. Kept separate rather than merged, because the
 * record schema is fixed and this file may not change it.
 */
export const VERDICTS = Object.freeze(['PRESENT', 'ABSENT', 'UNOBSERVED']);

/** A verdict that means the property was seen to be gone. */
const GONE = new Set(['ABSENT', 'LOST']);

export class StateHistoryError extends Error {
  constructor(message, where) {
    super(where ? `${message} (at ${where})` : message);
    this.name = 'StateHistoryError';
    this.where = where ?? null;
  }
}

/**
 * The effective state of one entry: its explicit `state` when it has one, its
 * `verdict` otherwise. `UNOBSERVED` maps onto `NOT_OBSERVED`, which is the
 * same claim in the vocabulary of section 3.
 *
 * @param {Record<string, unknown>} entry
 * @returns {string}
 */
export function effectiveState(entry) {
  if (typeof entry.state === 'string') return entry.state;
  if (entry.verdict === 'UNOBSERVED') return 'NOT_OBSERVED';
  if (typeof entry.verdict === 'string') return entry.verdict;
  return 'NOT_OBSERVED';
}

/**
 * The WHOLE history: every transition, in order, with nothing dropped.
 *
 * @param {Array<Record<string, unknown>>} states
 * @param {{ propertyId?: string }} [opts]
 * @returns {{
 *   sequence: Array<{index: number, checkpoint: string|null, state: string, verdict: string|null}>,
 *   losses: Array<{index: number, from: string|null, to: string}>,
 *   reintroductions: Array<{index: number, checkpoint: string|null}>,
 *   observed: number,
 *   unobserved: number,
 *   unknownStates: Array<{index: number, state: string}>,
 *   reintroducedWithoutLoss: Array<{index: number, checkpoint: string|null}>,
 * }}
 */
export function stateHistory(states, opts = {}) {
  const list = Array.isArray(states) ? states : [];
  const sequence = [];
  const losses = [];
  const reintroductions = [];
  const unknownStates = [];
  const reintroducedWithoutLoss = [];
  let observed = 0;
  let unobserved = 0;
  let lastSeenCheckpoint = null;
  let currentlyGone = false;
  let everGone = false;

  for (let i = 0; i < list.length; i += 1) {
    const entry = list[i] ?? {};
    const state = effectiveState(entry);
    const checkpoint = typeof entry.checkpoint === 'string' ? entry.checkpoint : null;
    const verdict = typeof entry.verdict === 'string' ? entry.verdict : null;

    if (!PROPERTY_STATES.includes(state)) unknownStates.push({ index: i, state });

    if (state === 'NOT_OBSERVED') unobserved += 1;
    else observed += 1;

    sequence.push({ index: i, checkpoint, state, verdict });

    // Every transition is recorded. The walk does not stop at the first loss,
    // and a reintroduction resets the "gone" flag so a SECOND loss is a second
    // entry in `losses` rather than being swallowed.
    if (GONE.has(state)) {
      if (!currentlyGone) {
        losses.push({ index: i, from: lastSeenCheckpoint, to: checkpoint });
        currentlyGone = true;
        everGone = true;
      }
    } else if (state === 'PRESENT' || state === 'REINTRODUCED') {
      if (state === 'REINTRODUCED') {
        reintroductions.push({ index: i, checkpoint });
        if (!everGone) reintroducedWithoutLoss.push({ index: i, checkpoint });
      }
      currentlyGone = false;
      lastSeenCheckpoint = checkpoint;
    }
    // NOT_APPLICABLE changes neither: the question stopped having the same
    // referent, which is not a loss and not an observation of presence.
  }

  return {
    sequence,
    losses,
    reintroductions,
    observed,
    unobserved,
    unknownStates,
    reintroducedWithoutLoss,
    propertyId: opts.propertyId ?? null,
  };
}

/**
 * The oracle rule, asked of one state entry that carries counts.
 *
 * Returns `null` when the entry carries no counts — which is "not checked",
 * never "checked and clean". The caller decides what to do with that; it must
 * not silently become a pass.
 *
 * @param {Record<string, unknown>} entry
 * @returns {{ok: true}|{ok: false, reason: string, detail: string}|null}
 */
export function checkOracle(entry) {
  const effect = entry?.effect;
  const control = entry?.control;
  if (!Number.isInteger(effect) || !Number.isInteger(control)) return null;

  if (control === 0) {
    return {
      ok: false,
      reason: 'control-zero',
      detail:
        'the control count is 0. Every measurement carries a control whose effect cannot be ' +
        'optimised away, so a control at zero means the harness measured nothing — a broken ' +
        'measurement, not a finding about the subject.',
    };
  }
  if (control < 0 || effect < 0) {
    return {
      ok: false,
      reason: 'negative-count',
      detail: `counts are call-site counts and cannot be negative: effect=${effect} control=${control}.`,
    };
  }

  const verdict = entry.verdict;
  if (verdict === 'PRESENT' && effect === 0) {
    return {
      ok: false,
      reason: 'present-with-zero-effect',
      detail:
        'the verdict is PRESENT and the effect count is 0. The verdict and the count disagree ' +
        'on zero-versus-nonzero, so the verdict was not written by the measurement.',
    };
  }
  if (verdict === 'ABSENT' && effect !== 0) {
    return {
      ok: false,
      reason: 'absent-with-nonzero-effect',
      detail: `the verdict is ABSENT and the effect count is ${effect}, which is not zero.`,
    };
  }
  return { ok: true };
}

/**
 * Refuse a record whose histories break either rule. Used at seal time, so a
 * record that cannot be believed is never written in the first place.
 *
 * @param {Record<string, unknown>} record
 */
export function assertStatesAreSane(record) {
  const props = Array.isArray(record?.properties) ? record.properties : [];
  for (const property of props) {
    const pid = typeof property?.propertyId === 'string' ? property.propertyId : '(unnamed)';
    const states = Array.isArray(property?.states) ? property.states : [];
    const history = stateHistory(states, { propertyId: pid });

    if (history.unknownStates.length > 0) {
      const names = history.unknownStates.map((u) => JSON.stringify(u.state)).join(', ');
      throw new StateHistoryError(
        `${pid}: ${names} is not one of the six property states (${PROPERTY_STATES.join(', ')})`,
        `properties.${pid}.states`,
      );
    }
    if (history.reintroducedWithoutLoss.length > 0) {
      throw new StateHistoryError(
        `${pid}: a checkpoint is marked REINTRODUCED with no preceding loss in the same ` +
          'history. REINTRODUCED means "PRESENT again after being LOST"; without the loss it ' +
          'claims a recovery that never happened.',
        `properties.${pid}.states`,
      );
    }
    for (let i = 0; i < states.length; i += 1) {
      const verdict = checkOracle(states[i]);
      if (verdict && verdict.ok === false) {
        throw new StateHistoryError(
          `${pid}: checkpoint ${JSON.stringify(states[i]?.checkpoint ?? null)} — ${verdict.detail}`,
          `properties.${pid}.states[${i}]`,
        );
      }
    }
  }
}

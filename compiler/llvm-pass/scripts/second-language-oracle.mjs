// second-language-oracle — the counting rules, with no I/O in them.
//
// This file is the whole of the judgement for the second-language measurement,
// separated from the thing that produces the numbers so that the two can be
// tested apart. It knows three things and nothing else:
//
//   1. how to count an effect in LLVM IR text (call sites, never symbol names);
//   2. how to turn an ordered series of counts into a state history;
//   3. how to attribute the first loss in that history to a named pass.
//
// ── Why the counting rule is written the way it is ──────────────────────────
//
// interfaces.md section 4 is not a style preference. A deleted call leaves
//
//     declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)
//
// behind at module scope, so a search for the symbol keeps reporting the effect
// as present until some later pass sweeps unused declarations away. That
// misattributes the loss to the sweeper. Everything here counts CALL SITES, and
// a call site only exists inside a `define` body — which is also why the count
// is kept per IR unit rather than per module: after inlining, the out-of-line
// original survives until dead-code elimination removes it, and a module-wide
// count keeps reporting an effect from a function nobody calls.
//
// `declareLines` and `naiveTotal` are returned as well, not because anything
// decides on them, but so a record can show the two oracles disagreeing on the
// same input. On the measured Rust fixture at the highest optimisation level
// they disagree by exactly the declaration: call sites 0, naive total 2.

/** The effect this package measures: the zeroing intrinsic family. */
export const DEFAULT_EFFECT = 'llvm.memset';

/** States from interfaces.md section 3. NOT_OBSERVED is never inferred here. */
export const STATES = Object.freeze([
  'PRESENT',
  'ABSENT',
  'LOST',
  'REINTRODUCED',
  'NOT_APPLICABLE',
  'NOT_OBSERVED',
]);

// A `define` line names its unit as the last @name that is immediately followed
// by the parameter list. Rust emits both bare and quoted symbol names, so both
// spellings are accepted; the return type may itself mention an @ (a named
// struct type), which is why the parameter list is part of the pattern.
const DEFINE_RE = /^define\b[^@]*(?:@(?:"((?:[^"\\]|\\.)*)"|([\w$.\-]+))\s*\()/;
const DECLARE_RE = /^declare\b/;
// `call`, `tail call`, `musttail call`, `notail call`, and the two exception
// forms. An `invoke` is a call site too: Rust code that can unwind uses it.
const CALLSITE_RE = /(?:^|\s)(?:(?:tail|musttail|notail)\s+)?(?:call|invoke)\s/;

/**
 * Count call sites to `effect` in each IR unit of `irText`.
 *
 * @param {string} irText  textual LLVM IR (`--emit=llvm-ir`, or `opt -S`)
 * @param {{effect?: string}} [opts]
 * @returns {{units: Record<string, number>, unitOrder: string[],
 *            declareLines: number, naiveTotal: number, defineCount: number}}
 */
export function countCallSitesByUnit(irText, opts = {}) {
  if (typeof irText !== 'string') throw new TypeError('irText must be a string');
  const effect = opts.effect ?? DEFAULT_EFFECT;
  const units = Object.create(null);
  const unitOrder = [];
  let declareLines = 0;
  let naiveTotal = 0;
  let defineCount = 0;
  let current = null;

  for (const raw of irText.split('\n')) {
    const line = raw.trimEnd();
    if (line.includes(effect)) naiveTotal++;

    if (current === null) {
      const m = DEFINE_RE.exec(line);
      if (m) {
        current = m[1] !== undefined ? m[1] : m[2];
        defineCount++;
        if (!(current in units)) {
          units[current] = 0;
          unitOrder.push(current);
        }
        continue;
      }
      // Outside any body. A declaration of the effect is counted separately and
      // is deliberately NOT added to any unit: this single `continue` is what
      // keeps the naive oracle's answer out of the call-site oracle's answer.
      if (DECLARE_RE.test(line) && line.includes(effect)) declareLines++;
      continue;
    }

    if (line === '}') {
      current = null;
      continue;
    }
    if (CALLSITE_RE.test(line) && line.includes(effect)) units[current]++;
  }

  return { units, unitOrder, declareLines, naiveTotal, defineCount };
}

/**
 * Turn an ordered series of observation points into a state history.
 *
 * Each point is `{label, targetCallSites, controlCallSites}`. Order is
 * significant and is never sorted: it is the pipeline order, or the ascending
 * optimisation levels, whichever the caller measured.
 *
 * The whole sequence is returned. This function must not stop at the first
 * PRESENT -> LOST, because a later pass can undo the loss and reporting the
 * truncated history is a false positive with a plausible story attached.
 *
 * A control is "broken" only if it was established and then fell to zero. A
 * control reading zero before the effect exists in the IR at all is not broken:
 * at the lowest optimisation level the zeroing is still a call to a wrapper
 * that the always-inliner has not yet inlined, and both the subject and the
 * control legitimately read zero at that point.
 *
 * @param {{label: string, targetCallSites: number, controlCallSites: number}[]} points
 */
export function deriveStateHistory(points) {
  if (!Array.isArray(points)) throw new TypeError('points must be an array');
  const history = [];
  let established = false;
  let last = null;
  let controlEstablished = false;
  let brokenControlAt = null;

  for (const p of points) {
    requireCount(p, 'targetCallSites');
    requireCount(p, 'controlCallSites');

    // THE LINE. A zero count is only a LOSS if the effect was observed here
    // before; before that it is an ABSENCE, which is not a finding.
    const state = p.targetCallSites > 0
      ? (last === 'LOST' ? 'REINTRODUCED' : 'PRESENT')
      : (established ? 'LOST' : 'ABSENT');

    if (p.targetCallSites > 0) established = true;
    if (p.controlCallSites > 0) controlEstablished = true;
    else if (controlEstablished && brokenControlAt === null) brokenControlAt = p.label;

    history.push({ label: p.label, state });
    last = state;
  }

  return {
    history,
    states: history.map((h) => h.state),
    finalState: history.length ? history[history.length - 1].state : 'NOT_OBSERVED',
    everPresent: established,
    brokenControlAt,
  };
}

function requireCount(p, key) {
  const v = p?.[key];
  if (!Number.isInteger(v) || v < 0) {
    throw new TypeError(`${key} must be a non-negative integer, got ${JSON.stringify(v)}`);
  }
}

/**
 * Attribute the first loss to a pass, from a per-pass observation trace.
 *
 * `rows` are `{seq, phase, pass, unit, callSites}` in emission order, as the
 * pass-instrumentation observer writes them. The subject's and the control's
 * rows are interleaved; each is followed separately.
 *
 * Returns `firstLoss: null` when the subject never went from a positive count
 * to zero. That is a real answer, not a failure: it is what "the phenomenon was
 * not observed" looks like.
 */
export function firstLoss(rows, { target, control }) {
  if (!Array.isArray(rows)) throw new TypeError('rows must be an array');
  if (!target || !control) throw new TypeError('target and control are required');
  const t = rows.filter((r) => r.unit === target);
  const c = rows.filter((r) => r.unit === control);

  let prev = null;
  let loss = null;
  const transitions = [];
  for (const r of t) {
    requireCount(r, 'callSites');
    if (prev !== null && prev !== r.callSites) {
      transitions.push({ seq: r.seq, phase: r.phase, pass: r.pass, from: prev, to: r.callSites });
      if (prev > 0 && r.callSites === 0 && loss === null) {
        loss = { seq: r.seq, phase: r.phase, pass: r.pass, from: prev };
      }
    }
    prev = r.callSites;
  }

  // The control's minimum is taken only from the point at which it was first
  // established, for the same reason deriveStateHistory ignores a leading zero.
  let seenControl = false;
  let controlMin = null;
  for (const r of c) {
    requireCount(r, 'callSites');
    if (r.callSites > 0) seenControl = true;
    if (!seenControl) continue;
    controlMin = controlMin === null ? r.callSites : Math.min(controlMin, r.callSites);
  }

  const passes = new Set(rows.map((r) => r.pass));
  return {
    firstLoss: loss,
    transitions,
    observedPasses: passes.size,
    targetRows: t.length,
    controlRows: c.length,
    targetFirst: t.length ? t[0].callSites : null,
    targetLast: t.length ? t[t.length - 1].callSites : null,
    controlMin,
    controlEstablished: seenControl,
  };
}

// The targeted baseline the general fingerprint is measured against.
//
// This is deliberately NOT the general normaliser. It is the call-site oracle
// from compiler/schema/interfaces.md section 4, reimplemented here over the
// same parsed IR the fingerprint reads, so that both sides of the comparison
// see byte-identical input. It knows exactly one thing -- how to count calls to
// a named callee inside one function -- and that narrowness is the point: it is
// the baseline precisely because it was allowed to make a per-property decision
// the general version is not.
//
// Two rules it obeys, and one it demonstrates by counting both ways:
//   * count CALL SITES, resolved from the instruction, never the symbol name.
//     A deleted call leaves `declare void @llvm.memset.p0.i64(...)` behind, so
//     a name search reports the effect as present until some later pass sweeps
//     the declaration away, and blames the sweeper.
//   * count inside ONE IR unit, never across the module.
// `naiveNameHits` exists so a run can print the wrong number next to the right
// one rather than assert in prose that they differ.

import { isGlobal } from './tokens.mjs';
import { undecorateSymbol } from './normalise.mjs';

/** Callee of a call-like instruction, undecorated, or null. */
export function resolveCallee(inst) {
  const t = inst.tokens;
  if (t[0] !== 'call' && t[0] !== 'invoke' && t[0] !== 'musttail' && t[0] !== 'notail'
    && t[0] !== 'tail') return null;
  for (let i = 1; i < t.length; i += 1) {
    if (isGlobal(t[i]) && t[i + 1] === '(') return undecorateSymbol(t[i]);
  }
  return null; // indirect call
}

/**
 * Count call sites in one function whose callee name starts with `prefix`.
 * @returns {number}
 */
export function countCallSites(fn, prefix) {
  let n = 0;
  for (const b of fn.blocks) {
    for (const inst of b.insts) {
      const callee = resolveCallee(inst);
      if (callee !== null && callee.slice(1).startsWith(prefix)) n += 1;
    }
  }
  return n;
}

/**
 * The wrong oracle, kept so a measurement can show the gap instead of claiming
 * it. Counts every textual occurrence of the name in the whole module.
 */
export function naiveNameHits(text, name) {
  const re = new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
  return (text.match(re) ?? []).length;
}

/** Does the function still contain a conditional branch on a computed value? */
export function hasDataDependentBranch(fn) {
  for (const b of fn.blocks) {
    for (const inst of b.insts) {
      if (inst.tokens[0] !== 'br') continue;
      if (inst.tokens[1] === 'i1' && inst.tokens[2] !== 'true' && inst.tokens[2] !== 'false') return true;
    }
  }
  return false;
}

/**
 * The targeted verdict for the wipe property in one function, in the vocabulary
 * of interfaces.md section 3. `NOT_OBSERVED` when the function is absent -- it
 * is never reported as `ABSENT`, because those are different claims.
 */
export function targetedWipeState(mod, fnName, prefix = 'llvm.memset') {
  const fn = mod.byName.get(fnName);
  if (fn === undefined) return { state: 'NOT_OBSERVED', callSites: 0 };
  const n = countCallSites(fn, prefix);
  return { state: n > 0 ? 'PRESENT' : 'ABSENT', callSites: n };
}

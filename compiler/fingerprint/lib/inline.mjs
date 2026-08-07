// Normalisation 4: inlined calls.
//
// At -O0 a helper is a `call`; at -O2 the same helper is a run of instructions
// with no call at all. Nothing else in the pipeline can make those two agree,
// so this step expands calls to callees the module defines, and the two forms
// converge on the expanded one.
//
// The expansion is bounded and it refuses more cases than it accepts. Every
// refusal is recorded by name in `notes`, because a fingerprint computed with
// four call sites left unexpanded is a different measurement from one computed
// with none, and a caller that cannot tell them apart will read a mismatch as a
// semantic difference.

import { cloneFunction, splitTopLevel } from './parse.mjs';
import { isGlobal, isLocal, bareName } from './tokens.mjs';

export const DEFAULT_LIMITS = Object.freeze({ maxRounds: 4, maxInstructions: 6000 });

/** The callee of a plain `call`, or null when the instruction is not one. */
export function calleeOf(inst) {
  const t = inst.tokens;
  // `musttail` and `invoke` are never expanded: the first has a calling
  // convention this splice would break, the second has an unwind edge.
  if (t[0] !== 'call') return null;
  for (let i = 1; i < t.length; i += 1) {
    if (isGlobal(t[i]) && t[i + 1] === '(') return t[i];
  }
  return null;
}

/** The value token of each actual argument of a call. */
export function callArguments(inst) {
  const t = inst.tokens;
  let open = -1;
  for (let i = 1; i < t.length; i += 1) {
    if (isGlobal(t[i]) && t[i + 1] === '(') {
      open = i + 1;
      break;
    }
  }
  if (open === -1) return [];
  let depth = 0;
  let close = -1;
  for (let j = open; j < t.length; j += 1) {
    if (t[j] === '(') depth += 1;
    else if (t[j] === ')') {
      depth -= 1;
      if (depth === 0) {
        close = j;
        break;
      }
    }
  }
  if (close === -1) return [];
  // The value is the last token of each top-level group; the tokens before it
  // are the type. Parameter attributes are already gone by this point.
  return splitTopLevel(t.slice(open + 1, close)).map((g) => g[g.length - 1]);
}

function countInstructions(fn) {
  let n = 0;
  for (const b of fn.blocks) n += b.insts.length;
  return n;
}

/** Why a callee cannot be expanded, or null when it can. */
export function refusalReason(g) {
  if (g === undefined) return 'not defined in this module';
  if (g.varargs) return 'variadic';
  if (g.blocks.length === 0) return 'no body';
  let rets = 0;
  for (const b of g.blocks) {
    for (const inst of b.insts) {
      const op = inst.tokens[0];
      if (op === 'ret') rets += 1;
      if (op === 'invoke' || op === 'resume' || op === 'landingpad' || op === 'callbr'
        || op === 'indirectbr' || op === 'va_arg' || op === 'musttail'
        || op === 'catchswitch' || op === 'catchret' || op === 'cleanupret') {
        return `contains ${op}`;
      }
    }
  }
  if (rets !== 1) return `${rets} return instructions (only one is handled)`;
  return null;
}

function renameLocals(fn, pfx) {
  const rename = (t) => (isLocal(t) ? `%${pfx}${bareName(t)}` : t);
  for (const p of fn.params) if (p.name !== null) p.name = rename(p.name);
  for (const b of fn.blocks) {
    b.label = `${pfx}${b.label}`;
    for (const inst of b.insts) {
      if (inst.result !== null) inst.result = rename(inst.result);
      inst.tokens = inst.tokens.map(rename);
    }
  }
}

function substitute(fn, map) {
  if (map.size === 0) return;
  for (const b of fn.blocks) {
    for (const inst of b.insts) {
      for (let i = 0; i < inst.tokens.length; i += 1) {
        const r = map.get(inst.tokens[i]);
        if (r !== undefined) inst.tokens[i] = r;
      }
    }
  }
}

/**
 * Expand calls in `fn` (which must already be a clone). Returns
 * `{ expanded, refused }` where `refused` is one entry per call site left
 * alone, naming the callee and the reason.
 */
export function expandCalls(mod, fn, limits = DEFAULT_LIMITS) {
  const refused = [];
  let expanded = 0;
  let serial = 0;

  for (let round = 0; round < limits.maxRounds; round += 1) {
    let site = null;
    outer:
    for (let bi = 0; bi < fn.blocks.length; bi += 1) {
      const b = fn.blocks[bi];
      for (let ii = 0; ii < b.insts.length; ii += 1) {
        const inst = b.insts[ii];
        const callee = calleeOf(inst);
        if (callee === null) continue;
        if (callee === fn.name || inst.origins.includes(callee)) continue; // recursion
        const g = mod.byName.get(callee);
        const why = refusalReason(g);
        if (why !== null) continue;
        if (countInstructions(fn) + countInstructions(g) > limits.maxInstructions) continue;
        site = { bi, ii, g };
        break outer;
      }
    }
    if (site === null) break;
    spliceCall(fn, site.bi, site.ii, site.g, `il${serial}_`);
    serial += 1;
    expanded += 1;
  }

  // Whatever is still a call after the last round is reported, once per site.
  for (const b of fn.blocks) {
    for (const inst of b.insts) {
      const callee = calleeOf(inst);
      if (callee === null) continue;
      const g = mod.byName.get(callee);
      const why = callee === fn.name || inst.origins.includes(callee)
        ? 'recursive'
        : (refusalReason(g) ?? 'expansion budget exhausted');
      refused.push({ callee, reason: why });
    }
  }
  return { expanded, refused };
}

function spliceCall(fn, bi, ii, g, pfx) {
  const call = fn.blocks[bi].insts[ii];
  const args = callArguments(call);
  const gg = cloneFunction(g);
  renameLocals(gg, pfx);

  const paramMap = new Map();
  gg.params.forEach((p, i) => {
    if (p.name !== null) paramMap.set(p.name, args[i] ?? 'poison');
  });
  substitute(gg, paramMap);

  const origins = [...call.origins, g.name];
  for (const b of gg.blocks) for (const inst of b.insts) inst.origins = [...origins];

  let retBlock = -1;
  let retIdx = -1;
  for (let x = 0; x < gg.blocks.length && retBlock === -1; x += 1) {
    const y = gg.blocks[x].insts.findIndex((i) => i.tokens[0] === 'ret');
    if (y !== -1) {
      retBlock = x;
      retIdx = y;
    }
  }
  const retInst = gg.blocks[retBlock].insts[retIdx];
  // `ret void` has one token; `ret i32 %5` has the value last.
  const retVal = retInst.tokens.length > 1 && retInst.tokens[1] !== 'void'
    ? retInst.tokens[retInst.tokens.length - 1]
    : null;

  if (gg.blocks.length === 1) {
    const body = gg.blocks[0].insts.filter((_, k) => k !== retIdx);
    fn.blocks[bi].insts.splice(ii, 1, ...body);
  } else {
    // The callee's entry block is merged into the caller's block rather than
    // reached by a branch. An entry block has no predecessors, so the merge is
    // always legal -- and without it the expansion leaves an empty forwarding
    // block that the real inliner never produces, so the -O0 and -O2 forms
    // would differ by exactly one block and never agree.
    const contLabel = `${pfx}cont`;
    const tail = fn.blocks[bi].insts.slice(ii + 1);
    gg.blocks[retBlock].insts[retIdx] = {
      result: null, tokens: ['br', 'label', `%${contLabel}`], raw: '', origins,
    };
    const [entry, ...rest] = gg.blocks;
    fn.blocks[bi].insts = [...fn.blocks[bi].insts.slice(0, ii), ...entry.insts];
    fn.blocks.splice(bi + 1, 0, ...rest, { label: contLabel, implicit: false, insts: tail });
  }

  if (call.result !== null && retVal !== null) substitute(fn, new Map([[call.result, retVal]]));
}

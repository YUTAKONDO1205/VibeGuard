// The general property fingerprint.
//
// One digest per function, computed from a canonical form of its instruction
// graph. Property-class independent by construction: nothing below knows what a
// wipe is, what a fail-closed branch is, or what any rule looks for. That is
// the whole point of the block, and it is also the reason it is allowed to lose
// to the targeted extractors -- a normaliser that has to serve every property
// at once cannot make the decision any one of them would make.
//
// Order of operations, and why:
//   1. token rewrite (debug-paths, symbol-decoration, hygiene) over the WHOLE
//      module first, so that the inliner never splices a debug intrinsic in;
//   2. inlined-calls, which changes the block structure;
//   3. block order (block-names), because instruction canonicalisation needs a
//      dominating definition to already have its canonical name;
//   4. instruction order within each block (instruction-order);
//   5. canonical value names (ssa-values), assigned in that order;
//   6. serialisation, where commutative-operands is applied, since sorting
//      operands is only rename-stable once the names are canonical.

import { createHash } from 'node:crypto';

import { cloneFunction, TERMINATORS } from './parse.mjs';
import { expandCalls, DEFAULT_LIMITS } from './inline.mjs';
import {
  SEVEN, HYGIENE, MOVABLE, COMMUTATIVE, SWAPPED_PREDICATE, rewriteFunction,
} from './normalise.mjs';
import { isLocal, labelOperandIndices } from './tokens.mjs';

/** All seven plus the two hygiene steps. */
export function allSteps() {
  return new Set([...SEVEN, ...HYGIENE]);
}

/** All steps except the named ones. Used by the isolation tests. */
export function stepsWithout(...off) {
  const s = allSteps();
  for (const o of off) s.delete(o);
  return s;
}

function sha256(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/** Reverse post-order from the entry block; unreachable blocks appended. */
function reversePostOrder(fn, notes) {
  const byLabel = new Map(fn.blocks.map((b) => [b.label, b]));
  const seen = new Set();
  const post = [];
  const successors = (b) => {
    const term = b.insts[b.insts.length - 1];
    if (term === undefined) return [];
    if (!TERMINATORS.has(term.tokens[0])) return [];
    const out = [];
    for (const i of labelOperandIndices(term.tokens)) {
      const target = byLabel.get(term.tokens[i].slice(1));
      if (target === undefined) notes.push(`successor ${term.tokens[i]} does not name a block`);
      else out.push(target);
    }
    return out;
  };
  if (fn.blocks.length === 0) return [];
  // Iterative DFS, so a long chain of blocks cannot blow the stack.
  const stack = [{ b: fn.blocks[0], next: 0, succ: null }];
  seen.add(fn.blocks[0].label);
  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    if (top.succ === null) top.succ = successors(top.b);
    if (top.next < top.succ.length) {
      const s = top.succ[top.next];
      top.next += 1;
      if (!seen.has(s.label)) {
        seen.add(s.label);
        stack.push({ b: s, next: 0, succ: null });
      }
      continue;
    }
    post.push(top.b);
    stack.pop();
  }
  const ordered = post.reverse();
  const unreachable = fn.blocks.filter((b) => !seen.has(b.label));
  if (unreachable.length > 0) notes.push(`${unreachable.length} unreachable block(s) kept in textual order`);
  return [...ordered, ...unreachable];
}

/**
 * Split a block into runs. A run of movable instructions may be reordered; an
 * anchor is a run of one and never moves.
 */
function segments(insts) {
  const out = [];
  let cur = null;
  for (const inst of insts) {
    const movable = MOVABLE.has(inst.tokens[0]);
    if (movable && cur !== null) {
      cur.push(inst);
      continue;
    }
    if (cur !== null) {
      out.push({ movable: true, insts: cur });
      cur = null;
    }
    if (movable) cur = [inst];
    else out.push({ movable: false, insts: [inst] });
  }
  if (cur !== null) out.push({ movable: true, insts: cur });
  return out;
}

/**
 * Canonical order for one run of movable instructions.
 *
 * Sorting by the instruction's text would make the order depend on the value
 * names, which is exactly what `ssa-values` exists to remove. So the key is a
 * structural hash whose leaves are canonical names already assigned (a
 * dominating definition always has one, because blocks are visited in reverse
 * post-order) and whose internal nodes are the run's own instructions. Ties
 * break on the hash, and the result is a stable topological sort.
 */
function orderRun(run, canon, notes) {
  if (run.length < 2) return run;
  const defs = new Map();
  for (const inst of run) if (inst.result !== null) defs.set(inst.result, inst);

  const memo = new Map();
  const structHash = (inst, guard) => {
    if (memo.has(inst)) return memo.get(inst);
    if (guard.has(inst)) return 'cycle';
    guard.add(inst);
    // Build the same rendering the serialiser will, with hashes standing in for
    // names, and run it through the SAME operand canonicaliser. Using a
    // different rule here was a real bug: `icmp slt %x, %y` and the identical
    // `icmp sgt %y, %x` hashed differently, so the two forms sorted into
    // different positions and the finished fingerprints diverged even though
    // the serialiser would have canonicalised them to one line.
    const rendered = inst.tokens.map((t) => {
      if (!isLocal(t)) return t;
      if (canon.has(t)) return canon.get(t);
      if (defs.has(t)) return structHash(defs.get(t), guard);
      return `raw:${t}`;
    });
    canonicaliseOperands(rendered);
    const h = sha256(rendered.join(' ')).slice(0, 16);
    guard.delete(inst);
    memo.set(inst, h);
    return h;
  };

  const key = new Map(run.map((inst) => [inst, structHash(inst, new Set())]));
  const pending = new Set(run);
  const placed = [];
  const ready = (inst) => inst.tokens.slice(1).every(
    (t) => !isLocal(t) || !defs.has(t) || !pending.has(defs.get(t)),
  );

  while (pending.size > 0) {
    const candidates = [...pending].filter(ready);
    if (candidates.length === 0) {
      // A dependency cycle among movable instructions is impossible in valid
      // SSA. Refusing to reorder is the honest response; guessing is not.
      notes.push('a movable run had no ready instruction; left in textual order');
      placed.push(...[...pending]);
      break;
    }
    candidates.sort((a, b) => (key.get(a) < key.get(b) ? -1 : key.get(a) > key.get(b) ? 1 : 0));
    placed.push(candidates[0]);
    pending.delete(candidates[0]);
  }
  return placed;
}

/** Render one instruction with canonical names, then canonicalise operands. */
function render(inst, canon, blockId, on, notes) {
  const labelIdx = new Set(labelOperandIndices(inst.tokens));
  const out = inst.tokens.map((t, i) => {
    if (labelIdx.has(i)) {
      const id = blockId.get(t.slice(1));
      if (id === undefined) {
        notes.push(`block reference ${t} not resolved`);
        return on.has('block-names') ? '<unresolved-block>' : t;
      }
      return on.has('block-names') ? id : t;
    }
    if (!isLocal(t)) return t;
    if (!on.has('ssa-values')) return t;
    const id = canon.get(t);
    // A `%name` that is not a value is a named type (`%struct.foo`). Leaving it
    // alone is right; silently renaming it would be a collision waiting.
    return id === undefined ? t : id;
  });

  if (on.has('commutative-operands')) canonicaliseOperands(out);
  return out.join(' ');
}

/** In-place operand canonicalisation for the commutative and comparison forms. */
export function canonicaliseOperands(r) {
  const op = r[0];
  const commas = [];
  let depth = 0;
  for (let i = 0; i < r.length; i += 1) {
    if (r[i] === '(' || r[i] === '[' || r[i] === '{' || r[i] === '<') depth += 1;
    else if (r[i] === ')' || r[i] === ']' || r[i] === '}' || r[i] === '>') depth -= 1;
    else if (r[i] === ',' && depth === 0) commas.push(i);
  }
  if (commas.length !== 1) return r; // not the two-operand shape
  const c = commas[0];
  const a = r[c - 1];
  const b = r[c + 1];
  if (a === undefined || b === undefined) return r;

  if (COMMUTATIVE.has(op)) {
    if (a > b) {
      r[c - 1] = b;
      r[c + 1] = a;
    }
    return r;
  }
  if (op === 'icmp' || op === 'fcmp') {
    const pred = r[1];
    const swapped = SWAPPED_PREDICATE[pred];
    if (swapped === undefined) return r;
    if (a > b) {
      r[1] = swapped;
      r[c - 1] = b;
      r[c + 1] = a;
    }
    return r;
  }
  return r;
}

/**
 * Fingerprint one function.
 *
 * @returns {{digest:string, canonicalForm:string, blockCount:number,
 *            instructionCount:number, inlined:number, refusedCallSites:number,
 *            refused:Array, notes:string[], steps:string[]}}
 */
export function fingerprintFunction(mod, fnName, options = {}) {
  const on = options.steps ?? allSteps();
  const limits = options.limits ?? DEFAULT_LIMITS;
  const notes = [];
  const src = mod.byName.get(fnName);
  if (src === undefined) throw new Error(`no such function in module: ${fnName}`);

  // 1. token rewrite, over a clone of the whole module.
  const work = new Map();
  for (const f of mod.functions) {
    // Notes from other functions are not this function's notes; an inlined
    // callee's are lost, which is written down rather than merged in.
    const sink = f.name === fnName ? notes : [];
    work.set(f.name, rewriteFunction(cloneFunction(f), on, sink));
  }
  const rewritten = { functions: [...work.values()], byName: work, declares: mod.declares };
  const fn = work.get(fnName);

  // 2. inlined calls.
  let inlined = 0;
  let refused = [];
  if (on.has('inlined-calls')) {
    const r = expandCalls(rewritten, fn, limits);
    inlined = r.expanded;
    refused = r.refused;
  }

  // 3. block order.
  const blocks = on.has('block-names') ? reversePostOrder(fn, notes) : fn.blocks;
  const blockId = new Map();
  blocks.forEach((b, i) => blockId.set(b.label, `b${i}`));

  // 4 + 5. instruction order and canonical value names, in one pass, because
  // the ordering of a run needs the canonical names of everything before it.
  const canon = new Map();
  fn.params.forEach((p, i) => {
    if (p.name !== null) canon.set(p.name, `a${i}`);
  });
  let n = 0;
  const orderedBlocks = [];
  for (const b of blocks) {
    const ordered = [];
    for (const seg of segments(b.insts)) {
      const run = seg.movable && on.has('instruction-order')
        ? orderRun(seg.insts, canon, notes)
        : seg.insts;
      ordered.push(...run);
    }
    for (const inst of ordered) {
      if (inst.result !== null) {
        canon.set(inst.result, `v${n}`);
        n += 1;
      }
    }
    orderedBlocks.push({ label: b.label, insts: ordered });
  }

  // 6. serialise.
  const lines = [`fn ${fn.retType} (${fn.params.map((p) => p.type).join(' ')})${fn.varargs ? ' ...' : ''}`];
  let instructionCount = 0;
  for (const b of orderedBlocks) {
    lines.push(`${on.has('block-names') ? blockId.get(b.label) : b.label}:`);
    for (const inst of b.insts) {
      const lhs = inst.result === null
        ? ''
        : `${on.has('ssa-values') ? (canon.get(inst.result) ?? inst.result) : inst.result} = `;
      lines.push(`  ${lhs}${render(inst, canon, blockId, on, notes)}`);
      instructionCount += 1;
    }
  }
  const canonicalForm = lines.join('\n');

  return {
    digest: sha256(canonicalForm),
    canonicalForm,
    blockCount: orderedBlocks.length,
    instructionCount,
    inlined,
    refusedCallSites: refused.length,
    refused,
    notes,
    steps: [...on].sort(),
  };
}

/** Fingerprint every function a module defines. */
export function fingerprintModule(mod, options = {}) {
  return mod.functions.map((f) => ({ function: f.name, ...fingerprintFunction(mod, f.name, options) }));
}

// The seven normalisations, plus the two hygiene steps that are NOT part of
// the seven and are named here so they cannot be smuggled in as an eighth.
//
// Every entry in SEVEN is independently switchable. That is not a convenience:
// it is how each one is shown to be doing work. For each normalisation the
// tests hold a pair that differs only in the thing it normalises and assert
// three facts --
//
//   1. with the normalisation on, the pair fingerprints the same;
//   2. with that one normalisation off, the pair fingerprints DIFFERENTLY
//      (so the sameness in (1) came from this step and not from a fingerprint
//      that collapses everything);
//   3. a real semantic difference in the same shape fingerprints differently
//      with the normalisation on.
//
// (1) alone is satisfied by `return 0`. (1)+(2)+(3) is not.

import { isGlobal, isLocal, isMetaName, isMetaRef, isAttrGroup, labelOperandIndices } from './tokens.mjs';

/** The seven, in the order the design lists them. */
export const SEVEN = Object.freeze([
  'ssa-values',
  'block-names',
  'instruction-order',
  'inlined-calls',
  'commutative-operands',
  'debug-paths',
  'symbol-decoration',
]);

/**
 * Always applied, and deliberately not counted among the seven. Anything that
 * lands here is a loss of precision the fingerprint accepts on purpose, and the
 * README says what each costs.
 */
export const HYGIENE = Object.freeze(['lexical', 'metadata-hints']);

// ── lexical ─────────────────────────────────────────────────────────────────

/** Poison-generating and fast-math flags: added and removed by optimisation. */
const FLAG_KEYWORDS = new Set([
  'nsw', 'nuw', 'exact', 'inbounds', 'nneg', 'disjoint', 'samesign',
  'fast', 'nnan', 'ninf', 'nsz', 'arcp', 'contract', 'afn', 'reassoc',
  'tail', 'notail', 'inrange',
]);

const PARAM_ATTRS = new Set([
  'noundef', 'nonnull', 'nocapture', 'readonly', 'writeonly', 'readnone',
  'nofree', 'willreturn', 'returned', 'inreg', 'signext', 'zeroext', 'immarg',
  'noalias', 'nest', 'nosync', 'noext', 'allocptr', 'allocalign', 'writable',
  'dead_on_unwind', 'initializes',
]);

const PARAM_ATTRS_WITH_ARG = new Set([
  'dereferenceable', 'dereferenceable_or_null', 'align', 'byval', 'sret',
  'elementtype', 'inalloca', 'preallocated', 'byref', 'alignstack', 'captures',
  'range',
]);

// ── metadata-hints ──────────────────────────────────────────────────────────

/** Non-debug metadata attachments. Analysis annotations, not program text. */
const HINT_METADATA = new Set([
  '!tbaa', '!tbaa.struct', '!range', '!prof', '!llvm.loop', '!noalias',
  '!alias.scope', '!annotation', '!nosanitize', '!srcloc', '!callees',
  '!unpredictable', '!misexpect', '!callback', '!invariant.group',
  '!invariant.load', '!nontemporal', '!mem_parallel_loop_access',
  '!llvm.access.group', '!make.implicit', '!align', '!noundef', '!exclude',
]);

// ── debug-paths ─────────────────────────────────────────────────────────────

const DEBUG_INTRINSIC_RE = /^@llvm\.dbg\./;
const DEBUG_METADATA_NAME_RE = /^!(dbg|DI[A-Za-z]*|llvm\.dbg\.[a-z]+)$/;

/** Is this whole instruction a debug intrinsic that carries no computation? */
export function isDebugIntrinsic(tokens) {
  const callee = tokens.find((t) => isGlobal(t));
  return callee !== undefined && DEBUG_INTRINSIC_RE.test(callee);
}

// ── symbol-decoration ───────────────────────────────────────────────────────

/**
 * Suffixes the compiler appends when it clones, specialises or uniques a
 * symbol. `.llvm.<digits>` and a bare `.<digits>` are the two the linker and
 * the inliner produce; the rest are named clone kinds.
 *
 * Two things this must NOT do, both of which have their own test:
 *   * never strip from an `llvm.` intrinsic -- `@llvm.memset.p0.i64` would
 *     become a different, non-existent intrinsic;
 *   * never strip trailing digits that are not preceded by a dot, or `@wipe2`
 *     and `@wipe` become one symbol and the fingerprint stops being able to
 *     tell two callees apart.
 */
const DECORATION_RE = /(?:\.(?:llvm|constprop|isra|part|specialized|cold|localalias|resolver|omp_outlined|internal)(?:\.[0-9]+)?|\.[0-9]+)+$/;

export function undecorateSymbol(name) {
  const bare = name.slice(1);
  if (bare.startsWith('llvm.')) return name;
  const stripped = bare.replace(DECORATION_RE, '');
  return stripped === '' ? name : `${name[0]}${stripped}`;
}

// ── commutative-operands ────────────────────────────────────────────────────

export const COMMUTATIVE = new Set(['add', 'fadd', 'mul', 'fmul', 'and', 'or', 'xor']);

/** Predicate under operand swap. `a slt b` is `b sgt a`; `a sub b` is not. */
export const SWAPPED_PREDICATE = Object.freeze({
  eq: 'eq', ne: 'ne',
  ugt: 'ult', uge: 'ule', ult: 'ugt', ule: 'uge',
  sgt: 'slt', sge: 'sle', slt: 'sgt', sle: 'sge',
  oeq: 'oeq', one: 'one', ord: 'ord', uno: 'uno', ueq: 'ueq', une: 'une',
  ogt: 'olt', oge: 'ole', olt: 'ogt', ole: 'oge',
  true: 'true', false: 'false',
});

// ── instruction-order ───────────────────────────────────────────────────────

/**
 * Instructions with no observable effect, which may therefore be moved within
 * the run of such instructions they sit in. Everything absent from this set is
 * an anchor and keeps its position -- most importantly `store`, `load`, `call`
 * and `phi`. Reordering two stores would make a fingerprint that cannot tell a
 * wipe-then-read from a read-then-wipe.
 */
export const MOVABLE = new Set([
  'add', 'fadd', 'sub', 'fsub', 'mul', 'fmul', 'udiv', 'sdiv', 'fdiv',
  'urem', 'srem', 'frem', 'shl', 'lshr', 'ashr', 'and', 'or', 'xor',
  'trunc', 'zext', 'sext', 'fptrunc', 'fpext', 'fptoui', 'fptosi',
  'uitofp', 'sitofp', 'ptrtoint', 'inttoptr', 'bitcast', 'addrspacecast',
  'getelementptr', 'select', 'icmp', 'fcmp', 'extractvalue', 'insertvalue',
  'extractelement', 'insertelement', 'shufflevector', 'freeze', 'alloca',
]);

// ── the token-level rewrite ─────────────────────────────────────────────────

/**
 * Rewrite one instruction's tokens under the enabled steps. Returns null when
 * the whole instruction is removed (a debug intrinsic under `debug-paths`).
 *
 * `on` is a Set of enabled step ids. `notes` collects anything dropped that the
 * caller should know about.
 */
export function rewriteTokens(tokens, on, notes) {
  if (on.has('debug-paths') && isDebugIntrinsic(tokens)) return null;

  const out = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];

    // A metadata attachment is `, !name !12` or `, !name !DIExpression(...)`.
    if (isMetaName(t)) {
      const isDebug = DEBUG_METADATA_NAME_RE.test(t);
      const isHint = HINT_METADATA.has(t);
      const drop = (isDebug && on.has('debug-paths')) || (isHint && on.has('metadata-hints'));
      if (drop) {
        // Drop the name, its argument, and the comma that introduced it.
        while (out.length > 0 && out[out.length - 1] === ',') out.pop();
        i = skipMetadataOperand(tokens, i + 1) - 1;
        continue;
      }
      out.push(t);
      continue;
    }

    if (isAttrGroup(t)) {
      if (on.has('symbol-decoration')) continue;
      out.push(t);
      continue;
    }

    if (isGlobal(t)) {
      out.push(on.has('symbol-decoration') ? undecorateSymbol(t) : t);
      continue;
    }

    // Hygiene: flags and parameter attributes.
    if (FLAG_KEYWORDS.has(t)) continue;
    if (PARAM_ATTRS.has(t)) continue;
    if (PARAM_ATTRS_WITH_ARG.has(t)) {
      if (tokens[i + 1] === '(') {
        let depth = 0;
        let j = i + 1;
        for (; j < tokens.length; j += 1) {
          if (tokens[j] === '(') depth += 1;
          else if (tokens[j] === ')') {
            depth -= 1;
            if (depth === 0) break;
          }
        }
        i = j;
      } else if (/^[0-9]+$/.test(tokens[i + 1] ?? '')) {
        i += 1;
      }
      // `align 4` is written after a comma on a load or a store.
      while (out.length > 0 && out[out.length - 1] === ',') out.pop();
      continue;
    }

    out.push(t);
  }

  // A dangling comma can be left behind by a dropped trailing operand.
  while (out.length > 0 && out[out.length - 1] === ',') out.pop();
  if (out.length === 0) {
    notes.push('an instruction normalised away to nothing');
    return null;
  }
  return out;
}

/** Index just past a metadata operand starting at `i` (`!12`, or `!DIx(...)`). */
function skipMetadataOperand(tokens, i) {
  if (i >= tokens.length) return i;
  if (isMetaRef(tokens[i]) || tokens[i] === '!') {
    let j = i + 1;
    if (tokens[i] === '!' && tokens[j] === '{') {
      let depth = 0;
      for (; j < tokens.length; j += 1) {
        if (tokens[j] === '{') depth += 1;
        else if (tokens[j] === '}') {
          depth -= 1;
          if (depth === 0) return j + 1;
        }
      }
    }
    return j;
  }
  if (isMetaName(tokens[i])) {
    let j = i + 1;
    if (tokens[j] === '(') {
      let depth = 0;
      for (; j < tokens.length; j += 1) {
        if (tokens[j] === '(') depth += 1;
        else if (tokens[j] === ')') {
          depth -= 1;
          if (depth === 0) return j + 1;
        }
      }
    }
    return j;
  }
  return i;
}

/** Apply the token rewrite to every instruction of a function, in place. */
export function rewriteFunction(fn, on, notes) {
  for (const b of fn.blocks) {
    const kept = [];
    for (const inst of b.insts) {
      const t = rewriteTokens(inst.tokens, on, notes);
      if (t === null) continue;
      kept.push({ ...inst, tokens: t });
    }
    b.insts = kept;
  }
  return fn;
}

export { labelOperandIndices, isLocal };

// Structural layer: LLVM textual IR -> functions -> blocks -> instructions.
//
// Only as much of the grammar as the fingerprint needs is parsed. Anything the
// parser does not understand is kept as raw tokens and recorded in `notes`, so
// that a fingerprint computed over something half-understood says so instead of
// quietly hashing a shrug.

import { isLocal, tokenize, bareName, stripComment } from './tokens.mjs';

/** Terminators, for splitting a body into blocks and for finding successors. */
export const TERMINATORS = new Set([
  'ret', 'br', 'switch', 'indirectbr', 'invoke', 'callbr', 'resume',
  'catchswitch', 'catchret', 'cleanupret', 'unreachable',
]);

function mkInst(result, tokens, raw) {
  return { result, tokens, raw, origins: [] };
}

/** Split a parameter list's token run on top-level commas. */
function splitTopLevel(tokens) {
  const groups = [];
  let cur = [];
  let depth = 0;
  for (const t of tokens) {
    if (t === '(' || t === '[' || t === '{' || t === '<') depth += 1;
    else if (t === ')' || t === ']' || t === '}' || t === '>') depth -= 1;
    if (t === ',' && depth === 0) {
      groups.push(cur);
      cur = [];
      continue;
    }
    cur.push(t);
  }
  if (cur.length > 0) groups.push(cur);
  return groups;
}

/** Keywords that decorate a definition without changing what it computes. */
const DEFINITION_DECORATION = new Set([
  'private', 'internal', 'available_externally', 'linkonce', 'weak', 'common',
  'appending', 'extern_weak', 'linkonce_odr', 'weak_odr', 'external',
  'default', 'hidden', 'protected',
  'dllimport', 'dllexport',
  'dso_local', 'dso_preemptable',
  'ccc', 'fastcc', 'coldcc', 'tailcc', 'swiftcc', 'swifttailcc', 'cfguard_checkcc',
  'anyregcc', 'preserve_mostcc', 'preserve_allcc', 'ghccc', 'cxx_fast_tlscc',
]);

/** Parameter and return attributes: not part of the shape of a property. */
const PARAM_ATTRS = new Set([
  'noundef', 'nonnull', 'nocapture', 'readonly', 'writeonly', 'readnone',
  'nofree', 'willreturn', 'returned', 'inreg', 'signext', 'zeroext', 'immarg',
  'noalias', 'nest', 'nosync', 'noext', 'allocptr', 'allocalign', 'writable',
  'dead_on_unwind', 'initializes',
]);

/** Attributes that carry an argument in parentheses. */
const PARAM_ATTRS_WITH_ARG = new Set([
  'dereferenceable', 'dereferenceable_or_null', 'align', 'byval', 'sret',
  'elementtype', 'inalloca', 'preallocated', 'byref', 'alignstack', 'captures',
  'range',
]);

/**
 * Drop parameter attributes from a token run, leaving type and value tokens.
 * Used for reading a definition's signature, not for rendering instructions.
 */
function stripParamAttrs(tokens) {
  const out = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
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
      continue;
    }
    out.push(t);
  }
  return out;
}

function parseDefineHeader(tokens, notes) {
  // define <decoration...> <ret type...> @name ( params ) <trailing...> {
  let i = 1;
  while (i < tokens.length && DEFINITION_DECORATION.has(tokens[i])) i += 1;
  let at = -1;
  for (let j = i; j < tokens.length; j += 1) {
    if (tokens[j][0] === '@' && tokens[j + 1] === '(') {
      at = j;
      break;
    }
  }
  if (at === -1) {
    notes.push('define header without a recognisable @name(');
    return null;
  }
  const retType = stripParamAttrs(tokens.slice(i, at)).join(' ');
  let depth = 0;
  let close = -1;
  for (let j = at + 1; j < tokens.length; j += 1) {
    if (tokens[j] === '(') depth += 1;
    else if (tokens[j] === ')') {
      depth -= 1;
      if (depth === 0) {
        close = j;
        break;
      }
    }
  }
  if (close === -1) {
    notes.push(`define ${tokens[at]}: unterminated parameter list`);
    return null;
  }
  const params = [];
  let varargs = false;
  for (const g of splitTopLevel(tokens.slice(at + 2, close))) {
    if (g.length === 1 && g[0] === '...') {
      varargs = true;
      continue;
    }
    const clean = stripParamAttrs(g);
    const nameIdx = clean.findIndex((t) => isLocal(t));
    const name = nameIdx === -1 ? null : clean[nameIdx];
    const type = (nameIdx === -1 ? clean : clean.slice(0, nameIdx)).join(' ');
    params.push({ type, name });
  }
  return { name: tokens[at], retType, params, varargs };
}

const BLOCK_LABEL_RE = /^([-\w$.]+|"(?:[^"\\]|\\.)*"):/;

/**
 * Assign the labels LLVM leaves implicit.
 *
 * Unnamed values, unnamed blocks and unnamed parameters all draw from one
 * counter, in that textual order. Only the entry block is ever printed without
 * a header, so in practice this recovers exactly one name per function -- but
 * getting it wrong makes `br label %1` dangle, and a dangling successor edge
 * silently changes the block order the whole fingerprint is built on.
 */
function assignImplicitLabels(fn) {
  let counter = 0;
  const bump = (name) => {
    if (name !== null && /^%[0-9]+$/.test(name)) counter = Number(name.slice(1)) + 1;
  };
  for (const p of fn.params) bump(p.name);
  for (const b of fn.blocks) {
    if (b.label === null) {
      b.label = String(counter);
      b.implicit = true;
      counter += 1;
    } else if (/^[0-9]+$/.test(b.label)) {
      counter = Number(b.label) + 1;
    }
    for (const inst of b.insts) bump(inst.result);
  }
}

/**
 * Parse a module. Returns functions with bodies, the set of declared-only
 * symbols, and notes for everything not understood.
 */
export function parseModule(text) {
  const notes = [];
  const functions = [];
  const declares = new Set();
  const lines = text.split(/\r?\n/);

  let i = 0;
  while (i < lines.length) {
    const raw = lines[i];
    const tokens = tokenize(raw);
    if (tokens.length === 0) {
      i += 1;
      continue;
    }
    if (tokens[0] === 'declare') {
      const at = tokens.find((t) => t[0] === '@');
      if (at !== undefined) declares.add(at);
      i += 1;
      continue;
    }
    if (tokens[0] !== 'define') {
      i += 1;
      continue;
    }

    const header = parseDefineHeader(tokens, notes);
    i += 1;
    const bodyLines = [];
    while (i < lines.length && lines[i].trimEnd() !== '}') {
      bodyLines.push(lines[i]);
      i += 1;
    }
    i += 1; // the closing brace
    if (header === null) continue;

    const blocks = [];
    let cur = { label: null, implicit: false, insts: [] };
    for (const bl of bodyLines) {
      const trimmed = stripComment(bl).trim();
      if (trimmed === '') continue;
      const m = BLOCK_LABEL_RE.exec(trimmed);
      if (m !== null) {
        if (cur.insts.length > 0 || cur.label !== null || blocks.length === 0) blocks.push(cur);
        cur = { label: m[1].replace(/^"|"$/g, ''), implicit: false, insts: [] };
        continue;
      }
      const t = tokenize(bl);
      if (t.length === 0) continue;
      if (t[1] === '=' && (isLocal(t[0]) || t[0][0] === '@')) {
        cur.insts.push(mkInst(t[0], t.slice(2), trimmed));
      } else {
        cur.insts.push(mkInst(null, t, trimmed));
      }
    }
    blocks.push(cur);
    // The leading placeholder survives only when the body opened with a label.
    const cleaned = blocks.filter((b, idx) => !(idx === 0 && b.label === null && b.insts.length === 0));

    const fn = {
      name: header.name,
      retType: header.retType,
      params: header.params,
      varargs: header.varargs,
      blocks: cleaned,
      notes: [],
    };
    assignImplicitLabels(fn);
    functions.push(fn);
  }

  const byName = new Map(functions.map((f) => [f.name, f]));
  return { functions, byName, declares, notes };
}

/** Deep copy of a function, so a normalisation never edits the parse. */
export function cloneFunction(fn) {
  return {
    name: fn.name,
    retType: fn.retType,
    params: fn.params.map((p) => ({ ...p })),
    varargs: fn.varargs,
    blocks: fn.blocks.map((b) => ({
      label: b.label,
      implicit: b.implicit,
      insts: b.insts.map((x) => ({
        result: x.result, tokens: x.tokens.slice(), raw: x.raw, origins: x.origins.slice(),
      })),
    })),
    notes: fn.notes.slice(),
  };
}

export { stripParamAttrs, splitTopLevel, bareName, mkInst };

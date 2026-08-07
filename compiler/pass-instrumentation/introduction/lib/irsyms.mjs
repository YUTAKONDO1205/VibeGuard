// Reading an LLVM IR text module: what the front end emitted, and what is
// actually called.
//
// THE ORACLE RULE LIVES HERE. interfaces.md §4: never decide whether an effect
// is present by searching for a symbol name. A call that has been deleted
// leaves `declare void @llvm.memset.p0.i64(...)` behind, and a name search
// keeps reporting it as present until some later pass sweeps the declaration
// away -- which attributes the change to the sweeper instead of to the pass
// that made it.
//
// The mirror of that rule on the introduction side is the same rule: a `declare`
// line is not an external call. An external call is a `call` or `invoke`
// instruction whose callee resolves to a function with no body. `declarations`
// and `callSites` below are therefore separate sets, and nothing in this
// component reads one when it means the other.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

// An LLVM global identifier: either a quoted name, or the unquoted character
// set the language reference allows.
const NAME = String.raw`(?:"(?:[^"\\]|\\.)*"|[-a-zA-Z$._0-9]+)`;

function unquote(raw) {
  if (!raw.startsWith('"')) return raw;
  return raw.slice(1, -1).replace(/\\5C/g, '\\').replace(/\\22/g, '"');
}

const RE_DEFINE = new RegExp(String.raw`^define\b[^@\n]*@(${NAME})\s*\(`, 'gm');
const RE_DECLARE = new RegExp(String.raw`^declare\b[^@\n]*@(${NAME})\s*\(`, 'gm');
const RE_GLOBAL = new RegExp(String.raw`^@(${NAME})\s*=`, 'gm');
const RE_ALIAS = new RegExp(String.raw`^@(${NAME})\s*=[^\n]*\balias\b`, 'gm');

// A call site. The callee is the `@name` immediately followed by the argument
// list, which is what tells it apart from an `@global` passed as an argument:
// `call void %fp(ptr @g)` has no callee name at all, and this pattern does not
// invent one for it.
const RE_CALL = new RegExp(String.raw`\b(?:call|invoke|callbr)\b[^\n]*?@(${NAME})\s*\(`, 'g');

function collect(re, text) {
  const out = [];
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text)) !== null) out.push(unquote(m[1]));
  return out;
}

/**
 * Everything an IR module says about its own symbols.
 *
 * @param {string} text  the contents of a .ll file
 */
export function readIrModule(text) {
  const defines = new Set(collect(RE_DEFINE, text));
  const declarations = new Set(collect(RE_DECLARE, text));
  const globalsAll = collect(RE_GLOBAL, text);
  const aliases = new Set(collect(RE_ALIAS, text));
  const globals = new Set(globalsAll.filter((g) => !aliases.has(g)));

  // Call sites, counted rather than named-and-deduplicated: two calls to the
  // same callee are two call sites, and the count is what the oracle is defined
  // over.
  const callSiteList = collect(RE_CALL, text);
  const callSites = new Map();
  for (const callee of callSiteList) {
    callSites.set(callee, (callSites.get(callee) ?? 0) + 1);
  }

  // An external call is a call site whose callee has no body in this module.
  // A declaration with no call site is not one, which is the whole point.
  const externalCalls = new Map();
  for (const [callee, n] of callSites) {
    if (!defines.has(callee)) externalCalls.set(callee, n);
  }

  return {
    defines, declarations, globals, aliases, callSites, externalCalls,
    /** Every name the front end put in this module -- the measured baseline. */
    all: new Set([...defines, ...declarations, ...globals, ...aliases]),
  };
}

/**
 * The context shape `classifyOrigin` wants, built from a front-end IR dump.
 *
 * `haveFrontEnd` is the flag that keeps an unavailable baseline from being read
 * as a clean one: with no dump, every element that the structural rules do not
 * explain comes back Unresolved, and the run exits 3.
 */
export function frontEndSetFromIr(text) {
  const m = readIrModule(text);
  return {
    functions: new Set([...m.defines, ...m.declarations]),
    globals: m.globals,
    aliases: m.aliases,
  };
}

/**
 * The entries of `@llvm.global_ctors`, which is how the IR spells a static
 * initialiser. Each entry is `{ i32 priority, ptr @fn, ptr @assoc }`.
 */
export function globalCtorTargets(text) {
  const m = /^@llvm\.global_ctors\s*=[^\n]*$/m.exec(text);
  if (!m) return [];
  const out = [];
  const re = new RegExp(String.raw`\{\s*i32\s+(-?\d+)\s*,\s*ptr\s+@(${NAME})`, 'g');
  let e;
  while ((e = re.exec(m[0])) !== null) {
    out.push({ priority: Number(e[1]), target: unquote(e[2]) });
  }
  return out;
}

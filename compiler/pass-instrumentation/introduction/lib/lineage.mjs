// Clone lineage, and the Itanium ABI name shapes the compiler generates.
//
// This is the half of the toolchain baseline that does not need a measurement:
// a name whose *shape* is defined by the C++ ABI, or by LLVM's own naming
// conventions, was produced by the toolchain by construction. It generalises
// where a recorded list of names cannot -- `_ZTVN3app6WidgetE` is a vtable for a
// class nobody had written when these rules were, and the rule still explains
// it.
//
// The suffix stripping mirrors `lineageRoot` in the observer's Oracle.cpp on
// purpose. The two components have to agree on what "the same function, cloned"
// means, or one of them reports a birth where the other reports a survival.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

/**
 * Suffixes an optimiser attaches to a clone of an existing function. `.llvm`
 * and friends may carry a numeric tail (`.llvm.10412843`), which is stripped
 * first as a separate step.
 */
const CLONE_SUFFIXES = [
  'llvm', 'specialized', '__uniq', 'cold', 'constprop', 'part', 'isra',
  'internal', 'clone', 'resolver', 'lto_priv', 'localalias', 'stub',
];

function stripOneSuffix(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot + 1 >= name.length) return null;
  const tail = name.slice(dot + 1);
  if (/^[0-9]+$/.test(tail)) return name.slice(0, dot);
  if (CLONE_SUFFIXES.includes(tail)) return name.slice(0, dot);
  return null;
}

/**
 * The name this one is a clone of, or the name itself when it is not a clone.
 * Bounded, so that a pathological name cannot spin here.
 */
export function lineageRoot(name) {
  let cur = name;
  for (let i = 0; i < 8; i++) {
    const next = stripOneSuffix(cur);
    if (next === null || next === '') break;
    cur = next;
  }
  return cur;
}

/** True when `name` is `root` with one or more optimiser clone suffixes on it. */
export function isCloneOf(name, root) {
  return name !== root && lineageRoot(name) === root;
}

// --- Itanium C++ ABI: entities the compiler generates, by prefix -----------
//
// Each entry is [prefix, what it is]. The order matters only for the
// explanation string; the longest match wins so that `_ZTVN10__cxxabiv1...`
// is reported as a vtable rather than being caught by a shorter prefix.
const ABI_GENERATED = [
  ['_ZTVN10__cxxabiv1', 'ABI runtime class-type-info vtable'],
  ['_ZTV', 'virtual table'],
  ['_ZTT', 'virtual-table table (VTT)'],
  ['_ZTC', 'construction virtual table'],
  ['_ZTI', 'typeinfo object (RTTI)'],
  ['_ZTS', 'typeinfo name (RTTI)'],
  ['_ZThn', 'non-virtual thunk'],
  ['_ZTh', 'non-virtual thunk'],
  ['_ZTvn', 'virtual thunk'],
  ['_ZTv', 'virtual thunk'],
  ['_ZTcv', 'covariant-return thunk'],
  ['_ZTc', 'covariant-return thunk'],
  ['_ZGV', 'guard variable for a function-local static'],
  ['_ZGR', 'lifetime-extended reference temporary'],
  ['_ZTW', 'thread_local wrapper'],
  ['_ZTH', 'thread_local initialiser'],
];

/** Non-null when the name is an entity the C++ ABI tells the compiler to emit. */
export function abiGeneratedKind(name) {
  let best = null;
  for (const [prefix, what] of ABI_GENERATED) {
    if (name.startsWith(prefix) && (best === null || prefix.length > best[0].length)) {
      best = [prefix, what];
    }
  }
  return best ? best[1] : null;
}

/**
 * Static-initialisation machinery. These are the functions the front end
 * synthesises to run dynamic initialisers, and the .init_array entry that calls
 * them. A detector without this rule reports every C++ file with a global
 * object as having an unexplained initialiser.
 */
export function staticInitKind(name) {
  if (name.startsWith('__cxx_global_var_init')) return 'dynamic initialiser for a namespace-scope object';
  if (name.startsWith('__cxx_global_array_dtor')) return 'array destructor helper';
  if (/^_GLOBAL__sub_[ID]_/.test(name)) return 'translation-unit static-initialisation entry';
  if (/^_GLOBAL__[ID]_/.test(name)) return 'translation-unit static-initialisation entry (legacy encoding)';
  if (name === 'frame_dummy' || name === '__do_global_dtors_aux') return 'C runtime start-up helper';
  return null;
}

/**
 * A mangled name that carries template arguments -- the `I ... E` bracket in
 * the Itanium encoding -- is an instantiation the compiler produced rather than
 * a function anyone wrote out.
 *
 * This is a shape test, not a demangle. It is deliberately conservative: it
 * requires the name to be Itanium-mangled and to contain a template-argument
 * bracket that is not inside the substitution encoding. False negatives here
 * cost precision (something legitimate stays unexplained and gets reported,
 * which is the safe direction); false positives would cost the whole check.
 */
export function looksLikeTemplateInstantiation(name) {
  if (!name.startsWith('_Z')) return false;
  // `I` opening a template-argument list always follows a length-prefixed
  // identifier or an operator/ctor code, and the list is closed by `E`.
  return /[a-zA-Z0-9_]I[A-Za-z_0-9]/.test(name) && name.includes('E');
}

/**
 * A lambda's call operator, in either of the two encodings clang emits: the
 * standard `Ul...E_` closure-type encoding, and the `$_N` form it uses for
 * closures in a local scope.
 */
export function looksLikeLambda(name) {
  return /Ul.*E_/.test(name) || /\$_\d/.test(name);
}

/** An assembler-local temporary: string literals, constant pools, block labels. */
export function isAssemblerTemporary(name) {
  return name.startsWith('.L') || name.startsWith('.LC') || name.startsWith('L..');
}

/**
 * `.L.str.3` in the object is `.str.3` in the IR: the code generator prefixes
 * private globals with the target's private-label prefix. Mapping it back is
 * what lets a private string constant be matched against the front-end set
 * instead of looking like something codegen invented.
 */
export function stripPrivatePrefix(name) {
  return name.startsWith('.L') ? name.slice(2) : name;
}

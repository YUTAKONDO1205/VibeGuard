// The origin taxonomy, and the rules that assign one.
//
// THE PROBLEM THIS SOLVES. Compiling one small C++ file produces about a
// hundred and fifty symbols that the source never names: vtables, typeinfo,
// typeinfo names, VTTs, construction vtables, seven virtual thunks, a guard
// variable, a lambda call operator, sixty template instantiations, unwind
// tables, a personality reference, string literals, and calls into the runtime.
// Measured on this component's own negative fixture, at -O0, with
// clang++-18 -std=c++17: 152 defined-or-referenced symbols, of which the source
// names exactly three.
//
// A detector that reports "something appeared that the source did not ask for"
// therefore reports a hundred and forty-nine things on a file that is entirely
// normal, on every build, for ever. It is not a noisy detector, it is a broken
// one -- so the toolchain baseline is not a refinement to add later. It is the
// component, and the detector is the small part that runs after it.
//
// HOW THE BASELINE IS BUILT. Two halves, and both are needed:
//
//   1. MEASURED. The front end is asked what it produced from this exact
//      compilation -- same compiler, same flags, same source -- by running it
//      again with the optimisation pipeline disabled and the IR dumped. Every
//      symbol in that dump is something the front end emitted, which is a fact
//      about this build rather than a guess about builds in general.
//
//   2. STRUCTURAL. Names whose shape the C++ ABI or LLVM defines: `_ZTV` is a
//      vtable whether or not this build happened to contain one. This is what
//      covers the things that appear only after the front end -- codegen's
//      unwind tables, the optimiser's clones, the assembler's temporaries --
//      and what makes the rules generalise to classes nobody had written when
//      they were written.
//
// Neither half alone is enough. Measurement alone cannot explain a `.cold`
// clone that no earlier stage contained; shape alone cannot explain
// `intro_negative_main`, which is just a name.
//
// WHAT IS DELIBERATELY NOT DONE. There is no per-fixture exception list and no
// "known noisy symbol" set. If the negative fixture produces an Unexplained
// element, the rules are wrong and the rules get fixed. An exception list would
// make the fixture pass while leaving the detector exactly as broken, and would
// hide that fact behind a green tick.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import {
  abiGeneratedKind, isAssemblerTemporary, lineageRoot, looksLikeLambda,
  looksLikeTemplateInstantiation, staticInitKind, stripPrivatePrefix,
} from './lineage.mjs';

/**
 * The six permitted origins. An element with one of these is Explained; an
 * element with none is Unexplained; an element whose origin cannot be decided
 * because the evidence needed to decide it was not collected is Unresolved,
 * which is exit 3 and not exit 0.
 */
export const ORIGINS = [
  'source-derived',
  'generator-derived',
  'dependency-derived',
  'toolchain-derived',
  'linker-generated',
  'runtime-support',
];

export const VERDICTS = ['Explained', 'Unexplained', 'Unresolved'];

// --- linker-generated ------------------------------------------------------
// Symbols the link editor defines itself. None of them can appear in any input
// object, which is why they need a rule of their own: the front-end set will
// never contain them and every other rule would leave them unexplained.
const LINKER_SYMBOLS = new Set([
  '_init', '_fini', '_start', '__libc_csu_init', '__libc_csu_fini',
  '_dl_relocate_static_pie', '__bss_start', '_edata', '_end', '__end__',
  '__data_start', 'data_start', '_GLOBAL_OFFSET_TABLE_', '_DYNAMIC',
  '_PROCEDURE_LINKAGE_TABLE_', '__TMC_END__', '__ehdr_start',
  '__rela_iplt_start', '__rela_iplt_end',
  '__init_array_start', '__init_array_end',
  '__fini_array_start', '__fini_array_end',
  '__preinit_array_start', '__preinit_array_end',
  '__executable_start', '__etext', '_etext', '__exidx_start', '__exidx_end',
]);

// --- runtime-support -------------------------------------------------------
// Entry points into a runtime library that the compiler emits references to
// without the source naming them. Split by family so that the explanation says
// which runtime, rather than "a list said so".
const RUNTIME_PREFIXES = [
  ['__cxa_', 'Itanium C++ ABI runtime'],
  ['_Unwind_', 'the unwinder'],
  ['__gxx_personality', 'the C++ personality routine'],
  ['__gcc_personality', 'the C personality routine'],
  ['__stack_chk_', 'the stack-protector runtime'],
  ['__asan_', 'AddressSanitizer runtime'],
  ['__hwasan_', 'HWAddressSanitizer runtime'],
  ['__msan_', 'MemorySanitizer runtime'],
  ['__tsan_', 'ThreadSanitizer runtime'],
  ['__ubsan_', 'UndefinedBehaviorSanitizer runtime'],
  ['__sanitizer_', 'a sanitizer runtime'],
  ['__sancov', 'SanitizerCoverage'],
  ['__llvm_prf_', 'the instrumented-profiling runtime'],
  ['__llvm_gcov', 'the gcov-compatible profiling runtime'],
  ['__llvm_profile_', 'the instrumented-profiling runtime'],
  ['__profc_', 'the instrumented-profiling runtime'],
  ['__profd_', 'the instrumented-profiling runtime'],
  ['__profn_', 'the instrumented-profiling runtime'],
  ['_ITM_', 'the transactional-memory runtime'],
  ['llvm.', 'an LLVM intrinsic'],
];

const RUNTIME_SYMBOLS = new Set([
  // Itanium ABI entry points that do not carry the __cxa_ prefix
  '__dynamic_cast', '__cxa_pure_virtual', '__clang_call_terminate',
  '__cxa_deleted_virtual',
  // operator new / delete, in the mangled forms libsupc++ exports
  '_Znwm', '_Znam', '_ZdlPv', '_ZdaPv', '_ZdlPvm', '_ZdaPvm',
  '_ZnwmSt11align_val_t', '_ZnamSt11align_val_t',
  '_ZdlPvSt11align_val_t', '_ZdaPvSt11align_val_t',
  '_ZdlPvmSt11align_val_t', '_ZdaPvmSt11align_val_t',
  '_ZnwmRKSt9nothrow_t', '_ZnamRKSt9nothrow_t',
  // C runtime start-up
  '__dso_handle', '__libc_start_main', 'atexit', '__gmon_start__',
  'register_tm_clones', 'deregister_tm_clones',
  // The libcalls LLVM materialises from IR that names no function at all:
  // an intrinsic, a struct copy, a comparison, or an integer operation the
  // target cannot do in one instruction. There is no source line to attribute
  // these to, which is the whole reason they need a rule.
  'memcpy', 'memmove', 'memset', 'memcmp', 'bcmp', 'mempcpy', 'memset_pattern16',
  'strlen', 'strcpy', 'strncpy', 'strcmp', 'strncmp', 'strcat', 'strncat',
  '__memcpy_chk', '__memmove_chk', '__memset_chk', '__strcpy_chk',
  'abort', '__assert_fail', 'raise', 'trap',
  'setjmp', 'longjmp', '_setjmp', 'sigsetjmp',
]);

// compiler-rt integer/float helpers: `__udivti3`, `__muloti4`, `__adddf3`,
// `__fixunsdfdi`, `__atomic_load_8`, `__sync_fetch_and_add_4` ... The shape is
// regular enough to match rather than enumerate, and enumerating it would go
// stale the first time a target needed one that is not on the list.
const COMPILER_RT_SHAPE = /^__(?:[a-z]{2,}[a-z0-9]*[a-z]i[0-9]|atomic_|sync_|emutls_|multi3|divti3|udivti3|modti3|umodti3|muloti4|clzti2|ctzti2|ffsti2|popcountti2|fixunsdfti|floatuntidf|extendhfsf2|truncdfhf2|cpu_(?:model|indicator_init)|chkstk|alloca)/;

// --- toolchain-derived: codegen artefacts ----------------------------------
const CODEGEN_SYMBOL_SHAPES = [
  [/^GCC_except_table\d*$/, 'a language-specific unwind table emitted by the code generator'],
  [/^DW\.ref\./, "a code generator's indirect reference to the personality routine"],
  [/^__EH_FRAME_BEGIN__$/, 'the start of this object\'s unwind tables'],
  [/^asan\.module_(?:ctor|dtor)$/, "AddressSanitizer's per-module initialiser"],
  [/^tsan\.module_ctor$/, "ThreadSanitizer's per-module initialiser"],
  [/^sancov\./, 'SanitizerCoverage instrumentation state'],
  [/^__x86_indirect_thunk/, 'a retpoline thunk emitted for a mitigation flag'],
  [/^__llvm_retpoline/, 'a retpoline thunk emitted for a mitigation flag'],
  [/^__llvm_slsblr_thunk/, 'a straight-line-speculation thunk emitted for a mitigation flag'],
  [/^__cfi_check/, 'a control-flow-integrity check emitted for a mitigation flag'],
  [/^__typeid_/, 'a control-flow-integrity type identifier'],
  [/^__morestack/, 'the split-stack runtime hook'],
  [/^__unnamed_\d+$/, 'an unnamed private constant'],
  [/^__const\./, 'a private constant lifted out of a function body'],
  [/^switch\.table\./, 'a switch lookup table built by the optimiser'],
  [/^__func__\./, 'the implicit __func__ string'],
  [/^OUTLINED_FUNCTION_\d+$/, 'a fragment the machine outliner shared between call sites'],
];

// --- dependency-derived ----------------------------------------------------
// Namespaces the C++ standard reserves to the implementation. A symbol mangled
// into one of them is provided by, or instantiated from, the standard library,
// which is a dependency of every C++ translation unit whether the build system
// declares it or not.
const RESERVED_NAMESPACE_SHAPES = [
  [/^_ZNSt/, 'std'], [/^_ZNKSt/, 'std'], [/^_ZSt/, 'std'], [/^_ZNVSt/, 'std'],
  [/^_ZTVSt/, 'std'], [/^_ZTISt/, 'std'], [/^_ZTSSt/, 'std'],
  [/^_ZN9__gnu_cxx/, '__gnu_cxx'], [/^_ZNK9__gnu_cxx/, '__gnu_cxx'],
  [/^_ZN10__cxxabiv1/, '__cxxabiv1'], [/^_ZTVN10__cxxabiv1/, '__cxxabiv1'],
  [/^_ZN11__gnu_debug/, '__gnu_debug'],
  [/^_ZNSa/, 'std'], [/^_ZNKSa/, 'std'],
  [/^_ZNSs/, 'std'], [/^_ZNKSs/, 'std'],
  [/^_ZNSi/, 'std'], [/^_ZNSo/, 'std'], [/^_ZNKSo/, 'std'],
];

function reservedNamespace(name) {
  for (const [re, ns] of RESERVED_NAMESPACE_SHAPES) if (re.test(name)) return ns;
  return null;
}

/**
 * @typedef {object} OriginContext
 * @property {{functions: Set<string>, globals: Set<string>, aliases: Set<string>}} frontEnd
 *   Every name the front end emitted for this compilation. The measured half of
 *   the baseline.
 * @property {boolean} haveFrontEnd
 *   False when the front-end dump could not be produced. Everything the other
 *   rules do not explain is then Unresolved rather than Unexplained, because
 *   without this set the question has not been asked.
 * @property {Map<string, string>} dependencyExports  symbol -> dependency name
 * @property {boolean} haveDependencyExports
 * @property {(name: string) => (string | null)} sourceFileOf
 *   The source file an element came from, when debug information said so.
 * @property {string[]} generatedSourceGlobs
 * @property {boolean} haveSourceAttribution
 */

/** Empty context, used by callers that only want the structural half. */
export function emptyContext(overrides = {}) {
  return {
    frontEnd: { functions: new Set(), globals: new Set(), aliases: new Set() },
    haveFrontEnd: false,
    dependencyExports: new Map(),
    haveDependencyExports: false,
    sourceFileOf: () => null,
    generatedSourceGlobs: [],
    haveSourceAttribution: false,
    ...overrides,
  };
}

function inFrontEnd(ctx, name) {
  const fe = ctx.frontEnd;
  if (fe.functions.has(name) || fe.globals.has(name) || fe.aliases.has(name)) return true;
  // The code generator prefixes private globals with the target's private-label
  // prefix, so `.L.str.3` in the object is `.str.3` in the IR.
  const bare = stripPrivatePrefix(name);
  return bare !== name && (fe.functions.has(bare) || fe.globals.has(bare));
}

/**
 * A path glob as a regular expression.
 *
 * `**` has to be protected from the `*` rule that runs after it, so it is parked
 * on a placeholder first. The placeholder is a name, not a punctuation character
 * typed into the middle of the chain: the first version of this function used a
 * raw control byte, which is invisible in an editor, makes the whole file read as
 * binary to every text tool, and survived review for exactly that reason. It was
 * found by a grep for an ordinary identifier coming back "Binary file matches".
 */
const GLOB_STAR = '\u0000GLOBSTAR\u0000';

function globToRegExp(glob) {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .split('**').join(GLOB_STAR)
    .replace(/\*/g, '[^/]*')
    .split(GLOB_STAR).join('.*')
    .replace(/\?/g, '[^/]');
  return new RegExp(`^${escaped}$`);
}

function explained(origin, rule, reason) {
  return { origin, verdict: 'Explained', rule, reason };
}

/**
 * Decide where one element came from.
 *
 * The order of the rules is part of the contract. Structural rules run before
 * the measured front-end set, because the front-end set contains the ABI
 * entities too and would report a vtable as source-derived -- true in the sense
 * that the class was in the source, and useless as an origin, because the
 * question this component asks is *who put this here*, and for a vtable the
 * answer is the compiler.
 *
 * @param {{kind: string, name: string, defined?: boolean, section?: string}} element
 * @param {OriginContext} ctx
 */
export function classifyOrigin(element, ctx) {
  const name = element.name;
  const defined = element.defined !== false;

  // R1 linker-generated -----------------------------------------------------
  if (LINKER_SYMBOLS.has(name)) {
    return explained('linker-generated', 'R1.linker-symbol',
      'the link editor defines this symbol itself; no input object can contain it');
  }
  if (name.endsWith('@plt') || name.endsWith('@PLT')) {
    return explained('linker-generated', 'R1.plt-stub',
      'a procedure-linkage-table stub synthesised at link time');
  }

  // R2 runtime-support ------------------------------------------------------
  for (const [prefix, what] of RUNTIME_PREFIXES) {
    if (name.startsWith(prefix)) {
      return explained('runtime-support', 'R2.runtime-prefix', `an entry point of ${what}`);
    }
  }
  if (RUNTIME_SYMBOLS.has(name)) {
    return explained('runtime-support', 'R2.runtime-symbol',
      'a runtime entry point the compiler references without the source naming it');
  }
  if (COMPILER_RT_SHAPE.test(name)) {
    return explained('runtime-support', 'R2.compiler-rt',
      'a compiler-runtime helper materialised for an operation the target cannot do inline');
  }

  // R3 toolchain-derived ----------------------------------------------------
  const abi = abiGeneratedKind(name);
  if (abi) {
    return explained('toolchain-derived', 'R3.abi-entity',
      `${abi}: the C++ ABI requires the compiler to emit this`);
  }
  const init = staticInitKind(name);
  if (init) {
    return explained('toolchain-derived', 'R3.static-init', init);
  }
  for (const [re, what] of CODEGEN_SYMBOL_SHAPES) {
    if (re.test(name)) return explained('toolchain-derived', 'R3.codegen', what);
  }
  if (isAssemblerTemporary(name)) {
    // `.L.str.3` in the object is `.str.3` in the IR. Saying so is worth a rule
    // of its own: without it the element is still Explained, but by the clone
    // rule, and the run then reports `.L.str.3` as "a clone the optimiser made
    // of .L.str" -- a true-looking sentence about something that never
    // happened. Measured on the negative fixture at -O0: six elements took that
    // path before this rule existed.
    const bare = stripPrivatePrefix(name);
    if (bare !== name && ctx.haveFrontEnd && inFrontEnd(ctx, bare)) {
      return explained('toolchain-derived', 'R3.private-label',
        `${bare}, carrying the target's private-label prefix that the code generator adds`);
    }
    return explained('toolchain-derived', 'R3.assembler-temporary',
      'an assembler-local label: a string literal, constant pool entry or block label');
  }
  // A clone of something the front end emitted is the optimiser's work.
  const root = lineageRoot(name);
  if (root !== name && ctx.haveFrontEnd && inFrontEnd(ctx, root)) {
    return explained('toolchain-derived', 'R3.optimiser-clone',
      `a clone the optimiser made of ${root}`);
  }
  if (defined && looksLikeTemplateInstantiation(name)) {
    return explained('toolchain-derived', 'R3.template-instantiation',
      'a template instantiation: the compiler generated this body from a template');
  }
  if (defined && looksLikeLambda(name)) {
    return explained('toolchain-derived', 'R3.lambda',
      "a lambda's call operator, emitted for a closure type the source never named");
  }

  // R4 dependency-derived ---------------------------------------------------
  const ns = reservedNamespace(name);
  if (ns) {
    return explained('dependency-derived', 'R4.reserved-namespace',
      `mangled into namespace ${ns}, which the standard reserves to the implementation`);
  }
  if (ctx.dependencyExports.has(name)) {
    return explained('dependency-derived', 'R4.declared-dependency',
      `exported by the declared dependency ${ctx.dependencyExports.get(name)}`);
  }

  // R5 generator-derived ----------------------------------------------------
  if (ctx.generatedSourceGlobs.length > 0) {
    const file = ctx.sourceFileOf(name);
    if (file) {
      for (const glob of ctx.generatedSourceGlobs) {
        if (globToRegExp(glob).test(file)) {
          return explained('generator-derived', 'R5.generated-source',
            `defined in ${file}, which the policy lists as generated`);
        }
      }
    } else if (!ctx.haveSourceAttribution) {
      // The policy says some sources are machine-written, and we cannot tell
      // which file this came from. Guessing either way would be a lie, so the
      // element is Unresolved and the run is INCOMPLETE.
      if (!inFrontEnd(ctx, name)) {
        return {
          origin: null,
          verdict: 'Unresolved',
          rule: 'R5.no-source-attribution',
          reason: 'the policy declares generated sources, but this build carried no '
            + 'source attribution (no debug information), so whether this element came '
            + 'from a generated file could not be decided',
        };
      }
    }
  }

  // R6 source-derived -------------------------------------------------------
  if (!ctx.haveFrontEnd) {
    return {
      origin: null,
      verdict: 'Unresolved',
      rule: 'R6.no-baseline',
      reason: 'the front-end dump for this compilation was not produced, so there is no '
        + 'measured baseline to subtract and no rule can say whether the source '
        + 'accounts for this element',
    };
  }
  if (inFrontEnd(ctx, name)) {
    return explained('source-derived', 'R6.front-end-set',
      'the front end emitted this name from the translation unit');
  }

  return {
    origin: null,
    verdict: 'Unexplained',
    rule: 'R7.none',
    reason: 'no permitted origin accounts for this element: it is not in the front-end '
      + 'output for this compilation, its name matches no ABI, runtime, codegen or '
      + 'linker shape, and no declared dependency exports it',
  };
}

/** Tally verdicts over a list of classified elements. */
export function summariseVerdicts(classified) {
  const out = { Explained: 0, Unexplained: 0, Unresolved: 0 };
  const byOrigin = Object.fromEntries(ORIGINS.map((o) => [o, 0]));
  for (const c of classified) {
    out[c.verdict] = (out[c.verdict] ?? 0) + 1;
    if (c.origin) byOrigin[c.origin] += 1;
  }
  return { verdicts: out, byOrigin };
}

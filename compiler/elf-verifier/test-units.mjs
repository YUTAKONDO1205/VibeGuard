#!/usr/bin/env node
// Unit checks for the two pieces that decide the most and are the easiest to
// get quietly wrong: the mangled-name component scanner, and the canonical
// record rules.
//
// The mangled-name cases are not invented. Every string here was read out of a
// real control artefact, and the `_ZN5ShapeD2Ev` row is the one that mattered:
// reading the `2` in the destructor encoding as a length prefix yielded the
// component `Ev`, which appears in no source file, and turned twenty-six
// correct constructors and destructors into VG-INTRO-001 findings.
//
//   node test-units.mjs      exit 0 if every case holds

import { readFileSync } from 'node:fs';
import { mangledComponents, readName, readSectionName, stripOptimiserSuffix, stripVersion } from './lib/names.mjs';
import { canonicalBytes, evidenceDigest, seal } from './lib/canonical.mjs';
import { DT, SHF, SHN, SHT, STB, STT } from './lib/elf.mjs';
import { classifyArtifact } from './lib/origins.mjs';

let failed = 0;
function check(what, got, want) {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g === w) {
    console.log(`ok    ${what}`);
  } else {
    failed++;
    console.log(`FAIL  ${what}\n        want ${w}\n        got  ${g}`);
  }
}

// ---- mangled-name components ----------------------------------------------
const COMPONENT_CASES = [
  ['_ZN5ShapeD2Ev', ['Shape']], // base-object destructor: D2 is not a length
  ['_ZN6SquareC2Ei', ['Square']], // base-object constructor
  ['_ZN1DC1Ev', ['D']], // one-character class, complete-object constructor
  ['_ZNK3BoxIiE5twiceEv', ['Box', 'twice']],
  ['_Z7combineIiET_S0_S0_', ['combine']],
  ['_ZThn8_N1C1bEv', ['C', 'b']], // thunk offset stripped before scanning
  ['_ZTv0_n24_N1LD1Ev', ['L']],
  ['_ZTv0_n32_N1D1vEv', ['D', 'v']],
  ['_ZTC1D0_1L', ['D', 'L']],
  ['_ZTV6Square', ['Square']],
  ['_ZTS5Shape', ['Shape']],
  ['_ZZ4mainENK3$_0clEi', ['main', '$_0']], // clang closure spelling
  ['_ZZ4mainEN3$_08__invokeEi', ['main', '$_0', '__invoke']],
  ['_Z3runIZ4mainE3$_1EiT_i', ['run', 'main', '$_1']],
  ['_ZGVZ7countervE1c', ['counter', 'c']],
  ['_ZZ7countervE1c', ['counter', 'c']],
  ['_ZL3g_a', ['g_a']],
  ['_ZNKSt9type_info4nameEv', ['type_info', 'name']],
  ['_ZTVN10__cxxabiv120__si_class_type_infoE', ['__cxxabiv1', '__si_class_type_info']],
];
for (const [mangled, want] of COMPONENT_CASES) {
  const info = readName(mangled);
  const rest = info.mangled ? info.components : mangledComponents(mangled);
  check(`components ${mangled}`, rest, want);
}

// A class genuinely named `C1` must still be read as a name, not as a
// constructor encoding: the digit branch runs first because the length prefix
// comes first in the grammar.
check('components _ZN2C13fooEv', mangledComponents('_ZN2C13fooEv'), ['C1', 'foo']);

// ---- name kinds ------------------------------------------------------------
check('kind _ZTV6Square', readName('_ZTV6Square').kind, 'vtable');
check('kind _ZThn8_N1C1bEv', readName('_ZThn8_N1C1bEv').kind, 'thunk-non-virtual');
check('kind _ZTv0_n24_N1LD1Ev', readName('_ZTv0_n24_N1LD1Ev').kind, 'thunk-virtual');
check('kind _ZGVZ7countervE1c', readName('_ZGVZ7countervE1c').kind, 'guard-variable');
check('kind _GLOBAL__sub_I_x.cc', readName('_GLOBAL__sub_I_x.cc').kind, 'static-init-ctor');
check('unit _GLOBAL__sub_I_x.cc', readName('_GLOBAL__sub_I_x.cc').originFile, 'x.cc');
check('kind __cxx_global_var_init.1', readName('__cxx_global_var_init.1').kind, 'static-init-var');
check('kind asan.module_ctor', readName('asan.module_ctor').kind, 'sanitizer-module-init');
check('kind __odr_asan_gen_global_buf', readName('__odr_asan_gen_global_buf').references, 'global_buf');
check('kind __start_asan_globals', readName('__start_asan_globals').encapsulates, 'asan_globals');
check('kind DW.ref.__gxx_personality_v0', readName('DW.ref.__gxx_personality_v0').references, '__gxx_personality_v0');
check('kind main', readName('main').mangled, false);
check('closure _ZZ4mainENK3$_0clEi', readName('_ZZ4mainENK3$_0clEi').hasClosure, true);
check('closure _ZN5ShapeD2Ev', readName('_ZN5ShapeD2Ev').hasClosure, false);

// ---- suffix and version stripping -----------------------------------------
check('strip .llvm.N', stripOptimiserSuffix('helper.llvm.12345').base, 'helper');
check('strip .cold', stripOptimiserSuffix('main.cold').base, 'main');
check('strip .1', stripOptimiserSuffix('__cxx_global_var_init.1').base, '__cxx_global_var_init');
check('strip version', stripVersion('__cxa_finalize@GLIBC_2.2.5').base, '__cxa_finalize');

// ---- section grammar -------------------------------------------------------
check('section .text', readSectionName('.text').kind, 'abi-section');
check('section .data.rel.ro', readSectionName('.data.rel.ro').kind, 'abi-section');
check('section .gcc_except_table', readSectionName('.gcc_except_table').kind, 'abi-section');
check('section .rela.plt', readSectionName('.rela.plt').kind, 'relocation-section');
check('section .text._Z1fv', readSectionName('.text._Z1fv').kind, 'abi-section-with-suffix');
check('section asan_globals', readSectionName('asan_globals').kind, 'sanitizer-section');
check('section .injected_exec', readSectionName('.injected_exec').kind, 'unknown');
check('section .marker_pass', readSectionName('.marker_pass').kind, 'unknown');

// ---- canonical records -----------------------------------------------------
check(
  'canonical drops context and evidenceDigest at the top level only',
  canonicalBytes({ b: 1, a: 2, context: { x: 1 }, evidenceDigest: 'z', inner: { context: { keep: 1 } } }).toString(),
  '{"a":2,"b":1,"inner":{"context":{"keep":1}}}',
);
check('canonical sorts keys inside arrays of objects', canonicalBytes({ a: [{ z: 1, y: 2 }] }).toString(), '{"a":[{"y":2,"z":1}]}');
check('canonical keeps array order', canonicalBytes({ a: [3, 1, 2] }).toString(), '{"a":[3,1,2]}');
{
  let threw = null;
  try {
    canonicalBytes({ ratio: 0.75 });
  } catch (e) {
    threw = e.message.slice(0, 24);
  }
  check('canonical refuses a non-integer number', threw, 'non-integer number at $.');
}
{
  const a = seal({ x: 1, context: { generatedAt: 'A' } });
  const b = seal({ x: 1, context: { generatedAt: 'B' } });
  check('evidenceDigest ignores context', a.evidenceDigest === b.evidenceDigest, true);
  check('evidenceDigest is 64 lowercase hex', /^[0-9a-f]{64}$/.test(a.evidenceDigest), true);
  check('sealing is idempotent under re-digest', evidenceDigest(a) === a.evidenceDigest, true);
}

// ── The shared vectors ──────────────────────────────────────────────────────
//
// There are four canonicalisers in this directory and, until this ran, exactly
// one of them was checked against the vectors. This one agreed with the
// reference on all 22 valid records and disagreed on three of the eight it is
// supposed to refuse -- which means a record written here could be rejected as
// malformed by the verifier next door, with nothing wrong with the measurement.
// Agreeing about what is valid is half of agreeing.
{
  const vectorsPath = new URL('../evidence/testdata/digest-vectors.json', import.meta.url);
  const v = JSON.parse(readFileSync(vectorsPath, 'utf8'));
  let agree = 0;
  const disagreed = [];
  for (const t of v.vectors ?? []) {
    let mine;
    try {
      mine = canonicalBytes(t.input).toString('utf8');
    } catch (e) {
      disagreed.push(`${t.name}: threw ${e.message.slice(0, 40)}`);
      continue;
    }
    if (mine === t.canonicalText) agree += 1;
    else disagreed.push(`${t.name}: ${mine.slice(0, 50)}`);
  }
  check(`shared vectors: all ${(v.vectors ?? []).length} canonicalise identically`,
    disagreed.length === 0 ? true : disagreed.join(' | '), true);
  check('shared vectors: every valid one was actually read',
    agree === (v.vectors ?? []).length && agree > 0, true);

  const accepted = [];
  for (const t of v.mustFail ?? []) {
    try {
      canonicalBytes(t.input);
      accepted.push(t.name);
    } catch {
      /* refused, as required */
    }
  }
  check('shared vectors: every must-fail input is refused here too',
    accepted.length === 0 ? true : `accepted: ${accepted.join(', ')}`, true);
}

// ---- origin classification -------------------------------------------------
//
// WHY THESE EXIST. `classifyArtifact` decides, for every symbol and section in
// an artefact, which permitted origin accounts for it — and until these cases
// were written nothing tested it. The two files this harness did cover are the
// two it names at the top; origins.mjs was reachable only through classify.mjs,
// which needs a real linked binary from artefact-fixtures.sh, so on any machine
// without the toolchain it was checked by nothing at all.
//
// The artefact is synthetic on purpose. `definedSymbols`, `undefinedSymbols`,
// `readInitArrays` and `neededLibraries` all read plain fields, so a literal is
// a faithful stand-in for a parsed ELF and lets each rule be aimed at directly.
// What is asserted is the VERDICT and the RULE that produced it, not the prose:
// the three-way matched / did-not-match / could-not-run distinction is the one
// thing this component must never collapse, and it is the thing a refactor is
// most likely to collapse silently.

const sym = (name, over = {}) => ({
  name, st_shndx: 1, st_value: 0, type: STT.FUNC, bind: STB.GLOBAL, ...over,
});
const sec = (index, name, over = {}) => ({
  index, name, sh_flags: SHF.ALLOC, sh_type: SHT.PROGBITS, sh_size: 8, ...over,
});

/** A parsed-artefact stand-in. Every field `classifyArtifact` reads, and no more. */
function artefact({ symtab = [], sections = [], dynamic = [], buf = Buffer.alloc(0) } = {}) {
  return {
    symtab,
    dynsym: [],
    dynamic,
    relocations: [],
    buf,
    sections: [sec(0, ''), ...sections],
    ehdr: { e_type: 2 }, // ET_EXEC: init-array slots carry addresses, not relocations
  };
}

/** An empty baseline that MATCHED — so the baseline rules run and find nothing. */
const EMPTY_BASELINE = { defined: [], undefined: [], sections: [], initArrays: [] };

/** The `a` argument, with everything unavailable unless a case supplies it. */
function inputs(over = {}) {
  return {
    elf: artefact(over.elf ?? {}),
    baseline: null,
    baselineState: 'absent',
    source: { available: false, identifiers: new Set(), sourceBasenames: new Set() },
    libs: { available: false, index: new Map(), missing: ['libc.so.6'], allowed: null },
    flags: [],
    ...over,
    ...(over.elf ? { elf: artefact(over.elf) } : {}),
  };
}

/** The verdict and rule for one named item, as `verdict/rule`. */
function verdictOf(items, name, kind = null) {
  const i = items.find((x) => x.name === name && (kind === null || x.kind === kind));
  if (!i) return '(absent)';
  return `${i.verdict}/${i.rule ?? '-'}`;
}

{
  // A measured baseline is the strongest evidence and is consulted first.
  const withBaseline = classifyArtifact(inputs({
    elf: { symtab: [sym('__libc_start_main')], sections: [sec(1, '.text')] },
    baseline: {
      defined: [{ name: '__libc_start_main' }], undefined: [],
      sections: [{ name: '.text' }], initArrays: [],
    },
    baselineState: 'matched',
  }));
  check('origins: a baselined symbol is Explained by the baseline',
    verdictOf(withBaseline.items, '__libc_start_main'), 'Explained/baseline-literal');
  check('origins: a baselined section is Explained by the baseline',
    verdictOf(withBaseline.items, '.text'), 'Explained/baseline-literal');
}

{
  // No baseline: the baseline rules must report could-not-run, which makes an
  // otherwise unmatched item Unresolved. Reporting Unexplained here is the
  // false-positive direction of the collapse this component is written against.
  const noBaseline = classifyArtifact(inputs({
    elf: { symtab: [sym('mystery_symbol')], sections: [sec(1, '.text')] },
  }));
  check('origins: with nothing measured, an unmatched symbol is Unresolved, not Unexplained',
    verdictOf(noBaseline.items, 'mystery_symbol'), 'Unresolved/-');
}

{
  // A name grammar every toolchain emits, with no baseline at all. This is the
  // rule that must still fire when the baseline rule could not run.
  const synthesised = classifyArtifact(inputs({
    elf: {
      symtab: [sym('_edata'), sym('__start_myseg'), sym('__start_absent')],
      sections: [sec(1, '.text'), sec(2, 'myseg')],
    },
  }));
  check('origins: a linker-synthesised name is Explained without any baseline',
    verdictOf(synthesised.items, '_edata'), 'Explained/linker-synthesised-name');
  check('origins: an encapsulation symbol whose section exists is Explained',
    verdictOf(synthesised.items, '__start_myseg'), 'Explained/section-encapsulation-symbol');
  check('origins: an encapsulation symbol naming no section is NOT waved through',
    verdictOf(synthesised.items, '__start_absent'), 'Unresolved/-');
}

{
  // Every rule can run — a baseline that matched, a source universe, located
  // libraries — so an unmatched item becomes genuinely Unexplained. This is the
  // finding direction, and the case above is the other side of the same coin:
  // the SAME artefact is Unresolved when the baseline rule could not run.
  const withSource = classifyArtifact(inputs({
    elf: { symtab: [sym('declared_fn'), sym('smuggled_fn')], sections: [sec(1, '.text')] },
    baseline: EMPTY_BASELINE,
    baselineState: 'matched',
    source: {
      available: true,
      identifiers: new Set(['declared_fn']),
      sourceBasenames: new Set(['main.c']),
      declaresConstructor: false,
      declaresDestructor: false,
    },
    libs: { available: true, index: new Map(), missing: [], allowed: null },
  }));
  check('origins: a name the translation unit declares is Explained',
    verdictOf(withSource.items, 'declared_fn'), 'Explained/unmangled-name-in-translation-unit');
  check('origins: with every rule able to run, an unaccounted symbol is Unexplained',
    verdictOf(withSource.items, 'smuggled_fn'), 'Unexplained/-');
}

{
  // An undefined symbol that a permitted library provides is the dependency
  // rule; one that only a forbidden library provides must NOT be explained.
  const undef = classifyArtifact(inputs({
    elf: { symtab: [sym('printf', { st_shndx: SHN.UNDEF }), sym('evil', { st_shndx: SHN.UNDEF })] },
    baseline: EMPTY_BASELINE,
    baselineState: 'matched',
    source: {
      available: true, identifiers: new Set(), sourceBasenames: new Set(),
      declaresConstructor: false, declaresDestructor: false,
    },
    libs: {
      available: true,
      index: new Map([['printf', ['libc.so.6']], ['evil', ['libevil.so']]]),
      missing: [],
      allowed: new Set(['libc.so.6']),
    },
  }));
  check('origins: an undefined symbol a permitted library provides is Explained',
    verdictOf(undef.items, 'printf'), 'Explained/resolved-in-needed-library');
  check('origins: resolving only in an unauthorised library is not an explanation',
    verdictOf(undef.items, 'evil'), 'Unexplained/-');
}

{
  // Sanitizer names are runtime support only when the build asked for the
  // runtime. The same artefact without the flag must not be waved through.
  const asked = classifyArtifact(inputs({
    elf: { symtab: [sym('__asan_init')], sections: [sec(1, '.text')] },
    flags: ['-fsanitize=address'],
  }));
  const notAsked = classifyArtifact(inputs({
    elf: { symtab: [sym('__asan_init')], sections: [sec(1, '.text')] },
  }));
  check('origins: a sanitizer symbol IS runtime support when the flag asked for it',
    verdictOf(asked.items, '__asan_init'), 'Explained/runtime-support-name');
  check('origins: the same symbol with no sanitiser flag is not explained by the name',
    verdictOf(notAsked.items, '__asan_init'), 'Unresolved/-');
}

{
  // .init_array is the whole attack surface: putting an otherwise ordinary
  // function in it is the attack, so being an EXPLAINED SYMBOL must not be
  // enough to be an explained INITIALISER. Two slots, pointing at two symbols
  // that are both Explained — one whose job is to initialise and one whose is
  // not — and the classification has to separate them.
  const slots = Buffer.alloc(16);
  slots.writeBigUInt64LE(0x1000n, 0); // -> _GLOBAL__sub_I_main.c
  slots.writeBigUInt64LE(0x2000n, 8); // -> ordinary_fn
  const init = classifyArtifact(inputs({
    elf: {
      symtab: [
        sym('_GLOBAL__sub_I_main.c', { st_value: 0x1000 }),
        sym('ordinary_fn', { st_value: 0x2000 }),
      ],
      sections: [
        sec(1, '.text'),
        sec(2, '.init_array', { sh_type: SHT.INIT_ARRAY, sh_size: 16, sh_offset: 0, sh_addr: 0x3000 }),
      ],
      buf: slots,
    },
    baseline: EMPTY_BASELINE,
    baselineState: 'matched',
    source: {
      available: true,
      identifiers: new Set(['ordinary_fn']),
      sourceBasenames: new Set(['main.c']),
      declaresConstructor: false,
      declaresDestructor: false,
    },
    libs: { available: true, index: new Map(), missing: [], allowed: null },
  }));
  check('origins: a static initialiser is Explained as a symbol',
    verdictOf(init.items, '_GLOBAL__sub_I_main.c', 'defined-symbol'),
    'Explained/static-initialiser-for-declared-source');
  check('origins: and Explained as an entry in .init_array',
    verdictOf(init.items, '_GLOBAL__sub_I_main.c', 'init-array-entry'),
    'Explained/initialiser-is-a-static-initialiser');
  check('origins: an ordinary function IS explained as a symbol',
    verdictOf(init.items, 'ordinary_fn', 'defined-symbol'),
    'Explained/unmangled-name-in-translation-unit');
  check('origins: but placing it in .init_array is NOT explained — this is the attack',
    verdictOf(init.items, 'ordinary_fn', 'init-array-entry'), 'Unexplained/-');
}

{
  // DT_NEEDED is reported verbatim; the section grammar explains ABI names.
  const r = classifyArtifact(inputs({
    elf: {
      sections: [sec(1, '.text'), sec(2, '.rela.text', { sh_type: SHT.RELA })],
      dynamic: [{ tag: DT.NEEDED, string: 'libc.so.6' }],
    },
  }));
  check('origins: an ABI section name is Explained by the grammar',
    verdictOf(r.items, '.text'), 'Explained/abi-section-name');
  check('origins: a relocation section for a known section is Explained',
    verdictOf(r.items, '.rela.text'), 'Explained/relocation-section-for-known-section');
  check('origins: the needed libraries are reported', r.needed, ['libc.so.6']);
}

console.log(failed === 0 ? '\nall unit cases passed' : `\n${failed} unit case(s) failed`);
process.exit(failed === 0 ? 0 : 1);

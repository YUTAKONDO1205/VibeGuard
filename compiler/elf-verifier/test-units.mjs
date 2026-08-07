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

console.log(failed === 0 ? '\nall unit cases passed' : `\n${failed} unit case(s) failed`);
process.exit(failed === 0 ? 0 : 1);

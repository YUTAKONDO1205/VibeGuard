// The origin taxonomy: one test per rule, in both directions.
//
// The rules are the toolchain baseline. Getting one wrong in the permissive
// direction hides an injection; getting one wrong in the strict direction
// accuses the compiler of its own work on every build. Both are tested.

import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyOrigin, emptyContext, ORIGINS, summariseVerdicts } from '../lib/origins.mjs';
import { frontEnd } from './helpers.mjs';

function ctx(overrides = {}) {
  return emptyContext({ haveFrontEnd: true, frontEnd: frontEnd(), ...overrides });
}

function origin(name, over = {}, c = ctx()) {
  return classifyOrigin({ kind: 'symbol', name, defined: true, ...over }, c);
}

test('every origin the rules can produce is one of the six', () => {
  const names = ['_init', '__cxa_throw', '_ZTV3Foo', '_ZNSt6vectorIiEC2Ev', 'app_main'];
  const c = ctx({ frontEnd: frontEnd(['app_main']) });
  for (const n of names) {
    const r = origin(n, {}, c);
    if (r.origin !== null) assert.ok(ORIGINS.includes(r.origin), `${n} -> ${r.origin}`);
  }
});

test('R1: symbols the link editor defines itself', () => {
  for (const n of ['_init', '_fini', '__bss_start', '_edata', '__init_array_start']) {
    const r = origin(n);
    assert.equal(r.origin, 'linker-generated', n);
    assert.equal(r.verdict, 'Explained');
  }
});

test('R2: runtime entry points, by family', () => {
  const cases = [
    ['__cxa_throw', 'Itanium C++ ABI runtime'],
    ['_Unwind_Resume', 'the unwinder'],
    ['__gxx_personality_v0', 'the C++ personality routine'],
    ['__asan_report_load8', 'AddressSanitizer runtime'],
    ['__stack_chk_fail', 'the stack-protector runtime'],
    ['llvm.memcpy.p0.p0.i64', 'an LLVM intrinsic'],
  ];
  for (const [n, what] of cases) {
    const r = origin(n);
    assert.equal(r.origin, 'runtime-support', n);
    assert.match(r.reason, new RegExp(what.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('R2: the libcalls LLVM materialises from IR that names no function', () => {
  // These have no source line to attribute them to: the IR said `llvm.memmove`
  // or `%a = udiv i128`, and the back end turned that into a call.
  for (const n of ['memcpy', 'memmove', 'memset', 'strlen', '__udivti3', '__atomic_load_8']) {
    assert.equal(origin(n).origin, 'runtime-support', n);
  }
});

test('R3: every ABI entity the negative fixture produces', () => {
  const cases = [
    ['_ZTVN12_GLOBAL__N_16SquareE', 'virtual table'],
    ['_ZTTN12_GLOBAL__N_16SquareE', 'virtual-table table'],
    ['_ZTCN12_GLOBAL__N_16SquareE0_NS_5SizedE', 'construction virtual table'],
    ['_ZTIN12_GLOBAL__N_15ShapeE', 'typeinfo object'],
    ['_ZTSN12_GLOBAL__N_15ShapeE', 'typeinfo name'],
    ['_ZTv0_n32_NK12_GLOBAL__N_15Sized4areaEv', 'virtual thunk'],
    ['_ZThn8_N3Foo3barEv', 'non-virtual thunk'],
    ['_ZGVZL5tableB5cxx11vE5value', 'guard variable'],
  ];
  for (const [n, what] of cases) {
    const r = origin(n);
    assert.equal(r.origin, 'toolchain-derived', n);
    assert.equal(r.verdict, 'Explained');
    assert.match(r.reason, new RegExp(what));
  }
});

test('R3: static-initialisation machinery', () => {
  for (const n of ['__cxx_global_var_init', '__cxx_global_var_init.1', '_GLOBAL__sub_I_app.cpp', 'frame_dummy']) {
    assert.equal(origin(n).origin, 'toolchain-derived', n);
  }
});

test('R3: codegen artefacts that exist in no earlier stage', () => {
  for (const n of ['GCC_except_table12', 'DW.ref.__gxx_personality_v0', 'asan.module_ctor', '__x86_indirect_thunk_rax']) {
    assert.equal(origin(n).origin, 'toolchain-derived', n);
  }
});

test('R3: a private label is reported as the private label it is, not as a clone', () => {
  // `.L.str.3` in the object is `.str.3` in the IR. Before this rule existed the
  // clone rule caught it and the run said ".L.str.3 is a clone the optimiser
  // made of .L.str" -- a true-looking sentence about something that never
  // happened. Measured on the negative fixture at -O0: six elements.
  const c = ctx({ frontEnd: frontEnd([], ['.str', '.str.3']) });
  const r = origin('.L.str.3', {}, c);
  assert.equal(r.origin, 'toolchain-derived');
  assert.equal(r.rule, 'R3.private-label');
  assert.match(r.reason, /private-label prefix/);
});

test('R3: an assembler temporary with nothing behind it is still explained', () => {
  const r = origin('.LCPI8_0');
  assert.equal(r.rule, 'R3.assembler-temporary');
  assert.equal(r.origin, 'toolchain-derived');
});

test('R3: an optimiser clone of a front-end function', () => {
  const c = ctx({ frontEnd: frontEnd(['handle_request']) });
  const r = origin('handle_request.cold.1', {}, c);
  assert.equal(r.origin, 'toolchain-derived');
  assert.equal(r.rule, 'R3.optimiser-clone');
  assert.match(r.reason, /clone the optimiser made of handle_request/);
});

test('R3: a clone of something that is NOT in the front-end set stays unexplained', () => {
  // The clone rule must not become a way to explain anything with a dot in it.
  const c = ctx({ frontEnd: frontEnd(['app_main']) });
  const r = origin('payload.cold.1', {}, c);
  assert.equal(r.verdict, 'Unexplained');
});

test('R3: template instantiations and lambdas', () => {
  assert.equal(origin('_ZN3app11AccumulatorIiE3addERKi').origin, 'toolchain-derived');
  assert.equal(origin('_ZZ19intro_negative_mainENK3$_0clEPKc').origin, 'toolchain-derived');
});

test('R4: namespaces the standard reserves to the implementation', () => {
  for (const n of ['_ZNSt6vectorIiSaIiEED2Ev', '_ZSt19__throw_logic_errorPKc', '_ZN9__gnu_cxx5stuffEv']) {
    const r = origin(n, { defined: false });
    assert.equal(r.origin, 'dependency-derived', n);
  }
});

test('R4: a declared dependency\'s exports', () => {
  const c = ctx({ dependencyExports: new Map([['zlib_inflate', 'zlib']]), haveDependencyExports: true });
  const r = origin('zlib_inflate', { defined: false }, c);
  assert.equal(r.origin, 'dependency-derived');
  assert.match(r.reason, /zlib/);
});

test('R5: a generated source, when debug information said where it came from', () => {
  const c = ctx({
    generatedSourceGlobs: ['**/*.pb.cc'],
    haveSourceAttribution: true,
    sourceFileOf: (n) => (n === 'generated_thing' ? 'proto/msg.pb.cc' : null),
  });
  const r = origin('generated_thing', {}, c);
  assert.equal(r.origin, 'generator-derived');
});

test('R5: a policy that declares generated sources with no way to tell is Unresolved, not Explained', () => {
  const c = ctx({ generatedSourceGlobs: ['**/*.pb.cc'], haveSourceAttribution: false });
  const r = origin('mystery', {}, c);
  assert.equal(r.verdict, 'Unresolved');
  assert.equal(r.origin, null);
  assert.match(r.reason, /could not be decided/);
});

test('R6: the measured front-end set', () => {
  const c = ctx({ frontEnd: frontEnd(['app_main'], ['app_table']) });
  assert.equal(origin('app_main', {}, c).origin, 'source-derived');
  assert.equal(origin('app_table', {}, c).origin, 'source-derived');
});

test('no baseline means Unresolved, never Explained and never Unexplained', () => {
  // Without the measured half there is no way to say whether the source
  // accounts for a plain name, and guessing either way would be a lie. This is
  // the difference between exit 3 and exit 0.
  const c = emptyContext({ haveFrontEnd: false });
  const r = origin('app_main', {}, c);
  assert.equal(r.verdict, 'Unresolved');
  assert.equal(r.rule, 'R6.no-baseline');
});

test('the structural rules still work with no baseline', () => {
  const c = emptyContext({ haveFrontEnd: false });
  assert.equal(origin('_ZTV3Foo', {}, c).verdict, 'Explained');
  assert.equal(origin('__cxa_throw', {}, c).verdict, 'Explained');
});

test('R7: a name that fits nothing is Unexplained', () => {
  const c = ctx({ frontEnd: frontEnd(['app_main']) });
  const r = origin('intro_injected_thunk', {}, c);
  assert.equal(r.verdict, 'Unexplained');
  assert.equal(r.origin, null);
  assert.match(r.reason, /no permitted origin/);
});

test('summariseVerdicts counts both axes', () => {
  const rows = [
    { verdict: 'Explained', origin: 'toolchain-derived' },
    { verdict: 'Explained', origin: 'source-derived' },
    { verdict: 'Unexplained', origin: null },
    { verdict: 'Unresolved', origin: null },
  ];
  const s = summariseVerdicts(rows);
  assert.deepEqual(s.verdicts, { Explained: 2, Unexplained: 1, Unresolved: 1 });
  assert.equal(s.byOrigin['toolchain-derived'], 1);
  assert.equal(s.byOrigin['source-derived'], 1);
});

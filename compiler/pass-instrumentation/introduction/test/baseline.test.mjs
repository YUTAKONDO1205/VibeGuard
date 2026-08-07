// Baseline subtraction end to end, on object shapes rather than on names.
//
// Both directions, on purpose: the honest object must come out with nothing
// left, and the injected one must come out with exactly the four things that
// were injected. A test that only did the second would pass just as well
// against a detector that flags everything.

import assert from 'node:assert/strict';
import test from 'node:test';

import { classifySection, subtractBaseline, subtractionReport } from '../lib/baseline.mjs';
import { normaliseElf, objectElements, resolveRelocTarget } from '../lib/elf.mjs';
import { emptyContext } from '../lib/origins.mjs';
import { frontEnd, honestObject, injectedObject } from './helpers.mjs';

function analyse(doc, fe) {
  const elf = normaliseElf(doc);
  const elements = objectElements(elf, { objectName: 'test.o' });
  return subtractBaseline(elements, emptyContext({ haveFrontEnd: true, frontEnd: fe }));
}

test('the honest object leaves nothing', () => {
  const r = analyse(honestObject(), frontEnd(['app_main']));
  assert.equal(r.verdicts.Unexplained, 0, subtractionReport(r));
  assert.equal(r.verdicts.Unresolved, 0, subtractionReport(r));
  assert.ok(r.classified.length >= 6, 'the subtraction must have had something to do');
});

test('the injected object leaves exactly the four things that were injected', () => {
  const r = analyse(injectedObject(), frontEnd(['honest_fn']));
  const left = r.classified.filter((c) => c.verdict === 'Unexplained');
  assert.deepEqual(
    left.map((c) => `${c.finding} ${c.kind}:${c.name}`).sort(),
    [
      'VG-INTRO-001 symbol:injected_thunk',
      'VG-INTRO-002 extcall:dlopen',
      'VG-INTRO-003 initialiser:injected_thunk',
      'VG-INTRO-004 section:.text.injected',
    ],
  );
});

test('the honest .init_array entry is followed through its section symbol', () => {
  // The compiler's own static-initialisation slot relocates against
  // `.text.startup + 0`, not against the function by name. Resolving that
  // indirection is the difference between "an initialiser this build cannot
  // account for" and "_GLOBAL__sub_I_app.cpp, which every C++ file with a
  // global object has".
  const elf = normaliseElf(honestObject());
  const rel = elf.relocs.find((x) => x.targetSectionName === '.init_array');
  const resolved = resolveRelocTarget(elf, rel);
  assert.equal(resolved.name, '_GLOBAL__sub_I_app.cpp');
  assert.equal(resolved.indirect, true);
});

test('the injected .init_array entry names its target directly and is still caught', () => {
  const elf = normaliseElf(injectedObject());
  const rel = elf.relocs.find((x) => x.targetSectionName === '.init_array');
  const resolved = resolveRelocTarget(elf, rel);
  assert.equal(resolved.name, 'injected_thunk');
  assert.equal(resolved.indirect, false);
});

test('a per-function executable section is explained by what it holds', () => {
  // -ffunction-sections produces one of these per function -- fifty-one of them
  // on the negative fixture. A rule that only knew the standard section names
  // would report every one.
  const r = classifySection(
    { name: '.text._ZNSt6vectorIiSaIiEED2Ev', detail: { contains: ['_ZNSt6vectorIiSaIiEED2Ev'] } },
    new Map([['_ZNSt6vectorIiSaIiEED2Ev', { verdict: 'Explained' }]]),
  );
  assert.equal(r.verdict, 'Explained');
  assert.equal(r.rule, 'S2.explained-contents');
});

test('an executable section holding something unexplained is unexplained, and says which', () => {
  const r = classifySection(
    { name: '.text.injected', detail: { contains: ['payload'] } },
    new Map([['payload', { verdict: 'Unexplained' }]]),
  );
  assert.equal(r.verdict, 'Unexplained');
  assert.match(r.reason, /payload/);
});

test('an executable section holding nothing nameable is Unresolved, not Explained', () => {
  const r = classifySection({ name: '.text.opaque', detail: { contains: [] } }, new Map());
  assert.equal(r.verdict, 'Unresolved');
});

test('sections are decided after symbols, never on their names alone', () => {
  // The ordering is the point. A single pass would have to judge
  // `.text.something` by its name, and a name is one line for an attacker to
  // choose.
  const r = analyse(injectedObject(), frontEnd(['honest_fn']));
  const sec = r.classified.find((c) => c.kind === 'section' && c.name === '.text.injected');
  assert.equal(sec.verdict, 'Unexplained');
  assert.match(sec.reason, /injected_thunk/);
});

test('with no measured baseline the honest object goes Unresolved, not clean', () => {
  const elf = normaliseElf(honestObject());
  const elements = objectElements(elf, { objectName: 'test.o' });
  const r = subtractBaseline(elements, emptyContext({ haveFrontEnd: false }));
  assert.equal(r.verdicts.Unexplained, 0);
  assert.ok(r.verdicts.Unresolved > 0, 'an unavailable baseline must not read as a clean result');
});

test('the subtraction report shows the baseline doing work', () => {
  const text = subtractionReport(analyse(honestObject(), frontEnd(['app_main'])));
  assert.match(text, /introduced elements: \d+/);
  assert.match(text, /explained by the toolchain baseline: \d+/);
  assert.match(text, /Unexplained: 0/);
});

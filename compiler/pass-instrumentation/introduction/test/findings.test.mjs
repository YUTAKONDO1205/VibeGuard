// The four findings: their shape, their gates, and what does NOT produce one.
//
// interfaces.md §2 fixes the shape, including that `where.unit` and
// `where.pass` are null when the finding is not attributable to one and that
// null means "not applicable", never "not looked at".

import assert from 'node:assert/strict';
import test from 'node:test';

import { buildFindings, failing, FINDING_META, findingFor } from '../lib/findings.mjs';
import { DEFAULT_INTRO_POLICY, loadIntroPolicy, PolicyError, severityAtLeast } from '../lib/policy.mjs';

const POLICY = { ...DEFAULT_INTRO_POLICY };

function unexplained(over = {}) {
  return {
    kind: 'symbol', name: 'injected', finding: 'VG-INTRO-001', where: '.text.injected',
    verdict: 'Unexplained', origin: null, reason: 'no permitted origin accounts for this element',
    detail: {}, ...over,
  };
}

test('all four ids exist, with the severities the block declares', () => {
  assert.deepEqual(Object.keys(FINDING_META).sort(), [
    'VG-INTRO-001', 'VG-INTRO-002', 'VG-INTRO-003', 'VG-INTRO-004',
  ]);
  assert.equal(FINDING_META['VG-INTRO-003'].severity, 'critical',
    'a static initialiser runs before main, so it outranks the rest');
});

test('a finding has the shape interfaces.md fixes', () => {
  const f = findingFor(unexplained(), { policy: POLICY, path: 'src/x.c' });
  assert.deepEqual(Object.keys(f).sort(), ['detail', 'id', 'severity', 'title', 'where']);
  assert.deepEqual(Object.keys(f.where).sort(), ['kind', 'pass', 'path', 'unit']);
  assert.ok(['invocation', 'source', 'ir', 'object', 'link', 'artifact'].includes(f.where.kind));
});

test('an element found only in the object carries nulls, and says the pass level was not watched', () => {
  const f = findingFor(unexplained(), { policy: POLICY, path: 'src/x.c' });
  assert.equal(f.where.kind, 'object');
  assert.equal(f.where.unit, null);
  assert.equal(f.where.pass, null);
  assert.match(f.detail, /did not watch this compilation/);
  assert.match(f.detail, /not the same as no pass having introduced it/);
});

test('an element the observer watched appear carries the (pass, IR unit) pair', () => {
  const f = findingFor(unexplained({
    firstIntroduction: {
      pass: 'LoopIdiomRecognizePass', unit: 'subject', seq: 12,
      previousAfterPass: 'SROAPass', atEntry: false,
    },
    stateSeries: [{ state: 'ABSENT' }, { state: 'PRESENT' }],
  }), { policy: POLICY, path: 'src/x.c' });
  assert.equal(f.where.kind, 'ir');
  assert.equal(f.where.pass, 'LoopIdiomRecognizePass');
  assert.equal(f.where.unit, 'subject');
  assert.match(f.detail, /First introduced by LoopIdiomRecognizePass in subject/);
  assert.match(f.detail, /immediately before it on that unit was SROAPass/);
  assert.match(f.detail, /ABSENT -> PRESENT/);
});

test('an explained element produces no finding', () => {
  const f = findingFor({ ...unexplained(), verdict: 'Explained', origin: 'toolchain-derived' },
    { policy: POLICY, path: 'x.c' });
  assert.equal(f, null);
});

test('an Unresolved element is an incompleteness, not a finding', () => {
  const { findings, incomplete } = buildFindings(
    [{ ...unexplained(), verdict: 'Unresolved', rule: 'R6.no-baseline' }],
    { policy: POLICY, path: 'x.c' },
  );
  assert.equal(findings.length, 0);
  assert.equal(incomplete.length, 1);
  assert.equal(incomplete[0].rule, 'R6.no-baseline');
});

// --- VG-INTRO-002 and its second gate ---------------------------------------

const SOURCE_CALL = {
  kind: 'extcall', name: 'system', finding: 'VG-INTRO-002', where: '.text',
  verdict: 'Explained', origin: 'source-derived', reason: 'the front end emitted this name',
  detail: { callSites: 1 },
};

test('under the default baseline mode a source-declared call is explained', () => {
  // Policing a call the source wrote is the analyser's job, not this block's.
  // This block asks whether anything appeared that the build cannot account
  // for, and a source-declared call is accounted for.
  assert.equal(findingFor(SOURCE_CALL, { policy: POLICY, path: 'x.c' }), null);
});

test('under allowlist mode a source-declared call must be on the list', () => {
  const strict = { ...POLICY, externalCalls: { mode: 'allowlist', approved: [] } };
  const f = findingFor(SOURCE_CALL, { policy: strict, path: 'x.c' });
  assert.equal(f.id, 'VG-INTRO-002');
  assert.match(f.detail, /allowlist mode/);
});

test('allowlist mode accepts what the list names', () => {
  const strict = { ...POLICY, externalCalls: { mode: 'allowlist', approved: ['system'] } };
  assert.equal(findingFor(SOURCE_CALL, { policy: strict, path: 'x.c' }), null);
});

test('allowlist mode does not make the operator list __cxa_throw', () => {
  const strict = { ...POLICY, externalCalls: { mode: 'allowlist', approved: [] } };
  const runtime = { ...SOURCE_CALL, name: '__cxa_throw', origin: 'runtime-support' };
  assert.equal(findingFor(runtime, { policy: strict, path: 'x.c' }), null);
});

test('an approved call is not reported even when unexplained', () => {
  const p = { ...POLICY, externalCalls: { mode: 'baseline', approved: ['dlopen'] } };
  const el = unexplained({ kind: 'extcall', name: 'dlopen', finding: 'VG-INTRO-002', detail: { callSites: 1 } });
  assert.equal(findingFor(el, { policy: p, path: 'x.c' }), null);
});

test('an approved executable section is not reported', () => {
  const p = { ...POLICY, sections: { approvedExecutable: ['.text.trampolines'] } };
  const el = unexplained({ kind: 'section', name: '.text.trampolines', finding: 'VG-INTRO-004' });
  assert.equal(findingFor(el, { policy: p, path: 'x.c' }), null);
});

// --- policy -----------------------------------------------------------------

test('findings are filtered by the policy threshold', () => {
  const fs = [
    { id: 'VG-INTRO-001', severity: 'high' },
    { id: 'VG-INTRO-003', severity: 'critical' },
  ];
  assert.equal(failing(fs, { failOn: 'high' }).length, 2);
  assert.equal(failing(fs, { failOn: 'critical' }).length, 1);
});

test('severityAtLeast orders the four levels', () => {
  assert.equal(severityAtLeast('critical', 'high'), true);
  assert.equal(severityAtLeast('medium', 'high'), false);
});

test('the built-in defaults are what runs when no policy file is named', () => {
  const p = loadIntroPolicy(null);
  assert.equal(p.externalCalls.mode, 'baseline');
  assert.equal(p.source, '(built-in defaults)');
});

test('a malformed policy is refused rather than treated as permissive', () => {
  assert.throws(() => loadIntroPolicy('/definitely/not/here.json'), PolicyError);
});

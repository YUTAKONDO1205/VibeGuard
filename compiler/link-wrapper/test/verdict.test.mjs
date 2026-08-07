import test from 'node:test';
import assert from 'node:assert/strict';

import { buildObservation } from '../lib/observe.mjs';
import { readLinkPolicy } from '../lib/policy-link.mjs';
import { verdict } from '../lib/verdict.mjs';
import { LINK } from '../lib/findings.mjs';
import { EXIT_OK, EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY } from '../lib/exit.mjs';
import {
  approvingPolicy, elfHeader, fixture, LINK_ROOT, NEG_ARGV, POS_ARGV, SCR_ARGV, ARC_ARGV, WRAPPER_PROVENANCE,
} from './helpers.mjs';

function observe(stem, argv, { provenance = WRAPPER_PROVENANCE, header = `${stem}.elfhdr.hex` } = {}) {
  return buildObservation({
    linkRoot: LINK_ROOT,
    argv,
    mapText: fixture(`${stem}.map.txt`),
    mapProvenance: provenance,
    traceText: fixture(`${stem}.trace`),
    artifactPath: `${LINK_ROOT}/${stem}.bin`,
    artifactBytes: header ? elfHeader(header) : null,
  });
}

function judge(observation, policy, options = {}) {
  return verdict({ observation, policyResult: readLinkPolicy(policy), options });
}

const NEG = observe('neg', NEG_ARGV);
const POS = observe('pos', POS_ARGV, { header: 'pos.elfhdr.hex' });

const ids = (v) => v.findings.map((f) => f.id).sort();

// ── the two directions ───────────────────────────────────────────────────────

test('NEGATIVE: an approved link produces no findings and exit 0', () => {
  const v = judge(NEG, approvingPolicy());
  assert.deepEqual(v.findings, [], JSON.stringify(v.findings, null, 2));
  assert.deepEqual(v.incomplete, [], JSON.stringify(v.incomplete, null, 2));
  assert.equal(v.exitCode, EXIT_OK);
});

test('POSITIVE: an unapproved object linked in is caught', () => {
  const v = judge(POS, approvingPolicy());
  assert.ok(ids(v).includes(LINK.UNAUTHORISED_OBJECT));
  const f = v.findings.find((x) => x.id === LINK.UNAUTHORISED_OBJECT);
  assert.match(f.detail, /rogue\.o/);
  assert.equal(f.where.kind, 'object');
  assert.equal(f.where.path, 'rogue.o');
  assert.equal(v.exitCode, EXIT_FINDINGS);
});

// The control is the part of the measurement that must NOT move. If main.o ever
// comes out unauthorised, the run says nothing about rogue.o — it says the
// matcher is broken.
test('CONTROL: the approved objects stay approved in the positive run too', () => {
  const v = judge(POS, approvingPolicy());
  for (const ref of ['main.o', 'helper.o']) {
    const d = v.decisions.find((x) => x.ref === ref);
    assert.ok(d, `${ref} was not even considered`);
    assert.equal(d.checked, true, `${ref} was skipped`);
    assert.equal(d.allowed, true, `${ref} was flagged; the measurement is broken, not the build`);
  }
  const flagged = v.findings.filter((f) => f.where.path === 'main.o' || f.where.path === 'helper.o');
  assert.deepEqual(flagged, []);
});

test('the unapproved object is caught by count as well as by name: 0 findings vs more than 0', () => {
  assert.equal(judge(NEG, approvingPolicy()).findings.length, 0);
  assert.ok(judge(POS, approvingPolicy()).findings.length > 0);
});

// ── .init_array and the entry point ──────────────────────────────────────────

test('an unapproved object that runs code before main is reported for that too', () => {
  const v = judge(POS, approvingPolicy());
  const f = v.findings.find((x) => x.id === LINK.INIT_ARRAY_FROM_UNAUTHORISED_INPUT);
  assert.ok(f, 'rogue.o contributes to .init_array and that is a separate fact from being linked in');
  assert.match(f.detail, /before main/);
});

test('the approved link’s .init_array is recorded and produces no finding', () => {
  assert.equal(NEG.initArray.present, true);
  assert.ok(NEG.initArray.contributions.some((c) => c.input === 'main.o'));
  assert.equal(judge(NEG, approvingPolicy()).findings.some((f) => f.id === LINK.INIT_ARRAY_FROM_UNAUTHORISED_INPUT), false);
});

test('the entry point is resolved to a symbol and an input, not left unobserved', () => {
  assert.equal(NEG.entry.resolved, 'PRESENT');
  assert.equal(NEG.entry.symbol, '_start');
  assert.equal(NEG.entry.address, 0x1670);
  assert.equal(NEG.entry.input, 'system:lib/x86_64-linux-gnu/Scrt1.o');
});

test('an entry point defined by an unauthorised input is a finding of its own', () => {
  const policy = approvingPolicy({ allowedObjects: ['main.o', 'helper.o', 'system:usr/lib/gcc/**/*.o'] });
  const v = judge(NEG, policy);
  assert.ok(ids(v).includes(LINK.ENTRY_POINT_FROM_UNAUTHORISED_INPUT));
});

test('an artefact that was never read leaves the entry point NOT_OBSERVED, never PRESENT', () => {
  const o = observe('neg', NEG_ARGV, { header: null });
  assert.equal(o.entry.resolved, 'NOT_OBSERVED');
  const v = judge(o, approvingPolicy());
  assert.equal(v.exitCode, EXIT_INCOMPLETE, 'not looking is exit 3, never exit 0');
  assert.ok(v.incomplete.some((i) => i.what === 'entry-point'));
});

// ── the other policy fields ──────────────────────────────────────────────────

test('a linker script is caught, and forbidLinkerScripts defaults to true when absent', () => {
  const SCR = observe('scr', SCR_ARGV, { header: 'neg.elfhdr.hex' });
  const explicit = judge(SCR, approvingPolicy());
  assert.ok(ids(explicit).includes(LINK.LINKER_SCRIPT_USED));

  const noField = approvingPolicy();
  delete noField.link.forbidLinkerScripts;
  const defaulted = judge(SCR, noField);
  assert.ok(ids(defaulted).includes(LINK.LINKER_SCRIPT_USED), 'the schema default is true; absent must not read as permitted');
  assert.match(defaulted.findings.find((f) => f.id === LINK.LINKER_SCRIPT_USED).detail, /defaults to true/);
});

test('a policy that permits linker scripts does not flag one', () => {
  const SCR = observe('scr', SCR_ARGV, { header: 'neg.elfhdr.hex' });
  const v = judge(SCR, approvingPolicy({ forbidLinkerScripts: false }));
  assert.equal(ids(v).includes(LINK.LINKER_SCRIPT_USED), false);
});

test('a linker the policy does not list is caught', () => {
  const v = judge(NEG, approvingPolicy({ allowedLinkers: ['bfd'] }));
  assert.ok(ids(v).includes(LINK.UNAUTHORISED_LINKER));
  assert.match(v.findings.find((f) => f.id === LINK.UNAUTHORISED_LINKER).detail, /"lld"/);
});

test('a shared library the policy does not list is caught', () => {
  const v = judge(NEG, approvingPolicy({ allowedLibraries: ['system:lib64/*.so*'] }));
  const libs = v.findings.filter((f) => f.id === LINK.UNAUTHORISED_LIBRARY);
  assert.ok(libs.length > 0);
  assert.ok(libs.some((f) => /libc\.so\.6/.test(f.detail)));
});

test('an archive member may be authorised by the member or by the archive, and reports which', () => {
  const ARC = observe('arc', ARC_ARGV, { header: 'neg.elfhdr.hex' });
  const base = approvingPolicy();

  const byArchive = judge(ARC, approvingPolicy({
    allowedObjects: [...base.link.allowedObjects, 'mainarc.o'],
    allowedLibraries: [...base.link.allowedLibraries, 'libarch.a'],
  }));
  const dA = byArchive.decisions.find((d) => d.ref === 'libarch.a(arch.o)');
  assert.equal(dA.allowed, true);
  assert.equal(dA.list, 'allowedLibraries');

  const byMember = judge(ARC, approvingPolicy({
    allowedObjects: [...base.link.allowedObjects, 'mainarc.o', 'libarch.a(arch.o)'],
  }));
  const dM = byMember.decisions.find((d) => d.ref === 'libarch.a(arch.o)');
  assert.equal(dM.allowed, true);
  assert.equal(dM.list, 'allowedObjects');
});

test('an archive member on neither list is VG-LINK-002, not VG-LINK-001', () => {
  const ARC = observe('arc', ARC_ARGV, { header: 'neg.elfhdr.hex' });
  const v = judge(ARC, approvingPolicy({ allowedObjects: ['mainarc.o', 'helper.o', 'system:**/*.o'] }));
  assert.ok(ids(v).includes(LINK.UNAUTHORISED_ARCHIVE_MEMBER));
});

// ── absent is not empty, and neither is clean ────────────────────────────────

test('an ABSENT allowedObjects is exit 3 and names every input it could not check', () => {
  const policy = approvingPolicy();
  delete policy.link.allowedObjects;
  const v = judge(NEG, policy);
  assert.equal(v.exitCode, EXIT_INCOMPLETE, 'an unchecked list must never report exit 0');
  assert.ok(v.skipped.includes('main.o'));
  assert.ok(v.skipped.includes('helper.o'));
  assert.equal(v.findings.length, 0, 'not checking is not the same as finding something');
  for (const s of v.skipped) assert.equal(typeof s, 'string');
});

test('an EMPTY allowedObjects authorises nothing and is a decision, not a gap', () => {
  const v = judge(NEG, approvingPolicy({ allowedObjects: [] }));
  assert.equal(v.exitCode, EXIT_FINDINGS);
  assert.ok(v.findings.filter((f) => f.id === LINK.UNAUTHORISED_OBJECT).length >= 2);
});

test('a policy with no link section at all cannot check anything and says so', () => {
  const policy = approvingPolicy();
  delete policy.link;
  const v = judge(NEG, policy);
  assert.equal(v.exitCode, EXIT_INCOMPLETE);
  assert.ok(v.incomplete.length > 0);
});

test('a malformed policy is exit 4 and nothing else runs', () => {
  const v = judge(NEG, { policyVersion: 'policy-v0', failOn: 'high', link: { allowedObjects: 'main.o' } });
  assert.equal(v.exitCode, EXIT_INTEGRITY);
  assert.match(v.integrity, /allowedObjects must be an array/);
  assert.deepEqual(v.findings, []);
});

test('a key that is not in the schema’s link section is refused, not ignored', () => {
  const v = judge(NEG, { policyVersion: 'policy-v0', failOn: 'high', link: { allowObjects: ['main.o'] } });
  assert.equal(v.exitCode, EXIT_INTEGRITY);
  assert.match(v.integrity, /allowObjects/);
});

// A response file can carry any linker option, including one that redirects the
// map. The command line is then not fully observed, and the honest report is
// "could not check", not "checked and clean".
test('a response file makes the run incomplete rather than clean', () => {
  const o = buildObservation({
    linkRoot: LINK_ROOT,
    argv: ['clang-18', '-fuse-ld=lld', '@link.rsp', 'main.o', 'helper.o', '-o', 'neg.bin'],
    mapText: fixture('neg.map.txt'),
    mapProvenance: WRAPPER_PROVENANCE,
    traceText: fixture('neg.trace'),
    artifactPath: `${LINK_ROOT}/neg.bin`,
    artifactBytes: elfHeader('neg.elfhdr.hex'),
  });
  const v = judge(o, approvingPolicy());
  assert.ok(ids(v).includes(LINK.COMMAND_LINE_NOT_FULLY_OBSERVED));
  assert.ok(v.incomplete.some((i) => i.what === 'command-line'));
  assert.equal(v.exitCode, EXIT_FINDINGS);
  // and the same link without the response file is clean, so the finding is
  // about the response file and not about everything.
  assert.equal(judge(NEG, approvingPolicy()).exitCode, EXIT_OK);
});

// ── the two observations ─────────────────────────────────────────────────────

test('an input the map has and the trace does not is a disagreement, not a pass', () => {
  const o = buildObservation({
    linkRoot: LINK_ROOT,
    argv: NEG_ARGV,
    mapText: fixture('pos.map.txt'),   // the map says rogue.o contributed bytes
    mapProvenance: WRAPPER_PROVENANCE,
    traceText: fixture('neg.trace'), // the linker's own list never mentions it
    artifactPath: `${LINK_ROOT}/neg.bin`,
    artifactBytes: elfHeader('neg.elfhdr.hex'),
  });
  const v = judge(o, approvingPolicy({ allowedObjects: ['main.o', 'helper.o', 'rogue.o', 'system:**/*.o'] }));
  const f = v.findings.find((x) => x.id === LINK.OBSERVATIONS_DISAGREE);
  assert.ok(f, 'the two captures describe different links and that is the finding');
  assert.equal(f.where.path, 'rogue.o');
});

test('a shared library present only in the trace is normal, not a disagreement', () => {
  const v = judge(NEG, approvingPolicy());
  assert.equal(v.findings.some((f) => f.id === LINK.OBSERVATIONS_DISAGREE), false);
  const libc = NEG.inputs.find((i) => i.ref.endsWith('libc.so.6'));
  assert.deepEqual(libc.sources, ['trace'], 'a .so contributes no input section, so the map cannot see it');
});

test('the linker’s synthetic input is skipped by name, never silently', () => {
  const v = judge(NEG, approvingPolicy());
  assert.ok(v.skipped.includes('internal:<linker-generated>'));
  assert.equal(v.findings.some((f) => f.where.path === 'internal:<linker-generated>'), false);
});

// ── symbol resolution is recorded ────────────────────────────────────────────

test('symbol resolution is recorded: which input defines which symbol', () => {
  const start = NEG.symbols.find((s) => s.name === '_start');
  assert.equal(start.input, 'system:lib/x86_64-linux-gnu/Scrt1.o');
  const control = NEG.symbols.find((s) => s.name === 'control_fn');
  assert.equal(control.input, 'main.o');
  assert.ok(NEG.symbols.length > 10, `only ${NEG.symbols.length} symbols recorded`);
});

test('the record carries the options, the sections and the counts, not just a verdict', () => {
  assert.ok(NEG.sections.some((s) => s.name === '.text'));
  assert.ok(NEG.counts.symbols > 0 && NEG.counts.sections > 0 && NEG.counts.mapInputs > 0);
  assert.equal(NEG.command.linker, 'lld');
  assert.equal(NEG.command.output, 'neg.bin');
});

// ── failOn ───────────────────────────────────────────────────────────────────

// interfaces.md §7: exit 2 is "findings AT OR ABOVE the policy's failure
// threshold". A finding below it is still reported — it is in the record and on
// stdout — but the policy decided it does not fail the build. The thing being
// asserted here is that raising the threshold changes the exit code and NOT the
// findings: a threshold that also suppressed the report would make the record
// depend on the reader's tolerance.
test('failOn raises the bar without hiding the finding', () => {
  const policy = approvingPolicy();
  policy.failOn = 'critical';
  const v = judge(POS, policy);
  assert.ok(ids(v).includes(LINK.UNAUTHORISED_OBJECT), 'the finding is still reported');
  assert.deepEqual(v.firing, [], 'nothing reached the critical threshold');
  assert.equal(v.exitCode, EXIT_OK);
  assert.equal(judge(POS, approvingPolicy()).exitCode, EXIT_FINDINGS, 'and at the default threshold it fires');
});

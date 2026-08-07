// The ABSENT -> INTRODUCED series, and the whole-sequence rule.
//
// interfaces.md §3: a state history must keep the whole sequence and must not
// stop at the first transition. The test that matters here is the one where an
// element is introduced, removed, and introduced again -- a checker that
// stopped early would report a state that a later pass had already undone.

import assert from 'node:assert/strict';
import test from 'node:test';

import { attributionFor, elementKey, measurementFault, parseIntroLog } from '../lib/introlog.mjs';
import { crossCheck, passIntroduced, reduceSeries } from '../lib/states.mjs';

// A log in the exact format Census.cpp writes, with the fields in the order
// Census.h documents. Three elements: one at entry, one introduced by a pass,
// one that goes all the way round.
const LOG = [
  'HANDSHAKE\tintroduction-observer-v1\tapp.c\tstandard\tctl\tsymbols,extcalls,initialisers,sections',
  'SUMMARY\t(module)\tsymbol\tctl\t1\tbefore\tAnnotation2MetadataPass\tmodule\tapp.c\t\t-1\t1\tPRESENT\t1\t0\t0\t1\t0\t1',
  'HIST\t(module)\tsymbol\tctl\t0\t1\tbefore\tAnnotation2MetadataPass\t1\tPRESENT\t40\t80\tEnd',
  'SUMMARY\tsubject\textcall\tllvm.memset.p0.i64\t12\tafter\tLoopIdiomRecognizePass\tloop\tsubject\tPassManager<Function>\t-1\t0\tPRESENT\t1\t0\t0\t1\t0\t2',
  'HIST\tsubject\textcall\tllvm.memset.p0.i64\t0\t11\tbefore\tLoopIdiomRecognizePass\t0\tABSENT\t1\t11\tLoopIdiomRecognizePass',
  'HIST\tsubject\textcall\tllvm.memset.p0.i64\t1\t12\tafter\tLoopIdiomRecognizePass\t1\tPRESENT\t9\t80\tEnd',
  'SUMMARY\tround\textcall\tllvm.memset.p0.i64\t1\tbefore\tAnnotation2MetadataPass\tmodule\tapp.c\t\t-1\t1\tREINTRODUCED\t1\t1\t1\t2\t1\t3',
  'HIST\tround\textcall\tllvm.memset.p0.i64\t0\t1\tbefore\tAnnotation2MetadataPass\t1\tPRESENT\t5\t9\tInstCombinePass',
  'HIST\tround\textcall\tllvm.memset.p0.i64\t1\t10\tafter\tInstCombinePass\t0\tLOST\t1\t10\tInstCombinePass',
  'HIST\tround\textcall\tllvm.memset.p0.i64\t2\t40\tafter\tLoopIdiomRecognizePass\t1\tREINTRODUCED\t6\t80\tEnd',
  'STATS\t80\t400\t3\t3\t0\tstandard\t1\tPRESENT',
].join('\n');

test('the introduction is the ABSENT -> PRESENT transition, not a seventh state', () => {
  const r = reduceSeries([
    { seq: 11, pass: 'LoopIdiomRecognizePass', count: 0 },
    { seq: 12, pass: 'LoopIdiomRecognizePass', count: 1 },
  ], { firstObservationIsEntry: false });
  assert.deepEqual(r.series.map((s) => s.state), ['ABSENT', 'PRESENT']);
  assert.equal(r.firstIntroduction.seq, 12);
  assert.equal(r.firstIntroduction.pass, 'LoopIdiomRecognizePass');
  assert.equal(r.firstIntroduction.atEntry, false);
});

test('present at the first look means the front end put it there, not a pass', () => {
  const r = reduceSeries([{ seq: 1, pass: 'Annotation2MetadataPass', count: 1 }]);
  assert.equal(r.firstIntroduction.atEntry, true);
  assert.deepEqual(r.series.map((s) => s.state), ['PRESENT']);
});

test('the whole series is kept: it does not stop at the first loss', () => {
  const r = reduceSeries([
    { seq: 1, pass: 'A', count: 1 },
    { seq: 2, pass: 'InstCombinePass', count: 0 },
    { seq: 3, pass: 'LoopIdiomRecognizePass', count: 1 },
    { seq: 4, pass: 'DSEPass', count: 0 },
  ]);
  assert.deepEqual(r.series.map((s) => s.state), ['PRESENT', 'LOST', 'REINTRODUCED', 'LOST']);
  assert.equal(r.finalState, 'LOST');
  assert.equal(r.everLost, true);
  assert.equal(r.everReintroduced, true);
  assert.equal(r.introEpisodes, 2);
  assert.equal(r.lossEpisodes, 2);
});

test('runs of the same answer are folded but counted', () => {
  const r = reduceSeries([
    { seq: 1, pass: 'A', count: 1 },
    { seq: 2, pass: 'B', count: 1 },
    { seq: 3, pass: 'C', count: 1 },
    { seq: 4, pass: 'D', count: 2 },
  ]);
  assert.equal(r.series.length, 2, 'a repeated state is not a new state');
  assert.equal(r.series[0].repeats, 3);
  assert.equal(r.series[0].lastSeq, 3);
  assert.equal(r.series[1].count, 2, 'a count change starts a new entry');
});

test('a count change is a change even when the state is not', () => {
  const r = reduceSeries([
    { seq: 1, pass: 'A', count: 1 },
    { seq: 2, pass: 'B', count: 3 },
  ]);
  assert.equal(r.series.length, 2);
  assert.deepEqual(r.series.map((s) => s.count), [1, 3]);
});

// --- reading a real log -----------------------------------------------------

test('the log parses into elements with their whole series', () => {
  const p = parseIntroLog(LOG);
  assert.equal(p.handshake.schema, 'introduction-observer-v1');
  assert.equal(p.summaries.length, 3);
  assert.equal(p.stats.controlFinalState, 'PRESENT');
  const round = p.byElement.get(elementKey({ scope: 'round', kind: 'extcall', name: 'llvm.memset.p0.i64' }));
  assert.deepEqual(round.series.map((h) => h.state), ['PRESENT', 'LOST', 'REINTRODUCED']);
});

test('the summary and its own history agree', () => {
  assert.deepEqual(crossCheck(parseIntroLog(LOG)), []);
});

test('a doctored summary is caught by its own history', () => {
  // The point of running the state machine twice, in two languages, from the
  // two ends: an answer that does not follow from the evidence is reported as a
  // disagreement instead of being believed.
  const doctored = LOG.replace(
    'SUMMARY\tround\textcall\tllvm.memset.p0.i64\t1\tbefore\tAnnotation2MetadataPass\tmodule\tapp.c\t\t-1\t1\tREINTRODUCED',
    'SUMMARY\tround\textcall\tllvm.memset.p0.i64\t1\tbefore\tAnnotation2MetadataPass\tmodule\tapp.c\t\t-1\t1\tLOST',
  );
  const problems = crossCheck(parseIntroLog(doctored));
  assert.equal(problems.length, 1);
  assert.equal(problems[0].field, 'finalState');
  assert.equal(problems[0].summary, 'LOST');
  assert.equal(problems[0].derived, 'REINTRODUCED');
});

test('only the pass-introduced elements are reported as such', () => {
  const introduced = passIntroduced(parseIntroLog(LOG));
  assert.deepEqual(introduced.map((i) => i.scope), ['subject']);
  assert.equal(introduced[0].pass, 'LoopIdiomRecognizePass');
  assert.equal(introduced[0].unitKind, 'loop');
  assert.equal(introduced[0].unit, 'subject');
  assert.equal(introduced[0].previousAfterPass, 'PassManager<Function>');
});

test('the attribution handed to a finding carries both halves and the series', () => {
  const p = parseIntroLog(LOG);
  const a = attributionFor(p.byElement.get(elementKey({ scope: 'subject', kind: 'extcall', name: 'llvm.memset.p0.i64' })));
  assert.equal(a.firstIntroduction.pass, 'LoopIdiomRecognizePass');
  assert.equal(a.firstIntroduction.unit, 'subject');
  assert.equal(a.stateSeries.length, 2);
});

test('at-entry elements carry no pass, because no pass introduced them', () => {
  const p = parseIntroLog(LOG);
  const a = attributionFor(p.byElement.get(elementKey({ scope: '(module)', kind: 'symbol', name: 'ctl' })));
  assert.equal(a.firstIntroduction.atEntry, true);
  assert.equal(a.firstIntroduction.pass, null);
});

// --- a measurement that is not one ------------------------------------------

test('a log with no control is a broken measurement, not a clean result', () => {
  const p = parseIntroLog(LOG.replace('\t1\tPRESENT\n', '\t0\tNOT_OBSERVED\n')
    .replace('STATS\t80\t400\t3\t3\t0\tstandard\t1\tPRESENT', 'STATS\t80\t400\t3\t3\t0\tstandard\t0\tNOT_OBSERVED'));
  assert.match(measurementFault(p), /control ctl was never observed/);
});

test('a control that did not survive invalidates the run', () => {
  const p = parseIntroLog(LOG.replace(
    'STATS\t80\t400\t3\t3\t0\tstandard\t1\tPRESENT',
    'STATS\t80\t400\t3\t3\t0\tstandard\t1\tLOST',
  ));
  assert.match(measurementFault(p), /measurement is broken/);
});

test('a sound log has no fault', () => {
  assert.equal(measurementFault(parseIntroLog(LOG)), null);
});

test('a summary-only side file says what it is instead of claiming the plugin never ran', () => {
  const summaryOnly = LOG.split('\n').filter((l) => l.startsWith('SUMMARY') || l.startsWith('HIST')).join('\n');
  assert.match(measurementFault(parseIntroLog(summaryOnly)), /summary-only side file/);
});

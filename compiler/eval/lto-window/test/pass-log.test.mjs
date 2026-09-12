/**
 * Guard 2, and the log reader it depends on.
 *
 * Two of these tests are here because the first hand-written version of this
 * comparison got them wrong and the wrong answer looked plausible:
 *
 *   - splitting `Running pass: <id> on <unit>` at the FIRST space truncated
 *     `PassManager<LazyCallGraph::SCC, CGSCCAnalysisManager, ...>` into
 *     `PassManager<LazyCallGraph::SCC,` and reported it as a pass the linker
 *     never ran;
 *   - not stripping lld's ` (7 instructions)` suffix reported 151 of 176 pairs
 *     as mismatched on a run that was in fact in exact agreement.
 *
 * Both would have produced a BROKEN_MEASUREMENT for a healthy link, which is the
 * cheap direction to fail in but still a lie about the instrument.
 *
 * No compiler is required and nothing is measured here.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  parseLldPassLog, parseObserverLog, comparePassReadings, normaliseUnit, isSpecialPass, MODULE_UNIT,
} from '../lib/pass-log.mjs';

/* ------------------------------------------------------- the lld reading -- */

test('the pass id is split at the LAST " on ", so an id containing spaces survives', () => {
  const text = [
    'Running pass: VerifierPass on [module]',
    'Running pass: PassManager<LazyCallGraph::SCC, CGSCCAnalysisManager, LazyCallGraph &, CGSCCUpdateResult &> on (secure_wipe) (1 node)',
    'Running analysis: VerifierAnalysis on [module]',
    'Invalidating analysis: DominatorTreeAnalysis on handle',
  ].join('\n');
  const { runs, lineKinds } = parseLldPassLog(text);
  assert.equal(runs.length, 2);
  assert.equal(runs[1].pass, 'PassManager<LazyCallGraph::SCC, CGSCCAnalysisManager, LazyCallGraph &, CGSCCUpdateResult &>');
  assert.equal(runs[1].unit, '(secure_wipe)');
  // The other line kinds are counted but are not pass runs.
  assert.equal(lineKinds['Running analysis'], 1);
  assert.equal(lineKinds['Invalidating analysis'], 1);
});

test('an empty pass log yields zero runs -- the shape a non-LTO link produces', () => {
  assert.equal(parseLldPassLog('').runs.length, 0);
  assert.equal(parseLldPassLog(null).runs.length, 0);
});

test('the size suffix is stripped, and only when it is one', () => {
  assert.equal(normaliseUnit('handle (7 instructions)'), 'handle');
  assert.equal(normaliseUnit('(secure_wipe) (1 node)'), '(secure_wipe)');
  assert.equal(normaliseUnit('loop (3 blocks)'), 'loop');
  assert.equal(normaliseUnit('[module]'), '[module]');
  // Not a size suffix: a function whose name really ends that way keeps it.
  assert.equal(normaliseUnit('fn (not a count)'), 'fn (not a count)');
});

/* ---------------------------------------------------- the observer reading -- */

const obsLine = (...f) => f.join('\t');

test('a healthy observer log parses into its record types and reads as intact', () => {
  const log = [
    obsLine('HANDSHAKE', 'obs-log-v1', 'ld-temp.o', 'handle', 'wipe_kept', 'memset', 'trace', '0'),
    obsLine('SUBJECTRES', '1', 'ld-temp.o', 'subject', 'handle', 'resolved'),
    obsLine('PASS', '1', 'before', 'VerifierPass', 'module', 'ld-temp.o'),
    obsLine('EV', '1', 'before', 'VerifierPass', 'module', 'handle', 'handle', 'subject', '0', 'ABSENT', '1'),
  ].join('\n');
  const p = parseObserverLog(Buffer.from(log, 'utf8'));
  assert.equal(p.intact, true);
  assert.equal(p.handshakes[0].moduleId, 'ld-temp.o');
  assert.equal(p.subjectRes[0].resolution, 'resolved');
  assert.equal(p.ev[0].state, 'ABSENT');
  assert.equal(p.counts.PASS, 1);
});

test('a shredded log is reported as shredded, not silently cleaned up', () => {
  // The ThinLTO shape, in miniature: a NUL hole from a truncating reopen, a torn
  // line, and more than one HANDSHAKE. Any one of the three is enough.
  const shredded = Buffer.concat([
    Buffer.from(obsLine('HANDSHAKE', 'obs-log-v1', 'use.t.o', 'handle', 'wipe_kept', 'memset', 'trace', '0') + '\n'),
    Buffer.alloc(4, 0),
    Buffer.from('ANDSHAKE\tobs-log-v1\twipe.t.o\n'),
    Buffer.from(obsLine('HANDSHAKE', 'obs-log-v1', 'main.t.o', 'handle', 'wipe_kept', 'memset', 'trace', '0') + '\n'),
  ]);
  const p = parseObserverLog(shredded);
  assert.equal(p.intact, false);
  assert.equal(p.nulBytes, 4);
  assert.equal(p.handshakes.length, 2);
  assert.equal(p.tornLines.length, 1);
  assert.match(p.tornLines[0], /^ANDSHAKE/);
});

test('SUMMARY is read for the fields a verdict needs, and "-" is null rather than 0', () => {
  const row = obsLine('SUMMARY', 'handle', 'handle', 'subject', '0', '206', 'DSEPass', 'DSEPass',
    'MemCpyOptPass', '18', 'LOST', '1', '1', '0', '1', 'LIVE', '-', '-', '3');
  const noLoss = obsLine('SUMMARY', 'wipe_kept', 'wipe_kept', 'control', '0', '-', '-', '-', '-',
    '-1', 'PRESENT', '1', '0', '0', '0', 'LIVE', '-', '-', '1');
  const p = parseObserverLog(Buffer.from(`${row}\n${noLoss}\n`, 'utf8'));
  assert.equal(p.summaries[0].finalState, 'LOST');
  assert.equal(p.summaries[0].firstLossPass, 'DSEPass');
  assert.equal(p.summaries[0].firstLossSeq, 206);
  assert.equal(p.summaries[1].finalState, 'PRESENT');
  assert.equal(p.summaries[1].firstLossPass, null);
  assert.equal(p.summaries[1].everLost, false);
});

/* ------------------------------------------------------------- guard two -- */

const beforePass = (pass, unitKind, unitName) => ({ phase: 'before', pass, unitKind, unitName });

test('the pass-manager and pass-adaptor shapes are excluded, and nothing else is', () => {
  assert.equal(isSpecialPass('ModuleToFunctionPassAdaptor'), true);
  assert.equal(isSpecialPass('PassManager<Function>'), true);
  assert.equal(isSpecialPass('DSEPass'), false);
  assert.equal(isSpecialPass('RequireAnalysisPass<llvm::GlobalsAA, llvm::Module, llvm::AnalysisManager<Module>>'), false);
});

test('agreement on the real run shape: subset holds and the sequences are equal', () => {
  const observer = [
    beforePass('VerifierPass', 'module', 'ld-temp.o'),
    beforePass('ModuleToFunctionPassAdaptor', 'module', 'ld-temp.o'),
    beforePass('CallSiteSplittingPass', 'function', 'handle'),
    beforePass('DSEPass', 'function', 'handle'),
    // An `after` callback is not part of the comparison: lld prints one line per
    // pass RUN, the observer records a boundary on each side of it.
    { phase: 'after', pass: 'DSEPass', unitKind: 'function', unitName: 'handle' },
  ];
  const lld = parseLldPassLog([
    'Running pass: VerifierPass on [module]',
    'Running pass: CallSiteSplittingPass on handle (7 instructions)',
    'Running pass: DSEPass on handle (7 instructions)',
  ].join('\n')).runs;

  const a = comparePassReadings(observer, lld);
  assert.equal(a.comparable, true);
  assert.equal(a.subset, true);
  assert.equal(a.sequenceEqual, true);
  assert.deepEqual(a.observerOnly, []);
  assert.deepEqual(a.lldOnly, []);
  assert.deepEqual(a.excludedPassIds, ['ModuleToFunctionPassAdaptor']);
  assert.deepEqual(a.counts, {
    observerBeforeCallbacks: 4, observerSpecialExcluded: 1, observerCompared: 3, lldRunningPassLines: 3,
  });
  assert.equal(MODULE_UNIT, '[module]');
});

test('a pass the observer saw and the linker did not is a disagreement, not an exclusion', () => {
  const observer = [beforePass('VerifierPass', 'module', 'ld-temp.o'), beforePass('SomeInventedPass', 'function', 'handle')];
  const lld = parseLldPassLog('Running pass: VerifierPass on [module]').runs;
  const a = comparePassReadings(observer, lld);
  assert.equal(a.subset, false);
  assert.deepEqual(a.observerOnly, ['SomeInventedPass']);
});

test('the same passes in a different ORDER fail sequence equality while passing subset', () => {
  // Reported separately on purpose. Subset is what the lane requires; equality
  // is what it has always in fact observed, and a run where the two diverge is
  // worth seeing rather than averaging away.
  const observer = [beforePass('DSEPass', 'function', 'handle'), beforePass('SROAPass', 'function', 'handle')];
  const lld = parseLldPassLog([
    'Running pass: SROAPass on handle (7 instructions)',
    'Running pass: DSEPass on handle (7 instructions)',
  ].join('\n')).runs;
  const a = comparePassReadings(observer, lld);
  assert.equal(a.subset, true);
  assert.equal(a.sequenceEqual, false);
  assert.equal(a.firstMismatches.length, 2);
});

test('an empty reading on either side is "cannot be compared", never a pass', () => {
  assert.equal(comparePassReadings([], parseLldPassLog('Running pass: X on [module]').runs).comparable, false);
  assert.equal(comparePassReadings([beforePass('X', 'module', 'm')], []).comparable, false);
});

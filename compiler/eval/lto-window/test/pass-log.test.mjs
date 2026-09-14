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
import { readFileSync, readdirSync } from 'node:fs';

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

test('a SUMMARY row torn at the END is a torn line, not a healthy row', () => {
  // THE MID-LINE TEAR. Until 2026-09-15 intactness asked one question of a
  // line -- is field 0 a legal record type? -- and the ThinLTO / interrupted-
  // write failure mode does not touch field 0. It cuts the line somewhere in
  // the MIDDLE, and the surviving fragment still begins `SUMMARY\t`.
  //
  // The exact input this was reproduced on: a handshake, both SUBJECTRES rows
  // resolved, one EV, a 4-field subject SUMMARY, and a full control SUMMARY.
  // Before the fix this parsed to `intact: true`, `tornLines: 0`, TWO
  // summaries, and a subject whose `finalState` was `undefined` -- which is
  // not a member of STATE, and which JSON.stringify drops, so the published
  // cell had no `state` key at all.
  const log = [
    obsLine('HANDSHAKE', 'obs-log-v1', 'ld-temp.o', 'handle', 'wipe_kept', 'memset', 'trace', '0'),
    obsLine('SUBJECTRES', '1', 'ld-temp.o', 'subject', 'handle', 'resolved'),
    obsLine('SUBJECTRES', '1', 'ld-temp.o', 'control', 'wipe_kept', 'resolved'),
    obsLine('EV', '1', 'before', 'DSEPass', 'function', 'handle', 'handle', 'subject', '0', 'ABSENT', '1'),
    obsLine('SUMMARY', 'handle', 'handle', 'subject'),
    obsLine('SUMMARY', 'wipe_kept', 'wipe_kept', 'control', '0', '-', '-', '-', '-',
      '-1', 'PRESENT', '1', '0', '0', '0', 'LIVE', '-', '-', '1'),
  ].join('\n');
  const p = parseObserverLog(Buffer.from(log, 'utf8'));
  assert.equal(p.intact, false, 'a log with a row cut mid-line is not intact');
  assert.equal(p.tornLines.length, 1);
  assert.match(p.tornLines[0], /^SUMMARY\thandle\thandle\tsubject$/);
  // And the short row never becomes a summary: only the whole one survives, so
  // no `finalState: undefined` can reach a cell.
  assert.equal(p.summaries.length, 1);
  assert.equal(p.summaries[0].role, 'control');
  assert.equal(p.summaries[0].finalState, 'PRESENT');
  // The records that WERE whole are still read; this is a torn-line finding,
  // not a refusal to parse the file.
  assert.equal(p.handshakes.length, 1);
  assert.equal(p.ev.length, 1);
});

test('the same tear is caught in every record type, and a spliced-LONG row too', () => {
  // The tear does not choose its record. Each of these is a real type with one
  // field missing, and each has to be torn for the same reason.
  const short = [
    obsLine('HANDSHAKE', 'obs-log-v1', 'ld-temp.o', 'handle', 'wipe_kept', 'memset', 'trace'),
    obsLine('SUBJECTRES', '1', 'ld-temp.o', 'subject', 'handle'),
    obsLine('PASS', '1', 'before', 'VerifierPass', 'module'),
    obsLine('EV', '1', 'before', 'DSEPass', 'function', 'handle', 'handle', 'subject', '0', 'ABSENT'),
    obsLine('UNIT', '1', 'DSEPass', 'handle', 'handle'),
    obsLine('HIST', 'handle', '0', '1', 'before', 'DSEPass', '0'),
    obsLine('STATS', '448', '388', '2', '2', '0'),
  ];
  for (const line of short) {
    const p = parseObserverLog(Buffer.from(`${line}\n`, 'utf8'));
    assert.equal(p.tornLines.length, 1, `a short ${line.split('\t')[0]} row was read as whole`);
    assert.equal(p.intact, false);
  }
  // EXACT, not a minimum: a splice joins the tail of one line to the head of
  // another and leaves a row with a legal type and MORE fields than the schema
  // has. No writer in History.cpp emits a variable count, so that row is torn
  // in exactly the same way.
  const long = parseObserverLog(Buffer.from(
    `${obsLine('STATS', '448', '388', '2', '2', '0', 'trace', 'HANDSHAKE')}\n`, 'utf8'));
  assert.equal(long.tornLines.length, 1);
  assert.equal(long.stats.length, 0);
});

test('the side file is read as BYTES, which is why no text-taking parser exists for it', () => {
  // WHY `parseObserverSummaryFile` was deleted on 2026-09-15 rather than wired
  // up. It took TEXT, and it was the DOCUMENTED entry point for reading
  // `<OBS_OUT>.summary.tsv` -- it carried this module's longest justification
  // comment, the one a reviewer auditing "is the side file read as its own
  // file?" would find and be satisfied by. The running one was `readObserver`
  // in ../run-lto-window.mjs, calling parseObserverLog on the file's bytes.
  // One hit across all of compiler/: the definition.
  //
  // Wiring it in would have meant reading the side file as a STRING, and a
  // decode-then-encode is not the identity on a shredded log: 0x80 is not
  // valid UTF-8 and comes back as U+FFFD, three bytes where there was one. The
  // count below is the whole argument -- a parser whose job includes counting
  // what is in the file cannot be handed something that is no longer the file.
  const bytes = Buffer.concat([
    Buffer.from(obsLine('SUMMARY', 'handle', 'handle', 'subject', '0', '206', 'DSEPass', 'DSEPass',
      'MemCpyOptPass', '18', 'LOST', '1', '1', '0', '1', 'LIVE', '-', '-', '3') + '\n'),
    Buffer.from([0x80, 0x00]), Buffer.from('\n'),
  ]);
  const roundTripped = Buffer.from(bytes.toString('utf8'), 'utf8');
  assert.equal(bytes.length, 96);
  assert.equal(roundTripped.length, 98, 'the decode/encode round trip added bytes to the file');

  // STATED PRECISELY, because the weaker claim is the true one and the
  // stronger one would be this comment doing the same thing the deleted
  // function did. For THIS corruption both readings agree: NUL is valid ASCII,
  // so the count survives, and the torn line is the same line either way.
  // What does not survive is the guarantee that the bytes being counted are
  // the bytes on disk, and `nulBytes` is reported as a byte-level fact about
  // the file.
  for (const b of [bytes, roundTripped]) {
    const p = parseObserverLog(b);
    assert.equal(p.nulBytes, 1);
    assert.equal(p.intact, false);
    assert.equal(p.summaries[0].finalState, 'LOST');
  }
});

test('every reader this module exports is called by running code, not only documented', () => {
  // F5, mechanically. `parseObserverSummaryFile` was exported from
  // lib/pass-log.mjs, carried the module's longest justification comment, and
  // was called by NOTHING -- one hit across all of compiler/, the definition.
  // The side file was really read by `readObserver` calling parseObserverLog.
  // A reviewer auditing "is the side file read as its own file?" finds the
  // documented entry point, reads its reasoning, and is satisfied by a
  // function that never runs.
  //
  // So the rule, for this module: an export is either called by running code
  // or it does not exist. COMMENT lines do not count -- both the deletion note
  // here and the relocated paragraph in readObserver name the dead function,
  // and counting those would let it be re-added and still look referenced.
  // Test files do not count either: an export exercised only by its own test
  // is exactly the shape this catches.
  const lane = new URL('../', import.meta.url);
  const isComment = (l) => {
    const t = l.trim();
    return t.startsWith('*') || t.startsWith('//') || t.startsWith('/*');
  };
  const src = readFileSync(new URL('lib/pass-log.mjs', lane), 'utf8');
  const names = src.split('\n')
    .map((l) => l.match(/^export (?:function|const) (\w+)/))
    .filter(Boolean).map((m) => m[1]);
  assert.ok(names.length >= 7, `expected this module's exports, found ${names.length}`);

  const files = ['run-lto-window.mjs', ...readdirSync(new URL('lib/', lane)).map((f) => `lib/${f}`)];
  for (const n of names) {
    const callers = files.filter((f) => readFileSync(new URL(f, lane), 'utf8').split('\n')
      .filter((l) => !isComment(l))
      .filter((l) => !l.startsWith(`export function ${n}`) && !l.startsWith(`export const ${n}`))
      .some((l) => l.includes(n)));
    assert.ok(callers.length > 0,
      `lib/pass-log.mjs exports \`${n}\` and no running file in this lane calls it. Either wire it up or `
      + 'delete it and move its reasoning to where the work happens -- a documented mechanism that does not '
      + 'run is what a reviewer audits instead of the one that does.');
  }
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

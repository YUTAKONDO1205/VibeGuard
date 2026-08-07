// RQ2 ground-truth harness for the property observer.
//
// The question RQ2 asks is "how often is the first-loss pass right", and that
// question has no answer until "right" is defined. Nothing about a real -O2
// compilation supplies one: which pass removed the effect is exactly what is in
// dispute, so agreement between tools is not truth, it is agreement.
//
// So the ground truth is manufactured:
//
//   1. Take the pre-optimisation IR from clang with -disable-llvm-passes.
//   2. Take the pipeline string from the SAME clang invocation
//      (-mllvm -print-pipeline-passes). `opt -passes='default<O2>'` is NOT
//      clang's -O2 -- clang builds its pipeline with its own tuning options --
//      so a harness that assumes it injects at a position that does not exist
//      in the compilation it claims to describe.
//   3. Replay that string under opt, with a synthetic pass that removes the
//      effect placed at an index the harness chose.
//
// The correct attribution is then known because this file wrote it down before
// the observer ran.
//
// Usage:  node ~/vg-lab/pass-observer/rq2/rq2.mjs
// Exit:   0 all checks passed, 2 a check failed, 3 the harness could not run.

import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HOME = os.homedir();
const LAB = process.env.OBS_LAB || path.join(HOME, 'vg-lab', 'pass-observer');
const RQ2 = path.join(LAB, 'rq2');
const WORK = path.join(LAB, 'work');
const RESULTS = path.join(LAB, "results");
const RUNLOG = path.join(LAB, 'run-log.txt');
const OBS = path.join(HOME, 'vg-build', 'pass-observer', 'libPropertyObserver.so');
const SGT = path.join(HOME, 'vg-build', 'pass-observer-rq2', 'libSyntheticGroundTruth.so');
const FIXTURE = path.join(LAB, 'rq2-fixtures', 'wipe.c');

const TARGET = 'handle_request';
const CONTROL = 'wipe_kept';
const SYMBOLS = 'llvm.memset,memset,explicit_bzero,bzero,__memset_chk';

fs.mkdirSync(WORK, { recursive: true });
fs.mkdirSync(RESULTS, { recursive: true });

function sh(cmd, args, env = {}) {
  const r = spawnSync(cmd, args, {
    encoding: 'utf8',
    env: { ...process.env, ...env },
    maxBuffer: 64 * 1024 * 1024,
  });
  const line = [cmd, ...args].join(' ');
  const envLine = Object.keys(env).length
    ? Object.entries(env).map(([k, v]) => `${k}=${v}`).join(' ') + ' '
    : '';
  fs.appendFileSync(
    RUNLOG,
    `\n=== ${new Date().toISOString()}\n$ ${envLine}${line}\n` +
      (r.stdout || '') + (r.stderr || '') +
      `--- exit=${r.status}\n`
  );
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function die(msg) {
  console.error(`harness cannot run: ${msg}`);
  process.exit(3);
}

for (const f of [OBS, SGT, FIXTURE]) {
  if (!fs.existsSync(f)) die(`missing ${f}`);
}

// ---------------------------------------------------------------------------
// Observer log parsing

function parseSummary(outPath) {
  const p = outPath + '.summary.tsv';
  if (!fs.existsSync(p)) return null;
  const units = [];
  const hist = {};
  let stats = null;
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    if (!line) continue;
    const f = line.split('\t');
    if (f[0] === 'SUMMARY') {
      units.push({
        unit: f[1], lineage: f[2], role: f[3], clone: f[4] === '1',
        firstLossSeq: f[5] === '-' ? null : Number(f[5]),
        firstLossPass: f[6] === '-' ? null : f[6],
        firstLossPrevPass: f[7] === '-' ? null : f[7],
        firstLossPrevAfterPass: f[8] === '-' ? null : f[8],
        firstLossFnIdx: Number(f[9]),
        finalState: f[10],
        everPresent: f[11] === '1', everLost: f[12] === '1',
        everReintroduced: f[13] === '1', lossEpisodes: Number(f[14]),
        fate: f[15],
        fateSeq: f[16] === '-' ? null : Number(f[16]),
        fatePass: f[17] === '-' ? null : f[17],
        histLen: Number(f[18]),
      });
    } else if (f[0] === 'HIST') {
      (hist[f[1]] ||= []).push({
        idx: Number(f[2]), seq: Number(f[3]), phase: f[4], pass: f[5],
        count: Number(f[6]), state: f[7],
      });
    } else if (f[0] === 'STATS') {
      stats = {
        passesSeen: Number(f[1]), evRecords: Number(f[2]),
        unitsTracked: Number(f[3]), lineages: Number(f[4]),
        skipped: Number(f[5]), mode: f[6],
      };
    }
  }
  return { units, hist, stats };
}

function obsEnv(outPath, mode = 'trace', extra = {}) {
  return {
    OBS_TARGET_FN: TARGET, OBS_CONTROL_FN: CONTROL, OBS_EFFECT_SYMBOLS: SYMBOLS,
    OBS_OUT: outPath, OBS_MODE: mode, ...extra,
  };
}

/// Run opt with a pipeline, with the observer attached. Returns the parsed
/// summary, or null when the observer wrote nothing.
function runOpt(name, pipeline, inputLL, { withSGT = true, mode = 'trace' } = {}) {
  const out = path.join(WORK, `${name}.tsv`);
  for (const f of [out, out + '.summary.tsv']) if (fs.existsSync(f)) fs.unlinkSync(f);
  const args = [
    `-load-pass-plugin=${OBS}`,
    ...(withSGT ? [`-load-pass-plugin=${SGT}`] : []),
    `-passes=${pipeline}`, '-S', inputLL, '-o', path.join(WORK, `${name}.ll`),
  ];
  const r = sh('opt-18', args, {
    ...obsEnv(out, mode),
    SGT_FN: TARGET, SGT_SYMBOLS: SYMBOLS,
  });
  return { run: r, out, summary: parseSummary(out) };
}

/// The class name LLVM itself reports for a pipeline element. Read from
/// -debug-pass-manager, which is LLVM's own instrumentation and not this
/// plugin, so an expectation built from it is independent of what is measured.
function classNameOf(pipelineElement, inputLL, fn) {
  const r = sh('opt-18', [
    '-disable-verify', `-passes=function(${pipelineElement})`,
    '-debug-pass-manager', '-S', inputLL, '-o', '/dev/null',
  ]);
  const out = r.stdout + r.stderr;
  for (const m of out.matchAll(/Running pass: (\S+) on (\S+)/g)) {
    if (m[2] === fn) return m[1];
  }
  return null;
}

const checks = [];
function check(id, claim, expected, measured, ok) {
  checks.push({ id, claim, expected, measured, pass: !!ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${id}  ${claim}`);
  if (!ok) console.log(`      expected: ${expected}\n      measured: ${measured}`);
}
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const unitOf = (s, n) => (s ? s.units.find((u) => u.unit === n) : undefined);

// ---------------------------------------------------------------------------
// Stage 1. Pre-optimisation IR and the pipeline string, from the same compiler
// invocation the measurement is about.

const preLL = path.join(WORK, 'pre.ll');
const r1 = sh('clang-18', [
  '-O2', '-Xclang', '-disable-llvm-passes', '-emit-llvm', '-S',
  FIXTURE, '-o', preLL,
]);
if (r1.code !== 0) die('could not produce pre-optimisation IR');

const r2 = sh('clang-18', ['-O2', '-mllvm', '-print-pipeline-passes', '-c', FIXTURE, '-o', '/dev/null']);
if (r2.code !== 0) die('could not read the pipeline string from clang');
const CLANG_PIPE = r2.stdout.trim().split('\n').filter((l) => l.includes(',')).pop();
fs.writeFileSync(path.join(WORK, 'clang-O2-pipeline.txt'), CLANG_PIPE + '\n');

// The warning that motivates taking the string from clang: opt's own default
// pipeline for the same level is a different string.
const r3 = sh('opt-18', ['-print-pipeline-passes', "-passes=default<O2>", '-S', preLL, '-o', '/dev/null']);
const OPT_PIPE = (r3.stdout || '').trim().split('\n').filter((l) => l.includes(',')).pop() || '';
check(
  'RQ2-01',
  "clang -O2's pipeline string differs from opt -passes='default<O2>'",
  'the two strings differ',
  `clang len=${CLANG_PIPE.length} opt len=${OPT_PIPE.length} equal=${CLANG_PIPE === OPT_PIPE}`,
  CLANG_PIPE !== OPT_PIPE && OPT_PIPE.length > 0
);

// Replay fidelity: does the string, fed to opt over the pre-opt IR, reproduce
// what clang itself emits at -O2?
const replay = runOpt('replay-clang-pipeline', CLANG_PIPE, preLL, { withSGT: false });
const clangO2LL = path.join(WORK, 'clang-O2.ll');
sh('clang-18', ['-O2', '-emit-llvm', '-S', FIXTURE, '-o', clangO2LL]);
const strip = (p) => fs.readFileSync(p, 'utf8').split('\n')
  .filter((l) => !l.startsWith('; ModuleID') && !l.startsWith('source_filename'))
  .join('\n');
const replayLL = path.join(WORK, 'replay-clang-pipeline.ll');
const identical = fs.existsSync(replayLL) && strip(replayLL) === strip(clangO2LL);
check(
  'RQ2-02',
  'replaying that string over the pre-opt IR reproduces clang -O2 IR',
  'byte-identical after dropping ModuleID/source_filename',
  identical ? 'identical' : 'differs',
  identical
);

// Same attribution through clang itself, for comparison with the replay.
const directOut = path.join(WORK, 'clang-direct.tsv');
sh('clang-18', ['-O2', '-c', FIXTURE, '-o', path.join(WORK, 'direct.o'), `-fpass-plugin=${OBS}`], obsEnv(directOut));
const direct = parseSummary(directOut);
const dTarget = unitOf(direct, TARGET);
const rTarget = unitOf(replay.summary, TARGET);
check(
  'RQ2-03',
  'the replay attributes the loss to the same (pass, unit) as the real compilation',
  `clang: ${dTarget?.firstLossPass} on ${TARGET}`,
  `replay: ${rTarget?.firstLossPass} on ${rTarget?.unit}`,
  !!dTarget && !!rTarget && dTarget.firstLossPass === rTarget.firstLossPass &&
    dTarget.unit === rTarget.unit
);
check(
  'RQ2-04',
  'the real compilation blames DSEPass on handle_request, as the prototype three-channel result did',
  'DSEPass on handle_request',
  `${dTarget?.firstLossPass} on ${dTarget?.unit}`,
  dTarget?.firstLossPass === 'DSEPass' && dTarget?.unit === TARGET
);
check(
  'RQ2-05',
  'the control function kept the effect (a measurement where it did not would be broken, not a finding)',
  'wipe_kept PRESENT, never lost',
  JSON.stringify(unitOf(direct, CONTROL) &&
    { state: unitOf(direct, CONTROL).finalState, everLost: unitOf(direct, CONTROL).everLost }),
  unitOf(direct, CONTROL)?.finalState === 'PRESENT' && unitOf(direct, CONTROL)?.everLost === false
);

// ---------------------------------------------------------------------------
// Stage 2. Positional attribution, on an explicit pipeline the harness owns.

const MIN = ['sroa<modify-cfg>', 'early-cse<>', 'instcombine', 'reassociate',
             'simplifycfg', 'instsimplify', 'aggressive-instcombine', 'adce'];

const baseline = runOpt('min-baseline', `function(${MIN.join(',')})`, preLL, { withSGT: false });
const bTarget = unitOf(baseline.summary, TARGET);
check(
  'RQ2-06',
  'without an injected eraser the explicit pipeline removes nothing (the positional test has a clean baseline)',
  'handle_request PRESENT, everLost=false',
  `${bTarget?.finalState}, everLost=${bTarget?.everLost}, fnObs=${baseline.summary?.stats?.evRecords}`,
  bTarget?.finalState === 'PRESENT' && bTarget?.everLost === false
);

const POSITIONS = [1, 4, 7];
const positional = [];
for (const k of POSITIONS) {
  const list = [...MIN];
  list.splice(k, 0, 'synthetic-erase');
  const s = runOpt(`min-inject-${k}`, `function(${list.join(',')})`, preLL);
  const u = unitOf(s.summary, TARGET);
  const expectedPrev = classNameOf(MIN[k - 1], preLL, TARGET);
  positional.push({ k, expectedPrev, unit: u, pipeline: list.join(',') });
  check(
    `RQ2-07.${k}`,
    `eraser injected at index ${k}: the blamed pass is the injected one`,
    'SyntheticErasePass',
    String(u?.firstLossPass),
    u?.firstLossPass === 'SyntheticErasePass'
  );
  check(
    `RQ2-08.${k}`,
    `eraser injected at index ${k}: the reported position is ${k}`,
    String(k),
    String(u?.firstLossFnIdx),
    u?.firstLossFnIdx === k
  );
  check(
    `RQ2-09.${k}`,
    `eraser injected at index ${k}: the pass reported as running immediately before is ${MIN[k - 1]}`,
    String(expectedPrev),
    String(u?.firstLossPrevAfterPass),
    expectedPrev !== null && u?.firstLossPrevAfterPass === expectedPrev
  );
}
const idxs = positional.map((p) => p.unit?.firstLossFnIdx);
const prevs = positional.map((p) => p.unit?.firstLossPrevAfterPass);
check(
  'RQ2-10',
  'moving the cause moves the attribution: three injections, three different answers',
  'three distinct positions and three distinct predecessors',
  `positions=${JSON.stringify(idxs)} predecessors=${JSON.stringify(prevs)}`,
  new Set(idxs).size === 3 && new Set(prevs).size === 3
);

// ---------------------------------------------------------------------------
// Stage 3. The same, injected into clang's own -O2 pipeline string.

const ANCHORS = [
  { name: 'mem2reg', text: 'mem2reg,' },
  { name: 'reassociate', text: 'reassociate,' },
  { name: 'gvn<>', text: 'gvn<>,' },
];
const real = [];
for (const a of ANCHORS) {
  const occurrences = CLANG_PIPE.split(a.text).length - 1;
  if (occurrences !== 1) {
    check(`RQ2-11.${a.name}`, `anchor ${a.name} is unique in clang's -O2 pipeline`,
      '1 occurrence', String(occurrences), false);
    continue;
  }
  const pipe = CLANG_PIPE.replace(a.text, a.text + 'synthetic-erase,');
  const s = runOpt(`real-inject-${a.name.replace(/[^a-z0-9]/g, '')}`, pipe, preLL);
  const u = unitOf(s.summary, TARGET);
  const expectedPrev = classNameOf(a.name, preLL, TARGET);
  real.push({ anchor: a.name, expectedPrev, unit: u });
  check(
    `RQ2-11.${a.name}`,
    `injected after ${a.name} in clang's real pipeline: the injected pass is blamed, not DSEPass`,
    'SyntheticErasePass',
    String(u?.firstLossPass),
    u?.firstLossPass === 'SyntheticErasePass'
  );
  check(
    `RQ2-12.${a.name}`,
    `injected after ${a.name}: the pass reported as running immediately before is ${a.name}`,
    String(expectedPrev),
    String(u?.firstLossPrevAfterPass),
    expectedPrev !== null && u?.firstLossPrevAfterPass === expectedPrev
  );
}
const realSeqs = real.map((r) => r.unit?.firstLossSeq);
check(
  'RQ2-13',
  'in the real pipeline the loss moves later as the injection moves later',
  'strictly increasing sequence numbers',
  JSON.stringify(realSeqs),
  realSeqs.length === 3 && realSeqs[0] < realSeqs[1] && realSeqs[1] < realSeqs[2]
);

// ---------------------------------------------------------------------------
// Stage 4. PRESENT -> LOST -> REINTRODUCED.

const reintroPipe =
  'function(sroa<modify-cfg>,synthetic-erase,instcombine,synthetic-restore,instcombine,adce,dse)';
const reintro = runOpt('reintroduced', reintroPipe, preLL);
const reUnit = unitOf(reintro.summary, TARGET);
const reHist = (reintro.summary?.hist[TARGET] || []).map((h) => h.state);
check(
  'RQ2-14',
  'a synthetic erase-then-restore produces all three states in the history',
  '["PRESENT","LOST","REINTRODUCED"]',
  JSON.stringify(reHist),
  eq(reHist, ['PRESENT', 'LOST', 'REINTRODUCED'])
);
check(
  'RQ2-15',
  'the first loss and the final state are recorded as separate facts',
  'firstLoss=SyntheticErasePass, finalState=REINTRODUCED',
  `firstLoss=${reUnit?.firstLossPass}, finalState=${reUnit?.finalState}`,
  reUnit?.firstLossPass === 'SyntheticErasePass' && reUnit?.finalState === 'REINTRODUCED'
);
check(
  'RQ2-16',
  'the history did not stop at the first PRESENT -> LOST transition',
  'passes after the restore still observed',
  `histLen=${reUnit?.histLen}, everReintroduced=${reUnit?.everReintroduced}`,
  reUnit?.histLen === 3 && reUnit?.everReintroduced === true
);

// ---------------------------------------------------------------------------
// Stage 5. A vanished unit is not a lost property; a clone is not a return.

const delPipe = 'function(sroa<modify-cfg>),synthetic-delete-unit,function(instcombine,adce)';
const del = runOpt('unit-deleted', delPipe, preLL);
const delUnit = unitOf(del.summary, TARGET);
check(
  'RQ2-17',
  'deleting the function is recorded as the unit disappearing, not as the property being lost',
  'fate=ERASED, everLost=false',
  `fate=${delUnit?.fate}, fatePass=${delUnit?.fatePass}, everLost=${delUnit?.everLost}, finalState=${delUnit?.finalState}`,
  delUnit?.fate === 'ERASED' && delUnit?.everLost === false &&
    delUnit?.fatePass === 'SyntheticDeleteUnitPass'
);

const erasePipe = 'function(sroa<modify-cfg>,synthetic-erase),function(instcombine,adce)';
const era = runOpt('property-erased', erasePipe, preLL);
const eraUnit = unitOf(era.summary, TARGET);
check(
  'RQ2-18',
  'losing the property and losing the unit produce different records',
  'property run: everLost=true fate=LIVE; unit run: everLost=false fate=ERASED',
  `property run: everLost=${eraUnit?.everLost} fate=${eraUnit?.fate}; unit run: everLost=${delUnit?.everLost} fate=${delUnit?.fate}`,
  eraUnit?.everLost === true && eraUnit?.fate === 'LIVE' &&
    delUnit?.everLost === false && delUnit?.fate === 'ERASED'
);

const clonePipe =
  'function(sroa<modify-cfg>),synthetic-clone,synthetic-delete-unit,function(instcombine,adce)';
const clone = runOpt('clone-lineage', clonePipe, preLL);
const cloneName = `${TARGET}.llvm.4242`;
const orig = unitOf(clone.summary, TARGET);
const cl = unitOf(clone.summary, cloneName);
check(
  'RQ2-19',
  'a clone is grouped into the original lineage and starts its own history',
  `unit ${cloneName}, lineage ${TARGET}, clone=true`,
  cl ? `unit ${cl.unit}, lineage ${cl.lineage}, clone=${cl.clone}` : 'clone not tracked',
  cl?.lineage === TARGET && cl?.clone === true
);
check(
  'RQ2-20',
  'the original vanishing and the clone appearing is not reported as a reintroduction',
  'everReintroduced=false for both units',
  `${TARGET}=${orig?.everReintroduced}, ${cloneName}=${cl?.everReintroduced}`,
  orig?.everReintroduced === false && cl?.everReintroduced === false
);

// Positive control for that design: replay the same event stream the way a
// name-keyed implementation would, and show it does report the reintroduction
// that never happened. A check that cannot fail is not a check.
function naiveReplay(logPath, lineage) {
  const states = [];
  let cur = 'NOT_OBSERVED';
  const step = (present) => {
    let next;
    if (present) next = (cur === 'LOST' || cur === 'REINTRODUCED') ? 'REINTRODUCED' : 'PRESENT';
    else next = (cur === 'PRESENT' || cur === 'REINTRODUCED' || cur === 'LOST') ? 'LOST' : 'ABSENT';
    if (next !== cur) { states.push(next); cur = next; }
  };
  for (const line of fs.readFileSync(logPath, 'utf8').split('\n')) {
    const f = line.split('\t');
    if (f[0] === 'EV' && f[6] === lineage) step(Number(f[8]) > 0);
    // the naive reading: the function is gone, so the property is gone
    else if (f[0] === 'UNIT' && f[3] === lineage && f[5] === 'ERASED') step(false);
  }
  return states;
}
const naive = naiveReplay(clone.out, TARGET);
check(
  'RQ2-21',
  'positive control: a name-keyed reading of the same events does invent a reintroduction',
  'the naive replay reaches REINTRODUCED',
  JSON.stringify(naive),
  naive.includes('REINTRODUCED')
);

// ---------------------------------------------------------------------------
// Stage 6. Controls on the harness itself.

const emptyOut = path.join(WORK, 'empty.tsv');
for (const f of [emptyOut, emptyOut + '.summary.tsv']) if (fs.existsSync(f)) fs.unlinkSync(f);
sh('opt-18', [`-load-pass-plugin=${OBS}`, `-passes=default<O2>`, '-S', preLL, '-o', '/dev/null'], {
  OBS_TARGET_FN: 'no_such_function', OBS_CONTROL_FN: 'no_such_control',
  OBS_EFFECT_SYMBOLS: SYMBOLS, OBS_OUT: emptyOut, OBS_MODE: 'standard',
});
const emptySummary = parseSummary(emptyOut);
check(
  'RQ2-22',
  'positive control: a run that observed nothing says so instead of looking clean',
  'unitsTracked=0 and evRecords=0',
  JSON.stringify(emptySummary?.stats),
  emptySummary?.stats?.unitsTracked === 0 && emptySummary?.stats?.evRecords === 0
);

const rejOut = path.join(WORK, 'rejected.tsv');
if (fs.existsSync(rejOut)) fs.unlinkSync(rejOut);
const rej = sh('opt-18', [`-load-pass-plugin=${OBS}`, `-passes=default<O2>`, '-S', preLL, '-o', '/dev/null'], {
  OBS_TARGET_FN: TARGET, OBS_CONTROL_FN: CONTROL, OBS_EFFECT_SYMBOLS: SYMBOLS,
  OBS_OUT: '', OBS_MODE: 'standard',
});
check(
  'RQ2-23',
  'positive control: an incompletely configured observer refuses to install and says which field is missing',
  'a message naming OBS_OUT, and no log file',
  `stderr=${JSON.stringify(rej.stderr.trim().slice(0, 120))} logExists=${fs.existsSync(rejOut)}`,
  /OBS_OUT/.test(rej.stderr) && !fs.existsSync(rejOut)
);

// A deliberately wrong expectation must fail, or the positional checks above
// are not checking anything.
const wrongK = positional[0];
check(
  'RQ2-24',
  'positive control: asserting the wrong position for injection 1 does fail',
  'the check for position 4 against injection at 1 is false',
  `firstLossFnIdx=${wrongK?.unit?.firstLossFnIdx}, asserted 4`,
  wrongK?.unit?.firstLossFnIdx !== 4
);

// ---------------------------------------------------------------------------

const failed = checks.filter((c) => !c.pass);
const report = {
  schemaVersion: 'rq2-harness-v1',
  fixture: path.relative(RQ2, FIXTURE),
  target: TARGET, control: CONTROL, effectSymbols: SYMBOLS.split(','),
  clangPipelineChars: CLANG_PIPE.length,
  optDefaultPipelineChars: OPT_PIPE.length,
  positional: positional.map((p) => ({
    injectedAtIndex: p.k, expectedPrevPass: p.expectedPrev,
    reportedPass: p.unit?.firstLossPass ?? null,
    reportedIndex: p.unit?.firstLossFnIdx ?? null,
    reportedPrevPass: p.unit?.firstLossPrevAfterPass ?? null,
  })),
  realPipeline: real.map((r) => ({
    anchor: r.anchor, expectedPrevPass: r.expectedPrev,
    reportedPass: r.unit?.firstLossPass ?? null,
    reportedPrevPass: r.unit?.firstLossPrevAfterPass ?? null,
    reportedSeq: r.unit?.firstLossSeq ?? null,
  })),
  reintroducedHistory: reHist,
  checks,
  passed: checks.length - failed.length,
  failed: failed.length,
};
fs.writeFileSync(path.join(RESULTS, 'rq2.json'), JSON.stringify(report, null, 2) + '\n');
console.log(`\n${report.passed}/${checks.length} checks passed; report in ${path.join(RESULTS, 'rq2.json')}`);
process.exit(failed.length === 0 ? 0 : 2);

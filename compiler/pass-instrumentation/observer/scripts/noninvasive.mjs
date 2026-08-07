// Non-invasiveness measurement for the property observer.
//
// The research claim has two halves and this file records both, every run:
//
//   (i)  the compiler is not modified -- nothing is patched, nothing is
//        rebuilt; the toolchain binaries are digested before and after so that
//        "we did not touch it" is a measurement and not an assurance;
//   (ii) with the plugin loaded and without it, the object file and the linked
//        executable are byte-identical.
//
// Two rules the harness follows because breaking either makes the result
// meaningless:
//
//   * Byte-identity is only reported together with evidence that the observer
//     actually observed. A plugin that silently declined to install produces
//     identical bytes trivially, and that is the failure this pairing exists to
//     catch. A run whose log has no EV records fails; it does not pass quietly.
//
//   * There is a negative control. If nothing in this harness can make the
//     object file change, then "it did not change" is not information.
//     -opt-bisect-limit is applied to the same compilation and the object file
//     is required to differ.
//
// One mechanical note, learned by getting it wrong: OBS_OUT names one file, and
// a clang invocation with three source files runs three cc1 instances that each
// open it. The last one to run wins and its log is the one on disk. So every
// translation unit is compiled separately here, with its own OBS_OUT, and the
// objects are linked afterwards -- which is also how a build system does it.
//
// Usage:  node ~/vg-lab/pass-observer/noninvasive.mjs
// Exit:   0 all checks passed, 2 a check failed, 3 the harness could not run.

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HOME = os.homedir();
const LAB = process.env.OBS_LAB || path.join(HOME, 'vg-lab', 'pass-observer');
const WORK = path.join(LAB, 'noninvasive');
const RESULTS = path.join(LAB, 'rq2', 'results');
const RUNLOG = path.join(LAB, 'run-log.txt');
const OBS = path.join(HOME, 'vg-build', 'pass-observer', 'libPropertyObserver.so');
const FIX = path.join(LAB, 'fixtures', 'erasure');

const TARGET = 'handle_request';
const CONTROL = 'wipe_kept';
const SYMBOLS = 'llvm.memset,memset,explicit_bzero,bzero,__memset_chk';
const TUS = ['target.c', 'opaque.c', 'main.c'];

fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(WORK, { recursive: true });
fs.mkdirSync(RESULTS, { recursive: true });

function sh(cmd, args, env = {}) {
  const r = spawnSync(cmd, args, {
    encoding: 'utf8', env: { ...process.env, ...env }, maxBuffer: 64 * 1024 * 1024,
  });
  const envLine = Object.keys(env).length
    ? Object.entries(env).map(([k, v]) => `${k}=${v}`).join(' ') + ' ' : '';
  fs.appendFileSync(RUNLOG,
    `\n=== ${new Date().toISOString()}\n$ ${envLine}${[cmd, ...args].join(' ')}\n` +
    (r.stdout || '') + (r.stderr || '') + `--- exit=${r.status}\n`);
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

const sha = (p) => fs.existsSync(p)
  ? crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex') : null;
const short = (h) => (h ? h.slice(0, 16) : 'none');

const checks = [];
function check(id, claim, expected, measured, ok) {
  checks.push({ id, claim, expected, measured, pass: !!ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${id}  ${claim}`);
  if (!ok) console.log(`      expected: ${expected}\n      measured: ${measured}`);
}

if (!fs.existsSync(OBS)) { console.error(`missing ${OBS}`); process.exit(3); }

const obsEnv = (out, mode = 'standard') => ({
  OBS_TARGET_FN: TARGET, OBS_CONTROL_FN: CONTROL, OBS_EFFECT_SYMBOLS: SYMBOLS,
  OBS_OUT: out, OBS_MODE: mode,
});
const evCount = (p) => (fs.existsSync(p)
  ? fs.readFileSync(p, 'utf8').split('\n').filter((l) => l.startsWith('EV\t')).length : 0);

// --- (i) the compiler itself ------------------------------------------------
// Digested before and after everything else runs. This is what "we did not
// modify the compiler" looks like when it is measured rather than asserted.
const TOOLS = ['/usr/lib/llvm-18/bin/clang-18', '/usr/lib/llvm-18/bin/opt',
               '/usr/lib/llvm-18/lib/libLLVM.so.1'];
const toolsBefore = Object.fromEntries(TOOLS.map((t) => [t, sha(t)]));

// --- (ii) the bytes ---------------------------------------------------------

const OPTS = ['-O0', '-O1', '-O2', '-O3'];
const cells = [];

for (const O of OPTS) {
  const tag = O.replace('-', '');
  const objOff = [], objOn = [], logs = {};
  let ok = true;

  for (const tu of TUS) {
    const src = path.join(FIX, tu);
    const base = tu.replace('.c', '');
    const off = path.join(WORK, `${tag}_off_${base}.o`);
    const off2 = path.join(WORK, `${tag}_off2_${base}.o`);
    const on = path.join(WORK, `${tag}_on_${base}.o`);
    const log = path.join(WORK, `${tag}_${base}.tsv`);
    ok = sh('clang-18', [O, '-c', src, '-o', off]).code === 0 && ok;
    ok = sh('clang-18', [O, '-c', src, '-o', off2]).code === 0 && ok;
    ok = sh('clang-18', [O, '-c', src, '-o', on, `-fpass-plugin=${OBS}`], obsEnv(log)).code === 0 && ok;
    objOff.push({ tu, off: sha(off), off2: sha(off2), on: sha(on) });
    logs[tu] = evCount(log);
    objOn.push(on);
  }

  const offElf = path.join(WORK, `${tag}_off.elf`);
  const onElf = path.join(WORK, `${tag}_on.elf`);
  ok = sh('clang-18', [O, ...TUS.map((t) => path.join(WORK, `${tag}_off_${t.replace('.c', '')}.o`)), '-o', offElf]).code === 0 && ok;
  ok = sh('clang-18', [O, ...objOn, '-o', onElf]).code === 0 && ok;

  const cell = {
    opt: O, compileOk: ok, objects: objOff,
    execOff: sha(offElf), execOn: sha(onElf), observerEvRecords: logs,
  };
  cells.push(cell);

  const detOk = objOff.every((o) => o.off !== null && o.off === o.off2);
  check(`NI-01${O}`, `${O}: two plugin-free compilations of every unit agree (the comparison is not vacuous)`,
    'identical', objOff.map((o) => `${o.tu}:${short(o.off)}`).join(' '), detOk);

  const objOk = objOff.every((o) => o.off !== null && o.off === o.on);
  check(`NI-02${O}`, `${O}: every object file is byte-identical with and without the observer, AND the observer observed the unit that has the property`,
    'identical sha256 for all three units, and target.c EV records > 0',
    objOff.map((o) => `${o.tu}:${short(o.off)}/${short(o.on)}`).join(' ') + ` ev(target.c)=${logs['target.c']}`,
    objOk && logs['target.c'] > 0);

  // The AND is not decoration. A translation unit the observer had nothing to
  // say about is byte-identical for the uninteresting reason: nothing looked at
  // it, so nothing could have changed it. Measured on this fixture: of the three
  // units, only target.c ever produces records, and an executable-identity claim
  // with no observation behind it is a claim about a plugin that did not run.
  // So the executable check carries the same condition the object check does.
  check(`NI-03${O}`, `${O}: the linked executable is byte-identical, in a build where the observer did run`,
    'identical sha256 AND target.c EV records > 0',
    `off=${short(cell.execOff)} on=${short(cell.execOn)} ev(target.c)=${logs['target.c']}`,
    cell.execOff !== null && cell.execOff === cell.execOn && logs['target.c'] > 0);

  // And the trivial cells are named rather than folded in silently: this says
  // out loud which units carried an observation and which did not.
  const loadBearing = Object.entries(logs).filter(([, n]) => n > 0).map(([tu]) => tu);
  check(`NI-03b${O}`, `${O}: at least one unit's identity claim is backed by an observation`,
    'one or more units with EV records > 0',
    `load-bearing=[${loadBearing.join(' ')}] trivial=[${Object.entries(logs).filter(([, n]) => n === 0).map(([tu]) => tu).join(' ')}]`,
    loadBearing.length > 0);
}

// --- negative control -------------------------------------------------------
// Something that is supposed to change the object file, so that "unchanged"
// carries information.
const bisectOff = path.join(WORK, 'bisect_off.o');
const bisectOn = path.join(WORK, 'bisect_on.o');
const bisectLog = path.join(WORK, 'bisect.tsv');
const BISECT = ['-mllvm', '-opt-bisect-limit=40'];
sh('clang-18', ['-O2', ...BISECT, '-c', path.join(FIX, 'target.c'), '-o', bisectOff]);
sh('clang-18', ['-O2', ...BISECT, '-c', path.join(FIX, 'target.c'), '-o', bisectOn, `-fpass-plugin=${OBS}`],
   obsEnv(bisectLog, 'trace'));
const plainO2 = cells.find((c) => c.opt === '-O2').objects.find((o) => o.tu === 'target.c').off;
check('NI-04',
  'negative control: -opt-bisect-limit=40 does change the object file (so byte-identity above is a result, not an artefact)',
  'different sha256 from the plain -O2 object',
  `plain=${short(plainO2)} bisect=${short(sha(bisectOff))}`,
  sha(bisectOff) !== null && sha(bisectOff) !== plainO2);
check('NI-05',
  'under -opt-bisect-limit the observer is still non-invasive, and still observes',
  'identical sha256 and EV records > 0',
  `off=${short(sha(bisectOff))} on=${short(sha(bisectOn))} ev=${evCount(bisectLog)}`,
  sha(bisectOff) !== null && sha(bisectOff) === sha(bisectOn) && evCount(bisectLog) > 0);
const bisectSkipped = fs.existsSync(bisectLog)
  ? fs.readFileSync(bisectLog, 'utf8').split('\n')
      .filter((l) => l.startsWith('PASS\t') && l.split('\t')[2] === 'skipped').length : 0;
check('NI-06',
  'the skipped-pass callback fires under -opt-bisect-limit, so a budget-limited run is recorded as budget-limited',
  'at least one skipped-pass record',
  `skipped records=${bisectSkipped}`,
  bisectSkipped > 0);

// The attribution under a truncated budget must not silently become the
// bisect cut-off. Recorded rather than asserted: what it should be depends on
// where the budget lands, and this harness does not get to choose that.
const bisectSummaryPath = bisectLog + '.summary.tsv';
const bisectSummary = fs.existsSync(bisectSummaryPath)
  ? fs.readFileSync(bisectSummaryPath, 'utf8').split('\n')
      .filter((l) => l.startsWith('SUMMARY\t')).map((l) => l.split('\t'))
  : [];
const bisectTarget = bisectSummary.find((f) => f[1] === TARGET);

// --- (i) again, after everything --------------------------------------------
const toolsAfter = Object.fromEntries(TOOLS.map((t) => [t, sha(t)]));
const toolsUnchanged = TOOLS.every((t) => toolsBefore[t] !== null && toolsBefore[t] === toolsAfter[t]);
check('NI-07',
  'the compiler binaries are the same bytes after the measurement as before it',
  'clang-18, opt and libLLVM digests unchanged',
  TOOLS.map((t) => `${path.basename(t)}=${short(toolsBefore[t])}/${short(toolsAfter[t])}`).join(' '),
  toolsUnchanged);

// The plugin links no LLVM library: it resolves against the process that loads
// it. If it did link one it would carry a second copy of LLVM's globals, and
// "the compiler was not modified" would be a much weaker statement.
const ldd = sh('ldd', [OBS]);
const linksLLVM = /libLLVM|libclang/.test(ldd.stdout);
check('NI-08',
  'the plugin links no LLVM library of its own',
  'no libLLVM / libclang in ldd output',
  ldd.stdout.trim().split('\n').map((l) => l.trim().split(' ')[0]).join(' '),
  !linksLLVM);

const failed = checks.filter((c) => !c.pass);
const report = {
  schemaVersion: 'noninvasive-v1',
  pluginSha256: sha(OBS),
  toolchain: { before: toolsBefore, after: toolsAfter },
  cells,
  bisect: {
    limit: 40,
    objectOff: sha(bisectOff), objectOn: sha(bisectOn), plainO2Object: plainO2,
    evRecords: evCount(bisectLog), skippedPassRecords: bisectSkipped,
    targetSummary: bisectTarget ? {
      firstLossPass: bisectTarget[6] === '-' ? null : bisectTarget[6],
      finalState: bisectTarget[10], fate: bisectTarget[15],
    } : null,
  },
  checks, passed: checks.length - failed.length, failed: failed.length,
};
fs.writeFileSync(path.join(RESULTS, 'noninvasive.json'), JSON.stringify(report, null, 2) + '\n');
console.log(`\n${report.passed}/${checks.length} checks passed; report in ${path.join(RESULTS, 'noninvasive.json')}`);
if (report.bisect.targetSummary) {
  console.log(`bisect(40) attribution for ${TARGET}: ${JSON.stringify(report.bisect.targetSummary)}`);
}
process.exit(failed.length === 0 ? 0 : 2);

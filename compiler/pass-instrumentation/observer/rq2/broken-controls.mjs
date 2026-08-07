// Positive controls for the observer's two load-bearing design decisions.
//
// RQ2-14 and RQ2-17 pass. That is only worth something if they *can* fail. So
// this file takes the observer's own sources, removes exactly the mechanism
// each check is supposed to be checking, builds the result, and requires the
// check to go red. A check that stays green against a build with the mechanism
// deleted was never checking the mechanism.
//
//   variant "no-census"    the module census is removed -- the observer no
//                          longer notices that a function was deleted, so a
//                          vanished unit should look LIVE and PRESENT for ever.
//   variant "stop-at-loss" the history stops at the first PRESENT -> LOST, so
//                          a later reintroduction should be invisible.
//
// Nothing here is built from, or writes to, the repository copy of the sources.
//
// Usage:  node ~/vg-lab/pass-observer/rq2/broken-controls.mjs
// Exit:   0 both controls behaved as required, 2 one did not, 3 could not run.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HOME = os.homedir();
const LAB = process.env.OBS_LAB || path.join(HOME, 'vg-lab', 'pass-observer');
const RQ2 = path.join(LAB, 'rq2');
const WORK = path.join(LAB, 'work-broken');
const RESULTS = path.join(LAB, 'results');
const RUNLOG = path.join(LAB, 'run-log.txt');
// Where this script is, not where it was written. An absolute path baked into
// a tracked source is one machine's layout published as if it were everyone's.
const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GOOD = path.join(HOME, 'vg-build', 'pass-observer', 'libPropertyObserver.so');
const SGT = path.join(HOME, 'vg-build', 'pass-observer-rq2', 'libSyntheticGroundTruth.so');

const TARGET = 'handle_request';
const CONTROL = 'wipe_kept';
const SYMBOLS = 'llvm.memset,memset,explicit_bzero,bzero,__memset_chk';

fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(WORK, { recursive: true });
fs.mkdirSync(RESULTS, { recursive: true });

function sh(cmd, args, env = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', env: { ...process.env, ...env }, maxBuffer: 64 << 20 });
  const envLine = Object.keys(env).length
    ? Object.entries(env).map(([k, v]) => `${k}=${v}`).join(' ') + ' ' : '';
  fs.appendFileSync(RUNLOG, `\n=== ${new Date().toISOString()}\n$ ${envLine}${[cmd, ...args].join(' ')}\n` +
    (r.stdout || '') + (r.stderr || '') + `--- exit=${r.status}\n`);
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

const checks = [];
function check(id, claim, expected, measured, ok) {
  checks.push({ id, claim, expected, measured, pass: !!ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${id}  ${claim}`);
  if (!ok) console.log(`      expected: ${expected}\n      measured: ${measured}`);
}

// --- build a variant ---------------------------------------------------------
function buildVariant(name, patch) {
  const dir = path.join(WORK, name);
  fs.mkdirSync(dir, { recursive: true });
  for (const f of fs.readdirSync(SRC)) {
    if (/\.(cpp|h)$/.test(f) || f === 'CMakeLists.txt') {
      fs.writeFileSync(path.join(dir, f), fs.readFileSync(path.join(SRC, f), 'utf8').replace(/\r\n/g, '\n'));
    }
  }
  const target = path.join(dir, 'History.cpp');
  const before = fs.readFileSync(target, 'utf8');
  const after = patch(before);
  if (after === before) { console.error(`patch for ${name} did not apply`); process.exit(3); }
  fs.writeFileSync(target, after);

  const build = path.join(HOME, 'vg-build', `pass-observer-broken-${name}`);
  // Configured from scratch. A cache from a previous run records the source
  // directory it was generated for, so a build tree left over from a run under
  // a different lab root refuses to configure -- and the harness would report
  // that as "the variant did not build", which is a different sentence.
  fs.rmSync(build, { recursive: true, force: true });
  const cfg = sh('bash', ['-lc',
    `cmake -S ${dir} -B ${build} -G Ninja -DLLVM_DIR=$(llvm-config-18 --cmakedir) -DCMAKE_BUILD_TYPE=Release >/dev/null && ninja -C ${build} >/dev/null`]);
  if (cfg.code !== 0) { console.error(`variant ${name} did not build`); process.exit(3); }
  return path.join(build, 'libPropertyObserver.so');
}

const noCensus = buildVariant('no-census', (s) =>
  s.replace(
    'void Tracker::syncModule(uint64_t S, StringRef PassID, const Module &M,\n                         bool Full) {\n  if (!Out)\n    return;',
    'void Tracker::syncModule(uint64_t S, StringRef PassID, const Module &M,\n                         bool Full) {\n  (void)S; (void)PassID; (void)M; (void)Full;\n  return; // BROKEN ON PURPOSE: the census is what notices a deleted function\n  if (!Out)\n    return;'));

const stopAtLoss = buildVariant('stop-at-loss', (s) =>
  s.replace(
    '  UnitRecord &U = *UP;\n  U.HadBody = true;',
    '  UnitRecord &U = *UP;\n  if (U.HaveFirstLoss)\n    return; // BROKEN ON PURPOSE: stop at the first PRESENT -> LOST\n  U.HadBody = true;'));

// --- run one pipeline under one build ---------------------------------------
function run(obsSo, name, pipeline, mode = 'trace') {
  const out = path.join(WORK, `${name}.tsv`);
  for (const f of [out, out + '.summary.tsv']) if (fs.existsSync(f)) fs.unlinkSync(f);
  sh('opt-18', [`-load-pass-plugin=${obsSo}`, `-load-pass-plugin=${SGT}`, `-passes=${pipeline}`,
                '-S', path.join(WORK, 'pre.ll'), '-o', path.join(WORK, `${name}.ll`)],
     { OBS_TARGET_FN: TARGET, OBS_CONTROL_FN: CONTROL, OBS_EFFECT_SYMBOLS: SYMBOLS,
       OBS_OUT: out, OBS_MODE: mode, SGT_FN: TARGET, SGT_SYMBOLS: SYMBOLS });
  const rows = fs.existsSync(out + '.summary.tsv')
    ? fs.readFileSync(out + '.summary.tsv', 'utf8').split('\n').filter(Boolean).map((l) => l.split('\t')) : [];
  const s = rows.find((f) => f[0] === 'SUMMARY' && f[1] === TARGET);
  const hist = rows.filter((f) => f[0] === 'HIST' && f[1] === TARGET).map((f) => f[7]);
  return { summary: s ? { fate: s[15], fatePass: s[17], everLost: s[12] === '1', finalState: s[10] } : null, hist };
}

sh('clang-18', ['-O2', '-Xclang', '-disable-llvm-passes', '-emit-llvm', '-S',
                path.join(LAB, 'rq2-fixtures', 'wipe.c'), '-o', path.join(WORK, 'pre.ll')]);

const DEL_PIPE = 'function(sroa<modify-cfg>),synthetic-delete-unit,function(instcombine,adce)';
const REINTRO_PIPE = 'function(sroa<modify-cfg>,synthetic-erase,instcombine,synthetic-restore,instcombine,adce,dse)';

const goodDel = run(GOOD, 'good-del', DEL_PIPE);
const brokenDel = run(noCensus, 'broken-del', DEL_PIPE);
check('CTRL-01',
  'RQ2-17 fails against a build with the census removed (so it is testing the census)',
  'good build reports fate=ERASED; no-census build does not',
  `good=${JSON.stringify(goodDel.summary)} broken=${JSON.stringify(brokenDel.summary)}`,
  goodDel.summary?.fate === 'ERASED' && brokenDel.summary?.fate !== 'ERASED');

const goodRe = run(GOOD, 'good-reintro', REINTRO_PIPE);
const brokenRe = run(stopAtLoss, 'broken-reintro', REINTRO_PIPE);
check('CTRL-02',
  'RQ2-14 fails against a build that stops at the first loss (so it is testing the whole history)',
  'good build records PRESENT,LOST,REINTRODUCED; stop-at-loss build does not',
  `good=${JSON.stringify(goodRe.hist)} broken=${JSON.stringify(brokenRe.hist)}`,
  JSON.stringify(goodRe.hist) === JSON.stringify(['PRESENT', 'LOST', 'REINTRODUCED']) &&
  JSON.stringify(brokenRe.hist) !== JSON.stringify(['PRESENT', 'LOST', 'REINTRODUCED']));

const failed = checks.filter((c) => !c.pass);
fs.writeFileSync(path.join(RESULTS, 'broken-controls.json'), JSON.stringify({
  schemaVersion: 'broken-controls-v1',
  variants: { 'no-census': noCensus, 'stop-at-loss': stopAtLoss },
  observed: { goodDel, brokenDel, goodRe, brokenRe },
  checks, passed: checks.length - failed.length, failed: failed.length,
}, null, 2) + '\n');
console.log(`\n${checks.length - failed.length}/${checks.length} controls behaved as required`);
process.exit(failed.length === 0 ? 0 : 2);

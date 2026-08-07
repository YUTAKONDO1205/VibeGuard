// Coverage for the parts of the observer the RQ2 harness does not exercise:
// the loop IR unit, the three modes, and the live-branch rule.
//
// Usage:  node ~/vg-lab/pass-observer/rq2/modes.mjs
// Exit:   0 all checks passed, 2 a check failed, 3 the harness could not run.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HOME = os.homedir();
const LAB = process.env.OBS_LAB || path.join(HOME, 'vg-lab', 'pass-observer');
const RQ2 = path.join(LAB, 'rq2');
const WORK = path.join(LAB, 'work-modes');
const RESULTS = path.join(LAB, 'results');
const RUNLOG = path.join(LAB, 'run-log.txt');
const OBS = path.join(HOME, 'vg-build', 'pass-observer', 'libPropertyObserver.so');
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

const obsEnv = (out, mode, extra = {}) => ({
  OBS_TARGET_FN: TARGET, OBS_CONTROL_FN: CONTROL, OBS_EFFECT_SYMBOLS: SYMBOLS,
  OBS_OUT: out, OBS_MODE: mode, ...extra,
});
const lines = (p) => (fs.existsSync(p) ? fs.readFileSync(p, 'utf8').split('\n').filter(Boolean) : []);
function summaryOf(out) {
  const rows = lines(out + '.summary.tsv').filter((l) => l.startsWith('SUMMARY\t')).map((l) => l.split('\t'));
  const r = rows.find((f) => f[1] === TARGET);
  return r ? { firstLossPass: r[6] === '-' ? null : r[6], finalState: r[10], everPresent: r[11] === '1' } : null;
}

// --- a fixture whose effect sits inside a loop -------------------------------
const loopSrc = path.join(WORK, 'loopwipe.c');
fs.writeFileSync(loopSrc, `#include <string.h>

void get_secret(unsigned char *out, unsigned long n);
void consume(const unsigned char *p, unsigned long n);

/* Subject: the wipe is inside a loop, so loop passes see this function as a
 * loop IR unit and the observer's loop branch is exercised. */
void handle_request(unsigned long rounds) {
    unsigned char secret[32];
    for (unsigned long i = 0; i < rounds; i++) {
        get_secret(secret, sizeof secret);
        consume(secret, sizeof secret);
        memset(secret, 0, sizeof secret);
    }
}

/* Control: observable wipe, cannot be removed. */
void wipe_kept(void) {
    unsigned char secret[32];
    get_secret(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
    consume(secret, sizeof secret);
}
`);
const loopPre = path.join(WORK, 'loop-pre.ll');
if (sh('clang-18', ['-O2', '-Xclang', '-disable-llvm-passes', '-emit-llvm', '-S', loopSrc, '-o', loopPre]).code !== 0) {
  console.error('cannot build the loop fixture'); process.exit(3);
}

const loopOut = path.join(WORK, 'loop.tsv');
sh('opt-18', [`-load-pass-plugin=${OBS}`, '-passes=default<O2>', '-S', loopPre, '-o', path.join(WORK, 'loop.ll')],
   obsEnv(loopOut, 'trace'));
const evKinds = {};
for (const l of lines(loopOut)) {
  const f = l.split('\t');
  if (f[0] === 'EV') evKinds[f[4]] = (evKinds[f[4]] || 0) + 1;
}
check('MODE-01',
  'the loop IR unit is handled: a loop pass observation is recorded, not skipped',
  'at least one EV record with unitKind=loop',
  JSON.stringify(evKinds),
  (evKinds.loop || 0) > 0);
const skipCount = lines(loopOut).filter((l) => l.startsWith('SKIP\t')).length;
check('MODE-02',
  'all four IR unit kinds of the new pass manager are decoded; nothing fell through to SKIP',
  'module, cgscc, function and loop all present, SKIP count 0',
  `kinds=${Object.keys(evKinds).sort().join(',')} skip=${skipCount}`,
  ['module', 'cgscc', 'function', 'loop'].every((k) => (evKinds[k] || 0) > 0) && skipCount === 0);

// --- the three modes ---------------------------------------------------------
const erasureFix = path.join(LAB, 'fixtures', 'erasure', 'target.c');
const modeOut = {};
for (const m of ['standard', 'trace']) {
  const out = path.join(WORK, `mode-${m}.tsv`);
  sh('clang-18', ['-O2', '-c', erasureFix, '-o', path.join(WORK, `mode-${m}.o`), `-fpass-plugin=${OBS}`],
     obsEnv(out, m));
  modeOut[m] = { out, ev: lines(out).filter((l) => l.startsWith('EV\t')).length,
                 pass: lines(out).filter((l) => l.startsWith('PASS\t')).length,
                 summary: summaryOf(out) };
}
check('MODE-03',
  'standard and trace attribute the loss identically; only the volume of record differs',
  'same firstLossPass, standard strictly smaller',
  `standard=${JSON.stringify(modeOut.standard.summary)} ev=${modeOut.standard.ev}/pass=${modeOut.standard.pass}; ` +
  `trace=${JSON.stringify(modeOut.trace.summary)} ev=${modeOut.trace.ev}/pass=${modeOut.trace.pass}`,
  modeOut.standard.summary?.firstLossPass === modeOut.trace.summary?.firstLossPass &&
  modeOut.standard.summary?.firstLossPass === 'DSEPass' &&
  modeOut.standard.ev < modeOut.trace.ev && modeOut.standard.pass === 0 && modeOut.trace.pass > 0);

const forOut = path.join(WORK, 'forensic.tsv');
const snapDir = path.join(WORK, 'snapshots');
fs.mkdirSync(snapDir, { recursive: true });
const wipePre = path.join(WORK, 'wipe-pre.ll');
sh('clang-18', ['-O2', '-Xclang', '-disable-llvm-passes', '-emit-llvm', '-S',
                path.join(LAB, 'rq2-fixtures', 'wipe.c'), '-o', wipePre]);
sh('opt-18', [`-load-pass-plugin=${OBS}`, `-load-pass-plugin=${SGT}`,
              '-passes=function(sroa<modify-cfg>,synthetic-erase,instcombine,synthetic-restore)',
              '-S', wipePre, '-o', path.join(WORK, 'forensic.ll')],
   { ...obsEnv(forOut, 'forensic', { OBS_SNAPSHOT_DIR: snapDir }), SGT_FN: TARGET, SGT_SYMBOLS: SYMBOLS });
const snaps = lines(forOut).filter((l) => l.startsWith('SNAP\t')).map((l) => l.split('\t')[5]);
const snapsOnDisk = snaps.filter((p) => fs.existsSync(p));
const bothPresent = snapsOnDisk.every((p) => {
  const t = fs.readFileSync(p, 'utf8');
  return t.includes(`define`) && t.includes(TARGET) && t.includes(CONTROL);
});
check('MODE-04',
  'forensic mode writes the IR at every boundary where the count changed, with the control in the same file',
  'at least two snapshots on disk, each containing subject and control',
  `snapRecords=${snaps.length} onDisk=${snapsOnDisk.length} bothPresent=${bothPresent}`,
  snaps.length >= 2 && snapsOnDisk.length === snaps.length && bothPresent);

const forensicNoDir = sh('opt-18', [`-load-pass-plugin=${OBS}`, '-passes=default<O2>', '-S', wipePre, '-o', '/dev/null'],
  { OBS_TARGET_FN: TARGET, OBS_CONTROL_FN: CONTROL, OBS_EFFECT_SYMBOLS: SYMBOLS,
    OBS_OUT: path.join(WORK, 'forensic-nodir.tsv'), OBS_MODE: 'forensic' });
check('MODE-05',
  'positive control: forensic mode without a snapshot directory is refused rather than silently degraded to trace',
  'a message naming OBS_SNAPSHOT_DIR, and no log file',
  `stderr=${JSON.stringify(forensicNoDir.stderr.trim().slice(0, 100))} log=${fs.existsSync(path.join(WORK, 'forensic-nodir.tsv'))}`,
  /OBS_SNAPSHOT_DIR/.test(forensicNoDir.stderr) && !fs.existsSync(path.join(WORK, 'forensic-nodir.tsv')));

// --- the live-branch rule ----------------------------------------------------
// handle_request has no conditional branch at all, so under the rule its effect
// does not count. That is the whole behaviour of the flag, and it is visible.
const lbOut = path.join(WORK, 'livebranch.tsv');
sh('clang-18', ['-O2', '-c', erasureFix, '-o', path.join(WORK, 'lb.o'), `-fpass-plugin=${OBS}`],
   obsEnv(lbOut, 'standard', { OBS_REQUIRE_LIVE_BRANCH: '1' }));
const lb = summaryOf(lbOut);
check('MODE-06',
  'OBS_REQUIRE_LIVE_BRANCH changes what counts as the effect (a branch-guarded property is not counted once the branch is gone)',
  'without the flag PRESENT then LOST; with it, never PRESENT',
  `withFlag=${JSON.stringify(lb)} withoutFlag=${JSON.stringify(modeOut.standard.summary)}`,
  lb?.everPresent === false && lb?.finalState === 'ABSENT' &&
  modeOut.standard.summary?.everPresent === true);

const failed = checks.filter((c) => !c.pass);
fs.writeFileSync(path.join(RESULTS, 'modes.json'),
  JSON.stringify({ schemaVersion: 'modes-v1', evKinds, checks, passed: checks.length - failed.length, failed: failed.length }, null, 2) + '\n');
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed; report in ${path.join(RESULTS, 'modes.json')}`);
process.exit(failed.length === 0 ? 0 : 2);

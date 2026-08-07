// Does this plugin agree with two channels that are not this plugin?
//
// The observer walks the IR object model from inside the pass manager. The two
// channels below read what the compiler prints (-print-after-all) and what the
// pass-budget machinery does (-opt-bisect-limit). Three different mechanisms,
// so an artefact of one cannot manufacture agreement with the others -- which
// is the only reason the agreement is worth anything.
//
// Nothing here reads a previously recorded result; all three are measured now.
//
// Usage:  node ~/vg-lab/pass-observer/crosscheck.mjs
// Exit:   0 the three agree, 2 they do not, 3 a channel could not be read.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HOME = os.homedir();
const LAB = process.env.OBS_LAB || path.join(HOME, 'vg-lab', 'pass-observer');
const WORK = path.join(LAB, 'crosscheck');
const RESULTS = path.join(LAB, 'rq2', 'results');
const RUNLOG = path.join(LAB, 'run-log.txt');
const OBS = path.join(HOME, 'vg-build', 'pass-observer', 'libPropertyObserver.so');
const FIX = path.join(LAB, 'fixtures', 'erasure', 'target.c');

const TARGET = 'handle_request';
const CONTROL = 'wipe_kept';
const SYMBOLS = 'llvm.memset,memset,explicit_bzero,bzero,__memset_chk';

fs.rmSync(WORK, { recursive: true, force: true });
fs.mkdirSync(WORK, { recursive: true });

function sh(cmd, args, env = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', env: { ...process.env, ...env }, maxBuffer: 256 << 20 });
  const envLine = Object.keys(env).length
    ? Object.entries(env).map(([k, v]) => `${k}=${v}`).join(' ') + ' ' : '';
  fs.appendFileSync(RUNLOG, `\n=== ${new Date().toISOString()}\n$ ${envLine}${[cmd, ...args].join(' ')}\n` +
    `[output ${((r.stdout || '').length + (r.stderr || '').length)} bytes suppressed in log]\n--- exit=${r.status}\n`);
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

const checks = [];
function check(id, claim, expected, measured, ok) {
  checks.push({ id, claim, expected, measured, pass: !!ok });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${id}  ${claim}`);
  if (!ok) console.log(`      expected: ${expected}\n      measured: ${measured}`);
}

// --- channel 1: what the compiler prints ------------------------------------
// The oracle rule still applies here: count call sites, not the string
// "memset". A `declare` left behind by a deleted call would otherwise keep the
// effect looking present until something sweeps declarations away.
const paa = sh('clang-18', ['-O2', '-c', FIX, '-o', '/dev/null',
  '-mllvm', '-print-after-all', '-mllvm', `-filter-print-funcs=${TARGET}`]);
const dumps = [];
for (const part of (paa.stderr).split(/^; \*\*\* IR Dump After /m).slice(1)) {
  const head = part.slice(0, part.indexOf('\n'));
  const m = head.match(/^(\S+)\s+on\s+(\S+)/);
  if (!m || m[2] !== TARGET) continue;
  const body = part.slice(part.indexOf('\n'));
  const hasCall = /^\s*(tail\s+)?call[^\n]*@(llvm\.memset|memset|explicit_bzero|bzero|__memset_chk)/m.test(body);
  dumps.push({ pass: m[1], hasCall });
}
let printAfterAll = null;
for (let i = 0; i < dumps.length; i++) {
  if (!dumps[i].hasCall && (i === 0 || dumps[i - 1].hasCall)) { printAfterAll = dumps[i].pass; break; }
}

// --- channel 2: the pass budget ---------------------------------------------
function memsetGoneAt(limit) {
  const r = sh('clang-18', ['-O2', '-emit-llvm', '-S', FIX, '-o', '-',
    '-mllvm', `-opt-bisect-limit=${limit}`]);
  const body = r.stdout.split(/^define /m).find((s) => s.includes(`@${TARGET}(`)) || '';
  const has = /^\s*(tail\s+)?call[^\n]*@(llvm\.memset|memset|explicit_bzero|bzero|__memset_chk)/m.test(body);
  return { gone: !has, stderr: r.stderr };
}
let lo = 0, hi = 600;
if (!memsetGoneAt(hi).gone) { console.error('the effect survives the whole pipeline; nothing to bisect'); process.exit(3); }
while (lo < hi) {
  const mid = (lo + hi) >> 1;
  if (memsetGoneAt(mid).gone) hi = mid; else lo = mid + 1;
}
const boundary = memsetGoneAt(lo);
const bisectLine = (boundary.stderr.match(new RegExp(`^BISECT: running pass \\(${lo}\\) (.+)$`, 'm')) || [])[1] || null;
// "BISECT: running pass (66) DSEPass on handle_request" -- the unit is named
// after " on ", so the pass is everything before it.
const bisectMatch = bisectLine ? bisectLine.match(/^(.*?)\s+on\s+(.*)$/) : null;
const optBisect = bisectMatch ? bisectMatch[1].trim() : bisectLine;
const optBisectUnit = bisectMatch ? bisectMatch[2].trim() : null;

// --- channel 3: this plugin --------------------------------------------------
const out = path.join(WORK, 'plugin.tsv');
sh('clang-18', ['-O2', '-c', FIX, '-o', path.join(WORK, 'target.o'), `-fpass-plugin=${OBS}`], {
  OBS_TARGET_FN: TARGET, OBS_CONTROL_FN: CONTROL, OBS_EFFECT_SYMBOLS: SYMBOLS,
  OBS_OUT: out, OBS_MODE: 'standard',
});
const srow = fs.readFileSync(out + '.summary.tsv', 'utf8').split('\n')
  .filter((l) => l.startsWith('SUMMARY\t')).map((l) => l.split('\t')).find((f) => f[1] === TARGET);
const plugin = srow && srow[6] !== '-' ? { pass: srow[6], unit: srow[1] } : null;

console.log(`  print-after-all : ${printAfterAll}`);
console.log(`  opt-bisect      : ${optBisect} on ${optBisectUnit}  (step ${lo})`);
console.log(`  pass plugin     : ${plugin?.pass} on ${plugin?.unit}`);

check('XC-01', 'the plugin and -print-after-all name the same pass',
  String(printAfterAll), String(plugin?.pass),
  printAfterAll !== null && plugin?.pass === printAfterAll);
check('XC-02', 'the plugin and -opt-bisect-limit name the same pass and the same unit',
  `${optBisect} on ${optBisectUnit}`, `${plugin?.pass} on ${plugin?.unit}`,
  optBisect !== null && optBisect === plugin?.pass && optBisectUnit === plugin?.unit);

check('XC-03', 'all three channels agree, and they agree on handle_request',
  'one pass, one unit, three channels',
  `paa=${printAfterAll} bisect=${optBisect}/${optBisectUnit} plugin=${plugin?.pass}/${plugin?.unit}`,
  plugin?.unit === TARGET && printAfterAll === plugin?.pass && optBisect === plugin?.pass && optBisectUnit === plugin?.unit);

const failed = checks.filter((c) => !c.pass);
fs.writeFileSync(path.join(RESULTS, 'crosscheck.json'), JSON.stringify({
  schemaVersion: 'crosscheck-v1', fixture: 'erasure/target.c', opt: '-O2',
  printAfterAll, optBisect: { pass: optBisect, unit: optBisectUnit, step: lo, rawLine: bisectLine },
  passPlugin: plugin, dumpsSeen: dumps.length, checks,
  passed: checks.length - failed.length, failed: failed.length,
}, null, 2) + '\n');
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed; report in ${path.join(RESULTS, 'crosscheck.json')}`);
process.exit(failed.length === 0 ? 0 : 2);

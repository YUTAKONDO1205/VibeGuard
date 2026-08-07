#!/usr/bin/env node
// The acceptance run: build every control, build every baseline they need,
// classify them, and check each result against what it was built to show.
//
//   node run-controls.mjs [--lab ~/vg-lab/elf-verifier] [--build ~/vg-build/elf-verifier]
//                         [--baseline-dir ~/vg-lab/introduction-analysis/baseline]
//                         [--marker-plugin <libMarkerPass.so>]
//
// Exit 0 only if every case matched its expectation. A case that could not be
// run is reported as SKIPPED and fails the run, because "we did not run the
// positive control" and "the positive control passed" are the two claims this
// file exists to keep apart.

import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync, appendFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { writeControls, NEGATIVE_CONTROLS, POSITIVE_CONTROL, CONSTRUCTOR_ATTRIBUTE } from './controls.mjs';
import { buildBaseline, DEFAULT_BASELINE_DIR } from './baseline.mjs';
import { classify } from './classify.mjs';
import { readElf, decidePie, decideRelroFull, decideNx } from './lib/elf.mjs';

const args = process.argv.slice(2);
const opt = (n, d) => {
  const i = args.indexOf(n);
  return i === -1 ? d : args[i + 1];
};

const LAB = opt('--lab', join(homedir(), 'vg-lab', 'elf-verifier'));
const BUILD = opt('--build', join(homedir(), 'vg-build', 'elf-verifier'));
const BASE = opt('--baseline-dir', DEFAULT_BASELINE_DIR);
const CXX = opt('--cxx', 'clang++-18');
const MARKER = opt('--marker-plugin', join(homedir(), 'vg-build', 'elf-verifier', 'marker', 'libMarkerPass.so'));
const SRC = join(LAB, 'controls');
const OBJ = join(BUILD, 'controls');
const LOG = join(LAB, 'run-log.txt');

mkdirSync(LAB, { recursive: true });
mkdirSync(OBJ, { recursive: true });

function log(line) {
  appendFileSync(LOG, `${line}\n`, 'utf8');
}

function sh(cmd, argv, { allowFail = false } = {}) {
  log(`\n=== ${new Date().toISOString()} ===\n$ ${cmd} ${argv.join(' ')}`);
  try {
    const out = execFileSync(cmd, argv, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    if (out.trim()) log(out.trimEnd());
    log('[exit 0]');
    return { code: 0, out };
  } catch (e) {
    const out = `${e.stdout ?? ''}${e.stderr ?? ''}`;
    if (out.trim()) log(out.trimEnd());
    log(`[exit ${e.status ?? 1}]`);
    if (!allowFail) throw new Error(`${cmd} failed (${e.status}): ${out.slice(0, 400)}`);
    return { code: e.status ?? 1, out };
  }
}

const cases = [];
function record(id, what, expectation, got, pass, extra = {}) {
  cases.push({ id, what, expectation, got, pass: pass ? 1 : 0, ...extra });
  const tag = pass ? 'PASS' : 'FAIL';
  const line = `${tag}  ${id.padEnd(10)} ${what}\n        expected: ${expectation}\n        observed: ${got}`;
  console.log(line);
  log(line);
}
function skip(id, what, why) {
  cases.push({ id, what, expectation: 'the case runs at all', got: `SKIPPED: ${why}`, pass: 0, skipped: 1 });
  const line = `SKIP  ${id.padEnd(10)} ${what}\n        ${why}`;
  console.log(line);
  log(line);
}

// ---------------------------------------------------------------- 0. sources
writeControls(SRC);

// -------------------------------------------------------------- 1. baselines
const FLAGS_PLAIN = ['-O0', '-g0'];
const FLAGS_ASAN = ['-O0', '-g0', '-fsanitize=address'];
const FLAGS_O3 = ['-O3', '-g0'];
const FLAGS_PROT = ['-O0', '-g0', '-fstack-protector-strong', '-D_FORTIFY_SOURCE=2'];

const builtBaselines = [];
for (const [flags, form] of [
  [FLAGS_PLAIN, 'exec-pie'],
  [FLAGS_PLAIN, 'object'],
  [FLAGS_ASAN, 'exec-pie'],
  [FLAGS_PROT, 'exec-pie'],
]) {
  log(`\n=== baseline ${form} [${flags.join(' ')}] ===`);
  const r = buildBaseline({ flags, form, outDir: BASE, cxx: CXX, workDir: join(BUILD, 'baseline-work') });
  builtBaselines.push({ form, flags, keyId: r.key.id, evidenceDigest: r.record.evidenceDigest, counts: r.record.counts });
  log(`baseline ${form} [${flags.join(' ')}] key=${r.key.id} digest=${r.record.evidenceDigest} counts=${JSON.stringify(r.record.counts)}`);
}
// -O3 is deliberately NOT built: case POS-4 needs a key with no baseline.

// ------------------------------------------------------- 2. build every case
function compileLink(name, srcFile, flags, { objOnly = false, extra = [] } = {}) {
  const o = join(OBJ, `${name}.o`);
  sh(CXX, [...flags, ...extra, '-c', join(SRC, srcFile), '-o', o]);
  if (objOnly) return { obj: o, exe: null };
  const e = join(OBJ, `${name}.out`);
  sh(CXX, [...flags, ...extra, o, '-o', e]);
  return { obj: o, exe: e };
}

// --------------------------------------------- 3. negative controls: six kinds
for (const c of NEGATIVE_CONTROLS) {
  const flags = c.flags.includes('-fsanitize=address') ? FLAGS_ASAN : FLAGS_PLAIN;
  const built = compileLink(c.name, c.file, flags);
  const r = classify({
    artifact: built.exe,
    sources: [join(SRC, c.file)],
    compileFlags: flags,
    baselineDir: BASE,
    cxx: CXX,
  });
  const s = r.summary.byVerdict;
  const nonBaseline = r.items.filter((i) => i.verdict === 'Explained' && i.rule !== 'baseline-literal').length;
  record(
    `NEG-${c.name}`,
    `${c.file} → ${c.why}`,
    'Unexplained=0 and Unresolved=0',
    `Unexplained=${s.Unexplained} Unresolved=${s.Unresolved} Explained=${s.Explained} ` +
      `(of which ${nonBaseline} decided by a rule other than baseline-literal), exit ${r.exitCode}`,
    s.Unexplained === 0 && s.Unresolved === 0 && r.exitCode === 0,
    { unexplained: r.items.filter((i) => i.verdict === 'Unexplained').map((i) => i.name) },
  );
}

// -------------------------------- 4. POS-1: a symbol put into an object by hand
{
  const base = compileLink('inject_base', POSITIVE_CONTROL.file, FLAGS_PLAIN, { objOnly: true });
  const injected = join(OBJ, 'inject_objcopy.o');
  const probe = '__unaccounted_objcopy_probe';
  sh('llvm-objcopy-18', [`--add-symbol=${probe}=.text:0,global,function`, base.obj, injected]);
  const r = classify({
    artifact: injected,
    sources: [join(SRC, POSITIVE_CONTROL.file)],
    compileFlags: FLAGS_PLAIN,
    baselineDir: BASE,
    cxx: CXX,
  });
  const un = r.items.filter((i) => i.verdict === 'Unexplained').map((i) => i.name);
  record(
    'POS-1',
    'one symbol added to an object after compilation',
    `exactly 1 Unexplained item, named ${probe}, VG-INTRO-001, exit 2`,
    `Unexplained=${un.length} [${un.join(', ')}] findings=[${r.findings.map((f) => f.id).join(',')}] exit ${r.exitCode}`,
    un.length === 1 && un[0] === probe && r.findings.length === 1 && r.findings[0].id === 'VG-INTRO-001' && r.exitCode === 2,
  );
}

// ------------------------------ 5. POS-2: a real pass plugin, really loaded
if (!existsSync(MARKER)) {
  skip('POS-2', 'an LLVM pass plugin injects into a real compilation', `no plugin at ${MARKER}`);
} else {
  const o = join(OBJ, 'inject_pass.o');
  const e = join(OBJ, 'inject_pass.out');
  sh(CXX, [...FLAGS_PLAIN, `-fpass-plugin=${MARKER}`, '-c', join(SRC, POSITIVE_CONTROL.file), '-o', o]);
  sh(CXX, [...FLAGS_PLAIN, `-fpass-plugin=${MARKER}`, o, '-o', e]);
  // Classified against the flags the build *declares*, which do not mention the
  // plugin. That is the threat: the recorded configuration does not account for
  // what is in the artefact.
  const r = classify({
    artifact: e,
    sources: [join(SRC, POSITIVE_CONTROL.file)],
    compileFlags: FLAGS_PLAIN,
    baselineDir: BASE,
    cxx: CXX,
  });
  const un = r.items.filter((i) => i.verdict === 'Unexplained').map((i) => i.name);
  record(
    'POS-2',
    'a pass plugin the declared flags do not mention injects a symbol, a global and a section',
    'the injected symbol is named among the Unexplained items, exit 2',
    `Unexplained=${un.length} [${un.join(', ')}] exit ${r.exitCode}`,
    un.includes('__marker_pass_present') && r.exitCode === 2,
  );
}

// ------- 6. POS-3: an executable section and an .init_array slot, added by hand
{
  const asmObj = join(OBJ, 'injection.o');
  sh(CXX, [...FLAGS_PLAIN, '-c', join(SRC, 'injection.s'), '-o', asmObj]);
  const merged = join(OBJ, 'inject_asm.o');
  sh('ld', ['-r', join(OBJ, 'inject_base.o'), asmObj, '-o', merged]);
  const exe = join(OBJ, 'inject_asm.out');
  sh(CXX, [...FLAGS_PLAIN, merged, '-o', exe]);
  const r = classify({
    artifact: exe,
    sources: [join(SRC, POSITIVE_CONTROL.file)],
    compileFlags: FLAGS_PLAIN,
    baselineDir: BASE,
    cxx: CXX,
  });
  const ids = r.findings.map((f) => f.id).sort();
  const init = r.findings.find((f) => f.id === 'VG-INTRO-003');
  const exec = r.findings.find((f) => f.id === 'VG-INTRO-004');
  record(
    'POS-3',
    'an executable section and an .init_array slot added to the link',
    'VG-INTRO-003 naming __unaccounted_init_probe and VG-INTRO-004 naming .injected_exec',
    `findings=[${ids.join(',')}] init=${init ? init.detail.slice(0, 60) : 'none'} exec=${exec ? exec.detail.slice(0, 50) : 'none'} exit ${r.exitCode}`,
    Boolean(init && /__unaccounted_init_probe/.test(init.detail)) &&
      Boolean(exec && /\.injected_exec/.test(exec.detail)) &&
      r.exitCode === 2,
  );

  // NX has to still hold, or the positive control changed two things at once.
  const elf = readElf(exe);
  const nx = decideNx(elf);
  record(
    'POS-3nx',
    'the injection did not also turn the stack executable',
    'nx=true, so POS-3 isolates the introduction',
    `nx=${nx.value} decided by ${nx.decidedBy.map((d) => d.field).join(' + ')}`,
    nx.value === true,
  );
}

// ------------------- 7. POS-4: an -O3 artefact against an -O0-only baseline set
{
  const built = compileLink('template_O3', 'ctl_template.cc', FLAGS_O3);
  const fail = classify({
    artifact: built.exe,
    sources: [join(SRC, 'ctl_template.cc')],
    compileFlags: FLAGS_O3,
    baselineDir: BASE,
    onKeyMismatch: 'fail',
    cxx: CXX,
  });
  record(
    'POS-4a',
    'an -O3 artefact when only an -O0 baseline exists (default mode)',
    'baseline state key-mismatch and exit 3 — no deduction attempted',
    `baseline=${fail.record.baseline.state} exit ${fail.exitCode} ` +
      `(have instead: ${fail.record.baseline.availableForThisToolchain.map((a) => `${a.form}[${a.flags.join(' ')}]`).join(' ')})`,
    fail.record.baseline.state === 'key-mismatch' && fail.exitCode === 3,
  );

  const soft = classify({
    artifact: built.exe,
    sources: [join(SRC, 'ctl_template.cc')],
    compileFlags: FLAGS_O3,
    baselineDir: BASE,
    onKeyMismatch: 'unresolved',
    cxx: CXX,
  });
  const s = soft.summary.byVerdict;
  record(
    'POS-4b',
    'the same -O3 artefact with the baseline rule marked unavailable',
    'Unresolved > 0 and Unexplained = 0 — abstains rather than deducting or accusing',
    `Unexplained=${s.Unexplained} Unresolved=${s.Unresolved} Explained=${s.Explained} exit ${soft.exitCode}`,
    s.Unresolved > 0 && s.Unexplained === 0 && soft.exitCode === 3,
  );
}

// -- 8. POS-5: the same artefact against the right and the wrong flag-set key
{
  const asanExe = join(OBJ, 'sanitizer-address.out');
  const right = classify({
    artifact: asanExe,
    sources: [join(SRC, 'ctl_asan.cc')],
    compileFlags: FLAGS_ASAN,
    baselineDir: BASE,
    cxx: CXX,
  });
  const wrong = classify({
    artifact: asanExe,
    sources: [join(SRC, 'ctl_asan.cc')],
    compileFlags: FLAGS_PLAIN,
    baselineDir: BASE,
    onKeyMismatch: 'unresolved',
    cxx: CXX,
  });
  // What this case is for: the flag component of the key has to change the
  // *content* of the deduction, not just the digest. The wrong key here is not
  // a missing baseline — a baseline for [-O0 -g0] exec-pie exists and is found.
  // It is the baseline for a build that never asked for a sanitiser, and the
  // right behaviour is to report the sanitiser material rather than write it
  // off. Had the baseline been keyed on the toolchain alone, these 5890 items
  // would have been deducted in silence.
  const wrongUn = wrong.summary.byVerdict.Unexplained;
  record(
    'POS-5',
    'one -fsanitize=address artefact, classified under its own flag set and under a declared flag set that omits the sanitiser',
    'the right key explains all of it; the wrong key reports the sanitiser material instead of deducting it',
    `right: Explained=${right.summary.byVerdict.Explained} Unexplained=${right.summary.byVerdict.Unexplained} exit ${right.exitCode}  |  ` +
      `wrong (baseline found, different flag set): Explained=${wrong.summary.byVerdict.Explained} ` +
      `Unresolved=${wrong.summary.byVerdict.Unresolved} Unexplained=${wrongUn} exit ${wrong.exitCode}  ` +
      `— the flag component of the key moved ${right.summary.byVerdict.Explained - wrong.summary.byVerdict.Explained} items`,
    right.summary.byVerdict.Unexplained === 0 && right.exitCode === 0 && wrongUn > 1000 && wrong.exitCode === 2,
  );
}

// ---------- 9. POS-6: the source universe is load-bearing, not decorative
{
  const exe = join(OBJ, 'thunk.out');
  const withSrc = classify({ artifact: exe, sources: [join(SRC, 'ctl_thunk.cc')], compileFlags: FLAGS_PLAIN, baselineDir: BASE, cxx: CXX });
  const without = classify({ artifact: exe, sources: [], compileFlags: FLAGS_PLAIN, baselineDir: BASE, cxx: CXX });
  record(
    'POS-6',
    'the thunk control classified with and without its declared source',
    'without the source the source-attributed verdicts become Unresolved, not Explained and not Unexplained',
    `with: Explained=${withSrc.summary.byVerdict.Explained} Unresolved=${withSrc.summary.byVerdict.Unresolved}  |  ` +
      `without: Explained=${without.summary.byVerdict.Explained} Unresolved=${without.summary.byVerdict.Unresolved} Unexplained=${without.summary.byVerdict.Unexplained}`,
    withSrc.summary.byVerdict.Unresolved === 0 &&
      without.summary.byVerdict.Unresolved > 0 &&
      without.summary.byVerdict.Unexplained === 0 &&
      without.exitCode === 3,
  );
}

// ----------- 9b. POS-7: an external call into a library the policy excludes
{
  const exe = join(OBJ, 'vtable-rtti.out');
  const open = classify({ artifact: exe, sources: [join(SRC, 'ctl_vtable.cc')], compileFlags: FLAGS_PLAIN, baselineDir: BASE, cxx: CXX });
  // libstdc++ removed from the allowlist. `operator new`, `operator delete`
  // and __dynamic_cast still resolve there — the library is on DT_NEEDED — but
  // the policy no longer authorises it, so resolving is not the same as being
  // permitted.
  const shut = classify({
    artifact: exe,
    sources: [join(SRC, 'ctl_vtable.cc')],
    compileFlags: FLAGS_PLAIN,
    baselineDir: BASE,
    allowedLibs: ['libc.so.6', 'libm.so.6'],
    cxx: CXX,
  });
  const f2 = shut.findings.filter((f) => f.id === 'VG-INTRO-002').map((f) => f.detail.split(' ')[0]);
  record(
    'POS-7',
    'the same artefact with libstdc++ removed from the authorised dependency list',
    'VG-INTRO-002 for each call that resolves only in the excluded library, and 0 with the library allowed',
    `allowed: Unexplained=${open.summary.byVerdict.Unexplained} exit ${open.exitCode}  |  ` +
      `excluded: VG-INTRO-002 x${f2.length} [${f2.join(', ')}] exit ${shut.exitCode}`,
    open.summary.byVerdict.Unexplained === 0 && f2.length === 4 && f2.includes('_Znwm') && shut.exitCode === 2,
  );
}

// ------ 10. BND-1: a source that legitimately asks for pre-main code
{
  const built = compileLink('ctorattr', CONSTRUCTOR_ATTRIBUTE.file, FLAGS_PLAIN);
  const r = classify({ artifact: built.exe, sources: [join(SRC, CONSTRUCTOR_ATTRIBUTE.file)], compileFlags: FLAGS_PLAIN, baselineDir: BASE, cxx: CXX });
  const s = r.summary.byVerdict;
  record(
    'BND-1',
    '__attribute__((constructor)) in the declared source',
    'Unexplained=0 — the initialiser rule accepts a constructor the source asked for',
    `Unexplained=${s.Unexplained} Unresolved=${s.Unresolved} exit ${r.exitCode}`,
    s.Unexplained === 0 && s.Unresolved === 0,
  );
}

// ------ 10b. BND-2: an object file whose source calls into another unit
//
// Every control above is a linked C++ executable, where libstdc++ resolves what
// the source names. That left a whole shape untested, and it is the ordinary
// one: compile a C file that declares a function defined elsewhere and calls
// it, stop before the link, and the symbol is undefined with no library to
// resolve it. Measured before this control existed: VG-INTRO-002 against the
// program's own call, because the undefined chain had no rule that could say
// "the source asked for this". A checker that accuses an unremarkable two-file
// C program is not usable, and nothing here would have said so.
{
  const src = join(LAB, 'bnd2.c');
  writeFileSync(src, [
    '/* Declared here, defined in another translation unit, called from here. */',
    'void other_unit(unsigned char *p, unsigned long n);',
    'void entry(void) { unsigned char buf[16]; other_unit(buf, sizeof buf); }',
    '',
  ].join(String.fromCharCode(10)));
  const obj = join(OBJ, 'bnd2.o');
  sh('clang-18', ['-O2', '-c', src, '-o', obj]);
  // The baseline for this (toolchain, flags, form) has to exist or the verifier
  // abstains, which would make this control pass for the wrong reason.
  buildBaseline({ flags: ['-O2'], form: 'object', outDir: BASE, cxx: 'clang-18' });
  const r = classify({ artifact: obj, sources: [src], compileFlags: ['-O2'], baselineDir: BASE, cxx: 'clang-18' });
  const s = r.summary.byVerdict;
  const named = r.items.filter((i) => i.verdict !== 'Explained').map((i) => i.name);
  record(
    'BND-2',
    'a C object whose source declares and calls a function from another unit',
    'Unexplained=0 and Unresolved=0 — an undefined symbol the source named is source-derived',
    `Unexplained=${s.Unexplained} Unresolved=${s.Unresolved} Explained=${s.Explained} exit ${r.exitCode}` +
      (named.length ? ` [${named.join(', ')}]` : ''),
    s.Unexplained === 0 && s.Unresolved === 0 && r.exitCode === 0,
  );
}

// -------- 11. TOOLS: why the structural fields are read instead of the wording
{
  const exe = join(OBJ, 'template-instantiation.out');
  const elf = readElf(exe);
  const pie = decidePie(elf);
  const relro = decideRelroFull(elf);
  const gnu = sh('readelf', ['-h', exe], { allowFail: true }).out;
  const llvm = sh('llvm-readelf-18', ['-h', exe], { allowFail: true }).out;
  const gnuType = (gnu.match(/^\s*Type:\s*(.+)$/m) ?? [])[1] ?? '(not found)';
  const llvmType = (llvm.match(/^\s*Type:\s*(.+)$/m) ?? [])[1] ?? '(not found)';
  record(
    'TOOL-1',
    'the two installed readers describe the same header differently',
    'the wording differs while the structural verdict does not',
    `GNU readelf: "${gnuType.trim()}"  |  llvm-readelf-18: "${llvmType.trim()}"  |  ` +
      `structural: pie=${pie.value} from ${pie.decidedBy.map((d) => d.field).join(' + ')}; ` +
      `relro-full=${relro.value} from ${relro.decidedBy.map((d) => d.field).join(' + ')}`,
    gnuType.trim() !== llvmType.trim() && pie.value === true,
  );
}

// ------------------------------------------------------------------ summary
const passed = cases.filter((c) => c.pass === 1).length;
const total = cases.length;
const out = {
  recordType: 'introduction-analysis-control-run',
  schemaVersion: 1,
  baselines: builtBaselines,
  cases,
  totals: { passed, total, failed: total - passed },
  context: {
    generatedAt: new Date().toISOString(),
    timeSource: 'wall-clock',
    sourceDateEpoch: null,
    host: 'redacted-by-policy',
  },
};
writeFileSync(join(LAB, 'control-run.json'), `${JSON.stringify(out, null, 2)}\n`, 'utf8');
const tail = `\n${passed}/${total} cases passed. Detail: ${join(LAB, 'control-run.json')}`;
console.log(tail);
log(tail);
process.exit(passed === total ? 0 : 1);

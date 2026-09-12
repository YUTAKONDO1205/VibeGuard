#!/usr/bin/env node
/**
 * residue-tracer -- did the SECRET survive, not did the WIPE INSTRUCTION survive.
 *
 *   node run-residue-tracer.mjs --out <lab dir> [options]
 *
 * Every other lane in compiler/eval/ ends at a verdict about an artefact:
 * differential compilation says whether deleting the wipe from the source changes
 * the assembly, and WIPE_SURVIVED means the instruction is still there. That is
 * the right question for a checker and the wrong question for an attacker, who
 * reads memory and does not care what instruction produced it. This lane asks the
 * second question on the SAME build, at a defined instant, with the first
 * question's own code deciding the first question.
 *
 * WHAT MAKES THE PAIRING HONEST. For each cell the target is compiled to
 * assembly with ai-generated/lib/ablation-cell.mjs -- the find step's own
 * compile, its own wipe-span finder, its own ablation, its own verdictOf -- and
 * then THAT LISTING is assembled into the object that is linked and executed.
 * The sha256 of the .s and of the .o are both recorded. So "confirm said
 * WIPE_SURVIVED and the secret was readable" cannot be waved away as judging one
 * build and running another: there is one build, and its digest is in the row.
 *
 * WHAT IS MEASURED IS RESIDENCY, NOT SECRECY. A NONE reading says the tracer was
 * not in this window at this instant. It does not say the secret is gone: the
 * heap, other threads, the parts of the stack outside the window, kernel-saved
 * state and the upper halves of the vector registers are all unobserved, and each
 * is named in every row rather than left to be inferred from silence.
 *
 * THE WINDOW IS CHECKED AGAINST THE SUBJECT, NOT AGAINST THE CONTROL. Each cell's
 * linked executable is disassembled with objdump and the subject function's frame
 * depth is read out of it, because a readable co-resident control only proves the
 * window reached the CONTROL. A layout that puts the control shallow and the
 * secret deeper than the window reads control 32/32 and subject NONE, which is a
 * false clean in the worst direction. The window is grown to cover the measured
 * frame where it can be, and a cell whose window still does not reach it -- or
 * whose frame could not be read at all -- is BROKEN_MEASUREMENT, never a residue
 * verdict.
 *
 * RUNNING CONCURRENTLY WITH ANOTHER LANE IS A WAY TO MANUFACTURE DATA. compile()
 * in ablation-cell.mjs returns null on its 90 s timeout and verdictOf maps null
 * to COMPILE_ERROR, so a machine loaded by another sweep produces rows that say
 * the compiler failed when it did not. Default concurrency here is low for that
 * reason and --jobs is the knob.
 */
import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { longestRun, longestRunOverSlots, hexToBytes, needleSanity, agrees, PARTIAL_FLOOR } from './lib/scan.mjs';
import { CONTROLS, gradeCell, gradeControl, runValidity, assertPairing, crossTab, anomalies } from './lib/grade.mjs';
import { parseFrame, requiredBelow, FRAME_MARGIN_BYTES, WINDOW_MAX_BYTES } from './lib/frame.mjs';
import {
  OPTS, VENDORS, IDIOMS, ARMS, plannedCells, buildRow, assertIntegers, assertNoPaths, renderCrossTab,
  pluginMismatch, vendorOf,
} from './lib/manifest.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const CELL_PATH = resolve(HERE, '../ai-generated/lib/ablation-cell.mjs');
const OBSERVER_SRC = join(HERE, 'observer', 'residue-observer.c');
const FIXTURE_SH = join(HERE, 'tools', 'make-residue-fixtures.sh');
const SUBJECT_FN = 'handle_request';

const USAGE = `residue-tracer -- is the secret still in the process after the frame that held it dies?

  node run-residue-tracer.mjs --out <lab dir> [options]

  --out <dir>          where fixtures, binaries, observations and rows go.
                       Default $HOME/vg-lab/residue-tracer. Never under compiler/.
  --cc <list>          comma-separated compilers. Default ${VENDORS.join(',')}
  --opt <list>         comma-separated levels. Default ${OPTS.join(',')}
  --idiom <list>       comma-separated idioms. Default ${IDIOMS.join(',')}
  --plugin <so>        libWipePin.so, the LLVM repair plugin, for the clang half
                       of the second arm.
  --plugin-gcc <so>    libWipePinGcc.so, the GCC repair plugin, for the gcc half.
                       The two are different binaries and neither compiler can
                       load the other's, so they are separate options and the
                       basename is checked against the vendor before any compile.
                       A vendor with no plugin has every wipepin cell recorded
                       BROKEN_MEASUREMENT/plugin-absent -- never silently dropped
                       and never reported as stock.
  --controls-only      run the three controls and stop. The instrument check on
                       its own, which is what a first run on a new box wants.
  --below N            stack bytes below rsp in the window. Default 4096. This is
                       a FLOOR: each cell's window is grown to cover the subject
                       frame objdump reports for that cell, plus a ${FRAME_MARGIN_BYTES}-byte margin.
  --no-auto-window     do not grow it. A cell whose window is then shallower than
                       its subject frame is BROKEN_MEASUREMENT with the size it
                       needed, rather than a reading from the wrong depth.
  --above N            stack bytes above rsp in the window. Default 64
  --jobs N             concurrent compiles. Default 2. See the header.
  --write-data         also write the tracked rows under this lane's data/.
                       Refused unless the full matrix was run.
  -h, --help

Exit codes: 0 measured; 1 INVALID_RUN (a control did not hold, nothing written);
5 the lane could not be set up at all.`;

function die(code, msg) { process.stderr.write(`residue-tracer: ${msg}\n`); process.exit(code); }
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const sha256File = (p) => (existsSync(p) ? sha256(readFileSync(p)) : null);

/* ------------------------------------------------------------------ options */

function parseArgs(argv) {
  const a = {
    out: join(process.env.HOME || '.', 'vg-lab', 'residue-tracer'),
    ccs: [...VENDORS], opts: [...OPTS], idioms: [...IDIOMS],
    plugin: null, pluginGcc: null,
    controlsOnly: false, below: 4096, above: 64, jobs: 2, writeData: false, autoWindow: true,
  };
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    const next = () => { if (i + 1 >= argv.length) die(5, `${k} needs a value`); return argv[++i]; };
    if (k === '-h' || k === '--help') { process.stdout.write(`${USAGE}\n`); process.exit(0); }
    else if (k === '--out') a.out = next();
    else if (k === '--cc') a.ccs = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (k === '--opt') a.opts = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (k === '--idiom') a.idioms = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (k === '--plugin') a.plugin = next();
    else if (k === '--plugin-gcc') a.pluginGcc = next();
    else if (k === '--controls-only') a.controlsOnly = true;
    else if (k === '--no-auto-window') a.autoWindow = false;
    else if (k === '--below') a.below = Number(next());
    else if (k === '--above') a.above = Number(next());
    else if (k === '--jobs') a.jobs = Number(next());
    else if (k === '--write-data') a.writeData = true;
    else die(5, `unknown option ${k}`);
  }
  if (!Number.isInteger(a.below) || !Number.isInteger(a.above) || a.below < 0 || a.above < 0) die(5, '--below/--above must be non-negative integers');
  if (!Number.isInteger(a.jobs) || a.jobs < 1) die(5, '--jobs must be a positive integer');
  for (const o of a.opts) if (!OPTS.includes(o)) die(5, `${o} is not one of ${OPTS.join(' ')}`);
  for (const d of a.idioms) if (!IDIOMS.includes(d)) die(5, `${d} is not one of ${IDIOMS.join(' ')}`);
  return a;
}

/* ------------------------------------------------------------------- setup */

async function haveTool(bin) {
  try { await run(bin, ['--version'], { timeout: 20000 }); return true; } catch { return false; }
}

async function main() {
  const args = parseArgs(process.argv);
  const LAB = resolve(args.out);
  const FX = join(LAB, 'fixtures');
  const BIN = join(LAB, 'bin');
  const BUILD = join(LAB, 'build');
  const OBS = join(LAB, 'obs');
  for (const d of [LAB, BIN, BUILD, OBS]) mkdirSync(d, { recursive: true });

  if (!existsSync(CELL_PATH)) {
    die(5, 'ai-generated/lib/ablation-cell.mjs is missing. This lane takes its confirm verdict from the '
      + 'find step\'s own code and keeps no copy of it -- two copies is how two lanes quietly stop measuring '
      + 'the same thing.');
  }
  const cell = await import(pathToFileURL(CELL_PATH).href);
  for (const n of ['FLAGS', 'CONTROL', 'wipeSpans', 'ablateSpans', 'bodyOf', 'controlPresent', 'compile', 'verdictOf']) {
    if (!(n in cell)) die(5, `ablation-cell.mjs does not export ${n}`);
  }

  // --- fixtures -----------------------------------------------------------
  if (!existsSync(join(FX, 'target-memset.c'))) {
    try {
      await run('bash', [FIXTURE_SH], { env: { ...process.env, RESIDUE_LAB: LAB }, timeout: 60000 });
    } catch (e) { die(5, `the fixture generator failed: ${String(e.stderr || e.message).slice(0, 400)}`); }
  }
  for (const f of ['main.c', 'opaque.c', 'target-retain.c', 'target-memset.c', 'target-volatile-loop.c', 'target-explicit-bzero.c']) {
    if (!existsSync(join(FX, f))) die(5, `fixture ${f} is missing after generation`);
  }

  // --- observer -----------------------------------------------------------
  const observer = join(BIN, 'residue-observer');
  try {
    await run('gcc-13', ['-O2', '-std=gnu11', '-Wall', '-Wextra', '-o', observer, OBSERVER_SRC], { timeout: 120000 });
  } catch (e) { die(5, `the observer did not build with gcc-13: ${String(e.stderr || e.message).slice(0, 600)}`); }
  const observerSha = sha256File(observer);

  // --- compilers ----------------------------------------------------------
  const ccs = [];
  const absent = [];
  for (const cc of args.ccs) ((await haveTool(cc)) ? ccs : absent).push(cc);
  if (ccs.length === 0) die(5, `none of ${args.ccs.join(', ')} is on PATH`);

  // --- objdump ------------------------------------------------------------
  //
  // Not optional. Without it nothing measures how deep the subject's frame goes,
  // and a run that cannot establish that the window reached the buffer can only
  // produce BROKEN_MEASUREMENT rows. Failing here says so once instead of
  // producing a full matrix of them.
  if (!(await haveTool('objdump'))) {
    die(5, 'objdump is not on PATH. Every cell needs the subject frame read out of its own binary: '
      + 'a co-resident control that is readable proves the window reached the CONTROL, not the secret, '
      + 'so without this bound the lane cannot tell a clean wipe from a window that looked too shallow.');
  }

  // --- tracers ------------------------------------------------------------
  //
  // Drawn here, at run time, never written in a fixture. A literal would be
  // constant-folded into .rodata and the observer would find it in a place no
  // wipe was ever responsible for. Three independent draws:
  //   A  the subject tracer, the needle every cell searches for
  //   K  the co-resident control tracer, held unwiped in the SAME frame
  //   B  the decoy, given to control-nosecret's tracee INSTEAD of A
  const draw = () => { for (;;) { const b = randomBytes(32); if (needleSanity(b).ok) return b; } };
  const A = draw(), K = draw(), B = draw();
  const needleA = join(LAB, 'needle-a.bin'), needleK = join(LAB, 'needle-k.bin');
  const tracerMain = join(LAB, 'tracer-main.bin'), tracerDecoy = join(LAB, 'tracer-decoy.bin');
  writeFileSync(needleA, A); writeFileSync(needleK, K);
  writeFileSync(tracerMain, Buffer.concat([A, K]));
  writeFileSync(tracerDecoy, Buffer.concat([B, K]));

  // --- the two fixed units ------------------------------------------------
  //
  // opaque.c is compiled at -O0 in every configuration and that is a measurement
  // decision. At -O2 the consumer loop vectorises, sixteen bytes of the tracer
  // land in an xmm register, and the observer reads register residue no wipe was
  // ever responsible for. main.c is -O0 for the same reason plus one more: its
  // call site is where the observer's second breakpoint lands.
  const FIXED = ['-O0', '-std=gnu11', '-w', '-fcf-protection=none'];
  const fixedObj = {};
  for (const cc of ccs) {
    fixedObj[cc] = {};
    for (const unit of ['opaque', 'main']) {
      const o = join(BUILD, `${unit}.${cc}.o`);
      try { await run(cc, [...FIXED, '-c', join(FX, `${unit}.c`), '-o', o], { timeout: 90000 }); }
      catch (e) { die(5, `${cc} could not compile ${unit}.c: ${String(e.stderr || e.message).slice(0, 400)}`); }
      fixedObj[cc][unit] = o;
    }
  }

  // The repair plugin is per VENDOR, not per run. WipePin is an LLVM pass plugin
  // and WipePinGcc is a GCC plugin; they are different binaries built from
  // different sources, and neither compiler can load the other's. Handing gcc the
  // LLVM `.so` with -fplugin= is not a measurement that failed, it is a run that
  // was configured wrong -- and it used to spend fifteen cells finding that out,
  // one COMPILE_ERROR at a time:
  //
  //   cc1: error: cannot load plugin .../libWipePin.so:
  //        undefined symbol: _ZN4llvm17PreservedAnalyses14AllAnalysesKeyE
  //
  // Those fifteen were honestly recorded (the lane has never reported a wipepin
  // cell as stock) but they are noise where a refusal belongs, and a reader who
  // skims "excluded: 15 x compile-failed" learns nothing about the arm. So the
  // basename is checked against the vendor before anything is compiled, which is
  // the guard repair-loop's runner already has for the same two binaries.
  const pluginFor = (cc) => (vendorOf(cc) === 'clang' ? args.plugin : args.pluginGcc ?? null);
  if (!args.controlsOnly) {
    for (const cc of ccs) {
      const so = pluginFor(cc);
      if (!so) continue;
      if (!existsSync(so)) die(5, `--plugin${vendorOf(cc) === 'gcc' ? '-gcc' : ''}: ${basename(so)} does not exist`);
      const bad = pluginMismatch(cc, basename(so));
      if (bad) die(4, bad.message);
    }
  }
  // A cell's arm is measurable iff ITS vendor has a plugin. With only --plugin
  // the clang wipepin cells are measured and the gcc ones stay plugin-absent --
  // which is a statement about what was run, not a failure.
  const pluginPresent = !!(args.plugin && existsSync(args.plugin));

  // --- the matrix ---------------------------------------------------------
  const planned = plannedCells({
    opts: args.opts, vendors: ccs, idioms: args.idioms,
    arms: args.controlsOnly ? [] : ARMS, controls: CONTROLS,
  }).filter((c) => args.opts.includes(c.opt) || c.kind === 'control');

  const rows = [];
  const controlGrades = [];

  for (const p of planned) {
    const row = await measureCell(p);
    rows.push(row);
    if (p.kind === 'control') {
      const g = gradeControl(p.control, {
        measurement: row.measurement, reason: row.reason,
        residue: row.residue, longestRunBytes: row.longestRunBytes,
      });
      // One control runs at several levels; it has held only if it held at all
      // of them, and the first failure is the one reported.
      const prev = controlGrades.find((c) => c.name === p.control);
      if (!prev) controlGrades.push({ ...g, at: [p.cell] });
      else { prev.at.push(p.cell); if (!g.held && prev.held) { prev.held = false; prev.why = `${p.cell}: ${g.why}`; } }
    }
    process.stdout.write(`${p.cell.padEnd(44)} confirm=${String(row.confirmVerdict).padEnd(18)} `
      + `residue=${String(row.residue.stack).padEnd(13)} run=${row.longestRunBytes ?? '-'}/${row.needleLen} `
      + `ctl=${row.controlRunBytes ?? '-'} frame=${row.frame.subjectBytes ?? '-'}/${row.window.belowReached ?? '-'} `
      + `${row.measurement === 'OK' ? '' : `[${row.reason}]`}\n`);
  }

  /**
   * One cell, end to end: judge the source with the find step's code, assemble
   * the listing that was judged, link it, and read the process it becomes.
   */
  async function measureCell(p) {
    const notObserved = (reason) => buildRow({
      planned: p, confirm: null, obs: null, digests: {}, needleLen: A.length, controlNeedleLen: K.length,
      graded: gradeCell(null, { needleLen: A.length, controlNeedleLen: K.length, notRun: reason }),
    });
    if (p.arm === 'wipepin' && !pluginFor(p.cc)) return notObserved('plugin-absent');

    const src = readFileSync(join(FX, `target-${p.target}.c`), 'utf8');
    const { spans } = cell.wipeSpans(src, SUBJECT_FN);
    const tag = p.cell.replace(/[^A-Za-z0-9]+/g, '_');
    const pluginOn = p.arm === 'wipepin';
    const env = pluginOn ? { WPIN_OUT: join(BUILD, `${tag}.pin.json`), WPIN_SCOPE: 'module' } : undefined;
    const extra = pluginOn ? [p.opt, `${/clang/.test(basename(p.cc)) ? '-fpass-plugin=' : '-fplugin='}${pluginFor(p.cc)}`] : [p.opt];

    // The listing that is judged is the listing that is assembled. The control
    // function from ablation-cell.mjs is appended exactly as the corpus
    // measurement appends it, so controlPresent() inside verdictOf reads the
    // same positive control here as there.
    const pW = join(BUILD, `${tag}.w.c`), pWo = join(BUILD, `${tag}.wo.c`);
    writeFileSync(pW, src + cell.CONTROL, 'utf8');
    writeFileSync(pWo, cell.ablateSpans(src, spans) + cell.CONTROL, 'utf8');
    const asm = join(BUILD, `${tag}.w.s`);
    const aW = await cell.compile(p.cc, extra, pW, asm, env ? { env } : {});
    const aWo = spans.length
      ? await cell.compile(p.cc, extra, pWo, join(BUILD, `${tag}.wo.s`), env ? { env } : {})
      : null;

    let confirm;
    if (!spans.length) {
      // No wipe in the source at all. ablateSpans would be a no-op and verdictOf
      // would compare a listing with itself and call it WIPE_ELIMINATED, which
      // would be a verdict about nothing. build-analyze.mjs uses this word for
      // the same case.
      confirm = { verdict: aW ? 'NO_WIPE_WRITTEN' : 'COMPILE_ERROR', nSpans: 0 };
      if (aW) { const c = cell.controlPresent(aW); confirm.control = c.ok ? 'PRESENT' : c.via; confirm.control_via = c.via; }
    } else {
      confirm = { ...cell.verdictOf(aW, aWo, SUBJECT_FN), nSpans: spans.length };
    }
    if (!aW) return { ...notObserved('compile-failed'), confirmVerdict: confirm.verdict, nSpans: confirm.nSpans };

    // Assemble THAT listing, then link it. -no-pie so the symbol table's
    // st_value is the runtime address; the observer still reads /proc/<pid>/maps
    // and refuses a non-zero load bias rather than trusting the flag.
    const obj = join(BUILD, `${tag}.o`), exe = join(BUILD, `${tag}.exe`);
    try { await run(p.cc, ['-c', asm, '-o', obj], { timeout: 90000 }); }
    catch (e) { return { ...notObserved(`assemble-failed: ${String(e.stderr || e.message).slice(0, 120)}`), confirmVerdict: confirm.verdict }; }
    try { await run(p.cc, ['-no-pie', obj, fixedObj[p.cc].opaque, fixedObj[p.cc].main, '-o', exe], { timeout: 90000 }); }
    catch (e) { return { ...notObserved(`link-failed: ${String(e.stderr || e.message).slice(0, 120)}`), confirmVerdict: confirm.verdict }; }

    // The frame of the function under test, out of the binary that will be run.
    // This is the only thing in the cell that says where the secret CAN be, and
    // it comes from the artefact rather than from the observation, so a window
    // that missed the buffer cannot also certify itself.
    let frame;
    try {
      const { stdout } = await run('objdump', ['-d', '--no-show-raw-insn', exe],
        { timeout: 60000, maxBuffer: 64 * 1024 * 1024 });
      frame = parseFrame(stdout, SUBJECT_FN);
    } catch (e) {
      frame = { parsed: false, subjectBytes: null, form: null,
        why: `objdump-failed: ${String(e.code || e.message).slice(0, 80)}` };
    }
    const need = requiredBelow(frame);
    frame = { ...frame, requiredBelow: need };
    // Grown to cover the frame, never shrunk below what was asked for, and never
    // past what the observer will accept -- a cell needing more than that is
    // refused by the grader with the number it needed, not measured shallow.
    const below = args.autoWindow && Number.isInteger(need)
      ? Math.min(Math.max(args.below, need), WINDOW_MAX_BYTES - args.above)
      : args.below;

    const exeBefore = sha256File(exe);
    const obsJson = join(OBS, `${tag}.json`), winBin = join(OBS, `${tag}.win.bin`);
    const tracer = p.control === 'control-nosecret' ? tracerDecoy : tracerMain;
    try {
      await run(observer, ['--needle', needleA, '--control-needle', needleK, '--symbol', SUBJECT_FN,
        '--out', obsJson, '--window', winBin, '--below', String(below), '--above', String(args.above),
        '--', exe, tracer], { timeout: 60000 });
    } catch { /* the observer writes its own record on failure; that is what is read */ }
    const exeAfter = sha256File(exe);

    let obs = null;
    try { obs = JSON.parse(readFileSync(obsJson, 'utf8')); } catch { obs = null; }

    // Re-count in a second language over the bytes the observer dumped. The
    // observer is the only component here that both chooses where to look and
    // decides what it saw; a disagreement means one of the two searches is wrong
    // and neither reading is usable.
    let scanAgrees = null;
    if (obs && obs.ok === true && existsSync(winBin)) {
      const win = new Uint8Array(readFileSync(winBin));
      const mine = longestRun(win, new Uint8Array(A));
      const mineCtl = longestRun(win, new Uint8Array(K));
      const gprSlots = (obs.gprHex || []).map(hexToBytes);
      const mineGpr = longestRunOverSlots(gprSlots, new Uint8Array(A));
      scanAgrees = agrees(obs.stack.longestRunBytes, mine.len)
        && agrees(obs.stackControl.longestRunBytes, mineCtl.len)
        && agrees(obs.gpr.longestRunBytes, mineGpr.len);
    }

    let graded = gradeCell(obs, { needleLen: A.length, controlNeedleLen: K.length, frame });
    if (graded.measurement === 'OK' && scanAgrees === false) {
      graded = gradeCell(null, { needleLen: A.length, controlNeedleLen: K.length, notRun: 'second-scan-disagrees' });
    }

    return buildRow({
      planned: p, confirm, graded, obs, needleLen: A.length, controlNeedleLen: K.length, scanAgrees, frame,
      digests: {
        asm: sha256File(asm), obj: sha256File(obj), exeBefore, exeAfter,
        window: sha256File(winBin),
      },
    });
  }

  /* ------------------------------------------------------------- reporting */

  const validity = runValidity(controlGrades);
  const pairing = assertPairing(rows);
  const tab = crossTab(rows.filter((r) => r.kind === 'subject'));
  const anom = anomalies(rows.filter((r) => r.kind === 'subject'));

  const L = [];
  L.push('');
  L.push('residue-tracer');
  L.push(`observer sha256   ${observerSha}`);
  L.push(`compilers         ${ccs.join(', ')}${absent.length ? `  (absent, not run: ${absent.join(', ')})` : ''}`);
  L.push(`levels            ${args.opts.join(' ')}`);
  L.push(`window floor      [rsp-${args.below}, rsp+${args.above})   partial floor ${PARTIAL_FLOOR} bytes`);
  L.push(`frame bound       ${args.autoWindow ? 'window grown per cell' : 'window NOT grown (--no-auto-window)'} `
    + `to cover the subject frame objdump reports, + ${FRAME_MARGIN_BYTES} B margin`);
  L.push(`arms              ${args.controlsOnly ? 'controls only' : ARMS.join(', ')}`);
  if (!args.controlsOnly) {
    // Per vendor, because that is how the plugin is per vendor. A line that said
    // only "plugin-absent" could not distinguish "no repair arm was measured at
    // all" from "it was measured on clang and not on gcc", and those are
    // different runs.
    for (const cc of ccs) {
      const so = pluginFor(cc);
      L.push(`  ${cc.padEnd(10)} ${so ? `wipepin via ${basename(so)}` : 'wipepin: plugin-absent, every such cell NOT observed'}`);
    }
  }
  L.push('');
  L.push('controls');
  for (const g of controlGrades) {
    L.push(`  ${g.held ? 'HELD ' : 'FAILED'} ${g.name.padEnd(18)} ${CONTROLS[g.name].expect.padEnd(5)} `
      + `over ${g.at.length} cell(s)${g.held ? '' : ` -- ${g.why}`}`);
  }
  if (!validity.valid) for (const p of validity.problems) L.push(`  problem: ${p}`);
  L.push('');
  if (!pairing.ok) { L.push('PAIRING RULE VIOLATED (interfaces.md 3.1):'); for (const p of pairing.problems) L.push(`  ${p}`); L.push(''); }
  if (!args.controlsOnly) {
    L.push(renderCrossTab(tab));
    L.push('');
    for (const f of anom.findings) L.push(`FINDING  ${f}`);
    for (const a of anom.anomalous) L.push(`ANOMALY  ${a}`);
    if (!anom.findings.length && !anom.anomalous.length) L.push('no (WIPE_SURVIVED, readable) cell and no (WIPE_ELIMINATED, NONE) cell in this run');
    L.push('');
  }
  L.push('NOT observed in any cell: ymm/zmm upper halves (PTRACE_GETFPREGS returns xmm only), the heap,');
  L.push('other threads, the stack on either side of the window -- deeper than it, and the caller frames');
  L.push('above it -- and kernel-saved state. A NONE reading is residency, not secrecy. What a NONE does');
  L.push('carry is that the window reached the bottom of the frame the subject function owns, read out');
  L.push('of its binary with objdump: a cell where it did not is BROKEN_MEASUREMENT, not a clean wipe.');
  const report = L.join('\n');
  process.stdout.write(`${report}\n`);

  for (const r of rows) {
    const i = assertIntegers(r), n = assertNoPaths(r);
    if (!i.ok) die(5, `row ${r.cell} has a non-integer number: ${i.problems[0]}`);
    if (!n.ok) die(5, `row ${r.cell} carries a path: ${n.problems[0]}`);
  }
  writeFileSync(join(LAB, 'rows.json'), `${JSON.stringify(rows, null, 2)}\n`, 'utf8');
  writeFileSync(join(LAB, 'results.txt'), `${report}\n`, 'utf8');

  if (!validity.valid) {
    process.stderr.write('\nINVALID_RUN: a control did not hold. Nothing is written to data/; the rows in the\n'
      + 'lab are kept so the failure can be looked at, and they are not measurements of anything.\n');
    process.exit(1);
  }
  if (args.writeData) {
    if (args.controlsOnly) die(5, '--write-data refused: a controls-only run measures the instrument, not the matrix');
    const DATA = join(HERE, 'data');
    mkdirSync(DATA, { recursive: true });
    writeFileSync(join(DATA, `residue-rows-${ccs.join('-')}.json`), `${JSON.stringify(rows, null, 2)}\n`, 'utf8');
    process.stdout.write(`wrote ${rows.length} rows to data/\n`);
  }
  process.exit(0);
}

main().catch((e) => { process.stderr.write(`residue-tracer: ${e && e.stack ? e.stack : e}\n`); process.exit(5); });

#!/usr/bin/env node
/**
 * A7 -- the link-time observation window.
 *
 * The property observer sees one translation unit at compile time. Under LTO the
 * optimiser runs a second time, at LINK time, in a different process, over a
 * merged module -- and cross-translation-unit disappearance happens exactly
 * there and nowhere else. This lane extends the observation window to the LTO
 * backend and closes the budget over the whole catchment rather than over one
 * stream gauge.
 *
 *   node compiler/eval/lto-window/run-lto-window.mjs \
 *        --lab    ~/vg-lab/lto-window \
 *        --out    ~/vg-lab/lto-window/_results/<stamp> \
 *        --plugin ~/vg-build/pass-observer/libPropertyObserver.so
 *
 * Options
 *   --lab <dir>        the workspace holding fixtures/ (make-lto-fixtures.sh) and
 *                      this run's work/ directory. Required.
 *   --out <dir>        where the results JSON goes. Refused inside the checkout.
 *   --plugin <path>    libPropertyObserver.so. Required.
 *   --fixtures a,b     default xtu,xtu-inline,erasure. `xtu` and `xtu-inline`
 *                      are a PAIR -- the same translation units with and without
 *                      `__attribute__((noinline))` -- and measuring only one of
 *                      them leaves the lane unable to say what the intervention
 *                      buys. See the README's section on the pair.
 *   --forms full,thin  default full,thin. `thin` is measured for its refusal,
 *                      never for an attribution -- see the README.
 *   --cc <clang>       default clang-18. The plugin is built against one LLVM's
 *                      headers and will not load into another's lld.
 *   --gcc <gcc>        default gcc-13. Probed for refusals only.
 *   --opt <level>      default -O2. Passed through to the compiler and the
 *                      linker unchanged, so -O0/-O1/-O3/-Os/-Oz are all accepted
 *                      and nothing here restricts the axis -- what a run is, is
 *                      ONE level, recorded as `optLevel` in its result. Four
 *                      levels are four runs with four --out directories; the
 *                      result file name is fixed, so a shared --out overwrites.
 *   --skip-thinlto-evidence   do not run the ThinLTO link that earns the
 *                      BROKEN_MEASUREMENT word. The cell then says the word was
 *                      not earned in this run, which is not the same claim.
 *   --skip-gcc         do not probe gcc at all
 *   --skip-negative-control   do not run the non-LTO link that shows guard 1
 *                      firing. A guard never shown to fire is not a guard, so
 *                      this is off by default.
 *   --keep             leave work/ behind
 *
 * Every one of the three --skip flags writes its own record (`skipped: true`
 * with the flag and what was given up) and none of them can return 0: a run that
 * turned a check off has not checked everything it asks a reader to believe.
 * See lib/record.mjs, which is where that decision lives and is tested.
 *
 * Exit codes follow ../../schema/interfaces.md section 7:
 *   0  every requested cell was checked and nothing was found
 *   1  a compile or link this lane needed failed
 *   2  a finding at threshold -- currently only: the observer changed the bytes
 *   3  a requested cell could not be completed (ThinLTO, gcc, a fallen control),
 *      or a cell measured OK with nothing to read, or a check was skipped.
 *      Never 0. A run that asks for --forms thin returns 3 by construction.
 *   4  usage, or a refusal: --out inside the checkout, a missing plugin, a
 *      record that still carries an absolute path
 *
 * Nothing here decides what a wipe is; that is the observer's oracle. Nothing
 * here decides what a verdict word means; that is lib/cell.mjs against
 * interfaces.md. This file walks cells, runs the toolchain, and writes down what
 * came back -- including the words for "the toolchain refused" and "we did not
 * look", which are not the same word and are never merged.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { objectKind, ltoFormFromBcanalyzerDump, gradeInputs } from './lib/lto-inputs.mjs';
import { parseLldPassLog, parseObserverLog, comparePassReadings } from './lib/pass-log.mjs';
import { gradeCell, MEASUREMENT, STATE, REASON, STAGE_COMPILE, STAGE_LTO_BACKEND, CHECKPOINT_AFTER_PASS } from './lib/cell.mjs';
import {
  skippedRecord, skipSummaryLines, SKIP_WHY, linkGuardRecord, scrubbed, exitDecision,
  interventionAbsentReading, absorbedFillReading, interventionPairVerdict,
} from './lib/record.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..', '..');

/* ---------------------------------------------------------------- args -- */

function parseArgs(argv) {
  const o = {
    // The pair is in the DEFAULT run. A family measured only when someone
    // remembers to name it on the command line is a family whose result nobody
    // has, and the question it answers -- "you only saw it because of noinline"
    // -- is the first one a reader asks of this lane.
    fixtures: ['xtu', 'xtu-inline', 'erasure'], forms: ['full', 'thin'],
    cc: 'clang-18', gcc: 'gcc-13', opt: '-O2',
    skipThinEvidence: false, skipGcc: false, skipNegativeControl: false, keep: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--lab') o.lab = argv[++i];
    else if (a === '--out') o.out = argv[++i];
    else if (a === '--plugin') o.plugin = argv[++i];
    else if (a === '--fixtures') o.fixtures = argv[++i].split(',');
    else if (a === '--forms') o.forms = argv[++i].split(',');
    else if (a === '--cc') o.cc = argv[++i];
    else if (a === '--gcc') o.gcc = argv[++i];
    else if (a === '--opt') o.opt = argv[++i];
    else if (a === '--skip-thinlto-evidence') o.skipThinEvidence = true;
    else if (a === '--skip-gcc') o.skipGcc = true;
    else if (a === '--skip-negative-control') o.skipNegativeControl = true;
    else if (a === '--keep') o.keep = true;
    else die(4, `unknown option ${a}`);
  }
  return o;
}

function die(code, msg) {
  process.stderr.write(`lto-window: ${msg}\n`);
  process.exit(code);
}

/* ------------------------------------------------------------ fixtures -- */

/**
 * What each family is and which unit holds what. This mirrors
 * tools/make-lto-fixtures.sh; the generator is the source of the bytes and this
 * is the source of the questions asked about them. Both are tracked, so a drift
 * between them is a diff rather than a mystery.
 *
 * `intervention` names the fixture intervention a family carries, or null. It is
 * not decoration: a family with `intervention: null` beside one that carries it
 * is a PAIR, and every cell of the un-intervened family is graded as a reading
 * of what the intervention buys rather than as a repeat of the measurement (see
 * interventionAbsentReading in lib/record.mjs, and the README's section on the
 * pair).
 *
 * `artifact` says which function the DISASSEMBLY reader should be pointed at.
 * That is a different question from which function the observer looks for: once
 * the intervention is removed the subject and the control are absorbed into
 * `main`, and asking objdump about `handle` in a program that no longer defines
 * it returns NOT_OBSERVED -- which would read as "the executable cannot be read"
 * when the truth is "the function is not there any more, which is the point".
 */
const FIXTURES = {
  xtu: {
    subject: 'handle', control: 'wipe_kept', helper: 'secure_wipe', bufferBytes: 32,
    subjectTU: 'use.c',
    lto: ['use.c', 'wipe.c', 'main.c'],
    opaque: ['io.c'],
    intervention: 'noinline',
    artifact: { subjectCaller: 'handle', controlCaller: 'wipe_kept', absorbed: false },
    expects: 'the wipe is in another unit; only a full-LTO link can inline it and then remove it',
  },
  // The same four translation units with `__attribute__((noinline))` deleted and
  // nothing else changed. NOT a repaired fixture and NOT a second sample: the
  // expected outcome is that the observer can no longer resolve `handle` as a
  // unit, so the ATTRIBUTION becomes impossible (OK / NOT_OBSERVED) while the
  // elimination itself stays demonstrable from the artifact. The claim the pair
  // supports is "the elimination does not depend on the intervention; the
  // intervention is required only to have a (pass, unit) to attribute it TO".
  'xtu-inline': {
    subject: 'handle', control: 'wipe_kept', helper: 'secure_wipe', bufferBytes: 32,
    subjectTU: 'use.c',
    lto: ['use.c', 'wipe.c', 'main.c'],
    opaque: ['io.c'],
    intervention: null,
    pairedWith: 'xtu',
    // Both wipes end up in `main`, so both readings are taken there. The verdict
    // word stops discriminating at that point -- one body, two buffers -- and
    // what carries the reading is the zero-fill BYTE COUNT, graded by
    // absorbedFillReading(). See lib/record.mjs for why that is a necessary
    // reading and not a sufficient one.
    artifact: { subjectCaller: 'main', controlCaller: 'main', absorbed: true },
    expects: 'without the intervention the link may absorb subject and control into main; '
      + 'the attribution then has no unit to name, and the elimination has to be read from the artifact',
  },
  erasure: {
    subject: 'handle_request', control: 'wipe_kept', helper: null, bufferBytes: 32,
    subjectTU: 'target.c',
    lto: ['target.c', 'opaque.c', 'main.c'],
    opaque: [],
    intervention: 'noinline',
    artifact: { subjectCaller: 'handle_request', controlCaller: 'wipe_kept', absorbed: false },
    expects: 'the loss is complete at compile time; the link-time window must not manufacture a second one',
  },
};

/* ------------------------------------------------------------- running -- */

/**
 * Run a command, capture everything. rc is data, never a verdict.
 *
 * `spawnSync` rather than `execFileSync`, and that is not a style choice. The
 * first version used execFileSync, which returns stdout and DISCARDS stderr when
 * the command succeeds -- and `--lto-debug-pass-manager` writes to stderr on a
 * link that exits 0. Every healthy full-LTO cell therefore read the linker's
 * pass log as empty, and guard 1 refused all four of them as "not an LTO link"
 * while the observer sat there with 448 pass records. The guard was right to
 * refuse; the harness was wrong about what it had read.
 */
function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 180_000, maxBuffer: 64 * 1024 * 1024, ...opts });
  if (r.error) return { rc: null, signal: null, stdout: '', stderr: String(r.error.message) };
  return {
    rc: typeof r.status === 'number' ? r.status : null,
    signal: r.signal ?? null,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
  };
}

const sha256File = (p) => createHash('sha256').update(fs.readFileSync(p)).digest('hex');
/**
 * Every absolute path in a captured diagnostic becomes its basename.
 *
 * Not cosmetic. A tool's own words are the most useful thing a record can carry
 * -- `/usr/bin/ld: unrecognized option '--load-pass-plugin='` is the whole
 * evidence for the gcc row -- and they arrive full of machine paths. Dropping
 * the diagnostic would lose the evidence; keeping it raw would put a home
 * directory into a record. So the words are kept and the paths are not.
 *
 * Applied to every string this lane did not write itself, including the module
 * identifiers: under ThinLTO the module id IS the object's path. The scan at the
 * end of main() is the backstop rather than the mechanism -- it fired on the
 * first real run, with 17 hits, which is how these call sites were found.
 */
const ABSOLUTE_TOKEN = /(?:[A-Za-z]:[\\/]|\/)(?:[\w.+@-]+[\\/])*[\w.+@-]+/g;
const redact = (s) => (typeof s === 'string'
  ? s.replace(ABSOLUTE_TOKEN, (m) => `<${m.replace(/\\/g, '/').split('/').pop()}>`)
  : s);
const redactLines = (s, n) => String(s ?? '').trim().split('\n').slice(0, n).map(redact);
const firstLine = (s) => redact(String(s ?? '').split('\n')[0].trim());

function toolchainIdentity(o) {
  const id = {};
  for (const [key, cmd, args] of [
    ['cc', o.cc, ['--version']],
    ['lld', 'ld.lld-18', ['--version']],
    ['gcc', o.gcc, ['--version']],
    ['objdump', 'objdump', ['--version']],
    ['bcanalyzer', 'llvm-bcanalyzer-18', ['--version']],
  ]) {
    const r = run(cmd, args);
    id[key] = r.rc === 0 ? firstLine(r.stdout) : { unresolved: firstLine(r.stderr) || 'not runnable' };
  }
  const u = run('uname', ['-srm']);
  id.host = u.rc === 0 ? u.stdout.trim() : { unresolved: 'uname failed' };
  return id;
}

/** The declared symbol list, read from the registry rather than spelled here. */
function effectSymbols() {
  const registry = JSON.parse(fs.readFileSync(path.join(REPO, 'compiler', 'schema', 'effect-symbol-lists.json'), 'utf8'));
  const id = 'wipe-5-observer';
  const spec = registry.lists?.[id];
  if (!spec) die(4, `compiler/schema/effect-symbol-lists.json has no list "${id}"`);
  return { id, symbols: spec.symbols, literal: spec.literal };
}

/* ---------------------------------------------------------------- cells -- */

const OBS_MODE = 'trace';

function observerEnv({ subject, control, symbols, outPath }) {
  return {
    ...process.env,
    OBS_TARGET_FN: subject,
    OBS_CONTROL_FN: control,
    OBS_EFFECT_SYMBOLS: symbols.join(','),
    OBS_OUT: outPath,
    OBS_MODE,
  };
}

function readObserver(outPath) {
  const main = fs.existsSync(outPath) ? parseObserverLog(fs.readFileSync(outPath)) : null;
  const sidePath = `${outPath}.summary.tsv`;
  const side = fs.existsSync(sidePath) ? parseObserverLog(fs.readFileSync(sidePath)) : null;
  // finish() runs from the tracker's destructor, and lld exits without
  // unwinding, so under full LTO the SUMMARY rows exist only in the side file.
  const fromMain = Boolean(main?.summaries?.length);
  const summaries = (fromMain ? main.summaries : side?.summaries) ?? [];
  // WHICH file the verdict is being read out of, and whether THAT file is
  // intact. Until 2026-09-12 the integrity guards ran on the main log only,
  // while under full LTO every verdict in this lane came from the side file --
  // the guarded file and the read file were two different files, and the side
  // file is the one this lane's own ThinLTO section calls the dangerous one.
  const summarySource = fromMain ? 'main' : (side?.summaries?.length ? 'side' : 'none');
  const summaryIntact = summarySource === 'main' ? (main?.intact ?? false)
    : summarySource === 'side' ? (side?.intact ?? false)
      : null;
  return { main, side, summaries, sidePath, summarySource, summaryIntact };
}

const summaryFor = (summaries, unit) => summaries.find((s) => s.unit === unit) ?? null;

/**
 * The compile-time window, for contrast. One translation unit, one process,
 * `-fpass-plugin=` -- the window the observer already had.
 */
function compileWindowCell({ o, fx, name, form, work, plugin, symbols }) {
  const src = path.join(o.lab, 'fixtures', name, fx.subjectTU);
  const obs = path.join(work, `compile-${name}-${form}.tsv`);
  const obj = path.join(work, `compile-${name}-${form}.o`);
  const ltoFlag = form === 'thin' ? '-flto=thin' : '-flto';
  const r = run(o.cc, [o.opt, ltoFlag, '-c', src, '-o', obj, `-fpass-plugin=${plugin}`],
    { env: observerEnv({ subject: fx.subject, control: fx.control, symbols, outPath: obs }) });
  if (r.rc !== 0) return { toolFailed: true, stderr: redact(r.stderr).slice(0, 2000) };

  const read = readObserver(obs);
  const cell = gradeCell({
    guards: {
      logIntact: read.main?.intact ?? false,
      summaryLogIntact: read.summaryIntact,
      evidenceRecords: read.main?.ev.length ?? 0,
    },
    subject: summaryFor(read.summaries, fx.subject),
    control: summaryFor(read.summaries, fx.control),
    subjectResolved: read.main?.subjectRes.some((s) => s.role === 'subject' && s.resolution === 'resolved') ?? null,
  });
  return {
    cell,
    counts: {
      passRecords: read.main?.counts.PASS ?? 0,
      evRecords: read.main?.ev.length ?? 0,
      tornLines: read.main?.tornLines.length ?? 0,
      // Which file the verdict came out of, and every unit the observer wrote a
      // SUMMARY row for. The second one is what makes "no row for this subject"
      // diagnosable: the observer records clones under their mangled names.
      summarySource: read.summarySource,
      summaryUnits: read.summaries.map((s) => s.unit),
    },
  };
}

/**
 * The link-time window. Three links, because each one answers a question the
 * others cannot:
 *
 *   A  stock, no plugin, no debug flag   -- the bytes the build produces
 *   B  no plugin, --lto-debug-pass-manager -- guard 1's independent reading of
 *      the pipeline, which needs no plugin and therefore cannot be fooled by one
 *   C  plugin + --lto-debug-pass-manager  -- the observation, and guard 2's two
 *      readings taken from ONE process
 *
 * A vs B says the debug flag changed nothing. A vs C is non-invasiveness.
 */
function linkWindowCell({ o, fx, name, form, work, plugin, symbols, objects, withPlugin }) {
  const dir = path.join(work, `link-${name}-${form}`);
  fs.mkdirSync(dir, { recursive: true });
  const ltoFlag = form === 'thin' ? '-flto=thin' : '-flto';
  const base = [o.opt, ltoFlag, '-fuse-ld=lld', ...objects.all];

  const appA = path.join(dir, 'app.stock');
  const a = run(o.cc, [...base, '-o', appA]);
  if (a.rc !== 0) return { toolFailed: true, where: 'stock link', stderr: redact(a.stderr).slice(0, 2000) };

  const appB = path.join(dir, 'app.passlog');
  const b = run(o.cc, [...base, '-o', appB, '-Wl,--lto-debug-pass-manager']);
  if (b.rc !== 0) return { toolFailed: true, where: 'pass-log link', stderr: redact(b.stderr).slice(0, 2000) };
  const lldStock = parseLldPassLog(b.stderr);

  const inputs = gradeInputs({
    ltoInputs: objects.lto, opaqueInputs: objects.opaque, forms: objects.forms, expectForm: form,
  });

  const shared = {
    inputs,
    linkerPipeline: { runs: lldStock.runs.length, lineKinds: lldStock.lineKinds },
    bytes: { stock: sha256File(appA), passlog: sha256File(appB) },
    // The STOCK executable's path, for the artifact reading. Kept out of every
    // record -- it is a machine path, and the scan at the end of main() would
    // refuse the run if it reached one. The artifact is read from this build and
    // not from `app.observed` on purpose: a reading of the observed link would
    // be a reading of a program the build does not produce, which is the thing
    // the sha256 equality check exists to rule out rather than to assume.
    exe: { stock: appA },
  };
  shared.debugFlagChangedBytes = shared.bytes.stock !== shared.bytes.passlog;

  if (!withPlugin) return { linkOnly: true, ...shared };

  const obs = path.join(dir, 'observer.tsv');
  const appC = path.join(dir, 'app.observed');
  const c = run(o.cc, [...base, '-o', appC, `-Wl,--load-pass-plugin=${plugin}`, '-Wl,--lto-debug-pass-manager'],
    { env: observerEnv({ subject: fx.subject, control: fx.control, symbols, outPath: obs }) });
  if (c.rc !== 0) return { toolFailed: true, where: 'observed link', stderr: redact(c.stderr).slice(0, 2000) };

  const lldObserved = parseLldPassLog(c.stderr);
  const read = readObserver(obs);
  shared.bytes.observed = sha256File(appC);
  shared.byteIdentical = shared.bytes.stock === shared.bytes.observed;
  const agreement = read.main ? comparePassReadings(read.main.passes, lldObserved.runs) : null;

  const cell = gradeCell({
    guards: {
      inputs,
      linkerPipeline: shared.linkerPipeline,
      passAgreement: agreement,
      logIntact: read.main?.intact ?? false,
      summaryLogIntact: read.summaryIntact,
      evidenceRecords: read.main?.ev.length ?? 0,
    },
    subject: summaryFor(read.summaries, fx.subject),
    control: summaryFor(read.summaries, fx.control),
    subjectResolved: read.main?.subjectRes.some((s) => s.role === 'subject' && s.resolution === 'resolved') ?? null,
  });

  return {
    ...shared,
    agreement,
    moduleId: redact(read.main?.handshakes[0]?.moduleId ?? null),
    cell,
    counts: {
      passRecords: read.main?.counts.PASS ?? 0,
      evRecords: read.main?.ev.length ?? 0,
      handshakes: read.main?.handshakes.length ?? 0,
      tornLines: read.main?.tornLines.length ?? 0,
      nulBytes: read.main?.nulBytes ?? 0,
      lldRunningPassLines: lldObserved.runs.length,
      summarySource: read.summarySource,
      summaryTornLines: read.side?.tornLines.length ?? 0,
      summaryNulBytes: read.side?.nulBytes ?? 0,
      summaryUnits: read.summaries.map((s) => s.unit),
    },
  };
}

/**
 * The lane's own negative control: a link that is NOT an LTO link, run through
 * exactly the same code path, which must be refused.
 *
 * The objects are compiled without `-flto` and the link line still says `-flto`
 * -- a real build shape, and the one the silent-ignore trap is dangerous in.
 * `--load-pass-plugin` is then examined by nobody: exit 0, empty stderr, no
 * observer log. Guard 1 must fire on both halves (ELF inputs, zero
 * `Running pass` lines).
 *
 * A guard that has never been shown to fire is not a guard, so this runs by
 * default and a run in which it does NOT fire fails the whole invocation.
 */
function negativeControl({ o, fx, name, work, plugin, symbols }) {
  const fxDir = path.join(o.lab, 'fixtures', name);
  const dir = path.join(work, `negctl-${name}`);
  fs.mkdirSync(dir, { recursive: true });
  const objects = { lto: [], opaque: [], forms: {}, all: [] };
  for (const s of [...fx.lto, ...fx.opaque]) {
    const obj = path.join(dir, `${path.basename(s, '.c')}.o`);
    const r = run(o.cc, [o.opt, '-c', path.join(fxDir, s), '-o', obj]);
    if (r.rc !== 0) return { ran: false, why: `${s} did not compile without -flto` };
    // Declared as lto inputs on purpose: that is what the cell BELIEVES, and the
    // guard's job is to disagree with it.
    objects.lto.push({ name: path.basename(obj), kind: objectKind(fs.readFileSync(obj)) });
    objects.all.push(obj);
  }
  const lw = linkWindowCell({ o, fx, name, form: 'full', work: dir, plugin, symbols, objects, withPlugin: true });
  if (lw.toolFailed) return { ran: false, why: `the ${lw.where} failed` };
  return {
    ran: true,
    fired: lw.cell.measurement === MEASUREMENT.BROKEN_MEASUREMENT
      && lw.cell.reasons.includes(REASON.NOT_AN_LTO_LINK),
    measurement: lw.cell.measurement,
    reasons: lw.cell.reasons,
    inputKinds: objects.lto.map((i) => i.kind),
    lldRunningPassLines: lw.linkerPipeline.runs,
    observerEvRecords: lw.counts?.evRecords ?? 0,
  };
}

/**
 * ThinLTO: the refusal, and the measurement that earns it.
 *
 * Under `-flto=thin` lld builds one PassBuilder per backend module.
 * `llvmGetPassPluginInfo` is called once per PassBuilder
 * (PropertyObserver.cpp:141), its registration callback replaces a
 * process-global tracker (PropertyObserver.cpp:55, :153), and that tracker's
 * constructor opens OBS_OUT with no append flag, truncating it
 * (History.cpp:56). With lld's default thread pool the backends also run
 * concurrently, so the surviving file is not the last backend's history -- it is
 * whatever the interleaving left.
 *
 * This function runs that link ONCE and records how intact the log came back.
 * It never reads an attribution out of it. Without this run the lane would be
 * asserting a defect rather than measuring one, which is the thing the README of
 * every other lane here refuses to do.
 */
function thinLtoEvidence({ o, fx, name, work, plugin, symbols, objects }) {
  const dir = path.join(work, `thin-evidence-${name}`);
  fs.mkdirSync(dir, { recursive: true });
  const obs = path.join(dir, 'observer.tsv');
  const app = path.join(dir, 'app.thin');
  const r = run(o.cc, [o.opt, '-flto=thin', '-fuse-ld=lld', ...objects.all, '-o', app,
    `-Wl,--load-pass-plugin=${plugin}`],
  { env: observerEnv({ subject: fx.subject, control: fx.control, symbols, outPath: obs }) });
  if (r.rc !== 0) {
    // Recorded rather than retried. A ThinLTO link that does not survive the
    // plugin at all is the same defect showing a different face, and the
    // interleaved stderr below -- two backends' diagnostics spliced mid-word --
    // is itself the concurrency evidence.
    return {
      attempted: true, linkFailed: true, linkRc: r.rc, signal: r.signal,
      stderr: redact(r.stderr).slice(0, 1200),
    };
  }
  const log = fs.existsSync(obs) ? parseObserverLog(fs.readFileSync(obs)) : null;
  const moduleIds = {};
  for (const h of log?.handshakes ?? []) {
    // Under ThinLTO the module identifier is the object's path, so it is
    // basenamed here rather than at the scan.
    const id = redact(h.moduleId);
    moduleIds[id] = (moduleIds[id] ?? 0) + 1;
  }
  return {
    attempted: true,
    linkRc: r.rc,
    logBytes: fs.existsSync(obs) ? fs.statSync(obs).size : 0,
    nulBytes: log?.nulBytes ?? 0,
    handshakeRecords: log?.handshakes.length ?? 0,
    distinctHandshakeModuleIds: Object.keys(moduleIds).length,
    handshakeModuleIds: moduleIds,
    tornLines: log?.tornLines.length ?? 0,
    tornLineSamples: (log?.tornLines ?? []).slice(0, 5).map(redact),
    intact: log?.intact ?? false,
  };
}

/**
 * gcc. Three probes, all of them refusals, and one differential that needs no
 * observer at all.
 *
 * The word for the first three is UNSUPPORTED and it is the correct one:
 * interfaces.md 3.1 reserves it for "the toolchain refused the invocation", and
 * that is literally what happens -- `/usr/bin/ld: unrecognized option
 * '--load-pass-plugin='`. It is NOT the ThinLTO situation, where the toolchain
 * accepts the invocation and the instrument comes apart; that one is
 * BROKEN_MEASUREMENT with state NOT_OBSERVED.
 */
function gccProbes({ o, name, fx, work, plugin }) {
  const dir = path.join(work, `gcc-${name}`);
  fs.mkdirSync(dir, { recursive: true });
  const fxDir = path.join(o.lab, 'fixtures', name);
  const objs = { lto: [], nolto: [] };
  for (const s of fx.lto) {
    const obj = path.join(dir, `${path.basename(s, '.c')}.lto.o`);
    const r = run(o.gcc, [o.opt, '-flto', '-c', path.join(fxDir, s), '-o', obj]);
    if (r.rc !== 0) return { available: false, why: firstLine(r.stderr) || `${o.gcc} could not compile ${s}` };
    objs.lto.push(obj);
  }
  for (const s of fx.opaque) {
    const obj = path.join(dir, `${path.basename(s, '.c')}.o`);
    const r = run(o.gcc, [o.opt, '-c', path.join(fxDir, s), '-o', obj]);
    if (r.rc !== 0) return { available: false, why: firstLine(r.stderr) };
    objs.nolto.push(obj);
  }
  const all = [...objs.lto, ...objs.nolto];

  const probes = {};
  const p1 = run(o.gcc, [o.opt, '-flto', '-o', path.join(dir, 'a1'), ...all, `-Wl,--load-pass-plugin=${plugin}`]);
  probes.loadPassPluginOnGccLink = { rc: p1.rc, stderr: redactLines(p1.stderr, 3) };
  const p2 = run(o.gcc, [o.opt, '-flto', '-o', path.join(dir, 'a2'), ...all, `-fplugin=${plugin}`]);
  probes.llvmPluginIntoLto1 = { rc: p2.rc, stderr: redactLines(p2.stderr, 3) };
  const p3 = run(o.gcc, [o.opt, '-flto', '-fuse-ld=lld', '-o', path.join(dir, 'a3'), ...all, '-Wl,--lto-debug-pass-manager']);
  probes.gccObjectsThroughLld = { rc: p3.rc, stderr: redactLines(p3.stderr, 3) };

  // The differential the artifact can still answer: is the wipe there without
  // LTO and gone with it? That question does not need a pass observer, and
  // answering it is what keeps the gcc row from reading as "nothing happens on
  // gcc" when in fact the same thing happens and only the attribution is out of
  // reach.
  const artifact = {};
  const stockLto = path.join(dir, 'stock.lto');
  const rl = run(o.gcc, [o.opt, '-flto', '-o', stockLto, ...all]);
  const noltoObjs = [];
  let ok = rl.rc === 0;
  for (const s of [...fx.lto]) {
    const obj = path.join(dir, `${path.basename(s, '.c')}.n.o`);
    const r = run(o.gcc, [o.opt, '-c', path.join(fxDir, s), '-o', obj]);
    if (r.rc !== 0) { ok = false; break; }
    noltoObjs.push(obj);
  }
  const stockNo = path.join(dir, 'stock.nolto');
  if (ok) ok = run(o.gcc, [o.opt, '-o', stockNo, ...noltoObjs, ...objs.nolto]).rc === 0;
  if (ok) {
    for (const [k, exe] of [['nolto', stockNo], ['fullLto', stockLto]]) {
      artifact[k] = readWipe(exe, fx);
    }
  } else {
    artifact.unavailable = 'a gcc stock build for the differential did not link';
  }

  return {
    available: true,
    probes,
    // UNSUPPORTED, earned: the linker refused the option.
    attributionCell: gradeCell({
      refusal: {
        measurement: MEASUREMENT.UNSUPPORTED,
        reason: `${REASON.LINKER_REFUSED_PLUGIN_OPTION}: ${probes.loadPassPluginOnGccLink.stderr[0] ?? 'no diagnostic'}`,
      },
    }),
    artifact,
    note: 'there is no gcc pass observer in this tree either (compiler/pass-instrumentation holds three LLVM plugins), '
      + 'so even a channel would have nothing to load. That second fact is about this tree, not about gcc, and is kept separate.',
  };
}

/**
 * The artifact-level reading, through the shared objdump oracle.
 *
 * Pointed at `fx.artifact`'s callers rather than at the observer's subject and
 * control names. In a family without the noinline intervention there is no
 * `handle` in the linked program at all, and asking objdump about it comes back
 * NOT_OBSERVED -- a reading that says "the executable cannot be read for this
 * cell" when the truth is "that function was absorbed, which is the measurement".
 * The absorbing function is named in the fixture table.
 *
 * This is the ONE instrument in this lane that survives the intervention being
 * removed: it reads the linked bytes, not the pass pipeline, so it still answers
 * in a family where no unit is left to attribute anything to. That is why the
 * elimination half of the pair's claim is taken from here and the attribution
 * half from the observer -- taking both from the observer would be circular.
 */
function readWipe(exe, fx) {
  const where = fx.artifact ?? { subjectCaller: fx.subject, controlCaller: fx.control, absorbed: false };
  const script = path.join(HERE, 'tools', 'read-wipe.py');
  const r = run('python3', [script, exe, where.subjectCaller, fx.helper ?? '-', String(fx.bufferBytes),
    where.controlCaller, String(fx.bufferBytes)]);
  if (r.rc !== 0) return { unavailable: firstLine(r.stderr) || `read-wipe.py exited ${r.rc}` };
  let j;
  try {
    j = JSON.parse(r.stdout);
  } catch {
    return { unavailable: 'read-wipe.py did not print JSON' };
  }
  const out = {
    subject: j.subjectDescribed,
    control: j.controlDescribed,
    inlined: j.subject.inlined,
    readAt: { subject: where.subjectCaller, control: where.controlCaller },
    // The numbers the words were folded from. `describe()` rounds a reading into
    // one cell of a table; a byte count that only ever appears inside a sentence
    // cannot be reconciled against anything, which is the defect lib/record.mjs
    // was split out over.
    fill: {
      verdict: j.subject.verdict,
      where: j.subject.where,
      bytes: j.subject.bytes,
      stores: j.subject.stores,
      memsetCalls: j.subject.memsetCalls,
    },
  };
  if (!where.absorbed) return out;

  // Both wipes are in one body here, so the verdict WORD stops discriminating --
  // `PRESENT in main` is what a surviving subject store and a surviving control
  // store both produce. What still discriminates is how many wipes' worth of
  // zero fill that body holds.
  out.absorbedFill = j.subject.where === where.subjectCaller
    ? absorbedFillReading({ bytes: j.subject.bytes, memsetCalls: j.subject.memsetCalls, bufferBytes: fx.bufferBytes })
    : {
      reading: 'fill-read-outside-the-absorbing-body',
      discriminating: false,
      why: `the reading resolved to ${j.subject.where} rather than ${where.subjectCaller}: the helper was not `
        + 'absorbed after all, so this byte count is not the count of both fills in one body',
    };
  return out;
}

/* ----------------------------------------------------------------- main -- */

function main() {
  const o = parseArgs(process.argv);
  if (!o.lab) die(4, 'no --lab');
  if (!o.out) die(4, 'no --out');
  if (!o.plugin) die(4, 'no --plugin');
  if (!fs.existsSync(o.plugin)) die(4, `no plugin at the path given to --plugin`);
  const outAbs = path.resolve(o.out);
  if (!path.relative(REPO, outAbs).startsWith('..')) {
    die(4, '--out is inside the checkout. Results are measurement output and live in the lab.');
  }
  for (const name of o.fixtures) if (!FIXTURES[name]) die(4, `unknown fixture ${name}`);
  for (const f of o.forms) if (f !== 'full' && f !== 'thin') die(4, `unknown LTO form ${f}`);

  const fxRoot = path.join(o.lab, 'fixtures');
  if (!fs.existsSync(fxRoot)) die(4, 'no fixtures in the lab: run tools/make-lto-fixtures.sh first');

  const work = path.join(o.lab, 'work');
  fs.rmSync(work, { recursive: true, force: true });
  fs.mkdirSync(work, { recursive: true });

  const symbols = effectSymbols();
  const results = {
    schema: 'lto-window-v1',
    lane: 'lto-window',
    generatedBy: 'compiler/eval/lto-window/run-lto-window.mjs',
    optLevel: o.opt,
    toolchain: toolchainIdentity(o),
    plugin: { basename: path.basename(o.plugin), sha256: sha256File(o.plugin) },
    effectSymbols: { list: symbols.id, symbols: symbols.symbols },
    observationPoints: [],
    cells: [],
    // One entry per (family with the intervention, family without it) pair that
    // this run measured BOTH halves of. Empty is a legal and honest state: a run
    // given `--fixtures xtu` has not put the question.
    interventionPairs: [],
    thinLto: {},
    negativeControl: {},
    gcc: {},
    unobserved: [],
    // What this run turned off, in one place, whether or not any of it is true.
    // A reader should not have to infer a skip from an absence.
    skipped: {
      negativeControl: o.skipNegativeControl,
      gcc: o.skipGcc,
      thinltoEvidence: o.skipThinEvidence,
    },
  };

  // A cell that COMPLETED: the instrument worked and a property was read. `OK`
  // alone is not that -- interfaces.md 3.1 allows OK with NOT_OBSERVED, which is
  // an instrument that worked and had nothing to read at this point.
  const completed = (cell) => cell.measurement === MEASUREMENT.OK && cell.state !== STATE.NOT_OBSERVED;

  let toolFailure = null;
  let byteFinding = false;
  // Cells from a family without the intervention whose instrument faulted. Kept
  // as its own list so the run can say, in the words it prints, that those cells
  // are not the family's result.
  const interventionFaults = [];

  for (const name of o.fixtures) {
    const fx = FIXTURES[name];
    const fxDir = path.join(fxRoot, name);

    for (const form of o.forms) {
      const ltoFlag = form === 'thin' ? '-flto=thin' : '-flto';
      const objDir = path.join(work, `obj-${name}-${form}`);
      fs.mkdirSync(objDir, { recursive: true });

      const objects = { lto: [], opaque: [], forms: {}, all: [] };
      let compileFailed = null;
      for (const s of fx.lto) {
        const obj = path.join(objDir, `${path.basename(s, '.c')}.o`);
        const r = run(o.cc, [o.opt, ltoFlag, '-c', path.join(fxDir, s), '-o', obj]);
        if (r.rc !== 0) { compileFailed = { s, stderr: redact(r.stderr).slice(0, 1000) }; break; }
        objects.lto.push({ name: path.basename(obj), kind: objectKind(fs.readFileSync(obj)) });
        objects.all.push(obj);
        const dump = run('llvm-bcanalyzer-18', ['-dump', obj]);
        objects.forms[path.basename(obj)] = dump.rc === 0 ? ltoFormFromBcanalyzerDump(dump.stdout) : null;
      }
      for (const s of fx.opaque) {
        const obj = path.join(objDir, `${path.basename(s, '.c')}.o`);
        const r = run(o.cc, [o.opt, '-c', path.join(fxDir, s), '-o', obj]);
        if (r.rc !== 0) { compileFailed = { s, stderr: redact(r.stderr).slice(0, 1000) }; break; }
        objects.opaque.push({ name: path.basename(obj), kind: objectKind(fs.readFileSync(obj)) });
        objects.all.push(obj);
      }
      if (compileFailed) { toolFailure = `${name}/${form}: ${compileFailed.s} did not compile`; continue; }

      /* --- compile-time window --------------------------------------- */
      const cw = compileWindowCell({ o, fx, name, form, work, plugin: o.plugin, symbols: symbols.symbols });
      if (cw.toolFailed) {
        toolFailure = `${name}/${form}: the compile-window compile failed`;
      } else {
        results.cells.push({
          id: `${name}.${form}.compile`, fixture: name, form, vendor: 'clang', window: 'compile',
          stage: STAGE_COMPILE, checkpoint: CHECKPOINT_AFTER_PASS,
          ...cw.cell, counts: cw.counts,
        });
        results.observationPoints.push({
          id: `${name}-${form}-compile`, checkpoint: CHECKPOINT_AFTER_PASS, stage: STAGE_COMPILE,
          reached: completed(cw.cell), optLevel: o.opt, tool: results.toolchain.cc,
          unreachedReason: completed(cw.cell) ? null : cw.cell.reasons.join('; '),
        });
      }

      /* --- link-time window ------------------------------------------ */
      const withPlugin = form === 'full';
      const lw = linkWindowCell({ o, fx, name, form, work, plugin: o.plugin, symbols: symbols.symbols, objects, withPlugin });
      if (lw.toolFailed) {
        toolFailure = `${name}/${form}: the ${lw.where} failed`;
        continue;
      }

      if (withPlugin) {
        if (lw.byteIdentical === false) byteFinding = true;
        const record = {
          id: `${name}.${form}.link`, fixture: name, form, vendor: 'clang', window: 'link',
          stage: STAGE_LTO_BACKEND, checkpoint: CHECKPOINT_AFTER_PASS,
          moduleId: lw.moduleId,
          ...lw.cell,
          guards: linkGuardRecord(lw),
          counts: lw.counts,
          intervention: fx.intervention,
          // Read from the STOCK executable of this same link, in every family.
          // The intervened families get it too: a claim about what removing the
          // attribute costs needs the same reading on both sides of the pair, or
          // the two sides differ in the instrument as well as in the fixture.
          artifactReading: readWipe(lw.exe.stock, fx),
        };
        if (fx.intervention === null) {
          // The family WITHOUT the intervention. Its cell is graded as a reading
          // of what the intervention buys -- not as a repeat of the intervened
          // family's measurement, and not as the fixture repaired.
          //
          // The branch that matters is the one that says nothing: a
          // BROKEN_MEASUREMENT here is an instrument fault and looks EXACTLY
          // like the expected outcome in a results table (both are a link cell
          // that carries no attribution). Reporting one as the other would be
          // taking a shredded log for evidence about inlining.
          record.interventionAbsent = interventionAbsentReading(lw.cell);
          if (!record.interventionAbsent.usable) {
            results.unobserved.push(`${name}.${form}.what-the-intervention-buys`);
            interventionFaults.push(`${name}.${form}.link: ${record.interventionAbsent.why}`);
          }
        }
        results.cells.push(record);
        results.observationPoints.push({
          id: `${name}-${form}-lto-backend`, checkpoint: CHECKPOINT_AFTER_PASS, stage: STAGE_LTO_BACKEND,
          reached: completed(lw.cell), optLevel: o.opt, tool: results.toolchain.lld,
          unreachedReason: completed(lw.cell) ? null : lw.cell.reasons.join('; '),
        });
      } else {
        // ThinLTO. Refused, with the refusal earned by its own measurement.
        const evidence = o.skipThinEvidence
          ? skippedRecord('thinltoEvidence', SKIP_WHY.thinltoEvidence)
          : thinLtoEvidence({ o, fx, name, work, plugin: o.plugin, symbols: symbols.symbols, objects });
        results.thinLto[name] = { evidence, linkerPipelineRuns: lw.linkerPipeline.runs, inputsOk: lw.inputs.ok };
        results.cells.push({
          id: `${name}.thin.link`, fixture: name, form: 'thin', vendor: 'clang', window: 'link',
          stage: STAGE_LTO_BACKEND, checkpoint: CHECKPOINT_AFTER_PASS,
          ...gradeCell({
            refusal: {
              measurement: MEASUREMENT.BROKEN_MEASUREMENT,
              reason: REASON.MULTI_PASSBUILDER,
            },
          }),
          guards: linkGuardRecord(lw),
          evidenceThisRun: evidence.attempted === true,
        });
        results.unobserved.push(`${name}.thin.link-time-attribution`);
        results.observationPoints.push({
          id: `${name}-thin-lto-backend`, checkpoint: CHECKPOINT_AFTER_PASS, stage: STAGE_LTO_BACKEND,
          reached: false, optLevel: o.opt, tool: results.toolchain.lld,
          unreachedReason: `${REASON.MULTI_PASSBUILDER}: lld builds one PassBuilder per backend module and the `
            + 'observer keeps a single process-global tracker whose constructor truncates OBS_OUT',
        });
      }
    }

    /* --- the lane's negative control, once per fixture ----------------- */
    // A skip is written down. It used to leave the field as `{}`, which reads
    // as "there is nothing to say about the negative control here" -- and the
    // README claimed the opposite.
    results.negativeControl[name] = o.skipNegativeControl
      ? skippedRecord('negativeControl', SKIP_WHY.negativeControl)
      : negativeControl({ o, fx, name, work, plugin: o.plugin, symbols: symbols.symbols });

    /* --- gcc, once per fixture ---------------------------------------- */
    if (o.skipGcc) {
      results.gcc[name] = skippedRecord('gcc', SKIP_WHY.gcc);
    } else {
      results.gcc[name] = gccProbes({ o, name, fx, work, plugin: o.plugin });
      if (results.gcc[name].available) {
        // The gcc row is a cell like any other, so that the tally counts its
        // word. UNSUPPORTED that only appears in a side block is a word nobody
        // sees.
        results.cells.push({
          id: `${name}.gcc.link`, fixture: name, form: 'full', vendor: 'gcc', window: 'link',
          stage: STAGE_LTO_BACKEND, checkpoint: CHECKPOINT_AFTER_PASS,
          ...results.gcc[name].attributionCell,
          artifactDifferential: results.gcc[name].artifact,
        });
        results.unobserved.push(`${name}.gcc.link-time-pass-attribution`);
        results.observationPoints.push({
          id: `${name}-gcc-lto-backend`, checkpoint: CHECKPOINT_AFTER_PASS, stage: STAGE_LTO_BACKEND,
          reached: false, optLevel: o.opt, tool: results.toolchain.gcc,
          unreachedReason: results.gcc[name].attributionCell.reasons.join('; '),
        });
      }
    }
  }

  /* --- the intervention pair, once both halves are in ------------------- */
  //
  // Assembled from the cells rather than measured separately: the pair is a way
  // of READING two cells this run already produced, and a third measurement
  // would be a third thing to keep in step. A pair is only formed when both
  // halves were asked for; a run given one of them says so by carrying no pair,
  // which is a different claim from a pair that failed.
  for (const name of o.fixtures) {
    const fx = FIXTURES[name];
    if (fx.intervention !== null || !fx.pairedWith) continue;
    const plain = results.cells.find((c) => c.id === `${name}.full.link`);
    const intervened = results.cells.find((c) => c.id === `${fx.pairedWith}.full.link`);
    if (!plain || !intervened) continue;
    results.interventionPairs.push({
      withIntervention: fx.pairedWith,
      withoutIntervention: name,
      intervention: FIXTURES[fx.pairedWith].intervention,
      optLevel: o.opt,
      claim: 'the elimination does not depend on the intervention; the intervention is required only to have '
        + 'a (pass, unit) to attribute the elimination TO',
      attributionWithIntervention: intervened.attribution ?? null,
      readingWithoutIntervention: plain.interventionAbsent ?? null,
      artifactWithIntervention: intervened.artifactReading ?? null,
      artifactWithoutIntervention: plain.artifactReading ?? null,
      verdict: interventionPairVerdict({
        intervenedCell: intervened,
        plainReading: plain.interventionAbsent ?? null,
        plainFill: plain.artifactReading?.absorbedFill ?? null,
      }),
    });
  }

  results.counts = {
    cells: results.cells.length,
    ok: results.cells.filter((c) => c.measurement === MEASUREMENT.OK).length,
    // OK and still nothing to read -- interfaces.md 3.1's third situation.
    // Counted on its own, because "the instrument worked" and "a property was
    // read" are two facts and one number for both is how they get merged.
    okNothingRead: results.cells.filter((c) => c.measurement === MEASUREMENT.OK && c.state === STATE.NOT_OBSERVED).length,
    completed: results.cells.filter(completed).length,
    brokenMeasurement: results.cells.filter((c) => c.measurement === MEASUREMENT.BROKEN_MEASUREMENT).length,
    unsupported: results.cells.filter((c) => c.measurement === MEASUREMENT.UNSUPPORTED).length,
    linkTimeAttributions: results.cells.filter((c) => c.stage === STAGE_LTO_BACKEND && c.attribution).length,
    // A ratio, never a float: interfaces.md's records carry integers.
    okShare: { num: results.cells.filter((c) => c.measurement === MEASUREMENT.OK).length, den: results.cells.length },
    completedShare: { num: results.cells.filter(completed).length, den: results.cells.length },
  };

  fs.mkdirSync(outAbs, { recursive: true });
  const json = `${JSON.stringify(results, null, 2)}\n`;
  const hits = scrubbed(json);
  if (hits.length) {
    process.stderr.write(`lto-window: the result carries ${hits.length} absolute path(s); refusing to write.\n`);
    for (const h of hits.slice(0, 5)) process.stderr.write(`  ${h}\n`);
    process.exit(4);
  }
  const outFile = path.join(outAbs, 'lto-window.json');
  fs.writeFileSync(outFile, json);
  if (!o.keep) fs.rmSync(work, { recursive: true, force: true });

  for (const c of results.cells) {
    const attr = c.attribution ? `${c.attribution.pass} on ${c.attribution.unit}` : '-';
    process.stdout.write(
      `${c.id.padEnd(24)} ${String(c.stage).padEnd(12)} ${c.measurement.padEnd(19)} ${String(c.state).padEnd(13)} ${attr}\n`);
  }
  process.stdout.write(`\n${results.counts.ok}/${results.counts.cells} cells OK; `
    + (results.counts.okNothingRead ? `${results.counts.okNothingRead} of them with nothing to read; ` : '')
    + `${results.counts.linkTimeAttributions} link-time attribution(s); results written\n`);
  // In the report's own summary, not only in the JSON: the table a reader looks
  // at is the table that has to say which demonstration behind it was skipped.
  for (const line of skipSummaryLines(results.skipped)) process.stdout.write(`${line}\n`);

  // The pair, in the printed report. A reader who sees `xtu-inline.full.link`
  // carrying no attribution and nothing else has been shown the shape of the
  // expected outcome and none of its meaning.
  for (const p of results.interventionPairs) {
    const v = p.verdict.supported;
    process.stdout.write(`\n${p.withIntervention} vs ${p.withoutIntervention} (${p.intervention} present / absent), ${p.optLevel}\n`);
    process.stdout.write(`  with:    ${p.attributionWithIntervention ? `${p.attributionWithIntervention.pass} on ${p.attributionWithIntervention.unit}` : 'no attribution'}\n`);
    process.stdout.write(`  without: ${p.readingWithoutIntervention?.reading ?? 'not measured'}\n`);
    process.stdout.write(`  artifact without the intervention: ${p.artifactWithoutIntervention?.absorbedFill?.reading ?? p.artifactWithoutIntervention?.subject ?? 'not read'}\n`);
    process.stdout.write(`  claim ${v === true ? 'SUPPORTED' : v === false ? 'CONTRADICTED' : 'NOT ESTABLISHED'}: ${p.verdict.why}\n`);
  }
  // Said on its own line, in the report, not only as a `usable: false` field in
  // the JSON. This is the sentence that keeps a broken instrument from being
  // published as the finding the family exists to produce.
  for (const f of interventionFaults) {
    process.stdout.write(`\nNOT the family's result -- ${f}\n`);
  }

  const decision = exitDecision({
    cells: results.cells,
    skipped: results.skipped,
    toolFailure,
    byteFinding,
    negativeControls: results.negativeControl,
    // The families this run was ASKED for, so that a family which reached the
    // cells but not the per-family checks is caught by its absence from the
    // negative-control record rather than by a field it never wrote.
    families: o.fixtures,
  });
  for (const m of decision.messages) process.stderr.write(`lto-window: ${m}\n`);
  process.exit(decision.code);
}

main();

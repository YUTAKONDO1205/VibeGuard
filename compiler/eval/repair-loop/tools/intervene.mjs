#!/usr/bin/env node
/**
 * intervene -- does the property come back if the pass that ate it is taken out
 * of the pipeline?
 *
 * The repair loop measures ONE repair candidate: a pin that makes the wipe
 * unremovable. This tool measures a different one, so that `pin-families.json`
 * has more than a single candidate per shape to choose between: DELETE THE
 * ATTRIBUTED PASS and replay. If the property comes back, the shape is
 * repairable by suppressing that pass and the row says which pass; if it does
 * not come back at any position tried, the shape is not repairable that way and
 * the family routes to the source-side rule instead.
 *
 * The measurement is a replay, in five steps, on one translation unit:
 *
 *   1. The pre-optimisation IR, from the compiler the measurement is about:
 *        clang -O<n> -Xclang -disable-llvm-passes -emit-llvm -S
 *   2. THE PIPELINE STRING THAT COMPILER ACTUALLY BUILT:
 *        clang -O<n> -mllvm -print-pipeline-passes
 *      NOT `default<O2>`. clang tunes its own pipeline, and this repository has
 *      already established that the two strings differ
 *      (../../../pass-instrumentation/observer/rq2/rq2.mjs, check RQ2-01), so a
 *      harness that replays `default<O2>` injects at positions that do not
 *      exist in the compilation it claims to describe.
 *   3. The UNMODIFIED replay: that string, under opt-18, over that IR, then
 *      llc-18. It must reproduce the loss. If it does not, the interventions
 *      below would be interventions on a different pipeline, and the tool says
 *      so and stops -- that is a result, not a failure.
 *   4. Attribution: the same pipeline truncated after each pass in turn, both
 *      forms compiled, and the state of the property read at every prefix. The
 *      WHOLE sequence is kept, not the first PRESENT -> LOST transition
 *      (../../../schema/interfaces.md section 3).
 *   5. The interventions: the attributed pass deleted, and separately the pass
 *      after it, from the same string -- by POSITION, so that deleting pass 59
 *      deletes that one occurrence and not the other eleven `instcombine`s.
 *
 * TWO CHANNELS, BOTH READ, AND WHY THAT IS NOT OPTIONAL. Every reading is taken
 * on the IR (after opt) and on the assembly (after llc). ../../calibration has a
 * measured cell where a wipe survives the entire IR optimiser and is dropped
 * after it: an IR-only reading there reports a must-survive property holding in
 * an artefact that does not clear the buffer. A shape can therefore look
 * repaired at IR and still be gone at asm, and this tool would misclassify it as
 * repairable. The asm channel decides; the IR channel says at which stage.
 *
 * CONTROLS, without which none of the above means anything:
 *   - the positive control travels in the same translation unit. It is the find
 *     step's own CONTROL, imported from ../../ai-generated/lib/ablation-cell.mjs
 *     and appended to the subject, and it is read with that lane's
 *     controlPresent(). The fixture's own read-after-wipe control (`wipe_kept`)
 *     is read beside it. If either goes missing in a replay, the reading is
 *     BROKEN_MEASUREMENT, not a finding.
 *   - the verdict is always DIFFERENTIAL: the subject compiled as written
 *     against the subject with its wipe statement deleted, judged by the find
 *     step's verdictOf. Nothing here decides survival by searching a listing for
 *     a symbol name. The memset counts that are printed are a corroboration
 *     beside the verdict and are never the verdict.
 *   - "never comes back" is not this file's decision. It is
 *     ../lib/pin-families.mjs's interventionVerdict(), which refuses the phrase
 *     unless at least two positions were tried AND the asm channel was read.
 *
 * gcc: THE SAME QUESTION, THROUGH THE ONLY CHANNEL GCC OFFERS. gcc prints no
 * pass pipeline and has no `opt`/`llc` to replay one under, so steps 1-5 above
 * have no gcc form. What gcc does expose is `-fdisable-tree-<pass>`, and the
 * walk that finds which pass to name is gcc's own `-fdump-tree-all` sequence:
 *
 *   1. compile both units with `-fdump-tree-all -fdump-rtl-all` and read every
 *      numbered dump DIFFERENTIALLY -- the target function's region as written
 *      against the same region with the wipe ablated -- to find the first dump
 *      at which the wipe stops making a difference (`firstIndifferentDump`);
 *   2. compile again with `-fdisable-tree-<that pass>` and see whether it comes
 *      back; then at a second position, which is where the walk says the loss
 *      moved to, and finally with both passes disabled together.
 *
 * The result is NOT written under clang's name, and it is not written under the
 * neighbouring gcc probe's name either: clang's reading is a position in a
 * pipeline this tool replays; `../../second-vendor/run-gcc-dump-probe.mjs` reads
 * gcc's dumps by searching ONE unit's region for a memset token and calls the
 * answer `firstAbsentDump`; this channel reads the same dumps DIFFERENTIALLY, a
 * different oracle giving a different statement, and calls its answer
 * `firstIndifferentDump`. This tool emits that word, and never `firstLossPass`,
 * never `firstAbsentDump` and never `attribution.pass`. The three-way
 * distinction is set out in `../lib/gcc-disable-tree.mjs`.
 *
 * THE GCC CHANNEL'S OWN CONTROLS, all four required, because a flag that was
 * ignored and a flag that was honoured produce the same exit code -- and because
 * a walk that read nothing at all answers like a walk that read something:
 *   (a) gcc announces every disable on stderr (`note: disable pass tree-dse1 for
 *       functions in the range of ...`). The note naming the pass that was asked
 *       for must be present in BOTH compiles of an intervention. A build that
 *       merely succeeded is never read as the intervention having happened.
 *   (b) a deliberately misspelled pass name must make the build FAIL (`error:
 *       unknown pass tree-dse1xx specified in '-fdisable'`), once per run and
 *       before any reading is taken. Without it, "no note" could mean "gcc does
 *       not announce disables" rather than "nothing was disabled".
 *   (c) the co-resident positive control and the fixture's own read-after-wipe
 *       control must be PRESENT in every replay, as on clang.
 *   (d) the walk must have READ the function in at least one dump. A dump that
 *       does not hold the function in both units is NOT_OBSERVED, and a walk
 *       made entirely of those compared nothing: it is `function-in-no-dump`,
 *       which is an apparatus failure and not a finding about the wipe. gcc-13
 *       `-O2 -fdump-tree-all` emits ~122 dumps for a small file, so zero
 *       readable ones means the walk, not the compiler, is what went wrong.
 *
 *   node intervene.mjs --out <lab dir> [--cc clang-18|gcc-13] [--opt -O2]
 *                      [--fixture <dir>] [--fn handle_request] [--sweep full|bisect]
 *   node intervene.mjs --selftest        (no compiler; the pipeline surgery only)
 *
 * --out must lie outside the repository: this is a lab tool and writes nothing
 * to data/. Exit codes: 0 the run completed and its verdict is in the report
 * (including CAME_BACK, NEVER_CAME_BACK and NOT_ENOUGH_EVIDENCE, which are
 * results); 2 the replay did not reproduce the loss, a control went missing, or
 * the gcc channel could not be shown to have been exercised, so there is no
 * reading; 3 a tool or the fixture is missing; 4 bad arguments; 5 the report
 * carried an absolute path and was not written.
 *
 * EVERY EXIT-2 REASON ON THE GCC CHANNEL IS NAMED, once, in
 * `../lib/gcc-disable-tree.mjs`'s `GCC_EXIT_REASONS`, and every one of those
 * names is printed in `../PIN-FAMILIES.md`. `report.verdict.reason` is that key
 * and `report.verdict.why` is its sentence, so what a reader transcribes is what
 * actually happened rather than the gate's sentence about some other control.
 *
 * WHAT A READER TAKES FROM A RUN. `report.verdict` (the verdict, its reason key
 * and its sentence) and `report.gateEvidence` (what the gate was given, plus
 * `fatality` when the run stopped early). `gateEvidence` is written on EVERY
 * exit from the gcc channel, including the refusals -- it used to be written
 * only on the path that reached the gate, so precisely the runs a reader most
 * needs to explain had nothing to copy.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, appendFileSync, copyFileSync, readdirSync, rmSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { homedir } from 'node:os';
import {
  FLAGS, CONTROL, CONTROL_EFFECT, wipeSpans, ablateSpans, verdictOf, controlPresent, bodyOf,
} from '../../ai-generated/lib/ablation-cell.mjs';
import {
  parsePipeline, renderPipeline, leaves, withoutLeaf, prefixLeaves, interventionVerdict,
} from '../lib/pin-families.mjs';
import { vendorOf } from '../lib/vendor.mjs';
import {
  STAGES, orderDumps, buildDumpSequence, firstIndifferentDump, transitionsOf, flipBacks,
  disableTreeFlag, disableNoteSeen, unknownPassRefused, misspell, readingStatus, cameBack,
  FATAL_READING_STATUSES, FATAL_WALK_STATUSES, observedDumps, unpairedReading, refusalSplit,
  brokenBecause,
} from '../lib/gcc-disable-tree.mjs';
import { absolutePathHits } from '../lib/provenance.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const REPO = resolve(LANE, '..', '..', '..');
const ORACLE = resolve(LANE, '..', 'second-vendor', 'lib', 'asm-oracle.mjs');
const { observeEffect } = await import(pathToFileURL(ORACLE).href);

// ---------------------------------------------------------------------------
// arguments

function parseArgs(argv) {
  const a = {
    cc: 'clang-18', opt: '-O2', fn: 'handle_request', fixtureControl: 'wipe_kept',
    sweep: 'full', out: null, fixture: null, selftest: false, spans: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    const v = () => { const x = argv[++i]; if (x === undefined) fail(`${k} needs a value`); return x; };
    if (k === '--selftest') a.selftest = true;
    else if (k === '--cc') a.cc = v();
    else if (k === '--opt') a.opt = v();
    else if (k === '--fn') a.fn = v();
    else if (k === '--fixture') a.fixture = v();
    else if (k === '--fixture-control') a.fixtureControl = v();
    else if (k === '--sweep') a.sweep = v();
    else if (k === '--span') { const n = Number(v()); if (!Number.isInteger(n) || n < 0) fail('--span takes a 0-based span index'); a.spans.push(n); }
    else if (k === '--out') a.out = v();
    else fail(`unknown argument ${k}`);
  }
  return a;
}
function fail(msg) { process.stderr.write(`intervene: ${msg}\n`); process.exit(4); }
function cannotRun(msg) { process.stderr.write(`intervene: cannot run: ${msg}\n`); process.exit(3); }

// ---------------------------------------------------------------------------
// the pipeline surgery, self-checked
//
// The parser lives in ../lib/pin-families.mjs (pure, and tested with the table).
// What is checked HERE is the thing a unit test cannot check: that it round-trips
// the string this compiler actually printed, on this machine, today. A parser
// that silently drops a pass would otherwise produce a "pipeline without the
// attributed pass" that is missing something else as well.

const SELFTEST_CASES = [
  'a,b,c',
  'function<eager-inv>(lower-expect,sroa<modify-cfg>)',
  'cgscc(devirt<4>(inline<only-mandatory>,instcombine<max-iterations=1>)),globaldce',
  'simplifycfg<bonus-inst-threshold=1;no-forward-switch-cond>,dse',
];

function selftest() {
  const problems = [];
  for (const s of SELFTEST_CASES) {
    const t = parsePipeline(s);
    if (renderPipeline(t) !== s) problems.push(`round trip: ${s} -> ${renderPipeline(t)}`);
  }
  const t = parsePipeline(SELFTEST_CASES[2]);
  const L = leaves(t);
  if (L.map((l) => l.name).join(',') !== 'inline,instcombine,globaldce') problems.push(`leaves: ${L.map((l) => l.name).join(',')}`);
  if (L[0].path.join('>') !== 'cgscc>devirt<4>') problems.push(`path: ${L[0].path.join('>')}`);
  // deleting the only leaf of an adaptor must take the adaptor with it
  if (renderPipeline(withoutLeaf(parsePipeline('f(a),b'), 0)) !== 'b') problems.push('empty adaptor not pruned');
  if (renderPipeline(prefixLeaves(t, 2)) !== 'cgscc(devirt<4>(inline<only-mandatory>,instcombine<max-iterations=1>))') {
    problems.push(`prefix: ${renderPipeline(prefixLeaves(t, 2))}`);
  }
  if (renderPipeline(prefixLeaves(t, 0)) !== '') problems.push('empty prefix is not the empty string');
  // the gate, which is the only thing allowed to say "never comes back"
  const base = { positionsTried: 2, asmChannelRead: true, irChannelRead: true, cameBackAt: [], replayReproducedLoss: true, controlHeld: true };
  const expect = [
    [base, 'NEVER_CAME_BACK'],
    [{ ...base, positionsTried: 1 }, 'NOT_ENOUGH_EVIDENCE'],
    [{ ...base, positionsTried: 0, asmChannelRead: false }, 'NOT_ENOUGH_EVIDENCE'],
    [{ ...base, asmChannelRead: false }, 'NOT_ENOUGH_EVIDENCE'],
    [{ ...base, cameBackAt: [59] }, 'CAME_BACK'],
    [{ ...base, replayReproducedLoss: false }, 'BROKEN_MEASUREMENT'],
    [{ ...base, controlHeld: false }, 'BROKEN_MEASUREMENT'],
  ];
  for (const [ev, want] of expect) {
    const got = interventionVerdict(ev).verdict;
    if (got !== want) problems.push(`gate: expected ${want}, got ${got}`);
  }
  for (const line of problems) process.stdout.write(`FAIL  ${line}\n`);
  if (problems.length === 0) process.stdout.write(`PASS  selftest: ${SELFTEST_CASES.length} pipeline strings, leaf surgery, and the gate\n`);
  return problems.length === 0 ? 0 : 2;
}

// ---------------------------------------------------------------------------
// running things

let RUNLOG = null;
async function sh(cmd, args, opts = {}) {
  let code = 0, stdout = '', stderr = '';
  try {
    const r = await run(cmd, args, { timeout: 90000, maxBuffer: 64 * 1024 * 1024, ...opts });
    stdout = r.stdout; stderr = r.stderr;
  } catch (e) {
    code = typeof e.code === 'number' ? e.code : 1;
    stdout = e.stdout ?? ''; stderr = e.stderr ?? String(e.message ?? e);
  }
  if (RUNLOG) {
    appendFileSync(RUNLOG, `\n$ ${cmd} ${args.map((x) => (x.length > 120 ? `${x.slice(0, 60)}...<${x.length} chars>` : x)).join(' ')}\n${stdout}${stderr}--- exit=${code}\n`);
  }
  return { code, stdout, stderr };
}

/** The find step's flags, minus -S, for invocations that are not producing assembly. */
const noS = FLAGS.filter((f) => f !== '-S');

// ---------------------------------------------------------------------------
// the two channels
//
// Both read the SAME question the find step asks -- does the target function's
// body differ with and without the wipe statement -- at two points. Neither
// searches for a symbol to decide it.

/** One function's body out of a .ll, normalised: comments, blank lines and attribute noise dropped. */
export function irBodyOf(ll, fn) {
  const lines = String(ll).split('\n');
  const start = lines.findIndex((l) => new RegExp(`^define[^@]*@${fn}\\(`).test(l));
  if (start < 0) return null;
  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i] === '}') return out.join('\n');
    const l = lines[i].replace(/;.*$/, '').trimEnd();
    if (l.trim() !== '') out.push(l);
  }
  return null; // unterminated define: not a body
}

/** The IR channel's verdict, by the same differential rule as the asm channel. */
function irVerdict(llW, llWo, fn) {
  if (llW === null || llWo === null) return 'BROKEN_MEASUREMENT';
  const bW = irBodyOf(llW, fn), bWo = irBodyOf(llWo, fn);
  if (bW === null || bWo === null) return 'NOT_OBSERVED';
  return bW === bWo ? 'WIPE_ELIMINATED' : 'WIPE_SURVIVED';
}

/** Corroboration only, printed beside the verdict and never used as one. */
const memsetCalls = (ll, fn) => (irBodyOf(ll, fn) ?? '').split('\n').filter((l) => /@llvm\.memset|@memset|@__memset_chk/.test(l)).length;

// ---------------------------------------------------------------------------
// main

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.selftest) process.exit(selftest());
  if (!args.out) fail('--out <lab dir> is required (and must lie outside the repository)');
  const out = resolve(args.out);
  if (out === REPO || out.startsWith(REPO + '/') || out.startsWith(REPO + '\\')) {
    fail(`--out ${args.out} is inside the repository; this tool writes lab output only`);
  }
  if (!['full', 'bisect'].includes(args.sweep)) fail(`--sweep must be full or bisect`);
  // The vendor decides which channel this run is, and it is read from the --cc
  // basename by the lane's own vendorOf -- the same rule ../run-repair-loop.mjs
  // uses, so one spelling never means two things in one directory.
  const vendor = vendorOf(args.cc);
  if (!vendor) {
    fail(`--cc ${args.cc}: the basename names neither clang nor gcc, and which channel to drive is not guessed at (../lib/vendor.mjs)`);
  }
  const level = (vendor === 'clang' ? /^-O[0123]$/ : /^-O[0123s]$/).test(args.opt) ? args.opt : null;
  if (!level) {
    fail(vendor === 'clang'
      ? `--opt ${args.opt}: the clang channel replays through llc, which has -O0..-O3 and no -Os/-Oz`
      : `--opt ${args.opt}: the gcc channel drives gcc directly, at the five levels the lane measures (-O0..-O3, -Os)`);
  }
  if (vendor === 'gcc' && args.sweep !== 'full') {
    fail(`--sweep ${args.sweep}: the gcc channel has no pipeline prefix to bisect; it walks gcc's own dump sequence`);
  }

  const fixture = resolve(args.fixture ?? join(process.env.IRCK_LAB ?? join(homedir(), 'vg-lab', 'llvm-pass'), 'fixtures', 'erasure'));
  const targetC = join(fixture, 'target.c');
  if (!existsSync(targetC)) {
    cannotRun(`no target.c in the fixture directory. Generate it first:\n  bash compiler/llvm-pass/tools/make-fixtures.sh`);
  }
  const work = join(out, 'work');
  mkdirSync(work, { recursive: true });
  RUNLOG = join(out, 'run-log.txt');
  const suffix = `${args.cc}${level}`;
  // opt and llc are the clang channel's replay instruments; the gcc channel has
  // no counterpart and never invokes them, so it does not require them either.
  const tool = vendor === 'clang'
    ? { opt: args.cc.replace(/^clang/, 'opt'), llc: args.cc.replace(/^clang/, 'llc') }
    : {};
  for (const [what, cmd] of Object.entries({ cc: args.cc, ...tool })) {
    const r = await sh(cmd, ['--version']);
    if (r.code !== 0) cannotRun(`${what}: ${cmd} is not usable here (${r.stderr.split('\n')[0]})`);
  }

  // The subject, with the lane's positive control appended so that it is
  // co-resident in every compile of this measurement.
  const src = readFileSync(targetC, 'utf8') + CONTROL;
  const ws = wipeSpans(src, args.fn);
  if (ws.spans.length === 0) cannotRun(`no wipe span found in ${args.fn} of ${basename(targetC)}`);
  // Which spans to delete. The default is the find step's own answer -- all of
  // them -- and --span narrows it. The narrowing exists because wipeSpans is
  // derived from the generated corpus and this tool is pointed at hand-written
  // fixtures: on a `void` target whose body zeroes something, wipeHelpers puts
  // the TARGET'S OWN NAME in its call-name list, so the function's header is
  // matched as a wipe call and deleting it does not compile. No corpus erasure
  // target is declared `void`, so the tracked rows do not contain this shape;
  // the fixture does. The list is printed either way, so a span nobody meant to
  // delete is visible rather than silently included.
  const chosen = args.spans.length > 0 ? args.spans : ws.spans.map((_, i) => i);
  for (const i of chosen) if (!ws.spans[i]) fail(`--span ${i}: this subject has ${ws.spans.length} span(s)`);
  const spanText = (i) => src.slice(ws.spans[i][0], ws.spans[i][1]).replace(/\s+/g, ' ').slice(0, 72);
  for (let i = 0; i < ws.spans.length; i++) {
    process.stdout.write(`span ${i}  ${ws.kinds[i].padEnd(13)} ${chosen.includes(i) ? 'DELETED ' : 'kept    '} ${spanText(i)}\n`);
  }
  const srcW = join(work, 'w.c'), srcWo = join(work, 'wo.c');
  writeFileSync(srcW, src);
  writeFileSync(srcWo, ablateSpans(src, chosen.map((i) => ws.spans[i])));

  const report = {
    schemaVersion: 'intervene-v1',
    tool: 'compiler/eval/repair-loop/tools/intervene.mjs',
    subject: { module: basename(targetC), fn: args.fn, spans: ws.spans.length, kinds: ws.kinds, deleted: chosen },
    controls: { coResident: 'vgctl_control', fixtureOwn: args.fixtureControl },
    cc: args.cc, vendor, opt: level,
    channel: vendor === 'clang' ? 'clang/print-pipeline-passes replayed under opt and llc' : 'gcc/-fdisable-tree-<pass>, located by gcc -fdump-tree-all',
    steps: [], sequence: [], interventions: [],
  };
  if (vendor === 'gcc') {
    // The neighbour probe's warning, carried here for the same reason it exists
    // there: two different kinds of reading must not end up under one name.
    report.vocabulary = {
      emits: 'firstIndifferentDump',
      doesNotEmit: ['firstLossPass', 'firstAbsentDump', 'attribution.pass'],
      why: 'this channel reads gcc describing its own behaviour through -fdump-tree-all. Nothing is instrumented and nothing independently confirms that the dump boundary is where the transformation happened, so it is not the same kind of result as the clang channel in this same tool and is not given that field name. It is not given the NEIGHBOURING gcc probe\'s name either: ../../second-vendor/run-gcc-dump-probe.mjs reads one unit\'s dump region for a memset token and calls the answer firstAbsentDump, where "absent" means the token was not found; this channel compares the written unit\'s region against the ablated unit\'s and reports the first dump at which the wipe made no difference. Same dumps, different oracle, different statement, different word.',
    };
    delete report.sequence; // the gcc walk is report.dumpWalk.sequence, and is not a pipeline prefix sweep
  }
  const say = (s) => { process.stdout.write(`${s}\n`); report.steps.push(s); };

  // --- step 0: the stock compilation, which is what the loss is a loss in ----
  const asmOf = async (srcPath, extra, tag) => {
    const o = join(work, `${tag}.s`);
    const r = await sh(args.cc, [...FLAGS, level, ...extra, '-o', o, srcPath]);
    return r.code === 0 && existsSync(o) ? readFileSync(o, 'utf8') : null;
  };
  const stockW = await asmOf(srcW, [], `stock-w-${suffix}`);
  const stockWo = await asmOf(srcWo, [], `stock-wo-${suffix}`);
  const stock = verdictOf(stockW, stockWo, args.fn);
  report.stock = stock;
  say(`stock  ${args.cc} ${level} -S            subject ${stock.verdict}, control ${stock.control ?? '(not read)'}`);
  if (stock.verdict === 'ABLATION_DID_NOT_COMPILE') {
    say(`RESULT ABLATION_DID_NOT_COMPILE -- deleting the span(s) above leaves a translation unit the compiler rejects, so there is no ablated form to compare against. Choose the span with --span <k> (see run-log.txt for the compiler's own message).`);
    finish(report, out, suffix, 2);
  }
  if (stock.verdict !== 'WIPE_ELIMINATED') {
    say(`RESULT NO_LOSS_TO_REPLAY -- the stock compilation does not lose the property here (${stock.verdict}), so there is nothing for an intervention to bring back.`);
    finish(report, out, suffix, 0);
  }

  // Everything above is the same question on both vendors; below it, the two
  // compilers offer different channels and are driven by different code.
  if (vendor === 'gcc') {
    await gccChannel({ args, level, work, out, suffix, report, say, srcW, srcWo });
    return; // gccChannel always finishes
  }

  // --- step 1 and 2: the pre-opt IR and the string this compiler built -------
  const preOf = async (srcPath, tag) => {
    const o = join(work, `${tag}.ll`);
    const r = await sh(args.cc, [...FLAGS, level, '-emit-llvm', '-Xclang', '-disable-llvm-passes', '-o', o, srcPath]);
    return r.code === 0 && existsSync(o) ? o : null;
  };
  const preW = await preOf(srcW, `pre-w-${suffix}`), preWo = await preOf(srcWo, `pre-wo-${suffix}`);
  if (!preW || !preWo) cannotRun('could not produce the pre-optimisation IR');

  const pp = await sh(args.cc, [...noS, level, '-mllvm', '-print-pipeline-passes', '-c', '-o', join(work, 'pp.o'), srcW]);
  const PIPE = (pp.stdout + pp.stderr).trim().split('\n').filter((l) => l.includes(',')).pop();
  if (!PIPE) cannotRun('could not read the pipeline string from the compiler');
  const tree = parsePipeline(PIPE);
  if (renderPipeline(tree) !== PIPE) {
    cannotRun(`the pipeline parser does not round-trip this compiler's string; refusing to operate on it`);
  }
  const L = leaves(tree);
  writeFileSync(join(work, `pipeline-${suffix}.txt`), `${PIPE}\n`);
  report.pipeline = { passes: L.length, chars: PIPE.length, roundTrips: true, file: `work/pipeline-${suffix}.txt` };
  say(`pipeline  ${L.length} passes, ${PIPE.length} chars, printed by ${args.cc} itself (not default<O${level.slice(2)}>), parser round-trips it`);

  // --- step 3: the unmodified replay ----------------------------------------
  const replay = async (passes, preLL, tag) => {
    const ll = join(work, `${tag}.ll`), s = join(work, `${tag}.s`);
    if (passes === '') copyFileSync(preLL, ll);
    else {
      const r = await sh(tool.opt, [`-passes=${passes}`, preLL, '-S', '-o', ll]);
      if (r.code !== 0 || !existsSync(ll)) return { ll: null, asm: null, optFailed: true };
    }
    const r2 = await sh(tool.llc, [level, ll, '-o', s]);
    return {
      ll: readFileSync(ll, 'utf8'),
      asm: r2.code === 0 && existsSync(s) ? readFileSync(s, 'utf8') : null,
      optFailed: false,
    };
  };
  const un = {
    w: await replay(PIPE, preW, `replay-w-${suffix}`),
    wo: await replay(PIPE, preWo, `replay-wo-${suffix}`),
  };
  const unAsm = verdictOf(un.w.asm, un.wo.asm, args.fn);
  const unIr = irVerdict(un.w.ll, un.wo.ll, args.fn);
  const fixtureControlOf = (asm) => (asm === null ? 'NOT_OBSERVED' : observeEffect(asm, args.fixtureControl, CONTROL_EFFECT).verdict);
  report.unmodifiedReplay = {
    asm: unAsm, ir: unIr,
    fixtureControl: fixtureControlOf(un.w.asm),
    memsetCallsInIr: { w: memsetCalls(un.w.ll, args.fn), wo: memsetCalls(un.wo.ll, args.fn) },
  };
  say(`replay  unmodified                    asm ${unAsm.verdict}, ir ${unIr}, control ${unAsm.control}, ${args.fixtureControl} ${report.unmodifiedReplay.fixtureControl}`);
  const controlHeld = unAsm.control === 'PRESENT' && report.unmodifiedReplay.fixtureControl === 'PRESENT';
  const replayReproducedLoss = unAsm.verdict === 'WIPE_ELIMINATED';
  if (!replayReproducedLoss) {
    say(`RESULT REPLAY_DID_NOT_REPRODUCE -- the stock compilation loses the property and the replay of its own pipeline does not (${unAsm.verdict}). No intervention below would be an intervention on the pipeline the loss came from. This is the measurement's result, not its failure.`);
    report.verdict = interventionVerdict({ positionsTried: 0, asmChannelRead: true, irChannelRead: true, cameBackAt: [], replayReproducedLoss, controlHeld });
    finish(report, out, suffix, 2);
  }
  if (!controlHeld) {
    say(`RESULT BROKEN_MEASUREMENT -- a positive control is not PRESENT in the unmodified replay, so the oracle is blind here and nothing below is a reading.`);
    report.verdict = interventionVerdict({ positionsTried: 0, asmChannelRead: true, irChannelRead: true, cameBackAt: [], replayReproducedLoss, controlHeld });
    finish(report, out, suffix, 2);
  }

  // --- step 4: attribution, keeping the whole sequence -----------------------
  const stateAt = async (k) => {
    const passes = renderPipeline(prefixLeaves(tree, k));
    const w = await replay(passes, preW, `pfx-w-${k}`), wo = await replay(passes, preWo, `pfx-wo-${k}`);
    if (w.optFailed || wo.optFailed) return { k, ir: 'BROKEN_MEASUREMENT' };
    return { k, ir: irVerdict(w.ll, wo.ll, args.fn) };
  };
  const seq = [];
  if (args.sweep === 'full') {
    for (let k = 0; k <= L.length; k++) seq.push(await stateAt(k));
  } else {
    let lo = 0, hi = L.length;
    const cache = new Map();
    const at = async (k) => { if (!cache.has(k)) cache.set(k, await stateAt(k)); return cache.get(k); };
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((await at(mid)).ir === 'WIPE_ELIMINATED') hi = mid; else lo = mid + 1;
    }
    for (const k of [...cache.keys()].sort((a, b) => a - b)) seq.push(cache.get(k));
  }
  report.sequence = seq.map((s) => ({ prefix: s.k, pass: s.k > 0 ? L[s.k - 1].name : '(pre-opt IR)', ir: s.ir }));
  const transitions = [];
  for (let i = 1; i < seq.length; i++) if (seq[i].ir !== seq[i - 1].ir) transitions.push({ at: seq[i].k, from: seq[i - 1].ir, to: seq[i].ir, pass: L[seq[i].k - 1]?.name ?? '?' });
  report.transitions = transitions;
  const firstLoss = seq.find((s) => s.ir === 'WIPE_ELIMINATED');
  say(`sweep   ${args.sweep}, ${seq.length} prefixes read on the IR channel; state changes: ${transitions.length ? transitions.map((t) => `${t.from}->${t.to} at ${t.at} (${t.pass})`).join('; ') : 'none'}`);

  let attributed = null;
  if (!firstLoss || firstLoss.k === 0) {
    report.attribution = {
      stage: unIr === 'WIPE_ELIMINATED' ? 'unattributed' : 'after the IR pipeline (codegen)',
      pass: null,
      note: unIr === 'WIPE_ELIMINATED'
        ? 'the IR channel never saw the property present, so no pass can be named'
        : 'the IR channel holds the property to the end of the pipeline and the asm channel does not: the loss is in the backend, where deleting a middle-end pass cannot reach it',
    };
    say(`attrib  none -- ${report.attribution.note}`);
  } else {
    const leaf = L[firstLoss.k - 1];
    attributed = leaf.index;
    report.attribution = { stage: 'compile', pass: leaf.name, position: leaf.index, path: leaf.path, note: 'the first prefix at which the IR channel reads the property eliminated' };
    say(`attrib  ${leaf.name} at position ${leaf.index} [${leaf.path.join(' > ')}]`);
  }

  // --- step 5: the interventions --------------------------------------------
  const positions = [];
  if (attributed !== null) {
    positions.push(attributed);
    if (attributed + 1 < L.length) positions.push(attributed + 1);
  }
  const cameBackAt = [];
  for (const k of positions) {
    const passes = renderPipeline(withoutLeaf(tree, k));
    const w = await replay(passes, preW, `cut-w-${k}`), wo = await replay(passes, preWo, `cut-wo-${k}`);
    const asm = verdictOf(w.asm, wo.asm, args.fn);
    const ir = irVerdict(w.ll, wo.ll, args.fn);
    const fc = fixtureControlOf(w.asm);
    const row = {
      position: k, pass: L[k].name, path: L[k].path,
      deleted: k === attributed ? 'the attributed pass' : 'the pass after the attributed one',
      ir, asm: asm.verdict, control: asm.control, fixtureControl: fc,
      memsetCallsInIr: { w: memsetCalls(w.ll, args.fn), wo: memsetCalls(w.ll ? wo.ll : null, args.fn) },
      cameBack: asm.verdict === 'WIPE_SURVIVED' && asm.control === 'PRESENT' && fc === 'PRESENT',
    };
    report.interventions.push(row);
    if (row.cameBack) cameBackAt.push(k);
    say(`cut ${String(k).padStart(3)}  ${row.pass.padEnd(24)} ${row.deleted.padEnd(34)} ir ${ir}, asm ${asm.verdict}, control ${asm.control}/${fc}`);
    if (asm.control !== 'PRESENT' || fc !== 'PRESENT') say(`        WARNING a control is not PRESENT in this replay; this row is not a reading`);
  }

  const ev = {
    positionsTried: positions.length,
    asmChannelRead: report.interventions.every((r) => r.asm !== 'COMPILE_ERROR' && r.asm !== 'NOT_OBSERVED') && report.interventions.length > 0,
    irChannelRead: seq.length > 0,
    cameBackAt,
    replayReproducedLoss,
    controlHeld: controlHeld && report.interventions.every((r) => r.control === 'PRESENT' && r.fixtureControl === 'PRESENT'),
  };
  report.gateEvidence = ev;
  report.verdict = interventionVerdict(ev);
  say(`RESULT  ${report.verdict.verdict} -- ${report.verdict.why}`);
  // BROKEN_MEASUREMENT is "a control went missing", which this tool's exit codes
  // have always called 2. It used to reach here as 0, so a control that went
  // missing in an intervention -- rather than in the unmodified replay, which
  // exits 2 above -- left a run that looked like a result. Both vendors exit the
  // same way on it now.
  finish(report, out, suffix, report.verdict.verdict === 'BROKEN_MEASUREMENT' ? 2 : 0);
}

// ---------------------------------------------------------------------------
// the gcc channel
//
// One instrument, used four or five times: compile both units with the same
// flags plus whatever passes this reading disables, read the assembly through
// the find step's verdictOf, and read gcc's own dumps differentially beside it.
// Everything that decides anything is imported: verdictOf and the controls from
// the find step, interventionVerdict from ../lib/pin-families.mjs, the dump
// reading from ../lib/gcc-disable-tree.mjs. Nothing here is a second oracle.

const REP_STOS = resolve(HERE, '..', '..', '..', 'gcc-repair', 'scripts', 'lib', 'asm-presence.mjs');

/** How far past the located dump the walk will look for a pass gcc will disable. */
const MAX_CANDIDATES = 6;

/**
 * Build both units once, with `disabled` passes taken out, and read everything
 * this channel reads from that pair of compiles.
 *
 * The dumps land in the compile's own directory, one per (reading, unit), so no
 * two readings of a run can see each other's files -- and a dump left over from
 * an earlier reading can never be read as this one's, which is the same rule
 * ../run-repair-loop.mjs applies to plugin records.
 */
function gccObserver(ctx, repStosZeroFill) {
  const { args, level, work } = ctx;
  const fn = args.fn;

  const fixtureControlOf = (asm) => {
    if (asm === null) return { verdict: 'NOT_OBSERVED', via: null };
    const v = observeEffect(asm, args.fixtureControl, CONTROL_EFFECT);
    if (v.verdict === 'PRESENT') return { verdict: 'PRESENT', via: 'oracle' };
    // The oracle does not know `rep stos`, which is how gcc writes a zero fill
    // at -Os. The reading is labelled rather than folded in (../README.md).
    if (repStosZeroFill(asm, args.fixtureControl)) return { verdict: 'PRESENT', via: 'rep-stos-fallback' };
    return { verdict: v.verdict, via: null };
  };

  const build = async (tag, srcPath, disabled) => {
    const dir = join(work, tag);
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    const flags = [...FLAGS, level, ...disabled.map(disableTreeFlag), '-fdump-tree-all', '-fdump-rtl-all'];
    const r = await sh(args.cc, [...flags, '-o', 'out.s', srcPath], { cwd: dir });
    const asmPath = join(dir, 'out.s');
    return {
      dir,
      code: r.code,
      stderr: r.stderr,
      asm: r.code === 0 && existsSync(asmPath) ? readFileSync(asmPath, 'utf8') : null,
      dumps: orderDumps(readdirSync(dir)),
    };
  };

  return async function observe(tag, disabled) {
    const bw = await build(`${tag}-w`, ctx.srcW, disabled);
    const bwo = await build(`${tag}-wo`, ctx.srcWo, disabled);
    return readingFrom(bw, bwo, {
      fn,
      disabled,
      asm: verdictOf(bw.asm, bwo.asm, fn),
      fixtureControl: fixtureControlOf(bw.asm),
      readDump: (b, file) => readFileSync(join(b.dir, file), 'utf8'),
    });
  };
}

/**
 * ONE READING, ASSEMBLED FROM TWO BUILDS. Everything this channel decides with,
 * except the two verdicts the find step's own oracles give (`asm`,
 * `fixtureControl`), which are passed in because they belong to those oracles
 * and not to this file.
 *
 * It is separate from `gccObserver` so that it can be driven without a compiler:
 * `../test/intervene-gcc-driver.test.mjs` hands it synthetic builds -- two
 * stderrs, two exit codes, two dump listings -- and checks the things that are
 * true of a reading rather than of gcc. `readDump(build, file)` is how the dump
 * text is fetched, so the test can keep its dumps in memory.
 *
 * The refusal is read in BOTH units. It was read in the with-wipe build's stderr
 * alone until 2026-09-14, in a channel whose premise is that every reading is a
 * differential pair: a name gcc refused in one unit and accepted in the other
 * read as a plain refusal, and the other compile went unclassified. A one-sided
 * refusal is `asymmetric`, which is NOT a refusal -- the refusing unit exits
 * non-zero, so `readingStatus` calls the reading `compile-failed`, which is
 * fatal. The same applies to the disable note, which has always been required in
 * both.
 *
 * Dumps one unit wrote and the other did not cannot be compared and are dropped;
 * `unpairedReading` counts them and says whether so many were dropped that the
 * walk is no longer either compilation's sequence.
 */
export function readingFrom(bw, bwo, { fn, disabled, asm, fixtureControl, readDump }) {
  const byKey = new Map(bwo.dumps.map((d) => [d.key, d]));
  const paired = [], onlyW = [];
  for (const d of bw.dumps) {
    const other = byKey.get(d.key);
    if (!other) { onlyW.push(d.key); continue; }
    paired.push({ ...d, w: readDump(bw, d.file), wo: readDump(bwo, other.file) });
  }
  const wKeys = new Set(bw.dumps.map((d) => d.key));
  const onlyWo = bwo.dumps.filter((d) => !wKeys.has(d.key)).map((d) => d.key);
  const sequence = buildDumpSequence(paired, fn);
  const notes = disabled.map((p) => ({ pass: p, w: disableNoteSeen(bw.stderr, p), wo: disableNoteSeen(bwo.stderr, p) }));
  const treeSeq = sequence.filter((e) => STAGES[e.stage]?.inScope);
  const refusal = refusalSplit(
    { code: bw.code, stderr: bw.stderr }, { code: bwo.code, stderr: bwo.stderr }, disabled,
  );
  return {
    disabled,
    codes: { w: bw.code, wo: bwo.code },
    notes,
    noteOk: notes.length > 0 && notes.every((n) => n.w && n.wo),
    refusedBy: refusal.refusedBy,
    refusal,
    asm,
    fixtureControl,
    sequence,
    dumpsCompared: sequence.length,
    observedDumps: observedDumps(sequence),
    treeDumps: treeSeq.length,
    unpaired: unpairedReading({ paired: paired.length, onlyW, onlyWo }),
    lastTreeState: treeSeq.filter((e) => e.state !== 'NOT_OBSERVED').pop()?.state ?? 'NOT_OBSERVED',
    located: firstIndifferentDump(sequence),
  };
}

/** The row this channel writes for one reading. No path, no source text. */
const gccRow = (r, why) => ({
  disabledPasses: r.disabled,
  why,
  status: readingStatus(r),
  disableNoteSeen: r.notes.map((n) => ({ pass: n.pass, w: n.w, wo: n.wo })),
  compileCodes: r.codes,
  refusedBy: r.refusal?.refusedBy ?? r.refusedBy ?? [],
  refusalAsymmetric: r.refusal?.asymmetric ?? [],
  asm: r.asm.verdict,
  control: r.asm.control ?? null,
  fixtureControl: r.fixtureControl.verdict,
  fixtureControlVia: r.fixtureControl.via,
  gimpleLastTreeDumpState: r.lastTreeState,
  firstIndifferentDumpAfter: r.located.entry?.key ?? null,
  firstIndifferentDumpStatus: r.located.status,
  dumpsCompared: r.dumpsCompared,
  dumpsObserved: r.observedDumps,
  unpaired: r.unpaired,
  cameBack: cameBack(r),
});

/**
 * POSITIVE CONTROL (b), run once and before any reading is believed: a pass name
 * gcc cannot know must make the build FAIL. If gcc accepted it, the channel is
 * not checked at all and the absence of a note in some later reading would say
 * nothing, so there is no measurement to take.
 */
async function gccMisspellControl(ctx, report, say, base, taken) {
  const bogus = misspell(base, taken);
  const r = await sh(ctx.args.cc, [...FLAGS, ctx.level, disableTreeFlag(bogus), '-o', join(ctx.work, 'misspell.s'), ctx.srcW]);
  const refused = unknownPassRefused(r, bogus);
  const m = /unknown pass\s+tree-\S+\s+specified in \S+/.exec(String(r.stderr ?? ''));
  report.channelControls = {
    misspelledPass: bogus,
    builtFrom: base,
    exitCode: r.code,
    refused,
    refusalSeen: m ? m[0] : null,
    means: 'a pass name gcc does not know must be an error, or a missing "disable pass" note would be unreadable',
  };
  say(`control -fdisable-tree-${bogus}  exit ${r.code}, ${refused ? 'REFUSED by gcc (the channel is checked)' : 'ACCEPTED -- the channel is NOT checked'}`);
  return refused;
}

/**
 * The interventions themselves.
 *
 * The first position is where the walk located the loss. The second is where the
 * walk says the loss moved to once the first pass is gone -- which is the thing
 * the gate's two-position rule exists to catch, rather than an assumption that
 * the next pass in the file is the one entitled to make the same elimination.
 * A position gcc refuses (a dump whose name is not a pass it can disable) is
 * recorded and the walk moves on; a position gcc ACCEPTS WITHOUT ANNOUNCING is
 * fatal, because then nothing says the intervention happened.
 */
async function gccInterventions(observe, report, say, first, treeSeq) {
  const tried = new Set();
  const rows = [];
  let why = 'the dump the walk located';
  let next = first;
  while (next && rows.filter((r) => readingStatus(r) === 'intervened').length < 2 && tried.size < MAX_CANDIDATES) {
    tried.add(next);
    const r = await observe(`cut-${next}`, [next]);
    const row = gccRow(r, why);
    rows.push(r);
    report.interventions.push(row);
    say(`cut  ${next.padEnd(20)} ${row.status.padEnd(16)} asm ${row.asm}, control ${row.control}/${row.fixtureControl}, next indifferent at ${row.firstIndifferentDumpAfter ?? '(none)'}`);
    if (FATAL_READING_STATUSES.includes(row.status)) return { rows, fatal: row };
    if (row.cameBack) break;
    // where the loss went once this pass was gone, then the next tree dump after it
    const moved = r.located.entry;
    const candidate = moved && STAGES[moved.stage]?.inScope && !tried.has(moved.pass) ? moved.pass : null;
    const after = treeSeq.find((e) => !tried.has(e.pass) && e.num > (treeSeq.find((x) => x.pass === next)?.num ?? -1));
    next = candidate ?? (after ? after.pass : null);
    why = candidate ? 'where the walk says the loss moved to once the first pass was gone' : 'the next tree dump the walk holds';
  }
  return { rows, fatal: null };
}

/**
 * The gcc channel, end to end. Every exit from here is a result or a refusal,
 * each one says which, and each one writes `report.verdict` and
 * `report.gateEvidence` before it goes.
 *
 * INJECTION, AND WHY IT IS HERE RATHER THAN IN A TEST'S IMAGINATION. Everything
 * below is a fail-closed guard, and until 2026-09-14 not one of them was pinned
 * by any test: deleting the fatality check, the misspell control, the NO_DUMPS
 * guard, the DUMP_BUILD_FAILED guard or the control guard left the suite green,
 * which means the suite was not defending the reason this channel is allowed to
 * exist. A guard that no test fails without is decorative. So `ctx` may carry
 * `observe`, `misspellControl` and `finish`, which is all it takes for
 * `../test/intervene-gcc-driver.test.mjs` to drive these guards over scripted
 * readings with no compiler present -- and for deleting any one of them to turn
 * that suite red. The defaults are the real instruments and the real exit, so a
 * lab run is unchanged.
 *
 * `finish` never returns (it exits the process), and the injected one must not
 * either: the code after each guard assumes the run has stopped.
 */
export async function gccChannel(ctx) {
  const { report, say, out, suffix } = ctx;
  const done = ctx.finish ?? finish;
  const misspellControl = ctx.misspellControl ?? gccMisspellControl;
  let observe = ctx.observe;
  if (!observe) {
    let repStosZeroFill;
    try {
      ({ repStosZeroFill } = await import(pathToFileURL(REP_STOS).href));
    } catch (e) {
      cannotRun(`the rep-stos reading (compiler/gcc-repair/scripts/lib/asm-presence.mjs) could not be used: ${e.message}`);
    }
    observe = gccObserver(ctx, repStosZeroFill);
  }

  // What the gate has been given SO FAR. It starts as what a run that has read
  // nothing can honestly claim -- which is nothing -- and is filled in as each
  // reading is actually taken. `asmChannelRead` in particular stays false until
  // an intervention reading exists: it used to be passed as `true` on four paths
  // where zero interventions had been made, which is a control that cannot fail
  // asserted as one that passed.
  const ev = {
    positionsTried: 0,
    asmChannelRead: false,
    irChannelRead: false,
    cameBackAt: [],
    replayReproducedLoss: false,
    controlHeld: false,
  };
  /** Stop the run with a named refusal, its true reason, and the evidence as it stood. */
  const stop = (key, detail) => {
    report.verdict = brokenBecause(key, detail);
    report.gateEvidence = { ...ev, fatality: key };
    say(`RESULT ${key} -- ${report.verdict.why}`);
    done(report, out, suffix, 2);
  };

  // --- the walk: gcc's own dump sequence, read differentially ---------------
  const un = await observe(`walk-${suffix}`, []);
  const treeSeq = un.sequence.filter((e) => STAGES[e.stage]?.inScope);
  report.dumpWalk = {
    dumpsCompared: un.dumpsCompared,
    dumpsObserved: un.observedDumps,
    treeDumps: treeSeq.length,
    unpaired: un.unpaired,
    compileCodes: un.codes,
    asm: un.asm.verdict,
    control: un.asm.control ?? null,
    fixtureControl: un.fixtureControl.verdict,
    fixtureControlVia: un.fixtureControl.via,
    status: un.located.status,
    firstIndifferentDump: un.located.entry?.key ?? null,
    firstIndifferentDumpStage: un.located.entry ? STAGES[un.located.entry.stage].what : null,
    transitions: transitionsOf(un.sequence),
    flipBacks: flipBacks(un.sequence),
    sequence: un.sequence,
  };
  say(`walk    ${un.dumpsCompared} dumps compared (${treeSeq.length} GIMPLE), ${un.observedDumps} held ${ctx.args.fn} in both units, asm ${un.asm.verdict}, control ${un.asm.control ?? "(not read)"}/${un.fixtureControl.verdict}`);
  say(`walk    unpaired dumps ${un.unpaired.unpaired}/${un.unpaired.union} (${(un.unpaired.share * 100).toFixed(1)}%${un.unpaired.unpaired > 0 ? `: only-w ${un.unpaired.onlyW.join(',') || '-'}, only-wo ${un.unpaired.onlyWo.join(',') || '-'}` : ''})`);
  say(`walk    ${un.located.status}${un.located.entry ? ` at ${un.located.entry.key}` : ''}; state changes: ${report.dumpWalk.transitions.length}, flip-backs: ${report.dumpWalk.flipBacks.length}`);

  // A dump build that did not compile is not a walk with nothing in it. It is
  // said in its own words, so it cannot be read as any of the ones below.
  if (un.codes.w !== 0 || un.codes.wo !== 0) {
    stop('DUMP_BUILD_FAILED', `exit ${un.codes.w}/${un.codes.wo}; see run-log.txt`);
  }
  // P4: no dumps is NOT_OBSERVED, and never "the wipe survived the walk".
  if (un.dumpsCompared === 0) {
    stop('NO_DUMPS', 'the walk compared 0 dumps');
  }
  // CONTROL (d), the one this channel was missing. A walk every entry of which
  // is NOT_OBSERVED compared nothing, and the walk's own answer for that used to
  // be the substantive finding "the wipe made no difference in any dump gcc
  // emits" -- reported at exit 0. gcc-13 -O2 -fdump-tree-all emits ~122 dumps
  // for a small file, so zero readable ones is the apparatus, not the wipe.
  if (FATAL_WALK_STATUSES.includes(un.located.status)) {
    stop('FUNCTION_IN_NO_DUMP', `${un.dumpsCompared} dumps compared, ${un.observedDumps} of them held ${ctx.args.fn} in both units`);
  }
  // Dumps present in one unit and not the other cannot be read differentially
  // and are dropped. That is right, and it was silent and unbounded.
  if (un.unpaired.overThreshold) {
    stop('DUMP_SETS_DISAGREE', `${un.unpaired.unpaired} of ${un.unpaired.union} dumps unpaired (${(un.unpaired.share * 100).toFixed(1)}%, threshold ${(un.unpaired.maxShare * 100).toFixed(1)}%); only-w ${un.unpaired.onlyW.join(',') || '-'}, only-wo ${un.unpaired.onlyWo.join(',') || '-'}`);
  }
  ev.irChannelRead = un.sequence.length > 0;
  ev.replayReproducedLoss = un.asm.verdict === 'WIPE_ELIMINATED';
  ev.controlHeld = un.asm.control === 'PRESENT' && un.fixtureControl.verdict === 'PRESENT';
  if (!ev.replayReproducedLoss) {
    stop('REPLAY_DID_NOT_REPRODUCE', `the dump build reads ${un.asm.verdict}`);
  }
  if (!ev.controlHeld) {
    stop('CONTROL_NOT_PRESENT', `in the dump build: co-resident ${un.asm.control ?? '(not read)'}, ${ctx.args.fixtureControl} ${un.fixtureControl.verdict}`);
  }

  // --- control (b), before any reading is taken from the channel ------------
  const base = un.located.entry?.pass ?? treeSeq[0]?.pass;
  if (!base) {
    stop('NO_GIMPLE_DUMP', `${un.dumpsCompared} dumps compared, none of them GIMPLE`);
  }
  if (!await misspellControl(ctx, report, say, base, un.sequence.map((e) => e.pass))) {
    stop('CHANNEL_NOT_CHECKED', `gcc exit ${report.channelControls?.exitCode} for -fdisable-tree-${report.channelControls?.misspelledPass}`);
  }

  // --- is there anything to intervene at? ----------------------------------
  const located = un.located.entry;
  if (!located || !STAGES[located.stage].inScope) {
    report.attributionOutOfChannel = {
      status: un.located.status,
      dump: located?.key ?? null,
      stage: located ? STAGES[located.stage].what : null,
      note: located
        ? `the wipe stops making a difference in a ${STAGES[located.stage].what} dump, which ${STAGES[located.stage].flag} reaches and -fdisable-tree- does not. That channel is not driven by this tool.`
        : un.located.status === 'indifferent-from-first-dump'
          ? 'the function was read in the walk, and the wipe made no difference in any dump gcc emitted, so no pass in the sequence can be named for its loss'
          : 'the wipe still made a difference in the last dump that held the function, so the loss is after the walk and no pass in it can be taken out to bring it back',
    };
    say(`RESULT  no position in this channel -- ${report.attributionOutOfChannel.note}`);
    report.gateEvidence = { ...ev };
    report.verdict = interventionVerdict(ev);
    say(`RESULT  ${report.verdict.verdict} -- ${report.verdict.why}`);
    done(report, out, suffix, 0);
  }

  // --- the interventions ---------------------------------------------------
  const { rows, fatal } = await gccInterventions(observe, report, say, located.pass, treeSeq);
  if (fatal) {
    stop(fatal.status === 'no-note' ? 'INTERVENTION_NOT_ANNOUNCED' : 'INTERVENTION_BUILD_FAILED',
      fatal.status === 'no-note'
        ? `gcc built ${fatal.disabledPasses.join(', ')} at exit 0 and announced no disable`
        : `${fatal.disabledPasses.join(', ')}: exit ${fatal.compileCodes.w}/${fatal.compileCodes.wo}${fatal.refusalAsymmetric?.length ? `, and gcc refused ${fatal.refusalAsymmetric.join(', ')} in one unit only` : ''}; see run-log.txt`);
  }
  const intervened = rows.filter((r) => readingStatus(r) === 'intervened');
  const cameBackAt = report.interventions.filter((r) => r.cameBack).map((r) => r.disabledPasses.join('+'));

  // Both passes at once: the reading the two-position rule is actually about.
  // One pass out of the pipeline can hand the same elimination to the next pass
  // entitled to make it, and only disabling both says whether that is what
  // happened.
  //
  // It is UNDER THE SAME RULES as every other reading, which it was not until
  // 2026-09-14: a `no-note` or `compile-failed` cut-both was recorded and
  // ignored -- the one reading whose whole purpose is to catch an elimination
  // handed on to the next pass, allowed to fail silently -- and when it did
  // read, its controls were left out of the gate's evidence.
  const readings = [...intervened];
  if (intervened.length >= 2 && cameBackAt.length === 0) {
    const both = intervened.slice(0, 2).map((r) => r.disabled[0]);
    const r = await observe(`cut-both`, both);
    const row = gccRow(r, 'both positions at once');
    report.interventions.push(row);
    say(`cut  ${both.join('+').padEnd(20)} ${row.status.padEnd(16)} asm ${row.asm}, control ${row.control}/${row.fixtureControl}`);
    if (FATAL_READING_STATUSES.includes(row.status)) {
      stop(row.status === 'no-note' ? 'INTERVENTION_NOT_ANNOUNCED' : 'INTERVENTION_BUILD_FAILED',
        row.status === 'no-note'
          ? `gcc built ${both.join('+')} (both positions at once) at exit 0 and announced no disable`
          : `${both.join('+')} (both positions at once): exit ${row.compileCodes.w}/${row.compileCodes.wo}${row.refusalAsymmetric.length ? `, and gcc refused ${row.refusalAsymmetric.join(', ')} in one unit only` : ''}; see run-log.txt`);
    }
    if (row.status === 'intervened') {
      readings.push(r);
      if (row.cameBack) cameBackAt.push(both.join('+'));
    }
  }

  // `positionsTried` counts the single-position readings: cut-both is a third
  // reading of two positions already counted, not a third position. Its
  // controls are evidence like any other reading's, which is why it is in
  // `readings` and not in the count.
  const finalEv = {
    ...ev,
    positionsTried: intervened.length,
    asmChannelRead: readings.length > 0 && readings.every((r) => r.asm.verdict !== 'COMPILE_ERROR' && r.asm.verdict !== 'NOT_OBSERVED'),
    cameBackAt,
    controlHeld: ev.controlHeld && readings.every((r) => r.asm.control === 'PRESENT' && r.fixtureControl.verdict === 'PRESENT'),
  };
  report.gateEvidence = finalEv;
  report.verdict = interventionVerdict(finalEv);
  say(`RESULT  ${report.verdict.verdict} -- ${report.verdict.why}`);
  done(report, out, suffix, report.verdict.verdict === 'BROKEN_MEASUREMENT' ? 2 : 0);
}

function finish(report, out, suffix, code) {
  const text = JSON.stringify(report, null, 2);
  const hits = absolutePathHits(text);
  if (hits.length > 0) {
    process.stderr.write(`intervene: the report carries an absolute path (${hits.join(', ')}); not writing it\n`);
    process.exit(5);
  }
  const p = join(out, `intervene-${suffix}.json`);
  writeFileSync(p, `${text}\n`);
  process.stdout.write(`report  ${basename(p)} in the lab directory\n`);
  process.exit(code);
}

// The CLI entry point, and only when this file IS the entry point. It used to
// call main() unconditionally, which meant importing the module ran a
// compilation -- so nothing could import it, so the gcc driver's fail-closed
// guards above were pinned by no test at all. See gccChannel's header.
//
// The comparison is case-insensitive on win32 ON PURPOSE. This guard has a
// silent-pass shape of its own: a mismatch means the tool does nothing, prints
// nothing and exits 0, and `C:\...` against `c:\...` is enough of a mismatch on
// a platform where those name the same file. `../test/intervene-gcc-driver.test.mjs`
// runs `--selftest` through the CLI so that a guard which stopped recognising
// its own file is a red test rather than a run that quietly did nothing.
const ENTRY = process.argv[1] ? resolve(process.argv[1]) : null;
const SELF = resolve(fileURLToPath(import.meta.url));
export const INVOKED_AS_CLI = ENTRY !== null
  && (process.platform === 'win32' ? ENTRY.toLowerCase() === SELF.toLowerCase() : ENTRY === SELF);
if (INVOKED_AS_CLI) await main();

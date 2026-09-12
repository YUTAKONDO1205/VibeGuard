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
 * gcc: the same question has a channel there too -- `-fdisable-tree-<pass>` --
 * and it is NOT implemented here. Marked [SPEC] in ../PIN-FAMILIES.md and left
 * unmeasured rather than guessed at.
 *
 *   node intervene.mjs --out <lab dir> [--cc clang-18] [--opt -O2]
 *                      [--fixture <dir>] [--fn handle_request] [--sweep full|bisect]
 *   node intervene.mjs --selftest        (no compiler; the pipeline surgery only)
 *
 * --out must lie outside the repository: this is a lab tool and writes nothing
 * to data/. Exit codes: 0 the run completed and its verdict is in the report
 * (including CAME_BACK, NEVER_CAME_BACK and NOT_ENOUGH_EVIDENCE, which are
 * results); 2 the replay did not reproduce the loss, or a control went missing,
 * so there is no reading; 3 a tool or the fixture is missing; 4 bad arguments.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, appendFileSync, copyFileSync } from 'node:fs';
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
async function sh(cmd, args) {
  let code = 0, stdout = '', stderr = '';
  try {
    const r = await run(cmd, args, { timeout: 90000, maxBuffer: 64 * 1024 * 1024 });
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
  const level = /^-O[0123]$/.test(args.opt) ? args.opt : null;
  if (!level) fail(`--opt ${args.opt}: this tool replays through llc, which has -O0..-O3 and no -Os/-Oz`);
  if (!args.cc.startsWith('clang')) {
    fail(`--cc ${args.cc}: only clang has a printed pass pipeline this tool can replay. gcc's -fdisable-tree-<pass> channel is [SPEC] and not implemented`);
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
  const tool = { opt: args.cc.replace(/^clang/, 'opt'), llc: args.cc.replace(/^clang/, 'llc') };
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
    cc: args.cc, opt: level,
    steps: [], sequence: [], interventions: [],
  };
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
  finish(report, out, suffix, 0);
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

await main();

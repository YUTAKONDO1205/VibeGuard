#!/usr/bin/env node
/**
 * lto-probe -- does a wipe WipePin pinned at compile time survive the LTO
 * backend, judged by the find step's own verdict on the post-LTO assembly?
 *
 * compiler/llvm-repair/README.md ("Other forms") says a `-flto` / `-flto=thin`
 * compile with the plugin loaded writes a record and its bitcode carries the
 * volatile memset, and that what the LTO backend then does was not measured.
 * This probe measures it. For every selected file, LTO form and level, the
 * wipe-kept unit w and the ablated unit wo (made with the imported ablateSpans)
 * are compiled with the find step's FLAGS, `-S` replaced by `-c` plus `-flto` or
 * `-flto=thin`, and each object is linked ALONE with
 *
 *   clang-18 <opt> -flto[=thin] -fuse-ld=lld -shared -Wl,--lto-emit-asm
 *            [-Wl,--thinlto-jobs=1] -o <dir>/<tag>.s <dir>/u.o
 *
 * so that lld stops after the LTO backend and writes the assembly it would have
 * assembled. verdictOf(w, wo, fn) -- imported from
 * ../../ai-generated/lib/ablation-cell.mjs, with its bodyOf and positive control
 * -- judges that assembly. Configurations, per cell:
 *
 *   (i)   plugin at compile time (-fpass-plugin), stock link    the measurement
 *   (ii)  plugin only on the link line (-Wl,--load-pass-plugin) WipePin registers
 *         at pipeline start, which an LTO link does not run: its pass must not
 *         run, and the plugin must say so, exactly once (LINK_LINE_REMOVED)
 *   (iii) plugin at compile time in dry-run mode, stock link    the red control
 *   and   the same object linked twice                          determinism
 *
 * Every object must start with the bitcode magic, and every link must write the
 * one file its form writes; a cell where either fails is NOT_LTO and is never
 * counted as an LTO result.
 *
 * Lab output only. Everything -- sources, objects, assembly, records, rows,
 * results -- goes under --out, which must lie outside the repository. There is
 * no --write-data: nothing here is tracked data. See LTO.md.
 *
 *   node lto-probe.mjs --plugin <libWipePin.so> --out <lab dir> [options]
 *
 * Exit codes: 0 run complete and every integrity check held; 2 run complete but
 * a cell was NOT_LTO, a link was not deterministic, the dry-run red control
 * did not hold, or configuration (ii) did not read as graded (gradeLinkPlugin);
 * 3 nothing selected; 4 bad arguments; 5 a tool, the plugin or the
 * shared verdict module could not be used, the preflight found no way to read
 * post-LTO assembly, or a text about to be written carried an absolute path.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, existsSync, statSync, copyFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join, basename, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  ELIMINATED, MODES, ltoCompileFlags, ltoLinkArgs, llcOptFor, objectKind, expectedOutputs, pickOutput,
  readRecordFields, ltoOutcome, LTO_OUTCOMES, SENTINEL, linkPluginState, linkLineStderr, zeroMemsetsInFunctions,
  evenSample, summarizeGroup, insideRepo,
} from './lib/lto.mjs';
import { sha256Text, absolutePathHits } from '../lib/provenance.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const REPO = resolve(LANE, '..', '..', '..');
const AIGEN = resolve(LANE, '..', 'ai-generated');
const GEN = join(AIGEN, 'generated-corpus', 'r2');
const SCEN_PATH = join(AIGEN, 'scenarios.json');
const CELL_PATH = join(AIGEN, 'lib', 'ablation-cell.mjs');
const DEFAULT_ROWS = join(AIGEN, 'data', 'r2-build-rows.json');
const ALL_OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];
const SELECT_OPT = '-O2';

const USAGE = `usage: node lto-probe.mjs --plugin <so> --out <dir> [options]

  --plugin <so>        WipePin (required; there is no default)
  --out <dir>          lab directory, outside the repository (required)
  --cc <compiler>      default clang-18
  --llvm-dis <tool>    default llvm-dis-18 (reads the compile-stage bitcode; optional column)
  --llc <tool>         default llc-18 (only for the llvm+llc fallback)
  --modes <list>       comma list of full,thin (default both)
  --opts <list>        comma list from ${ALL_OPTS.join(' ')} (default ${SELECT_OPT})
  --files <list>       comma list of basenames or globs, within the selection below
  --sample <n>         n files spread evenly over the selection (default: all)
  --conc <n>           parallel cells (default 4)
  --force-fallback     read post-LTO code through --save-temps' precodegen.bc + llc even if
                       --lto-emit-asm passes the preflight (exercises the fallback)
  --rows <path>        tracked find-step rows (default the ai-generated lane's r2-build-rows.json)

The selection is fixed: the clang-18 erasure files the tracked rows score WIPE_ELIMINATED at ${SELECT_OPT}.
Everything is written under --out; there is no --write-data.
`;

function die(code, msg) {
  process.stderr.write(`lto-probe: ${msg}\n`);
  process.exit(code);
}

function globToRe(g) {
  const s = g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + s + '$');
}

function parseArgs(argv) {
  const a = { plugin: null, out: null, cc: 'clang-18', llvmDis: 'llvm-dis-18', llc: 'llc-18', modes: ['full', 'thin'],
    opts: [SELECT_OPT], files: null, sample: null, conc: 4, forceFallback: false, rows: DEFAULT_ROWS };
  const need = (i, flag) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${flag} needs a value`); return argv[i + 1]; };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--plugin': a.plugin = need(i, f); i++; break;
      case '--out': a.out = need(i, f); i++; break;
      case '--cc': a.cc = need(i, f); i++; break;
      case '--llvm-dis': a.llvmDis = need(i, f); i++; break;
      case '--llc': a.llc = need(i, f); i++; break;
      case '--modes': a.modes = list(need(i, f)); i++; break;
      case '--opts': a.opts = list(need(i, f)); i++; break;
      case '--files': a.files = list(need(i, f)); i++; break;
      case '--sample': a.sample = Number(need(i, f)); i++; break;
      case '--conc': a.conc = Number(need(i, f)); i++; break;
      case '--force-fallback': a.forceFallback = true; break;
      case '--rows': a.rows = need(i, f); i++; break;
      case '--write-data': die(4, '--write-data does not exist here: the LTO probe writes its lab directory and nothing else'); break;
      case '-h': case '--help': process.stdout.write(USAGE); process.exit(0); break;
      default: die(4, `unknown argument ${f}\n${USAGE}`);
    }
  }
  if (!a.plugin) die(4, '--plugin is required');
  if (!a.out) die(4, '--out is required: everything the probe writes goes to a lab directory outside the repository');
  for (const m of a.modes) if (!MODES[m]) die(4, `--modes: ${m} is not one of ${Object.keys(MODES).join(' ')}`);
  if (!a.modes.length) die(4, '--modes is empty');
  for (const o of a.opts) if (!ALL_OPTS.includes(o)) die(4, `--opts: ${o} is not one of ${ALL_OPTS.join(' ')}`);
  if (!a.opts.length) die(4, '--opts is empty');
  a.opts = ALL_OPTS.filter((o) => a.opts.includes(o));
  a.modes = Object.keys(MODES).filter((m) => a.modes.includes(m));
  if (a.sample !== null && (!Number.isInteger(a.sample) || a.sample < 1)) die(4, '--sample must be a positive integer');
  if (!Number.isInteger(a.conc) || a.conc < 1) die(4, '--conc must be a positive integer');
  a.plugin = resolve(a.plugin);
  a.out = resolve(a.out);
  a.rows = resolve(a.rows);
  if (insideRepo(a.out, REPO, sep)) die(4, '--out lies inside the repository; the probe writes lab output only');
  return a;
}

const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
const sha256File = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

/** process.env with every WPIN_* removed: nothing inherited may steer a compile or a link. */
function cleanEnv() {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith('WPIN_')) env[k] = v;
  return env;
}

/** Run a tool; never throws. stderr is returned for inspection and never written anywhere. */
async function tool(cmd, args, env, timeout = 90000) {
  try {
    const { stdout, stderr } = await run(cmd, args, { env, timeout, maxBuffer: 64 * 1024 * 1024 });
    return { rc: 0, stdout, stderr };
  } catch (e) {
    return { rc: typeof e.code === 'number' ? e.code : -1, stdout: String(e.stdout || ''), stderr: String(e.stderr || e.message || '') };
  }
}

function readOrNull(p) {
  try { return readFileSync(p); } catch { return null; }
}

// ---------------------------------------------------------------- main -------
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const inherited = Object.keys(process.env).filter((k) => k.startsWith('WPIN_'));
  for (const k of inherited) delete process.env[k];
  if (inherited.length) process.stderr.write(`note: ignoring inherited ${inherited.join(' ')}\n`);
  const BASE_ENV = cleanEnv();

  if (!existsSync(args.plugin) || !statSync(args.plugin).isFile()) die(5, 'the --plugin path does not name a file');
  if (!existsSync(CELL_PATH)) die(5, 'ai-generated/lib/ablation-cell.mjs is missing; the probe judges with the find step\'s own verdict code and has no copy');
  const cell = await import(pathToFileURL(CELL_PATH).href);
  for (const name of ['FLAGS', 'CONTROL', 'wipeSpans', 'ablateSpans', 'bodyOf', 'controlPresent', 'verdictOf', 'pool']) {
    if (!(name in cell)) die(5, `ablation-cell.mjs does not export ${name}`);
  }
  const FLAGS_BY_MODE = {};
  try { for (const m of args.modes) FLAGS_BY_MODE[m] = ltoCompileFlags(cell.FLAGS, m); } catch (e) { die(5, e.message); }

  const ccv = await tool(args.cc, ['--version'], BASE_ENV, 30000);
  if (ccv.rc !== 0) die(5, `${args.cc} --version failed: the compiler is not runnable here`);
  const ccVersion = ccv.stdout.split('\n')[0].trim();
  const ccName = basename(args.cc);
  const ldv = await tool(args.cc, ['-fuse-ld=lld', '-Wl,--version'], BASE_ENV, 30000);
  const lldVersion = ldv.rc === 0 ? (ldv.stdout.split('\n').find((l) => /LLD/.test(l)) || '').trim() : null;
  if (!lldVersion) die(5, `${args.cc} -fuse-ld=lld -Wl,--version did not name LLD: the linker the probe needs is not reachable`);
  const disv = await tool(args.llvmDis, ['--version'], BASE_ENV, 30000);
  const haveDis = disv.rc === 0;
  const pluginSha = sha256File(args.plugin);

  // ---- selection: the tracked clang-18 erasure files eliminated at -O2 -------
  let tracked;
  try { tracked = JSON.parse(readFileSync(args.rows, 'utf8')); } catch { die(5, 'the --rows file could not be read as JSON'); }
  const scen = JSON.parse(readFileSync(SCEN_PATH, 'utf8'));
  const trackedVerdict = new Map();
  for (const r of tracked) if (r.kind === 'erasure' && r.cc === 'clang-18') trackedVerdict.set(`${r.id}|${r.opt}`, r.verdict);
  let ids = [...new Set(tracked.filter((r) => r.kind === 'erasure' && r.cc === 'clang-18' && r.opt === SELECT_OPT && r.verdict === ELIMINATED).map((r) => r.id))].sort();
  const selectedTotal = ids.length;
  if (args.files) {
    const res = args.files.map(globToRe);
    ids = ids.filter((id) => res.some((re) => re.test(id) || re.test(`${id}.c`)));
  }
  ids = evenSample(ids, args.sample ?? undefined);
  if (!ids.length) die(3, 'nothing selected');

  const OUT = args.out;
  const SRC = join(OUT, 'src');
  const CELLS = join(OUT, 'cells');
  const PRE = join(OUT, 'preflight');
  for (const d of [SRC, CELLS, PRE]) mkdirSync(d, { recursive: true });

  const pluginArg = `-fpass-plugin=${args.plugin}`;
  const wpinEnv = (recordPath, requested, dryRun) => {
    const env = { ...BASE_ENV, WPIN_OUT: recordPath, WPIN_TARGET_FNS: requested.join(',') };
    if (dryRun) env.WPIN_DRY_RUN = '1';
    return env;
  };

  /** Compile one unit to an LTO object; returns the object kind. */
  async function compileObj(src, obj, mode, opt, env, plugin) {
    rmSync(obj, { force: true });
    const r = await tool(args.cc, [...FLAGS_BY_MODE[mode], opt, ...(plugin ? [pluginArg] : []), '-o', obj, src], env);
    const kind = objectKind(r.rc === 0 ? readOrNull(obj) : null);
    return { rc: r.rc, kind };
  }

  /**
   * Link one object alone and return the post-LTO assembly (or null) with what
   * the link wrote. The object sits alone in its directory with its links' -o
   * names beside it, so every output lld 18 writes (see expectedOutputs) lands
   * there and "the files that appeared" is the complete list.
   *
   * The fallback links a byte-identical copy of the object in a directory of its
   * own: --save-temps names some of its files after the object, and a second
   * link of the same object in the same directory would overwrite them rather
   * than write new ones, so "the files that appeared" would no longer be the
   * list of what this link wrote.
   */
  async function linkAsm(obj, tag, mode, opt, emit, { env = BASE_ENV, linkPlugin = null } = {}) {
    let dir = dirname(obj);
    let input = obj;
    if (emit === 'llvm+llc') {
      dir = join(dirname(obj), `${tag}.fallback`);
      rmSync(dir, { recursive: true, force: true });
      mkdirSync(dir, { recursive: true });
      input = join(dir, basename(obj));
      copyFileSync(obj, input);
    }
    const outBase = `${tag}.s`;
    const before = new Set(readdirSync(dir));
    const r = await tool(args.cc, [...ltoLinkArgs({ opt, mode, emit, linkPlugin }), '-o', join(dir, outBase), input], env);
    const fresh = readdirSync(dir).filter((n) => !before.has(n));
    const stderrEmpty = r.stderr.trim() === '';
    const stderrFlags = { wipePin: /WipePin:/.test(r.stderr), failedToLoad: /Failed to load passes/.test(r.stderr) };
    const linkLine = linkLineStderr(r.stderr);
    if (r.rc !== 0) return { asm: null, problem: `link rc ${r.rc}`, layout: null, stderrEmpty, stderrFlags, linkLine };
    const pick = pickOutput(fresh, expectedOutputs({ mode, emit, outBase, objStem: basename(input).replace(/\.o$/, '') }));
    if (!pick.ok) return { asm: null, problem: pick.problem, layout: pick.problem, stderrEmpty, stderrFlags, linkLine };
    if (emit === 'asm') return { asm: readFileSync(join(dir, pick.name), 'utf8'), problem: null, layout: null, stderrEmpty, stderrFlags, linkLine };
    // fallback: the module after the LTO optimisation pipeline, through llc at the matching level
    const bc = join(dir, pick.name);
    if (objectKind(readOrNull(bc)) !== 'bitcode') return { asm: null, problem: 'precodegen output is not bitcode', layout: 'precodegen output is not bitcode', stderrEmpty, stderrFlags, linkLine };
    const sOut = join(dir, `${tag}.llc.s`);
    const l = await tool(args.llc, [llcOptFor(opt), '-relocation-model=pic', '-o', sOut, bc], BASE_ENV);
    if (l.rc !== 0) return { asm: null, problem: `llc rc ${l.rc}`, layout: null, stderrEmpty, stderrFlags, linkLine };
    return { asm: readFileSync(sOut, 'utf8'), problem: null, layout: null, stderrEmpty, stderrFlags, linkLine };
  }

  // ---- preflight: can post-LTO assembly be cut, and does the plugin run under -flto? ----
  const pre = {};
  {
    const src = join(PRE, 'pf.c');
    writeFileSync(src, 'void vgpre_wipe(unsigned char *p) { __builtin_memset(p, 0, 64); }\n' + cell.CONTROL, 'utf8');
    for (const mode of args.modes) {
      for (const opt of args.opts) {
        const key = `${mode}${opt}`;
        const d = join(PRE, key);
        rmSync(d, { recursive: true, force: true });
        mkdirSync(d, { recursive: true });
        const obj = join(d, 'u.o');
        const c = await compileObj(src, obj, mode, opt, BASE_ENV, false);
        const p = { objectKind: c.kind, asm: null, llvmLlc: null, emit: null, plugin: null };
        const cuts = (asm) => !!asm && cell.controlPresent(asm).ok && cell.bodyOf(asm, 'vgctl_control') !== null && cell.bodyOf(asm, 'vgpre_wipe') !== null;
        // A reading path is usable only if (a) what it yields is cut by bodyOf
        // with the positive control PRESENT, and (b) its link demonstrably
        // builds the LTO optimisation pipeline: with WipePin on that link line,
        // the sentinel at WPIN_OUT must be gone, because WipePin's load-time
        // callback runs when the LTO backend builds its pass pipeline. (b) is
        // what `--plugin-opt=emit-llvm` fails: it writes the module before that
        // pipeline, and the sentinel stays.
        const pathCheck = async (emit, tag) => {
          const l = await linkAsm(obj, tag, mode, opt, emit);
          if (!cuts(l.asm)) return l.problem || 'not cut by bodyOf / control not PRESENT';
          const sRec = join(d, `${tag}-pipeline-sentinel.json`);
          writeFileSync(sRec, SENTINEL, 'utf8');
          await linkAsm(obj, `${tag}-pipeline`, mode, opt, emit, { env: wpinEnv(sRec, ['vgpre_wipe'], false), linkPlugin: args.plugin });
          const b = readOrNull(sRec);
          const st = linkPluginState({ exists: b !== null, text: b ? b.toString('utf8') : null });
          return st === 'removed' || st === 'record-written' ? 'PRESENT' : `no LTO pipeline built on this link (sentinel ${st})`;
        };
        if (c.kind === 'bitcode') {
          p.asm = await pathCheck('asm', 'pf-asm');
          p.llvmLlc = await pathCheck('llvm+llc', 'pf-llvm');
        }
        if (args.forceFallback) p.emit = p.llvmLlc === 'PRESENT' ? 'llvm+llc' : null;
        else p.emit = p.asm === 'PRESENT' ? 'asm' : (p.llvmLlc === 'PRESENT' ? 'llvm+llc' : null);
        // The plugin must load into an -flto compile and write a record there.
        const rec = join(d, 'pf-record.json');
        rmSync(rec, { force: true });
        const objOn = join(d, 'on', 'u.o');
        mkdirSync(dirname(objOn), { recursive: true });
        const cOn = await compileObj(src, objOn, mode, opt, wpinEnv(rec, ['vgpre_wipe'], false), true);
        const rr = readRecordFields(readOrNull(rec)?.toString('utf8') ?? null, { dryRun: false, module: 'pf.c' });
        p.plugin = cOn.kind !== 'bitcode' ? `object ${cOn.kind}` : !rr.ok ? `record refused (${rr.problems.join(',')})`
          : rr.pinnedCount < 1 ? 'record pinned nothing' : 'record valid, pinned';
        // The sentinel reading of configuration (ii) must be able to say "kept":
        // a stock link, and a link naming a plugin that does not exist, both leave
        // it where it was. Otherwise "removed" would not mean "WipePin's load-time
        // callback ran".
        if (c.kind === 'bitcode') {
          const sRec = join(d, 'sentinel.json');
          writeFileSync(sRec, SENTINEL, 'utf8');
          await linkAsm(obj, 'pf-sentinel-stock', mode, opt, 'asm', { env: wpinEnv(sRec, ['vgpre_wipe'], false) });
          const b1 = readOrNull(sRec);
          p.sentinelStockLink = linkPluginState({ exists: b1 !== null, text: b1 ? b1.toString('utf8') : null });
          writeFileSync(sRec, SENTINEL, 'utf8');
          const bad = await linkAsm(obj, 'pf-sentinel-absent', mode, opt, 'asm',
            { env: wpinEnv(sRec, ['vgpre_wipe'], false), linkPlugin: join(d, 'absent-plugin.so') });
          const b2 = readOrNull(sRec);
          p.sentinelAbsentPlugin = linkPluginState({ exists: b2 !== null, text: b2 ? b2.toString('utf8') : null });
          p.absentPluginStderr = bad.stderrFlags && bad.stderrFlags.failedToLoad ? 'Failed to load passes' : (bad.stderrEmpty ? 'empty' : 'other');
        }
        pre[key] = p;
        if (c.kind !== 'bitcode') die(5, `preflight ${key}: the -flto compile produced a ${c.kind} object, not bitcode`);
        if (p.sentinelStockLink !== 'sentinel-kept' || p.sentinelAbsentPlugin !== 'sentinel-kept') {
          die(5, `preflight ${key}: the WPIN_OUT sentinel did not survive a link without WipePin (stock ${p.sentinelStockLink}, `
            + `absent plugin ${p.sentinelAbsentPlugin}); configuration (ii) could not be read`);
        }
        if (!p.emit) die(5, `preflight ${key}: post-LTO code could not be cut by bodyOf either way (asm: ${p.asm}; llvm+llc: ${p.llvmLlc})`);
        if (p.plugin !== 'record valid, pinned') die(5, `preflight ${key}: the plugin did not run in an -flto compile (${p.plugin})`);
        if (p.emit !== 'asm') process.stderr.write(`note: ${key} reads post-LTO code through --save-temps precodegen.bc + llc (${args.forceFallback ? 'forced' : `--lto-emit-asm: ${p.asm}`})\n`);
      }
    }
  }

  // ---- sources -----------------------------------------------------------------
  const units = [];
  for (const id of ids) {
    const sc = id.split('_')[2];
    const m = scen[sc];
    if (!m || m.fam !== 'erasure') die(5, `${id}: not an erasure scenario in scenarios.json`);
    const text = readFileSync(join(GEN, `${id}.c`), 'utf8');
    const ws = cell.wipeSpans(text, m.fn);
    if (!ws.spans.length) die(5, `${id}: the find step's wipeSpans finds no wipe although the tracked rows score one`);
    const pW = join(SRC, `${id}.w.c`);
    const pWo = join(SRC, `${id}.wo.c`);
    writeFileSync(pW, text + cell.CONTROL, 'utf8');
    writeFileSync(pWo, cell.ablateSpans(text, ws.spans) + cell.CONTROL, 'utf8');
    units.push({ id, fn: m.fn, pW, pWo, requested: [...new Set([m.fn, ...ws.helpers])], nSpans: ws.spans.length });
  }
  const jobs = [];
  for (const u of units) for (const mode of args.modes) for (const opt of args.opts) jobs.push({ u, mode, opt });
  process.stderr.write(`${units.length} of ${selectedTotal} selected file(s), modes ${args.modes.join(' ')}, opts ${args.opts.join(' ')}: ${jobs.length} cell(s), `
    + '6 compiles and 12 links each\n');

  // ---- cells -------------------------------------------------------------------
  const rows = [];
  let done = 0;
  await cell.pool(jobs, async ({ u, mode, opt }) => {
    const emit = pre[`${mode}${opt}`].emit;
    const cdir = join(CELLS, u.id, `${mode}${opt}`);
    rmSync(cdir, { recursive: true, force: true });
    const sides = { w: u.pW, wo: u.pWo };
    const objs = {};
    const recs = {};
    const kinds = {};
    const compiled = {};
    for (const side of ['w', 'wo']) {
      for (const cfg of ['off', 'on', 'dry']) {
        const k = `${side}.${cfg}`;
        const d = join(cdir, k);
        mkdirSync(d, { recursive: true });
        objs[k] = join(d, 'u.o');
        if (cfg === 'off') {
          const c = await compileObj(sides[side], objs[k], mode, opt, BASE_ENV, false);
          kinds[k] = c.kind; compiled[k] = c.rc === 0;
        } else {
          recs[k] = join(d, 'record.json');
          rmSync(recs[k], { force: true });
          const c = await compileObj(sides[side], objs[k], mode, opt, wpinEnv(recs[k], u.requested, cfg === 'dry'), true);
          kinds[k] = c.kind; compiled[k] = c.rc === 0;
        }
      }
    }
    const notLto = Object.entries(kinds).filter(([, v]) => v !== 'bitcode' && v !== 'missing').map(([k, v]) => `${k} object is ${v}`);
    const asm = {};
    const links = {};
    const doLink = async (k, tag, opts2) => {
      if (kinds[k] !== 'bitcode') return { asm: null, problem: `no bitcode object (${kinds[k]})`, layout: null, stderrEmpty: null, stderrFlags: null, linkLine: null };
      const l = await linkAsm(objs[k], tag, mode, opt, emit, opts2);
      if (l.layout) notLto.push(`${k} ${tag}: ${l.layout}`);
      return l;
    };
    for (const k of ['w.off', 'wo.off', 'w.on', 'wo.on', 'w.dry', 'wo.dry']) {
      links[k] = await doLink(k, 'stock1');
      asm[k] = links[k].asm;
    }
    // determinism: the same object, linked again
    const deterministic = {};
    for (const k of ['w.off', 'wo.off', 'w.on', 'wo.on']) {
      const again = await doLink(k, 'stock2');
      deterministic[k] = asm[k] !== null && again.asm !== null ? sha256Text(asm[k]) === sha256Text(again.asm) : null;
    }
    // (ii) the plugin on the link line only, with a sentinel at WPIN_OUT
    const lp = {};
    for (const side of ['w', 'wo']) {
      const k = `${side}.off`;
      const rec = join(dirname(objs[k]), 'link-plugin-record.json');
      writeFileSync(rec, SENTINEL, 'utf8');
      const l = await doLink(k, 'linkplugin', { env: wpinEnv(rec, u.requested, false), linkPlugin: args.plugin });
      const buf = readOrNull(rec);
      lp[side] = {
        state: linkPluginState({ exists: buf !== null, text: buf ? buf.toString('utf8') : null }),
        asmEqualsStock: l.asm !== null && asm[k] !== null ? l.asm === asm[k] : null,
        stderrLineCount: l.linkLine ? l.linkLine.count : null,
        stderrExactlyLine: l.linkLine ? l.linkLine.exactlyOnce : null,
        stderrFailedToLoad: l.stderrFlags ? l.stderrFlags.failedToLoad : null,
        asm: l.asm,
      };
    }

    const baseline = cell.verdictOf(asm['w.off'], asm['wo.off'], u.fn);
    const repaired = cell.verdictOf(asm['w.on'], asm['wo.on'], u.fn);
    const dry = cell.verdictOf(asm['w.dry'], asm['wo.dry'], u.fn);
    const lpVerdict = cell.verdictOf(lp.w.asm, lp.wo.asm, u.fn);
    const recText = (k) => { const b = readOrNull(recs[k]); return b ? b.toString('utf8') : null; };
    const recW = readRecordFields(recText('w.on'), { dryRun: false, module: basename(u.pW) });
    const recWo = readRecordFields(recText('wo.on'), { dryRun: false, module: basename(u.pWo) });
    const recDryW = readRecordFields(recText('w.dry'), { dryRun: true, module: basename(u.pW) });
    const recDryWo = readRecordFields(recText('wo.dry'), { dryRun: true, module: basename(u.pWo) });
    const controlOnW = asm['w.on'] ? cell.controlPresent(asm['w.on']).ok : false;
    const controlOnWo = asm['wo.on'] ? cell.controlPresent(asm['wo.on']).ok : false;
    const oc = ltoOutcome({ notLto, baseline, repaired, recW, recWo, controlOnW, controlOnWo });

    // where the loss happens: the compile-stage bitcode of the requested functions
    let bitcode = null;
    if (haveDis) {
      const dis = async (k) => {
        if (kinds[k] !== 'bitcode') return null;
        const r = await tool(args.llvmDis, ['-o', '-', objs[k]], BASE_ENV);
        return r.rc === 0 ? zeroMemsetsInFunctions(r.stdout, u.requested) : null;
      };
      const wOff = await dis('w.off');
      const wOn = await dis('w.on');
      bitcode = { wOff: wOff && { volatile: wOff.volatile, plain: wOff.plain }, wOn: wOn && { volatile: wOn.volatile, plain: wOn.plain } };
    }

    const eqObj = (a, b) => (kinds[a] === 'bitcode' && kinds[b] === 'bitcode' ? sha256File(objs[a]) === sha256File(objs[b]) : null);
    const eqAsm = (a, b) => (asm[a] !== null && asm[b] !== null ? asm[a] === asm[b] : null);
    const tv = trackedVerdict.get(`${u.id}|${opt}`) ?? null;
    rows.push({
      id: u.id, fn: u.fn, mode, opt, emit, requested: u.requested, n_spans: u.nSpans,
      objects: kinds, compiled,
      tracked: tv, baseline: baseline.verdict, baselineControl: baseline.control ?? null,
      repaired: repaired.verdict, repairedControl: repaired.control ?? null,
      dry: dry.verdict,
      outcome: oc.outcome, outcomeReason: oc.reason,
      recW: recW.ok ? { ok: true, pinnedCount: recW.pinnedCount } : { ok: false, problems: recW.problems },
      recWo: recWo.ok ? { ok: true, pinnedCount: recWo.pinnedCount } : { ok: false, problems: recWo.problems },
      recDryW: recDryW.ok ? { ok: true, pinnedCount: recDryW.pinnedCount } : { ok: false, problems: recDryW.problems },
      recDryWo: recDryWo.ok ? { ok: true, pinnedCount: recDryWo.pinnedCount } : { ok: false, problems: recDryWo.problems },
      controlOnW, controlOnWo,
      linkProblems: Object.fromEntries(Object.entries(links).filter(([, l]) => l.problem).map(([k, l]) => [k, l.problem])),
      linkPlugin: {
        verdict: lpVerdict.verdict,
        w: { state: lp.w.state, asmEqualsStock: lp.w.asmEqualsStock, stderrLineCount: lp.w.stderrLineCount, stderrExactlyLine: lp.w.stderrExactlyLine, stderrFailedToLoad: lp.w.stderrFailedToLoad },
        wo: { state: lp.wo.state, asmEqualsStock: lp.wo.asmEqualsStock, stderrLineCount: lp.wo.stderrLineCount, stderrExactlyLine: lp.wo.stderrExactlyLine, stderrFailedToLoad: lp.wo.stderrFailedToLoad },
      },
      deterministic,
      dryObjectEqualsOff: { w: eqObj('w.dry', 'w.off'), wo: eqObj('wo.dry', 'wo.off') },
      dryAsmEqualsOff: { w: eqAsm('w.dry', 'w.off'), wo: eqAsm('wo.dry', 'wo.off') },
      bitcode,
      listings: Object.fromEntries(Object.entries(asm).map(([k, v]) => [k, sha256Text(v)])),
    });
    if (++done % 50 === 0) process.stderr.write(`  ${done} cells\n`);
  }, args.conc);

  rows.sort((a, b) => cmp(a.mode, b.mode) || cmp(ALL_OPTS.indexOf(a.opt), ALL_OPTS.indexOf(b.opt)) || cmp(a.id, b.id));

  // ---- results -------------------------------------------------------------------
  const groups = [];
  for (const mode of args.modes) for (const opt of args.opts) {
    const sub = rows.filter((r) => r.mode === mode && r.opt === opt);
    groups.push({ mode, opt, emit: pre[`${mode}${opt}`].emit, s: summarizeGroup(sub) });
  }
  const text = render({ args, ccName, ccVersion, lldVersion, pluginSha, pre, groups, units, selectedTotal, haveDis, rows });
  const rowsText = '[\n' + rows.map((r) => JSON.stringify(r)).join(',\n') + '\n]\n';
  const manifestText = JSON.stringify({
    generatedAt: new Date().toISOString(), node: process.version, cc: ccName, ccVersion, lld: lldVersion,
    plugin: { basename: basename(args.plugin), sha256: pluginSha },
    modes: args.modes, opts: args.opts, files: args.files, sample: args.sample, selectedTotal, measuredFiles: units.length,
    forceFallback: args.forceFallback, conc: args.conc, llvmDis: haveDis, preflight: pre,
    compileFlags: FLAGS_BY_MODE, linkArgs: Object.fromEntries(args.modes.map((m) => [m, ltoLinkArgs({ opt: '-O2', mode: m })])),
    ignoredInheritedEnv: inherited,
  }, null, 2) + '\n';
  const hits = [];
  for (const [name, t] of [['lto-rows.json', rowsText], ['lto-results.txt', text], ['manifest.json', manifestText]]) {
    const h = absolutePathHits(t);
    if (h.length) hits.push(`${name}: ${h.join(', ')}`);
  }
  writeFileSync(join(OUT, 'lto-rows.json'), rowsText, 'utf8');
  writeFileSync(join(OUT, 'lto-results.txt'), text, 'utf8');
  writeFileSync(join(OUT, 'manifest.json'), manifestText, 'utf8');
  process.stdout.write(text);
  if (hits.length) die(5, `an absolute path was written into the lab texts (${hits.join('; ')})`);

  const broken = groups.some(({ s }) => s.outcomes.NOT_LTO > 0 || s.determinism.identical !== s.determinism.pairs
    || (s.baselineEliminated > 0 && !s.dry.held) || !s.linkPlugin.grade.held);
  process.exit(broken ? 2 : 0);
}

// ---------------------------------------------------------------- rendering --
function pad(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }

function render({ args, ccName, ccVersion, lldVersion, pluginSha, pre, groups, units, selectedTotal, haveDis, rows }) {
  const L = [];
  L.push('lto-probe results (tools/lto-probe.mjs)');
  L.push('');
  L.push(`compiler        ${ccName}  (${ccVersion})`);
  L.push(`linker          ${lldVersion}`);
  L.push(`plugin sha256   ${pluginSha}`);
  L.push(`files           ${units.length} of the ${selectedTotal} clang-18 erasure files tracked WIPE_ELIMINATED at ${SELECT_OPT}`
    + `${args.files ? ` (--files ${args.files.join(',')})` : ''}${args.sample ? ` (--sample ${args.sample})` : ''}`);
  L.push(`modes / opts    ${args.modes.join(',')} / ${args.opts.join(',')}`);
  L.push('link            each object alone: -shared, -fuse-ld=lld, post-LTO code via --lto-emit-asm'
    + `${args.forceFallback ? ' (forced to the fallback: --save-temps precodegen.bc + llc)' : ''}`);
  L.push('');
  L.push('preflight (per form and level: bitcode object; for each reading path, post-LTO code cut by bodyOf with the positive control PRESENT');
  L.push('           and the LTO pipeline built on that link (WipePin on the link line clears a sentinel); plugin record under -flto)');
  for (const [k, p] of Object.entries(pre)) {
    L.push(`  ${pad(k, 9)} object ${p.objectKind}; --lto-emit-asm ${p.asm}; fallback (precodegen+llc) ${p.llvmLlc}; reading via ${p.emit}; plugin ${p.plugin}`);
    L.push(`  ${pad('', 9)} WPIN_OUT sentinel after a stock link: ${p.sentinelStockLink}; after a link naming an absent plugin: ${p.sentinelAbsentPlugin} (linker stderr: ${p.absentPluginStderr})`);
  }
  L.push('');
  for (const { mode, opt, emit, s } of groups) {
    L.push(`== ${mode} LTO ${opt}  (${s.cells} cells, post-LTO code via ${emit})`);
    L.push(`  baseline (plugin off, stock link)   eliminated ${s.baselineEliminated}, survived ${s.baselineSurvived}, other ${s.baselineOther}`);
    L.push(`  differs from the tracked non-LTO row: ${s.trackedDiff.length}`);
    for (const d of s.trackedDiff) L.push(`    DIFF ${d.id}: tracked (no LTO) ${d.tracked}, LTO ${d.lto}`);
    L.push('  (i) plugin at compile time, stock link');
    for (const o of LTO_OUTCOMES) if (s.outcomes[o]) L.push(`    ${pad(o, 22)} ${s.outcomes[o]}`);
    const here = rows.filter((r) => r.mode === mode && r.opt === opt);
    for (const r of here.filter((x) => x.outcome === 'NOT_LTO')) L.push(`    NOT_LTO ${r.id}: ${r.outcomeReason}`);
    for (const r of here.filter((x) => x.baseline === ELIMINATED && x.outcome !== 'RETAINED')) L.push(`    NOT RETAINED ${r.id}: ${r.outcome} -- ${r.outcomeReason}`);
    L.push(`  (iii) dry run at compile time: red control ${s.dry.held ? 'HELD' : 'FAILED'} -- still eliminated ${s.dry.stillEliminated}/${s.dry.considered}`);
    for (const v of s.dry.violations) L.push(`    VIOLATION ${v}`);
    L.push(`    dry-run object byte-identical to plugin-off ${s.dryObjectEqualsOff.equal}/${s.dryObjectEqualsOff.of}; post-LTO assembly identical ${s.dryAsmEqualsOff.equal}/${s.dryAsmEqualsOff.of}`);
    const lp = s.linkPlugin;
    L.push(`  (ii) plugin on the link line only (${lp.links} links): record written ${lp.recordWritten}; load-time callback ran (sentinel at WPIN_OUT removed) ${lp.callbackRan}; sentinel kept ${lp.sentinelKept}`);
    L.push(`    assembly byte-identical to the stock link of the same object ${lp.asmEqualsStock}/${lp.links}; linker stderr exactly the WipePin link-time line, once ${lp.stderrExactlyLine}/${lp.links}; verdict equals the baseline ${lp.verdictEqualsBaseline}/${lp.cells}`);
    L.push(`    graded: ${lp.grade.held ? 'HELD' : 'FAILED'} (${lp.grade.links} links: sentinel removed, no record, the line exactly once and nothing else, assembly equal to the stock link)`);
    for (const v of lp.grade.violations.slice(0, 20)) L.push(`    VIOLATION ${v}`);
    if (lp.grade.violations.length > 20) L.push(`    ... ${lp.grade.violations.length - 20} more`);
    L.push(`  determinism: the same object linked twice, byte-identical assembly ${s.determinism.identical}/${s.determinism.pairs}`);
    if (haveDis) {
      const st = s.stage;
      L.push(`  compile-stage bitcode, baseline-eliminated cells (${st.eliminated}), requested functions: w/off still holds a plain zero-fill memset ${st.wOffBitcodeHoldsPlainMemset}, holds none ${st.wOffBitcodeHoldsNone}; w/on holds a volatile one ${st.wOnBitcodeHoldsVolatile}; unread ${st.unread}`);
    } else {
      L.push('  compile-stage bitcode: not read (llvm-dis not runnable)');
    }
    L.push('');
  }
  return L.join('\n');
}

main().catch((e) => die(5, `unexpected failure: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`));

#!/usr/bin/env node
/**
 * lto-probe-gcc -- does a wipe WipePinGcc pinned at compile time survive gcc's
 * link-time optimisation, judged by the find step's own verdict on the assembly
 * lto1 writes?
 *
 * The gcc twin of lto-probe.mjs. compiler/gcc-repair/README.md ("Other forms")
 * shows it on one fixture; this measures it on the r2 corpus. For every selected
 * file and level, the wipe-kept unit w and the ablated unit wo (made with the
 * imported ablateSpans) are compiled with the find step's FLAGS, `-S` replaced
 * by `-c` plus `-flto`, and each object is linked ALONE, in its own directory:
 *
 *   gcc-13 <opt> -flto -shared -save-temps -o <dir>/<tag>.so <dir>/u.o
 *
 * -save-temps keeps what lto1 wrote, among it the assembly of the one partition
 * (<tag>.so.ltrans0.ltrans.s), and verdictOf(w, wo, fn) -- imported from
 * ../../ai-generated/lib/ablation-cell.mjs, with its bodyOf and positive control
 * -- judges that assembly. Configurations, per cell:
 *
 *   (i)   plugin at compile time (-fplugin), stock link      the measurement
 *   (ii)  plugin only on the link line (-fplugin)            lto1 refuses to install it:
 *         the refusal exactly twice (the whole-program analysis and the one partition),
 *         no record, the sentinel at WPIN_OUT removed, and the post-LTO assembly and the
 *         shared object byte-identical to the stock link of the same object
 *   (iii) plugin at compile time in dry-run mode, stock link the red control
 *   and   every object linked a second time                  determinism
 *
 * Where the loss happens is read from the objects themselves: lto-dump-13 prints
 * the GIMPLE cc1 wrote into w/off, wo/off and w/on, and the probe counts the
 * zero-fill memsets in the requested functions -- does the stock wipe reach the
 * link at all, and does the pinned one? A reading counts only when the same
 * object's positive control reads as one plain memset.
 *
 * Every object must be an ELF file with `.gnu.lto_` sections, and every stock
 * link must write exactly the files a one-partition LTO link writes; a cell
 * where either fails is NOT_LTO and is never counted as an LTO result. Every
 * record is read through ../lib/pin-record.mjs, told the component is
 * WipePinGcc.
 *
 * Lab output only. Everything -- sources, objects, links, records, rows,
 * results -- goes under --out, which must lie outside the repository. There is
 * no --write-data: nothing here is tracked data. See LTO.md.
 *
 *   node lto-probe-gcc.mjs --plugin <libWipePinGcc.so> --out <lab dir> [options]
 *
 * Exit codes: 0 run complete and every integrity check held; 2 run complete but
 * a cell was NOT_LTO, a relink was not byte-identical, the dry-run red control
 * did not hold, configuration (ii) was not HELD, or WipePinGcc printed on a
 * stock link; 3 nothing selected; 4 bad arguments (a --cc that is not gcc,
 * --out inside the repository, --write-data); 5 a tool, the plugin, the tracked
 * rows or the shared verdict module could not be used, the preflight failed, or
 * a text about to be written carried an absolute path.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join, basename, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ELIMINATED, LTO_OUTCOMES, SENTINEL, linkPluginState, evenSample, insideRepo, pickOutput } from './lib/lto.mjs';
import {
  GCC_COMPONENT, gccCompileFlags, gccLinkArgs, gccObjectKind, optsNamePlugin, gccExpectedOutputs, gccLayoutOf,
  EXPECTED_LAYOUT, EXPECTED_REFUSALS, refusalReading, wipePinGccLines, stderrLines, gccLtoOutcome, selectIds,
  summarizeGccGroup, brokenReasons, gimpleBodyOf, zeroMemsetsInGimple, gimpleControlOk,
} from './lib/lto-gcc.mjs';
import { readPinRecord } from '../lib/pin-record.mjs';
import { vendorOf, dataFileNames, trackedCcProblem } from '../lib/vendor.mjs';
import { differsOnlyInLabels } from '../lib/surgicality.mjs';
import { sha256Text, absolutePathHits } from '../lib/provenance.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const REPO = resolve(LANE, '..', '..', '..');
const AIGEN = resolve(LANE, '..', 'ai-generated');
const GEN = join(AIGEN, 'generated-corpus', 'r2');
const SCEN_PATH = join(AIGEN, 'scenarios.json');
const CELL_PATH = join(AIGEN, 'lib', 'ablation-cell.mjs');
const DEFAULT_CC = 'gcc-13';
const DEFAULT_LTO_DUMP = 'lto-dump-13';
const DEFAULT_ROWS = join(LANE, 'data', dataFileNames(DEFAULT_CC).rows);
const ALL_OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];
const SIDES = ['w', 'wo'];
const CFGS = ['off', 'on', 'dry'];
const OBJECTS = SIDES.flatMap((s) => CFGS.map((c) => `${s}.${c}`));

const USAGE = `usage: node lto-probe-gcc.mjs --plugin <so> --out <dir> [options]

  --plugin <so>        WipePinGcc (required; there is no default)
  --out <dir>          lab directory, outside the repository (required)
  --cc <compiler>      default ${DEFAULT_CC}; its basename must name gcc, and the tracked rows must hold it
  --opts <list>        comma list from ${ALL_OPTS.join(' ')} (default -O2)
  --all-removable      select every removable-idiom file at each level, not only the eliminated ones
  --files <list>       comma list of basenames or globs, within the selection
  --sample <n>         n files spread evenly over each level's selection (default: all)
  --conc <n>           parallel cells (default 2)
  --rows <path>        tracked gcc repair rows (default the lane's data/${dataFileNames(DEFAULT_CC).rows})
  --lto-dump <tool>    default ${DEFAULT_LTO_DUMP} (reads the compile-stage GIMPLE of the objects; optional column)

The selection, per level: the erasure files the tracked rows score WIPE_ELIMINATED there
(with --all-removable, every file of the removable idiom there).
Everything is written under --out; there is no --write-data.
`;

function die(code, msg) {
  process.stderr.write(`lto-probe-gcc: ${msg}\n`);
  process.exit(code);
}

function globToRe(g) {
  const s = g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + s + '$');
}

function parseArgs(argv) {
  const a = { plugin: null, out: null, cc: DEFAULT_CC, opts: ['-O2'], allRemovable: false, files: null, sample: null, conc: 2, rows: DEFAULT_ROWS, ltoDump: DEFAULT_LTO_DUMP };
  const need = (i, flag) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${flag} needs a value`); return argv[i + 1]; };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--plugin': a.plugin = need(i, f); i++; break;
      case '--out': a.out = need(i, f); i++; break;
      case '--cc': a.cc = need(i, f); i++; break;
      case '--opts': a.opts = list(need(i, f)); i++; break;
      case '--all-removable': a.allRemovable = true; break;
      case '--files': a.files = list(need(i, f)); i++; break;
      case '--sample': a.sample = Number(need(i, f)); i++; break;
      case '--conc': a.conc = Number(need(i, f)); i++; break;
      case '--rows': a.rows = need(i, f); i++; break;
      case '--lto-dump': a.ltoDump = need(i, f); i++; break;
      case '--write-data': die(4, '--write-data does not exist here: the LTO probe writes its lab directory and nothing else'); break;
      case '-h': case '--help': process.stdout.write(USAGE); process.exit(0); break;
      default: die(4, `unknown argument ${f}\n${USAGE}`);
    }
  }
  if (!a.plugin) die(4, '--plugin is required');
  if (!a.out) die(4, '--out is required: everything the probe writes goes to a lab directory outside the repository');
  if (vendorOf(a.cc) !== 'gcc') die(4, `--cc ${basename(a.cc)}: this probe drives gcc and WipePinGcc; for clang use lto-probe.mjs`);
  for (const o of a.opts) if (!ALL_OPTS.includes(o)) die(4, `--opts: ${o} is not one of ${ALL_OPTS.join(' ')}`);
  if (!a.opts.length) die(4, '--opts is empty');
  a.opts = ALL_OPTS.filter((o) => a.opts.includes(o));
  if (a.sample !== null && (!Number.isInteger(a.sample) || a.sample < 1)) die(4, '--sample must be a positive integer');
  if (!Number.isInteger(a.conc) || a.conc < 1) die(4, '--conc must be a positive integer');
  a.plugin = resolve(a.plugin);
  a.out = resolve(a.out);
  a.rows = resolve(a.rows);
  if (insideRepo(a.out, REPO, sep)) die(4, '--out lies inside the repository; the probe writes lab output only');
  return a;
}

const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
const sha256File = (p) => { try { return createHash('sha256').update(readFileSync(p)).digest('hex'); } catch { return null; } };

/** process.env with every WPIN_* removed: nothing inherited may steer a compile or a link. */
function cleanEnv() {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith('WPIN_')) env[k] = v;
  return env;
}

/** Run a tool; never throws. stderr is returned for inspection and never written anywhere. */
async function tool(cmd, args, env, { timeout = 90000, cwd } = {}) {
  try {
    const { stdout, stderr } = await run(cmd, args, { env, timeout, cwd, maxBuffer: 64 * 1024 * 1024 });
    return { rc: 0, stdout, stderr };
  } catch (e) {
    return { rc: typeof e.code === 'number' ? e.code : -1, stdout: String(e.stdout || ''), stderr: String(e.stderr || e.message || '') };
  }
}

function readOrNull(p) {
  try { return readFileSync(p); } catch { return null; }
}

/** A record read through pin-record.mjs, cut down to what a row carries: never the record itself. */
function recSummary(rr) {
  return rr.ok
    ? { ok: true, dryRun: rr.record.dryRun, pinnedCount: rr.record.pinnedCount, wouldPinCount: rr.record.wouldPinCount }
    : { ok: false, problems: rr.problems };
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
  let COMPILE_FLAGS;
  try { COMPILE_FLAGS = gccCompileFlags(cell.FLAGS); } catch (e) { die(5, e.message); }

  const ccv = await tool(args.cc, ['--version'], BASE_ENV, { timeout: 30000 });
  if (ccv.rc !== 0) die(5, `${args.cc} --version failed: the compiler is not runnable here`);
  const ccVersion = ccv.stdout.split('\n')[0].trim();
  const ccName = basename(args.cc);
  const ldv = await tool(args.cc, ['-Wl,--version'], BASE_ENV, { timeout: 30000 });
  const ldVersion = ldv.rc === 0 ? (ldv.stdout.split('\n')[0] || '').trim() : null;
  if (!ldVersion) die(5, `${args.cc} -Wl,--version failed: the linker the probe needs is not reachable`);
  const pluginSha = sha256File(args.plugin);

  // ---- selection: per level, from the tracked gcc repair rows -------------------
  let tracked;
  try { tracked = JSON.parse(readFileSync(args.rows, 'utf8')); } catch { die(5, 'the --rows file could not be read as JSON'); }
  const ccWhy = trackedCcProblem(tracked, ccName);
  if (ccWhy) die(5, ccWhy);
  const scen = JSON.parse(readFileSync(SCEN_PATH, 'utf8'));
  const trackedRow = new Map();
  for (const r of tracked) if (r && r.kind === 'erasure' && r.cc === ccName) trackedRow.set(`${r.id}|${r.opt}`, r);
  const selection = {};
  let selectedCells = 0;
  for (const opt of args.opts) {
    let ids = selectIds(tracked, { cc: ccName, opt, allRemovable: args.allRemovable });
    const total = ids.length;
    if (args.files) {
      const res = args.files.map(globToRe);
      ids = ids.filter((id) => res.some((re) => re.test(id) || re.test(`${id}.c`)));
    }
    ids = evenSample(ids, args.sample ?? undefined);
    selection[opt] = { total, ids };
    selectedCells += ids.length;
  }
  if (!selectedCells) die(3, 'nothing selected');

  const OUT = args.out;
  const SRC = join(OUT, 'src');
  const CELLS = join(OUT, 'cells');
  const PRE = join(OUT, 'preflight');
  for (const d of [SRC, CELLS, PRE]) mkdirSync(d, { recursive: true });

  const pluginArg = `-fplugin=${args.plugin}`;
  const wpinEnv = (recordPath, requested, dryRun) => {
    const env = { ...BASE_ENV, WPIN_OUT: recordPath, WPIN_TARGET_FNS: requested.join(',') };
    if (dryRun) env.WPIN_DRY_RUN = '1';
    return env;
  };

  /** Compile one unit to an LTO object; returns the object kind. */
  async function compileObj(src, obj, opt, env, plugin) {
    rmSync(obj, { force: true });
    const r = await tool(args.cc, [...COMPILE_FLAGS, opt, ...(plugin ? [pluginArg] : []), '-o', obj, src], env);
    return { rc: r.rc, kind: gccObjectKind(r.rc === 0 ? readOrNull(obj) : null) };
  }

  /**
   * Link one object alone and return the post-LTO assembly (or null), the shared
   * object's digest, and what the link wrote and printed. The object sits alone
   * in its directory, the link runs there with its -o beside the object, and
   * every file gcc 13 writes for it lands there (see gccExpectedOutputs), so
   * "the files that appeared" is the complete list. Links of one object run one
   * after another, and each writes only names that start with its own -o.
   */
  async function linkLto(obj, tag, opt, { env = BASE_ENV, linkPlugin = null } = {}) {
    const dir = dirname(obj);
    const outBase = `${tag}.so`;
    const before = new Set(readdirSync(dir));
    const r = await tool(args.cc, [...gccLinkArgs({ opt, linkPlugin }), '-o', join(dir, outBase), obj], env, { cwd: dir });
    const fresh = readdirSync(dir).filter((n) => !before.has(n));
    const layout = gccLayoutOf(fresh, outBase);
    const base = { rc: r.rc, stderr: r.stderr, layout };
    if (r.rc !== 0) return { ...base, asm: null, soSha: null, problem: `link rc ${r.rc}`, layoutProblem: null };
    const want = gccExpectedOutputs({ outBase });
    const pick = pickOutput(fresh, want);
    if (!pick.ok) {
      const p = `${layout} layout: ${pick.problem}`;
      return { ...base, asm: null, soSha: sha256File(join(dir, want.so)), problem: p, layoutProblem: p };
    }
    return { ...base, asm: readFileSync(join(dir, pick.name), 'utf8'), soSha: sha256File(join(dir, want.so)), problem: null, layoutProblem: null };
  }

  const readRec = (file, { dryRun, opt, module, requested }) =>
    readPinRecord(file, { component: GCC_COMPONENT, scope: 'functions', dryRun, opt, module, requested });

  // The GIMPLE reader is optional, as llvm-dis is for the clang probe: a tool that
  // cannot be started leaves the column unread. One that starts must read the
  // preflight unit correctly (below), or the run stops.
  const dumpStart = await tool(args.ltoDump, ['-help'], BASE_ENV, { timeout: 30000 });
  const haveDump = !(dumpStart.rc === -1 && /ENOENT/.test(dumpStart.stderr));
  const ltoDumpName = basename(args.ltoDump);

  /**
   * The compile-stage GIMPLE of one object, read with lto-dump: the zero-fill
   * memsets in `names` (zeroMemsetsInGimple), counted only when the same object's
   * positive control reads as one plain memset. `-o /dev/null`: without it
   * lto-dump writes an empty `u.s` beside the object.
   */
  async function readGimple(obj, names) {
    const dump = async (fn) => gimpleBodyOf(await tool(args.ltoDump, [`-dump-body=${fn}`, obj, '-o', '/dev/null'], BASE_ENV), fn);
    const ctl = await dump('vgctl_control');
    if (ctl.state !== 'body' || !gimpleControlOk(ctl.body)) {
      return { ok: false, problem: `the positive control read ${ctl.state === 'body' ? 'without exactly one plain zero-fill memset' : ctl.state}` };
    }
    const bodies = {};
    for (const fn of names) {
      const b = await dump(fn);
      if (b.state === 'unreadable') return { ok: false, problem: `${fn}: unreadable` };
      bodies[fn] = b.body;
    }
    if (bodies[names[0]] === null) return { ok: false, problem: `${names[0]}: not defined in the object` };
    const m = zeroMemsetsInGimple(bodies);
    return { ok: true, plain: m.plain, pinned: m.pinned, helperCalls: m.helperCalls, defined: m.defined };
  }

  // ---- preflight, per level, before any cell -------------------------------------
  const pre = {};
  {
    const src = join(PRE, 'pf.c');
    writeFileSync(src, 'void vgpre_wipe(unsigned char *p) { __builtin_memset(p, 0, 64); }\n' + cell.CONTROL, 'utf8');
    const req = ['vgpre_wipe'];
    for (const opt of args.opts) {
      const d = join(PRE, opt);
      rmSync(d, { recursive: true, force: true });
      mkdirSync(d, { recursive: true });
      const p = {};
      const fail = [];
      // 1. a stock -flto compile is a gcc LTO object
      const obj = join(d, 'u.o');
      const c = await compileObj(src, obj, opt, BASE_ENV, false);
      p.objectKind = c.kind;
      if (c.kind !== 'gcc-lto') fail.push(`the -flto compile wrote a ${c.kind} object`);
      // 2. its stock link writes the one-partition layout, and the assembly is cut by
      //    bodyOf with the positive control PRESENT
      const stock = c.kind === 'gcc-lto' ? await linkLto(obj, 'pf-stock', opt) : null;
      p.stockLayout = stock ? stock.layout : null;
      const cuts = (asm) => !!asm && cell.controlPresent(asm).ok && cell.bodyOf(asm, 'vgctl_control') !== null && cell.bodyOf(asm, 'vgpre_wipe') !== null;
      p.asm = !stock ? 'no link' : stock.problem ? stock.problem : cuts(stock.asm) ? 'PRESENT' : 'not cut by bodyOf / control not PRESENT';
      if (p.asm !== 'PRESENT') fail.push(`post-LTO assembly: ${p.asm}`);
      p.stockStderrLines = stock ? stderrLines(stock.stderr).length : null;
      // 3. the plugin on the link line: lto1 refuses it, EXPECTED_REFUSALS times, and
      //    removes the sentinel at WPIN_OUT; the link's output is the stock link's
      if (stock && stock.asm) {
        const sRec = join(d, 'pf-sentinel.json');
        writeFileSync(sRec, SENTINEL, 'utf8');
        const lp = await linkLto(obj, 'pf-linkplugin', opt, { env: wpinEnv(sRec, req, false), linkPlugin: args.plugin });
        const b = readOrNull(sRec);
        const rr = refusalReading(lp.stderr, stock.stderr);
        p.linkPlugin = {
          rc: lp.rc, refusals: rr.count, restIsStock: rr.restIsStock, layout: lp.layout,
          sentinel: linkPluginState({ exists: b !== null, text: b ? b.toString('utf8') : null }),
          asmEqualsStock: lp.asm !== null && lp.asm === stock.asm, soEqualsStock: !!lp.soSha && lp.soSha === stock.soSha,
        };
        const x = p.linkPlugin;
        if (x.rc !== 0 || x.refusals !== EXPECTED_REFUSALS || !x.restIsStock || x.layout !== EXPECTED_LAYOUT || x.sentinel !== 'removed' || !x.asmEqualsStock || !x.soEqualsStock) {
          fail.push(`the plugin on the link line did not read as lto1 refusing it (rc ${x.rc}, refusals ${x.refusals}, rest is stock ${x.restIsStock}, `
            + `layout ${x.layout}, sentinel ${x.sentinel}, assembly equal ${x.asmEqualsStock}, shared object equal ${x.soEqualsStock})`);
        }
      }
      // 4. the plugin loads into an -flto compile and writes a record there that
      //    pin-record.mjs accepts as WipePinGcc's, and that pinned something
      const rec = join(d, 'pf-record.json');
      rmSync(rec, { force: true });
      const objOn = join(d, 'on', 'u.o');
      mkdirSync(dirname(objOn), { recursive: true });
      const cOn = await compileObj(src, objOn, opt, wpinEnv(rec, req, false), true);
      const rr = readRec(rec, { dryRun: false, opt, module: 'pf.c', requested: req });
      p.plugin = cOn.kind !== 'gcc-lto' ? `object ${cOn.kind}` : !rr.ok ? `record refused (${rr.problems.join('; ')})`
        : rr.record.pinnedCount < 1 ? 'record pinned nothing' : 'record valid, pinned';
      if (p.plugin !== 'record valid, pinned') fail.push(`the plugin in an -flto compile: ${p.plugin}`);
      // 5. that object records the compile's -fplugin in .gnu.lto_.opts, and a stock
      //    link of it does not load the plugin: no WipePinGcc line, sentinel kept
      p.onObjectOptsNamePlugin = optsNamePlugin(readOrNull(objOn));
      if (cOn.kind === 'gcc-lto') {
        const sRec = join(d, 'on', 'sentinel.json');
        writeFileSync(sRec, SENTINEL, 'utf8');
        const l = await linkLto(objOn, 'pf-on-stock', opt, { env: wpinEnv(sRec, req, false) });
        const b = readOrNull(sRec);
        p.onObjectStockLink = {
          rc: l.rc, layout: l.layout, wipePinGccLines: wipePinGccLines(l.stderr),
          sentinel: linkPluginState({ exists: b !== null, text: b ? b.toString('utf8') : null }),
        };
        const x = p.onObjectStockLink;
        if (x.rc !== 0 || x.layout !== EXPECTED_LAYOUT || x.wipePinGccLines !== 0 || x.sentinel !== 'sentinel-kept') {
          fail.push(`a stock link of the plugin-on object: rc ${x.rc}, layout ${x.layout}, WipePinGcc lines ${x.wipePinGccLines}, sentinel ${x.sentinel}`);
        }
      }
      // 6. the sentinel reading of (ii) can say "kept": a stock link, and a link
      //    naming a plugin file that does not exist, leave it where it was
      if (c.kind === 'gcc-lto') {
        const sRec = join(d, 'sentinel.json');
        writeFileSync(sRec, SENTINEL, 'utf8');
        await linkLto(obj, 'pf-sentinel-stock', opt, { env: wpinEnv(sRec, req, false) });
        let b = readOrNull(sRec);
        p.sentinelStockLink = linkPluginState({ exists: b !== null, text: b ? b.toString('utf8') : null });
        writeFileSync(sRec, SENTINEL, 'utf8');
        const bad = await linkLto(obj, 'pf-sentinel-absent', opt, { env: wpinEnv(sRec, req, false), linkPlugin: join(d, 'absent-plugin.so') });
        b = readOrNull(sRec);
        p.sentinelAbsentPlugin = linkPluginState({ exists: b !== null, text: b ? b.toString('utf8') : null });
        p.absentPluginLink = `rc ${bad.rc}, stderr ${/cannot open shared object file/.test(bad.stderr) ? 'says it cannot open the plugin' : stderrLines(bad.stderr).length ? 'other' : 'empty'}`;
        if (p.sentinelStockLink !== 'sentinel-kept' || p.sentinelAbsentPlugin !== 'sentinel-kept') {
          fail.push(`the WPIN_OUT sentinel did not survive a link without WipePinGcc (stock ${p.sentinelStockLink}, absent plugin ${p.sentinelAbsentPlugin})`);
        }
      }
      // 7. the GIMPLE reader, when it runs at all: vgpre_wipe's memset writes through
      //    its parameter, so it reaches the object -- one plain zero-fill memset
      //    without the plugin, one pinned with it -- and both controls read as one
      //    plain memset. A reader that reads anything else would make "the wipe is
      //    gone before the link" a reading of nothing.
      if (haveDump) {
        const gOff = c.kind === 'gcc-lto' ? await readGimple(obj, ['vgpre_wipe']) : null;
        const gOn = cOn.kind === 'gcc-lto' ? await readGimple(objOn, ['vgpre_wipe']) : null;
        p.gimple = { off: gOff, on: gOn };
        const okOff = !!gOff && gOff.ok && gOff.plain === 1 && gOff.pinned === 0;
        const okOn = !!gOn && gOn.ok && gOn.plain === 0 && gOn.pinned === 1;
        if (!okOff || !okOn) {
          const say = (g) => (!g ? 'not read' : !g.ok ? g.problem : `plain ${g.plain}, pinned ${g.pinned}`);
          fail.push(`${ltoDumpName} did not read the preflight unit's GIMPLE as it is (plugin off: ${say(gOff)}, expected plain 1, pinned 0; `
            + `plugin on: ${say(gOn)}, expected plain 0, pinned 1)`);
        }
      }
      p.problems = fail;
      pre[opt] = p;
      if (fail.length) die(5, `preflight ${opt}: ${fail.join('; ')}`);
    }
  }

  // ---- sources -----------------------------------------------------------------
  const units = new Map();
  const allIds = [...new Set(Object.values(selection).flatMap((s) => s.ids))].sort();
  for (const id of allIds) {
    const sc = id.split('_')[2];
    const m = scen[sc];
    if (!m || m.fam !== 'erasure') die(5, `${id}: not an erasure scenario in scenarios.json`);
    const text = readFileSync(join(GEN, `${id}.c`), 'utf8');
    const ws = cell.wipeSpans(text, m.fn);
    if (!ws.spans.length) die(5, `${id}: the find step's wipeSpans finds no wipe although the tracked rows score one`);
    const requested = [...new Set([m.fn, ...ws.helpers])];
    for (const opt of args.opts) {
      const tr = trackedRow.get(`${id}|${opt}`);
      if (tr && JSON.stringify(tr.requested) !== JSON.stringify(requested)) {
        die(5, `${id} ${opt}: the tracked row requested [${tr.requested.join(' ')}], this tree's find step gives [${requested.join(' ')}]`);
      }
    }
    const pW = join(SRC, `${id}.w.c`);
    const pWo = join(SRC, `${id}.wo.c`);
    writeFileSync(pW, text + cell.CONTROL, 'utf8');
    writeFileSync(pWo, cell.ablateSpans(text, ws.spans) + cell.CONTROL, 'utf8');
    units.set(id, { id, fn: m.fn, pW, pWo, requested, nSpans: ws.spans.length });
  }
  const jobs = [];
  for (const opt of args.opts) for (const id of selection[opt].ids) jobs.push({ u: units.get(id), opt });
  process.stderr.write(`${allIds.length} file(s), opts ${args.opts.join(' ')}: ${jobs.length} cell(s), 6 compiles and 14 links each\n`);

  // ---- cells -------------------------------------------------------------------
  const rows = [];
  let done = 0;
  await cell.pool(jobs, async ({ u, opt }) => {
    const cdir = join(CELLS, u.id, opt);
    rmSync(cdir, { recursive: true, force: true });
    const sides = { w: u.pW, wo: u.pWo };
    const objs = {};
    const recs = {};
    const kinds = {};
    for (const k of OBJECTS) {
      const [side, cfg] = k.split('.');
      const d = join(cdir, k);
      mkdirSync(d, { recursive: true });
      objs[k] = join(d, 'u.o');
      if (cfg === 'off') {
        kinds[k] = (await compileObj(sides[side], objs[k], opt, BASE_ENV, false)).kind;
      } else {
        recs[k] = join(d, 'record.json');
        rmSync(recs[k], { force: true });
        kinds[k] = (await compileObj(sides[side], objs[k], opt, wpinEnv(recs[k], u.requested, cfg === 'dry'), true)).kind;
      }
    }
    const notLto = Object.entries(kinds).filter(([, v]) => v !== 'gcc-lto' && v !== 'missing').map(([k, v]) => `${k} object is ${v}`);
    const stock = {};
    const again = {};
    const noLink = (k) => ({ rc: null, stderr: null, layout: null, asm: null, soSha: null, problem: `no LTO object (${kinds[k]})`, layoutProblem: null });
    const doLink = async (k, tag, opts2) => {
      if (kinds[k] !== 'gcc-lto') return noLink(k);
      const l = await linkLto(objs[k], tag, opt, opts2);
      return l;
    };
    for (const k of OBJECTS) {
      stock[k] = await doLink(k, 'stock1');
      if (stock[k].layoutProblem) notLto.push(`${k} stock1: ${stock[k].layoutProblem}`);
    }
    // determinism: every object, linked a second time
    const deterministic = {};
    for (const k of OBJECTS) {
      again[k] = await doLink(k, 'stock2');
      if (again[k].layoutProblem) notLto.push(`${k} stock2: ${again[k].layoutProblem}`);
      deterministic[k] = {
        asm: stock[k].asm !== null && again[k].asm !== null ? stock[k].asm === again[k].asm : null,
        so: stock[k].soSha && again[k].soSha ? stock[k].soSha === again[k].soSha : null,
      };
    }
    // (ii) the plugin on the link line only, with a sentinel at WPIN_OUT
    const lp = {};
    const lpAsm = {};
    for (const side of SIDES) {
      const k = `${side}.off`;
      const rec = join(dirname(objs[k]), 'link-plugin-record.json');
      writeFileSync(rec, SENTINEL, 'utf8');
      const l = await doLink(k, 'linkplugin', { env: wpinEnv(rec, u.requested, false), linkPlugin: args.plugin });
      const buf = readOrNull(rec);
      const rr = refusalReading(l.stderr, stock[k].stderr);
      lpAsm[side] = l.asm;
      lp[side] = {
        rc: l.rc,
        state: linkPluginState({ exists: buf !== null, text: buf ? buf.toString('utf8') : null }),
        refusals: rr.count, restIsStock: rr.restIsStock, layout: l.layout,
        asmEqualsStock: l.asm !== null && stock[k].asm !== null ? l.asm === stock[k].asm : null,
        soEqualsStock: l.soSha && stock[k].soSha ? l.soSha === stock[k].soSha : null,
      };
    }

    const asm = Object.fromEntries(OBJECTS.map((k) => [k, stock[k].asm]));
    const baseline = cell.verdictOf(asm['w.off'], asm['wo.off'], u.fn);
    const repaired = cell.verdictOf(asm['w.on'], asm['wo.on'], u.fn);
    const dry = cell.verdictOf(asm['w.dry'], asm['wo.dry'], u.fn);
    const lpVerdict = cell.verdictOf(lpAsm.w, lpAsm.wo, u.fn);
    const rW = readRec(recs['w.on'], { dryRun: false, opt, module: basename(u.pW), requested: u.requested });
    const rWo = readRec(recs['wo.on'], { dryRun: false, opt, module: basename(u.pWo), requested: u.requested });
    const rDryW = readRec(recs['w.dry'], { dryRun: true, opt, module: basename(u.pW), requested: u.requested });
    const rDryWo = readRec(recs['wo.dry'], { dryRun: true, opt, module: basename(u.pWo), requested: u.requested });
    const controlOnW = asm['w.on'] ? cell.controlPresent(asm['w.on']).ok : false;
    const controlOnWo = asm['wo.on'] ? cell.controlPresent(asm['wo.on']).ok : false;
    const oc = gccLtoOutcome({ notLto, baseline, repaired, recordW: rW, recordWo: rWo, controlOnOk: controlOnW && controlOnWo });

    // where the loss happens: the compile-stage GIMPLE of w/off, wo/off and w/on,
    // read after every link of the cell
    let gimple = null;
    if (haveDump && ['w.off', 'wo.off', 'w.on'].every((k) => kinds[k] === 'gcc-lto')) {
      gimple = {};
      for (const [key, k] of [['wOff', 'w.off'], ['woOff', 'wo.off'], ['wOn', 'w.on']]) {
        const g = await readGimple(objs[k], u.requested);
        gimple[key] = g.ok ? { plain: g.plain, pinned: g.pinned, helperCalls: g.helperCalls, defined: g.defined } : null;
        if (!g.ok) gimple[`${key}Problem`] = g.problem;
      }
    }

    const stockLinks = [...Object.values(stock), ...Object.values(again)].filter((l) => l.rc !== null);
    const tr = trackedRow.get(`${u.id}|${opt}`) ?? null;
    const body = (a) => (a ? cell.bodyOf(a, u.fn) : null);
    rows.push({
      id: u.id, fn: u.fn, mode: '-flto', opt, requested: u.requested, n_spans: u.nSpans, idiom: tr ? tr.idiom : null,
      objects: kinds,
      tracked: tr ? tr.baseline : null, trackedOutcome: tr ? tr.outcome : null,
      baseline: baseline.verdict, baselineControl: baseline.control ?? null,
      repaired: repaired.verdict, repairedControl: repaired.control ?? null,
      dry: dry.verdict,
      outcome: oc.outcome, outcomeReason: oc.reason,
      recW: recSummary(rW), recWo: recSummary(rWo), recDryW: recSummary(rDryW), recDryWo: recSummary(rDryWo),
      controlOnW, controlOnWo,
      linkProblems: Object.fromEntries([...OBJECTS.map((k) => [`${k} stock1`, stock[k].problem]), ...OBJECTS.map((k) => [`${k} stock2`, again[k].problem])]
        .filter(([, p]) => p)),
      linkPlugin: { verdict: lpVerdict.verdict, w: lp.w, wo: lp.wo },
      deterministic,
      dryAsmEqualsOff: { w: asm['w.dry'] !== null && asm['w.off'] !== null ? asm['w.dry'] === asm['w.off'] : null,
        wo: asm['wo.dry'] !== null && asm['wo.off'] !== null ? asm['wo.dry'] === asm['wo.off'] : null },
      drySoEqualsOff: { w: stock['w.dry'].soSha && stock['w.off'].soSha ? stock['w.dry'].soSha === stock['w.off'].soSha : null,
        wo: stock['wo.dry'].soSha && stock['wo.off'].soSha ? stock['wo.dry'].soSha === stock['wo.off'].soSha : null },
      stockStderr: {
        links: stockLinks.length,
        withWipePinGccLine: stockLinks.filter((l) => wipePinGccLines(l.stderr) > 0).length,
        nonEmpty: stockLinks.filter((l) => stderrLines(l.stderr).length > 0).length,
      },
      labelsOnly: {
        baseline: differsOnlyInLabels(body(asm['w.off']), body(asm['wo.off'])),
        repaired: differsOnlyInLabels(body(asm['w.on']), body(asm['wo.on'])),
      },
      gimple,
      listings: Object.fromEntries(OBJECTS.map((k) => [k, sha256Text(asm[k])])),
      sharedObjects: Object.fromEntries(OBJECTS.map((k) => [k, stock[k].soSha])),
    });
    if (++done % 25 === 0) process.stderr.write(`  ${done} cells\n`);
  }, args.conc);

  rows.sort((a, b) => cmp(ALL_OPTS.indexOf(a.opt), ALL_OPTS.indexOf(b.opt)) || cmp(a.id, b.id));

  // ---- results -------------------------------------------------------------------
  const groups = args.opts.map((opt) => ({ opt, s: summarizeGccGroup(rows.filter((r) => r.opt === opt)) }));
  const rowsText = '[\n' + rows.map((r) => JSON.stringify(r)).join(',\n') + '\n]\n';
  const manifestText = JSON.stringify({
    generatedAt: new Date().toISOString(), node: process.version, cc: ccName, ccVersion, linker: ldVersion,
    plugin: { basename: basename(args.plugin), sha256: pluginSha }, component: GCC_COMPONENT,
    opts: args.opts, allRemovable: args.allRemovable, files: args.files, sample: args.sample,
    selection: Object.fromEntries(Object.entries(selection).map(([o, s]) => [o, { total: s.total, measured: s.ids.length }])),
    rowsFile: args.rows === DEFAULT_ROWS ? '(default)' : '(given with --rows)', rowsSha256: sha256File(args.rows),
    conc: args.conc, preflight: pre, compileFlags: COMPILE_FLAGS, linkArgs: gccLinkArgs({ opt: '-O2' }),
    gimpleReader: { tool: ltoDumpName, read: haveDump },
    ignoredInheritedEnv: inherited,
  }, null, 2) + '\n';
  const broken = brokenReasons(groups);
  let text = render({ args, ccName, ccVersion, ldVersion, pluginSha, pre, groups, selection, rows, broken, haveDump, ltoDumpName });
  const hits = [];
  for (const [name, t] of [['lto-gcc-rows.json', rowsText], ['lto-gcc-results.txt', text], ['manifest.json', manifestText]]) {
    const h = absolutePathHits(t);
    if (h.length) hits.push(`${name}: ${h.join(', ')}`);
  }
  text += `absolute-path hits in the lab texts (rows, results, manifest): ${hits.length}\n`;
  writeFileSync(join(OUT, 'lto-gcc-rows.json'), rowsText, 'utf8');
  writeFileSync(join(OUT, 'lto-gcc-results.txt'), text, 'utf8');
  writeFileSync(join(OUT, 'manifest.json'), manifestText, 'utf8');
  process.stdout.write(text);
  if (hits.length) die(5, `an absolute path was written into the lab texts (${hits.join('; ')})`);
  process.exit(broken.length ? 2 : 0);
}

// ---------------------------------------------------------------- rendering --
function pad(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }

function render({ args, ccName, ccVersion, ldVersion, pluginSha, pre, groups, selection, rows, broken, haveDump, ltoDumpName }) {
  const L = [];
  L.push('lto-probe-gcc results (tools/lto-probe-gcc.mjs)');
  L.push('');
  L.push(`compiler        ${ccName}  (${ccVersion})`);
  L.push(`linker          ${ldVersion}, through the driver and gcc's LTO linker plugin`);
  L.push(`plugin sha256   ${pluginSha}  (${GCC_COMPONENT}; records read through lib/pin-record.mjs, component ${GCC_COMPONENT})`);
  L.push(`selection       ${args.allRemovable ? 'every removable-idiom erasure file' : 'the erasure files tracked WIPE_ELIMINATED'} at each level, `
    + `from the tracked ${ccName} repair rows${args.files ? ` (--files ${args.files.join(',')})` : ''}${args.sample ? ` (--sample ${args.sample})` : ''}`);
  L.push(`                ${args.opts.map((o) => `${o} ${selection[o].ids.length} of ${selection[o].total}`).join(', ')}`);
  L.push('link            each object alone: -flto -shared -save-temps, post-LTO code read from <o>.ltrans0.ltrans.s');
  L.push(`GIMPLE reader   ${haveDump ? `${ltoDumpName} -dump-body, on w/off, wo/off and w/on of every cell (compile-stage GIMPLE, the code lto1 starts from)` : `not read (${ltoDumpName} could not be started)`}`);
  L.push('');
  L.push('preflight (per level: an -flto object with .gnu.lto_ sections; its stock link writes the one-partition layout and its assembly is cut by bodyOf');
  L.push('           with the positive control PRESENT; the plugin on the link line is refused by lto1 twice; the plugin in an -flto compile writes a record');
  L.push('           pin-record.mjs accepts; a stock link of that object does not load the plugin; the WPIN_OUT sentinel survives links without WipePinGcc;');
  L.push('           the GIMPLE reader reads the unit\'s memset as plain without the plugin and pinned with it)');
  for (const [k, p] of Object.entries(pre)) {
    L.push(`  ${pad(k, 4)} object ${p.objectKind}; stock link ${p.stockLayout}, assembly ${p.asm}; plugin ${p.plugin}`);
    const lp = p.linkPlugin || {};
    L.push(`       plugin on the link line: rc ${lp.rc}, refusals ${lp.refusals}, rest of stderr as stock ${lp.restIsStock}, layout ${lp.layout}, `
      + `sentinel ${lp.sentinel}, assembly equal ${lp.asmEqualsStock}, shared object equal ${lp.soEqualsStock}`);
    const on = p.onObjectStockLink || {};
    L.push(`       plugin-on object: .gnu.lto_.opts names -fplugin ${p.onObjectOptsNamePlugin}; its stock link: rc ${on.rc}, layout ${on.layout}, `
      + `WipePinGcc lines ${on.wipePinGccLines}, sentinel ${on.sentinel}`);
    L.push(`       WPIN_OUT sentinel after a stock link: ${p.sentinelStockLink}; after a link naming an absent plugin: ${p.sentinelAbsentPlugin} (${p.absentPluginLink})`);
    if (p.gimple) {
      const say = (g) => (!g ? 'not read' : !g.ok ? g.problem : `plain ${g.plain}, pinned ${g.pinned}`);
      L.push(`       GIMPLE of vgpre_wipe: plugin off ${say(p.gimple.off)}; plugin on ${say(p.gimple.on)}`);
    }
  }
  L.push('');
  for (const { opt, s } of groups) {
    const here = rows.filter((r) => r.opt === opt);
    L.push(`== ${opt}  (${s.cells} cells)`);
    L.push(`  baseline (plugin off, stock link)   eliminated ${s.baselineEliminated}, survived ${s.baselineSurvived}, other ${s.baselineOther}`);
    L.push(`  differs from the tracked non-LTO ${ccName} row: ${s.trackedDiff.length}`);
    for (const d of s.trackedDiff) L.push(`    DIFF ${d.id}: tracked (no LTO) ${d.tracked}, LTO ${d.lto}; outcome ${d.outcome}`);
    if (args.allRemovable) {
      L.push(`  eliminations the LTO link adds (tracked survived, LTO eliminated): ${s.addedEliminations.length}`);
      for (const a of s.addedEliminations) L.push(`    ADDED ${a.id}: ${a.outcome}`);
    }
    L.push('  (i) plugin at compile time, stock link');
    for (const o of LTO_OUTCOMES) if (s.outcomes[o]) L.push(`    ${pad(o, 22)} ${s.outcomes[o]}`);
    for (const r of here.filter((x) => x.outcome === 'NOT_LTO')) L.push(`    NOT_LTO ${r.id}: ${r.outcomeReason}`);
    for (const r of here.filter((x) => x.baseline === ELIMINATED && x.outcome !== 'RETAINED')) L.push(`    NOT RETAINED ${r.id}: ${r.outcome} -- ${r.outcomeReason}`);
    L.push(`  (iii) dry run at compile time: red control ${s.dry.held ? 'HELD' : 'FAILED'} -- still eliminated ${s.dry.stillEliminated}/${s.dry.considered}`);
    for (const v of s.dry.violations.slice(0, 20)) L.push(`    VIOLATION ${v}`);
    if (s.dry.violations.length > 20) L.push(`    ... ${s.dry.violations.length - 20} more`);
    L.push(`    post-LTO assembly identical to plugin-off ${s.dryAsmEqualsOff.equal}/${s.dryAsmEqualsOff.of}; shared object identical ${s.drySoEqualsOff.equal}/${s.drySoEqualsOff.of}`);
    const lp = s.linkPlugin;
    const hist = Object.entries(lp.refusalHistogram).sort((a, b) => Number(a[0]) - Number(b[0])).map(([k, v]) => `${k}: ${v}`).join(', ');
    L.push(`  (ii) plugin on the link line only (${lp.links} links): refusals per link {${hist}} (expected ${EXPECTED_REFUSALS}); sentinel at WPIN_OUT removed ${lp.removed}, `
      + `record written ${lp.recordWritten}, sentinel kept ${lp.sentinelKept}`);
    L.push(`    rest of stderr as the stock link's ${lp.restIsStock}/${lp.links}; layout ${EXPECTED_LAYOUT} ${lp.layoutExpected}/${lp.links}; `
      + `assembly byte-identical to the stock link ${lp.asmEqualsStock}/${lp.links}; shared object ${lp.soEqualsStock}/${lp.links}; verdict equals the baseline ${lp.verdictEqualsBaseline}/${lp.cells}`);
    L.push(`    graded: ${lp.grade.held ? 'HELD' : 'FAILED'} (${lp.grade.links} links)`);
    for (const v of lp.grade.violations.slice(0, 20)) L.push(`    VIOLATION ${v}`);
    if (lp.grade.violations.length > 20) L.push(`    ... ${lp.grade.violations.length - 20} more`);
    L.push(`  determinism: every object linked twice, byte-identical assembly and shared object ${s.determinism.identical}/${s.determinism.pairs}`);
    L.push(`  stock links ${s.stockLinks.links}: with a WipePinGcc line ${s.stockLinks.withWipePinGccLine} (must be 0); with any stderr ${s.stockLinks.nonEmpty}`);
    L.push(`  target bodies that differ only in .L<n> label names: baseline ${s.labelsOnly.baseline}, repaired ${s.labelsOnly.repaired} (reported; verdicts unchanged)`);
    if (haveDump) {
      const st = s.stage;
      L.push(`  compile-stage GIMPLE, requested functions, baseline-eliminated cells (${st.eliminated}): w/off still carries the wipe to the link `
        + `(more zero-fill memsets or named-helper calls than wo/off) ${st.wOffCarries}; w/off holds no zero-fill memset ${st.wOffHoldsNone}; `
        + `w/on holds a pinned one ${st.wOnPinned}; unread ${st.unread}`);
      if (st.survived) L.push(`    baseline-survived cells (${st.survived}): w/off still carries the wipe to the link ${st.survivedWOffCarries}; unread ${st.survivedUnread}`);
      for (const r of here.filter((x) => x.gimple && (!x.gimple.wOff || !x.gimple.woOff || !x.gimple.wOn))) {
        L.push(`    UNREAD ${r.id}: ${['wOff', 'woOff', 'wOn'].filter((k) => r.gimple[`${k}Problem`]).map((k) => `${k} ${r.gimple[`${k}Problem`]}`).join('; ')}`);
      }
    } else {
      L.push(`  compile-stage GIMPLE: not read (${ltoDumpName} could not be started)`);
    }
    L.push('');
  }
  L.push(`integrity: ${broken.length ? `BROKEN (exit 2) -- ${broken.join('; ')}` : 'every check held'}`);
  return L.join('\n') + '\n';
}

main().catch((e) => die(5, `unexpected failure: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`));

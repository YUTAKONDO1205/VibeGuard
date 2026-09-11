#!/usr/bin/env node
/**
 * fbu-levels -- does every followedByUse site read, at -O1 and above, what it
 * reads at -O0?
 *
 * compiler/llvm-repair/README.md ("What `followedByUse` can and cannot say")
 * shows that wipe-pin-v1 read four error-path sites `true` at -O1..-Os and
 * `false` at -O0, through clang's cleanup dispatch, and that with wipe-pin-v2
 * the number of `true` sites is the same at every level. The same number is not
 * the same sites. This tool asks site by site. For every erasure-family file the
 * repair loop measures (lib/corpus.mjs, the selection run-repair-loop.mjs uses)
 * and every level, one compile with the find step's FLAGS (imported from
 * ../../ai-generated/lib/ablation-cell.mjs, never copied), the level, a line
 * flag, and the plugin loaded in module scope as a dry run:
 *
 *   <cc> FLAGS <opt> <line flag> <plugin flag><so> -o /dev/null <corpus>/<id>.c
 *   with WPIN_OUT=<out>/records/<id>/<cc><opt>.json WPIN_SCOPE=module WPIN_DRY_RUN=1
 *
 * The vendor comes from --cc through lib/vendor.mjs: clang loads WipePin with
 * -fpass-plugin=, gcc loads WipePinGcc with -fplugin=. Module scope, so every
 * zero-fill site of every function is listed; a dry run, so nothing is changed
 * and the record is written exactly as if pinning. Every record is read through
 * the strict reader (lib/pin-record.mjs; --reader only for an older schema, see
 * below). Sites are joined across levels on (file, function, index) with the
 * line as a second key, and every site that does not join is counted, never
 * dropped (tools/lib/fbu.mjs). Two controls run in every invocation:
 *
 *   -O0 again   every file compiled at -O0 a second time into a record of its
 *               own and compared with the first exactly as a level is: it must
 *               show 0 differences and 0 unmatched sites, and the same
 *               evidenceDigest
 *   line flag   the files (--line-sample, default all) compiled at every level
 *               WITHOUT the line flag: each record must equal the one with the
 *               flag on every field but pinned[].line (context and
 *               evidenceDigest aside)
 *
 * --reader: records are read by lib/pin-record.mjs, which accepts wipe-pin-v2
 * only. A plugin built from an older commit writes an older schema; to measure
 * it (the wipe-pin-v1 control), pass the lib/pin-record.mjs of that commit,
 * extracted with the files it imports. Every record is still read strictly, by
 * the reader of the schema that wrote it, and the results name that reader's
 * schemaVersion and sha256.
 *
 * Lab output only, under --out, which must lie outside the repository: the
 * records, fbu-rows.json (one row per site: its line, followedByUse and
 * destKind at every level), fbu-compiles.json (every compile: rc, whether the
 * record was accepted, the reader's problems, the plugin's own stderr lines),
 * fbu-results.txt and manifest.json. There is no --write-data.
 *
 *   node fbu-levels.mjs --plugin <so> --out <lab dir> [options]
 *
 * Exit codes: 0 run complete: every compile succeeded, every record was
 * accepted, every site was accounted for, and both controls held -- whatever
 * the levels show (a site that reads differently from -O0 is the finding, and
 * is listed, not an error); 2 run complete but a compile failed, a record was
 * missing or refused, a site was not accounted for, or a control did not hold;
 * 3 nothing selected; 4 bad arguments; 5 a tool, the plugin or the reader could
 * not be used (including a preflight record the reader refuses), or a text
 * about to be written carried an absolute path.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { devNull } from 'node:os';
import { dirname, resolve, join, basename, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { vendorOf, vendorConfig } from '../lib/vendor.mjs';
import { corpusFiles, erasureFamily } from '../lib/corpus.mjs';
import { absolutePathHits, rowsFileLabel } from '../lib/provenance.mjs';
import { evenSample, insideRepo } from './lib/lto.mjs';
import {
  REFERENCE_OPT, LINE_FLAG, CHANGES, sitesOf, siteName, compareLevel, accounted, changeCount, identical, tally,
  lineControl, siteRows,
} from './lib/fbu.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const REPO = resolve(LANE, '..', '..', '..');
const AIGEN = resolve(LANE, '..', 'ai-generated');
const GEN = join(AIGEN, 'generated-corpus', 'r2');
const SCEN_PATH = join(AIGEN, 'scenarios.json');
const CELL_PATH = join(AIGEN, 'lib', 'ablation-cell.mjs');
const DEFAULT_READER = join(LANE, 'lib', 'pin-record.mjs');
const ALL_OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];

const USAGE = `usage: node fbu-levels.mjs --plugin <so> --out <dir> [options]

  --plugin <so>        the repair plugin (required; there is no default): libWipePin.so for clang,
                       libWipePinGcc.so for gcc
  --out <dir>          lab directory, outside the repository (required)
  --cc <compiler>      default clang-18. The vendor is read from the basename (lib/vendor.mjs)
  --opts <list>        comma list from ${ALL_OPTS.join(' ')} (default all five; ${REFERENCE_OPT}, the reference, is required)
  --line-flag <flag>   the flag that gives every site a line: default ${LINE_FLAG.clang} for clang,
                       ${LINE_FLAG.gcc} for gcc (gcc-13 refuses ${LINE_FLAG.clang}); none compiles without one
                       and skips the line-flag control
  --line-sample <n>    files, spread evenly over the selection, that the line-flag control compiles
                       again at every level without the flag (default: all of them)
  --files <list>       comma list of basenames or globs (* ?), with or without .c, within the selection
  --conc <n>           parallel compiles (default 2)
  --reader <mjs>       the record reader (default: lib/pin-record.mjs). Only for a plugin of an older
                       schema: the lib/pin-record.mjs of the commit that built it

The selection is lib/corpus.mjs's erasure family, the files run-repair-loop.mjs measures.
Everything is written under --out; there is no --write-data.
`;

function die(code, msg) {
  process.stderr.write(`fbu-levels: ${msg}\n`);
  process.exit(code);
}

function globToRe(g) {
  const s = g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + s + '$');
}

function parseArgs(argv) {
  const a = { plugin: null, out: null, cc: 'clang-18', opts: [...ALL_OPTS], lineFlag: undefined, lineSample: null,
    files: null, conc: 2, reader: DEFAULT_READER };
  const need = (i, flag) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${flag} needs a value`); return argv[i + 1]; };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--plugin': a.plugin = need(i, f); i++; break;
      case '--out': a.out = need(i, f); i++; break;
      case '--cc': a.cc = need(i, f); i++; break;
      case '--opts': a.opts = list(need(i, f)); i++; break;
      case '--line-flag': a.lineFlag = need(i, f); i++; break;
      case '--line-sample': a.lineSample = Number(need(i, f)); i++; break;
      case '--files': a.files = list(need(i, f)); i++; break;
      case '--conc': a.conc = Number(need(i, f)); i++; break;
      case '--reader': a.reader = need(i, f); i++; break;
      case '--write-data': die(4, '--write-data does not exist here: this tool writes its lab directory and nothing else'); break;
      case '-h': case '--help': process.stdout.write(USAGE); process.exit(0); break;
      default: die(4, `unknown argument ${f}\n${USAGE}`);
    }
  }
  if (!a.plugin) die(4, '--plugin is required. There is no default: the plugin under test must be named by whoever runs the tool.');
  if (!a.out) die(4, '--out is required: everything this tool writes goes to a lab directory outside the repository');
  a.vendor = vendorOf(a.cc);
  if (a.vendor === null) {
    die(4, `--cc ${basename(a.cc)}: the basename names neither clang nor gcc, so neither the plugin flag nor the `
      + 'record component can be chosen. Name the compiler as clang[-N] or gcc[-N] / g++[-N].');
  }
  for (const o of a.opts) if (!ALL_OPTS.includes(o)) die(4, `--opts: ${o} is not one of ${ALL_OPTS.join(' ')}`);
  if (!a.opts.includes(REFERENCE_OPT)) die(4, `--opts must include ${REFERENCE_OPT}: every other level is compared with it`);
  a.opts = ALL_OPTS.filter((o) => a.opts.includes(o));
  if (a.lineFlag === undefined) a.lineFlag = LINE_FLAG[a.vendor];
  else if (a.lineFlag === 'none') a.lineFlag = null;
  else if (!/^-g[A-Za-z0-9=_-]*$/.test(a.lineFlag)) die(4, `--line-flag ${a.lineFlag}: expected a -g option or none`);
  if (a.lineSample !== null && (!Number.isInteger(a.lineSample) || a.lineSample < 1)) die(4, '--line-sample must be a positive integer');
  if (!Number.isInteger(a.conc) || a.conc < 1) die(4, '--conc must be a positive integer');
  a.plugin = resolve(a.plugin);
  a.out = resolve(a.out);
  a.reader = resolve(a.reader);
  if (insideRepo(a.out, REPO, sep)) die(4, '--out lies inside the repository; this tool writes lab output only');
  return a;
}

const sha256File = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');

/** process.env with every WPIN_* removed: nothing inherited may steer a compile. */
function cleanEnv() {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith('WPIN_')) env[k] = v;
  return env;
}

/** Run a tool; never throws. */
async function tool(cmd, args, env, timeout = 90000) {
  try {
    const { stdout, stderr } = await run(cmd, args, { env, timeout, maxBuffer: 16 * 1024 * 1024 });
    return { rc: 0, stdout, stderr };
  } catch (e) {
    return { rc: typeof e.code === 'number' ? e.code : -1, stdout: String(e.stdout || ''), stderr: String(e.stderr || e.message || '') };
  }
}

// ---------------------------------------------------------------- main -------
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const inherited = Object.keys(process.env).filter((k) => k.startsWith('WPIN_'));
  for (const k of inherited) delete process.env[k];
  if (inherited.length) process.stderr.write(`note: ignoring inherited ${inherited.join(' ')}\n`);
  const BASE_ENV = cleanEnv();

  if (!existsSync(args.plugin) || !statSync(args.plugin).isFile()) die(5, 'the --plugin path does not name a file');
  if (!existsSync(CELL_PATH)) die(5, 'ai-generated/lib/ablation-cell.mjs is missing; the compiles use the find step\'s FLAGS from it and have no copy');
  const cell = await import(pathToFileURL(CELL_PATH).href);
  for (const name of ['FLAGS', 'pool']) if (!(name in cell)) die(5, `ablation-cell.mjs does not export ${name}`);
  if (!existsSync(args.reader) || !statSync(args.reader).isFile()) die(5, 'the --reader path does not name a file');
  let reader;
  try { reader = await import(pathToFileURL(args.reader).href); } catch (e) { die(5, `the reader could not be imported (${e && e.code ? e.code : 'error'})`); }
  if (typeof reader.readPinRecord !== 'function' || typeof reader.SCHEMA_VERSION !== 'string') {
    die(5, 'the reader does not export readPinRecord and SCHEMA_VERSION');
  }
  // Named without a path: the tree's own reader, a path inside the repository,
  // or "(outside the repository)" for one extracted from another commit.
  const readerWhere = rowsFileLabel(args.reader, { defaultPath: DEFAULT_READER, repoRoot: REPO });
  const readerInfo = {
    label: readerWhere === '(default)' ? 'compiler/eval/repair-loop/lib/pin-record.mjs (this tree)' : `${readerWhere} (--reader)`,
    schemaVersion: reader.SCHEMA_VERSION,
    sha256: sha256File(args.reader),
  };

  const ccv = await tool(args.cc, ['--version'], BASE_ENV, 30000);
  if (ccv.rc !== 0) die(5, `${args.cc} --version failed: the compiler is not runnable here`);
  const ccVersion = ccv.stdout.split('\n')[0].trim();
  const ccName = basename(args.cc);
  const vc = vendorConfig(args.vendor, args.plugin);
  const component = vc.component;
  const pluginSha = sha256File(args.plugin);
  const lineArgs = args.lineFlag ? [args.lineFlag] : [];

  // ---- selection: the repair loop's erasure family ---------------------------
  const scen = JSON.parse(readFileSync(SCEN_PATH, 'utf8'));
  const family = erasureFamily(corpusFiles(readdirSync(GEN)), scen);
  const res = args.files ? args.files.map(globToRe) : null;
  const selected = family.filter(({ f }) => !res || res.some((re) => re.test(f) || re.test(f.replace(/\.c$/, ''))));
  if (!selected.length) die(3, 'no erasure-family file was selected; nothing was measured');
  const lineIds = new Set(args.lineFlag ? evenSample(selected.map((x) => x.meta.id), args.lineSample ?? undefined) : []);

  const OUT = args.out;
  const REC = join(OUT, 'records');
  const PRE = join(OUT, 'preflight');
  for (const d of [REC, PRE]) mkdirSync(d, { recursive: true });

  const wpinEnv = (recordPath) => ({ ...BASE_ENV, WPIN_OUT: recordPath, WPIN_SCOPE: 'module', WPIN_DRY_RUN: '1' });

  /** One compile, its record read through the reader. `ok` needs rc 0 and an accepted record. */
  async function compileOne(src, opt, withLine, recordPath) {
    rmSync(recordPath, { force: true });
    const argv = [...cell.FLAGS, opt, ...(withLine ? lineArgs : []), vc.pluginArg, '-o', devNull, src];
    const r = await tool(args.cc, argv, wpinEnv(recordPath));
    const rr = reader.readPinRecord(recordPath, { component, scope: 'module', dryRun: true, opt, module: basename(src) });
    const lines = r.stderr.split('\n').filter((l) => l.trim() !== '');
    const problems = [...(r.rc !== 0 ? [`compile rc ${r.rc}`] : []), ...rr.problems];
    return {
      rc: r.rc, ok: r.rc === 0 && rr.ok, problems, record: rr.ok ? rr.record : null,
      pluginLines: lines.filter((l) => l.startsWith(`${component}:`)),
      otherStderrLines: lines.filter((l) => !l.startsWith(`${component}:`)).length,
    };
  }

  // ---- preflight: the compiler takes the line flag, the plugin loads, the reader accepts its record ----
  const pre = {};
  {
    const src = join(PRE, 'pf.c');
    writeFileSync(src, 'void vgpre_use(unsigned char *p);\nvoid vgpre_wipe(void) {\n  unsigned char k[32];\n  vgpre_use(k);\n'
      + '  __builtin_memset(k, 0, sizeof k);\n}\n', 'utf8');
    const c = await compileOne(src, REFERENCE_OPT, true, join(PRE, 'pf.json'));
    const site = c.record && c.record.pinned.length === 1 ? c.record.pinned[0] : null;
    pre.rc = c.rc;
    pre.accepted = c.ok;
    pre.problems = c.problems;
    pre.site = site ? { followedByUse: site.followedByUse, line: site.line, destKind: site.destKind } : null;
    if (c.rc !== 0) die(5, `preflight: the compile failed (rc ${c.rc}) with ${args.lineFlag ?? 'no line flag'} and the plugin loaded; first plugin lines: ${c.pluginLines.slice(0, 3).join(' | ') || '(none)'}`);
    if (!c.ok) {
      die(5, `preflight: the reader (${readerInfo.schemaVersion}) refused the plugin's record: ${c.problems.slice(0, 3).join('; ')}`
        + '. A plugin of another schema needs the reader of its own commit (--reader).');
    }
    if (!site || site.followedByUse !== false || site.destKind !== 'alloca' || (args.lineFlag && site.line !== 5)) {
      die(5, `preflight: the record of a trailing memset on a local buffer did not read one site, alloca, followedByUse false${args.lineFlag ? ', line 5' : ''} (${JSON.stringify(pre.site)})`);
    }
  }

  // ---- compiles ------------------------------------------------------------------
  const jobs = [];
  for (const { f, meta } of selected) {
    for (const opt of args.opts) jobs.push({ f, id: meta.id, opt, variant: 'main' });
    jobs.push({ f, id: meta.id, opt: REFERENCE_OPT, variant: 'again' });
    if (lineIds.has(meta.id)) for (const opt of args.opts) jobs.push({ f, id: meta.id, opt, variant: 'noline' });
  }
  process.stderr.write(`${selected.length} of ${family.length} erasure-family file(s), opts ${args.opts.join(' ')}, `
    + `line flag ${args.lineFlag ?? '(none)'}, line-flag control on ${lineIds.size} file(s): ${jobs.length} compile(s)\n`);

  const results = [];
  let done = 0;
  await cell.pool(jobs, async (j) => {
    const dir = join(REC, j.id);
    mkdirSync(dir, { recursive: true });
    const suffix = j.variant === 'main' ? '' : `.${j.variant}`;
    const c = await compileOne(join(GEN, j.f), j.opt, j.variant !== 'noline', join(dir, `${ccName}${j.opt}${suffix}.json`));
    results.push({ ...j, ...c, sites: c.ok ? sitesOf(j.id, c.record) : [] });
    if (++done % 500 === 0) process.stderr.write(`  ${done} compiles\n`);
  }, args.conc);

  const byOpt = new Map(args.opts.map((o) => [o, new Map()]));
  const again = new Map();
  const noline = new Map(args.opts.map((o) => [o, new Map()]));
  for (const r of results) {
    const entry = { ok: r.ok, sites: r.sites, record: r.record };
    if (r.variant === 'main') byOpt.get(r.opt).set(r.id, entry);
    else if (r.variant === 'again') again.set(r.id, entry);
    else noline.get(r.opt).set(r.id, entry);
  }

  // ---- comparisons ------------------------------------------------------------
  const ref = byOpt.get(REFERENCE_OPT);
  const tallies = Object.fromEntries(args.opts.map((o) => [o, tally(byOpt.get(o))]));
  const againTally = tally(again);
  const levels = args.opts.filter((o) => o !== REFERENCE_OPT).map((o) => ({ opt: o, cmp: compareLevel(ref, byOpt.get(o)) }));
  const repeat = compareLevel(ref, again);
  const repeatDigests = [...again.keys()].filter((id) => {
    const a = ref.get(id); const b = again.get(id);
    return a && a.ok && b && b.ok && a.record.evidenceDigest === b.record.evidenceDigest;
  }).length;
  const repeatHeld = identical(repeat) && repeatDigests === again.size;
  const lineCtl = args.lineFlag ? args.opts.map((o) => ({ opt: o, c: lineControl(byOpt.get(o), noline.get(o)) })) : [];
  const lineHeld = lineCtl.every(({ c }) => c.unequal.length === 0 && c.notCompared.length === 0 && c.equal === c.pairs);
  const allAccounted = [...levels.map((l) => l.cmp), repeat].every(accounted);
  const failed = results.filter((r) => !r.ok);

  // ---- output -------------------------------------------------------------------
  const text = render({
    args, ccName, ccVersion, component, pluginSha, readerInfo, lineArgs, flags: cell.FLAGS, family, selected, lineIds,
    results, failed, tallies, againTally, levels, repeat, repeatDigests, repeatHeld, lineCtl, lineHeld, allAccounted,
  });
  const rows = siteRows(args.opts, byOpt);
  const rowsText = '[\n' + rows.map((r) => JSON.stringify(r)).join(',\n') + '\n]\n';
  const cmpd = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const compilesText = '[\n' + results
    .map(({ id, opt, variant, rc, ok, problems, pluginLines, otherStderrLines }) => ({ id, opt, variant, rc, ok, problems, pluginLines, otherStderrLines }))
    .sort((a, b) => cmpd(a.id, b.id) || cmpd(ALL_OPTS.indexOf(a.opt), ALL_OPTS.indexOf(b.opt)) || cmpd(a.variant, b.variant))
    .map((r) => JSON.stringify(r)).join(',\n') + '\n]\n';
  const manifestText = JSON.stringify({
    generatedAt: new Date().toISOString(), node: process.version, cc: ccName, ccVersion, vendor: args.vendor, component,
    pluginFlag: vc.pluginArg.split('=')[0] + '=', plugin: { basename: basename(args.plugin), sha256: pluginSha }, reader: readerInfo,
    flags: cell.FLAGS, lineFlag: args.lineFlag, env: { WPIN_SCOPE: 'module', WPIN_DRY_RUN: '1' }, opts: args.opts,
    files: args.files, familyFiles: family.length, selectedFiles: selected.length, lineSample: args.lineSample, lineControlFiles: lineIds.size,
    compiles: results.length, conc: args.conc, preflight: pre, ignoredInheritedEnv: inherited,
  }, null, 2) + '\n';
  const hits = [];
  for (const [name, t] of [['fbu-results.txt', text], ['fbu-rows.json', rowsText], ['fbu-compiles.json', compilesText], ['manifest.json', manifestText]]) {
    const h = absolutePathHits(t);
    if (h.length) hits.push(`${name}: ${h.join(', ')}`);
  }
  writeFileSync(join(OUT, 'fbu-results.txt'), text, 'utf8');
  writeFileSync(join(OUT, 'fbu-rows.json'), rowsText, 'utf8');
  writeFileSync(join(OUT, 'fbu-compiles.json'), compilesText, 'utf8');
  writeFileSync(join(OUT, 'manifest.json'), manifestText, 'utf8');
  process.stdout.write(text);
  if (hits.length) die(5, `an absolute path was written into the lab texts (${hits.join('; ')})`);
  process.exit(failed.length || !allAccounted || !repeatHeld || !lineHeld ? 2 : 0);
}

// ---------------------------------------------------------------- rendering --
function pad(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }
function lpad(s, n) { s = String(s); return s.length >= n ? s : ' '.repeat(n - s.length) + s; }

function render(x) {
  const { args, ccName, ccVersion, component, pluginSha, readerInfo, lineArgs, flags, family, selected, lineIds } = x;
  const L = [];
  L.push('fbu-levels results (tools/fbu-levels.mjs)');
  L.push('');
  L.push(`compiler        ${ccName}  (${ccVersion})`);
  L.push(`vendor          ${args.vendor}: plugin ${component}, loaded with ${args.vendor === 'gcc' ? '-fplugin=' : '-fpass-plugin='}<so>`);
  L.push(`plugin sha256   ${pluginSha}`);
  L.push(`reader          ${readerInfo.label}: accepts ${readerInfo.schemaVersion}, sha256 ${readerInfo.sha256}`);
  L.push(`compile         ${flags.join(' ')} <opt>${lineArgs.length ? ` ${lineArgs.join(' ')}` : ''}, WPIN_SCOPE=module WPIN_DRY_RUN=1`);
  L.push(`files           ${selected.length} of the ${family.length} erasure-family files (lib/corpus.mjs, the selection run-repair-loop.mjs uses)`
    + `${args.files ? ` (--files ${args.files.join(',')})` : ''}`);
  L.push(`opts            ${args.opts.join(' ')}  (reference ${REFERENCE_OPT})`);
  const main = x.results.filter((r) => r.variant === 'main');
  L.push(`compiles        ${x.results.length}: ${main.length} measured, ${x.results.filter((r) => r.variant === 'again').length} for the ${REFERENCE_OPT} repeat, `
    + `${x.results.filter((r) => r.variant === 'noline').length} without the line flag`);
  L.push(`records         accepted by the reader ${x.results.filter((r) => r.ok).length}/${x.results.length}`);
  for (const r of x.failed.slice(0, 20)) L.push(`  NOT ACCEPTED ${r.id} ${r.opt} ${r.variant}: ${r.problems.slice(0, 3).join('; ')}`);
  if (x.failed.length > 20) L.push(`  ... ${x.failed.length - 20} more`);
  L.push('');

  L.push('sites per level (every site of every accepted record, module scope; followedByUse)');
  L.push(`  ${pad('level', 12)}${lpad('records', 8)}${lpad('sites', 7)}${lpad('true', 6)}${lpad('false', 7)}${lpad('null', 6)}${lpad('no line', 9)}`);
  const trow = (name, t) => L.push(`  ${pad(name, 12)}${lpad(t.accepted, 8)}${lpad(t.sites, 7)}${lpad(t.true, 6)}${lpad(t.false, 7)}${lpad(t.null, 6)}${lpad(t.noLine, 9)}`);
  for (const o of args.opts) trow(o, x.tallies[o]);
  trow(`${REFERENCE_OPT} again`, x.againTally);
  L.push('');

  L.push(`each level against ${REFERENCE_OPT}, site by site: joined on (file, function, index), the line as a second key`);
  L.push(`  ${pad('level', 12)}${lpad('sites', 6)}${lpad('joined', 8)}${lpad('line differs', 14)}${lpad(`only ${REFERENCE_OPT}`, 10)}${lpad('only here', 11)}`
    + `${lpad('dup', 5)}${lpad('false->true', 13)}${lpad('true->false', 13)}${lpad('null', 6)}${lpad('other fields', 14)}${lpad('not compared', 14)}`);
  const crow = (name, c) => L.push(`  ${pad(name, 12)}${lpad(c.sites, 6)}${lpad(c.joined, 8)}${lpad(c.lineDiffers.length, 14)}${lpad(c.onlyRef.length, 10)}`
    + `${lpad(c.onlyOther.length, 11)}${lpad(c.duplicate.length, 5)}${lpad(c.changes['false->true'].length, 13)}${lpad(c.changes['true->false'].length, 13)}`
    + `${lpad(c.changes.null.length, 6)}${lpad(c.otherFields.length, 14)}${lpad(c.notCompared.length, 14)}`);
  for (const { opt, cmp } of x.levels) crow(opt, cmp);
  const sum = (f) => x.levels.reduce((n, { cmp }) => n + f(cmp), 0);
  L.push(`  all levels: followedByUse differs from ${REFERENCE_OPT} at ${sum(changeCount)} site(s); not joined: line differs ${sum((c) => c.lineDiffers.length)} pair(s), `
    + `only on one side ${sum((c) => c.onlyRef.length + c.onlyOther.length)} site(s), duplicate key ${sum((c) => c.duplicate.length)} site(s), `
    + `in files not compared ${sum((c) => c.notCompared.reduce((n, e) => n + e.refSites + e.otherSites, 0))} site(s)`);
  L.push(`  every site accounted for (2 x joined + 2 x line differs + unmatched + duplicate = sites on both sides): ${x.allAccounted ? 'yes' : 'NO (exit 2)'}`);
  for (const { opt, cmp } of x.levels) listIds(L, opt, cmp);
  L.push('');

  L.push('controls');
  const rp = x.repeat;
  L.push(`  ${REFERENCE_OPT} compiled twice: ${rp.sites} sites, joined ${rp.joined}, line differs ${rp.lineDiffers.length}, unmatched ${rp.onlyRef.length + rp.onlyOther.length}, `
    + `duplicate ${rp.duplicate.length}, followedByUse differs ${changeCount(rp)}, other fields ${rp.otherFields.length}, not compared ${rp.notCompared.length}; `
    + `same evidenceDigest ${x.repeatDigests}/${x.againTally.files}: ${x.repeatHeld ? 'HELD' : 'FAILED (exit 2)'}`);
  if (!x.repeatHeld) listIds(L, `${REFERENCE_OPT} again`, rp);
  if (!args.lineFlag) {
    L.push('  line flag: not run (--line-flag none)');
  } else {
    const agg = x.lineCtl.reduce((a, { c }) => ({ pairs: a.pairs + c.pairs, equal: a.equal + c.equal, sites: a.sites + c.sites,
      withLine: a.withLine + c.withLine, withoutLine: a.withoutLine + c.withoutLine }), { pairs: 0, equal: 0, sites: 0, withLine: 0, withoutLine: 0 });
    L.push(`  line flag ${args.lineFlag} against none, ${lineIds.size} file(s) x ${args.opts.length} level(s): records equal on every field but pinned[].line `
      + `${agg.equal}/${agg.pairs}; sites carrying a line ${agg.withLine}/${agg.sites} with the flag, ${agg.withoutLine}/${agg.sites} without: `
      + `${x.lineHeld ? 'HELD' : 'FAILED (exit 2)'}`);
    for (const { opt, c } of x.lineCtl) {
      for (const id of c.unequal) L.push(`    LINE FLAG CHANGED THE RECORD ${id} ${opt}`);
      for (const id of c.notCompared) L.push(`    NOT COMPARED ${id} ${opt}: a record was not accepted`);
    }
  }
  L.push('');
  L.push(`${REFERENCE_OPT} is the reference, not the truth: a site the analysis reads wrongly at every level alike (a flag tested before a use,`);
  L.push(`a constant stored before the memset, a cleanup dispatch ${REFERENCE_OPT} has too, a search bound, an address kept where the analysis`);
  L.push('does not follow it) is the same at every level and does not show here. This measures whether the answer depends on the level.');
  L.push('');
  return L.join('\n');
}

function listIds(L, opt, cmp) {
  for (const p of cmp.lineDiffers) L.push(`  ${opt} LINE DIFFERS ${siteName(p.ref)}: line ${p.other.line} at ${opt}`);
  for (const s of cmp.onlyRef) L.push(`  ${opt} ONLY AT ${REFERENCE_OPT} ${siteName(s)} (followedByUse ${s.followedByUse})`);
  for (const s of cmp.onlyOther) L.push(`  ${opt} ONLY AT ${opt} ${siteName(s)} (followedByUse ${s.followedByUse})`);
  for (const s of cmp.duplicate) L.push(`  ${opt} DUPLICATE KEY ${siteName(s)}`);
  for (const c of CHANGES) {
    for (const p of cmp.changes[c]) {
      L.push(`  ${opt} ${c.toUpperCase()} ${siteName(p.ref)}${c === 'null' ? `: ${p.ref.followedByUse} -> ${p.other.followedByUse}` : ''}`);
    }
  }
  for (const p of cmp.otherFields) {
    L.push(`  ${opt} OTHER FIELDS ${siteName(p.ref)}: ${p.fields.map((f) => `${f} ${JSON.stringify(p.ref[f])} -> ${JSON.stringify(p.other[f])}`).join(', ')}`);
  }
  for (const n of cmp.notCompared) {
    L.push(`  ${opt} NOT COMPARED ${n.id}: ${REFERENCE_OPT} record ${n.refOk ? 'accepted' : 'not accepted'} (${n.refSites} sites), `
      + `${opt} record ${n.otherOk ? 'accepted' : 'not accepted'} (${n.otherSites} sites)`);
  }
}

main().catch((e) => die(5, `unexpected failure: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`));

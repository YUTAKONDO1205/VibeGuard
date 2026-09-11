#!/usr/bin/env node
/**
 * repair-loop -- does a repair plugin turn an eliminated wipe into a surviving one,
 * judged by the same stock observation that found the elimination?
 *
 * For every erasure-family generation in ../ai-generated/generated-corpus/r2 and
 * every requested optimisation level, four compiles with identical flags:
 *
 *            plugin off        plugin on
 *   wipe     w/off             w/on
 *   ablated  wo/off            wo/on
 *
 *   baseline = verdictOf(w/off, wo/off, fn)   -- the find step, re-run here
 *   repaired = verdictOf(w/on,  wo/on,  fn)   -- the SAME verdict code, plugin loaded
 *
 * The verdict code is imported from ../ai-generated/lib/ablation-cell.mjs and is
 * not duplicated: a repair judged by a second, private copy of the oracle would be
 * judging itself. The plugin's own record is read only to show that the repair ran
 * on the functions it was asked about; it never decides survival. See README.md.
 *
 *   node run-repair-loop.mjs --plugin <libWipePin.so> --out <lab dir> [options]
 *
 * Exit codes: 0 run complete and every integrity check held; 2 run complete but a
 * baseline disagreed with the tracked rows or a surgicality check was violated;
 * 3 vacuous (nothing selected); 4 bad arguments; 5 a tool, the plugin or the
 * shared verdict module could not be used.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readPinRecord, unresolvedNames, SEEN_KEYS, UNHANDLED_KEYS } from './lib/pin-record.mjs';
import { outcomeOf, absentAfterAblation, gradeRedControl, OUTCOMES, ELIMINATED } from './lib/outcome.mjs';
import { ablatedUnchanged, controlUntouched, noPinNoChange, pinDelta } from './lib/surgicality.mjs';
import { authzSummary, configguardTargets, configguardRow, unsupportedVendorLine, notAttemptedLine } from './lib/stage-gate.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const AIGEN = resolve(HERE, '..', 'ai-generated');
const GEN = join(AIGEN, 'generated-corpus', 'r2');
const SCEN_PATH = join(AIGEN, 'scenarios.json');
const CELL_PATH = join(AIGEN, 'lib', 'ablation-cell.mjs');
const DEFAULT_ROWS = join(AIGEN, 'data', 'r2-build-rows.json');
// Build scratch: regenerable, ignored by .gitignore.
const BUILD = join(HERE, '_build');
const DATA = join(HERE, 'data');
const ALL_OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];
const CONTROL_FN = 'vgctl_control';

const USAGE = `usage: node run-repair-loop.mjs --plugin <so> --out <dir> [options]

  --plugin <so>          the repair plugin (required; there is no default)
  --out <dir>            lab directory for records, rows and the manifest (required)
  --cc <compiler>        default clang-18; gcc is refused
  --scope functions|module     default functions
  --opts <list>          comma list from ${ALL_OPTS.join(' ')} (default: all five)
  --dry-run              load the plugin with WPIN_DRY_RUN=1 (red control)
  --target-suffix <s>    append <s> to every requested function name (red control)
  --files <list>         comma list of basenames or globs (* ?), with or without .c
  --rows <path>          tracked baseline rows (default: the ai-generated lane's r2-build-rows.json)
  --conc <n>             parallel compiles (default 8)
  --write-data           also write data/r2-repair-rows.json and data/r2-repair-results.txt
                         (refused for red controls and partial runs)
`;

function die(code, msg) {
  process.stderr.write(`run-repair-loop: ${msg}\n`);
  process.exit(code);
}

// ---------------------------------------------------------------- arguments --
function parseArgs(argv) {
  const a = { cc: 'clang-18', scope: 'functions', opts: [...ALL_OPTS], dryRun: false, targetSuffix: null,
    files: null, rows: DEFAULT_ROWS, conc: 8, writeData: false, plugin: null, out: null };
  const need = (i, flag) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${flag} needs a value`); return argv[i + 1]; };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--plugin': a.plugin = need(i, f); i++; break;
      case '--out': a.out = need(i, f); i++; break;
      case '--cc': a.cc = need(i, f); i++; break;
      case '--scope': a.scope = need(i, f); i++; break;
      case '--opts': a.opts = need(i, f).split(',').map((s) => s.trim()).filter(Boolean); i++; break;
      case '--dry-run': a.dryRun = true; break;
      case '--target-suffix': a.targetSuffix = need(i, f); i++; break;
      case '--files': a.files = need(i, f).split(',').map((s) => s.trim()).filter(Boolean); i++; break;
      case '--rows': a.rows = need(i, f); i++; break;
      case '--conc': a.conc = Number(need(i, f)); i++; break;
      case '--write-data': a.writeData = true; break;
      case '-h': case '--help': process.stdout.write(USAGE); process.exit(0); break;
      default: die(4, `unknown argument ${f}\n${USAGE}`);
    }
  }
  if (!a.plugin) die(4, '--plugin is required. There is no default: the plugin under test must be named by whoever runs the lane.');
  if (!a.out) die(4, '--out is required: records and manifests go to a lab directory outside the repository.');
  const ccBase = basename(a.cc);
  if (/^(gcc|g\+\+)(-[\d.]+)?$/.test(ccBase) || /-(gcc|g\+\+)(-[\d.]+)?$/.test(ccBase)) {
    die(4, `--cc ${a.cc} refused: an LLVM pass plugin cannot load into gcc. gcc's cells are reported as `
      + 'UNSUPPORTED_VENDOR from the tracked rows; there is nothing to run.');
  }
  if (!['functions', 'module'].includes(a.scope)) die(4, `--scope must be functions or module, not ${a.scope}`);
  for (const o of a.opts) if (!ALL_OPTS.includes(o)) die(4, `--opts: ${o} is not one of ${ALL_OPTS.join(' ')}`);
  if (!a.opts.length) die(4, '--opts is empty');
  a.opts = ALL_OPTS.filter((o) => a.opts.includes(o));
  if (a.targetSuffix !== null && a.scope !== 'functions') die(4, '--target-suffix renames requested functions and means nothing in module scope');
  if (a.targetSuffix === '') die(4, '--target-suffix must not be empty');
  if (!Number.isInteger(a.conc) || a.conc < 1) die(4, '--conc must be a positive integer');
  if (a.writeData) {
    const why = [];
    if (a.dryRun) why.push('--dry-run');
    if (a.targetSuffix !== null) why.push('--target-suffix');
    if (a.files) why.push('--files');
    if (a.scope !== 'functions') why.push('--scope module');
    if (a.opts.length !== ALL_OPTS.length) why.push('a partial --opts');
    if (why.length) {
      die(4, `--write-data refused with ${why.join(', ')}: the tracked data file is the full functions-scope `
        + 'run over every level. A red control or a subset written there would be read as the result.');
    }
  }
  a.plugin = resolve(a.plugin);
  a.out = resolve(a.out);
  a.rows = resolve(a.rows);
  return a;
}

function globToRe(g) {
  const s = g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + s + '$');
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// ---------------------------------------------------------------- helpers ----
function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex');
}

/** process.env with every WPIN_* removed, so no inherited setting reaches a compile. */
function cleanEnv() {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith('WPIN_')) env[k] = v;
  return env;
}

function summarizeRecord(rr) {
  if (!rr.ok) return { ok: false, problems: rr.problems };
  const r = rr.record;
  return {
    ok: true,
    pinnedCount: r.pinnedCount,
    wouldPinCount: r.wouldPinCount,
    unresolved: unresolvedNames(r),
    seen: { ...r.seen },
    unhandled: { ...r.unhandled },
  };
}

function idiomOf(kinds) {
  if (kinds.includes('removable') && kinds.includes('nonremovable')) return 'both';
  return kinds.includes('removable') ? 'removable' : 'nonremovable';
}

// ---------------------------------------------------------------- main -------
async function main() {
  const args = parseArgs(process.argv.slice(2));

  // Nothing inherited may steer a plugin-on compile. Removed from process.env too,
  // in case the shared compile() merges its env over the parent's.
  const inherited = Object.keys(process.env).filter((k) => k.startsWith('WPIN_'));
  for (const k of inherited) delete process.env[k];
  if (inherited.length) process.stderr.write(`note: ignoring inherited ${inherited.join(' ')}\n`);
  const BASE_ENV = cleanEnv();

  if (!existsSync(args.plugin) || !statSync(args.plugin).isFile()) die(5, 'the --plugin path does not name a file');
  if (!existsSync(CELL_PATH)) {
    die(5, 'ai-generated/lib/ablation-cell.mjs is missing. This lane judges with the find step\'s own verdict code '
      + 'and has no private copy to fall back on.');
  }
  const cell = await import(pathToFileURL(CELL_PATH).href);
  for (const name of ['FLAGS', 'CONTROL', 'wipeSpans', 'controlPresent', 'ablateSpans', 'bodyOf', 'compile', 'pool', 'verdictOf']) {
    if (!(name in cell)) die(5, `ablation-cell.mjs does not export ${name}`);
  }

  let ccVersion;
  try {
    const { stdout } = await run(args.cc, ['--version'], { timeout: 30000 });
    ccVersion = stdout.split('\n')[0].trim();
  } catch {
    die(5, `${args.cc} --version failed: the compiler is not runnable here`);
  }
  const ccName = basename(args.cc);
  const pluginSha = sha256(args.plugin);

  const scen = JSON.parse(readFileSync(SCEN_PATH, 'utf8'));
  let tracked;
  try { tracked = JSON.parse(readFileSync(args.rows, 'utf8')); }
  catch { die(5, 'the --rows file could not be read as JSON'); }

  mkdirSync(BUILD, { recursive: true });
  mkdirSync(join(args.out, 'records'), { recursive: true });

  const pluginArg = `-fpass-plugin=${args.plugin}`;
  const pluginEnv = (recordPath, requested, scope = args.scope) => {
    const env = { ...BASE_ENV, WPIN_OUT: recordPath };
    if (scope === 'module') env.WPIN_SCOPE = 'module';
    else env.WPIN_TARGET_FNS = requested.join(',');
    if (args.dryRun) env.WPIN_DRY_RUN = '1';
    return env;
  };

  // ---- preflight: does the plugin load, and does it refuse when it should? ----
  const pre = { loads: null, loadStderr: null, recordOnModuleScope: null, noRecordWithoutTarget: null, noRecordWithoutOut: null };
  {
    const src = join(BUILD, '_preflight.c');
    writeFileSync(src, 'void vgpre_wipe(unsigned char *p) { __builtin_memset(p, 0, 64); }\n', 'utf8');
    const asm = join(BUILD, '_preflight.s');
    const recA = join(args.out, 'records', '_preflight-module.json');
    const recB = join(args.out, 'records', '_preflight-no-target.json');
    rmSync(recA, { force: true }); rmSync(recB, { force: true });
    try {
      await run(args.cc, [...cell.FLAGS, '-O2', pluginArg, '-o', asm, src], { env: pluginEnv(recA, [], 'module'), timeout: 90000 });
      pre.loads = true;
    } catch (e) {
      pre.loads = false;
      pre.loadStderr = String(e.stderr || e.message || '').split('\n').slice(0, 6).join('\n');
    }
    if (!pre.loads) die(5, `the plugin did not load into ${ccName}; first lines of stderr:\n${pre.loadStderr}`);
    const rA = readPinRecord(recA, { scope: 'module', dryRun: args.dryRun, opt: '-O2', module: basename(src) });
    pre.recordOnModuleScope = rA.ok ? 'valid' : rA.problems.join(', ');
    // Contract: WPIN_OUT set but no target -> no record.
    const envB = { ...BASE_ENV, WPIN_OUT: recB };
    if (args.dryRun) envB.WPIN_DRY_RUN = '1';
    try { await run(args.cc, [...cell.FLAGS, '-O2', pluginArg, '-o', asm, src], { env: envB, timeout: 90000 }); } catch { /* the check is the file */ }
    pre.noRecordWithoutTarget = !existsSync(recB);
    // Contract: no WPIN_OUT -> no record and a refusal on stderr. Where a record
    // would go is unknowable, so all that is recorded is whether stderr said
    // anything. Its text is not copied: it may carry a path, and this value
    // reaches the results file.
    try {
      const { stderr } = await run(args.cc, [...cell.FLAGS, '-O2', pluginArg, '-o', asm, src],
        { env: { ...BASE_ENV, WPIN_SCOPE: 'module' }, timeout: 90000 });
      pre.noRecordWithoutOut = stderr.trim().length > 0 ? 'stderr-nonempty' : 'stderr-empty';
    } catch {
      pre.noRecordWithoutOut = 'compile-failed';
    }
    if (!rA.ok) {
      process.stderr.write(`warning: the plugin loaded but its module-scope preflight record was refused (${pre.recordOnModuleScope}); `
        + 'expect BROKEN_REPAIR in every cell\n');
    }
  }

  // ---- select files -----------------------------------------------------------
  const res = args.files ? args.files.map(globToRe) : null;
  const selected = (f) => !res || res.some((re) => re.test(f) || re.test(f.replace(/\.c$/, '')));
  const all = readdirSync(GEN).filter((f) => f.endsWith('.c')).sort();
  const metaOf = (f) => {
    const id = f.replace(/\.c$/, '');
    const [model, framing, sc, rep] = id.split('_');
    const m = scen[sc];
    return m ? { id, model, framing, scen: sc, rep, fam: m.fam, fn: m.fn } : null;
  };
  const erasure = all.filter(selected).map((f) => ({ f, meta: metaOf(f) })).filter((x) => x.meta && x.meta.fam === 'erasure');
  const cfgIds = new Set(all.filter(selected).map((f) => f.replace(/\.c$/, '')));

  const trackedVerdict = new Map();
  const trackedIdiom = new Map();
  const trackedNone = new Set();
  for (const r of tracked) {
    if (r.kind === 'erasure') { trackedVerdict.set(`${r.id}|${r.cc}|${r.opt}`, r.verdict); trackedIdiom.set(r.id, r.idiom); }
    else if (r.kind === 'none') trackedNone.add(r.id);
  }

  // ---- prepare sources ------------------------------------------------------
  const cells = [];
  const noneCells = [];
  for (const { f, meta } of erasure) {
    const src = readFileSync(join(GEN, f), 'utf8');
    const ws = cell.wipeSpans(src, meta.fn);
    const pW = join(BUILD, `${meta.id}.w.c`);
    writeFileSync(pW, src + cell.CONTROL, 'utf8');
    const baseNames = [...new Set([meta.fn, ...ws.helpers])];
    const requested = args.scope === 'functions' ? baseNames.map((n) => n + (args.targetSuffix ?? '')) : [];
    if (!ws.spans.length) {
      for (const opt of args.opts) noneCells.push({ meta, opt, pW, requested });
      continue;
    }
    const pWo = join(BUILD, `${meta.id}.wo.c`);
    writeFileSync(pWo, cell.ablateSpans(src, ws.spans) + cell.CONTROL, 'utf8');
    const idiom = idiomOf(ws.kinds);
    for (const opt of args.opts) cells.push({ meta, opt, pW, pWo, requested, idiom, nSpans: ws.spans.length });
  }
  if (!cells.length && !noneCells.length) die(3, 'no erasure-family file was selected; nothing was measured');
  process.stderr.write(`${erasure.length} erasure file(s): ${cells.length} wipe cell(s), ${noneCells.length} no-wipe cell(s), `
    + `opts ${args.opts.join(' ')}, scope ${args.scope}${args.dryRun ? ', DRY RUN' : ''}`
    + `${args.targetSuffix !== null ? `, target suffix ${JSON.stringify(args.targetSuffix)}` : ''}\n`);

  const recDir = (id) => { const d = join(args.out, 'records', id); mkdirSync(d, { recursive: true }); return d; };
  const asmPath = (id, opt, side, mode) => join(BUILD, `${id}.${ccName}${opt}.${side}.${mode}.s`);
  const baseExpect = { scope: args.scope, dryRun: args.dryRun };

  // ---- the four-compile cell -------------------------------------------------
  const rows = [];
  let done = 0;
  const tick = () => { if (++done % 100 === 0) process.stderr.write(`  ${done} cells\n`); };

  await cell.pool(cells, async (c) => {
    const { meta, opt, pW, pWo, requested } = c;
    const rd = recDir(meta.id);
    const recW = join(rd, `${ccName}${opt}.w.json`);
    const recWo = join(rd, `${ccName}${opt}.wo.json`);
    rmSync(recW, { force: true });
    rmSync(recWo, { force: true });

    const aWoff = await cell.compile(args.cc, [opt], pW, asmPath(meta.id, opt, 'w', 'off'));
    const aWooff = await cell.compile(args.cc, [opt], pWo, asmPath(meta.id, opt, 'wo', 'off'));
    const aWon = await cell.compile(args.cc, [opt, pluginArg], pW, asmPath(meta.id, opt, 'w', 'on'), { env: pluginEnv(recW, requested) });
    const aWoon = await cell.compile(args.cc, [opt, pluginArg], pWo, asmPath(meta.id, opt, 'wo', 'on'), { env: pluginEnv(recWo, requested) });

    const baseline = cell.verdictOf(aWoff, aWooff, meta.fn);
    const repaired = cell.verdictOf(aWon, aWoon, meta.fn);
    const rW = readPinRecord(recW, { ...baseExpect, opt, module: basename(pW), requested });
    const rWo = readPinRecord(recWo, { ...baseExpect, opt, module: basename(pWo), requested });
    const ctlW = aWon ? cell.controlPresent(aWon) : { ok: false, via: 'COMPILE_ERROR' };
    const ctlWo = aWoon ? cell.controlPresent(aWoon) : { ok: false, via: 'COMPILE_ERROR' };
    const oc = outcomeOf(baseline, repaired, rW, rWo, ctlW.ok && ctlWo.ok);

    const tv = trackedVerdict.get(`${meta.id}|${ccName}|${opt}`);
    rows.push({
      id: meta.id, model: meta.model, framing: meta.framing, scen: meta.scen, fam: meta.fam, fn: meta.fn,
      kind: 'erasure', idiom: c.idiom, idiomMatchesTracked: trackedIdiom.has(meta.id) ? trackedIdiom.get(meta.id) === c.idiom : null,
      n_spans: c.nSpans, cc: ccName, opt, scope: args.scope, dryRun: args.dryRun, targetSuffix: args.targetSuffix,
      requested,
      baseline: baseline.verdict, baselineControl: baseline.control ?? null,
      repaired: repaired.verdict, repairedControl: repaired.control ?? null,
      trackedVerdict: tv ?? null,
      baselineMatchesTracked: tv === undefined ? null : tv === baseline.verdict,
      outcome: oc.outcome, outcomeReason: oc.reason,
      controlOnW: ctlW.ok, controlOnWVia: ctlW.via, controlOnWo: ctlWo.ok, controlOnWoVia: ctlWo.via,
      recordW: summarizeRecord(rW), recordWo: summarizeRecord(rWo),
      absentAfterAblation: absentAfterAblation(rW, rWo),
      pinDelta: pinDelta(rW, rWo),
      ablatedUnchanged: ablatedUnchanged({ asmWoOff: aWooff, asmWoOn: aWoon, fn: meta.fn, recordWo: rWo, bodyOf: cell.bodyOf }),
      controlUntouched: controlUntouched({ scope: args.scope, pairs: [[aWoff, aWon], [aWooff, aWoon]], bodyOf: cell.bodyOf, controlFn: CONTROL_FN }),
      noPinNoChangeW: noPinNoChange({ asmOff: aWoff, asmOn: aWon, record: rW }),
      noPinNoChangeWo: noPinNoChange({ asmOff: aWooff, asmOn: aWoon, record: rWo }),
    });
    tick();
  }, args.conc);

  // ---- files that wrote no wipe: two compiles, and the plugin must change nothing it did not pin
  await cell.pool(noneCells, async (c) => {
    const { meta, opt, pW, requested } = c;
    const rd = recDir(meta.id);
    const recW = join(rd, `${ccName}${opt}.w.json`);
    rmSync(recW, { force: true });
    const aOff = await cell.compile(args.cc, [opt], pW, asmPath(meta.id, opt, 'w', 'off'));
    const aOn = await cell.compile(args.cc, [opt, pluginArg], pW, asmPath(meta.id, opt, 'w', 'on'), { env: pluginEnv(recW, requested) });
    const rW = readPinRecord(recW, { ...baseExpect, opt, module: basename(pW), requested });
    rows.push({
      id: meta.id, model: meta.model, framing: meta.framing, scen: meta.scen, fam: meta.fam, fn: meta.fn,
      kind: 'none', verdict: 'NO_WIPE_WRITTEN', cc: ccName, opt, scope: args.scope, dryRun: args.dryRun, targetSuffix: args.targetSuffix,
      requested,
      baselineMatchesTracked: trackedNone.has(meta.id),
      compiledOff: !!aOff, compiledOn: !!aOn,
      controlOn: aOn ? cell.controlPresent(aOn).ok : false,
      record: summarizeRecord(rW),
      pinnedCount: rW.ok ? rW.record.pinnedCount : null,
      noPinNoChange: noPinNoChange({ asmOff: aOff, asmOn: aOn, record: rW }),
      controlUntouched: controlUntouched({ scope: args.scope, pairs: [[aOff, aOn]], bodyOf: cell.bodyOf, controlFn: CONTROL_FN }),
    });
    tick();
  }, args.conc);

  // ---- out of reach ------------------------------------------------------------
  const authz = authzSummary(tracked);
  let cfgNote;
  let cfgSelection = null;
  const cfgRows = [];
  if (!args.opts.includes('-O2')) {
    cfgNote = 'configguard: not measured in this run (-O2 is not among --opts)';
  } else {
    const allTargets = configguardTargets(tracked, { cc: ccName, opt: '-O2' });
    const targets = allTargets.filter((t) => cfgIds.has(t.id));
    cfgSelection = `${targets.length} of ${allTargets.length} tracked DEFAULT_DIFFERS file(s) selected`;
    await cell.pool(targets, async (t) => {
      const src = readFileSync(join(GEN, `${t.id}.c`), 'utf8');
      const p = join(BUILD, `${t.id}.cg.c`);
      writeFileSync(p, src + cell.CONTROL, 'utf8');
      const rec = join(recDir(t.id), `${ccName}-O2.default.json`);
      rmSync(rec, { force: true });
      const aOff = await cell.compile(args.cc, ['-O2'], p, asmPath(t.id, '-O2', 'default', 'off'));
      const aOn = await cell.compile(args.cc, ['-O2', pluginArg], p, asmPath(t.id, '-O2', 'default', 'on'), { env: pluginEnv(rec, [], 'module') });
      const aEn = await cell.compile(args.cc, ['-O2', ...t.macros.map((m) => `-D${m}=1`)], p, asmPath(t.id, '-O2', 'enabled', 'off'));
      const rr = readPinRecord(rec, { scope: 'module', dryRun: args.dryRun, opt: '-O2', module: basename(p) });
      cfgRows.push(configguardRow(t, {
        bodyDefaultOff: aOff ? cell.bodyOf(aOff, t.fn) : null,
        bodyDefaultOn: aOn ? cell.bodyOf(aOn, t.fn) : null,
        bodyEnabledOff: aEn ? cell.bodyOf(aEn, t.fn) : null,
        recordOk: rr.ok, pinnedCount: rr.ok ? rr.record.pinnedCount : null,
        controlOn: aOn ? cell.controlPresent(aOn).ok : false,
      }, { cc: ccName, opt: '-O2', scope: 'module', dryRun: args.dryRun }));
    }, args.conc);
    cfgNote = null;
  }
  rows.push(...cfgRows);

  rows.sort((a, b) => cmp(a.id, b.id) || cmp(a.opt, b.opt) || cmp(a.kind, b.kind));

  // ---- results text ----------------------------------------------------------------
  const red = gradeRedControl(rows, { dryRun: args.dryRun, targetSuffix: args.targetSuffix });
  const text = renderResults({ args, ccName, ccVersion, pluginSha, pre, rows, authz, cfgNote, cfgSelection, tracked, red });

  const rowsText = '[\n' + rows.map((r) => JSON.stringify(r)).join(',\n') + '\n]\n';
  writeFileSync(join(args.out, 'r2-repair-rows.json'), rowsText, 'utf8');
  writeFileSync(join(args.out, 'r2-repair-results.txt'), text, 'utf8');
  writeFileSync(join(args.out, 'manifest.json'), JSON.stringify({
    generatedAt: new Date().toISOString(), node: process.version,
    cc: args.cc, ccVersion, plugin: args.plugin, pluginSha256: pluginSha,
    scope: args.scope, dryRun: args.dryRun, targetSuffix: args.targetSuffix, opts: args.opts,
    files: args.files, rowsFile: args.rows, conc: args.conc, preflight: pre,
    erasureFiles: erasure.length, cells: cells.length, noWipeCells: noneCells.length, configguardRows: cfgRows.length,
    ignoredInheritedEnv: inherited,
  }, null, 2) + '\n', 'utf8');
  if (args.writeData) {
    mkdirSync(DATA, { recursive: true });
    writeFileSync(join(DATA, 'r2-repair-rows.json'), rowsText, 'utf8');
    writeFileSync(join(DATA, 'r2-repair-results.txt'), text, 'utf8');
  }
  process.stdout.write(text);

  const integrityBroken = rows.some((r) =>
    r.baselineMatchesTracked === false
    || r.ablatedUnchanged === false || r.controlUntouched === false
    || r.noPinNoChangeW === false || r.noPinNoChangeWo === false || r.noPinNoChange === false);
  process.exit(integrityBroken || (red && !red.held) ? 2 : 0);
}

// ---------------------------------------------------------------- rendering --
function pad(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }
function lpad(s, n) { s = String(s); return s.length >= n ? s : ' '.repeat(n - s.length) + s; }

function tri(rows, field) {
  let t = 0, f = 0, n = 0;
  for (const r of rows) { if (r[field] === true) t++; else if (r[field] === false) f++; else n++; }
  return `held ${t}, violated ${f}, n/a ${n}`;
}

function renderResults({ args, ccName, ccVersion, pluginSha, pre, rows, authz, cfgNote, cfgSelection, tracked, red }) {
  const L = [];
  const er = rows.filter((r) => r.kind === 'erasure');
  const none = rows.filter((r) => r.kind === 'none');
  const cfg = rows.filter((r) => r.kind === 'configguard');
  const opts = args.opts;

  L.push('repair-loop results (run-repair-loop.mjs)');
  L.push('');
  L.push(`compiler        ${ccName}  (${ccVersion})`);
  L.push(`plugin sha256   ${pluginSha}`);
  L.push(`scope           ${args.scope}`);
  L.push(`dry run         ${args.dryRun}`);
  L.push(`target suffix   ${args.targetSuffix === null ? '(none)' : JSON.stringify(args.targetSuffix)}`);
  L.push(`opts            ${opts.join(' ')}`);
  L.push(`file subset     ${args.files ? args.files.join(',') : '(all erasure files)'}`);
  L.push(`cells           ${er.length} wipe, ${none.length} no-wipe, ${cfg.length} configguard`);
  L.push('');
  L.push('preflight');
  L.push(`  plugin loads                          ${pre.loads}`);
  L.push(`  module-scope record                   ${pre.recordOnModuleScope}`);
  L.push(`  no record when no target is given     ${pre.noRecordWithoutTarget}`);
  L.push(`  without WPIN_OUT (expect a refusal)   ${pre.noRecordWithoutOut}`);
  L.push('');

  if (red) {
    L.push(`red control ${red.control}: ${red.held ? 'HELD' : 'FAILED'}`);
    L.push(`  expected  ${red.expected}`);
    for (const v of red.violations) L.push(`  VIOLATION ${v}`);
    L.push('');
  }

  // baseline agreement
  const cmpd = er.filter((r) => r.baselineMatchesTracked !== null);
  const agree = cmpd.filter((r) => r.baselineMatchesTracked).length;
  const noTracked = er.length - cmpd.length;
  const noneAgree = none.filter((r) => r.baselineMatchesTracked).length;
  const idiomCmp = er.filter((r) => r.idiomMatchesTracked !== null);
  L.push('baseline (plugin off) against the tracked find-step rows');
  L.push(`  wipe cells       ${agree}/${cmpd.length} agree${noTracked ? `, ${noTracked} without a tracked row` : ''}`);
  L.push(`  no-wipe cells    ${noneAgree}/${none.length} tracked as NO_WIPE_WRITTEN too`);
  L.push(`  idiom label      ${idiomCmp.filter((r) => r.idiomMatchesTracked).length}/${idiomCmp.length} agree`);
  for (const r of cmpd.filter((x) => !x.baselineMatchesTracked)) L.push(`  DISAGREE ${r.id} ${r.opt}: tracked ${r.trackedVerdict}, measured ${r.baseline}`);
  for (const r of none.filter((x) => !x.baselineMatchesTracked)) L.push(`  DISAGREE ${r.id} ${r.opt}: no wipe found now, tracked as a wipe file`);
  L.push('');

  // outcome distribution per idiom x opt
  for (const idiom of ['removable', 'nonremovable', 'both']) {
    const sub = er.filter((r) => r.idiom === idiom);
    if (!sub.length) continue;
    L.push(`outcomes -- idiom ${idiom}`);
    L.push('  ' + pad('outcome', 22) + opts.map((o) => lpad(o, 6)).join(''));
    for (const oc of OUTCOMES) {
      const counts = opts.map((o) => sub.filter((r) => r.opt === o && r.outcome === oc).length);
      L.push('  ' + pad(oc, 22) + counts.map((n) => lpad(n, 6)).join(''));
    }
    L.push('  ' + pad('total', 22) + opts.map((o) => lpad(sub.filter((r) => r.opt === o).length, 6)).join(''));
    L.push('');
  }

  // control on plugin-on compiles
  L.push('positive control PRESENT in the plugin-on compiles');
  for (const o of opts) {
    const sub = er.filter((r) => r.opt === o);
    const nsub = none.filter((r) => r.opt === o);
    L.push(`  ${pad(o, 4)} w/on ${sub.filter((r) => r.controlOnW).length}/${sub.length}   wo/on ${sub.filter((r) => r.controlOnWo).length}/${sub.length}`
      + `   no-wipe on ${nsub.filter((r) => r.controlOn).length}/${nsub.length}`);
  }
  L.push('');

  // surgicality
  L.push('surgicality (reported beside the outcome, never folded into it)');
  L.push(`  ablatedUnchanged     ${tri(er, 'ablatedUnchanged')}`);
  L.push(`  controlUntouched     ${tri(er, 'controlUntouched')}   (functions scope only)`);
  L.push(`  noPinNoChange  w     ${tri(er, 'noPinNoChangeW')}`);
  L.push(`  noPinNoChange  wo    ${tri(er, 'noPinNoChangeWo')}`);
  L.push(`  noPinNoChange  none  ${tri(none, 'noPinNoChange')}`);
  L.push(`  controlUntouched none ${tri(none, 'controlUntouched')}`);
  for (const r of er) {
    for (const k of ['ablatedUnchanged', 'controlUntouched', 'noPinNoChangeW', 'noPinNoChangeWo']) {
      if (r[k] === false) L.push(`  VIOLATED ${k} ${r.id} ${r.opt}`);
    }
  }
  for (const r of none) {
    for (const k of ['noPinNoChange', 'controlUntouched']) if (r[k] === false) L.push(`  VIOLATED ${k} ${r.id} ${r.opt} (no-wipe)`);
  }
  L.push('');

  // records
  const recs = [];
  for (const r of er) { recs.push(r.recordW, r.recordWo); }
  for (const r of none) recs.push(r.record);
  const valid = recs.filter((x) => x && x.ok);
  L.push('plugin records (plugin-on compiles)');
  L.push(`  valid ${valid.length}/${recs.length}`);
  const problemCounts = new Map();
  for (const x of recs) if (x && !x.ok) for (const p of x.problems) {
    const key = p.length > 100 ? p.slice(0, 100) + '...' : p;
    problemCounts.set(key, (problemCounts.get(key) || 0) + 1);
  }
  for (const [p, n] of [...problemCounts].sort((a, b) => b[1] - a[1] || cmp(a[0], b[0]))) L.push(`  refused: ${n} x ${p}`);
  const sum = (k, sub) => valid.reduce((n, x) => n + (x[sub][k] || 0), 0);
  L.push(`  pinned sites (sum of pinnedCount)      ${valid.reduce((n, x) => n + x.pinnedCount, 0)}`);
  L.push(`  would-pin sites (sum of wouldPinCount) ${valid.reduce((n, x) => n + x.wouldPinCount, 0)}`);
  for (const k of SEEN_KEYS) L.push(`  seen.${pad(k, 24)} ${sum(k, 'seen')}`);
  for (const k of UNHANDLED_KEYS) L.push(`  unhandled.${pad(k, 20)} ${sum(k, 'unhandled')}`);
  L.push(`  no-wipe files with pinnedCount > 0     ${none.filter((r) => (r.pinnedCount ?? 0) > 0).length}/${none.length}`);
  const absent = er.filter((r) => r.absentAfterAblation.length);
  L.push(`  helper resolved in w, not-in-module in wo (its only call was the ablated wipe; tolerated, not broken): ${absent.length} cell(s)`);
  L.push('');

  // attribution for RETAINED
  const ret = er.filter((r) => r.outcome === 'RETAINED');
  const weak = ret.filter((r) => !(r.pinDelta > 0));
  L.push('attribution of RETAINED cells');
  L.push(`  RETAINED ${ret.length}; the wipe-kept compile pinned more sites than the wipe-deleted one in ${ret.length - weak.length}`);
  for (const r of weak) L.push(`  WEAK ${r.id} ${r.opt}: pinDelta ${r.pinDelta}`);
  L.push('');

  // non-RETAINED among baseline-ELIMINATED
  const elim = er.filter((r) => r.baseline === ELIMINATED && r.outcome !== 'RETAINED');
  L.push(`baseline WIPE_ELIMINATED cells that are not RETAINED: ${elim.length}`);
  for (const r of elim) L.push(`  ${r.id} ${r.opt} ${r.outcome} -- ${r.outcomeReason}`);
  L.push('');

  // out of reach
  L.push('out of reach');
  L.push(`  ${authz.line}`);
  if (cfgNote) L.push(`  ${cfgNote}`);
  else {
    const c = (k, v) => cfg.filter((r) => r[k] === v).length;
    L.push(`  configguard: OUT_OF_REACH_PREPROCESS -- ${cfgSelection} at ${ccName} -O2, plugin in module scope`);
    L.push(`    default differs from enabled, re-observed plugin off   yes ${c('defaultDiffersReproduced', true)}, no ${c('defaultDiffersReproduced', false)}, undecided ${c('defaultDiffersReproduced', null)}`);
    L.push(`    plugin left the default target body unchanged           yes ${c('pluginLeftDefaultBodyUnchanged', true)}, no ${c('pluginLeftDefaultBodyUnchanged', false)}, undecided ${c('pluginLeftDefaultBodyUnchanged', null)}`);
    L.push(`    plugin made the default body equal the enabled body     yes ${c('pluginDefaultEqualsEnabled', true)}, no ${c('pluginDefaultEqualsEnabled', false)}, undecided ${c('pluginDefaultEqualsEnabled', null)}`);
    L.push(`    record valid ${c('recordOk', true)}/${cfg.length}, control PRESENT with the plugin ${c('controlOn', true)}/${cfg.length}`);
    for (const r of cfg.filter((x) => x.pluginLeftDefaultBodyUnchanged === false)) L.push(`    CHANGED ${r.id}: pinnedCount ${r.pinnedCount}`);
  }
  L.push(`  ${unsupportedVendorLine(tracked, 'gcc-13')}`);
  L.push(`  ${notAttemptedLine()}`);
  L.push('');
  return L.join('\n');
}

main().catch((e) => die(5, `unexpected failure: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`));

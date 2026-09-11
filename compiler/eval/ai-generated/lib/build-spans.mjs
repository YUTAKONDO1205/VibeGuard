#!/usr/bin/env node
/**
 * The per-span supplement to the find step, on the stock compilers.
 *
 * The find step's tracked erasure numbers (build-analyze.mjs -> r2-build-rows.json)
 * are cell-level: every wipe span of the target function is deleted at once, and
 * the two bodies are compared. That is the find step's criterion and it is not
 * changed here. But when a target body holds two zero-fills, deleting both can
 * change the code for a reason that has nothing to do with the wipe the reader
 * cares about -- an initialiser that matters, or a loop laid out differently --
 * so the cell reads WIPE_SURVIVED although the trailing wipe, deleted on its own,
 * changes nothing. The repair loop found 63 such clang-18 cells in 19 files
 * before this supplement looked at gcc-13.
 *
 * So, for every erasure file whose TRACKED rows show two or more wipe spans, for
 * each requested vendor and level:
 *
 *   w      the file as written                   (+ the positive control)
 *   wo     every span ablated                    -> cell   = verdictOf(w, wo)
 *   wo_i   only removable span i ablated         -> span_i = verdictOf(w, wo_i)
 *
 * with FLAGS, compile, pool, wipeSpans, spanPlan, ablateSpans, verdictOf and the
 * control imported from ./ablation-cell.mjs -- the find step's own code, not a
 * copy. `cell` is re-derived only to show that this run reproduces the tracked
 * verdict; the rows beside it are the supplement. A nonremovable span of a
 * multi-span file is listed and not ablated alone (spanPlan says why). A file
 * whose spans are all nonremovable gets rows and no compile: there is nothing to
 * ablate on its own.
 *
 * Every span also carries initialiserLike (./span-label.mjs), a lexical label
 * reported beside the verdict and never folded into it.
 *
 * Cross-check, per vendor, for every vendor whose repair rows file exists: each
 * span verdict here must equal the repair loop's plugin-off verdict for the same
 * (vendor, id, level, span index) wherever that loop measured the span alone
 * (spans[].off with source 'span'), and the two hiddenElimination flags must
 * agree. The files are the ones span-summary.mjs REPAIR_ROWS_FILES names --
 * ../../repair-loop/data/r2-repair-rows.json for clang-18 and
 * ../../repair-loop/data/r2-repair-rows-gcc-13.json for gcc-13 -- read as data;
 * no code of the repair loop is imported. A vendor without a file is printed as
 * not cross-checked and is never counted as held.
 *
 *   node build-spans.mjs --out <lab dir> [options]
 *
 * Nothing is written to the repository unless --write-data is given, and that is
 * refused for anything but the full run (every multi-span file, both vendors,
 * all five levels, the default input files) with every integrity check held and
 * both vendors cross-checked and held.
 *
 * Exit codes: 0 run complete and every check that could run held (a vendor with
 * no repair rows is reported as not cross-checked; that alone does not fail the
 * run, but it does refuse --write-data); 2 run complete, but a span count or
 * idiom disagreed with the tracked rows, a re-derived cell verdict disagreed with
 * the tracked one, a planned span was not measured, or a vendor's cross-check
 * failed (a mismatch, or no span compared at all while that vendor's spans were
 * measured) -- with --write-data, nothing is then written; 3 nothing selected;
 * 4 bad arguments, including --write-data with a subset or a non-default input
 * (refused before any compile); 5 a compiler could not be run, an input file
 * could not be read (a --repair-rows file that was named but is missing
 * included), or a text about to be written carried an absolute path.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CONTROL, wipeSpans, spanPlan, ablateSpans, compile, pool, verdictOf,
} from './ablation-cell.mjs';
import { initialiserLabels } from './span-label.mjs';
import {
  ALL_OPTS, VENDORS, REPAIR_ROWS_FILES, multiSpanFiles, trackedVerdicts, spanRow, integrityProblems,
  crossCheckRepairRows, crossCheckSummary, spansMeasuredAlone, parseRepairRowsArg,
  hiddenSummary, undercountLine, labelSummary, writeDataProblems, pathHits,
} from './span-summary.mjs';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const GEN = join(ROOT, 'generated-corpus', 'r2');
const SCEN_PATH = join(ROOT, 'scenarios.json');
const DEFAULT_ROWS = join(ROOT, 'data', 'r2-build-rows.json');
// Per vendor, the repair loop's tracked rows (span-summary.mjs REPAIR_ROWS_FILES).
const DEFAULT_REPAIR_ROWS = Object.fromEntries(VENDORS.map((cc) => [cc, resolve(HERE, REPAIR_ROWS_FILES[cc])]));
const DATA_OUT = join(ROOT, 'data', 'r2-span-rows.json');

const USAGE = `usage: node build-spans.mjs --out <dir> [options]

  --out <dir>            lab directory for the rows, results, manifest and build scratch (required)
  --cc <list>            comma list from ${VENDORS.join(' ')} (default: both)
  --opts <list>          comma list from ${ALL_OPTS.join(' ')} (default: all five)
  --files <list>         comma list of basenames or globs (* ?), with or without .c
  --rows <path>          the find step's tracked rows (default: ../data/r2-build-rows.json)
  --repair-rows <cc>=<path>[,<cc>=<path>]
                         the repair loop's rows to cross-check a vendor against, instead of its
                         default (${VENDORS.map((cc) => `${cc}: ${REPAIR_ROWS_FILES[cc]}`).join(', ')});
                         a vendor whose default file does not exist is not cross-checked
  --conc <n>             parallel cells (default 4)
  --write-data           also write data/r2-span-rows.json (refused for anything but the full run)
`;

function die(code, msg) {
  process.stderr.write(`build-spans: ${msg}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const a = { out: null, ccs: [...VENDORS], opts: [...ALL_OPTS], files: null, rows: DEFAULT_ROWS,
    repairRows: { ...DEFAULT_REPAIR_ROWS }, repairRowsGiven: {}, conc: 4, writeData: false };
  const need = (i, flag) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${flag} needs a value`); return argv[i + 1]; };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--out': a.out = need(i, f); i++; break;
      case '--cc': a.ccs = list(need(i, f)); i++; break;
      case '--opts': a.opts = list(need(i, f)); i++; break;
      case '--files': a.files = list(need(i, f)); i++; break;
      case '--rows': a.rows = need(i, f); i++; break;
      case '--repair-rows': {
        const p = parseRepairRowsArg(need(i, f)); i++;
        if (p.problems.length) die(4, `--repair-rows: ${p.problems.join('; ')}`);
        Object.assign(a.repairRowsGiven, p.given);
        break;
      }
      case '--conc': a.conc = Number(need(i, f)); i++; break;
      case '--write-data': a.writeData = true; break;
      case '-h': case '--help': process.stdout.write(USAGE); process.exit(0); break;
      default: die(4, `unknown argument ${f}\n${USAGE}`);
    }
  }
  if (!a.out) die(4, '--out is required: rows and build scratch go to a lab directory outside the repository');
  for (const c of a.ccs) if (!VENDORS.includes(c)) die(4, `--cc: ${c} is not one of ${VENDORS.join(' ')}`);
  for (const o of a.opts) if (!ALL_OPTS.includes(o)) die(4, `--opts: ${o} is not one of ${ALL_OPTS.join(' ')}`);
  if (!a.ccs.length) die(4, '--cc is empty');
  if (!a.opts.length) die(4, '--opts is empty');
  a.ccs = VENDORS.filter((c) => a.ccs.includes(c));
  a.opts = ALL_OPTS.filter((o) => a.opts.includes(o));
  if (!Number.isInteger(a.conc) || a.conc < 1) die(4, '--conc must be a positive integer');
  a.out = resolve(a.out);
  a.rows = resolve(a.rows);
  for (const [cc, p] of Object.entries(a.repairRowsGiven)) a.repairRows[cc] = resolve(p);
  a.repairRowsIsDefault = VENDORS.every((cc) => a.repairRows[cc] === DEFAULT_REPAIR_ROWS[cc]);
  // What the arguments alone rule out is refused before any compile; what the
  // run finds (integrity, the cross-check) is refused after it.
  if (a.writeData) {
    const why = writeDataProblems({ files: a.files, vendors: a.ccs, opts: a.opts,
      rowsIsDefault: a.rows === DEFAULT_ROWS, repairRowsIsDefault: a.repairRowsIsDefault, integrity: [], crossCheck: null });
    if (why.length) die(4, `--write-data refused with ${why.join(', ')}: data/r2-span-rows.json is the full run over the default inputs`);
  }
  return a;
}

function globToRe(g) {
  const s = g.replace(/\.c$/, '').replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp('^' + s + '$');
}

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function readJson(path, what) {
  try { return { text: readFileSync(path), json: JSON.parse(readFileSync(path, 'utf8')) }; }
  catch { die(5, `${what} could not be read as JSON`); }
  return null;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const versions = {};
  for (const cc of args.ccs) {
    try { versions[cc] = (await run(cc, ['--version'], { timeout: 30000 })).stdout.split('\n')[0].trim(); }
    catch { die(5, `${cc} --version failed: the compiler is not runnable here`); }
  }

  const scen = JSON.parse(readFileSync(SCEN_PATH, 'utf8'));
  const trackedIn = readJson(args.rows, 'the --rows file');
  const tracked = trackedIn.json;
  // Per selected vendor: its repair rows, or null when its DEFAULT file does not
  // exist (then it is printed as not cross-checked, never as held). A file that
  // exists but cannot be read, or one named with --repair-rows that does not
  // exist, stops the run here rather than printing results that were never checked.
  const repairIn = {};
  for (const cc of args.ccs) {
    const p = args.repairRows[cc];
    if (!(cc in args.repairRowsGiven) && !existsSync(p)) { repairIn[cc] = null; continue; }
    repairIn[cc] = readJson(p, `the ${cc} repair rows file`);
  }

  const { files: multi, problems: trackedProblems } = multiSpanFiles(tracked);
  const tv = trackedVerdicts(tracked);
  const res = args.files ? args.files.map(globToRe) : null;
  const selected = [...multi.keys()].filter((id) => !res || res.some((re) => re.test(id)));
  if (!selected.length) die(3, 'no multi-span erasure file was selected; nothing was measured');

  const BUILD = join(args.out, 'build');
  mkdirSync(BUILD, { recursive: true });

  // ---- prepare sources; the span count must be the tracked one ----------------
  const integrity = trackedProblems.map((id) => `TRACKED ROWS DISAGREE ${id}: n_spans or idiom differs between its rows`);
  const units = [];
  for (const id of selected) {
    const [model, framing, sc, rep] = id.split('_');
    const meta = { id, model, framing, scen: sc, rep, fn: scen[sc] && scen[sc].fn };
    if (!meta.fn || scen[sc].fam !== 'erasure') { integrity.push(`NOT AN ERASURE FILE ${id}`); continue; }
    const src = readFileSync(join(GEN, `${id}.c`), 'utf8');
    const ws = wipeSpans(src, meta.fn);
    const want = multi.get(id);
    const idiom = ws.kinds.includes('removable') && ws.kinds.includes('nonremovable') ? 'both'
      : ws.kinds.includes('removable') ? 'removable' : 'nonremovable';
    if (ws.spans.length !== want.nSpans || idiom !== want.idiom) {
      integrity.push(`SPANS DISAGREE ${id}: tracked ${want.nSpans} span(s) ${want.idiom}, found ${ws.spans.length} ${idiom}`);
      continue;
    }
    const plan = spanPlan(ws.kinds);
    const labels = initialiserLabels(src, meta.fn, ws.spans);
    const toMeasure = plan.filter((p) => p.source === 'span');
    const paths = { w: join(BUILD, `${id}.w.c`), wo: join(BUILD, `${id}.wo.c`), span: {} };
    if (toMeasure.length) {
      writeFileSync(paths.w, src + CONTROL, 'utf8');
      writeFileSync(paths.wo, ablateSpans(src, ws.spans) + CONTROL, 'utf8');
      for (const p of toMeasure) {
        paths.span[p.index] = join(BUILD, `${id}.wo${p.index}.c`);
        writeFileSync(paths.span[p.index], ablateSpans(src, [ws.spans[p.index]]) + CONTROL, 'utf8');
      }
    }
    for (const cc of args.ccs) for (const opt of args.opts) {
      units.push({ meta, cc, opt, idiom, nSpans: ws.spans.length, plan, labels, toMeasure, paths });
    }
  }
  const spanPairs = units.reduce((n, u) => n + u.toMeasure.length, 0);
  process.stderr.write(`${selected.length} multi-span file(s), ${units.length} cell(s), ${spanPairs} per-span compile(s) `
    + `plus ${units.filter((u) => u.toMeasure.length).length * 2} cell compile(s); cc ${args.ccs.join(' ')}; opts ${args.opts.join(' ')}\n`);

  // ---- compile ------------------------------------------------------------------
  const asm = (id, cc, opt, side) => join(BUILD, `${id}.${cc}${opt}.${side}.s`);
  let done = 0;
  const rows = await pool(units, async (u) => {
    const { meta, cc, opt } = u;
    let cell = null;
    const measured = {};
    if (u.toMeasure.length) {
      const aW = await compile(cc, [opt], u.paths.w, asm(meta.id, cc, opt, 'w'));
      const aWo = await compile(cc, [opt], u.paths.wo, asm(meta.id, cc, opt, 'wo'));
      cell = verdictOf(aW, aWo, meta.fn);
      for (const p of u.toMeasure) {
        const aS = await compile(cc, [opt], u.paths.span[p.index], asm(meta.id, cc, opt, `wo${p.index}`));
        measured[p.index] = verdictOf(aW, aS, meta.fn);
      }
    }
    if (++done % 100 === 0) process.stderr.write(`  ${done} cells\n`);
    return spanRow({ meta, cc, opt, idiom: u.idiom, nSpans: u.nSpans, plan: u.plan, labels: u.labels, cell, measured,
      trackedVerdict: tv.get(`${meta.id}|${cc}|${opt}`) });
  }, args.conc);
  rows.sort((a, b) => cmp(a.id, b.id) || cmp(a.cc, b.cc) || cmp(ALL_OPTS.indexOf(a.opt), ALL_OPTS.indexOf(b.opt)));
  integrity.push(...integrityProblems(rows));

  // ---- cross-check against the repair loop, per vendor ---------------------------
  const perVendor = {};
  const measuredAlone = {};
  for (const cc of args.ccs) {
    measuredAlone[cc] = spansMeasuredAlone(rows, cc);
    perVendor[cc] = repairIn[cc] ? crossCheckRepairRows(rows, repairIn[cc].json, cc) : null;
  }
  const cross = crossCheckSummary(perVendor, measuredAlone);

  // ---- the lexical label over every erasure file (no compile) -------------------
  const labelFiles = [];
  for (const f of readdirSync(GEN).filter((x) => x.endsWith('.c')).sort()) {
    const id = f.replace(/\.c$/, '');
    const m = scen[id.split('_')[2]];
    if (!m || m.fam !== 'erasure') continue;
    const src = readFileSync(join(GEN, f), 'utf8');
    const ws = wipeSpans(src, m.fn);
    if (!ws.spans.length) continue;
    labelFiles.push({ id, kinds: ws.kinds, labels: initialiserLabels(src, m.fn, ws.spans) });
  }
  const labels = labelSummary(labelFiles);

  // ---- results --------------------------------------------------------------------
  const hidden = hiddenSummary(tracked, rows, { vendors: args.ccs, opts: args.opts });
  const label = (p, def) => (p === def ? '(default)' : '(given)');
  const L = [];
  L.push('per-span supplement (build-spans.mjs): each removable span of a multi-span file ablated alone, same verdictOf, same FLAGS');
  L.push('tracked cell verdicts unchanged; this is a second measurement beside them');
  L.push('');
  for (const cc of args.ccs) L.push(`compiler        ${cc}  (${versions[cc]})`);
  L.push(`opts            ${args.opts.join(' ')}`);
  L.push(`file subset     ${args.files ? args.files.join(',') : `(all ${multi.size} multi-span files)`}`);
  L.push(`tracked rows    ${label(args.rows, DEFAULT_ROWS)} sha256 ${sha256(trackedIn.text)}`);
  for (const cc of args.ccs) {
    L.push(`repair rows     ${cc} ${repairIn[cc] ? `${label(args.repairRows[cc], DEFAULT_REPAIR_ROWS[cc])} sha256 ${sha256(repairIn[cc].text)}` : '(none: no repair rows file)'}`);
  }
  L.push(`cells           ${rows.length} (${rows.filter((r) => r.measured).length} measured; the rest have no removable span to ablate alone)`);
  L.push(`per-span verdicts ${rows.reduce((n, r) => n + r.spans.filter((s) => s.source === 'span' && s.off !== null).length, 0)}`);
  L.push('');
  L.push('integrity (span count and idiom against the tracked rows; the cell verdict re-derived against the tracked one)');
  const cellCmp = rows.filter((r) => r.cellMatchesTracked !== null);
  L.push(`  cell verdicts   ${cellCmp.filter((r) => r.cellMatchesTracked).length}/${cellCmp.length} agree with the tracked rows`);
  for (const p of integrity) L.push(`  ${p}`);
  if (!integrity.length) L.push('  held');
  L.push('');
  L.push('cross-check against the repair loop\'s plugin-off per-span verdicts (per vendor, spans that loop measured alone)');
  for (const v of cross.vendors) {
    if (v.status === 'not-cross-checked') {
      L.push(`  ${v.cc}  not cross-checked (no repair rows)`);
      continue;
    }
    const c = v.cross;
    L.push(`  ${v.cc}  span verdicts compared ${c.compared}, agree ${c.agreed}, not compared ${c.notCompared}; `
      + `hiddenElimination compared ${c.hiddenCompared}, disagree ${c.hiddenMismatches.length}`);
    for (const m of c.mismatches) L.push(`    MISMATCH ${m.id} ${m.opt} span ${m.index}: here ${m.ours}, repair rows ${m.theirs}${m.kinds ? ` (kind ${m.kinds.join(' vs ')})` : ''}`);
    for (const m of c.hiddenMismatches) L.push(`    HIDDEN MISMATCH ${m.id} ${m.opt}: here ${m.ours}, repair rows ${m.theirs}`);
    if (v.vacuous) L.push(`    VACUOUS: ${v.cc} spans were measured but none could be compared`);
    L.push(`    ${v.status === 'failed' ? `FAILED (ids: ${c.ids.join(' ') || '-'})` : 'held'}`);
  }
  L.push(`  held for ${cross.held.length} of ${cross.vendors.length} vendor(s)${cross.held.length ? ` (${cross.held.join(', ')})` : ''}`
    + `${cross.failed.length ? `; FAILED for ${cross.failed.join(', ')}` : ''}`
    + `${cross.notChecked.length ? `; not cross-checked: ${cross.notChecked.join(', ')}` : ''}`);
  L.push('');
  L.push('hidden eliminations: tracked WIPE_SURVIVED cells in which a removable span, ablated alone, is WIPE_ELIMINATED');
  for (const h of hidden) {
    const idi = Object.entries(h.hiddenByIdiom).map(([k, v]) => `${k} ${v}`).join(', ');
    L.push(`  ${h.cc} ${h.opt}  ${h.hidden} of ${h.survivedCells} measured SURVIVED multi-span cells${idi ? ` (${idi})` : ''}`
      + `; in ${h.hiddenOnlyInitialiserLike} of them every eliminated span is itself initialiser-like`);
    for (const x of h.hiddenIds) {
      L.push(`    HIDDEN ${x.id} [${x.idiom}] span(s) ${x.spans.join(',')}`
        + `${x.eliminatedInitialiserLike.length ? `; eliminated span(s) ${x.eliminatedInitialiserLike.join(',')} initialiser-like` : ''}`
        + `${x.initialiserLikeElsewhere ? '; another span is initialiser-like' : ''}`);
    }
  }
  L.push('');
  L.push('the undercount, one line per vendor and level (the tracked count is over the whole erasure family)');
  for (const h of hidden) L.push(`  ${undercountLine(h)}`);
  L.push('');
  L.push(`initialiserLike (lexical, reported beside verdicts, never folded in) over every erasure file with a wipe span: ${labels.files} files, ${labels.spans} spans`);
  for (const [k, v] of Object.entries(labels.counts).sort()) L.push(`  ${k.padEnd(20)} ${v}`);
  L.push(`  one-span files whose only span is initialiser-like (their cell verdict is about that span): ${labels.oneSpanInit.length}`);
  for (const id of labels.oneSpanInit) L.push(`    ${id}`);
  const multiInit = rows.filter((r) => r.opt === args.opts[0] && r.cc === args.ccs[0])
    .reduce((n, r) => n + r.spans.filter((s) => s.kind === 'removable' && s.initialiserLike === true).length, 0);
  L.push(`  removable spans of the selected multi-span files labelled initialiser-like: ${multiInit}`);
  L.push('');
  const text = L.join('\n');

  const rowsText = '[\n' + rows.map((r) => JSON.stringify(r)).join(',\n') + '\n]\n';
  const manifestText = JSON.stringify({
    generatedAt: new Date().toISOString(), node: process.version, versions,
    ccs: args.ccs, opts: args.opts, files: args.files, conc: args.conc,
    rowsFile: label(args.rows, DEFAULT_ROWS), rowsSha256: sha256(trackedIn.text),
    repairRows: Object.fromEntries(args.ccs.map((cc) => [cc, repairIn[cc]
      ? { file: label(args.repairRows[cc], DEFAULT_REPAIR_ROWS[cc]), sha256: sha256(repairIn[cc].text) } : null])),
    crossCheck: { held: cross.held, failed: cross.failed, notCrossChecked: cross.notChecked },
    multiSpanFiles: multi.size, selectedFiles: selected.length, cells: rows.length, perSpanCompiles: spanPairs,
  }, null, 2) + '\n';

  const hits = [];
  for (const [name, t] of [['r2-span-rows.json', rowsText], ['r2-span-results.txt', text], ['manifest.json', manifestText]]) {
    const h = pathHits(t);
    if (h.length) hits.push(`${name}: ${h.join(', ')}`);
  }
  writeFileSync(join(args.out, 'r2-span-rows.json'), rowsText, 'utf8');
  writeFileSync(join(args.out, 'r2-span-results.txt'), text, 'utf8');
  writeFileSync(join(args.out, 'manifest.json'), manifestText, 'utf8');
  process.stdout.write(text + '\n');
  if (hits.length) die(5, `an absolute path would be written (${hits.join('; ')}); nothing was written to data/`);

  const crossFailed = cross.failed.length > 0;
  if (args.writeData) {
    const why = writeDataProblems({ files: args.files, vendors: args.ccs, opts: args.opts,
      rowsIsDefault: args.rows === DEFAULT_ROWS, repairRowsIsDefault: args.repairRowsIsDefault,
      integrity, crossCheck: cross });
    if (why.length) die(2, `--write-data refused with ${why.join(', ')}: data/r2-span-rows.json is the full run, checked`);
    if (!existsSync(dirname(DATA_OUT))) die(5, 'the data directory is missing');
    writeFileSync(DATA_OUT, rowsText, 'utf8');
    process.stderr.write(`wrote ${rows.length} rows to data/r2-span-rows.json\n`);
  }
  process.exit(integrity.length || crossFailed ? 2 : 0);
}

main().catch((e) => die(5, `unexpected failure: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`));

#!/usr/bin/env node
/**
 * Replay the r6b auto-loop's choice of repair method, without a compiler.
 *
 * The r6b loop (a lab tool outside this tree; README.md, *Choosing the next
 * method*) compiled each eliminated cell with a repair method, read the result
 * with the find step's verdictOf, and when the wipe was still eliminated chose
 * the next method from the plugin record's `unhandled` counters. Every choice it
 * made, and why, is in the loop JSON it wrote. This tool re-makes every one of
 * those choices with the pure functions of ./lib/select-method.mjs and the
 * method set copied into ./select-method.r6b.json, from what the row itself
 * kept (the stage, the shapes, each attempt's verdict and record summary), and
 * lists every row whose choices or outcome differ. It never compiles, never
 * reads a record file and never decides survival: the verdicts it replays over
 * are the loop's own.
 *
 *   node select-method.mjs --check <loop.json> [--check <loop.json> ...] [--out <file.json>]
 *       replay every row of each loop file with the table that file names
 *   node select-method.mjs --learn <loop.json> [--from cold] [--expect learned] [--out <file.json>]
 *       re-derive the rows the table gained from that run (learnRows, r6b's
 *       learn.py) and compare them with the table --expect names
 *   node select-method.mjs --select --cc <cc> [--cond L2] [--stage <cls>] [--shapes a,b]
 *                          [--table learned] [--tried m1,m2] [--unhandled <json>]
 *       one choice, printed as JSON: the method to try next, or a route
 *
 * --set <json> replaces the copied set (default ./select-method.r6b.json).
 * --out writes the summary as JSON, outside the repository only; there is no
 * --write-data.
 *
 * Exit status: 0 every row replayed agrees (or the learned rows match, or a
 * choice was printed); 2 at least one row differs, or a learned row differs,
 * and each is listed (findings, section 7 of compiler/schema/interfaces.md; not
 * 1, which is a tool that failed); 4 bad arguments; 5 an input could not be used (a file
 * that does not parse, a set that does not validate, a loop file that used a
 * table or a plugin build the set does not hold).
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, resolve, join, basename, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { insideRepo } from './lib/lto.mjs';
import { validateSet, compareLoopRow, learnRows, selectMethod, CONDS } from './lib/select-method.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..', '..', '..');
const DEFAULT_SET = join(HERE, 'select-method.r6b.json');
const SHOW = 20;

const USAGE = `usage:
  node select-method.mjs --check <loop.json> [--check <loop.json> ...] [--set <json>] [--out <file.json>]
  node select-method.mjs --learn <loop.json> [--from cold] [--expect learned] [--set <json>] [--out <file.json>]
  node select-method.mjs --select --cc <cc> [--cond L2] [--stage <cls>] [--shapes a,b] [--table learned]
                         [--tried m1,m2] [--unhandled <json>] [--set <json>]

Nothing is compiled. --out lies outside the repository; there is no --write-data.
`;

function die(code, msg) {
  process.stderr.write(`select-method: ${msg}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const a = { check: [], learn: null, select: false, set: DEFAULT_SET, out: null, from: 'cold', expect: 'learned',
    cc: null, cond: 'L2', stage: null, shapes: [], table: null, tried: [], unhandled: null };
  const need = (i, flag) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${flag} needs a value`); return argv[i + 1]; };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--check': a.check.push(need(i, f)); i++; break;
      case '--learn': a.learn = need(i, f); i++; break;
      case '--select': a.select = true; break;
      case '--set': a.set = need(i, f); i++; break;
      case '--out': a.out = need(i, f); i++; break;
      case '--from': a.from = need(i, f); i++; break;
      case '--expect': a.expect = need(i, f); i++; break;
      case '--cc': a.cc = need(i, f); i++; break;
      case '--cond': a.cond = need(i, f); i++; break;
      case '--stage': a.stage = need(i, f); i++; break;
      case '--shapes': a.shapes = list(need(i, f)); i++; break;
      case '--table': a.table = need(i, f); i++; break;
      case '--tried': a.tried = list(need(i, f)); i++; break;
      case '--unhandled': a.unhandled = need(i, f); i++; break;
      case '--write-data': die(4, '--write-data does not exist here: this tool reads lab files and writes nothing in the tree'); break;
      case '-h': case '--help': process.stdout.write(USAGE); process.exit(0); break;
      default: die(4, `unknown argument ${f}\n${USAGE}`);
    }
  }
  const modes = [a.check.length > 0, a.learn !== null, a.select].filter(Boolean).length;
  if (modes !== 1) die(4, `name exactly one of --check, --learn, --select\n${USAGE}`);
  if (a.select && !a.cc) die(4, '--select needs --cc');
  if (a.select && !CONDS.includes(a.cond)) die(4, `--cond ${a.cond} is not one of ${CONDS.join(', ')}`);
  if (a.out) {
    a.out = resolve(a.out);
    if (insideRepo(a.out, REPO, sep)) die(4, '--out lies inside the repository; this tool writes lab output only');
  }
  return a;
}

function readJson(p, what) {
  if (!existsSync(p)) die(5, `${what} ${p} does not exist`);
  try { return JSON.parse(readFileSync(p, 'utf8')); } catch (e) { die(5, `${what} ${p} does not parse: ${e.message}`); }
  return null;
}

/** The copied file entry for a table, which carries the sha16 the loop records name it by. */
function tableEntry(set, name) {
  return (set.copiedFrom?.files ?? []).find((f) => f.file === `table-${name}.json`) ?? null;
}

/**
 * The digest of what a table row decides: the first 16 hex digits of SHA-256
 * over JSON.stringify of [cc, stage, shape, method] for each row, in order --
 * the four fields fromTable() reads. The loop's own digest (loopSha16) is over
 * the whole original file, untranslated, so the English copy cannot re-derive
 * it; this one it can. The copy records it as computed from the original file
 * (copiedFrom.files[].selectionSha16), and loopFileProblems() recomputes it from
 * the copied rows, so a row dropped, added, reordered or changed in the copy is
 * a refusal (exit 5) rather than a replay that disagrees.
 */
export function tableSelectionSha16(table) {
  const rows = Array.isArray(table?.rows) ? table.rows : [];
  return createHash('sha256').update(JSON.stringify(rows.map((r) => [r.cc, r.stage, r.shape, r.method]))).digest('hex').slice(0, 16);
}

/**
 * Is this loop file one the set can replay? The table it names must be one the
 * set holds, by name and by the digest the loop recorded; the set's copy of that
 * table must still choose what the file it was copied from chose (its rows'
 * selectionSha16, recomputed here); and every plugin build the loop lists must
 * be the one the set's method of that name was copied with.
 */
export function loopFileProblems(doc, set) {
  const p = [];
  if (!doc || !Array.isArray(doc.rows)) return ['the file has no rows[]'];
  const name = doc.table?.name;
  if (!name || !set.tables?.[name]) p.push(`it used table ${JSON.stringify(name)}, which the set does not hold`);
  else {
    const e = tableEntry(set, name);
    if (!e || e.loopSha16 !== doc.table.sha16) {
      p.push(`it used a table named ${name} with digest ${doc.table.sha16}; the set's copy is ${e?.loopSha16 ?? '(none recorded)'}`);
    }
    const got = tableSelectionSha16(set.tables[name]);
    if (!e || e.selectionSha16 !== got) {
      p.push(`the set's copy of table ${name} chooses by rows with selection digest ${got}; `
        + `the file it was copied from had ${e?.selectionSha16 ?? '(none recorded)'}`);
    }
  }
  for (const [m, sha] of Object.entries(doc.methods ?? {})) {
    if (!set.methods[m]) p.push(`it lists method ${m}, which the set does not hold`);
    else if (set.methods[m].pluginSha16 !== sha) p.push(`its method ${m} is plugin build ${sha}; the set's is ${set.methods[m].pluginSha16}`);
  }
  return p;
}

/** Replay every row of one loop file. Rows the loop could not run (EXCEPTION) are counted apart, never compared. */
export function checkLoopDoc(doc, set) {
  const table = set.tables[doc.table.name];
  const out = { table: doc.table.name, rows: doc.rows.length, compared: 0, agree: 0, differ: 0, notCompared: 0,
    byCondOutcome: {}, differences: [], notComparedRows: [] };
  for (const r of doc.rows) {
    const where = { id: r.id, cc: r.cc, cfg: r.cfg, cond: r.cond };
    if (r.outcome === 'EXCEPTION' || !Array.isArray(r.iters)) {
      out.notCompared++;
      out.notComparedRows.push({ ...where, outcome: r.outcome ?? null, message: r.message ?? null });
      continue;
    }
    out.compared++;
    const k = `${r.cond}.${r.outcome}`;
    out.byCondOutcome[k] = (out.byCondOutcome[k] ?? 0) + 1;
    const diff = compareLoopRow(r, { set, table });
    if (diff.length) { out.differ++; out.differences.push({ ...where, diff }); } else out.agree++;
  }
  return out;
}

function runCheck(a, set) {
  const files = [];
  let anyDiffer = false;
  for (const f of a.check) {
    const p = resolve(f);
    const doc = readJson(p, 'loop file');
    const problems = loopFileProblems(doc, set);
    if (problems.length) die(5, `${p}: cannot be replayed with this set: ${problems.join('; ')}`);
    const r = checkLoopDoc(doc, set);
    anyDiffer ||= r.differ > 0;
    files.push({ file: basename(p), sha256: createHash('sha256').update(readFileSync(p)).digest('hex'), ...r });
    process.stdout.write(`${basename(p)}  table ${r.table}  rows ${r.rows}  compared ${r.compared}  agree ${r.agree}  differ ${r.differ}`
      + `  not compared ${r.notCompared}\n`);
    process.stdout.write(`  by cond.outcome ${JSON.stringify(Object.fromEntries(Object.entries(r.byCondOutcome).sort()))}\n`);
    for (const d of r.differences.slice(0, SHOW)) process.stdout.write(`  DIFFERS ${d.id} ${d.cc} ${d.cfg} ${d.cond}: ${d.diff.join(' | ')}\n`);
    if (r.differences.length > SHOW) process.stdout.write(`  ... and ${r.differences.length - SHOW} more (all are in --out)\n`);
    for (const n of r.notComparedRows.slice(0, SHOW)) process.stdout.write(`  NOT COMPARED ${n.id} ${n.cc} ${n.cfg} ${n.cond}: ${n.outcome}\n`);
  }
  const total = files.reduce((s, f) => ({ rows: s.rows + f.rows, agree: s.agree + f.agree, differ: s.differ + f.differ,
    notCompared: s.notCompared + f.notCompared }), { rows: 0, agree: 0, differ: 0, notCompared: 0 });
  process.stdout.write(`total  rows ${total.rows}  agree ${total.agree}  differ ${total.differ}  not compared ${total.notCompared}\n`);
  return { mode: 'check', files, total, exit: anyDiffer ? 2 : 0 };
}

function runLearn(a, set) {
  const p = resolve(a.learn);
  const doc = readJson(p, 'loop file');
  const from = set.tables?.[a.from];
  const expect = set.tables?.[a.expect];
  if (!from) die(4, `--from ${a.from}: the set has no such table`);
  if (!expect) die(4, `--expect ${a.expect}: the set has no such table`);
  if (doc.table?.name !== a.from) die(5, `${basename(p)} ran with table ${JSON.stringify(doc.table?.name)}, not ${a.from}`);
  const problems = loopFileProblems(doc, set);
  if (problems.length) die(5, `${p}: cannot be replayed with this set: ${problems.join('; ')}`);
  const got = learnRows(doc.rows, from, (g) => `${basename(p)}: ${g.rows.length} cell(s)`);
  const key = (r) => [r.cc, r.stage, r.shape, r.method].join('|');
  const want = expect.rows.filter((r) => !from.rows.some((c) => key(c) === key(r))).map(key);
  const have = got.adopted.map(key);
  const missing = want.filter((k) => !have.includes(k));
  const extra = have.filter((k) => !want.includes(k));
  const orderSame = missing.length === 0 && extra.length === 0 && want.every((k, i) => have[i] === k);
  process.stdout.write(`${basename(p)}  from ${a.from} (${from.rows.length} rows)  adopted ${got.adopted.length}  expected ${want.length}`
    + `  missing ${missing.length}  extra ${extra.length}  same order ${orderSame}\n`);
  for (const c of got.considered) {
    process.stdout.write(`  ${c.adopted ? 'ADOPTED    ' : 'not adopted'} ${c.cc} ${c.stage} ${c.shapes.join('+') || '(no shape)'}`
      + `  cells ${c.cells}  ${JSON.stringify(c.outcomes)}${c.adopted ? ` -> ${c.adopted}` : ''}\n`);
  }
  for (const k of missing) process.stdout.write(`  MISSING ${k}\n`);
  for (const k of extra) process.stdout.write(`  EXTRA ${k}\n`);
  return { mode: 'learn', file: basename(p), from: a.from, expect: a.expect, adopted: got.adopted, considered: got.considered,
    missing, extra, orderSame, exit: missing.length || extra.length || !orderSame ? 2 : 0 };
}

function runSelect(a, set) {
  const table = a.table ? set.tables?.[a.table] : null;
  if (a.table && !table) die(4, `--table ${a.table}: the set has no such table`);
  let record = null;
  if (a.unhandled !== null) {
    try { record = { pinnedCount: null, unhandled: JSON.parse(a.unhandled) }; } catch (e) { die(4, `--unhandled does not parse as JSON: ${e.message}`); }
  }
  for (const m of a.tried) if (!set.methods[m]) die(4, `--tried ${m}: the set has no such method`);
  const stage = a.stage ? { cls: a.stage } : null;
  const choice = selectMethod({ set, table, cc: a.cc, cond: a.cond, stage, shapes: a.shapes, record, tried: a.tried });
  process.stdout.write(`${JSON.stringify(choice)}\n`);
  return { mode: 'select', choice, exit: 0 };
}

function main() {
  const a = parseArgs(process.argv.slice(2));
  const set = readJson(resolve(a.set), 'method set');
  const sp = validateSet(set);
  if (sp.length) die(5, `the method set does not validate: ${sp.join('; ')}`);
  // Every table in the set records the digest the loop files name it by. The
  // copy itself does not hash to it (its evidence strings were translated), so
  // what ties a loop file to a table is that recorded digest, checked per file.
  for (const name of Object.keys(set.tables ?? {})) {
    const e = tableEntry(set, name);
    if (!e) die(5, `the set holds table ${name} but records no copied file for it`);
  }
  const res = a.check.length ? runCheck(a, set) : a.learn ? runLearn(a, set) : runSelect(a, set);
  if (a.out) {
    const { exit, ...body } = res;
    writeFileSync(a.out, `${JSON.stringify({ schema: 'select-method-check-v1', set: basename(resolve(a.set)), ...body }, null, 1)}\n`);
  }
  process.exit(res.exit);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();

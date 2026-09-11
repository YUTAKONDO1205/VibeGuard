#!/usr/bin/env node
/**
 * Does _FORTIFY_SOURCE move an erasure verdict?
 *
 * Ubuntu's gcc-13 predefines _FORTIFY_SOURCE=3 whenever it optimises; clang-18
 * predefines nothing. FLAGS does not equalise that, so every gcc-13 erasure cell
 * at -O1 and above was built with glibc's fortifying headers. This script is the
 * measurement behind the README's sentence about it, made from the tree:
 *
 * For every erasure file with a wipe span, for one --cc and each level of --opts,
 * two cells with the find step's own code (wipeSpans, ablateSpans, compile,
 * verdictOf, the positive control -- imported from ./ablation-cell.mjs, not
 * copied):
 *
 *   default      w and wo compiled with FLAGS + <opt>           -> verdictOf
 *   no fortify   w and wo compiled with FLAGS + <opt> + NO_FORTIFY -> verdictOf
 *
 * where NO_FORTIFY (-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0) is added to BOTH
 * compiles. The default verdict is compared with the tracked find-step row for
 * the same (id, cc, opt) -- it has to re-derive it, or the comparison below is
 * about some other build -- and the no-fortify verdict with the default one.
 * Also printed, per level: what the compiler predefines about FORTIFY with
 * FLAGS (`-dM -E`; -E wins over the -S in FLAGS), with and without NO_FORTIFY.
 *
 *   node fortify-check.mjs --cc gcc-13 --opts -O1,-O2,-O3,-Os --out <lab dir> [--files <globs>] [--conc 8]
 *
 * Output goes to the lab directory only (fortify-check.json, fortify-check.txt,
 * build scratch); an --out inside the repository is refused. Nothing is written
 * to data/.
 *
 * Exit codes: 0 complete, and the default build re-derived the tracked verdict
 * in every cell; 2 complete, but a default verdict disagreed with the tracked
 * row, or a cell has no tracked row; 3 nothing selected; 4 bad arguments; 5 the
 * compiler could not be run or the tracked rows could not be read.
 *
 * The pure parts (the defines reading, the per-level summary, the exit code)
 * are exported and tested in ../test/fortify-check.test.mjs; main() runs only
 * when this file is executed.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { dirname, resolve, join, relative, isAbsolute } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { FLAGS, CONTROL, wipeSpans, ablateSpans, compile, pool, verdictOf } from './ablation-cell.mjs';

export const NO_FORTIFY = Object.freeze(['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=0']);
export const ALL_OPTS = Object.freeze(['-O0', '-O1', '-O2', '-O3', '-Os']);
export const CCS = Object.freeze(['clang-18', 'gcc-13']);

// ---------------------------------------------------------------- pure --------

/**
 * The `#define` lines of a `-dM -E` listing whose macro name mentions FORTIFY,
 * sorted, CRs dropped. Empty when there are none (clang-18 predefines none).
 */
export function fortifyDefines(text) {
  if (typeof text !== 'string') return [];
  return text.split('\n').map((l) => l.replace(/\r$/, '').trimEnd())
    .filter((l) => /^#define[ \t]+\w*FORTIFY\w*\b/.test(l)).sort();
}

/** The value `_FORTIFY_SOURCE` is defined to ('' for a bare definition), or null when it is not defined. */
export function fortifyValue(text) {
  if (typeof text !== 'string') return null;
  const m = /^#define[ \t]+_FORTIFY_SOURCE(?:[ \t]+([^\r\n]*?))?[ \t]*\r?$/m.exec(text);
  if (!m) return null;
  return m[1] ?? '';
}

/**
 * A listing with its local labels (`.L<letters><digits>`: .L3, .LC0, .LFB15,
 * ...) renamed in order of first appearance. gcc numbers them across the whole
 * unit, so a header that adds or drops an inline function renumbers every
 * later label without changing one instruction; comparing renamed listings
 * separates that from a change in the code.
 */
export function labelsRenamed(text) {
  if (typeof text !== 'string') return text;
  const names = new Map();
  return text.replace(/\.L[A-Za-z_]*\d+\b/g, (m) => {
    if (!names.has(m)) names.set(m, `.L#${names.size}`);
    return names.get(m);
  });
}

/**
 * One row per (file, level).
 * @param tracked  the tracked verdict for (id, cc, opt), or undefined when there is none
 */
export function fortifyRow({ id, cc, opt, tracked, dflt, noFortify, wListingChanged = null, wCodeChanged = null }) {
  const t = tracked ?? null;
  return {
    id, cc, opt,
    tracked: t,
    default: dflt,
    noFortify,
    defaultMatchesTracked: t === null ? null : dflt === t,
    changed: dflt !== noFortify,
    // Whether the file-as-written listing differs between the two builds at
    // all (wListingChanged), and once local labels are renamed (wCodeChanged).
    // Zero such cells would make "no verdict changed" say nothing: the flags
    // would not have reached the code.
    wListingChanged,
    wCodeChanged,
  };
}

/**
 * Per level: cells, how many default verdicts re-derive the tracked one, and the
 * verdict changes with ids. Levels in ALL_OPTS order; a level with no rows is
 * not printed as a zero.
 */
export function fortifySummary(rows, opts = ALL_OPTS) {
  const out = [];
  for (const opt of ALL_OPTS.filter((o) => opts.includes(o))) {
    const sub = rows.filter((r) => r.opt === opt);
    if (!sub.length) continue;
    out.push({
      opt,
      cells: sub.length,
      compared: sub.filter((r) => r.defaultMatchesTracked !== null).length,
      matched: sub.filter((r) => r.defaultMatchesTracked === true).length,
      wListingChanged: sub.filter((r) => r.wListingChanged === true).length,
      wCodeChanged: sub.filter((r) => r.wCodeChanged === true).length,
      noTracked: sub.filter((r) => r.defaultMatchesTracked === null).map((r) => r.id).sort(),
      disagree: sub.filter((r) => r.defaultMatchesTracked === false).map((r) => ({ id: r.id, tracked: r.tracked, default: r.default }))
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
      changes: sub.filter((r) => r.changed).map((r) => ({ id: r.id, from: r.default, to: r.noFortify }))
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    });
  }
  return out;
}

/** 2 when a default verdict disagreed with the tracked row or a cell had none; 0 otherwise. */
export function fortifyExitCode(summary) {
  return summary.some((s) => s.disagree.length || s.noTracked.length) ? 2 : 0;
}

// ---------------------------------------------------------------- main --------

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const REPO = resolve(ROOT, '..', '..', '..');
const GEN = join(ROOT, 'generated-corpus', 'r2');
const SCEN_PATH = join(ROOT, 'scenarios.json');
const DEFAULT_ROWS = join(ROOT, 'data', 'r2-build-rows.json');

function die(code, msg) {
  process.stderr.write(`fortify-check: ${msg}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const a = { cc: null, opts: null, out: null, files: null, rows: DEFAULT_ROWS, conc: 8 };
  const need = (i, f) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${f} needs a value`); return argv[i + 1]; };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--cc': a.cc = need(i, f); i++; break;
      case '--opts': a.opts = list(need(i, f)); i++; break;
      case '--out': a.out = need(i, f); i++; break;
      case '--files': a.files = list(need(i, f)); i++; break;
      case '--rows': a.rows = need(i, f); i++; break;
      case '--conc': a.conc = Number(need(i, f)); i++; break;
      default: die(4, `unknown argument ${f}`);
    }
  }
  if (!a.cc || !CCS.includes(a.cc)) die(4, `--cc must be one of ${CCS.join(' ')} (the tracked rows name them so)`);
  if (!a.opts || !a.opts.length) die(4, `--opts is required: a comma list from ${ALL_OPTS.join(' ')}`);
  for (const o of a.opts) if (!ALL_OPTS.includes(o)) die(4, `--opts: ${o} is not one of ${ALL_OPTS.join(' ')}`);
  if (!a.out) die(4, '--out is required: a lab directory outside the repository');
  if (!Number.isInteger(a.conc) || a.conc < 1) die(4, '--conc must be a positive integer');
  a.out = resolve(a.out);
  const rel = relative(REPO, a.out);
  if (!rel || (!rel.startsWith('..') && !isAbsolute(rel))) die(4, '--out is inside the repository; this measurement writes to a lab directory only');
  a.rows = resolve(a.rows);
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  let version;
  try { version = (await run(args.cc, ['--version'], { timeout: 30000 })).stdout.split('\n')[0].trim(); }
  catch { die(5, `${args.cc} --version failed: the compiler is not runnable here`); }
  let rowsText, trackedRows;
  try { rowsText = readFileSync(args.rows); trackedRows = JSON.parse(rowsText.toString('utf8')); }
  catch { die(5, 'the --rows file could not be read as JSON'); }
  const tracked = new Map();
  for (const r of trackedRows) if (r.kind === 'erasure') tracked.set(`${r.id}|${r.cc}|${r.opt}`, r.verdict);

  const scen = JSON.parse(readFileSync(SCEN_PATH, 'utf8'));
  const res = args.files ? args.files.map((g) => new RegExp('^' + g.replace(/\.c$/, '').replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$')) : null;
  const BUILD = join(args.out, 'build');
  mkdirSync(BUILD, { recursive: true });

  const files = [];
  for (const f of readdirSync(GEN).filter((x) => x.endsWith('.c')).sort()) {
    const id = f.replace(/\.c$/, '');
    const m = scen[id.split('_')[2]];
    if (!m || m.fam !== 'erasure') continue;
    if (res && !res.some((re) => re.test(id))) continue;
    const src = readFileSync(join(GEN, f), 'utf8');
    const ws = wipeSpans(src, m.fn);
    if (!ws.spans.length) continue;
    const w = join(BUILD, `${id}.w.c`);
    const wo = join(BUILD, `${id}.wo.c`);
    writeFileSync(w, src + CONTROL, 'utf8');
    writeFileSync(wo, ablateSpans(src, ws.spans) + CONTROL, 'utf8');
    files.push({ id, fn: m.fn, w, wo });
  }
  if (!files.length) die(3, 'no erasure file with a wipe span was selected');

  // What the compiler predefines, per level, with FLAGS and with FLAGS + NO_FORTIFY.
  const probe = join(BUILD, '_defines.c');
  writeFileSync(probe, 'int vgfortify_probe;\n', 'utf8');
  const defines = {};
  for (const opt of args.opts) {
    defines[opt] = {};
    for (const [tag, extra] of [['default', []], ['noFortify', [...NO_FORTIFY]]]) {
      try {
        const { stdout } = await run(args.cc, [...FLAGS, opt, ...extra, '-dM', '-E', probe], { timeout: 30000, maxBuffer: 16 << 20 });
        defines[opt][tag] = { value: fortifyValue(stdout), lines: fortifyDefines(stdout) };
      } catch {
        die(5, `${args.cc} ${opt} -dM -E failed`);
      }
    }
  }

  const units = [];
  for (const f of files) for (const opt of args.opts) units.push({ ...f, opt });
  process.stderr.write(`${files.length} erasure file(s) with a wipe span, ${units.length} cell(s), ${units.length * 4} compile(s); cc ${args.cc}; opts ${args.opts.join(' ')}\n`);
  let done = 0;
  const asm = (id, opt, side, tag) => join(BUILD, `${id}.${args.cc}${opt}.${side}.${tag}.s`);
  const rows = await pool(units, async (u) => {
    const aW = await compile(args.cc, [u.opt], u.w, asm(u.id, u.opt, 'w', 'default'));
    const aWo = await compile(args.cc, [u.opt], u.wo, asm(u.id, u.opt, 'wo', 'default'));
    const nW = await compile(args.cc, [u.opt, ...NO_FORTIFY], u.w, asm(u.id, u.opt, 'w', 'nofortify'));
    const nWo = await compile(args.cc, [u.opt, ...NO_FORTIFY], u.wo, asm(u.id, u.opt, 'wo', 'nofortify'));
    if (++done % 200 === 0) process.stderr.write(`  ${done} cells\n`);
    return fortifyRow({ id: u.id, cc: args.cc, opt: u.opt, tracked: tracked.get(`${u.id}|${args.cc}|${u.opt}`),
      dflt: verdictOf(aW, aWo, u.fn).verdict, noFortify: verdictOf(nW, nWo, u.fn).verdict,
      wListingChanged: aW === null || nW === null ? null : aW !== nW,
      wCodeChanged: aW === null || nW === null ? null : labelsRenamed(aW) !== labelsRenamed(nW) });
  }, args.conc);
  rows.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : ALL_OPTS.indexOf(a.opt) - ALL_OPTS.indexOf(b.opt)));

  const summary = fortifySummary(rows, args.opts);
  const L = [];
  L.push('fortify check (fortify-check.mjs): every erasure file with a wipe span, the find step\'s own cell code,');
  L.push(`default flags against ${NO_FORTIFY.join(' ')} added to both compiles`);
  L.push('');
  L.push(`compiler        ${args.cc}  (${version})`);
  L.push(`tracked rows    ${args.rows === DEFAULT_ROWS ? '(default)' : '(given)'} sha256 ${createHash('sha256').update(rowsText).digest('hex')}`);
  L.push(`file subset     ${args.files ? args.files.join(',') : `(all ${files.length} erasure files with a wipe span)`}`);
  L.push('');
  L.push('predefined about FORTIFY with FLAGS (-dM -E), per level');
  for (const opt of args.opts) {
    const d = defines[opt];
    const show = (x) => (x.lines.length ? x.lines.join('; ') : '(none)');
    L.push(`  ${opt.padEnd(4)} default: ${show(d.default)}   with ${NO_FORTIFY.join(' ')}: ${show(d.noFortify)}`);
  }
  L.push('');
  L.push('per level');
  for (const s of summary) {
    L.push(`  ${s.opt.padEnd(4)} cells ${s.cells}, default re-derived == tracked ${s.matched}/${s.compared}`
      + `${s.noTracked.length ? `, ${s.noTracked.length} without a tracked row` : ''}, verdict changes ${s.changes.length}`
      + `  (file-as-written listing differs between the two builds in ${s.wListingChanged}, `
      + `${s.wCodeChanged} of them beyond .L label numbering)`);
    for (const x of s.disagree) L.push(`       DEFAULT DISAGREES ${x.id}: tracked ${x.tracked}, re-derived ${x.default}`);
    for (const id of s.noTracked) L.push(`       NO TRACKED ROW ${id}`);
    for (const c of s.changes) L.push(`       CHANGED ${c.id}: ${c.from} -> ${c.to}`);
  }
  L.push('');
  const text = L.join('\n');
  writeFileSync(join(args.out, 'fortify-check.json'), '[\n' + rows.map((r) => JSON.stringify(r)).join(',\n') + '\n]\n', 'utf8');
  writeFileSync(join(args.out, 'fortify-check.txt'), text, 'utf8');
  process.stdout.write(text + '\n');
  process.exit(fortifyExitCode(summary));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((e) => die(5, `unexpected failure: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`));
}

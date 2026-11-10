#!/usr/bin/env node
/**
 * The zero-write count beside the find step's verdict, in the lab: for each
 * cell, the number of zero writes asm-oracle's observeEffect sees in the target
 * body with the wipe (w) and without it (wo), the difference, and the two lists
 * of ./lib/zero-delta.mjs -- cells verdictOf calls WIPE_SURVIVED with no extra
 * zero write in w, and cells whose bodies differ only by a moved frame. It never
 * changes a verdict and writes no tracked data.
 *
 *   node zero-delta.mjs --corpus --out <dir> [--cc clang-18] [--opts -O0,-O1,-O2,-O3,-Os]
 *                       [--files <list>] [--conc 2]
 *       compile the repair loop's selection (lib/corpus.mjs's erasure family)
 *       without a plugin, w and wo exactly as the find step builds them
 *       (wipeSpans, every span ablated, CONTROL appended, FLAGS + level), read
 *       verdictOf, and compare each verdict with the tracked
 *       ../ai-generated/data/r2-build-rows.json
 *   node zero-delta.mjs --pairs <list.json> --out <dir>
 *       read listings that already exist: list.json is [{id, fn, w, wo, group?}]
 *       with w / wo paths to assembly files (relative to the list). Nothing is
 *       compiled
 *
 * Lab output only, under --out, which must lie outside the repository:
 * zero-delta-rows.json (one row per cell) and zero-delta-results.txt. There is
 * no --write-data. The count's symbol list is the `wipe-6` list of
 * compiler/schema/effect-symbol-lists.json, read at run time.
 *
 * Exit status: 0 run complete; 2 run complete but a verdict differs from the
 * tracked row's (--corpus), or a listing could not be read (--pairs); 4 bad
 * arguments; 5 an input could not be used.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { dirname, resolve, join, basename, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { insideRepo } from './lib/lto.mjs';
import { corpusFiles, erasureFamily } from '../lib/corpus.mjs';
import { absolutePathHits } from '../lib/provenance.mjs';
import { effectFromRegistry, zeroDeltaCell, summarize, trackedAgreement } from './lib/zero-delta.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const REPO = resolve(LANE, '..', '..', '..');
const AIGEN = resolve(LANE, '..', 'ai-generated');
const GEN = join(AIGEN, 'generated-corpus', 'r2');
const SCEN_PATH = join(AIGEN, 'scenarios.json');
const TRACKED = join(AIGEN, 'data', 'r2-build-rows.json');
const CELL_PATH = join(AIGEN, 'lib', 'ablation-cell.mjs');
const REGISTRY = join(REPO, 'compiler', 'schema', 'effect-symbol-lists.json');
const ALL_OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];

const USAGE = `usage:
  node zero-delta.mjs --corpus --out <dir> [--cc clang-18] [--opts ${ALL_OPTS.join(',')}] [--files <list>] [--conc 2]
  node zero-delta.mjs --pairs <list.json> --out <dir>

--out lies outside the repository; there is no --write-data.
`;

function die(code, msg) {
  process.stderr.write(`zero-delta: ${msg}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const a = { corpus: false, pairs: null, out: null, cc: 'clang-18', opts: [...ALL_OPTS], files: null, conc: 2 };
  const need = (i, flag) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${flag} needs a value`); return argv[i + 1]; };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--corpus': a.corpus = true; break;
      case '--pairs': a.pairs = need(i, f); i++; break;
      case '--out': a.out = need(i, f); i++; break;
      case '--cc': a.cc = need(i, f); i++; break;
      case '--opts': a.opts = list(need(i, f)); i++; break;
      case '--files': a.files = list(need(i, f)).map((x) => x.replace(/\.c$/, '')); i++; break;
      case '--conc': a.conc = Number(need(i, f)); i++; break;
      case '--write-data': die(4, '--write-data does not exist here: this tool writes its lab directory and nothing else'); break;
      case '-h': case '--help': process.stdout.write(USAGE); process.exit(0); break;
      default: die(4, `unknown argument ${f}\n${USAGE}`);
    }
  }
  if (a.corpus === (a.pairs !== null)) die(4, `name exactly one of --corpus and --pairs\n${USAGE}`);
  if (!a.out) die(4, '--out is required: everything this tool writes goes to a lab directory outside the repository');
  for (const o of a.opts) if (!ALL_OPTS.includes(o)) die(4, `--opts: ${o} is not one of ${ALL_OPTS.join(' ')}`);
  a.opts = ALL_OPTS.filter((o) => a.opts.includes(o));
  if (!Number.isInteger(a.conc) || a.conc < 1) die(4, '--conc must be a positive integer');
  a.out = resolve(a.out);
  if (insideRepo(a.out, REPO, sep)) die(4, '--out lies inside the repository; this tool writes lab output only');
  return a;
}

const readText = (p) => (existsSync(p) ? readFileSync(p, 'utf8') : null);

async function corpusRows(a, cell, effect) {
  const scenarios = JSON.parse(readFileSync(SCEN_PATH, 'utf8'));
  let fam = erasureFamily(corpusFiles(readdirSync(GEN)), scenarios);
  if (a.files) fam = fam.filter((x) => a.files.includes(x.meta.id));
  if (!fam.length) die(4, 'the selection is empty');
  const work = join(a.out, 'asm');
  mkdirSync(work, { recursive: true });
  // A compile that never runs a plugin still has the WPIN_* environment removed:
  // nothing inherited may steer it.
  for (const k of Object.keys(process.env)) if (k.startsWith('WPIN_')) delete process.env[k];
  const jobs = [];
  let noWipe = 0;
  for (const { f, meta } of fam) {
    const src = readFileSync(join(GEN, f), 'utf8');
    const ws = cell.wipeSpans(src, meta.fn);
    if (!ws.spans.length) { noWipe++; continue; }
    const pW = join(work, `${meta.id}.w.c`), pWo = join(work, `${meta.id}.wo.c`);
    writeFileSync(pW, src + cell.CONTROL, 'utf8');
    writeFileSync(pWo, cell.ablateSpans(src, ws.spans) + cell.CONTROL, 'utf8');
    for (const opt of a.opts) jobs.push({ meta, opt, pW, pWo });
  }
  const t0 = Date.now();
  const rows = await cell.pool(jobs, async ({ meta, opt, pW, pWo }, i) => {
    const sW = join(work, `${meta.id}${opt}.w.s`), sWo = join(work, `${meta.id}${opt}.wo.s`);
    const aW = await cell.compile(a.cc, [opt], pW, sW);
    const aWo = await cell.compile(a.cc, [opt], pWo, sWo);
    const v = cell.verdictOf(aW, aWo, meta.fn);
    if ((i + 1) % 200 === 0) process.stderr.write(`[${i + 1}/${jobs.length}] ${Math.round((Date.now() - t0) / 1000)}s\n`);
    return { id: meta.id, cc: a.cc, opt, group: `${a.cc} ${opt}`, fn: meta.fn,
      ...zeroDeltaCell({ aW, aWo, fn: meta.fn, verdict: v, bodyOf: cell.bodyOf, effect }) };
  }, a.conc);
  return { rows, noWipe, files: fam.length, seconds: Math.round((Date.now() - t0) / 1000) };
}

function pairRows(a, cell, effect) {
  const listPath = resolve(a.pairs);
  if (!existsSync(listPath)) die(5, `--pairs ${listPath} does not exist`);
  let list;
  try { list = JSON.parse(readFileSync(listPath, 'utf8')); } catch (e) { die(5, `--pairs does not parse: ${e.message}`); }
  if (!Array.isArray(list) || !list.length) die(5, '--pairs must be a non-empty array of {id, fn, w, wo}');
  const base = dirname(listPath);
  const unreadable = [];
  const rows = list.map((p, i) => {
    if (!p || typeof p.id !== 'string' || typeof p.fn !== 'string' || typeof p.w !== 'string' || typeof p.wo !== 'string') {
      die(5, `--pairs[${i}] is not {id, fn, w, wo}`);
    }
    const aW = readText(resolve(base, p.w)), aWo = readText(resolve(base, p.wo));
    if (aW === null || aWo === null) unreadable.push(p.id);
    const v = cell.verdictOf(aW, aWo, p.fn);
    return { id: p.id, group: p.group ?? '(all)', fn: p.fn,
      ...zeroDeltaCell({ aW, aWo, fn: p.fn, verdict: v, bodyOf: cell.bodyOf, effect }) };
  });
  return { rows, unreadable };
}

function render(head, sums, extra) {
  const L = [...head, ''];
  for (const s of sums) {
    L.push(`== ${s.group}: ${s.cells} cell(s)  ${JSON.stringify(s.byVerdict)}`);
    L.push(`   WIPE_SURVIVED ${s.survived}, delta read in ${s.deltaRead}${s.survivedDeltaNotRead.length ? `, not read in ${s.survivedDeltaNotRead.length}: ${s.survivedDeltaNotRead.join(' ')}` : ''}`);
    L.push(`   survivedNoExtraZero ${s.survivedNoExtraZero.length}${s.survivedNoExtraZero.length ? `: ${s.survivedNoExtraZero.join(' ')}` : ''}`);
    L.push(`   frameShift ${s.frameShift.length}${s.frameShift.length ? `: ${s.frameShift.join(' ')}` : ''}`);
    L.push(`   in both lists ${s.both.length}${s.both.length ? `: ${s.both.join(' ')}` : ''}`);
    L.push(`   labelsOnly ${s.labelsOnly.length}${s.labelsOnly.length ? `: ${s.labelsOnly.join(' ')}` : ''}`);
  }
  return [...L, '', ...extra].join('\n') + '\n';
}

async function main() {
  const a = parseArgs(process.argv.slice(2));
  if (!existsSync(CELL_PATH)) die(5, 'ai-generated/lib/ablation-cell.mjs is missing; verdictOf, bodyOf and the compiles come from it and have no copy');
  const cell = await import(pathToFileURL(CELL_PATH).href);
  let effect;
  try { effect = effectFromRegistry(JSON.parse(readFileSync(REGISTRY, 'utf8'))); } catch (e) { die(5, e.message); }
  mkdirSync(a.out, { recursive: true });
  const head = [
    'zero-delta: the zero writes observeEffect sees in the target body, w minus wo, beside verdictOf. No verdict is changed.',
    `count     observeEffect evidence with the ${effect.listId} list of compiler/schema/effect-symbol-lists.json (${effect.symbols.length} symbols)`
      + ' and inline zero stores; rep stos, indirect calls and unlisted callees are not counted (rep stos is kept beside it)',
  ];
  let rows, extra = [], exit = 0, meta;
  if (a.corpus) {
    const r = await corpusRows(a, cell, effect);
    rows = r.rows;
    let tracked = [];
    try { const d = JSON.parse(readFileSync(TRACKED, 'utf8')); tracked = Array.isArray(d) ? d : d.rows; } catch (e) { die(5, `the tracked rows do not parse: ${e.message}`); }
    const ag = trackedAgreement(rows, tracked);
    head.push(`input     the erasure family of ai-generated/generated-corpus/r2: ${r.files} file(s), ${r.noWipe} with no wipe written (not compiled), `
      + `${a.cc} ${a.opts.join(' ')}, no plugin, ${r.seconds}s`);
    extra = [`verdict against the tracked ai-generated/data/r2-build-rows.json: ${ag.agree} agree, ${ag.disagree.length} differ, ${ag.untracked.length} with no tracked row`,
      ...ag.disagree.map((d) => `  DIFFERS ${d.cell}: here ${d.here}, tracked ${d.tracked}`),
      ...ag.untracked.slice(0, 20).map((k) => `  UNTRACKED ${k}`)];
    if (ag.disagree.length) exit = 2;
    meta = { mode: 'corpus', cc: a.cc, opts: a.opts, files: r.files, noWipe: r.noWipe, tracked: ag };
  } else {
    const r = pairRows(a, cell, effect);
    rows = r.rows;
    head.push(`input     ${rows.length} pair(s) from ${basename(resolve(a.pairs))}; nothing compiled`);
    if (r.unreadable.length) { extra = [`listings missing: ${r.unreadable.join(' ')}`]; exit = 2; }
    meta = { mode: 'pairs', list: basename(resolve(a.pairs)), unreadable: r.unreadable };
  }
  const sums = summarize(rows);
  const txt = render(head, sums, extra);
  const json = `${JSON.stringify({ schema: 'zero-delta-v1', effect, ...meta, summary: sums, rows }, null, 1)}\n`;
  // Neither text may carry a machine path (both are lab output, but they get pasted).
  const hits = [...absolutePathHits(txt), ...absolutePathHits(json)];
  if (hits.length) die(5, `the output would carry an absolute path: ${hits.slice(0, 3).join(', ')}`);
  writeFileSync(join(a.out, 'zero-delta-results.txt'), txt);
  writeFileSync(join(a.out, 'zero-delta-rows.json'), json);
  process.stdout.write(txt);
  process.exit(exit);
}

main();

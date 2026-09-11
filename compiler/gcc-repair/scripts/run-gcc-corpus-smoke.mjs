#!/usr/bin/env node
/**
 * Corpus smoke for WipePinGcc: a few gcc-13 cells the find step scored
 * WIPE_ELIMINATED, re-run through the find step's own code, with and without
 * the plugin.
 *
 *   node run-gcc-corpus-smoke.mjs --plugin <libWipePinGcc.so> --out <lab dir> [--n 3] [--opt -O2] [--cc gcc-13]
 *
 * Which cells: the first --n ids, sorted, among the rows of
 * ../../eval/ai-generated/data/r2-build-rows.json with cc gcc-13, the given
 * opt, idiom `removable` and verdict WIPE_ELIMINATED.
 *
 * What runs is the four-compile cell of ../../eval/repair-loop/run-repair-loop.mjs,
 * mirrored for gcc: the file as written and the file with every wipe span
 * ablated (wipeSpans / ablateSpans), each compiled with the find step's FLAGS
 * and the level, once without the plugin and once with -fplugin=<so>
 * (WPIN_TARGET_FNS = the target and the wipe helpers, as that runner asks).
 *
 *   stock    = verdictOf(w/off, wo/off, fn)   -- must reproduce the tracked row
 *   repaired = verdictOf(w/on,  wo/on,  fn)   -- the same verdict code
 *
 * verdictOf, wipeSpans, ablateSpans, bodyOf, compile, FLAGS and CONTROL are
 * imported from ../../eval/ai-generated/lib/ablation-cell.mjs and not copied: a
 * repair judged by a private copy of the verdict would be judging itself. The
 * plugin's record is printed, never used as the verdict.
 *
 * Everything compiled or written goes under --out. Exit 0 when every stock
 * verdict reproduced the tracked one (whatever the repaired verdicts are -- this
 * is a smoke, and it reports them), 2 when one did not, 3 when nothing was
 * selected or a compile failed, 4 on bad arguments.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const AIGEN = resolve(HERE, '..', '..', 'eval', 'ai-generated');
const ROWS = join(AIGEN, 'data', 'r2-build-rows.json');
const GEN = join(AIGEN, 'generated-corpus', 'r2');

/** The rows the smoke runs: first `n` ids, sorted, matching the four fields. */
export function selectRows(rows, { cc, opt, n }) {
  const picked = rows
    .filter((r) => r && r.kind === 'erasure' && r.cc === cc && r.opt === opt
      && r.idiom === 'removable' && r.verdict === 'WIPE_ELIMINATED')
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const seen = new Set();
  const out = [];
  for (const r of picked) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    out.push(r);
    if (out.length >= n) break;
  }
  return out;
}

/**
 * What the plugin changed in a function body: the lines only in `after` and
 * the lines only in `before`, as multisets (order-insensitive, so a moved line
 * is not reported).
 */
export function bodyDelta(before, after) {
  if (before === null || after === null) return null;
  const count = (text) => {
    const m = new Map();
    for (const l of text.split('\n').map((s) => s.trim()).filter(Boolean)) m.set(l, (m.get(l) || 0) + 1);
    return m;
  };
  const b = count(before);
  const a = count(after);
  const added = [];
  const removed = [];
  for (const [l, k] of a) for (let i = 0; i < k - (b.get(l) || 0); i++) added.push(l);
  for (const [l, k] of b) for (let i = 0; i < k - (a.get(l) || 0); i++) removed.push(l);
  return { added, removed, identical: before === after };
}

function parseArgs(argv) {
  const a = { plugin: null, out: null, n: 3, opt: '-O2', cc: 'gcc-13' };
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i];
    const v = argv[i + 1];
    if (v === undefined) return null;
    if (k === '--plugin') a.plugin = v;
    else if (k === '--out') a.out = v;
    else if (k === '--n') a.n = Number(v);
    else if (k === '--opt') a.opt = v;
    else if (k === '--cc') a.cc = v;
    else return null;
  }
  if (!a.plugin || !a.out || !Number.isInteger(a.n) || a.n < 1) return null;
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args) {
    process.stderr.write('usage: run-gcc-corpus-smoke.mjs --plugin <so> --out <dir> [--n 3] [--opt -O2] [--cc gcc-13]\n');
    return 4;
  }
  const plugin = resolve(args.plugin);
  const out = resolve(args.out);
  if (!existsSync(plugin)) {
    process.stderr.write('run-gcc-corpus-smoke: no plugin at the --plugin path\n');
    return 4;
  }
  // Nothing inherited may configure a plugin-on compile.
  for (const k of Object.keys(process.env)) if (k.startsWith('WPIN_')) delete process.env[k];

  const cell = await import(pathToFileURL(join(AIGEN, 'lib', 'ablation-cell.mjs')).href);
  const rows = JSON.parse(readFileSync(ROWS, 'utf8'));
  const picked = selectRows(rows, { cc: args.cc, opt: args.opt, n: args.n });
  if (!picked.length) {
    process.stderr.write('run-gcc-corpus-smoke: no row selected\n');
    return 3;
  }
  mkdirSync(out, { recursive: true });

  const lines = [];
  let bad = 0;
  let broken = 0;
  for (const r of picked) {
    const src = readFileSync(join(GEN, `${r.id}.c`), 'utf8');
    const ws = cell.wipeSpans(src, r.fn);
    const requested = [...new Set([r.fn, ...ws.helpers])];
    const pW = join(out, `${r.id}.w.c`);
    const pWo = join(out, `${r.id}.wo.c`);
    writeFileSync(pW, src + cell.CONTROL, 'utf8');
    writeFileSync(pWo, cell.ablateSpans(src, ws.spans) + cell.CONTROL, 'utf8');
    const recW = join(out, `${r.id}${args.opt}.w.json`);
    const recWo = join(out, `${r.id}${args.opt}.wo.json`);
    rmSync(recW, { force: true });
    rmSync(recWo, { force: true });
    const env = (rec) => ({ WPIN_OUT: rec, WPIN_TARGET_FNS: requested.join(',') });
    const s = (side, mode) => join(out, `${r.id}${args.opt}.${side}.${mode}.s`);
    const pluginArg = `-fplugin=${plugin}`;

    const aWoff = await cell.compile(args.cc, [args.opt], pW, s('w', 'off'));
    const aWooff = await cell.compile(args.cc, [args.opt], pWo, s('wo', 'off'));
    const aWon = await cell.compile(args.cc, [args.opt, pluginArg], pW, s('w', 'on'), { env: env(recW) });
    const aWoon = await cell.compile(args.cc, [args.opt, pluginArg], pWo, s('wo', 'on'), { env: env(recWo) });
    if (!aWoff || !aWooff || !aWon || !aWoon) broken++;

    const stock = cell.verdictOf(aWoff, aWooff, r.fn);
    const repaired = cell.verdictOf(aWon, aWoon, r.fn);
    if (stock.verdict !== r.verdict) bad++;
    const delta = bodyDelta(aWoff && cell.bodyOf(aWoff, r.fn), aWon && cell.bodyOf(aWon, r.fn));
    const deltaWo = bodyDelta(aWooff && cell.bodyOf(aWooff, r.fn), aWoon && cell.bodyOf(aWoon, r.fn));
    const rec = (p) => {
      try {
        const j = JSON.parse(readFileSync(p, 'utf8'));
        const sites = j.pinned.map((x) => `${x.line}/${x.followedByUse}`).join(',') || '-';
        return `pinned ${j.pinnedCount}/${j.wouldPinCount} sites ${sites} ${j.resolution.map((x) => `${x.name}:${x.resolution}`).join(',')}`;
      } catch {
        return 'no record';
      }
    };
    lines.push(`${r.id} ${args.opt} fn ${r.fn} spans ${ws.spans.length} requested [${requested.join(',')}]`);
    lines.push(`  tracked ${r.verdict} | stock ${stock.verdict} (control ${stock.control ?? '-'}) | with the plugin on both sides ${repaired.verdict} (control ${repaired.control ?? '-'})`);
    lines.push(`  record w:  ${rec(recW)}`);
    lines.push(`  record wo: ${rec(recWo)}`);
    if (delta) {
      lines.push(`  target body, w/off -> w/on: ${delta.identical ? 'identical' : `+${delta.added.length} -${delta.removed.length} lines`}`);
      for (const l of delta.added) lines.push(`    + ${l}`);
      for (const l of delta.removed) lines.push(`    - ${l}`);
    }
    if (deltaWo) lines.push(`  target body, wo/off -> wo/on: ${deltaWo.identical ? 'identical' : `+${deltaWo.added.length} -${deltaWo.removed.length} lines`}`);
  }
  lines.push('');
  lines.push(`${picked.length} cell(s); stock verdict reproduced the tracked row in ${picked.length - bad}; compiles failed in ${broken}`);
  process.stdout.write(lines.join('\n') + '\n');
  if (broken) return 3;
  return bad ? 2 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().then((c) => { process.exitCode = c; }, (e) => {
    process.stderr.write(`run-gcc-corpus-smoke: ${e && e.stack ? e.stack.split('\n').slice(0, 3).join(' | ') : e}\n`);
    process.exitCode = 3;
  });
}

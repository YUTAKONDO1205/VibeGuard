#!/usr/bin/env node
/**
 * Cross-check of the lexical initialiserLike label (./span-label.mjs) against the
 * repair plugin's own answer to a similar question, `followedByUse`.
 *
 * The plugin (compiler/llvm-repair, WipePin) records, for every zero-fill
 * llvm.memset it sees, whether some other instruction touching the same stack
 * object can run after it (llvm::isPotentiallyReachable on the IR the front end
 * wrote). It is read here at -O0 only: at -O0 there is no cleanup code for the
 * plugin to over-approximate through, so its answer is the closest thing to a
 * second, independent reading of "is this zero-fill the buffer's last word?"
 * that the repository has. Neither side is the truth. Where they disagree, the
 * disagreement is listed span by span so a reader can open the source and say
 * which one is wrong and why.
 *
 * For every erasure file with a wipe span: the file as written plus the positive
 * control, compiled with clang at -O0, the plugin loaded in module scope as a
 * dry run (it decides and records, and mutates nothing). Twice: once with
 * -gline-tables-only, so that each recorded site carries the source line a span
 * can be matched on, and once without, to show the line tables did not change a
 * single recorded site apart from its line. A span is matched to a site in the
 * target function whose line falls within the span's lines; exactly one such
 * site is a match. Spans that are not llvm.memset in the target function (helper
 * calls, volatile loops, a call through a volatile function pointer) have no site
 * and are counted, not compared. followedByUse null (the buffer is not a stack
 * object of this function) is counted, not compared.
 *
 * The record is read with the repair loop's strict reader
 * (../../repair-loop/lib/pin-record.mjs), imported rather than copied. This is
 * the one place in this lane that imports from the repair loop, and it is a
 * diagnostic of the label: nothing on the find step's verdict path depends on it.
 *
 *   node label-check.mjs --plugin <libWipePin.so> --out <lab dir> [--cc clang-18] [--files <list>] [--conc 4]
 *
 * Output goes to the lab only: label-check.json (one entry per span: id, index,
 * kind, line numbers, the two answers, how they were matched) and
 * label-check.txt. Nothing is written to the repository.
 *
 * Exit codes: 0 complete; 2 a record was missing or refused, or the line tables
 * changed a recorded site; 3 nothing selected; 4 bad arguments; 5 the compiler,
 * the plugin or the record reader could not be used.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { dirname, resolve, join, basename } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { CONTROL, wipeSpans, compile, pool } from './ablation-cell.mjs';
import { initialiserLabels } from './span-label.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const GEN = join(ROOT, 'generated-corpus', 'r2');
const SCEN = JSON.parse(readFileSync(join(ROOT, 'scenarios.json'), 'utf8'));
const READER = resolve(ROOT, '..', 'repair-loop', 'lib', 'pin-record.mjs');
const OPT = '-O0';
// The files the README names as initialiser-only: printed on their own line so
// the requirement that both read initialiser-like is visible in every run.
const NAMED = ['opus_N_pinpad_r2', 'sonnet_S_privkey_r3'];

function die(code, msg) { process.stderr.write(`label-check: ${msg}\n`); process.exit(code); }

function parseArgs(argv) {
  const a = { plugin: null, out: null, cc: 'clang-18', files: null, conc: 4 };
  const need = (i, f) => { if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, `${f} needs a value`); return argv[i + 1]; };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    switch (f) {
      case '--plugin': a.plugin = need(i, f); i++; break;
      case '--out': a.out = need(i, f); i++; break;
      case '--cc': a.cc = need(i, f); i++; break;
      case '--files': a.files = need(i, f).split(',').map((s) => s.trim()).filter(Boolean); i++; break;
      case '--conc': a.conc = Number(need(i, f)); i++; break;
      default: die(4, `unknown argument ${f}`);
    }
  }
  if (!a.plugin || !a.out) die(4, '--plugin and --out are required');
  if (!Number.isInteger(a.conc) || a.conc < 1) die(4, '--conc must be a positive integer');
  a.plugin = resolve(a.plugin);
  a.out = resolve(a.out);
  return a;
}

const lineOf = (src, off) => src.slice(0, off).split('\n').length;
const siteKey = (p) => JSON.stringify([p.function, p.index, p.lengthBytes, p.destKind, p.alreadyVolatile, p.followedByUse]);

async function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const k of Object.keys(process.env)) if (k.startsWith('WPIN_')) delete process.env[k];
  if (!existsSync(args.plugin)) die(5, 'the --plugin path does not name a file');
  if (!existsSync(READER)) die(5, 'repair-loop/lib/pin-record.mjs is missing; the record is read with that reader and no copy');
  const { readPinRecord } = await import(pathToFileURL(READER).href);

  const res = args.files ? args.files.map((g) => new RegExp('^' + g.replace(/\.c$/, '').replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$')) : null;
  const jobs = [];
  for (const f of readdirSync(GEN).filter((x) => x.endsWith('.c')).sort()) {
    const id = f.replace(/\.c$/, '');
    const m = SCEN[id.split('_')[2]];
    if (!m || m.fam !== 'erasure') continue;
    if (res && !res.some((re) => re.test(id))) continue;
    const src = readFileSync(join(GEN, f), 'utf8');
    const ws = wipeSpans(src, m.fn);
    if (!ws.spans.length) continue;
    jobs.push({ id, fn: m.fn, src, ws, labels: initialiserLabels(src, m.fn, ws.spans) });
  }
  if (!jobs.length) die(3, 'no erasure file with a wipe span was selected');

  const BUILD = join(args.out, 'build');
  mkdirSync(BUILD, { recursive: true });
  const plugin = `-fpass-plugin=${args.plugin}`;
  const problems = [];
  const spans = [];
  let unmatchedSites = 0;

  await pool(jobs, async (j) => {
    const w = join(BUILD, `${j.id}.w.c`);
    writeFileSync(w, j.src + CONTROL, 'utf8');
    const read = async (tag, extra) => {
      const rec = join(BUILD, `${j.id}.${tag}.json`);
      rmSync(rec, { force: true });
      const asm = await compile(args.cc, [OPT, ...extra, plugin], w, join(BUILD, `${j.id}.${tag}.s`),
        { env: { WPIN_OUT: rec, WPIN_SCOPE: 'module', WPIN_DRY_RUN: '1' } });
      if (asm === null) return { ok: false, problems: ['compile-failed'] };
      return readPinRecord(rec, { scope: 'module', dryRun: true, opt: OPT, module: basename(w) });
    };
    const withLines = await read('g', ['-gline-tables-only']);
    const plain = await read('nog', []);
    if (!withLines.ok || !plain.ok) {
      problems.push(`RECORD ${j.id}: ${[...(withLines.problems || []), ...(plain.problems || [])].slice(0, 3).join('; ')}`);
      return;
    }
    const a = withLines.record.pinned.map(siteKey);
    const b = plain.record.pinned.map(siteKey);
    if (a.length !== b.length || a.some((x, i) => x !== b[i])) problems.push(`LINE TABLES CHANGED A SITE ${j.id}`);

    const sites = withLines.record.pinned.filter((p) => p.function === j.fn);
    const used = new Set();
    j.ws.spans.forEach(([s0, s1], index) => {
      const l0 = lineOf(j.src, s0), l1 = lineOf(j.src, s1 - 1);
      const hits = sites.filter((p) => p.line !== null && p.line >= l0 && p.line <= l1);
      for (const h of hits) used.add(h);
      const entry = { id: j.id, index, kind: j.ws.kinds[index], lines: [l0, l1], lexical: j.labels[index], followedByUse: null, match: null };
      if (hits.length === 0) entry.match = 'no-site';
      else if (hits.length > 1) entry.match = 'ambiguous';
      else {
        entry.followedByUse = hits[0].followedByUse;
        entry.match = hits[0].followedByUse === null ? 'plugin-null'
          : j.labels[index] === null ? 'lexical-null'
            : hits[0].followedByUse === j.labels[index] ? 'agree' : 'disagree';
      }
      spans.push(entry);
    });
    unmatchedSites += sites.filter((p) => !used.has(p)).length;
  }, args.conc);

  spans.sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : x.index - y.index));
  const count = (pred) => spans.filter(pred).length;
  const L = [];
  L.push(`initialiserLike (lexical) against WipePin followedByUse, ${args.cc} ${OPT}, module scope, dry run`);
  L.push(`files ${jobs.length}, spans ${spans.length}`);
  for (const kind of ['removable', 'nonremovable']) {
    const k = (m) => count((s) => s.kind === kind && s.match === m);
    L.push(`  ${kind.padEnd(12)} agree ${k('agree')}, disagree ${k('disagree')}, plugin null ${k('plugin-null')}, lexical null ${k('lexical-null')}, no site ${k('no-site')}, ambiguous ${k('ambiguous')}`);
  }
  L.push(`  sites in the target function matched to no span (e.g. an \`= {0}\` initialiser): ${unmatchedSites}`);
  L.push('disagreements (lexical vs followedByUse)');
  for (const s of spans.filter((x) => x.match === 'disagree')) {
    L.push(`  DISAGREE ${s.id} span ${s.index} [${s.kind}] line ${s.lines[0]}${s.lines[1] !== s.lines[0] ? `-${s.lines[1]}` : ''}: lexical ${s.lexical}, plugin ${s.followedByUse}`);
  }
  for (const s of spans.filter((x) => x.match === 'ambiguous')) L.push(`  AMBIGUOUS ${s.id} span ${s.index}: more than one site on its lines`);
  L.push('named initialiser-only files');
  for (const id of NAMED) {
    for (const s of spans.filter((x) => x.id === id)) L.push(`  ${id} span ${s.index}: lexical ${s.lexical}, plugin ${s.followedByUse} (${s.match})`);
  }
  L.push(`record problems ${problems.length}`);
  for (const p of problems) L.push(`  ${p}`);
  const text = L.join('\n') + '\n';
  writeFileSync(join(args.out, 'label-check.json'), '[\n' + spans.map((s) => JSON.stringify(s)).join(',\n') + '\n]\n', 'utf8');
  writeFileSync(join(args.out, 'label-check.txt'), text, 'utf8');
  process.stdout.write(text);
  process.exit(problems.length ? 2 : 0);
}

main().catch((e) => die(5, `unexpected failure: ${e && e.stack ? e.stack.split('\n').slice(0, 4).join(' | ') : e}`));

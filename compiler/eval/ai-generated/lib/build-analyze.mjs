/**
 * Round 2 build-side analysis.
 *
 * erasure     : ablation across 5 optimisation levels x 2 vendors.
 *               Round 1 could not score a volatile wipe written inline (no helper
 *               call to delete), leaving 46 opportunities unjudged. This version
 *               removes the enclosing loop statement instead, and refuses to score
 *               any file whose ablated form does not compile - a self-filter that
 *               is honest by construction.
 * authz       : does the check survive -DNDEBUG? That is the poster's
 *               "lost in preprocessing" result, asked of AI-written code.
 * configguard : does the default build (no macros defined) differ from the build
 *               with every macro the file mentions? If so the defence is
 *               configuration-dependent and the default is what ships.
 *
 * Survival is always decided by differential compilation, never by searching the
 * assembly for a name: section 8 of the poster shows name search mislabels 6 of 8
 * configurations.
 *
 * The pieces of one cell - finding the wipe, ablating it, compiling both forms,
 * reading the target body, deciding the verdict - live in ./ablation-cell.mjs, so
 * that another lane reaches its verdict through the same code rather than a copy.
 * This file is the measurement: it owns the corpus, the scratch directory and the
 * output, and it is the only one of the two with side effects.
 */
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import {
  CONTROL, maskNonCode, wipeSpans, ablateSpans, bodyOf, compile, pool, verdictOf,
} from './ablation-cell.mjs';
import { pathHits } from './span-summary.mjs';
import { runSpikeGate, summarise as summariseSpikeGate } from '../../spike/lib/gate.mjs';
import { homedir } from 'node:os';
const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));

const ROOT = resolve(HERE, '..');
const GEN = join(ROOT, 'generated-corpus/r2');
// Build scratch. Regenerable, so it is ignored rather than tracked.
const AB = join(ROOT, '_build');
mkdirSync(AB, { recursive: true });
const SCEN = JSON.parse(readFileSync(join(ROOT, 'scenarios.json'), 'utf8'));

const VENDORS = ['clang-18', 'gcc-13'];
const OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];
const DATA_OUT = join(ROOT, 'data', 'r2-build-rows.json');

// ---- where the rows go, and what it takes to overwrite the tracked ones -----
//
// Until 2026-09-12 this file ended with an unconditional write to
// data/r2-build-rows.json. Two things were wrong with that. The rows are pushed
// in pool completion order, so a re-run that measures exactly the same thing
// writes a different byte sequence, and data/r2-span-results.txt pins the
// tracked file's sha256 -- a re-run therefore broke a test whatever it found.
// And a run has no way to be a rehearsal: looking at what the corpus does today
// meant overwriting the record of what it did the day it was reviewed.
//
// So --out is required and takes the rows, --write-data is what reaches the
// repository, and ../lib/compare-rows.mjs is how a lab file and the tracked one
// are compared (multiset, not bytes). This is build-spans.mjs's arrangement,
// spelled the same way on purpose.
const USAGE = `usage: node build-analyze.mjs --out <dir> [--write-data]

  --out <dir>     lab directory for the rows and the manifest (required, outside the repository)
  --write-data    also overwrite data/r2-build-rows.json with this run's rows
  -h, --help      this

exit: 0 the run completed; 3 the spike/recovery gate did not hold and nothing
was written; 4 bad arguments; 5 a path that names this machine would have been
written, and nothing was.
`;

function die(code, msg) { process.stderr.write(`build-analyze: ${msg}\n`); process.exit(code); }

function parseArgs(argv) {
  const a = { out: null, writeData: false };
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i];
    if (f === '--out') {
      if (i + 1 >= argv.length || argv[i + 1].startsWith('--')) die(4, '--out needs a value');
      a.out = argv[++i];
    } else if (f === '--write-data') a.writeData = true;
    else if (f === '-h' || f === '--help') { process.stdout.write(USAGE); process.exit(0); }
    else die(4, `unknown argument ${f}`);
  }
  if (!a.out) die(4, '--out is required: the rows of a run go to a lab directory, and --write-data is what reaches data/');
  a.out = resolve(a.out);
  if (a.out === ROOT || a.out.startsWith(join(ROOT, 'data'))) die(4, '--out must not be the repository\'s own data directory');
  return a;
}

const args = parseArgs(process.argv.slice(2));
mkdirSync(args.out, { recursive: true });

// ---- spike/recovery gate, before the corpus ---------------------------------
//
// The corpus cannot check itself: a model file whose wipe survived and one the
// instrument failed to read are the same row, and 720 of them look like a
// measurement either way. So two known translation units go through the same
// verdictOf first -- one whose wipe the optimiser may delete, one whose it may
// not -- together with a run whose subject name is deliberately misspelt and
// which the gate must refuse. Nothing is rewritten when it does not hold.
//
// OPTS must keep at least one level above -O0: at -O0 both spikes are registered
// to read the same word, so a -O0-only gate is 2/2 for an instrument that can
// only ever report that word. The gate refuses such a run by itself
// (NO_DISCRIMINATING_CONFIGURATION), which is a red corpus run, not a silent one.
//
// The gate's scratch goes to the lab, not to _build: _build is inside the
// repository, and interfaces.md section 1 puts measurement inputs on the side
// that produces them.
const SPIKE_LAB = process.env.SPIKE_LAB || join(homedir(), 'vg-lab', 'spike');
const spike = await runSpikeGate({ ccs: VENDORS, opts: OPTS, lab: SPIKE_LAB });
process.stderr.write(`${summariseSpikeGate(spike)}\n`);
if (!spike.established) {
  for (const why of spike.verdict.reasons) process.stderr.write(`  spike gate: ${why}\n`);
  process.stderr.write('the spike/recovery gate did not hold; data/r2-build-rows.json was NOT rewritten\n');
  process.exit(3);
}

// ---------------------------------------------------------------- main -------
const files = readdirSync(GEN).filter((f) => f.endsWith('.c')).sort();
process.stderr.write(`${files.length} files\n`);

const jobs = [];
for (const f of files) {
  const id = f.replace(/\.c$/, '');
  const [model, framing, scen, rep] = id.split('_');
  const meta = SCEN[scen];
  if (!meta) continue;
  // `path` is for reading the file and must NOT reach the rows: it is an absolute
  // path on the machine that ran the measurement, and the tracked JSON is scanned
  // by scripts/check-disclosure-shape.mjs, which classifies a home directory as a
  // disclosure. `id` identifies the generation anyway.
  jobs.push({ meta: { id, model, framing, scen, rep, fam: meta.fam, fn: meta.fn }, id, fn: meta.fn, fam: meta.fam, path: join(GEN, f) });
}

const rows = [];

// ---- erasure: ablation over 5 x 2 -------------------------------------------
const eras = jobs.filter((j) => j.fam === 'erasure');
await pool(eras, async (j) => {
  const src = readFileSync(j.path, 'utf8');
  const { spans, kinds, namedSecret, scoped } = wipeSpans(src, j.fn);
  if (!spans.length) { rows.push({ ...j.meta, kind: 'none', verdict: 'NO_WIPE_WRITTEN', scoped }); return; }
  const idiom = kinds.includes('removable') && kinds.includes('nonremovable') ? 'both'
    : kinds.includes('removable') ? 'removable' : 'nonremovable';
  const pW = join(AB, `${j.id}.w.c`), pWo = join(AB, `${j.id}.wo.c`);
  writeFileSync(pW, src + CONTROL, 'utf8');
  writeFileSync(pWo, ablateSpans(src, spans) + CONTROL, 'utf8');
  for (const cc of VENDORS) for (const opt of OPTS) {
    const aW = await compile(cc, [opt], pW, join(AB, `${j.id}.${cc}${opt}.w.s`));
    const aWo = await compile(cc, [opt], pWo, join(AB, `${j.id}.${cc}${opt}.wo.s`));
    const row = { ...j.meta, kind: 'erasure', idiom, cc, opt, n_spans: spans.length, named_secret: namedSecret, scoped };
    // verdictOf returns its keys in row order (control, control_via, verdict, or
    // verdict alone), so assigning it keeps the rows' key order what it was.
    Object.assign(row, verdictOf(aW, aWo, j.fn));
    rows.push(row);
  }
});
process.stderr.write(`erasure done (${rows.length} rows)\n`);

// ---- authz: does the check survive -DNDEBUG? --------------------------------
const authz = jobs.filter((j) => j.fam === 'authz');
await pool(authz, async (j) => {
  const src = readFileSync(j.path, 'utf8');
  const masked = maskNonCode(src);
  const usesAssert = /\bassert\s*\(/.test(masked);
  const p = join(AB, `${j.id}.c`);
  writeFileSync(p, src + CONTROL, 'utf8');
  for (const cc of VENDORS) for (const opt of ['-O0', '-O2']) {
    const a1 = await compile(cc, [opt], p, join(AB, `${j.id}.${cc}${opt}.dbg.s`));
    const a2 = await compile(cc, [opt, '-DNDEBUG'], p, join(AB, `${j.id}.${cc}${opt}.nd.s`));
    const row = { ...j.meta, kind: 'authz', cc, opt, uses_assert: usesAssert };
    if (!a1 || !a2) { row.verdict = 'COMPILE_ERROR'; rows.push(row); continue; }
    const b1 = bodyOf(a1, j.fn), b2 = bodyOf(a2, j.fn);
    if (b1 === null || b2 === null) row.verdict = 'NOT_OBSERVED';
    else row.verdict = b1 === b2 ? 'NDEBUG_NO_EFFECT' : 'CHANGED_BY_NDEBUG';
    rows.push(row);
  }
});
process.stderr.write(`authz done (${rows.length} rows)\n`);

// ---- configguard: default build vs all-macros-defined ------------------------
const cfg = jobs.filter((j) => j.fam === 'configguard');
await pool(cfg, async (j) => {
  const src = readFileSync(j.path, 'utf8');
  const macros = new Set();
  for (const m of src.matchAll(/^\s*#\s*if(?:n?def)\s+([A-Za-z_]\w*)/gm)) macros.add(m[1]);
  for (const m of src.matchAll(/defined\s*\(?\s*([A-Za-z_]\w*)/g)) macros.add(m[1]);
  const p = join(AB, `${j.id}.c`);
  writeFileSync(p, src + CONTROL, 'utf8');
  const defs = [...macros].map((m) => `-D${m}=1`);
  for (const cc of VENDORS) for (const opt of ['-O0', '-O2']) {
    const a1 = await compile(cc, [opt], p, join(AB, `${j.id}.${cc}${opt}.def.s`));
    const a2 = await compile(cc, [opt, ...defs], p, join(AB, `${j.id}.${cc}${opt}.on.s`));
    const row = { ...j.meta, kind: 'configguard', cc, opt, macros: [...macros], n_macros: macros.size };
    if (!a1 || !a2) { row.verdict = 'COMPILE_ERROR'; rows.push(row); continue; }
    const b1 = bodyOf(a1, j.fn), b2 = bodyOf(a2, j.fn);
    if (b1 === null || b2 === null) row.verdict = 'NOT_OBSERVED';
    else if (!macros.size) row.verdict = 'NO_MACRO_GUARD';
    else row.verdict = b1 === b2 ? 'DEFAULT_EQUALS_ENABLED' : 'DEFAULT_DIFFERS';
    rows.push(row);
  }
});
process.stderr.write(`configguard done (${rows.length} rows)\n`);

// ---- output ------------------------------------------------------------------
const rowsText = JSON.stringify(rows);

// What the instrument was, beside what it read. The gate's own numbers are here
// because "these rows were taken with the gate holding" is a claim about the run
// and nowhere else records it; the toolchain versions are here because a row
// that differs between two runs is a toolchain difference or a measurement
// difference, and nothing below can tell them apart afterwards.
const versions = {};
for (const cc of VENDORS) {
  try { versions[cc] = (await run(cc, ['--version'], { timeout: 30000 })).stdout.split('\n')[0].trim(); }
  catch { versions[cc] = null; }
}
const manifestText = JSON.stringify({
  tool: 'build-analyze', generatedAt: new Date().toISOString(), node: process.version,
  vendors: VENDORS, opts: OPTS, versions,
  files: files.length, rows: rows.length, rowsSha256: createHash('sha256').update(rowsText).digest('hex'),
  spikeGate: {
    established: spike.established,
    configurations: spike.verdict.configurations,
    discriminating: spike.verdict.discriminating,
    // `injected` is the run whose subject name is misspelt; the gate must refuse
    // it. null means it was not performed, which is itself a red gate.
    injectionHeld: spike.injected ? spike.injected.held === true : null,
  },
}, null, 2) + '\n';

const hits = [];
for (const [name, t] of [['r2-build-rows.json', rowsText], ['manifest.json', manifestText]]) {
  const h = pathHits(t);
  if (h.length) hits.push(`${name}: ${h.join(', ')}`);
}
if (hits.length) die(5, `a path that names this machine would have been written (${hits.join('; ')}); nothing was written`);

writeFileSync(join(args.out, 'r2-build-rows.json'), rowsText, 'utf8');
writeFileSync(join(args.out, 'manifest.json'), manifestText, 'utf8');
process.stderr.write(`wrote ${rows.length} rows to the lab\n`);

if (args.writeData) {
  if (!existsSync(dirname(DATA_OUT))) die(5, 'the data directory is missing');
  writeFileSync(DATA_OUT, rowsText, 'utf8');
  process.stderr.write(`wrote ${rows.length} rows to data/r2-build-rows.json\n`);
} else {
  process.stderr.write('data/r2-build-rows.json was not touched (no --write-data)\n');
}

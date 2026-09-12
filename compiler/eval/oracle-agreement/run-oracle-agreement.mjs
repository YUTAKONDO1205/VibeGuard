#!/usr/bin/env node
/**
 * run-oracle-agreement -- do the two oracles say the same thing about the same
 * cells, and where exactly do they not?
 *
 * O1 is `verdictOf` in `../ai-generated/lib/ablation-cell.mjs`: differential
 * assembly text, read out of the TRACKED rows and never re-measured here. O2 is
 * the PropertyObserver LLVM pass: an IR call-site count read between passes,
 * measured now, on the same generation, with the same positive control appended.
 *
 *   node compiler/eval/oracle-agreement/run-oracle-agreement.mjs --dry-run
 *   node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
 *        --observer ~/vg-build/pass-observer/libPropertyObserver.so \
 *        --cc clang-18 --opt -O2 --per-bucket 12 --out ~/vg-lab/oracle-agreement
 *
 * This lane writes NO tracked data and never opens the tracked rows for writing.
 * Everything it produces -- the copied sources, the object files, the plugin
 * logs, the report -- goes under `--out`, which must lie outside the repository.
 *
 * EXIT CODES (interfaces.md section 7). Read `laneVerdict` in lib/agreement.mjs
 * before changing any of these; the first one is the one that is usually got
 * wrong.
 *
 *   0  THE COMPARISON WAS PERFORMED. At least one stratum above `-O0` has a
 *      non-empty denominator and neither instrument's marginal is degenerate in
 *      it. Perfect agreement exits 0. Perfect DISAGREEMENT also exits 0 -- the
 *      off-diagonal is the result this lane exists to find, and a lane that went
 *      red on it would be a lane with an incentive.
 *   2  THE RUN COULD NOT ASK ITS QUESTION. Every cell was excluded, or only
 *      `-O0` was run, or the selected cells were uniform on one side so the
 *      table cannot separate an agreeing second instrument from one that can
 *      only say one word. Not a claim about agreement.
 *   3  A CHECK COULD NOT BE COMPLETED: the plugin is not built, the requested
 *      compiler is not installed, the tracked rows could not be read -- or the
 *      run was a `--dry-run`, which measures nothing and must never be readable
 *      as a green lane.
 *   4  the arguments were bad, the lab is inside the repository, or the report
 *      would carry an absolute path and was refused.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import process from 'node:process';

import {
  tabulate, laneVerdict, formatRate, STRATUM, KIND,
} from './lib/agreement.mjs';
import {
  loadRows, indexRows, selectCells, bucketSizes, sourcePathOf, keyOf, o1Of, ROWS_PATH,
} from './lib/rows.mjs';
import { observeCell, channelAvailable, effectSymbols } from './lib/observe.mjs';
import { insideRepo, vendorLabel, probeCompilers } from '../spike/lib/measure.mjs';
import { absolutePathHits } from '../repair-loop/lib/provenance.mjs';

const DEFAULT_CCS = ['clang-18'];
const DEFAULT_OPTS = ['-O2'];

function usage(msg) {
  if (msg) process.stderr.write(`run-oracle-agreement.mjs: ${msg}\n`);
  process.stderr.write(
    'usage: run-oracle-agreement.mjs --out <lab dir> --observer <libPropertyObserver.so>\n'
    + '                               [--cc clang-18] [--opt -O2,-O0] [--per-bucket 8]\n'
    + '                               [--ids a,b,c] [--rows <r2-build-rows.json>] [--json] [--no-write]\n'
    + '                               [--dry-run]\n',
  );
  process.exit(4);
}

function parseArgs(argv) {
  const args = {
    out: process.env.OA_LAB || null,
    observer: null,
    ccs: DEFAULT_CCS,
    opts: DEFAULT_OPTS,
    perBucket: 8,
    ids: null,
    rows: ROWS_PATH,
    json: false,
    write: true,
    dryRun: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { const v = argv[++i]; if (v === undefined) usage(`${a} needs a value`); return v; };
    if (a === '--out') args.out = next();
    else if (a === '--observer') args.observer = next();
    else if (a === '--cc') args.ccs = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--opt') args.opts = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--per-bucket') args.perBucket = Number.parseInt(next(), 10);
    else if (a === '--ids') args.ids = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--rows') args.rows = resolve(next());
    else if (a === '--json') args.json = true;
    else if (a === '--no-write') args.write = false;
    else if (a === '--dry-run') args.dryRun = true;
    else if (a === '-h' || a === '--help') usage(null);
    else usage(`unknown option ${a}`);
  }
  if (!args.ccs.length) usage('--cc listed no compiler');
  if (!args.opts.length) usage('--opt listed no level');
  if (!Number.isInteger(args.perBucket) || args.perBucket < 1) usage('--per-bucket must be a positive integer');
  if (!args.dryRun && !args.out) usage('--out is required (or set OA_LAB); it must be outside the repository');
  return args;
}

const args = parseArgs(process.argv.slice(2));

// ---- the O1 side, read ------------------------------------------------------
let rows;
try {
  rows = loadRows(args.rows);
} catch (err) {
  // Exit 3 and not 4: the rows being unreadable is a check that could not be
  // completed, not an operator who typed something wrong. The difference matters
  // to whoever reads a CI log six weeks later.
  process.stderr.write(`run-oracle-agreement.mjs: cannot read the tracked rows: ${err.message}\n`);
  process.exit(3);
}
let index;
try {
  index = indexRows(rows);
} catch (err) {
  process.stderr.write(`run-oracle-agreement.mjs: ${err.message}\n`);
  process.exit(3);
}

const chosen = selectCells(rows, {
  ccs: args.ccs, opts: args.opts, perBucket: args.perBucket, ids: args.ids,
});

// ---- the dry run ------------------------------------------------------------
//
// Exit 3, deliberately. A dry run has measured nothing, and a lane whose
// "nothing was measured" path exits 0 is a lane that goes green in CI the day
// someone adds --dry-run to make the job faster.
if (args.dryRun) {
  const sizes = bucketSizes(rows, { ccs: args.ccs, opts: args.opts });
  process.stdout.write('DRY RUN -- nothing was compiled and no oracle was consulted.\n');
  process.stdout.write(`tracked rows: ${rows.length} (${index.size} carry a (vendor, level) pair)\n`);
  process.stdout.write('buckets the selection draws from:\n');
  for (const k of Object.keys(sizes).sort()) process.stdout.write(`  ${k.padEnd(34)} ${sizes[k]}\n`);
  process.stdout.write(`selected ${chosen.length} cells at --per-bucket ${args.perBucket}:\n`);
  for (const c of chosen) {
    const src = sourcePathOf(c.id);
    const here = existsSync(src) ? '' : '   [the generation is not in the corpus directory]';
    process.stdout.write(`  ${c.id.padEnd(26)} ${c.cc} ${c.opt.padEnd(4)} fn=${c.fn} idiom=${c.idiom} o1=${c.o1.verdict}${here}\n`);
  }
  process.stdout.write('\nexit 3: a dry run measures nothing, so it is not a green lane.\n');
  process.exit(3);
}

// ---- can the O2 channel run at all? -----------------------------------------
const lab = resolve(args.out);
if (insideRepo(lab)) {
  process.stderr.write('run-oracle-agreement.mjs: --out is inside the repository; measurement output must not be\n');
  process.exit(4);
}

const plugin = args.observer ? resolve(args.observer) : null;
const channel = channelAvailable({ plugin });
if (!channel.available) {
  // Exit 3 rather than an empty table. "0/0, they agree perfectly" because the
  // plugin was not built is the worst output this lane could produce.
  process.stderr.write(`run-oracle-agreement.mjs: ${channel.reason}\n`);
  process.exit(3);
}

const { unavailable } = await probeCompilers(args.ccs);
if (unavailable.length) {
  // Not `UNSUPPORTED`: interfaces.md section 3.1 defines that word for a
  // toolchain that ran and refused, and does not settle whether an absent one is
  // covered. This lane does not settle it on that file's behalf.
  process.stderr.write(`run-oracle-agreement.mjs: not installed on this host: ${unavailable.join(', ')}\n`);
  process.exit(3);
}

let symbols;
try {
  symbols = effectSymbols();
} catch (err) {
  process.stderr.write(`run-oracle-agreement.mjs: ${err.message}\n`);
  process.exit(3);
}

// ---- measure ----------------------------------------------------------------
const pairs = [];
for (const c of chosen) {
  const src = sourcePathOf(c.id);
  if (!existsSync(src)) {
    // The generation named by a tracked row is not in the corpus directory. A
    // cell with no source is not a cell whose oracles disagreed.
    pairs.push({ ...c, o2: null });
    continue;
  }
  let o2;
  try {
    o2 = await observeCell({
      plugin, cc: c.cc, opt: c.opt, lab, id: c.id, fn: c.fn, srcPath: src, symbols,
    });
  } catch (err) {
    process.stderr.write(`run-oracle-agreement.mjs: ${err.message}\n`);
    process.exit(4);
  }
  // The O1 half comes from the index rather than from the selection, so that a
  // `--ids` run that named a cell the selector would not have chosen still gets
  // the row that actually belongs to it.
  const row = index.get(keyOf(c.id, c.cc, c.opt)) || null;
  pairs.push({ ...c, o1: row ? o1Of(row) : null, o2 });
  process.stderr.write(`  ${c.id} ${c.cc} ${c.opt}  O1=${row ? row.verdict : '(no row)'}  O2=${o2.finalState} control=${o2.control ?? '-'}\n`);
}

const tab = tabulate(pairs);
const verdict = laneVerdict(tab);

// ---- the report -------------------------------------------------------------
//
// `compileError` is deliberately NOT carried into the report: it is the driver's
// own message and it names the lab directory, which is an absolute path on the
// measuring machine. It is printed to stderr above and stops there.
const report = {
  schemaVersion: 'vibeguard.oracle-agreement/1',
  oracles: {
    O1: 'verdictOf (compiler/eval/ai-generated/lib/ablation-cell.mjs) -- differential assembly text, read from the TRACKED rows and not re-measured in this run',
    O2: 'PropertyObserver LLVM pass -- IR call-site PRESENT/LOST, measured in this run',
  },
  requested: {
    compilers: args.ccs.map(vendorLabel),
    levels: args.opts,
    perBucket: args.perBucket,
    ids: args.ids,
    rowsFile: args.rows === ROWS_PATH ? '(tracked default)' : '(a file named on the command line)',
    corpus: '(compiler/eval/ai-generated/generated-corpus/r2)',
  },
  selected: chosen.length,
  strata: tab.strata,
  seen: tab.seen,
  accountedFor: tab.accountedFor,
  verdict,
};

const text = JSON.stringify(report, null, 2);
const hits = absolutePathHits(text);
if (hits.length) {
  for (const why of verdict.reasons) process.stderr.write(`run-oracle-agreement.mjs: ${why}\n`);
  process.stderr.write(`run-oracle-agreement.mjs: the report carries an absolute path (${hits.join(', ')}); refusing to write it\n`);
  process.exit(4);
}

if (args.write) {
  mkdirSync(lab, { recursive: true });
  writeFileSync(join(lab, 'oracle-agreement.json'), `${text}\n`, 'utf8');
}
if (args.json) process.stdout.write(`${text}\n`);

// ---- print ------------------------------------------------------------------
process.stdout.write(`\nO1 = verdictOf, differential assembly text (tracked rows)\n`);
process.stdout.write(`O2 = PropertyObserver, IR call-site state (measured in this run)\n`);
process.stdout.write(`${pairs.length} cells observed; ${tab.accountedFor} accounted for\n`);

for (const s of tab.strata) {
  process.stdout.write(`\n== ${s.name} ==  levels: ${s.levels.length ? s.levels.join(', ') : '(none run)'}\n`);
  if (s.name === STRATUM.AT_O0) {
    process.stdout.write('   tabulated separately and NEVER pooled: at -O0 the tracked rows have never\n');
    process.stdout.write('   recorded an elimination, so agreement here means "neither instrument can\n');
    process.stdout.write('   report the phenomenon", not "the instruments agree".\n');
  }
  process.stdout.write('                      O2 LOST   O2 PRESENT\n');
  process.stdout.write(`   O1 ELIMINATED   ${String(s.table['ELIMINATED/LOST']).padStart(8)}   ${String(s.table['ELIMINATED/PRESENT']).padStart(10)}\n`);
  process.stdout.write(`   O1 SURVIVED     ${String(s.table['SURVIVED/LOST']).padStart(8)}   ${String(s.table['SURVIVED/PRESENT']).padStart(10)}\n`);
  process.stdout.write(`   on the diagonal: ${formatRate(s.agreement)}\n`);
  // Why a stratum is not discriminating, as a list rather than as three
  // conditional fragments concatenated: an empty denominator is degenerate on
  // both sides at once, so the naive spelling runs the words together.
  const why = s.den === 0
    ? ['empty denominator']
    : [s.degenerate.o1 ? 'O1 marginal degenerate' : null, s.degenerate.o2 ? 'O2 marginal degenerate' : null].filter(Boolean);
  process.stdout.write(`   discriminating: ${s.discriminating ? 'yes' : `NO -- ${why.join('; ')}`}\n`);

  if (s.offDiagonal.length) {
    process.stdout.write(`   OFF-DIAGONAL (${s.offDiagonal.length}) -- each of these is a case to diagnose, not a failure:\n`);
    for (const c of s.offDiagonal) {
      process.stdout.write(`     ${c.cell.padEnd(20)} ${c.id.padEnd(26)} ${c.cc} ${c.opt.padEnd(4)} idiom=${c.idiom ?? '-'} O1=${c.o1Verdict} O2=${c.o2State} firstLoss=${c.firstLossPass ?? '-'}\n`);
    }
  } else if (s.den > 0) {
    process.stdout.write('   OFF-DIAGONAL: none in this stratum\n');
  }

  const ex = s.excluded;
  process.stdout.write(`   excluded from the denominator: ${ex.total}`);
  if (ex.total) {
    process.stdout.write(` (${KIND.BROKEN_MEASUREMENT} ${ex.byKind[KIND.BROKEN_MEASUREMENT]}, ${KIND.NO_READING} ${ex.byKind[KIND.NO_READING]}, ${KIND.NOT_COMPARABLE} ${ex.byKind[KIND.NOT_COMPARABLE]})`);
  }
  process.stdout.write('\n');
  for (const k of Object.keys(ex.byReason).sort()) {
    process.stdout.write(`     ${k.padEnd(44)} ${ex.byReason[k]}\n`);
  }
  for (const c of ex.cells) {
    process.stdout.write(`       ${c.id.padEnd(26)} ${c.cc} ${c.opt.padEnd(4)} ${c.kind} ${c.reason}${c.detail ? `(${c.detail})` : ''}\n`);
  }
}

process.stdout.write(`\n${verdict.meaning}\n`);
if (!verdict.readable) {
  process.stdout.write('THE COMPARISON WAS NOT PERFORMED:\n');
  for (const why of verdict.reasons) process.stdout.write(`  - ${why}\n`);
}

// One more time, in the place a reader stops: the cell counts above are a
// property of the SELECTION (balanced across the two O1 verdicts on purpose),
// not an estimate of the corpus. See lib/rows.mjs selectCells.
process.stdout.write('the marginals above are an artefact of a deliberately balanced selection; this is not the corpus rate\n');

process.exit(verdict.code);

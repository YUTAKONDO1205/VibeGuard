#!/usr/bin/env node
/**
 * run-oracle-agreement -- do the two oracles say the same thing about the same
 * cells, and where exactly do they not?
 *
 * O1 is `verdictOf` in `../ai-generated/lib/ablation-cell.mjs`: differential
 * assembly text, read out of the TRACKED rows and never re-measured for the
 * table. There are TWO second oracles, one per vendor, and which one runs is a
 * fact about the driver rather than a preference:
 *
 *   O2  the PropertyObserver LLVM pass -- an IR call-site count read between
 *       passes. clang only: gcc does not load an LLVM pass plugin.
 *   O3  `../lto-window/tools/read-wipe.py` over `objdump` -- the zero fill of one
 *       function in the LINKED program. This is the gcc side, and until it
 *       existed the corpus's gcc half had no second instrument at all.
 *
 * They answer in DIFFERENT WORDS and this file never merges them: O2's "the wipe
 * is gone" is `LOST` and O3's is `ABSENT`, and `ABSENT` is also one of O2's own
 * words meaning something else. Every table, every cell name and every degeneracy
 * message is built from the vocabulary the run tabulated under.
 *
 *   node compiler/eval/oracle-agreement/run-oracle-agreement.mjs --dry-run
 *   node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
 *        --observer ~/vg-build/pass-observer/libPropertyObserver.so \
 *        --cc clang-18 --opt -O2 --per-bucket 12 --out ~/vg-lab/oracle-agreement
 *   node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
 *        --cc gcc-13 --opt -O0,-O2 --per-bucket 24 --restrict-domain --live-o1 \
 *        --out ~/vg-lab/oracle-agreement
 *
 * THE BYTE COUNT. O3 grades a fill against a number of bytes, and no tracked row
 * carries a buffer size. The number is established per cell by constant-expression
 * evaluation, with a positive control at the probe point, and a cell that does not
 * get one leaves the denominator BY NAME -- never defaulted, never guessed. See
 * lib/bufferbytes.mjs, and run tools/check-bytes-readout.mjs and
 * tools/check-o3-apparatus.mjs on a host before believing an O3 table from it.
 *
 * `--live-o1` recomputes O1 NOW, with this driver, and prints it beside the
 * tracked verdict. The table still grades the TRACKED O1; the live column is what
 * separates "the two instruments disagree" from "the toolchain moved since the
 * corpus run", which nothing in this lane could tell apart before. It is lab
 * output and is never written into `data/`.
 *
 * This lane never opens the tracked rows for writing. Everything a run produces
 * -- the copied sources, the object files, the plugin logs, the report -- goes
 * under `--out`, which must lie outside the repository. The ONE exception is
 * `--write-data`, which writes one tracked record of the run itself into
 * `data/`: integers, booleans and short strings, scanned for machine paths
 * first, and refused for anything but a full run. See lib/record.mjs for why
 * that exception was made and what it is fenced with.
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
 *   3  A CHECK COULD NOT BE COMPLETED: the plugin is not built, the disassembly
 *      reader or objdump cannot be run, the requested compiler is not installed,
 *      the tracked rows could not be read, no byte count could be established for
 *      any cell -- or the run was a `--dry-run`, which measures nothing and must
 *      never be readable as a green lane.
 *   4  the arguments were bad, the lab is inside the repository, the report
 *      would carry an absolute path and was refused -- or `--write-data` was
 *      asked for by a run that is not the full one (see writeDataRefusals).
 *   5  a TRACKED file would have carried something tracked files must not: an
 *      absolute path, or a number that is not an integer. Nothing was written to
 *      `data/`. Separate from 4 because 4 is an operator error and 5 is a
 *      disclosure the run caught in itself; `../repair-loop/lib/provenance.mjs`
 *      defines the scan and uses the same code for it.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { basename, join, resolve } from 'node:path';
import process from 'node:process';

import {
  tabulate, laneVerdict, formatRate, STRATUM, KIND, stratumOf, VOCABULARIES, REASON,
} from './lib/agreement.mjs';
import {
  loadRows, indexRows, selectCells, bucketSizes, sourcePathOf, keyOf, o1Of, ROWS_PATH,
} from './lib/rows.mjs';
import { observeCell, channelAvailable, effectSymbols } from './lib/observe.mjs';
import { observeCellO3, channelAvailableO3, READ_WIPE, OBJDUMP, PYTHON } from './lib/disasm.mjs';
import { establishBytes, locateWipe, controlBytes } from './lib/bufferbytes.mjs';
import { recomputeO1, summariseDrift, DRIFT } from './lib/liveo1.mjs';
import {
  symbolsOf, countIrCallSites, splitByCallSites, splitIsPerfect, splitTotal, emitIrAtO0,
} from './lib/callsites.mjs';
import {
  buildRecord, writeRecord, writeDataRefusals, versionTriple, dataFileName, defaultSecondOracle,
} from './lib/record.mjs';
import { insideRepo, vendorLabel, probeCompilers } from '../spike/lib/measure.mjs';
import { absolutePathHits } from '../repair-loop/lib/provenance.mjs';

const run = promisify(execFile);
const DEFAULT_CCS = ['clang-18'];
const DEFAULT_OPTS = ['-O2'];

function usage(msg) {
  if (msg) process.stderr.write(`run-oracle-agreement.mjs: ${msg}\n`);
  process.stderr.write(
    'usage: run-oracle-agreement.mjs --out <lab dir> [--observer <libPropertyObserver.so>]\n'
    + '                               [--cc clang-18] [--opt -O2,-O0] [--per-bucket 8]\n'
    + '                               [--second-oracle O2|O3] [--restrict-domain] [--live-o1]\n'
    + '                               [--ids a,b,c] [--rows <r2-build-rows.json>] [--json] [--no-write]\n'
    + '                               [--dry-run] [--diagnose-callsites] [--write-data]\n'
    + '\n'
    + '  --second-oracle       WHICH second instrument. O2 is the PropertyObserver pass\n'
    + '                        plugin and needs --observer; O3 is the disassembly reader\n'
    + '                        (read-wipe.py) and needs none. The default follows the\n'
    + '                        vendor, because gcc does not load an LLVM pass plugin:\n'
    + '                        clang -> O2, anything else -> O3. O2 on a non-clang driver\n'
    + '                        is REFUSED (no plugin is loaded); O3 on clang is allowed and\n'
    + '                        is the three-way reading, but cannot --write-data.\n'
    + '  --restrict-domain     select only cells the second oracle can be ASKED. O3 reads\n'
    + '                        one (caller, helper, bytes) triple, so a subject with four\n'
    + '                        wipes has no reading for it; without this the run spends its\n'
    + '                        selection on cells it will exclude by name. The narrowing is\n'
    + '                        recorded: the denominator is then over that domain, not the corpus.\n'
    + '  --live-o1             ALSO recompute O1 now, with this driver, and print it beside\n'
    + '                        the tracked verdict. The table still grades the TRACKED O1;\n'
    + '                        the live column is what separates "the instruments disagree"\n'
    + '                        from "the toolchain moved since the corpus run". Lab only.\n'
    + `  --diagnose-callsites  also count the -O0 IR wipe call sites of every selected\n`
    + '                        generation, which is what decides whether O2 could be ASKED\n'
    + `  --write-data          also write the tracked record, data/${dataFileName('clang-18')}\n`
    + '                        for clang-18 and one named after any other --cc. Refused for\n'
    + '                        anything but a full run: see writeDataRefusals in lib/record.mjs\n',
  );
  process.exit(4);
}

/**
 * Which second oracle a vendor can actually be read with.
 *
 * The README has said since the lane was written that `gcc-13` is accepted by
 * `--cc` and will not work, because the plugin is an LLVM pass plugin. The
 * sentence was true and the behaviour was bad: a gcc run compiled every cell,
 * failed to load the plugin, and produced a table of BROKEN_MEASUREMENT. The
 * default now follows the vendor, and an impossible pairing is refused before a
 * compile rather than discovered after fifty.
 *
 * The rule itself lives in `lib/record.mjs`, because `writeDataRefusals` has to
 * apply it too and two spellings of it is how a run gets refused by one of them
 * and allowed by the other. Re-exported here under the name the tests and the
 * refusals above use.
 */
export { defaultSecondOracle };

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
    diagnoseCallSites: false,
    writeData: false,
    secondOracle: null,
    restrictDomain: false,
    liveO1: false,
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
    else if (a === '--diagnose-callsites') args.diagnoseCallSites = true;
    else if (a === '--write-data') args.writeData = true;
    else if (a === '--second-oracle') args.secondOracle = next().trim().toUpperCase();
    else if (a === '--restrict-domain') args.restrictDomain = true;
    else if (a === '--live-o1') args.liveO1 = true;
    else if (a === '-h' || a === '--help') usage(null);
    else usage(`unknown option ${a}`);
  }
  if (!args.ccs.length) usage('--cc listed no compiler');
  if (!args.opts.length) usage('--opt listed no level');
  if (!Number.isInteger(args.perBucket) || args.perBucket < 1) usage('--per-bucket must be a positive integer');
  if (!args.dryRun && !args.out) usage('--out is required (or set OA_LAB); it must be outside the repository');

  // ---- which second oracle, and the pairings that are refused --------------
  if (args.secondOracle === null) args.secondOracle = defaultSecondOracle(args.ccs[0]);
  if (!Object.prototype.hasOwnProperty.call(VOCABULARIES, args.secondOracle)) {
    usage(`--second-oracle must be one of ${Object.keys(VOCABULARIES).join(', ')}`);
  }
  // ONE OF THESE TWO PAIRINGS IS IMPOSSIBLE AND THE OTHER WAS MERELY PREFERRED.
  //
  // O2 on a driver that is not clang is an impossibility: the PropertyObserver
  // is an LLVM pass plugin, this driver does not load it, and every cell would
  // read BROKEN_MEASUREMENT. That refusal stays, and it is taken before a
  // compile.
  //
  // O3 on clang was refused for the same shape of reason and it is not the same
  // kind of reason. Nothing stops it: `read-wipe.py` and `objdump_fill.py` match
  // x86-64 disassembly -- a vector register zeroed against itself and stored, an
  // immediate zero stored, a call to `memset`/`__memset_chk` -- and none of those
  // is a spelling only gcc emits; `lib/disasm.mjs` compiles and links with
  // whatever `--cc` names and stubs the symbols the LINKER reported, which is
  // vendor-neutral; and `lib/bufferbytes.mjs` establishes its count with
  // `_Static_assert` under `-fsyntax-only`, which clang has. The refusal said the
  // pass observer "says more", which is a preference about which instrument is
  // more informative -- and it foreclosed the cheapest validation this lane's
  // newest instrument has: run O3 over clang cells where O2 has already answered,
  // and every cell gets a THREE-WAY reading on one vendor. A disagreement there
  // is localisable in a way a gcc-only O3 table never is, because the gcc table
  // has no second opinion to disagree with.
  //
  // So it is allowed. What is still refused is `--write-data` for it, and for a
  // reason that is an impossibility rather than a preference: `lib/record.mjs`
  // `dataFileName` names the record after the COMPILER alone, so an O3 run on
  // clang would write `oracle-agreement-clang-18.json` over the O2 record that is
  // this lane's measured result. See `writeDataRefusals`.
  for (const cc of args.ccs) {
    if (args.secondOracle === 'O2' && defaultSecondOracle(cc) !== 'O2') {
      usage(`--second-oracle O2 with --cc ${vendorLabel(cc)}: `
        + 'the PropertyObserver is an LLVM pass plugin and this driver does not load it. Every cell would read '
        + 'BROKEN_MEASUREMENT and the table would be a statement about a plugin that never ran. Use --second-oracle O3.');
    }
  }
  // Said out loud, because a run whose columns are not the vendor's default is a
  // run whose report will be read as though they were.
  const offDefault = args.secondOracle === 'O3' && args.ccs.some((cc) => defaultSecondOracle(cc) === 'O2');
  if (offDefault) {
    process.stderr.write('run-oracle-agreement.mjs: --second-oracle O3 on a clang driver. This is the THREE-WAY '
      + 'reading -- O1, and O3 over cells O2 has already answered -- and not the lane\'s default columns for this '
      + 'vendor. The record cannot be written from it (--write-data is refused): the tracked file is named after '
      + 'the compiler alone and would overwrite the O2 record.\n');
  }
  if (args.secondOracle === 'O3' && args.diagnoseCallSites) {
    usage('--diagnose-callsites with --second-oracle O3: the call-site count is emitted with -emit-llvm and '
      + 'diagnoses what O2 could be asked. What bounds O3 is the byte count, which every O3 run establishes '
      + 'per cell and lists its refusals of by id.');
  }
  if (args.secondOracle === 'O2' && args.restrictDomain) {
    usage('--restrict-domain is an O3 filter: it selects for a single wipe with a length the compiler can '
      + 'evaluate. O2 reads a call-site count and is not bounded that way; its own domain is what '
      + '--diagnose-callsites measures.');
  }
  // Refused HERE, before a single compile: a run that is going to be told at the
  // end that its record cannot be written is a run whose operator waited for
  // fifty compiles to learn about a typo. The same reason
  // `../repair-loop/run-repair-loop.mjs` puts its --write-data refusals in
  // parseArgs rather than beside the write.
  if (args.writeData) {
    const why = writeDataRefusals(args);
    if (why.length) {
      usage(`--write-data refused: the tracked record is the full run, and this one is not.\n  - ${why.join('\n  - ')}`);
    }
  }
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

// The vocabulary every table, every cell name and every degeneracy message in
// this run is built from. Taken once, here, so nothing downstream has to decide
// which instrument it is printing.
const vocab = VOCABULARIES[args.secondOracle];

/**
 * The optional domain filter, and why it is a filter on the SELECTION.
 *
 * O3 reads ONE (caller, helper, bytes) triple out of a linked program. A subject
 * that performs four wipes, or wipes through a `volatile` function pointer, has
 * no such triple; `locateWipe` says so without a compiler, so the run can decline
 * to spend a build on a cell it would exclude by name afterwards. Applied before
 * the balancing, so `--per-bucket` still draws equally from the two O1 verdicts.
 *
 * Measured over the tracked rows before this was written: of the 321 gcc-13
 * erasure generations at `-O2`, 166 have exactly one wipe span and 155 have two
 * or more. Without the filter roughly half of any selection leaves by name.
 */
const domainFilter = (args.restrictDomain && vocab.oracle === 'O3')
  ? (row) => {
    const src = sourcePathOf(row.id);
    if (!existsSync(src)) return false;
    return locateWipe(readFileSync(src, 'utf8'), row.fn).located;
  }
  : null;

const chosen = selectCells(rows, {
  ccs: args.ccs, opts: args.opts, perBucket: args.perBucket, ids: args.ids, keep: domainFilter,
});

// ---- the dry run ------------------------------------------------------------
//
// Exit 3, deliberately. A dry run has measured nothing, and a lane whose
// "nothing was measured" path exits 0 is a lane that goes green in CI the day
// someone adds --dry-run to make the job faster.
if (args.dryRun) {
  const sizes = bucketSizes(rows, { ccs: args.ccs, opts: args.opts });
  process.stdout.write('DRY RUN -- nothing was compiled and no oracle was consulted.\n');
  process.stdout.write(`second oracle: ${vocab.oracle} -- ${vocab.instrument}\n`);
  process.stdout.write(`columns: O1 ELIMINATED/SURVIVED against ${vocab.oracle} ${vocab.gone}/${vocab.kept}\n`);
  if (domainFilter) {
    process.stdout.write('selection RESTRICTED to the cells the second oracle can be asked (--restrict-domain):\n');
    process.stdout.write('   one wipe span, a call, not through a volatile function pointer. The denominator of\n');
    process.stdout.write('   a restricted run is over that domain and is not a statement about the corpus.\n');
  }
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

// ---- can the chosen second channel run at all? ------------------------------
const lab = resolve(args.out);
if (insideRepo(lab)) {
  process.stderr.write('run-oracle-agreement.mjs: --out is inside the repository; measurement output must not be\n');
  process.exit(4);
}

const plugin = args.observer ? resolve(args.observer) : null;
// Exit 3 rather than an empty table, on either channel. "0/0, they agree
// perfectly" because the plugin was not built -- or because objdump is not
// installed -- is the worst output this lane could produce.
const channel = vocab.oracle === 'O3'
  ? await channelAvailableO3()
  : channelAvailable({ plugin });
if (!channel.available) {
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

// The effect-symbol list is what the PASS is configured with. O3 reads
// instructions, not call sites, and has no symbol list to be handed; asking the
// registry for one on an O3 run would make a missing registry stop a run that
// never needed it.
let symbols = null;
if (vocab.oracle === 'O2') {
  try {
    symbols = effectSymbols();
  } catch (err) {
    process.stderr.write(`run-oracle-agreement.mjs: ${err.message}\n`);
    process.exit(3);
  }
}

// ---- the byte count, established before anything is linked -----------------
//
// THE FIRST THING AN O3 RUN DOES, and the thing it is most likely to be wrong
// about if it skipped. `lib/bufferbytes.mjs` has the argument in full; the
// summary is that the tracked rows carry no buffer size, that a default would
// turn every surviving wipe of another size into `PARTIAL`, and that a number
// read out of the source text is the mistake this repository has already made
// twice. So the number comes from the compiler, one cell at a time, with a
// positive control at the probe point, and a cell that does not get one leaves
// the denominator BY NAME.
//
// Cached by generation: the length is a property of the source, not of the
// level, so a cell at `-O0` and the same cell at `-O2` share one establishment.
const bytesFor = new Map();
const bytesRefusals = [];
if (vocab.oracle === 'O3') {
  const ids = [...new Set(chosen.map((c) => c.id))];
  process.stdout.write(`\nestablishing the byte count for ${ids.length} generation(s), by constant-expression evaluation:\n`);
  for (const c of chosen) {
    if (bytesFor.has(c.id)) continue;
    const src = sourcePathOf(c.id);
    if (!existsSync(src)) continue;
    let got;
    try {
      // eslint-disable-next-line no-await-in-loop
      got = await establishBytes({ cc: c.cc, lab, id: c.id, src: readFileSync(src, 'utf8'), fn: c.fn });
    } catch (err) {
      // The probe compiler could not be RUN. That is a check that could not be
      // completed, and continuing would establish nothing for every remaining
      // cell and report the whole run as "no byte count could be established"
      // -- a sentence about the corpus, produced by a missing compiler.
      process.stderr.write(`run-oracle-agreement.mjs: ${err.message}\n`);
      process.exit(3);
    }
    bytesFor.set(c.id, got);
    if (!got.established) bytesRefusals.push({ id: c.id, reason: got.reason, why: got.why });
    process.stderr.write(`  ${c.id.padEnd(26)} ${got.established ? `${got.bytes} bytes (${got.probes} probes)` : `REFUSED: ${got.why}`}\n`);
  }
  const established = [...bytesFor.values()].filter((b) => b.established).length;
  process.stdout.write(`   ${established} established, ${bytesFor.size - established} refused by name and kept out of the denominator\n`);
  if (established === 0) {
    // Not exit 2 by way of an empty table: a run in which the read-out itself
    // never worked is a check that could not be completed, and it must not look
    // like a corpus in which no wipe had a length.
    process.stderr.write('run-oracle-agreement.mjs: no byte count could be established for any selected cell; '
      + 'the read-out is not working on this host, which is not a fact about the corpus\n');
    process.exit(3);
  }
}

// ---- measure ----------------------------------------------------------------
const pairs = [];
const liveCells = [];
for (const c of chosen) {
  const src = sourcePathOf(c.id);
  if (!existsSync(src)) {
    // The generation named by a tracked row is not in the corpus directory. A
    // cell with no source is not a cell whose oracles disagreed.
    pairs.push({ ...c, o2: null });
    continue;
  }
  let o2;
  if (vocab.oracle === 'O3') {
    const bytes = bytesFor.get(c.id);
    if (!bytes || !bytes.established) {
      // BY NAME, never defaulted. The reading this cell does not get is the
      // reading nobody could have taken: `classifyPair` files it under the
      // channel's own reason word and `summariseExclusions` lists it with its
      // id, which is what keeps this from being a quiet drop.
      o2 = {
        finalState: 'NOT_OBSERVED',
        control: null,
        brokenReason: bytes ? bytes.reason : REASON.O3_BYTES_UNESTABLISHED,
        brokenDetail: bytes ? null : 'the generation was not probed',
      };
    } else {
      try {
        o2 = await observeCellO3({
          cc: c.cc, opt: c.opt, lab, id: c.id, fn: c.fn, srcPath: src,
          bytes: bytes.bytes, helper: bytes.helper,
        });
      } catch (err) {
        process.stderr.write(`run-oracle-agreement.mjs: ${err.message}\n`);
        process.exit(4);
      }
      // The compiler's and the linker's own text, which can name the lab, goes
      // to stderr and no further. It is deliberately not a field of the reading
      // that reaches the report.
      if (o2.diagnostics) process.stderr.write(`     ${c.id}: ${o2.diagnostics.split('\n')[0]}\n`);
      delete o2.diagnostics;
    }
  } else {
    try {
      o2 = await observeCell({
        plugin, cc: c.cc, opt: c.opt, lab, id: c.id, fn: c.fn, srcPath: src, symbols,
      });
    } catch (err) {
      process.stderr.write(`run-oracle-agreement.mjs: ${err.message}\n`);
      process.exit(4);
    }
  }
  // The O1 half comes from the index rather than from the selection, so that a
  // `--ids` run that named a cell the selector would not have chosen still gets
  // the row that actually belongs to it.
  const row = index.get(keyOf(c.id, c.cc, c.opt)) || null;

  // ---- O1, recomputed NOW, as a THIRD column --------------------------------
  //
  // The table below still grades the TRACKED verdict. This column exists so that
  // an off-diagonal cell can be attributed: tracked == live means the two
  // instruments disagree about this build, and tracked != live means the O1
  // reading itself has moved since the corpus run and the cell says nothing
  // about the second oracle either way. Lab output only -- see lib/liveo1.mjs.
  let live = null;
  if (args.liveO1) {
    try {
      live = await recomputeO1({ cc: c.cc, opt: c.opt, lab, id: c.id, fn: c.fn, srcPath: src });
    } catch (err) {
      process.stderr.write(`run-oracle-agreement.mjs: ${err.message}\n`);
      process.exit(4);
    }
    liveCells.push({ id: c.id, cc: c.cc, opt: c.opt, tracked: row ? row.verdict : null, live: live.verdict });
  }

  pairs.push({ ...c, o1: row ? o1Of(row) : null, o2, live });
  process.stderr.write(`  ${c.id} ${c.cc} ${c.opt}  O1=${row ? row.verdict : '(no row)'}`
    + `${live ? ` O1live=${live.verdict}` : ''}`
    + `  ${vocab.oracle}=${o2.finalState} control=${o2.control ?? '-'}`
    + `${o2.brokenReason ? ` (${o2.brokenReason})` : ''}\n`);
}

// The live column, summarised. Computed even when the mode was off, so the
// report always carries the three counts and a reader can see that the column
// exists and was not run rather than inferring it from a missing field.
const drift = args.liveO1
  ? summariseDrift(liveCells)
  : { total: 0, byDrift: { [DRIFT.SAME]: 0, [DRIFT.MOVED]: 0, [DRIFT.NOT_RECOMPUTED]: pairs.length }, moved: [], meaning: 'O1 was not recomputed in this run (--live-o1 was not given), so nothing here says whether the tracked reading still reproduces' };

const tab = tabulate(pairs, { vocab });
const verdict = laneVerdict(tab);

// ---- was O2 ASKABLE at all? -------------------------------------------------
//
// The diagnosis behind the README's "the 23 exclusions are the boundary of what
// O2 can be ASKED". O2 watches a CALL SITE; a wipe written as a volatile pointer
// loop has none, so `ABSENT` there is O2 declining a question rather than
// answering it. Counted rather than asserted: the first attempt at this split
// grepped the source for `memset(` and matched the word inside the files' own
// comments. See lib/callsites.mjs.
let callSites = null;
if (args.diagnoseCallSites) {
  const symbolList = symbolsOf(symbols);
  const above = tab.strata.find((s) => s.name === STRATUM.ABOVE_O0) || null;
  const excludedKeys = new Set((above ? above.excluded.cells : []).map((c) => keyOf(c.id, c.cc, c.opt)));
  const perId = new Map();
  const bySymbol = Object.fromEntries(symbolList.map((s) => [s, 0]));
  const cells = [];
  for (const p of pairs) {
    if (stratumOf(p.opt) !== STRATUM.ABOVE_O0) continue;
    const src = sourcePathOf(p.id);
    if (!existsSync(src)) continue;
    if (!perId.has(p.id)) {
      let ir;
      try {
        ir = await emitIrAtO0({ cc: p.cc, srcPath: src, lab, id: p.id });
      } catch (err) {
        // Exit 3 and not 4: the IR could not be produced, so a check could not
        // be completed. Writing the record anyway would put a split in a tracked
        // file that was measured over the cells the compiler happened to manage.
        process.stderr.write(`run-oracle-agreement.mjs: could not emit -O0 IR for ${p.id}: ${String(err.message).slice(0, 160)}\n`);
        process.exit(3);
      }
      const c = countIrCallSites(ir, symbolList, p.fn);
      perId.set(p.id, c);
      for (const s of symbolList) bySymbol[s] += c.bySymbol[s];
    }
    const counted = perId.get(p.id);
    cells.push({
      id: p.id,
      excluded: excludedKeys.has(keyOf(p.id, p.cc, p.opt)),
      count: counted.inFile,
      inFunction: counted.inFunction,
      functionSeen: counted.functionSeen,
    });
  }
  const byFile = splitByCallSites(cells);
  const byFunction = splitByCallSites(cells.map((c) => ({ excluded: c.excluded, count: c.inFunction })));
  callSites = {
    // The word the README's table needs, and the one this flag exists to earn:
    // `tool` means these four figures were counted by this run, `lab-run` means
    // they were transcribed from a run's prose. There is no third state.
    provenance: 'tool',
    scope: 'the -O0 IR of each corpus generation, WITHOUT the appended control',
    symbols: symbolList,
    stratum: STRATUM.ABOVE_O0,
    cells: splitTotal(byFile),
    generations: perId.size,
    bySymbol,
    // The README counts "the -O0 LLVM IR of each corpus file", so `split` is the
    // file-scoped one its table is about. The function-scoped count is the
    // closer analogue of what O2 watches and is recorded beside it rather than
    // instead of it; a disagreement between the two is a finding.
    split: byFile,
    splitInSubjectFunction: byFunction,
    perfect: splitIsPerfect(byFile),
    perfectInSubjectFunction: splitIsPerfect(byFunction),
    perGeneration: [...perId.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([id, c]) => ({ id, inFile: c.inFile, inFunction: c.inFunction, subjectFunctionSeen: c.functionSeen })),
  };
  process.stdout.write(`\nIR wipe call sites at -O0 (${callSites.generations} generations, ${callSites.cells} cells above -O0):\n`);
  process.stdout.write(`   excluded cells: ${byFile.excludedZero} with none, ${byFile.excludedNonZero} with at least one\n`);
  process.stdout.write(`   graded cells:   ${byFile.gradedZero} with none, ${byFile.gradedNonZero} with at least one\n`);
  process.stdout.write(`   the split is ${callSites.perfect ? 'perfect' : 'NOT perfect -- O2 refused a cell that had a call site to watch, or graded one that had none'}\n`);
}

// ---- the report -------------------------------------------------------------
//
// `compileError` is deliberately NOT carried into the report: it is the driver's
// own message and it names the lab directory, which is an absolute path on the
// measuring machine. It is printed to stderr above and stops there.
const report = {
  schemaVersion: 'vibeguard.oracle-agreement/1',
  oracles: {
    O1: 'verdictOf (compiler/eval/ai-generated/lib/ablation-cell.mjs) -- differential assembly text, read from the TRACKED rows and not re-measured in this run',
    // Named from the vocabulary rather than from a literal: a gcc report that
    // described itself as a run of the pass observer would be describing the run
    // that cannot happen.
    [vocab.oracle]: `${vocab.instrument}, measured in this run`,
  },
  secondOracle: {
    name: vocab.oracle,
    gone: vocab.gone,
    kept: vocab.kept,
    notInTable: [...vocab.notInTable],
  },
  requested: {
    compilers: args.ccs.map(vendorLabel),
    levels: args.opts,
    perBucket: args.perBucket,
    ids: args.ids,
    rowsFile: args.rows === ROWS_PATH ? '(tracked default)' : '(a file named on the command line)',
    corpus: '(compiler/eval/ai-generated/generated-corpus/r2)',
    restrictDomain: args.restrictDomain,
    liveO1: args.liveO1,
  },
  selected: chosen.length,
  strata: tab.strata,
  seen: tab.seen,
  accountedFor: tab.accountedFor,
  // THE LIVE O1 COLUMN LIVES HERE AND NOWHERE ELSE. It is lab output: the
  // tracked record in `data/` carries what the lane measured against the FROZEN
  // rows, and today's recompilation of a frozen number is a different claim that
  // must not be mixed into it.
  liveO1: args.liveO1 ? {
    ...drift,
    cells: liveCells,
    note: 'the table above grades the TRACKED O1; this column says only whether that reading still reproduces with this driver',
  } : { ...drift, cells: [], note: '--live-o1 was not given, so O1 was not recomputed' },
  /**
   * The numbers the WORDS were folded from, per cell.
   *
   * `../lto-window/run-lto-window.mjs` keeps the same three and says why: a byte
   * count that only ever appears inside a sentence cannot be reconciled against
   * anything. `PARTIAL` without the number it was partial OF is not a reading
   * anybody can check, and `ABSENT` without the count that was asked for is not
   * one either. The table cells carry the word; this carries the arithmetic.
   *
   * Lab output. It is not in the tracked record, which carries counts of cells
   * and not readings of them.
   */
  readings: pairs.map((x) => ({
    id: x.id,
    cc: x.cc,
    opt: x.opt,
    o1: x.o1 ? x.o1.verdict : null,
    o1Live: x.live ? x.live.verdict : null,
    second: x.o2 ? x.o2.finalState : null,
    control: x.o2 ? (x.o2.control === undefined ? null : x.o2.control) : null,
    brokenReason: x.o2 && x.o2.brokenReason ? x.o2.brokenReason : null,
    fill: x.o2 && x.o2.fill ? x.o2.fill : null,
    controlFill: x.o2 && x.o2.controlFill ? x.o2.controlFill : null,
    bytesAskedFor: x.o2 && x.o2.bytesAskedFor !== undefined ? x.o2.bytesAskedFor : null,
    helper: x.o2 && x.o2.helper !== undefined ? x.o2.helper : null,
    // How many symbols the link had to be given a stub for. A cell whose link
    // needed twenty stubs is a cell worth looking at before its reading is
    // quoted; the NAMES are here too, because they come from the corpus source
    // and not from a machine.
    stubbed: x.o2 && x.o2.stubbed ? x.o2.stubbed : null,
    firstLossPass: x.o2 && x.o2.firstLossPass !== undefined ? x.o2.firstLossPass : null,
  })),
  bytes: vocab.oracle === 'O3' ? {
    provenance: 'compiler',
    how: 'constant-expression evaluation of the wipe\u2019s own length argument, with a live/dead assertion pair at the probe point as the positive control',
    established: [...bytesFor.values()].filter((b) => b.established).length,
    refused: bytesRefusals.length,
    refusals: bytesRefusals,
    perGeneration: [...bytesFor.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([id, b]) => (b.established
        ? { id, bytes: b.bytes, helper: b.helper, object: b.object, probes: b.probes, established: true }
        : { id, established: false, reason: b.reason, why: b.why })),
    control: controlBytes(),
  } : null,
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

// ---- the tracked record -----------------------------------------------------
//
// Written LAST, and after the lab copy: a run whose record is refused has to
// stay debuggable from its own lab directory. The refusals that depend only on
// the arguments already fired in parseArgs; what is left here are the two that
// can only be checked against the bytes -- a machine's path, and a number that
// is not an integer.
if (args.writeData) {
  const sha256File = (p) => createHash('sha256').update(readFileSync(p)).digest('hex');
  // The disassembler's own version line, for an O3 record. Read from the reader
  // rather than from a second invocation of objdump, so the record names the
  // binary the reading actually went through.
  let objdumpVersion = null;
  if (vocab.oracle === 'O3') {
    const seen = pairs.map((x) => x.o2 && x.o2.objdump).filter(Boolean);
    objdumpVersion = seen.length ? seen[0] : null;
    if (new Set(seen).size > 1) {
      process.stderr.write('run-oracle-agreement.mjs: the cells were read through more than one objdump; '
        + 'the record would name one of them as though it were all of them\n');
      process.exit(5);
    }
  }
  let ccVersion = null;
  try {
    const { stdout } = await run(args.ccs[0], ['--version'], { timeout: 30000 });
    // The triple only. `clang --version` also prints its InstalledDir, which is
    // an absolute path on the measuring machine.
    ccVersion = versionTriple(stdout);
  } catch { ccVersion = null; }

  const record = buildRecord({
    tab,
    verdict,
    chosen,
    pairs,
    args,
    vocab,
    toolchain: { version: ccVersion, vendor: /^(gcc|g\+\+)/.test(vendorLabel(args.ccs[0])) ? 'gcc' : 'clang' },
    // The plugin is O2's identification and there is none on an O3 run. What
    // identifies O3 is the reader and the disassembler it read through, and the
    // record carries that instead rather than leaving the field out.
    plugin: plugin ? { basename: basename(plugin), sha256: sha256File(plugin) } : null,
    instrument: vocab.oracle === 'O3'
      ? { reader: basename(READ_WIPE), objdump: objdumpVersion, python: basename(PYTHON) }
      : null,
    domain: {
      restricted: args.restrictDomain,
      what: args.restrictDomain
        ? 'cells with exactly one wipe span, written as a call, not through a volatile function pointer'
        : 'every erasure cell the selector drew; cells the second oracle cannot be asked leave by name',
    },
    bytes: vocab.oracle === 'O3' ? {
      provenance: 'compiler',
      established: [...bytesFor.values()].filter((b) => b.established).length,
      refused: bytesRefusals.length,
      controlBytes: controlBytes().bytes,
    } : null,
    rows: {
      file: args.rows === ROWS_PATH ? '(tracked default)' : '(a file named on the command line)',
      sha256: sha256File(args.rows),
    },
    callSites,
    generatedAt: new Date().toISOString(),
    node: process.version,
  });

  const written = writeRecord(record, { cc: args.ccs[0] });
  if (!written.written) {
    if (written.hits.length) process.stderr.write(`run-oracle-agreement.mjs: the tracked record would carry an absolute path (${written.hits.join(', ')})\n`);
    if (written.floats.length) {
      process.stderr.write(`run-oracle-agreement.mjs: the tracked record would carry a number that is not an integer (${written.floats.join(', ')}); `
        + 'a rate belongs in the record as an integer pair, never as a percentage\n');
    }
    process.stderr.write('run-oracle-agreement.mjs: nothing was written to data/\n');
    process.exit(5);
  }
  process.stdout.write(`\ntracked record: compiler/eval/oracle-agreement/data/${dataFileName(args.ccs[0])}\n`);
}

// ---- print ------------------------------------------------------------------
process.stdout.write(`\nO1 = verdictOf, differential assembly text (tracked rows)\n`);
process.stdout.write(`${vocab.oracle} = ${vocab.instrument} (measured in this run)\n`);
process.stdout.write(`${pairs.length} cells observed; ${tab.accountedFor} accounted for\n`);
if (args.restrictDomain) {
  process.stdout.write('the selection was RESTRICTED to the cells the second oracle can be asked, so every\n');
  process.stdout.write(`count below is over that domain and not over the ${vendorLabel(args.ccs[0])} half of the corpus\n`);
}
if (args.liveO1) {
  process.stdout.write(`\nO1 recomputed with this driver: ${drift.byDrift[DRIFT.SAME]} of ${drift.total} cells read the same as the tracked rows, ${drift.byDrift[DRIFT.MOVED]} moved\n`);
  for (const m of drift.moved) {
    process.stdout.write(`   MOVED ${m.id.padEnd(26)} ${m.cc} ${m.opt.padEnd(4)} tracked=${m.tracked} live=${m.live}\n`);
  }
  process.stdout.write(`   ${drift.meaning}\n`);
} else {
  process.stdout.write('O1 was NOT recomputed in this run (--live-o1 was not given): a disagreement below cannot\n');
  process.stdout.write('be told apart from a toolchain that has moved since the corpus run\n');
}

for (const s of tab.strata) {
  process.stdout.write(`\n== ${s.name} ==  levels: ${s.levels.length ? s.levels.join(', ') : '(none run)'}\n`);
  if (s.name === STRATUM.AT_O0) {
    process.stdout.write('   tabulated separately and NEVER pooled: at -O0 the tracked rows have never\n');
    process.stdout.write('   recorded an elimination, so agreement here means "neither instrument can\n');
    process.stdout.write('   report the phenomenon", not "the instruments agree".\n');
  }
  // The column headings come from the stratum's own recorded columns. A literal
  // here would print `O2 LOST` over a count of O3's `ABSENT`, which is the exact
  // merge of two vocabularies this lane exists to refuse.
  const col = s.columns;
  process.stdout.write(`                   ${`${col.oracle} ${col.gone}`.padStart(9)}   ${`${col.oracle} ${col.kept}`.padStart(10)}\n`);
  process.stdout.write(`   O1 ELIMINATED   ${String(s.table[`ELIMINATED/${col.gone}`]).padStart(8)}   ${String(s.table[`ELIMINATED/${col.kept}`]).padStart(10)}\n`);
  process.stdout.write(`   O1 SURVIVED     ${String(s.table[`SURVIVED/${col.gone}`]).padStart(8)}   ${String(s.table[`SURVIVED/${col.kept}`]).padStart(10)}\n`);
  process.stdout.write(`   on the diagonal: ${formatRate(s.agreement)}\n`);
  // Why a stratum is not discriminating, as a list rather than as three
  // conditional fragments concatenated: an empty denominator is degenerate on
  // both sides at once, so the naive spelling runs the words together.
  const why = s.den === 0
    ? ['empty denominator']
    : [s.degenerate.o1 ? 'O1 marginal degenerate' : null, s.degenerate.o2 ? `${col.oracle} marginal degenerate` : null].filter(Boolean);
  process.stdout.write(`   discriminating: ${s.discriminating ? 'yes' : `NO -- ${why.join('; ')}`}\n`);

  if (s.offDiagonal.length) {
    process.stdout.write(`   OFF-DIAGONAL (${s.offDiagonal.length}) -- each of these is a case to diagnose, not a failure:\n`);
    for (const c of s.offDiagonal) {
      process.stdout.write(`     ${c.cell.padEnd(20)} ${c.id.padEnd(26)} ${c.cc} ${c.opt.padEnd(4)} idiom=${c.idiom ?? '-'} O1=${c.o1Verdict} ${col.oracle}=${c.o2State} firstLoss=${c.firstLossPass ?? '-'}\n`);
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
if (vocab.oracle === 'O3') {
  const established = [...bytesFor.values()].filter((b) => b.established).length;
  process.stdout.write(`byte counts: ${established} established by constant-expression evaluation, ${bytesRefusals.length} refused by name and excluded\n`);
  process.stdout.write('a cell whose byte count could not be established was never graded against a default: there is none\n');
}

process.exit(verdict.code);

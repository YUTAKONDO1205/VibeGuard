#!/usr/bin/env node
/**
 * run-spike -- the spike/recovery self-test, run on its own.
 *
 * Mixes two known translation units into a measurement the way an analytical
 * laboratory spikes a sample, and reports how many of the two came back
 * reading what they were registered to read. Anything but 2/2 in any
 * configuration makes the run INVALID; so does the deliberately broken run
 * failing to make the gate go red.
 *
 *   node compiler/eval/spike/run-spike.mjs --out ~/vg-lab/spike
 *   node compiler/eval/spike/run-spike.mjs --cc clang-18,gcc-13 --opt -O0,-O2 --out ~/vg-lab/spike
 *   node compiler/eval/spike/run-spike.mjs --out ~/vg-lab/spike --json
 *
 * Everything a run produces -- sources, listings, the results file -- goes under
 * --out, which must lie outside the repository. The one exception is
 * `--write-data`, which additionally writes `data/spike-gate.json` inside the
 * lane: the matrix of what the gate read, kept in the tree so that the numbers
 * in README.md are checked by test/data.test.mjs on every run of the suite
 * instead of being prose that cannot fail. It is refused for anything but a
 * full run (see lib/data-record.mjs).
 *
 * EXIT CODES (interfaces.md section 7)
 *   0  every requested configuration recovered 2/2, at least one of them
 *      registered two DIFFERENT answers, and the injected run went red
 *   2  the gate is RED: a spike did not read what was registered, a spike did not
 *      produce a reading at all, a configuration was never registered, no
 *      configuration in the run registered two different answers (so 2/2 was
 *      also what an instrument stuck on one word would have scored), or the
 *      injected run stayed green (all reported as NOT ESTABLISHED)
 *   3  a check could not be completed: a requested compiler is not installed on
 *      this host. This lane does not call that `UNSUPPORTED`; interfaces.md
 *      section 3.1 defines that word for a toolchain that refused an invocation
 *      and does not settle whether an absent one is covered
 *   4  the pre-registered expectations are missing or malformed, the arguments
 *      were bad, the lab is inside the repository, the report would carry an
 *      absolute path and was refused, or `--write-data` was asked of an
 *      otherwise green run that is not the full matrix (the missing pieces are
 *      named). A RED run refused a data write keeps the gate's own 2 or 3: the
 *      verdict is the more fundamental fact about it
 *   5  `--write-data` built a record carrying a value a tracked file may not
 *      carry -- a non-integer number, or a string naming a machine -- and wrote
 *      nothing. The lab report at --out is unaffected and was already written
 *
 * A compile failure of a spike lands at 2, not at 1. The gate's business is
 * whether this run may be believed, and a run whose own spike would not compile
 * may not be -- calling that "the underlying tool failed" would tell a caller
 * something true about the compiler and nothing about the run.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

import { runSpikeGate, summarise, INCOMPLETE } from './lib/gate.mjs';
import { loadExpected } from './lib/claims.mjs';
import { DATA_FILE, spikeDataRecord, unwritableValues, writeDataRefusals } from './lib/data-record.mjs';
import { absolutePathHits } from '../repair-loop/lib/provenance.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

const DEFAULT_CCS = ['clang-18', 'gcc-13'];
const DEFAULT_OPTS = ['-O0', '-O2'];

function usage(msg) {
  if (msg) process.stderr.write(`run-spike.mjs: ${msg}\n`);
  process.stderr.write(
    'usage: run-spike.mjs --out <lab dir> [--cc a,b] [--opt -O0,-O2] [--inject-at -O2] [--json] [--no-write]\n'
    + '                     [--observer <libPropertyObserver.so>] [--observer-opt -O2] [--observer-cc clang-18]\n'
    + '                     [--write-data]\n'
    + '\n'
    + `  --write-data  also write the tracked record data/${DATA_FILE}: the matrix of what the gate\n`
    + '                read, which test/data.test.mjs checks the README\'s numbers against. Refused\n'
    + '                for anything but a full run -- every registered configuration, both channels,\n'
    + '                the injection graded on each -- and refused with --no-write.\n',
  );
  process.exit(4);
}

function parseArgs(argv) {
  const args = {
    ccs: DEFAULT_CCS, opts: DEFAULT_OPTS, out: process.env.SPIKE_LAB || null,
    json: false, write: true, writeData: false, injectAt: null,
    observer: null, observerOpt: '-O2', observerCc: 'clang-18',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { const v = argv[++i]; if (v === undefined) usage(`${a} needs a value`); return v; };
    if (a === '--out') args.out = next();
    else if (a === '--cc') args.ccs = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--opt') args.opts = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--inject-at') args.injectAt = next().split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--observer') args.observer = next();
    else if (a === '--observer-opt') args.observerOpt = next();
    else if (a === '--observer-cc') args.observerCc = next();
    else if (a === '--json') args.json = true;
    else if (a === '--no-write') args.write = false;
    else if (a === '--write-data') args.writeData = true;
    else if (a === '-h' || a === '--help') usage(null);
    else usage(`unknown option ${a}`);
  }
  if (!args.out) usage('--out is required (or set SPIKE_LAB); it must be outside the repository');
  if (!args.ccs.length) usage('--cc listed no compiler');
  if (!args.opts.length) usage('--opt listed no level');
  return args;
}

const args = parseArgs(process.argv.slice(2));
const lab = resolve(args.out);

let gate;
try {
  gate = await runSpikeGate({
    ccs: args.ccs,
    opts: args.opts,
    lab,
    injectAt: args.injectAt,
    observer: args.observer ? { plugin: resolve(args.observer), cc: args.observerCc, opt: args.observerOpt } : null,
  });
} catch (err) {
  process.stderr.write(`run-spike.mjs: ${err.message}\n`);
  process.exit(4);
}

// The report. It carries no path and no digest of this machine: the run is
// identified by what it compiled and what read, so the same run on another host
// produces the same bytes.
const report = {
  schemaVersion: gate.schemaVersion,
  established: gate.established,
  incomplete: gate.incomplete,
  unavailable: gate.unavailable,
  requested: { compilers: args.ccs, levels: args.opts, injectedAt: args.injectAt || [args.opts[args.opts.length - 1]] },
  subjects: gate.subjects || [],
  configurations: (gate.configurations || []).map((c) => ({
    channel: c.channel,
    vendor: c.vendor,
    opt: c.opt,
    recovery: c.grade.recovery,
    recovered: c.grade.recovered,
    held: c.grade.held,
    // Whether this configuration's two registered answers differ, and the one
    // word both were registered to read when they do not. A reader of the file
    // can then see which rows could have caught an instrument stuck on a verdict
    // and which could not.
    discriminating: c.grade.discriminating,
    sharedAnswer: c.grade.sharedAnswer,
    violations: c.grade.violations,
    readings: c.readings,
  })),
  injected: gate.injected ? {
    misspeltSuffix: gate.injected.misspeltSuffix,
    wentRed: gate.injected.held,
    violations: gate.injected.violations,
    configurations: gate.injected.configurations.map((c) => ({
      channel: c.channel,
      vendor: c.vendor,
      opt: c.opt,
      recovery: c.grade.recovery,
      wentRed: c.grade.wentRed,
      // An injection at an unregistered configuration is red whatever came back,
      // so `wentRed` alone cannot be read as "the gate was shown to refuse".
      gradeable: c.grade.gradeable,
      redBecause: c.grade.redBecause,
      readings: c.readings,
    })),
  } : null,
  observerChannel: gate.observer ? {
    requested: gate.observer.requested,
    available: gate.observer.available,
    reason: gate.observer.reason,
    vendor: gate.observer.vendor,
    opt: gate.observer.opt,
  } : null,
  verdict: gate.verdict,
};

const text = JSON.stringify(report, null, 2);
const hits = absolutePathHits(text);
if (hits.length) {
  // WHY the run failed comes first. This guard also fires on the reason text,
  // and a run refused for something else -- a claims file that is not there, a
  // compiler named by an absolute path that is not installed -- must not be
  // reported to the operator as a path problem and nothing else. Measured on
  // 2026-09-12: with the claims file moved away, the path refusal was the only
  // line printed, and the missing file was never mentioned.
  for (const why of gate.verdict.reasons) process.stderr.write(`run-spike.mjs: ${why}\n`);
  process.stderr.write(`run-spike.mjs: the report carries an absolute path (${hits.join(', ')}); refusing to write it\n`);
  process.exit(gate.incomplete === INCOMPLETE.NO_COMPILER ? 3 : 4);
}

if (args.write) {
  mkdirSync(lab, { recursive: true });
  writeFileSync(join(lab, 'spike-gate.json'), text + '\n', 'utf8');
}
if (args.json) process.stdout.write(text + '\n');

const summaryLine = summarise(gate);

// ------------------------------------------------------------------ report ---
process.stdout.write(`${summaryLine}\n`);
for (const c of gate.configurations || []) {
  process.stdout.write(`  ${c.vendor} ${c.opt} [${c.channel}]  recovery ${c.grade.recovery}\n`);
  for (const r of c.readings) {
    const extra = r.channel === 'observer'
      ? `subjectResolutionExit=${r.subjectResolutionExit} firstLoss=${r.firstLossPass ?? '-'}`
      : `spans=${r.n_spans}`;
    process.stdout.write(`    ${r.spike.padEnd(13)} verdict=${r.verdict} control=${r.control ?? '-'} ${extra}\n`);
  }
  for (const v of c.grade.violations) {
    process.stdout.write(`    VIOLATION ${v.code}${v.spike ? ` (${v.spike})` : ''}: ${v.detail}\n`);
  }
}
if (gate.injected) {
  process.stdout.write(`  injected (subject name + "${gate.injected.misspeltSuffix}") -- the gate must refuse these\n`);
  for (const c of gate.injected.configurations) {
    const state = c.grade.gradeable === false
      ? 'NOT GRADEABLE -- nothing is registered for this configuration, so the gate is red either way'
      : `the gate went ${c.grade.wentRed ? 'RED' : 'GREEN'}`;
    process.stdout.write(`    ${c.vendor} ${c.opt} [${c.channel}]  recovery ${c.grade.recovery}  ${state}\n`);
    for (const r of c.readings) {
      const extra = r.channel === 'observer' ? ` subjectResolutionExit=${r.subjectResolutionExit}` : '';
      process.stdout.write(`      ${r.spike.padEnd(13)} verdict=${r.verdict} fn=${r.fn}${extra}\n`);
    }
  }
}
if (gate.observer && !gate.observer.requested) {
  process.stdout.write(`  observer channel: NOT OBSERVED -- ${gate.observer.reason}\n`);
} else if (gate.observer && !gate.observer.available) {
  process.stdout.write(`  observer channel: NOT OBSERVED -- ${gate.observer.reason}\n`);
}
if (!gate.established) {
  process.stdout.write('\nNOT ESTABLISHED. No measurement taken in this run may be written as data.\n');
  for (const why of gate.verdict.reasons) process.stdout.write(`  - ${why}\n`);
}

// ------------------------------------------------------------ tracked data ---
//
// The one thing this runner puts inside the repository, and the only place the
// README's numbers can be checked from. Refused unless the run is the full
// matrix: a subset, or a run one of whose two channels never ran, written to
// this path would be read as THE result by everyone who reads data/ rather than
// re-running the lane.
//
// It comes after the report on purpose. A refusal is a sentence about what was
// asked for, and the operator still needs the run beside it -- especially the
// NOT ESTABLISHED reasons, which are the refusal's usual cause.
let dataRefused = false;
if (args.writeData) {
  let doc = null;
  try {
    doc = loadExpected();
  } catch (err) {
    process.stderr.write(`run-spike.mjs: --write-data: ${err.message}\n`);
    process.exit(4);
  }
  const why = writeDataRefusals({ gate, args, doc });
  if (why.length) {
    dataRefused = true;
    process.stderr.write(`run-spike.mjs: --write-data refused; data/${DATA_FILE} was not written:\n`);
    for (const w of why) process.stderr.write(`  - ${w}\n`);
    process.stderr.write('run-spike.mjs: record it from a run of every registered configuration, with '
      + '--observer, and the injection graded on each channel -- or do not record this run as the result\n');
  } else {
    const record = spikeDataRecord(gate, args, summaryLine);
    const bad = unwritableValues(record);
    if (bad.length) {
      // Named by JSON path and by what was wrong with the value, never by the
      // value: printing the offending text is the disclosure the scan exists to
      // prevent.
      process.stderr.write('run-spike.mjs: --write-data: the record carries a value a tracked file may '
        + 'not carry, and nothing was written:\n');
      for (const b of bad) process.stderr.write(`  - ${b}\n`);
      process.exit(5);
    }
    const dataDir = join(HERE, 'data');
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(join(dataDir, DATA_FILE), JSON.stringify(record, null, 2) + '\n', 'utf8');
    process.stderr.write(`run-spike.mjs: wrote data/${DATA_FILE}\n`);
  }
}

if (gate.incomplete === INCOMPLETE.BAD_CLAIMS) process.exit(4);
if (gate.incomplete === INCOMPLETE.NO_COMPILER) process.exit(3);
if (!gate.established) process.exit(2);
// A refused --write-data on a run that IS established is an argument problem and
// nothing else, so it gets exit 4 rather than the gate's 0.
process.exit(dataRefused ? 4 : 0);

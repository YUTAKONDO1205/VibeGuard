#!/usr/bin/env node
// intro-passes: read an introduction observer log and report, for every
// element, the (pass, IR unit) pair that first introduced it and the whole
// state series that followed.
//
//   node cli/intro-passes.mjs <log>... [--allow-empty] [--all] [--json <path>]
//
// WHY THE ATTRIBUTION IS A PAIR. LLVM's pipeline nests module inside call graph
// inside function inside loop, and a function pass's callback fires once per
// function -- so "the seventh pass" is not a position anyone can point at. This
// component's own fixture makes the point in one line of output: one pass,
// LoopIdiomRecognizePass, introduces the same element into two different
// functions at two different points, and a flat P0..Pn model would have to
// choose one of them and be wrong about the other.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';

import { Tally } from '../lib/count.mjs';
import { EXIT_INCOMPLETE, EXIT_OK, EXIT_TOOL_FAILED } from '../lib/exit.mjs';
import { elementKey, measurementFault, parseIntroLog } from '../lib/introlog.mjs';
import { crossCheck, passIntroduced } from '../lib/states.mjs';

function parseArgs(argv) {
  const opts = { logs: [], allowEmpty: false, all: false, json: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--allow-empty') opts.allowEmpty = true;
    else if (a === '--all') opts.all = true;
    else if (a === '--json') opts.json = argv[++i];
    else if (a.startsWith('--')) throw new Error(`unknown option ${a}`);
    else opts.logs.push(a);
  }
  return opts;
}

/** The per-log section: what was introduced, by which pass, and the series after. */
function printLog(log, parsed, introduced, problemCount, showAll, out) {
  out.log(`\n--- ${basename(log)} ---`);
  out.log(`control=${parsed.handshake.control} (${parsed.stats.controlFinalState}) `
    + `passesSeen=${parsed.stats.passesSeen} elements=${parsed.stats.elementsTracked} `
    + `scopes=${parsed.stats.scopes} crossCheckDisagreements=${problemCount}`);
  out.log(`at-entry (the front end emitted them): ${parsed.summaries.length - introduced.length}`);
  out.log(`introduced by a pass: ${introduced.length}`);
  for (const i of introduced) {
    out.log(`  ${i.kind} ${i.name}`);
    out.log(`    first introduced by ${i.pass} on ${i.unitKind} ${i.unit} (seq ${i.seq});`
      + ` the pass before it on that unit was ${i.previousAfterPass ?? '(none)'}`);
    const entry = parsed.byElement.get(elementKey(i));
    const series = entry ? entry.series.map((h) => `${h.state}@${h.pass}`).join(' -> ') : '(no series)';
    out.log(`    series: ${series}`);
  }
  if (showAll) {
    for (const s of parsed.summaries.filter((x) => x.atEntry)) {
      out.log(`  [at entry] ${s.kind} ${s.name} in ${s.scope}: ${s.finalState}`);
    }
  }
}

/**
 * Read one log, check it, print its section. Returns what this log contributes
 * to the run's totals; `entry` is null for a log that produced no result.
 *
 * Extracted from `main` for the reason VG-SMELL-003 names: this was the body of
 * a loop inside an 80-line function, and the two ways a log can fail to produce
 * a result — unreadable, and readable but broken — sat far enough apart in that
 * body to read as unrelated. They are the same decision, and they are now
 * adjacent: one returns a skip, the other returns a broken measurement, and
 * neither is allowed to look like a log that was fine.
 */
function readLog(log, showAll, tally, out) {
  let parsed;
  try {
    parsed = parseIntroLog(readFileSync(log, 'utf8'));
  } catch (e) {
    tally.skip(basename(log), `unreadable: ${e.message}`);
    return { broken: 1, disagreements: 0, entry: null };
  }

  const fault = measurementFault(parsed);
  if (fault) {
    // Not a skip. A broken measurement is a result this run cannot produce,
    // and reporting it as anything else is how "we did not look" becomes
    // "it is clean".
    out.error(`intro-passes: ${basename(log)}: ${fault}`);
    return { broken: 1, disagreements: 0, entry: null };
  }
  tally.counted();

  const problems = crossCheck(parsed);
  for (const p of problems) {
    out.error(`intro-passes: ${basename(log)}: the summary and its own history disagree `
      + `on ${p.field} for ${p.element}: summary says ${p.summary}, the series implies ${p.derived}`);
  }

  const introduced = passIntroduced(parsed);
  printLog(log, parsed, introduced, problems.length, showAll, out);
  return {
    broken: 0,
    disagreements: problems.length,
    entry: { log: basename(log), introduced, stats: parsed.stats },
  };
}

export function main(argv, out = console) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    out.error(`intro-passes: ${e.message}`);
    return EXIT_TOOL_FAILED;
  }

  const tally = new Tally('intro-passes', { allowEmpty: opts.allowEmpty });
  tally.input(opts.logs.length);
  if (tally.emptyAndUnauthorised) {
    out.log(tally.render());
    out.error(tally.emptyReason());
    return EXIT_INCOMPLETE;
  }

  let broken = 0;
  let disagreements = 0;
  const all = [];

  for (const log of opts.logs) {
    const r = readLog(log, opts.all, tally, out);
    broken += r.broken;
    disagreements += r.disagreements;
    if (r.entry) all.push(r.entry);
  }

  out.log('');
  out.log(tally.render());
  out.log(`brokenMeasurements=${broken} crossCheckDisagreements=${disagreements}`);
  if (opts.json) writeFileSync(opts.json, `${JSON.stringify(all, null, 2)}\n`, 'utf8');

  if (broken > 0 || disagreements > 0) return EXIT_INCOMPLETE;
  return tally.exitFor(EXIT_OK);
}

if (process.argv[1]?.endsWith('intro-passes.mjs')) {
  process.exit(main(process.argv.slice(2)));
}

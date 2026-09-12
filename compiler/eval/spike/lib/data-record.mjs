/**
 * The tracked record of a full gate run, and the rules for refusing to write one.
 *
 * WHY THIS FILE EXISTS
 *
 * Until 2026-09-12 this lane wrote nothing into the checkout. `--out` took the
 * whole report to a lab directory outside the repository and the only record of
 * what the gate had ever read was prose in README.md. A reviewer asking "show me
 * the run" for the version ladder gets data/version-ladder-sweep.json with its
 * counts and its resolved compiler digests; asking the same of this lane got a
 * paragraph, and a paragraph cannot fail.
 *
 * `--write-data` keeps the half a later run can be checked against: the matrix
 * of configurations, what each spike read, which rows discriminate, and that the
 * injection went red. The listings, the assembly and the observer logs stay in
 * the lab, because they are large and because they are reproducible from this.
 *
 * THREE RULES, AND THEY ARE THE POINT
 *
 *   1. A PARTIAL RUN MAY NOT BE WRITTEN. The tracked record is the full matrix:
 *      every configuration the claims file registers, on both channels, with the
 *      injection graded on each. A subset written to the same path would be read
 *      as the result -- `--opt -O0` alone recovers 2/2 for an instrument that
 *      cannot report an elimination at all, and a record of that run is a record
 *      of nothing. `writeDataRefusals` names every missing piece rather than
 *      failing on the first, so one re-run fixes the whole command.
 *
 *   2. INTEGERS, BOOLEANS AND SHORT STRINGS ONLY. interfaces.md section 5: every
 *      number in a record is an integer and a ratio is a `{num, den}` pair. This
 *      lane has no floats to write -- a recovery is 2 of 2, never 1.0 -- so a
 *      float appearing here means something started computing a rate, and the
 *      run is refused rather than rounded.
 *
 *   3. NO MACHINE. No absolute path, no home directory, no drive letter, no
 *      timestamp. The runner already claims the report "carries no path and no
 *      digest of this machine: the run is identified by what it compiled and
 *      what read, so the same run on another host produces the same bytes". A
 *      tracked file is where that claim is worth something, so the record is
 *      scanned value by value before it is written and the run exits 5 on a hit.
 *      That is also why there is no `generatedAt`: a clock would make two
 *      identical runs produce different bytes, and the drift test could no
 *      longer say the record is the run.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { registeredConfigurations } from './claims.mjs';
import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';

/** The record's own version, distinct from the gate reading's schemaVersion. */
export const RECORD_VERSION = 'vibeguard.spike-gate-data/1';

/** What `--write-data` writes, under the lane's `data/` directory. */
export const DATA_FILE = 'spike-gate.json';

const label = (c) => `${c.vendor} ${c.opt}`;

/**
 * Why this run may NOT be written to `data/`, as sentences naming what is missing.
 *
 * Empty means the run is a full one. Every reason is independent and all of them
 * are collected: an operator who is told only about the absent observer channel
 * re-runs with `--observer` and is then told about the injection.
 *
 * @param {object} a
 * @param {object} a.gate  the reading `runSpikeGate` returned
 * @param {{write: boolean}} a.args  the parsed command line
 * @param {object} a.doc   the loaded claims document
 * @returns {string[]}
 */
export function writeDataRefusals({ gate, args, doc }) {
  const why = [];
  const configurations = (gate && gate.configurations) || [];
  const registered = registeredConfigurations(doc);

  if (!gate || !gate.established) {
    const reasons = gate && gate.verdict && gate.verdict.reasons ? gate.verdict.reasons : [];
    why.push('the gate is NOT ESTABLISHED, so no measurement in this run may be written as data'
      + (reasons.length ? ` (${reasons.join('; ')})` : ''));
  }

  if (args && args.write === false) {
    why.push('--no-write: the tracked record is the same run as the lab report, and a run that '
      + 'declined to write its own report leaves nothing to check the tracked copy against');
  }

  // 1. every registered configuration, on the differential channel
  const graded = new Set(configurations.filter((c) => c.channel === 'differential').map(label));
  const missing = registered.filter((r) => !graded.has(label(r))).map(label);
  if (missing.length) {
    why.push(`a partial run: nothing was measured at ${missing.join(', ')}. The tracked record is the `
      + 'full matrix of every registered configuration, and a subset written to that path would be read '
      + 'as the result');
  }

  // 2. the observer channel, which is opt-in and therefore the easy one to omit
  const obs = gate && gate.observer;
  if (!obs || !obs.requested) {
    why.push('no observer channel: --observer was not given, so only one of the two instruments was '
      + 'gated and a record of this run would not say which');
  } else if (!obs.available) {
    why.push(`the observer channel was asked for and not obtainable: ${obs.reason || 'no reason given'}`);
  }

  // 3. the injection, on every vendor and on the observer channel when it ran
  const inj = gate && gate.injected;
  const injCfgs = (inj && inj.configurations) || [];
  if (!inj || injCfgs.length === 0) {
    why.push('no injection was run, so the gate was never shown to go red in the run being recorded');
  } else {
    if (!inj.held) {
      why.push('the injection did not make the gate go red, so this run is not evidence that the gate '
        + 'can refuse anything');
    }
    const injectedVendors = new Set(injCfgs.filter((c) => c.channel === 'differential').map((c) => c.vendor));
    const uninjected = [...new Set(registered.map((r) => r.vendor))].filter((v) => !injectedVendors.has(v));
    if (uninjected.length) {
      why.push(`the injection was not run on ${uninjected.join(', ')}: the gate was shown to refuse on `
        + 'one vendor and not on the other');
    }
    if (obs && obs.available && !injCfgs.some((c) => c.channel === 'observer')) {
      why.push('the injection was not run on the observer channel, so that channel was never shown to '
        + 'go red');
    }
  }

  return why;
}

/** One reading, reduced to what a tracked record keeps. */
function recordReading(r, channel) {
  const out = {
    spike: r.spike,
    verdict: r.verdict,
    control: typeof r.control === 'string' ? r.control : null,
  };
  if (channel === 'observer') {
    out.subjectResolutionExit = Number.isInteger(r.subjectResolutionExit) ? r.subjectResolutionExit : null;
    out.firstLossPass = typeof r.firstLossPass === 'string' ? r.firstLossPass : null;
  } else {
    out.n_spans = Number.isInteger(r.n_spans) ? r.n_spans : null;
  }
  return out;
}

/**
 * Build the tracked record from a full gate reading.
 *
 * Nothing is copied wholesale: every field is named here, so a field added to
 * the lab report does not silently become tracked data, and a float or a path
 * arriving in a reading has to get past `unwritableValues` first.
 *
 * @param {object} gate  the reading `runSpikeGate` returned
 * @param {{ccs: string[], opts: string[], injectAt: string[]|null}} args
 * @param {string} summaryLine  the one line `summarise()` printed for this run,
 *        kept so the README's quotation of it can be checked against the record
 * @returns {object}
 */
export function spikeDataRecord(gate, args, summaryLine) {
  const configurations = (gate.configurations || []).map((c) => ({
    channel: c.channel,
    vendor: c.vendor,
    opt: c.opt,
    recovery: c.grade.recovery,
    recovered: { num: c.grade.recovered.num, den: c.grade.recovered.den },
    held: c.grade.held === true,
    discriminating: c.grade.discriminating === true,
    sharedAnswer: typeof c.grade.sharedAnswer === 'string' ? c.grade.sharedAnswer : null,
    readings: (c.readings || []).map((r) => recordReading(r, c.channel)),
  }));

  const injCfgs = ((gate.injected && gate.injected.configurations) || []).map((c) => ({
    channel: c.channel,
    vendor: c.vendor,
    opt: c.opt,
    recovery: c.grade.recovery,
    wentRed: c.grade.wentRed === true,
    gradeable: c.grade.gradeable === true,
    // WHICH refusal the injection rested on. `wentRed: true` beside an empty
    // list would be a gate that went red for a reason nobody recorded.
    redBecause: [...(c.grade.redBecause || [])],
  }));

  const byChannel = {};
  for (const c of configurations) byChannel[c.channel] = (byChannel[c.channel] || 0) + 1;

  return {
    record: RECORD_VERSION,
    schemaVersion: gate.schemaVersion,
    established: gate.established === true,
    summaryLine,
    requested: {
      compilers: [...args.ccs],
      levels: [...args.opts],
      injectedAt: [...(args.injectAt || [args.opts[args.opts.length - 1]])],
    },
    subjects: (gate.subjects || []).map((s) => ({ spike: s.spike, file: s.file, fn: s.fn })),
    counting: {
      configurations: { num: gate.verdict.configurations.num, den: gate.verdict.configurations.den },
      discriminating: { num: gate.verdict.discriminating.num, den: gate.verdict.discriminating.den },
      byChannel,
      readings: configurations.reduce((n, c) => n + c.readings.length, 0),
      injectedConfigurations: injCfgs.length,
    },
    configurations,
    injected: {
      misspeltSuffix: gate.injected.misspeltSuffix,
      wentRed: gate.injected.held === true,
      configurations: injCfgs,
    },
    observerChannel: {
      requested: gate.observer.requested === true,
      available: gate.observer.available === true,
      vendor: gate.observer.vendor,
      opt: gate.observer.opt,
    },
  };
}

/**
 * Values a tracked record may not carry: a non-integer number, or a string that
 * names a machine.
 *
 * Returns the JSON path of each hit and what was wrong with it -- never the
 * offending text, which is the thing that must not be printed.
 *
 * @param {unknown} record
 * @returns {string[]}
 */
export function unwritableValues(record) {
  const hits = [];
  const walk = (v, at) => {
    if (typeof v === 'number') {
      if (!Number.isInteger(v)) hits.push(`${at}: a non-integer number (interfaces.md section 5: a ratio is {num, den})`);
      return;
    }
    if (typeof v === 'string') {
      for (const m of absolutePathHits(v)) hits.push(`${at}: ${m}`);
      if (v.includes('~/')) hits.push(`${at}: a home-directory reference`);
      if (v.includes('\\')) hits.push(`${at}: a backslash, which is a path separator on the host that wrote it`);
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, `${at}[${i}]`));
      return;
    }
    if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) walk(x, at ? `${at}.${k}` : k);
    }
  };
  walk(record, '');
  return hits;
}

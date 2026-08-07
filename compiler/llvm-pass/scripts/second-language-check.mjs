// second-language-check — grade the records that second-language-record.mjs wrote.
//
//   node second-language-check.mjs --records <dir> [--allow-empty] [--json]
//
// Exit codes are the shared ones (interfaces.md section 7): 0 clean, 2 findings,
// 3 a check could not be completed, 4 an integrity failure. 3 is never
// conflated with 0 — including the case where there was nothing to check, which
// is the failure mode this repository has shipped three times.
//
// WHAT IT IS LOOKING FOR
//
// The headline finding is VG-PROP-022: a property that was PRESENT at a low
// optimisation level and is gone at a high one, in the same record, with a
// control that survived. Everything else exists to stop that finding being
// issued on evidence that does not support it:
//
//   VG-PROP-020  the record shows only an absence. One reading, or no reading in
//                which the effect was ever present. Not a loss — consistent with
//                the effect never having existed. Reported so that a one-sided
//                measurement is visible rather than silently believed.
//   VG-PROP-021  the control's own count fell to zero after being established.
//                interfaces.md section 4: that is a broken measurement, not a
//                finding, and no loss may be reported from it.
//   VG-PROP-023  the record was produced by a symbol-name oracle, or one that
//                counts declarations. Its numbers cannot be compared with these.
//   VG-PROP-024  the state history is shorter than the readings it summarises,
//                i.e. it was truncated — probably at the first PRESENT -> LOST,
//                which hides a later REINTRODUCED.
//   VG-PROP-025  the verdict contradicts the expectation the fixture declared.
//                This is what the surviving fixture is for: it fires if the
//                checker has learned to report a loss on everything.
//
// A record that says the property survived is not a failure of anything. It is
// reported as observed-and-survived, and the run stays clean on it. Both
// directions have to be expressible or the checker is a false-positive factory.
//
// Note that a SUCCESSFUL demonstration of the phenomenon exits 2, not 0: the
// property really was lost, VG-PROP-022 really is a finding, and a checker that
// returned 0 for it would be reporting a loss as clean.
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';
import { digestRecord } from './second-language-record.mjs';

export const EXIT = { OK: 0, TOOL_FAILED: 1, FINDINGS: 2, INCOMPLETE: 3, INTEGRITY: 4 };

const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

function finding(id, severity, title, detail, where) {
  return { id, severity, title, detail, where };
}

/** What each declared expectation requires the verdict to be. A fixture that
 * declares nothing is not checked against anything. */
const EXPECTED_VERDICT = { LOST_AT_HIGH_OPT: 'LOSS_OBSERVED', SURVIVES: 'SURVIVED' };

/**
 * Grade one record. Returns `{findings, verdict}` where verdict is one of
 * `LOSS_OBSERVED`, `SURVIVED`, `NOT_OBSERVED`, `UNUSABLE`.
 *
 * The declared expectation is compared with the verdict afterwards, so that the
 * fixture whose job is to survive can catch a checker that has learned to
 * report a loss on everything.
 */
export function gradeRecord(record, name) {
  const graded = gradeCore(record, name);
  const want = EXPECTED_VERDICT[record?.expectation];
  if (want && want !== graded.verdict) {
    graded.findings.push(
      finding(
        'VG-PROP-025',
        'high',
        'The measured verdict contradicts the fixture it came from',
        `${name} declares ${record.expectation}, which requires ${want}, but the readings ` +
          `grade as ${graded.verdict} (${graded.reason}).`,
        { kind: 'ir', path: record?.sourceRel ?? name, unit: record?.property?.subject ?? null, pass: null },
      ),
    );
  }
  return graded;
}

function gradeCore(record, name) {
  const findings = [];
  const where = { kind: 'ir', path: record?.sourceRel ?? name, unit: null, pass: null };

  if (!record || typeof record !== 'object') {
    return { findings, verdict: 'UNUSABLE', reason: 'not an object' };
  }
  const readings = Array.isArray(record.readings) ? record.readings : [];
  const history = Array.isArray(record.stateHistory) ? record.stateHistory : [];

  if (record.oracle?.kind !== 'ir-call-site' || record.oracle?.countsDeclarations !== false) {
    findings.push(
      finding(
        'VG-PROP-023',
        'medium',
        'The record was not produced by the call-site oracle',
        `oracle.kind=${JSON.stringify(record.oracle?.kind)} ` +
          `countsDeclarations=${JSON.stringify(record.oracle?.countsDeclarations)}; ` +
          'a symbol-name count blames the declaration sweeper instead of the eliminating pass.',
        where,
      ),
    );
  }

  if (history.length && history.length < readings.length) {
    findings.push(
      finding(
        'VG-PROP-024',
        'medium',
        'The state history is shorter than the readings it summarises',
        `${readings.length} readings, ${history.length} states; a history truncated at the ` +
          'first loss hides a later reintroduction.',
        where,
      ),
    );
  }

  if (readings.length < 2) {
    findings.push(
      finding(
        'VG-PROP-020',
        'high',
        'The record carries a single reading',
        'A loss is a pair of readings. One reading cannot distinguish "it was removed" from ' +
          '"it was never emitted".',
        where,
      ),
    );
    return { findings, verdict: 'UNUSABLE', reason: 'fewer than two readings' };
  }

  // The control, from the point at which it was first established.
  let controlEstablished = false;
  let brokenAt = null;
  for (const r of readings) {
    if (r.controlCallSites > 0) controlEstablished = true;
    else if (controlEstablished && brokenAt === null) brokenAt = r.optLevel;
  }
  if (!controlEstablished) {
    findings.push(
      finding(
        'VG-PROP-021',
        'high',
        'The control was never observed at all',
        'Every reading has controlCallSites 0. Nothing here shows the oracle can see the ' +
          'effect, so an absence in the subject means nothing.',
        where,
      ),
    );
    return { findings, verdict: 'UNUSABLE', reason: 'control never present' };
  }
  if (brokenAt !== null) {
    findings.push(
      finding(
        'VG-PROP-021',
        'high',
        "The control's own effect was eliminated",
        `controlCallSites fell to 0 at -O${brokenAt}. interfaces.md section 4: that is a ` +
          'broken measurement, not a finding; no loss is reported from this record.',
        where,
      ),
    );
    return { findings, verdict: 'UNUSABLE', reason: 'broken control' };
  }

  const present = readings.filter((r) => r.targetCallSites > 0);
  const absent = readings.filter((r) => r.targetCallSites === 0);

  if (present.length === 0) {
    findings.push(
      finding(
        'VG-PROP-020',
        'high',
        'The record shows an absence with no matching presence',
        'The subject reads 0 at every optimisation level measured. That is not a loss; it is ' +
          'consistent with the effect never having been emitted.',
        where,
      ),
    );
    return { findings, verdict: 'NOT_OBSERVED', reason: 'never present' };
  }

  if (absent.length === 0) {
    return { findings, verdict: 'SURVIVED', reason: 'present at every level measured' };
  }

  // A loss only counts if the absence is at a HIGHER optimisation level than a
  // presence. Ascending order is not assumed; it is checked.
  const lowestAbsent = Math.min(...absent.map((r) => r.optLevel));
  const highestPresent = Math.max(...present.map((r) => r.optLevel));
  if (!(lowestAbsent > Math.min(...present.map((r) => r.optLevel)))) {
    findings.push(
      finding(
        'VG-PROP-020',
        'high',
        'The absence is not above a presence',
        `absent at -O${lowestAbsent}, present up to -O${highestPresent}; the pair does not ` +
          'order into a loss.',
        where,
      ),
    );
    return { findings, verdict: 'NOT_OBSERVED', reason: 'unordered pair' };
  }

  const pass = record.passObservation?.firstLoss?.pass ?? null;
  findings.push(
    finding(
      'VG-PROP-022',
      'critical',
      'A security property present at a low optimisation level is gone at a high one',
      `${record.property?.subject}: ${record.readings
        .map((r) => `-O${r.optLevel}=${r.targetCallSites}`)
        .join(' ')}; control ${record.property?.control}: ${record.readings
        .map((r) => `-O${r.optLevel}=${r.controlCallSites}`)
        .join(' ')}` +
        (pass ? `; first removed by ${pass}` : '; no pass attribution in this record'),
      { ...where, unit: record.property?.subject ?? null, pass },
    ),
  );
  return { findings, verdict: 'LOSS_OBSERVED', reason: pass ? `first loss in ${pass}` : 'no attribution' };
}

function parseArgs(argv) {
  const args = { records: null, allowEmpty: false, json: false, noDigest: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--records') args.records = argv[++i];
    else if (argv[i] === '--allow-empty') args.allowEmpty = true;
    else if (argv[i] === '--json') args.json = true;
    else if (argv[i] === '--no-digest') args.noDigest = true;
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  return args;
}

export function main(argv, log = console.log, err = console.error) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    err(`second-language-check: ${e.message}`);
    return EXIT.INCOMPLETE;
  }
  if (!args.records) {
    err('second-language-check: --records <dir> is required');
    return EXIT.INCOMPLETE;
  }
  if (!existsSync(args.records) || !statSync(args.records).isDirectory()) {
    err(`second-language-check: ${basename(args.records)} is not a directory`);
    log('inputs=0 checked=0 skipped=0');
    return EXIT.INCOMPLETE;
  }

  const files = readdirSync(args.records)
    .filter((f) => f.endsWith('.json'))
    .sort();
  const allowSkip = process.env.SECOND_LANGUAGE_ALLOW_SKIP === '1';

  let checked = 0;
  const skipped = [];
  const unreadable = [];
  const integrity = [];
  const findings = [];
  const verdicts = [];

  for (const f of files) {
    let record;
    try {
      record = JSON.parse(readFileSync(join(args.records, f), 'utf8'));
    } catch (e) {
      // skip is not pass: an unreadable record is a failure unless a skip was
      // explicitly authorised, and then it is named.
      if (allowSkip) skipped.push(`${f} (${e.message})`);
      else unreadable.push(`${f}: ${e.message}`);
      continue;
    }
    if (!args.noDigest) {
      let recomputed;
      try {
        recomputed = digestRecord(record);
      } catch (e) {
        integrity.push(`${f}: ${e.message}`);
        continue;
      }
      if (recomputed !== record.evidenceDigest) {
        integrity.push(`${f}: evidenceDigest does not match the record it is attached to`);
        continue;
      }
    }
    const graded = gradeRecord(record, f);
    findings.push(...graded.findings);
    verdicts.push({ record: f, verdict: graded.verdict, reason: graded.reason });
    checked++;
  }

  log(`inputs=${files.length} checked=${checked} skipped=${skipped.length}`);
  for (const s of skipped) log(`skipped: ${s}`);
  for (const v of verdicts) log(`${v.record}: ${v.verdict} (${v.reason})`);
  for (const fnd of findings) log(`${fnd.id} ${fnd.severity} ${fnd.title} -- ${fnd.detail}`);
  for (const u of unreadable) err(`second-language-check: unreadable ${u}`);
  for (const i of integrity) err(`second-language-check: integrity ${i}`);
  if (args.json) log(JSON.stringify({ findings, verdicts }, null, 2));

  if (files.length === 0) {
    if (args.allowEmpty) {
      log('second-language-check: no records, and --allow-empty was given');
      return EXIT.OK;
    }
    err('second-language-check: no records were found; an empty scan is not a clean scan');
    return EXIT.INCOMPLETE;
  }
  if (integrity.length) return EXIT.INTEGRITY;
  if (unreadable.length) return EXIT.INCOMPLETE;
  // Records were found and every one of them was skipped. The `files.length`
  // guard above does not see this: the emptiness is in `checked`, not in
  // `files`, and the two come apart as soon as SECOND_LANGUAGE_ALLOW_SKIP
  // authorises a skip. Measured before this existed: `inputs=2 checked=0
  // skipped=2` and exit 0 — a run that examined nothing reporting nothing wrong.
  //
  // It sits BELOW the integrity and unreadable branches on purpose. A record
  // that failed its digest comparison WAS examined — that is how the mismatch
  // was found — and it does not increment `checked`, so placing this first
  // turned a detected forgery (4) into "could not check" (3). That regression
  // was caught by the suite's own tamper test rather than by reasoning, which
  // is the argument for having kept it.
  //
  // `--allow-empty` deliberately does not reach here either: it is the caller
  // saying an empty INPUT SET was expected, and the input set was not empty.
  if (checked === 0) {
    err(`second-language-check: all ${files.length} record(s) were skipped, so nothing was `
      + 'examined. That is incomplete verification, not a clean scan.');
    return EXIT.INCOMPLETE;
  }
  const worst = findings.reduce((m, f) => Math.max(m, SEVERITY_RANK[f.severity] ?? 0), -1);
  if (worst >= SEVERITY_RANK.medium) return EXIT.FINDINGS;
  return EXIT.OK;
}

const invokedDirectly =
  process.argv[1] && basename(process.argv[1]) === 'second-language-check.mjs';
if (invokedDirectly) process.exit(main(process.argv.slice(2)));

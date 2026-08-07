#!/usr/bin/env node
// Verify evidence-carrying artefact bundles.
//
//   node bin/verify-bundle.mjs --bundle  <dir>   one bundle
//   node bin/verify-bundle.mjs --bundles <dir>   every bundle directory under <dir>
//
//   --fail-on <low|medium|high|critical>   threshold for exit 2 (default low)
//   --allow-empty                          an input with no bundles is not a failure
//   --json                                 machine-readable output
//   --no-calibrate                         skip the vector calibration (see below)
//
// Exit 0 clean, 2 findings at or above the threshold, 3 the run could not be
// completed, 4 a record or manifest that cannot be canonicalised at all.
//
// ── CALIBRATION RUNS FIRST, AND ITS FAILURE IS NOT A VERDICT ────────────────
//
// Before any bundle is read, the re-derivation is checked against the digest
// vectors. An uncalibrated canonicaliser cannot distinguish a bad record from
// its own bug, and it will report the second as the first — with a critical
// severity attached. So a calibration failure exits 3 (could not complete)
// rather than 2 (findings), because there are no findings, only a broken tool.
//
// `--no-calibrate` exists for one purpose: measuring how long verification
// itself takes. It prints a line saying calibration did not run, on every
// invocation, so a log with that line in it cannot be mistaken for a full run.

import { calibrate } from '../src/calibrate.mjs';
import { EXIT, emptyScanVerdict, reportCounts } from '../src/counting.mjs';
import { SEVERITY_ORDER, VERDICT, findBundleDirs, verifyBundle } from '../src/verify-bundle.mjs';

function main(argv) {
  const write = (s) => process.stdout.write(s);
  const err = (s) => process.stderr.write(s);
  const flag = (n) => argv.includes(n);
  const val = (n, d = null) => {
    const i = argv.indexOf(n);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d;
  };

  if (argv.length === 0 || flag('--help') || flag('-h')) {
    write(
      [
        'usage: node bin/verify-bundle.mjs --bundle <dir>',
        '       node bin/verify-bundle.mjs --bundles <dir>',
        '',
        '  --fail-on <low|medium|high|critical>  threshold for exit 2 (default low)',
        '  --allow-empty                         no bundles found is not a failure',
        '  --json                                machine-readable output',
        '  --no-calibrate                        do not check the vectors first',
        '',
        'exit: 0 clean, 2 findings, 3 could not complete, 4 malformed evidence',
      ].join('\n') + '\n',
    );
    return EXIT.OK;
  }

  const asJson = flag('--json');
  const failOn = SEVERITY_ORDER[val('--fail-on', 'low')] ?? 0;

  if (flag('--no-calibrate')) {
    write('calibration: NOT RUN (--no-calibrate). This run cannot tell a bad record from a bug\n');
    write('             in its own canonicaliser, so its verdicts are provisional.\n');
  } else {
    let cal;
    try {
      cal = calibrate();
    } catch (e) {
      reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
      err(`calibration could not run: ${e.message}\n`);
      return EXIT.INCOMPLETE;
    }
    if (cal.failed.length > 0) {
      reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
      err(`calibration failed on ${cal.failed.length} vector(s); no bundle was read.\n`);
      for (const f of cal.failed) err(`  FAIL ${f.name}: ${f.reason}\n`);
      return EXIT.INCOMPLETE;
    }
    write(`calibration: ${cal.passed}/${cal.inputs} vectors reproduced\n`);
  }

  const root = val('--bundle') ?? val('--bundles');
  if (root === null) {
    reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
    err('one of --bundle <dir> or --bundles <dir> is required.\n');
    return EXIT.INCOMPLETE;
  }
  const dirs = flag('--bundle') ? [root] : findBundleDirs(root);

  const reports = dirs.map((d) => verifyBundle(d));
  const counts = {
    inputs: dirs.length,
    checked: reports.length,
    skipped: 0,
    skippedNames: [],
  };
  reportCounts(write, counts);

  const empty = emptyScanVerdict({
    inputs: dirs.length,
    allowEmpty: flag('--allow-empty'),
    subject: 'bundles',
    write: err,
  });
  if (empty !== null) return empty;

  if (asJson) {
    write(`${JSON.stringify(reports, null, 2)}\n`);
  } else {
    for (const r of reports) {
      const mark = r.findings.length === 0 && !r.error ? 'ok  ' : 'FAIL';
      write(
        `${mark} ${r.dir}  ${r.verdict}  evidenceDigest=${(r.evidenceDigest ?? '-').slice(0, 16)} ` +
          `checked=${r.checked.length} unchecked=${r.unchecked.length}\n`,
      );
      for (const f of r.findings) {
        write(`       [${f.severity}] ${f.id} ${f.title}\n         ${f.detail}\n`);
      }
      if (r.error) write(`       ${r.error}\n`);
      if (r.unchecked.length > 0) write(`       unchecked: ${r.unchecked.join(', ')}\n`);
    }
    write('\nlimits of this verification:\n');
    for (const limit of reports[0]?.limits ?? []) write(`  - ${limit}\n`);
  }

  let worst = -1;
  let incomplete = 0;
  let malformed = 0;
  for (const r of reports) {
    if (r.malformed) malformed += 1;
    else if (r.verdict === VERDICT.INCOMPLETE || r.verdict === VERDICT.UNSUPPORTED) incomplete += 1;
    for (const f of r.findings) worst = Math.max(worst, SEVERITY_ORDER[f.severity] ?? 0);
  }

  if (malformed > 0) return EXIT.INTEGRITY;
  if (worst >= failOn) return EXIT.FINDINGS;
  if (incomplete > 0) return EXIT.INCOMPLETE;
  return EXIT.OK;
}

process.exit(main(process.argv.slice(2)));

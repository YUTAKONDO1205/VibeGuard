#!/usr/bin/env node
// Reproduce every digest vector with this package's canonicaliser.
//
//   node bin/calibrate.mjs [--vectors <file>] [--no-pin] [--allow-empty] [--json]
//
// Exit 0 when every vector is reproduced and every must-fail case refused,
// 3 when the run could not be completed (no vectors, an unreadable file, a pin
// that does not match), 2 when a vector failed.

import { calibrate } from '../src/calibrate.mjs';
import { EXIT, emptyScanVerdict, reportCounts } from '../src/counting.mjs';

function main(argv) {
  const write = (s) => process.stdout.write(s);
  const flag = (n) => argv.includes(n);
  const val = (n, d = null) => {
    const i = argv.indexOf(n);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d;
  };

  if (flag('--help') || flag('-h')) {
    write(
      'usage: node bin/calibrate.mjs [--vectors <file>] [--no-pin] [--allow-empty] [--json]\n',
    );
    return EXIT.OK;
  }

  let result;
  try {
    result = calibrate({ file: val('--vectors') ?? undefined, requirePin: !flag('--no-pin') });
  } catch (e) {
    // A missing or unpinned vectors file is INCOMPLETE, never OK. The whole
    // point of a calibration run is that an uncalibrated canonicaliser cannot
    // tell a bad record from its own bug.
    reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
    process.stderr.write(`${e.message}\n`);
    return EXIT.INCOMPLETE;
  }

  reportCounts(write, result);

  const empty = emptyScanVerdict({
    inputs: result.inputs,
    allowEmpty: flag('--allow-empty'),
    subject: 'digest vectors',
    write: (s) => process.stderr.write(s),
  });
  if (empty !== null) return empty;

  if (flag('--json')) {
    write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    write(`vectors file: ${result.file}\n`);
    write(`fingerprint:  ${result.fingerprint}\n`);
    write(`reproduced:   ${result.passed}/${result.inputs}\n`);
    for (const f of result.failed) write(`  FAIL ${f.name}: ${f.reason}\n`);
  }

  return result.failed.length === 0 ? EXIT.OK : EXIT.FINDINGS;
}

process.exit(main(process.argv.slice(2)));

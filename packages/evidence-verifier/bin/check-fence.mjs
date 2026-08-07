#!/usr/bin/env node
// Are these two packages fenced out of the shipped bundles?
//
//   node bin/check-fence.mjs [--root <dir>] [--json]
//
// Exit 0 when both are on both lists, 2 when either is missing from either
// list, 3 when the lists could not be found at all.
//
// This probe can only REPORT. The packaging script is not this package's to
// edit, so closing the gap is a one-line change somewhere else — which is
// exactly why the gap needs a probe rather than a note in a README.

import { repoRootFrom } from '../src/contract-copies.mjs';
import { EXIT, reportCounts } from '../src/counting.mjs';
import { OUR_PACKAGES, PACKAGING_SCRIPT, probeFenceAt, remedyFor } from '../src/fence-probe.mjs';

function main(argv) {
  const write = (s) => process.stdout.write(s);
  const err = (s) => process.stderr.write(s);
  const flag = (n) => argv.includes(n);
  const val = (n, d = null) => {
    const i = argv.indexOf(n);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d;
  };

  if (flag('--help') || flag('-h')) {
    write('usage: node bin/check-fence.mjs [--root <dir>] [--json]\n');
    return EXIT.OK;
  }

  let root;
  try {
    root = val('--root') ?? repoRootFrom();
  } catch (e) {
    reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
    err(`${e.message}\n`);
    return EXIT.INCOMPLETE;
  }

  let result;
  try {
    result = probeFenceAt(root);
  } catch (e) {
    reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
    err(`${e.message}\n`);
    return EXIT.INCOMPLETE;
  }

  const checked = result.determined ? OUR_PACKAGES.length : 0;
  reportCounts(write, { inputs: OUR_PACKAGES.length, checked, skipped: 0 });

  if (flag('--json')) write(`${JSON.stringify(result, null, 2)}\n`);

  if (!result.determined) {
    err(`${result.reason}\n`);
    return EXIT.INCOMPLETE;
  }

  for (const pkg of result.fenced) write(`fenced     ${pkg}\n`);
  for (const u of result.unfenced) {
    write(`NOT FENCED ${u.package} — missing from ${u.missingFrom.join(' and ')}\n`);
  }

  if (result.unfenced.length > 0) {
    err(`\n${remedyFor(result.unfenced)}\n`);
    err(`\nThe file to edit is ${PACKAGING_SCRIPT}, at the repository root.\n`);
    return EXIT.FINDINGS;
  }

  write(`both packages are on both lists in ${PACKAGING_SCRIPT}\n`);
  return EXIT.OK;
}

process.exit(main(process.argv.slice(2)));

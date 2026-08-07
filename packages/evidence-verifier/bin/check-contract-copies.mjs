#!/usr/bin/env node
// Every copy of the digest-vector contract in this repository must say the
// same thing.
//
//   node bin/check-contract-copies.mjs [--root <dir>] [--allow-empty] [--json]
//
// Exit 0 when two or more copies were found and all of them agree, 2 when they
// disagree, 3 when fewer than two were found (nothing was compared) or git
// could not be asked.

import { COPY_FLOOR, ContractScanError, compareContractCopies } from '../src/contract-copies.mjs';
import { EXIT, emptyScanVerdict, reportCounts } from '../src/counting.mjs';

function main(argv) {
  const write = (s) => process.stdout.write(s);
  const err = (s) => process.stderr.write(s);
  const flag = (n) => argv.includes(n);
  const val = (n, d = null) => {
    const i = argv.indexOf(n);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : d;
  };

  if (flag('--help') || flag('-h')) {
    write('usage: node bin/check-contract-copies.mjs [--root <dir>] [--allow-empty] [--json]\n');
    return EXIT.OK;
  }

  let result;
  try {
    result = compareContractCopies({ repoRoot: val('--root') ?? undefined });
  } catch (e) {
    reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
    err(`${e.message}\n`);
    return e instanceof ContractScanError ? EXIT.INCOMPLETE : EXIT.TOOL_FAILED;
  }

  reportCounts(write, result);

  const empty = emptyScanVerdict({
    inputs: result.inputs,
    allowEmpty: flag('--allow-empty'),
    subject: 'copies of the digest-vector contract',
    write: err,
  });
  if (empty !== null) return empty;

  if (flag('--json')) {
    write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    for (const group of result.groups) {
      write(`${group.fingerprint}\n`);
      for (const p of group.paths) write(`  ${p}\n`);
    }
  }

  if (result.belowFloor) {
    err(
      `only ${result.checked} copy/copies of the contract were compared, below the floor of ` +
        `${COPY_FLOOR}. "All copies agree" is trivially true of one copy and of none, so this is ` +
        'reported as an incomplete run rather than as agreement.\n',
    );
    return EXIT.INCOMPLETE;
  }
  if (!result.agree) {
    err(
      `${result.groups.length} different versions of the contract are in this repository. Every ` +
        'canonicaliser calibrated against one of them is calibrated against a different oracle, ' +
        'and their digests will disagree on the day it matters. Reconcile them, and raise the ' +
        'pinned fingerprint in every package that carries one, in the same commit.\n',
    );
    return EXIT.FINDINGS;
  }

  write(`all ${result.checked} copies agree on ${result.groups[0].fingerprint}\n`);
  return EXIT.OK;
}

process.exit(main(process.argv.slice(2)));

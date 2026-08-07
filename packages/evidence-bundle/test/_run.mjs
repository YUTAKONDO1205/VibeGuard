#!/usr/bin/env node
// Run every test file in this directory.
//
// WHY THIS EXISTS RATHER THAN `node --test test/*.test.mjs`
//
// Two reasons:
//
//   * how `node --test` treats its positional arguments has changed across the
//     versions this repository has to run on. Measured on the runtime in use
//     here: passing the DIRECTORY throws MODULE_NOT_FOUND. Glob expansion in
//     those positions is a newer feature, and `cmd.exe` does not expand globs
//     either, so a literal pattern cannot be relied on to reach the runner as
//     anything but a literal. NOT measured here: which of those two spellings
//     the Node the CI pins accepts. Enumerating explicit file paths is the one
//     form every version has always accepted, so the question does not arise.
//   * a floor. A test directory that has quietly stopped being found runs zero
//     tests and reports success, which is the failure mode this whole package
//     is written against. Below the floor this refuses to run at all.

import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** Measured 2026-08-07. Raise it when test files are added. */
const TEST_FILE_FLOOR = 5;

const files = readdirSync(HERE)
  .filter((f) => f.endsWith('.test.mjs'))
  .sort();

process.stdout.write(`inputs=${files.length} checked=${files.length} skipped=0\n`);

if (files.length < TEST_FILE_FLOOR) {
  process.stderr.write(
    `only ${files.length} test file(s) found in ${HERE}, below the floor of ${TEST_FILE_FLOOR}.\n` +
      'Either files were removed — raise or lower the floor in the same commit — or this runner\n' +
      'is looking in the wrong place and would otherwise report a green run over nothing.\n',
  );
  process.exit(3);
}

const result = spawnSync(process.execPath, ['--test', ...files.map((f) => join(HERE, f))], {
  stdio: 'inherit',
});
process.exit(result.status ?? 1);

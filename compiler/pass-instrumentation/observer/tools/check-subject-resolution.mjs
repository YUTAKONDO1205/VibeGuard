#!/usr/bin/env node
// Did this run observe the subject it was configured with?
//
// Reads the OBS_OUT logs of one run -- all of them, because the question is
// about the run and not about a module -- and answers whether the configured
// names ever resolved. See lib/subject-resolution.mjs for why the plugin
// records the fact and this side draws the conclusion.
//
// Usage:
//   node check-subject-resolution.mjs <log.tsv> [<log.tsv> ...]
//   node check-subject-resolution.mjs --role=subject out/*.tsv
//   node check-subject-resolution.mjs --json out/*.tsv
//
// Exit: 0 the names resolved, 2 the run is broken, 3 it could not be judged
//       (no logs, no SUBJECTRES record, or no module boundary was reached).
//       Pass a `.summary.tsv` side file and you will get 3: those deliberately
//       do not carry the record.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { readFileSync } from 'node:fs';
import process from 'node:process';

import {
  ROLES, aggregateResolution, exitCodeFor, formatResolutionReport,
} from '../lib/subject-resolution.mjs';

const argv = process.argv.slice(2);
const paths = [];
let roles = ROLES;
let asJson = false;

for (const arg of argv) {
  if (arg === '--json') { asJson = true; continue; }
  if (arg.startsWith('--role=')) {
    const want = arg.slice('--role='.length);
    if (want === 'both') { roles = ROLES; continue; }
    if (!ROLES.includes(want)) {
      process.stderr.write(`unknown role '${want}'; expected one of ${ROLES.join(', ')}, both\n`);
      process.exit(3);
    }
    roles = [want];
    continue;
  }
  if (arg === '-h' || arg === '--help') {
    process.stdout.write('usage: check-subject-resolution.mjs [--role=subject|control|both] [--json] <log.tsv>...\n');
    process.exit(0);
  }
  if (arg.startsWith('-')) {
    process.stderr.write(`unknown option '${arg}'\n`);
    process.exit(3);
  }
  paths.push(arg);
}

const logs = [];
for (const p of paths) {
  try {
    logs.push({ source: p, text: readFileSync(p, 'utf8') });
  } catch (err) {
    // Not a skip. A log that cannot be read is a log whose verdict is unknown,
    // and continuing over it would let a missing file average out into a pass.
    process.stderr.write(`cannot read ${p}: ${err.message}\n`);
    process.exit(3);
  }
}

const verdict = aggregateResolution(logs, { roles });
process.stdout.write((asJson
  ? JSON.stringify({ schemaVersion: 'subject-resolution-v1', rolesJudged: roles, ...verdict }, null, 2)
  : formatResolutionReport(verdict)) + '\n');
process.exit(exitCodeFor(verdict));

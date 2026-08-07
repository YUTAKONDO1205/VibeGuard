#!/usr/bin/env node
// Seal one or more evidence-carrying artefact bundles.
//
//   node bin/seal-bundle.mjs --out <dir> --record <file> [--artifact <file>]
//   node bin/seal-bundle.mjs --out <dir> --records <dir> [--allow-empty]
//
// In directory mode every `<name>.json` under `--records` becomes the bundle
// `<out>/<name>/`, and a sibling `<name>.bin` is sealed in as its artefact when
// one is there. A record with no sibling is sealed WITHOUT an artefact and is
// listed as such in the output — the bundle then verifies as INCOMPLETE rather
// than clean, because a record naming no artefact has nothing to be checked
// against, and that is a different answer from "checked and fine".
//
// Exit 0 on success, 1 when a record could not be sealed, 3 when there was
// nothing to seal and --allow-empty was not given.

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, extname, join } from 'node:path';

import { EXIT, emptyScanVerdict, reportCounts } from '../src/counting.mjs';
import { writeBundle } from '../src/bundle.mjs';

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
        'usage: node bin/seal-bundle.mjs --out <dir> --record <file> [--artifact <file>]',
        '       node bin/seal-bundle.mjs --out <dir> --records <dir> [--allow-empty]',
        '',
        '  --out <dir>        where bundles are written',
        '  --record <file>    one evidence-v0 record',
        '  --records <dir>    every *.json in a directory; <name>.bin is its artefact',
        '  --artifact <file>  the artefact bytes, single-record mode only',
        '  --allow-empty      an empty input directory is not a failure',
        '',
        'exit: 0 sealed, 1 a record could not be sealed, 3 nothing to seal',
      ].join('\n') + '\n',
    );
    return EXIT.OK;
  }

  const out = val('--out');
  if (out === null) {
    reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
    err('--out <dir> is required.\n');
    return EXIT.INCOMPLETE;
  }

  /** @type {Array<{name: string, record: string, artifact: string|null}>} */
  const jobs = [];
  const recordsDir = val('--records');
  const single = val('--record');

  if (recordsDir !== null) {
    if (!existsSync(recordsDir) || !statSync(recordsDir).isDirectory()) {
      reportCounts(write, { inputs: 0, checked: 0, skipped: 0 });
      err(`not a directory: ${recordsDir}\n`);
      return EXIT.INCOMPLETE;
    }
    for (const entry of readdirSync(recordsDir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : 1,
    )) {
      if (!entry.isFile() || extname(entry.name) !== '.json') continue;
      const name = basename(entry.name, '.json');
      const artifact = join(recordsDir, `${name}.bin`);
      jobs.push({
        name,
        record: join(recordsDir, entry.name),
        artifact: existsSync(artifact) ? artifact : null,
      });
    }
  } else if (single !== null) {
    jobs.push({
      name: basename(single, extname(single)),
      record: single,
      artifact: val('--artifact'),
    });
  }

  const skippedNames = [];
  let sealed = 0;
  const failures = [];

  for (const job of jobs) {
    let record;
    try {
      record = JSON.parse(readFileSync(job.record, 'utf8'));
    } catch (e) {
      failures.push(`${job.record}: does not parse: ${e.message}`);
      continue;
    }
    if (job.artifact === null) {
      skippedNames.push(`${job.name}: no artefact, sealed as a record-only bundle`);
    }
    try {
      const dir = recordsDir !== null ? join(out, job.name) : out;
      const result = writeBundle(dir, {
        record,
        artifact:
          job.artifact === null
            ? null
            : { name: basename(job.artifact), bytes: readFileSync(job.artifact) },
      });
      sealed += 1;
      write(
        `sealed ${job.name}  evidenceDigest=${result.evidenceDigest.slice(0, 16)} ` +
          `bundleDigest=${result.bundleDigest.slice(0, 16)}\n`,
      );
    } catch (e) {
      failures.push(`${job.name}: ${e.message}`);
    }
  }

  reportCounts(write, {
    inputs: jobs.length,
    checked: sealed,
    skipped: skippedNames.length,
    skippedNames,
  });

  const empty = emptyScanVerdict({
    inputs: jobs.length,
    allowEmpty: flag('--allow-empty'),
    subject: 'records to seal',
    write: err,
  });
  if (empty !== null) return empty;

  for (const f of failures) err(`FAILED ${f}\n`);
  return failures.length === 0 ? EXIT.OK : EXIT.TOOL_FAILED;
}

process.exit(main(process.argv.slice(2)));

#!/usr/bin/env node
// Sign sealed evidence records, detached.
//
//   node tools/sign-evidence.mjs --key <private.pem> --record <a.json> [--record <b.json>]
//   node tools/sign-evidence.mjs --key <private.pem> --dir <directory> [--allow-empty]
//
// Writes `<record>.sig.json` next to each record. The record itself is not
// touched: a detached signature is the only kind that can be added to an
// already-digested document without changing what the digest was taken over.
//
// COUNTING CONTRACT
//
//   Prints `inputs=N checked=N skipped=S`. Exits non-zero when N is 0 unless
//   `--allow-empty` was given. `--skip-signed` is the only way to produce a
//   skip, and every skip is named in the output.

import { readFileSync, readdirSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { basename, join } from 'node:path';

import { EXIT_INCOMPLETE, EXIT_OK, EXIT_TOOL_FAILED } from '../../driver/lib/exit.mjs';
import { parseArgv, reportCounts } from '../lib/cli.mjs';
import { loadPrivateKey } from '../lib/keys.mjs';
import { signRecord } from '../lib/signing.mjs';
import { createPublicKey } from 'node:crypto';

const args = parseArgv(process.argv.slice(2));

if (args.has('help') || args.has('h')) {
  process.stdout.write(
    'usage: sign-evidence.mjs --key <private.pem> (--record <file> | --dir <directory>)\n'
    + '                        [--allow-empty] [--skip-signed]\n',
  );
  process.exit(EXIT_OK);
}

const keyPath = args.get('key');
if (typeof keyPath !== 'string' || keyPath.length === 0) {
  process.stderr.write('--key <private.pem> is required.\n');
  process.exit(EXIT_INCOMPLETE);
}

let privateKey;
try {
  privateKey = loadPrivateKey(keyPath);
} catch (err) {
  process.stderr.write(`cannot use that signing key: ${err.message}\n`);
  process.exit(EXIT_INCOMPLETE);
}
const publicKey = createPublicKey(privateKey);

/** Records named directly, plus every `*.json` in `--dir` that is not a signature. */
function collect() {
  const named = args.all('record').filter((r) => typeof r === 'string');
  const dirs = args.all('dir').filter((d) => typeof d === 'string');
  const fromDirs = [];
  for (const d of dirs) {
    let entries;
    try {
      entries = readdirSync(d);
    } catch (err) {
      process.stderr.write(`cannot read directory ${basename(d)}: ${err.code ?? 'failed'}\n`);
      process.exit(EXIT_INCOMPLETE);
    }
    for (const e of entries.sort()) {
      if (!e.endsWith('.json') || e.endsWith('.sig.json')) continue;
      const p = join(d, e);
      if (statSync(p).isFile()) fromDirs.push(p);
    }
  }
  return [...named, ...fromDirs];
}

const inputs = collect();
const skipSigned = args.has('skip-signed');
const skippedNames = [];
let checked = 0;
let failed = 0;

for (const path of inputs) {
  const sigPath = `${path.replace(/\.json$/, '')}.sig.json`;
  if (skipSigned && existsSync(sigPath)) {
    skippedNames.push(`${basename(path)} (already signed, --skip-signed)`);
    continue;
  }
  let record;
  try {
    record = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    process.stderr.write(`${basename(path)}: not readable as JSON (${err.message})\n`);
    failed += 1;
    checked += 1;
    continue;
  }
  const envelope = signRecord({
    record,
    privateKey,
    publicKey,
    subjectFile: basename(path),
  });
  writeFileSync(sigPath, `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
  process.stdout.write(`signed ${basename(path)} -> ${basename(sigPath)} (${envelope.payload.bytes} B canonical)\n`);
  checked += 1;
}

const byCounts = reportCounts({
  inputs: inputs.length,
  checked,
  skipped: skippedNames.length,
  skippedNames,
  allowEmpty: args.has('allow-empty'),
  // Every skip this tool can emit means "this record already carries a
  // signature", which is the finished state, not a missing prerequisite: there
  // was nothing outstanding to sign. Signing is also the one operation here
  // that is genuinely idempotent, so a second run over the same directory is
  // expected to check nothing and is expected to succeed.
  //
  // This is the ONLY caller entitled to that reading. The reproducibility
  // runner skips because a compiler is absent, which measures nothing and must
  // stay at exit 3 — so it does not pass this.
  allSkippedMeans: args.has('skip-signed')
    ? 'every record in the directory already carried a signature, so there was nothing left to sign'
    : null,
});
if (byCounts !== null) process.exit(byCounts);
process.exit(failed > 0 ? EXIT_TOOL_FAILED : EXIT_OK);

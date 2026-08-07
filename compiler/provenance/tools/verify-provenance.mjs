#!/usr/bin/env node
// Verify signed provenance records.
//
//   node tools/verify-provenance.mjs --public-key <key.pub.pem> \
//        (--record <file> | --dir <directory>) \
//        [--pin <toolchain-pin.json>] [--expect-commit <40hex>] \
//        [--artifact-root <dir>] [--strict] [--fail-on low|medium|high|critical]
//        [--allow-empty] [--json]
//
// `--public-key` is REQUIRED and there is no fallback to the key inside the
// signature. Verifying a signature against the key that came with it checks
// that a document is self-consistent, which is a property every forgery has.
// Without a trust anchor there is no check to run, so the run reports exit 3
// (could not complete) rather than exit 0.
//
// EXIT CODES (interfaces.md §7)
//
//   0  everything asked for was checked and held.
//   2  the record verified cryptographically and disagrees with the world.
//   3  something could not be checked: no key, an unreadable file, or --strict
//      with a check the caller gave the verifier no way to make.
//   4  the trust chain failed — signature, key, digest, context, or the pin.
//
// COUNTING CONTRACT
//
//   `inputs=N checked=N skipped=S`, and exit non-zero when N is 0 unless
//   `--allow-empty`. Every NOT_OBSERVED check is listed by name at the end of
//   the run, whatever the exit code, because a clean exit over three checks
//   nobody made reads exactly like a clean exit over six.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, join } from 'node:path';

import { EXIT_INCOMPLETE, EXIT_OK, EXIT_NAMES } from '../../driver/lib/exit.mjs';
import { parseArgv, reportCounts } from '../lib/cli.mjs';
import { loadPublicKey } from '../lib/keys.mjs';
import { loadPin } from '../lib/pin.mjs';
import { exitCodeFor, verifyProvenance } from '../lib/verify-core.mjs';

const args = parseArgv(process.argv.slice(2));
const asJson = args.has('json');

if (args.has('help') || args.has('h')) {
  process.stdout.write(
    'usage: verify-provenance.mjs --public-key <key.pub.pem> (--record <file> | --dir <dir>)\n'
    + '                            [--pin <pin.json>] [--expect-commit <40hex>]\n'
    + '                            [--artifact-root <dir>] [--strict] [--allow-empty]\n'
    + '                            [--fail-on low|medium|high|critical] [--json]\n',
  );
  process.exit(EXIT_OK);
}

const keyPath = args.get('public-key');
if (typeof keyPath !== 'string' || keyPath.length === 0) {
  process.stderr.write(
    '--public-key <file> is required. A signature checked against the key packaged with it\n'
    + 'proves only internal consistency; there is no check to run without a trust anchor.\n',
  );
  process.exit(EXIT_INCOMPLETE);
}
let trustedPublicKey;
try {
  trustedPublicKey = loadPublicKey(keyPath);
} catch (err) {
  process.stderr.write(`cannot use that public key: ${err.message}\n`);
  process.exit(EXIT_INCOMPLETE);
}

let pin = null;
const pinPath = args.get('pin');
if (typeof pinPath === 'string' && pinPath.length > 0) {
  const r = loadPin(pinPath);
  if (!r.ok) {
    process.stderr.write(`the pin is unusable (${r.reason}): ${r.detail}\n`);
    process.exit(EXIT_INCOMPLETE);
  }
  pin = r.pin;
}

const expectCommit = typeof args.get('expect-commit') === 'string' ? args.get('expect-commit') : null;
const artifactRoot = typeof args.get('artifact-root') === 'string' ? args.get('artifact-root') : null;
const failOn = typeof args.get('fail-on') === 'string' ? args.get('fail-on') : 'low';
const strict = args.has('strict');

/** Every record named directly, plus every non-signature `*.json` under `--dir`. */
function collect() {
  const named = args.all('record').filter((r) => typeof r === 'string');
  const fromDirs = [];
  for (const d of args.all('dir').filter((x) => typeof x === 'string')) {
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
const results = [];
let checked = 0;
let incompleteAny = false;

for (const path of inputs) {
  const label = basename(path);
  const sigPath = `${path.replace(/\.json$/, '')}.sig.json`;
  let record = null;
  let envelope = null;
  let readError = null;
  try {
    record = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    readError = `record not readable as JSON: ${err.message}`;
  }
  if (readError === null) {
    try {
      envelope = JSON.parse(readFileSync(sigPath, 'utf8'));
    } catch (err) {
      readError = `detached signature ${basename(sigPath)} not readable as JSON: ${err.message}`;
    }
  }

  checked += 1;
  if (readError !== null) {
    incompleteAny = true;
    results.push({
      label,
      checks: [{ detail: readError, name: 'files-readable', state: 'NOT_OBSERVED' }],
      findings: [],
      exitCode: EXIT_INCOMPLETE,
    });
    continue;
  }

  const { checks, findings } = verifyProvenance({
    artifactRoot, envelope, expectCommit, label, pin, record, trustedPublicKey,
  });
  const code = exitCodeFor({ checks, failOn, findings, strict });
  results.push({ checks, exitCode: code, findings, label });
}

// ---- output ---------------------------------------------------------------

const notObserved = results.flatMap((r) => r.checks
  .filter((c) => c.state === 'NOT_OBSERVED')
  .map((c) => `${r.label}: ${c.name} — ${c.detail}`));

if (asJson) {
  process.stdout.write(`${JSON.stringify({ notObserved, results }, null, 2)}\n`);
} else {
  for (const r of results) {
    process.stdout.write(`${r.label}\n`);
    for (const c of r.checks) process.stdout.write(`  ${c.state.padEnd(15)} ${c.name} — ${c.detail}\n`);
    for (const f of r.findings) process.stdout.write(`  ${f.id} ${f.severity}: ${f.title}\n      ${f.detail.split('\n').join('\n      ')}\n`);
  }
}

const byCounts = reportCounts({
  inputs: inputs.length,
  checked,
  skipped: 0,
  skippedNames: [],
  allowEmpty: args.has('allow-empty'),
});
if (byCounts !== null) process.exit(byCounts);

if (notObserved.length > 0) {
  process.stdout.write(`not-observed=${notObserved.length}\n`);
  for (const n of notObserved) process.stdout.write(`  ${n}\n`);
  process.stdout.write(
    'Those are checks nobody made, not checks that passed. Supply --pin, --expect-commit\n'
    + 'and --artifact-root to make them, or --strict to have their absence fail the run.\n',
  );
}

// The worst outcome across the set decides. Precedence is in verify-core.mjs.
const ORDER = [4, 3, 2, 0];
let worst = EXIT_OK;
for (const r of results) {
  if (ORDER.indexOf(r.exitCode) < ORDER.indexOf(worst)) worst = r.exitCode;
}
if (incompleteAny && ORDER.indexOf(EXIT_INCOMPLETE) < ORDER.indexOf(worst)) worst = EXIT_INCOMPLETE;
process.stdout.write(`verdict=${EXIT_NAMES[worst]} (${worst})\n`);
process.exit(worst);

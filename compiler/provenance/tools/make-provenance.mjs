#!/usr/bin/env node
// Build — and optionally sign — a SLSA-shaped provenance record for a set of
// artefacts that have already been built.
//
//   node tools/make-provenance.mjs \
//        --artifact-root <dir> --subject out/wipe.o [--subject out/wipe] \
//        --source <relative path> [--source ...] \
//        --pin <toolchain-pin.json> (--commit <40hex> | --repo <dir>) \
//        --out <record.json> [--key <private.pem>] \
//        [--build-param k=v ...] [--entry-point <path>] [--reproducible yes|no|unknown]
//
// Every subject and every source is digested from the bytes on disk. Nothing is
// taken on trust from an argument except the names.
//
// COUNTING CONTRACT
//
//   `inputs` is subjects + sources: the files this run had to read to make a
//   claim. Exits non-zero when that is 0 unless `--allow-empty` was given —
//   though a provenance document with no subject is refused for a second,
//   independent reason (statementProblems), which is deliberate belt and braces.

import { createHash, createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';

import { EXIT_INCOMPLETE, EXIT_OK } from '../../driver/lib/exit.mjs';
import { parseArgv, reportCounts } from '../lib/cli.mjs';
import { loadPin, toolchainBlock, declaredToolchainDigest } from '../lib/pin.mjs';
import { buildProvenanceRecord } from '../lib/record.mjs';
import { buildStatement, statementProblems } from '../lib/statement.mjs';
import { loadPrivateKey } from '../lib/keys.mjs';
import { signRecord } from '../lib/signing.mjs';

const args = parseArgv(process.argv.slice(2));

if (args.has('help') || args.has('h')) {
  process.stdout.write(
    'usage: make-provenance.mjs --artifact-root <dir> --subject <rel> [--subject <rel>]\n'
    + '                          [--source <rel>] --pin <pin.json>\n'
    + '                          (--commit <40hex> | --repo <dir>) --out <record.json>\n'
    + '                          [--key <private.pem>] [--build-param k=v]\n'
    + '                          [--entry-point <path>] [--reproducible yes|no|unknown]\n',
  );
  process.exit(EXIT_OK);
}

function die(msg) {
  process.stderr.write(`${msg}\n`);
  process.exit(EXIT_INCOMPLETE);
}

const artifactRoot = args.get('artifact-root');
if (typeof artifactRoot !== 'string') die('--artifact-root <dir> is required.');
const outPath = args.get('out');
if (typeof outPath !== 'string') die('--out <record.json> is required.');
const pinPath = args.get('pin');
if (typeof pinPath !== 'string') die('--pin <toolchain-pin.json> is required. Provenance that records no toolchain describes a build nobody can repeat.');

const pinLoad = loadPin(pinPath);
if (!pinLoad.ok) die(`the pin is unusable (${pinLoad.reason}): ${pinLoad.detail}`);
const pin = pinLoad.pin;

let commit = args.get('commit');
if (typeof commit !== 'string') {
  const repo = args.get('repo');
  if (typeof repo !== 'string') die('one of --commit <40hex> or --repo <dir> is required.');
  try {
    commit = execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch (err) {
    die(`could not read HEAD out of that checkout: ${err.message}`);
  }
}
if (!/^[0-9a-f]{40}$/.test(commit)) die(`--commit must be 40 lowercase hex characters, got ${JSON.stringify(commit)}`);

const subjectNames = args.all('subject').filter((s) => typeof s === 'string');
const sourceNames = args.all('source').filter((s) => typeof s === 'string');

function sha256Of(rel) {
  return createHash('sha256').update(readFileSync(join(artifactRoot, rel))).digest('hex');
}

const subjects = [];
const materials = [];
let checked = 0;
let readFailures = 0;

for (const name of subjectNames) {
  try {
    subjects.push({ name, sha256: sha256Of(name) });
    checked += 1;
  } catch (err) {
    readFailures += 1;
    checked += 1;
    process.stderr.write(`subject ${name}: ${err.code ?? 'unreadable'}\n`);
  }
}
for (const name of sourceNames) {
  try {
    materials.push({ sha256: sha256Of(name), uri: `urn:vibeguard:material:source:${name}` });
    checked += 1;
  } catch (err) {
    readFailures += 1;
    checked += 1;
    process.stderr.write(`source ${name}: ${err.code ?? 'unreadable'}\n`);
  }
}

// A record is written only when every file it claims to describe was read. A
// document that quietly omits the subject it could not open is worse than no
// document: it verifies.
if (readFailures > 0) {
  reportCounts({
    inputs: subjectNames.length + sourceNames.length,
    checked,
    skipped: 0,
    skippedNames: [],
    allowEmpty: args.has('allow-empty'),
  });
  process.stderr.write(`${readFailures} named file(s) could not be read; no record was written.\n`);
  process.exit(EXIT_INCOMPLETE);
}

const parameters = {};
for (const kv of args.all('build-param')) {
  if (typeof kv !== 'string') continue;
  const i = kv.indexOf('=');
  if (i < 0) die(`--build-param takes k=v, got ${JSON.stringify(kv)}`);
  parameters[kv.slice(0, i)] = kv.slice(i + 1);
}

const rawEpoch = process.env.SOURCE_DATE_EPOCH;
const environment = {
  arch: process.arch,
  node: process.version,
  platform: process.platform,
  sourceDateEpoch: /^[0-9]{1,15}$/.test(rawEpoch ?? '') ? Number(rawEpoch) : null,
};

const reproducibleArg = args.get('reproducible', 'unknown');
const reproducible = reproducibleArg === 'yes' ? true : reproducibleArg === 'no' ? false : null;

const statement = buildStatement({
  commitSha: commit,
  configSourceUri: typeof args.get('config-source-uri') === 'string' ? args.get('config-source-uri') : undefined,
  entryPoint: typeof args.get('entry-point') === 'string' ? args.get('entry-point') : undefined,
  environment,
  materials,
  parameters,
  reproducible,
  subjects,
  toolchainDigest: declaredToolchainDigest(pin),
});

const problems = statementProblems(statement);
if (problems.length > 0) {
  process.stderr.write(`the provenance this run would write is not complete:\n  ${problems.join('\n  ')}\n`);
  process.exit(EXIT_INCOMPLETE);
}

const record = buildProvenanceRecord({ statement, toolchain: toolchainBlock(pin) });

mkdirSync(dirname(resolve(outPath)), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
process.stdout.write(`record ${basename(outPath)} evidenceDigest=${record.evidenceDigest}\n`);

const keyPath = args.get('key');
if (typeof keyPath === 'string' && keyPath.length > 0) {
  let privateKey;
  try {
    privateKey = loadPrivateKey(keyPath);
  } catch (err) {
    die(`cannot use that signing key: ${err.message}`);
  }
  const envelope = signRecord({
    record,
    privateKey,
    publicKey: createPublicKey(privateKey),
    subjectFile: basename(outPath),
  });
  const sigPath = `${outPath.replace(/\.json$/, '')}.sig.json`;
  writeFileSync(sigPath, `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
  process.stdout.write(`signature ${basename(sigPath)} keyId=${envelope.keyId}\n`);
} else {
  process.stdout.write('unsigned: no --key was given, so this record is bound to nobody.\n');
}

const byCounts = reportCounts({
  inputs: subjectNames.length + sourceNames.length,
  checked,
  skipped: 0,
  skippedNames: [],
  allowEmpty: args.has('allow-empty'),
});
if (byCounts !== null) process.exit(byCounts);
process.exit(readFailures > 0 ? EXIT_INCOMPLETE : EXIT_OK);

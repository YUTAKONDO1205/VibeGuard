#!/usr/bin/env node
// Run the verifier over the REAL fixture matrix and assert the measured table.
//
// This is not part of `npm test`: it needs binaries that only a Linux toolchain
// can produce, and the repository is developed on a machine that has none
// outside a subsystem. The hermetic tests in `test/` pin the deciders to
// synthetic images; THIS pins those synthetic images to reality. Without it the
// synthetic fixtures would only prove the deciders agree with my idea of what
// gcc emits.
//
//   bash compiler/elf-verifier/artefact-fixtures.sh /somewhere/matrix
//   node tools/verify-real-fixtures.mjs --dir /somewhere/matrix/bin
//
// COUNTING CONTRACT: prints `inputs=N checked=N skipped=S` and exits non-zero
// when N is 0 unless --allow-empty.
//
// SKIP IS NOT PASS: a fixture the table names and the directory does not hold
// is a FAILURE. `VG_ART_ALLOW_MISSING_FIXTURES=1` downgrades it to a skip, and
// then every skipped fixture is listed by name and the run still refuses to
// report agreement for it.

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readElf, linkForm, runPaths } from '../src/elf.mjs';
import { decideAll } from '../src/properties.mjs';
import { findBuildPaths, findForbiddenStrings, checkResidueControls } from '../src/residue.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_TABLE = join(HERE, '..', 'test', 'real-fixture-expectations.json');

function parseArgs(argv) {
  const o = { dir: null, table: DEFAULT_TABLE, allowEmpty: false, verbose: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') o.dir = argv[++i];
    else if (a === '--table') o.table = argv[++i];
    else if (a === '--allow-empty') o.allowEmpty = true;
    else if (a === '--verbose') o.verbose = true;
    else if (a === '-h' || a === '--help') o.help = true;
    else throw new Error(`unknown option ${a}`);
  }
  return o;
}

function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`verify-real-fixtures: ${e.message}\n`);
    return 1;
  }
  if (opts.help || !opts.dir) {
    process.stdout.write('usage: node tools/verify-real-fixtures.mjs --dir <matrix/bin> [--table f] [--allow-empty]\n');
    return opts.help ? 0 : 1;
  }

  const table = JSON.parse(readFileSync(opts.table, 'utf8'));
  const want = table.fixtures;
  const dir = resolve(opts.dir);
  const allowMissing = process.env.VG_ART_ALLOW_MISSING_FIXTURES === '1';

  const present = existsSync(dir) ? new Set(readdirSync(dir)) : new Set();
  const names = Object.keys(want);

  const missing = names.filter((n) => !present.has(n));
  const checkable = names.filter((n) => present.has(n));

  const skipped = [];
  const failures = [];
  let checked = 0;
  let comparisons = 0;

  for (const name of checkable) {
    const elf = readElf(join(dir, name), { path: name });
    if (!elf.supported) {
      failures.push(`${name}: not readable as ELF64 LSB — ${elf.reason}`);
      continue;
    }
    checked += 1;
    const exp = want[name];
    const got = decideAll(elf);
    const say = (field, actual, expected) => {
      comparisons += 1;
      if (actual !== expected) failures.push(`${name}.${field}: measured ${actual}, table says ${expected}`);
    };

    say('linkForm', linkForm(elf), exp.linkForm);
    for (const p of ['pie', 'nx', 'relro-full', 'stack-protector', 'fortify', 'build-id', 'no-writable-executable-section']) {
      say(p, got[p].state, exp[p]);
    }
    if (exp.relroLevel) say('relroLevel', got['relro-full'].level, exp.relroLevel);
    if (exp.runPaths !== undefined) say('runPaths', runPaths(elf).length, exp.runPaths);

    const paths = findBuildPaths(elf);
    say('buildPathResidue', paths.length > 0, exp.buildPathResidue);

    if (exp.buildPathResidue) {
      // The redaction must hold on a real path too, not only on the synthetic one.
      comparisons += 1;
      const leaked = paths.filter((p) => !/<\d+ further segment\(s\)/.test(p.redacted));
      if (leaked.length > 0) failures.push(`${name}: a reported path was not redacted`);
    }

    if (opts.verbose) {
      process.stdout.write(`  ${name.padEnd(20)} ${linkForm(elf).padEnd(14)} ` +
        ['pie', 'nx', 'relro-full', 'stack-protector', 'fortify', 'build-id', 'no-writable-executable-section']
          .map((p) => `${p}=${got[p].state}`).join(' ') + '\n');
    }
  }

  // ── the residue extractor's own control, on real bytes ────────────────────
  const controlName = 'hardened';
  if (present.has(controlName)) {
    const elf = readElf(join(dir, controlName), { path: controlName });
    const ctl = checkResidueControls(elf, [table.controlString]);
    comparisons += 1;
    if (!ctl[0].found) {
      failures.push(`CONTROL: the residue extractor did not find ${JSON.stringify(table.controlString)} in ${controlName}. ` +
        'The extractor is broken; nothing it reported as clean can be believed.');
    }
    comparisons += 1;
    const secret = findForbiddenStrings(elf, [table.forbiddenString]);
    if (secret.length === 0) {
      failures.push(`CONTROL: the forbidden marker ${JSON.stringify(table.forbiddenString)} is in the fixture source ` +
        `and was not found in ${controlName}. 0-vs-nonzero failed on the nonzero side.`);
    }
  } else {
    failures.push(`CONTROL: ${controlName} is absent, so the residue extractor was never exercised on real bytes.`);
  }

  for (const n of missing) {
    if (allowMissing) skipped.push([n, 'not present in --dir (VG_ART_ALLOW_MISSING_FIXTURES=1)']);
    else failures.push(`${n}: the table names this fixture and --dir does not hold it. ` +
      'Build the matrix with compiler/elf-verifier/artefact-fixtures.sh, or set VG_ART_ALLOW_MISSING_FIXTURES=1 ' +
      'to downgrade this to a listed skip.');
  }

  const inputs = checkable.length + missing.length;
  process.stdout.write(`\ninputs=${inputs} checked=${checked} skipped=${skipped.length}\n`);
  process.stdout.write(`comparisons=${comparisons} failures=${failures.length}\n`);
  if (skipped.length > 0) {
    process.stdout.write('skipped fixtures, by name:\n');
    for (const [n, why] of skipped) process.stdout.write(`  ${n} — ${why}\n`);
    process.stdout.write('  (a skipped fixture is NOT agreement; the rows above cover the rest only)\n');
  }
  for (const f of failures) process.stdout.write(`  FAIL ${f}\n`);

  if (inputs === 0 && !opts.allowEmpty) {
    process.stderr.write('verify-real-fixtures: nothing was checked. An empty run is not a pass.\n');
    return 3;
  }
  if (checked === 0 && !opts.allowEmpty) {
    process.stderr.write('verify-real-fixtures: no fixture was actually read. An empty run is not a pass.\n');
    return 3;
  }
  return failures.length > 0 ? 2 : 0;
}

process.exitCode = main(process.argv.slice(2));

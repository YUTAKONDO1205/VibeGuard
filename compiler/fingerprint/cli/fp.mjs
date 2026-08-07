#!/usr/bin/env node
// Fingerprint every function in every .ll file given.
//
//   node fp.mjs --dir <directory>            fingerprint every .ll / .ll.txt in it
//   node fp.mjs <file.ll> [file.ll ...]      fingerprint these
//   node fp.mjs --dir <d> --allow-empty      an empty set is the expected case
//   node fp.mjs --dir <d> --canonical <fn>   also print the canonical form
//   node fp.mjs --dir <d> --without <step>   disable one normalisation
//   node fp.mjs --dir <d> --json             machine-readable
//
// Exit 0 when something was fingerprinted, 3 when nothing was (INCOMPLETE --
// an empty scan is never reported as a clean one), 1 when a file could not be
// read.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';

import { parseModule } from '../lib/parse.mjs';
import { fingerprintFunction, allSteps, stepsWithout } from '../lib/fingerprint.mjs';
import { SEVEN, HYGIENE } from '../lib/normalise.mjs';
import { EXIT, reportCounts } from '../lib/count.mjs';

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const opt = (n, d = null) => {
  const i = argv.indexOf(n);
  return i === -1 || i + 1 >= argv.length ? d : argv[i + 1];
};

const dir = opt('--dir');
const allowEmpty = flag('--allow-empty');
const asJson = flag('--json');
const showCanonical = opt('--canonical');
const without = argv.reduce((acc, a, i) => (a === '--without' ? [...acc, argv[i + 1]] : acc), []);

for (const w of without) {
  if (!SEVEN.includes(w) && !HYGIENE.includes(w)) {
    console.error(`--without ${w}: not a step. Steps: ${[...SEVEN, ...HYGIENE].join(', ')}`);
    process.exit(EXIT.TOOL_FAILED);
  }
}
const steps = without.length === 0 ? allSteps() : stepsWithout(...without);

// `.ll.txt` as well as `.ll`. The tracked testdata carries the doubled
// extension because a repository-wide ignore rule for generated IR
// (`compiler/**/*.ll`) would otherwise drop hand-written fixtures at commit
// time -- see testdata/README.md. Both are the same text either way.
const isIr = (f) => f.endsWith('.ll') || f.endsWith('.ll.txt');

let files = argv.filter((a) => isIr(a) && !without.includes(a));
if (dir !== null) {
  let entries;
  try {
    entries = statSync(dir).isDirectory() ? readdirSync(dir) : [];
  } catch (e) {
    console.error(`cannot read --dir ${dir}: ${e.message}`);
    console.log('inputs=0 checked=0 skipped=0');
    process.exit(EXIT.TOOL_FAILED);
  }
  files = [...files, ...entries.filter(isIr).sort().map((f) => join(dir, f))];
}

const results = [];
const skippedNames = [];
for (const f of files) {
  let text;
  try {
    text = readFileSync(f, 'utf8');
  } catch (e) {
    // A file that was listed and then could not be read is a failure, not a
    // skip: the caller asked for it by name.
    console.error(`cannot read ${f}: ${e.message}`);
    console.log(`inputs=${files.length} checked=${results.length} skipped=${skippedNames.length}`);
    process.exit(EXIT.TOOL_FAILED);
  }
  const mod = parseModule(text);
  if (mod.functions.length === 0) {
    skippedNames.push(`${basename(f)} (no function definitions)`);
    continue;
  }
  for (const fn of mod.functions) {
    const r = fingerprintFunction(mod, fn.name, { steps });
    results.push({
      file: basename(f),
      function: fn.name,
      digest: r.digest,
      blockCount: r.blockCount,
      instructionCount: r.instructionCount,
      inlinedCallSites: r.inlined,
      refusedCallSites: r.refusedCallSites,
      notes: r.notes,
    });
    if (showCanonical !== null && fn.name === showCanonical) {
      console.log(`--- canonical form of ${fn.name} in ${basename(f)} ---`);
      console.log(r.canonicalForm);
      console.log('---');
    }
  }
}

if (asJson) {
  console.log(JSON.stringify({ steps: [...steps].sort(), results }, null, 2));
} else {
  for (const r of results) {
    console.log(`${r.digest.slice(0, 16)}  ${r.file}  ${r.function}  blocks=${r.blockCount} instructions=${r.instructionCount} inlined=${r.inlinedCallSites} refused=${r.refusedCallSites}`);
  }
}

const code = reportCounts({
  inputs: files.length,
  checked: files.length - skippedNames.length,
  skipped: skippedNames.length,
  allowEmpty,
  skippedNames,
});
process.exit(code);

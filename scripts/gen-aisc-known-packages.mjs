#!/usr/bin/env node
// Offline (re)generator + validator for VG-AISC-001's bundled known-package data
// (packages/rules/src/rules/ai-supply-chain-data.ts).
//
// WHY OFFLINE-ONLY: VibeGuard is zero-send. The rule matches imports against a
// LOCAL const array, never a registry API. This script runs at AUTHORING time to
// (re)build that array from a popularity dump you download yourself; it is NOT run
// in CI or at scan time. Coverage gaps cause false negatives (an unknown-not-near-
// miss import is silent), never false positives — the safe direction.
//
// USAGE
//   Validate the committed data (default; run in CI-adjacent checks if desired):
//     node scripts/gen-aisc-known-packages.mjs --check
//   Regenerate the KNOWN_NPM / KNOWN_PYPI arrays from local popularity dumps:
//     node scripts/gen-aisc-known-packages.mjs --npm npm-top.json --pypi pypi-top.json
//   where each JSON is an array of package-name strings (most-popular first). Get
//   them offline, e.g.:
//     - npm:  https://github.com/npm/download-counts  or an npm-rank export
//     - PyPI: https://hugovk.github.io/top-pypi-packages/ (top-pypi-packages.json)
//
// This script only PRINTS the regenerated array bodies; paste them into the data
// file (keeping the builtins / stoplist / curated sections). It never writes the
// TypeScript file automatically — a human reviews what ships.

import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const opt = (flag) => {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
};

const DEFAULT_TOP = 300; // cap per ecosystem; enough to seed near-miss targets.

function normalizeNames(names, cap) {
  const seen = new Set();
  const out = [];
  for (const raw of names) {
    if (typeof raw !== 'string') continue;
    const n = raw.trim().toLowerCase();
    if (!n || seen.has(n)) continue;
    // Package-name shape only: letters, digits, - _ . and (npm) leading @scope/.
    if (!/^[a-z0-9._-]+$/.test(n)) continue;
    seen.add(n);
    out.push(n);
    if (out.length >= cap) break;
  }
  return out;
}

function emitArray(name, names) {
  const lines = [];
  let row = '  ';
  for (const n of names) {
    const token = `'${n}', `;
    if (row.length + token.length > 98) {
      lines.push(row.replace(/\s+$/, ''));
      row = '  ';
    }
    row += token;
  }
  if (row.trim()) lines.push(row.replace(/\s+$/, ''));
  return `export const ${name}: readonly string[] = [\n${lines.join('\n')}\n];`;
}

if (opt('--npm') || opt('--pypi')) {
  const cap = Number(opt('--top') ?? DEFAULT_TOP);
  if (opt('--npm')) {
    const names = normalizeNames(JSON.parse(readFileSync(opt('--npm'), 'utf8')), cap);
    console.log(`// ${names.length} npm names\n${emitArray('KNOWN_NPM', names)}\n`);
  }
  if (opt('--pypi')) {
    const names = normalizeNames(JSON.parse(readFileSync(opt('--pypi'), 'utf8')), cap);
    console.log(`// ${names.length} PyPI names\n${emitArray('KNOWN_PYPI', names)}\n`);
  }
  process.exit(0);
}

// Default / --check: validate the committed data module for the invariants the
// rule relies on (lowercase, no duplicates, no whitespace).
const dataPath = new URL('../packages/rules/src/rules/ai-supply-chain-data.ts', import.meta.url);
const src = readFileSync(dataPath, 'utf8');
let failures = 0;
for (const arr of ['KNOWN_NPM', 'KNOWN_PYPI']) {
  // Match the array LITERAL (`= [ … ]`), not the `string[]` type annotation.
  const m = src.match(new RegExp(`export const ${arr}[^=]*=\\s*\\[([\\s\\S]*?)\\];`));
  if (!m) {
    console.error(`MISSING array: ${arr}`);
    failures += 1;
    continue;
  }
  const names = [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
  const seen = new Set();
  const dupes = [];
  for (const n of names) {
    if (n !== n.toLowerCase()) {
      console.error(`${arr}: not lowercase: ${n}`);
      failures += 1;
    }
    if (seen.has(n)) dupes.push(n);
    seen.add(n);
  }
  if (dupes.length) {
    console.error(`${arr}: duplicates: ${dupes.join(', ')}`);
    failures += 1;
  }
  console.log(`${arr}: ${names.length} names${dupes.length ? ` (${dupes.length} dupes!)` : ''}`);
}
if (failures) {
  console.error(`\n${failures} problem(s) in ai-supply-chain-data.ts`);
  process.exit(1);
}
console.log('ai-supply-chain-data.ts OK');

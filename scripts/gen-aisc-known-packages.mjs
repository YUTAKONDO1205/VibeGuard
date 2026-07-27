#!/usr/bin/env node
// Offline (re)generator + validator + FP AUDITOR for VG-AISC-001's bundled
// known-package data (packages/rules/src/rules/ai-supply-chain-data.ts).
//
// WHY OFFLINE-ONLY: VibeGuard is zero-send. The rule matches imports against a
// LOCAL const array, never a registry API. This script runs at AUTHORING time to
// (re)build and audit that array; it is NOT run in CI or at scan time. Coverage
// gaps cause false negatives (an unknown-not-near-miss import is silent), never
// false positives — the safe direction.
//
// USAGE
//   Validate the committed data (default):
//     node scripts/gen-aisc-known-packages.mjs --check
//
//   Audit the committed data against a list of REAL package names and print the
//   names that the rule would false-positive on (§17z-a):
//     node scripts/aisc-corpus-extract.mjs --out-npm npm.json --out-pypi pypi.json
//     node scripts/gen-aisc-known-packages.mjs --audit --npm-real npm.json --pypi-real pypi.json
//   Add `--rounds N` to bound the closure iteration (default 12), `--json FILE`
//   to dump the accepted additions per round.
//
//   Regenerate the KNOWN_NPM / KNOWN_PYPI arrays from local popularity dumps:
//     node scripts/gen-aisc-known-packages.mjs --npm npm-top.json --pypi pypi-top.json
//   where each JSON is an array of package-name strings (most-popular first). Get
//   them offline, e.g.:
//     - npm:  https://github.com/npm/download-counts  or an npm-rank export
//     - PyPI: https://hugovk.github.io/top-pypi-packages/ (top-pypi-packages.json)
//
// This script only PRINTS regenerated array bodies / audit results; paste them
// into the data file (keeping the builtins / stoplist / curated sections). It
// never writes the TypeScript file automatically — a human reviews what ships.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const DEFAULT_TOP = 300; // cap per ecosystem; enough to seed near-miss targets.

// ---------------------------------------------------------------------------
// NEAR-MISS ORACLE — must stay bit-identical to ai-supply-chain.ts
// ---------------------------------------------------------------------------
// Mirror target: `classifyImportName` / `withinEditDistance1` / `normKey` /
// `buildIndex` in packages/rules/src/rules/ai-supply-chain.ts. The exemption
// ORDER there (builtin → alias stoplist → literally known → curated → separator
// collision → edit distance) is part of the contract, not an implementation
// detail: reordering it changes which name a finding blames.
//
// The audit is only worth anything if it answers the *same* question the rule
// asks. Three ways to guarantee that were considered:
//
//   1. import the predicate from ai-supply-chain.ts — rejected: this is a plain
//      .mjs run by `node` with no TypeScript loader, and adding a build step to
//      an authoring-time script would make the audit depend on `npm run build`
//      (the one thing agents working this tree are told not to run).
//   2. generate this file from the rule at build time — rejected: a generated
//      script that nobody can read or edit in place is worse than a duplicated
//      20-line predicate.
//   3. duplicate the predicate here and PIN the duplication with a differential
//      test — chosen. `rules.test.ts` imports `auditVerdict` from this module and
//      asserts, over every branch plus a generated mutation battery, that its
//      verdict agrees with what `hallucinatedDependency.match()` actually does.
//      Drift then fails the suite instead of silently producing a wrong audit.
//
// Any edit below must be mirrored in ai-supply-chain.ts (and vice versa); the
// pin test is what makes that a rule rather than a hope.

export const normKey = (s) => s.toLowerCase().replace(/[-_.]/g, '');

/** True when the optimal string alignment distance between a and b is <= 1. */
export function withinEditDistance1(a, b) {
  if (a === b) return true;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  if (la === lb) {
    let diffs = 0;
    let firstDiff = -1;
    for (let i = 0; i < la; i += 1) {
      if (a[i] !== b[i]) {
        diffs += 1;
        if (diffs === 1) firstDiff = i;
        if (diffs > 2) return false;
      }
    }
    if (diffs <= 1) return true;
    if (diffs === 2 && firstDiff >= 0) {
      return a[firstDiff] === b[firstDiff + 1] && a[firstDiff + 1] === b[firstDiff];
    }
    return false;
  }
  const shorter = la < lb ? a : b;
  const longer = la < lb ? b : a;
  let i = 0;
  let j = 0;
  let skipped = false;
  while (i < shorter.length && j < longer.length) {
    if (shorter[i] === longer[j]) {
      i += 1;
      j += 1;
    } else {
      if (skipped) return false;
      skipped = true;
      j += 1;
    }
  }
  return true;
}

export function buildIndex(names) {
  const set = new Set();
  const normKeys = new Map();
  const byLen = new Map();
  for (const raw of names) {
    const n = raw.toLowerCase();
    set.add(n);
    if (!normKeys.has(normKey(n))) normKeys.set(normKey(n), n);
    const bucket = byLen.get(n.length);
    if (bucket) bucket.push(n);
    else byLen.set(n.length, [n]);
  }
  return { set, normKeys, byLen };
}

/**
 * The rule's decision for one candidate package name.
 * @returns {{confidence: 'high'|'medium', didYouMean?: string}|null} null = SILENT.
 */
export function auditVerdict(pkg, { index, builtins, stoplist, curated }) {
  if (builtins.has(pkg)) return null;
  if (stoplist.has(pkg)) return null;
  if (index.set.has(pkg)) return null;
  if (curated.has(pkg)) return { confidence: 'high' };
  const canon = index.normKeys.get(normKey(pkg));
  if (canon && canon !== pkg) return { confidence: 'medium', didYouMean: canon };
  if (pkg.length >= 5) {
    for (const len of [pkg.length - 1, pkg.length, pkg.length + 1]) {
      const bucket = index.byLen.get(len);
      if (!bucket) continue;
      const hit = bucket.find((known) => withinEditDistance1(pkg, known));
      if (hit) return { confidence: 'medium', didYouMean: hit };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Parsing the committed data module
// ---------------------------------------------------------------------------
// Reading the .ts as text (rather than importing it) keeps this script runnable
// by bare `node` with no build. The shapes it has to survive are exactly two:
// `export const X: readonly string[] = [ 'a', 'b' ];` and
// `export const X: ReadonlySet<string> = new Set([ 'a', 'b' ]);`.

export const DATA_PATH = fileURLToPath(
  new URL('../packages/rules/src/rules/ai-supply-chain-data.ts', import.meta.url),
);

/**
 * Extract the single-quoted string literals of one exported collection.
 *
 * Line comments are stripped FIRST. This is not cosmetic: the data file documents
 * each audited addition inline, and one English apostrophe ("the rule's key") is
 * enough to make the `'([^']+)'` scan pair up a run of prose as if it were a
 * package name — which is exactly how this parser failed the first time the
 * §17z-a block was written. Safe here because the file holds package names only,
 * so no string literal can contain `//`.
 */
export function parseNames(src, name) {
  const stripped = src.replace(/\/\/[^\n]*/g, '');
  const m = stripped.match(new RegExp(`export const ${name}[^=]*=\\s*(?:new Set\\()?\\s*\\[([\\s\\S]*?)\\]`));
  if (!m) return null;
  return [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]);
}

export function loadData(src = readFileSync(DATA_PATH, 'utf8')) {
  const get = (n) => {
    const names = parseNames(src, n);
    if (!names) throw new Error(`MISSING collection: ${n}`);
    return names;
  };
  return {
    KNOWN_NPM: get('KNOWN_NPM'),
    KNOWN_PYPI: get('KNOWN_PYPI'),
    NODE_BUILTINS: new Set(get('NODE_BUILTINS')),
    PY_STDLIB: new Set(get('PY_STDLIB')),
    ALIAS_STOPLIST: new Set(get('ALIAS_STOPLIST')),
    CURATED_HALLUCINATIONS: new Set(get('CURATED_HALLUCINATIONS')),
  };
}

// ---------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------

/**
 * Closure audit for one ecosystem.
 *
 * WHY A CLOSURE AND NOT ONE PASS: adding a name to KNOWN does two things — it
 * silences that name, and it creates a new near-miss TARGET. A second real name
 * sitting one edit away from the freshly added one becomes a false positive that
 * did not exist before the fix. So the audit re-runs with the accepted additions
 * folded into the index until a round produces nothing. The number of rounds is
 * reported because "we ran it once" is exactly the mistake this guards against.
 *
 * @param realNames names known to exist in the registry (audit input)
 * @param opts.flaggable optional filter: names the rule can never SEE as a
 *        candidate (e.g. a hyphenated PyPI distribution name can never appear in
 *        a python `import` statement) are not FP sources and must not be added.
 */
export function auditClosure(known, realNames, { builtins, stoplist, curated, maxRounds = 12, flaggable = () => true }) {
  const accepted = [];
  const rounds = [];
  let current = [...known];
  for (let round = 1; round <= maxRounds; round += 1) {
    const index = buildIndex(current);
    const found = [];
    for (const name of realNames) {
      if (!flaggable(name)) continue;
      const v = auditVerdict(name, { index, builtins, stoplist, curated });
      if (v) found.push({ name, ...v });
    }
    if (found.length === 0) {
      rounds.push([]);
      return { accepted, rounds, roundsRun: round, converged: true };
    }
    rounds.push(found);
    accepted.push(...found);
    current = current.concat(found.map((f) => f.name));
  }
  return { accepted, rounds, roundsRun: maxRounds, converged: false };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

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

// A PyPI *distribution* name containing a hyphen or a dot can never be produced
// by the rule's python candidate extractor (`[A-Za-z_][\w.]*` after `import` /
// `from`, first dotted segment taken), so it is not a false-positive source and
// must not be pulled into KNOWN_PYPI by the audit. Adding it would only widen the
// near-miss target set — i.e. manufacture new false positives for free.
const pyFlaggable = (n) => /^[a-z_][a-z0-9_]*$/.test(n);

function runCli(args) {
  const opt = (flag) => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const has = (flag) => args.includes(flag);

  if (has('--audit')) {
    const data = loadData();
    const report = { rounds: {}, additions: {} };
    let failures = 0;
    const jobs = [
      ['npm', '--npm-real', data.KNOWN_NPM, data.NODE_BUILTINS, () => true],
      ['pypi', '--pypi-real', data.KNOWN_PYPI, data.PY_STDLIB, pyFlaggable],
    ];
    for (const [eco, flag, known, builtins, flaggable] of jobs) {
      const file = opt(flag);
      if (!file) continue;
      const realNames = normalizeNames(JSON.parse(readFileSync(file, 'utf8')), Infinity);
      // A name that is BOTH on the curated-hallucination list AND declared as a
      // real dependency somewhere in the corpus is the worst possible outcome:
      // the rule would accuse a real package of being a hallucination. Loud.
      const collisions = realNames.filter((n) => data.CURATED_HALLUCINATIONS.has(n));
      if (collisions.length) {
        console.error(`!! ${eco}: CURATED_HALLUCINATIONS names found as REAL deps: ${collisions.join(', ')}`);
        failures += 1;
      }
      const res = auditClosure(known, realNames, {
        builtins,
        stoplist: data.ALIAS_STOPLIST,
        curated: data.CURATED_HALLUCINATIONS,
        maxRounds: Number(opt('--rounds') ?? 12),
        flaggable,
      });
      console.log(`\n=== ${eco}: ${realNames.length} real names audited, ${res.roundsRun} round(s), converged=${res.converged}`);
      res.rounds.forEach((r, i) => {
        if (!r.length) return;
        console.log(`  round ${i + 1}: ${r.length} MUST-ADD`);
        for (const f of r) console.log(`    ${f.name}  <- near-miss of ${f.didYouMean ?? '(curated)'} [${f.confidence}]`);
      });
      if (!res.converged) {
        console.error(`!! ${eco}: closure did NOT converge in ${res.roundsRun} rounds`);
        failures += 1;
      }
      report.rounds[eco] = res.rounds.map((r) => r.map((f) => f.name));
      report.additions[eco] = res.accepted.map((f) => f.name);
      console.log(`  TOTAL MUST-ADD ${eco}: ${res.accepted.length}`);
    }
    if (opt('--json')) writeFileSync(opt('--json'), JSON.stringify(report, null, 2));
    process.exit(failures ? 1 : 0);
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
  const src = readFileSync(DATA_PATH, 'utf8');
  let failures = 0;
  for (const arr of ['KNOWN_NPM', 'KNOWN_PYPI']) {
    const names = parseNames(src, arr);
    if (!names) {
      console.error(`MISSING array: ${arr}`);
      failures += 1;
      continue;
    }
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
}

// Only run the CLI when INVOKED as a script. The differential pin test in
// rules.test.ts imports auditVerdict/loadData from this module; without this
// guard the import would run --check and call process.exit() mid-suite.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runCli(process.argv.slice(2));
}

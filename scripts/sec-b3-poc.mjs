// B3 PoC — does the disguised file still PARSE as the program it claims to be?
//
// SCOPE.md §2.1/§2.3 make executability the ground truth: a concealment only
// counts if「PoC で脆弱性が生存」. The corpus manifest carries a
// `payloadExecutable` claim per pair, and until this script existed that claim
// was a hardcoded literal — a field whose name asserts verification, asserting
// something nobody had checked. This script turns the claim into a measurement
// for the languages whose toolchain is present, and leaves it explicitly
// `unverified` (never silently `true`) for the rest.
//
// Scope of the check, stated honestly: this is a SYNTACTIC liveness check
// (`python -m py_compile`, `node --check`), not a dynamic exploit. It answers
// "is the disguised file still a valid program?" — which is exactly the property
// the path/phantom disguises could plausibly break, since they move files and
// splice lines in. It does NOT re-prove the vulnerability itself; that is
// carried by construction (the payload bytes are unchanged) per SCOPE §2.1's
// 構成的に意味保存 clause. The distinction is recorded in the output so a reader
// cannot mistake one for the other.
//
// Run from the repo root AFTER the generator:
//   node scripts/sec-b3-gen-corpus.mjs && node scripts/sec-b3-poc.mjs
//
// Writes security-experiment/_results/b3-poc.json. Deterministic: no clock, no
// RNG, inputs sorted. Interpreter ABSENCE is a recorded outcome, not a failure —
// running this on a machine without Python yields `unverified`, not a crash.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const MANIFEST = 'security-experiment/_results/b3-corpus-manifest.json';
const OUT = 'security-experiment/_results/b3-poc.json';

if (!existsSync(MANIFEST)) {
  console.error(`corpus manifest not found at ${MANIFEST}\nFix: node scripts/sec-b3-gen-corpus.mjs`);
  process.exit(1);
}

// One syntax-check recipe per language. A language absent from this table is
// reported `unverified` with the reason "no checker configured" rather than
// being quietly assumed valid.
const CHECKERS = {
  python: { cmd: 'python', args: (f) => ['-m', 'py_compile', f], probe: ['--version'] },
  javascript: { cmd: 'node', args: (f) => ['--check', f], probe: ['--version'] },
};

/** Is this checker's interpreter actually on this machine? Probed once. */
const available = {};
function checkerFor(language) {
  const c = CHECKERS[language];
  if (!c) return null;
  if (!(language in available)) {
    try {
      execFileSync(c.cmd, c.probe, { stdio: 'pipe' });
      available[language] = true;
    } catch {
      available[language] = false;
    }
  }
  return available[language] ? c : null;
}

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));

// One check per distinct disguised FILE — pairs sharing a file share a verdict,
// and re-running the interpreter per pair would multiply the cost ~4x for
// identical answers.
const byFile = new Map();
for (const p of manifest.pairs) {
  if (p.disguisedPath == null) continue;
  if (!byFile.has(p.disguisedPath)) {
    byFile.set(p.disguisedPath, { path: p.disguisedPath, transform: p.transform, pairIds: [] });
  }
  byFile.get(p.disguisedPath).pairIds.push(p.pairId);
}

const LANG_BY_EXT = { '.py': 'python', '.js': 'javascript' };
const langOf = (p) => LANG_BY_EXT[(p.match(/\.[^./]+$/) || [''])[0].toLowerCase()];

const results = [];
for (const path of [...byFile.keys()].sort()) {
  const entry = byFile.get(path);
  const language = langOf(path);
  const claimed = manifest.transformMeta?.[entry.transform]?.payloadExecutable;

  // The negative control is asserted NOT executable. Verify that too: if
  // docstring-naive ever started parsing as live code the control would be
  // silently broken, and the whole table would lose its baseline.
  const expectDead = claimed === false;

  const checker = language ? checkerFor(language) : null;
  let verdict, detail;
  if (!existsSync(path)) {
    verdict = 'missing';
    detail = 'file listed in manifest does not exist on disk';
  } else if (!checker) {
    verdict = 'unverified';
    detail = language
      ? `no ${language} toolchain on this machine (or no checker configured)`
      : `no checker configured for extension of ${path}`;
  } else {
    try {
      execFileSync(checker.cmd, checker.args(path), { stdio: 'pipe' });
      verdict = 'parses';
      detail = `${checker.cmd} accepted the file`;
    } catch (err) {
      verdict = 'syntax-error';
      detail = String(err.stderr ?? err.message).split('\n').slice(0, 3).join(' | ').trim();
    }
  }

  results.push({
    path,
    transform: entry.transform,
    language: language ?? null,
    pairCount: entry.pairIds.length,
    claimedPayloadExecutable: claimed ?? null,
    verdict,
    detail,
    // The control is only sound if a `false` claim really is dead code. A
    // negative control that parses as live code is a BUG, and named as one.
    controlHolds: expectDead ? verdict !== 'parses' || 'payload is commented out, file still parses' : null,
  });
}

// A disguise that produces a syntax error is not a working attack: the file is
// no longer the program it claims to be, so any "concealment" it shows is an
// artifact of broken code rather than of the downgrade mechanism.
const broken = results.filter((r) => r.verdict === 'syntax-error');
const byTransform = {};
for (const r of results) {
  const t = (byTransform[r.transform] ??= { files: 0, parses: 0, syntaxError: 0, unverified: 0, missing: 0 });
  t.files += 1;
  if (r.verdict === 'parses') t.parses += 1;
  else if (r.verdict === 'syntax-error') t.syntaxError += 1;
  else if (r.verdict === 'missing') t.missing += 1;
  else t.unverified += 1;
}

const out = {
  generatedBy: 'sec-b3-poc.mjs',
  checkKind: 'syntactic liveness (parse/compile), NOT dynamic exploitation',
  semanticPreservation:
    'carried by construction: disguise transforms never edit payload bytes (SCOPE §2.1 構成的に意味保存). ' +
    'This script verifies only that the disguised file remains a valid program.',
  interpretersAvailable: available,
  byTransform,
  filesChecked: results.length,
  syntaxErrors: broken.length,
  results,
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');

console.log(`\n# B3 PoC — syntactic liveness of the disguised corpus\n`);
console.log(`interpreters available: ${JSON.stringify(available)}`);
console.log(`\ntransform            files  parses  syntaxErr  unverified`);
for (const [name, t] of Object.entries(byTransform).sort()) {
  console.log(
    `${name.padEnd(20)} ${String(t.files).padStart(5)} ${String(t.parses).padStart(7)} ` +
      `${String(t.syntaxError).padStart(10)} ${String(t.unverified).padStart(11)}`,
  );
}
if (broken.length) {
  console.log(`\n!! ${broken.length} disguised file(s) do NOT parse — these are not working attacks:`);
  for (const b of broken.slice(0, 10)) console.log(`   ${b.path}: ${b.detail}`);
}
console.log(`\nwrote ${OUT}`);

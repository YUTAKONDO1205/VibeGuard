#!/usr/bin/env node
// Compare a gate record against tools/expected.json.
//
//   node check-verdicts.mjs <expected.json> <fixture-name> <gate-record.json>
//
// Exit 0 when every expectation matches, 2 when any does not, 3 when the
// comparison could not be made at all (missing file, unknown fixture). 3 is
// never merged into 0: "we could not check" reported as "clean" is exactly the
// failure interfaces.md §7 is written against.
import { readFileSync } from 'node:fs';

const [expectedPath, fixture, recordPath] = process.argv.slice(2);
if (!expectedPath || !fixture || !recordPath) {
  console.error('usage: check-verdicts.mjs <expected.json> <fixture> <record.json>');
  process.exit(3);
}

let expectedAll, record;
try {
  expectedAll = JSON.parse(readFileSync(expectedPath, 'utf8'));
  record = JSON.parse(readFileSync(recordPath, 'utf8'));
} catch (e) {
  console.error(`CANNOT CHECK ${fixture}: ${e.message}`);
  process.exit(3);
}

const expected = expectedAll[fixture];
if (!expected) {
  console.error(`CANNOT CHECK ${fixture}: no expectation recorded`);
  process.exit(3);
}

const problems = [];

const actual = record.verdicts.map((v) => ({
  line: v.lexical.line,
  rule: v.findingId,
  verdict: v.verdict,
  reason: v.reason,
  sites: v.sites.map((s) => `${s.file}:${s.line}${s.function ? '@' + s.function : ''}`),
}));

if (actual.length !== expected.verdicts.length) {
  problems.push(
    `verdict count: expected ${expected.verdicts.length}, got ${actual.length}`,
  );
}

for (const want of expected.verdicts) {
  const got = actual.find((a) => a.line === want.line && a.rule === want.rule);
  if (!got) {
    problems.push(`no verdict for ${want.rule} at line ${want.line}`);
    continue;
  }
  if (got.verdict !== want.verdict)
    problems.push(`line ${want.line}: verdict expected ${want.verdict}, got ${got.verdict}`);
  if (got.reason !== want.reason)
    problems.push(`line ${want.line}: reason expected ${want.reason}, got ${got.reason}`);
  const wantSites = JSON.stringify(want.sites);
  const gotSites = JSON.stringify(got.sites);
  if (wantSites !== gotSites)
    problems.push(`line ${want.line}: sites expected ${wantSites}, got ${gotSites}`);
}

if (record.astOnly.length !== expected.astOnly)
  problems.push(`astOnly: expected ${expected.astOnly}, got ${record.astOnly.length}`);

const gotKinds = record.requirements.map((r) => r.kind).sort();
const wantKinds = [...expected.requirementKinds].sort();
if (JSON.stringify(gotKinds) !== JSON.stringify(wantKinds))
  problems.push(
    `requirement kinds: expected ${JSON.stringify(wantKinds)}, got ${JSON.stringify(gotKinds)}`,
  );

if (problems.length) {
  console.log(`FAIL ${fixture}`);
  for (const p of problems) console.log(`  - ${p}`);
  process.exit(2);
}
console.log(`PASS ${fixture} (${actual.length} verdicts, ${record.requirements.length} requirements)`);
process.exit(0);

#!/usr/bin/env node
// Live-demo harness — EMBEDDED arm (companion to scripts/demo-0.2.x.mjs, which
// covers the web-side 0.2.x corpora and is deliberately left untouched).
//
// Three beats, all with the REAL built engine, zero network:
//   1. samples/embedded/vulnerable  — the single-file embedded rules
//                                     (VG-MEM / VG-EMB / VG-RTOS / VG-CRYPTO)
//   2. samples/embedded/safe        — the paired corpus stays at zero
//   3. cross-file (0.3.0-alpha)     — the defects a single file cannot show:
//                                     VG-RTOS-003 / VG-AISC-002 / VG-AISC-003,
//                                     each with its paired negative fixture
//
// The counts printed here are checked against the SAME thresholds CI enforces
// in .github/workflows/security-scan.yml, so a rehearsal run fails loudly
// instead of the number quietly drifting before demo day.
//
//   npm run build && node scripts/demo-emb.mjs
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'apps/cli/dist/index.js');

// Same invocation shape as the CI `samples` job (`--mode standard`), so the
// numbers below are comparable to the gate values without a caveat.
function scan(dir, extraArgs = []) {
  const out = execFileSync(
    'node',
    [cli, join(root, dir), '--mode', 'standard', '--format', 'json', '--fail-on', 'never', ...extraArgs],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  return JSON.parse(out).findings;
}

// Mirrors .github/workflows/security-scan.yml (embedded steps) and the corpus
// table in README.md. `measured` is documentation, not a gate: a mismatch warns.
const GATE = {
  vulnerable: { floor: 18, measured: 26 }, // `test "$COUNT" -ge 18`
  safe: { exact: 0 }, //                      `test "$COUNT" -eq 0`
};

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const base = (p) => String(p).replace(/\\/g, '/').split('/').pop();
const bar = '─'.repeat(72);

let failures = 0;
let warnings = 0;
const t0 = Date.now();

console.log(`\n${bar}\n  VibeGuard — embedded arm: VG-MEM / VG-EMB / VG-RTOS  +  cross-file (0.3.0-α)\n${bar}`);

// ── 1. single-file embedded corpus ──────────────────────────────────────────
const vuln = scan('samples/embedded/vulnerable');
const files = new Set(vuln.map((f) => base(f.filePath)));
const byRule = new Map();
for (const f of vuln) {
  if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, []);
  byRule.get(f.ruleId).push(f);
}
console.log(
  `\n▼ samples/embedded/vulnerable  —  ${vuln.length} finding(s), ${byRule.size} rule(s), ${files.size} file(s)`,
);
const ordered = [...byRule.entries()].sort((a, b) => {
  const d = (SEV_RANK[a[1][0].severity] ?? 9) - (SEV_RANK[b[1][0].severity] ?? 9);
  return d !== 0 ? d : a[0].localeCompare(b[0]);
});
for (const [ruleId, fs] of ordered) {
  const sev = `[${fs[0].severity}]`.padEnd(10);
  console.log(
    `   • ${sev} ${ruleId.padEnd(13)} ×${String(fs.length).padEnd(2)} ${fs[0].title}`,
  );
  console.log(`       ${base(fs[0].filePath)}:${fs[0].startLine}`);
}

// ── 2. paired safe corpus ───────────────────────────────────────────────────
const safe = scan('samples/embedded/safe');
const safeOk = safe.length === GATE.safe.exact;
console.log(
  `\n▲ samples/embedded/safe  —  ${safe.length} finding(s)  ${safeOk ? '✓ clean (no false positives)' : '✗ UNEXPECTED FINDINGS'}`,
);
if (!safeOk) {
  failures++;
  for (const f of safe) console.log(`   ! ${f.ruleId} ${base(f.filePath)}:${f.startLine}`);
}

// ── the CI gate, re-checked live ────────────────────────────────────────────
const floorOk = vuln.length >= GATE.vulnerable.floor;
if (!floorOk) failures++;
console.log(`\n   CI gate (.github/workflows/security-scan.yml, embedded steps):`);
console.log(
  `     vulnerable ≥ ${GATE.vulnerable.floor}  →  ${vuln.length}  ${floorOk ? '✓' : '✗ BELOW FLOOR'}`,
);
console.log(`     safe      = ${GATE.safe.exact}   →  ${safe.length}  ${safeOk ? '✓' : '✗'}`);
if (vuln.length !== GATE.vulnerable.measured) {
  warnings++;
  console.log(
    `     ⚠ README/ledger record ${GATE.vulnerable.measured} for this corpus — measured ${vuln.length}; update the docs (gate itself is intact).`,
  );
}

// ── 3. cross-file arm (0.3.0-α) ─────────────────────────────────────────────
// Only reachable behind --include-design-smells; each positive is stated with
// the rule it must produce, and is paired with fixtures that must stay silent.
const CROSSFILE = [
  {
    fixture: 'samples/crossfile-fixtures/embedded-volatile-missing',
    rule: 'VG-RTOS-003',
    note: 'ISR-shared variable, declaration in a third file — VG-RTOS-002 cannot see it',
    negatives: [
      'samples/crossfile-fixtures/embedded-volatile-declared',
      'samples/crossfile-fixtures/embedded-volatile-static',
    ],
  },
  {
    fixture: 'samples/crossfile-fixtures/embedded-hallucinated',
    rule: 'VG-AISC-002',
    note: 'firmware calls an SDK symbol the vendor header never declares',
    negatives: ['samples/crossfile-fixtures/embedded-real-api', 'samples/crossfile-fixtures/embedded-partial-sdk'],
  },
  {
    fixture: 'samples/crossfile-fixtures/embedded-unintegrated',
    rule: 'VG-AISC-003',
    note: 'security routine generated but never wired into the execution closure',
    negatives: ['samples/crossfile-fixtures/embedded-wired'],
  },
];

console.log(`\n${bar}\n  cross-file — needs --include-design-smells (0.3.0-α)\n${bar}`);
for (const c of CROSSFILE) {
  const found = scan(c.fixture, ['--include-design-smells']);
  const hit = found.filter((f) => f.ruleId === c.rule);
  const ok = hit.length === 1 && found.length === 1;
  if (!ok) failures++;
  console.log(
    `\n▼ ${c.fixture.split('/').pop()}  →  ${c.rule}  ${ok ? '✓' : `✗ expected exactly 1 ${c.rule}, got ${found.length} finding(s)`}`,
  );
  console.log(`     ${c.note}`);
  for (const f of hit) {
    console.log(`   • ${base(f.filePath)}:${f.startLine}  ${f.title}  [${f.severity}/${f.confidence}]`);
    for (const e of f.evidence ?? []) console.log(`       ${e}`);
    for (const r of f.relatedLocations ?? []) {
      console.log(`       ↳ ${base(r.filePath)}:${r.startLine}  ${r.evidence ?? ''}`);
    }
  }
  for (const f of found.filter((x) => x.ruleId !== c.rule)) {
    console.log(`   ! unexpected ${f.ruleId} ${base(f.filePath)}:${f.startLine}`);
  }
  for (const neg of c.negatives) {
    const n = scan(neg, ['--include-design-smells']);
    const negOk = n.length === 0;
    if (!negOk) failures++;
    console.log(
      `   ▲ ${neg.split('/').pop().padEnd(28)} ${n.length} finding(s)  ${negOk ? '✓ silent' : '✗ FALSE POSITIVE'}`,
    );
    if (!negOk) for (const f of n) console.log(`       ! ${f.ruleId} ${base(f.filePath)}:${f.startLine}`);
  }
}

// ── verdict ─────────────────────────────────────────────────────────────────
const secs = ((Date.now() - t0) / 1000).toFixed(1);
console.log(`\n${bar}`);
console.log(
  failures === 0
    ? `  All embedded expectations hold (${secs}s). Local regex/lexical + lexical cross-file — zero network.`
    : `  ${failures} expectation(s) BROKEN (${secs}s) — do not demo until resolved.`,
);
if (warnings > 0) console.log(`  ${warnings} documentation warning(s) above.`);
console.log(`${bar}\n`);
process.exit(failures === 0 ? 0 : 1);

#!/usr/bin/env node
// Live-demo harness for Phase 0.2.x — the second defence line (single-file design
// smells) + the fourth defence line (AI supply chain) + prototype pollution.
//
// Scans the 0.2.x fixture corpora with the REAL built engine and prints a compact,
// demo-friendly summary: the smell/vuln each rule catches on the "smells" corpus,
// and proof the paired "safe" corpus stays clean. Zero-send, deterministic.
//
//   npm run build && node scripts/demo-0.2.x.mjs
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'apps/cli/dist/index.js');

function scan(dir) {
  const out = execFileSync('node', [cli, join(root, dir), '--format', 'json', '--fail-on', 'never'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(out).findings;
}

const RULE_NAMES = {
  'VG-SMELL-012': 'Primitive Role Check',
  'VG-SMELL-004': 'Security Swiss Army Knife',
  'VG-SMELL-003': 'Long Security Method',
  'VG-AISC-001': 'Hallucinated Dependency (slopsquatting)',
  'VG-INJ-020': 'Prototype-polluting merge',
};

const bar = '─'.repeat(72);
console.log(`\n${bar}\n  VibeGuard 0.2.x — second defence line + supply chain + proto pollution\n${bar}`);

for (const [smells, safe] of [['samples/design-smells', 'samples/design-safe'], ['samples/proto-pollution', 'samples/proto-safe']]) {
  const found = scan(smells);
  const clean = scan(safe);
  console.log(`\n▼ ${smells}  —  ${found.length} finding(s)`);
  const byRule = new Map();
  for (const f of found) {
    if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, []);
    byRule.get(f.ruleId).push(f);
  }
  for (const [ruleId, fs] of [...byRule.entries()].sort()) {
    const file = fs[0].filePath.replace(/\\/g, '/').split('/').slice(-1)[0];
    const sevs = [...new Set(fs.map((f) => f.severity))].join('/');
    console.log(`   • ${ruleId}  ${RULE_NAMES[ruleId] ?? ''}  [${sevs}]  ×${fs.length}  (${file})`);
    console.log(`       ${fs[0].description?.slice(0, 96) ?? ''}`);
  }
  const ok = clean.length === 0;
  console.log(`\n▲ ${safe}  —  ${clean.length} finding(s)  ${ok ? '✓ clean (no false positives)' : '✗ UNEXPECTED FINDINGS'}`);
  if (!ok) for (const f of clean) console.log(`   ! ${f.ruleId} ${f.filePath}:${f.startLine}`);
}
console.log(`\n${bar}\n  All detections are local regex/lexical — zero network, four-channel identical.\n${bar}\n`);

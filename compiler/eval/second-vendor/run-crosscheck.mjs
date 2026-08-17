#!/usr/bin/env node
/**
 * Cross-check this lane's independently written asm oracle against the existing
 * #V7 SCE envelope.
 *
 * The prior envelope (_results/envelope.json) is READ ONLY here. Nothing in this
 * file writes to it. The point is replication, not revision: two separately
 * written instruments reading the same fixtures should agree on which cells kept
 * the property, and any cell where they disagree is a finding that needs a human.
 *
 * Only the PRESERVED/LOST state is compared. firstLossPass is deliberately NOT
 * compared: the prior envelope has pass names for clang from the LLVM pass-plugin
 * observer, this lane has none for either vendor, and comparing a field one side
 * never measured would manufacture a disagreement out of a scope difference.
 *
 * Usage: node run-crosscheck.mjs [--prior <path>] [--mine <path>] [--out <dir>]
 */

import fs from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i += 2) out[argv[i].replace(/^--/, '')] = argv[i + 1];
  return out;
}

const args = parseArgs(process.argv);
const priorPath = args.prior || '$LAB/_results/envelope.json';
const minePath = args.mine || '$LAB/_results-wave2/second-vendor/second-vendor-envelope.json';
const outRoot = args.out || '$LAB/_results-wave2/second-vendor';

if (!fs.existsSync(priorPath)) {
  console.error('prior envelope not found: ' + priorPath);
  console.error('Reporting NOT_OBSERVED rather than assuming agreement.');
  process.exit(3);
}

const prior = JSON.parse(fs.readFileSync(priorPath, 'utf8'));
const mine = JSON.parse(fs.readFileSync(minePath, 'utf8'));

/** Prior cellIds look like "clang-18__O0__mit-off"; this lane uses the same shape. */
function indexCells(env) {
  const m = new Map();
  for (const p of env.properties) {
    for (const c of p.cells) m.set(p.propertyId + '|' + c.cellId, c);
  }
  return m;
}

const priorIdx = indexCells(prior);
const mineIdx = indexCells(mine);

const rows = [];
let agree = 0, disagree = 0, onlyPrior = 0, onlyMine = 0;

for (const [key, mc] of mineIdx) {
  const pc = priorIdx.get(key);
  if (!pc) { onlyMine += 1; rows.push({ key, prior: 'ABSENT_FROM_PRIOR', mine: mc.state, agreement: 'NOT_COMPARABLE' }); continue; }
  const same = pc.state === mc.state;
  if (same) agree += 1; else disagree += 1;
  rows.push({
    key,
    prior: pc.state,
    mine: mc.state,
    agreement: same ? 'AGREE' : 'DISAGREE',
    priorFirstLossPass: pc.firstLossPass ?? null,
    priorFirstLossStage: pc.firstLossStage ?? null,
  });
}
for (const key of priorIdx.keys()) {
  if (!mineIdx.has(key)) { onlyPrior += 1; rows.push({ key, prior: priorIdx.get(key).state, mine: 'ABSENT_FROM_THIS_LANE', agreement: 'NOT_COMPARABLE' }); }
}

const report = {
  schemaVersion: 'second-vendor-crosscheck-v0',
  generatedAt: new Date().toISOString(),
  generator: 'compiler/eval/second-vendor/run-crosscheck.mjs',
  priorEnvelope: { path: priorPath, generatedAt: prior.generatedAt ?? null, readOnly: true },
  thisLane: { path: minePath, generatedAt: mine.generatedAt ?? null },
  comparedField: 'cell state only (PRESERVED / LOST / ...)',
  notCompared: {
    firstLossPass:
      'NOT_COMPARABLE. The prior envelope carries pass names for clang from the LLVM pass-plugin observer. This lane measured no pass names for either vendor, by design, so there is nothing to compare against.',
  },
  totals: { comparable: agree + disagree, agree, disagree, onlyInPrior: onlyPrior, onlyInThisLane: onlyMine },
  rows,
};
report.verdict =
  disagree === 0 && report.totals.comparable > 0
    ? 'REPLICATED: an independently written oracle assigned the same state to every comparable cell'
    : 'DIVERGENT: at least one cell differs; neither record is automatically correct';

fs.mkdirSync(outRoot, { recursive: true });
const outPath = path.join(outRoot, 'second-vendor-crosscheck.json');
fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
console.log('WROTE ' + outPath);
console.log(JSON.stringify(report.totals, null, 2));
console.log(report.verdict);
for (const r of rows.filter((r) => r.agreement !== 'AGREE')) console.log('  ' + JSON.stringify(r));

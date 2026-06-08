// E1 — cross-channel judgment consistency (paper item ②).
//
// Upgrades E1 from a structural argument ("the four channels depend on a single
// analyzer-core package, so they must agree") to an EMPIRICAL, CI-enforced
// check: it runs the *built* node entry (`@vibeguard/analyzer-core` →
// dist/index.js → scanPath, the CLI / GitHub Action path) and the *built*
// browser entry (`@vibeguard/analyzer-core/browser` → dist/browser.js → scan,
// the Chrome / VS Code path) over the same corpora and asserts that every
// finding's (filePath, ruleId, severity, startLine, startColumn, confidence,
// category) tuple is identical. The only legitimately non-deterministic field,
// findingId, is excluded.
//
// Run from the repo root after `npm run build`:
//   node scripts/e1-consistency-eval.mjs
// Exits non-zero if any divergence is found, so it can gate CI.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { scanPath } from '@vibeguard/analyzer-core';
import { scan as scanBrowser } from '@vibeguard/analyzer-core/browser';

const IGNORE = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', '__pycache__']);

const CORPORA = [
  { label: 'samples/vulnerable', target: 'samples/vulnerable' },
  { label: 'test_problem', target: 'test_problem/test_problem.py' },
];

// Enumerate (filePath-as-the-node-engine-reports-it, content) for a target,
// mirroring scanPath: a file target keeps the exact target string; a directory
// target uses the forward-slashed path relative to it.
function enumerate(target) {
  const st = statSync(target);
  if (st.isFile()) return [{ filePath: target, content: readFileSync(target, 'utf8') }];
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (IGNORE.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        out.push({
          filePath: relative(target, full).split(sep).join('/'),
          content: readFileSync(full, 'utf8'),
        });
      }
    }
  };
  walk(target);
  return out;
}

function canonical(findings) {
  return findings
    .map((f) => ({
      filePath: f.filePath,
      ruleId: f.ruleId,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      startLine: f.startLine,
      startColumn: f.startColumn,
      endLine: f.endLine,
      endColumn: f.endColumn,
    }))
    .sort(
      (a, b) =>
        (a.filePath ?? '').localeCompare(b.filePath ?? '') ||
        a.ruleId.localeCompare(b.ruleId) ||
        (a.startLine ?? 0) - (b.startLine ?? 0) ||
        (a.startColumn ?? 0) - (b.startColumn ?? 0),
    );
}

const key = (f) => `${f.filePath}|${f.ruleId}|${f.severity}|${f.confidence}|${f.startLine}:${f.startColumn}`;

const lines = [];
const log = (s = '') => {
  lines.push(s);
  console.log(s);
};

log('# E1 — cross-channel judgment consistency (paper item ②)\n');
log('Built node entry (`scanPath`, used by CLI + GitHub Action) vs built browser');
log('entry (`scan`, used by Chrome + VS Code) over identical inputs. A divergence');
log('is any finding tuple present on one path but not the other.\n');
log('| channel | entry point (built artifact) |');
log('|---|---|');
log('| Chrome / VS Code | `@vibeguard/analyzer-core/browser` → `dist/browser.js` (`scan`) |');
log('| CLI / GitHub Action | `@vibeguard/analyzer-core` → `dist/index.js` (`scanPath`) |');
log('');
log('| corpus | files | findings (node) | findings (browser) | divergences |');
log('|---|---|---|---|---|');

let totalDivergences = 0;
for (const { label, target } of CORPORA) {
  const files = enumerate(target);
  const node = canonical((await scanPath(target, { mode: 'standard', config: false })).findings);
  const browser = canonical(
    files.flatMap(
      (f) => scanBrowser({ targetType: 'file', content: f.content, filePath: f.filePath, mode: 'standard' }).findings,
    ),
  );

  const nodeKeys = new Set(node.map(key));
  const browserKeys = new Set(browser.map(key));
  const onlyNode = node.filter((f) => !browserKeys.has(key(f)));
  const onlyBrowser = browser.filter((f) => !nodeKeys.has(key(f)));
  const divergences = onlyNode.length + onlyBrowser.length;
  totalDivergences += divergences;

  log(`| ${label} | ${files.length} | ${node.length} | ${browser.length} | ${divergences} |`);
  for (const f of onlyNode) log(`|   ↳ node-only | | | | ${key(f)} |`);
  for (const f of onlyBrowser) log(`|   ↳ browser-only | | | | ${key(f)} |`);
}

log('');
log(
  totalDivergences === 0
    ? `**Result: 0 divergences — node and browser paths are byte-identical on the detection tuple. ✓**`
    : `**Result: ${totalDivergences} divergences. ⚠**`,
);

// Persist the report next to the other paper artifacts.
try {
  const { writeFileSync } = await import('node:fs');
  writeFileSync('paper_data/e1_consistency.md', lines.join('\n') + '\n');
} catch {
  /* paper_data/ may be absent in a fresh checkout; the console output is the source of truth */
}

if (totalDivergences > 0) process.exit(1);

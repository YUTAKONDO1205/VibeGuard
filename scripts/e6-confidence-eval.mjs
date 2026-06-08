// E6 — context-window confidence evaluation (paper item ①).
//
// Demonstrates that the context-window confidence layer DOWN-RANKS findings that
// sit in a non-executed context (comment / docstring / block comment / test
// path) while leaving real, executable occurrences of the *same* pattern at
// their default confidence. Produces:
//   1. a per-finding before -> after table over paper_data/e6repo (control vs
//      treatment pairs);
//   2. a "no collateral damage" check over samples/vulnerable (real true
//      positives must keep their confidence);
//   3. a false-positive guard over samples/safe (must stay 0 findings).
//
// Run from the repo root after `npm run build`:
//   node scripts/e6-confidence-eval.mjs
//
// It replicates the analyzer's confidence resolution directly from the rule
// layer (allRules + contextConfidence) so the numbers are transparent; the
// summary cross-checks the samples totals against the engine's published E2/E3
// figures so the replication is self-validating.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  allRules,
  languageMatches,
  contextConfidence,
  detectDowngradeSignals,
} from '@vibeguard/rules';

const LANG_BY_EXT = {
  '.py': 'python',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.go': 'go',
  '.java': 'java',
  '.rb': 'ruby',
  '.php': 'php',
  '.cs': 'csharp',
};

function languageOf(path) {
  const dot = path.lastIndexOf('.');
  return dot === -1 ? undefined : LANG_BY_EXT[path.slice(dot).toLowerCase()];
}

// Line of the first non-whitespace character of the evidence (mirrors the
// analyzer's internal inspectedLine): corrects the `^\s*` newline-anchor skew.
function displayLine(m) {
  const ev = m.evidence ?? '';
  const firstNonWs = ev.search(/\S/);
  if (firstNonWs <= 0) return m.startLine;
  let newlines = 0;
  for (let i = 0; i < firstNonWs; i++) if (ev[i] === '\n') newlines += 1;
  return m.startLine + newlines;
}

function listFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listFiles(full));
    else if (languageOf(full)) out.push(full);
  }
  return out;
}

// Replicate the analyzer's per-match confidence resolution, but also capture the
// "before" value and the signals that fired so we can explain each row.
function analyze(dir) {
  const rows = [];
  for (const file of listFiles(dir)) {
    const content = readFileSync(file, 'utf8');
    const language = languageOf(file);
    const ctx = { content, lines: content.split('\n'), language, filePath: file };
    for (const rule of allRules) {
      if (!languageMatches(rule.languages, language)) continue;
      let matches;
      try {
        matches = rule.match(ctx);
      } catch {
        continue;
      }
      const mode = rule.contextConfidence ?? 'auto';
      for (const m of matches) {
        const before = rule.defaultConfidence;
        const after = contextConfidence(before, ctx, m, mode);
        const signals = mode === 'off' ? ['opt-out'] : detectDowngradeSignals(ctx, m);
        rows.push({
          ruleId: rule.ruleId,
          file: file.replace(/\\/g, '/'),
          // Display the line of the matched payload, not the raw startLine: some
          // rules anchor with `^\s*` and `\s` matches the preceding newline, so
          // startLine can point one line early. (Pre-existing reported-line
          // off-by-one, independent of item ①; see notes.)
          line: displayLine(m),
          severity: rule.severity,
          before,
          after,
          signals,
          changed: before !== after,
        });
      }
    }
  }
  return rows;
}

function dist(rows) {
  const d = { high: 0, medium: 0, low: 0 };
  for (const r of rows) d[r.after] += 1;
  return d;
}

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

// ---- 1. e6repo detail table -------------------------------------------------
const e6 = analyze('paper_data/e6repo').sort(
  (a, b) => a.file.localeCompare(b.file) || a.line - b.line,
);
console.log('# E6 — context-window confidence (paper item ①)\n');
console.log('## paper_data/e6repo — control vs treatment\n');
console.log(
  '| ruleId | location | sev | context signal | before → after |',
);
console.log('|---|---|---|---|---|');
for (const r of e6) {
  const loc = `${r.file.split('/').pop()}:${r.line}`;
  const sig = r.signals.length ? r.signals.join('+') : '— (executable)';
  const arrow = r.changed ? `**${r.before} → ${r.after}**` : `${r.before} → ${r.after}`;
  console.log(`| ${r.ruleId} | ${loc} | ${r.severity} | ${sig} | ${arrow} |`);
}
const treated = e6.filter((r) => r.changed);
const control = e6.filter((r) => !r.changed);
console.log(
  `\n- findings: **${e6.length}**  ·  down-ranked (treatment): **${treated.length}**  ·  unchanged (control/executable): **${control.length}**`,
);
console.log(`- confidence after ①: ${JSON.stringify(dist(e6))}`);

// ---- 2. no-collateral check over samples/vulnerable -------------------------
const vuln = analyze('samples/vulnerable');
const vulnChanged = vuln.filter((r) => r.changed);
console.log('\n## samples/vulnerable — no-collateral check\n');
console.log(`- findings: **${vuln.length}** (engine E2 baseline: 50)`);
console.log(`- confidence after ①: ${JSON.stringify(dist(vuln))} (E2 baseline: {"high":6,"medium":26,"low":18})`);
console.log(
  `- true-positives down-ranked: **${vulnChanged.length}** ${vulnChanged.length === 0 ? '✓ (no collateral damage)' : '⚠'}`,
);
for (const r of vulnChanged) {
  console.log(`    ${r.ruleId} ${r.file.split('/').pop()}:${r.line} ${r.before}->${r.after} [${r.signals.join('+')}]`);
}

// ---- 3. false-positive guard over samples/safe ------------------------------
const safe = analyze('samples/safe');
console.log('\n## samples/safe — false-positive guard\n');
console.log(`- findings: **${safe.length}** (gate: must be 0) ${safe.length === 0 ? '✓' : '⚠'}`);

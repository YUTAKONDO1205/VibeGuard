// ④ — baseline SAST comparison (VibeGuard vs Semgrep OSS).
//
// NOT a win/lose contest — pure-regex VibeGuard is at a disadvantage on a raw
// precision/recall race against Semgrep's dataflow/taint engine, and that is
// fine. The thesis is COMPLEMENTARITY: we map both tools' findings to source
// locations and partition them into
//   * overlap      — locations BOTH flag (VibeGuard catches the obvious vulns);
//   * semgrep-only — what Semgrep's deeper analysis catches that VibeGuard's
//                    regex misses (honest about the engine's ceiling);
//   * vibeguard-only — VibeGuard's niche: ai-quality / self-admitted-technical-
//                    debt patterns (stubs, placeholders, debug-on, "for now")
//                    that Semgrep's security packs do not target.
//
// Usage (after producing the two inputs — see scripts/run-semgrep.sh):
//   node scripts/sast-baseline-eval.mjs <label> <vibeguard.json> <semgrep.json>
import { readFileSync, writeFileSync, existsSync, appendFileSync } from 'node:fs';
import { basename } from 'node:path';

const [label, vgPath, basePath] = process.argv.slice(2);
if (!label || !vgPath || !basePath) {
  console.error('usage: node scripts/sast-baseline-eval.mjs <label> <vibeguard.json> <baseline.json>');
  process.exit(2);
}

const LINE_TOL = 2; // a "co-located" finding is within +/- 2 lines in the same file

// --- Baseline results: auto-detect Semgrep (`results[].path`) vs Bandit
// (`results[].filename`). "等" in the plan — Semgrep is unavailable natively on
// Windows (no OCaml core build) and the Docker daemon was unreachable in this
// environment, so we run Bandit, a pure-Python AST SAST, as the baseline. The
// harness still ingests Semgrep --json unchanged for a future multi-language run.
const baseRaw = JSON.parse(readFileSync(basePath, 'utf8'));
let baselineTool;
let sg;
if (Array.isArray(baseRaw.results) && baseRaw.results.some((r) => 'check_id' in r || 'path' in r)) {
  baselineTool = 'Semgrep';
  sg = baseRaw.results.map((r) => ({
    file: basename(r.path ?? ''),
    line: r.start?.line ?? 0,
    id: r.check_id,
    cwe: [].concat(r.extra?.metadata?.cwe ?? []).map(String).join(';'),
    sev: r.extra?.severity,
  }));
} else {
  baselineTool = 'Bandit';
  sg = (baseRaw.results ?? []).map((r) => ({
    file: basename(r.filename ?? ''),
    line: r.line_number ?? 0,
    id: `${r.test_id} ${r.test_name}`,
    cwe: r.issue_cwe?.id != null ? `CWE-${r.issue_cwe.id}` : '',
    sev: r.issue_severity,
  }));
}

// --- VibeGuard findings -----------------------------------------------------
const vgRaw = JSON.parse(readFileSync(vgPath, 'utf8'));
let vg = (vgRaw.findings ?? []).map((f) => ({
  file: basename(f.filePath ?? ''),
  line: f.startLine ?? 0,
  id: f.ruleId,
  category: f.category,
  aiQuality: f.category === 'ai-quality',
  sev: f.severity,
}));
// Compare only on the baseline's supported language so "VibeGuard-only" means
// "missed by the baseline", not "the baseline does not parse this language".
if (baselineTool === 'Bandit') vg = vg.filter((f) => f.file.endsWith('.py'));

const coLocated = (a, b) => a.file === b.file && Math.abs(a.line - b.line) <= LINE_TOL;

const vgOverlap = vg.filter((a) => sg.some((b) => coLocated(a, b)));
const vgOnly = vg.filter((a) => !sg.some((b) => coLocated(a, b)));
const sgOverlap = sg.filter((b) => vg.some((a) => coLocated(a, b)));
const sgOnly = sg.filter((b) => !vg.some((a) => coLocated(a, b)));

const aiq = vg.filter((f) => f.aiQuality);
const aiqOverlap = aiq.filter((a) => sg.some((b) => coLocated(a, b)));

const out = [];
const w = (s = '') => {
  out.push(s);
  console.log(s);
};

const T = baselineTool;
w(`# ④ — SAST baseline: VibeGuard ∩ ${T} over \`${label}\`\n`);
w(`Baseline: **${T}**${baselineTool === 'Bandit' ? ' (Python AST SAST; comparison scoped to .py files)' : ''}. ` +
  `VibeGuard is pure-regex — this is a complementarity map, not a precision race.\n`);
w('| partition | count | meaning |');
w('|---|---|---|');
w(`| both (overlap) | ${vgOverlap.length} | locations flagged by VibeGuard **and** ${T} — the obvious vulns VibeGuard does not miss |`);
w(`| VibeGuard-only | ${vgOnly.length} | flagged by VibeGuard, not ${T} (incl. VibeGuard's ai-quality niche) |`);
w(`| ${T}-only | ${sgOnly.length} | deeper AST/dataflow ${T} catches that VibeGuard's regex misses |`);
w(`| VibeGuard total${baselineTool === 'Bandit' ? ' (.py)' : ''} | ${vg.length} | |`);
w(`| ${T} total | ${sg.length} | |`);

w(`\n## VibeGuard's niche — ai-quality / SATD findings\n`);
w(`- VibeGuard ai-quality (category=ai-quality, the AI-trace heuristics) findings: **${aiq.length}**`);
w(`- of those, co-located with any ${T} finding: **${aiqOverlap.length}** ` +
  `→ **${aiq.length ? (((aiq.length - aiqOverlap.length) / aiq.length) * 100).toFixed(0) : 0}%** are unique to VibeGuard ` +
  `(${T}'s rules target code-security bugs, not self-admitted-technical-debt / AI-trace patterns).`);

w(`\n## What ${T} catches that VibeGuard misses (honest ceiling)\n`);
if (sgOnly.length === 0) {
  w(`- none in this corpus at the chosen ruleset.`);
} else {
  w(`| file:line | ${T} check | cwe |`);
  w('|---|---|---|');
  for (const r of sgOnly.slice(0, 40)) w(`| ${r.file}:${r.line} | ${r.id} | ${r.cwe || '—'} |`);
  if (sgOnly.length > 40) w(`| … +${sgOnly.length - 40} more | | |`);
}

w(`\n## Partition by VibeGuard category (overlap vs unique)\n`);
const cats = [...new Set(vg.map((f) => f.category))].sort();
w(`| category | total | overlap w/ ${T} | VibeGuard-only |`);
w('|---|---|---|---|');
for (const c of cats) {
  const all = vg.filter((f) => f.category === c);
  const ov = all.filter((a) => sg.some((b) => coLocated(a, b)));
  w(`| ${c} | ${all.length} | ${ov.length} | ${all.length - ov.length} |`);
}

const report = 'paper_data/sast_baseline.md';
if (existsSync(report) && process.env.APPEND === '1') appendFileSync(report, '\n' + out.join('\n') + '\n');
else writeFileSync(report, out.join('\n') + '\n');

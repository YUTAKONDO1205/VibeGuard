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

// ── WHY PATHS, NOT BASENAMES ────────────────────────────────────────────────
//
// Both sides used to reduce a finding's location to `basename(path)`, and
// co-location then meant "same FILE NAME, within LINE_TOL lines". In any real
// repository that is wrong in the direction that flatters the result: every
// `__init__.py`, `index.js`, `utils.py` and `test_utils.py` in a different
// directory becomes the same file, so unrelated findings pair up and the
// overlap is overstated. Comparing normalised relative paths costs nothing and
// removes the collision entirely.
//
// Same class of defect as the E6 numerator/denominator mismatch: a comparison
// whose two sides describe different populations.
const SEP = new RegExp(String.fromCharCode(92, 92), 'g'); // one literal backslash
const norm = (p) => String(p ?? '').replace(SEP, '/').replace(/^\.\//, '');

// ── AND WHY THE PATHS STILL HAVE TO BE RECONCILED ───────────────────────────
//
// The two artifacts are not written against the same base. VibeGuard reports
// paths relative to the SCAN TARGET (`auth_bypass.py` for a scan of
// `samples/vulnerable`); Bandit reports them relative to where it was invoked
// (`samples/vulnerable/auth_bypass.py`). Comparing them raw pairs nothing.
//
// So each VibeGuard path is resolved to the baseline path it is a suffix of.
// When that is AMBIGUOUS — two baseline files whose paths both end with the
// same relative path — the pair is dropped and counted, not guessed. That
// ambiguity is precisely what basename matching used to resolve silently and
// wrongly, in the direction that inflated the overlap.
function suffixResolver(baselinePaths) {
  const all = [...baselinePaths];
  const cache = new Map();
  let ambiguous = 0;
  const resolve = (vgPath) => {
    if (cache.has(vgPath)) return cache.get(vgPath);
    const hits = all.filter((b) => b === vgPath || b.endsWith(`/${vgPath}`));
    let out = null;
    if (hits.length === 1) out = hits[0];
    else if (hits.length > 1) ambiguous += 1;
    cache.set(vgPath, out);
    return out;
  };
  return { resolve, ambiguousCount: () => ambiguous };
}
if (Array.isArray(baseRaw.results) && baseRaw.results.some((r) => 'check_id' in r || 'path' in r)) {
  baselineTool = 'Semgrep';
  sg = baseRaw.results.map((r) => ({
    file: norm(r.path),
    line: r.start?.line ?? 0,
    id: r.check_id,
    cwe: [].concat(r.extra?.metadata?.cwe ?? []).map(String).join(';'),
    sev: r.extra?.severity,
  }));
} else {
  baselineTool = 'Bandit';
  sg = (baseRaw.results ?? []).map((r) => ({
    file: norm(r.filename),
    line: r.line_number ?? 0,
    id: `${r.test_id} ${r.test_name}`,
    cwe: r.issue_cwe?.id != null ? `CWE-${r.issue_cwe.id}` : '',
    sev: r.issue_severity,
  }));
}

// --- VibeGuard findings -----------------------------------------------------
const vgRaw = JSON.parse(readFileSync(vgPath, 'utf8'));
let vg = (vgRaw.findings ?? []).map((f) => ({
  file: norm(f.filePath),
  line: f.startLine ?? 0,
  id: f.ruleId,
  category: f.category,
  aiQuality: f.category === 'ai-quality',
  sev: f.severity,
}));
// ── WHY THE ANALYSED SET, NOT THE EXTENSION ─────────────────────────────────
//
// "VibeGuard-only" is supposed to mean "the baseline looked and missed it". The
// filter used to be `endsWith('.py')`, which means "the baseline COULD have
// looked" — a different claim. A file Bandit skipped or failed to parse still
// ends in `.py`, so every VibeGuard finding in it counted as a miss by the
// baseline, inflating the complementarity number in VibeGuard's favour.
//
// Both tools report what they actually analysed: Bandit keys `metrics` by file,
// Semgrep lists `paths.scanned`. Restricting to that set makes "only" mean what
// the sentence says. What gets excluded is COUNTED and reported, because a
// large exclusion is itself a result about the baseline's coverage.
const analysed = new Set();
if (baselineTool === 'Bandit') {
  for (const k of Object.keys(baseRaw.metrics ?? {})) {
    if (k !== '_totals') analysed.add(norm(k));
  }
} else {
  for (const k of baseRaw.paths?.scanned ?? []) analysed.add(norm(k));
}
let excludedNotAnalysed = 0;
let ambiguousPaths = 0;
if (analysed.size > 0) {
  // Lift VibeGuard's target-relative paths onto the baseline's base, so both
  // sides name the same file with the same string from here on.
  const resolver = suffixResolver(analysed);
  const before = vg.length;
  vg = vg
    .map((f) => {
      const resolved = resolver.resolve(f.file);
      return resolved ? { ...f, file: resolved } : null;
    })
    .filter(Boolean);
  ambiguousPaths = resolver.ambiguousCount();
  excludedNotAnalysed = before - vg.length;
  if (ambiguousPaths > 0) {
    console.warn(
      `warning: ${ambiguousPaths} VibeGuard path(s) matched more than one analysed baseline file; ` +
        'dropped rather than paired by guess.',
    );
  }
} else {
  // No coverage information in the artifact. Fall back to the old extension
  // filter, and SAY SO rather than presenting the weaker comparison as the
  // strong one.
  console.warn(
    `warning: ${baselineTool} artifact carries no analysed-file list; ` +
      'falling back to an extension filter, so "VibeGuard-only" may include files the baseline never opened.',
  );
  if (baselineTool === 'Bandit') vg = vg.filter((f) => f.file.endsWith('.py'));
}

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
w(`Baseline: **${T}**${baselineTool === 'Bandit' ? ' (Python AST SAST)' : ''}. ` +
  `VibeGuard is pure-regex — this is a complementarity map, not a precision race.\n`);
// The comparison's own scope, stated in the artifact rather than left in a
// console warning nobody keeps. "VibeGuard-only" is only meaningful against a
// file the baseline actually opened, so the size of what was excluded is part
// of the result — a large number here is a finding about the baseline's
// coverage, not a detail about this harness.
w(
  `Scope: compared over the **${analysed.size}** file(s) ${T} reports having analysed. ` +
    `**${excludedNotAnalysed}** VibeGuard finding(s) fell outside that set and are excluded` +
    `${ambiguousPaths > 0 ? `, of which ${ambiguousPaths} had a path matching more than one analysed file and were dropped rather than paired by guess` : ''}. ` +
    `Locations are matched on full relative paths, not file names.\n`,
);
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

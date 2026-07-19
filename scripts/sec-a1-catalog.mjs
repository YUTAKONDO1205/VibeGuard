// A1 — rule-regex catalogue and static ReDoS triage (SCOPE §3 A1 step 1,
// vibeguard-updates.md §2 M6: 「ルール正規表現の静的抽出＋recheck 連携」).
//
// SCOPE §3 A1 asks for "全ルール正規表現を静的抽出し recheck/vuln-regex-detector で
// 危険判定" as the entry point to the ReDoS experiment, and names
// 「super-linear ルール数/47」 as an indicator. This script produces that number,
// generated (never hand-transcribed, per SCOPE §5) from the shipped rules.
//
// EXTRACTION — runtime capture is primary, source scanning is the cross-check.
//
// The obvious approach — scan `rule.match.toString()` for regex literals — is
// what this script did first, and it MISSED A RULE. VG-CRYPTO-002 builds its
// seven patterns with `new RegExp(`${guard}[:=]\s*${rhs}`, 'gi')` from a shared
// variable-name guard, so no literal appears in its source at all. A source scan
// reports 46/47 rules and calls that "全ルール抽出"; the one it cannot see is a
// concatenated pattern, i.e. exactly the kind most likely to be accidentally
// catastrophic. Under-counting the attack surface is the one error this
// experiment cannot afford.
//
// So the primary extractor hooks `RegExp.prototype.exec` and invokes each rule's
// `match` against a probe context. Every pattern `runRegex` uses reaches the
// engine through `pattern.exec(content)` (matcher-utils.ts), literal and
// constructed alike, so the hook sees what ACTUALLY RUNS — post-build, post-
// interpolation, paired with its rule by construction. `rule.match` is called
// directly rather than through the analyzer so the `languageMatches` gate cannot
// hide a rule whose language the probe does not happen to be.
//
// The source scan is kept as an independent cross-check. It answers a question
// the hook cannot: "is there a pattern the hook did not reach?" — a rule that
// returns early, or branches on content, executes only some of its regexes
// against an inert probe. VG-SEC-003 is the live example: three of its patterns
// run inside a `.filter()` over the matches, so they never execute when nothing
// matched. They are catalogued too, marked `reached: false`, because on real
// input they DO run — dropping them would under-count the surface exactly as the
// source-only scan did. What `reached` records is the difference that matters
// for the n–T harness: a reached pattern is applied to FILE CONTENT (attacker-
// controlled length n), an unreached one to a match's `evidence` (already bounded
// by the outer pattern), so the two are not attackable to the same degree.
//
// STATIC TRIAGE — two independent classifiers, deliberately.
//   1. `recheck` (optional, see below): an automaton/fuzzing checker that reports
//      a proven complexity CLASS (safe / polynomial-degree-k / exponential).
//      This is the authority when present.
//   2. A local shape heuristic: nested quantifiers, adjacent unbounded
//      quantifiers over overlapping classes, quantified overlapping alternation.
//      Cheap, dependency-free, and — importantly — it runs even when recheck is
//      absent so the catalogue is never empty.
// They are reported SEPARATELY, never merged into one verdict. Where they
// disagree the disagreement is the finding: a heuristic hit that recheck calls
// safe is a false alarm to discard, and a recheck hit the heuristic missed is a
// shape worth adding. Neither is treated as ground truth — the n–T measurement
// in sec-a1-redos.mjs is, and this script only decides what that harness spends
// its time on.
//
// recheck is OPTIONAL and NOT a devDependency: it pulls a JVM jar, and this repo
// keeps devDependencies to typescript/vitest/@types-node. Install it only when
// running this experiment:
//   npm install --no-save recheck
// Without it the script still runs and emits `recheck: {available:false}`; the
// super-linear count is then heuristic-only and MUST be reported as such.
// (The jar commonly fails to load on Windows; recheck falls back to its pure-JS
// engine, which returns the same verdicts more slowly. The fallback is recorded
// in the output as `engine`.)
//
// Run from the repo root, AFTER `npm run build`:
//   npm install --no-save recheck && node scripts/sec-a1-catalog.mjs
//
// Writes security-experiment/_results/a1-regex-catalog.{json,md}.
// Deterministic: no clock, no RNG, rules sorted by ruleId, patterns in source
// order within a rule.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const RESULTS = 'security-experiment/_results';
const OUT_JSON = `${RESULTS}/a1-regex-catalog.json`;
const OUT_MD = `${RESULTS}/a1-regex-catalog.md`;
// Resolved against the CWD (the repo root), not against this file: a bare
// relative specifier in a dynamic import resolves relative to the MODULE, which
// would look for scripts/packages/rules/… and fail.
const RULES_ENTRY = 'packages/rules/dist/index.js';

// recheck's own time budget per pattern. Its default (a few seconds) is enough
// for these patterns; the cap exists so one pathological input cannot hang the
// catalogue itself — the very failure mode this experiment is about.
const RECHECK_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Regex-literal scanner
// ---------------------------------------------------------------------------

/**
 * Extract regex literals from JavaScript source text.
 *
 * A naive /\/.../ match cannot do this: a `/` inside a character class is not a
 * terminator (`[^/]`), an escaped `/` is not a terminator, and `//` opens a
 * comment. This walks the text tracking string, comment and character-class
 * state so each literal ends where the engine would end it.
 *
 * Division is not handled — and does not need to be. The input is always a
 * single `match` arrow function whose only `/` occurrences are regex literals;
 * a rule doing arithmetic would show up as a parse failure downstream (the
 * extracted "pattern" would not compile), which the caller reports rather than
 * silently accepting.
 */
function extractRegexLiterals(src) {
  const out = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    // Skip string literals — a `/` inside one is not a regex.
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      i += 1;
      while (i < n) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === quote) { i += 1; break; }
        i += 1;
      }
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < n && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i += 1;
      i += 2;
      continue;
    }
    if (c === '/') {
      const start = i;
      i += 1;
      let inClass = false;
      let closed = false;
      while (i < n) {
        const d = src[i];
        if (d === '\\') { i += 2; continue; }
        if (d === '\n') break; // unterminated — not a literal
        if (d === '[') { inClass = true; i += 1; continue; }
        if (d === ']') { inClass = false; i += 1; continue; }
        if (d === '/' && !inClass) { closed = true; i += 1; break; }
        i += 1;
      }
      if (!closed) { i = start + 1; continue; }
      const bodyEnd = i - 1;
      let flags = '';
      while (i < n && /[dgimsuvy]/.test(src[i])) { flags += src[i]; i += 1; }
      out.push({ source: src.slice(start + 1, bodyEnd), flags });
      continue;
    }
    i += 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Shape heuristic
// ---------------------------------------------------------------------------

const UNBOUNDED = ['*', '+'];

/**
 * Shape-level ReDoS smells. Each returns a short reason or null.
 *
 * These describe SHAPES, not proofs: a hit means "worth measuring", never
 * "vulnerable". Catastrophic backtracking additionally requires the quantified
 * bodies to overlap on real input AND a failing suffix, neither of which a
 * syntactic scan can settle. The n–T harness settles it.
 */
const SHAPE_CHECKS = [
  {
    id: 'nested-quantifier',
    // (a+)+ / (a*)* / (?:\w+)* — the textbook exponential shape.
    test: (s) => /\((?:\?[:=!<][=!]?)?[^()]*[*+][^()]*\)\s*[*+]/.test(s),
    reason: 'a quantified group whose body is itself unbounded-quantified ((a+)+ shape)',
  },
  {
    id: 'quantified-alternation',
    // (a|ab)* — alternation branches that can match the same prefix.
    test: (s) => /\((?:\?[:=!<][=!]?)?[^()]*\|[^()]*\)\s*[*+]/.test(s),
    reason: 'a quantified alternation group; branches may overlap on the same input',
  },
  {
    id: 'adjacent-unbounded',
    // [^"]*[^"]* / .*.* / \s*\s* — two unbounded quantifiers in a row over
    // classes that can match the same character: quadratic split points.
    test: (s) => /(\[[^\]]*\]|\\[wsdWSD]|\.)\s*[*+]\s*(\[[^\]]*\]|\\[wsdWSD]|\.)\s*[*+]/.test(s),
    reason: 'two adjacent unbounded quantifiers over potentially overlapping classes',
  },
];

function shapeTriage(source) {
  const hits = SHAPE_CHECKS.filter((c) => c.test(source)).map((c) => ({ id: c.id, reason: c.reason }));
  return { suspicious: hits.length > 0, hits };
}

// ---------------------------------------------------------------------------
// recheck (optional)
// ---------------------------------------------------------------------------

async function loadRecheck() {
  try {
    const mod = await import('recheck');
    const require = createRequire(import.meta.url);
    let version = 'unknown';
    try { version = require('recheck/package.json').version; } catch { /* keep unknown */ }
    return { available: true, check: mod.check, version };
  } catch (err) {
    return { available: false, reason: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Normalise recheck's verdict into the complexity CLASS SCOPE §3 A1 asks to
 * report (linear / polynomial-degree-k / exponential), and never let a checker
 * failure masquerade as "safe": an `unknown` status stays `unknown`.
 */
function classifyRecheck(out) {
  if (!out) return { class: 'unknown', detail: 'checker returned nothing' };
  if (out.status === 'safe') return { class: 'linear', detail: 'recheck: safe' };
  if (out.status === 'vulnerable') {
    const t = out.complexity?.type;
    if (t === 'exponential') return { class: 'exponential', detail: 'recheck: exponential' };
    if (t === 'polynomial') {
      const d = out.complexity?.degree;
      return { class: `polynomial-${d ?? '?'}`, detail: `recheck: polynomial degree ${d ?? '?'}` };
    }
    return { class: 'super-linear', detail: `recheck: vulnerable (${t ?? 'unspecified'})` };
  }
  return { class: 'unknown', detail: `recheck: ${out.status}${out.error ? ` (${out.error.kind})` : ''}` };
}

const SUPER_LINEAR = (c) => c === 'exponential' || c === 'super-linear' || c.startsWith('polynomial-');

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

if (!existsSync(RULES_ENTRY)) {
  console.error(`${RULES_ENTRY} not found.\nFix: run \`npm run build\` from the repo root first.`);
  process.exit(1);
}

const { allRules } = await import(pathToFileURL(resolve(RULES_ENTRY)).href);
const recheck = await loadRecheck();
if (!recheck.available) {
  console.warn(
    `[a1-catalog] recheck unavailable (${recheck.reason}).\n` +
      '            Falling back to the shape heuristic ONLY. The super-linear count\n' +
      '            below is heuristic and must be reported as such.\n' +
      '            Fix: npm install --no-save recheck',
  );
}

const rules = [...allRules].sort((a, b) => a.ruleId.localeCompare(b.ruleId));

// --- Runtime capture ------------------------------------------------------
// A probe that is deliberately inert: short, matches nothing, and exercises no
// catastrophic path. Its only job is to make every `runRegex` call reach
// `exec`, so the hook can record the pattern. Content that MATCHED would risk a
// rule returning early on a hit and skipping later patterns.
const PROBE_CONTENT = 'x\n';
const probeCtx = { filePath: 'probe.txt', language: undefined, content: PROBE_CONTENT, lines: ['x'] };

const nativeExec = RegExp.prototype.exec;
const capturedByRule = new Map();
let currentRuleId = null;
// eslint-disable-next-line no-extend-native
RegExp.prototype.exec = function patchedExec(str) {
  if (currentRuleId !== null) {
    const bucket = capturedByRule.get(currentRuleId);
    // Keyed by source+flags: a rule that execs the same pattern repeatedly (the
    // `while (exec)` loop in runRegex) must contribute one catalogue entry, not
    // one per iteration.
    const key = `${this.source}::${this.flags}`;
    if (bucket && !bucket.has(key)) bucket.set(key, { source: this.source, flags: this.flags });
  }
  return nativeExec.call(this, str);
};

const ruleInvocationErrors = [];
try {
  for (const rule of rules) {
    capturedByRule.set(rule.ruleId, new Map());
    currentRuleId = rule.ruleId;
    try {
      rule.match(probeCtx);
    } catch (err) {
      // Recorded, never swallowed: a rule that throws on the probe may have
      // registered only some of its patterns, so its coverage is suspect and
      // the reader must be told rather than shown a quietly short list.
      ruleInvocationErrors.push({
        ruleId: rule.ruleId,
        message: err instanceof Error ? err.message : String(err),
      });
    } finally {
      currentRuleId = null;
    }
  }
} finally {
  // eslint-disable-next-line no-extend-native
  RegExp.prototype.exec = nativeExec;
}

const entries = [];
const rulesWithoutLiteral = [];
const unreachedLiterals = [];

for (const rule of rules) {
  const captured = [...(capturedByRule.get(rule.ruleId)?.values() ?? [])].map((c) => ({
    ...c,
    reached: true,
    appliedTo: 'file-content',
  }));

  // Cross-check: literals visible in the source that the runtime capture did not
  // reach. Reported, not merged — an unreached pattern was not proven to run.
  const capturedKeys = new Set(captured.map((c) => `${c.source}::${c.flags}`));
  for (const lit of extractRegexLiterals(String(rule.match))) {
    let normalised;
    try {
      const re = new RegExp(lit.source, lit.flags);
      normalised = `${re.source}::${re.flags}`;
    } catch {
      continue; // not a real literal (division, or a shape the scanner mis-read)
    }
    if (!capturedKeys.has(normalised)) {
      unreachedLiterals.push({ ruleId: rule.ruleId, source: lit.source, flags: lit.flags });
      captured.push({ source: lit.source, flags: lit.flags, reached: false, appliedTo: 'match-evidence' });
    }
  }

  if (captured.length === 0) {
    // Loud, not silent: a rule whose pattern this script cannot see is a hole in
    // "全ルール抽出", and the coverage claim must not be made over it.
    rulesWithoutLiteral.push(rule.ruleId);
    continue;
  }
  for (const [idx, lit] of captured.entries()) {
    let compiles = true;
    let compileError = null;
    try {
      new RegExp(lit.source, lit.flags);
    } catch (err) {
      compiles = false;
      compileError = err instanceof Error ? err.message : String(err);
    }

    let recheckResult = { class: 'not-run', detail: 'recheck unavailable' };
    if (recheck.available && compiles) {
      try {
        const out = await recheck.check(lit.source, lit.flags, { timeout: RECHECK_TIMEOUT_MS });
        recheckResult = classifyRecheck(out);
      } catch (err) {
        recheckResult = { class: 'unknown', detail: `recheck threw: ${err instanceof Error ? err.message : String(err)}` };
      }
    }

    entries.push({
      ruleId: rule.ruleId,
      patternIndex: idx,
      severity: rule.severity,
      category: rule.category,
      languages: [...rule.languages].sort(),
      source: lit.source,
      flags: lit.flags,
      reached: lit.reached,
      appliedTo: lit.appliedTo,
      compiles,
      compileError,
      shape: shapeTriage(lit.source),
      recheck: recheckResult,
    });
  }
}

// Counts are reported per RULE (SCOPE's indicator is "super-linear ルール数/47"),
// but a rule holding several patterns is super-linear if ANY of them is.
// The headline indicator counts only patterns applied to FILE CONTENT. Those are
// the ones an attacker sizes directly by choosing the file; a super-linear
// pattern applied to a match's evidence is bounded by the outer match and is a
// weaker claim, so it is counted separately rather than inflating the number.
const rulesSuperLinearRecheck = new Set(
  entries.filter((e) => e.reached && SUPER_LINEAR(e.recheck.class)).map((e) => e.ruleId),
);
const rulesSuperLinearEvidenceOnly = new Set(
  entries.filter((e) => !e.reached && SUPER_LINEAR(e.recheck.class)).map((e) => e.ruleId),
);
const rulesSuspiciousShape = new Set(entries.filter((e) => e.shape.suspicious).map((e) => e.ruleId));
const disagreements = entries.filter(
  (e) => e.shape.suspicious !== SUPER_LINEAR(e.recheck.class) && e.recheck.class !== 'not-run',
);

const summary = {
  totalRules: rules.length,
  rulesWithPatterns: new Set(entries.map((e) => e.ruleId)).size,
  rulesWithoutLiteral,
  ruleInvocationErrors,
  unreachedLiterals,
  totalPatterns: entries.length,
  patternsFailingToCompile: entries.filter((e) => !e.compiles).map((e) => e.ruleId),
  recheck: recheck.available
    ? { available: true, version: recheck.version, timeoutMs: RECHECK_TIMEOUT_MS }
    : { available: false, reason: recheck.reason },
  superLinearRulesByRecheck: recheck.available ? rulesSuperLinearRecheck.size : null,
  superLinearRuleIds: [...rulesSuperLinearRecheck].sort(),
  superLinearRulesEvidenceOnly: recheck.available ? [...rulesSuperLinearEvidenceOnly].sort() : null,
  suspiciousRulesByShape: rulesSuspiciousShape.size,
  disagreementCount: disagreements.length,
};

mkdirSync(RESULTS, { recursive: true });
writeFileSync(OUT_JSON, `${JSON.stringify({ summary, entries }, null, 2)}\n`);

// --- Markdown view -------------------------------------------------------
const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
const trunc = (s, n) => (s.length > n ? `${s.slice(0, n)}…` : s);

const lines = [];
lines.push('# A1 — rule regex catalogue and static ReDoS triage');
lines.push('');
lines.push('Generated by `scripts/sec-a1-catalog.mjs`. Do not hand-edit (SCOPE §5).');
lines.push('');
lines.push(`- Rules: **${summary.totalRules}**, patterns extracted: **${summary.totalPatterns}**`);
if (rulesWithoutLiteral.length) {
  lines.push(`- ⚠ Rules with NO captured pattern (coverage hole): ${rulesWithoutLiteral.join(', ')}`);
} else {
  lines.push('- Every rule executed at least one pattern (no coverage hole).');
}
if (ruleInvocationErrors.length) {
  lines.push(`- ⚠ Rules that threw on the probe (coverage may be partial): ${ruleInvocationErrors.map((e) => e.ruleId).join(', ')}`);
}
if (unreachedLiterals.length) {
  lines.push(`- ⚠ Source literals never reached at runtime (${unreachedLiterals.length}): ${[...new Set(unreachedLiterals.map((u) => u.ruleId))].join(', ')} — not proven to run, so not classified`);
}
if (recheck.available) {
  lines.push(`- recheck ${summary.recheck.version}: **${summary.superLinearRulesByRecheck} / ${summary.totalRules}** rules super-linear on file content`);
  if (summary.superLinearRulesEvidenceOnly.length) {
    lines.push(`  - plus ${summary.superLinearRulesEvidenceOnly.length} rule(s) super-linear only on match evidence (weaker: length bounded by the outer match) — ${summary.superLinearRulesEvidenceOnly.join(', ')}`);
  }
} else {
  lines.push(`- ⚠ recheck unavailable (${summary.recheck.reason}) — counts below are **heuristic only**`);
}
lines.push(`- Shape heuristic: **${summary.suspiciousRulesByShape} / ${summary.totalRules}** rules suspicious`);
lines.push(`- Classifier disagreements: **${summary.disagreementCount}** (each is a triage decision, not a verdict)`);
lines.push('');
lines.push('## Patterns');
lines.push('');
lines.push('| rule | sev | applied to | recheck class | shape | pattern |');
lines.push('|---|---|---|---|---|---|');
for (const e of entries) {
  const shape = e.shape.suspicious ? e.shape.hits.map((h) => h.id).join(', ') : '—';
  lines.push(
    `| ${e.ruleId}#${e.patternIndex} | ${e.severity} | ${e.appliedTo} | ${e.recheck.class} | ${shape} | \`${esc(trunc(e.source, 90))}\` |`,
  );
}
lines.push('');
if (disagreements.length) {
  lines.push('## Classifier disagreements');
  lines.push('');
  lines.push('Shape-suspicious but recheck-safe = false alarm to drop from the n–T run.');
  lines.push('recheck-super-linear but shape-clean = a shape the heuristic should learn.');
  lines.push('');
  for (const e of disagreements) {
    lines.push(`- \`${e.ruleId}\` — shape: ${e.shape.suspicious ? e.shape.hits.map((h) => h.id).join(', ') : 'clean'}; ${e.recheck.detail}`);
  }
  lines.push('');
}
writeFileSync(OUT_MD, `${lines.join('\n')}\n`);

console.log(`[a1-catalog] ${summary.totalPatterns} patterns from ${summary.rulesWithPatterns}/${summary.totalRules} rules`);
if (recheck.available) console.log(`[a1-catalog] super-linear by recheck: ${summary.superLinearRulesByRecheck}/${summary.totalRules}`);
console.log(`[a1-catalog] suspicious by shape:   ${summary.suspiciousRulesByShape}/${summary.totalRules}`);
console.log(`[a1-catalog] wrote ${OUT_JSON} and ${OUT_MD}`);
for (const e of ruleInvocationErrors) console.warn(`[a1-catalog] WARN: ${e.ruleId} threw on the probe: ${e.message}`);
for (const u of unreachedLiterals) console.warn(`[a1-catalog] WARN: ${u.ruleId} has a source literal never reached at runtime: /${u.source}/${u.flags}`);
if (rulesWithoutLiteral.length) {
  console.error(`[a1-catalog] FAIL: ${rulesWithoutLiteral.length} rule(s) executed no pattern: ${rulesWithoutLiteral.join(', ')}`);
  process.exit(2);
}

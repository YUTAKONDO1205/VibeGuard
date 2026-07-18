// E6 — context-window confidence evaluation (paper item ① + D1 A/B).
//
// Demonstrates that the context-window confidence layer DOWN-RANKS findings that
// sit in a non-executed context (comment / docstring / block comment / test
// path) while leaving real, executable occurrences of the *same* pattern at
// their default confidence. Produces:
//   1. a per-finding table over samples/context-window (control vs treatment
//      pairs) reporting BOTH arms side by side:
//        * "① un-gated" — what the context-window layer alone would produce;
//        * "①+D1 gated" — after the severity gate (D1) bounds the downgrade.
//      The two arms come from one `explainContextConfidence` call, so the A/B is
//      measured without a "disable the gate" flag existing in shipped code.
//   2. a "no collateral damage" check over samples/vulnerable (real true
//      positives must keep their confidence);
//   3. a false-positive guard over samples/safe (must stay 0 findings).
//
// The gate only ever *withholds* a downgrade, so the gated arm is >= the un-gated
// arm row by row, and rows where the two differ are exactly the findings the gate
// kept above the action threshold — the gate-held count.
//
// Run from the repo root after `npm run build`:
//   node scripts/e6-confidence-eval.mjs
// (`npm run build` is not optional: this imports the built dist, so running it
// against a stale dist silently reports the pre-change numbers.)
//
// It replicates the analyzer's confidence resolution directly from the rule
// layer (allRules + explainContextConfidence) so the numbers are transparent;
// the summary cross-checks the samples totals against the engine's published
// E2/E3 figures so the replication is self-validating.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  allRules,
  languageMatches,
  explainContextConfidence,
  SEVERITY_CONFIDENCE_FLOOR,
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
// "before" value, the un-gated arm and the signals that fired so we can explain
// each row.
//
// The analyzer's chokepoint is `m.confidence ?? contextConfidence(base,
// rule.severity, ctx, m, mode)`. `explainContextConfidence` takes the same
// arguments and `contextConfidence` is a thin wrapper over its `.confidence`,
// so calling the explain variant here reproduces the analyzer exactly while also
// yielding the un-gated arm and the signals — no second signal-detection pass.
//
// NOTE (argument order): this harness is plain .mjs, so nothing type-checks the
// call below, and `severity` is argument 2. The pre-D1 call shape
// `(base, ctx, m, mode)` happens to fail loudly — the arguments shift, `mode`
// lands in the `match` slot and signal detection throws — but a `severity` that
// merely arrives *undefined* (wrong field name, forgotten plumbing) does not:
// the floor lookup yields undefined, the gate quietly stops existing, and this
// table reverts to the pre-D1 numbers while looking perfectly healthy. That is
// the failure mode `assertGateReached` exists to catch; it re-derives the
// expected gate from the exported floor table instead of trusting this call.
// (Verified against both variants: the undefined-severity bug is caught.)
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
        const res = explainContextConfidence(before, rule.severity, ctx, m, mode);
        // `mode === 'off'` short-circuits before signal detection (it returns
        // `signals: []`), so keep the harness's explicit opt-out marker.
        const signals = mode === 'off' ? ['opt-out'] : res.signals;
        rows.push({
          ruleId: rule.ruleId,
          file: file.replace(/\\/g, '/'),
          // Display the line of the matched payload, not the raw startLine: some
          // rules anchor with `^\s*` and `\s` matches the preceding newline, so
          // startLine can point one line early. (Pre-existing reported-line
          // off-by-one, independent of item ①; see notes.)
          line: displayLine(m),
          severity: rule.severity,
          mode,
          before,
          ungated: res.ungated, // arm A: item ① alone
          after: res.confidence, // arm B: item ① + D1 severity gate
          floored: res.floored, // the gate actually held a downgrade back
          signals,
          changed: before !== res.confidence,
          ungatedChanged: before !== res.ungated,
        });
      }
    }
  }
  return rows;
}

// Structural self-check for the untyped call above. `SEVERITY_CONFIDENCE_FLOOR`
// is imported rather than re-declared so this cannot drift from the policy.
// Two invariants, both of which a dropped/misplaced `severity` argument breaks:
//   * downgrade-only: the gated arm never exceeds the rule's declared base;
//   * floor bound: for ANY non-null floor the resolver computes
//       effective = max(RANK[ungated], min(RANK[base], RANK[floor]))
//     so the gated arm must satisfy
//       RANK[after] >= min(RANK[before], RANK[floor]).
//     This is checked in its general form rather than being specialised to one
//     floor value. Backwards compatibility: when floor === 'high' (the top rung
//     of the ladder) min(RANK[before], 2) === RANK[before], so the inequality
//     degenerates to RANK[after] >= RANK[before], which combined with the
//     downgrade-only check above is exactly the old `after === before` assertion
//     for critical/high. A `medium` floor is now checked too — the previous
//     `floor !== 'high' ? continue` form silently skipped those rows, so a
//     regression in the medium band would still have printed "consistent ✓".
const RANK = { low: 0, medium: 1, high: 2 };
function assertGateReached(rows, label) {
  const problems = [];
  let gateEligible = 0;
  const byFloor = {}; // floor value -> eligible row count
  for (const r of rows) {
    if (RANK[r.after] > RANK[r.before]) {
      problems.push(`${r.ruleId} ${r.file}:${r.line} promoted ${r.before}->${r.after}`);
    }
    if (r.mode === 'off') continue;
    const floor = SEVERITY_CONFIDENCE_FLOOR[r.severity];
    if (floor == null) continue; // no floor declared: the gate cannot bind
    gateEligible += 1;
    byFloor[floor] = (byFloor[floor] || 0) + 1;
    const bound = Math.min(RANK[r.before], RANK[floor]);
    if (RANK[r.after] < bound) {
      problems.push(
        `${r.ruleId} ${r.file}:${r.line} sev=${r.severity} floor=${floor} but ${r.before}->${r.after} ` +
          `(below min(before,floor))`,
      );
    }
  }
  return { problems, gateEligible, byFloor, label };
}

// Severity classes that currently declare a floor, derived from the policy table
// instead of hard-coded, so adding/removing a floor updates the report text.
function flooredSeverities() {
  return Object.entries(SEVERITY_CONFIDENCE_FLOOR)
    .filter(([, v]) => v != null)
    .map(([sev]) => sev);
}

function dist(rows, key = 'after') {
  const d = { high: 0, medium: 0, low: 0 };
  for (const r of rows) d[r[key]] += 1;
  return d;
}

function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

// ---- 1. context-window fixture detail table ---------------------------------
const e6 = analyze('samples/context-window').sort(
  (a, b) => a.file.localeCompare(b.file) || a.line - b.line,
);
console.log('# E6 — context-window confidence (paper item ①) + D1 severity gate\n');
console.log('## samples/context-window — control vs treatment, un-gated vs gated\n');
console.log(
  '| ruleId | location | sev | context signal | ① un-gated | ①+D1 gated | gate |',
);
console.log('|---|---|---|---|---|---|---|');
for (const r of e6) {
  const loc = `${r.file.split('/').pop()}:${r.line}`;
  const sig = r.signals.length ? r.signals.join('+') : '— (executable)';
  const armA = r.ungatedChanged ? `**${r.before} → ${r.ungated}**` : `${r.before} → ${r.ungated}`;
  const armB = r.changed ? `**${r.before} → ${r.after}**` : `${r.before} → ${r.after}`;
  const gate = r.floored ? `**held (${r.ungated} → ${r.after})**` : '—';
  console.log(`| ${r.ruleId} | ${loc} | ${r.severity} | ${sig} | ${armA} | ${armB} | ${gate} |`);
}
const treated = e6.filter((r) => r.changed);
const control = e6.filter((r) => !r.changed);
const treatedUngated = e6.filter((r) => r.ungatedChanged);
const held = e6.filter((r) => r.floored);
console.log(
  `\n- findings: **${e6.length}**  ·  down-ranked (treatment): **${treated.length}**  ·  unchanged (control/executable): **${control.length}**`,
);
console.log(`- confidence after ① (un-gated):  ${JSON.stringify(dist(e6, 'ungated'))}  — down-ranked: **${treatedUngated.length}**`);
console.log(`- confidence after ①+D1 (gated):  ${JSON.stringify(dist(e6, 'after'))}  — down-ranked: **${treated.length}**`);
// The gate-held count: findings whose downgrade the severity gate withheld.
console.log(
  `- **gate held (D1 A/B): ${held.length}** of ${e6.length} — findings at a floored severity (${flooredSeverities().join('/')}) that the context signals would have down-ranked, held at or above their floor. ` +
    `The hold is not always all the way back to the declared confidence: a \`medium\` severity finding stops at \`medium\`, not at \`high\`.`,
);
for (const r of held) {
  console.log(
    `    ${r.ruleId} ${r.file.split('/').pop()}:${r.line} sev=${r.severity} [${r.signals.join('+')}] ungated=${r.ungated} → gated=${r.after}`,
  );
}
const e6Check = assertGateReached(e6, 'samples/context-window');
const flooredSevs = flooredSeverities();
const floorTable = Object.entries(SEVERITY_CONFIDENCE_FLOOR)
  .map(([sev, v]) => `${sev}=${v ?? 'null'}`)
  .join(', ');
const byFloorStr = Object.entries(e6Check.byFloor)
  .sort((a, b) => RANK[b[0]] - RANK[a[0]])
  .map(([f, n]) => `${f}=${n}`)
  .join(', ');
console.log(
  `- gate self-check: ${e6Check.gateEligible} eligible row(s) (sev∈{${flooredSevs.join(',')}}, mode≠off)` +
    `${byFloorStr ? ` · by floor: ${byFloorStr}` : ''} · ` +
    `${e6Check.problems.length === 0 ? 'consistent with SEVERITY_CONFIDENCE_FLOOR ✓' : `⚠ ${e6Check.problems.length} violation(s)`}`,
);
console.log(`- floor policy in force: {${floorTable}}`);
for (const p of e6Check.problems) console.log(`    ⚠ ${p}`);
if (e6Check.gateEligible === 0) {
  console.log(
    `    ⚠ no gate-eligible rows: the fixture has no row whose severity declares a floor (sev∈{${flooredSevs.join(',')}}) — ` +
      'D1 is not exercised at all (or `severity` is not reaching the gate)',
  );
}
// Per-floor coverage: a floor that exists in policy but has zero rows in this
// fixture is untested — the self-check would print "consistent ✓" without having
// looked at that band even once. Call it out explicitly.
const floorOwners = {}; // floor value -> severities declaring it
for (const sev of flooredSevs) {
  const f = SEVERITY_CONFIDENCE_FLOOR[sev];
  (floorOwners[f] ||= []).push(sev);
}
for (const [f, sevs] of Object.entries(floorOwners)) {
  if (!e6Check.byFloor[f]) {
    console.log(
      `    ⚠ floor '${f}' (declared for sev∈{${sevs.join(',')}}) has 0 eligible row(s): this fixture does not exercise it`,
    );
  }
}

// ---- 2. no-collateral check over samples/vulnerable -------------------------
const vuln = analyze('samples/vulnerable');
const vulnChanged = vuln.filter((r) => r.changed);
const vulnChangedUngated = vuln.filter((r) => r.ungatedChanged);
console.log('\n## samples/vulnerable — no-collateral check\n');
console.log(`- findings: **${vuln.length}** (engine E2 baseline: 50)`);
console.log(`- confidence after ①+D1: ${JSON.stringify(dist(vuln))} (E2 baseline: {"high":6,"medium":26,"low":18})`);
console.log(
  `- true-positives down-ranked: **${vulnChanged.length}** ${vulnChanged.length === 0 ? '✓ (no collateral damage)' : '⚠'}`,
);
for (const r of vulnChanged) {
  console.log(`    ${r.ruleId} ${r.file.split('/').pop()}:${r.line} ${r.before}->${r.after} [${r.signals.join('+')}]`);
}
// D1 can only withhold downgrades, and this corpus has zero downgrades to
// withhold — so the gate is provably inert here and the E2 fixed point must be
// bit-identical to the pre-D1 run. Report both arms to make that verifiable
// rather than asserted.
console.log(
  `- D1 inert here: un-gated down-ranked **${vulnChangedUngated.length}** = gated **${vulnChanged.length}**, gate held **${vuln.filter((r) => r.floored).length}** ` +
    `${vulnChangedUngated.length === vulnChanged.length ? '✓ (E2 unchanged by D1, as the spec deduces)' : '⚠'}`,
);

// ---- 3. false-positive guard over samples/safe ------------------------------
const safe = analyze('samples/safe');
console.log('\n## samples/safe — false-positive guard\n');
console.log(`- findings: **${safe.length}** (gate: must be 0) ${safe.length === 0 ? '✓' : '⚠'}`);

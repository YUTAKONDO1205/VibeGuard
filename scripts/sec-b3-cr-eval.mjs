// B3 — concealment-rate (CR) A/B evaluator (security paper, SCOPE.md §2.3).
//
// Reads the corpus manifest produced by scripts/sec-b3-gen-corpus.mjs, re-scans
// BOTH the original file and the disguised file through the rule layer, and
// resolves each match's confidence with `explainContextConfidence` — whose
// single call yields both arms of the A/B:
//   * `.ungated`    — item ① alone, i.e. "before D1" (context downgrade unbounded)
//   * `.confidence` — item ①+D1, i.e. "after D1"  (severity floor applied)
// No "disable the gate" flag exists or is needed.
//
// Metric (SCOPE.md 2.3), implemented literally:
//   action(k, x) = 1  <=>  RANK[confidence(x)] >= RANK[threshold k]
//   CR(d, k) = |{ v : action(v)=1 AND action(d(v))=0 AND severity preserved }|
//              / |{ v : action(v)=1 }|
// B3 attacks CONFIDENCE-BASED TRIAGE, not the severity `--fail-on` CI gate, so
// the threshold is a confidence threshold and severity only stratifies (and is
// checked for preservation: a pair whose severity moved is NOT concealment, it
// is a different finding).
//
// Determinism: no clock, no randomness, every readdir is sorted, every path in
// the JSON output is forward-slashed and repo-root relative.
//
// Run from the repo root (dist must be built — this imports @vibeguard/rules):
//   node scripts/sec-b3-cr-eval.mjs
//   node scripts/sec-b3-cr-eval.mjs --manifest <path> --out <path> --threshold medium
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { allRules, languageMatches, explainContextConfidence } from '@vibeguard/rules';

// Severity as the RULE REGISTRY declares it. This is the independent reference
// the per-pair severity assertion checks against — see `severityMatchesRegistry`.
// Severity being static per rule is what makes it usable as the bound in
// SEVERITY_CONFIDENCE_FLOOR and as the "attacker cannot move this" premise in
// SCOPE §1; if that ever stops holding, the B3 win condition changes meaning.
const RULE_SEVERITY = new Map(allRules.map((r) => [r.ruleId, r.severity]));

// Syntactic-liveness verdicts from sec-b3-poc.mjs, keyed by disguised path.
// SCOPE §2.3's win condition requires the vulnerability to SURVIVE the disguise;
// a disguised file that no longer parses is not a working attack, and counting
// it as concealment inflates CR with broken code. Optional by design: if the PoC
// script has not been run, every pair is `unverified` and the numerator is
// unchanged — but the output says so rather than implying verification happened.
const POC_PATH = 'security-experiment/_results/b3-poc.json';
const pocVerdicts = new Map();
let pocPresent = false;
if (existsSync(POC_PATH)) {
  pocPresent = true;
  for (const r of JSON.parse(readFileSync(POC_PATH, 'utf8')).results ?? []) {
    pocVerdicts.set(r.path, r.verdict);
  }
}
// parseSuppressions/isSuppressed are NOT re-exported from @vibeguard/rules, so we
// reach into analyzer-core's dist directly. They are load-bearing here: analyzer.ts
// drops a suppressed match BEFORE confidence is ever computed
// (`if (isSuppressed(suppressions, rule.ruleId, m.startLine)) continue;`), so an
// evaluator that only calls explainContextConfidence scores the suppress-wildcard
// transform as CR=0 when in fact it conceals EVERYTHING. Verified empirically:
// the corpus pragma yields fileWide expiresAt 2099-12-31 and suppresses every ruleId.
import {
  parseSuppressions,
  isSuppressed,
} from '../packages/analyzer-core/dist/suppress.js';

// ---------------------------------------------------------------- constants --
const REPO_ROOT = process.cwd();
const DEFAULT_MANIFEST = 'security-experiment/_results/b3-corpus-manifest.json';
const DEFAULT_OUT = 'security-experiment/_results/b3-cr.json';
const CORPUS_ROOT = 'security-experiment/track-b-detection-robustness/b3-suppression-abuse/corpus';
const THRESHOLDS = ['high', 'medium', 'low'];
const RANK = { low: 0, medium: 1, high: 2 };
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const PAIR_LINE_TOLERANCE = 2; // SCOPE 2.1 independent pairing rule

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

// ------------------------------------------------------------------- utils --
function slash(p) {
  return String(p).replace(/\\/g, '/');
}
function rel(p) {
  return slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));
}
function languageOf(path) {
  const dot = path.lastIndexOf('.');
  return dot === -1 ? undefined : LANG_BY_EXT[path.slice(dot).toLowerCase()];
}
/** Mirrors confidence.ts `inspectedLine`: the `^\s*` newline-anchor correction. */
function inspectedLine(m) {
  const ev = m.evidence ?? '';
  const firstNonWs = ev.search(/\S/);
  if (firstNonWs <= 0) return m.startLine;
  let newlines = 0;
  for (let i = 0; i < firstNonWs; i++) if (ev[i] === '\n') newlines += 1;
  return m.startLine + newlines;
}
function ruleFamilyOf(ruleId) {
  const parts = String(ruleId).split('-');
  return parts.length >= 2 ? `${parts[0]}-${parts[1]}` : String(ruleId);
}
function fail(msg) {
  console.error(`\nsec-b3-cr-eval: ${msg}\n`);
  process.exit(1);
}
function ratio(n, d) {
  return d === 0 ? null : Number((n / d).toFixed(6));
}

// ------------------------------------------------------------------- argv ----
const argv = process.argv.slice(2);
function argOf(name, dflt) {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] != null ? argv[i + 1] : dflt;
}
const manifestPath = resolve(REPO_ROOT, argOf('--manifest', DEFAULT_MANIFEST));
const outPath = resolve(REPO_ROOT, argOf('--out', DEFAULT_OUT));
const primaryThreshold = argOf('--threshold', 'medium');
if (!THRESHOLDS.includes(primaryThreshold)) {
  fail(`--threshold must be one of ${THRESHOLDS.join('|')} (got "${primaryThreshold}")`);
}

// ------------------------------------------------------------- rule layer ----
const RULE_ERRORS = []; // counted and reported, never swallowed
const SUPPRESSED_DROPS = []; // matches killed by a vibeguard:disable pragma, as analyzer.ts would
const PER_MATCH_CONFIDENCE = new Map(); // ruleId -> [{file,line,confidence}] — must stay empty
const OPT_OUT_RULES = allRules
  .filter((r) => (r.contextConfidence ?? 'auto') === 'off')
  .map((r) => r.ruleId)
  .sort();
const OPT_OUT_SET = new Set(OPT_OUT_RULES);

const scanCache = new Map();

/**
 * Scan one file through every applicable rule and resolve both confidence arms.
 * Returns [] (and records a note) for a file with no recognised language: the
 * scanner cannot run there at all, which is itself an observation, not a crash.
 */
function scanFile(absPath) {
  const key = slash(absPath);
  if (scanCache.has(key)) return scanCache.get(key);
  const out = [];
  const language = languageOf(key);
  if (!existsSync(absPath)) {
    RULE_ERRORS.push({ kind: 'missing-file', file: rel(absPath), message: 'file does not exist' });
    scanCache.set(key, out);
    return out;
  }
  const content = readFileSync(absPath, 'utf8');
  const ctx = { content, lines: content.split('\n'), language, filePath: slash(absPath) };
  // Mirror analyzer.ts exactly, including its quirks: parseSuppressions is called
  // with NO `now` override (so suppress.ts falls back to new Date() — the corpus
  // therefore uses only the literal far-future until=2099-12-31, which cannot
  // expire and keeps this deterministic), and isSuppressed is keyed on the RAW
  // m.startLine, not the newline-corrected inspectedLine(m) that confidence.ts uses.
  const suppressions = parseSuppressions(content);
  for (const rule of allRules) {
    if (!languageMatches(rule.languages, language)) continue;
    let matches;
    try {
      matches = rule.match(ctx);
    } catch (err) {
      RULE_ERRORS.push({
        kind: 'rule-throw',
        ruleId: rule.ruleId,
        file: rel(absPath),
        message: String(err && err.message ? err.message : err),
      });
      continue;
    }
    const mode = rule.contextConfidence ?? 'auto';
    for (const m of matches) {
      // Suppressed matches never reach the confidence layer in production, so they
      // must not reach it here either. Dropping the row makes the finding VANISH
      // from the scan, which the pair resolver already scores as action(d(v))=0 —
      // concealment via the suppression mechanism rather than a downgrade.
      if (isSuppressed(suppressions, rule.ruleId, m.startLine)) {
        SUPPRESSED_DROPS.push({ ruleId: rule.ruleId, file: rel(absPath), line: m.startLine });
        continue;
      }
      if (m.confidence != null) {
        // A per-match confidence bypasses the whole context/gate module. No rule
        // does this today; if one starts, surface it instead of absorbing it.
        if (!PER_MATCH_CONFIDENCE.has(rule.ruleId)) PER_MATCH_CONFIDENCE.set(rule.ruleId, []);
        PER_MATCH_CONFIDENCE.get(rule.ruleId).push({
          file: rel(absPath),
          line: inspectedLine(m),
          confidence: m.confidence,
        });
      }
      const res = explainContextConfidence(rule.defaultConfidence, rule.severity, ctx, m, mode);
      out.push({
        ruleId: rule.ruleId,
        ruleFamily: ruleFamilyOf(rule.ruleId),
        severity: rule.severity,
        mode,
        base: rule.defaultConfidence,
        // analyzer.ts suppresses on the RAW startLine while confidence.ts keys off
        // inspectedLine(); keep both so pair resolution can accept either.
        rawLine: m.startLine,
        line: inspectedLine(m),
        // per-match confidence would bypass the module in the real analyzer:
        // model that faithfully so the arms match production if it ever happens.
        ungated: m.confidence ?? res.ungated,
        gated: m.confidence ?? res.confidence,
        signals: res.signals.slice(),
        floored: res.floored,
      });
    }
  }
  out.sort((a, b) => a.line - b.line || a.ruleId.localeCompare(b.ruleId));
  scanCache.set(key, out);
  return out;
}

function listFiles(dir) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listFiles(full));
    else if (languageOf(slash(full))) out.push(full);
  }
  return out.sort();
}
function scanDir(dir) {
  const rows = [];
  for (const f of listFiles(resolve(REPO_ROOT, dir))) rows.push(...scanFile(f));
  return rows;
}

// --------------------------------------------------------------- manifest ----
if (!existsSync(manifestPath)) {
  fail(
    `corpus manifest not found at ${rel(manifestPath)}.\n` +
      `  The evaluator has nothing to evaluate until the generator has run.\n` +
      `  Fix: node scripts/sec-b3-gen-corpus.mjs   (or pass --manifest <path>)`,
  );
}
let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
} catch (err) {
  fail(`corpus manifest at ${rel(manifestPath)} is not valid JSON: ${err.message}`);
}
if (!manifest || !Array.isArray(manifest.pairs)) {
  fail(`corpus manifest at ${rel(manifestPath)} has no "pairs" array — cannot evaluate.`);
}
if (manifest.pairs.length === 0) {
  fail(`corpus manifest at ${rel(manifestPath)} contains 0 pairs — nothing to evaluate.`);
}

/** disguisedPath may be repo-root relative or corpus-relative; accept both. */
function resolveCorpusPath(p) {
  const direct = resolve(REPO_ROOT, p);
  if (existsSync(direct)) return direct;
  const viaCorpus = resolve(REPO_ROOT, CORPUS_ROOT, p);
  if (existsSync(viaCorpus)) return viaCorpus;
  return direct; // scanFile records the missing-file error
}

// ------------------------------------------------------- pair resolution -----
/** Exact-ish resolution of the manifest's declared finding inside a scan. */
function findDeclared(findings, ruleId, line) {
  // The generator writes disguisedLine: null when the finding vanished from the
  // disguised copy. Without this guard, `Math.abs(f.line - null)` coerces null to 0
  // and the tolerant pass silently matches ANY same-rule finding on lines 1-2 —
  // turning a genuine concealment into a bogus "still detected" pair.
  if (line == null) return { finding: null, how: 'declared-absent' };
  const sameRule = findings.filter((f) => f.ruleId === ruleId);
  let hit = sameRule.find((f) => f.line === line || f.rawLine === line);
  if (hit) return { finding: hit, how: 'exact' };
  hit = sameRule
    .filter((f) => Math.abs(f.line - line) <= PAIR_LINE_TOLERANCE || Math.abs(f.rawLine - line) <= PAIR_LINE_TOLERANCE)
    .sort((a, b) => Math.abs(a.line - line) - Math.abs(b.line - line))[0];
  if (hit) return { finding: hit, how: 'tolerant' };
  return { finding: null, how: 'unresolved' };
}

/**
 * SCOPE 2.1's INDEPENDENT pairing rule, re-derived here without looking at the
 * generator's declared ruleId/line: same file, line within ±2 of the expected
 * position, same rule FAMILY. Agreement with the generator's explicit pairing is
 * the cross-check; disagreement is a bug signal in the generator (or in us).
 */
function independentPair(findings, family, expectedLine) {
  const cands = findings
    .filter((f) => f.ruleFamily === family)
    .filter(
      (f) =>
        Math.abs(f.line - expectedLine) <= PAIR_LINE_TOLERANCE ||
        Math.abs(f.rawLine - expectedLine) <= PAIR_LINE_TOLERANCE,
    )
    .sort((a, b) => Math.abs(a.line - expectedLine) - Math.abs(b.line - expectedLine) || a.ruleId.localeCompare(b.ruleId));
  return cands[0] ?? null;
}

const pairRows = [];
const excludedOptOutPairs = [];
const unresolved = [];
let agreeCount = 0;
let agreeDenom = 0;

for (const p of [...manifest.pairs].sort((a, b) => String(a.pairId).localeCompare(String(b.pairId)))) {
  const ruleId = p.ruleId;
  const family = p.ruleFamily ?? ruleFamilyOf(ruleId);
  const transform = p.transform ?? 'unknown';

  if (OPT_OUT_SET.has(ruleId)) {
    excludedOptOutPairs.push({ pairId: p.pairId, ruleId, transform, reason: "contextConfidence:'off'" });
    continue;
  }

  const origAbs = resolve(REPO_ROOT, p.origPath);
  const disgAbs = resolveCorpusPath(p.disguisedPath);
  const origFindings = scanFile(origAbs);
  const disgFindings = scanFile(disgAbs);

  const origHit = findDeclared(origFindings, ruleId, p.origLine);
  const disgHit = findDeclared(disgFindings, ruleId, p.disguisedLine);

  if (!origHit.finding) {
    unresolved.push({
      pairId: p.pairId,
      side: 'original',
      transform,
      ruleId,
      path: rel(origAbs),
      line: p.origLine,
      reason: 'no matching finding in re-scan of the original',
    });
    continue;
  }

  // Independent SCOPE 2.1 cross-check of the DISGUISED side (the side the
  // generator actually chose). Expected line = origLine + lineDelta when the
  // generator declares one, else the declared disguisedLine.
  const expected = p.disguisedLine ?? p.origLine + (p.lineDelta ?? 0);
  const indep = independentPair(disgFindings, family, expected);
  agreeDenom += 1;
  const declared = disgHit.finding;
  const agrees =
    (declared == null && indep == null) ||
    (declared != null && indep != null && declared.ruleId === indep.ruleId && declared.line === indep.line);
  if (agrees) agreeCount += 1;

  pairRows.push({
    pairId: p.pairId,
    transform,
    ruleId,
    ruleFamily: family,
    severity: origHit.finding.severity,
    manifestSeverity: p.severity ?? null,
    payloadExecutable: p.payloadExecutable !== false,
    pocVerdict: p.disguisedPath == null ? null : (pocVerdicts.get(p.disguisedPath) ?? 'unverified'),
    orig: origHit.finding,
    // A disguised finding that vanished entirely is DETECTION LOSS, not a
    // confidence downgrade. It is still action(d(v))=0, so it still conceals —
    // but it is tracked separately because the mechanism differs.
    disguised: disgHit.finding, // may be null
    disguisedVanished: disgHit.finding == null,
    // Severity preservation — the third clause of the CR win condition.
    //
    // Read carefully: this comparison CANNOT fail, and that is a fact about the
    // engine, not a gap in the harness. `RuleMatch` (packages/rules/src/rule-types.ts)
    // carries no severity; severity lives only on `RuleDefinition`, and pairing
    // keys on `ruleId`, so both sides read the same static field. Reporting
    // `severityChanged: 0` as though it were a measurement would be dressing a
    // tautology up as evidence.
    //
    // So we assert the invariant against the RULE REGISTRY rather than comparing
    // two copies of the same value: if a finding's severity ever diverges from
    // its rule's declared severity, something upstream is rewriting severity and
    // the whole "severity is attacker-immutable" premise (SCOPE §1) is void.
    // That is worth catching loudly; the tautological equality is not.
    severityPreserved: disgHit.finding == null ? null : disgHit.finding.severity === origHit.finding.severity,
    severityMatchesRegistry:
      RULE_SEVERITY.get(ruleId) == null
        ? null
        : origHit.finding.severity === RULE_SEVERITY.get(ruleId) &&
          (disgHit.finding == null || disgHit.finding.severity === RULE_SEVERITY.get(ruleId)),
    pairingAgrees: agrees,
    resolution: { orig: origHit.how, disguised: disgHit.how },
  });
}

// ------------------------------------------------------------- CR compute ----
function action(conf, threshold) {
  return conf != null && RANK[conf] >= RANK[threshold];
}

function computeArms(threshold) {
  const byTransform = {};
  const totals = {
    denominatorUngated: 0,
    denominatorGated: 0,
    concealedUngated: 0,
    concealedGated: 0,
  };
  for (const row of pairRows) {
    // `countsTowardAsr` / `mechanism` come from the manifest's transformMeta and
    // are carried onto every transform row, because the worst-case headline below
    // must be re-derivable from the emitted JSON alone.
    const meta = manifest.transformMeta?.[row.transform] ?? {};
    const t = (byTransform[row.transform] ??= {
      bySeverity: {},
      total: null,
      mechanism: meta.mechanism ?? null,
      payloadExecutable: meta.payloadExecutable ?? null,
      countsTowardAsr: meta.countsTowardAsr ?? meta.payloadExecutable !== false,
    });
    const sev = (t.bySeverity[row.severity] ??= {
      pairs: 0,
      denominator: 0, // gated-arm denominator (the shipped engine's view)
      denominatorUngated: 0,
      denominatorGated: 0,
      concealedUngated: 0,
      concealedGated: 0,
      severityChanged: 0,
      disguisedVanished: 0,
      notLive: 0,
      crUngated: null,
      crGated: null,
    });
    sev.pairs += 1;
    if (row.disguisedVanished) sev.disguisedVanished += 1;
    if (row.severityPreserved === false) sev.severityChanged += 1;

    // severity preservation is a precondition on the CONCEALMENT numerator only;
    // a vanished disguised finding has no severity to change, so it qualifies.
    const preserved = row.severityPreserved !== false;

    // Liveness precondition (SCOPE §2.3: the vulnerability must survive). A
    // disguised file that fails its language's syntax check is broken code, not
    // a concealment — it stays in the DENOMINATOR (the original was actionable)
    // but is barred from the NUMERATOR, so a broken disguise scores as a FAILED
    // attack rather than a successful one. `unverified` does not bar: absence of
    // a toolchain is not evidence of breakage.
    const live = row.pocVerdict !== 'syntax-error';
    if (!live) sev.notLive += 1;

    for (const arm of ['ungated', 'gated']) {
      const vConf = row.orig[arm];
      if (!action(vConf, threshold)) continue;
      sev[arm === 'ungated' ? 'denominatorUngated' : 'denominatorGated'] += 1;
      totals[arm === 'ungated' ? 'denominatorUngated' : 'denominatorGated'] += 1;
      const dConf = row.disguised ? row.disguised[arm] : null;
      if (!action(dConf, threshold) && preserved && live) {
        sev[arm === 'ungated' ? 'concealedUngated' : 'concealedGated'] += 1;
        totals[arm === 'ungated' ? 'concealedUngated' : 'concealedGated'] += 1;
      }
    }
    sev.denominator = sev.denominatorGated;
  }
  for (const t of Object.values(byTransform)) {
    const agg = {
      pairs: 0,
      denominatorUngated: 0,
      denominatorGated: 0,
      concealedUngated: 0,
      concealedGated: 0,
    };
    for (const sev of Object.values(t.bySeverity)) {
      sev.crUngated = ratio(sev.concealedUngated, sev.denominatorUngated);
      sev.crGated = ratio(sev.concealedGated, sev.denominatorGated);
      for (const k of Object.keys(agg)) agg[k] += sev[k];
    }
    // stable severity ordering in the emitted JSON
    t.bySeverity = Object.fromEntries(
      Object.entries(t.bySeverity).sort(
        (a, b) => SEVERITY_ORDER.indexOf(a[0]) - SEVERITY_ORDER.indexOf(b[0]),
      ),
    );
    t.total = {
      ...agg,
      denominator: agg.denominatorGated,
      crUngated: ratio(agg.concealedUngated, agg.denominatorUngated),
      crGated: ratio(agg.concealedGated, agg.denominatorGated),
    };
  }
  const sorted = Object.fromEntries(Object.entries(byTransform).sort((a, b) => a[0].localeCompare(b[0])));

  // NO POOLED `overall`. A single averaged CR across transforms was reported
  // here and it was not a defensible number: it pooled the negative control
  // (docstring-naive, payload genuinely commented out) with real attacks, and
  // pooled `suppression` mechanism rows (finding DROPPED before confidence is
  // computed) with `confidence` mechanism rows (finding downgraded). Averaging
  // those is averaging different experiments.
  //
  // SCOPE.md §2.3「最悪ケース主義: 平均精度で薄めない」forbids it independently:
  // the methodology commits to worst-case per rule family, not to means. So the
  // headline is the WORST CASE over transforms that (a) count toward ASR and
  // (b) conceal via the confidence mechanism — with every arm, including the
  // zeros, still present per-transform above so nothing can be cherry-picked.
  const asrEligible = Object.entries(sorted).filter(
    ([, t]) => t.countsTowardAsr && t.mechanism === 'confidence',
  );
  let worstCase = null;
  for (const [name, t] of asrEligible) {
    for (const [severity, sev] of Object.entries(t.bySeverity)) {
      if (sev.crUngated == null) continue;
      // Tie-break on denominator: several rows reach CR=1.0, and reporting the
      // one backed by 2 pairs when another is backed by 7 invites a fair "n=2"
      // objection. Max CR first, best-evidenced instance of it second — this
      // cannot cherry-pick upward because the CR value is unchanged by the tie-break.
      const better =
        worstCase == null ||
        sev.crUngated > worstCase.crUngated ||
        (sev.crUngated === worstCase.crUngated && sev.denominatorUngated > worstCase.denominator);
      if (better) {
        worstCase = {
          transform: name,
          severity,
          crUngated: sev.crUngated,
          crGated: sev.crGated,
          concealedUngated: sev.concealedUngated,
          concealedGated: sev.concealedGated,
          denominator: sev.denominatorUngated,
        };
      }
    }
  }
  return {
    byTransform: sorted,
    // Named so it cannot be mistaken for a mean, and carrying its own eligibility
    // rule so a reader can re-derive which rows were in scope.
    worstCase,
    worstCaseScope: {
      rule: 'max CR_ungated over (transform, severity) where countsTowardAsr && mechanism==="confidence"',
      eligibleTransforms: asrEligible.map(([n]) => n),
      excluded: Object.entries(sorted)
        .filter(([, t]) => !(t.countsTowardAsr && t.mechanism === 'confidence'))
        .map(([n, t]) => ({
          transform: n,
          reason: !t.countsTowardAsr
            ? 'negative control (payload not executable)'
            : `mechanism is ${t.mechanism}, not a confidence downgrade`,
        })),
    },
  };
}

const sweep = {};
for (const t of THRESHOLDS) sweep[t] = computeArms(t);
const primary = sweep[primaryThreshold];

// -------------------------------------------------------- side constraints ---
const safeRows = scanDir('samples/safe');
const vulnRows = scanDir('samples/vulnerable');
function dist(rows, key) {
  const d = { high: 0, medium: 0, low: 0 };
  for (const r of rows) d[r[key]] += 1;
  return d;
}
const EXPECT_VULN_TOTAL = 50;
const EXPECT_VULN_DIST = { high: 6, medium: 26, low: 18 };
const actualVulnDist = dist(vulnRows, 'gated');
const sideConstraints = {
  safeFindings: safeRows.length,
  safeFindingsExpected: 0,
  safeFindingsOk: safeRows.length === 0,
  vulnerableTotal: vulnRows.length,
  vulnerableTotalExpected: EXPECT_VULN_TOTAL,
  vulnerableTotalOk: vulnRows.length === EXPECT_VULN_TOTAL,
  vulnerableDistribution: actualVulnDist,
  vulnerableDistributionExpected: EXPECT_VULN_DIST,
  vulnerableDistributionOk:
    JSON.stringify(actualVulnDist) === JSON.stringify(EXPECT_VULN_DIST),
  vulnerableDistributionUngated: dist(vulnRows, 'ungated'),
};

// ------------------------------------------------------------------ output ---
const perMatchConfidenceRules = [...PER_MATCH_CONFIDENCE.entries()]
  .sort((a, b) => a[0].localeCompare(b[0]))
  .map(([ruleId, occurrences]) => ({ ruleId, count: occurrences.length, examples: occurrences.slice(0, 3) }));

const result = {
  metric: 'CR (concealment rate) — SCOPE.md §2.3; confidence-based triage, not the --fail-on severity gate',
  generatedBy: 'sec-b3-cr-eval.mjs',
  manifest: rel(manifestPath),
  manifestEngineVersion: manifest.engineVersion ?? null,
  threshold: primaryThreshold,
  arms: {
    ungated: 'explainContextConfidence(...).ungated — item ① alone (before D1)',
    gated: 'explainContextConfidence(...).confidence — item ①+D1 severity floor (after D1)',
  },
  byTransform: primary.byTransform,
  worstCase: primary.worstCase,
  worstCaseScope: primary.worstCaseScope,
  thresholdSweep: sweep,
  pairs: {
    declared: manifest.pairs.length,
    evaluated: pairRows.length,
    excludedOptOut: excludedOptOutPairs.length,
    unresolvedOriginal: unresolved.length,
    disguisedVanished: pairRows.filter((r) => r.disguisedVanished).length,
    // Tautological by construction (see `severityPreserved` above) — reported so
    // the number is on the page, but NOT as evidence the clause was exercised.
    severityChanged: pairRows.filter((r) => r.severityPreserved === false).length,
    severityChangedNote:
      'structurally always 0: severity is a static RuleDefinition field, not a RuleMatch field, ' +
      'and pairing keys on ruleId. Not evidence; see severityRegistryViolations for the real check.',
    // The check that CAN fail: a finding whose severity diverges from what its
    // rule declares would mean severity is not attacker-immutable after all.
    severityRegistryViolations: pairRows.filter((r) => r.severityMatchesRegistry === false).length,
  },
  pairingAgreement: agreeDenom === 0 ? null : ratio(agreeCount, agreeDenom),
  pairingAgreementDetail: {
    rule: 'SCOPE 2.1 — same file × line ±2 × rule family, re-derived independently of the manifest ruleId/line',
    agreed: agreeCount,
    checked: agreeDenom,
    disagreements: pairRows.filter((r) => !r.pairingAgrees).map((r) => ({
      pairId: r.pairId,
      transform: r.transform,
      ruleId: r.ruleId,
      declaredResolved: r.disguised ? { ruleId: r.disguised.ruleId, line: r.disguised.line } : null,
    })),
  },
  sideConstraints,
  excluded: {
    optOutRules: OPT_OUT_RULES,
    optOutPairs: excludedOptOutPairs,
    perMatchConfidenceRules,
  },
  unresolvedPairs: unresolved,
  // Concealment via the suppression layer is invisible to explainContextConfidence;
  // record it explicitly so a CR of 1.0 for suppress-wildcard is auditable.
  suppression: {
    note: 'matches dropped by a vibeguard:disable pragma before confidence is computed, mirroring analyzer.ts',
    droppedMatches: SUPPRESSED_DROPS.length,
    droppedFiles: [...new Set(SUPPRESSED_DROPS.map((d) => d.file))].sort().length,
  },
  ruleErrors: RULE_ERRORS,
  manifestUnsupported: manifest.unsupported ?? [],
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8');

// ------------------------------------------------------------ human report ---
function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}
console.log('# B3 — concealment rate (CR), before/after D1\n');
console.log(`manifest: ${rel(manifestPath)}  ·  engineVersion: ${result.manifestEngineVersion ?? '(none)'}`);
console.log(
  `pairs: declared ${result.pairs.declared} · evaluated ${result.pairs.evaluated} · ` +
    `opt-out excluded ${result.pairs.excludedOptOut} · unresolved-original ${result.pairs.unresolvedOriginal}\n`,
);
console.log(`## CR at threshold = ${primaryThreshold}\n`);
console.log('| transform | severity | denom (ungated/gated) | concealed (ungated/gated) | CR ungated | CR gated |');
console.log('|---|---|---|---|---|---|');
for (const [tname, t] of Object.entries(primary.byTransform)) {
  for (const [sev, s] of Object.entries(t.bySeverity)) {
    console.log(
      `| ${pad(tname, 14)} | ${pad(sev, 8)} | ${s.denominatorUngated}/${s.denominatorGated} | ` +
        `${s.concealedUngated}/${s.concealedGated} | ${s.crUngated ?? 'n/a'} | ${s.crGated ?? 'n/a'} |`,
    );
  }
  console.log(
    `| **${tname}** | **all** | ${t.total.denominatorUngated}/${t.total.denominatorGated} | ` +
      `${t.total.concealedUngated}/${t.total.concealedGated} | **${t.total.crUngated ?? 'n/a'}** | **${t.total.crGated ?? 'n/a'}** |`,
  );
}
// Worst case, NOT a mean. See computeArms() for why no pooled average is emitted.
const wc = primary.worstCase;
console.log(
  wc == null
    ? '\nworst case: none (no ASR-eligible confidence-mechanism row had a denominator)'
    : `\nworst case (max CR over ASR-eligible confidence-downgrade rows): ` +
        `**${wc.transform} / ${wc.severity}** — CR ungated **${wc.crUngated}** ` +
        `(${wc.concealedUngated}/${wc.denominator}) → CR gated **${wc.crGated}** ` +
        `(${wc.concealedGated}/${wc.denominator})`,
);
console.log(
  `excluded from the worst-case scope: ` +
    (primary.worstCaseScope.excluded.map((e) => `${e.transform} (${e.reason})`).join('; ') || 'none') +
    `\n(all excluded rows are still shown in the per-transform table above — nothing is dropped from view)`,
);

console.log('\n## threshold sweep (worst case per threshold)\n');
console.log('| threshold | worst row | CR ungated | CR gated |');
console.log('|---|---|---|---|');
for (const t of THRESHOLDS) {
  const w = sweep[t].worstCase;
  console.log(
    w == null
      ? `| ${t} | n/a | n/a | n/a |`
      : `| ${t} | ${w.transform}/${w.severity} | ${w.crUngated} | ${w.crGated} |`,
  );
}

console.log(
  `\n## pairing cross-check\n\n- SCOPE 2.1 agreement: **${result.pairingAgreement ?? 'n/a'}** (${agreeCount}/${agreeDenom})` +
    `${result.pairingAgreementDetail.disagreements.length ? ` ⚠ ${result.pairingAgreementDetail.disagreements.length} disagreement(s)` : ' ✓'}`,
);
for (const d of result.pairingAgreementDetail.disagreements.slice(0, 10)) {
  console.log(`    ⚠ ${d.pairId} (${d.transform})`);
}

console.log('\n## side constraints\n');
console.log(`- samples/safe findings: ${sideConstraints.safeFindings} (expected 0) ${sideConstraints.safeFindingsOk ? '✓' : '⚠ MISMATCH'}`);
console.log(`- samples/vulnerable findings: ${sideConstraints.vulnerableTotal} (expected ${EXPECT_VULN_TOTAL}) ${sideConstraints.vulnerableTotalOk ? '✓' : '⚠ MISMATCH'}`);
console.log(
  `- samples/vulnerable distribution: ${JSON.stringify(actualVulnDist)} (expected ${JSON.stringify(EXPECT_VULN_DIST)}) ${sideConstraints.vulnerableDistributionOk ? '✓' : '⚠ MISMATCH'}`,
);

console.log('\n## exclusions & integrity\n');
console.log(`- contextConfidence:'off' rules excluded from the denominator: ${OPT_OUT_RULES.join(', ') || '(none)'} (${excludedOptOutPairs.length} pair(s) dropped)`);
console.log(
  `- rules setting per-match m.confidence: ${perMatchConfidenceRules.length === 0 ? 'none ✓ (the module is the sole chokepoint)' : `⚠ ${perMatchConfidenceRules.map((r) => `${r.ruleId}×${r.count}`).join(', ')} — these BYPASS the context layer and its severity gate`}`,
);
console.log(`- matches dropped by suppression pragmas (as analyzer.ts would): ${SUPPRESSED_DROPS.length} across ${result.suppression.droppedFiles} file(s)`);
console.log(`- rule errors: ${RULE_ERRORS.length}${RULE_ERRORS.length ? ' ⚠' : ' ✓'}`);
for (const e of RULE_ERRORS.slice(0, 10)) {
  console.log(`    ⚠ ${e.kind} ${e.ruleId ?? ''} ${e.file}: ${e.message}`);
}
if (unresolved.length) {
  console.log(`- unresolved pairs (original side not reproducible): ${unresolved.length} ⚠`);
  for (const u of unresolved.slice(0, 10)) console.log(`    ⚠ ${u.pairId} ${u.path}:${u.line} ${u.reason}`);
}

console.log(`\nwrote ${rel(outPath)}`);

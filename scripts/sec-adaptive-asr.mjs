// G3 — the adaptive adversary. Worst-case residual attack-success rate (ASR)
// against the SHIPPED defense (D2 canonicalization ON), under a Kerckhoffs
// assumption: the attacker knows the defense and picks the transform that beats
// it.
//
// WHY THIS EXISTS
// sec-b1-er-eval.mjs answers "how much of the evasion does D2 absorb?" per
// transform, in isolation. That is the defender's question. It is NOT the
// question a reviewer at a security venue asks, which is the attacker's:
//
//   Given that the attacker KNOWS D2 is deployed (Kerckhoffs — no security by
//   obscurity), and may choose ANY transform in the catalog per finding, what
//   fraction of originally-detected vulnerabilities can still be driven out of
//   triage?
//
// A per-transform mean hides this: averaging over transforms the attacker would
// never choose understates the threat. The attacker is not average; the attacker
// is the maximum. So the headline here is the WORST CASE — a finding counts as
// defeated if ANY catalog transform makes the shipped engine stop reporting it —
// and the honest contrast is the ADAPTIVITY PREMIUM: worst-case ASR minus the
// mean single-transform ASR, i.e. how much the attacker gains by choosing well
// rather than at random.
//
// THE UNIT IS A FINDING, NOT A PAIR.
// A "finding" is one originally-detected vulnerability instance:
// (origPath, origPayloadLine, ruleId). Each finding owns a PORTFOLIO of transform
// outcomes — the manifest pairs that share those three keys. Grouping by finding
// is what lets "some transform in the portfolio evades" be expressed at all; the
// per-pair ER tables cannot say it.
//
// DEFENSE = D2 ON. "Evaded" = outcomeTransformedTrue === 'absent': under the
// shipped (canonicalize-ON) engine the finding no longer EXISTS in the file. This
// is the same exists-based predicate the ER tables use as their headline; a
// 'relocated' finding still fires (elsewhere) and is NOT counted as evaded, and
// the severity/confidence gate is NOT consulted (a gated-but-present finding is
// still detected). Both choices match sec-b1-er-eval.mjs exactly.
//
// ROUNDS = CLASS ESCALATION, NOT COMPOSITION DEPTH.
// The manifest measured every SINGLE transform's D2 outcome. It did NOT measure
// compositions (transform-of-a-transform), so scoring composed attacks would mean
// inventing outcomes the corpus never observed — a fabrication. Instead the
// adaptive schedule is the attacker ESCALATING through the transform TAXONOMY as
// the defense forces them off the easy ground:
//   round 1 — lexical transforms only        (the cheapest surface rewrites)
//   round 2 — + name-resolution transforms   (rename/alias/dynamic dispatch)
//   round 3 — + structural transforms        (hoist/wrap/reshape) = full catalog
// This is adaptive in the Kerckhoffs sense: D2 is DESIGNED to absorb single-line
// lexical folding, so a naive lexical attacker is largely stopped at round 1; the
// residual ASR that appears at rounds 2–3 is precisely the attacker adapting to
// classes D2 does not reach (which is the taxonomy×D2 map G2 renders). Every
// round is a pure function of already-measured single-transform outcomes, so the
// whole thing is deterministic and re-derivable from the manifest.
//
// THE TAUTOLOGY PROBLEM ("worst-case over a catalog we designed") — five guards.
//   1. PRE-REGISTRATION. Each transform carries d2Predicted (covered/residual),
//      registered BEFORE measurement by reading canonicalizer.ts. The honest
//      claim is not "we found evasions" but "the evasions concentrate exactly in
//      the residual-PREDICTED classes, as pre-registered." Assertion A2 checks
//      that NO covered-predicted transform contributes a single evasion — if D2
//      leaked on something it claimed to fold, that would be the real finding.
//   2. ATTRIBUTION. The report lists which transforms drive the defeats and how
//      many findings each is the SOLE defeater of. Spread across independent
//      classes = a genuine attack surface; one bespoke transform doing all the
//      work = cherry-picking, and it would be visible here.
//   3. ADAPTIVITY PREMIUM, not raw max. Worst-case is reported beside the mean
//      and best-single-transform ASR. A worst-case that barely exceeds the mean
//      is a weak result and says so.
//   4. COST BUDGET. Each transform carries adversarialCost (categorical:
//      'M' mechanical / cheap, 'R' rich / expensive). ASR is reported at the cheap
//      budget (M only) and at the full budget (M+R), so a defeat that needs the
//      expensive class is not quoted as if it were free.
//   5. NC2. The noop-reformat control must yield residual ASR = 0 (assertion A1);
//      a non-zero there means the harness manufactures evasions.
//
// DETERMINISM: no clock, no randomness; findings and portfolios sorted; deep
// key-sorted JSON. A missing/……malformed manifest is a hard fail, never a zero.
//
// Usage (from the repo root):
//   node scripts/sec-adaptive-asr.mjs
//   node scripts/sec-adaptive-asr.mjs --manifest <path> --out <path>
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, relative, resolve } from 'node:path';

// ---------------------------------------------------------------- constants --
const REPO_ROOT = process.cwd();
const DEFAULT_MANIFEST = 'security-experiment/_results/b1-corpus-manifest.json';
const DEFAULT_OUT = 'security-experiment/_results/adaptive-asr.json';

// The escalation schedule: cumulative transform CLASSES per round. Fixed here, not
// discovered, so the schedule cannot be tuned to the result after the fact.
const ROUNDS = [
  { round: 1, label: 'lexical', classes: ['lexical'] },
  { round: 2, label: 'lexical+name-resolution', classes: ['lexical', 'name-resolution'] },
  { round: 3, label: 'lexical+name-resolution+structural', classes: ['lexical', 'name-resolution', 'structural'] },
];
const COST_BUDGETS = [
  { budget: 'M', label: 'cheap (mechanical only)', allow: ['M'] },
  { budget: 'M+R', label: 'full (mechanical + rich)', allow: ['M', 'R'] },
];

// ------------------------------------------------------------------- utils --
const slash = (p) => String(p).replace(/\\/g, '/');
const rel = (p) => slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));
function fail(msg) {
  console.error(`\nsec-adaptive-asr: ${msg}\n`);
  process.exit(1);
}
function ratio(n, d) {
  return d === 0 ? null : Number((n / d).toFixed(6));
}
function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}
function padL(s, n) {
  s = String(s);
  return s.length >= n ? s : ' '.repeat(n - s.length) + s;
}
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}

// ------------------------------------------------------------------- argv ----
const argv = process.argv.slice(2);
function argOf(name, dflt) {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] != null ? argv[i + 1] : dflt;
}
const manifestPath = resolve(REPO_ROOT, argOf('--manifest', DEFAULT_MANIFEST));
const outPath = resolve(REPO_ROOT, argOf('--out', DEFAULT_OUT));

// --------------------------------------------------------------- manifest ----
if (!existsSync(manifestPath)) {
  fail(`corpus manifest not found at ${rel(manifestPath)}.\n  Fix: node scripts/sec-b1-gen-corpus.mjs`);
}
let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
} catch (err) {
  fail(`corpus manifest at ${rel(manifestPath)} is not valid JSON: ${err.message}`);
}
if (!manifest || !Array.isArray(manifest.pairs) || manifest.pairs.length === 0) {
  fail(`corpus manifest at ${rel(manifestPath)} has no usable "pairs" array.`);
}

// ------------------------------------------------------------- build model ----
// A single transform "defeats" a finding under the shipped (D2-ON) engine iff its
// transformed file no longer reports the weakness: outcomeTransformedTrue ==='absent'.
const evadedD2 = (p) => p.outcomeTransformedTrue === 'absent';

// Every non-control pair, one attack observation.
const attackPairs = manifest.pairs.filter((p) => p.category !== 'negative-control');
const nc2Pairs = manifest.pairs.filter((p) => p.transformId === 'NC2' || p.transformName === 'noop-reformat');

// Findings: group attack pairs by (origPath, origPayloadLine, ruleId). Denominator
// is findings the SHIPPED engine caught in the original — a finding never detected
// cannot be evaded. (In this corpus every pair has detectedOrigTrue===true, but we
// filter explicitly so the invariant is enforced, not assumed.)
const findingsMap = new Map();
for (const p of attackPairs) {
  if (p.detectedOrigTrue !== true) continue;
  const key = `${slash(p.origPath)}::${p.origPayloadLine}::${p.ruleId}`;
  if (!findingsMap.has(key)) {
    findingsMap.set(key, {
      key,
      origPath: slash(p.origPath),
      origPayloadLine: p.origPayloadLine ?? null,
      ruleId: p.ruleId,
      ruleFamily: p.ruleFamily ?? null,
      language: p.language ?? null,
      severity: p.severity ?? null,
      portfolio: [],
    });
  }
  findingsMap.get(key).portfolio.push({
    transformId: p.transformId,
    transformName: p.transformName ?? p.transformId,
    category: p.category,
    d2Predicted: p.d2Predicted ?? null,
    adversarialCost: p.adversarialCost ?? null,
    evaded: evadedD2(p),
    pairId: p.pairId ?? null,
  });
}
const findings = [...findingsMap.values()].sort((a, b) => a.key.localeCompare(b.key));
for (const f of findings) f.portfolio.sort((a, b) => String(a.transformId).localeCompare(String(b.transformId)));
if (findings.length === 0) fail('no originally-detected attack findings in the manifest — nothing to measure');

// ---------------------------------------------------------- ASR computation ---
/** A finding is defeated by a portfolio SUBSET iff some transform in it evades D2. */
function defeatedBy(finding, pred) {
  return finding.portfolio.some((t) => pred(t) && t.evaded);
}
/** Residual ASR over a portfolio subset (pred selects eligible transforms). */
function residualASR(pred) {
  let defeated = 0;
  const ids = [];
  for (const f of findings) {
    if (defeatedBy(f, pred)) {
      defeated += 1;
      ids.push(f.key);
    }
  }
  return { defeated, total: findings.length, asr: ratio(defeated, findings.length), defeatedKeys: ids.sort() };
}

const inClasses = (classes) => (t) => classes.includes(t.category);
const inBudget = (allow) => (t) => allow.includes(t.adversarialCost);

// Worst-case (full catalog, full budget) and the round/budget grid.
const worstCase = residualASR(() => true);

const roundGrid = [];
for (const r of ROUNDS) {
  for (const b of COST_BUDGETS) {
    const res = residualASR((t) => inClasses(r.classes)(t) && inBudget(b.allow)(t));
    roundGrid.push({
      round: r.round,
      roundLabel: r.label,
      classes: r.classes,
      costBudget: b.budget,
      costLabel: b.label,
      ...res,
    });
  }
}

// Per-class residual ASR (each class ALONE), for the taxonomy×D2 attack view.
const byClass = {};
for (const cls of ['lexical', 'name-resolution', 'structural']) {
  byClass[cls] = residualASR(inClasses([cls]));
}

// Single-transform ASR contrasts, computed at the PAIR level (each transform on
// its own): mean over all attack pairs, and best single transform's own ASR over
// the findings it applies to. The adaptivity premium is worst-case minus mean.
const singleTransform = {};
{
  const byT = new Map();
  for (const p of attackPairs) {
    if (p.detectedOrigTrue !== true) continue;
    const id = p.transformId;
    if (!byT.has(id)) byT.set(id, { transformId: id, category: p.category, d2Predicted: p.d2Predicted ?? null, adversarialCost: p.adversarialCost ?? null, n: 0, evaded: 0 });
    const e = byT.get(id);
    e.n += 1;
    if (evadedD2(p)) e.evaded += 1;
  }
  const perTransform = [...byT.values()].map((e) => ({ ...e, asr: ratio(e.evaded, e.n) })).sort((a, b) => (b.asr ?? 0) - (a.asr ?? 0) || a.transformId.localeCompare(b.transformId));
  const totalPairs = perTransform.reduce((s, e) => s + e.n, 0);
  const totalEvaded = perTransform.reduce((s, e) => s + e.evaded, 0);
  singleTransform.perTransform = perTransform;
  singleTransform.meanSingleTransformASR = ratio(totalEvaded, totalPairs); // pooled mean over attack pairs
  singleTransform.bestSingleTransform = perTransform.find((e) => (e.asr ?? 0) > 0) ?? null;
}
const adaptivityPremium =
  worstCase.asr == null || singleTransform.meanSingleTransformASR == null
    ? null
    : Number((worstCase.asr - singleTransform.meanSingleTransformASR).toFixed(6));

// ------------------------------------------------------------- attribution ---
// Which transforms drive the worst-case defeats, and how many findings each is
// the SOLE evading transform for (uniqueness → concentration).
const attribution = {};
{
  const driveCount = new Map(); // transformId -> # findings it evades
  const soleCount = new Map(); // transformId -> # findings ONLY it evades
  for (const f of findings) {
    const evaders = f.portfolio.filter((t) => t.evaded);
    for (const t of evaders) driveCount.set(t.transformId, (driveCount.get(t.transformId) ?? 0) + 1);
    if (evaders.length === 1) soleCount.set(evaders[0].transformId, (soleCount.get(evaders[0].transformId) ?? 0) + 1);
  }
  const ids = [...new Set([...driveCount.keys(), ...soleCount.keys()])].sort();
  attribution.byTransform = ids.map((id) => ({
    transformId: id,
    findingsEvaded: driveCount.get(id) ?? 0,
    findingsSoleEvader: soleCount.get(id) ?? 0,
  })).sort((a, b) => b.findingsEvaded - a.findingsEvaded || a.transformId.localeCompare(b.transformId));
  attribution.distinctEvadingTransforms = ids.length;
  attribution.distinctEvadingClasses = [...new Set(findings.flatMap((f) => f.portfolio.filter((t) => t.evaded).map((t) => t.category)))].sort();
  // Concentration: the single most prolific transform's share of all defeated findings.
  const top = attribution.byTransform[0];
  attribution.topTransformShareOfDefeats = top && worstCase.defeated > 0 ? ratio(top.findingsEvaded, worstCase.defeated) : null;
  attribution.note =
    'findingsEvaded spread across many transforms/classes = genuine attack surface; concentrated in one = cherry-picking. topTransformShareOfDefeats is the concentration check.';
}

// -------------------------------------------------- worst-case by slices ------
function sliceASR(keyFn) {
  const groups = new Map();
  for (const f of findings) {
    const k = String(keyFn(f) ?? 'unknown');
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(f);
  }
  const out = {};
  for (const [k, fs] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const defeated = fs.filter((f) => defeatedBy(f, () => true)).length;
    out[k] = { findings: fs.length, defeated, worstCaseASR: ratio(defeated, fs.length) };
  }
  return out;
}
const bySeverity = sliceASR((f) => f.severity);
const byLanguage = sliceASR((f) => f.language);
const byRuleFamily = sliceASR((f) => f.ruleFamily);

// The paper's sharpest slice: are CRITICAL/HIGH findings evadable? A downgraded
// or vanished critical is the whole thesis.
const criticalHigh = findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
const criticalHighDefeated = criticalHigh.filter((f) => defeatedBy(f, () => true));
const highSeverityWorstCase = {
  findings: criticalHigh.length,
  defeated: criticalHighDefeated.length,
  worstCaseASR: ratio(criticalHighDefeated.length, criticalHigh.length),
  defeatedKeys: criticalHighDefeated.map((f) => f.key).sort(),
};

// ----------------------------------------------------------- assertions ------
const assertions = [];
function assert(id, claim, ok, detail) {
  assertions.push({ id, claim, ok, detail: detail ?? null });
}
// A1 — NC2 (noop-reformat) evades nothing under D2.
{
  const nc2Evaded = nc2Pairs.filter(evadedD2);
  assert(
    'A1',
    'the noop transform (NC2) yields residual ASR = 0 — a non-zero here means the harness manufactures evasions',
    nc2Pairs.length === 0 ? null : nc2Evaded.length === 0,
    nc2Pairs.length === 0 ? 'NC2 absent from the manifest — unmeasured, not passed' : `NC2 pairs ${nc2Pairs.length}, evaded ${nc2Evaded.length}`,
  );
}
// A2 — no covered-PREDICTED transform contributes an evasion under D2. This is the
// real sanity gate (NOT "round-1 lexical ≈ 0": lexical contains residual-predicted
// transforms — escapes, multiline — that D2 legitimately does not fold).
{
  const leaks = attackPairs.filter((p) => p.d2Predicted === 'covered' && evadedD2(p));
  assert(
    'A2',
    'no transform pre-registered as d2Predicted="covered" evades under D2 — D2 does exactly what it claimed to cover',
    leaks.length === 0,
    leaks.length === 0 ? `covered-predicted attack pairs all folded by D2` : `LEAKS: ${leaks.map((p) => p.transformId + '/' + p.pairId).slice(0, 10).join(', ')}`,
  );
}
// A3 — worst-case ASR >= mean single-transform ASR (an OR-aggregation cannot be
// below its mean member). A violation means a computation bug.
assert(
  'A3',
  'worst-case ASR >= mean single-transform ASR (the max-over-portfolio dominates the mean)',
  worstCase.asr == null || singleTransform.meanSingleTransformASR == null ? null : worstCase.asr >= singleTransform.meanSingleTransformASR,
  `worstCase=${worstCase.asr}, mean=${singleTransform.meanSingleTransformASR}, premium=${adaptivityPremium}`,
);
// A4 — rounds are monotonic non-decreasing in ASR (cumulative class sets).
{
  let mono = true;
  const seq = [];
  for (const b of COST_BUDGETS) {
    let prev = -1;
    for (const r of ROUNDS) {
      const cell = roundGrid.find((g) => g.round === r.round && g.costBudget === b.budget);
      const v = cell.asr ?? 0;
      seq.push(`${b.budget}/r${r.round}=${v}`);
      if (v < prev - 1e-9) mono = false;
      prev = v;
    }
  }
  assert('A4', 'residual ASR is monotonic non-decreasing across cumulative rounds within each cost budget', mono, seq.join(' '));
}
// A5 — every finding in the denominator was detected in the original by the shipped engine.
assert(
  'A5',
  'every scored finding was detected in the original by the shipped engine (denominator hygiene)',
  true,
  `findings=${findings.length}; all built from detectedOrigTrue===true pairs by construction`,
);
const assertionsAllOk = assertions.every((a) => a.ok !== false);

// -------------------------------------------------------------- output -------
const result = {
  metric: 'worst-case residual ASR — attack-success (evasion) rate against the SHIPPED (D2-ON) engine under a Kerckhoffs adaptive adversary',
  generatedBy: 'sec-adaptive-asr.mjs',
  model: {
    defense: 'VibeGuard shipped engine, canonicalization (D2) ON',
    attacker: 'Kerckhoffs — knows the defense; may choose any catalog transform per finding',
    unit: 'finding = (origPath, origPayloadLine, ruleId); portfolio = the transform pairs sharing those keys',
    evadedPredicate: "outcomeTransformedTrue === 'absent' (exists-based; 'relocated' is NOT evasion; the severity gate is NOT consulted) — identical to sec-b1-er-eval.mjs",
    worstCaseAggregation: 'a finding is defeated iff SOME transform in the eligible subset evades D2 (OR over the portfolio = per-finding max-evasion)',
    rounds: 'cumulative transform CLASSES (lexical → +name-resolution → +structural); NOT composition depth — the manifest measured single transforms only, so composed outcomes are never invented',
    determinism: 'pure function of the manifest; no clock, no randomness; sorted throughout',
  },
  headline: {
    worstCaseASR: worstCase.asr,
    worstCaseDefeated: worstCase.defeated,
    findings: worstCase.total,
    worstCaseInterpretation:
      'worst-case over the MEASURED single-transform catalog (OR of each finding\'s portfolio). Compositions (transform-of-a-transform) were never measured and are NOT included, so this is a CONSERVATIVE LOWER BOUND on the true worst case a composing adversary could reach — not an upper bound. Reported this way on purpose: scoring unmeasured compositions would fabricate outcomes.',
    meanSingleTransformASR: singleTransform.meanSingleTransformASR,
    adaptivityPremium,
    adaptivityPremiumNote:
      'worst-case minus mean single-transform ASR: how much the adaptive attacker gains by choosing the right transform per finding rather than applying one at random. A small premium is a weak result and is reported as such.',
    highSeverityWorstCaseASR: highSeverityWorstCase.worstCaseASR,
  },
  provenance: {
    manifest: rel(manifestPath),
    manifestSha256: createHash('sha256').update(readFileSync(manifestPath)).digest('hex'),
    manifestEngineVersion: manifest.engineVersion ?? null,
    nodeVersion: process.version,
    attackPairs: attackPairs.length,
    findings: findings.length,
  },
  roundGrid,
  byClass: {
    note: 'residual ASR of each transform CLASS alone (each defeats a finding if any of its transforms evades D2). This is the attacker-side view of the taxonomy×D2 map that sec-b1-coverage-matrix.mjs renders defender-side.',
    ...byClass,
  },
  singleTransform,
  attribution,
  worstCaseBySeverity: bySeverity,
  worstCaseByLanguage: byLanguage,
  worstCaseByRuleFamily: byRuleFamily,
  highSeverityWorstCase,
  guards: {
    note: 'the five anti-tautology guards, so "worst-case over a catalog we designed" is auditable',
    preRegistration: 'A2 — worst-case defeats occur only in residual-PREDICTED classes; covered-predicted transforms leak nothing',
    attribution: 'attribution.byTransform + topTransformShareOfDefeats — defeats spread across classes, not one bespoke transform',
    adaptivityPremium: 'headline.adaptivityPremium — worst-case reported against the mean, not in isolation',
    costBudget: 'roundGrid split by M / M+R — a defeat that needs the expensive class is not quoted as free',
    negativeControl: 'A1 — NC2 residual ASR = 0',
  },
  assertions: { allOk: assertionsAllOk, results: assertions },
  findings: findings.map((f) => ({
    key: f.key,
    ruleId: f.ruleId,
    ruleFamily: f.ruleFamily,
    language: f.language,
    severity: f.severity,
    portfolioSize: f.portfolio.length,
    defeated: defeatedBy(f, () => true),
    evadingTransforms: f.portfolio.filter((t) => t.evaded).map((t) => t.transformId).sort(),
    firstDefeatedAtRound:
      ROUNDS.find((r) => defeatedBy(f, inClasses(r.classes)))?.round ?? null,
    portfolio: f.portfolio,
  })),
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(sortDeep(result), null, 2) + '\n');

// -------------------------------------------------------------- stdout -------
const log = (s = '') => console.log(s);
log(`\nWorst-case residual ASR — adaptive Kerckhoffs adversary vs the shipped (D2-ON) engine\n`);
log(`manifest: ${rel(manifestPath)} (engine ${manifest.engineVersion ?? '?'})   findings: ${findings.length}\n`);

log(`HEADLINE  (worst-case = OR over MEASURED single transforms; compositions unmeasured ⇒ conservative LOWER bound, not an upper bound)`);
log(`  worst-case residual ASR (any catalog transform)  ${worstCase.asr}   (${worstCase.defeated}/${worstCase.total})`);
log(`  mean single-transform ASR                        ${singleTransform.meanSingleTransformASR}`);
log(`  adaptivity premium (worst-case - mean)           ${adaptivityPremium}`);
log(`  worst-case ASR on critical/high findings         ${highSeverityWorstCase.worstCaseASR}   (${highSeverityWorstCase.defeated}/${highSeverityWorstCase.findings})\n`);

log(`round grid — residual ASR by escalation round × cost budget`);
log(`  ${pad('round', 36)}${pad('budget', 8)}${padL('ASR', 9)}   defeated/total`);
for (const g of roundGrid) {
  log(`  ${pad(g.round + '. ' + g.roundLabel, 36)}${pad(g.costBudget, 8)}${padL(g.asr ?? '-', 9)}   ${g.defeated}/${g.total}`);
}

log(`\nper class (each alone)`);
for (const cls of ['lexical', 'name-resolution', 'structural']) {
  log(`  ${pad(cls, 20)} ASR = ${padL(byClass[cls].asr ?? '-', 9)}   (${byClass[cls].defeated}/${byClass[cls].total})`);
}

log(`\nattribution — transforms driving the defeats (spread = genuine, concentrated = cherry-pick)`);
log(`  distinct evading transforms: ${attribution.distinctEvadingTransforms}   classes: ${attribution.distinctEvadingClasses.join(', ')}   top share: ${attribution.topTransformShareOfDefeats}`);
for (const a of attribution.byTransform.slice(0, 12)) {
  log(`  ${pad(a.transformId, 8)} evades ${padL(a.findingsEvaded, 3)} finding(s)  (sole evader of ${a.findingsSoleEvader})`);
}

log(`\nworst-case ASR by severity`);
for (const sev of Object.keys(bySeverity).sort()) {
  log(`  ${pad(sev, 12)} ${padL(bySeverity[sev].worstCaseASR ?? '-', 9)}   (${bySeverity[sev].defeated}/${bySeverity[sev].findings})`);
}

log(`\nassertions`);
for (const a of assertions) log(`  ${a.ok === true ? 'ok  ' : a.ok === false ? 'FAIL' : '??  '} ${a.id}  ${a.claim}`);

log(`\nwrote ${rel(outPath)}\n`);
if (!assertionsAllOk) process.exitCode = 1;

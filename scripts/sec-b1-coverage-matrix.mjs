// G2 — the D2 coverage matrix, rendered as the taxonomy × defense map the paper
// argues (design手順書 §387):字句(lexical) / 名前解決(name-resolution) / 構造(structural)
// on one axis, "does the D2 canonicalizer absorb the evasion?" on the other.
//
// WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT.
// The B1 transform ENGINE (the taxonomy, the per-transform `category`, the plugin
// registry) already exists in scripts/sec-b1-transforms.mjs, and the D2 coverage
// is already MEASURED per transform×rule in scripts/sec-b1-er-eval.mjs, which
// emits a `predictionLedger` classifying each transform as `covered` / `residual`
// / `no-evasion` against a PRE-REGISTERED `d2Predicted`. Nothing in that pipeline
// needs rewriting, and this script does not touch it: it is a PURE READER of the
// er-eval JSON artifact. It neither re-scans nor imports the transforms' apply()
// functions, so it cannot regress the byte-identical corpus reproduction that the
// engine guarantees.
//
// THE ONE THING THAT WAS MISSING is the per-CATEGORY rollup. er-eval keys its
// matrix by RULE, not by taxonomy class, so the paper's category-level ○/×/△ map
// — the "map of where the defense reaches" — could not be read off it directly.
// This script rolls the ledger up by `category` and renders exactly that map,
// carrying the pre-registration through so a reviewer can see prediction and
// measurement agree (or, honestly, where they do not).
//
// THE VERDICT ALPHABET (per non-control category):
//   ○ absorbed  — every EVASION-EXHIBITING transform in the class is `covered`
//                 (erFalse>0, erTrue=0): D2 folds all the evasions this class
//                 produces. No `residual` in the class.
//   △ mixed     — the class has BOTH `covered` and `residual` transforms: D2 folds
//                 some evasions in the class but not others. (This is the honest
//                 result for `lexical`: D2 folds single-line concatenation but not
//                 escape re-spelling or multi-line runs — it does no escape
//                 decoding and breaks runs at physical-line boundaries.)
//   × residual  — the class has `residual` transforms and NO `covered` ones: D2
//                 does not reach this class at all. (name-resolution: N holds no
//                 symbol table, so alias/dynamic-dispatch evasions survive by
//                 construction — that is the taint analyzer's job, not N's.)
//   untested    — the class exhibited NO evasion in either arm (all `no-evasion`):
//                 there is nothing for D2 to cover, so its coverage here is not a
//                 success, it is simply unmeasured. Reported as such, never as ○.
//
// `no-evasion` is kept distinct from `covered` on purpose: a transform that never
// evaded tells you nothing about D2, and folding it into "covered" would inflate
// the apparent reach of the defense.
//
// The attacker-side companion is scripts/sec-adaptive-asr.mjs (byClass): this map
// is the DEFENDER view (what D2 folds), that one is the ATTACKER view (what a
// Kerckhoffs adversary can still evade). They read the same taxonomy from opposite
// ends and should tell a consistent story — where this map says ×/△, that one
// should show residual ASR.
//
// DETERMINISM: pure function of the er-eval JSON; no clock, no randomness; deep
// key-sorted output. A missing/stale input is a hard fail, never a fabricated map.
//
// Usage (from the repo root):
//   node scripts/sec-b1-coverage-matrix.mjs
//   node scripts/sec-b1-coverage-matrix.mjs --in <er-eval.json> --out <path>
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, relative, resolve } from 'node:path';

const REPO_ROOT = process.cwd();
const DEFAULT_IN = 'security-experiment/_results/b1-er-eval.json';
const DEFAULT_OUT = 'security-experiment/_results/coverage-matrix.json';

const slash = (p) => String(p).replace(/\\/g, '/');
const rel = (p) => slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));
function fail(msg) {
  console.error(`\nsec-b1-coverage-matrix: ${msg}\n`);
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
const inPath = resolve(REPO_ROOT, argOf('--in', DEFAULT_IN));
const outPath = resolve(REPO_ROOT, argOf('--out', DEFAULT_OUT));

if (!existsSync(inPath)) {
  fail(
    `er-eval artifact not found at ${rel(inPath)}.\n` +
      `  This script is a pure reader of that artifact; it does not re-scan.\n` +
      `  Fix: node scripts/sec-b1-er-eval.mjs   (or pass --in <path>)`,
  );
}
let er;
try {
  er = JSON.parse(readFileSync(inPath, 'utf8'));
} catch (e) {
  fail(`er-eval artifact at ${rel(inPath)} is not valid JSON: ${e.message}`);
}
const ledger = er.predictionLedger;
if (!Array.isArray(ledger) || ledger.length === 0) {
  fail(`er-eval artifact at ${rel(inPath)} has no usable "predictionLedger" array — regenerate with sec-b1-er-eval.mjs`);
}

// ----------------------------------------------------------- category rollup --
const CLASS_ORDER = ['lexical', 'name-resolution', 'structural'];
const CLASS_JA = { lexical: '字句', 'name-resolution': '名前解決', structural: '構造' };

// Split controls out — they are not statements about D2's reach over attacks.
const attackEntries = ledger.filter((e) => e.negativeControl !== true && e.category !== 'negative-control');
const controlEntries = ledger.filter((e) => e.negativeControl === true || e.category === 'negative-control');

function verdictFor(counts) {
  const { covered, residual, noEvasion } = counts;
  const testable = covered + residual;
  if (testable === 0) return { symbol: 'untested', gloss: 'no evasion exhibited in either arm — nothing for D2 to cover here' };
  if (residual === 0) return { symbol: '○ absorbed', gloss: 'every evasion in this class is folded by D2 (all covered, no residual)' };
  if (covered === 0) return { symbol: '× residual', gloss: 'D2 does not reach this class — every evasion survives (residual, none covered)' };
  return { symbol: '△ mixed', gloss: 'D2 folds some evasions in this class but not others (both covered and residual present)' };
}

const byCategory = {};
for (const cls of CLASS_ORDER) {
  const es = attackEntries.filter((e) => e.category === cls).sort((a, b) => String(a.transformId).localeCompare(String(b.transformId)));
  const counts = {
    transforms: es.length,
    covered: es.filter((e) => e.observed === 'covered').length,
    residual: es.filter((e) => e.observed === 'residual').length,
    noEvasion: es.filter((e) => e.observed === 'no-evasion').length,
  };
  const v = verdictFor(counts);
  // Prediction reconciliation: does d2Predicted match observed for this class?
  const predictedResidual = es.filter((e) => e.d2Predicted === 'residual').length;
  const predictedCovered = es.filter((e) => e.d2Predicted === 'covered').length;
  const agree = es.filter((e) => e.d2PredictedAgrees === true).length;
  const disagreements = es
    .filter((e) => e.d2PredictedAgrees === false)
    .map((e) => ({ transformId: e.transformId, name: e.name, d2Predicted: e.d2Predicted, observed: e.observed, observedWhy: e.observedWhy }));
  byCategory[cls] = {
    labelJa: CLASS_JA[cls],
    verdict: v.symbol,
    verdictGloss: v.gloss,
    counts,
    // pooled evasion "reach": mean erFalse (pre-D2) vs erTrue (shipped) over the class
    meanErFalse: ratio(es.reduce((s, e) => s + (e.erFalse ?? 0), 0), es.length),
    meanErTrue: ratio(es.reduce((s, e) => s + (e.erTrue ?? 0), 0), es.length),
    prediction: {
      predictedResidual,
      predictedCovered,
      agree,
      total: es.length,
      allAgree: agree === es.length,
      disagreements,
    },
    transforms: es.map((e) => ({
      transformId: e.transformId,
      name: e.name,
      d2Predicted: e.d2Predicted,
      observed: e.observed,
      d2PredictedAgrees: e.d2PredictedAgrees,
      erFalse: e.erFalse ?? null,
      erTrue: e.erTrue ?? null,
      deltaEr: e.deltaEr ?? null,
      denominator: e.denominator ?? null,
      observedWhy: e.observedWhy ?? null,
    })),
  };
}

// ------------------------------------------------------------ cross-foot -----
// The rollup must reconcile to the ledger it came from, or it is silently dropping
// rows. covered+residual+no-evasion over all attack entries must equal their count,
// and the union of categories must be exactly the attack ledger.
const rollupTotal = Object.values(byCategory).reduce((s, c) => s + c.counts.transforms, 0);
const attackClassified = CLASS_ORDER.reduce(
  (s, cls) => s + attackEntries.filter((e) => e.category === cls).length,
  0,
);
const uncategorized = attackEntries.filter((e) => !CLASS_ORDER.includes(e.category)).map((e) => ({ transformId: e.transformId, category: e.category }));
const observedTallies = {
  covered: attackEntries.filter((e) => e.observed === 'covered').length,
  residual: attackEntries.filter((e) => e.observed === 'residual').length,
  noEvasion: attackEntries.filter((e) => e.observed === 'no-evasion').length,
  other: attackEntries.filter((e) => !['covered', 'residual', 'no-evasion'].includes(e.observed)).length,
};

// ------------------------------------------------------------ assertions -----
const assertions = [];
function assert(id, claim, ok, detail) {
  assertions.push({ id, claim, ok, detail: detail ?? null });
}
assert(
  'A1',
  'the category rollup reconciles to the attack ledger (no transform dropped or double-counted)',
  rollupTotal === attackEntries.length && uncategorized.length === 0,
  `rollupTotal=${rollupTotal}, attackEntries=${attackEntries.length}, uncategorized=${JSON.stringify(uncategorized)}`,
);
assert(
  'A2',
  'per-category covered+residual+no-evasion sums to the category size',
  Object.values(byCategory).every((c) => c.counts.covered + c.counts.residual + c.counts.noEvasion === c.counts.transforms),
  JSON.stringify(Object.fromEntries(Object.entries(byCategory).map(([k, c]) => [k, `${c.counts.covered}+${c.counts.residual}+${c.counts.noEvasion}=${c.counts.transforms}`]))),
);
assert(
  'A3',
  'every pre-registered d2Predicted agrees with the observed D2 coverage (the ledger is not a post-hoc fit)',
  attackEntries.every((e) => e.d2PredictedAgrees === true),
  attackEntries.every((e) => e.d2PredictedAgrees === true)
    ? 'all attack transforms: prediction == observation'
    : `disagreements: ${attackEntries.filter((e) => e.d2PredictedAgrees === false).map((e) => e.transformId).join(', ')}`,
);
assert(
  'A4',
  'observed classifications are drawn only from {covered, residual, no-evasion}',
  observedTallies.other === 0,
  JSON.stringify(observedTallies),
);
assert(
  'A5',
  'this reporter did not re-scan or import the transform engine — it is a pure read of the er-eval artifact',
  true,
  `input ${rel(inPath)} sha256 ${createHash('sha256').update(readFileSync(inPath)).digest('hex').slice(0, 16)}`,
);
const assertionsAllOk = assertions.every((a) => a.ok !== false);

// ---------------------------------------------------------------- controls ---
const controls = controlEntries
  .map((e) => ({ transformId: e.transformId, name: e.name, observed: e.observed, erFalse: e.erFalse ?? null, erTrue: e.erTrue ?? null }))
  .sort((a, b) => String(a.transformId).localeCompare(String(b.transformId)));

// -------------------------------------------------------------- output -------
const result = {
  metric: 'D2 coverage matrix — transform taxonomy (字句/名前解決/構造) × does the D2 canonicalizer absorb the evasion',
  generatedBy: 'sec-b1-coverage-matrix.mjs',
  role: 'DEFENDER view (what D2 folds). Pure reader of the er-eval predictionLedger; does not re-scan or touch the transform engine.',
  companion: 'ATTACKER view = scripts/sec-adaptive-asr.mjs byClass (what a Kerckhoffs adversary still evades). The two read the same taxonomy from opposite ends.',
  verdictAlphabet: {
    '○ absorbed': 'every evasion-exhibiting transform in the class is covered by D2 (no residual)',
    '△ mixed': 'the class has both covered and residual transforms — D2 folds some evasions, not others',
    '× residual': 'the class has residual transforms and none covered — D2 does not reach it',
    untested: 'no evasion exhibited in the class — nothing for D2 to cover (NOT a success)',
  },
  provenance: {
    source: rel(inPath),
    sourceSha256: createHash('sha256').update(readFileSync(inPath)).digest('hex'),
    sourceGeneratedBy: er.generatedBy ?? null,
    sourceManifestEngineVersion: er.manifestEngineVersion ?? null,
    nodeVersion: process.version,
    ledgerEntries: ledger.length,
    attackEntries: attackEntries.length,
    controlEntries: controlEntries.length,
  },
  map: {
    note: 'the paper figure: one row per taxonomy class, the ○/△/×/untested verdict, the counts behind it, and the pre-registration reconciliation',
    classes: CLASS_ORDER,
    byCategory,
  },
  crossFoot: {
    rollupTotal,
    attackClassified,
    attackEntries: attackEntries.length,
    observedTallies,
    uncategorized,
  },
  controls: {
    note: 'negative controls, reported separately — never part of the D2-reach verdict. NC1 (fix-real) removes the vuln; NC2 (noop) must not evade.',
    entries: controls,
  },
  assertions: { allOk: assertionsAllOk, results: assertions },
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(sortDeep(result), null, 2) + '\n');

// -------------------------------------------------------------- stdout -------
const log = (s = '') => console.log(s);
log(`\nD2 coverage matrix — taxonomy × defense (defender view)\n`);
log(`source: ${rel(inPath)} (${er.generatedBy ?? '?'}, engine ${er.manifestEngineVersion ?? '?'})\n`);
log(`  ${pad('class', 18)}${pad('verdict', 14)}${padL('cov', 4)}${padL('res', 4)}${padL('noEv', 5)}   ${padL('ER pre-D2', 10)}${padL('ER shipped', 11)}   prediction`);
for (const cls of CLASS_ORDER) {
  const c = byCategory[cls];
  log(
    `  ${pad(cls + ' (' + c.labelJa + ')', 18)}${pad(c.verdict, 14)}${padL(c.counts.covered, 4)}${padL(c.counts.residual, 4)}${padL(c.counts.noEvasion, 5)}   ` +
      `${padL(c.meanErFalse ?? '-', 10)}${padL(c.meanErTrue ?? '-', 11)}   ${c.prediction.allAgree ? 'all agree' : c.prediction.disagreements.length + ' disagree'}`,
  );
}
log(`\nverdict legend: ○ absorbed | △ mixed | × residual | untested (no evasion to cover)`);
log(`\nper-transform (attack transforms only)`);
for (const cls of CLASS_ORDER) {
  log(`  ${cls} (${byCategory[cls].labelJa}) — ${byCategory[cls].verdict}`);
  for (const t of byCategory[cls].transforms) {
    log(`    ${pad(t.transformId, 6)} ${pad(t.name, 24)} pred=${pad(t.d2Predicted ?? '?', 9)} obs=${pad(t.observed ?? '?', 11)} ${t.d2PredictedAgrees ? '✓' : '✗'}  ER ${t.erFalse}→${t.erTrue}`);
  }
}
log(`\ncontrols (excluded from the verdict): ${controls.map((c) => c.transformId + '=' + c.observed).join(', ')}`);
log(`\nassertions`);
for (const a of assertions) log(`  ${a.ok === true ? 'ok  ' : a.ok === false ? 'FAIL' : '??  '} ${a.id}  ${a.claim}`);
log(`\nwrote ${rel(outPath)}\n`);
if (!assertionsAllOk) process.exitCode = 1;

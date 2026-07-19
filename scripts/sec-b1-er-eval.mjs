// B1 — evasion-rate (ER) A/B evaluator (security paper, track B).
//
// Reads the corpus manifest produced by scripts/sec-b1-gen-corpus.mjs and
// aggregates it into the ER table. The manifest already carries the OBSERVED
// landing of every (finding × transform) pair in BOTH arms of the A/B, so this
// script does not re-scan the corpus to compute ER — it re-scans only for the
// rescan assertions (§ assertions), where an INDEPENDENT observation is the
// whole point.
//
//   arm `false` = new Analyzer({ canonicalize: false })  — the pre-D2 engine
//   arm `true`  = new Analyzer({ canonicalize: true  })  — the shipped engine
//
// Metric, per transform t, rule k and arm c, with INDEPENDENT denominators
// (sharing one denominator across arms is the mistake this file exists to avoid):
//
//   denom_c(t,k) = { v : detectedOrig_c(v) = true }
//   num_c(t,k)   = { v in denom_c : detectedTransformed_c(v) = false }
//   ER_c(t,k)    = |num_c| / |denom_c|
//   dER          = ER_false - ER_true          (how much of the evasion D2 covers)
//
// A finding the ORIGINAL file never produced in arm c is excluded from arm c
// entirely; it cannot be "evaded" if it was never there. Since D2 is a union
// (`D'(x) = D(x) u D(N(x))`, analyzer.ts:96), denom_true is structurally a
// superset of denom_false, and dividing by different-sized denominators makes
// dER partly an artefact of the denominators. So the HEADLINE is ER on the
// COMMON BASIS `denom_false n denom_true` — the same findings in both arms — and
// the arm-specific-denominator ER is reported alongside, never instead of it.
//
// TWO OBSERVATION KINDS are carried all the way through:
//   * `exists`  — a finding existed at all, thresholds ignored  (HEADLINE)
//   * `gate`    — the severity/confidence threshold was passed  (secondary)
// The headline is `exists`, not `gate`, because SCOPE §2.3 defines `detect(k,v)`
// as "a finding satisfying the pairing rule EXISTS ⇔ 1" — the severity threshold
// is NOT part of that predicate. (The ER bracket "= the severity gate is also
// cleared" is the entailment "finding gone ⇒ the gate is trivially cleared", not
// an extra condition on `detect`.) Reporting `gate` as the headline dropped every
// medium-only multi-language row (go/ruby/php/csharp under --fail-on high never
// pass the gate) out of the denominator; on `exists` they land on the common
// basis. `gate` is kept as the secondary observation so the actionable-set view
// is still on the page.
//
// NEGATIVE CONTROLS (NC1 fix-real, NC2 noop-reformat) are excluded from the
// headline. NC1 really removes the vulnerability, so counting its disappearance
// as "evasion" inflates ER — the schema's `isNegativeControl` (payloadExecutable
// === false) catches it. NC2 leaves the program unchanged and every finding
// survives (ER=0); it is `payloadExecutable:'unverified'`, so isNegativeControl
// does NOT catch it, but pooling its 71 all-surviving pairs into the headline
// denominator is the average-dilution SCOPE §2.3「平均で薄めない」forbids, so it
// is excluded via its `category:'negative-control'` too. Both are reported in
// their own `negativeControls` health block, and both still appear per-transform
// in `byTransform`, so nothing is hidden — only kept out of the pooled headline.
//
// Determinism: no Date.now(), no Math.random(), no wall clock. Every readdir is
// sorted, every emitted path is repo-root relative with forward slashes.
//
// Run from the repo root (dist must be built — this imports @vibeguard/*):
//   node scripts/sec-b1-er-eval.mjs
//   node scripts/sec-b1-er-eval.mjs --manifest <path> --out <path> --no-rescan
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { Analyzer, canonicalize } from '@vibeguard/analyzer-core';
// The pair-record shape lives in ONE place, shared with the generator. Reads go
// through the fail-closed accessors so a missing/renamed field THROWS here rather
// than degrading to a falsy default — the silent dead-read this module family was
// built to make impossible (see sec-b1-schema.mjs header).
import {
  F,
  req,
  reqBool,
  landing,
  relocatedInArm,
  isNegativeControl,
  census,
  assertVaries,
  validatePairs,
} from './sec-b1-schema.mjs';

// ---------------------------------------------------------------- constants --
const REPO_ROOT = process.cwd();
const DEFAULT_MANIFEST = 'security-experiment/_results/b1-corpus-manifest.json';
const DEFAULT_OUT = 'security-experiment/_results/b1-er-eval.json';
// Re-scanned for the rescan assertions. samples/vulnerable is the population the
// corpus was derived from; samples/safe is the false-positive side constraint.
const ASSERT_DIRS = ['samples/vulnerable', 'samples/safe'];
const SAFE_DIR = 'samples/safe';
const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };
const STDOUT_LIST_LIMIT = 10; // stdout only; the JSON always carries every row

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
const slash = (p) => String(p).replace(/\\/g, '/');
const rel = (p) => slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));
const languageOf = (p) => LANG_BY_EXT[extname(String(p)).toLowerCase()];

function fail(msg) {
  console.error(`\nsec-b1-er-eval: ${msg}\n`);
  process.exit(1);
}
function ratio(n, d) {
  return d === 0 ? null : Number((n / d).toFixed(6));
}
/** Difference of two possibly-null ratios; null when either side has no denominator. */
function delta(a, b) {
  return a == null || b == null ? null : Number((a - b).toFixed(6));
}
function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

// erfc via Abramowitz & Stegun 7.1.26 (|error| <= 1.5e-7). Used ONLY to turn a
// McNemar χ² into a p-value; no stats dependency is pulled in for one number.
function erfc(x) {
  const z = Math.abs(x);
  const t = 1 / (1 + 0.3275911 * z);
  const y =
    1 -
    ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) *
      t *
      Math.exp(-z * z);
  const erf = x >= 0 ? y : -y;
  return 1 - erf;
}
/**
 * Upper-tail p-value of a chi-square statistic with 1 degree of freedom.
 * For df=1 the survival function is exactly `erfc(sqrt(x/2))` — a chi-square(1)
 * variate is the square of a standard normal, so P(X > x) = 2·P(Z > sqrt(x)) =
 * erfc(sqrt(x/2)). Approximation is in erfc only; the reduction is exact.
 */
function chiSquarePValueDf1(chi2) {
  if (!Number.isFinite(chi2) || chi2 <= 0) return 1;
  return Number(erfc(Math.sqrt(chi2 / 2)).toFixed(8));
}

/**
 * Exact binomial (sign) test for McNemar — the small-sample-safe alternative to
 * the chi-square approximation. Under H0 the discordant split is Binomial(b+c,
 * 0.5); two-sided p = min(1, 2·P(X ≥ max(b,c))). Preferred when discordant pairs
 * are few or c=0, where the chi-square is boundary (here b=12/c=0: exact
 * 2·0.5^12 ≈ 0.000488 vs the χ² 0.000532 — same conclusion, tighter for review).
 * Exact rational arithmetic; b+c is small so the binomial coefficients are safe.
 */
function mcnemarExactP(b, c) {
  const n = b + c;
  if (n === 0) return 1;
  const k = Math.max(b, c);
  let coeff = 1; // C(n, n) = 1, walk downward via C(n,i-1) = C(n,i)·i/(n-i+1)
  let tail = 0;
  for (let i = n; i >= k; i--) {
    tail += coeff;
    coeff = (coeff * i) / (n - i + 1);
  }
  return Number(Math.min(1, 2 * tail * Math.pow(0.5, n)).toFixed(8));
}

// ------------------------------------------------------------------- argv ----
const argv = process.argv.slice(2);
function argOf(name, dflt) {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] != null ? argv[i + 1] : dflt;
}
const manifestPath = resolve(REPO_ROOT, argOf('--manifest', DEFAULT_MANIFEST));
const outPath = resolve(REPO_ROOT, argOf('--out', DEFAULT_OUT));
const rescan = !argv.includes('--no-rescan');

// --------------------------------------------------------------- manifest ----
if (!existsSync(manifestPath)) {
  fail(
    `corpus manifest not found at ${rel(manifestPath)}.\n` +
      `  The evaluator has nothing to evaluate until the generator has run.\n` +
      `  Fix: node scripts/sec-b1-gen-corpus.mjs   (or pass --manifest <path>)`,
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

// Fail-closed structural gate over the WHOLE manifest before any scoring. A pair
// missing a required field or carrying an out-of-range landing is a corrupt input,
// not a data point to score around, so this aborts rather than degrading — the
// same fail-closed stance the schema is built on.
try {
  validatePairs(manifest.pairs);
} catch (err) {
  fail(`corpus manifest at ${rel(manifestPath)} failed schema validation: ${err.message}`);
}

// Pre-registered transform metadata, keyed by id. The manifest stores it as the
// `transforms` array (there is no `transformMeta` map); `d2Predicted` here is the
// AUTHORITATIVE pre-registration the prediction ledger scores against, so it is
// read from this table rather than from the per-pair copy the generator stamped.
const transformsById = new Map((manifest.transforms ?? []).map((t) => [t.id, t]));

// ----------------------------------------------------------------- scoring ---
// Everything the ER table is derived from is a PURE function of the pairs array,
// factored out so the mutation test (§ mutation) can re-run the exact scoring
// path on a one-field-mutated copy and prove the evaluator actually READS the
// field. Nothing in here touches the filesystem or the clock.
function scorePairs(pairs) {
  const rows = [];
  const unusablePairs = [];

  for (const p of [...pairs].sort((a, b) => String(a.pairId).localeCompare(String(b.pairId)))) {
    try {
      // Three-valued landing per arm, authoritative over the booleans, and
      // per-arm relocation. This is the欠陥1 fix: the old evaluator OR-ed the
      // arm-agnostic `needsManualReview` flag into BOTH arms, so a pair relocated
      // in only one arm was dropped from the other arm too (14 such pairs in the
      // shipped corpus). `relocatedInArm` reads only THAT arm's landing.
      const vFalse = landing(p, 'false');
      const vTrue = landing(p, 'true');
      const relocated = {
        false: relocatedInArm(p, 'false'),
        true: relocatedInArm(p, 'true'),
      };
      const exists = {
        origFalse: reqBool(p, F.detectedOrigFalse),
        origTrue: reqBool(p, F.detectedOrigTrue),
        transformedFalse: reqBool(p, F.detectedTransformedFalse),
        transformedTrue: reqBool(p, F.detectedTransformedTrue),
      };
      const gate = {
        origFalse: reqBool(p, F.gatePassedOrigFalse),
        origTrue: reqBool(p, F.gatePassedOrigTrue),
        transformedFalse: reqBool(p, F.gatePassedTransformedFalse),
        transformedTrue: reqBool(p, F.gatePassedTransformedTrue),
      };
      const payloadExecutable = req(p, F.payloadExecutable);
      const meta = transformsById.get(req(p, F.transformId)) ?? {};
      rows.push({
        pairId: p.pairId ?? null,
        transformId: req(p, F.transformId),
        // Direct reads of the REAL field names (`transformName`, not the dead
        // `p.transform`; `origPayloadLine`, not `p.payloadLine`; `p.occ`, not
        // `p.occurrence`). Report-quality only, no ER impact.
        transformName: p[F.transformName] ?? meta.name ?? p.transformId,
        category: p[F.category] ?? meta.category ?? null,
        d2Predicted: meta.d2Predicted ?? p[F.d2Predicted] ?? null,
        adversarialCost: p[F.adversarialCost] ?? meta.adversarialCost ?? null,
        ruleId: req(p, F.ruleId),
        severity: p.severity ?? null,
        language: p.language ?? null,
        origPath: p.origPath ?? null,
        transformedPath: p.transformedPath ?? null,
        origPayloadLine: p.origPayloadLine ?? null,
        occ: p.occ ?? null,
        // 'executed' | 'unverified' | false. NEVER collapsed to a boolean: the
        // hard-ER win condition and the negative-control filter both read it.
        payloadExecutable,
        // Whether the generator flagged this pair for manual review, and WHY it
        // did beyond relocation. On the shipped corpus every needsManualReview
        // pair is relocated in >=1 arm, so `mappingAmbiguous` is purely a data-
        // quality note here, not an exclusion — exclusion is per-arm relocation.
        needsManualReviewFlag: p[F.needsManualReview] === true,
        mappingAmbiguous: p.payloadLineCandidates > 1 || p.occAmbiguousAcrossArms === true,
        // isNegativeControl = payloadExecutable === false (NC1). The category
        // check additionally pulls NC2 (noop-reformat, payloadExecutable
        // 'unverified') out of the headline — see the header note on why a
        // negative control must not dilute the pooled ER.
        negativeControl: isNegativeControl(p) || p[F.category] === 'negative-control',
        exists,
        gate,
        landings: { false: vFalse, true: vTrue },
        relocated,
      });
    } catch (err) {
      // A pair whose observations cannot be read is NOT dropped quietly — it goes
      // here with the reason, and the count sits next to the ER.
      unusablePairs.push({ pairId: p.pairId ?? null, reason: String(err && err.message ? err.message : err) });
    }
  }

  // Rows that feed the pooled headline: attack transforms only. Negative controls
  // are kept out of the pool but reported in their own block below.
  const scoredRows = rows.filter((r) => !r.negativeControl);

  // D2 is a union, so a finding present in arm false must also be present in arm
  // true. A pair that violates this is not an ER data point, it is a bug report:
  // the soundness claim `D'(x) = D(x) u D(N(x))` would be false. detectedOrigTrue
  // is an OBSERVATION (the generator resolves it through the true-arm scan, see
  // assertVaries below), so this detector is live. It stays empty on this corpus
  // because the population has no union break to find — every original finding is
  // present in both arms — which is what monotonicity independently confirms.
  const structuralViolations = rows
    .filter((r) => r.exists.origFalse && !r.exists.origTrue)
    .map((r) => ({
      pairId: r.pairId,
      transformId: r.transformId,
      transformName: r.transformName,
      ruleId: r.ruleId,
      origPath: r.origPath,
      // Direct reads of origPayloadLine / occ: a union break needs the exact line
      // and occurrence ordinal to reproduce, so they belong on the violation.
      origPayloadLine: r.origPayloadLine,
      occ: r.occ,
      detail: 'detectedOrigFalse=true but detectedOrigTrue=false — D2 lost a finding the pre-D2 engine had',
    }));

  // ------------------------------------------------------------- ER compute --
  /**
   * ER for one arm over one row set. `kind` = 'exists' (headline) or 'gate'.
   * Relocated pairs leave BOTH numerator and denominator and are reported as
   * `relocatedExcluded` together with the bounds ER would take if every one of
   * them were scored as evaded (`erUpperBound`) or detected (`erLowerBound`) — how
   * a reader sees the size of the ambiguity instead of having to trust the exclusion.
   */
  function erFor(rowSet, kind, arm) {
    const oKey = arm === 'false' ? 'origFalse' : 'origTrue';
    const tKey = arm === 'false' ? 'transformedFalse' : 'transformedTrue';
    let denominator = 0;
    let numerator = 0;
    let relocatedExcluded = 0;
    const evaded = [];
    for (const r of rowSet) {
      const o = r[kind];
      if (o[oKey] !== true) continue; // never detected in the original: out of scope for this arm
      if (r.relocated[arm]) {
        relocatedExcluded += 1;
        continue;
      }
      denominator += 1;
      if (o[tKey] === false) {
        numerator += 1;
        evaded.push(r.pairId);
      }
    }
    const ambiguous = denominator + relocatedExcluded;
    return {
      denominator,
      numerator,
      er: ratio(numerator, denominator),
      relocatedExcluded,
      erLowerBound: ratio(numerator, ambiguous),
      erUpperBound: ratio(numerator + relocatedExcluded, ambiguous),
      evadedPairIds: evaded.sort(),
    };
  }

  /** Rows the ORIGINAL produced a finding for in BOTH arms — the common basis. */
  const onCommonBasis = (rowSet, kind) =>
    rowSet.filter((r) => r[kind].origFalse === true && r[kind].origTrue === true);

  /**
   * Common basis AND relocated in NEITHER arm — the matched-pair basis. Here both
   * arms share one denominator (no arm relocates a pair the other keeps), so dER
   * is a genuine matched-pair difference and lines up exactly with what McNemar
   * tests. On `common`, by contrast, relocation is excluded per arm, so a pair
   * relocated in only one arm inflates that arm's denominator relative to the
   * other and dER carries a slice of that asymmetry (here 0.0661 vs the paired
   * 0.0541 — the 0.012 gap is the 14 false-only-relocated pairs).
   */
  const onPairedBasis = (rowSet, kind) =>
    onCommonBasis(rowSet, kind).filter((r) => !r.relocated.false && !r.relocated.true);

  /** Both arms plus dER, for one basis and one observation kind. */
  function armPair(rowSet, kind) {
    const f = erFor(rowSet, kind, 'false');
    const t = erFor(rowSet, kind, 'true');
    return { false: f, true: t, deltaEr: delta(f.er, t.er) };
  }

  /** The full block reported for any grouping: primary (paired) + common + arm-specific. */
  function block(rowSet) {
    return {
      pairs: rowSet.length,
      // PRIMARY basis: detected in both arms AND relocated in neither, so both arms
      // share ONE denominator and dER is a matched-pair effect that lines up with
      // McNemar. This is the number to quote. `exists` is the HEADLINE observation,
      // `gate` the secondary one.
      paired: {
        basis: 'common basis AND relocated in neither arm — matched pairs (one shared denominator; McNemar operates here)',
        exists: armPair(onPairedBasis(rowSet, 'exists'), 'exists'),
        gate: armPair(onPairedBasis(rowSet, 'gate'), 'gate'),
      },
      // SECONDARY: same findings in both arms, but relocation excluded per arm, so
      // the two denominators can differ; dER then partly reflects that asymmetry.
      common: {
        basis: 'denom_false n denom_true (finding present in the original under BOTH arms); relocation excluded per arm',
        exists: armPair(onCommonBasis(rowSet, 'exists'), 'exists'),
        gate: armPair(onCommonBasis(rowSet, 'gate'), 'gate'),
      },
      // TERTIARY: each arm keeps its own denominator, which is what the raw
      // contract formula says; reported so the denominators themselves are visible.
      armSpecific: {
        basis: 'denom_c computed independently per arm (denom_true is a superset of denom_false)',
        exists: armPair(rowSet, 'exists'),
        gate: armPair(rowSet, 'gate'),
      },
    };
  }

  /**
   * hard-ER: the win condition is finding disappearance AND the vulnerability
   * surviving in the transformed file, so the numerator additionally requires
   * `payloadExecutable !== false`. Computed on the HEADLINE observation (`exists`,
   * common basis), consistent with the ER headline, and partitioned by
   * executability class so `executed` and `unverified` never pool into one number
   * that reads as if everything had been run.
   */
  function hardErFor(rowSet, arm, kind = 'exists') {
    const oKey = arm === 'false' ? 'origFalse' : 'origTrue';
    const tKey = arm === 'false' ? 'transformedFalse' : 'transformedTrue';
    const classes = {
      executed: { denominator: 0, numerator: 0, er: null },
      unverified: { denominator: 0, numerator: 0, er: null },
      notExecutable: { denominator: 0, numerator: 0, er: null },
    };
    let denominator = 0;
    let numeratorTotal = 0;
    for (const r of onCommonBasis(rowSet, kind)) {
      if (r[kind][oKey] !== true || r.relocated[arm]) continue;
      const cls =
        r.payloadExecutable === false
          ? 'notExecutable'
          : r.payloadExecutable === 'executed'
            ? 'executed'
            : 'unverified';
      denominator += 1;
      classes[cls].denominator += 1;
      if (r[kind][tKey] === false) {
        classes[cls].numerator += 1;
        if (cls !== 'notExecutable') numeratorTotal += 1;
      }
    }
    for (const c of Object.values(classes)) c.er = ratio(c.numerator, c.denominator);
    return {
      denominator,
      numeratorTotal,
      hardEr: ratio(numeratorTotal, denominator),
      byExecutability: classes,
    };
  }
  function hardErPair(rowSet) {
    const f = hardErFor(rowSet, 'false');
    const t = hardErFor(rowSet, 'true');
    return { false: f, true: t, deltaHardEr: delta(f.hardEr, t.hardEr) };
  }

  // -------------------------------------------------------------- groupings --
  function groupBy(rowSet, key) {
    const m = new Map();
    for (const r of rowSet) {
      const k = String(r[key] ?? 'unknown');
      if (!m.has(k)) m.set(k, []);
      m.get(k).push(r);
    }
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }

  // Headline is over the SCORED rows (negative controls excluded from the pool).
  const overall = { ...block(scoredRows), hardEr: hardErPair(scoredRows) };

  // byTransform keeps EVERY transform, including the negative controls, so their
  // numbers stay auditable per-transform even though the pooled headline drops them.
  const byTransform = {};
  for (const [tid, rs] of groupBy(rows, 'transformId')) {
    byTransform[tid] = {
      name: rs[0].transformName,
      category: rs[0].category,
      negativeControl: rs[0].negativeControl,
      d2Predicted: rs[0].d2Predicted,
      adversarialCost: rs[0].adversarialCost,
      payloadExecutable: [...new Set(rs.map((r) => String(r.payloadExecutable)))].sort(),
      ...block(rs),
      hardEr: hardErPair(rs),
    };
  }

  const byRule = {};
  for (const [ruleId, rs] of groupBy(scoredRows, 'ruleId')) {
    byRule[ruleId] = { severity: rs[0].severity, ...block(rs) };
  }

  // transform x rule heat-map on the headline basis (paired / exists), over the
  // scored rows. Emitted as a flat cell list plus its axes so it can be pivoted
  // without re-deriving keys. gate ER is carried alongside for the same cell.
  const matrixTransforms = [...new Set(scoredRows.map((r) => String(r.transformId)))].sort();
  const matrixRules = Object.keys(byRule).sort();
  const matrixCells = [];
  for (const tid of matrixTransforms) {
    for (const ruleId of matrixRules) {
      const rs = scoredRows.filter((r) => String(r.transformId) === tid && String(r.ruleId) === ruleId);
      if (rs.length === 0) continue; // absent cell, not a zero: never generated
      const basis = onPairedBasis(rs, 'exists');
      const f = erFor(basis, 'exists', 'false');
      const t = erFor(basis, 'exists', 'true');
      const gBasis = onPairedBasis(rs, 'gate');
      const gf = erFor(gBasis, 'gate', 'false');
      const gt = erFor(gBasis, 'gate', 'true');
      matrixCells.push({
        transformId: tid,
        ruleId,
        denominator: f.denominator,
        denominatorTrue: t.denominator,
        erFalse: f.er,
        erTrue: t.er,
        deltaEr: delta(f.er, t.er),
        erFalseGate: gf.er,
        erTrueGate: gt.er,
      });
    }
  }

  // --------------------------------------------- prediction vs measured ------
  // `d2Predicted` is PRE-REGISTERED in sec-b1-transforms.mjs and must not be
  // rewritten after the fact. Classified on the HEADLINE observation (exists), so
  // the medium-only multi-language transforms are testable instead of falling out
  // of a gate denominator.
  function classifyObserved(erFalse, erTrue) {
    if (erFalse == null || erTrue == null) return { observed: null, why: 'empty denominator' };
    if (erFalse === 0 && erTrue === 0) {
      return { observed: 'no-evasion', why: 'ER=0 in both arms — the transform never evaded, so D2 coverage is untestable here' };
    }
    if (erTrue === 0) return { observed: 'covered', why: 'ER_true=0 with ER_false>0 — D2 absorbs the transform' };
    return { observed: 'residual', why: 'ER_true>0 — evasion survives D2' };
  }

  const predictionLedger = [];
  const predictionMismatches = [];
  for (const tid of Object.keys(byTransform).sort()) {
    const t = byTransform[tid];
    const g = t.paired.exists;
    const { observed, why } = classifyObserved(g.false.er, g.true.er);
    const negativeControl = t.negativeControl;
    // Integrity: the per-pair d2Predicted the generator stamped must equal the
    // pre-registered value in manifest.transforms. A divergence would mean the
    // ledger is scoring against a rewritten prediction.
    const preregistered = transformsById.get(tid)?.d2Predicted ?? null;
    const entry = {
      transformId: tid,
      name: t.name,
      category: t.category,
      negativeControl,
      d2Predicted: preregistered ?? t.d2Predicted,
      d2PredictedAgrees: preregistered == null || preregistered === t.d2Predicted,
      observed,
      observedWhy: why,
      erFalse: g.false.er,
      erTrue: g.true.er,
      deltaEr: g.deltaEr,
      denominator: g.false.denominator,
      matches: observed != null && observed === (preregistered ?? t.d2Predicted),
    };
    predictionLedger.push(entry);
    // Negative controls are not predictions about D2 coverage — NC1 really fixes
    // the bug and NC2 changes nothing, so their outcome is fixed by construction.
    // They stay in the ledger but cannot be a prediction mismatch, where they
    // would be noise burying a real one.
    if (negativeControl) {
      // no mismatch row; the negativeControls health block covers them
    } else if (observed == null) {
      predictionMismatches.push({ ...entry, kind: 'untested', detail: 'no pair had a usable denominator' });
    } else if (observed === 'no-evasion') {
      predictionMismatches.push({
        ...entry,
        kind: 'unfalsifiable',
        detail: `predicted "${entry.d2Predicted}" but the transform evaded nothing in either arm`,
      });
    } else if (!entry.matches) {
      predictionMismatches.push({
        ...entry,
        kind: 'contradicted',
        detail: `predicted "${entry.d2Predicted}", measured "${observed}"`,
      });
    }
  }

  // --------------------------------------------------- negative controls -----
  // Health check, reported separately from the headline (SCOPE §2.3: controls are
  // not pooled with attacks). Expected: NC1 removes the finding (ER high), NC2
  // leaves it (ER=0). Values are OBSERVED — where the fixture makes fix-real
  // relocate the finding rather than delete it, that shows up in the landing
  // breakdown instead of being forced to the expected number.
  function landingBreakdown(rowSet, arm) {
    const b = { detected: 0, absent: 0, relocated: 0 };
    for (const r of rowSet) b[r.landings[arm]] += 1;
    return b;
  }
  function negControlHealth(rowSet) {
    return {
      pairs: rowSet.length,
      exists: armPair(rowSet, 'exists'),
      gate: armPair(rowSet, 'gate'),
      landingFalseArm: landingBreakdown(rowSet, 'false'),
      landingTrueArm: landingBreakdown(rowSet, 'true'),
    };
  }
  const nc1Rows = rows.filter((r) => r.transformId === 'NC1' || r.payloadExecutable === false);
  const nc2Rows = rows.filter((r) => r.transformId === 'NC2' || r.transformName === 'noop-reformat');
  const nc1 = nc1Rows.length ? negControlHealth(nc1Rows) : null;
  const nc2 = nc2Rows.length ? negControlHealth(nc2Rows) : null;
  const negativeControls = {
    note:
      'NC1 (fix-real) really removes the vulnerability — expected ER high (the finding disappears). ' +
      'NC2 (noop-reformat) changes nothing — expected ER=0 in both arms; a non-zero value means the ' +
      'harness fabricates evasions. Both are excluded from the headline. Values are observed, not asserted.',
    NC1: nc1 && {
      ...nc1,
      expected: 'ER high (fix removes the finding)',
      // Soft directional check: the fix demonstrably removes SOME findings. On the
      // shipped fixtures fix-real also relocates or leaves a residual same-rule
      // match, so ER lands below 1 — see landingFalseArm/landingTrueArm.
      ok: nc1.exists.false.er == null ? null : nc1.exists.false.er > 0,
      okNote:
        nc1.exists.false.er == null
          ? 'no NC1 pair had a usable denominator (all relocated) — unmeasured, not passed'
          : 'directional: fix-real removes at least some findings; residual detections/relocations are in the landing breakdown',
    },
    NC2: nc2 && {
      ...nc2,
      expected: 'ER=0 in both arms',
      // Strong check: a noop must not conceal anything. Numerator 0 in both arms.
      ok: nc2.exists.false.numerator === 0 && nc2.exists.true.numerator === 0,
      okNote:
        nc2.exists.false.numerator === 0 && nc2.exists.true.numerator === 0
          ? null
          : 'NC2 shows evasion — the harness is manufacturing a concealment where the program is unchanged',
    },
    NC2Present: nc2Rows.length > 0,
  };

  // -------------------------------------------------------- McNemar test -----
  // Paired test on the COMMON, non-relocated, scored rows: is the false-arm vs
  // true-arm evasion split asymmetric? Each qualifying pair is one subject seen
  // under both arms; discordant cells are b (evaded in false, detected in true —
  // D2 recovered the finding) and c (detected in false, gone in true — D2 LOST a
  // finding, i.e. a monotonicity violation). χ² = (b-c)²/(b+c), df=1, no continuity
  // correction (per contract). Lets the paper say D2's reduction is "significant"
  // rather than asserting it from the point estimate.
  function mcnemar(kind) {
    const oKey = 'orig';
    const population = onCommonBasis(scoredRows, kind).filter(
      (r) => !r.relocated.false && !r.relocated.true,
    );
    let a = 0;
    let b = 0;
    let c = 0;
    let d = 0;
    const bIds = [];
    const cIds = [];
    for (const r of population) {
      // Guard the pairing: a subject must be in the denominator of BOTH arms.
      if (r[kind][`${oKey}False`] !== true || r[kind][`${oKey}True`] !== true) continue;
      const evF = r[kind].transformedFalse === false;
      const evT = r[kind].transformedTrue === false;
      if (evF && evT) a += 1;
      else if (evF && !evT) {
        b += 1;
        bIds.push(r.pairId);
      } else if (!evF && evT) {
        c += 1;
        cIds.push(r.pairId);
      } else d += 1;
    }
    const discordant = b + c;
    const chiSquare = discordant === 0 ? 0 : Number((((b - c) * (b - c)) / discordant).toFixed(6));
    return {
      basis: `common ${kind} basis, scored rows, not relocated in either arm`,
      n: a + b + c + d,
      a_evadedBothArms: a,
      b_evadedFalseDetectedTrue: b,
      c_detectedFalseEvadedTrue: c,
      d_evadedNeither: d,
      discordant,
      chiSquare,
      df: 1,
      formula: 'chi2 = (b-c)^2 / (b+c); p = erfc(sqrt(chi2/2)) [df=1]',
      continuityCorrection: false,
      pValue: chiSquarePValueDf1(chiSquare),
      // Exact binomial p — small-sample-safe, reported alongside so a reviewer
      // does not have to trust the chi-square approximation at c=0.
      pValueExact: mcnemarExactP(b, c),
      // c > 0 means D2 dropped a finding the pre-D2 engine had — the same event
      // structuralViolations catches, surfaced here so the two agree.
      evadedFalseDetectedTruePairIds: bIds.sort(),
      detectedFalseEvadedTruePairIds: cIds.sort(),
    };
  }
  const mcnemarTest = { exists: mcnemar('exists'), gate: mcnemar('gate') };

  // ----------------------------------------------------- census cross-check --
  // The schema's conservation law (every pair in EXACTLY one bucket, buckets sum
  // to the total) run over ALL pairs for both arms and both kinds, cross-checked
  // against an independent tally computed from THIS script's row objects. If the
  // two ever disagree, the way erFor buckets a pair has drifted from the schema.
  function myCensus(arm, kind) {
    const b = { notInDenominator: 0, evaded: 0, survived: 0, relocated: 0 };
    const oKey = arm === 'false' ? 'origFalse' : 'origTrue';
    const tKey = arm === 'false' ? 'transformedFalse' : 'transformedTrue';
    for (const r of rows) {
      if (r.relocated[arm]) { b.relocated += 1; continue; }
      if (r[kind][oKey] !== true) { b.notInDenominator += 1; continue; }
      if (r[kind][tKey] === false) b.evaded += 1;
      else b.survived += 1;
    }
    return b;
  }
  const censusCrossCheck = [];
  for (const arm of ['false', 'true']) {
    for (const kind of ['exists', 'gate']) {
      const schemaBuckets = census(pairs, arm, kind);
      const mine = myCensus(arm, kind);
      const agrees = JSON.stringify(schemaBuckets) === JSON.stringify(mine);
      censusCrossCheck.push({ arm, kind, schema: schemaBuckets, evaluator: mine, agrees });
    }
  }

  // assertVaries on the four detection observations. detectedOrigTrue is an
  // OBSERVATION (resolved through the true-arm scan), constant `true` here only
  // because the population has no union break; recorded so a reader sees WHY
  // structuralViolations is empty on this manifest.
  const fieldVariance = [
    assertVaries(pairs, F.detectedOrigFalse),
    assertVaries(pairs, F.detectedOrigTrue),
    assertVaries(pairs, F.detectedTransformedFalse),
    assertVaries(pairs, F.detectedTransformedTrue),
  ].map((v) => ({
    ...v,
    note:
      v.field === F.detectedOrigTrue && v.constant
        ? 'constant true: an OBSERVATION (targets come from the true arm and every one is also detected there), not a hardcode. structuralViolations and McNemar cell c stay empty because the population has no union break — confirmed independently by the monotonicity assertion.'
        : v.field === F.detectedOrigFalse && v.constant
          ? 'constant true on this corpus: every finding was also present pre-D2. Legitimate here; not a dead read.'
          : null,
  }));

  return {
    rows,
    scoredRows,
    unusablePairs,
    structuralViolations,
    overall,
    byTransform,
    byRule,
    matrix: { basis: 'common / exists (headline); gate carried per cell', transforms: matrixTransforms, rules: matrixRules, cells: matrixCells },
    predictionLedger,
    predictionMismatches,
    negativeControls,
    mcnemarTest,
    censusCrossCheck,
    fieldVariance,
  };
}

const scored = scorePairs(manifest.pairs);
const {
  rows,
  scoredRows,
  unusablePairs,
  structuralViolations,
  overall,
  byTransform,
  byRule,
  matrix,
  predictionLedger,
  predictionMismatches,
  negativeControls,
  mcnemarTest,
  censusCrossCheck,
  fieldVariance,
} = scored;
const matrixTransforms = matrix.transforms;

// ------------------------------------------------------------- mutation test --
// Proof that the evaluator READS the fields it claims to. For each load-bearing
// field, mutate ONE pair and re-run the full scoring path: if the headline
// signature does not move, that field is a DEAD READ and the "measurement" was
// never a function of the manifest. A deliberate mutation is chosen per field
// (rather than sweeping every pair) so the test is O(1) rescores and deterministic.
function signatureOf(s) {
  const o = s.overall;
  return {
    erFalseExists: o.paired.exists.false.er,
    erTrueExists: o.paired.exists.true.er,
    erFalseGate: o.paired.gate.false.er,
    erTrueGate: o.paired.gate.true.er,
    hardErFalse: o.hardEr.false.hardEr,
    hardErTrue: o.hardEr.true.hardEr,
    scoredPairs: s.scoredRows.length,
  };
}
const baseSig = signatureOf(scored);

/** Build a pairs array identical to the manifest except one field on one pair. */
function withMutation(pairId, field, value) {
  return manifest.pairs.map((p) => (p.pairId === pairId ? { ...p, [field]: value } : p));
}
/** First row (sorted) matching `pred`, from the real scoring. */
function pickRow(pred) {
  return scoredRows.find(pred) ?? rows.find(pred) ?? null;
}

const mutationSpecs = [
  {
    field: F.detectedTransformedFalse,
    // A pair currently SURVIVING in the false arm (detected), flipped to gone.
    // That moves it into the false-arm numerator, so erFalseExists must change.
    pick: () => pickRow((r) => !r.negativeControl && !r.relocated.false && r.exists.transformedFalse === true && r.exists.origFalse === true),
    value: false,
    fallback: {
      pick: () => pickRow((r) => !r.negativeControl && !r.relocated.false && r.exists.transformedFalse === false && r.exists.origFalse === true),
      value: true,
    },
  },
  {
    field: F.outcomeTransformedFalse,
    // A pair currently RELOCATED in the false arm, re-landed as absent. That pulls
    // it back into the denominator AND the numerator, so the ER must change —
    // proving the landing (not just the boolean) is read.
    pick: () => pickRow((r) => !r.negativeControl && r.relocated.false),
    value: 'absent',
    fallback: {
      pick: () => pickRow((r) => !r.negativeControl && !r.relocated.false && r.exists.origFalse === true),
      value: 'relocated',
    },
  },
  {
    field: F.payloadExecutable,
    // A scored pair marked payloadExecutable:false becomes a negative control and
    // leaves the headline pool, so scoredPairs (and the ER) must change — proving
    // payloadExecutable gates the headline via isNegativeControl.
    pick: () => pickRow((r) => !r.negativeControl),
    value: false,
    fallback: {
      pick: () => pickRow((r) => r.negativeControl && r.payloadExecutable === false),
      value: 'executed',
    },
  },
];

const mutationResults = [];
for (const spec of mutationSpecs) {
  let target = spec.pick();
  let value = spec.value;
  let usedFallback = false;
  if (!target && spec.fallback) {
    target = spec.fallback.pick();
    value = spec.fallback.value;
    usedFallback = true;
  }
  if (!target) {
    mutationResults.push({
      field: spec.field,
      tested: false,
      ok: null,
      detail: 'no pair available to construct a mutation for this field on this manifest — unmeasured, not passed',
    });
    continue;
  }
  const origValue = manifest.pairs.find((p) => p.pairId === target.pairId)?.[spec.field];
  const mutatedSig = signatureOf(scorePairs(withMutation(target.pairId, spec.field, value)));
  const changed = JSON.stringify(mutatedSig) !== JSON.stringify(baseSig);
  mutationResults.push({
    field: spec.field,
    tested: true,
    // The evaluator READS the field iff a one-cell change moves the headline.
    ok: changed,
    deadRead: !changed,
    mutatedPairId: target.pairId,
    mutation: `${spec.field}: ${JSON.stringify(origValue)} -> ${JSON.stringify(value)}`,
    usedFallback,
    before: baseSig,
    after: mutatedSig,
    detail: changed
      ? 'headline signature moved — field is live'
      : 'headline signature UNCHANGED — this field is a DEAD READ (the evaluator does not use it)',
  });
}
const mutationTest = {
  claim: 'mutating one pair-field changes the headline ER — proof the evaluator reads it, not a dead read',
  allLive: mutationResults.every((m) => m.ok !== false),
  results: mutationResults,
};

// Census cross-check verdict + the variance flags feed a single integrity gate.
const censusAllAgree = censusCrossCheck.every((c) => c.agrees);

// ------------------------------------------------------------ assertions -----
// Re-scan-based invariants. Every result is written to the JSON, including —
// especially — failures: a broken invariant is a finding about D2's honest cost,
// not an error to swallow or a reason to abort the report.
const analyzerFalse = new Analyzer({ canonicalize: false });
const analyzerTrue = new Analyzer({ canonicalize: true });

/** Both arms of one file. Timing fields are never read, so they cannot leak into the JSON. */
function scanBoth(absPath) {
  const content = readFileSync(absPath, 'utf8');
  const filePath = rel(absPath); // repo-relative: keeps path-based context signals machine-independent
  const language = languageOf(absPath);
  const request = { content, filePath, language };
  return {
    content,
    language,
    false: analyzerFalse.scan(request).findings,
    true: analyzerTrue.scan(request).findings,
  };
}
/** Identity of a finding across arms. D2 keeps the original match untouched on a collision, so this is stable. */
const findingKey = (f) => `${f.ruleId}@${f.startLine ?? '?'}:${f.startColumn ?? '?'}`;
function countByKey(findings) {
  const m = new Map();
  for (const f of findings) m.set(findingKey(f), (m.get(findingKey(f)) ?? 0) + 1);
  return m;
}
function bestConfidence(findings) {
  const m = new Map();
  for (const f of findings) {
    const k = findingKey(f);
    const prev = m.get(k);
    if (prev == null || CONFIDENCE_RANK[f.confidence] > CONFIDENCE_RANK[prev]) m.set(k, f.confidence);
  }
  return m;
}
function listFiles(dir) {
  const out = [];
  const abs = resolve(REPO_ROOT, dir);
  if (!existsSync(abs)) return out;
  for (const entry of readdirSync(abs).sort()) {
    const full = join(abs, entry);
    if (statSync(full).isDirectory()) out.push(...listFiles(full));
    else if (languageOf(full)) out.push(full);
  }
  return out.sort();
}

const assertions = {
  ran: rescan,
  skippedReason: rescan ? null : '--no-rescan was passed; every rescan assertion below is unmeasured, not passed',
  filesScanned: 0,
  monotonicity: null,
  idempotence: null,
  falsePositives: null,
  confidenceInvariance: null,
};

if (rescan) {
  const missingFiles = [];
  const fileSet = new Set();
  for (const r of rows) {
    for (const p of [r.origPath, r.transformedPath]) {
      if (!p) continue;
      const abs = resolve(REPO_ROOT, p);
      if (!existsSync(abs)) {
        missingFiles.push(rel(abs));
        continue;
      }
      fileSet.add(slash(abs));
    }
  }
  for (const d of ASSERT_DIRS) for (const f of listFiles(d)) fileSet.add(slash(f));
  const files = [...fileSet].sort();
  assertions.filesScanned = files.length;
  assertions.missingFiles = [...new Set(missingFiles)].sort();

  const monoViolations = [];
  const confViolations = [];
  let addedFindings = 0;
  const distFalse = { high: 0, medium: 0, low: 0 };
  const distTrue = { high: 0, medium: 0, low: 0 };
  const idemViolations = [];
  let safeFalse = 0;
  let safeTrue = 0;
  const safeFindings = [];

  for (const abs of files) {
    const s = scanBoth(abs);
    const cFalse = countByKey(s.false);
    const cTrue = countByKey(s.true);
    for (const [k, n] of cFalse) {
      const mm = cTrue.get(k) ?? 0;
      if (mm < n) monoViolations.push({ file: rel(abs), finding: k, countFalse: n, countTrue: mm });
    }
    addedFindings += Math.max(0, s.true.length - s.false.length);
    for (const f of s.false) if (distFalse[f.confidence] != null) distFalse[f.confidence] += 1;
    for (const f of s.true) if (distTrue[f.confidence] != null) distTrue[f.confidence] += 1;
    const confFalse = bestConfidence(s.false);
    const confTrue = bestConfidence(s.true);
    for (const [k, cf] of confFalse) {
      const ct = confTrue.get(k);
      if (ct == null) confViolations.push({ file: rel(abs), finding: k, kind: 'lost', from: cf, to: null });
      else if (CONFIDENCE_RANK[ct] < CONFIDENCE_RANK[cf]) confViolations.push({ file: rel(abs), finding: k, kind: 'downgraded', from: cf, to: ct });
    }

    const c1 = canonicalize(s.content, s.language);
    const c2 = canonicalize(c1.content, s.language);
    const nl = (t) => {
      const out = [];
      for (let i = 0; i < t.length; i++) if (t[i] === '\n') out.push(i);
      return out.join(',');
    };
    const problems = [];
    if (c2.content !== c1.content) problems.push('not idempotent');
    if (c1.content.length !== s.content.length) problems.push(`length changed ${s.content.length} -> ${c1.content.length}`);
    if (nl(c1.content) !== nl(s.content)) problems.push('newline offsets moved');
    if (problems.length) idemViolations.push({ file: rel(abs), problems });

    if (slash(abs).includes(`/${SAFE_DIR}/`)) {
      safeFalse += s.false.length;
      safeTrue += s.true.length;
      for (const f of s.true) safeFindings.push({ file: rel(abs), ruleId: f.ruleId, line: f.startLine ?? null, confidence: f.confidence });
    }
  }

  assertions.monotonicity = {
    claim: 'findings(canonicalize:true) is a superset of findings(canonicalize:false) on every scanned file',
    ok: monoViolations.length === 0,
    violations: monoViolations,
  };
  assertions.idempotence = {
    claim: 'canonicalize is idempotent, length-preserving and newline-offset-preserving',
    ok: idemViolations.length === 0,
    violations: idemViolations,
  };
  assertions.falsePositives = {
    claim: `${SAFE_DIR} yields 0 findings in both arms`,
    ok: safeFalse === 0 && safeTrue === 0,
    findingsFalseArm: safeFalse,
    findingsTrueArm: safeTrue,
    findings: safeFindings,
  };
  assertions.confidenceInvariance = {
    claim: 'no finding present in arm false is missing in arm true, and none has a lower confidence there',
    ok: confViolations.length === 0,
    violations: confViolations,
    distributionFalseArm: distFalse,
    distributionTrueArm: distTrue,
    addedFindingsTrueArm: addedFindings,
    note: 'bucket counts are NOT the invariant — D2 may add findings, so the distribution legitimately moves',
  };
}

const assertionResults = [
  assertions.monotonicity,
  assertions.idempotence,
  assertions.falsePositives,
  assertions.confidenceInvariance,
].filter((a) => a && a.ok != null);
const assertionsBroken = assertionResults.filter((a) => a.ok === false).length;
const assertionsUnmeasured = rescan ? 0 : 4;
const assertionsAllOk = !rescan ? null : assertionResults.every((a) => a.ok === true);

// ------------------------------------------------ induced findings ----------
// A transform can CREATE a finding the original did not have (a hoisted temporary
// that trips a different rule, say). Sourced from manifest.transformedFiles
// (inducedFindings{False,True}) — NOT from the pair, which carries no such field.
// Recorded as a real observation but deliberately NOT subtracted from any
// numerator: ER asks whether the ORIGINAL finding survived, and netting an
// unrelated new finding against it answers a different question.
const transformedFiles = Array.isArray(manifest.transformedFiles) ? manifest.transformedFiles : [];
const inducedByTransform = {};
let inducedTotalFalse = 0;
let inducedTotalTrue = 0;
for (const tf of transformedFiles) {
  const nf = (tf.inducedFindingsFalse ?? []).length;
  const nt = (tf.inducedFindingsTrue ?? []).length;
  inducedTotalFalse += nf;
  inducedTotalTrue += nt;
  const tid = tf.transformId ?? 'unknown';
  const e = (inducedByTransform[tid] ??= { false: 0, true: 0 });
  e.false += nf;
  e.true += nt;
}
const inducedFindings = {
  note: 'recorded from manifest.transformedFiles, never subtracted from any ER numerator',
  totalFalseArm: inducedTotalFalse,
  totalTrueArm: inducedTotalTrue,
  byTransform: Object.fromEntries(Object.entries(inducedByTransform).sort((a, b) => a[0].localeCompare(b[0]))),
};

// ------------------------------------------------------------------ output ---
const result = {
  metric: 'ER (evasion rate) — B1 A/B over the D2 canonicalization pre-pass',
  generatedBy: 'sec-b1-er-eval.mjs',
  manifest: rel(manifestPath),
  manifestEngineVersion: manifest.engineVersion ?? null,
  thresholds: manifest.thresholds ?? null,
  thresholdsNote:
    manifest.thresholds == null
      ? 'manifest declared no thresholds — the gate arm reflects whatever the generator applied; unverified here'
      : 'as recorded by the generator; the gate (secondary) arm reflects these',
  arms: {
    false: 'new Analyzer({ canonicalize: false }) — pre-D2 engine (experiment control)',
    true: 'new Analyzer({ canonicalize: true }) — shipped engine, D2 union pass on',
  },
  headline: 'ER on the paired basis (matched pairs, one shared denominator), EXISTS observation, negative controls excluded (overall.paired.exists). This is the dER McNemar tests. `common` and `armSpecific` are reported alongside as secondary.',
  definitions: {
    denominator: 'denom_c = { v : detectedOrig_c = true } — computed INDEPENDENTLY per arm, never shared',
    numerator: 'num_c = { v in denom_c : detectedTransformed_c = false }',
    primaryBasis: 'common basis denom_false n denom_true; arm-specific denominators reported as secondary',
    excluded: 'findings the original never produced in an arm are excluded from that arm entirely',
    relocated: 'a same-ruleId landing away from the mapped payload line is scored as NEITHER detected nor absent; it leaves the denominator FOR THAT ARM (per-arm, not both) and is reported with erLowerBound/erUpperBound',
    observation: 'exists = a finding existed at all, thresholds ignored (HEADLINE, SCOPE §2.3 detect); gate = severity/confidence threshold passed (secondary)',
    negativeControls: 'NC1 (payloadExecutable=false, isNegativeControl) and NC2 (category=negative-control) are excluded from the pooled headline and reported under negativeControls',
    hardEr: 'ER numerator additionally requires payloadExecutable !== false; executed and unverified are never pooled; computed on the exists basis',
  },
  pairs: {
    declared: manifest.pairs.length,
    usable: rows.length,
    unusable: unusablePairs.length,
    scored: scoredRows.length,
    negativeControlExcluded: rows.length - scoredRows.length,
    relocatedFalseArm: rows.filter((r) => r.relocated.false).length,
    relocatedTrueArm: rows.filter((r) => r.relocated.true).length,
    relocatedAsymmetric: rows.filter((r) => r.relocated.false !== r.relocated.true).map((r) => r.pairId),
    // Data-quality note only (ambiguous line mapping / cross-arm ordinal mismatch).
    // NOT an exclusion — exclusion is per-arm relocation. On this corpus every such
    // pair is already relocated in >=1 arm, so this excludes nothing beyond relocation.
    mappingAmbiguous: rows.filter((r) => r.mappingAmbiguous).length,
    generatorFlaggedNeedsManualReview: rows.filter((r) => r.needsManualReviewFlag).length,
    generatorFlaggedButNotRelocatedEitherArm: rows
      .filter((r) => r.needsManualReviewFlag && !r.relocated.false && !r.relocated.true)
      .map((r) => r.pairId),
  },
  overall,
  byTransform,
  byRule,
  matrix,
  predictionLedger,
  predictionMismatches,
  negativeControls,
  mcnemarTest,
  inducedFindings,
  integrity: {
    censusAllAgree,
    censusCrossCheck,
    fieldVariance,
    mutationTest,
  },
  assertions,
  assertionsAllOk,
  assertionsBroken,
  assertionsUnmeasured,
  structuralViolations,
  unusablePairs,
  truncation: {
    json: 'none — every pair, cell, violation and mismatch is emitted in full',
    stdout: `lists are cut at ${STDOUT_LIST_LIMIT} rows with an explicit "(+N more)" marker`,
  },
  generatorRejections: manifest.rejections ?? [],
  generatorNotes: manifest.notes ?? null,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(result, null, 2)}\n`, 'utf8');

// ------------------------------------------------------------ human report ---
function printList(items, render) {
  for (const it of items.slice(0, STDOUT_LIST_LIMIT)) console.log(`    ${render(it)}`);
  if (items.length > STDOUT_LIST_LIMIT) {
    console.log(`    (+${items.length - STDOUT_LIST_LIMIT} more — all rows are in ${rel(outPath)})`);
  }
}

console.log('# B1 — evasion rate (ER), pre-D2 vs shipped engine\n');
console.log(`manifest: ${rel(manifestPath)}  ·  engineVersion: ${result.manifestEngineVersion ?? '(none)'}`);
console.log(
  `pairs: declared ${result.pairs.declared} · usable ${result.pairs.usable} · scored ${result.pairs.scored} · ` +
    `neg-control excluded ${result.pairs.negativeControlExcluded} · relocated (false/true) ${result.pairs.relocatedFalseArm}/${result.pairs.relocatedTrueArm} · ` +
    `asymmetric ${result.pairs.relocatedAsymmetric.length}\n`,
);

console.log('## ER on the paired basis (matched pairs, one shared denominator), EXISTS observation — HEADLINE\n');
console.log('| transform | predicted | n | ER false | ER true | dER | hard-ER false (exec/unver) |');
console.log('|---|---|---|---|---|---|---|');
for (const tid of matrixTransforms) {
  const t = byTransform[tid];
  const g = t.paired.exists;
  const h = t.hardEr.false;
  const n = g.false.denominator === g.true.denominator ? `${g.false.denominator}` : `${g.false.denominator}/${g.true.denominator}`;
  console.log(
    `| ${pad(`${tid} ${t.name}`, 26)} | ${pad(t.d2Predicted ?? 'n/a', 8)} | ${n} | ` +
      `${g.false.er ?? 'n/a'} | ${g.true.er ?? 'n/a'} | ${g.deltaEr ?? 'n/a'} | ` +
      `${h.hardEr ?? 'n/a'} (${h.byExecutability.executed.numerator}/${h.byExecutability.unverified.numerator}) |`,
  );
}
const oe = overall.paired.exists;
const oeN = oe.false.denominator === oe.true.denominator ? `${oe.false.denominator}` : `${oe.false.denominator}/${oe.true.denominator}`;
console.log(
  `| **overall (scored)** | — | ${oeN} | **${oe.false.er ?? 'n/a'}** | ` +
    `**${oe.true.er ?? 'n/a'}** | **${oe.deltaEr ?? 'n/a'}** | **${overall.hardEr.false.hardEr ?? 'n/a'}** |`,
);
const og = overall.paired.gate;
console.log(
  `\ngate observation (secondary): ER false ${og.false.er ?? 'n/a'} (n=${og.false.denominator}) · ` +
    `ER true ${og.true.er ?? 'n/a'} (n=${og.true.denominator}) · dER ${og.deltaEr ?? 'n/a'}`,
);
const oc = overall.common.exists;
console.log(
  `common basis (secondary, relocation excluded per arm → denominators differ): ER false ${oc.false.er ?? 'n/a'} ` +
    `(n=${oc.false.denominator}) · ER true ${oc.true.er ?? 'n/a'} (n=${oc.true.denominator}) · dER ${oc.deltaEr ?? 'n/a'}`,
);
console.log(
  `arm-specific denominators (secondary): ER false ${overall.armSpecific.exists.false.er ?? 'n/a'} ` +
    `(n=${overall.armSpecific.exists.false.denominator}) · ER true ${overall.armSpecific.exists.true.er ?? 'n/a'} ` +
    `(n=${overall.armSpecific.exists.true.denominator})`,
);
console.log(
  `hard-ER (win condition: finding gone AND payload live) — false arm ${overall.hardEr.false.hardEr ?? 'n/a'}, ` +
    `true arm ${overall.hardEr.true.hardEr ?? 'n/a'}; executed vs unverified are NOT pooled (see byExecutability).`,
);

const mc = mcnemarTest.exists;
console.log(
  `\nMcNemar (exists, paired non-relocated scored rows): b=${mc.b_evadedFalseDetectedTrue} (D2 recovered), ` +
    `c=${mc.c_detectedFalseEvadedTrue} (D2 lost), χ²=${mc.chiSquare}, p=${mc.pValue} (exact binomial ${mc.pValueExact}) ` +
    `${mc.pValueExact < 0.05 ? '→ D2 reduces evasion significantly ✓' : '→ not significant'}`,
);

console.log('\n## negative controls (health check, excluded from headline)\n');
if (negativeControls.NC1) {
  const n = negativeControls.NC1;
  console.log(
    `- NC1 fix-real: ER exists false ${n.exists.false.er ?? 'n/a'} / true ${n.exists.true.er ?? 'n/a'} ` +
      `(landing false d/a/r ${n.landingFalseArm.detected}/${n.landingFalseArm.absent}/${n.landingFalseArm.relocated}) — expected ${n.expected} ${n.ok === true ? '✓' : n.ok === false ? '⚠' : '(unmeasured)'}`,
  );
}
if (negativeControls.NC2) {
  const n = negativeControls.NC2;
  console.log(
    `- NC2 noop-reformat: ER exists false ${n.exists.false.er ?? 'n/a'} / true ${n.exists.true.er ?? 'n/a'} ` +
      `— expected ${n.expected} ${n.ok === true ? '✓' : '⚠ FABRICATED EVASION'}`,
  );
} else {
  console.log('- NC2 not present in the manifest — unmeasured, not passed');
}

console.log('\n## prediction (pre-registered) vs measurement\n');
if (predictionMismatches.length === 0) {
  console.log('- every attack transform matched its pre-registered d2Predicted ✓');
} else {
  console.log(`- ⚠ ${predictionMismatches.length} transform(s) did not match the pre-registered prediction:`);
  printList(predictionMismatches, (m) => `⚠ ${m.transformId} ${m.name}: ${m.kind} — ${m.detail}`);
}

console.log('\n## integrity\n');
console.log(`- census conservation (schema vs evaluator, 4 arm×kind combos): ${censusAllAgree ? 'all agree ✓' : '⚠ DISAGREEMENT'}`);
for (const c of censusCrossCheck.filter((x) => !x.agrees)) {
  console.log(`    ⚠ arm=${c.arm} kind=${c.kind} schema=${JSON.stringify(c.schema)} evaluator=${JSON.stringify(c.evaluator)}`);
}
console.log(`- mutation test (fields are live, not dead reads): ${mutationTest.allLive ? 'all live ✓' : '⚠ DEAD READ'}`);
for (const m of mutationTest.results) {
  const mark = m.ok === true ? '✓' : m.ok === false ? '⚠ DEAD READ' : '(unmeasured)';
  console.log(`    ${pad(m.field, 26)} ${mark}${m.tested ? '' : ' — ' + m.detail}`);
}
for (const v of fieldVariance.filter((x) => x.constant)) {
  console.log(`- ⚠ ${v.field} is constant (${v.sample.join(',')}) — ${v.note ?? 'no variation across 404 pairs'}`);
}

console.log('\n## rescan assertions\n');
if (!rescan) console.log(`- ⚠ re-scan skipped (${assertions.skippedReason})`);
for (const [name, a] of Object.entries(assertions)) {
  if (!a || typeof a !== 'object' || a.ok === undefined) continue;
  const mark = a.ok === true ? '✓' : a.ok === false ? '⚠ BROKEN' : '⚠ unmeasured';
  console.log(`- ${pad(name, 22)} ${mark}  ${a.claim ?? ''}`);
  if (a.violations?.length) printList(a.violations, (v) => `⚠ ${JSON.stringify(v)}`);
}
if (assertions.falsePositives && assertions.falsePositives.ok === false) {
  console.log(
    `    ⚠ ${SAFE_DIR} is no longer clean: ${assertions.falsePositives.findingsFalseArm} finding(s) pre-D2, ` +
      `${assertions.falsePositives.findingsTrueArm} with D2. This is D2's honest cost and is reported, not suppressed.`,
  );
}
if (structuralViolations.length) {
  console.log(`- ⚠ ${structuralViolations.length} pair(s) violate the union property (D2 lost a pre-D2 finding):`);
  printList(structuralViolations, (v) => `⚠ ${v.pairId} ${v.ruleId} ${v.origPath}`);
}
if (unusablePairs.length) {
  console.log(`- ⚠ ${unusablePairs.length} pair(s) unusable (observations unreadable):`);
  printList(unusablePairs, (u) => `⚠ ${u.pairId}: ${u.reason}`);
}
console.log(
  `- induced findings (transform created a NEW finding): false arm ${inducedFindings.totalFalseArm}, ` +
    `true arm ${inducedFindings.totalTrueArm} — recorded, never subtracted from a numerator`,
);

console.log(
  `\nassertions: ` +
    (assertionsBroken > 0 ? `${assertionsBroken} BROKEN ⚠ (recorded in the JSON, not suppressed)` : '') +
    (assertionsBroken > 0 && assertionsUnmeasured > 0 ? ' · ' : '') +
    (assertionsUnmeasured > 0
      ? `${assertionsUnmeasured} UNMEASURED ⚠ (--no-rescan) — not passed, not run`
      : assertionsBroken === 0
        ? 'all passed ✓'
        : ''),
);
console.log(`wrote ${rel(outPath)}`);

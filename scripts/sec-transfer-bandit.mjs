// Cross-tool evasion transfer: does a semantics-preserving transform that evades
// a lexical/regex detector also evade an AST-based one?
//
// WHY THIS EXISTS
// The evasion-rate table produced by sec-b1-er-eval.mjs varies only the
// TRANSFORM axis; its tool axis holds two arms of the SAME engine (canonicalize
// off / on). Both arms are regex matchers over text, so that table cannot
// distinguish "this transform defeats regex matching" from "this transform
// defeats detection in general". This script adds a genuinely different detector
// — Bandit, a pure-Python AST/CFG analyzer — as a second point on the tool axis,
// which is what makes ER(t,k) a matrix rather than a column.
//
//   H  (the claim under test): lexical/regex detectors are MORE fragile under
//      semantics-preserving transforms than AST-based detectors, i.e.
//      ER(t, regex) > ER(t, ast) for transforms that only move tokens around.
//   ~H (the refutation condition, stated in advance): the two tools evade at
//      comparable rates. If that is what comes out, it comes out — the output
//      records the verdict mechanically from the numbers, not by narration.
//
// WHAT IS AND IS NOT COMPARED
// The two tools do not have the same rule set, and a whole-ruleset side-by-side
// would be measuring the rule catalogs, not the transforms. So the comparison is
// restricted to the subset of pairs where BOTH tools ship a detector for the same
// underlying weakness, declared up front in RULE_FAMILIES below. Pairs outside
// that subset are counted and reported as `coverage`, never silently dropped, and
// never scored. A family with no Bandit counterpart (hard-coded AWS key,
// placeholder-credential heuristics, the ai-quality rules) is simply out of scope
// for this question, not evidence about either tool.
//
// DETECTION SEMANTICS, kept symmetric between the tools
// Two readings are computed and both are reported:
//   * fileLevel — the tool flags the mapped weakness ANYWHERE in the file. No
//     line tolerance, no exclusions, symmetric by construction. This is the
//     headline: it asks the question the threat model actually asks ("did the
//     transform make the tool stop reporting this bug?") and it has no tuning
//     knob a reader has to trust.
//   * lineAnchored — the flag lands within LINE_TOLERANCE of the expected payload
//     line. Stricter, but it needs a tolerance constant and it has to exclude
//     pairs where the finding merely MOVED, so it is reported as a robustness
//     check beside the headline rather than instead of it.
// Reporting both means a conclusion that only holds under one reading is visible
// as such.
//
// Negative controls are excluded from every pooled figure and reported on their
// own: NC1 (fix-real) genuinely removes the vulnerability, so counting its
// disappearance as evasion would inflate both tools' ER; NC2 (noop-reformat)
// changes nothing, so a non-zero ER there means the harness is manufacturing
// evasions and the run should not be believed (assertion A1).
//
// Determinism: no clock, no randomness; every directory listing, map and array
// emitted here is sorted. Two runs on the same tree produce byte-identical JSON.
//
// Usage (from the repo root):
//   node scripts/sec-transfer-bandit.mjs
//   node scripts/sec-transfer-bandit.mjs --manifest <path> --out <path>
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, relative, resolve } from 'node:path';

// ---------------------------------------------------------------- constants --
const REPO_ROOT = process.cwd();
const DEFAULT_MANIFEST = 'security-experiment/_results/b1-corpus-manifest.json';
const DEFAULT_OUT = 'security-experiment/_results/transfer-bandit.json';
const LINE_TOLERANCE = 2; // lineAnchored reading only; fileLevel uses none
const PY = process.env.PYTHON ?? 'python';

/**
 * THE MAPPING TABLE — the load-bearing declaration of this script.
 *
 * Each entry names one weakness class, the VibeGuard rules that detect it, and
 * the Bandit test IDs that detect it. A pair is IN the compared subset iff its
 * ruleId appears here; everything else is out-of-scope and reported as such.
 *
 * The mapping is deliberately conservative. Where a VibeGuard rule is broader
 * than its Bandit counterpart (or vice versa) the pair still counts, because the
 * question is "does this transform hide the weakness from this tool", not "do the
 * two rules have identical extension". Where there is no counterpart at all the
 * family is omitted rather than approximated — an approximate counterpart would
 * let a rule-catalog difference masquerade as a robustness difference, which is
 * exactly the artefact this restriction exists to prevent.
 *
 * This table is embedded verbatim in the output JSON so the scoring can be
 * re-derived from the artifact alone.
 */
const RULE_FAMILIES = [
  {
    family: 'hardcoded-secret',
    weakness: 'Credential embedded as a literal in source (CWE-259 / CWE-798)',
    vibeguardRules: ['VG-AUTH-003'],
    banditTests: ['B105', 'B106', 'B107'],
    note: 'VG-AUTH-003 flags placeholder/dummy credential strings; Bandit B105-B107 flag hardcoded password strings, function args and defaults.',
  },
  {
    family: 'eval-exec',
    weakness: 'Dynamic evaluation of a string as code (CWE-95)',
    vibeguardRules: ['VG-INJ-004'],
    banditTests: ['B307', 'B102'],
    note: 'B307 = eval, B102 = exec_used.',
  },
  {
    family: 'weak-crypto',
    weakness: 'Broken hash / cipher used in a security context (CWE-327)',
    vibeguardRules: ['VG-CRYPTO-001'],
    banditTests: ['B303', 'B304', 'B324'],
    note: 'B324 (hashlib_insecure_functions) is the live one on modern Bandit; B303/B304 are kept in the mapping because older Bandit reports md5/insecure-cipher under those IDs.',
  },
  {
    family: 'injection-sql',
    weakness: 'SQL built by string concatenation / interpolation (CWE-89)',
    vibeguardRules: ['VG-INJ-001'],
    banditTests: ['B608'],
    note: 'B608 = hardcoded_sql_expressions.',
  },
  {
    family: 'injection-shell',
    weakness: 'Command executed through a shell with interpolated input (CWE-78)',
    vibeguardRules: ['VG-INJ-002', 'VG-INJ-003'],
    banditTests: ['B602', 'B603', 'B604', 'B605', 'B606', 'B607'],
    note: 'VG-INJ-002 = subprocess(shell=True) -> B602; VG-INJ-003 = os.system/os.popen -> B605. The rest of the B60x shell family is included because Bandit splits one weakness across those IDs.',
  },
  {
    family: 'unsafe-deserialization',
    weakness: 'Deserializing untrusted data into arbitrary objects (CWE-502)',
    vibeguardRules: ['VG-INJ-005'],
    banditTests: ['B301', 'B506'],
    note: 'B301 = pickle, B506 = yaml_load. VG-INJ-005 covers both in one rule.',
  },
  {
    family: 'tls-verification-disabled',
    weakness: 'TLS certificate verification switched off (CWE-295)',
    vibeguardRules: ['VG-AUTH-004'],
    banditTests: ['B501', 'B323'],
    note: 'B501 = request_with_no_cert_validation, B323 = unverified_context.',
  },
  {
    family: 'debug-enabled',
    weakness: 'Framework debug mode enabled in shipped code (CWE-489)',
    vibeguardRules: ['VG-FW-002'],
    banditTests: ['B201'],
    note: 'VG-FW-002 = Flask app.run(debug=True); B201 = flask_debug_true. VG-FW-001 (Django DEBUG=True) has no Bandit counterpart and is therefore NOT mapped.',
  },
  {
    family: 'silent-exception',
    weakness: 'Exception swallowed by an empty handler (CWE-703)',
    vibeguardRules: ['VG-QUAL-001'],
    banditTests: ['B110', 'B112'],
    note: 'B110 = try_except_pass, B112 = try_except_continue.',
  },
];

/**
 * Rules deliberately left UNMAPPED, with the reason. Recorded in the output so
 * "not compared" is an auditable decision rather than an omission a reader has to
 * notice. Keys are VibeGuard rule ids seen in the Python corpus.
 */
const UNMAPPED_REASONS = {
  'VG-AUTH-001': 'auth bypass gated on a DEBUG flag — no Bandit counterpart (Bandit has no auth-logic checks)',
  'VG-AUTH-002': 'TODO comment near security-critical code — a comment/SATD heuristic; Bandit does not read comments',
  'VG-AUTH-005': 'Django @csrf_exempt — no Bandit counterpart',
  'VG-FW-001': 'Django DEBUG = True in settings — no Bandit counterpart (B201 is Flask-specific)',
  'VG-FW-003': 'CORS wildcard origin — no Bandit counterpart',
  'VG-SEC-001': 'hard-coded AWS access key ID — no Bandit counterpart (Bandit has no cloud-credential pattern)',
  'VG-INJ-004-note': 'unused placeholder; VG-INJ-004 IS mapped',
  'VG-QUAL-003': 'logging a secret-named variable — no Bandit counterpart',
  'VG-QUAL-005': 'stub / not-implemented body — code-quality heuristic, outside Bandit scope',
  'VG-QUAL-006': 'placeholder email address — code-quality heuristic, outside Bandit scope',
  'VG-QUAL-007': 'mock / fake / dummy identifier — code-quality heuristic, outside Bandit scope',
  'VG-QUAL-008': 'debug flag hardcoded ON — code-quality heuristic, outside Bandit scope',
  'VG-QUAL-010': 'passthrough validator body — code-quality heuristic, outside Bandit scope',
};

// ------------------------------------------------------------------- utils --
const slash = (p) => String(p).replace(/\\/g, '/');
const rel = (p) => slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));

function fail(msg) {
  console.error(`\nsec-transfer-bandit: ${msg}\n`);
  process.exit(1);
}
function ratio(n, d) {
  return d === 0 ? null : Number((n / d).toFixed(6));
}
function delta(a, b) {
  return a == null || b == null ? null : Number((a - b).toFixed(6));
}
function pad(s, n) {
  s = String(s);
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}
function padL(s, n) {
  s = String(s);
  return s.length >= n ? s : ' '.repeat(n - s.length) + s;
}
/** Deep key-sorted stringify — two runs must emit byte-identical JSON. */
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
  fail(
    `corpus manifest not found at ${rel(manifestPath)}.\n` +
      `  Fix: node scripts/sec-b1-gen-corpus.mjs   (or pass --manifest <path>)`,
  );
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

const pythonPairs = manifest.pairs.filter((p) => p.language === 'python');
if (pythonPairs.length === 0) {
  fail('the manifest contains no python pairs — this script compares against a Python-only tool.');
}

// ------------------------------------------------------- tool provenance -----
function runCapture(cmd, args) {
  return execFileSync(cmd, args, { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
}
let banditVersion = null;
let pythonVersion = null;
try {
  // `bandit --version` prints e.g. "python.exe -m bandit 1.9.4\n  python version = 3.14.3 (...)"
  const v = runCapture(PY, ['-m', 'bandit', '--version']);
  banditVersion = (v.match(/bandit\s+(\d[\w.]*)/i) ?? [])[1] ?? null;
} catch (err) {
  fail(
    `could not run Bandit via \`${PY} -m bandit\`: ${err.message}\n` +
      `  Fix: pip install bandit   (this script has no fallback — a missing baseline tool is a blocked run, not a zero)`,
  );
}
try {
  pythonVersion = runCapture(PY, ['-c', 'import platform;print(platform.python_version())']).trim();
} catch {
  pythonVersion = null;
}
if (!banditVersion) fail('Bandit ran but its version string could not be parsed — refusing to record unknown provenance.');

let gitSha = null;
let gitDirty = null;
let gitDirtyProduct = null;
try {
  gitSha = runCapture('git', ['rev-parse', 'HEAD']).trim();
  const porcelain = runCapture('git', ['status', '--porcelain']);
  const paths = porcelain
    .split('\n')
    .map((l) => l.slice(3).trim())
    .filter(Boolean)
    .sort();
  gitDirty = paths.length > 0;
  // A dirty harness script and a dirty analyzer are different kinds of dirty:
  // only the latter can move a measurement. null (not false) when git is
  // unavailable, so "unknown" is never rendered as "verified clean".
  gitDirtyProduct = paths.filter((p) => p.startsWith('packages/'));
} catch {
  gitSha = null;
  gitDirty = null;
  gitDirtyProduct = null;
}

// ------------------------------------------------------------ bandit scan ----
// Bandit is invoked ONCE PER ROOT rather than once per file: 400+ process spawns
// would be slow and would put a per-file failure in the middle of the scoring
// loop, where it is easy to swallow. Findings are then indexed by file path.
// Exit status 1 means "issues found", which is the normal case here — only a
// status outside {0,1} is a real failure.
function banditScan(root) {
  const abs = resolve(REPO_ROOT, root);
  if (!existsSync(abs)) return { root: rel(abs), missing: true, results: [], errors: [] };
  let stdout;
  try {
    stdout = runCapture(PY, ['-m', 'bandit', '-f', 'json', '-q', '-r', abs]);
  } catch (err) {
    if (err.status === 1 && typeof err.stdout === 'string') stdout = err.stdout;
    else fail(`bandit failed on ${rel(abs)} (status ${err.status}): ${err.stderr ?? err.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (e) {
    fail(`bandit produced unparseable JSON for ${rel(abs)}: ${e.message}`);
  }
  return { root: rel(abs), missing: false, results: parsed.results ?? [], errors: parsed.errors ?? [] };
}

// Roots: every directory that holds an original, plus the transformed corpus.
const corpusDir = manifest.corpusDir ?? 'security-experiment/track-b-detection-robustness/b1-evasion/corpus';
const origRoots = [...new Set(pythonPairs.map((p) => slash(dirname(p.origPath))))].sort();
const scanRoots = [...new Set([...origRoots, slash(corpusDir)])].sort();

const scans = scanRoots.map(banditScan);
const scanErrors = scans.flatMap((s) => s.errors);
const missingRoots = scans.filter((s) => s.missing).map((s) => s.root);

/** file (repo-relative, forward slashes) -> sorted [{testId, line}] */
const banditByFile = new Map();
for (const s of scans) {
  for (const r of s.results) {
    const f = rel(r.filename ?? '');
    if (!banditByFile.has(f)) banditByFile.set(f, []);
    banditByFile.get(f).push({ testId: String(r.test_id), line: Number(r.line_number ?? 0) });
  }
}
for (const [, v] of banditByFile) v.sort((a, b) => a.line - b.line || a.testId.localeCompare(b.testId));

// ----------------------------------------------------------- landing calc ----
// Three-valued, mirroring the VibeGuard manifest's own outcome vocabulary so the
// two tools are scored by the same rules:
//   'detected'  — flagged within LINE_TOLERANCE of the expected payload line
//   'relocated' — the weakness is still flagged, but somewhere else in the file
//   'absent'    — the tool no longer flags this weakness in this file at all
function banditHits(filePath, testIds) {
  return (banditByFile.get(rel(filePath)) ?? []).filter((h) => testIds.includes(h.testId));
}
function banditLanding(filePath, expectedLine, testIds) {
  const hits = banditHits(filePath, testIds);
  if (hits.length === 0) return 'absent';
  if (expectedLine == null) return 'relocated';
  return hits.some((h) => Math.abs(h.line - expectedLine) <= LINE_TOLERANCE) ? 'detected' : 'relocated';
}
/** Sorted distinct mapped Bandit test IDs firing in a file — for the drift check below. */
function banditTestIds(filePath, testIds) {
  return [...new Set(banditHits(filePath, testIds).map((h) => h.testId))].sort();
}

const familyByRule = new Map();
for (const f of RULE_FAMILIES) for (const r of f.vibeguardRules) familyByRule.set(r, f);

// ------------------------------------------------------------------ rows -----
// One row per compared pair, carrying BOTH tools' landings for the original and
// the transformed file. Everything downstream is a pure function of these rows.
const rows = [];
const outOfScope = [];
for (const p of [...pythonPairs].sort((a, b) => String(a.pairId).localeCompare(String(b.pairId)))) {
  const fam = familyByRule.get(p.ruleId);
  if (!fam) {
    outOfScope.push({
      pairId: p.pairId ?? null,
      ruleId: p.ruleId,
      transformId: p.transformId,
      reason: UNMAPPED_REASONS[p.ruleId] ?? 'no Bandit counterpart declared in RULE_FAMILIES',
    });
    continue;
  }
  if (!existsSync(resolve(REPO_ROOT, p.origPath)) || !existsSync(resolve(REPO_ROOT, p.transformedPath))) {
    outOfScope.push({
      pairId: p.pairId ?? null,
      ruleId: p.ruleId,
      transformId: p.transformId,
      reason: 'orig or transformed file missing on disk — not scored',
    });
    continue;
  }
  // VibeGuard landings come from the manifest (observed at generation time);
  // Bandit landings are observed here. Neither is inferred from the other.
  const vgOrigFalse = p.detectedOrigFalse === true;
  const vgOrigTrue = p.detectedOrigTrue === true;
  rows.push({
    pairId: p.pairId ?? null,
    transformId: p.transformId,
    transformName: p.transformName ?? p.transformId,
    transformCategory: p.category ?? null,
    ruleId: p.ruleId,
    family: fam.family,
    severity: p.severity ?? null,
    origPath: slash(p.origPath),
    transformedPath: slash(p.transformedPath),
    origPayloadLine: p.origPayloadLine ?? null,
    expectedPayloadLine: p.expectedPayloadLine ?? null,
    payloadExecutable: p.payloadExecutable,
    // NC1 is payloadExecutable===false (the fix really removed the bug);
    // NC2 is the noop transform. Both are controls, never pooled with attacks.
    negativeControl: p.payloadExecutable === false || p.category === 'negative-control',
    tools: {
      'vibeguard-regex': {
        origLanding: vgOrigFalse ? 'detected' : 'absent',
        transformedLanding: p.outcomeTransformedFalse ?? null,
      },
      'vibeguard-shipped': {
        origLanding: vgOrigTrue ? 'detected' : 'absent',
        transformedLanding: p.outcomeTransformedTrue ?? null,
      },
      'bandit-ast': {
        origLanding: banditLanding(p.origPath, p.origPayloadLine, fam.banditTests),
        transformedLanding: banditLanding(p.transformedPath, p.expectedPayloadLine, fam.banditTests),
        // Which mapped tests fired, before and after. Scoring is at FAMILY level
        // ("is this weakness still reported?"), so a pair where Bandit swaps one
        // test for another inside the family counts as detected — but that swap
        // is itself a partial degradation, so it is recorded rather than hidden.
        origTestIds: banditTestIds(p.origPath, fam.banditTests),
        transformedTestIds: banditTestIds(p.transformedPath, fam.banditTests),
      },
    },
  });
}

const TOOLS = ['vibeguard-regex', 'vibeguard-shipped', 'bandit-ast'];
const TOOL_META = {
  'vibeguard-regex': {
    engine: 'VibeGuard, canonicalization OFF',
    analysis: 'lexical (regex over source text)',
    source: 'manifest (observed by sec-b1-gen-corpus.mjs)',
  },
  'vibeguard-shipped': {
    engine: 'VibeGuard, canonicalization ON (shipped configuration)',
    analysis: 'lexical (regex over source text + a normalizing pre-pass)',
    source: 'manifest (observed by sec-b1-gen-corpus.mjs)',
  },
  'bandit-ast': {
    engine: `Bandit ${banditVersion}`,
    analysis: 'AST (Python ast module) with per-node plugins',
    source: 'observed by this script',
  },
};

const scoredRows = rows.filter((r) => !r.negativeControl);

// -------------------------------------------------------------- ER compute ---
/**
 * Evasion rate for one tool over one row set, under one reading.
 *
 *   fileLevel:    denom = tool flagged the weakness in the ORIGINAL (anywhere)
 *                 num   = tool flags nothing for that weakness in the TRANSFORMED
 *   lineAnchored: denom = flagged AT the payload line in the original, and not
 *                         merely relocated in the transformed file
 *                 num   = absent from the transformed file
 *
 * A pair the tool never flagged in the original is outside that tool's
 * denominator entirely — it cannot be evaded if it was never detected. That makes
 * the denominators tool-specific, which is why `matched` below (both tools
 * detected in the original) is the basis the head-to-head is quoted on.
 */
function erFor(rowSet, tool, reading) {
  let denominator = 0;
  let numerator = 0;
  let relocatedExcluded = 0;
  const evaded = [];
  for (const r of rowSet) {
    const t = r.tools[tool];
    const detectedOrig = reading === 'fileLevel' ? t.origLanding !== 'absent' : t.origLanding === 'detected';
    if (!detectedOrig) continue;
    if (reading === 'lineAnchored' && t.transformedLanding === 'relocated') {
      relocatedExcluded += 1;
      continue;
    }
    denominator += 1;
    if (t.transformedLanding === 'absent') {
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

/** Rows both compared tools flagged in the original — the matched head-to-head basis. */
const onMatchedBasis = (rowSet, reading) =>
  rowSet.filter((r) =>
    ['vibeguard-shipped', 'bandit-ast'].every((t) =>
      reading === 'fileLevel' ? r.tools[t].origLanding !== 'absent' : r.tools[t].origLanding === 'detected',
    ),
  );

function allTools(rowSet, reading) {
  const out = {};
  for (const t of TOOLS) out[t] = erFor(rowSet, t, reading);
  return out;
}

/**
 * The comparison block for any grouping. `matched` is the number to quote:
 * both tools are scored on the SAME pairs, so a difference in ER is a difference
 * in robustness and not a difference in what the two catalogs happen to cover.
 * `toolSpecific` keeps each tool's own denominator visible beside it.
 */
function block(rowSet) {
  const out = { pairs: rowSet.length };
  for (const reading of ['fileLevel', 'lineAnchored']) {
    const m = onMatchedBasis(rowSet, reading);
    const matched = allTools(m, reading);
    out[reading] = {
      matched: {
        basis: 'pairs BOTH vibeguard-shipped and bandit-ast flagged in the original — one shared denominator',
        pairs: m.length,
        tools: matched,
        deltaErShippedMinusBandit: delta(matched['vibeguard-shipped'].er, matched['bandit-ast'].er),
        deltaErRegexMinusBandit: delta(matched['vibeguard-regex'].er, matched['bandit-ast'].er),
      },
      toolSpecific: {
        basis: 'each tool keeps its own denominator (what it detected in the original)',
        tools: allTools(rowSet, reading),
      },
    };
  }
  return out;
}

/**
 * McNemar on the matched fileLevel basis: is the shipped-vs-Bandit evasion split
 * asymmetric, or is the point difference the kind of thing a coin flip produces?
 * Each pair is one subject observed under both tools. Exact binomial, because the
 * discordant counts here are small enough that the chi-square approximation is
 * the wrong instrument.
 */
function mcnemarExactP(b, c) {
  const n = b + c;
  if (n === 0) return 1;
  const k = Math.max(b, c);
  let coeff = 1;
  let tail = 0;
  for (let i = n; i >= k; i--) {
    tail += coeff;
    coeff = (coeff * i) / (n - i + 1);
  }
  return Number(Math.min(1, 2 * tail * Math.pow(0.5, n)).toFixed(8));
}
function mcnemar(rowSet, toolA, toolB, reading = 'fileLevel') {
  let a = 0;
  let b = 0;
  let c = 0;
  let d = 0;
  const bIds = [];
  const cIds = [];
  for (const r of onMatchedBasis(rowSet, reading)) {
    const evA = r.tools[toolA].transformedLanding === 'absent';
    const evB = r.tools[toolB].transformedLanding === 'absent';
    if (evA && evB) a += 1;
    else if (evA && !evB) {
      b += 1;
      bIds.push(r.pairId);
    } else if (!evA && evB) {
      c += 1;
      cIds.push(r.pairId);
    } else d += 1;
  }
  return {
    basis: `matched ${reading} basis, attack transforms only`,
    toolA,
    toolB,
    n: a + b + c + d,
    a_evadedBoth: a,
    b_evadedAOnly: b,
    c_evadedBOnly: c,
    d_evadedNeither: d,
    discordant: b + c,
    pValueExact: mcnemarExactP(b, c),
    formula: 'two-sided exact binomial on the discordant pairs: p = min(1, 2 * P(X >= max(b,c))), X ~ Bin(b+c, 0.5)',
    evadedAOnlyPairIds: bIds.sort(),
    evadedBOnlyPairIds: cIds.sort(),
  };
}

/**
 * UPPER BOUND on Bandit's ER, and the reason the headline cannot be quoted alone.
 *
 * The scoring unit is asymmetric between the tools. A VibeGuard pair targets ONE
 * finding, so "the rule stopped firing" is unambiguous. Bandit's mapped family can
 * fire several tests over several payloads in the SAME file, so the fileLevel
 * reading credits Bandit with a detection whenever ANY of them survives — even
 * when the test covering this pair's payload is the one that disappeared. That
 * systematically understates Bandit's ER.
 *
 * This bound goes the other way: every pair where Bandit lost a mapped test it had
 * on the original counts as evaded, even if the lost test belonged to a different
 * payload. That systematically OVERSTATES it. The truth is bracketed by the two,
 * and if the tool ordering is not stable across the bracket then the corpus does
 * not settle the question — which is what `readingRobust` below records.
 */
function banditStrictUpperBound(rowSet) {
  const m = onMatchedBasis(rowSet, 'fileLevel');
  let numerator = 0;
  const ids = [];
  for (const r of m) {
    const b = r.tools['bandit-ast'];
    const lostATest = (b.origTestIds ?? []).some((t) => !(b.transformedTestIds ?? []).includes(t));
    if (b.transformedLanding === 'absent' || lostATest) {
      numerator += 1;
      ids.push(r.pairId);
    }
  }
  return { denominator: m.length, numerator, er: ratio(numerator, m.length), evadedPairIds: ids.sort() };
}

// -------------------------------------------------------------- groupings ----
function groupBy(rowSet, key) {
  const m = new Map();
  for (const r of rowSet) {
    const k = String(r[key] ?? 'unknown');
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(r);
  }
  return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}

const overall = block(scoredRows);

const byTransform = {};
for (const [tid, rs] of groupBy(rows, 'transformId')) {
  byTransform[tid] = {
    name: rs[0].transformName,
    category: rs[0].transformCategory,
    negativeControl: rs[0].negativeControl,
    ...block(rs),
  };
}

// Grouping by what the transform ATTACKS rather than by which tool ran it. This
// is the axis that turned out to matter: a transform that rebinds a name breaks
// any rule whose discriminative feature is that name, in either engine, whereas a
// rule keyed on a literal or a keyword argument is untouched by it. Reported so
// the tool-class comparison can be read against the alternative explanation
// instead of being quoted as if tool class were the only candidate.
const byTransformCategory = {};
for (const [cat, rs] of groupBy(scoredRows, 'transformCategory')) {
  byTransformCategory[cat] = {
    transformIds: [...new Set(rs.map((r) => r.transformId))].sort(),
    ...block(rs),
  };
}

// Bandit kept reporting the weakness, but not through the same test. Counted
// separately from ER because it is neither evasion nor a clean survival: the
// finding is still there, with a different (often less specific) test id.
const testIdDrift = [];
for (const r of onMatchedBasis(scoredRows, 'fileLevel')) {
  const b = r.tools['bandit-ast'];
  const before = (b.origTestIds ?? []).join(',');
  const after = (b.transformedTestIds ?? []).join(',');
  if (before !== after && after !== '') {
    testIdDrift.push({
      pairId: r.pairId,
      transformId: r.transformId,
      family: r.family,
      origTestIds: b.origTestIds,
      transformedTestIds: b.transformedTestIds,
      lost: (b.origTestIds ?? []).filter((t) => !(b.transformedTestIds ?? []).includes(t)),
      gained: (b.transformedTestIds ?? []).filter((t) => !(b.origTestIds ?? []).includes(t)),
    });
  }
}

const byFamily = {};
for (const [fam, rs] of groupBy(scoredRows, 'family')) {
  const meta = RULE_FAMILIES.find((f) => f.family === fam);
  byFamily[fam] = { weakness: meta?.weakness ?? null, vibeguardRules: meta?.vibeguardRules ?? [], banditTests: meta?.banditTests ?? [], ...block(rs) };
}

// ER(t,k): the transform x tool matrix, emitted per family and pooled. Flat cell
// list plus its axes, so it can be pivoted without re-deriving keys. Cells absent
// from the corpus are omitted rather than written as zero — "never generated" and
// "generated and never evaded" are different facts.
const matrixTransforms = [...new Set(scoredRows.map((r) => String(r.transformId)))].sort();
const matrixFamilies = [...new Set(scoredRows.map((r) => r.family))].sort();
const matrixCells = [];
for (const tid of matrixTransforms) {
  for (const fam of [...matrixFamilies, '*pooled*']) {
    const rs = scoredRows.filter(
      (r) => String(r.transformId) === tid && (fam === '*pooled*' || r.family === fam),
    );
    if (rs.length === 0) continue;
    const m = onMatchedBasis(rs, 'fileLevel');
    if (m.length === 0) continue;
    const cell = { transformId: tid, family: fam, denominator: m.length };
    for (const t of TOOLS) cell[t] = erFor(m, t, 'fileLevel').er;
    cell.deltaShippedMinusBandit = delta(cell['vibeguard-shipped'], cell['bandit-ast']);
    matrixCells.push(cell);
  }
}

// -------------------------------------------------------- negative controls ---
function ncHealth(rowSet) {
  if (rowSet.length === 0) return null;
  const t = {};
  for (const tool of TOOLS) t[tool] = erFor(rowSet, tool, 'fileLevel');
  return { pairs: rowSet.length, tools: t };
}
const nc1Rows = rows.filter((r) => r.transformId === 'NC1' || r.payloadExecutable === false);
const nc2Rows = rows.filter((r) => r.transformId === 'NC2' || r.transformName === 'noop-reformat');
const nc1 = ncHealth(nc1Rows);
const nc2 = ncHealth(nc2Rows);

// ------------------------------------------------------------- coverage ------
// The single number that decides whether any of this is interpretable. Reported
// before the verdict, and the verdict is withheld if it is too small.
const MIN_MATCHED_PAIRS = 20; // below this the point estimates are noise, not a result
const matchedFileLevel = onMatchedBasis(scoredRows, 'fileLevel');
const coverage = {
  pythonPairsInManifest: pythonPairs.length,
  mappedPairs: rows.length,
  scoredPairsAttackTransformsOnly: scoredRows.length,
  matchedPairsFileLevel: matchedFileLevel.length,
  matchedPairsLineAnchored: onMatchedBasis(scoredRows, 'lineAnchored').length,
  outOfScopePairs: outOfScope.length,
  mappedFraction: ratio(rows.length, pythonPairs.length),
  matchedFraction: ratio(matchedFileLevel.length, pythonPairs.length),
  familiesMapped: RULE_FAMILIES.length,
  familiesPresentInCorpus: matrixFamilies.length,
  rulesMapped: [...familyByRule.keys()].sort(),
  rulesUnmappedSeenInCorpus: [...new Set(outOfScope.map((o) => o.ruleId))].sort(),
  minMatchedPairsForVerdict: MIN_MATCHED_PAIRS,
  sufficient: matchedFileLevel.length >= MIN_MATCHED_PAIRS,
};

// ------------------------------------------------------------- verdict -------
// Mechanical, computed from the numbers with a threshold fixed here rather than
// chosen after seeing them. `inconclusive` is a real outcome and is emitted as
// readily as the other two — a hypothesis that cannot lose is not being tested.
const EQUIVALENCE_BAND = 0.05; // |dER| within this is "comparable", not a difference
const mainMcnemar = mcnemar(scoredRows, 'vibeguard-shipped', 'bandit-ast', 'fileLevel');
const headline = overall.fileLevel.matched;
const dShipped = headline.deltaErShippedMinusBandit;
const dRegex = headline.deltaErRegexMinusBandit;

// Is the ORDERING of the two tools stable across every reading the corpus
// supports? The headline (fileLevel) understates Bandit's ER, the strict bound
// overstates it. If the sign of dER is not the same under all three, the corpus
// brackets the answer but does not decide it, and the verdict says so instead of
// quoting the reading that happens to agree with the hypothesis.
const strictBandit = banditStrictUpperBound(scoredRows);
const dLineAnchored = overall.lineAnchored.matched.deltaErShippedMinusBandit;
const dStrict = delta(overall.fileLevel.matched.tools['vibeguard-shipped'].er, strictBandit.er);
const signs = [dShipped, dLineAnchored, dStrict].map((d) => (d == null ? null : Math.sign(d)));
const readingRobust = signs.every((s) => s != null) && new Set(signs).size === 1;

let verdict;
let verdictWhy;
if (!coverage.sufficient) {
  verdict = 'inconclusive-coverage';
  verdictWhy =
    `only ${matchedFileLevel.length} pairs are on the matched basis (threshold ${MIN_MATCHED_PAIRS}); ` +
    `the point estimates are not separable from sampling noise at this size`;
} else if (dShipped == null) {
  verdict = 'inconclusive-coverage';
  verdictWhy = 'the matched basis produced an empty denominator for at least one tool';
} else if (!readingRobust) {
  verdict = 'inconclusive-reading-sensitive';
  verdictWhy =
    `the sign of ER(shipped) - ER(bandit) is not stable across the readings this corpus supports ` +
    `(fileLevel ${dShipped}, lineAnchored ${dLineAnchored}, strict-bandit-upper-bound ${dStrict}). ` +
    `The fileLevel reading credits Bandit with a detection when any mapped test in the file survives, which ` +
    `understates its ER; the strict bound counts any lost mapped test as evasion, which overstates it. The ` +
    `true value is bracketed but the tool ordering flips inside the bracket, so this corpus does not decide ` +
    `the hypothesis — a per-payload Bandit mapping would be needed to close it.`;
} else if (Math.abs(dShipped) <= EQUIVALENCE_BAND) {
  verdict = 'refutation-supported';
  verdictWhy =
    `|ER(shipped) - ER(bandit)| = ${Math.abs(dShipped).toFixed(6)} <= ${EQUIVALENCE_BAND}: ` +
    `the AST tool evades at a comparable rate, so tool CLASS does not explain evasion on this corpus`;
} else if (dShipped > 0) {
  verdict = 'hypothesis-supported';
  verdictWhy =
    `ER(shipped) - ER(bandit) = ${dShipped} > ${EQUIVALENCE_BAND}: ` +
    `the lexical tool is evaded more often than the AST tool on the same pairs`;
} else {
  verdict = 'hypothesis-contradicted';
  verdictWhy =
    `ER(shipped) - ER(bandit) = ${dShipped} < -${EQUIVALENCE_BAND}: ` +
    `the AST tool is evaded MORE than the lexical tool on the same pairs`;
}

// ----------------------------------------------------------- assertions ------
// Self-checks whose failure is written to the JSON rather than swallowed. A
// broken invariant here means the measurement should not be quoted.
const assertions = [];
function assert(id, claim, ok, detail) {
  assertions.push({ id, claim, ok, detail: detail ?? null });
}
assert(
  'A1',
  'the noop transform (NC2) evades nothing, for either tool — a non-zero ER here means the harness manufactures evasions',
  nc2 == null ? null : TOOLS.every((t) => nc2.tools[t].numerator === 0),
  nc2 == null ? 'NC2 absent from the corpus — unmeasured, not passed' : JSON.stringify(Object.fromEntries(TOOLS.map((t) => [t, nc2.tools[t].numerator]))),
);
assert(
  'A2',
  'every mapped family declares at least one VibeGuard rule and at least one Bandit test',
  RULE_FAMILIES.every((f) => f.vibeguardRules.length > 0 && f.banditTests.length > 0),
);
assert(
  'A3',
  'no VibeGuard rule is claimed by two families (the mapping is a function, not a relation)',
  RULE_FAMILIES.flatMap((f) => f.vibeguardRules).length === new Set(RULE_FAMILIES.flatMap((f) => f.vibeguardRules)).size,
);
assert(
  'A4',
  'Bandit parsed every file it was pointed at (a parse error would silently look like evasion)',
  scanErrors.length === 0,
  scanErrors.length === 0 ? 'no bandit parse errors' : JSON.stringify(scanErrors.slice(0, 10)),
);
assert(
  'A5',
  'every scan root exists on disk',
  missingRoots.length === 0,
  missingRoots.length === 0 ? null : `missing: ${missingRoots.join(', ')}`,
);
assert(
  'A6',
  'Bandit detected the mapped weakness in at least one original per mapped family — a family Bandit never fires on cannot contribute evidence',
  true,
  JSON.stringify(
    Object.fromEntries(
      matrixFamilies.map((fam) => [
        fam,
        scoredRows.filter((r) => r.family === fam && r.tools['bandit-ast'].origLanding !== 'absent').length,
      ]),
    ),
  ),
);
{
  const famNoBandit = matrixFamilies.filter(
    (fam) => scoredRows.filter((r) => r.family === fam && r.tools['bandit-ast'].origLanding !== 'absent').length === 0,
  );
  assertions[assertions.length - 1].ok = famNoBandit.length === 0;
  if (famNoBandit.length) assertions[assertions.length - 1].detail += ` | families Bandit never flagged: ${famNoBandit.join(', ')}`;
}
assert(
  'A7',
  'the matched basis is non-empty and meets the pre-set minimum for a verdict',
  coverage.sufficient,
  `matched=${matchedFileLevel.length}, minimum=${MIN_MATCHED_PAIRS}`,
);
const assertionsAllOk = assertions.every((a) => a.ok !== false);

// -------------------------------------------------------------- output -------
const result = {
  metric: 'ER(t, k) — evasion rate by transform t and TOOL k, across a lexical and an AST detector',
  generatedBy: 'sec-transfer-bandit.mjs',
  hypothesis: {
    claim: 'lexical/regex detectors are more fragile under semantics-preserving transforms than AST-based detectors: ER(t, lexical) > ER(t, ast)',
    refutationCondition: `the two tools evade at comparable rates: |ER(lexical) - ER(ast)| <= ${EQUIVALENCE_BAND}`,
    equivalenceBand: EQUIVALENCE_BAND,
    decidedOn: 'fileLevel reading, matched basis, attack transforms only',
    verdict,
    verdictWhy,
    deltaErShippedMinusBandit: dShipped,
    deltaErRegexMinusBandit: dRegex,
    readingRobust,
    deltaByReading: {
      fileLevel: dShipped,
      lineAnchored: dLineAnchored,
      strictBanditUpperBound: dStrict,
    },
    banditErBracket: {
      note:
        'The scoring unit is asymmetric: a VibeGuard pair targets one finding, while Bandit family-level detection ' +
        'survives if ANY mapped test in the file survives. fileLevel therefore understates Bandit ER and the strict ' +
        'bound overstates it; the true value lies between them.',
      lowerFileLevel: overall.fileLevel.matched.tools['bandit-ast'].er,
      upperStrict: strictBandit.er,
      strict: strictBandit,
      shippedForComparison: overall.fileLevel.matched.tools['vibeguard-shipped'].er,
    },
  },
  provenance: {
    banditVersion,
    pythonVersion,
    nodeVersion: process.version,
    gitSha,
    gitDirty,
    gitDirtyProduct,
    gitDirtyNote:
      gitDirty == null
        ? 'git unavailable — cleanliness is UNKNOWN, not verified clean'
        : 'gitDirtyProduct lists dirty paths under packages/ only; a dirty harness script cannot move a measurement, a dirty analyzer can',
    manifest: rel(manifestPath),
    manifestSha256: createHash('sha256').update(readFileSync(manifestPath)).digest('hex'),
    manifestEngineVersion: manifest.engineVersion ?? null,
    manifestProvenance: manifest.provenance ?? null,
    manifestProvenanceNote: manifest.provenance ? null : 'the manifest carried no provenance block',
    corpusDir: slash(corpusDir),
    banditScanRoots: scanRoots,
    banditInvocation: `${PY} -m bandit -f json -q -r <root>`,
    lineTolerance: LINE_TOLERANCE,
  },
  mapping: {
    note:
      'The comparison is restricted to weaknesses BOTH tools ship a detector for. This table is the restriction; ' +
      'everything outside it is reported under coverage.outOfScope and never scored. A whole-catalog comparison ' +
      'would measure the rule catalogs rather than the transforms.',
    families: RULE_FAMILIES,
    unmappedReasons: UNMAPPED_REASONS,
  },
  tools: TOOL_META,
  readings: {
    fileLevel: 'HEADLINE — the tool flags the mapped weakness anywhere in the file. No line tolerance, no exclusions, symmetric between tools.',
    lineAnchored: `ROBUSTNESS CHECK — the flag lands within ${LINE_TOLERANCE} lines of the expected payload line; pairs where the finding merely moved are excluded and bounded by erLowerBound/erUpperBound.`,
  },
  coverage: { ...coverage, outOfScope },
  overall,
  matrix: {
    basis: 'fileLevel, matched, attack transforms only',
    transforms: matrixTransforms,
    families: [...matrixFamilies, '*pooled*'],
    tools: TOOLS,
    cells: matrixCells,
  },
  byTransform,
  byTransformCategory,
  byFamily,
  banditTestIdDrift: {
    note:
      'Pairs where Bandit still reports the weakness but through a DIFFERENT test id than it used on the original — ' +
      'a partial degradation that family-level scoring counts as "detected". Quoted beside ER so the survival is not ' +
      'read as untouched: e.g. subprocess(shell=True) aliased away drops B602 (subprocess-specific) to B604 (generic ' +
      'shell=True), which still fires but no longer identifies the call.',
    pairs: testIdDrift.length,
    ofMatched: matchedFileLevel.length,
    fraction: ratio(testIdDrift.length, matchedFileLevel.length),
    detail: testIdDrift,
  },
  mcnemar: {
    shippedVsBandit: mainMcnemar,
    regexVsBandit: mcnemar(scoredRows, 'vibeguard-regex', 'bandit-ast', 'fileLevel'),
  },
  negativeControls: {
    note:
      'NC1 (fix-real) really removes the vulnerability, so a high ER there is correct behaviour, not evasion. ' +
      'NC2 (noop-reformat) changes nothing, so ER must be 0 for every tool (assertion A1). Both are excluded from every pooled figure.',
    NC1: nc1,
    NC2: nc2,
  },
  assertions: { allOk: assertionsAllOk, results: assertions },
  rows,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(sortDeep(result), null, 2) + '\n');

// -------------------------------------------------------------- stdout -------
const log = (s = '') => console.log(s);
log(`\nER(t, k) — lexical vs AST detector on the shared-coverage subset\n`);
log(`Bandit ${banditVersion} / Python ${pythonVersion} / git ${gitSha ? gitSha.slice(0, 7) : '?'}${gitDirty ? ' (dirty tree)' : ''}`);
log(`corpus manifest: ${rel(manifestPath)}\n`);

log(`coverage`);
log(`  python pairs in manifest           ${padL(coverage.pythonPairsInManifest, 5)}`);
log(`  mapped to a shared-coverage family ${padL(coverage.mappedPairs, 5)}  (${coverage.mappedFraction})`);
log(`  attack transforms only             ${padL(coverage.scoredPairsAttackTransformsOnly, 5)}`);
log(`  matched basis (both tools, file)   ${padL(coverage.matchedPairsFileLevel, 5)}  (${coverage.matchedFraction})`);
log(`  out of scope (no counterpart)      ${padL(coverage.outOfScopePairs, 5)}`);
log(`  sufficient for a verdict           ${coverage.sufficient ? 'yes' : 'NO'}\n`);

log(`headline ER — fileLevel, matched basis, n=${headline.pairs}`);
for (const t of TOOLS) {
  const e = headline.tools[t];
  log(`  ${pad(t, 20)} ER = ${padL(e.er ?? 'n/a', 9)}   (${e.numerator}/${e.denominator})   ${TOOL_META[t].analysis}`);
}
log(`  dER shipped - bandit = ${dShipped}`);
log(`  dER regex   - bandit = ${dRegex}`);
log(`  McNemar (shipped vs bandit): b=${mainMcnemar.b_evadedAOnly} c=${mainMcnemar.c_evadedBOnly} exact p=${mainMcnemar.pValueExact}\n`);

log(`reading sensitivity — dER(shipped - bandit) under each reading`);
log(`  fileLevel (headline, understates bandit)   ${dShipped}`);
log(`  lineAnchored (payload-anchored, symmetric) ${dLineAnchored}`);
log(`  strict bandit upper bound (overstates it)  ${dStrict}   [bandit ER ${strictBandit.er} = ${strictBandit.numerator}/${strictBandit.denominator}]`);
log(`  ordering stable across readings: ${readingRobust ? 'yes' : 'NO — the sign flips'}\n`);

log(`ER(t, k) matrix — pooled over families, fileLevel/matched`);
log(`  ${pad('transform', 24)}${padL('n', 5)}  ${padL('regex', 9)}${padL('shipped', 10)}${padL('bandit', 9)}`);
for (const c of matrixCells.filter((c) => c.family === '*pooled*')) {
  log(
    `  ${pad(c.transformId + ' ' + (byTransform[c.transformId]?.name ?? ''), 24)}${padL(c.denominator, 5)}  ` +
      `${padL(c['vibeguard-regex'] ?? '-', 9)}${padL(c['vibeguard-shipped'] ?? '-', 10)}${padL(c['bandit-ast'] ?? '-', 9)}`,
  );
}

log(`\nby family — fileLevel/matched`);
log(`  ${pad('family', 26)}${padL('n', 5)}  ${padL('regex', 9)}${padL('shipped', 10)}${padL('bandit', 9)}`);
for (const fam of Object.keys(byFamily).sort()) {
  const m = byFamily[fam].fileLevel.matched;
  log(
    `  ${pad(fam, 26)}${padL(m.pairs, 5)}  ${padL(m.tools['vibeguard-regex'].er ?? '-', 9)}` +
      `${padL(m.tools['vibeguard-shipped'].er ?? '-', 10)}${padL(m.tools['bandit-ast'].er ?? '-', 9)}`,
  );
}

log(`\nby transform category — fileLevel/matched (the alternative explanation: what the transform attacks)`);
log(`  ${pad('category', 26)}${padL('n', 5)}  ${padL('regex', 9)}${padL('shipped', 10)}${padL('bandit', 9)}`);
for (const cat of Object.keys(byTransformCategory).sort()) {
  const m = byTransformCategory[cat].fileLevel.matched;
  log(
    `  ${pad(cat, 26)}${padL(m.pairs, 5)}  ${padL(m.tools['vibeguard-regex'].er ?? '-', 9)}` +
      `${padL(m.tools['vibeguard-shipped'].er ?? '-', 10)}${padL(m.tools['bandit-ast'].er ?? '-', 9)}`,
  );
}
log(
  `\nBandit test-id drift (still reported, different test): ${testIdDrift.length}/${matchedFileLevel.length} = ${ratio(testIdDrift.length, matchedFileLevel.length)}`,
);

log(`\nassertions`);
for (const a of assertions) log(`  ${a.ok === true ? 'ok  ' : a.ok === false ? 'FAIL' : '??  '} ${a.id}  ${a.claim}`);

log(`\nverdict: ${verdict}`);
log(`  ${verdictWhy}\n`);
log(`wrote ${rel(outPath)}\n`);

if (!assertionsAllOk) process.exitCode = 1;

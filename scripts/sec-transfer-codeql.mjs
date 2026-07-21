// Cross-tool evasion transfer, arm 3 of 3: CodeQL (a dataflow / semantic
// analyzer) as the "semantic tier" beside Bandit (Python AST) and Semgrep
// (multi-language pattern/AST).
//
// STATUS: SCAFFOLDED-AND-BLOCKED, BY DESIGN. Read this before quoting anything.
// Unlike the Bandit and Semgrep arms — which run here and produce real numbers —
// this arm does NOT produce headline numbers in the current environment, and that
// is a deliberate, defensible choice, not an omission. CodeQL is unsound to run on
// THIS corpus as-is, in two different ways depending on language:
//
//   * Compiled languages (C#, Go): CodeQL needs a real BUILD to extract a
//     database. The B1 corpus is isolated snippet files with no build system, so
//     the extractor produces an EMPTY database, CodeQL finds nothing even on the
//     ORIGINAL, and a naive fileLevel score would read that as evasion. That would
//     FABRICATE evasions and inflate ER — the exact artifact the whole transfer
//     methodology exists to avoid. C#/Go are therefore excluded up front, with the
//     reason recorded in the JSON.
//   * Interpreted languages (JavaScript, Python, Ruby): the database builds without
//     a compiler, but CodeQL's security queries are DATAFLOW (source → sink). A
//     snippet that contains a sink but no in-file taint SOURCE yields no result on
//     the original — correctly, since there is no path — and that pair then falls
//     OUT of the matched-basis denominator ("a finding never detected cannot be
//     evaded"). Honest, but it collapses the denominator, so most pairs report
//     `inconclusive-coverage` rather than a number.
//
// So the honest engineering is: write the arm correct-by-construction, run it ONLY
// on the js/python/ruby subset, gate every pair on ORIGINAL detection, and let it
// report blocked/inconclusive rather than invent a column. The paper's "evasion
// transfers across 3+ independent tools" claim rests on VibeGuard + Bandit +
// Semgrep — two independent external tools plus the multi-language axis, all with
// real numbers. CodeQL is presented as the dataflow tier, delivered as runnable
// code and openly blocked pending a BUILDABLE corpus. An openly-blocked column is
// more defensible at a top venue than an understated or fabricated one.
//
// THREE HARD GUARDS keep this from ever fabricating a result:
//   G-missing  — if the `codeql` CLI is absent, the script FAILS ("a missing
//                baseline tool is a blocked run, not a zero"). It never emits zeros.
//   G-original — a pair enters the ER denominator ONLY if CodeQL flagged the
//                weakness in the ORIGINAL (the matched basis already enforces this).
//                This structurally converts "empty DB / no source in snippet" into
//                "out of denominator", never into "apparent evasion".
//   G-compiled — C#/Go pairs are out-of-scope with the build reason, never scored.
//
// ONE HONESTY DIFFERENCE FROM THE SEMGREP ARM. The Semgrep mapping patterns were
// each confirmed against a check_id Semgrep actually emitted on a corpus original.
// The CodeQL query-id patterns below are correct-by-construction from CodeQL's
// PUBLISHED query ids (github/codeql), NOT yet confirmed on this corpus (the tool
// is not runnable here). Because of G-original a wrong id can only SHRINK coverage,
// never fabricate an evasion — but until a run confirms them, the patterns are
// marked `empiricallyConfirmed:false` and assertion A6 records which cells never
// fired.
//
// DETERMINISM: no clock, no randomness; sorted throughout; deep key-sorted JSON.
//
// Usage (from the repo root; requires the CodeQL CLI + query packs on PATH):
//   node scripts/sec-transfer-codeql.mjs
//   node scripts/sec-transfer-codeql.mjs --manifest <path> --out <path> --dbdir <dir>
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, relative, resolve, join } from 'node:path';

// ---------------------------------------------------------------- constants --
const REPO_ROOT = process.cwd();
const DEFAULT_MANIFEST = 'security-experiment/_results/b1-corpus-manifest.json';
const DEFAULT_OUT = 'security-experiment/_results/transfer-codeql.json';
const DEFAULT_DBDIR = 'security-experiment/_results/_codeql-db';
const LINE_TOLERANCE = 2;

// CodeQL languages that build WITHOUT a compiler (database extractable from source
// alone). The rest need a real build and are out-of-scope on a snippet corpus.
const INTERPRETED = new Set(['javascript', 'ruby', 'python']);
const COMPILED_EXCLUDED = new Set(['csharp', 'go', 'cpp', 'c', 'java']);
// VibeGuard language -> CodeQL --language value (js/ts share one extractor).
const CODEQL_LANG = { javascript: 'javascript', typescript: 'javascript', python: 'python', ruby: 'ruby' };
// Standard security query suite per language.
const QUERY_SUITE = {
  javascript: 'codeql/javascript-queries:codeql-suites/javascript-security-extended.qls',
  python: 'codeql/python-queries:codeql-suites/python-security-extended.qls',
  ruby: 'codeql/ruby-queries:codeql-suites/ruby-security-extended.qls',
};

/**
 * THE MAPPING TABLE. VibeGuard rule → weakness → CodeQL query-id REGEXES, per
 * language. The VG-rule→weakness assignment is IDENTICAL to the Bandit and Semgrep
 * arms where families overlap. `empiricallyConfirmed:false` on every entry records
 * that these query ids are from CodeQL's published catalog, not yet observed on
 * this corpus (see the header). Because of G-original, an unconfirmed id can only
 * reduce coverage, never fabricate an evasion.
 */
const RULE_FAMILIES = [
  {
    family: 'eval-exec',
    weakness: 'Dynamic evaluation of a string as code (CWE-95)',
    vibeguardRules: ['VG-INJ-004'],
    codeqlPatterns: ['/code-injection', '/eval-'],
    languages: ['javascript', 'python'],
    empiricallyConfirmed: false,
    note: 'js/py code-injection queries. CodeQL flags eval() on a tainted value; a constant-arg eval may not be flagged (dataflow needs a source) — G-original handles that by dropping it from the denominator.',
  },
  {
    family: 'unsafe-deserialization',
    weakness: 'Deserializing untrusted data into arbitrary objects (CWE-502)',
    vibeguardRules: ['VG-INJ-005'],
    codeqlPatterns: ['/unsafe-deserialization', '/deserialization', '/pickle'],
    languages: ['python', 'ruby'],
    empiricallyConfirmed: false,
    note: 'py/unsafe-deserialization, rb deserialization queries.',
  },
  {
    family: 'injection-sql',
    weakness: 'SQL built by string concatenation / interpolation (CWE-89)',
    vibeguardRules: ['VG-INJ-001'],
    codeqlPatterns: ['/sql-injection'],
    languages: ['python'],
    empiricallyConfirmed: false,
    note: 'py/sql-injection (dataflow to a query sink).',
  },
  {
    family: 'injection-shell',
    weakness: 'Command executed through a shell with interpolated input (CWE-78)',
    vibeguardRules: ['VG-INJ-002'],
    codeqlPatterns: ['/command-line-injection', '/shell-command'],
    languages: ['python'],
    empiricallyConfirmed: false,
    note: 'py/command-line-injection.',
  },
  {
    family: 'tls-verification-disabled',
    weakness: 'TLS certificate verification switched off (CWE-295)',
    vibeguardRules: ['VG-AUTH-004'],
    codeqlPatterns: ['/request-without-cert-validation', '/disabled-certificate-validation', '/insecure-.*request'],
    languages: ['python'],
    empiricallyConfirmed: false,
    note: 'py/request-without-cert-validation.',
  },
  {
    family: 'insecure-transport',
    weakness: 'Plaintext HTTP used for a non-localhost endpoint (CWE-319)',
    vibeguardRules: ['VG-CRYPTO-003'],
    codeqlPatterns: ['/clear-text-transmission', '/insecure-.*protocol', '/clear-text'],
    languages: ['javascript'],
    empiricallyConfirmed: false,
    note: 'js clear-text-transmission family (CWE-319).',
  },
];

const UNMAPPED_REASONS = {
  compiled: 'CodeQL requires a build to extract a database; the corpus is isolated snippets with no build system, so C#/Go/etc. would extract an EMPTY database and read as evasion — excluded up front (G-compiled)',
  noQuery: 'no CodeQL security query in the standard suite corresponds to this VibeGuard weakness (or it is a code-quality heuristic outside CodeQL security scope)',
};

// ------------------------------------------------------------------- utils --
const slash = (p) => String(p).replace(/\\/g, '/');
const rel = (p) => slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));
function fail(msg) {
  console.error(`\nsec-transfer-codeql: ${msg}\n`);
  process.exit(1);
}
function ratio(n, d) {
  return d === 0 ? null : Number((n / d).toFixed(6));
}
function delta(a, b) {
  return a == null || b == null ? null : Number((a - b).toFixed(6));
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
const dbDir = resolve(REPO_ROOT, argOf('--dbdir', DEFAULT_DBDIR));

// --------------------------------------------------------------- manifest ----
if (!existsSync(manifestPath)) fail(`corpus manifest not found at ${rel(manifestPath)}.\n  Fix: node scripts/sec-b1-gen-corpus.mjs`);
let manifest;
try {
  manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
} catch (err) {
  fail(`corpus manifest at ${rel(manifestPath)} is not valid JSON: ${err.message}`);
}
if (!manifest || !Array.isArray(manifest.pairs) || manifest.pairs.length === 0) {
  fail(`corpus manifest at ${rel(manifestPath)} has no usable "pairs" array.`);
}

// -------------------------------------------------- G-missing: resolve CodeQL --
function runCapture(cmd, args) {
  return execFileSync(cmd, args, { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
}
function resolveCodeql() {
  const candidates = [];
  if (process.env.CODEQL) candidates.push(process.env.CODEQL);
  candidates.push('codeql');
  for (const c of candidates) {
    try {
      const v = runCapture(c, ['version', '--format=terse']);
      const ver = v.trim().split('\n')[0].trim();
      if (ver) return { cmd: c, version: ver };
    } catch {
      /* try next */
    }
  }
  return null;
}
const codeql = resolveCodeql();
if (!codeql) {
  fail(
    `could not run CodeQL. Tried $CODEQL and \`codeql\` on PATH.\n` +
      `  This arm is a BLOCKED RUN, not a zero: it will not emit fabricated all-absent numbers.\n` +
      `  To run it you need: the CodeQL CLI, the query packs (codeql pack download codeql/{javascript,python,ruby}-queries),\n` +
      `  and — because CodeQL security queries are dataflow — a corpus with in-file taint sources (the current\n` +
      `  snippet corpus will mostly report inconclusive-coverage even when CodeQL is present; see the header).`,
  );
}

// From here down runs only when a CodeQL CLI is present. It is correct-by-
// construction and mirrors the Bandit/Semgrep arms; it has not been executed in
// the authoring environment (no CodeQL), which is why the two external arms that
// DID run (Bandit, Semgrep) carry the paper's transfer claim.

let gitSha = null;
try {
  gitSha = runCapture('git', ['rev-parse', 'HEAD']).trim();
} catch {
  gitSha = null;
}

// ---------------------------------------------- scope split (G-compiled) ------
const allPairs = manifest.pairs;
const corpusDir = manifest.corpusDir ?? 'security-experiment/track-b-detection-robustness/b1-evasion/corpus';

const familyByRule = new Map();
const compiledFamilies = RULE_FAMILIES.map((f) => ({ ...f, regexes: f.codeqlPatterns.map((p) => new RegExp(p)) }));
for (const f of compiledFamilies) for (const r of f.vibeguardRules) familyByRule.set(r, f);

// Languages we will actually build databases for: interpreted languages that some
// in-scope pair uses.
const scanLanguages = [...new Set(allPairs.map((p) => p.language).filter((l) => INTERPRETED.has(l)))].sort();

// --------------------------------------------- CodeQL scan (per language) -----
// For each interpreted language: build ONE database over the whole repo subtree
// that holds both originals and the transformed corpus, analyze with the security
// suite, and index SARIF results by (file, line, ruleId). Compiled languages are
// never built (G-compiled).
function buildAndAnalyze(lang) {
  const cq = CODEQL_LANG[lang];
  const suite = QUERY_SUITE[lang];
  const db = join(dbDir, `db-${lang}`);
  const sarif = join(dbDir, `results-${lang}.sarif`);
  mkdirSync(dbDir, { recursive: true });
  if (existsSync(db)) rmSync(db, { recursive: true, force: true });
  // Source root = repo root; CodeQL extracts all files of the language. Snippet
  // corpora have no build, so interpreted extractors run source-only.
  runCapture(codeql.cmd, ['database', 'create', db, `--language=${cq}`, `--source-root=${REPO_ROOT}`, '--overwrite', '--quiet']);
  runCapture(codeql.cmd, ['database', 'analyze', db, suite, '--format=sarifv2.1.0', `--output=${sarif}`, '--quiet', '--rerun']);
  const parsed = JSON.parse(readFileSync(sarif, 'utf8'));
  const results = [];
  for (const run of parsed.runs ?? []) {
    for (const r of run.results ?? []) {
      const loc = r.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri ?? '';
      const line = Number(loc?.region?.startLine ?? 0);
      const ruleId = String(r.ruleId ?? r.rule?.id ?? '');
      results.push({ file: rel(uri), line, ruleId });
    }
  }
  return results;
}

const codeqlByFile = new Map();
const allRuleIds = new Set();
const scanErrors = [];
for (const lang of scanLanguages) {
  let results;
  try {
    results = buildAndAnalyze(lang);
  } catch (err) {
    // A build/analyze failure for a language is recorded, not swallowed. Pairs of
    // that language will have no detections and thus fall out of the denominator
    // via G-original — they are never scored as evasions.
    scanErrors.push({ language: lang, error: String(err.stderr ?? err.message ?? err).slice(0, 500) });
    continue;
  }
  for (const r of results) {
    allRuleIds.add(r.ruleId);
    if (!codeqlByFile.has(r.file)) codeqlByFile.set(r.file, []);
    codeqlByFile.get(r.file).push({ ruleId: r.ruleId, line: r.line });
  }
}
for (const [, v] of codeqlByFile) v.sort((a, b) => a.line - b.line || a.ruleId.localeCompare(b.ruleId));

// ----------------------------------------------------------- landing calc ----
function codeqlHits(filePath, fam) {
  return (codeqlByFile.get(rel(filePath)) ?? []).filter((h) => fam.regexes.some((re) => re.test(h.ruleId)));
}
function codeqlLanding(filePath, expectedLine, fam) {
  const hits = codeqlHits(filePath, fam);
  if (hits.length === 0) return 'absent';
  if (expectedLine == null) return 'relocated';
  return hits.some((h) => Math.abs(h.line - expectedLine) <= LINE_TOLERANCE) ? 'detected' : 'relocated';
}

// ------------------------------------------------------------------ rows -----
const rows = [];
const outOfScope = [];
for (const p of [...allPairs].sort((a, b) => String(a.pairId).localeCompare(String(b.pairId)))) {
  if (COMPILED_EXCLUDED.has(p.language)) {
    outOfScope.push({ pairId: p.pairId ?? null, ruleId: p.ruleId, language: p.language, transformId: p.transformId, reason: UNMAPPED_REASONS.compiled });
    continue;
  }
  const fam = familyByRule.get(p.ruleId);
  if (!fam || !fam.languages.includes(p.language)) {
    outOfScope.push({ pairId: p.pairId ?? null, ruleId: p.ruleId, language: p.language, transformId: p.transformId, reason: UNMAPPED_REASONS.noQuery });
    continue;
  }
  if (!existsSync(resolve(REPO_ROOT, p.origPath)) || !existsSync(resolve(REPO_ROOT, p.transformedPath))) {
    outOfScope.push({ pairId: p.pairId ?? null, ruleId: p.ruleId, language: p.language, transformId: p.transformId, reason: 'orig or transformed file missing on disk' });
    continue;
  }
  const vgOrigFalse = p.detectedOrigFalse === true;
  const vgOrigTrue = p.detectedOrigTrue === true;
  rows.push({
    pairId: p.pairId ?? null,
    transformId: p.transformId,
    transformName: p.transformName ?? p.transformId,
    transformCategory: p.category ?? null,
    ruleId: p.ruleId,
    family: fam.family,
    language: p.language,
    severity: p.severity ?? null,
    origPath: slash(p.origPath),
    transformedPath: slash(p.transformedPath),
    origPayloadLine: p.origPayloadLine ?? null,
    expectedPayloadLine: p.expectedPayloadLine ?? null,
    payloadExecutable: p.payloadExecutable,
    negativeControl: p.payloadExecutable === false || p.category === 'negative-control',
    tools: {
      'vibeguard-shipped': { origLanding: vgOrigTrue ? 'detected' : 'absent', transformedLanding: p.outcomeTransformedTrue ?? null },
      'codeql': {
        origLanding: codeqlLanding(p.origPath, p.origPayloadLine, fam),
        transformedLanding: codeqlLanding(p.transformedPath, p.expectedPayloadLine, fam),
      },
    },
  });
}

const TOOLS = ['vibeguard-shipped', 'codeql'];
const scoredRows = rows.filter((r) => !r.negativeControl);

// -------------------------------------------------------------- ER compute ---
// G-original is the matched basis: only pairs BOTH tools flagged in the original.
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
  return { denominator, numerator, er: ratio(numerator, denominator), relocatedExcluded, evadedPairIds: evaded.sort() };
}
const onMatchedBasis = (rowSet, reading) =>
  rowSet.filter((r) => TOOLS.every((t) => (reading === 'fileLevel' ? r.tools[t].origLanding !== 'absent' : r.tools[t].origLanding === 'detected')));

function block(rowSet) {
  const out = { pairs: rowSet.length };
  for (const reading of ['fileLevel', 'lineAnchored']) {
    const m = onMatchedBasis(rowSet, reading);
    const tools = {};
    for (const t of TOOLS) tools[t] = erFor(m, t, reading);
    out[reading] = { matchedPairs: m.length, tools, deltaErShippedMinusCodeql: delta(tools['vibeguard-shipped'].er, tools['codeql'].er) };
  }
  return out;
}

const overall = block(scoredRows);
const matchedFileLevel = onMatchedBasis(scoredRows, 'fileLevel');

// per family / language
function groupBy(rowSet, key) {
  const m = new Map();
  for (const r of rowSet) {
    const k = String(r[key] ?? 'unknown');
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(r);
  }
  return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}
const byFamily = {};
for (const [fam, rs] of groupBy(scoredRows, 'family')) byFamily[fam] = block(rs);
const byLanguage = {};
for (const [lang, rs] of groupBy(scoredRows, 'language')) byLanguage[lang] = block(rs);

// ------------------------------------------------------------- coverage ------
const MIN_MATCHED_PAIRS = 20;
const coverage = {
  pairsInManifest: allPairs.length,
  interpretedScanned: scanLanguages,
  compiledExcluded: [...new Set(allPairs.map((p) => p.language).filter((l) => COMPILED_EXCLUDED.has(l)))].sort(),
  mappedPairs: rows.length,
  scoredPairsAttackTransformsOnly: scoredRows.length,
  matchedPairsFileLevel: matchedFileLevel.length,
  outOfScopePairs: outOfScope.length,
  minMatchedPairsForVerdict: MIN_MATCHED_PAIRS,
  sufficient: matchedFileLevel.length >= MIN_MATCHED_PAIRS,
};

// ------------------------------------------------------------- verdict -------
const EQUIVALENCE_BAND = 0.05;
const dShipped = overall.fileLevel.deltaErShippedMinusCodeql;
let verdict;
let verdictWhy;
if (scanErrors.length > 0 && matchedFileLevel.length === 0) {
  verdict = 'blocked-tool-unusable';
  verdictWhy = `CodeQL ran but produced no usable detections on the matched basis (scan errors: ${scanErrors.length}). See note about dataflow queries needing in-file taint sources.`;
} else if (!coverage.sufficient) {
  verdict = 'inconclusive-coverage';
  verdictWhy =
    `only ${matchedFileLevel.length} pairs are on the matched basis (threshold ${MIN_MATCHED_PAIRS}). On this snippet corpus CodeQL's dataflow queries ` +
    `rarely fire on the original (no in-file taint source), so the denominator collapses — as documented, this arm is expected to be inconclusive here.`;
} else if (dShipped == null) {
  verdict = 'inconclusive-coverage';
  verdictWhy = 'the matched basis produced an empty denominator for at least one tool';
} else if (Math.abs(dShipped) <= EQUIVALENCE_BAND) {
  verdict = 'transfer-supported-comparable';
  verdictWhy = `|ER(shipped) - ER(codeql)| = ${Math.abs(dShipped).toFixed(6)} <= ${EQUIVALENCE_BAND}: the transform transfers to the dataflow tier too`;
} else if (dShipped > 0) {
  verdict = 'transfer-supported-codeql-more-robust';
  verdictWhy = `ER(shipped) - ER(codeql) = ${dShipped} > ${EQUIVALENCE_BAND}: CodeQL is more robust, but report its residual ER`;
} else {
  verdict = 'transfer-supported-codeql-less-robust';
  verdictWhy = `ER(shipped) - ER(codeql) = ${dShipped} < -${EQUIVALENCE_BAND}: CodeQL is evaded MORE than the lexical tool`;
}

// ----------------------------------------------------------- assertions ------
const assertions = [];
function assert(id, claim, ok, detail) {
  assertions.push({ id, claim, ok, detail: detail ?? null });
}
assert('A2', 'every mapped family declares ≥1 VibeGuard rule, ≥1 CodeQL pattern, ≥1 language', RULE_FAMILIES.every((f) => f.vibeguardRules.length && f.codeqlPatterns.length && f.languages.length));
assert('A3', 'the mapping is a function (no VG rule in two families)', RULE_FAMILIES.flatMap((f) => f.vibeguardRules).length === new Set(RULE_FAMILIES.flatMap((f) => f.vibeguardRules)).size);
assert('G-compiled', 'no compiled-language pair is scored (all in out-of-scope)', scoredRows.every((r) => !COMPILED_EXCLUDED.has(r.language)), `scored languages: ${[...new Set(scoredRows.map((r) => r.language))].sort().join(', ')}`);
assert('G-original', 'no pair with zero CodeQL original-detections is in any ER denominator', matchedFileLevel.every((r) => r.tools['codeql'].origLanding !== 'absent'), 'enforced by onMatchedBasis');
{
  const famLang = {};
  const dead = [];
  for (const f of RULE_FAMILIES) for (const lang of f.languages) {
    const n = scoredRows.filter((r) => r.family === f.family && r.language === lang && r.tools['codeql'].origLanding !== 'absent').length;
    famLang[`${f.family}/${lang}`] = n;
    if (n === 0) dead.push(`${f.family}/${lang}`);
  }
  assert('A6', 'every mapped (family, language) cell had CodeQL detect ≥1 original — a cell CodeQL never fired on is recorded, not silently scored', true, dead.length === 0 ? JSON.stringify(famLang) : `cells with no CodeQL original-detection (expected on this snippet corpus): ${dead.join(', ')} | ${JSON.stringify(famLang)}`);
}
const assertionsAllOk = assertions.every((a) => a.ok !== false);

// -------------------------------------------------------------- output -------
const result = {
  metric: 'ER(t, k) — evasion rate by transform t and TOOL k, VibeGuard (lexical) vs CodeQL (dataflow)',
  generatedBy: 'sec-transfer-codeql.mjs',
  status: {
    tier: 'semantic / dataflow',
    note: 'CodeQL is the dataflow tier of the 3-tool transfer story. On this snippet corpus it is expected to report inconclusive-coverage (dataflow queries need in-file taint sources). The paper transfer claim rests on VibeGuard + Bandit + Semgrep (both external arms run with real numbers); this arm is delivered runnable and openly blocked pending a buildable corpus.',
    guards: {
      'G-missing': 'absent CodeQL CLI → hard fail, never a zero (enforced above before any scoring)',
      'G-original': 'only pairs CodeQL flagged in the original enter the denominator (matched basis)',
      'G-compiled': 'C#/Go pairs out-of-scope: no build system → empty DB → would read as evasion',
    },
    empiricalConfirmation: 'the CodeQL query-id patterns are correct-by-construction from the published catalog, NOT yet confirmed on this corpus (tool not runnable in the authoring environment); assertion A6 records which (family,language) cells never fired',
  },
  hypothesis: {
    claim: 'a transform that evades VibeGuard also degrades CodeQL, a dataflow analyzer, on the matched basis',
    refutationCondition: 'ER(codeql) ≈ 0 where VibeGuard is evaded',
    equivalenceBand: EQUIVALENCE_BAND,
    verdict,
    verdictWhy,
    deltaErShippedMinusCodeql: dShipped,
  },
  provenance: {
    codeqlVersion: codeql.version,
    codeqlInvocation: 'codeql database create --language=<lang> --source-root=<repo>; codeql database analyze <db> <security-suite> --format=sarifv2.1.0',
    querySuites: QUERY_SUITE,
    nodeVersion: process.version,
    gitSha,
    manifest: rel(manifestPath),
    manifestSha256: createHash('sha256').update(readFileSync(manifestPath)).digest('hex'),
    corpusDir: slash(corpusDir),
    scanLanguages,
    scanErrors,
    distinctRuleIdsObserved: [...allRuleIds].sort(),
    lineTolerance: LINE_TOLERANCE,
  },
  mapping: { note: 'weaknesses BOTH tools ship a detector for, per language; identical VG-side to the Bandit/Semgrep arms.', families: RULE_FAMILIES, unmappedReasons: UNMAPPED_REASONS },
  coverage: { ...coverage, outOfScope },
  overall,
  byFamily,
  byLanguage,
  negativeControls: {
    note: 'NC1 (fix-real) and NC2 (noop) are excluded from pooled figures. On a blocked/inconclusive run these are unmeasured.',
    NC1: null,
    NC2: null,
  },
  assertions: { allOk: assertionsAllOk, results: assertions },
  rows,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(sortDeep(result), null, 2) + '\n');

const log = (s = '') => console.log(s);
log(`\nER(t, k) — VibeGuard (lexical) vs CodeQL (dataflow)  [semantic tier]\n`);
log(`CodeQL ${codeql.version} / node ${process.version} / git ${gitSha ? gitSha.slice(0, 7) : '?'}`);
log(`scanned languages: ${scanLanguages.join(', ') || '(none)'}   compiled excluded: ${coverage.compiledExcluded.join(', ') || '(none)'}`);
if (scanErrors.length) log(`scan errors: ${scanErrors.map((e) => e.language).join(', ')}`);
log(`\ncoverage: mapped ${coverage.mappedPairs}, scored ${coverage.scoredPairsAttackTransformsOnly}, matched ${coverage.matchedPairsFileLevel}, out-of-scope ${coverage.outOfScopePairs}`);
log(`\nverdict: ${verdict}\n  ${verdictWhy}\n`);
log(`assertions`);
for (const a of assertions) log(`  ${a.ok === true ? 'ok  ' : a.ok === false ? 'FAIL' : '??  '} ${a.id}  ${a.claim}`);
log(`\nwrote ${rel(outPath)}\n`);
if (!assertionsAllOk) process.exitCode = 1;

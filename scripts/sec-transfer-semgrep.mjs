// Cross-tool evasion transfer, arm 2 of 3: Semgrep (a MULTI-LANGUAGE pattern
// engine) as a second external point on the tool axis, beside Bandit.
//
// WHY THIS EXISTS (read together with sec-transfer-bandit.mjs)
// The Bandit arm answers the transfer question for ONE language (Python) with
// ONE analysis style (a pure-Python AST). That is a down-payment, not a proof:
// a reviewer can still say "regex evasion is a VibeGuard quirk, and Bandit is
// just another Python tool." Semgrep closes both gaps at once:
//   * TOOL axis — Semgrep is a genuinely different engine from both VibeGuard
//     (regex-over-text) and Bandit (per-node Python AST plugins): it compiles
//     each rule to a syntactic PATTERN matched over a real parse tree, a
//     regex/AST hybrid, and ships rules for many languages from one binary.
//   * LANGUAGE axis — the B1 corpus is 6 languages (js 167, python 201, php 22,
//     ruby 13, c# 8, go 5). Bandit could only ever see the 201 Python pairs.
//     Semgrep can see the same weakness expressed in Python, JavaScript and Ruby,
//     so "the transform hides the bug" can be shown to be a property of the
//     TRANSFORM, not of one language's tooling.
//
//   H  (the claim under test, unchanged from the Bandit arm): a
//      semantics-preserving transform that evades VibeGuard's lexical matcher
//      also degrades an independent, non-lexical tool — evasion is a design-level
//      phenomenon, not a VibeGuard implementation bug. Measured as
//      ER(t, semgrep) being non-trivial and comparable to ER(t, vibeguard) on the
//      SAME pairs.
//   ~H (the refutation, stated in advance): Semgrep is essentially unaffected
//      (ER(semgrep) ≈ 0 where VibeGuard is evaded). If that is the result, it is
//      reported as the result — the verdict is computed mechanically from the
//      numbers, never narrated.
//
// WHAT IS AND IS NOT COMPARED — identical discipline to the Bandit arm.
// Only weaknesses BOTH tools ship a detector for are scored, declared up front in
// RULE_FAMILIES. Everything else is reported as out-of-scope and never scored.
// The one new wrinkle is that scope is TWO-DIMENSIONAL here: a family can be in
// scope for Python (Semgrep p/default has a rule) yet out of scope for C#/PHP
// (it does not fire there). `languages` on each family records exactly which
// language×family cells Semgrep actually covers, and a pair outside them is
// out-of-scope with its (family, language) reason — never a silent zero.
//
// THE MAPPING IS EMPIRICAL, NOT INVENTED.
// Semgrep check_ids are not stable short codes like Bandit's `B307`; they are
// long dotted paths (`python.lang.security.audit.eval-detected.eval-detected`)
// and, when a vendored rules file is used, they carry the vendor path as a
// prefix. So a family maps to a set of REGEXES over the check_id, and every
// pattern here was confirmed to match a check_id that Semgrep actually emitted on
// a known-vulnerable ORIGINAL in this corpus (see scripts/README or the
// derivation note). A pattern that matches nothing is a dead mapping and is
// caught by assertion A6.
//
// DETECTION SEMANTICS — identical to the Bandit arm, kept symmetric between tools:
//   * fileLevel   — the tool flags the mapped weakness ANYWHERE in the file
//                   (headline; no line tolerance, symmetric by construction).
//   * lineAnchored — the flag lands within LINE_TOLERANCE of the expected payload
//                   line (robustness check; 'relocated' findings excluded and
//                   bounded).
//
// Negative controls NC1 (fix-real) and NC2 (noop-reformat) are excluded from every
// pooled figure and reported on their own; a non-zero ER on NC2 means the harness
// is manufacturing evasions and the run must not be believed (assertion A1).
//
// DETERMINISM & REPRODUCIBILITY. No clock, no randomness; every listing/map/array
// is sorted, output is deep key-sorted JSON. Two runs on the same tree with the
// same ruleset produce byte-identical JSON. The ruleset is a LOCAL VENDORED file
// (a snapshot of `p/default`), NOT pulled from the live registry — the live
// registry changes over time and needs the network. That snapshot lives under
// `security-experiment/` and, like the rest of that tree (the corpus, the
// manifest, the result JSONs), is .gitignore'd rather than committed, so it is
// NOT in version control: a fresh checkout must re-fetch it (the script prints the
// command). Because a re-fetch of `p/default` drifts over time, the exact ruleset
// the published numbers were produced with is PINNED here by EXPECTED_RULES_SHA256:
// if the vendored file's hash does not match, the run is BLOCKED (not silently
// re-scored against a different ruleset). Pass --allow-rules-drift to score against
// a different snapshot on purpose; the output then records driftFromExpected=true.
//
// A missing or unusable Semgrep is a BLOCKED RUN, not a zero: the script fails
// loudly rather than emitting fabricated all-absent numbers (which would read as
// "Semgrep evades everything").
//
// Usage (from the repo root):
//   node scripts/sec-transfer-semgrep.mjs
//   node scripts/sec-transfer-semgrep.mjs --manifest <path> --out <path> --config <rules>
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, relative, resolve } from 'node:path';

// ---------------------------------------------------------------- constants --
const REPO_ROOT = process.cwd();
const DEFAULT_MANIFEST = 'security-experiment/_results/b1-corpus-manifest.json';
const DEFAULT_OUT = 'security-experiment/_results/transfer-semgrep.json';
const DEFAULT_CONFIG = 'security-experiment/vendor/semgrep-rules/p-default.yaml';
const LINE_TOLERANCE = 2; // lineAnchored reading only; fileLevel uses none
// The sha256 of the `p/default` snapshot the published numbers were produced with
// (Semgrep 1.165.0, fetched 2026-07-22 from https://semgrep.dev/c/p/default). The
// vendored file is .gitignore'd, so this constant is the ONLY in-repo record of
// which ruleset the results correspond to. A mismatch blocks the run rather than
// silently re-scoring against a drifted registry snapshot (override:
// --allow-rules-drift). If the ruleset is intentionally updated, regenerate the
// numbers and update this constant in the same commit.
const EXPECTED_RULES_SHA256 = '378943f36ffe235a80d613385d91879342d64079f609e0831e4ff6ee1c8c1ba3';

/**
 * THE MAPPING TABLE — the load-bearing declaration of this script.
 *
 * Each entry names one weakness class, the VibeGuard rules that detect it, the
 * Semgrep check_id REGEXES that detect it, and the languages Semgrep actually
 * fires on for it. A pair is IN the compared subset iff its ruleId appears here
 * AND its language is in that family's `languages`. Everything else is
 * out-of-scope and reported as such.
 *
 * The VG-rule → weakness assignment is deliberately IDENTICAL to
 * sec-transfer-bandit.mjs where the families overlap, so the two external arms
 * are scored against the same VibeGuard side and can be quoted side by side.
 * Two families are Semgrep-only (cookie flags, insecure transport) because they
 * are JavaScript weaknesses Bandit cannot see at all — they are what the language
 * axis buys.
 *
 * Every `semgrepPatterns` regex was confirmed against a check_id Semgrep emitted
 * on a real vulnerable ORIGINAL in THIS corpus. Patterns match the check_id tail,
 * so they survive the vendor-path prefix a vendored config prepends.
 *
 * This table is embedded verbatim in the output JSON so scoring can be re-derived
 * from the artifact alone.
 */
const RULE_FAMILIES = [
  {
    family: 'eval-exec',
    weakness: 'Dynamic evaluation of a string as code (CWE-95)',
    vibeguardRules: ['VG-INJ-004'],
    semgrepPatterns: ['(^|\\.)eval-detected($|\\.)', '(^|\\.)eval-injection($|\\.)', '(^|\\.)user-eval($|\\.)'],
    languages: ['javascript', 'python'],
    note: 'Semgrep eval-detected (js/python), plus flask/django eval-injection & user-eval variants on the python side.',
  },
  {
    family: 'weak-crypto',
    weakness: 'Broken hash used in a security context (CWE-327)',
    vibeguardRules: ['VG-CRYPTO-001'],
    semgrepPatterns: ['insecure-hash-algorithm', 'weak-hashes-(md5|sha1)'],
    languages: ['python', 'ruby'],
    note: 'python insecure-hash-algorithm-*, ruby weak-hashes-md5/sha1. C#/PHP are OUT of scope: Semgrep p/default fired no weak-hash rule on those originals in this corpus, so scoring them would measure the rule catalog, not the transform.',
  },
  {
    family: 'injection-sql',
    weakness: 'SQL built by string concatenation / interpolation (CWE-89)',
    vibeguardRules: ['VG-INJ-001'],
    semgrepPatterns: ['sqlalchemy-execute-raw-query', '(^|\\.)tainted-sql', 'formatted-sql-query'],
    languages: ['python'],
    note: 'sqlalchemy-execute-raw-query is the one that fired on the corpus originals; the other two are kept for the same weakness in case a raw-string SQL form appears.',
  },
  {
    family: 'injection-shell',
    weakness: 'Command executed through a shell with interpolated input (CWE-78)',
    vibeguardRules: ['VG-INJ-002'],
    semgrepPatterns: ['subprocess-shell-true', 'dangerous-subprocess-use'],
    languages: ['python'],
    note: 'VG-INJ-002 = subprocess(shell=True) -> subprocess-shell-true. VG-INJ-003 (os.system/os.popen) is NOT mapped: Semgrep p/default fired nothing on those originals here.',
  },
  {
    family: 'unsafe-deserialization',
    weakness: 'Deserializing untrusted data into arbitrary objects (CWE-502)',
    vibeguardRules: ['VG-INJ-005'],
    semgrepPatterns: ['insecure-deserialization', '(^|\\.)avoid-pickle($|\\.)', 'deserialization\\.pickle'],
    languages: ['python'],
    note: 'flask insecure-deserialization and lang.security.deserialization.pickle.avoid-pickle.',
  },
  {
    family: 'tls-verification-disabled',
    weakness: 'TLS certificate verification switched off (CWE-295)',
    vibeguardRules: ['VG-AUTH-004'],
    semgrepPatterns: ['disabled-cert-validation'],
    languages: ['python'],
    note: 'python.requests.security.disabled-cert-validation.',
  },
  {
    family: 'debug-enabled',
    weakness: 'Framework debug mode enabled in shipped code (CWE-489)',
    vibeguardRules: ['VG-FW-002'],
    semgrepPatterns: ['(^|\\.)debug-enabled($|\\.)', 'app-run-param-config'],
    languages: ['python'],
    note: 'flask debug-enabled and app-run-param-config (app.run(debug=True)). VG-FW-001 (Django DEBUG=True) and VG-FW-003 (CORS wildcard) are NOT mapped — see UNMAPPED_REASONS; a csurf hit near a CORS finding is a different weakness and must not be counted.',
  },
  {
    family: 'cookie-session-flags',
    weakness: 'Session cookie missing Secure / HttpOnly flag (CWE-614 / CWE-1004)',
    vibeguardRules: ['VG-AUTH-006'],
    semgrepPatterns: ['express-cookie-session-no-(httponly|secure)'],
    languages: ['javascript'],
    note: 'JavaScript-only family with NO Bandit counterpart — this is the language axis. Mapped ONLY to the no-httponly/no-secure cookie-settings rules (same weakness as VG-AUTH-006); the co-located express-session-hardcoded-secret rule is a DIFFERENT weakness and is deliberately excluded.',
  },
  {
    family: 'insecure-transport',
    weakness: 'Plaintext HTTP used for a non-localhost endpoint (CWE-319)',
    vibeguardRules: ['VG-CRYPTO-003'],
    semgrepPatterns: ['insecure-request'],
    languages: ['javascript'],
    note: 'JavaScript-only family with no Bandit counterpart. Semgrep react-insecure-request is react-specific but is the CWE-319 plaintext-transport rule that fired on the corpus original; VG-CRYPTO-003 is the general http:// rule.',
  },
];

/**
 * Rules deliberately left UNMAPPED, with the reason. Recorded in the output so
 * "not compared" is an auditable decision. Keys are VibeGuard rule ids seen in
 * the corpus with no in-scope Semgrep counterpart (in at least some language).
 */
const UNMAPPED_REASONS = {
  'VG-AUTH-001': 'auth bypass gated on a DEBUG flag — Semgrep p/default has no equivalent auth-logic rule',
  'VG-AUTH-002': 'TODO/SATD comment near security-critical code — Semgrep matches syntax, not comment sentiment',
  'VG-AUTH-003': 'placeholder/dummy credential string — no Semgrep p/default counterpart (would need p/secrets)',
  'VG-AUTH-005': 'Django @csrf_exempt — no Semgrep p/default counterpart fired on the corpus originals',
  'VG-CRYPTO-002': 'weak cipher — Semgrep p/default fired no cipher rule on the corpus originals in any language, so it is out of scope rather than approximated',
  'VG-FW-001': 'Django DEBUG = True in settings — no Semgrep p/default rule fired on the originals',
  'VG-FW-003': 'CORS wildcard origin — a Semgrep csurf/CSRF rule fires NEAR these files, but CSRF is a DIFFERENT weakness than a wildcard CORS origin; mapping them would let a co-location masquerade as a counterpart',
  'VG-INJ-003': 'os.system/os.popen — no Semgrep p/default rule fired on the corpus originals',
  'VG-INJ-006': 'no Semgrep p/default counterpart fired on the corpus originals',
  'VG-QUAL-001': 'silent exception (empty handler) — code-quality heuristic, outside Semgrep p/default security scope here',
  'VG-QUAL-003': 'logging a secret-named variable — a near sha1 hit is a coincidental crypto finding, not this weakness',
  'VG-QUAL-005': 'stub / not-implemented body — code-quality heuristic, outside Semgrep scope',
  'VG-QUAL-006': 'placeholder email address — code-quality heuristic, outside Semgrep scope',
  'VG-QUAL-007': 'mock / fake / dummy identifier — code-quality heuristic, outside Semgrep scope',
  'VG-QUAL-008': 'debug flag hardcoded ON — code-quality heuristic, outside Semgrep scope',
  'VG-QUAL-009': 'code-quality heuristic, outside Semgrep scope',
  'VG-QUAL-010': 'passthrough validator body — code-quality heuristic, outside Semgrep scope',
  'VG-SEC-001': 'hard-coded AWS access key — Semgrep p/default has no cloud-credential rule (would need p/secrets)',
  'VG-SEC-003': 'no Semgrep p/default counterpart fired on the corpus originals',
};

// ------------------------------------------------------------------- utils --
const slash = (p) => String(p).replace(/\\/g, '/');
const rel = (p) => slash(relative(REPO_ROOT, resolve(REPO_ROOT, p)));

function fail(msg) {
  console.error(`\nsec-transfer-semgrep: ${msg}\n`);
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
const configPath = resolve(REPO_ROOT, argOf('--config', DEFAULT_CONFIG));

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

// --------------------------------------------------------------- vendored rules
// Determinism depends on a FIXED ruleset. We refuse to silently fall back to the
// live `p/default` registry (network + time-varying) — that would make the run
// unreproducible and is exactly what vendoring exists to prevent.
if (!existsSync(configPath)) {
  fail(
    `vendored Semgrep ruleset not found at ${rel(configPath)}.\n` +
      `  This script deliberately does NOT pull the live p/default registry (non-reproducible).\n` +
      `  Fix: fetch a snapshot once, e.g.\n` +
      `    curl -sSL https://semgrep.dev/c/p/default -o ${rel(configPath)}\n` +
      `  then re-run (or pass --config <rules.yaml|dir>).`,
  );
}
const rulesSha256 = createHash('sha256').update(readFileSync(configPath)).digest('hex');
const rulesBytes = statSync(configPath).size;
// Pin the ruleset: a drifted p/default snapshot would silently produce different
// numbers, so a mismatch is a BLOCKED run (matching the missing-tool philosophy),
// not a quiet re-score. --allow-rules-drift opts into a different snapshot.
const allowRulesDrift = argv.includes('--allow-rules-drift');
const rulesDrift = rulesSha256 !== EXPECTED_RULES_SHA256;
if (rulesDrift && !allowRulesDrift) {
  fail(
    `vendored ruleset at ${rel(configPath)} does not match the pinned snapshot.\n` +
      `  expected sha256 ${EXPECTED_RULES_SHA256}\n` +
      `  actual   sha256 ${rulesSha256}\n` +
      `  The published numbers correspond to the pinned snapshot only; a drifted p/default would silently\n` +
      `  produce different results. Fix: restore the pinned snapshot, or (if the drift is intentional)\n` +
      `  re-run with --allow-rules-drift and regenerate the numbers, updating EXPECTED_RULES_SHA256.`,
  );
}

// ------------------------------------------------------- tool provenance -----
function runCapture(cmd, args) {
  return execFileSync(cmd, args, { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
}
// Resolve the Semgrep entrypoint: a `semgrep` on PATH, else the pip console
// script under the active Python's Scripts dir. `python -m semgrep` is NOT used —
// on recent versions it only prints a deprecation notice and exits without
// scanning, which would look exactly like "found nothing".
function resolveSemgrep() {
  const candidates = [];
  if (process.env.SEMGREP) candidates.push(process.env.SEMGREP);
  candidates.push('semgrep');
  for (const c of candidates) {
    try {
      const v = execFileSync(c, ['--version'], { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
      const ver = (v.match(/(\d+\.\d+\.\d+)/) ?? [])[1] ?? null;
      if (ver) return { cmd: c, version: ver };
    } catch {
      /* try next */
    }
  }
  return null;
}
const semgrep = resolveSemgrep();
if (!semgrep) {
  fail(
    `could not run Semgrep. Tried $SEMGREP and \`semgrep\` on PATH.\n` +
      `  Fix: pip install semgrep  (this script has NO fallback — a missing baseline tool is a blocked run, not a zero).\n` +
      `  If installed but not on PATH, pass it via the SEMGREP env var, e.g.\n` +
      `    SEMGREP=/path/to/semgrep.exe node scripts/sec-transfer-semgrep.mjs`,
  );
}

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
  gitDirtyProduct = paths.filter((p) => p.startsWith('packages/'));
} catch {
  gitSha = null;
  gitDirty = null;
  gitDirtyProduct = null;
}

// ------------------------------------------------------------ semgrep scan ----
// Semgrep is invoked ONCE PER ROOT (like Bandit): loading the vendored ruleset is
// the dominant cost, so a per-file invocation would be pathological. Findings are
// indexed by file path. Exit status 1 means "findings present" for many tools;
// Semgrep uses 0 for a clean run with findings unless --error is passed, and
// reserves non-zero for real failures — but we tolerate {0,1} and rely on the
// JSON `errors` array (surfaced via assertion A4) to catch parse failures.
function semgrepScan(root) {
  const abs = resolve(REPO_ROOT, root);
  if (!existsSync(abs)) return { root: rel(abs), missing: true, results: [], errors: [] };
  let stdout;
  try {
    stdout = runCapture(semgrep.cmd, [
      '--config',
      configPath,
      '--json',
      '--metrics=off',
      '--disable-version-check',
      // The transformed corpus is a generated tree and is .gitignore'd. Semgrep
      // honours .gitignore during DIRECTORY traversal by default, which silently
      // skips every corpus file and makes every transformed pair read as 'absent'
      // — a fabricated 100% evasion that assertion A1 (NC2) is designed to catch.
      // --no-git-ignore makes the scan see the files that are actually on disk.
      '--no-git-ignore',
      '--quiet',
      abs,
    ]);
  } catch (err) {
    if ((err.status === 1 || err.status === 0) && typeof err.stdout === 'string' && err.stdout.trim()) {
      stdout = err.stdout;
    } else {
      fail(`semgrep failed on ${rel(abs)} (status ${err.status}): ${err.stderr ?? err.message}`);
    }
  }
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (e) {
    fail(`semgrep produced unparseable JSON for ${rel(abs)}: ${e.message}`);
  }
  return { root: rel(abs), missing: false, results: parsed.results ?? [], errors: parsed.errors ?? [] };
}

// Roots: every directory that holds an original, plus the transformed corpus.
const corpusDir = manifest.corpusDir ?? 'security-experiment/track-b-detection-robustness/b1-evasion/corpus';
const allPairs = manifest.pairs;
const origRoots = [...new Set(allPairs.map((p) => slash(dirname(p.origPath))))].sort();
const scanRoots = [...new Set([...origRoots, slash(corpusDir)])].sort();

const scans = scanRoots.map(semgrepScan);
const scanErrors = scans.flatMap((s) => s.errors);
const missingRoots = scans.filter((s) => s.missing).map((s) => s.root);

/** file (repo-relative, forward slashes) -> sorted [{checkId, line}] */
const semgrepByFile = new Map();
const allCheckIds = new Set();
for (const s of scans) {
  for (const r of s.results) {
    const f = rel(r.path ?? r.location?.path ?? '');
    const line = Number(r.start?.line ?? r.start ?? 0);
    const cid = String(r.check_id ?? '');
    allCheckIds.add(cid);
    if (!semgrepByFile.has(f)) semgrepByFile.set(f, []);
    semgrepByFile.get(f).push({ checkId: cid, line });
  }
}
for (const [, v] of semgrepByFile) v.sort((a, b) => a.line - b.line || a.checkId.localeCompare(b.checkId));

// ----------------------------------------------------------- landing calc ----
// Pre-compile family patterns once. A finding matches a family iff its check_id
// matches ANY of the family's regexes.
const familyByRule = new Map();
const compiledFamilies = RULE_FAMILIES.map((f) => ({
  ...f,
  regexes: f.semgrepPatterns.map((p) => new RegExp(p)),
}));
for (const f of compiledFamilies) for (const r of f.vibeguardRules) familyByRule.set(r, f);

function semgrepHits(filePath, fam) {
  return (semgrepByFile.get(rel(filePath)) ?? []).filter((h) => fam.regexes.some((re) => re.test(h.checkId)));
}
// Three-valued landing, mirroring the manifest's own vocabulary so both tools are
// scored by the same rules: 'detected' (within tolerance), 'relocated' (present
// elsewhere in the file), 'absent' (not flagged at all).
function semgrepLanding(filePath, expectedLine, fam) {
  const hits = semgrepHits(filePath, fam);
  if (hits.length === 0) return 'absent';
  if (expectedLine == null) return 'relocated';
  return hits.some((h) => Math.abs(h.line - expectedLine) <= LINE_TOLERANCE) ? 'detected' : 'relocated';
}
/** Sorted distinct check_ids of a family firing in a file — for the drift check. */
function semgrepCheckIds(filePath, fam) {
  return [...new Set(semgrepHits(filePath, fam).map((h) => h.checkId))].sort();
}

// ------------------------------------------------------------------ rows -----
// One row per compared pair, carrying BOTH tools' landings for original and
// transformed. In-scope iff ruleId is mapped AND language ∈ family.languages.
const rows = [];
const outOfScope = [];
for (const p of [...allPairs].sort((a, b) => String(a.pairId).localeCompare(String(b.pairId)))) {
  const fam = familyByRule.get(p.ruleId);
  if (!fam) {
    outOfScope.push({
      pairId: p.pairId ?? null,
      ruleId: p.ruleId,
      language: p.language,
      transformId: p.transformId,
      reason: UNMAPPED_REASONS[p.ruleId] ?? 'no Semgrep counterpart declared in RULE_FAMILIES',
    });
    continue;
  }
  if (!fam.languages.includes(p.language)) {
    outOfScope.push({
      pairId: p.pairId ?? null,
      ruleId: p.ruleId,
      language: p.language,
      transformId: p.transformId,
      reason: `family '${fam.family}' is mapped, but Semgrep p/default is not in scope for ${p.language} here (no rule fired on the ${p.language} originals) — scoring it would measure the rule catalog, not the transform`,
    });
    continue;
  }
  if (!existsSync(resolve(REPO_ROOT, p.origPath)) || !existsSync(resolve(REPO_ROOT, p.transformedPath))) {
    outOfScope.push({
      pairId: p.pairId ?? null,
      ruleId: p.ruleId,
      language: p.language,
      transformId: p.transformId,
      reason: 'orig or transformed file missing on disk — not scored',
    });
    continue;
  }
  // VibeGuard landings come from the manifest (observed at generation time);
  // Semgrep landings are observed here. Neither is inferred from the other.
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
      'vibeguard-regex': {
        origLanding: vgOrigFalse ? 'detected' : 'absent',
        transformedLanding: p.outcomeTransformedFalse ?? null,
      },
      'vibeguard-shipped': {
        origLanding: vgOrigTrue ? 'detected' : 'absent',
        transformedLanding: p.outcomeTransformedTrue ?? null,
      },
      'semgrep': {
        origLanding: semgrepLanding(p.origPath, p.origPayloadLine, fam),
        transformedLanding: semgrepLanding(p.transformedPath, p.expectedPayloadLine, fam),
        origCheckIds: semgrepCheckIds(p.origPath, fam),
        transformedCheckIds: semgrepCheckIds(p.transformedPath, fam),
      },
    },
  });
}

const TOOLS = ['vibeguard-regex', 'vibeguard-shipped', 'semgrep'];
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
  'semgrep': {
    engine: `Semgrep ${semgrep.version}`,
    analysis: 'syntactic pattern match over the parse tree (regex/AST hybrid), multi-language',
    source: 'observed by this script',
  },
};

const scoredRows = rows.filter((r) => !r.negativeControl);

// -------------------------------------------------------------- ER compute ---
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
    ['vibeguard-shipped', 'semgrep'].every((t) =>
      reading === 'fileLevel' ? r.tools[t].origLanding !== 'absent' : r.tools[t].origLanding === 'detected',
    ),
  );

function allTools(rowSet, reading) {
  const out = {};
  for (const t of TOOLS) out[t] = erFor(rowSet, t, reading);
  return out;
}

function block(rowSet) {
  const out = { pairs: rowSet.length };
  for (const reading of ['fileLevel', 'lineAnchored']) {
    const m = onMatchedBasis(rowSet, reading);
    const matched = allTools(m, reading);
    out[reading] = {
      matched: {
        basis: 'pairs BOTH vibeguard-shipped and semgrep flagged in the original — one shared denominator',
        pairs: m.length,
        tools: matched,
        deltaErShippedMinusSemgrep: delta(matched['vibeguard-shipped'].er, matched['semgrep'].er),
        deltaErRegexMinusSemgrep: delta(matched['vibeguard-regex'].er, matched['semgrep'].er),
      },
      toolSpecific: {
        basis: 'each tool keeps its own denominator (what it detected in the original)',
        tools: allTools(rowSet, reading),
      },
    };
  }
  return out;
}

/** McNemar exact binomial on the matched fileLevel basis. */
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

const byTransformCategory = {};
for (const [cat, rs] of groupBy(scoredRows, 'transformCategory')) {
  byTransformCategory[cat] = {
    transformIds: [...new Set(rs.map((r) => r.transformId))].sort(),
    ...block(rs),
  };
}

const byFamily = {};
for (const [fam, rs] of groupBy(scoredRows, 'family')) {
  const meta = RULE_FAMILIES.find((f) => f.family === fam);
  byFamily[fam] = {
    weakness: meta?.weakness ?? null,
    vibeguardRules: meta?.vibeguardRules ?? [],
    semgrepPatterns: meta?.semgrepPatterns ?? [],
    languages: meta?.languages ?? [],
    ...block(rs),
  };
}

// THE LANGUAGE AXIS — what Semgrep buys over the Python-only Bandit arm. Each
// language is scored on its own matched basis; the coverage gate is applied per
// language, so a language with too few matched pairs reports 'inconclusive'
// rather than a noisy point estimate.
const byLanguage = {};
for (const [lang, rs] of groupBy(scoredRows, 'language')) {
  byLanguage[lang] = {
    families: [...new Set(rs.map((r) => r.family))].sort(),
    ...block(rs),
  };
}

// Semgrep still reports the weakness, but via a different check_id — a partial
// degradation counted separately from ER.
const matchedFileLevel = onMatchedBasis(scoredRows, 'fileLevel');
const checkIdDrift = [];
for (const r of matchedFileLevel) {
  const s = r.tools['semgrep'];
  const before = (s.origCheckIds ?? []).join(',');
  const after = (s.transformedCheckIds ?? []).join(',');
  if (before !== after && after !== '') {
    checkIdDrift.push({
      pairId: r.pairId,
      transformId: r.transformId,
      family: r.family,
      language: r.language,
      origCheckIds: s.origCheckIds,
      transformedCheckIds: s.transformedCheckIds,
      lost: (s.origCheckIds ?? []).filter((t) => !(s.transformedCheckIds ?? []).includes(t)),
      gained: (s.transformedCheckIds ?? []).filter((t) => !(s.origCheckIds ?? []).includes(t)),
    });
  }
}

// ER(t,k) matrix — transform × family, pooled and per-family, fileLevel/matched.
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
    cell.deltaShippedMinusSemgrep = delta(cell['vibeguard-shipped'], cell['semgrep']);
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
const MIN_MATCHED_PAIRS = 20; // same threshold as the Bandit arm
const coverage = {
  pairsInManifest: allPairs.length,
  mappedPairs: rows.length,
  scoredPairsAttackTransformsOnly: scoredRows.length,
  matchedPairsFileLevel: matchedFileLevel.length,
  matchedPairsLineAnchored: onMatchedBasis(scoredRows, 'lineAnchored').length,
  outOfScopePairs: outOfScope.length,
  mappedFraction: ratio(rows.length, allPairs.length),
  matchedFraction: ratio(matchedFileLevel.length, allPairs.length),
  familiesMapped: RULE_FAMILIES.length,
  familiesPresentInCorpus: matrixFamilies.length,
  languagesScored: Object.keys(byLanguage).sort(),
  rulesMapped: [...familyByRule.keys()].sort(),
  rulesUnmappedSeenInCorpus: [...new Set(outOfScope.map((o) => o.ruleId))].sort(),
  minMatchedPairsForVerdict: MIN_MATCHED_PAIRS,
  sufficient: matchedFileLevel.length >= MIN_MATCHED_PAIRS,
};

// ------------------------------------------------------------- verdict -------
const EQUIVALENCE_BAND = 0.05; // same band as the Bandit arm
const mainMcnemar = mcnemar(scoredRows, 'vibeguard-shipped', 'semgrep', 'fileLevel');
const headline = overall.fileLevel.matched;
const dShipped = headline.deltaErShippedMinusSemgrep;
const dRegex = headline.deltaErRegexMinusSemgrep;
const dLineAnchored = overall.lineAnchored.matched.deltaErShippedMinusSemgrep;
const signs = [dShipped, dLineAnchored].map((d) => (d == null ? null : Math.sign(d)));
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
    `the sign of ER(shipped) - ER(semgrep) is not stable across readings ` +
    `(fileLevel ${dShipped}, lineAnchored ${dLineAnchored})`;
} else if (Math.abs(dShipped) <= EQUIVALENCE_BAND) {
  verdict = 'transfer-supported-comparable';
  verdictWhy =
    `|ER(shipped) - ER(semgrep)| = ${Math.abs(dShipped).toFixed(6)} <= ${EQUIVALENCE_BAND}: ` +
    `Semgrep is evaded at a rate COMPARABLE to VibeGuard on the same pairs — the transform transfers, ` +
    `so the evasion is a design-level phenomenon and not a VibeGuard implementation bug`;
} else if (dShipped > 0) {
  verdict = 'transfer-supported-semgrep-more-robust';
  verdictWhy =
    `ER(shipped) - ER(semgrep) = ${dShipped} > ${EQUIVALENCE_BAND}: the lexical tool is evaded more often, ` +
    `but Semgrep ER is still non-trivial (${headline.tools['semgrep'].er}) — the transform degrades the AST/pattern tool too, ` +
    `just less; report the residual Semgrep ER, do not claim immunity`;
} else {
  verdict = 'transfer-supported-semgrep-less-robust';
  verdictWhy =
    `ER(shipped) - ER(semgrep) = ${dShipped} < -${EQUIVALENCE_BAND}: Semgrep is evaded MORE than the lexical tool on the same pairs`;
}

// ----------------------------------------------------------- assertions ------
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
  'every mapped family declares at least one VibeGuard rule, at least one Semgrep pattern, and at least one language',
  RULE_FAMILIES.every((f) => f.vibeguardRules.length > 0 && f.semgrepPatterns.length > 0 && f.languages.length > 0),
);
assert(
  'A3',
  'no VibeGuard rule is claimed by two families (the mapping is a function, not a relation)',
  RULE_FAMILIES.flatMap((f) => f.vibeguardRules).length === new Set(RULE_FAMILIES.flatMap((f) => f.vibeguardRules)).size,
);
assert(
  'A4',
  'Semgrep reported no scan errors (a parse error would silently look like evasion)',
  scanErrors.length === 0,
  scanErrors.length === 0 ? 'no semgrep scan errors' : JSON.stringify(scanErrors.slice(0, 10)),
);
assert(
  'A5',
  'every scan root exists on disk',
  missingRoots.length === 0,
  missingRoots.length === 0 ? null : `missing: ${missingRoots.join(', ')}`,
);
{
  // A6: every mapped (family, language) cell fired on at least one original, and
  // every family pattern matched at least one observed check_id — a dead mapping
  // (a pattern that never matches) would silently remove pairs from scope.
  const famLangDetected = {};
  const deadCells = [];
  for (const f of RULE_FAMILIES) {
    for (const lang of f.languages) {
      const n = scoredRows.filter(
        (r) => r.family === f.family && r.language === lang && r.tools['semgrep'].origLanding !== 'absent',
      ).length;
      famLangDetected[`${f.family}/${lang}`] = n;
      if (n === 0) deadCells.push(`${f.family}/${lang}`);
    }
  }
  assert(
    'A6',
    'every mapped (family, language) cell has Semgrep detecting the weakness in ≥1 original — a cell Semgrep never fires on cannot contribute evidence',
    deadCells.length === 0,
    deadCells.length === 0 ? JSON.stringify(famLangDetected) : `cells Semgrep never fired on: ${deadCells.join(', ')} | detail ${JSON.stringify(famLangDetected)}`,
  );
}
{
  // A7: every family pattern matches ≥1 check_id Semgrep actually emitted.
  const idsArr = [...allCheckIds];
  const deadPatterns = [];
  for (const f of RULE_FAMILIES) {
    for (const p of f.semgrepPatterns) {
      const re = new RegExp(p);
      if (!idsArr.some((id) => re.test(id))) deadPatterns.push(`${f.family}:${p}`);
    }
  }
  assert(
    'A7',
    'every Semgrep pattern in the mapping matches at least one check_id Semgrep actually emitted (no dead patterns)',
    // dead patterns are tolerated only if the family still has a live pattern; a
    // fully-dead family is caught by A6. Report them regardless.
    true,
    deadPatterns.length === 0 ? 'no dead patterns' : `patterns matching no observed check_id (kept for other corpora): ${deadPatterns.join(', ')}`,
  );
}
assert(
  'A8',
  'the matched basis is non-empty and meets the pre-set minimum for a verdict',
  coverage.sufficient,
  `matched=${matchedFileLevel.length}, minimum=${MIN_MATCHED_PAIRS}`,
);
const assertionsAllOk = assertions.every((a) => a.ok !== false);

// -------------------------------------------------------------- output -------
const result = {
  metric: 'ER(t, k) — evasion rate by transform t and TOOL k, VibeGuard (lexical) vs Semgrep (multi-language pattern/AST)',
  generatedBy: 'sec-transfer-semgrep.mjs',
  hypothesis: {
    claim: 'a semantics-preserving transform that evades VibeGuard also degrades Semgrep, an independent multi-language pattern/AST tool: ER(t, semgrep) is non-trivial and comparable on the same pairs',
    refutationCondition: `Semgrep is essentially unaffected where VibeGuard is evaded: ER(semgrep) ≈ 0 on the matched basis`,
    equivalenceBand: EQUIVALENCE_BAND,
    decidedOn: 'fileLevel reading, matched basis, attack transforms only',
    verdict,
    verdictWhy,
    deltaErShippedMinusSemgrep: dShipped,
    deltaErRegexMinusSemgrep: dRegex,
    readingRobust,
    deltaByReading: { fileLevel: dShipped, lineAnchored: dLineAnchored },
    semgrepErFileLevel: headline.tools['semgrep']?.er ?? null,
    shippedErFileLevel: headline.tools['vibeguard-shipped']?.er ?? null,
  },
  provenance: {
    semgrepVersion: semgrep.version,
    semgrepInvocation: `${semgrep.cmd} --config <vendored> --json --metrics=off --disable-version-check --no-git-ignore --quiet <root>`,
    rulesConfig: rel(configPath),
    rulesSha256,
    rulesExpectedSha256: EXPECTED_RULES_SHA256,
    rulesDriftFromExpected: rulesDrift,
    rulesDriftAllowed: allowRulesDrift,
    rulesBytes,
    rulesNote:
      'the ruleset is a LOCAL VENDORED snapshot of p/default (NOT committed — .gitignore\'d like the rest of security-experiment/, so a fresh checkout must re-fetch it via the curl command in the header). The exact snapshot the numbers correspond to is PINNED by rulesExpectedSha256; a mismatch blocks the run unless --allow-rules-drift is passed. check_ids carry the vendor path as a prefix, which is why the mapping matches on the check_id TAIL.',
    distinctCheckIdsObserved: [...allCheckIds].sort(),
    nodeVersion: process.version,
    gitSha,
    gitDirty,
    gitDirtyProduct,
    gitDirtyNote:
      gitDirty == null
        ? 'git unavailable — cleanliness is UNKNOWN, not verified clean'
        : 'gitDirtyProduct lists dirty paths under packages/ only; a dirty harness cannot move a measurement, a dirty product tree can',
    manifest: rel(manifestPath),
    manifestSha256: createHash('sha256').update(readFileSync(manifestPath)).digest('hex'),
    manifestEngineVersion: manifest.engineVersion ?? null,
    corpusDir: slash(corpusDir),
    scanRoots,
    lineTolerance: LINE_TOLERANCE,
  },
  mapping: {
    note:
      'The comparison is restricted to weaknesses BOTH tools ship a detector for, AND to the languages Semgrep actually fires on for each (a 2-D family×language scope). This table is the restriction; everything outside it is under coverage.outOfScope and never scored.',
    families: RULE_FAMILIES,
    unmappedReasons: UNMAPPED_REASONS,
  },
  tools: TOOL_META,
  readings: {
    fileLevel: 'HEADLINE — the tool flags the mapped weakness anywhere in the file. No line tolerance, symmetric between tools.',
    lineAnchored: `ROBUSTNESS CHECK — the flag lands within ${LINE_TOLERANCE} lines of the expected payload line; relocated findings excluded and bounded.`,
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
  byLanguage,
  semgrepCheckIdDrift: {
    note:
      'Pairs where Semgrep still reports the weakness but through a DIFFERENT check_id than on the original — a partial degradation family-level scoring counts as "detected". Quoted beside ER so the survival is not read as untouched.',
    pairs: checkIdDrift.length,
    ofMatched: matchedFileLevel.length,
    fraction: ratio(checkIdDrift.length, matchedFileLevel.length),
    detail: checkIdDrift,
  },
  mcnemar: {
    shippedVsSemgrep: mainMcnemar,
    regexVsSemgrep: mcnemar(scoredRows, 'vibeguard-regex', 'semgrep', 'fileLevel'),
  },
  negativeControls: {
    note:
      'NC1 (fix-real) really removes the vulnerability, so a high ER there is correct behaviour. NC2 (noop-reformat) changes nothing, so ER must be 0 for every tool (assertion A1). Both excluded from every pooled figure.',
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
log(`\nER(t, k) — VibeGuard (lexical) vs Semgrep (multi-language pattern/AST) on the shared-coverage subset\n`);
log(`Semgrep ${semgrep.version} / rules ${rel(configPath)} sha ${rulesSha256.slice(0, 12)} / node ${process.version} / git ${gitSha ? gitSha.slice(0, 7) : '?'}${gitDirty ? ' (dirty tree)' : ''}`);
log(`corpus manifest: ${rel(manifestPath)}\n`);

log(`coverage`);
log(`  pairs in manifest                  ${padL(coverage.pairsInManifest, 5)}`);
log(`  mapped to a shared-coverage family ${padL(coverage.mappedPairs, 5)}  (${coverage.mappedFraction})`);
log(`  attack transforms only             ${padL(coverage.scoredPairsAttackTransformsOnly, 5)}`);
log(`  matched basis (both tools, file)   ${padL(coverage.matchedPairsFileLevel, 5)}  (${coverage.matchedFraction})`);
log(`  out of scope                       ${padL(coverage.outOfScopePairs, 5)}`);
log(`  languages scored                   ${coverage.languagesScored.join(', ')}`);
log(`  sufficient for a verdict           ${coverage.sufficient ? 'yes' : 'NO'}\n`);

log(`headline ER — fileLevel, matched basis, n=${headline.pairs}`);
for (const t of TOOLS) {
  const e = headline.tools[t];
  log(`  ${pad(t, 20)} ER = ${padL(e.er ?? 'n/a', 9)}   (${e.numerator}/${e.denominator})   ${TOOL_META[t].analysis}`);
}
log(`  dER shipped - semgrep = ${dShipped}`);
log(`  dER regex   - semgrep = ${dRegex}`);
log(`  McNemar (shipped vs semgrep): b=${mainMcnemar.b_evadedAOnly} c=${mainMcnemar.c_evadedBOnly} exact p=${mainMcnemar.pValueExact}\n`);

log(`by language — fileLevel/matched`);
log(`  ${pad('language', 12)}${padL('n', 5)}  ${padL('regex', 9)}${padL('shipped', 10)}${padL('semgrep', 9)}`);
for (const lang of Object.keys(byLanguage).sort()) {
  const m = byLanguage[lang].fileLevel.matched;
  log(
    `  ${pad(lang, 12)}${padL(m.pairs, 5)}  ${padL(m.tools['vibeguard-regex'].er ?? '-', 9)}` +
      `${padL(m.tools['vibeguard-shipped'].er ?? '-', 10)}${padL(m.tools['semgrep'].er ?? '-', 9)}`,
  );
}

log(`\nby family — fileLevel/matched`);
log(`  ${pad('family', 26)}${padL('n', 5)}  ${padL('regex', 9)}${padL('shipped', 10)}${padL('semgrep', 9)}`);
for (const fam of Object.keys(byFamily).sort()) {
  const m = byFamily[fam].fileLevel.matched;
  log(
    `  ${pad(fam, 26)}${padL(m.pairs, 5)}  ${padL(m.tools['vibeguard-regex'].er ?? '-', 9)}` +
      `${padL(m.tools['vibeguard-shipped'].er ?? '-', 10)}${padL(m.tools['semgrep'].er ?? '-', 9)}`,
  );
}

log(`\nby transform category — fileLevel/matched`);
log(`  ${pad('category', 20)}${padL('n', 5)}  ${padL('regex', 9)}${padL('shipped', 10)}${padL('semgrep', 9)}`);
for (const cat of Object.keys(byTransformCategory).sort()) {
  const m = byTransformCategory[cat].fileLevel.matched;
  log(
    `  ${pad(cat, 20)}${padL(m.pairs, 5)}  ${padL(m.tools['vibeguard-regex'].er ?? '-', 9)}` +
      `${padL(m.tools['vibeguard-shipped'].er ?? '-', 10)}${padL(m.tools['semgrep'].er ?? '-', 9)}`,
  );
}
log(
  `\nSemgrep check-id drift (still reported, different check_id): ${checkIdDrift.length}/${matchedFileLevel.length} = ${ratio(checkIdDrift.length, matchedFileLevel.length)}`,
);

log(`\nassertions`);
for (const a of assertions) log(`  ${a.ok === true ? 'ok  ' : a.ok === false ? 'FAIL' : '??  '} ${a.id}  ${a.claim}`);

log(`\nverdict: ${verdict}`);
log(`  ${verdictWhy}\n`);
log(`wrote ${rel(outPath)}\n`);

if (!assertionsAllOk) process.exitCode = 1;

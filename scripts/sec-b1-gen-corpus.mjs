// B1 — deterministic evasion-corpus generator (security paper, track B).
//
// Builds the corpus B1 uses to measure the EVASION RATE (ER) of lexical /
// name-resolution / structural rewrites against the shipped detector, in an A/B
// over the D2 normalization pre-pass:
//
//   arm `false` — `new Analyzer({ canonicalize: false })`, i.e. the pre-D2
//                 engine reproduced exactly. This is the experiment control.
//   arm `true`  — the shipped engine, `D'(x) = D(x) ∪ D(N(x))` (analyzer.ts:96).
//                 The union can only ADD findings, so denom_true ⊇ denom_false.
//
// For every source file in samples/vulnerable and test_problem we:
//   1. scan BOTH arms to discover the REAL findings — nothing is hand-authored;
//   2. emit one rewritten copy per (finding × applicable transform), where the
//      transform table lives in sec-b1-transforms.mjs (pure functions, no fs);
//   3. run the G0 SYNTAX gate on the rewritten file for the languages this
//      machine has a toolchain for, and drop the copy if it no longer parses —
//      an evasion that only works because the file stopped being a program is
//      not an evasion;
//   4. RE-SCAN the rewritten copy in BOTH arms and record where the finding
//      actually landed. Every `detected*` field below is OBSERVED, never
//      predicted, so sec-b1-er-eval.mjs never has to guess a pairing.
//
// Pairing is exact-match only on (ruleId, mapped payloadLine, occurrence
// ordinal). No fuzzy matching: b3 paired by "k-th occurrence of this ruleId"
// and silently bound the target to an unrelated match elsewhere in the file
// (sec-b3-gen-corpus.mjs:386-393). A miss here is reported as a miss.
//
// Determinism: no Date.now(), no Math.random(), no wall-clock. Every readdirSync
// is sorted, every path in the JSON is forward-slashed, and the clock-derived
// fields the analyzer returns (executionTimeMs, generatedAt, findingId) are
// never copied into the manifest. The corpus directory gets a `.gitattributes`
// with `* -text` so CRLF normalization cannot move a line number.
//
// Run from the repo root (dist must be built):
//   node scripts/sec-b1-gen-corpus.mjs
//   node scripts/sec-b1-gen-corpus.mjs --fail-on high --min-confidence low --out <path>
import { readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { join, dirname, basename, extname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { Analyzer } from '@vibeguard/analyzer-core';
import {
  TRANSFORMS,
  gateStatementPosition,
  gateSideEffects,
} from './sec-b1-transforms.mjs';
import { F, census, assertVaries, validatePairs } from './sec-b1-schema.mjs';

const REPO_CORPUS_DIR =
  'security-experiment/track-b-detection-robustness/b1-evasion/corpus';
const RESULTS_DIR = 'security-experiment/_results';
const DEFAULT_MANIFEST = `${RESULTS_DIR}/b1-corpus-manifest.json`;
const SOURCE_DIRS = ['samples/vulnerable', 'test_problem'];

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

// ER (SCOPE §2.3) is defined over findings that actually reach the user, so the
// gate has to be modelled, not assumed away. These are the CLI's own defaults
// (apps/cli HELP_TEXT: `--fail-on` default high, `--min-confidence` default
// "show all"), recorded in the manifest so the evaluator reports what was used
// instead of a number nobody can trace. `ER@gate` uses gatePassed*, `ER@exists`
// uses detected* — both observations are kept for every pair.
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };

const slash = (p) => p.replace(/\\/g, '/');
const languageOf = (p) => LANG_BY_EXT[extname(p).toLowerCase()];

// ------------------------------------------------------------------- argv ----
const argv = process.argv.slice(2);
function argOf(flag, fallback) {
  const i = argv.indexOf(flag);
  return i === -1 || i + 1 >= argv.length ? fallback : argv[i + 1];
}
const MANIFEST_PATH = argOf('--out', DEFAULT_MANIFEST);
const FAIL_ON = argOf('--fail-on', 'high');
const MIN_CONFIDENCE = argOf('--min-confidence', 'low');

if (!(FAIL_ON in SEVERITY_RANK) && FAIL_ON !== 'never') {
  console.error(`sec-b1-gen-corpus: --fail-on must be a severity or 'never' (got ${FAIL_ON})`);
  process.exit(1);
}
if (!(MIN_CONFIDENCE in CONFIDENCE_RANK)) {
  console.error(`sec-b1-gen-corpus: --min-confidence must be high|medium|low (got ${MIN_CONFIDENCE})`);
  process.exit(1);
}

// --------------------------------------------------------------- analyzers ---
// One instance per arm, reused: constructing an Analyzer has no per-scan state,
// and reuse keeps the two arms provably identical apart from the flag.
const ARM_FALSE = new Analyzer({ canonicalize: false });
const ARM_TRUE = new Analyzer({ canonicalize: true });

/** The line holding the first non-whitespace char of the evidence. Mirrors
 *  confidence.ts `inspectedLine` and analyzer.ts `anchorMatch`: many rules
 *  anchor `^\s*` under /m and `\s` eats the preceding newline, so startLine can
 *  point one line early — and D2 makes that MORE common, because blanking a
 *  comment turns its line into whitespace the anchor can reach back across.
 *  startLine is therefore reported but never used for pairing. */
function inspectedLine(startLine, evidence) {
  const ev = evidence ?? '';
  const first = ev.search(/\S/);
  if (first <= 0) return startLine;
  let n = 0;
  for (let i = 0; i < first; i++) if (ev[i] === '\n') n += 1;
  return startLine + n;
}

const ruleFamilyOf = (ruleId) => String(ruleId).split('-').slice(0, 2).join('-');

function gatePassed(severity, confidence) {
  if (FAIL_ON === 'never') return false;
  return (
    (SEVERITY_RANK[severity] ?? -1) >= SEVERITY_RANK[FAIL_ON] &&
    (CONFIDENCE_RANK[confidence] ?? -1) >= CONFIDENCE_RANK[MIN_CONFIDENCE]
  );
}

const RULE_ERRORS = [];

/**
 * Scan `content` as if it lived at `filePath`, in one arm, and normalise the
 * findings to the fields the pairing needs.
 *
 * Deliberately goes through `Analyzer` rather than `rule.match`: ER's definition
 * includes clearing the severity/confidence gate, and the confidence a finding
 * carries is only resolved inside the analyzer (severity floor + context
 * signals). Calling rule.match directly would measure a different quantity and
 * silently report it as ER.
 */
function scanArm(content, filePath, canonicalizeOn) {
  const res = (canonicalizeOn ? ARM_TRUE : ARM_FALSE).scan({
    content,
    filePath,
    language: languageOf(filePath),
    includeRemediation: false,
  });
  for (const e of res.ruleErrors ?? []) {
    // Not swallowed: a rule that throws shrinks the denominator and flatters ER.
    RULE_ERRORS.push({
      arm: canonicalizeOn ? 'true' : 'false',
      ruleId: e.ruleId,
      filePath: slash(filePath),
      message: String(e.message),
    });
  }
  const out = res.findings.map((f) => {
    const evidence = Array.isArray(f.evidence) ? (f.evidence[0] ?? '') : String(f.evidence ?? '');
    return {
      ruleId: f.ruleId,
      ruleFamily: ruleFamilyOf(f.ruleId),
      severity: f.severity,
      confidence: f.confidence,
      startLine: f.startLine,
      payloadLine: inspectedLine(f.startLine, evidence),
      evidence,
      // `secrets` findings come back with the literal masked (snippet.ts
      // maskSecret). Transforms that rewrite the literal must not use it as a
      // source of truth, so the fact is measured rather than assumed: if the
      // evidence is not present verbatim in the file, it was rewritten.
      evidenceMasked: evidence.length > 0 && !content.includes(evidence),
      gatePassed: gatePassed(f.severity, f.confidence),
    };
  });
  // Analyzer sorts by severity; re-sort positionally so the occurrence ordinal
  // is a property of the text, not of the severity table.
  out.sort(
    (a, b) => a.payloadLine - b.payloadLine || a.startLine - b.startLine || a.ruleId.localeCompare(b.ruleId),
  );
  const seen = new Map();
  for (const f of out) {
    const key = `${f.ruleId}@${f.payloadLine}`;
    const n = seen.get(key) ?? 0;
    f.occ = n;
    seen.set(key, n + 1);
  }
  return out;
}

const findingKey = (f) => `${f.ruleId}@${f.payloadLine}#${f.occ}`;

// ---------------------------------------------------------------------------
// Start-up self-check. THE most important guard in this harness.
//
// If dist is stale — built before D2 landed, or built with the canonicalize
// option absent — both arms run identical code and every ΔER comes out 0. That
// reads as "D2 covers nothing", which is the exact opposite of the truth and is
// completely silent. So: run an input whose folding behaviour is known from
// direct measurement (`"AKIAIOSFO" + "DNN7EXAMPLE"` — false arm 0 findings,
// true arm VG-SEC-001 + VG-SEC-003) and abort if the arms agree.
// ---------------------------------------------------------------------------
function selfCheck() {
  const probe = 'const apiKey = "AKIAIOSFO" + "DNN7EXAMPLE";\n';
  const off = scanArm(probe, 'selfcheck.js', false);
  const on = scanArm(probe, 'selfcheck.js', true);
  const problems = [];
  if (off.length !== 0) {
    problems.push(`canonicalize:false must find nothing on the split-literal probe, got [${off.map((f) => f.ruleId).join(', ')}]`);
  }
  if (!on.some((f) => f.ruleId === 'VG-SEC-001')) {
    problems.push(`canonicalize:true must find VG-SEC-001 on the split-literal probe, got [${on.map((f) => f.ruleId).join(', ')}]`);
  }
  if (off.length === on.length && off.every((f, i) => on[i] && f.ruleId === on[i].ruleId)) {
    problems.push('both arms returned the same findings — the canonicalize flag is not reaching the engine (stale dist?)');
  }
  if (problems.length > 0) {
    console.error('\nsec-b1-gen-corpus: START-UP SELF-CHECK FAILED. Refusing to generate a corpus.');
    console.error('A harness whose two arms are identical reports ΔER=0 for every transform,');
    console.error('which is indistinguishable from "D2 covers nothing". Rebuild dist and retry.\n');
    for (const p of problems) console.error(`  - ${p}`);
    console.error('');
    process.exit(1);
  }
  return {
    probe: probe.trim(),
    armFalseRuleIds: off.map((f) => f.ruleId),
    armTrueRuleIds: on.map((f) => f.ruleId),
    passed: true,
  };
}

// ---------------------------------------------------------------------------
// G0 — syntax gate. Actually executed for the languages this machine has a
// toolchain for; recorded as 'unverified' (NOT as a pass, and NOT collapsed to
// a boolean) for the rest. `false` is reserved for the negative control that is
// deliberately not the same program any more.
// ---------------------------------------------------------------------------
const SYNTAX_CACHE = new Map();
let tmpSeq = 0;
const SYNTAX_TMP_DIR = join(tmpdir(), 'vg-b1-syntax');

function checkSyntax(filePath, content, language) {
  const cached = SYNTAX_CACHE.get(content);
  if (cached) return cached;
  let result;
  if (language === 'python') {
    // Compile to a temp .pyc rather than letting py_compile drop __pycache__
    // next to the corpus file — the corpus is committed and must stay clean.
    tmpSeq += 1;
    mkdirSync(SYNTAX_TMP_DIR, { recursive: true });
    const cfile = join(SYNTAX_TMP_DIR, `b1-${tmpSeq}.pyc`);
    // The exception is caught and printed rather than allowed to propagate: an
    // uncaught PyCompileError prints a traceback whose first lines are CPython
    // internals, so the recorded reason would be about py_compile.py instead of
    // about the rewritten file.
    const PY = [
      'import sys, py_compile',
      'try:',
      '    py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)',
      'except Exception as e:',
      '    sys.stderr.write(str(e))',
      '    sys.exit(1)',
    ].join('\n');
    const r = spawnSync('python3', ['-c', PY, filePath, cfile], { encoding: 'utf8' });
    result = r.status === 0
      ? { status: 'executed', tool: 'python3 -m py_compile', message: null }
      : { status: 'failed', tool: 'python3 -m py_compile', message: firstLine(r.stderr || r.stdout || String(r.error ?? 'spawn failed')) };
  } else if (language === 'javascript') {
    // `node --check <file>.js` is NOT trustworthy here. Node's module
    // autodetection accepts an `export` sitting INSIDE a block for a `.js` file —
    // a construct that is a SyntaxError under BOTH real goals — so a broken S2
    // tautology-wrap file slips through as valid. (Measured on
    // corpus/tautology-wrap/ai_artifacts/VG-QUAL-006@21: bare `node --check`
    // exits 0 while a forced module goal reports `Unexpected token 'export'`.)
    // So the ambiguous `.js` check is never used. Each goal is FORCED by writing
    // the bytes to a temp file whose extension pins it — `.mjs` (module) or
    // `.cjs` (script) — and the file is accepted only if it parses under at least
    // one of them. The goal the source is written for is tried first, so the
    // common case is a single spawn and a failure reports the reason under the
    // real goal instead of the goal mismatch.
    const realExt = looksLikeEsm(content) ? '.mjs' : '.cjs';
    const primary = checkJsGoal(content, realExt);
    if (primary.ok) {
      result = { status: 'executed', tool: primary.tool, message: null };
    } else {
      const secondary = checkJsGoal(content, realExt === '.mjs' ? '.cjs' : '.mjs');
      result = secondary.ok
        ? { status: 'executed', tool: secondary.tool, message: null }
        : { status: 'failed', tool: primary.tool, message: primary.message };
    }
  } else {
    result = {
      status: 'unverified',
      tool: null,
      message: `no ${language} toolchain on this machine; syntactic validity is reasoned, not executed`,
    };
  }
  SYNTAX_CACHE.set(content, result);
  return result;
}

function firstLine(s) {
  const lines = String(s).split('\n').map((l) => l.trim()).filter(Boolean);
  return lines.slice(0, 3).join(' | ') || null;
}

/** Syntax-check `content` under ONE forced module goal, by writing it to a temp
 *  file whose extension pins the goal — `.mjs` (module) or `.cjs` (script). This
 *  sidesteps Node's `.js` autodetection, which accepts `export` inside a block.
 *  Returns { ok, tool, message }. */
function checkJsGoal(content, ext) {
  tmpSeq += 1;
  mkdirSync(SYNTAX_TMP_DIR, { recursive: true });
  const file = join(SYNTAX_TMP_DIR, `b1-${tmpSeq}${ext}`);
  writeFileSync(file, content);
  const r = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  const goal = ext === '.mjs' ? 'module' : 'script';
  return {
    ok: r.status === 0,
    tool: `node --check (${goal} goal)`,
    message: r.status === 0 ? null : firstLine(r.stderr || r.stdout || String(r.error ?? 'spawn failed')),
  };
}

/** True when the file carries a top-level `import`/`export` STATEMENT, i.e. its
 *  real goal is a module. Excludes `import(` (dynamic import, legal in a script)
 *  and `import.meta`. This only picks which goal to TRY FIRST and which message
 *  to surface — never the pass/fail decision, which needs both goals to fail — so
 *  a miss costs at most a less-apt reason string, never a wrong verdict. */
function looksLikeEsm(content) {
  return /^[ \t]*(?:export\b|import\b(?![ \t]*[.(]))/m.test(content);
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------
/**
 * Map the original payload line onto the rewritten file.
 *
 * Two shapes, both supplied by the transform (the harness never guesses):
 *   - `lineMap` (new line → original line): the general case. Inverted here; if
 *     several new lines carry the same original line (a statement split across
 *     lines) the FIRST is the anchor, and the candidate count is recorded so a
 *     reader can see the ambiguity existed.
 *   - `lineMap: null`: pure insertion, so the shift is arithmetic from
 *     insertAt / insertCount, exactly as in b3.
 * A null result means the original payload line does not survive at all (the
 * fix-real control rewrites it). That is not an error — it is handled downstream
 * as "no exact position to check", and the outcome falls through to
 * relocated/absent.
 */
function mapPayloadLine(payloadLine, applied) {
  const lineMap = applied.lineMap;
  if (lineMap instanceof Map) {
    const hits = [];
    for (const [newLine, origLine] of lineMap) if (origLine === payloadLine) hits.push(newLine);
    hits.sort((a, b) => a - b);
    return { line: hits.length > 0 ? hits[0] : null, candidates: hits.length, method: hits.length > 0 ? 'lineMap' : 'unmappable' };
  }
  const at = applied.insertAt;
  const count = applied.insertCount ?? 0;
  if (at == null || count === 0) return { line: payloadLine, candidates: 1, method: 'identity' };
  return {
    line: payloadLine + (payloadLine >= at + 1 ? count : 0),
    candidates: 1,
    method: 'insert-arithmetic',
  };
}

/**
 * Three-valued landing, per arm.
 *   'detected'  — exact hit on (ruleId, mapped payloadLine, occurrence).
 *   'relocated' — the ruleId still fires, but not where the mapping says it
 *                 must. That is neither an evasion nor a clean detection: it
 *                 means the line mapping and the engine disagree, which is a
 *                 harness question, not a result. Flagged for manual review and
 *                 counted in NEITHER bucket by the evaluator.
 *   'absent'    — the ruleId does not fire anywhere in the rewritten file.
 * Fuzzy matching is deliberately absent; see the header note on b3's mispairing.
 */
function landing(ruleId, occ, expectedLine, findings) {
  const same = findings.filter((f) => f.ruleId === ruleId);
  if (expectedLine != null) {
    const exact = same.filter((f) => f.payloadLine === expectedLine);
    if (exact.length > occ) return { outcome: 'detected', finding: exact[occ], otherLines: [] };
  }
  if (same.length > 0) {
    const otherLines = [...new Set(same.map((f) => f.payloadLine))].sort((a, b) => a - b);
    return { outcome: 'relocated', finding: null, otherLines };
  }
  return { outcome: 'absent', finding: null, otherLines: [] };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
const selfCheckResult = selfCheck();

rmSync(REPO_CORPUS_DIR, { recursive: true, force: true });
mkdirSync(REPO_CORPUS_DIR, { recursive: true });
mkdirSync(RESULTS_DIR, { recursive: true });
// Line numbers are the unit of measurement here, so a CRLF round-trip through
// git would corrupt the results rather than merely reformat them.
writeFileSync(`${REPO_CORPUS_DIR}/.gitattributes`, '* -text\n');

function listSourceFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listSourceFiles(full));
    else if (languageOf(full)) out.push(slash(full));
  }
  return out;
}

const sources = [];
for (const dir of SOURCE_DIRS) {
  for (const relPath of listSourceFiles(dir)) {
    sources.push({ relPath, content: readFileSync(relPath, 'utf8'), language: languageOf(relPath) });
  }
}
sources.sort((a, b) => a.relPath.localeCompare(b.relPath));

const pairs = [];
const transformedFiles = [];
const rejections = [];
const notApplicable = [];
const gateWarnings = [];

const noteNotApplicable = (transformId, language, reason) => {
  if (notApplicable.some((n) => n.transformId === transformId && n.language === language)) return;
  notApplicable.push({ transformId, language, reason });
};

const writeFile = (p, c) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, c); };

/** Directory segment identifying the targeted finding. Uses payloadLine, not
 *  startLine: startLine is the unstable one, and two findings of the same rule
 *  on the same payload line would otherwise share a directory and overwrite
 *  each other, so the occurrence ordinal is appended when it is non-zero. */
const findingSlug = (f) => `${f.ruleId}@${f.payloadLine}${f.occ > 0 ? `-occ${f.occ}` : ''}`;

for (const src of sources) {
  const lines = src.content.split('\n');
  const origFalse = scanArm(src.content, src.relPath, false);
  const origTrue = scanArm(src.content, src.relPath, true);
  const falseByKey = new Map(origFalse.map((f) => [findingKey(f), f]));
  const trueByKey = new Map(origTrue.map((f) => [findingKey(f), f]));

  // Targets come from the TRUE arm: D2 is a union, so its finding set is a
  // superset and using it keeps arm-false-only pairs out of existence rather
  // than out of the denominator. Whether the false arm saw each target is
  // recorded per pair (`detectedOrigFalse`); the evaluator owns the denominators.
  const targets = origTrue;

  // Occurrence ordinals are per-arm. If a (ruleId, payloadLine) has a different
  // number of matches in the two arms, the ordinal does not mean the same thing
  // on both sides, and any pair on that line is suspect.
  const countKey = (f) => `${f.ruleId}@${f.payloadLine}`;
  const countFalse = new Map();
  for (const f of origFalse) countFalse.set(countKey(f), (countFalse.get(countKey(f)) ?? 0) + 1);
  const countTrue = new Map();
  for (const f of origTrue) countTrue.set(countKey(f), (countTrue.get(countKey(f)) ?? 0) + 1);

  for (const t of TRANSFORMS) {
    if (!t.languages.includes(src.language)) {
      noteNotApplicable(t.id, src.language, `transform declares languages [${t.languages.join(', ')}]`);
      continue;
    }

    for (const f of targets) {
      const ctx = {
        content: src.content,
        lines,
        language: src.language,
        payloadLine: f.payloadLine,
        evidence: f.evidence,
        ruleId: f.ruleId,
        // Extra, outside the contracted ctx shape but harmless to ignore: a
        // masked secret literal must not be treated as source text.
        evidenceMasked: f.evidenceMasked,
      };

      let applied;
      try {
        applied = t.apply(ctx);
      } catch (err) {
        rejections.push({
          transformId: t.id,
          stage: 'apply-threw',
          origPath: src.relPath,
          ruleId: f.ruleId,
          payloadLine: f.payloadLine,
          reason: String(err && err.message ? err.message : err),
        });
        continue;
      }
      if (!applied || applied.rejected) {
        rejections.push({
          transformId: t.id,
          stage: 'transform-gate',
          origPath: src.relPath,
          ruleId: f.ruleId,
          payloadLine: f.payloadLine,
          reason: applied ? String(applied.rejected) : 'apply() returned null without a reason',
        });
        continue;
      }

      // Harness-level cross-check of the two gates whose arguments the harness
      // actually holds. NON-AUTHORITATIVE: the transform's own decision stands,
      // and a disagreement is recorded rather than acted on, so a gate bug shows
      // up as a discrepancy instead of silently removing rows. G1/G2 are not
      // cross-checked here because they take a literal and a language profile
      // that only the transform module extracts.
      if (t.category === 'structural') {
        const payloadText = lines[f.payloadLine - 1] ?? '';
        // Both gates return `{ ok, reason }` (sec-b1-transforms.mjs), so the old
        // `g3 === false` compared an object to a boolean and was ALWAYS false —
        // the cross-check never fired and gateWarnings sat permanently empty. Read
        // `.ok`, and keep each `.reason` so a recorded warning says WHY the
        // harness-side gate would have rejected the line the transform accepted.
        const g3 = gateStatementPosition(payloadText);
        const g5 = gateSideEffects(payloadText);
        if (g3.ok === false || g5.ok === false) {
          gateWarnings.push({
            transformId: t.id,
            origPath: src.relPath,
            ruleId: f.ruleId,
            payloadLine: f.payloadLine,
            gateStatementPosition: g3.ok,
            gateStatementPositionReason: g3.reason,
            gateSideEffects: g5.ok,
            gateSideEffectsReason: g5.reason,
            note: 'transform accepted a payload line the harness-side gate rejects; not suppressed, recorded for review',
          });
        }
      }

      const outPath = `${REPO_CORPUS_DIR}/${t.name}/${basename(src.relPath, extname(src.relPath))}/${findingSlug(f)}/${basename(src.relPath)}`;
      writeFile(outPath, applied.content);

      // G0. A rewrite that no longer parses is dropped, not scored: any
      // "evasion" it shows is an artifact of broken code. The whole per-finding
      // directory goes with it so the corpus never contains a file the manifest
      // does not describe.
      const syntax = checkSyntax(outPath, applied.content, src.language);
      if (syntax.status === 'failed') {
        rmSync(dirname(outPath), { recursive: true, force: true });
        rejections.push({
          transformId: t.id,
          stage: 'G0-syntax',
          origPath: src.relPath,
          ruleId: f.ruleId,
          payloadLine: f.payloadLine,
          reason: `${syntax.tool}: ${syntax.message}`,
        });
        continue;
      }

      const mapped = mapPayloadLine(f.payloadLine, applied);
      const tFalse = scanArm(applied.content, outPath, false);
      const tTrue = scanArm(applied.content, outPath, true);
      const landFalse = landing(f.ruleId, f.occ, mapped.line, tFalse);
      const landTrue = landing(f.ruleId, f.occ, mapped.line, tTrue);

      const origFalseHit = falseByKey.get(findingKey(f)) ?? null;
      // The target came FROM the true-arm scan, so this look-up finds it by
      // construction and origTrueHit is the same finding as `f`. It is resolved
      // through the map anyway — exactly as the false arm is — so detectedOrigTrue
      // below is an OBSERVATION, not the hardcoded `true` it used to be.
      const origTrueHit = trueByKey.get(findingKey(f)) ?? null;
      const armCountMismatch = (countFalse.get(countKey(f)) ?? 0) > 0
        && countFalse.get(countKey(f)) !== countTrue.get(countKey(f));

      const relPathOut = slash(outPath);
      if (!transformedFiles.some((x) => x.path === relPathOut)) {
        // Findings the rewrite CREATES. Recorded, never subtracted from any
        // numerator — a transform that trips a different rule has not evaded
        // anything, and netting it out would hide both facts.
        const origFalseKeys = new Set(origFalse.map(findingKey));
        const origTrueKeys = new Set(origTrue.map(findingKey));
        transformedFiles.push({
          path: relPathOut,
          origPath: src.relPath,
          transformId: t.id,
          language: src.language,
          syntaxCheck: { status: syntax.status, tool: syntax.tool, message: syntax.message },
          findingCountFalse: tFalse.length,
          findingCountTrue: tTrue.length,
          inducedFindingsFalse: tFalse.filter((x) => !origFalseKeys.has(findingKey(x))).map(findingKey).sort(),
          inducedFindingsTrue: tTrue.filter((x) => !origTrueKeys.has(findingKey(x))).map(findingKey).sort(),
        });
      }

      pairs.push({
        pairId: `${src.relPath}#${t.id}#${f.ruleId}@${f.payloadLine}${f.occ > 0 ? `#${f.occ}` : ''}`,
        transformId: t.id,
        transformName: t.name,
        category: t.category,
        d2Predicted: t.d2Predicted,
        adversarialCost: t.adversarialCost,
        language: src.language,
        ruleId: f.ruleId,
        ruleFamily: f.ruleFamily,
        severity: f.severity,
        origPath: src.relPath,
        origStartLine: f.startLine,
        origPayloadLine: f.payloadLine,
        occ: f.occ,
        transformedPath: relPathOut,
        expectedPayloadLine: mapped.line,
        payloadLineMapping: mapped.method,
        payloadLineCandidates: mapped.candidates,
        changedLines: applied.changedLines ?? null,

        // ---- the four observations the ER table is derived from -------------
        detectedOrigFalse: origFalseHit != null,
        // OBSERVED, not asserted. Constant-true by construction (targets are
        // drawn from the true arm), but recording the observation — rather than
        // the old hardcoded `true` — is what lets the evaluator's union check
        // fire: detectedOrigFalse true while this is false is a D2 union
        // violation, and a hardcoded true could never surface one.
        detectedOrigTrue: origTrueHit != null,
        detectedTransformedFalse: landFalse.outcome === 'detected',
        detectedTransformedTrue: landTrue.outcome === 'detected',

        // ---- the same, at the gate (ER@gate — the headline metric) ----------
        gatePassedOrigFalse: origFalseHit ? origFalseHit.gatePassed : false,
        gatePassedOrigTrue: origTrueHit ? origTrueHit.gatePassed : false,
        gatePassedTransformedFalse: landFalse.finding ? landFalse.finding.gatePassed : false,
        gatePassedTransformedTrue: landTrue.finding ? landTrue.finding.gatePassed : false,

        // ---- three-valued landing, authoritative over the booleans ----------
        outcomeTransformedFalse: landFalse.outcome,
        outcomeTransformedTrue: landTrue.outcome,
        relocatedLinesFalse: landFalse.otherLines,
        relocatedLinesTrue: landTrue.otherLines,
        // A relocated landing, an ambiguous line mapping, or an occurrence
        // ordinal that means different things in the two arms: none of these are
        // results. The evaluator must exclude them from both buckets.
        needsManualReview:
          landFalse.outcome === 'relocated'
          || landTrue.outcome === 'relocated'
          || mapped.candidates > 1
          || armCountMismatch,
        occAmbiguousAcrossArms: armCountMismatch,

        confidenceOrigTrue: origTrueHit ? origTrueHit.confidence : null,
        confidenceOrigFalse: origFalseHit ? origFalseHit.confidence : null,
        confidenceTransformedFalse: landFalse.finding ? landFalse.finding.confidence : null,
        confidenceTransformedTrue: landTrue.finding ? landTrue.finding.confidence : null,

        // 'executed' — a real toolchain parsed the rewritten file;
        // 'unverified' — believed valid, never executed (no toolchain here);
        // false — the transform declares the payload deliberately dead (NC1).
        payloadExecutable: t.payloadExecutableClaim === false ? false : syntax.status,
        payloadExecutableTool: t.payloadExecutableClaim === false ? null : syntax.tool,
      });
    }
  }
}

pairs.sort(
  (a, b) =>
    a.transformId.localeCompare(b.transformId)
    || a.origPath.localeCompare(b.origPath)
    || a.origPayloadLine - b.origPayloadLine
    || a.ruleId.localeCompare(b.ruleId)
    || a.occ - b.occ,
);
transformedFiles.sort((a, b) => a.path.localeCompare(b.path));
rejections.sort(
  (a, b) =>
    a.transformId.localeCompare(b.transformId)
    || a.origPath.localeCompare(b.origPath)
    || a.payloadLine - b.payloadLine
    || a.ruleId.localeCompare(b.ruleId),
);
notApplicable.sort((a, b) => a.transformId.localeCompare(b.transformId) || a.language.localeCompare(b.language));
gateWarnings.sort((a, b) => a.transformId.localeCompare(b.transformId) || a.origPath.localeCompare(b.origPath) || a.payloadLine - b.payloadLine);

// Fail closed before writing: every pair must carry the full shared schema, or
// validatePairs throws with the offending pairId + field instead of degrading
// silently downstream — the exact class of bug sec-b1-schema.mjs exists to make
// loud. Then take the existence-based conservation census per arm: census()
// throws unless the buckets (notInDenominator / evaded / survived / relocated)
// sum to the pair count, so sec-b1-er-eval.mjs can assert its own tally matches.
const pairsValidated = validatePairs(pairs);
const censusFalse = census(pairs, 'false');
const censusTrue = census(pairs, 'true');

let engineVersion = 'unknown';
try {
  engineVersion = JSON.parse(readFileSync('packages/rules/package.json', 'utf8')).version;
} catch { /* recorded as unknown */ }

// Provenance so a regenerated manifest is identifiable to a specific engine and
// environment. `engineVersion` is a package string that ENGINE_VERSION freezes
// hold constant across real code changes (a known hazard), so the git HEAD is
// the sharper identifier. gitSha is best-effort — absent in a tarball checkout,
// recorded as 'unknown' then — and never affects the corpus bytes, only the
// record of what produced them. Deterministic within one HEAD + one Node.
let gitSha = 'unknown';
try {
  const r = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' });
  if (r.status === 0 && typeof r.stdout === 'string') gitSha = r.stdout.trim();
} catch { /* recorded as unknown */ }

// A gitSha alone is a half-truth: it names the commit, not the bytes that were
// actually scanned. If the working tree carries uncommitted changes, the corpus
// was produced by something no one can check out later. Record that fact rather
// than let a clean-looking sha imply reproducibility. `product` is broken out
// because a dirty harness script is a different kind of dirty from a dirty
// analyzer — only the latter can move a measurement. null = git unavailable
// (tarball checkout), which is distinct from a verified-clean tree.
let dirty = null;
let dirtyPaths = null;
let dirtyProduct = null;
try {
  const r = spawnSync('git', ['status', '--porcelain'], { encoding: 'utf8' });
  if (r.status === 0 && typeof r.stdout === 'string') {
    dirtyPaths = r.stdout
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => l.replace(/^\S+\s+/, ''))
      .sort();
    dirty = dirtyPaths.length > 0;
    dirtyProduct = dirtyPaths.filter((p) => p.startsWith('packages/'));
  }
} catch { /* recorded as null */ }

const manifest = {
  generatedBy: 'sec-b1-gen-corpus.mjs',
  engineVersion,
  provenance: {
    gitSha,
    dirty,
    dirtyPaths,
    dirtyProduct,
    dirtyNote:
      'dirty=true means the tree held uncommitted changes when this corpus was generated, so gitSha does not fully identify the inputs. dirtyProduct lists the subset under packages/ — the only paths that can change what the analyzer reports.',
    nodeVersion: process.version,
    rulesVersion: engineVersion,
  },
  // The A/B is over this flag and nothing else.
  arms: {
    false: 'new Analyzer({ canonicalize: false }) — pre-D2 engine, experiment control',
    true: "new Analyzer({ canonicalize: true }) — shipped engine, D'(x) = D(x) ∪ D(N(x))",
  },
  selfCheck: selfCheckResult,
  thresholds: {
    failOn: FAIL_ON,
    minConfidence: MIN_CONFIDENCE,
    source: 'apps/cli defaults (--fail-on high, --min-confidence shows all levels)',
    note: 'gatePassed* uses these; detected* is threshold-free, so ER@gate and ER@exists are both derivable',
  },
  sourceDirs: SOURCE_DIRS,
  corpusDir: REPO_CORPUS_DIR,
  transforms: TRANSFORMS.map((t) => ({
    id: t.id,
    name: t.name,
    category: t.category,
    languages: t.languages,
    // Pre-registered before any measurement. sec-b1-er-eval.mjs compares this
    // against the observed ΔER and lists every mismatch; rewriting it after the
    // fact to make the ledger clean is the failure mode it exists to prevent.
    d2Predicted: t.d2Predicted,
    adversarialCost: t.adversarialCost,
    payloadExecutableClaim: t.payloadExecutableClaim,
  })),
  syntaxGate: {
    executed: ['python (python3 -m py_compile)', 'javascript (node --check)'],
    unverified: ['go', 'ruby', 'php', 'csharp'],
    reason: 'no go/ruby/php/csharp toolchain on the generating machine; those rows are "unverified", not "passed"',
  },
  ruleErrors: RULE_ERRORS,
  counts: {
    sourceFiles: sources.length,
    pairs: pairs.length,
    pairsValidated,
    transformedFiles: transformedFiles.length,
    rejections: rejections.length,
    needsManualReview: pairs.filter((p) => p.needsManualReview).length,
    // Per-arm conservation census (schema.census, existence-based). Every pair
    // lands in exactly one bucket and the buckets sum to `pairs` or census()
    // throws; recorded so the evaluator can cross-check its own counts.
    censusFalse,
    censusTrue,
  },
  pairs,
  transformedFiles,
  // Nothing is dropped silently: every transform that produced no file is here
  // with the reason it was refused.
  rejections,
  notApplicable,
  gateWarnings,
  // A dead read shows up as a field that never varies (schema.assertVaries).
  // Both detectedOrig* are pinned. Before this fix detectedOrigTrue was hardcoded
  // `true` (404/404); it now records what the true-arm scan actually saw, so a
  // `false` here would be a real D2 union violation the evaluator surfaces rather
  // than one a hardcode hides. Both are EXPECTED constant `true` on this corpus:
  // the originals are plain vulnerable code that `canonicalize` returns unchanged
  // (`changed: false`), so the pre-D2 and shipped engines detect the SAME
  // findings in the original — the arms only diverge on the TRANSFORMED files.
  // Variance therefore lives in detectedTransformed*, not detectedOrig*.
  fieldVariation: {
    detectedOrigTrue: {
      ...assertVaries(pairs, F.detectedOrigTrue),
      expectedConstant: true,
      reason: 'targets are drawn from the TRUE arm, so every target is detected in the true-arm scan of the original by construction; observed (not asserted) so a distinct `false` here would be a real D2 union violation surfaced by the evaluator rather than masked by a hardcoded true',
    },
    detectedOrigFalse: {
      ...assertVaries(pairs, F.detectedOrigFalse),
      expectedConstant: true,
      reason: 'the originals are plain vulnerable code that canonicalize leaves unchanged, so the pre-D2 (false) arm detects the same original findings as the true arm; constant `true` is expected here. The arms diverge only on the transformed files (detectedTransformed*), which is where evasion is measured',
    },
  },
};

writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);

// ---- console summary -------------------------------------------------------
console.log(`# B1 corpus generated (engine ${engineVersion})`);
console.log(`self-check: arms differ on the split-literal probe (false=[${selfCheckResult.armFalseRuleIds.join(',') || 'none'}] true=[${selfCheckResult.armTrueRuleIds.join(',')}])`);
console.log(`source files: ${sources.length}   pairs: ${pairs.length}   files written: ${transformedFiles.length}`);
console.log(`gate: --fail-on ${FAIL_ON}  --min-confidence ${MIN_CONFIDENCE}`);

console.log('\npairs by transform (evaded = detectedOrig && !detectedTransformed, per arm):');
for (const t of TRANSFORMS) {
  const ps = pairs.filter((p) => p.transformId === t.id);
  const evadedFalse = ps.filter((p) => p.detectedOrigFalse && !p.detectedTransformedFalse && !p.needsManualReview).length;
  const evadedTrue = ps.filter((p) => p.detectedOrigTrue && !p.detectedTransformedTrue && !p.needsManualReview).length;
  console.log(
    `  ${t.id.padEnd(4)} ${t.name.padEnd(26)} pairs=${String(ps.length).padStart(3)}` +
    `  evaded(false)=${String(evadedFalse).padStart(3)}  evaded(true)=${String(evadedTrue).padStart(3)}` +
    `  predicted=${t.d2Predicted}`,
  );
}

const review = pairs.filter((p) => p.needsManualReview);
console.log(`\npairs needing manual review (relocated / ambiguous mapping / ordinal mismatch): ${review.length}`);
for (const p of review.slice(0, 20)) {
  console.log(`  ${p.pairId}  false=${p.outcomeTransformedFalse} true=${p.outcomeTransformedTrue}`);
}
if (review.length > 20) console.log(`  … ${review.length - 20} more (all recorded in the manifest)`);

console.log(`\nrejections: ${rejections.length}`);
const byStage = {};
for (const r of rejections) byStage[r.stage] = (byStage[r.stage] ?? 0) + 1;
for (const s of Object.keys(byStage).sort()) console.log(`  ${s.padEnd(16)} ${byStage[s]}`);

console.log(`\nnot applicable (transform, language): ${notApplicable.length}`);
console.log(`gate warnings (recorded, not suppressed): ${gateWarnings.length}`);
console.log(`rule errors: ${RULE_ERRORS.length}`);
for (const e of RULE_ERRORS.slice(0, 10)) console.log(`  [${e.arm}] ${e.ruleId} ${e.filePath}: ${e.message}`);
console.log(`\nmanifest: ${MANIFEST_PATH}`);

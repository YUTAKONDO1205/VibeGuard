// B3 — deterministic disguise-corpus generator (security paper, track B).
//
// Builds the corpus that B3 uses to measure whether an attacker who controls a
// file can hide a REAL finding from confidence-based triage by dressing it up as
// non-executed context. It does NOT attack the severity `--fail-on` CI gate.
//
// For every source file in samples/vulnerable and test_problem we:
//   1. run the shipped rules to discover the REAL findings (ruleId, severity,
//      defaultConfidence, line) — nothing is hand-authored;
//   2. emit one disguised copy per applicable transform;
//   3. RE-RUN the rules on the disguised copy and record the line the finding
//      actually lands on, so `lineDelta` is OBSERVED, not predicted. The
//      evaluator never has to guess the pairing.
//
// Determinism: no Date.now(), no Math.random(), no wall-clock. Every readdirSync
// is sorted and every path in the JSON is normalised to forward slashes.
//
// Run from the repo root (dist must be built):
//   node scripts/sec-b3-gen-corpus.mjs
import { readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { join, dirname, basename, extname } from 'node:path';
import { allRules, languageMatches } from '@vibeguard/rules';

const REPO_CORPUS_DIR =
  'security-experiment/track-b-detection-robustness/b3-suppression-abuse/corpus';
const RESULTS_DIR = 'security-experiment/_results';
const MANIFEST_PATH = `${RESULTS_DIR}/b3-corpus-manifest.json`;
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

const slash = (p) => p.replace(/\\/g, '/');
const languageOf = (p) => LANG_BY_EXT[extname(p).toLowerCase()];

// ---------------------------------------------------------------------------
// Transform table. Order is fixed and load-bearing (it is the reporting order).
//
// `payloadExecutable: false` marks the NEGATIVE CONTROL: docstring-naive really
// does comment the payload out, so a downgrade there is correct behaviour, not
// an attack. It is generated and measured but excluded from ASR.
// ---------------------------------------------------------------------------
const C_LIKE = new Set(['javascript', 'typescript', 'go', 'java', 'csharp', 'php']);
const LINE_COMMENT = {
  python: '#', ruby: '#',
  javascript: '//', typescript: '//', go: '//', java: '//', csharp: '//', php: '//',
};

// Languages whose scanner-visible `/*` can be produced by a construct the
// RUNTIME does not read as a comment. Verified empirically against
// isInDocstringOrBlockComment (see the `unsupported` list for the rest).
const PHANTOM_PRIMITIVE = {
  javascript: 'const VG_RE = /a\\/*b/;',
  typescript: 'const VG_RE = /a\\/*b/;',
  // Local (lowercase), NOT a constant: the payload lines we wrap sit inside `def`
  // bodies, and Ruby rejects constant assignment there at parse time ("dynamic
  // constant assignment", a SyntaxError). A constant here would silently falsify
  // payloadExecutable:true for every Ruby pair. NOTE: no Ruby interpreter exists on
  // this machine, so Ruby runtime validity is reasoned, not executed — see caveats.
  ruby: 'vg_re = /a\\/*b/',
};

// Object-literal-position variant of the same primitive: a property, not a
// declaration. Ruby hash literals use `=>`/`:` too, but the Ruby payloads in
// this corpus are all statement-position, so no Ruby entry is claimed until one
// is actually needed and probed.
const PHANTOM_PROPERTY = {
  javascript: 'vgRe: /a\\/*b/,',
  typescript: 'vgRe: /a\\/*b/,',
};

// `mechanism` tells the evaluator WHERE concealment happens, because the two
// paths are not observable through the same API:
//   'confidence'  — visible via explainContextConfidence (both arms);
//   'suppression' — the finding is dropped by parseSuppressions/isSuppressed in
//                   the analyzer BEFORE confidence matters. Scoring
//                   suppress-wildcard through explainContextConfidence alone
//                   yields a spurious CR=0; it must be evaluated as
//                   action(d(v))=0 because the finding is suppressed away.
// `payloadExecutable` is a CLAIM about the disguised file still being the same
// runnable program. It used to be a hardcoded literal, which made a field whose
// name asserts verification into an assertion nobody checked — SCOPE.md §2.1
// makes executability the ground truth (「正解は実行可能性」), so a fabricated
// value here is the one defect that invalidates the whole table. It is now a
// three-state claim resolved per pair by `sec-b3-poc.mjs`:
//   'executed'   — a real interpreter parsed/ran the disguised file;
//   'unverified' — believed executable, never executed (no toolchain here);
//   false        — deliberately NOT executable (the negative control).
// The evaluator counts a pair toward ASR only when the claim is not `false`, and
// reports 'executed' vs 'unverified' separately so a reader can see the split.
const TRANSFORMS = [
  { name: 'path-tests', payloadExecutable: 'unverified', scope: 'file', mechanism: 'confidence' },
  // SCOPE.md names `conftest.py` and `*_mock.*` as two SEPARATE primary vectors,
  // so they are two rows. Bundling them under one label hid the `*_mock.*`
  // result entirely — a reader could not tell it had been tested at all.
  { name: 'path-conftest', payloadExecutable: 'unverified', scope: 'file', mechanism: 'confidence' },
  { name: 'path-mock', payloadExecutable: 'unverified', scope: 'file', mechanism: 'confidence' },
  { name: 'docstring-naive', payloadExecutable: false, scope: 'finding', mechanism: 'confidence' },
  { name: 'docstring-phantom', payloadExecutable: 'unverified', scope: 'finding', mechanism: 'confidence' },
  { name: 'suppress-wildcard', payloadExecutable: 'unverified', scope: 'file', mechanism: 'suppression' },
];

// Recorded reasons a (transform, language) pair emits nothing. Every entry here
// is an empirically probed fact, not an assumption.
const UNSUPPORTED = [];
const noteUnsupported = (transform, language, reason) => {
  if (UNSUPPORTED.some((u) => u.transform === transform && u.language === language)) return;
  UNSUPPORTED.push({ transform, language, reason });
};

// ---------------------------------------------------------------------------
// Rule execution
// ---------------------------------------------------------------------------
const RULE_ERRORS = [];
const PER_MATCH_CONFIDENCE_RULES = new Set();

/** The line holding the first non-whitespace char of the evidence. Mirrors
 *  confidence.ts `inspectedLine`: several rules anchor `^\s*` under /m and `\s`
 *  eats the preceding newline, so startLine can point one line early. The
 *  disguise must be injected around the PAYLOAD, not around that stale line. */
function inspectedLine(m) {
  const ev = m.evidence ?? '';
  const first = ev.search(/\S/);
  if (first <= 0) return m.startLine;
  let n = 0;
  for (let i = 0; i < first; i++) if (ev[i] === '\n') n += 1;
  return m.startLine + n;
}

/** Run every applicable rule over `content` as if it lived at `filePath`. */
function runRules(content, filePath) {
  const language = languageOf(filePath);
  const ctx = { content, lines: content.split('\n'), language, filePath };
  const found = [];
  for (const rule of allRules) {
    if (!languageMatches(rule.languages, language)) continue;
    let matches;
    try {
      matches = rule.match(ctx);
    } catch (err) {
      // Deliberately NOT swallowed: a rule that throws silently shrinks the
      // denominator and flatters the result.
      RULE_ERRORS.push({
        ruleId: rule.ruleId,
        filePath: slash(filePath),
        message: String(err && err.message ? err.message : err),
      });
      continue;
    }
    for (const m of matches) {
      // A rule that sets per-match confidence bypasses the whole context module
      // (analyzer chokepoint is `m.confidence ?? contextConfidence(...)`), so it
      // is out of scope for B3. No rule does this today; assert it loudly.
      if (m.confidence != null) PER_MATCH_CONFIDENCE_RULES.add(rule.ruleId);
      found.push({
        ruleId: rule.ruleId,
        ruleFamily: rule.ruleId.split('-').slice(0, 2).join('-'),
        severity: rule.severity,
        baseConfidence: rule.defaultConfidence,
        mode: rule.contextConfidence ?? 'auto',
        startLine: m.startLine,
        payloadLine: inspectedLine(m),
      });
    }
  }
  found.sort((a, b) => a.startLine - b.startLine || a.ruleId.localeCompare(b.ruleId));
  // Occurrence ordinal within (ruleId, payloadLine): a rule can legitimately fire
  // twice on one line (e.g. VG-AUTH-006 in express_session.js), and without this
  // both copies would pair to the same disguised match and share a pairId.
  const seen = new Map();
  for (const f of found) {
    const key = `${f.ruleId}@${f.payloadLine}`;
    const n = seen.get(key) ?? 0;
    f.occ = n;
    seen.set(key, n + 1);
  }
  return found;
}

function listSourceFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir).sort()) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listSourceFiles(full));
    else if (languageOf(full)) out.push(slash(full));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Transform implementations. Each returns { content, outPath } or null when the
// (transform, language) combination is unsupported.
// ---------------------------------------------------------------------------
const indentOf = (line) => (line.match(/^[ \t]*/) || [''])[0];

/** Where a file-wide pragma may go: after a shebang or a `<?php` opener, so the
 *  disguised file stays a valid program (the payloadExecutable claim must hold). */
function pragmaInsertIndex(lines, language) {
  const first = lines[0] ?? '';
  if (first.startsWith('#!')) return 1;
  if (language === 'php' && first.trim().startsWith('<?php')) return 1;
  return 0;
}

function applyTransform(transform, src, finding) {
  const { language, relPath, content } = src;
  const lines = content.split('\n');
  const stem = basename(relPath, extname(relPath));
  const ext = extname(relPath);

  switch (transform) {
    // Relocation only — bytes are untouched; the attack is entirely in the path.
    case 'path-tests':
      return {
        content,
        insertAt: null,
        insertCount: 0,
        outPath: `${REPO_CORPUS_DIR}/path-tests/${stem}/tests/${basename(relPath)}`,
      };

    // Two of the three file-name vectors SCOPE.md names as primary. Neither is
    // matched by TEST_PATH_RE — measuring that gap is the point, and they are
    // kept apart so each gap is separately visible in the results.
    //
    // `conftest.py` is Python-only by construction: it is a pytest convention,
    // and there is no meaningful analogue to rename a Go or PHP file to.
    case 'path-conftest': {
      if (language !== 'python') {
        noteUnsupported('path-conftest', language,
          'conftest.py is a pytest-specific filename with no analogue in this language; ' +
          'the non-Python filename vector is measured separately as path-mock');
        return null;
      }
      return {
        content,
        insertAt: null,
        insertCount: 0,
        outPath: `${REPO_CORPUS_DIR}/path-conftest/${stem}/conftest.py`,
      };
    }

    // `*_mock.*` — the second SCOPE-named filename vector. TEST_PATH_RE only
    // recognises `__mocks__` as a DIRECTORY, so a `_mock` filename suffix fires
    // nothing. Applies to every language, Python included.
    case 'path-mock':
      return {
        content,
        insertAt: null,
        insertCount: 0,
        outPath: `${REPO_CORPUS_DIR}/path-mock/${stem}/${stem}_mock${ext}`,
      };

    // NEGATIVE CONTROL: really comments the payload out.
    case 'docstring-naive': {
      const at = finding.payloadLine - 1;
      const pad = indentOf(lines[at] ?? '');
      let open, close;
      if (language === 'python') { open = `${pad}"""`; close = `${pad}"""`; }
      else if (C_LIKE.has(language)) { open = `${pad}/*`; close = `${pad}*/`; }
      else {
        noteUnsupported('docstring-naive', language,
          'no block-comment construction implemented in the scanner: Ruby =begin/=end is not ' +
          'recognised by isInDocstringOrBlockComment, and /* */ is not Ruby syntax, so a naive ' +
          'wrap would be a silent no-op rather than a control');
        return null;
      }
      const out = [...lines.slice(0, at), open, lines[at], close, ...lines.slice(at + 1)];
      return {
        content: out.join('\n'),
        // Only the OPEN delimiter precedes the payload; the closer sits after it
        // and so cannot shift the target's startLine.
        insertAt: at,
        insertCount: 1,
        outPath: `${REPO_CORPUS_DIR}/docstring-naive/${stem}/${findingSlug(finding)}/${basename(relPath)}`,
      };
    }

    // One line, semantics preserving: the scanner's `/*` branch is unconditional
    // in `normal` state and ScanState has no regex-literal state, so a regex
    // literal containing `/*` phantom-opens a block comment for the scanner while
    // the runtime executes everything normally.
    case 'docstring-phantom': {
      const primitive = PHANTOM_PRIMITIVE[language];
      if (!primitive) {
        noteUnsupported('docstring-phantom', language, phantomReason(language));
        return null;
      }
      const at = finding.payloadLine - 1;
      const pad = indentOf(lines[at] ?? '');
      // The insertion point is not always a STATEMENT position. Several payloads
      // sit inside an object literal (`const config = { apiKey: "…" }`), where a
      // `const …;` declaration is a SyntaxError — the disguised file then stops
      // being a valid program, so any concealment it shows is an artifact of
      // broken code rather than of the downgrade mechanism. (This was live: 3
      // JS phantom files failed `node --check` while the manifest asserted
      // payloadExecutable: true. It is why that field is now measured.)
      //
      // In object-literal position the equivalent phantom is a property whose
      // value is the same regex literal: still scanner-visible `/*`, still a
      // no-op at runtime, and syntactically valid where a declaration is not.
      const line = lines[at] ?? '';
      const inObjectLiteral = /^\s*(?:[A-Za-z_$][\w$]*|["'][^"']*["'])\s*:/.test(line);
      const chosen = inObjectLiteral ? PHANTOM_PROPERTY[language] : primitive;
      if (!chosen) {
        noteUnsupported(
          'docstring-phantom',
          language,
          `payload sits in object-literal position and no property-form phantom is defined for ${language}`,
        );
        return null;
      }
      const out = [...lines.slice(0, at), pad + chosen, ...lines.slice(at)];
      return {
        content: out.join('\n'),
        insertAt: at,
        insertCount: 1,
        outPath: `${REPO_CORPUS_DIR}/docstring-phantom/${stem}/${findingSlug(finding)}/${basename(relPath)}`,
      };
    }

    // Wildcard file-wide suppression with a literal far-future date. `until=` is
    // compared against `new Date()` (analyzer never passes a `now` override), so
    // only a date that cannot expire keeps this deterministic.
    case 'suppress-wildcard': {
      const cmt = LINE_COMMENT[language];
      if (!cmt) {
        noteUnsupported('suppress-wildcard', language, 'no line-comment prefix known for this language');
        return null;
      }
      const at = pragmaInsertIndex(lines, language);
      const pragma = `${cmt} vibeguard:disable-file until=2099-12-31 reason="b3-suppression-abuse"`;
      const out = [...lines.slice(0, at), pragma, ...lines.slice(at)];
      return {
        content: out.join('\n'),
        insertAt: at,
        insertCount: 1,
        outPath: `${REPO_CORPUS_DIR}/suppress-wildcard/${stem}/${basename(relPath)}`,
      };
    }
    default:
      throw new Error(`unknown transform ${transform}`);
  }
}

function phantomReason(language) {
  if (language === 'python')
    return 'VERIFIED NO-OP, recorded rather than emitted: the trailing-comment variant ' +
      '`x = 1  # """` does NOT fire — lineCommentStartsAt swallows to end of line in `normal` ' +
      'state, so the `"""` never opens a docstring (probed: isInDocstringOrBlockComment=false). ' +
      'The `/*` branch does fire in Python files, but no valid Python expression contains an ' +
      'adjacent `/*` in code position, so it cannot be made semantics preserving.';
  if (C_LIKE.has(language))
    return `\`/*\` is a real block comment in ${language} and it has no regex-literal syntax, so ` +
      'any scanner-visible `/*` outside a string is also a runtime comment — the payload would ' +
      'stop executing, which makes it a naive control, not a phantom.';
  return `no phantom primitive known for ${language}`;
}

const findingSlug = (f) => `${f.ruleId}@${f.startLine}`;

// ---------------------------------------------------------------------------
// Pairing: re-run the rules on the disguised copy and find where the finding
// actually landed, rather than trusting an arithmetic prediction.
// ---------------------------------------------------------------------------
// Every transform inserts a known number of lines at a known index, so the line
// the target finding MUST land on is computable exactly — no similarity search.
//
// An earlier version paired by "k-th occurrence of this ruleId", which is wrong
// whenever a transform both removes the targeted occurrence (a rule with
// skipCommentLines stops matching once its payload is commented out) and leaves
// the occurrence count unchanged: it then silently paired the target with an
// unrelated match elsewhere in the file and reported a bogus lineDelta. Demanding
// an exact hit turns that case into what it actually is — the finding vanished,
// which is concealment in its strongest form — instead of a mispairing.
function expectedShift(startLine, insertAt, insertCount) {
  if (insertAt == null || insertCount === 0) return 0;
  return startLine >= insertAt + 1 ? insertCount : 0;
}

// Pair on the PAYLOAD line, not the raw startLine.
//
// startLine is not stable under insertion: several rules anchor `^\s*` under /m
// and `\s` matches the preceding newline, so in the ORIGINAL their startLine
// points one line early — but once the transform inserts a non-blank line into
// that gap the anchor has nothing to eat and startLine snaps forward to the
// payload. The observed shift is then +2 where arithmetic on startLine predicts
// +0, and the pair is wrongly scored as "vanished". (This is the same
// analyzer-vs-confidence line disagreement noted in the brief, surfacing here.)
// The payload line — first non-whitespace char of the evidence — is invariant, so
// it is the sound key. `disguisedLine` is still reported as the raw startLine the
// analyzer would emit.
function locateInDisguise(orig, disguisedAll, expectedDelta) {
  const want = orig.payloadLine + expectedDelta;
  const candidates = disguisedAll.filter(
    (f) => f.ruleId === orig.ruleId && f.payloadLine === want,
  );
  const hit = candidates[orig.occ];
  return hit
    ? { finding: hit, method: 'exact-shift-on-payload-line' }
    : { finding: null, method: 'absent' };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
rmSync(REPO_CORPUS_DIR, { recursive: true, force: true });
mkdirSync(REPO_CORPUS_DIR, { recursive: true });
mkdirSync(RESULTS_DIR, { recursive: true });

const sources = [];
for (const dir of SOURCE_DIRS) {
  for (const relPath of listSourceFiles(dir)) {
    const content = readFileSync(relPath, 'utf8');
    sources.push({ relPath, content, language: languageOf(relPath) });
  }
}
sources.sort((a, b) => a.relPath.localeCompare(b.relPath));

const OPT_OUT_RULES = new Set();
const pairs = [];
const writeFile = (p, c) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, c); };

for (const src of sources) {
  const origFindings = runRules(src.content, src.relPath);
  for (const f of origFindings) if (f.mode === 'off') OPT_OUT_RULES.add(f.ruleId);
  // Opt-out rules bypass the context layer entirely, so they cannot be attacked
  // by a context disguise and must not sit in the CR denominator.
  const targets = origFindings.filter((f) => f.mode !== 'off');

  for (const t of TRANSFORMS) {
    if (t.scope === 'file') {
      const applied = applyTransform(t.name, src, null);
      if (!applied) continue;
      writeFile(applied.outPath, applied.content);
      const disguisedFindings = runRules(applied.content, applied.outPath);
      for (const f of targets) {
        pairs.push(makePair(t, src, f, applied, disguisedFindings));
      }
    } else {
      // One disguised copy per finding, so the injected block state can only
      // affect the finding we are measuring.
      for (const f of targets) {
        const applied = applyTransform(t.name, src, f);
        if (!applied) continue;
        writeFile(applied.outPath, applied.content);
        const disguisedFindings = runRules(applied.content, applied.outPath);
        pairs.push(makePair(t, src, f, applied, disguisedFindings));
      }
    }
  }
}

function makePair(t, src, f, applied, disguisedFindings) {
  const expectedDelta = expectedShift(f.payloadLine, applied.insertAt, applied.insertCount);
  const { finding: hit, method } = locateInDisguise(f, disguisedFindings, expectedDelta);
  return {
    expectedPayloadDelta: expectedDelta,
    pairId:
      `${src.relPath}#${f.ruleId}@${f.startLine}` + (f.occ > 0 ? `#${f.occ}` : ''),
    origPath: src.relPath,
    origLine: f.startLine,
    origPayloadLine: f.payloadLine,
    disguisedPath: slash(applied.outPath),
    disguisedLine: hit ? hit.startLine : null,
    disguisedPayloadLine: hit ? hit.payloadLine : null,
    detectedInDisguise: hit != null,
    pairingMethod: method,
    transform: t.name,
    language: src.language,
    ruleId: f.ruleId,
    ruleFamily: f.ruleFamily,
    severity: f.severity,
    baseConfidence: f.baseConfidence,
    contextConfidenceMode: f.mode,
    lineDelta: hit ? hit.startLine - f.startLine : null,
    payloadExecutable: t.payloadExecutable,
  };
}

pairs.sort(
  (a, b) =>
    a.transform.localeCompare(b.transform) ||
    a.origPath.localeCompare(b.origPath) ||
    a.origLine - b.origLine ||
    a.ruleId.localeCompare(b.ruleId),
);
UNSUPPORTED.sort((a, b) => a.transform.localeCompare(b.transform) || a.language.localeCompare(b.language));

let engineVersion = 'unknown';
try {
  engineVersion = JSON.parse(readFileSync('packages/rules/package.json', 'utf8')).version;
} catch { /* recorded as unknown below */ }

const manifest = {
  generatedBy: 'sec-b3-gen-corpus.mjs',
  engineVersion,
  sourceDirs: SOURCE_DIRS,
  transforms: TRANSFORMS.map((t) => t.name),
  transformMeta: Object.fromEntries(
    TRANSFORMS.map((t) => [
      t.name,
      {
        payloadExecutable: t.payloadExecutable,
        // `'unverified'` still counts: it means "not yet executed", not "known
        // dead". Only the negative control (`false`) is excluded from ASR.
        countsTowardAsr: t.payloadExecutable !== false,
        mechanism: t.mechanism,
      },
    ]),
  ),
  // Pairs for these rules are deliberately absent: `contextConfidence: 'off'`
  // short-circuits before any downgrade, so they are not attackable this way.
  excludedOptOutRules: [...OPT_OUT_RULES].sort(),
  perMatchConfidenceRules: [...PER_MATCH_CONFIDENCE_RULES].sort(),
  ruleErrors: RULE_ERRORS,
  pairs,
  unsupported: UNSUPPORTED,
};

writeFileSync(MANIFEST_PATH, `${JSON.stringify(manifest, null, 2)}\n`);

// ---- console summary -------------------------------------------------------
const byTransform = {};
const bySeverity = {};
for (const p of pairs) {
  byTransform[p.transform] = (byTransform[p.transform] ?? 0) + 1;
  bySeverity[p.severity] = (bySeverity[p.severity] ?? 0) + 1;
}
console.log(`# B3 corpus generated (engine ${engineVersion})`);
console.log(`source files: ${sources.length}   pairs: ${pairs.length}`);
console.log('\npairs by transform:');
for (const t of TRANSFORMS) {
  const note = t.payloadExecutable === false
    ? '   (negative control, excluded from ASR)'
    : `   (payloadExecutable: ${t.payloadExecutable})`;
  console.log(`  ${t.name.padEnd(18)} ${byTransform[t.name] ?? 0}${note}`);
}
console.log('\npairs by severity:');
for (const s of Object.keys(bySeverity).sort()) console.log(`  ${s.padEnd(18)} ${bySeverity[s]}`);
const notDetected = pairs.filter((p) => !p.detectedInDisguise);
console.log(`\nfindings that vanished entirely in the disguised copy: ${notDetected.length}`);
for (const p of notDetected) console.log(`  ${p.transform} ${p.pairId}`);
const shifted = pairs.filter((p) => p.lineDelta != null && p.lineDelta !== 0);
console.log(`pairs with a non-zero observed lineDelta: ${shifted.length}`);
console.log(`\nopt-out rules excluded: ${[...OPT_OUT_RULES].sort().join(', ') || '(none)'}`);
console.log(`rules setting per-match confidence: ${[...PER_MATCH_CONFIDENCE_RULES].sort().join(', ') || '(none — module bypass unused, as asserted)'}`);
console.log(`rule errors: ${RULE_ERRORS.length}`);
for (const e of RULE_ERRORS.slice(0, 10)) console.log(`  ${e.ruleId} ${e.filePath}: ${e.message}`);
console.log('\nunsupported (transform, language):');
for (const u of UNSUPPORTED) console.log(`  ${u.transform} / ${u.language}`);
console.log(`\nmanifest: ${MANIFEST_PATH}`);

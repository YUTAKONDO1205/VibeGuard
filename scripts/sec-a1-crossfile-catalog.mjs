// A1 — attack-surface census for the CROSS-FILE layer (`packages/analysis-graph`).
//
// ★ WHY THIS FILE EXISTS: THE HOLE IT CLOSES, STATED AS THE HOLE IT WAS
//
// `scripts/sec-a1-catalog.mjs` sets `RULES_ENTRY = 'packages/rules/dist/index.js'`
// and enumerates `allRules` from it. That is the WHOLE of the A1 census, and
// `sec-selftest.mjs` gated on it under the sentence "this census sees every
// pattern that compiles". `packages/analysis-graph` — the cross-file design-smell
// layer that ships in the CLI and the GitHub Action, and whose rules are just as
// regex-driven as the core ones — was never loaded. A catastrophic pattern added
// to a cross-file rule left every gate green.
//
// The size of the hole was recorded as MEASURED LIMIT 8 with the number "eight
// cross-file rules". By the time this script was written the registry held
// ELEVEN, and the shared `authz-lexicon.ts` extracted from VG-SMELL-010 had a
// header saying, in the product source, that its own bounds were "the only thing
// protecting the three-second contract here" because the census could not see
// them. A documented hole that grows is worse than an undocumented one: it reads
// as managed.
//
// ★ WHY THIS IS A SECOND SCRIPT AND NOT AN ARM OF sec-a1-catalog.mjs
//
// The two layers are not measurable by the same mechanism, and pretending they
// are is how a census lies.
//
//   - A core rule is `match(ctx: {content: string})`. One inert probe string
//     reaches every pattern it owns, and the pattern set is FIXED: what
//     `RegExp.prototype.exec` sees on the probe is what it will see on any input.
//   - A cross-file rule is `analyze(ctx: {project})` over a whole project index,
//     and — measured, see `crossCheck` in the output — a large fraction of the
//     patterns it executes are CONSTRUCTED FROM THE INPUT: `new RegExp(String.raw
//     `\b${escaped}\b`)` where `escaped` is an identifier read out of the file
//     being analysed. The set of `(source, flags)` pairs observed at runtime is
//     therefore a function of the corpus, not of the build.
//
// Folding an input-dependent set into `a1:surface-census` — an EXACT pin — would
// produce a gate that fails whenever a fixture is added. The failure mode of
// such a gate is not a false alarm, it is that people re-record the baseline
// without reading it, which is the same as having no gate. So the two censuses
// are kept apart and each is pinned on the axis that is actually stable:
//
//   STATIC arm (pinned exactly): regex LITERALS and `new RegExp(` CONSTRUCTION
//     SITES in `packages/analysis-graph/dist/**.js`. A function of the built
//     source alone. Adding a regex to a cross-file rule moves this number on the
//     day it lands, whether or not any fixture reaches it.
//
//   DYNAMIC arm (floored, never pinned): the fully-resolved patterns that
//     actually executed, captured by hooking `RegExp.prototype.exec` while each
//     rule's `analyze` runs over `samples/crossfile-fixtures/`. This is the arm
//     that can SHAPE-CHECK an interpolated pattern, because interpolation has
//     already happened by the time `exec` sees it. Its COUNT is fixture-
//     dependent and is reported, floored, and never pinned.
//
// Both arms feed one shape-suspicious SET, and that set is pinned exactly. It is
// currently empty, and an empty set is the one thing that is stable across both
// arms: the dynamic pattern population of any subset of the fixtures is a subset
// of the population measured here, so a suspicious set that is empty on the full
// fixture tree is empty on any subset of it (CI has fewer fixtures than a dirty
// working tree — 44 of 130 fixture projects were untracked when this was
// written).
//
// ★ THE POSITIVE CONTROL IS NOT OPTIONAL
//
// This project has already shipped a gate that passed with its fixtures deleted,
// and an A1 probe that read the wrong field, measured 0 patterns, and reported
// PASS. A census whose observation set is empty is the strongest possible pass on
// the weakest possible evidence. So `--check` FAILS unless four named product
// regexes are found in the DYNAMIC observation set:
//
//   authzComparisonPattern / authzFlagPattern / authzMembershipPattern — all
//     three built with `new RegExp(String.raw...)`, i.e. INVISIBLE to any source
//     literal scan, which is precisely the class sec-a1-catalog.mjs was rebuilt
//     around after it missed VG-CRYPTO-002; and
//   TEST_PATH — a plain literal, so the control fails distinguishably if the
//     hook works but the driver never reaches a rule at all.
//
// They are imported from the built lexicon rather than transcribed, so the
// control cannot drift into agreeing with a stale copy of itself.
//
// ★ WHAT THIS STILL DOES NOT MEASURE (read before quoting a number from it)
//
//  R1. A pattern built by `new RegExp` in a branch no fixture reaches is COUNTED
//      (its construction site is in the static census) but NOT SHAPE-CHECKED —
//      nothing resolves its interpolations. `staticNotDynamic` / the construction
//      site count are the size of that residue, reported every run.
//  R2. The static arm reads regex LITERALS. It cannot see the body of a
//      `new RegExp`, by construction, which is why the dynamic arm exists.
//  R3. Shape triage is a HEURISTIC, here as in sec-a1-catalog.mjs: a hit means
//      "measure this", a miss does not mean "linear". `recheck` is not wired into
//      this script; the wall-clock property for the cross-file layer rests on the
//      D3 budget in the graph itself plus review.
//  R4. `String.prototype.split(re)` reaches `exec` through a species-constructed
//      copy with the sticky flag added, so such a pattern is recorded with flags
//      `y` that appear nowhere in the source. Recorded as observed, not
//      normalised — the alternative is inventing a pattern nobody ran.
//
// Run from the repo root, AFTER `npm run build`:
//   node scripts/sec-a1-crossfile-catalog.mjs
//   node scripts/sec-a1-crossfile-catalog.mjs --check   # non-zero exit on a hole
//
// Writes security-experiment/_results/a1-crossfile-regex-catalog.{json,md}.
// Deterministic: no clock, no RNG, everything sorted.
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const RESULTS = 'security-experiment/_results';
const OUT_JSON = `${RESULTS}/a1-crossfile-regex-catalog.json`;
const OUT_MD = `${RESULTS}/a1-crossfile-regex-catalog.md`;

const AG_DIST = 'packages/analysis-graph/dist';
const AG_ENTRY = `${AG_DIST}/index.js`;
const AG_LEXICON = `${AG_DIST}/design-smells-crossfile/authz-lexicon.js`;
const CROSSFILE_SUBDIR = 'design-smells-crossfile';

// ------------------------------------------------------------------ argv ----
const argv = process.argv.slice(2);
const argValue = (flag, fallback) => {
  const i = argv.lastIndexOf(flag);
  return i === -1 || i + 1 >= argv.length ? fallback : argv[i + 1];
};
const CHECK = argv.includes('--check');
const FIXTURE_ROOT = argValue('--fixtures', 'samples/crossfile-fixtures');

// ---------------------------------------------------------------------------
// Regex-literal scanner — the same walker sec-a1-catalog.mjs uses.
// ---------------------------------------------------------------------------
// Copied rather than imported: sec-a1-catalog.mjs is a top-level PROGRAM that
// calls process.exit on its own error paths, so importing it to reuse one
// function would run the whole core-rules census as a side effect. The two
// copies are kept identical on purpose; a divergence between them would make the
// two censuses incomparable, which is worse than the duplication.
function extractRegexLiterals(src) {
  const out = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      i += 1;
      while (i < n) {
        if (src[i] === '\\') { i += 2; continue; }
        if (src[i] === quote) { i += 1; break; }
        i += 1;
      }
      continue;
    }
    if (c === '/' && src[i + 1] === '/') {
      while (i < n && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < n && !(src[i] === '*' && src[i + 1] === '/')) i += 1;
      i += 2;
      continue;
    }
    if (c === '/') {
      const start = i;
      i += 1;
      let inClass = false;
      let closed = false;
      while (i < n) {
        const d = src[i];
        if (d === '\\') { i += 2; continue; }
        if (d === '\n') break;
        if (d === '[') { inClass = true; i += 1; continue; }
        if (d === ']') { inClass = false; i += 1; continue; }
        if (d === '/' && !inClass) { closed = true; i += 1; break; }
        i += 1;
      }
      if (!closed) { i = start + 1; continue; }
      const bodyEnd = i - 1;
      let flags = '';
      while (i < n && /[dgimsuvy]/.test(src[i])) { flags += src[i]; i += 1; }
      out.push({ source: src.slice(start + 1, bodyEnd), flags });
      continue;
    }
    i += 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Shape heuristic — byte-identical to sec-a1-catalog.mjs's SHAPE_CHECKS.
// ---------------------------------------------------------------------------
const SHAPE_CHECKS = [
  {
    id: 'nested-quantifier',
    test: (s) => /\((?:\?[:=!<][=!]?)?[^()]*[*+][^()]*\)\s*[*+]/.test(s),
    reason: 'a quantified group whose body is itself unbounded-quantified ((a+)+ shape)',
  },
  {
    id: 'quantified-alternation',
    test: (s) => /\((?:\?[:=!<][=!]?)?[^()]*\|[^()]*\)\s*[*+]/.test(s),
    reason: 'a quantified alternation group; branches may overlap on the same input',
  },
  {
    id: 'adjacent-unbounded',
    test: (s) => /(\[[^\]]*\]|\\[wsdWSD]|\.)\s*[*+]\s*(\[[^\]]*\]|\\[wsdWSD]|\.)\s*[*+]/.test(s),
    reason: 'two adjacent unbounded quantifiers over potentially overlapping classes',
  },
];

function shapeHits(source) {
  return SHAPE_CHECKS.filter((c) => c.test(source)).map((c) => c.id).sort();
}

// ---------------------------------------------------------------------------
// ★ CANARY — a positive control for the SHAPE CHECKER ITSELF, not for the
// observation set.
//
// WHY THIS EXISTS. The suspicious set this census pins is EMPTY, and an empty
// expectation is the one shape that cannot distinguish "194 literals and 332
// runtime patterns were examined and none was superlinear" from "nothing was
// examined at all". That was demonstrated, not theorised: mutating `shapeHits`
// to `return []` left every line of this script's output and every gate in
// `sec-selftest.mjs --arms a1` byte-identical, exit 0 (measured 2026-08-03).
// The core catalogue does not have this hole only because its expected set is
// non-empty (7 entries), so killing its checker moves a number.
//
// The census already has a positive control (REQUIRED, below) and it works —
// but it proves the HOOK ran, not that the JUDGE is awake. Those are different
// failures and only one of them was covered.
//
// Each canary is a minimal string that must trip exactly one check. They are
// strings, never compiled and never executed: the point is the shape, and
// compiling `(a+)+` here would put a genuinely superlinear regex into the
// census's own process for no reason.
const SHAPE_CANARIES = [
  { id: 'nested-quantifier', probe: '(a+)+$' },
  { id: 'quantified-alternation', probe: '(a|ab)*$' },
  { id: 'adjacent-unbounded', probe: '\\s*\\w*$' },
];

function shapeCheckerCanary() {
  const fired = [];
  const missing = [];
  for (const { id, probe } of SHAPE_CANARIES) {
    if (shapeHits(probe).includes(id)) fired.push(id);
    else missing.push(id);
  }
  // A checker that answers "everything is suspicious" is as dead as one that
  // answers "nothing is": a benign literal must stay silent.
  const benign = shapeHits('^[a-z][a-z0-9_-]{0,63}$');
  return { ok: missing.length === 0 && benign.length === 0, fired: fired.sort(), missing: missing.sort(), benignHits: benign };
}

/**
 * A short, stable name for a pattern.
 *
 * The dynamic arm has no source-order index to key on — a pattern built from an
 * identifier has no fixed position — so suspicious entries are keyed by a digest
 * of the pattern itself. FNV-1a rather than `node:crypto` because this key ends
 * up in a baseline a human reads and diffs; a 64-hex sha256 in a gate message
 * teaches people to stop reading it.
 */
function fnv1a(text) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i) & 0xff;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return (hash >>> 0).toString(36);
}
const patternKey = (source, flags) => fnv1a(`${source}\u0000${flags}`);

// ---------------------------------------------------------------------------
// STATIC ARM — literals and construction sites in the built package
// ---------------------------------------------------------------------------
function listDistJs(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = join(cur, e.name);
      if (e.isDirectory()) { stack.push(full); continue; }
      // `.test.js` is the compiled vitest suite. It ships in dist but never runs
      // in the product, and counting it would inflate the surface with fixtures.
      if (!e.name.endsWith('.js') || e.name.endsWith('.test.js')) continue;
      out.push(full);
    }
  }
  return out.sort();
}

function staticArm() {
  const files = listDistJs(AG_DIST);
  const literals = [];
  const perModule = {};
  let constructionSites = 0;
  const uncompilable = [];

  for (const file of files) {
    const rel = relative(AG_DIST, file).replace(/\\/g, '/');
    const module = rel.includes('/') ? rel.slice(0, rel.indexOf('/')) : '(root)';
    const src = readFileSync(file, 'utf8');
    // `new RegExp(` sites are COUNTED, not parsed. Their bodies are template
    // literals with `${}` holes; a placeholder substitution would model a pattern
    // nobody runs, and modelling it wrong under-counts shape, which is the one
    // error this experiment cannot afford. The dynamic arm resolves them for real.
    const sites = (src.match(/new RegExp\(/g) ?? []).length;
    constructionSites += sites;

    const found = [];
    for (const lit of extractRegexLiterals(src)) {
      try {
        new RegExp(lit.source, lit.flags);
      } catch (err) {
        // Almost always the scanner mis-reading a division as a literal. Recorded
        // rather than dropped so a real broken pattern cannot hide in the noise.
        uncompilable.push({ file: rel, source: lit.source, flags: lit.flags, error: err instanceof Error ? err.message : String(err) });
        continue;
      }
      found.push(lit);
    }
    perModule[module] = perModule[module] ?? { files: 0, literals: 0, constructionSites: 0 };
    perModule[module].files += 1;
    perModule[module].literals += found.length;
    perModule[module].constructionSites += sites;

    for (const [idx, lit] of found.entries()) {
      literals.push({
        file: rel,
        indexInFile: idx,
        crossFileLayer: rel.startsWith(`${CROSSFILE_SUBDIR}/`),
        source: lit.source,
        flags: lit.flags,
        shape: shapeHits(lit.source),
      });
    }
  }

  return { files: files.map((f) => relative(AG_DIST, f).replace(/\\/g, '/')), literals, perModule, constructionSites, uncompilable };
}

// ---------------------------------------------------------------------------
// DYNAMIC ARM — what actually executed
// ---------------------------------------------------------------------------
/**
 * Drive every registered cross-file rule over every fixture project and record
 * the patterns that reached `RegExp.prototype.exec`.
 *
 * ★ WHY `samples/crossfile-fixtures` AND NOT `paper_data/corpus1k`. The corpus is
 * read-only research data that is gitignored and not redistributable; it does not
 * exist on CI, so a gate driven by it would be unrunnable exactly where it
 * matters. The fixture tree is tracked and ships with the repo.
 *
 * ★ WHY THE HOOK IS ARMED PER RULE AND NOT FOR THE WHOLE SCAN. `buildProjectIndex`
 * runs the structure indexer, whose regexes belong to no rule; attributing them
 * to whichever rule happened to be next would be a fabrication. They are captured
 * under the explicit pseudo-rule `(project-index)` instead, which is honest about
 * being a phase rather than a rule and keeps them out of the per-rule counts.
 */
async function dynamicArm(ag, ruleList) {
  const PSEUDO_INDEX = '(project-index)';
  const { buildProjectIndex, collectProjectFiles, createBudget } = ag;

  const projects = existsSync(FIXTURE_ROOT)
    ? readdirSync(FIXTURE_ROOT, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort()
    : [];

  const byRule = new Map([[PSEUDO_INDEX, new Map()]]);
  for (const r of ruleList) byRule.set(r.ruleId, new Map());

  const errors = [];
  const skippedByLanguage = new Map();
  const nativeExec = RegExp.prototype.exec;
  let current = null;
  // eslint-disable-next-line no-extend-native
  RegExp.prototype.exec = function patchedExec(str) {
    if (current !== null) {
      const bucket = byRule.get(current);
      const key = `${this.source}\u0000${this.flags}`;
      if (bucket && !bucket.has(key)) bucket.set(key, { source: this.source, flags: this.flags });
    }
    return nativeExec.call(this, str);
  };

  try {
    for (const name of projects) {
      const root = join(FIXTURE_ROOT, name);
      const budget = createBudget();
      let files;
      try {
        files = await collectProjectFiles(root, budget);
      } catch (err) {
        errors.push({ project: name, ruleId: null, message: err instanceof Error ? err.message : String(err) });
        continue;
      }
      let project;
      current = PSEUDO_INDEX;
      try {
        project = buildProjectIndex(root, files, budget);
      } catch (err) {
        errors.push({ project: name, ruleId: PSEUDO_INDEX, message: err instanceof Error ? err.message : String(err) });
        continue;
      } finally {
        current = null;
      }

      // ★MIRROR project.ts: the `languages` filter the product enforces. A rule
      // driven on inputs the product would never hand it reports a surface the
      // product does not have.
      const present = new Set(project.files.map((f) => f.language));
      for (const rule of ruleList) {
        if (!rule.languages.includes('*') && !rule.languages.some((l) => present.has(l))) {
          skippedByLanguage.set(rule.ruleId, (skippedByLanguage.get(rule.ruleId) ?? 0) + 1);
          continue;
        }
        current = rule.ruleId;
        try {
          rule.analyze({ project, budget });
        } catch (err) {
          // Never swallowed: a rule that threw registered only some of its
          // patterns, so its slice of the census is short and the reader must be
          // told rather than shown a quietly small number.
          errors.push({ project: name, ruleId: rule.ruleId, message: err instanceof Error ? err.message : String(err) });
        } finally {
          current = null;
        }
      }
    }
  } finally {
    // eslint-disable-next-line no-extend-native
    RegExp.prototype.exec = nativeExec;
  }

  const observed = [];
  const perRule = {};
  for (const [ruleId, bucket] of byRule) {
    perRule[ruleId] = bucket.size;
    for (const { source, flags } of bucket.values()) {
      observed.push({ ruleId, source, flags, shape: shapeHits(source) });
    }
  }
  observed.sort((a, b) => a.ruleId.localeCompare(b.ruleId) || a.source.localeCompare(b.source) || a.flags.localeCompare(b.flags));

  return {
    fixtureRoot: FIXTURE_ROOT,
    projects,
    observed,
    perRule,
    errors,
    skippedByLanguage: Object.fromEntries([...skippedByLanguage.entries()].sort()),
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
if (!existsSync(AG_ENTRY)) {
  console.error(`${AG_ENTRY} not found.\nFix: run \`npm run build\` from the repo root first.`);
  process.exit(1);
}

const ag = await import(pathToFileURL(resolve(AG_ENTRY)).href);
const lexicon = await import(pathToFileURL(resolve(AG_LEXICON)).href);
const { crossFileRules } = ag;

// Rule-shaped named exports, checked STRUCTURALLY. `index.ts` documents that a
// candidate rule may be exported without being registered so it can be measured
// before it ships; such a rule is not in `crossFileRules` and would otherwise be
// invisible here. Measured at the time of writing: 4 rule-shaped exports, all 11
// registered rules covered, 0 exported-but-unregistered.
const exportedRuleIds = new Set();
for (const value of Object.values(ag)) {
  if (!value || typeof value !== 'object') continue;
  if (typeof value.ruleId !== 'string') continue;
  if (typeof value.analyze !== 'function') continue;
  if (!Array.isArray(value.languages)) continue;
  exportedRuleIds.add(value.ruleId);
}
const registeredIds = new Set(crossFileRules.map((r) => r.ruleId));
const exportedUnregistered = [...exportedRuleIds].filter((id) => !registeredIds.has(id)).sort();

const stat = staticArm();
const dyn = await dynamicArm(ag, crossFileRules);

// --- cross-check: the two arms disagree, and the disagreement is the point ---
const staticKeys = new Set(stat.literals.map((l) => `${l.source}\u0000${l.flags}`));
const dynamicKeys = new Set(dyn.observed.map((o) => `${o.source}\u0000${o.flags}`));
const dynamicNotStatic = [...dynamicKeys].filter((k) => !staticKeys.has(k)).length;
const staticNotDynamic = [...staticKeys].filter((k) => !dynamicKeys.has(k)).length;

// --- one suspicious SET across both arms -----------------------------------
const shapeSuspicious = [
  ...stat.literals
    .filter((l) => l.shape.length > 0)
    .map((l) => `static:${l.file}#${l.indexInFile}=${l.shape.join('+')}`),
  ...dyn.observed
    .filter((o) => o.shape.length > 0)
    .map((o) => `dynamic:${o.ruleId}#${patternKey(o.source, o.flags)}=${o.shape.join('+')}`),
].sort((a, b) => a.localeCompare(b));

// --- positive control -------------------------------------------------------
// Four product regexes that MUST have executed. Three are `new RegExp(String.raw
// ...)` — invisible to any literal scan — and one is a plain literal, so a
// failure distinguishes "the hook is broken" from "the driver reached nothing".
const REQUIRED = [
  ['authzComparisonPattern', lexicon.authzComparisonPattern().source],
  ['authzFlagPattern', lexicon.authzFlagPattern().source],
  ['authzMembershipPattern', lexicon.authzMembershipPattern().source],
  ['TEST_PATH', lexicon.TEST_PATH.source],
];
const observedSources = new Set(dyn.observed.map((o) => o.source));
const controlMissing = REQUIRED.filter(([, src]) => !observedSources.has(src)).map(([name]) => name);
const positiveControlOk = controlMissing.length === 0;

const crossFileStaticLiterals = stat.literals.filter((l) => l.crossFileLayer).length;

const summary = {
  crossFileRules: crossFileRules.length,
  crossFileRuleIds: [...registeredIds].sort(),
  ruleShapedExports: exportedRuleIds.size,
  exportedUnregisteredRuleIds: exportedUnregistered,
  static: {
    filesScanned: stat.files.length,
    literals: stat.literals.length,
    literalsInCrossFileRules: crossFileStaticLiterals,
    constructionSites: stat.constructionSites,
    uncompilable: stat.uncompilable.length,
    perModule: stat.perModule,
  },
  dynamic: {
    fixtureRoot: dyn.fixtureRoot,
    fixtureProjects: dyn.projects.length,
    distinctRulePatternPairs: dyn.observed.length,
    distinctPatterns: dynamicKeys.size,
    perRule: dyn.perRule,
    rulesWithNoPattern: crossFileRules.map((r) => r.ruleId).filter((id) => (dyn.perRule[id] ?? 0) === 0).sort(),
    analyzeErrors: dyn.errors.length,
    skippedByLanguage: dyn.skippedByLanguage,
  },
  crossCheck: {
    dynamicNotStatic,
    staticNotDynamic,
    _why: 'dynamicNotStatic = patterns built at runtime that no literal scan can see (the VG-CRYPTO-002 lesson, in the cross-file layer). staticNotDynamic = literals present in the built source that this fixture driver never executed; they are counted but NOT shape-verified against resolved input.',
  },
  positiveControl: {
    ok: positiveControlOk,
    required: REQUIRED.map(([name]) => name),
    missing: controlMissing,
  },
  shapeSuspiciousCount: shapeSuspicious.length,
  // Pinned exactly by `a1:crossfile-shape-suspicious-set`. Without it that gate
  // reads an empty expectation against an empty actual and passes even when the
  // judge has been removed — see SHAPE_CANARIES.
  shapeChecker: shapeCheckerCanary(),
};

mkdirSync(RESULTS, { recursive: true });
writeFileSync(
  OUT_JSON,
  `${JSON.stringify({ summary, shapeSuspicious, staticLiterals: stat.literals, dynamicPatterns: dyn.observed, analyzeErrors: dyn.errors, uncompilable: stat.uncompilable }, null, 2)}\n`,
);

// --- Markdown view ---------------------------------------------------------
const esc = (s) => String(s).replace(/\|/g, '\\|').replace(/\n/g, ' ');
const trunc = (s, n) => (s.length > n ? `${s.slice(0, n)}…` : s);
const md = [];
md.push('# A1 — cross-file (analysis-graph) regex attack-surface census');
md.push('');
md.push('Generated by `scripts/sec-a1-crossfile-catalog.mjs`. Do not hand-edit (SCOPE §5).');
md.push('');
md.push(`- Registered cross-file rules: **${summary.crossFileRules}** (${summary.crossFileRuleIds.join(', ')})`);
md.push(`- Rule-shaped named exports: **${summary.ruleShapedExports}**; exported-but-unregistered: ${exportedUnregistered.length ? exportedUnregistered.join(', ') : '(none)'}`);
md.push(`- STATIC (pinned): **${summary.static.literals}** regex literals + **${summary.static.constructionSites}** \`new RegExp(\` sites over **${summary.static.filesScanned}** built files`);
md.push(`  - of which in \`${CROSSFILE_SUBDIR}/\`: **${crossFileStaticLiterals}** literals`);
md.push(`- DYNAMIC (floored, fixture-dependent): **${summary.dynamic.distinctRulePatternPairs}** (rule, pattern) pairs / **${summary.dynamic.distinctPatterns}** distinct patterns over **${summary.dynamic.fixtureProjects}** fixture projects`);
md.push(`- Cross-check: **${dynamicNotStatic}** runtime-constructed patterns invisible to the literal scan; **${staticNotDynamic}** literals the driver never executed`);
md.push(`- Positive control: ${positiveControlOk ? '**ok**' : `**FAILED** (missing: ${controlMissing.join(', ')})`} — ${REQUIRED.map(([n]) => n).join(', ')}`);
md.push(`- Shape-suspicious (both arms): **${shapeSuspicious.length}**`);
md.push(`- Rules that executed no pattern: ${summary.dynamic.rulesWithNoPattern.length ? summary.dynamic.rulesWithNoPattern.join(', ') : '(none)'}`);
md.push(`- Rule invocation errors: **${summary.dynamic.analyzeErrors}**`);
md.push('');
md.push('## Patterns per rule (dynamic)');
md.push('');
md.push('| rule | distinct patterns executed |');
md.push('|---|---|');
for (const id of Object.keys(dyn.perRule).sort()) md.push(`| ${id} | ${dyn.perRule[id]} |`);
md.push('');
md.push('## Static literals per module');
md.push('');
md.push('| module | files | literals | new RegExp sites |');
md.push('|---|---|---|---|');
for (const m of Object.keys(stat.perModule).sort()) {
  const v = stat.perModule[m];
  md.push(`| ${m} | ${v.files} | ${v.literals} | ${v.constructionSites} |`);
}
md.push('');
if (shapeSuspicious.length) {
  md.push('## Shape-suspicious patterns');
  md.push('');
  md.push('| key | pattern |');
  md.push('|---|---|');
  for (const l of stat.literals.filter((x) => x.shape.length)) {
    md.push(`| static:${l.file}#${l.indexInFile}=${l.shape.join('+')} | \`${esc(trunc(l.source, 90))}\` |`);
  }
  for (const o of dyn.observed.filter((x) => x.shape.length)) {
    md.push(`| dynamic:${o.ruleId}#${patternKey(o.source, o.flags)}=${o.shape.join('+')} | \`${esc(trunc(o.source, 90))}\` |`);
  }
  md.push('');
} else {
  md.push('No pattern in either arm carries a super-linear SHAPE. That is a shape claim, not a timing claim (R3).');
  md.push('');
}
writeFileSync(OUT_MD, `${md.join('\n')}\n`);

console.log(`[a1-crossfile] ${summary.crossFileRules} cross-file rules; static ${summary.static.literals} literals + ${summary.static.constructionSites} construction sites over ${summary.static.filesScanned} files`);
console.log(`[a1-crossfile] dynamic ${summary.dynamic.distinctRulePatternPairs} (rule,pattern) pairs over ${summary.dynamic.fixtureProjects} fixture projects`);
console.log(`[a1-crossfile] cross-check: ${dynamicNotStatic} runtime-only, ${staticNotDynamic} literal-only`);
console.log(`[a1-crossfile] shape-suspicious: ${shapeSuspicious.length}`);
console.log(`[a1-crossfile] positive control: ${positiveControlOk ? 'ok' : `MISSING ${controlMissing.join(', ')}`}`);
console.log(`[a1-crossfile] wrote ${OUT_JSON} and ${OUT_MD}`);
for (const e of dyn.errors) console.warn(`[a1-crossfile] WARN: ${e.ruleId ?? '(collect)'} threw on ${e.project}: ${e.message}`);
for (const u of stat.uncompilable) console.warn(`[a1-crossfile] WARN: uncompilable literal in ${u.file}: /${u.source}/${u.flags} (${u.error})`);

if (CHECK) {
  const problems = [];
  if (!positiveControlOk) problems.push(`positive control failed: ${controlMissing.join(', ')} never executed — the census observed nothing it can vouch for`);
  if (summary.dynamic.distinctRulePatternPairs === 0) problems.push('the dynamic arm observed 0 patterns');
  if (summary.dynamic.rulesWithNoPattern.length) problems.push(`rules that executed no pattern: ${summary.dynamic.rulesWithNoPattern.join(', ')}`);
  if (summary.dynamic.analyzeErrors) problems.push(`${summary.dynamic.analyzeErrors} rule invocation error(s)`);
  if (shapeSuspicious.length) problems.push(`${shapeSuspicious.length} shape-suspicious pattern(s): ${shapeSuspicious.join(', ')}`);
  if (!summary.shapeChecker.ok) {
    problems.push(
      `shape-checker canary failed (missing: ${summary.shapeChecker.missing.join(', ') || 'none'}; benign hits: ${summary.shapeChecker.benignHits.join(', ') || 'none'})`
      + ' — the suspicious set being empty means nothing while the judge is dead',
    );
  }
  if (problems.length) {
    for (const p of problems) console.error(`[a1-crossfile] FAIL: ${p}`);
    process.exit(2);
  }
  console.log('[a1-crossfile] --check: ok');
}

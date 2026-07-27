// VG-SMELL-010 evaluation — what cross-file analysis actually finds in the wild.
//
// WHY THIS EXISTS
//
// The rule ships with a sample corpus of positive and negative fixtures. That
// corpus is a REGRESSION TEST and nothing more. It says the rule does today what
// it did yesterday, and it is worthless as a RESULT, because the same person who
// wrote the detector decided what it should detect. Reporting "every fixture
// behaved" as a finding would be reporting that we agree with ourselves.
//
// What a result needs is code nobody in this project wrote. That is what
// `paper_data/corpus1k` and `paper_data/corpus1k_vibe` are: repositories cloned
// from GitHub, the second sampled for markers of AI-assisted development. Running
// the rule across both answers the two questions the write-up has to answer:
//
//   1. Does it fire on real code at all, or only on a fixture built to trip it?
//   2. Does it fire MORE on the AI-assisted corpus than on the general one?
//
// Question 2 is the interesting one, and it is the reason both corpora are
// scanned rather than just the vibe one. "Scattered authorization exists in the
// wild" is not a claim about AI-generated code. "It is more common in the
// AI-assisted corpus than in the baseline" is, and the only way to say it is to
// measure both with the same instrument on the same day.
//
// ★ WHAT THIS SCRIPT DOES NOT DO
//
// It does not label findings true or false. It cannot: that requires reading the
// implicated handlers and deciding whether centralising them would be right, and
// that judgement is the researcher's. What it produces is the population to
// label — every finding, with its sites, written out so a human can go through
// them and record a verdict. A precision number quoted without that pass would be
// fabricated, and the JSON deliberately contains no field to put one in.
//
// The labels live in a SEPARATE file, `paper_data/smell010_labels.json`, written
// by hand against `docs/smell010-labeling-rubric.md` and joined back by
// `scripts/smell010-precision.mjs`. Keeping them out of this file is what stops
// a re-run of the measurement from quietly erasing a day of labelling — and it
// keeps this script's output a pure function of the corpus, which is what makes
// two runs comparable.
//
// ★ RESUME, AND WHY THE AGGREGATE IS COMPUTED FROM THE ROWS
//
// A full pass is 2,683 repositories and takes hours. A harness that loses all of
// it to one Ctrl-C, one laptop sleep, or one unlucky repository is a harness that
// never actually gets run to completion, so this one writes ONE JSONL ROW PER
// REPOSITORY as it goes (`paper_data/smell010_eval.rows.jsonl`) and skips
// repositories that already have a row.
//
// The important half is what happens after the loop: the summary JSON is folded
// out of the ROWS FILE, never out of in-memory counters. That is the property
// that makes "run it straight through" and "kill it at repo 900 and resume"
// produce the same file — the counters can only see the repositories this
// process happened to visit, the rows file sees all of them, so folding from the
// rows removes the difference by construction rather than by care. Verified by
// running `--limit 1` then `--limit 2` and diffing against a single `--limit 2`
// run; the outputs match apart from `generatedAt` and the `rows` block.
//
// Rejected alternatives, and why:
//
//  - Checkpoint the whole aggregate JSON every N repositories. Cheaper to write
//    and wrong in the same way a partial scan that looks clean is wrong: the file
//    on disk would be a complete-looking result whose denominators are a prefix
//    of the corpus. This script's whole argument rests on its denominators.
//  - Key the resume on repository INDEX ("resume at 901"). Breaks silently the
//    moment the corpus gains or loses a directory, since the index-to-repo map
//    shifts under the rows already written. Keyed on `corpus\0repo` instead.
//  - One row per FINDING. Then "this repository was analysed and produced
//    nothing" is unrepresentable, and every zero would be indistinguishable from
//    a repository that was never reached — which is exactly the ambiguity the
//    denominators exist to kill.
//
// Run from the repo root, after `npm run build`:
//   node scripts/smell010-eval.mjs                 # default sample per corpus
//   node scripts/smell010-eval.mjs --limit 300     # larger sample
//   node scripts/smell010-eval.mjs --limit 0       # every repository (the run
//                                                  # that goes in the write-up)
//   node scripts/smell010-eval.mjs --limit 0 --fresh          # ignore prior rows
//   node scripts/smell010-eval.mjs --limit 2 --out /tmp/x.json --rows /tmp/x.jsonl
//
// Writes paper_data/smell010_eval.json (gitignored — research output stays local)
// and prints a Markdown summary.

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import {
  analyzeProject,
  buildProjectIndex,
  collectProjectFiles,
  createBudget,
} from '@vibeguard/analysis-graph';

const REPO_ROOT = process.cwd();
const CORPORA = [
  ['baseline', join(REPO_ROOT, 'paper_data', 'corpus1k')],
  ['vibe', join(REPO_ROOT, 'paper_data', 'corpus1k_vibe')],
];

/**
 * Default sample size per corpus.
 *
 * Cross-file analysis reads every source file in a project, so a full pass over
 * the whole corpus is a long job. A sample keeps the script runnable while
 * iterating; `--limit 0` takes everything for the run that goes in the write-up.
 *
 * The sample is the first N repositories in SORTED order, not a random draw.
 * Random sampling would make two runs of this script incomparable, and there is
 * no seedable RNG here worth introducing to fix that. Sorted-prefix sampling is
 * biased — it favours names early in the alphabet — and that bias is stated in
 * the output rather than hidden, because a stated bias can be reasoned about and
 * an unstated one cannot.
 */
const DEFAULT_LIMIT = 150;

const argLimit = (() => {
  const i = process.argv.indexOf('--limit');
  if (i === -1) return DEFAULT_LIMIT;
  const v = Number(process.argv[i + 1]);
  return Number.isFinite(v) && v >= 0 ? v : DEFAULT_LIMIT;
})();

const argValue = (name, fallback) => {
  const i = process.argv.indexOf(name);
  if (i === -1) return fallback;
  const v = process.argv[i + 1];
  return v === undefined || v.startsWith('--') ? fallback : v;
};
const argFlag = (name) => process.argv.includes(name);

const OUT_PATH = argValue('--out', join(REPO_ROOT, 'paper_data', 'smell010_eval.json'));
const ROWS_PATH = argValue('--rows', join(REPO_ROOT, 'paper_data', 'smell010_eval.rows.jsonl'));
const FRESH = argFlag('--fresh');
const ACCEPT_STALE = argFlag('--accept-stale-rows');

const CODE_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
const SKIP_DIR = new Set(['.git', 'node_modules', 'dist', 'build', 'vendor', 'out', 'target']);

/**
 * Row schema version. Bump when the shape of a row changes in a way that makes
 * an old row unfoldable; rows carrying a different version are refused rather
 * than reinterpreted, because a silently misread row becomes a wrong number in
 * a paper and nothing anywhere would flag it.
 */
const ROW_SCHEMA = 2;

/** FNV-1a, the same hash `project.ts` uses for finding ids. Not a security hash. */
function fnv1a(text, seed = 0x811c9dc5) {
  let hash = seed;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

/**
 * A fingerprint of the ENGINE that produced a row.
 *
 * Resume is a correctness hazard the moment the analyser changes underneath it:
 * rows written by yesterday's rule folded together with rows written by today's
 * produce a summary that describes no version of the code, and nothing in the
 * numbers looks wrong. So every row records what built it, and a resume across a
 * boundary is refused by default.
 *
 * Hashed over the BUILT `dist/**\/*.js` rather than the TypeScript sources,
 * because dist is what actually ran — a source tree with uncommitted edits and a
 * stale dist would otherwise invalidate rows that are in fact still valid, and
 * (worse) an edited-but-unbuilt rule would look like a change that never
 * happened. `.test.js` is excluded: test files churn constantly and cannot
 * affect a measurement.
 *
 * ⚠ MEASURED LIMIT: this covers `@vibeguard/analysis-graph` only. File
 * admission and language detection come from `@vibeguard/analyzer-core`
 * (`DEFAULT_IGNORE`, `detectLanguageFromPath`), which is outside the
 * fingerprint. A change there could alter which files are read without
 * invalidating a row. Including core would be more correct and would also
 * invalidate every row on any unrelated core rule edit, which in a
 * multi-hour job is its own kind of failure; `--fresh` is the answer when
 * core's file handling has moved.
 */
const ENGINE_FINGERPRINT = (() => {
  const distRoot = join(REPO_ROOT, 'packages', 'analysis-graph', 'dist');
  const found = [];
  const stack = [distRoot];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!entry.name.endsWith('.js') || entry.name.endsWith('.test.js')) continue;
      found.push(full);
    }
  }
  if (found.length === 0) return 'ag-nodist';
  found.sort();
  let hash = 0x811c9dc5;
  for (const file of found) {
    hash = fnv1a(file.slice(distRoot.length), hash);
    try {
      hash = fnv1a(readFileSync(file, 'utf8'), hash);
    } catch {
      hash = fnv1a('<unreadable>', hash);
    }
  }
  return `ag-${found.length}-${hash.toString(36)}`;
})();

/** Count TS/JS files and lines, so density can be reported per KLOC. */
function measureSize(dir) {
  let files = 0;
  let lines = 0;
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIR.has(entry.name)) stack.push(join(current, entry.name));
        continue;
      }
      const dot = entry.name.lastIndexOf('.');
      if (dot === -1 || !CODE_EXT.has(entry.name.slice(dot))) continue;
      files += 1;
      try {
        const full = join(current, entry.name);
        if (statSync(full).size > 1024 * 1024) continue;
        lines += readFileSync(full, 'utf8').split('\n').length;
      } catch {
        /* unreadable file: counted in `files`, not in `lines` */
      }
    }
  }
  return { files, lines };
}

function listRepos(corpusDir) {
  if (!existsSync(corpusDir)) return null;
  return readdirSync(corpusDir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

const rowKey = (corpus, repo) => `${corpus}\0${repo}`;

/**
 * A join key for one finding, stable across re-runs of the measurement.
 *
 * Deliberately built from the same facts as `stableId` in
 * `packages/analysis-graph/src/project.ts` — rule, primary path, primary line,
 * site count — so the identity a label is attached to is the identity the
 * PRODUCT already treats as "the same finding". Inventing a second notion of
 * sameness here would let a label follow a finding that the tool considers new,
 * or fail to follow one it considers unchanged.
 *
 * Not the product's `findingId` itself: that id is not carried in this file's
 * rows, and reaching for it would tie the labelling workflow to an internal the
 * evaluation has no business depending on. `scripts/smell010-precision.mjs`
 * recomputes this key from the row and refuses to run if its recomputation
 * disagrees with what is stored — two implementations that must agree, checked
 * rather than assumed.
 */
function findingKeyOf(corpus, repo, finding) {
  const first = finding.sites[0];
  return `${corpus}/${repo}#VG-SMELL-010#${first ? first.filePath : '?'}:${
    first ? first.startLine : 0
  }#n${finding.sites.length}`;
}

// ── Rows file ───────────────────────────────────────────────────────────────

/**
 * Read prior rows.
 *
 * Tolerates a truncated final line, because the process being killed mid-append
 * is the normal way this file ends up short and losing the whole run over one
 * half-written byte sequence would defeat the point. It does NOT tolerate a row
 * it cannot interpret quietly: malformed and duplicate counts are reported into
 * the output JSON, so a reader can see the rows file was not pristine.
 *
 * Last row wins on a duplicate key. A duplicate means the same repository was
 * analysed twice (a crash between the analysis and the append, then a re-run),
 * and the later analysis is the one that completed under the current setup.
 */
function readRows(path) {
  const byKey = new Map();
  const fingerprints = new Set();
  let malformed = 0;
  let duplicates = 0;
  if (!existsSync(path)) return { byKey, malformed, duplicates, fingerprints };
  const text = readFileSync(path, 'utf8');
  for (const line of text.split(/\r?\n/)) {
    if (line.trim() === '') continue;
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      malformed += 1;
      continue;
    }
    if (typeof row !== 'object' || row === null || !row.corpus || !row.repo) {
      malformed += 1;
      continue;
    }
    fingerprints.add(`${row.v}:${row.fp}`);
    const key = rowKey(row.corpus, row.repo);
    if (byKey.has(key)) duplicates += 1;
    byKey.set(key, row);
  }
  return { byKey, malformed, duplicates, fingerprints };
}

function appendRow(path, row) {
  appendFileSync(path, `${JSON.stringify(row)}\n`, 'utf8');
}

/**
 * Terminate a half-written final line before appending to it.
 *
 * A process killed between the write and the newline leaves a fragment with no
 * `\n`, and the next append would land on the SAME line — turning one lost row
 * into two unreadable ones, the second of which is a row that was computed
 * correctly and then destroyed by the recovery. One newline at startup makes the
 * damage stop at the row that was actually interrupted.
 */
function healTrailingLine(path) {
  if (!existsSync(path)) return;
  let size;
  try {
    size = statSync(path).size;
  } catch {
    return;
  }
  if (size === 0) return;
  const tail = readFileSync(path, 'utf8').slice(-1);
  if (tail !== '\n') {
    appendFileSync(path, '\n', 'utf8');
    console.error(`rows file did not end in a newline; terminated the partial final line`);
  }
}

// ── Aggregation ─────────────────────────────────────────────────────────────

/**
 * Fold rows into the summary shape.
 *
 * Every increment below mirrors the in-loop accounting of the pre-resume version
 * of this script one-for-one, INCLUDING its order of operations: a repository
 * that failed to analyse contributes to `reposSkipped` and to nothing else (no
 * size, no denominators), and size is accumulated for every repository that
 * analysed, findings or not. The summary field names are frozen — the write-up's
 * table is written against them and a rename would silently break the
 * comparison against previously published numbers.
 */
function foldCorpus(label, all, selected, byKey) {
  const perCorpus = {
    corpus: label,
    reposAvailable: all.length,
    reposAnalysed: selected.length,
    sampling: argLimit === 0 ? 'full' : `first ${argLimit} by sorted name`,
    reposWithFinding: 0,
    reposSkipped: 0,
    totalFindings: 0,
    totalSites: 0,
    totalFiles: 0,
    totalLines: 0,
    severity: { high: 0, medium: 0 },
    siteCountHistogram: {},
    // ── Denominators, without which the headline number is uninterpretable ──
    //
    // A bare "0 repositories fired" has two completely different readings: the
    // rule is precise and the phenomenon is rare, or the rule is broken on real
    // code and finds nothing anywhere. Those demand opposite responses, and no
    // reader can tell them apart from the firing count alone.
    //
    // The chain below is what separates them. Each step is a strictly smaller
    // population than the last, and a zero appearing early means something very
    // different from a zero appearing late: `reposWithHandlers = 0` would say the
    // indexer never recognised a route handler in the entire corpus (broken),
    // whereas handlers in the thousands and no findings says the rule looked at
    // real handlers and declined to accuse them (precise).
    reposWithTsJs: 0,
    reposWithRoutes: 0,
    reposWithHandlers: 0,
    totalRoutes: 0,
    totalHandlers: 0,
  };
  const findings = [];
  const missing = [];

  for (const name of selected) {
    const row = byKey.get(rowKey(label, name));
    if (!row) {
      missing.push(name);
      continue;
    }
    if (row.error !== null && row.error !== undefined) {
      // A repository that cannot be analysed is recorded, not dropped. A silent
      // drop moves a repo out of the denominator and inflates every rate.
      perCorpus.reposSkipped += 1;
      findings.push({ corpus: label, repo: name, error: row.error });
      continue;
    }
    if (row.denom && row.denom.tsjs) {
      perCorpus.reposWithTsJs += 1;
      perCorpus.totalRoutes += row.denom.routes;
      perCorpus.totalHandlers += row.denom.handlers;
      if (row.denom.routes > 0) perCorpus.reposWithRoutes += 1;
      if (row.denom.handlers > 0) perCorpus.reposWithHandlers += 1;
    }
    if (row.size) {
      perCorpus.totalFiles += row.size.files;
      perCorpus.totalLines += row.size.lines;
    }
    if (!row.findings || row.findings.length === 0) continue;
    perCorpus.reposWithFinding += 1;
    perCorpus.totalFindings += row.findings.length;
    for (const f of row.findings) {
      const sites = f.sites.length;
      perCorpus.totalSites += sites;
      perCorpus.severity[f.severity] = (perCorpus.severity[f.severity] ?? 0) + 1;
      perCorpus.siteCountHistogram[sites] = (perCorpus.siteCountHistogram[sites] ?? 0) + 1;
      findings.push(f);
    }
  }

  perCorpus.repoFiringRate =
    perCorpus.reposAnalysed > 0
      ? Number((perCorpus.reposWithFinding / perCorpus.reposAnalysed).toFixed(4))
      : null;
  perCorpus.sitesPerFinding =
    perCorpus.totalFindings > 0
      ? Number((perCorpus.totalSites / perCorpus.totalFindings).toFixed(2))
      : null;

  return { perCorpus, findings, missing };
}

// ── Run ─────────────────────────────────────────────────────────────────────

const outDir = join(REPO_ROOT, 'paper_data');
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });

if (FRESH && existsSync(ROWS_PATH)) {
  rmSync(ROWS_PATH);
  console.error(`--fresh: removed ${ROWS_PATH}`);
}

healTrailingLine(ROWS_PATH);
const prior = readRows(ROWS_PATH);
const staleFingerprints = [...prior.fingerprints].filter(
  (f) => f !== `${ROW_SCHEMA}:${ENGINE_FINGERPRINT}`,
);
if (staleFingerprints.length > 0 && !ACCEPT_STALE) {
  console.error('');
  console.error(`REFUSING TO RESUME: ${ROWS_PATH} holds rows from a different engine build.`);
  console.error(`  rows carry:  ${staleFingerprints.join(', ')}`);
  console.error(`  this build:  ${ROW_SCHEMA}:${ENGINE_FINGERPRINT}`);
  console.error('');
  console.error('Folding rows from two builds produces a summary that describes neither, and');
  console.error('nothing in the numbers would look wrong. Choose one:');
  console.error('  --fresh                 recompute everything with this build (hours)');
  console.error('  --rows <other-path>     start a separate rows file for this build');
  console.error('  --accept-stale-rows     fold anyway; the mixture is recorded in the output');
  process.exit(2);
}

const startedAt = Date.now();
let analysedThisRun = 0;
let reusedThisRun = 0;

const summary = {};
const results = [];
const foldProblems = [];
/** Corpora that exist, with their selection, kept for the fold after the loop. */
const plan = [];

for (const [label, dir] of CORPORA) {
  const all = listRepos(dir);
  if (all === null) {
    console.error(`skipping ${label}: ${dir} does not exist`);
    continue;
  }
  const selected = argLimit === 0 ? all : all.slice(0, argLimit);
  plan.push({ label, all, selected });
  // Never a silent cap: the write-up must be able to say what was and was not
  // looked at, and a reader who sees only "37 repositories fired" has no way to
  // know it was out of a sample rather than out of the whole corpus.
  console.error(
    `${label}: analysing ${selected.length} of ${all.length} repositories ` +
      `(sorted-prefix sample${argLimit === 0 ? ', FULL' : ''})`,
  );

  let i = 0;
  for (const name of selected) {
    i += 1;
    if (prior.byKey.has(rowKey(label, name))) {
      reusedThisRun += 1;
      // Quiet on the resumed prefix: on a job resumed at repo 1,500 the useful
      // signal is where the work is now, and 1,499 "already done" lines bury it.
      if (i % 200 === 0) console.error(`[${label}] ${i}/${selected.length} (resumed)`);
      continue;
    }

    const repoDir = join(dir, name);
    const started = Date.now();
    const row = {
      v: ROW_SCHEMA,
      fp: ENGINE_FINGERPRINT,
      corpus: label,
      repo: name,
      ts: new Date().toISOString(),
      ms: 0,
      error: null,
      size: null,
      denom: null,
      degradations: [],
      findings: [],
    };

    let out;
    try {
      out = await analyzeProject(repoDir);
    } catch (err) {
      row.error = String(err && err.message);
      row.ms = Date.now() - started;
      appendRow(ROWS_PATH, row);
      analysedThisRun += 1;
      console.error(`[${label}] ${i}/${selected.length} ${name} ERROR ${row.error}`);
      continue;
    }

    // Which bounds bit, per repository. Not in the summary and deliberately in
    // the row: `GRAPH_DEADLINE_MS` is WALL-CLOCK, so a repository near the limit
    // can be complete on one machine and truncated on another, and a run whose
    // zeroes are partly "nothing there" and partly "we stopped early" is not the
    // measurement anyone thinks it is. Recording it per repository is what makes
    // that answerable afterwards instead of unknowable.
    row.degradations = (out.degradations ?? []).map((d) => d.detail);

    // Re-index to read the denominators. Deliberately a second pass rather than
    // a return value threaded out of `analyzeProject`: these numbers are an
    // evaluation concern, and widening the product API so a research script can
    // see its internals is how a measurement harness ends up dictating the
    // shape of the thing it measures.
    try {
      const budget = createBudget();
      const files = await collectProjectFiles(repoDir, budget);
      const tsjs = files.filter((f) => f.language === 'typescript' || f.language === 'javascript');
      if (tsjs.length > 0) {
        const index = buildProjectIndex(repoDir, files, budget);
        let routes = 0;
        let handlers = 0;
        for (const s of index.structures.values()) {
          routes += s.routes.length;
          handlers += s.symbols.filter((x) => x.kind === 'route-handler').length;
        }
        row.denom = { tsjs: true, routes, handlers };
      } else {
        row.denom = { tsjs: false, routes: 0, handlers: 0 };
      }
    } catch {
      /* denominators are best-effort; a failure here must not lose the finding */
    }

    const smells = out.findings.filter((f) => f.ruleId === 'VG-SMELL-010');
    row.size = measureSize(repoDir);

    for (const f of smells) {
      const finding = {
        corpus: label,
        repo: name,
        ruleId: f.ruleId,
        severity: f.severity,
        confidence: f.confidence,
        duplicatedCheckCount: f.metrics?.duplicatedCheckCount ?? null,
        fanIn: f.metrics?.fanIn ?? null,
        // Every site, so the labelling pass has what it needs without re-running
        // the scan. This is the actual deliverable of the script.
        sites: [
          { filePath: f.filePath, startLine: f.startLine, evidence: f.primaryLocation?.evidence },
          ...(f.relatedLocations ?? []).map((l) => ({
            filePath: l.filePath,
            startLine: l.startLine,
            evidence: l.evidence,
          })),
        ],
        // Reserved for the human pass. Deliberately null, and deliberately the
        // only place a verdict can live: nothing in this script computes it.
        // Verdicts are recorded in `paper_data/smell010_labels.json`, joined
        // back on `findingKey` — this field stays null FOREVER, including after
        // labelling, so that re-running the measurement can never destroy work
        // and so no future reader can mistake a computed value for a judged one.
        label: null,
        findingKey: '',
      };
      finding.findingKey = findingKeyOf(label, name, finding);
      row.findings.push(finding);
    }

    row.ms = Date.now() - started;
    appendRow(ROWS_PATH, row);
    analysedThisRun += 1;

    console.error(
      `[${label}] ${i}/${selected.length} ${name} ok findings=${row.findings.length} ` +
        `routes=${row.denom ? row.denom.routes : '?'} ${row.ms}ms` +
        (row.degradations.length > 0 ? ` DEGRADED(${row.degradations.length})` : ''),
    );
    if (analysedThisRun % 50 === 0) {
      const elapsedMin = (Date.now() - startedAt) / 60000;
      const rate = analysedThisRun / Math.max(elapsedMin, 0.001);
      console.error(
        `-- progress: ${i}/${selected.length} in ${label}; ${analysedThisRun} analysed this run; ` +
          `${elapsedMin.toFixed(1)}min elapsed; ${rate.toFixed(1)} repo/min --`,
      );
    }
  }

}

/**
 * Fold from the rows file on disk, re-read after the loop — never from the
 * counters this process built up.
 *
 * The re-read is the whole resume-equivalence argument in one line. A process
 * that folded its own in-memory rows would produce a correct file when it ran
 * the corpus end to end and a silently short one when it resumed, because its
 * memory holds only what IT analysed. Reading back from disk means the fold sees
 * the same input in both cases, and it also puts every row through the JSON
 * round-trip, so a row that serialises badly is caught by the numbers rather
 * than by nobody.
 */
const finalRows = readRows(ROWS_PATH);
for (const { label, all, selected } of plan) {
  const folded = foldCorpus(label, all, selected, finalRows.byKey);
  if (folded.missing.length > 0) {
    foldProblems.push(
      `${label}: ${folded.missing.length} selected repositories have no row ` +
        `(first: ${folded.missing.slice(0, 3).join(', ')})`,
    );
  }
  summary[label] = folded.perCorpus;
  results.push(...folded.findings);
}

// A summary folded from an incomplete rows file is exactly the "partial result
// that looks clean" this project treats as the worse of the two failures, so it
// is not written at all. The rows survive; re-running resumes and finishes.
if (foldProblems.length > 0) {
  console.error('');
  console.error('REFUSING TO WRITE THE SUMMARY — the rows file does not cover the selection:');
  for (const p of foldProblems) console.error(`  ${p}`);
  console.error('Re-run to fill the gaps (already-analysed repositories are skipped).');
  process.exit(3);
}

writeFileSync(
  OUT_PATH,
  JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      note:
        'VG-SMELL-010 population for manual labelling. `label` is null on every ' +
        'row by construction: no precision or recall figure in this file was ' +
        'computed, because none can be without a human reading the sites.',
      // Provenance for the resume machinery. Outside `summary` on purpose: the
      // summary's fields are the write-up's table and are frozen.
      rows: {
        path: ROWS_PATH,
        engineFingerprint: ENGINE_FINGERPRINT,
        schema: ROW_SCHEMA,
        analysedThisRun,
        reusedFromRows: reusedThisRun,
        malformedLinesIgnored: finalRows.malformed,
        duplicateRowsLastWins: finalRows.duplicates,
        mixedEngineBuilds: staleFingerprints.length > 0 ? staleFingerprints : null,
      },
      summary,
      findings: results,
    },
    null,
    2,
  ),
);

// ── Markdown summary ────────────────────────────────────────────────────────
const line = (s) => process.stdout.write(`${s}\n`);
line('');
line('# VG-SMELL-010 — cross-file evaluation');
line('');
line('| corpus | analysed | with TS/JS | with routes | with handlers | handlers | FIRING | findings |');
line('|---|---|---|---|---|---|---|---|');
for (const [label, s] of Object.entries(summary)) {
  line(
    `| ${label} | ${s.reposAnalysed}/${s.reposAvailable} | ${s.reposWithTsJs} | ` +
      `${s.reposWithRoutes} (${s.totalRoutes} routes) | ${s.reposWithHandlers} | ` +
      `${s.totalHandlers} | **${s.reposWithFinding}** | ${s.totalFindings} |`,
  );
}
line('');
line('The middle columns are the denominators. Read left to right: a zero in');
line('`with handlers` would mean the indexer never recognised a handler and the');
line('rule was never given the chance to fire (a broken pipeline). Handlers in the');
line('hundreds with `FIRING` at zero means the rule inspected real handlers in real');
line('projects and declined to accuse any of them — which is a precision result,');
line('not an absence of one.');
line('');
for (const [label, s] of Object.entries(summary)) {
  line(`- **${label}**: sampling = ${s.sampling}; skipped ${s.reposSkipped}; ` +
    `severity ${JSON.stringify(s.severity)}; sites histogram ${JSON.stringify(s.siteCountHistogram)}`);
}
line('');
line(`Population written to \`${OUT_PATH}\` — ${results.length} row(s), every \`label\` null.`);
line(
  `Rows: \`${ROWS_PATH}\` — ${analysedThisRun} analysed this run, ${reusedThisRun} reused` +
    (finalRows.malformed > 0 ? `, ${finalRows.malformed} malformed line(s) ignored` : '') +
    (finalRows.duplicates > 0 ? `, ${finalRows.duplicates} duplicate row(s) (last wins)` : '') +
    '.',
);
line('');
line('**No precision figure is reported here and none is computable from this file.**');
line('Labelling the rows is a separate, human pass; until it is done the honest');
line('statement is "the rule fires at rate X on corpus Y", not "the rule is X% precise".');
line('Record verdicts in `paper_data/smell010_labels.json` against');
line('`docs/smell010-labeling-rubric.md`, then run `node scripts/smell010-precision.mjs`.');

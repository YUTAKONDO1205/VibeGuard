// VG-SMELL-010 — threshold sensitivity, measured WITHOUT moving the thresholds.
//
// WHY THIS EXISTS
//
// The full-corpus run produced 0 findings on the general corpus and 5 on the
// AI-assisted one (Fisher two-sided p ≈ 0.16). The direction is what the rule
// predicts and the count is too small to say anything with, and the first
// question anyone reading that will ask is: how much of the smallness is the
// PHENOMENON being rare, and how much is the THRESHOLD being strict? The rule
// fires at three or more inline checks across two or more files (`MIN_SITES` /
// `MIN_FILES`). Nothing in the published numbers says whether the corpus is full
// of two-site cases sitting just under the bar, or genuinely empty.
//
// This script answers that by recomputing the firing decision at every
// combination of (minSites, minFiles) ∈ {2,3} × {1,2} over the SAME site
// population the shipped rule collects.
//
// ★ WHAT IT MUST NOT DO, AND HOW THAT IS ENFORCED HERE
//
// It must not change the shipped thresholds, and it must not become an argument
// for changing them. A sensitivity study whose conclusion is "we would find more
// at 2 sites" is not a finding — of course a lower bar fires more; the question
// that matters is what the extra firings ARE, and this script cannot answer that
// because it does not label anything. So:
//
//   - `MIN_SITES` and `MIN_FILES` are not imported, not read, and not written.
//     The four cells are literals below. If someone edits the constants in
//     `scattered-authorization.ts`, the (3,2) self-check at the bottom starts
//     failing, which is the correct alarm rather than a silent re-baselining.
//   - It calls `collectScatteredAuthSites`, which returns the site population
//     BEFORE any threshold is applied. It does not call `analyze`, so no
//     alternative finding is ever constructed and nothing here can be mistaken
//     for a scan result.
//   - The output is a matrix of COUNTS. It contains no severity, no confidence,
//     and no `label` field, so it cannot be mistaken for a population to label.
//
// ★ THE TWO CHECKS THAT MAKE THE MATRIX TRUSTWORTHY
//
//  1. MONOTONICITY. Loosening a threshold cannot lose a repository. If the
//     (2,1) set ever fails to contain the (3,2) set, the harness is wrong — the
//     counting, not the rule — and the script fails loudly rather than printing
//     a plausible table. Asserted per repository (the strong form: fires-at-
//     stricter implies fires-at-looser) as well as on the totals, because the
//     totals can stay ordered while individual repositories swap sides.
//  2. THE (3,2) CELL IS THE SHIPPED RULE. It is compared against what the
//     production harness (`smell010-eval.mjs`) actually recorded, repository by
//     repository. Agreement is the evidence that the other three cells are
//     measuring the same thing the product does; a disagreement means this
//     script's model of the rule has drifted from the rule, and the numbers in
//     the other cells are then worth nothing.
//
// Run from the repo root, after `npm run build`:
//   node scripts/smell010-sensitivity.mjs --limit 2      # smoke
//   node scripts/smell010-sensitivity.mjs --limit 0      # every repository
//
// Writes paper_data/smell010_sensitivity.json (gitignored) and a Markdown table.
//
// ★ ON THE DUPLICATED CORPUS/RESUME PLUMBING
//
// The repository walk, the sorted-prefix sampling, and the JSONL resume are
// copied from `smell010-eval.mjs` rather than extracted into a module the two
// share. The duplication is real and is taken on purpose: the eval harness
// measures the SHIPPED pipeline end to end and is the number the write-up
// quotes, and a helper shared with a sensitivity study is exactly the thing that
// gets "improved" for one caller and silently moves the other's denominators.
// Where the two must agree, they are CHECKED against each other — that is what
// the (3,2) self-check is — rather than made to agree by construction.

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
import * as analysisGraph from '@vibeguard/analysis-graph';

const { buildProjectIndex, collectProjectFiles, createBudget, collectScatteredAuthSites } =
  analysisGraph;

// ── The dependency this script cannot fake ──────────────────────────────────
//
// `collectScatteredAuthSites` is the pre-threshold site population, exported
// from `packages/analysis-graph/src/index.ts`. There is no honest substitute: a
// reimplementation of the site collector here would be a DIFFERENT detector, and
// its matrix would describe a rule nobody ships. So the script refuses to run
// rather than approximate, and says exactly what is missing.
if (typeof collectScatteredAuthSites !== 'function') {
  console.error('');
  console.error('CANNOT RUN: `collectScatteredAuthSites` is not exported by @vibeguard/analysis-graph.');
  console.error('');
  console.error('It must be exported from packages/analysis-graph/src/index.ts as');
  console.error('  export function collectScatteredAuthSites(project: ProjectIndex): readonly CheckSite[]');
  console.error('returning the site population BEFORE MIN_SITES/MIN_FILES are applied, and the');
  console.error('package must then be rebuilt (`npm run build`) — this script loads `dist`.');
  console.error('');
  console.error('No fallback is attempted on purpose: a site collector reimplemented here would');
  console.error('be a different detector, and its sensitivity matrix would describe a rule that');
  console.error('is not the one shipped.');
  process.exit(2);
}

const REPO_ROOT = process.cwd();
const CORPORA = [
  ['baseline', join(REPO_ROOT, 'paper_data', 'corpus1k')],
  ['vibe', join(REPO_ROOT, 'paper_data', 'corpus1k_vibe')],
];

/**
 * The cells. `[minSites, minFiles]`, literals, deliberately not imported.
 *
 * (3,2) is the shipped pair and is listed last so the table reads from loosest
 * to strictest and ends on the one that is real.
 */
const CELLS = [
  [2, 1],
  [2, 2],
  [3, 1],
  [3, 2],
];
const SHIPPED_CELL = '3/2';
const cellKey = ([s, f]) => `${s}/${f}`;

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

const OUT_PATH = argValue('--out', join(REPO_ROOT, 'paper_data', 'smell010_sensitivity.json'));
const ROWS_PATH = argValue(
  '--rows',
  join(REPO_ROOT, 'paper_data', 'smell010_sensitivity.rows.jsonl'),
);
/** The production run this is checked against, per repository. */
const EVAL_ROWS_PATH = argValue(
  '--eval-rows',
  join(REPO_ROOT, 'paper_data', 'smell010_eval.rows.jsonl'),
);
const EVAL_JSON_PATH = argValue('--eval', join(REPO_ROOT, 'paper_data', 'smell010_eval.json'));
const FRESH = argFlag('--fresh');
const ACCEPT_STALE = argFlag('--accept-stale-rows');

const ROW_SCHEMA = 1;
/** Bound on stored sites per repository: the counts are the result, not the dump. */
const MAX_STORED_SITES = 50;

function fnv1a(text, seed = 0x811c9dc5) {
  let hash = seed;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

/** See the same constant in `smell010-eval.mjs` for the reasoning and its limit. */
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

function listRepos(corpusDir) {
  if (!existsSync(corpusDir)) return null;
  return readdirSync(corpusDir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

const rowKey = (corpus, repo) => `${corpus}\0${repo}`;

function readRows(path) {
  const byKey = new Map();
  const fingerprints = new Set();
  let malformed = 0;
  let duplicates = 0;
  if (!existsSync(path)) return { byKey, malformed, duplicates, fingerprints };
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
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

function healTrailingLine(path) {
  if (!existsSync(path)) return;
  let size;
  try {
    size = statSync(path).size;
  } catch {
    return;
  }
  if (size === 0) return;
  if (readFileSync(path, 'utf8').slice(-1) !== '\n') appendFileSync(path, '\n', 'utf8');
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
const stale = [...prior.fingerprints].filter((f) => f !== `${ROW_SCHEMA}:${ENGINE_FINGERPRINT}`);
if (stale.length > 0 && !ACCEPT_STALE) {
  console.error(`REFUSING TO RESUME: ${ROWS_PATH} holds rows from another engine build.`);
  console.error(`  rows carry: ${stale.join(', ')}   this build: ${ROW_SCHEMA}:${ENGINE_FINGERPRINT}`);
  console.error('Use --fresh, or --rows <other-path>, or --accept-stale-rows.');
  process.exit(2);
}

const startedAt = Date.now();
let analysedThisRun = 0;
let reusedThisRun = 0;
const plan = [];

for (const [label, dir] of CORPORA) {
  const all = listRepos(dir);
  if (all === null) {
    console.error(`skipping ${label}: ${dir} does not exist`);
    continue;
  }
  const selected = argLimit === 0 ? all : all.slice(0, argLimit);
  plan.push({ label, all, selected });
  console.error(
    `${label}: collecting sites in ${selected.length} of ${all.length} repositories ` +
      `(sorted-prefix sample${argLimit === 0 ? ', FULL' : ''})`,
  );

  let i = 0;
  for (const name of selected) {
    i += 1;
    if (prior.byKey.has(rowKey(label, name))) {
      reusedThisRun += 1;
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
      siteCount: 0,
      fileCount: 0,
      // ★ Recorded because the production rule is BUDGETED and this pass is not.
      // `runCrossFileRules` checks `budget.expired()` before running any rule, so
      // a repository whose indexing overran the 10s wall-clock budget produces no
      // finding in production no matter how many sites it contains. Here the
      // collector is called regardless. Without this flag such a repository looks
      // like a (3,2) disagreement — i.e. like a broken harness — when it is
      // actually the deadline doing its job.
      expired: false,
      degradations: [],
      sites: [],
      sitesTruncated: false,
    };

    try {
      const budget = createBudget();
      const files = await collectProjectFiles(repoDir, budget);
      const project = buildProjectIndex(repoDir, files, budget);
      row.expired = budget.expired();
      const sites = collectScatteredAuthSites(project);
      row.siteCount = sites.length;
      row.fileCount = new Set(sites.map((s) => s.filePath)).size;
      row.sites = sites.slice(0, MAX_STORED_SITES).map((s) => ({
        filePath: s.filePath,
        line: s.line,
        signature: s.signature,
        elevated: s.elevated,
        handlerName: s.handlerName,
        evidence: typeof s.evidence === 'string' ? s.evidence.slice(0, 200) : null,
      }));
      row.sitesTruncated = sites.length > MAX_STORED_SITES;
      row.degradations = budget.degradations().map((d) => d.kind);
    } catch (err) {
      row.error = String(err && err.message);
    }

    row.ms = Date.now() - started;
    appendFileSync(ROWS_PATH, `${JSON.stringify(row)}\n`, 'utf8');
    analysedThisRun += 1;
    console.error(
      `[${label}] ${i}/${selected.length} ${name} ` +
        (row.error ? `ERROR ${row.error}` : `sites=${row.siteCount} files=${row.fileCount}`) +
        `${row.expired ? ' EXPIRED' : ''} ${row.ms}ms`,
    );
    if (analysedThisRun % 50 === 0) {
      const min = (Date.now() - startedAt) / 60000;
      console.error(
        `-- progress: ${i}/${selected.length} in ${label}; ${analysedThisRun} analysed this run; ` +
          `${min.toFixed(1)}min elapsed; ${(analysedThisRun / Math.max(min, 0.001)).toFixed(1)} repo/min --`,
      );
    }
  }
}

// ── Fold, from the rows on disk (see smell010-eval.mjs for why) ─────────────

const finalRows = readRows(ROWS_PATH);
const missing = [];
const perCorpus = {};
const perRepo = [];
const violations = [];

const fires = (row, [minSites, minFiles]) => row.siteCount >= minSites && row.fileCount >= minFiles;

for (const { label, all, selected } of plan) {
  const stats = {
    corpus: label,
    reposAvailable: all.length,
    reposAnalysed: selected.length,
    sampling: argLimit === 0 ? 'full' : `first ${argLimit} by sorted name`,
    reposErrored: 0,
    reposExpired: 0,
    reposWithAnySite: 0,
    totalSites: 0,
    // How many repositories sit at each site count. This is the number the
    // sensitivity question is really about: a corpus whose repositories cluster
    // at 1–2 sites has a threshold problem, and one that is empty at 1 has a
    // phenomenon-rarity problem. The matrix summarises it; this shows the shape.
    siteCountHistogram: {},
    wouldFire: Object.fromEntries(CELLS.map((c) => [cellKey(c), 0])),
  };

  for (const name of selected) {
    const row = finalRows.byKey.get(rowKey(label, name));
    if (!row) {
      missing.push(`${label}/${name}`);
      continue;
    }
    if (row.error) {
      stats.reposErrored += 1;
      continue;
    }
    if (row.expired) stats.reposExpired += 1;
    stats.totalSites += row.siteCount;
    if (row.siteCount > 0) {
      stats.reposWithAnySite += 1;
      stats.siteCountHistogram[row.siteCount] = (stats.siteCountHistogram[row.siteCount] ?? 0) + 1;
    }

    // ── Is the row internally consistent? ─────────────────────────────────
    //
    // This is the check with teeth, and it is a different one from monotonicity.
    // `siteCount` and `fileCount` are what every cell is decided from, and they
    // were computed in the collection loop from a site list that is also stored.
    // Re-deriving them from that list catches the failure the matrix could not
    // otherwise survive: a collector that returns duplicate sites, a fold that
    // reads the wrong field, or a row written by an older schema whose counts
    // meant something slightly different. Only possible when the stored list is
    // complete, hence the `sitesTruncated` guard.
    if (!row.sitesTruncated && Array.isArray(row.sites)) {
      if (row.sites.length !== row.siteCount) {
        violations.push(
          `${label}/${name}: siteCount=${row.siteCount} but ${row.sites.length} sites stored`,
        );
      }
      const derivedFiles = new Set(row.sites.map((s) => s.filePath)).size;
      if (derivedFiles !== row.fileCount) {
        violations.push(
          `${label}/${name}: fileCount=${row.fileCount} but stored sites span ${derivedFiles} files`,
        );
      }
    }

    const firedAt = {};
    for (const cell of CELLS) firedAt[cellKey(cell)] = fires(row, cell);
    for (const cell of CELLS) if (firedAt[cellKey(cell)]) stats.wouldFire[cellKey(cell)] += 1;

    // ── Monotonicity, per repository ──────────────────────────────────────
    //
    // For any two cells where one is componentwise ≤ the other, firing at the
    // STRICTER pair must imply firing at the LOOSER one.
    //
    // ★ HONEST LIMIT: with `fires()` as it stands — two independent `>=` tests
    // over the same two numbers — this loop is a TAUTOLOGY and can never fail.
    // It is kept anyway, and stated to be a tautology rather than presented as
    // evidence, because it is a tripwire for the next version of `fires()`: the
    // moment a cell gains a condition that is not a monotone function of
    // (siteCount, fileCount) — "and at least one site is elevated", "and not in
    // a test path" — the ordering stops being free and this starts catching it.
    // The checks that can fail today are the row-consistency one above and the
    // totals one below.
    for (const a of CELLS) {
      for (const b of CELLS) {
        if (a[0] <= b[0] && a[1] <= b[1] && firedAt[cellKey(b)] && !firedAt[cellKey(a)]) {
          violations.push(
            `${label}/${name}: fires at ${cellKey(b)} but not at the looser ${cellKey(a)} ` +
              `(sites=${row.siteCount} files=${row.fileCount})`,
          );
        }
      }
    }

    if (row.siteCount > 0) {
      perRepo.push({
        corpus: label,
        repo: name,
        siteCount: row.siteCount,
        fileCount: row.fileCount,
        expired: row.expired,
        wouldFire: firedAt,
        sites: row.sites,
        sitesTruncated: row.sitesTruncated,
      });
    }
  }

  // Monotonicity on the totals as well. Implied by the per-repository check when
  // that passes, and kept because it is the property a reader of the TABLE can
  // verify by eye — if the printed table is non-monotone the printing is wrong,
  // and that is a different bug from the counting being wrong.
  for (const a of CELLS) {
    for (const b of CELLS) {
      if (a[0] <= b[0] && a[1] <= b[1] && stats.wouldFire[cellKey(a)] < stats.wouldFire[cellKey(b)]) {
        violations.push(
          `${label}: total at ${cellKey(a)} (${stats.wouldFire[cellKey(a)]}) < total at the ` +
            `stricter ${cellKey(b)} (${stats.wouldFire[cellKey(b)]})`,
        );
      }
    }
  }

  perCorpus[label] = stats;
}

if (missing.length > 0) {
  console.error('');
  console.error(`REFUSING TO WRITE: ${missing.length} selected repositories have no row.`);
  console.error(`  first: ${missing.slice(0, 3).join(', ')}`);
  console.error('Re-run to fill the gaps (already-collected repositories are skipped).');
  process.exit(3);
}

if (violations.length > 0) {
  console.error('');
  console.error('HARNESS SELF-CHECK FAILED (row consistency / monotonicity) — a bug, not a result:');
  for (const v of violations.slice(0, 20)) console.error(`  ${v}`);
  if (violations.length > 20) console.error(`  … and ${violations.length - 20} more`);
  console.error('');
  console.error('Stored counts must match the stored sites, and loosening a threshold cannot');
  console.error('lose a repository. Nothing below is trustworthy while either is false, so no');
  console.error('output file is written.');
  process.exit(4);
}

// ── Self-check: the (3,2) cell IS the shipped rule ──────────────────────────

const selfCheck = (() => {
  const evalRows = readRows(EVAL_ROWS_PATH);
  const check = {
    source: null,
    compared: 0,
    agreed: 0,
    disagreements: [],
    excludedExpired: 0,
    note: '',
  };

  const shippedSet = new Set(
    perRepo.filter((r) => r.wouldFire[SHIPPED_CELL]).map((r) => `${r.corpus}\0${r.repo}`),
  );

  if (evalRows.byKey.size > 0) {
    check.source = EVAL_ROWS_PATH;
    for (const { label, selected } of plan) {
      for (const name of selected) {
        const evalRow = evalRows.byKey.get(rowKey(label, name));
        if (!evalRow || evalRow.error) continue;
        const here = finalRows.byKey.get(rowKey(label, name));
        if (!here || here.error) continue;
        // A repository the production run truncated cannot be compared: no rule
        // ran there at all, so its "no finding" is not a threshold decision.
        if (here.expired || (evalRow.degradations ?? []).length > 0) {
          check.excludedExpired += 1;
          continue;
        }
        check.compared += 1;
        const productionFired = (evalRow.findings ?? []).length > 0;
        const hereFires = shippedSet.has(rowKey(label, name));
        if (productionFired === hereFires) check.agreed += 1;
        else {
          check.disagreements.push({
            corpus: label,
            repo: name,
            productionFired,
            sensitivityFires: hereFires,
            siteCount: here.siteCount,
            fileCount: here.fileCount,
          });
        }
      }
    }
    check.note =
      'Compared repository by repository against the production harness rows. ' +
      'Repositories where either run reported a budget degradation are excluded: ' +
      'a truncated scan produces no finding for reasons that have nothing to do ' +
      'with the threshold, and counting it as a disagreement would hide a real one.';
  } else if (existsSync(EVAL_JSON_PATH)) {
    check.source = `${EVAL_JSON_PATH} (one-directional)`;
    try {
      const evalJson = JSON.parse(readFileSync(EVAL_JSON_PATH, 'utf8'));
      for (const f of evalJson.findings ?? []) {
        if (!f.ruleId) continue;
        check.compared += 1;
        if (shippedSet.has(rowKey(f.corpus, f.repo))) check.agreed += 1;
        else {
          check.disagreements.push({
            corpus: f.corpus,
            repo: f.repo,
            productionFired: true,
            sensitivityFires: false,
            siteCount: null,
            fileCount: null,
          });
        }
      }
    } catch {
      check.source = null;
    }
    check.note =
      'Only the rows file carries per-repository results, and it was absent, so this ' +
      'check ran against the summary JSON and could only verify ONE direction: every ' +
      'repository production reported also fires at (3,2) here. It cannot see a ' +
      'repository that fires here and did not in production. Run smell010-eval.mjs ' +
      'to produce the rows file for the full check.';
  } else {
    check.note =
      'NOT PERFORMED: neither the production rows file nor the summary JSON was found. ' +
      'The matrix below is unverified — the (3,2) cell has not been shown to match the ' +
      'shipped rule, so the other cells are not known to be measuring the same thing.';
  }
  return check;
})();

writeFileSync(
  OUT_PATH,
  JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      note:
        'VG-SMELL-010 threshold sensitivity. ANALYSIS ONLY — the shipped thresholds ' +
        '(MIN_SITES=3, MIN_FILES=2) are unchanged and were not read by this script. ' +
        'Cells other than 3/2 describe a rule that is not shipped and whose extra ' +
        'firings are UNLABELLED: this file says how many, never how many are correct.',
      cells: CELLS.map(cellKey),
      shippedCell: SHIPPED_CELL,
      engineFingerprint: ENGINE_FINGERPRINT,
      rows: {
        path: ROWS_PATH,
        analysedThisRun,
        reusedFromRows: reusedThisRun,
        malformedLinesIgnored: finalRows.malformed,
        duplicateRowsLastWins: finalRows.duplicates,
      },
      monotonicity: {
        checked: true,
        violations: [],
        whatWasChecked:
          'per-repository ordering (a tautology while a cell is two >= tests over the same ' +
          'two numbers, kept as a tripwire for a future non-monotone cell), the ordering of ' +
          'the printed totals (which a counting bug CAN break), and row consistency: stored ' +
          'siteCount/fileCount re-derived from the stored site list.',
      },
      selfCheck,
      perCorpus,
      perRepo,
    },
    null,
    2,
  ),
);

// ── Markdown ────────────────────────────────────────────────────────────────
const line = (s) => process.stdout.write(`${s}\n`);
line('');
line('# VG-SMELL-010 — threshold sensitivity (analysis only; shipping thresholds unchanged)');
line('');
line(`| corpus | analysed | repos with ≥1 site | total sites | ${CELLS.map((c) => `would fire ${cellKey(c)}`).join(' | ')} |`);
line(`|---|---|---|---|${CELLS.map(() => '---').join('|')}|`);
for (const [label, s] of Object.entries(perCorpus)) {
  line(
    `| ${label} | ${s.reposAnalysed}/${s.reposAvailable} | ${s.reposWithAnySite} | ${s.totalSites} | ` +
      `${CELLS.map((c) => (cellKey(c) === SHIPPED_CELL ? `**${s.wouldFire[cellKey(c)]}**` : s.wouldFire[cellKey(c)])).join(' | ')} |`,
  );
}
line('');
line(`**${SHIPPED_CELL} is the shipped pair** (MIN_SITES=3, MIN_FILES=2) and is the only column`);
line('that corresponds to a rule anyone runs. The others are counts of what a');
line('DIFFERENT rule would report, with no labelling behind them: a lower bar fires');
line('more by construction, and how many of those extra firings are real is a');
line('question this script does not ask and cannot answer.');
line('');
for (const [label, s] of Object.entries(perCorpus)) {
  line(
    `- **${label}**: sampling = ${s.sampling}; errored ${s.reposErrored}; budget-truncated ` +
      `${s.reposExpired}; site-count histogram ${JSON.stringify(s.siteCountHistogram)}`,
  );
}
line('');
line('## Self-check — does the (3,2) cell reproduce the shipped rule?');
line('');
if (selfCheck.source === null) {
  line(`- **NOT VERIFIED.** ${selfCheck.note}`);
} else {
  line(`- source: \`${selfCheck.source}\``);
  line(
    `- compared ${selfCheck.compared} repositories, **agreed on ${selfCheck.agreed}**, ` +
      `disagreed on ${selfCheck.disagreements.length}` +
      (selfCheck.excludedExpired > 0 ? `, excluded ${selfCheck.excludedExpired} budget-truncated` : ''),
  );
  for (const d of selfCheck.disagreements.slice(0, 10)) {
    line(
      `  - ${d.corpus}/${d.repo}: production fired=${d.productionFired}, here=${d.sensitivityFires}` +
        (d.siteCount === null ? '' : ` (sites=${d.siteCount}, files=${d.fileCount})`),
    );
  }
  if (selfCheck.disagreements.length > 0) {
    line('');
    line('  ⚠ A disagreement means this script no longer models the shipped rule. Until it');
    line('  is explained, the other three columns are not measuring the same detector and');
    line('  must not be quoted.');
  }
  line(`- ${selfCheck.note}`);
}
line('');
line('## Monotonicity and row consistency');
line('');
line('- no violations; the script exits non-zero WITHOUT writing output if there are any.');
line('- checked: (a) per-repository ordering — currently a tautology, kept as a tripwire');
line('  for a future cell that is not a monotone function of (sites, files); (b) the');
line('  ordering of the printed totals, which a counting bug can break; (c) row');
line('  consistency — `siteCount`/`fileCount` re-derived from the stored site list.');
line('');
line(`Written to \`${OUT_PATH}\`.`);

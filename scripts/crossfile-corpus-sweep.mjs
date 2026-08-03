// crossfile-corpus-sweep — run ANY cross-file rule over a real-code corpus,
// including rules that are not yet admitted to the registry.
//
// ★ WHY THIS EXISTS, AND WHY IT HAD TO BE GENERIC
//
// `design-smells-crossfile/index.ts` records the price of admission to the
// registry, and it is not "the rule has passing tests". VG-SMELL-041 and
// VG-SMELL-052 were both submitted with full fixture sets and both rejected
// after a sweep of `paper_data/corpus1k`: 041 produced three findings and none
// were true, and 052 fired on a correctly-mounted guard reached through an
// `export *` barrel. Fixtures could not have caught either, because the same
// person who wrote the detector wrote the fixtures.
//
// So the gate is a real-corpus sweep. The problem was that the only harness
// able to run one — `smell010-eval.mjs` — is welded to VG-SMELL-010: it filters
// `f.ruleId === 'VG-SMELL-010'`, computes 010's denominators, and writes 010's
// output paths. Every rule since has therefore been swept by an ad-hoc script
// written for that rule and thrown away afterwards, which means the GATE itself
// was un-reviewed, un-tested, and different every time. A gate that is
// re-implemented per candidate is not a gate.
//
// ★ THE PROPERTY THAT MAKES THIS USABLE BEFORE ADMISSION
//
// `analyzeProject` runs `crossFileRules`, and a candidate rule is deliberately
// NOT in that array until it has passed this sweep. Running the gate through
// `analyzeProject` would therefore be circular: nothing could ever be measured
// before it shipped. This harness resolves rule objects from the package's
// NAMED EXPORTS instead, so a rule can be exported (and therefore importable,
// testable, and measurable) while still being absent from the registry that
// decides what users see. That separation is what lets "implemented" and
// "shipped" be different states, which the no-empty-stubs doctrine requires.
//
// The dispatch below is a deliberate re-implementation of the loop in
// `project.ts` rather than a call into it, and the parts that must match are
// marked ★MIRROR. Chief among them is the `languages` filter, which
// `project.ts` enforces because VG-SMELL-010's Python arm once ran live and
// unfixtured. A sweep that ignored `languages` would measure a rule on inputs
// the product will never hand it, and report a precision the product does not
// have.
//
// ★ WHAT THIS SCRIPT DOES NOT DO
//
// It does not label findings true or false. That requires reading the
// implicated code and deciding, and that judgement is the reviewer's — the same
// position `smell010-eval.mjs` takes, for the same reason. What it produces is
// the population to label: EVERY finding, with repository, file, line and
// message, so a human can go through them. There is no field in the output to
// put a precision number in, because a precision number quoted without that
// pass would be fabricated.
//
// Usage:
//   node scripts/crossfile-corpus-sweep.mjs --rule VG-SMELL-011
//   node scripts/crossfile-corpus-sweep.mjs --rule VG-SMELL-011 --rule VG-SMELL-013
//   node scripts/crossfile-corpus-sweep.mjs --registry --limit 200
//   node scripts/crossfile-corpus-sweep.mjs --rule VG-SMELL-030 --corpus paper_data/corpus1k_vibe
//
// Output: `paper_data/crossfile_sweep_<slug>.rows.jsonl` (one row per
// repository, resumable) and `paper_data/crossfile_sweep_<slug>.json`, plus a
// Markdown summary on stdout. Both are gitignored research output.

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import * as ag from '@vibeguard/analysis-graph';

const { analyzeProject, buildProjectIndex, collectProjectFiles, createBudget, crossFileRules } = ag;

const REPO_ROOT = process.cwd();

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);

function argValues(flag) {
  const out = [];
  for (let i = 0; i < argv.length - 1; i += 1) {
    if (argv[i] === flag) out.push(argv[i + 1]);
  }
  return out;
}
function argValue(flag, fallback) {
  const all = argValues(flag);
  return all.length > 0 ? all[all.length - 1] : fallback;
}
const argFlag = (flag) => argv.includes(flag);

const wantedRuleIds = argValues('--rule');
const useRegistry = argFlag('--registry') || wantedRuleIds.length === 0;
const corpusDirs = argValues('--corpus');
const argLimit = Number(argValue('--limit', '0'));
const fresh = argFlag('--fresh');

if (!Number.isInteger(argLimit) || argLimit < 0) {
  console.error(`--limit must be a non-negative integer, got ${JSON.stringify(argValue('--limit'))}`);
  process.exit(2);
}

const CORPORA =
  corpusDirs.length > 0
    ? corpusDirs.map((d) => [d.replace(/[\\/]+$/, '').split(/[\\/]/).pop(), join(REPO_ROOT, d)])
    : [['corpus1k', join(REPO_ROOT, 'paper_data', 'corpus1k')]];

// ---------------------------------------------------------------------------
// Rule resolution — the reason this file exists
// ---------------------------------------------------------------------------

/**
 * Every rule-shaped named export of the package, by ruleId.
 *
 * "Rule-shaped" is checked structurally rather than by name, so a rule that is
 * exported but not registered is found, and a helper that happens to be
 * exported is not. The duplicate check matters: two exports claiming the same
 * ruleId would make `--rule` ambiguous and silently measure whichever the
 * iteration order reached first.
 */
function ruleExports() {
  const byId = new Map();
  for (const [exportName, value] of Object.entries(ag)) {
    if (!value || typeof value !== 'object') continue;
    if (typeof value.ruleId !== 'string') continue;
    if (typeof value.analyze !== 'function') continue;
    if (!Array.isArray(value.languages)) continue;
    const prior = byId.get(value.ruleId);
    if (prior && prior.rule !== value) {
      console.error(
        `two different exports claim ruleId ${value.ruleId} ` +
          `(${prior.exportName}, ${exportName}) — refusing to guess which one to measure`,
      );
      process.exit(2);
    }
    byId.set(value.ruleId, { exportName, rule: value });
  }
  return byId;
}

const available = ruleExports();
const registeredIds = new Set(crossFileRules.map((r) => r.ruleId));

let selected;
if (useRegistry) {
  selected = crossFileRules.map((r) => ({ rule: r, registered: true }));
} else {
  selected = [];
  for (const id of wantedRuleIds) {
    const hit = available.get(id);
    if (!hit) {
      console.error(`no exported rule with ruleId ${id}.`);
      console.error(`exported: ${[...available.keys()].sort().join(', ') || '(none)'}`);
      console.error(
        'A candidate rule must be exported from packages/analysis-graph/src/index.ts to be ' +
          'measurable. Exporting it does NOT register it — registration is the separate line ' +
          'in design-smells-crossfile/index.ts that this sweep is the gate for.',
      );
      process.exit(2);
    }
    selected.push({ rule: hit.rule, registered: registeredIds.has(id) });
  }
}

if (selected.length === 0) {
  console.error('no rules selected');
  process.exit(2);
}

const slug =
  useRegistry
    ? 'registry'
    : selected
        .map((s) => s.rule.ruleId.replace(/[^A-Za-z0-9]+/g, '-'))
        .sort()
        .join('_')
        .toLowerCase();

const ROWS_PATH = argValue('--rows', join(REPO_ROOT, 'paper_data', `crossfile_sweep_${slug}.rows.jsonl`));
const OUT_PATH = argValue('--out', join(REPO_ROOT, 'paper_data', `crossfile_sweep_${slug}.json`));

// ---------------------------------------------------------------------------
// Engine fingerprint — invalidates resumed rows when the build moved
// ---------------------------------------------------------------------------

const ROW_SCHEMA = 'cfsweep-1';

function fnv1a(text, seed) {
  let hash = seed >>> 0;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i) & 0xff;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

/**
 * A hash of the built `analysis-graph`, so a resumed run cannot mix rows
 * produced by two different builds.
 *
 * ⚠ MEASURED LIMIT, inherited verbatim from `smell010-eval.mjs`: this covers
 * `@vibeguard/analysis-graph` only. File admission and language detection come
 * from `@vibeguard/analyzer-core`, which is OUTSIDE the fingerprint — a change
 * there can alter which files are read without invalidating a row. `--fresh` is
 * the answer when core's file handling has moved.
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

// The selection is part of the row's validity too: a row written by a run that
// measured one rule says nothing about a second rule, so resuming across a
// different `--rule` set must not reuse it.
const SELECTION_FINGERPRINT = selected
  .map((s) => s.rule.ruleId)
  .sort()
  .join(',');
const ROW_VALIDITY = `${ROW_SCHEMA}:${ENGINE_FINGERPRINT}:${fnv1a(SELECTION_FINGERPRINT, 0x811c9dc5).toString(36)}`;

// ---------------------------------------------------------------------------
// Corpus walking
// ---------------------------------------------------------------------------

function listRepos(corpusDir) {
  if (!existsSync(corpusDir)) return null;
  return readdirSync(corpusDir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort();
}

const rowKey = (corpus, repo) => `${corpus}\u0000${repo}`;

function loadPriorRows(path) {
  const byKey = new Map();
  const stale = [];
  if (!existsSync(path)) return { byKey, stale };
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (line.trim().length === 0) continue;
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    if (row.valid !== ROW_VALIDITY) {
      stale.push(row);
      continue;
    }
    byKey.set(rowKey(row.corpus, row.repo), row);
  }
  return { byKey, stale };
}

function appendRow(path, row) {
  mkdirSync(dirname(path), { recursive: true });
  appendFileSync(path, `${JSON.stringify(row)}\n`, 'utf8');
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

if (fresh && existsSync(ROWS_PATH)) {
  writeFileSync(ROWS_PATH, '', 'utf8');
  console.error(`--fresh: cleared ${ROWS_PATH}`);
}

const prior = loadPriorRows(ROWS_PATH);
if (prior.stale.length > 0) {
  console.error(
    `${prior.stale.length} row(s) in ${ROWS_PATH} were written by a different build or rule ` +
      `selection and are being IGNORED (not deleted). This build: ${ROW_VALIDITY}`,
  );
}

console.error(
  `sweeping ${selected.length} rule(s): ` +
    selected.map((s) => `${s.rule.ruleId}${s.registered ? '' : ' [UNREGISTERED]'}`).join(', '),
);

const rows = [];
let analysedThisRun = 0;
let reusedThisRun = 0;

for (const [label, dir] of CORPORA) {
  const all = listRepos(dir);
  if (all === null) {
    console.error(`skipping ${label}: ${dir} does not exist`);
    continue;
  }
  const chosen = argLimit === 0 ? all : all.slice(0, argLimit);
  // Never a silent cap. A reader who sees "3 findings" must be able to tell
  // whether that was out of 200 repositories or out of 1,000.
  console.error(
    `${label}: analysing ${chosen.length} of ${all.length} repositories` +
      `${argLimit === 0 ? ' (FULL)' : ' (sorted-prefix sample — NOT the whole corpus)'}`,
  );

  let i = 0;
  for (const name of chosen) {
    i += 1;
    const key = rowKey(label, name);
    const done = prior.byKey.get(key);
    if (done) {
      rows.push(done);
      reusedThisRun += 1;
      if (i % 200 === 0) console.error(`[${label}] ${i}/${chosen.length} (resumed)`);
      continue;
    }

    const repoDir = join(dir, name);
    const started = Date.now();
    const row = {
      valid: ROW_VALIDITY,
      corpus: label,
      repo: name,
      ms: 0,
      error: null,
      languages: [],
      skippedByLanguage: [],
      degradations: [],
      findings: [],
    };

    try {
      const budget = createBudget();
      const files = await collectProjectFiles(repoDir, budget);
      const project = buildProjectIndex(repoDir, files, budget);

      // ★MIRROR project.ts: languages actually present, computed once.
      const presentLanguages = new Set(project.files.map((f) => f.language));
      row.languages = [...presentLanguages].sort();

      for (const { rule } of selected) {
        // ★MIRROR project.ts: between rules, not inside them.
        if (budget.expired()) break;
        // ★MIRROR project.ts: ENFORCE `languages`. Measuring a rule on inputs
        // the product would never hand it reports a precision the product does
        // not have.
        if (
          !rule.languages.includes('*') &&
          !rule.languages.some((l) => presentLanguages.has(l))
        ) {
          row.skippedByLanguage.push(rule.ruleId);
          continue;
        }
        let produced;
        try {
          produced = rule.analyze({ project, budget });
        } catch (err) {
          // ★MIRROR project.ts: a rule that threw produces an ABSENCE, not a
          // clean result, and the sweep must say so rather than score a zero.
          row.degradations.push(`${rule.ruleId} THREW: ${err instanceof Error ? err.message : String(err)}`);
          continue;
        }
        for (const f of produced) {
          row.findings.push({
            ruleId: f.ruleId,
            severity: f.severity,
            confidence: f.confidence,
            file: f.filePath ?? '(no file)',
            line: f.startLine ?? 0,
            // `title` is the one-line accusation and `description` is the
            // argument for it. The labelling pass needs both: the title alone
            // is too short to judge and the description alone does not say
            // which rule is speaking.
            title: f.title ?? '(no title)',
            description: f.description ?? '',
            // The claim of a design smell is about the SET of locations, so a
            // reviewer who reads only the primary one is judging a different,
            // weaker finding than the rule actually made.
            related: (f.relatedLocations ?? []).map((l) => `${l.filePath}:${l.startLine}`),
          });
        }
      }

      for (const d of [...project.degradations, ...budget.degradations()]) {
        row.degradations.push(d.detail);
      }
    } catch (err) {
      row.error = String(err && err.message);
    }

    row.ms = Date.now() - started;
    appendRow(ROWS_PATH, row);
    rows.push(row);
    analysedThisRun += 1;

    const hits = row.findings.length;
    if (hits > 0 || row.error) {
      console.error(
        `[${label}] ${i}/${chosen.length} ${name} ${row.error ? `ERROR ${row.error}` : `${hits} finding(s)`}`,
      );
    } else if (i % 100 === 0) {
      console.error(`[${label}] ${i}/${chosen.length}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Fold — computed from the ROWS, never from in-memory counters
// ---------------------------------------------------------------------------

const perRule = new Map();
for (const { rule } of selected) {
  perRule.set(rule.ruleId, {
    ruleId: rule.ruleId,
    registered: registeredIds.has(rule.ruleId),
    languages: rule.languages,
    findings: 0,
    reposWithFindings: 0,
    reposSkippedByLanguage: 0,
    sites: [],
  });
}

let reposAnalysed = 0;
let reposErrored = 0;
let reposThrewInRule = 0;
for (const row of rows) {
  reposAnalysed += 1;
  if (row.error) reposErrored += 1;
  if ((row.degradations ?? []).some((d) => d.includes('THREW'))) reposThrewInRule += 1;
  for (const id of row.skippedByLanguage ?? []) {
    const agg = perRule.get(id);
    if (agg) agg.reposSkippedByLanguage += 1;
  }
  const seenRules = new Set();
  for (const f of row.findings ?? []) {
    const agg = perRule.get(f.ruleId);
    if (!agg) continue;
    agg.findings += 1;
    if (!seenRules.has(f.ruleId)) {
      agg.reposWithFindings += 1;
      seenRules.add(f.ruleId);
    }
    agg.sites.push({ corpus: row.corpus, repo: row.repo, ...f });
  }
}

const summary = {
  schema: ROW_SCHEMA,
  rowValidity: ROW_VALIDITY,
  engineFingerprint: ENGINE_FINGERPRINT,
  corpora: CORPORA.map(([label, dir]) => ({ label, dir: dir.slice(REPO_ROOT.length + 1) })),
  limit: argLimit === 0 ? 'full' : argLimit,
  reposAnalysed,
  reposErrored,
  reposWithRuleCrash: reposThrewInRule,
  analysedThisRun,
  reusedThisRun,
  rules: [...perRule.values()],
  // Deliberately absent: any precision or true-positive field. Labelling is a
  // human pass over `sites`, and a number here would invite it being skipped.
};

mkdirSync(dirname(OUT_PATH), { recursive: true });
writeFileSync(OUT_PATH, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

// ---------------------------------------------------------------------------
// Markdown, on stdout
// ---------------------------------------------------------------------------

const lines = [];
lines.push('# cross-file corpus sweep');
lines.push('');
lines.push(`- corpora: ${summary.corpora.map((c) => `\`${c.dir}\``).join(', ')}`);
lines.push(`- repositories analysed: **${reposAnalysed}**${argLimit === 0 ? ' (full corpus)' : ` (capped at ${argLimit} per corpus — NOT the whole corpus)`}`);
lines.push(`- repositories that errored: ${reposErrored}`);
lines.push(`- repositories where a rule threw: ${reposThrewInRule}${reposThrewInRule > 0 ? ' ⚠ those findings are ABSENT, not clean' : ''}`);
lines.push(`- engine fingerprint: \`${ENGINE_FINGERPRINT}\``);
lines.push('');
lines.push('| rule | registered | findings | repos hit | repos skipped (language) |');
lines.push('|---|---|---|---|---|');
for (const agg of summary.rules) {
  lines.push(
    `| ${agg.ruleId} | ${agg.registered ? 'yes' : '**no — candidate**'} | ${agg.findings} | ` +
      `${agg.reposWithFindings} | ${agg.reposSkippedByLanguage} |`,
  );
}
lines.push('');
for (const agg of summary.rules) {
  if (agg.sites.length === 0) {
    lines.push(`## ${agg.ruleId} — 0 findings`);
    lines.push('');
    lines.push(
      'Zero findings over real code establishes that the rule does not fire on a large body ' +
        'of code nobody here wrote. It establishes NOTHING about recall: no true positive was ' +
        'produced either, so the only evidence of usefulness is the rule\'s own fixtures.',
    );
    lines.push('');
    continue;
  }
  lines.push(`## ${agg.ruleId} — ${agg.sites.length} findings, ALL listed (label each)`);
  lines.push('');
  for (const s of agg.sites) {
    lines.push(`- \`${s.corpus}/${s.repo}\` **${s.file}:${s.line}** [${s.severity}/${s.confidence}]`);
    lines.push(`  - ${String(s.title ?? '').replace(/\s+/g, ' ')}`);
    if (s.description) lines.push(`  - ${String(s.description).replace(/\s+/g, ' ')}`);
    if (s.related.length > 0) lines.push(`  - related: ${s.related.map((r) => `\`${r}\``).join(', ')}`);
  }
  lines.push('');
}
lines.push('---');
lines.push('');
lines.push(
  '**No verdict is computed here.** Each site above has to be opened and judged true or false ' +
    'by a reviewer; a precision figure that did not come from that pass would be fabricated. ' +
    `Rows: \`${ROWS_PATH.slice(REPO_ROOT.length + 1)}\` · summary: \`${OUT_PATH.slice(REPO_ROOT.length + 1)}\``,
);

console.log(lines.join('\n'));

// `analyzeProject` is imported so the module graph matches what the product
// loads, and referenced here so a linter cannot quietly drop the import and
// change what the fingerprint covers.
void analyzeProject;

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
// Run from the repo root, after `npm run build`:
//   node scripts/smell010-eval.mjs                 # default sample per corpus
//   node scripts/smell010-eval.mjs --limit 300     # larger sample
//   node scripts/smell010-eval.mjs --limit 0       # every repository
//
// Writes paper_data/smell010_eval.json (gitignored — research output stays local)
// and prints a Markdown summary.

import { readdirSync, readFileSync, statSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
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

const CODE_EXT = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
const SKIP_DIR = new Set(['.git', 'node_modules', 'dist', 'build', 'vendor', 'out', 'target']);

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

const results = [];
const summary = {};

for (const [label, dir] of CORPORA) {
  const all = listRepos(dir);
  if (all === null) {
    console.error(`skipping ${label}: ${dir} does not exist`);
    continue;
  }
  const selected = argLimit === 0 ? all : all.slice(0, argLimit);
  // Never a silent cap: the write-up must be able to say what was and was not
  // looked at, and a reader who sees only "37 repositories fired" has no way to
  // know it was out of a sample rather than out of the whole corpus.
  console.error(
    `${label}: analysing ${selected.length} of ${all.length} repositories ` +
      `(sorted-prefix sample${argLimit === 0 ? ', FULL' : ''})`,
  );

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

  for (const name of selected) {
    const repoDir = join(dir, name);
    let out;
    try {
      out = await analyzeProject(repoDir);
    } catch (err) {
      // A repository that cannot be analysed is recorded, not dropped. A silent
      // drop moves a repo out of the denominator and inflates every rate.
      perCorpus.reposSkipped += 1;
      results.push({ corpus: label, repo: name, error: String(err && err.message) });
      continue;
    }

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
        perCorpus.reposWithTsJs += 1;
        const index = buildProjectIndex(repoDir, files, budget);
        let routes = 0;
        let handlers = 0;
        for (const s of index.structures.values()) {
          routes += s.routes.length;
          handlers += s.symbols.filter((x) => x.kind === 'route-handler').length;
        }
        perCorpus.totalRoutes += routes;
        perCorpus.totalHandlers += handlers;
        if (routes > 0) perCorpus.reposWithRoutes += 1;
        if (handlers > 0) perCorpus.reposWithHandlers += 1;
      }
    } catch {
      /* denominators are best-effort; a failure here must not lose the finding */
    }

    const smells = out.findings.filter((f) => f.ruleId === 'VG-SMELL-010');
    const size = measureSize(repoDir);
    perCorpus.totalFiles += size.files;
    perCorpus.totalLines += size.lines;

    if (smells.length === 0) continue;
    perCorpus.reposWithFinding += 1;
    perCorpus.totalFindings += smells.length;

    for (const f of smells) {
      const sites = 1 + (f.relatedLocations ?? []).length;
      perCorpus.totalSites += sites;
      perCorpus.severity[f.severity] = (perCorpus.severity[f.severity] ?? 0) + 1;
      perCorpus.siteCountHistogram[sites] = (perCorpus.siteCountHistogram[sites] ?? 0) + 1;

      results.push({
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
        label: null,
      });
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
  summary[label] = perCorpus;
}

const outDir = join(REPO_ROOT, 'paper_data');
if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
const outPath = join(outDir, 'smell010_eval.json');
writeFileSync(
  outPath,
  JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      note:
        'VG-SMELL-010 population for manual labelling. `label` is null on every ' +
        'row by construction: no precision or recall figure in this file was ' +
        'computed, because none can be without a human reading the sites.',
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
line(`Population written to \`${outPath}\` — ${results.length} row(s), every \`label\` null.`);
line('');
line('**No precision figure is reported here and none is computable from this file.**');
line('Labelling the rows is a separate, human pass; until it is done the honest');
line('statement is "the rule fires at rate X on corpus Y", not "the rule is X% precise".');

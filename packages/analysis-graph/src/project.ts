// The runner: read a project, build the index, run the cross-file rules, and
// hand back findings in the shape the CLI can merge into an ordinary scan.
//
// WHY THIS DEPENDS ON @vibeguard/analyzer-core
//
// It would be easy to walk the directory here with a private ignore list, and it
// would be wrong. The CLI runs the core engine and this pass over the SAME
// target, and their outputs land in one report. If the two disagree about which
// files exist — because one honours `DEFAULT_IGNORE` and the other reimplements
// it, or because one maps `.mjs` to JavaScript and the other does not — then a
// cross-file finding can cite a file the core scan never opened, or miss a
// handler the core scan reported on. That inconsistency would be invisible in
// testing and infuriating in use.
//
// So the ignore set and the language mapping come from `analyzer-core`, which
// owns them. The dependency direction is the safe one: this package may know
// about core, and core must never know about this package — that asymmetry is
// what keeps the extensions free of cross-file code, and it is asserted by
// `scripts/check-packaging-invariants.mjs` rather than left to discipline.

import { readdir, readFile, stat } from 'node:fs/promises';
import { join as pathJoin, relative, resolve, sep } from 'node:path';
import {
  DEFAULT_IGNORE,
  detectLanguageFromPath,
  evaluatePathSuppression,
  suppressionsForPath,
  type VibeguardConfig,
} from '@vibeguard/analyzer-core';
import type { Finding, ScanDegradation, ScanResponse } from '@vibeguard/findings-schema';
import { summarize } from '@vibeguard/findings-schema';
import { admitFiles, createBudget, type CreateBudgetOptions } from './budget.js';
import {
  buildDependencyGraph,
  linkRouteHandlers,
  normalizePath,
  toSourceFile,
} from './dependency-graph/index.js';
import { indexFile, isIndexableLanguage } from './structure-indexer/index.js';
import { buildSymbolTable } from './symbol-table/index.js';
import { ANALYSIS_GRAPH_VERSION } from './version.js';
import { crossFileRules } from './design-smells-crossfile/index.js';
import type {
  CrossFileFinding,
  GraphBudget,
  GraphDegradation,
  ProjectIndex,
  SourceFile,
} from './types.js';

/**
 * Largest single file admitted, mirroring `MAX_FILE_BYTES` in the core file
 * scanner so the two passes agree on what counts as a source file.
 */
const MAX_FILE_BYTES = 1024 * 1024;

export interface AnalyzeProjectOptions extends CreateBudgetOptions {
  /** Extra directory names to ignore, on top of `DEFAULT_IGNORE`. */
  ignore?: string[];
  /** Injected id generator, so tests get stable ids. */
  makeId?: (index: number) => string;
}

async function* walk(dir: string, ignore: Set<string>): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  // Sorted, so admission under a budget cap is the same on every run and on
  // every filesystem. See `admitFiles` for why that matters.
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    if (ignore.has(entry.name)) continue;
    const full = pathJoin(dir, entry.name);
    if (entry.isDirectory()) yield* walk(full, ignore);
    else if (entry.isFile()) yield full;
  }
}

/**
 * Read the project's source files, honouring the budget.
 *
 * Sizes are collected before any content is read so `admitFiles` can decline a
 * file rather than decline it after paying for it.
 */
export async function collectProjectFiles(
  rootDir: string,
  budget: GraphBudget,
  options: AnalyzeProjectOptions = {},
): Promise<SourceFile[]> {
  const ignore = new Set([...DEFAULT_IGNORE, ...(options.ignore ?? [])]);
  const root = resolve(rootDir);

  const candidates: { filePath: string; absolute: string; size: number }[] = [];
  for await (const absolute of walk(root, ignore)) {
    const language = detectLanguageFromPath(absolute);
    // Only languages this phase can index. A YAML file contributes no symbols,
    // no imports, and no routes, so admitting it would spend budget to learn
    // nothing — and would make the file-limit degradation misreport how much
    // analysable source was skipped.
    if (!language || !isIndexableLanguage(language)) continue;
    let info;
    try {
      info = await stat(absolute);
    } catch {
      continue;
    }
    if (info.size > MAX_FILE_BYTES) continue;
    candidates.push({
      filePath: normalizePath(relative(root, absolute).split(sep).join('/')),
      absolute,
      size: info.size,
    });
  }

  const byPath = new Map(candidates.map((c) => [c.filePath, c]));
  const admitted = admitFiles(
    candidates.map((c) => ({ filePath: c.filePath, size: c.size })),
    budget,
    options,
  );

  const files: SourceFile[] = [];
  for (const filePath of admitted) {
    const candidate = byPath.get(filePath)!;
    let content: string;
    try {
      content = await readFile(candidate.absolute, 'utf8');
    } catch {
      continue;
    }
    files.push(toSourceFile(filePath, detectLanguageFromPath(candidate.absolute)!, content));
  }
  return files;
}

/**
 * Build the read-only index the cross-file rules run against.
 *
 * Phase order is index → graph → symbols, and it is a real dependency chain
 * rather than an arbitrary sequence: the graph resolves the imports the indexer
 * found, and the symbol table's strongest guard signal ("this symbol was used in
 * a route's pre-handler position") comes from route bindings the indexer
 * produced. The deadline is checked BETWEEN phases; see `GRAPH_DEADLINE_MS` for
 * why not inside them.
 */
export function buildProjectIndex(
  rootDir: string,
  files: SourceFile[],
  budget: GraphBudget,
): ProjectIndex {
  const structures = files.map((f) => indexFile(f));
  const graph = buildDependencyGraph(structures);
  // Must run after the graph: it resolves handler bindings through import edges,
  // which do not have a `resolvedFile` until the graph has been built.
  linkRouteHandlers(structures, graph);
  const symbols = budget.expired()
    ? { roles: new Map(), guards: new Set<string>() }
    : buildSymbolTable(structures);

  return {
    rootDir,
    files,
    structures: new Map(structures.map((s) => [s.filePath, s])),
    graph,
    symbols,
    degradations: budget.degradations(),
  };
}

/**
 * Deterministic finding ids.
 *
 * The core engine's ids embed `Date.now()`, so two scans of an unchanged tree
 * produce different ids. That is harmless there — nothing keys off them — but
 * it is exactly wrong for a design smell, whose whole workflow is "is this the
 * same finding I already triaged, or a new one". Ids here are derived from the
 * rule and the primary location, so an unchanged finding keeps its identity
 * across runs and a baseline diff stays empty.
 *
 * FNV-1a rather than `node:crypto`, so nothing in this file's hot path depends
 * on a Node builtin that a future browser-side reuse could not provide. A hash
 * collision would merge two ids and is not a security property here — the id is
 * a correlation key, not a claim.
 */
function stableId(finding: CrossFileFinding): string {
  const key = `${finding.ruleId}|${finding.filePath ?? ''}|${finding.startLine ?? 0}|${
    (finding.relatedLocations ?? []).length
  }`;
  let hash = 0x811c9dc5;
  for (let i = 0; i < key.length; i += 1) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `vg-ag-${hash.toString(36)}`;
}

/** Convert a graph budget outcome into the schema's degradation channel. */
function toScanDegradation(d: GraphDegradation): ScanDegradation {
  return {
    // The schema's `kind` union is closed and describes the core engine's own
    // bounds. Rather than widen a shared type for an optional package, graph
    // bounds report as `input-truncated` — the closest true statement, since
    // every one of them means "part of the input was not read" — and the
    // `detail` string carries which bound it was.
    kind: 'input-truncated',
    ruleId: 'VG-GRAPH',
    detail: d.detail,
  };
}

export interface CrossFileResult {
  findings: Finding[];
  degradations: ScanDegradation[];
  engineVersion: string;
}

/**
 * Apply the config `suppress` channel to cross-file findings.
 *
 * WHY THIS IS NOT OPTIONAL PLUMBING
 *
 * Without it, a team that writes `{"suppress":[{"paths":["src/legacy/**"],
 * "rules":["VG-SMELL-010"]}]}` watches the finding come back on every run. The
 * whole "precision contract plus an escape hatch" design of this project rests
 * on the hatch existing; a rule that cannot be silenced is a rule that gets
 * turned off wholesale, and for a design smell emitted at `high` under the
 * default `--fail-on high` gate, "turned off wholesale" means the CI job is
 * either red forever or the flag is removed. Neither is a supported outcome.
 *
 * The suppression decision is made against the PRIMARY location, not against
 * every related one, and that choice needs stating because it is the one place
 * a `project`-scoped finding does not fit the per-file model the config was
 * written for. A cross-file finding implicates several files; asking "is it
 * suppressed" for each of them yields several answers with no principled way to
 * combine them:
 *
 *  - ANY match suppresses  → one ignored legacy file silences a finding whose
 *    other four sites are in live code. Too weak.
 *  - ALL must match        → a finding is unsuppressable unless every site is
 *    covered, so the natural request ("stop telling me about the legacy area")
 *    fails whenever the smell straddles the boundary. Too strong to be usable.
 *
 * The primary location is where the finding is FILED — it is what `filePath`
 * says, what a reviewer clicks, and what a `baseline` keys on. Suppressing by it
 * means the config question is asked of the same path the rest of the pipeline
 * already treats as the finding's home, so the answer is predictable from what
 * the user sees. Findings whose primary site is outside the glob still appear,
 * which is the conservative direction.
 *
 * The severity gate is NOT re-implemented here: `evaluatePathSuppression` is the
 * same function the core path calls, so a blanket wildcard is refused for
 * security-judgement severities in exactly the same way and by exactly the same
 * code. Duplicating that policy for this channel is how the two drift.
 */
export function applyConfigSuppression(
  result: CrossFileResult,
  config: VibeguardConfig | undefined,
  now: Date = new Date(),
): CrossFileResult {
  if (!config?.suppress || result.findings.length === 0) return result;

  const kept: Finding[] = [];
  for (const finding of result.findings) {
    const path = finding.filePath;
    if (path === undefined) {
      kept.push(finding);
      continue;
    }
    const suppressed = suppressionsForPath(config, path, now);
    const decision = evaluatePathSuppression(suppressed, finding.ruleId, finding.severity);
    if (decision.suppressed) continue;
    kept.push(
      decision.overridden
        ? // A blanket suppression matched and the severity gate refused it. The
          // finding survives and carries the evidence of the attempt, the same
          // contract `SuppressionOverride` documents for the core path.
          { ...finding, suppressionOverridden: decision.overridden }
        : finding,
    );
  }

  return { ...result, findings: kept };
}

/** Run every cross-file rule over an already-built index. */
export function runCrossFileRules(
  project: ProjectIndex,
  budget: GraphBudget,
  options: AnalyzeProjectOptions = {},
): CrossFileResult {
  const findings: Finding[] = [];
  let index = 0;

  // Languages actually present in the scanned tree. Computed once: every rule
  // asks the same question and the answer cannot change mid-run.
  const presentLanguages = new Set(project.files.map((f) => f.language));
  const ruleErrors: ScanDegradation[] = [];

  for (const rule of crossFileRules) {
    // Between rules, not inside them: a rule that has started should finish, so
    // a partial rule result never masquerades as a complete one.
    if (budget.expired()) break;

    // ENFORCE `CrossFileRule.languages`. It was declared from the start and
    // consulted by nothing, which made it a contract fiction: a rule author
    // reading the interface would reasonably conclude that listing languages
    // restricts where the rule runs, and it did not. The consequence was not
    // theoretical — VG-SMELL-010's Python arm was live and unfixtured, firing on
    // Flask handlers that no test covered.
    //
    // A declaration nothing reads is worse than no declaration, because it
    // creates a belief. Either the field means something or it should not exist;
    // this makes it mean something.
    if (
      !rule.languages.includes('*') &&
      !rule.languages.some((l) => presentLanguages.has(l))
    ) {
      continue;
    }

    let produced: CrossFileFinding[];
    try {
      produced = rule.analyze({ project, budget });
    } catch (err) {
      // One broken rule must not take the scan down — same posture as the core
      // analyzer. But it must not vanish either: `budget.ts` states that a
      // partial result which looks clean is the worse of the two failures, and a
      // rule that threw produces exactly that. So the crash is reported through
      // the degradation channel the CLI already renders, rather than being
      // swallowed with a comment apologising for swallowing it.
      ruleErrors.push({
        kind: 'input-truncated',
        ruleId: rule.ruleId,
        detail:
          `Cross-file rule ${rule.ruleId} threw and was skipped ` +
          `(${err instanceof Error ? err.message : String(err)}). Findings it would have ` +
          `reported are ABSENT, not clean — this scan does not answer the question that ` +
          `rule asks.`,
      });
      continue;
    }
    for (const f of produced) {
      findings.push({ ...f, findingId: options.makeId?.(index) ?? stableId(f) } as Finding);
      index += 1;
    }
  }

  return {
    findings,
    degradations: [
      ...[...project.degradations, ...budget.degradations()]
        // The project's list and the budget's list overlap when a bound bit
        // during indexing; dedupe on the message so the reader sees each fact
        // once.
        .filter((d, i, all) => all.findIndex((o) => o.detail === d.detail) === i)
        .map(toScanDegradation),
      ...ruleErrors,
    ],
    engineVersion: ANALYSIS_GRAPH_VERSION,
  };
}

/** Read a directory, index it, and run every cross-file rule over it. */
export async function analyzeProject(
  rootDir: string,
  options: AnalyzeProjectOptions = {},
): Promise<CrossFileResult> {
  const budget = createBudget(options);
  const files = await collectProjectFiles(rootDir, budget, options);
  const project = buildProjectIndex(rootDir, files, budget);
  return runCrossFileRules(project, budget, options);
}

/**
 * Fold cross-file findings into an ordinary scan response.
 *
 * Lives HERE rather than in `analyzer-core`, even though the target package
 * plan once put a `result-merger` there. Putting it in core would mean core
 * carrying a function whose only purpose is to consume this package's output —
 * a conceptual dependency pointing the forbidden way, and a standing invitation
 * for someone to make it a real import. The merge is a CLI-layer concern and
 * this is the CLI's side of the boundary.
 *
 * What it does NOT do is as important as what it does: it does not touch
 * `engineVersions.core`, does not renumber or reorder the existing findings, and
 * does not alter their ids. A consumer filtering the design-smell category back
 * out must get byte-identical output to a scan that never ran this pass, because
 * that identity is the regression contract E2 is written against.
 */
export function mergeCrossFileFindings(
  response: ScanResponse,
  result: CrossFileResult,
): ScanResponse {
  if (result.findings.length === 0 && result.degradations.length === 0) {
    return {
      ...response,
      engineVersions: { ...response.engineVersions, 'analysis-graph': result.engineVersion },
    };
  }
  const findings = [...response.findings, ...result.findings];
  const degradations = [...(response.degradations ?? []), ...result.degradations];
  return {
    ...response,
    findings,
    summary: summarize(findings),
    engineVersions: { ...response.engineVersions, 'analysis-graph': result.engineVersion },
    ...(degradations.length > 0 ? { degradations } : {}),
  };
}

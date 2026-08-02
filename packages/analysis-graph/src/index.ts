// @vibeguard/analysis-graph — the cross-file brain (Phase 0.3.0-α).
//
// ★ THE CONSTRAINT THIS PACKAGE EXISTS TO SATISFY
//
// Cross-file analysis, taint tracking, and any AST dependency stay HERE, behind
// an opt-in flag, reachable only from the CLI and the GitHub Action. The Chrome
// extension and the VS Code extension bundle `analyzer-core` + `rules` and
// nothing else. That is not a packaging preference; it is what keeps the three
// product pillars true — zero dependencies, light enough to run on every
// keystroke in a browser, and four channels that provably agree — and those
// three pillars are the whole distribution strategy. A single import of this
// package from `analyzer-core` would put a project-wide graph builder inside a
// service worker, and the pillars would go with it.
//
// The boundary is not maintained by discipline. `scripts/check-packaging-
// invariants.mjs` asserts it three ways (source imports, declared dependencies,
// and the literal `AG_BUNDLE_SENTINEL` below appearing in no shipped bundle),
// and that check runs in the test suite.
//
// WHAT LIVES HERE
//
//   structure-indexer/     what is in a file      (symbols, routes, imports)
//   dependency-graph/      what points at what    (import edges, #include edges)
//   symbol-table/          what identifiers mean  (role/guard/token inference)
//   metrics/              what the numbers are   (DesignMetrics)
//   design-smells-crossfile/ the rules that need all four
//   taint/                 intra-procedural source→sink (H1 skeleton)

/**
 * A string that must never appear in a shipped browser or editor bundle.
 *
 * The packaging probe's third and strongest invariant. The other two read
 * declarations — `package.json` dependency lists and `import` statements in
 * source — and both share a blind spot: they check what the code SAYS, and a
 * bundler follows what the code DOES. A transitive path through a re-export, a
 * dynamic import a bundler decided to inline, or a hand-edited `dist` would
 * satisfy both while shipping this package to every extension user.
 *
 * A literal string survives minification — identifier mangling does not touch
 * string contents — and is greppable in a built artefact with no parsing. So the
 * probe's question becomes empirical rather than declarative: not "should this
 * package be in the bundle" but "is it".
 *
 * ★ MEASURED LIMIT — this is a SECONDARY needle, not the primary one.
 *
 * The first version of this comment claimed the sentinel "cannot be tree-shaken
 * out of a module whose code was included". That was measured and is false, in
 * two stages, and the record is kept here because the false version was
 * convincing enough to ship:
 *
 *  1. esbuild includes a module and then drops the individual declarations
 *     nothing references. A `const` string nobody reads is exactly such a
 *     declaration, so a realistic leak left no sentinel behind.
 *  2. Giving it a non-elidable side effect (`Object.defineProperty(globalThis,
 *     …)`) did not help either, for a more interesting reason: esbuild FLATTENS
 *     re-exports. `import { createBudget } from '@vibeguard/analysis-graph'`
 *     resolves straight through this barrel into `budget.js`, so this file is
 *     never part of the bundle at all and no statement in it can be evidence of
 *     anything. An anchor in a module the bundler skips anchors nothing.
 *
 * What actually detects a leak is `packages/analysis-graph/` appearing in the
 * bundler's per-module path comments, which are emitted for every module that IS
 * included. `scripts/check-packaging-invariants.mjs` uses that as the primary
 * needle and asserts the needle is still viable before trusting it.
 *
 * This constant remains as the secondary needle, for the case the path comment
 * cannot cover: a hand-patched or vendored `dist` that was not produced by the
 * current build at all, and whose module comments therefore prove nothing. It
 * costs one line and covers a case nothing else does.
 *
 * Never change this value casually — `check-packaging-invariants.mjs` hard-codes
 * it, and a mismatch makes the probe pass by searching for a string nobody
 * emits, which is the exact failure mode of a check that looks green forever.
 * `scripts/packaging-invariants.test.ts` guards the pair.
 */
export const AG_BUNDLE_SENTINEL = 'vibeguard:analysis-graph:must-not-ship-in-extensions';

export { ANALYSIS_GRAPH_VERSION } from './version.js';

export {
  analyzeProject,
  applyConfigSuppression,
  buildProjectIndex,
  collectProjectFiles,
  mergeCrossFileFindings,
  runCrossFileRules,
  type AnalyzeProjectOptions,
  type CrossFileResult,
} from './project.js';

export { crossFileRules, scatteredAuthorization } from './design-smells-crossfile/index.js';

/**
 * VG-SMELL-010's pre-threshold population, for the recall / sensitivity analysis.
 *
 * Imported from the RULE MODULE rather than from `design-smells-crossfile/
 * index.js`, and that is deliberate rather than an oversight. That barrel is the
 * RULE REGISTRY — `crossFileRules` is what `runCrossFileRules` iterates, and
 * everything re-exported beside it reads as "part of the rule set". This is not
 * a rule and not part of one: it is an inspection affordance for a study that
 * runs beside the engine, and filing it with the registry would invite the next
 * reader to wonder which pass executes it.
 *
 * `CheckSite` comes with it because a `readonly CheckSite[]` a caller cannot
 * name is a return type they have to re-declare, and a re-declared structural
 * copy is a contract that silently stops matching the day a field is added.
 *
 * ★ The thresholds this deliberately does not apply (`MIN_SITES`, `MIN_FILES`)
 * are NOT exported and must not be: an analysis that could read them would be
 * one step from changing them, and the whole point of measuring sensitivity is
 * that the shipped verdict stays fixed while the question moves.
 */
export {
  collectScatteredAuthSites,
  type CheckSite,
} from './design-smells-crossfile/scattered-authorization.js';

export {
  indexFile,
  isIndexableLanguage,
  symbolBody,
  symbolBodyBlanked,
} from './structure-indexer/index.js';

export {
  buildDependencyGraph,
  fanIn,
  fanOut,
  includeClosure,
  normalizePath,
  resolveSpecifier,
  toSourceFile,
} from './dependency-graph/index.js';

export { buildSymbolTable } from './symbol-table/index.js';

/**
 * H1 — intraprocedural taint (`taint/`), promoted from skeleton to load-bearing.
 *
 * ★ WHY THIS EXPORT IS ITSELF A DESIGN DECISION, NOT PLUMBING
 *
 * 0.3.0-α landed the taint engine and deliberately did not export it. That was
 * correct then and is wrong now, and the difference is worth stating because the
 * same question recurs for every module built ahead of its consumer.
 *
 * Unexported, the module was verifiable but not falsifiable: its own tests
 * proved it computed what it claimed, and nothing proved that what it claimed
 * was what a rule needs. A source→sink engine with no rule reading it is a
 * hypothesis about the shape of evidence, held at arm's length from the only
 * thing that could refute it. The 0.3.0-β catalogue supplies the refutation
 * surface — VG-SMELL-041 and VG-SMELL-052 are specified as taint-backed rather
 * than structural precisely so that "the flow is real" stops being this module's
 * private claim and becomes a finding a user can check line by line.
 *
 * So the export is what makes H1 done. Shipping the engine was necessary and is
 * not sufficient: until a finding carries a `hops` chain a developer can read,
 * the difference between a working dataflow engine and a plausible one is not
 * observable from outside this package.
 *
 * ★ WHAT THIS EXPORT MUST NOT BECOME
 *
 * The package boundary above applies unchanged: this reaches the CLI and the
 * Action, never a browser or editor bundle. `analyzeProjectTaint` walks every
 * symbol of every file and is budgeted per project (`MAX_FLOWS_PER_PROJECT`),
 * which is the opposite of the per-keystroke, per-textarea contract the core
 * engine holds. `scripts/check-packaging-invariants.mjs` enforces this
 * empirically rather than by convention, so the guarantee does not depend on
 * this comment being read.
 *
 * `analyzeFunction` is exported alongside the project-level entry point because
 * a rule that has already located one symbol should not have to re-walk the
 * project to ask about it — and because the nested-symbol containment argument
 * in `AnalyzeFunctionOptions` is a trap a caller can fall into silently. Naming
 * the option in the public surface is what makes the trap visible.
 */
export {
  analyzeFunction,
  analyzeProjectTaint,
  type AnalyzeFunctionOptions,
  type SinkKind,
  type TaintFlow,
  type TaintSink,
  type TaintSource,
} from './taint/index.js';

export {
  admitFiles,
  createBudget,
  GRAPH_DEADLINE_MS,
  GRAPH_FILE_LIMIT,
  GRAPH_TOTAL_BYTES_CAP,
  type CreateBudgetOptions,
} from './budget.js';

export type {
  CodeLocation,
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  DependencyGraph,
  GraphBudget,
  GraphDegradation,
  ImportEdge,
  IndexedSymbol,
  ProjectIndex,
  RouteBinding,
  SourceFile,
  StructureIndex,
  SymbolKind,
  SymbolRole,
  SymbolTable,
} from './types.js';

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

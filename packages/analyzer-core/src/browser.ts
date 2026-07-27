/**
 * Browser-safe entry for analyzer-core.
 *
 * The default `./` entry includes `scanPath` from `file-scanner.ts`, which
 * imports `node:fs` / `node:path`. Bundling that into a Chrome extension or
 * any non-Node environment fails. This module re-exports only the
 * synchronous, fs-free API: feed in a string, get findings out.
 *
 * Use via the `@vibeguard/analyzer-core/browser` subpath.
 */

export { Analyzer, scan, ENGINE_VERSION, type AnalyzerOptions } from './analyzer.js';
// Exported on the browser entry too, even though no browser channel has a
// lockfile to build a declared set from: the two entries differ only by what
// needs `node:fs`, and this module needs none. A browser consumer that receives
// a package list from elsewhere (a manifest the user pasted in, a host page)
// can therefore use the same veto rather than reimplementing it — and, more to
// the point, the API surfaces stay identical so E1's "one engine, four
// channels" claim keeps meaning what it says.
export {
  buildDeclaredPackageIndex,
  isDeclaredPackage,
  declaredPackageOfMatch,
  DECLARED_PACKAGE_VARIABLE,
  type DeclaredPackageIndex,
  type DeclaredPackageVeto,
} from './declared-veto.js';
export {
  canonicalize,
  canonicalizePreprocessor,
  type CanonicalizeResult,
  type CanonicalizeStats,
} from './canonicalizer.js';
export { detectLanguageFromContent, detectLanguageFromPath } from './language-detect.js';
export { extractSnippet, maskSecret } from './snippet.js';
export {
  parseSuppressions,
  isSuppressed,
  evaluateSuppression,
  tallySuppression,
  mergeSuppressions,
  collectSuppressions,
  type SuppressionTally,
  type SuppressMap,
  type SuppressEntry,
  type SuppressionDecision,
  type ParseSuppressOptions,
} from './suppress.js';
export {
  suppressionsForPath,
  isPathSuppressed,
  evaluatePathSuppression,
  type PathSuppressionDecision,
  type VibeguardConfig,
  type SuppressRuleConfig,
} from './config.js';
export { matchesGlob, matchesAnyGlob } from './glob.js';

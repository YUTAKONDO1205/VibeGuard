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
export { detectLanguageFromContent, detectLanguageFromPath } from './language-detect.js';
export { extractSnippet, maskSecret } from './snippet.js';
export {
  parseSuppressions,
  isSuppressed,
  type SuppressMap,
  type SuppressEntry,
  type ParseSuppressOptions,
} from './suppress.js';
export {
  suppressionsForPath,
  isPathSuppressed,
  type VibeguardConfig,
  type SuppressRuleConfig,
} from './config.js';
export { matchesGlob, matchesAnyGlob } from './glob.js';

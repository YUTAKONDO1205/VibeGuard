export { Analyzer, scan, ENGINE_VERSION, type AnalyzerOptions } from './analyzer.js';
export {
  canonicalize,
  type CanonicalizeResult,
  type CanonicalizeStats,
} from './canonicalizer.js';
export { scanPath, DEFAULT_IGNORE, type ScanPathOptions } from './file-scanner.js';
export { detectLanguageFromPath, detectLanguageFromContent } from './language-detect.js';
export { extractSnippet, maskSecret } from './snippet.js';
export {
  parseSuppressions,
  isSuppressed,
  evaluateSuppression,
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
  parseConfig,
  CONFIG_FILENAMES,
  type VibeguardConfig,
  type SuppressRuleConfig,
} from './config.js';
export { loadConfig, type LoadConfigResult } from './config-loader.js';
export { matchesGlob, matchesAnyGlob } from './glob.js';

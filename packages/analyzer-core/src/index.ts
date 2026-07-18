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
  type SuppressMap,
  type SuppressEntry,
  type ParseSuppressOptions,
} from './suppress.js';
export {
  suppressionsForPath,
  isPathSuppressed,
  parseConfig,
  CONFIG_FILENAMES,
  type VibeguardConfig,
  type SuppressRuleConfig,
} from './config.js';
export { loadConfig, type LoadConfigResult } from './config-loader.js';
export { matchesGlob, matchesAnyGlob } from './glob.js';

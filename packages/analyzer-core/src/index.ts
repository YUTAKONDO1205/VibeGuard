export { Analyzer, scan, ENGINE_VERSION, type AnalyzerOptions } from './analyzer.js';
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
  type CanonicalizeResult,
  type CanonicalizeStats,
} from './canonicalizer.js';
export { scanPath, DEFAULT_IGNORE, MAX_FILE_BYTES, type ScanPathOptions } from './file-scanner.js';
export { detectLanguageFromPath, detectLanguageFromContent } from './language-detect.js';
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
  parseConfig,
  CONFIG_FILENAMES,
  type VibeguardConfig,
  type SuppressRuleConfig,
} from './config.js';
export { loadConfig, type LoadConfigResult } from './config-loader.js';
export { matchesGlob, matchesAnyGlob } from './glob.js';

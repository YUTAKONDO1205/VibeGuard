export { Analyzer, scan, ENGINE_VERSION, type AnalyzerOptions } from './analyzer.js';
export { scanPath, DEFAULT_IGNORE, type ScanPathOptions } from './file-scanner.js';
export { detectLanguageFromPath, detectLanguageFromContent } from './language-detect.js';
export { extractSnippet, maskSecret } from './snippet.js';
export { parseSuppressions, isSuppressed, type SuppressMap } from './suppress.js';

import type { RuleDefinition } from './rule-types.js';
import { authRules } from './rules/auth.js';
import { cryptoRules } from './rules/crypto.js';
import { frameworkRules } from './rules/framework.js';
import { injectionRules } from './rules/injection.js';
import { qualityRules } from './rules/quality.js';
import { secretsRules } from './rules/secrets.js';
import { goRules } from './rules/lang-go.js';
import { javaRules } from './rules/lang-java.js';
import { rubyRules } from './rules/lang-ruby.js';
import { phpRules } from './rules/lang-php.js';

export type { RuleDefinition, RuleMatch, RuleContext } from './rule-types.js';
export {
  runRegex,
  indexToPosition,
  languageMatches,
  getLineText,
  isCommentLine,
  getLineCommentSpec,
  lineCommentStartsAt,
  hasLineCommentSpec,
  type KnownLanguage,
  type LineCommentSpec,
} from './matcher-utils.js';
export {
  contextConfidence,
  explainContextConfidence,
  downgradeConfidence,
  detectDowngradeSignals,
  isInDocstringOrBlockComment,
  isTestPath,
  SEVERITY_CONFIDENCE_FLOOR,
  TEST_PATH_RE,
  type ContextConfidenceMode,
  type ContextConfidenceResult,
  type DowngradeSignal,
} from './confidence.js';

export const allRules: RuleDefinition[] = [
  ...injectionRules,
  ...authRules,
  ...secretsRules,
  ...cryptoRules,
  ...frameworkRules,
  ...qualityRules,
  ...goRules,
  ...javaRules,
  ...rubyRules,
  ...phpRules,
];

export function getRule(ruleId: string): RuleDefinition | undefined {
  return allRules.find((r) => r.ruleId === ruleId);
}

export function getRulesForLanguage(language?: string): RuleDefinition[] {
  if (!language) return allRules;
  return allRules.filter(
    (r) => r.languages.includes('*') || r.languages.includes(language),
  );
}

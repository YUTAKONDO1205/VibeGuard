import type { RuleDefinition } from './rule-types.js';
import { authRules } from './rules/auth.js';
import { cryptoRules } from './rules/crypto.js';
import { frameworkRules } from './rules/framework.js';
import { injectionRules } from './rules/injection.js';
import { qualityRules } from './rules/quality.js';
import { secretsRules } from './rules/secrets.js';

export type { RuleDefinition, RuleMatch, RuleContext } from './rule-types.js';
export { runRegex, indexToPosition, languageMatches, getLineText } from './matcher-utils.js';

export const allRules: RuleDefinition[] = [
  ...injectionRules,
  ...authRules,
  ...secretsRules,
  ...cryptoRules,
  ...frameworkRules,
  ...qualityRules,
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

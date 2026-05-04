import type { Remediation } from '@vibeguard/findings-schema';
import type { RuleDefinition } from '@vibeguard/rules';

const DEFAULT_REFERENCES: Record<string, string[]> = {
  injection: ['https://owasp.org/Top10/A03_2021-Injection/'],
  auth: ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],
  secrets: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  crypto: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
  'access-control': ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'],
  'ai-quality': ['https://owasp.org/www-project-top-10-for-large-language-model-applications/'],
  quality: [],
  logging: ['https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/'],
};

/**
 * MVP remediation engine: composes a Remediation from the rule's static template plus
 * category-default references. Future versions can interpolate variables from RuleMatch
 * and tailor exampleFix per-language.
 */
export function buildRemediation(rule: RuleDefinition): Remediation {
  const tmpl = rule.remediation;
  if (!tmpl) {
    return {
      why: rule.description,
      how: 'Review this finding manually and apply the safer pattern recommended for the rule category.',
      references: DEFAULT_REFERENCES[rule.category] ?? [],
    };
  }
  const refs = [
    ...(rule.references ?? []),
    ...(DEFAULT_REFERENCES[rule.category] ?? []),
  ];
  return {
    why: tmpl.why,
    how: tmpl.how,
    exampleFix: tmpl.exampleFix,
    references: refs.length ? Array.from(new Set(refs)) : undefined,
  };
}

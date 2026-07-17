import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const hardcodedAwsKey: RuleDefinition = {
  ruleId: 'VG-SEC-001',
  name: 'Hard-coded AWS access key ID',
  description: 'A literal AWS access key ID was found in source. Treat as compromised the moment it lands in version control.',
  languages: ['*'],
  category: 'secrets',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-798'],
  remediation: {
    why: 'Source-embedded credentials end up in git history, build artefacts, and logs forever — and AWS keys grant immediate cloud access.',
    how: 'Rotate the key, then load credentials from environment variables, AWS Secrets Manager, or your runtime IAM role.',
  },
  match: (ctx) =>
    runRegex(ctx.content, /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g),
};

export const hardcodedPrivateKey: RuleDefinition = {
  ruleId: 'VG-SEC-002',
  name: 'Embedded PEM private key',
  description: 'A PEM-encoded private key block appears in source.',
  languages: ['*'],
  category: 'secrets',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-798'],
  remediation: {
    why: 'A private key in source can sign or decrypt for the entire system; once committed it must be rotated.',
    how: 'Rotate the key immediately and load private keys from a secret manager or filesystem location with restricted permissions.',
  },
  match: (ctx) =>
    runRegex(ctx.content, /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g),
};

export const genericApiKey: RuleDefinition = {
  ruleId: 'VG-SEC-003',
  name: 'Likely API key / secret in literal',
  description:
    'Long high-entropy literal assigned to a variable named api_key, secret, token, or password.',
  languages: ['*'],
  category: 'secrets',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-798'],
  tags: ['ai-prone'],
  remediation: {
    why: 'Hard-coded API keys leak through source control, screenshots, and shared notebooks.',
    how: 'Replace with an environment variable lookup and add the placeholder to .env.example only.',
    exampleFix: 'const apiKey = process.env.STRIPE_API_KEY;',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']/gi,
      { skipCommentLines: true, language: ctx.language },
    ).filter((m) => {
      const literal = m.evidence.match(/["']([^"']+)["']\s*$/)?.[1] ?? '';
      // Filter obvious placeholders to reduce noise — VG-AUTH-003 already covers them.
      if (/^(?:changeme|dummy|placeholder|your|xxxx)/i.test(literal)) return false;
      // Filter env var lookups that happen to match.
      if (/process\.env|os\.environ|getenv/.test(m.evidence)) return false;
      return true;
    }),
};

export const githubToken: RuleDefinition = {
  ruleId: 'VG-SEC-004',
  name: 'Embedded GitHub personal access token',
  description: 'Literal matches the GitHub token format (ghp_/gho_/ghs_/ghr_/github_pat_).',
  languages: ['*'],
  category: 'secrets',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-798'],
  remediation: {
    why: 'GitHub tokens grant repository (and possibly org) access; once leaked they must be revoked at github.com/settings/tokens.',
    how: 'Revoke the token, then load it from a secret store at runtime.',
  },
  match: (ctx) =>
    runRegex(ctx.content, /\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b/g),
};

export const secretsRules: RuleDefinition[] = [
  hardcodedAwsKey,
  hardcodedPrivateKey,
  genericApiKey,
  githubToken,
];

import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const exceptionSwallow: RuleDefinition = {
  ruleId: 'VG-QUAL-001',
  name: 'Empty except / catch block',
  description:
    'Catching exceptions and silently passing hides real failures, including security-relevant ones like auth or signature errors.',
  languages: ['python', 'javascript', 'typescript', 'java'],
  category: 'quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  cwe: ['CWE-390'],
  tags: ['ai-prone'],
  remediation: {
    why: 'Swallowing exceptions makes the system look healthy while real errors (including security failures) accumulate.',
    how: 'Log the error with context and either re-raise, return a typed error, or take an explicit safe action.',
  },
  match: (ctx) => [
    ...runRegex(ctx.content, /except[^:\n]*:\s*(?:#[^\n]*\n\s*)*pass\b/g),
    ...runRegex(ctx.content, /catch\s*\([^)]*\)\s*\{\s*\}/g),
  ],
};

export const corsWildcardWithCredentials: RuleDefinition = {
  ruleId: 'VG-QUAL-002',
  name: 'CORS wildcard origin with credentials',
  description:
    'Access-Control-Allow-Origin: * combined with Allow-Credentials: true is a CORS misconfiguration that exposes the API to cross-site abuse.',
  languages: ['javascript', 'typescript', 'python', 'go'],
  category: 'access-control',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-942'],
  remediation: {
    why: 'A wildcard origin combined with credentials lets any site read authenticated responses on behalf of the user.',
    how: 'Echo a specific allowed origin from a strict allowlist, and only set Allow-Credentials when truly needed.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["'][\s\S]{0,200}?Access-Control-Allow-Credentials["']?\s*[:,]\s*["']?true/gi,
    ),
};

export const debugLogOfSecret: RuleDefinition = {
  ruleId: 'VG-QUAL-003',
  name: 'Logging a secret-named variable',
  description:
    'console.log / print of a variable whose name suggests it carries credentials. Secrets should never reach logs.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'logging',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-532'],
  tags: ['ai-prone'],
  remediation: {
    why: 'Secrets in logs end up in log aggregation, screen recordings, and bug reports.',
    how: 'Remove the log, or replace with a redacted form (e.g. last 4 chars).',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /(?:console\.log|print)\s*\([^)]*\b(?:password|secret|api[_-]?key|token|access[_-]?key|private[_-]?key)\b/gi,
      { skipCommentLines: true },
    ),
};

export const openRedirect: RuleDefinition = {
  ruleId: 'VG-QUAL-004',
  name: 'Redirect to a value derived from request input',
  description:
    'Redirecting to a URL that came from query / body without validation enables phishing via your domain.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'access-control',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-601'],
  remediation: {
    why: 'Open redirects let attackers send victims to attacker-controlled sites via a trusted origin.',
    how: 'Validate the target against an allowlist of internal paths or hostnames before redirecting.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /res\.redirect\s*\(\s*req\.(?:query|body|params)\.[\w$]+\s*\)/g,
      { skipCommentLines: true },
    ),
};

export const qualityRules: RuleDefinition[] = [
  exceptionSwallow,
  corsWildcardWithCredentials,
  debugLogOfSecret,
  openRedirect,
];

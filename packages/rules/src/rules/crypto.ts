import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const weakHashForSecurity: RuleDefinition = {
  ruleId: 'VG-CRYPTO-001',
  name: 'Weak hash (MD5 / SHA1) used in security context',
  description:
    'MD5 and SHA1 are broken for collision resistance and inadequate for password or signature use.',
  languages: ['*'],
  category: 'crypto',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-327'],
  remediation: {
    why: 'MD5 and SHA1 collisions are practical; using them for passwords, signatures, or integrity is insecure.',
    how: 'Use SHA-256 or SHA-3 for integrity, and a password hash like bcrypt / argon2 / scrypt for credentials.',
  },
  match: (ctx) => [
    ...runRegex(ctx.content, /hashlib\.(?:md5|sha1)\s*\(/g, { skipCommentLines: true }),
    ...runRegex(ctx.content, /createHash\s*\(\s*["'](?:md5|sha1)["']/g, { skipCommentLines: true }),
    ...runRegex(ctx.content, /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/g, {
      skipCommentLines: true,
    }),
  ],
};

export const weakRandomForSecurity: RuleDefinition = {
  ruleId: 'VG-CRYPTO-002',
  name: 'Non-cryptographic random used for tokens / IDs',
  description:
    'Math.random / random.random produce predictable values and must not be used for tokens, session IDs, or secrets.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'crypto',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-338'],
  tags: ['ai-prone'],
  remediation: {
    why: 'Math.random / random.random are seeded PRNGs; their output is predictable enough to brute force tokens.',
    how: 'Use crypto.randomBytes / crypto.getRandomValues / secrets.token_urlsafe for any value that must resist guessing.',
    exampleFix: 'crypto.randomBytes(32).toString("hex")',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /(?:token|secret|password|session[_-]?id|csrf|nonce|salt|otp)[^=\n]{0,40}=\s*Math\.random\s*\(/gi,
      { skipCommentLines: true },
    ),
    ...runRegex(
      ctx.content,
      /(?:token|secret|password|session[_-]?id|csrf|nonce|salt|otp)[^=\n]{0,40}=\s*random\.random\s*\(/gi,
      { skipCommentLines: true },
    ),
  ],
};

export const httpInsteadOfHttps: RuleDefinition = {
  ruleId: 'VG-CRYPTO-003',
  name: 'http:// URL used for non-localhost endpoint',
  description: 'Plaintext HTTP URLs to non-localhost hosts expose traffic to interception and modification.',
  languages: ['*'],
  category: 'crypto',
  severity: 'low',
  defaultConfidence: 'low',
  cwe: ['CWE-319'],
  remediation: {
    why: 'Non-TLS traffic can be observed and rewritten by anyone on the network path.',
    how: 'Use https:// for any endpoint that handles auth, secrets, or user data. Localhost traffic is typically fine to leave as http.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /["']http:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|host\.docker\.internal))[^"'\s]+["']/g,
      { skipCommentLines: true },
    ),
};

export const cryptoRules: RuleDefinition[] = [
  weakHashForSecurity,
  weakRandomForSecurity,
  httpInsteadOfHttps,
];

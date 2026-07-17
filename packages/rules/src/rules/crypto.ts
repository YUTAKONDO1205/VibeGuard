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
    // Python
    ...runRegex(ctx.content, /hashlib\.(?:md5|sha1)\s*\(/g, { skipCommentLines: true, language: ctx.language }),
    // Node.js
    ...runRegex(ctx.content, /createHash\s*\(\s*["'](?:md5|sha1)["']/g, { skipCommentLines: true, language: ctx.language }),
    // Java
    ...runRegex(ctx.content, /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|SHA1)["']/g, {
      skipCommentLines: true,
      language: ctx.language,
    }),
    // Ruby
    ...runRegex(ctx.content, /Digest::(?:MD5|SHA1)\.(?:hexdigest|digest|new)\b/g, {
      skipCommentLines: true,
      language: ctx.language,
    }),
    // C# — System.Security.Cryptography
    ...runRegex(ctx.content, /\b(?:MD5|SHA1)\.Create\s*\(/g, { skipCommentLines: true, language: ctx.language }),
    ...runRegex(ctx.content, /new\s+(?:MD5|SHA1)CryptoServiceProvider\s*\(/g, {
      skipCommentLines: true,
      language: ctx.language,
    }),
    // PHP — top-level md5() / sha1() functions. Use a negative lookbehind
    // to avoid double-matching `hashlib.md5(` (Python, already covered above)
    // and method calls like `obj.md5(`.
    ...runRegex(ctx.content, /(?<![.\w])(?:md5|sha1)\s*\(/g, { skipCommentLines: true, language: ctx.language }),
  ],
};

export const weakRandomForSecurity: RuleDefinition = {
  ruleId: 'VG-CRYPTO-002',
  name: 'Non-cryptographic random used for tokens / IDs',
  description:
    'Predictable PRNGs (Math.random, random.random, mt_rand, new Random, math/rand, Kernel#rand, etc.) must not be used for tokens, session IDs, or secrets.',
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'php', 'ruby', 'csharp'],
  category: 'crypto',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-338'],
  tags: ['ai-prone'],
  remediation: {
    why: 'Standard-library random functions are seeded PRNGs; their output is predictable enough to brute force tokens.',
    how: 'Use a CSPRNG: crypto.randomBytes / crypto.getRandomValues (Node), secrets.token_urlsafe (Python), crypto/rand (Go), SecureRandom (Java/Ruby), random_bytes / random_int (PHP), RandomNumberGenerator (C#).',
    exampleFix: 'crypto.randomBytes(32).toString("hex")',
  },
  match: (ctx) => {
    // Variable-name guard: the assignment LHS must look security-relevant.
    // We share this across language-specific RHS patterns to keep the rule
    // narrow (this is a low-confidence, syntax-driven heuristic).
    const guard =
      '(?:token|secret|password|session[_-]?id|csrf|nonce|salt|otp)[^=\\n]{0,40}';
    const buildPattern = (rhs: string): RegExp => new RegExp(`${guard}[:=]\\s*${rhs}`, 'gi');
    return [
      // JS / TS / Java / Kotlin: Math.random()
      ...runRegex(ctx.content, buildPattern('Math\\.random\\s*\\('), {
        skipCommentLines: true,
        language: ctx.language,
      }),
      // Python: random.random / random.randint / random.randrange / random.choice
      ...runRegex(ctx.content, buildPattern('random\\.(?:random|randint|randrange|choice|getrandbits)\\s*\\('), {
        skipCommentLines: true,
        language: ctx.language,
      }),
      // Java / C#: new Random()
      ...runRegex(ctx.content, buildPattern('new\\s+Random\\s*\\('), {
        skipCommentLines: true,
        language: ctx.language,
      }),
      // Go: math/rand → rand.Int / rand.Intn / rand.Float64 etc.
      ...runRegex(ctx.content, buildPattern('rand\\.(?:Int|Intn|Int31|Int63|Uint32|Uint64|Float32|Float64|Read)\\s*\\('), {
        skipCommentLines: true,
        language: ctx.language,
      }),
      // PHP: mt_rand() top-level
      ...runRegex(ctx.content, buildPattern('mt_rand\\s*\\('), {
        skipCommentLines: true,
        language: ctx.language,
      }),
      // Ruby: Random.new / Random.rand
      ...runRegex(ctx.content, buildPattern('Random\\.(?:new|rand)\\s*\\('), {
        skipCommentLines: true,
        language: ctx.language,
      }),
      // PHP / Ruby / C: bare top-level rand(). Negative lookbehind avoids
      // namespaced calls like `math/rand` package's `rand.Intn` (already
      // covered above) and method calls like `obj.rand(`.
      ...runRegex(ctx.content, buildPattern('(?<![.\\w])rand\\s*\\('), {
        skipCommentLines: true,
        language: ctx.language,
      }),
    ];
  },
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
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const cryptoRules: RuleDefinition[] = [
  weakHashForSecurity,
  weakRandomForSecurity,
  httpInsteadOfHttps,
];

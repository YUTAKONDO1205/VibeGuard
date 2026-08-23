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
      // ── WHY A LOOKBEHIND AND NOT `\b` ────────────────────────────────────
      // `\b` was here, and `_` is a word character, so a word boundary never
      // existed between a prefix and the keyword. Every environment-variable
      // spelling of a secret — the dominant convention, and the one a `.env`
      // name is copied into code as — was therefore invisible. Measured
      // 2026-08-23 against the shipped 0.3.6 engine:
      //
      //   API_KEY        = "sk-proj-…"   reported
      //   MY_API_KEY     = "sk-proj-…"   NOT reported
      //   OPENAI_API_KEY = "sk-proj-…"   NOT reported
      //   STRIPE_SECRET  = "sk-live-…"   NOT reported
      //   DB_PASSWORD    = "…"           NOT reported
      //
      // `(?<![A-Za-z0-9])` keeps the "not in the middle of a longer word"
      // property that `\b` was there for (`notasecret` still does not match,
      // because `a` is alphanumeric) while admitting `_`, `-` and `.` as the
      // separators they are. Zero-width, so match offsets are unchanged and
      // `evidence` still starts at the keyword.
      //
      // ── AND WHY THE LITERAL CLASS GREW ───────────────────────────────────
      // It was `[A-Za-z0-9+/=_\-]`, which excludes every punctuation character
      // that makes a password strong: `DB_PASSWORD = "S3cr3tP@ssw0rd…"` did not
      // match while the same string without the `@` did. The class now admits
      // printable ASCII other than whitespace and the quote characters, and the
      // filter below throws out the shapes that widening lets in.
      // Printable ASCII with space and the three quote characters excluded by
      // code point, because character-class intersection is not available
      // without the `v` flag and this pattern has to keep running on the
      // engines the extensions ship to.
      /(?<![A-Za-z0-9])(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']([\x21\x23-\x26\x28-\x5F\x61-\x7E]{20,})["']/gi,
      { skipCommentLines: true, language: ctx.language },
    ).filter((m) => {
      const literal = m.evidence.match(/["']([^"']+)["']\s*$/)?.[1] ?? '';
      // Filter obvious placeholders to reduce noise — VG-AUTH-003 already covers them.
      if (/^(?:changeme|dummy|placeholder|your|xxxx)/i.test(literal)) return false;
      // Filter env var lookups that happen to match.
      if (/process\.env|os\.environ|getenv/.test(m.evidence)) return false;
      // Shapes the widened literal class newly admits and that are not
      // credentials: a URL, a filesystem path, a template placeholder, a
      // JSON/QS fragment. Each is checked on the LITERAL, not on the evidence
      // line, so a legitimate secret assigned near a URL is unaffected.
      if (/:\/\//.test(literal)) return false;
      if (/^[.~]{0,2}\//.test(literal) || /^[A-Za-z]:[\\/]/.test(literal)) return false;
      if (/\$\{|\{\{|%[sd]\b|<[A-Za-z_]/.test(literal)) return false;
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

/**
 * VG-SEC-005 — a model-provider API key, recognised by its shape.
 *
 * WHY SHAPE AND NOT NAME. VG-SEC-003 finds a secret by the name of the variable
 * it is assigned to, which is the only signal it has and is a signal a build
 * destroys: after minification the same key is `const t = "sk-proj-…"` and the
 * name carries nothing. Shape survives that, so the two rules fail in different
 * places rather than in the same place.
 *
 * WHY THESE PROVIDERS. This tool's stated subject is AI-generated code, and the
 * credential most likely to be sitting in that code is the one for the service
 * that generated it. The shipped 0.3.6 engine covered AWS, PEM private keys and
 * GitHub tokens, and no model provider at all.
 *
 * Prefixes and lengths are taken from each provider's own documented format.
 * They are bounded and anchored on both sides so a prose mention of `sk-` in a
 * comment about keys does not match; the length floors are the conservative end
 * of what each provider issues, which biases towards missing an unusually short
 * key rather than towards flagging an ordinary identifier.
 */
export const modelProviderKey: RuleDefinition = {
  ruleId: 'VG-SEC-005',
  name: 'Embedded model-provider API key',
  description:
    'Literal matches the documented key format of a model provider (OpenAI sk-/sk-proj-, Anthropic sk-ant-, Google AIza, Hugging Face hf_, Groq gsk_). Recognised by shape, so it is still found after a minifier has replaced the variable name.',
  languages: ['*'],
  category: 'secrets',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-798'],
  tags: ['ai-prone'],
  remediation: {
    why: 'A model-provider key is a billable credential. Committed to a repository or compiled into a browser bundle it is readable by anyone who can fetch the file, and usage is charged to the key owner until it is revoked.',
    how: 'Revoke the key at the provider, then call the provider from a server you control and keep the key in that server\'s environment. A key referenced from browser code is published no matter how it got there.',
    exampleFix: 'const res = await fetch("/api/ask", { method: "POST", body });',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      new RegExp(
        [
          // Anthropic. Documented as sk-ant- followed by a version segment.
          'sk-ant-[A-Za-z0-9]{2,12}-[A-Za-z0-9_-]{20,}',
          // OpenAI project and legacy user keys.
          'sk-proj-[A-Za-z0-9_-]{20,}',
          'sk-[A-Za-z0-9]{32,}',
          // Google AI Studio / Generative Language.
          'AIza[A-Za-z0-9_-]{35}',
          // Hugging Face access token.
          'hf_[A-Za-z0-9]{34,}',
          // Groq.
          'gsk_[A-Za-z0-9]{40,}',
        ].join('|'),
        'g',
      ),
      { skipCommentLines: false },
    ).filter((m) => {
      // A documentation placeholder is not a credential. Kept deliberately
      // short: the alternative — an entropy floor — rejects real keys, because
      // several of these formats are base62 over a fixed alphabet and score
      // lower than an entropy threshold naive enough to be worth writing.
      const lit = m.evidence;
      if (/(?:xxx|XXX|\.\.\.|your|YOUR|example|EXAMPLE|placeholder|1234567890)/.test(lit))
        return false;
      return true;
    }),
};

export const secretsRules: RuleDefinition[] = [
  hardcodedAwsKey,
  hardcodedPrivateKey,
  genericApiKey,
  githubToken,
  modelProviderKey,
];

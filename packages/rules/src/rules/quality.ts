// vibeguard:disable-file VG-QUAL-005 VG-QUAL-006 VG-QUAL-007 VG-QUAL-008 VG-QUAL-009 VG-QUAL-010
// AI-heuristic rules below match on literal patterns ("Not implemented",
// "noreply@example.com", "DEBUG = True", etc.). The regex bodies and prose
// in this file legitimately contain those literals.
import type { RuleDefinition, RuleMatch } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';
import { isTestPath } from '../confidence.js';

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

// ---------------------------------------------------------------------------
// AI-heuristic rules (VG-QUAL-005..010, category: 'ai-quality')
//
// These rules detect "AI-generated boilerplate" tells: stub bodies, sample
// emails, mock data identifiers, debug flags flipped on, "for now / not for
// production" prose, validators that don't validate. They lean medium /low
// severity because they're heuristics, not guaranteed bugs — but in practice
// each one has produced real production incidents when ignored.
// ---------------------------------------------------------------------------

// A `raise NotImplementedError` whose enclosing `def` is decorated with
// @abstractmethod (or @abc.abstractmethod) is the idiomatic Python way to
// declare an abstract contract — the concrete subclass supplies the body. That
// is intentional, not a shipped stub, so it must not be flagged. (Identified as
// the dominant VG-QUAL-005 false-positive class in the ai-quality precision
// benchmark, paper item ③.)
function isAbstractMethod(lines: string[], matchLine: number): boolean {
  for (let i = matchLine - 1; i >= 0; i--) {
    if (!/^\s*def\s/.test(lines[i] ?? '')) continue;
    for (let j = i - 1; j >= 0; j--) {
      const deco = (lines[j] ?? '').trim();
      if (deco === '') continue;
      if (deco.startsWith('@')) {
        if (/^@(?:[\w.]+\.)?abstractmethod\b/.test(deco)) return true;
        continue; // another decorator; keep scanning upward
      }
      break; // first non-decorator, non-blank line above the def
    }
    return false;
  }
  return false;
}

export const stubBody: RuleDefinition = {
  ruleId: 'VG-QUAL-005',
  name: 'Stub or not-implemented function body',
  description:
    'Function body is a "Not implemented" throw / raise / panic. AI scaffolds compile but skip the actual logic — easy to ship by accident.',
  languages: ['javascript', 'typescript', 'python', 'go', 'java'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  tags: ['ai-prone'],
  remediation: {
    why: 'A "not implemented" body looks like real code at the call site but performs no work — security checks, validation, or business logic that should run silently does not.',
    how: 'Implement the function, or raise loudly *and* mark the call site as blocked (typed error / 5xx) so callers cannot silently proceed.',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /throw\s+new\s+Error\s*\(\s*["'`](?:Not[\s_-]?implemented|TODO\b|FIXME\b|stub\b|unimplemented)/gi,
    ),
    ...runRegex(ctx.content, /\braise\s+NotImplementedError\b/g).filter(
      (m) => !isAbstractMethod(ctx.lines, m.startLine),
    ),
    ...runRegex(
      ctx.content,
      /\bpanic\s*\(\s*["`](?:not\s+implemented|TODO|unimplemented)/gi,
    ),
    ...runRegex(
      ctx.content,
      /^\s*(?:return\s+(?:null|None|nil|undefined|true|false))\s*[;]?\s*(?:#|\/\/)\s*(?:TODO|FIXME|stub|implement\b)/gim,
    ),
  ],
};

export const placeholderEmail: RuleDefinition = {
  ruleId: 'VG-QUAL-006',
  name: 'Placeholder email address in source',
  description:
    'Hard-coded emails on example.com / test.com / foo.bar / domain.com — left over from AI templates. They become silent send-failures or info disclosure in production.',
  languages: ['*'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  tags: ['ai-prone'],
  remediation: {
    why: 'AI templates use these literal domains as stand-ins. Shipped, they either bounce, silently swallow notifications, or leak intent to a third party that owns the placeholder domain.',
    how: 'Move the address to configuration, fail at startup if the value still matches a known placeholder list, and avoid baking any address into source.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /["'`][\w.+-]+@(?:example\.(?:com|org|net)|test\.(?:com|local)|foo\.bar|domain\.com|email\.com|mail\.com)["'`]/gi,
    ),
};

function filterTestPaths(ctx: { filePath?: string }, matches: RuleMatch[]): RuleMatch[] {
  if (isTestPath(ctx.filePath)) return [];
  return matches;
}

export const mockDataInProductionPath: RuleDefinition = {
  ruleId: 'VG-QUAL-007',
  name: 'Mock / fake / dummy identifier outside test paths',
  description:
    'Identifier prefixed mock / fake / dummy used in non-test source. AI fills incomplete branches with mock data that bypasses real logic.',
  languages: ['javascript', 'typescript', 'python', 'go', 'java'],
  category: 'ai-quality',
  severity: 'low',
  defaultConfidence: 'low',
  tags: ['ai-prone'],
  remediation: {
    why: 'A mock value reached at runtime in production short-circuits validation, auth, or data fetches and looks indistinguishable from real flow until something downstream fails.',
    how: 'Move the mock into a test fixture, or guard it behind an explicit non-production environment check that throws if reached otherwise.',
  },
  match: (ctx) => {
    const matches = [
      ...runRegex(
        ctx.content,
        /\b(?:const|let|var)\s+(?:mock|fake|dummy)[A-Z][\w$]*\s*=/g,
        { skipCommentLines: true },
      ),
      ...runRegex(
        ctx.content,
        /\b(?:mock|fake|dummy)_[a-z][\w]*\s*=/g,
        { skipCommentLines: true },
      ),
      ...runRegex(
        ctx.content,
        /\breturn\s+(?:mock|fake|dummy)[A-Z_][\w$]*\s*[;)]/g,
        { skipCommentLines: true },
      ),
    ];
    return filterTestPaths(ctx, matches);
  },
};

export const debugFlagOn: RuleDefinition = {
  ruleId: 'VG-QUAL-008',
  name: 'Debug / verbose flag hardcoded ON',
  description:
    'A debug, verbose, or trace flag is set to true / True directly in source. Different from VG-AUTH-001 (auth bypass): this is the flag itself being flipped on by default.',
  languages: ['javascript', 'typescript', 'python', 'go', 'java'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  tags: ['ai-prone'],
  remediation: {
    why: 'Debug-on by default leaks stack traces, internal paths, and PII. AI templates often ship with verbose: true because that is what their training examples show.',
    how: 'Default debug / verbose / trace flags to false, and source the override from environment configuration.',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /\b(?:debug|verbose|trace|enable[_-]?debug|enable[_-]?verbose|debug[_-]?mode)\s*:\s*true\b/gi,
      { skipCommentLines: true },
    ),
    ...runRegex(
      ctx.content,
      /^\s*(?:DEBUG|VERBOSE|TRACE)\s*=\s*True\b/gm,
    ),
    ...runRegex(
      ctx.content,
      /^\s*(?:const|let|var)\s+(?:DEBUG|VERBOSE|TRACE)\s*=\s*true\b/gm,
    ),
  ],
};

export const notForProductionComment: RuleDefinition = {
  ruleId: 'VG-QUAL-009',
  name: '"Not for production" / "for now" placeholder comment',
  description:
    'Comment self-labels the surrounding code as a placeholder, demo, or temporary workaround. Strong signal that AI-generated boilerplate landed without review.',
  languages: ['*'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  // The comment IS the signal; never down-rank it for being inside a comment.
  contextConfidence: 'off',
  tags: ['ai-prone'],
  remediation: {
    why: 'The comment is the author admitting the code should not have shipped as-is. Either the warning is correct (replace the code) or the comment is stale (delete it).',
    how: 'Replace the placeholder with the real implementation, or remove the comment after confirming the code is in fact production-ready.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /(?:\/\/|#|\/\*|\*)\s*(?:not\s+for\s+production|for\s+now\b|just\s+an?\s+example|placeholder\s+(?:only|impl|implementation)|demo\s+only|do\s+not\s+use\s+in\s+(?:prod|production)|in\s+real\s+code\b|in\s+production[,\s]+you|you\s+(?:should|would)\s+want\s+to\s+(?:replace|implement)|replace\s+(?:this\s+)?with\s+(?:real|actual))/gi,
    ),
};

export const emptyValidator: RuleDefinition = {
  ruleId: 'VG-QUAL-010',
  name: 'Validator / sanitizer with passthrough body',
  description:
    'Function whose name claims to validate, sanitize, or check input but whose body just returns true / returns the input unchanged.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-20'],
  tags: ['ai-prone'],
  remediation: {
    why: 'A validator that always returns true gives callers false confidence. Downstream code skips defensive handling because "it has been validated".',
    how: 'Implement the actual checks, or rename the function so callers do not assume validation has happened.',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /function\s+(?:validate|sanitize|sanitise|check|verify)\w*\s*\([^)]*\)\s*\{\s*return\s+(?:true|input|value|val|x|data|arg|args\[0\])\s*;?\s*\}/g,
    ),
    ...runRegex(
      ctx.content,
      /\b(?:const|let|var)\s+(?:validate|sanitize|sanitise|check|verify)\w*\s*=\s*(?:\([^)]*\)|[\w$]+)\s*=>\s*(?:true\b|input\b|value\b|val\b|x\b|data\b)\s*;?/g,
    ),
    ...runRegex(
      ctx.content,
      /^\s*def\s+(?:validate|sanitize|sanitise|check|verify)\w*\s*\([^)]*\)\s*:\s*(?:\n\s*(?:'''|""")[^\n]*(?:'''|""")\s*)?\n\s*return\s+(?:True|input|value|val|x|data|args?\[0\])\s*$/gm,
    ),
  ],
};

export const qualityRules: RuleDefinition[] = [
  exceptionSwallow,
  corsWildcardWithCredentials,
  debugLogOfSecret,
  openRedirect,
  stubBody,
  placeholderEmail,
  mockDataInProductionPath,
  debugFlagOn,
  notForProductionComment,
  emptyValidator,
];

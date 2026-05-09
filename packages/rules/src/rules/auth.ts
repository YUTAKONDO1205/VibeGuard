// vibeguard:disable-file VG-AUTH-003 VG-AUTH-004 VG-AUTH-006
// This file defines the auth rules; dummy-token, TLS-disable, and the
// "secure: false" / "httpOnly: false" literals appear inside regex
// patterns and remediation prose by design.
import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const debugBypass: RuleDefinition = {
  ruleId: 'VG-AUTH-001',
  name: 'Authentication bypass when DEBUG is enabled',
  description:
    'Code path that skips auth when a debug or development flag is set. Easy to leave on accidentally in production.',
  languages: ['*'],
  category: 'auth',
  severity: 'critical',
  defaultConfidence: 'medium',
  cwe: ['CWE-489'],
  tags: ['ai-prone'],
  remediation: {
    why: 'A debug bypass that ships to production silently disables authentication. AI-assisted code frequently leaves these in.',
    how: 'Remove the bypass entirely, or gate it behind an explicit non-production environment check that fails closed.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /if\s*\(?\s*(?:DEBUG|isDev|IS_DEV|process\.env\.NODE_ENV\s*===?\s*["']development["']|debug)\s*\)?\s*[:{][^}]*?(?:return\s+true|skip[_\s]?auth|bypass|allow|permit)/gi,
      { skipCommentLines: false },
    ),
};

export const todoSecurity: RuleDefinition = {
  ruleId: 'VG-AUTH-002',
  name: 'TODO comment near security-critical code',
  description:
    'TODO / FIXME / XXX comment that mentions auth, validation, or security. AI-generated code often emits placeholders for the dangerous parts.',
  languages: ['*'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  tags: ['ai-prone'],
  remediation: {
    why: 'A TODO next to security-critical logic typically means the safety check was deferred and may never be implemented.',
    how: 'Implement the missing check, or track the gap as a blocking issue before this code reaches production.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /(?:\/\/|#|\/\*)\s*(?:TODO|FIXME|XXX|HACK)\b[^\n]*?(?:auth|valid|sanit|escape|secur|permission|role|token|password|encrypt|verif)/gi,
    ),
};

export const dummyToken: RuleDefinition = {
  ruleId: 'VG-AUTH-003',
  name: 'Dummy or placeholder credential string',
  description:
    'Hard-coded placeholder values like "dummy_token", "test_password", "changeme" frequently survive the trip to production.',
  languages: ['*'],
  category: 'secrets',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-798'],
  tags: ['ai-prone'],
  remediation: {
    why: 'Placeholder credentials in source are easy to forget about and disclose what the surrounding system trusts.',
    how: 'Move the value to a configuration / secret store and fail loudly when the placeholder is detected at startup.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /["'](?:changeme|dummy[_-]?(?:token|key|secret)|test[_-]?(?:password|token|secret)|placeholder[_-]?(?:token|key|secret)|your[_-]?(?:api)?[_-]?key[_-]?here|xxxxxxxx+)["']/gi,
    ),
};

export const tlsVerifyDisabled: RuleDefinition = {
  ruleId: 'VG-AUTH-004',
  name: 'TLS certificate verification disabled',
  description:
    'verify=False, rejectUnauthorized: false, InsecureSkipVerify: true — all disable TLS validation, defeating MITM protection.',
  languages: ['python', 'javascript', 'typescript', 'go'],
  category: 'crypto',
  severity: 'high',
  defaultConfidence: 'high',
  cwe: ['CWE-295'],
  remediation: {
    why: 'Disabling certificate verification turns TLS into a bare encrypted channel with no authentication of the peer. Active MITM is trivial.',
    how: 'Remove the flag. If a self-signed cert is needed, install it as a trusted CA for the relevant client only.',
  },
  match: (ctx) => [
    ...runRegex(ctx.content, /verify\s*=\s*False\b/g, { skipCommentLines: true }),
    ...runRegex(ctx.content, /rejectUnauthorized\s*:\s*false\b/g, { skipCommentLines: true }),
    ...runRegex(ctx.content, /InsecureSkipVerify\s*:\s*true\b/g, { skipCommentLines: true }),
  ],
};

export const csrfExemptDecorator: RuleDefinition = {
  ruleId: 'VG-AUTH-005',
  name: 'Django @csrf_exempt decorator disables CSRF protection',
  description:
    'Marking a Django view with @csrf_exempt opts out of CSRF token validation. Routinely added to make POST endpoints "just work" during development and forgotten.',
  languages: ['python'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'high',
  cwe: ['CWE-352'],
  owasp: ['A01:2021'],
  tags: ['django', 'ai-prone'],
  remediation: {
    why: 'Without CSRF validation, an attacker can trigger state-changing requests from a victim\'s browser using forged forms or fetch calls.',
    how: 'Remove @csrf_exempt and submit a CSRF token (Django will inject {% csrf_token %} into forms / require X-CSRFToken on fetch). For pure JSON APIs, use Django REST Framework\'s SessionAuthentication or token auth which handles CSRF correctly.',
  },
  match: (ctx) =>
    runRegex(ctx.content, /^\s*@csrf_exempt\b/gm, { skipCommentLines: true }),
};

export const insecureSessionCookie: RuleDefinition = {
  ruleId: 'VG-AUTH-006',
  name: 'Express session cookie missing secure / httpOnly flag',
  description:
    'express-session config with cookie.secure: false or cookie.httpOnly: false leaves session IDs readable by JavaScript or transmittable over plain HTTP.',
  languages: ['javascript', 'typescript'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-614', 'CWE-1004'],
  tags: ['express', 'ai-prone'],
  remediation: {
    why: 'cookie.secure: false sends the session ID over plain HTTP where any network observer can capture it. cookie.httpOnly: false lets injected scripts read document.cookie and exfiltrate the session.',
    how: 'Set cookie: { secure: true, httpOnly: true, sameSite: "lax" } in the session() options. In local dev only, gate secure on NODE_ENV.',
    exampleFix: 'session({ cookie: { secure: true, httpOnly: true, sameSite: "lax" } })',
  },
  match: (ctx) => [
    ...runRegex(ctx.content, /\b(?:secure|httpOnly)\s*:\s*false\b/g, {
      skipCommentLines: true,
    }),
  ],
};

export const authRules: RuleDefinition[] = [
  debugBypass,
  todoSecurity,
  dummyToken,
  tlsVerifyDisabled,
  csrfExemptDecorator,
  insecureSessionCookie,
];

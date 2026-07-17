// vibeguard:disable-file VG-INJ-008 VG-INJ-009 VG-FW-004
// This file defines Go-specific rules; the literal patterns
// (`fmt.Sprintf` with SELECT, `template.HTML(`, `0.0.0.0` HTTP bind)
// appear inside regex sources and remediation prose by design.
import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const goSqlSprintf: RuleDefinition = {
  ruleId: 'VG-INJ-008',
  name: 'Go SQL query built with fmt.Sprintf',
  description:
    'fmt.Sprintf used to assemble a SQL string that is then handed to db.Query / Exec. AI-generated Go code routinely takes this shortcut instead of using ? placeholders.',
  languages: ['go'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-89'],
  owasp: ['A03:2021'],
  tags: ['sql-injection', 'ai-prone'],
  remediation: {
    why: 'Sprintf interpolates Go values into the SQL string before the driver sees it, so quoted user input can change the query structure.',
    how: 'Use parameterised queries: pass the bare SQL with ? placeholders and the values as variadic args to db.Query / db.Exec.',
    exampleFix: 'db.Query("SELECT * FROM users WHERE id = ?", userId)',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /fmt\.Sprintf\s*\(\s*["`][^"`\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|INTO|WHERE)\b/gi,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const goTemplateHtmlCast: RuleDefinition = {
  ruleId: 'VG-INJ-009',
  name: 'html/template.HTML() cast bypasses escaping',
  description:
    'Wrapping a value in template.HTML (or template.JS / template.URL) marks it as already safe and disables contextual auto-escaping. With non-literal input this is a direct XSS sink.',
  languages: ['go'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-79'],
  tags: ['xss', 'ai-prone'],
  remediation: {
    why: 'html/template auto-escapes string values per context. A template.HTML(value) cast tells the template engine "trust me, this is safe HTML", so any HTML / script in `value` reaches the browser unchanged.',
    how: 'Pass the value as a plain string and let html/template escape it. If raw HTML is actually required, sanitise first (bluemonday or similar) and only then wrap.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\btemplate\.(?:HTML|JS|URL|HTMLAttr|CSS|Srcset)\s*\(\s*(?!["`])[\w.()\[\]]+\s*\)/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const goListenAllInterfacesHttp: RuleDefinition = {
  ruleId: 'VG-FW-004',
  name: 'Go http.ListenAndServe on all interfaces without TLS',
  description:
    'http.ListenAndServe bound to ":<port>" (all interfaces) serves plain HTTP. AI-generated Go servers ship like this and end up exposed without TLS.',
  languages: ['go'],
  category: 'config',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-319'],
  tags: ['go', 'ai-prone'],
  remediation: {
    why: 'Binding to `:<port>` listens on every interface — public when the host is reachable. ListenAndServe (no TLS) means credentials, sessions, and bodies travel in clear text.',
    how: 'Either bind explicitly to 127.0.0.1 for local-only use, or call http.ListenAndServeTLS with a real certificate. Front with a reverse proxy that terminates TLS.',
    exampleFix: 'http.ListenAndServeTLS(":443", certFile, keyFile, mux)',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\bhttp\.ListenAndServe\s*\(\s*["`]:\d+["`]/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const goRules: RuleDefinition[] = [
  goSqlSprintf,
  goTemplateHtmlCast,
  goListenAllInterfacesHttp,
];

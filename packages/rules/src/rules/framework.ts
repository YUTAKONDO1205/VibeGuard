// vibeguard:disable-file VG-FW-001 VG-FW-002 VG-FW-003
// This file *defines* the framework rules; the literal patterns
// (`DEBUG = True`, `app.run(debug=True)`, `cors({ origin: '*' })`,
// `Access-Control-Allow-Origin: *`, `'origins': '*'`) appear inside
// regex sources and remediation examples by design.
// Framework-specific configuration rules. These detect dangerous defaults
// that AI-generated scaffolding routinely leaves in place: Django DEBUG=True,
// Flask debug servers, wildcard CORS, etc. The rule-ID prefix VG-FW groups
// them by structural family; the `category` field carries the risk taxonomy.
import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const djangoDebugTrue: RuleDefinition = {
  ruleId: 'VG-FW-001',
  name: 'Django DEBUG = True in settings',
  description:
    'DEBUG = True in a Django settings module exposes stack traces, environment variables, and SQL on every error page.',
  languages: ['python'],
  category: 'config',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-489', 'CWE-215'],
  tags: ['django', 'ai-prone'],
  remediation: {
    why: 'When DEBUG is on, Django\'s 500 page renders local variables, settings (including SECRET_KEY), and the request\'s POST body. Shipping that to production is a full-disclosure leak.',
    how: 'Read DEBUG from an environment variable defaulting to False: DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1". Keep ALLOWED_HOSTS narrow alongside it.',
    exampleFix: 'DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"',
  },
  match: (ctx) =>
    runRegex(ctx.content, /^\s*DEBUG\s*=\s*True\b/gm, { skipCommentLines: true }),
};

export const flaskDebugRun: RuleDefinition = {
  ruleId: 'VG-FW-002',
  name: 'Flask app.run(debug=True) — Werkzeug debugger reachable',
  description:
    'Calling app.run(debug=True) enables the Werkzeug debugger, which provides an interactive Python console on uncaught exceptions. Combined with host="0.0.0.0" this is remote code execution.',
  languages: ['python'],
  category: 'config',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-489', 'CWE-94'],
  tags: ['flask', 'ai-prone'],
  remediation: {
    why: 'The Werkzeug debugger lets anyone who can hit a 500 page execute arbitrary Python in the server process. AI-generated `if __name__ == "__main__": app.run(debug=True)` blocks routinely ship like this.',
    how: 'Run Flask via a real WSGI server (gunicorn / uWSGI) in production, and never set debug=True on a public bind. For local dev, keep host=127.0.0.1.',
    exampleFix: 'app.run()  # use gunicorn in production',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /\bapp\.run\s*\([^)]*\bdebug\s*=\s*True\b/g,
      { skipCommentLines: true },
    ),
  ],
};

export const corsWildcardOrigin: RuleDefinition = {
  ruleId: 'VG-FW-003',
  name: 'CORS configured with wildcard origin',
  description:
    'cors({ origin: "*" }), Access-Control-Allow-Origin: * literals, or Flask-CORS resources={"/*": {"origins": "*"}} disable the same-origin policy for every browser.',
  languages: ['javascript', 'typescript', 'python', 'go', 'java'],
  category: 'access-control',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-942'],
  owasp: ['A05:2021'],
  tags: ['cors', 'express', 'flask', 'ai-prone'],
  remediation: {
    why: 'A wildcard CORS origin lets any site read responses from your API in a victim\'s browser, including responses for authenticated users.',
    how: 'List allowed origins explicitly. If credentials are involved, the origin must echo the request\'s Origin header — wildcard is rejected by browsers when withCredentials=true anyway.',
    exampleFix: 'cors({ origin: ["https://app.example.com"], credentials: true })',
  },
  match: (ctx) => [
    // Express / koa / hapi — cors({ origin: '*' })
    ...runRegex(ctx.content, /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*["'`]\*["'`]/g, {
      skipCommentLines: true,
    }),
    // Raw header strings — Access-Control-Allow-Origin: *
    ...runRegex(
      ctx.content,
      /["'`]Access-Control-Allow-Origin["'`]\s*[,:]\s*["'`]\*["'`]/g,
      { skipCommentLines: true },
    ),
    // Flask-CORS — "origins": "*" or origins='*'
    ...runRegex(ctx.content, /["']?\borigins\b["']?\s*[:=]\s*["']\*["']/g, {
      skipCommentLines: true,
    }),
  ],
};

export const frameworkRules: RuleDefinition[] = [
  djangoDebugTrue,
  flaskDebugRun,
  corsWildcardOrigin,
];

// vibeguard:disable-file VG-INJ-004 VG-INJ-013 VG-INJ-014 VG-INJ-015 VG-AUTH-007
// This file defines Ruby/Rails-specific rules; the literal patterns
// (`raw(`, `html_safe`, `params.permit!`, `protect_from_forgery ... skip`,
// `eval(`, `instance_eval`) appear inside regex sources and remediation
// prose by design. VG-INJ-004 (generic eval) also fires on the regex
// itself when scanning this file.
import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const rubyRailsRawOrHtmlSafe: RuleDefinition = {
  ruleId: 'VG-INJ-013',
  name: 'Rails raw() / html_safe on non-literal input',
  description:
    'raw(value) or value.html_safe disables ERB auto-escaping. When the value is not a literal, this is a direct XSS sink — one of the top three Rails findings on AI-generated views.',
  languages: ['ruby'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-79'],
  owasp: ['A03:2021'],
  tags: ['xss', 'rails', 'ai-prone'],
  remediation: {
    why: 'raw / html_safe tells Rails "this string is already safe HTML", so any <script> or attribute injection in the value lands in the rendered page unchanged.',
    how: 'Drop raw / html_safe and let ERB escape the value. If you genuinely need HTML markup, use sanitize(value, tags: [...]) which strips dangerous tags and attributes.',
    exampleFix: '<%= sanitize @user.bio, tags: %w[b i br] %>',
  },
  match: (ctx) => [
    // raw(non-literal)
    ...runRegex(
      ctx.content,
      /\braw\s*\(\s*(?!["'][^"']*["']\s*\))[\w@.\[\]]+/g,
      { skipCommentLines: true, language: ctx.language },
    ),
    // foo.html_safe (anything other than a literal string before .html_safe)
    ...runRegex(
      ctx.content,
      /(?<![\w@.\[\]"'])[\w@.\[\]]+\.html_safe\b/g,
      { skipCommentLines: true, language: ctx.language },
    ),
  ],
};

export const rubyEvalFamily: RuleDefinition = {
  ruleId: 'VG-INJ-014',
  name: 'Ruby eval / instance_eval / class_eval with non-literal',
  description:
    'eval(), instance_eval, class_eval, and module_eval execute arbitrary Ruby. Called with a variable argument they are full RCE.',
  languages: ['ruby'],
  category: 'injection',
  severity: 'critical',
  defaultConfidence: 'medium',
  cwe: ['CWE-95'],
  tags: ['rce', 'ai-prone'],
  remediation: {
    why: 'These methods compile and run the argument as Ruby code. Any path from user input to that argument is remote code execution in the host process.',
    how: 'Replace with explicit dispatch (a hash of allowed method names → procs) or a parser appropriate to the input (JSON, YAML.safe_load).',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /(?<![.\w])eval\s*\(\s*(?!["'][^"']*["']\s*\))[\w@.\[\]]+/g,
      { skipCommentLines: true, language: ctx.language },
    ),
    ...runRegex(
      ctx.content,
      /\.(?:instance_eval|class_eval|module_eval)\s*\(\s*(?!["'][^"']*["']\s*\))[\w@.\[\]]+/g,
      { skipCommentLines: true, language: ctx.language },
    ),
  ],
};

export const rubyParamsPermitBang: RuleDefinition = {
  ruleId: 'VG-INJ-015',
  name: 'Rails params.permit! (mass assignment open to every attribute)',
  description:
    'params.permit! marks every parameter as permitted for mass assignment. Any column on the model can be written, including admin flags or password digests.',
  languages: ['ruby'],
  category: 'access-control',
  severity: 'high',
  defaultConfidence: 'high',
  cwe: ['CWE-915'],
  tags: ['rails', 'mass-assignment', 'ai-prone'],
  remediation: {
    why: 'Strong parameters exist specifically to block mass assignment of sensitive fields. permit! opts out of that protection for every column at once.',
    how: 'Replace with an explicit permit list: params.require(:user).permit(:name, :email).',
    exampleFix: 'params.require(:user).permit(:name, :email)',
  },
  match: (ctx) =>
    runRegex(ctx.content, /\bparams\.permit!\s*(?:\)|$)/gm, { skipCommentLines: true, language: ctx.language }),
};

export const railsCsrfDisabled: RuleDefinition = {
  ruleId: 'VG-AUTH-007',
  name: 'Rails CSRF protection disabled or weakened',
  description:
    'skip_before_action :verify_authenticity_token, protect_from_forgery with: :null_session, or skip_forgery_protection in an ApplicationController disables Rails CSRF for the matching actions.',
  languages: ['ruby'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'high',
  cwe: ['CWE-352'],
  owasp: ['A01:2021'],
  tags: ['rails', 'csrf', 'ai-prone'],
  remediation: {
    why: 'Without CSRF validation, an attacker can drive state-changing requests from a victim\'s browser via a forged form or fetch.',
    how: 'Leave protect_from_forgery with: :exception in place. For JSON-only APIs, use a token-based scheme (Devise + JWT, Doorkeeper) instead of disabling CSRF.',
  },
  match: (ctx) => [
    ...runRegex(
      ctx.content,
      /\bskip_before_action[^\S\r\n]+:verify_authenticity_token\b/g,
      { skipCommentLines: true, language: ctx.language },
    ),
    ...runRegex(
      ctx.content,
      /\bprotect_from_forgery[^\S\r\n]+with:[^\S\r\n]*:null_session\b/g,
      { skipCommentLines: true, language: ctx.language },
    ),
    ...runRegex(
      ctx.content,
      /^[^\S\r\n]*skip_forgery_protection\b/gm,
      { skipCommentLines: true, language: ctx.language },
    ),
  ],
};

export const rubyRules: RuleDefinition[] = [
  rubyRailsRawOrHtmlSafe,
  rubyEvalFamily,
  rubyParamsPermitBang,
  railsCsrfDisabled,
];

// vibeguard:disable-file VG-INJ-016 VG-INJ-017 VG-INJ-018 VG-INJ-019
// This file defines PHP-specific rules; the literal patterns
// (`extract($_GET`, `include $`, `unserialize(`, `mysql_query(`) appear
// inside regex sources and remediation prose by design.
import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const phpExtractRequest: RuleDefinition = {
  ruleId: 'VG-INJ-016',
  name: 'extract() on a request superglobal',
  description:
    'extract($_GET / $_POST / $_REQUEST) imports every key from the request into the local symbol table, letting an attacker overwrite arbitrary variables in the calling scope.',
  languages: ['php'],
  category: 'injection',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-915'],
  tags: ['mass-assignment', 'ai-prone'],
  remediation: {
    why: 'Once extract pulls keys from $_GET into local variables, any code below that reads $is_admin, $user_id, etc. is reading attacker-supplied values.',
    how: 'Remove the extract() call. Read each request value explicitly: $name = $_POST["name"] ?? null;. If you must merge, pass EXTR_SKIP and prefix to avoid clobbering.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const phpDynamicInclude: RuleDefinition = {
  ruleId: 'VG-INJ-017',
  name: 'include / require with a variable path',
  description:
    'include / require / include_once / require_once called with a variable (especially one tied to request input) enables Local File Inclusion and, with allow_url_include, Remote File Inclusion.',
  languages: ['php'],
  category: 'injection',
  severity: 'critical',
  defaultConfidence: 'medium',
  cwe: ['CWE-98'],
  tags: ['lfi', 'rfi', 'ai-prone'],
  remediation: {
    why: 'PHP\'s include treats the resolved path as PHP source. If the path can be steered (e.g. ?page=../../etc/passwd or http://evil/payload.php), the included file is executed.',
    how: 'Switch on a fixed allowlist of pages instead of including a variable: $pages = ["home" => "home.php", ...]; include $pages[$_GET["page"]] ?? "404.php";. Confirm allow_url_include is Off in php.ini regardless.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\b(?:include|require)(?:_once)?\s*(?:\(\s*)?\$[A-Za-z_][\w]*/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const phpUnserialize: RuleDefinition = {
  ruleId: 'VG-INJ-018',
  name: 'unserialize() on potentially untrusted input',
  description:
    'unserialize() instantiates arbitrary classes and triggers their magic methods (__wakeup, __destruct). On attacker-controlled input it is a long-standing RCE vector.',
  languages: ['php'],
  category: 'injection',
  severity: 'critical',
  defaultConfidence: 'medium',
  cwe: ['CWE-502'],
  tags: ['deserialization', 'ai-prone'],
  remediation: {
    why: 'unserialize chains object construction with magic methods, giving public PoP gadgets in popular libraries (Laravel, Symfony, WordPress, etc.) a path to code execution.',
    how: 'Use JSON: json_decode($input, true). If serialize is unavoidable, pass ["allowed_classes" => false] (PHP 7+) so only stdClass / scalars are reconstructed.',
    exampleFix: 'json_decode($input, true)',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\bunserialize\s*\(\s*(?![^)]*["']?allowed_classes["']?\s*=>\s*false)/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const phpLegacyMysqlConcat: RuleDefinition = {
  ruleId: 'VG-INJ-019',
  name: 'mysql_query / mysqli_query with string concatenation',
  description:
    'Legacy mysql_query / mysqli_query / pg_query called with a query built from "..." . $var concatenation. No bound parameters means user input changes the SQL.',
  languages: ['php'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-89'],
  owasp: ['A03:2021'],
  tags: ['sql-injection', 'ai-prone'],
  remediation: {
    why: 'Concatenated query strings let any quoted user input redefine the query. AI-generated PHP samples reach for "$query = \\"SELECT ... \\" . $id;" because that is how the training corpus is written.',
    how: 'Use PDO with prepared statements: $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);. mysqli_prepare with bind_param works too.',
    exampleFix: '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /\b(?:mysql_query|mysqli_query|pg_query)[^\S\r\n]*\([^)]{0,500}\.[^\S\r\n]*\$[A-Za-z_]/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

export const phpRules: RuleDefinition[] = [
  phpExtractRequest,
  phpDynamicInclude,
  phpUnserialize,
  phpLegacyMysqlConcat,
];

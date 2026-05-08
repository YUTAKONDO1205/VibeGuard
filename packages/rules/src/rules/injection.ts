import type { RuleDefinition } from '../rule-types.js';
import { runRegex } from '../matcher-utils.js';

export const sqlStringConcat: RuleDefinition = {
  ruleId: 'VG-INJ-001',
  name: 'SQL string concatenation',
  description:
    'SQL query is built via string concatenation or interpolation. Untrusted input concatenated into SQL is the primary vector for SQL injection.',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php', 'ruby', 'csharp'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-89'],
  owasp: ['A03:2021'],
  tags: ['sql-injection', 'ai-prone'],
  remediation: {
    why: 'Concatenated SQL allows attacker-controlled input to alter the query structure and exfiltrate or corrupt data.',
    how: 'Use parameterised queries / prepared statements. Pass user input as bound parameters, not as parts of the SQL string.',
    exampleFix: "db.query('SELECT * FROM ${table} WHERE id = ?', [userId])",
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /["'`][^"'`\n]*\b(?:FROM|INTO|UPDATE)\s+(?<table>\w+)[^"'`\n]*["'`]\s*[+%]\s*\w/gi,
      { skipCommentLines: true },
    ),
};

export const commandInjectionShellTrue: RuleDefinition = {
  ruleId: 'VG-INJ-002',
  name: 'subprocess with shell=True and dynamic args',
  description:
    'subprocess.run / Popen / call invoked with shell=True passes the command through a shell, enabling injection when arguments are interpolated.',
  languages: ['python'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-78'],
  owasp: ['A03:2021'],
  tags: ['command-injection', 'ai-prone'],
  remediation: {
    why: 'shell=True invokes a shell that interprets metacharacters; an attacker who controls any part of the string gets command execution.',
    how: 'Pass arguments as a list and avoid shell=True. If a shell really is needed, use shlex.quote on every interpolated value.',
    exampleFix: 'subprocess.run(["git", "log", commit_id])',
  },
  match: (ctx) =>
    runRegex(ctx.content, /subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True/gms, {
      skipCommentLines: false,
    }),
};

export const osSystemUsage: RuleDefinition = {
  ruleId: 'VG-INJ-003',
  name: 'os.system / os.popen with interpolated input',
  description: 'os.system or os.popen executes via shell. Building the command from variables is a classic injection vector.',
  languages: ['python'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-78'],
  remediation: {
    why: 'os.system / os.popen run a shell. Interpolated variables become shell tokens.',
    how: 'Replace with subprocess.run([...]) using a list and no shell, or sanitise via shlex.quote.',
  },
  match: (ctx) =>
    runRegex(ctx.content, /os\.(?:system|popen)\s*\(\s*(?:f["']|["'][^"']*["']\s*[+%]|.*\{)/g, {
      skipCommentLines: true,
    }),
};

export const evalUsage: RuleDefinition = {
  ruleId: 'VG-INJ-004',
  name: 'Use of eval()',
  description: 'eval() executes arbitrary code from a string. It is rarely necessary and almost never safe with non-literal input.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'injection',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-95'],
  tags: ['rce', 'ai-prone'],
  remediation: {
    why: 'eval() runs whatever string it receives as code. Any path from user input to that string is remote code execution.',
    how: 'Replace eval() with a structured parser (JSON.parse, ast.literal_eval) or a dispatch table for the operations you actually need.',
    exampleFix: 'JSON.parse(input)',
  },
  match: (ctx) =>
    runRegex(ctx.content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true }),
};

export const dangerousDeserialization: RuleDefinition = {
  ruleId: 'VG-INJ-005',
  name: 'Unsafe deserialization (pickle / yaml.load)',
  description:
    'pickle.load / pickle.loads and yaml.load without SafeLoader can execute arbitrary Python objects from input.',
  languages: ['python'],
  category: 'injection',
  severity: 'critical',
  defaultConfidence: 'high',
  cwe: ['CWE-502'],
  remediation: {
    why: 'pickle and unsafe yaml load instantiate arbitrary classes during load, giving attacker-controlled input direct code execution.',
    how: 'Use json or yaml.safe_load. If you must use pickle, only load from data you produced and signed yourself.',
    exampleFix: 'yaml.safe_load(data)',
  },
  match: (ctx) => [
    ...runRegex(ctx.content, /pickle\.(?:load|loads)\s*\(/g, { skipCommentLines: true }),
    ...runRegex(ctx.content, /yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/g, {
      skipCommentLines: true,
    }),
  ],
};

export const innerHtmlAssignment: RuleDefinition = {
  ruleId: 'VG-INJ-006',
  name: 'innerHTML assignment with non-literal value',
  description:
    'Assigning a non-literal string to innerHTML is a common XSS sink. AI-generated UI code often does this without sanitisation.',
  languages: ['javascript', 'typescript'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-79'],
  owasp: ['A03:2021'],
  tags: ['xss', 'ai-prone'],
  remediation: {
    why: 'Strings written to innerHTML are parsed as HTML and can introduce script execution.',
    how: 'Prefer textContent for plain text. For HTML, sanitise with DOMPurify or use the framework escape mechanism.',
    exampleFix: '${target}.textContent = userInput;',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /(?<target>[\w$]+)\.innerHTML\s*=\s*(?!\s*["'][^"'\n]*["']\s*;?\s*$)[^;\n]+/g,
      { skipCommentLines: true },
    ),
};

export const pathTraversalConcat: RuleDefinition = {
  ruleId: 'VG-INJ-007',
  name: 'Path built from string concatenation',
  description:
    'Building file paths via concatenation with variables can enable path traversal if any input contains "..".',
  languages: ['javascript', 'typescript', 'python'],
  category: 'injection',
  severity: 'medium',
  defaultConfidence: 'low',
  cwe: ['CWE-22'],
  remediation: {
    why: 'A user-controlled component may contain ".." and break out of the intended directory.',
    how: 'Resolve paths with path.resolve / os.path.normpath and verify the result starts with the allowed root.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /(?:fs\.(?:readFile|writeFile|createReadStream|createWriteStream|open)|open|os\.path\.join)\s*\([^)]*[+,]\s*\w+/g,
      { skipCommentLines: true },
    ),
};

export const injectionRules: RuleDefinition[] = [
  sqlStringConcat,
  commandInjectionShellTrue,
  osSystemUsage,
  evalUsage,
  dangerousDeserialization,
  innerHtmlAssignment,
  pathTraversalConcat,
];

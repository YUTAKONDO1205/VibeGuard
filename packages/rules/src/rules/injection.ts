// vibeguard:disable-file VG-INJ-004 VG-INJ-020
// This file *defines* injection rules; the literal strings "eval(", "__proto__",
// and the polluting-merge shapes appear inside rule descriptions, regexes, and
// remediation text by design.
import type { RuleDefinition, RuleMatch } from '../rule-types.js';
import { runRegex, blankJsLiterals, extractBlockAfter, indexToPosition, REGEX_INPUT_CAP } from '../matcher-utils.js';

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
      /["'`][^"'`\n]*\b(?:FROM|INTO|UPDATE)[^\S\r\n]+(?<table>\w+)[^"'`\n]*["'`]\s*[+%]\s*\w/gi,
      { skipCommentLines: true, language: ctx.language },
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
    // A1: the argument scan is BOUNDED, but generously. black splits a
    // subprocess call across many kwargs before reaching `shell=True`, and a
    // 200-char bound cut real calls short. Raising the bound costs linear time —
    // it is the UNBOUNDED form that backtracked, not a large K.
    runRegex(ctx.content, /subprocess\.(?:run|call|Popen|check_output|check_call)\s{0,20}\([^)]{0,600}shell\s{0,20}=\s{0,20}True/gms, {
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
    runRegex(ctx.content, // Bounded rather than horizontal-only: `os.system(\n    f"ls {d}"\n)` is a
      // normal formatting of this call and banning line breaks lost it.
      /os\.(?:system|popen)\s{0,20}\((?:\s{0,20}f["']|\s{0,20}["'][^"'\n]{0,200}["']\s{0,20}[+%]|[^\n]{0,200}\{)/g, {
      skipCommentLines: true,
      language: ctx.language,
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
    runRegex(ctx.content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true, language: ctx.language }),
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
    ...runRegex(ctx.content, /pickle\.(?:load|loads)\s*\(/g, { skipCommentLines: true, language: ctx.language }),
    ...runRegex(ctx.content, /yaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/g, {
      skipCommentLines: true,
      language: ctx.language,
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
      /(?<![\w$])(?<target>[\w$]+)\.innerHTML\s*=\s*(?!\s*["'][^"'\n]*["']\s*;?\s*$)[^;\n]+/g,
      { skipCommentLines: true, language: ctx.language },
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
      // Argument lists routinely span lines — `os.path.join(\n root,\n user_input\n)`
      // is what black produces — so the inner class must NOT exclude newlines.
      // Bounding it (`{0,200}`) is what removes the quadratic; excluding line
      // breaks was over-correction and silently lost that shape.
      /(?:fs\.(?:readFile|writeFile|createReadStream|createWriteStream|open)|open|os\.path\.join)\s{0,20}\([^()]{0,200}[+,]\s{0,20}\w+/g,
      { skipCommentLines: true, language: ctx.language },
    ),
};

// --- VG-INJ-020: Prototype-polluting merge (D1b adversarial-review derivative) ---
//
// Two shapes, one rule. Branch A is a LITERAL write to a prototype sink; Branch B
// is a RECURSIVE unguarded for-in merge. The classic slopsquatting-adjacent AI
// smell: a `deepMerge`/`extend` helper copies attacker-controlled keys straight
// onto the target with no own-property guard, so `{"__proto__":{"isAdmin":true}}`
// pollutes Object.prototype (CWE-1321, OWASP A08).
//
// DELIBERATELY NOT DETECTED: generic dynamic-write `obj[key] = value`. That is the
// single most common legitimate JS shape; a taint-free regex for it is an FP
// flood (it collided with the project's E3=0 safe-corpus contract). Branch B fires
// only on the conjunction for-in + dynamic-write-with-loop-var + self-recursion +
// NO guard — each conjunct removes a large class of false positives.

// Branch A — a literal assignment INTO a prototype sink. The trailing `=(?![=>])`
// requires a real assignment and rejects `===`/`==` comparisons and `=>` arrows,
// which is what makes the required negatives free: `key === '__proto__'` guards
// are comparisons, `delete obj['__proto__']` has no `=`. `.prototype` on its own
// (the ubiquitous `MyClass.prototype.method = fn`) is NOT a sink — only
// `.constructor.prototype` is, so ordinary prototype-method assignment is silent.
const PROTO_WRITE =
  /(?:\.__proto__|\[[^\S\r\n]{0,2}(["'`])__proto__\1[^\S\r\n]{0,2}\]|\.constructor[^\S\r\n]{0,2}\.[^\S\r\n]{0,2}prototype|\[[^\S\r\n]{0,2}(["'`])constructor\2[^\S\r\n]{0,2}\][^\S\r\n]{0,2}\[[^\S\r\n]{0,2}(["'`])prototype\3[^\S\r\n]{0,2}\])(?:[^\S\r\n]{0,2}(?:\.[\w$]{1,60}|\[[^\]\n]{1,80}\]))?[^\S\r\n]{0,2}=(?![=>])/g;

// A guard anywhere in the merge body vetoes Branch B. Run on the ORIGINAL body
// text (NOT the comment/string-blanked copy) so a `key === '__proto__'` string
// literal and a `'constructor'` denylist entry are still visible — blanking would
// erase exactly the guard we are looking for.
const MERGE_GUARD =
  /hasOwnProperty|\bhasOwn\b|Object[^\S\r\n]{0,2}\.[^\S\r\n]{0,2}(?:keys|entries|getOwnPropertyNames)\b|["'`]__proto__["'`]|["'`]constructor["'`]|["'`]prototype["'`]|Object[^\S\r\n]{0,2}\.[^\S\r\n]{0,2}create[^\S\r\n]{0,2}\([^\S\r\n]{0,2}null|[\w$]{1,40}[^\S\r\n]{0,2}\.[^\S\r\n]{0,2}(?:has|includes)[^\S\r\n]{0,2}\(/;

// Function heads WITH a name (a self-recursion check needs the name). Both
// `function foo(` and `const foo = (…) =>` / `const foo = function`.
const MERGE_HEAD =
  /function[^\S\r\n]{1,4}(?<fn1>[\w$]{1,60})[^\S\r\n]{0,4}\(|(?:const|let|var)[^\S\r\n]{1,4}(?<fn2>[\w$]{1,60})[^\S\r\n]{0,4}=[^\S\r\n]{0,4}(?:async[^\S\r\n]{0,4})?(?:function\b|\([^()\n]{0,200}\)[^\S\r\n]{0,4}=>|[\w$]{1,40}[^\S\r\n]{0,4}=>)/g;

// A for-in loop, capturing the iteration variable.
const FOR_IN = /for[^\S\r\n]{0,4}\([^\S\r\n]{0,4}(?:const|let|var)?[^\S\r\n]{0,4}(?<k>[\w$]{1,40})[^\S\r\n]{1,4}in[^\S\r\n]{1,4}[\w$.]{1,60}/;

// Branch A — literal prototype-sink writes. Matches on RAW content (so the
// bracket-string form `obj["__proto__"] = x`, whose string literal IS the
// payload, is kept), but REJECTS any match whose sink START sits inside a string
// or comment. `blanked` has those regions overwritten with spaces length- and
// newline-preservingly, so a match position that is a space in `blanked` but not
// in `content` was inside a string/comment — e.g. a `.__proto__ =` printed inside
// an Error message by defensive code. That is a false positive; skip it.
function protoWrites(content: string, blanked: string, lines: string[]): RuleMatch[] {
  const out: RuleMatch[] = [];
  let m: RegExpExecArray | null;
  let count = 0;
  PROTO_WRITE.lastIndex = 0;
  while (count < 1000 && (m = PROTO_WRITE.exec(content)) !== null) {
    count += 1;
    if (m[0].length === 0) {
      PROTO_WRITE.lastIndex += 1;
      continue;
    }
    // Sink start blanked (inside a string/comment) → not a real assignment sink.
    if (blanked[m.index] !== content[m.index]) continue;
    const pos = indexToPosition(content, m.index);
    const lineText = lines[pos.line - 1] ?? '';
    out.push({
      startLine: pos.line,
      endLine: pos.line,
      startColumn: pos.column,
      endColumn: pos.column + m[0].length,
      evidence: (lineText.trim() || m[0]).slice(0, 200),
    });
  }
  return out;
}

function prototypePollutingMerges(content: string, lines: string[], blanked: string): RuleMatch[] {
  // Structural detection runs on the blanked copy (code only — a `for…in` or a
  // dynamic write inside a string/comment does not count); geometry is preserved
  // so offsets map back to `content` 1:1.
  const out: RuleMatch[] = [];
  let h: RegExpExecArray | null;
  let heads = 0;
  MERGE_HEAD.lastIndex = 0;
  while (heads < 200 && (h = MERGE_HEAD.exec(blanked)) !== null) {
    heads += 1;
    if (h[0].length === 0) {
      MERGE_HEAD.lastIndex += 1;
      continue;
    }
    const fn = h.groups?.fn1 ?? h.groups?.fn2;
    if (!fn) continue;
    // Seed extractBlockAfter just before the params/brace; its 200-char head gap
    // skips `(params)` and its `;`-stop rejects a bare declaration with no body.
    const block = extractBlockAfter(blanked, h.index + h[0].length - 1);
    if (!block) continue;
    const body = block.body; // blanked
    const forIn = FOR_IN.exec(body);
    if (!forIn?.groups?.k) continue;
    // `k`/`fn` are `[\w$]+`; `$` is a regex metachar (end-anchor), so it MUST be
    // escaped before embedding — a `$`-prefixed loop var or function name (jQuery-
    // style `$k`) otherwise builds an unmatchable pattern and silently misses.
    const k = forIn.groups.k.replace(/\$/g, '\\$');
    const fnEsc = fn.replace(/\$/g, '\\$');
    // A dynamic bracket WRITE keyed by the loop var: `target[k] = …` (not `==`).
    const writeRe = new RegExp(`\\[[^\\S\\r\\n]{0,2}${k}[^\\S\\r\\n]{0,2}\\][^\\S\\r\\n]{0,2}=(?![=>])`);
    if (!writeRe.test(body)) continue;
    // The recursion signal: the function calls ITSELF inside the body. This is
    // the "recursive merge" requirement and the main suppressor of shallow
    // single-level `for (k in src) dst[k] = src[k]` copies, which cannot be
    // steered into prototype pollution the classic way and are ubiquitous.
    const recRe = new RegExp(`\\b${fnEsc}[^\\S\\r\\n]{0,2}\\(`);
    if (!recRe.test(body)) continue;
    // Guard veto — checked on the ORIGINAL body slice.
    if (MERGE_GUARD.test(content.slice(block.start, block.end))) continue;
    const forInOffset = block.start + forIn.index;
    const pos = indexToPosition(content, forInOffset);
    const lineText = lines[pos.line - 1] ?? '';
    out.push({
      startLine: pos.line,
      endLine: pos.line,
      startColumn: pos.column,
      endColumn: pos.column + forIn[0].length,
      evidence: lineText.trim().slice(0, 200) || forIn[0],
    });
  }
  return out;
}

export const prototypePollutingMerge: RuleDefinition = {
  ruleId: 'VG-INJ-020',
  name: 'Prototype-polluting merge',
  description:
    'A recursive merge/extend copies keys into a target without an own-property guard, or writes directly into __proto__ / constructor.prototype. Attacker-controlled keys like "__proto__" then pollute Object.prototype.',
  languages: ['javascript', 'typescript'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-1321'],
  owasp: ['A08:2021'],
  tags: ['prototype-pollution', 'ai-prone'],
  remediation: {
    why: 'Merging untrusted keys without a guard lets an input key of "__proto__", "constructor", or "prototype" mutate Object.prototype, corrupting every object in the process (privilege escalation, DoS, RCE gadgets).',
    how: 'Guard every copied key: skip "__proto__"/"constructor"/"prototype", use Object.hasOwn(src, key) before recursing, or build the target with Object.create(null). Prefer a vetted deep-merge library.',
    exampleFix: "for (const key of Object.keys(src)) { if (key === '__proto__' || key === 'constructor') continue; /* … */ }",
  },
  match: (ctx) => {
    // D3 parity: the hand-rolled scans below do not self-truncate, so cap here.
    const content = ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    const lines = content === ctx.content ? ctx.lines : content.split('\n');
    const blanked = blankJsLiterals(content);
    return [
      ...protoWrites(content, blanked, lines),
      ...prototypePollutingMerges(content, lines, blanked),
    ];
  },
};

export const injectionRules: RuleDefinition[] = [
  sqlStringConcat,
  commandInjectionShellTrue,
  osSystemUsage,
  evalUsage,
  dangerousDeserialization,
  innerHtmlAssignment,
  pathTraversalConcat,
  prototypePollutingMerge,
];

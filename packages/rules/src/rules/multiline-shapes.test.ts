// vibeguard:disable-file VG-AUTH-001 VG-FW-003 VG-INJ-007 VG-QUAL-003
// Fixtures are intentionally vulnerable code shapes.
import { describe, expect, it } from 'vitest';
import { allRules } from '../index.js';
import type { RuleContext } from '../rule-types.js';

/**
 * REAL CODE SPANS LINES. This file exists because the A1 ReDoS rewrite forgot
 * that, and the differential that was supposed to catch it could not.
 *
 * The rewrite replaced `\s` with a horizontal-only class everywhere, which fixed
 * the backtracking and silently stopped matching six ordinary formattings —
 * Allman braces (`catch (e)\n{`), black-formatted argument lists, multi-line
 * Python signatures. Every one of them matched before the rewrite. The
 * regression corpus (samples/ + test_problem/) happened to contain none of them,
 * so the "zero-diff" differential passed with 80/80 findings identical and the
 * loss went unnoticed until an audit went looking for it specifically.
 *
 * The lesson is about the CORPUS, not the rewrite: a differential can only prove
 * that the shapes it contains are unchanged. These fixtures encode the shapes a
 * formatter actually produces, so a future rewrite that bans line breaks fails
 * here instead of shipping.
 *
 * THE RULE FOR REWRITES, stated once: whitespace that can legitimately cross a
 * line break must be BOUNDED (`\s{0,20}`), never BANNED (`[^\S\r\n]*`). It is the
 * unbounded quantifier that backtracks, not the newline. `sec-a1-shape-check.mjs`
 * checks both obligations of a candidate at once; this test locks the result in.
 */

function ctxFor(content: string, language: string): RuleContext {
  return { content, lines: content.split('\n'), language, filePath: `fixture.${language}` };
}

function matchCount(ruleId: string, content: string, language: string): number {
  const rule = allRules.find((r) => r.ruleId === ruleId);
  if (!rule) throw new Error(`no such rule: ${ruleId}`);
  return rule.match(ctxFor(content, language)).length;
}

/**
 * Each case is a formatting a real formatter emits. `single` is the same code on
 * one line — it pins that the rule still works at all, so a case failing on BOTH
 * means the fixture is wrong rather than the rule.
 */
const MULTILINE_CASES: Array<{
  ruleId: string;
  language: string;
  label: string;
  single: string;
  multi: string;
}> = [
  {
    ruleId: 'VG-QUAL-001',
    language: 'java',
    label: 'Allman brace on an empty catch (dominant Java/C# style)',
    single: 'catch (Exception e) {\n}\n',
    multi: 'catch (Exception e)\n{\n}\n',
  },
  {
    ruleId: 'VG-INJ-007',
    language: 'python',
    label: 'black-formatted os.path.join argument list',
    single: 'os.path.join(root, user_input)\n',
    multi: 'os.path.join(\n    root,\n    user_input\n)\n',
  },
  {
    ruleId: 'VG-INJ-003',
    language: 'python',
    label: 'os.system with the f-string on its own line',
    single: 'os.system(f"ls {d}")\n',
    multi: 'os.system(\n    f"ls {d}"\n)\n',
  },
  {
    ruleId: 'VG-AUTH-001',
    language: 'javascript',
    label: 'Allman brace on a debug-bypass branch (critical rule)',
    single: 'if (debug) { return true; }\n',
    multi: 'if (debug)\n{\n  return true;\n}\n',
  },
  {
    ruleId: 'VG-AUTH-001',
    language: 'javascript',
    label: 'debug-bypass with the condition wrapped across lines',
    single: 'if (DEBUG) { return true; }\n',
    multi: 'if (\n  DEBUG\n) {\n  return true;\n}\n',
  },
  {
    ruleId: 'VG-QUAL-005',
    language: 'python',
    label: 'stub return with a blank line before the marker comment',
    single: 'return True  # TODO implement\n',
    multi: 'return True\n\n# TODO implement\n',
  },
  {
    ruleId: 'VG-QUAL-010',
    language: 'python',
    label: 'validator with a black-formatted multi-line signature',
    single: 'def validate(x):\n    return True\n',
    multi: 'def validate(\n    x,\n):\n    return True\n',
  },
  {
    ruleId: 'VG-QUAL-010',
    language: 'python',
    label: 'validator with a docstring between signature and return',
    single: 'def check(a):\n    return input\n',
    multi: 'def check(a):\n    """doc"""\n    return input\n',
  },
  {
    ruleId: 'VG-FW-002',
    language: 'python',
    label: 'Flask app.run with arguments across lines',
    single: 'app.run(host="0.0.0.0", debug=True)\n',
    multi: 'app.run(\n    host="0.0.0.0",\n    debug=True,\n)\n',
  },
  {
    ruleId: 'VG-FW-003',
    language: 'javascript',
    label: 'cors() config object across lines',
    single: "cors({ origin: '*' })\n",
    multi: "cors({\n  origin: '*',\n})\n",
  },
  {
    ruleId: 'VG-INJ-002',
    language: 'python',
    label: 'subprocess.run with shell=True on a later line',
    single: 'subprocess.run(cmd, shell=True)\n',
    multi: 'subprocess.run(\n    cmd,\n    shell=True,\n)\n',
  },
  {
    ruleId: 'VG-QUAL-003',
    language: 'javascript',
    label: 'console.log of a secret across lines',
    single: 'console.log("token", token)\n',
    multi: 'console.log(\n  "token",\n  token,\n)\n',
  },
  // Go, PHP and Ruby had no coverage at all in the first version of this file,
  // which is how two lang-go rules kept banning line breaks after the other
  // languages were fixed. A fixture set that only covers the languages someone
  // happened to think of reproduces the original blind spot.
  {
    ruleId: 'VG-INJ-008',
    language: 'go',
    label: 'gofmt keeps the line break after Sprintf( for a long SQL string',
    single: 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)\n',
    multi: 'query := fmt.Sprintf(\n\t"SELECT * FROM users WHERE id = %s", id)\n',
  },
  {
    ruleId: 'VG-INJ-009',
    language: 'go',
    label: 'template.HTML cast with its argument on the next line',
    single: 't := template.HTML(userInput)\n',
    multi: 't := template.HTML(\n\tuserInput)\n',
  },
  {
    ruleId: 'VG-INJ-019',
    language: 'php',
    label: 'mysql_query with the interpolated argument on the next line',
    single: 'mysql_query("SELECT * FROM t WHERE id=" . $id);\n',
    multi: 'mysql_query(\n    "SELECT * FROM t WHERE id=" . $id\n);\n',
  },
  {
    ruleId: 'VG-INJ-010',
    language: 'java',
    label: 'ProcessBuilder with concatenated argument on a later line',
    single: 'new ProcessBuilder("sh", "-c", "ls " + userInput);\n',
    multi: 'new ProcessBuilder(\n    "sh",\n    "-c",\n    "ls " + userInput\n);\n',
  },
];

describe('rules still match code that spans lines', () => {
  for (const c of MULTILINE_CASES) {
    it(`${c.ruleId}: ${c.label}`, () => {
      // Sanity: the one-line form must match, or the fixture is wrong.
      expect(matchCount(c.ruleId, c.single, c.language), 'single-line control').toBeGreaterThan(0);
      // The real assertion. A failure here means a rewrite banned line breaks
      // instead of bounding them — a SILENT FALSE NEGATIVE on ordinary code.
      // Fix the pattern (bound the quantifier), do not delete the case.
      expect(matchCount(c.ruleId, c.multi, c.language), 'multi-line form').toBeGreaterThan(0);
    });
  }
});

/**
 * The other half of the contract: bounding must not have made anything
 * over-match. These are near-misses that must stay unmatched.
 */
const MUST_NOT_MATCH: Array<{ ruleId: string; language: string; label: string; content: string }> = [
  { ruleId: 'VG-QUAL-001', language: 'java', label: 'catch with a body', content: 'catch (Exception e) {\n  log(e);\n}\n' },
  { ruleId: 'VG-AUTH-001', language: 'javascript', label: 'non-debug branch', content: 'if (user.isAdmin) {\n  return user;\n}\n' },
  { ruleId: 'VG-QUAL-005', language: 'python', label: 'return of a real value', content: 'return userValue  # ok\n' },
  { ruleId: 'VG-QUAL-010', language: 'python', label: 'validator that actually validates', content: 'def validate(x):\n    return sanitize(x)\n' },
  { ruleId: 'VG-INJ-007', language: 'python', label: 'join with no interpolation', content: 'os.path.join("a", "b")\n' },
];

describe('bounding whitespace did not widen the rules', () => {
  for (const c of MUST_NOT_MATCH) {
    it(`${c.ruleId}: does not match ${c.label}`, () => {
      expect(matchCount(c.ruleId, c.content, c.language)).toBe(0);
    });
  }
});

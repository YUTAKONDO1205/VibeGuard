// vibeguard:disable-file VG-INJ-005 VG-SMELL-012
// Fixtures below are deliberate rule inputs, not code this repository runs.
import { describe, expect, it } from 'vitest';
import { allRules } from '../index.js';
import type { RuleContext, RuleDefinition, RuleMatch } from '../rule-types.js';

function rule(ruleId: string): RuleDefinition {
  const found = allRules.find((r) => r.ruleId === ruleId);
  if (!found) throw new Error(`no such rule: ${ruleId}`);
  return found;
}

function matchLines(ruleId: string, content: string, language: string): number[] {
  const def = rule(ruleId);
  const ctx: RuleContext = {
    content,
    lines: content.split('\n'),
    language,
    filePath: `fixture.${language === 'python' ? 'py' : 'js'}`,
  };
  return def.match(ctx).map((m: RuleMatch) => m.startLine);
}

/**
 * VG-INJ-005 vetoed `yaml.load(…, Loader=yaml.SafeLoader)` and nothing else, so
 * the form PyYAML's own documentation uses — `from yaml import SafeLoader`, then
 * a bare `Loader=SafeLoader` — was reported as a critical arbitrary-code-execution
 * finding on code that had already done the right thing.
 *
 * This matters more than an ordinary false positive because critical/high
 * findings take no context downgrade (`SEVERITY_CONFIDENCE_FLOOR` pins them to
 * `high` confidence), so there is no layer downstream that can soften it: the
 * finding fails the default `--fail-on high` gate and breaks the build.
 */
describe('VG-INJ-005 recognises safe PyYAML loaders however they are imported', () => {
  const wrap = (call: string): string =>
    `import yaml\nfrom yaml import SafeLoader, CSafeLoader, BaseLoader\n\n\ndef load(data):\n    return ${call}\n`;

  it.each([
    ['bare SafeLoader', 'yaml.load(data, Loader=SafeLoader)'],
    ['bare CSafeLoader', 'yaml.load(data, Loader=CSafeLoader)'],
    ['bare BaseLoader', 'yaml.load(data, Loader=BaseLoader)'],
    ['qualified SafeLoader', 'yaml.load(data, Loader=yaml.SafeLoader)'],
    ['qualified CSafeLoader', 'yaml.load(data, Loader=yaml.CSafeLoader)'],
  ])('does not flag %s', (_label, call) => {
    expect(matchLines('VG-INJ-005', wrap(call), 'python')).toEqual([]);
  });

  it.each([
    ['no Loader at all', 'yaml.load(data)'],
    // FullLoader still constructs arbitrary Python objects — deliberately unsafe.
    ['FullLoader', 'yaml.load(data, Loader=yaml.FullLoader)'],
    ['UnsafeLoader', 'yaml.load(data, Loader=yaml.UnsafeLoader)'],
  ])('still flags %s', (_label, call) => {
    expect(matchLines('VG-INJ-005', wrap(call), 'python').length).toBe(1);
  });
});

/**
 * VG-SMELL-012's mitigation veto ran against the raw file, so anything that
 * merely MENTIONED a mitigation counted as having one. A doc string, a log line
 * or an error message containing `Object.freeze(` disabled every role
 * comparison in the file, and the file then reported nothing at all.
 */
describe('VG-SMELL-012 vetoes on real mitigation, not on a mention of one', () => {
  // Two fixture properties are load-bearing, and getting either wrong makes
  // every assertion below pass for the wrong reason (0 === 0):
  //  - braces on their own lines, because `ROLE_FWD` is anchored per line and
  //    does not match the single-line `if (…) { return true; }` form;
  //  - THREE comparison sites, because the rule reports nothing below that
  //    floor (`if (sites.length < 3) return []`) — the smell is "roles are
  //    compared ad hoc all over", not "there is one comparison".
  const ROLE_CHECKS = `function checkA(user) {
  if (user.role === 'admin') {
    return true;
  }
  return false;
}

function checkB(user) {
  if (user.role == 'administrator') {
    return true;
  }
  return false;
}

function checkC(user) {
  if ('superadmin' === user.role) {
    return true;
  }
  return false;
}
`;

  it('reports the role comparisons in a plain file', () => {
    expect(matchLines('VG-SMELL-012', ROLE_CHECKS, 'javascript').length).toBe(3);
  });

  it.each([
    ['a string literal', `const doc = 'see Object.freeze() docs';\n${ROLE_CHECKS}`],
    ['a line comment', `// TODO: Object.freeze( ) the table\n${ROLE_CHECKS}`],
    ['a block comment', `/* Object.freeze( */\n${ROLE_CHECKS}`],
  ])('is not vetoed by %s that only mentions the mitigation', (_label, content) => {
    expect(matchLines('VG-SMELL-012', content, 'javascript').length).toBe(3);
  });

  it('is still vetoed by an actual frozen role table', () => {
    const content = `const ROLES = Object.freeze({ ADMIN: 'admin' });\n${ROLE_CHECKS}`;
    expect(matchLines('VG-SMELL-012', content, 'javascript')).toEqual([]);
  });
});

/**
 * The JS blanker decides what counts as CODE. Two of its calls were wrong in
 * opposite directions, and `VG-INJ-020` shows both, because Branch A matches on
 * RAW text and consults the blanked copy only as a veto:
 *
 *   if (blanked[m.index] !== content[m.index]) continue;
 *
 * So blanking something that is code loses the finding (FN), and failing to
 * blank something that is not code keeps a bogus one (FP). "Fails to blank" was
 * documented as the fail-safe direction; for this consumer it is fail-OPEN.
 */
describe('blankJsLiterals classifies template substitutions and regex literals', () => {
  const SINK = 'obj.__proto__.polluted = userInput;';

  it('reports a sink written plainly', () => {
    expect(matchLines('VG-INJ-020', `function f(userInput, obj) {\n  ${SINK}\n}\n`, 'javascript'))
      .toEqual([2]);
  });

  // `${…}` is evaluated. Blanking it wholesale hid every sink inside an
  // interpolation while the identical statement one line up was reported.
  it('sees a sink inside a template substitution', () => {
    const content = `function f(userInput, obj) {\n  const x = \`\${${SINK.slice(0, -1)}}\`;\n  return x;\n}\n`;
    expect(matchLines('VG-INJ-020', content, 'javascript')).toEqual([2]);
  });

  it('still blanks ordinary template TEXT', () => {
    // Not a substitution — plain text that merely looks like a sink.
    const content = `const doc = \`write ${SINK} to pollute\`;\n`;
    expect(matchLines('VG-INJ-020', content, 'javascript')).toEqual([]);
  });

  // `return /re/`: the preceding significant char is `n`, so a char-only
  // heuristic read the `/` as division, never entered the regex state, and
  // reported the pattern body as a live assignment at `high`.
  it('does not report the body of a regex literal after `return`', () => {
    const content = `function describe() {\n  return /${SINK.slice(0, -1)}/;\n}\n`;
    expect(matchLines('VG-INJ-020', content, 'javascript')).toEqual([]);
  });

  it.each([
    ['identifier', 'const r = a / b;'],
    ['paren close', 'const r = (a + b) / 2;'],
    ['index close', 'const r = arr[0] / 2;'],
    ['call result', 'const r = f() / 2;'],
    ['member', 'const r = this.x / 2;'],
    ['number', 'const r = 1.5 / 0.5;'],
  ])('still treats `/` after a value position as division (%s)', (_label, line) => {
    // If the `/` were read as a regex start it would swallow to the next `/`
    // or newline and hide the sink below.
    expect(matchLines('VG-INJ-020', `${line}\n${SINK}\n`, 'javascript')).toEqual([2]);
  });
});

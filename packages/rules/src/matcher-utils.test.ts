// vibeguard:disable-file
// Fixtures embed eval()/SQL literals to exercise the comment-line predicate;
// they are not real vulnerabilities.
import { describe, expect, it } from 'vitest';
import {
  getLineCommentSpec,
  hasLineCommentSpec,
  isCommentLine,
  type KnownLanguage,
  lineCommentStartsAt,
  runRegex,
} from './matcher-utils.js';

/**
 * `LINE_COMMENT_SPECS` is deliberately not exported (callers must go through
 * `getLineCommentSpec` so the unknown-language fallback cannot be bypassed), so
 * the language list lives here instead. `satisfies Record<KnownLanguage, true>`
 * makes it exhaustive at compile time: adding a language to `KnownLanguage`
 * without listing it here is a type error, and the specs below then have to be
 * stated for it.
 */
const ALL_LANGUAGE_KEYS = {
  javascript: true,
  typescript: true,
  python: true,
  ruby: true,
  go: true,
  java: true,
  kotlin: true,
  csharp: true,
  php: true,
  rust: true,
  swift: true,
  c: true,
  cpp: true,
  shell: true,
  yaml: true,
  json: true,
  toml: true,
  sql: true,
  html: true,
} satisfies Record<KnownLanguage, true>;

const ALL_LANGUAGES = Object.keys(ALL_LANGUAGE_KEYS) as KnownLanguage[];

/** Languages whose allowlist entry has no `#` prefix, so `#` is live syntax. */
const HASH_IS_NOT_COMMENT: readonly KnownLanguage[] = [
  'javascript',
  'typescript',
  'java',
  'go',
  'kotlin',
  'csharp',
  'swift',
  'c',
  'cpp',
  'rust',
  'json',
];

/** VG-SEC-003's pattern, verbatim (rules/secrets.ts). */
const SECRET_PATTERN =
  /\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']/gi;

/** VG-AUTH-004's first pattern, verbatim (rules/auth.ts). */
const VERIFY_FALSE_PATTERN = /verify\s*=\s*False\b/g;

describe('isCommentLine', () => {
  it('treats a leading // as a comment only where // is comment syntax', () => {
    expect(isCommentLine('// x', 'javascript')).toBe(true);
    expect(isCommentLine('  // x', 'go')).toBe(true);
    // Python's `//` is floor division, not a comment (hiding vector 1).
    expect(isCommentLine('// x', 'python')).toBe(false);
    // Unknown language: nothing is a comment (hiding vector 4).
    expect(isCommentLine('// x', undefined)).toBe(false);
  });

  it('does not treat a leading # as a comment where # is real syntax', () => {
    // ES2022 private class field — executed code, not a comment.
    expect(isCommentLine('#x = 1', 'javascript')).toBe(false);
    expect(isCommentLine('  #q = (s) => eval(s);', 'typescript')).toBe(false);
    // Preprocessor / attribute / directive syntax, one realistic form per family.
    expect(isCommentLine('#define DB_PASSWORD "hunter2"', 'c')).toBe(false);
    expect(isCommentLine('#include <stdio.h>', 'cpp')).toBe(false);
    expect(isCommentLine('#[derive(Debug)]', 'rust')).toBe(false);
    expect(isCommentLine('#if DEBUG', 'swift')).toBe(false);
    expect(isCommentLine('#x = 1', 'kotlin')).toBe(false);
  });

  it('treats a leading # as a comment where # starts a comment', () => {
    expect(isCommentLine('#x = 1', 'python')).toBe(true);
    expect(isCommentLine('# eval(x)', 'ruby')).toBe(true);
    expect(isCommentLine('  # comment', 'php')).toBe(true);
  });

  it('unknown language treats nothing as a comment (fail-safe)', () => {
    // The allowlist has no entry, so no syntax opens a comment and no match is
    // dropped. Failing this way costs at worst a false positive on a line that
    // really was a comment; the old blocklist's "# is a comment" fallback let an
    // unrecognised extension erase findings before anything could see them.
    expect(isCommentLine('#x = 1', undefined)).toBe(false);
    expect(isCommentLine('// x', undefined)).toBe(false);
    expect(isCommentLine('-- x', undefined)).toBe(false);
    expect(isCommentLine('#x = 1', 'no-such-language')).toBe(false);
  });

  it('classifies # as non-comment in every language whose spec has no # prefix', () => {
    for (const language of HASH_IS_NOT_COMMENT) {
      // Guard the list above against drifting from the real map.
      expect(getLineCommentSpec(language).prefixes).not.toContain('#');
      expect(isCommentLine('#x = 1', language)).toBe(false);
      // `//` stays a comment in those languages regardless.
      expect(isCommentLine('// x = 1', language)).toBe(true);
    }
  });

  it('does not treat code with a trailing comment as a comment line', () => {
    expect(isCommentLine('const x = 1; // note', 'javascript')).toBe(false);
    expect(isCommentLine('x = 1  # note', 'python')).toBe(false);
  });

  it('treats both # and -- as comments in sql, but not //', () => {
    expect(isCommentLine('-- x', 'sql')).toBe(true);
    expect(isCommentLine('# x', 'sql')).toBe(true);
    expect(isCommentLine('// x', 'sql')).toBe(false);
    // KNOWN RESIDUAL GAP, fixed here as current behaviour rather than repaired:
    // MySQL requires whitespace after `--` for it to open a comment, so
    // `--payload` is executed code. The `--` test is a naive `startsWith`, so we
    // classify it as a comment and drop its match — a silent false negative.
    // Deliberately out of scope for this change; do not "fix" without also
    // deciding what other dialects (Postgres, SQLite) expect from bare `--`.
    expect(isCommentLine('--payload', 'sql')).toBe(true);
  });

  it('treats nothing as a comment in html', () => {
    // HTML's only comment syntax is the multi-line `<!-- -->`, which this
    // line-oriented predicate does not model (a known limitation, unchanged).
    // `//` and `#` inside an HTML file are live syntax: a protocol-relative URL,
    // a CSS id selector, a private field in an inline <script>.
    expect(isCommentLine('// x', 'html')).toBe(false);
    expect(isCommentLine('# x', 'html')).toBe(false);
  });
});

describe('line-comment allowlist', () => {
  it('has an explicit entry for every known language', () => {
    for (const language of ALL_LANGUAGES) {
      expect(hasLineCommentSpec(language)).toBe(true);
    }
  });

  it('falls back to the empty spec for unknown or absent languages', () => {
    expect(hasLineCommentSpec(undefined)).toBe(false);
    expect(hasLineCommentSpec('no-such-language')).toBe(false);
    expect(getLineCommentSpec(undefined)).toEqual({ prefixes: [], exclusions: [] });
    // html is an explicit entry that looks identical to the fallback; the two
    // are told apart by reference, not by structure.
    expect(getLineCommentSpec('html')).toEqual({ prefixes: [], exclusions: [] });
    expect(hasLineCommentSpec('html')).toBe(true);
  });

  it('returns the empty spec for prototype-chain keys, not an inherited value', () => {
    // A caller-supplied `language` of `__proto__`/`constructor`/`toString` must
    // not resolve to an inherited object: that has no `prefixes`, so
    // `lineCommentStartsAt` would throw, and inside `rule.match` the analyzer's
    // per-rule try/catch swallows it — silently dropping the rule's findings,
    // the exact undeclared-suppression channel the allowlist exists to close.
    for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      expect(hasLineCommentSpec(key)).toBe(false);
      expect(getLineCommentSpec(key)).toEqual({ prefixes: [], exclusions: [] });
      // Must not throw — this is the crash the guard prevents.
      expect(() => lineCommentStartsAt('# x', 0, getLineCommentSpec(key))).not.toThrow();
    }
  });

  it('never uses an empty-string prefix', () => {
    // `''.startsWith('')` is true, so an empty prefix would classify every line
    // in that language as a comment and silently drop all of its findings.
    for (const language of ALL_LANGUAGES) {
      expect(getLineCommentSpec(language).prefixes).not.toContain('');
    }
  });

  it('only excludes tokens that some prefix would otherwise match', () => {
    // An exclusion that starts with no prefix could never fire — it would be
    // dead config hiding a typo (e.g. `['#[']` under a spec that lost its `#`).
    for (const language of ALL_LANGUAGES) {
      const { prefixes, exclusions } = getLineCommentSpec(language);
      for (const exclusion of exclusions) {
        expect(prefixes.some((p) => exclusion.startsWith(p))).toBe(true);
      }
    }
  });
});

describe('runRegex({ skipCommentLines, language })', () => {
  it('keeps a match on an ES2022 private field line when language is given', () => {
    const content = 'class C {\n  #q = (s) => eval(s);\n}';
    const matches = runRegex(content, /(?<![.\w])eval\s*\(/g, {
      skipCommentLines: true,
      language: 'javascript',
    });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(2);
  });

  it('keeps the match when no language is given (fail-safe)', () => {
    const content = 'class C {\n  #q = (s) => eval(s);\n}';
    const matches = runRegex(content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(2);
  });

  it('still skips a real Python # comment', () => {
    const content = '# eval(x)\ny = 1';
    expect(
      runRegex(content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true, language: 'python' }),
    ).toEqual([]);
  });

  it('keeps a secret on a C preprocessor line (VG-SEC-003 pattern)', () => {
    // `#define` is executed syntax, so the secret is live — dropping it would be
    // a silent false negative on a severity=high rule. VG-SEC-003's own pattern,
    // verbatim: it needs a `:`/`=`, so `#define token = "…"` is the reachable
    // shape (`#define TOKEN "…"` never matches it, with or without this fix).
    const pattern =
      /\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["']([A-Za-z0-9+/=_\-]{20,})["']/gi;
    const content = '#define token = "s3cr3tValue0123456789abc"';
    expect(runRegex(content, pattern, { skipCommentLines: true, language: 'c' }).length).toBe(1);
    // Same text in a language where # really is a comment stays skipped.
    expect(runRegex(content, pattern, { skipCommentLines: true, language: 'python' })).toEqual([]);
  });

  it('still skips a // comment when a language is given', () => {
    const content = '// eval(x)\nconst y = 1;';
    expect(
      runRegex(content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true, language: 'javascript' }),
    ).toEqual([]);
  });

  it('ignores language when skipCommentLines is not set', () => {
    const content = '# eval(x)';
    expect(runRegex(content, /(?<![.\w])eval\s*\(/g, { language: 'python' }).length).toBe(1);
  });
});

/**
 * The four concealment vectors this allowlist exists to close, each fixed at
 * both levels: the classifier (`isCommentLine`) and the drop it drives
 * (`runRegex({ skipCommentLines })`).
 *
 * These matter more than an ordinary false negative. `skipCommentLines` DELETES
 * the match upstream of the analyzer's confidence chokepoint, so the severity
 * gate never sees it and cannot bound the mistake. Under the old blocklist each
 * vector let an attacker erase a high-severity finding with a line of ordinary,
 * declaration-free source — no suppression comment, nothing to audit.
 */
describe('comment-classifier concealment vectors (regression)', () => {
  it('vector 1: a Python // continuation line is code, not a comment', () => {
    expect(isCommentLine('// 2', 'python')).toBe(false);
    expect(isCommentLine('    // b', 'python')).toBe(false);

    // Floor division inside a parenthesised call: the continuation line really
    // can start with `//`, so `verify=False` (VG-AUTH-004, severity=high) rode
    // out on a line the old classifier called a comment.
    const content = 'resp = requests.get(url, timeout=(total\n    // 2), verify=False)';
    const matches = runRegex(content, VERIFY_FALSE_PATTERN, {
      skipCommentLines: true,
      language: 'python',
    });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(2);
  });

  it('vector 2: # in an HTML inline <script> is a private field, not a comment', () => {
    expect(isCommentLine('#priv = eval(s)', 'html')).toBe(false);

    const content =
      '<script>\nclass Client {\n  #token = "s3cr3tValue0123456789abc";\n}\n</script>';
    const matches = runRegex(content, SECRET_PATTERN, {
      skipCommentLines: true,
      language: 'html',
    });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(3);
  });

  it('vector 3: a PHP 8 #[Attribute] is executed syntax, not a comment', () => {
    expect(isCommentLine('#[Route("/x", token: "s3cr3tValue0123456789abc")]', 'php')).toBe(false);
    // PHP's other comment syntax is untouched by the `#[` exclusion.
    expect(isCommentLine('# comment', 'php')).toBe(true);
    expect(isCommentLine('// x', 'php')).toBe(true);
    // The space means it does not start with `#[`, so this stays a comment.
    expect(isCommentLine('# [x]', 'php')).toBe(true);

    const content = '#[Route("/x", token: "s3cr3tValue0123456789abc")]\nfunction x() {}';
    const matches = runRegex(content, SECRET_PATTERN, { skipCommentLines: true, language: 'php' });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(1);
    // Contrast: the same literal behind a genuine PHP `#` comment is still skipped.
    expect(
      runRegex('# token: "s3cr3tValue0123456789abc"', SECRET_PATTERN, {
        skipCommentLines: true,
        language: 'php',
      }),
    ).toEqual([]);
  });

  it('vector 4: # under an unknown extension does not hide a secret', () => {
    expect(isCommentLine('#token = "s3cr3tValue0123456789abc"', undefined)).toBe(false);

    // An unrecognised extension leaves ctx.language undefined. VG-SEC-003 runs
    // on every language (`languages: ['*']`), so the old `#` fallback made
    // renaming a file enough to erase the finding.
    const content = '#token = "s3cr3tValue0123456789abc"';
    const matches = runRegex(content, SECRET_PATTERN, { skipCommentLines: true });
    expect(matches.length).toBe(1);
    expect(matches[0]!.startLine).toBe(1);
    // Same via an explicitly unknown language string, not just an absent one.
    expect(
      runRegex(content, SECRET_PATTERN, { skipCommentLines: true, language: 'no-such-language' })
        .length,
    ).toBe(1);
  });
});

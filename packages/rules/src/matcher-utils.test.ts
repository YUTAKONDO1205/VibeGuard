// vibeguard:disable-file
// Fixtures embed eval()/SQL literals to exercise the comment-line predicate;
// they are not real vulnerabilities.
import { describe, expect, it } from 'vitest';
import { HASH_NOT_COMMENT, isCommentLine, runRegex } from './matcher-utils.js';

describe('isCommentLine', () => {
  it('treats a leading // as a comment in any language', () => {
    expect(isCommentLine('// x', 'javascript')).toBe(true);
    expect(isCommentLine('// x', 'python')).toBe(true);
    expect(isCommentLine('  // x', 'go')).toBe(true);
    expect(isCommentLine('// x', undefined)).toBe(true);
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

  it('falls back to "# is a comment" when the language is unknown', () => {
    // Preserves the pre-language behaviour for callers that cannot supply one.
    expect(isCommentLine('#x = 1', undefined)).toBe(true);
  });

  it('classifies # as non-comment for every HASH_NOT_COMMENT language', () => {
    for (const language of HASH_NOT_COMMENT) {
      expect(isCommentLine('#x = 1', language)).toBe(false);
      // `//` stays a comment in those languages regardless.
      expect(isCommentLine('// x = 1', language)).toBe(true);
    }
  });

  it('does not treat code with a trailing comment as a comment line', () => {
    expect(isCommentLine('const x = 1; // note', 'javascript')).toBe(false);
    expect(isCommentLine('x = 1  # note', 'python')).toBe(false);
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

  it('drops the same match when no language is given (documented fallback)', () => {
    const content = 'class C {\n  #q = (s) => eval(s);\n}';
    expect(runRegex(content, /(?<![.\w])eval\s*\(/g, { skipCommentLines: true })).toEqual([]);
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

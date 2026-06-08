// vibeguard:disable-file
// Fixtures embed eval()/innerHTML/DEBUG/secret literals to exercise the
// context-window confidence helper; they are not real vulnerabilities.
import { describe, expect, it } from 'vitest';
import {
  contextConfidence,
  detectDowngradeSignals,
  downgradeConfidence,
  isInDocstringOrBlockComment,
  isTestPath,
} from './confidence.js';
import type { RuleContext, RuleMatch } from './rule-types.js';

function ctxOf(content: string, opts: { filePath?: string; language?: string } = {}): RuleContext {
  return { content, lines: content.split('\n'), filePath: opts.filePath, language: opts.language };
}

function matchAtLine(startLine: number): RuleMatch {
  return { startLine, endLine: startLine, startColumn: 1, endColumn: 1, evidence: '' };
}

describe('downgradeConfidence', () => {
  it('lowers by the given number of ladder steps', () => {
    expect(downgradeConfidence('high', 1)).toBe('medium');
    expect(downgradeConfidence('high', 2)).toBe('low');
    expect(downgradeConfidence('medium', 1)).toBe('low');
  });

  it('clamps at low and is a no-op for zero/negative steps', () => {
    expect(downgradeConfidence('high', 3)).toBe('low');
    expect(downgradeConfidence('low', 2)).toBe('low');
    expect(downgradeConfidence('high', 0)).toBe('high');
    expect(downgradeConfidence('medium', -1)).toBe('medium');
  });
});

describe('isTestPath', () => {
  it('recognises test / spec / fixture paths', () => {
    expect(isTestPath('src/foo.test.ts')).toBe(true);
    expect(isTestPath('tests/test_client.py')).toBe(true);
    expect(isTestPath('pkg/__mocks__/db.js')).toBe(true);
    expect(isTestPath('app/fixtures/data.json')).toBe(true);
    expect(isTestPath('src/handler.spec.tsx')).toBe(true);
  });

  it('does not flag ordinary source paths', () => {
    expect(isTestPath('src/handlers.ts')).toBe(false);
    expect(isTestPath('app/settings.py')).toBe(false);
    expect(isTestPath(undefined)).toBe(false);
  });
});

describe('isInDocstringOrBlockComment', () => {
  it('detects a Python docstring line', () => {
    const lines = [
      'def configure():',
      '    """',
      '    Example config:',
      '        DEBUG = True',
      '    """',
      '    return DEBUG',
    ];
    expect(isInDocstringOrBlockComment(lines, 4, 'python')).toBe(true); // DEBUG = True inside docstring
    expect(isInDocstringOrBlockComment(lines, 6, 'python')).toBe(false); // return DEBUG, after close
    expect(isInDocstringOrBlockComment(lines, 1, 'python')).toBe(false);
  });

  it('detects a JS/Java block comment line', () => {
    const lines = ['/*', ' * el.innerHTML = data;', ' */', 'render();'];
    expect(isInDocstringOrBlockComment(lines, 2, 'javascript')).toBe(true);
    expect(isInDocstringOrBlockComment(lines, 4, 'javascript')).toBe(false);
  });

  it('does not treat a closed single-line docstring as ongoing', () => {
    const lines = ['x = """short"""', 'DEBUG = True'];
    expect(isInDocstringOrBlockComment(lines, 2, 'python')).toBe(false);
  });

  it('is not fooled by /* or // inside a string literal (regression: flask CORS sample)', () => {
    // r'/*' is a raw string containing /*, NOT a block-comment opener. A naive
    // scanner would treat everything after it as a block comment and wrongly
    // down-rank the real app.run(debug=True) below.
    const lines = [
      "CORS(app, resources={r'/*': {'origins': '*'}})",
      "    app.run(host='0.0.0.0', debug=True)",
    ];
    expect(isInDocstringOrBlockComment(lines, 2, 'python')).toBe(false);
  });

  it('treats a real block comment opened after a string as ongoing', () => {
    const lines = ['const s = "x"; /*', 'eval(payload)', '*/', 'run()'];
    expect(isInDocstringOrBlockComment(lines, 2, 'javascript')).toBe(true);
    expect(isInDocstringOrBlockComment(lines, 4, 'javascript')).toBe(false);
  });

  it('ignores # as a comment marker in languages where it is not one', () => {
    // `this.#secret` is a JS private field, not a comment; must not swallow the
    // subsequent block-comment opener.
    const lines = ['this.#secret = "x"; /*', 'eval(payload)', '*/', 'run()'];
    expect(isInDocstringOrBlockComment(lines, 2, 'javascript')).toBe(true);
  });
});

describe('detectDowngradeSignals', () => {
  it('flags a whole-line comment', () => {
    const ctx = ctxOf('// eval(userInput)', { filePath: 'a.js', language: 'javascript' });
    expect(detectDowngradeSignals(ctx, matchAtLine(1))).toEqual(['comment']);
  });

  it('flags a docstring line', () => {
    const ctx = ctxOf('"""\nDEBUG = True\n"""', { filePath: 'settings.py', language: 'python' });
    expect(detectDowngradeSignals(ctx, matchAtLine(2))).toEqual(['docstring']);
  });

  it('flags a test path and stacks with comment context', () => {
    const ctx = ctxOf('// secret = "x"', { filePath: 'a.test.js', language: 'javascript' });
    expect(detectDowngradeSignals(ctx, matchAtLine(1))).toEqual(['comment', 'test-path']);
  });

  it('returns no signals for a plain code line in a source path', () => {
    const ctx = ctxOf('const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' });
    expect(detectDowngradeSignals(ctx, matchAtLine(1))).toEqual([]);
  });

  it('reads the payload line, not the previous comment line, for ^\\s*-anchored evidence', () => {
    // Mirrors VG-QUAL-008 / VG-FW-001: the `^\s*` match swallows the newline, so
    // startLine points at the comment on line 1 but the real code is line 2.
    const ctx = ctxOf('# DEBUG left on below\nDEBUG = True', {
      filePath: 'settings.py',
      language: 'python',
    });
    const match: RuleMatch = {
      startLine: 1,
      endLine: 2,
      startColumn: 1,
      endColumn: 1,
      evidence: '\nDEBUG = True',
    };
    expect(detectDowngradeSignals(ctx, match)).toEqual([]); // line 2 is real code
  });
});

describe('contextConfidence', () => {
  const codeCtx = ctxOf('const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' });
  const commentCtx = ctxOf('// const x = eval(input);', { filePath: 'src/run.js', language: 'javascript' });
  const testCtx = ctxOf('const x = eval(input);', { filePath: 'src/run.test.js', language: 'javascript' });

  it('leaves confidence unchanged on a plain production code line', () => {
    expect(contextConfidence('high', codeCtx, matchAtLine(1))).toBe('high');
  });

  it('drops two steps for a comment (high -> low)', () => {
    expect(contextConfidence('high', commentCtx, matchAtLine(1))).toBe('low');
  });

  it('drops one step for a test path (high -> medium)', () => {
    expect(contextConfidence('high', testCtx, matchAtLine(1))).toBe('medium');
    expect(contextConfidence('medium', testCtx, matchAtLine(1))).toBe('low');
  });

  it('sums stacked signals and clamps at low', () => {
    const commentInTest = ctxOf('// secret', { filePath: 'a.test.js', language: 'javascript' });
    expect(contextConfidence('high', commentInTest, matchAtLine(1))).toBe('low');
  });

  it('is a no-op when mode is off (comment-is-the-signal rules)', () => {
    expect(contextConfidence('medium', commentCtx, matchAtLine(1), 'off')).toBe('medium');
  });

  it('never raises confidence (downgrade-only)', () => {
    expect(contextConfidence('low', codeCtx, matchAtLine(1))).toBe('low');
    expect(contextConfidence('medium', codeCtx, matchAtLine(1))).toBe('medium');
  });
});

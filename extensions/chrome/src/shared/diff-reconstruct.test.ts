// vibeguard:disable-file VG-QUAL-003 VG-SEC-001 VG-SEC-003
import { describe, expect, it } from 'vitest';
import {
  addedLineSet,
  languageFromPath,
  reconstructPseudoContent,
  MAX_PSEUDO_LINES,
  reconstructPseudoFile,
  type ParsedDiffFile,
} from './diff-reconstruct.js';

describe('reconstructPseudoContent', () => {
  it('places lines at their new-file line numbers and pads with empty lines', () => {
    const file: ParsedDiffFile = {
      filePath: 'a.ts',
      lines: [
        { ln: 3, text: 'const a = 1', added: true },
        { ln: 5, text: 'console.log(a)', added: true },
      ],
    };
    expect(reconstructPseudoContent(file)).toBe('\n\nconst a = 1\n\nconsole.log(a)');
    // Lines 1, 2, 4 are empty; lines 3 and 5 carry text.
    const rebuilt = reconstructPseudoContent(file).split('\n');
    expect(rebuilt[2]).toBe('const a = 1');
    expect(rebuilt[4]).toBe('console.log(a)');
  });

  it('keeps context lines as well as added lines (analyzer regex context)', () => {
    const file: ParsedDiffFile = {
      filePath: 'b.py',
      lines: [
        { ln: 1, text: 'import os', added: false },
        { ln: 2, text: 'token = "AKIAIOSFODNN7EXAMPLE"', added: true },
        { ln: 3, text: 'print(token)', added: false },
      ],
    };
    const content = reconstructPseudoContent(file);
    expect(content.split('\n')).toEqual([
      'import os',
      'token = "AKIAIOSFODNN7EXAMPLE"',
      'print(token)',
    ]);
  });

  it('handles out-of-order input (extractor may emit hunks unsorted)', () => {
    const file: ParsedDiffFile = {
      filePath: 'c.ts',
      lines: [
        { ln: 10, text: 'tenth', added: true },
        { ln: 1, text: 'first', added: false },
      ],
    };
    const out = reconstructPseudoContent(file).split('\n');
    expect(out).toHaveLength(10);
    expect(out[0]).toBe('first');
    expect(out[9]).toBe('tenth');
  });

  it('returns empty string for an empty diff', () => {
    expect(reconstructPseudoContent({ filePath: 'x', lines: [] })).toBe('');
  });
});

describe('addedLineSet', () => {
  it('only includes lines with added=true', () => {
    const file: ParsedDiffFile = {
      filePath: 'a',
      lines: [
        { ln: 1, text: 'x', added: false },
        { ln: 2, text: 'y', added: true },
        { ln: 3, text: 'z', added: true },
      ],
    };
    const s = addedLineSet(file);
    expect(s.has(1)).toBe(false);
    expect(s.has(2)).toBe(true);
    expect(s.has(3)).toBe(true);
    expect(s.size).toBe(2);
  });
});

describe('languageFromPath', () => {
  it('maps known extensions', () => {
    expect(languageFromPath('src/a.ts')).toBe('typescript');
    expect(languageFromPath('src/a.tsx')).toBe('typescript');
    expect(languageFromPath('a.py')).toBe('python');
    expect(languageFromPath('main.go')).toBe('go');
    expect(languageFromPath('A.java')).toBe('java');
    expect(languageFromPath('foo.rb')).toBe('ruby');
    expect(languageFromPath('foo.php')).toBe('php');
    expect(languageFromPath('foo.cs')).toBe('csharp');
  });

  it('returns undefined for unknown or missing extension', () => {
    expect(languageFromPath('README')).toBeUndefined();
    expect(languageFromPath('a.rs')).toBeUndefined();
  });
});

/**
 * Line numbers come from `data-line-number` in the page, which is
 * attacker-controlled on any site the user can be steered to (the extension
 * holds `<all_urls>`). Sizing the buffer by the highest one seen made
 * `data-line-number="999999999"` a one-attribute denial of service against the
 * side panel — before a single rule had run.
 */
describe('reconstructPseudoFile bounds a hostile line number', () => {
  it('reconstructs an ordinary file exactly as before', () => {
    const file: ParsedDiffFile = {
      filePath: 'a.js',
      lines: [
        { ln: 3, text: 'a', added: true },
        { ln: 5, text: 'b', added: true },
      ],
    };
    const r = reconstructPseudoFile(file);
    expect(r.content).toBe('\n\na\n\nb');
    expect(r.truncatedAt).toBeUndefined();
  });

  it('caps the buffer and says so', () => {
    const file: ParsedDiffFile = {
      filePath: 'evil.js',
      lines: [
        { ln: 1, text: 'const a = 1;', added: true },
        { ln: 999_999_999, text: 'const b = 2;', added: true },
      ],
    };
    const r = reconstructPseudoFile(file);
    expect(r.content.split('\n').length).toBe(MAX_PSEUDO_LINES);
    expect(r.truncatedAt).toBe(999_999_999);
    // The lines that DID fit are still there — the cap costs the tail, not the file.
    expect(r.content.startsWith('const a = 1;')).toBe(true);
  });

  it('does not allocate for a line number just under the cap', () => {
    const file: ParsedDiffFile = {
      filePath: 'big.js',
      lines: [{ ln: MAX_PSEUDO_LINES, text: 'x', added: true }],
    };
    const r = reconstructPseudoFile(file);
    expect(r.truncatedAt).toBeUndefined();
    expect(r.content.split('\n').length).toBe(MAX_PSEUDO_LINES);
  });
});

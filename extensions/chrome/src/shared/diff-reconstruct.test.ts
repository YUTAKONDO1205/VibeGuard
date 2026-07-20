// vibeguard:disable-file VG-QUAL-003 VG-SEC-001 VG-SEC-003
import { describe, expect, it } from 'vitest';
import {
  addedLineSet,
  languageFromPath,
  reconstructPseudoContent,
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

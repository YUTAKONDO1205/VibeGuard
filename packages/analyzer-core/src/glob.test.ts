import { describe, expect, it } from 'vitest';
import { matchesGlob, matchesAnyGlob } from './glob.js';

describe('matchesGlob', () => {
  it('matches a literal path', () => {
    expect(matchesGlob('src/index.ts', 'src/index.ts')).toBe(true);
  });

  it('* matches within a single segment', () => {
    expect(matchesGlob('src/*.ts', 'src/index.ts')).toBe(true);
    expect(matchesGlob('src/*.ts', 'src/sub/index.ts')).toBe(false);
  });

  it('** matches across segments', () => {
    expect(matchesGlob('src/**/index.ts', 'src/index.ts')).toBe(true);
    expect(matchesGlob('src/**/index.ts', 'src/a/index.ts')).toBe(true);
    expect(matchesGlob('src/**/index.ts', 'src/a/b/index.ts')).toBe(true);
  });

  it('trailing /** matches subtree files', () => {
    expect(matchesGlob('samples/vulnerable/**', 'samples/vulnerable/a.py')).toBe(true);
    expect(matchesGlob('samples/vulnerable/**', 'samples/vulnerable/sub/b.py')).toBe(true);
  });

  it('? matches one character (not /)', () => {
    expect(matchesGlob('file?.ts', 'fileA.ts')).toBe(true);
    expect(matchesGlob('file?.ts', 'file12.ts')).toBe(false);
  });

  it('escapes regex meta in the pattern', () => {
    expect(matchesGlob('a.b.c', 'a.b.c')).toBe(true);
    expect(matchesGlob('a.b.c', 'aXbXc')).toBe(false);
  });

  it('normalises backslashes in the path', () => {
    expect(matchesGlob('src/**/index.ts', 'src\\a\\index.ts')).toBe(true);
  });
});

describe('matchesAnyGlob', () => {
  it('returns false for an empty list', () => {
    expect(matchesAnyGlob([], 'a.ts')).toBe(false);
    expect(matchesAnyGlob(undefined, 'a.ts')).toBe(false);
  });

  it('returns true when any pattern matches', () => {
    expect(matchesAnyGlob(['no/match', '**/*.ts'], 'src/a.ts')).toBe(true);
  });
});

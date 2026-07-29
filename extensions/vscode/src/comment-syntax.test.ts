import { describe, expect, it } from 'vitest';
import { COMMENT_STYLES, suppressionComment } from './comment-syntax.js';

const RULE = 'VG-CRYPTO-003';

/**
 * The property that matters is not "which token do we emit" but "does the file
 * still parse after the Quick Fix ran". These tests assert that directly where
 * a parser is available (JSON), and structurally where one is not.
 */
describe('suppressionComment', () => {
  it('emits a line comment for languages that have one', () => {
    expect(suppressionComment('python', RULE)).toBe(`# vibeguard:disable-next-line ${RULE}`);
    expect(suppressionComment('typescript', RULE)).toBe(`// vibeguard:disable-next-line ${RULE}`);
    expect(suppressionComment('sql', RULE)).toBe(`-- vibeguard:disable-next-line ${RULE}`);
  });

  it('falls back to a block comment when the language has no line comment', () => {
    expect(suppressionComment('css', RULE)).toBe(`/* vibeguard:disable-next-line ${RULE} */`);
    expect(suppressionComment('html', RULE)).toBe(`<!-- vibeguard:disable-next-line ${RULE} -->`);
  });

  // The regression this whole module exists for. VG-CRYPTO-003 matches an
  // `http://` URL in any text, so findings DO land in .json files; the old
  // `//`-for-everything fallback then produced a suppression that broke the
  // file it was suppressing in.
  it('withholds the fix for strict JSON, which has no comment syntax', () => {
    expect(suppressionComment('json', RULE)).toBeNull();
  });

  it('still offers the fix for JSON with Comments', () => {
    expect(suppressionComment('jsonc', RULE)).toBe(`// vibeguard:disable-next-line ${RULE}`);
  });

  it('does not emit `//` for PowerShell, where it is not a comment', () => {
    const emitted = suppressionComment('powershell', RULE);
    expect(emitted).not.toBeNull();
    expect(emitted!.startsWith('//')).toBe(false);
    expect(emitted).toBe(`# vibeguard:disable-next-line ${RULE}`);
  });

  it('falls back to `//` for an unclassified language', () => {
    expect(suppressionComment('some-future-language', RULE)).toBe(
      `// vibeguard:disable-next-line ${RULE}`,
    );
  });

  // Whatever we emit has to be recognisable to the parser that consumes it.
  // `PRAGMA_RE` in analyzer-core keys off the directive text alone, so this is
  // a check that no style mangles or omits it.
  it('always carries the directive and the rule id verbatim', () => {
    for (const languageId of Object.keys(COMMENT_STYLES)) {
      const emitted = suppressionComment(languageId, RULE);
      if (emitted === null) continue;
      expect(emitted).toContain(`vibeguard:disable-next-line ${RULE}`);
    }
  });

  describe('inserting the comment leaves the document parseable', () => {
    const insertBefore = (source: string, line: number, comment: string): string => {
      const lines = source.split('\n');
      lines.splice(line, 0, comment);
      return lines.join('\n');
    };

    it('never corrupts a JSON document, because it declines to edit one', () => {
      const source = '{\n  "endpoint": "http://api.example.com/v1"\n}\n';
      expect(() => JSON.parse(source) as unknown).not.toThrow();

      const comment = suppressionComment('json', RULE);
      expect(comment).toBeNull();

      // Demonstrates what the previous behaviour did, and why null is the fix.
      const asIfWeHadInserted = insertBefore(source, 1, '  // vibeguard:disable-next-line');
      expect(() => JSON.parse(asIfWeHadInserted) as unknown).toThrow();
    });

    it('produces a comment JSONC accepts', () => {
      const comment = suppressionComment('jsonc', RULE)!;
      // JSONC's defining property: a line starting `//` is a comment, so the
      // shape below is exactly what the language expects.
      expect(comment.startsWith('//')).toBe(true);
    });

    it('produces a balanced block comment for CSS and HTML', () => {
      expect(suppressionComment('css', RULE)!).toMatch(/^\/\*.*\*\/$/);
      expect(suppressionComment('html', RULE)!).toMatch(/^<!--.*-->$/);
    });
  });
});

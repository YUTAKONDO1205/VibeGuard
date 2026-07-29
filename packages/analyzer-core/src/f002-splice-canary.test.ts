// vibeguard:disable-file VG-MEM-001
// Fixtures call gets() on purpose — that is the detection being measured.
import { describe, expect, it } from 'vitest';
import { scan } from './analyzer.js';

/**
 * F-002, the half that is NOT fixed — pinned so it cannot pass silently.
 *
 * C translation phase 2 deletes backslash-newline before tokens are
 * recognised. Two things follow, and only one is modelled:
 *
 *   MODELLED (false positive, closed): a `//` comment ending in a backslash
 *   continues onto the next physical line, so the line below is comment and
 *   must not be reported. Closing this cost nothing, because comment blanking
 *   is length-preserving.
 *
 *   NOT MODELLED (false negative, open): a splice inside an IDENTIFIER joins
 *   it, so `ge\` + newline + `ts(buf);` is `gets(buf)`. Closing this needs a
 *   transformed text whose offsets no longer match the original, and every
 *   position VibeGuard reports — findings, snippets, `disable-line` lookups,
 *   SARIF regions, the Quick Fix insertion point — is identity-mapped to the
 *   source by construction. The face would put a translation seam in front of
 *   all of them.
 *
 * These tests assert the CURRENT answer, not the desired one. Implementing the
 * splicing face SHOULD break them; that is the point. When it does, invert the
 * expectations rather than deleting the file, and move the entry out of the
 * residual list in `matcher-utils.ts`.
 *
 * Fixtures build their backslash from its code point. Written as an escape it
 * survives TypeScript but not every tool in the path, and a fixture that has
 * lost its backslash is an ordinary two-line file on which every assertion here
 * passes for the wrong reason.
 */
const BS = String.fromCharCode(92);
const lines = (...parts: string[]): string => `${parts.join('\n')}\n`;

const scanC = (content: string): ReturnType<typeof scan> =>
  scan({ targetType: 'file', content, filePath: 'a.c', mode: 'standard', language: 'c' });

const hits = (r: ReturnType<typeof scan>): number =>
  r.findings.filter((f) => f.ruleId === 'VG-MEM-001').length;

describe('F-002 — the comment half IS modelled', () => {
  const SPLICED_COMMENT = lines(
    '#include <stdio.h>',
    'void f(void) {',
    '  char buf[64];',
    `  // disabled call ${BS}`,
    '  gets(buf);',
    '}',
  );

  it('the fixture really ends a comment line with a backslash', () => {
    expect(SPLICED_COMMENT).toContain(`call ${BS}\n  gets`);
  });

  it('does not report code that the splice turned into comment', () => {
    expect(hits(scanC(SPLICED_COMMENT))).toBe(0);
  });

  it('still reports a real gets() on an ordinary line', () => {
    const plain = lines('#include <stdio.h>', 'void f(void) {', '  char buf[64];', '  gets(buf);', '}');
    expect(hits(scanC(plain))).toBe(1);
  });

  it('still reports code after an ordinary comment with no splice', () => {
    const noSplice = lines(
      '#include <stdio.h>',
      'void f(void) {',
      '  char buf[64];',
      '  // disabled call',
      '  gets(buf);',
      '}',
    );
    expect(hits(scanC(noSplice))).toBe(1);
  });
});

describe('F-002 — the identifier half is a KNOWN RESIDUAL and still evades', () => {
  const SPLICED_IDENT = lines(
    '#include <stdio.h>',
    'void f(void) {',
    '  char buf[64];',
    `  ge${BS}`,
    'ts(buf);',
    '}',
  );

  it('the fixture really splits the identifier across a spliced newline', () => {
    expect(SPLICED_IDENT).toContain(`  ge${BS}\nts(buf);`);
  });

  // ⚠ CURRENT BEHAVIOUR, NOT DESIRED BEHAVIOUR. A compiler reads this as
  // `gets(buf)`. If this assertion starts failing, the splicing face has landed
  // — invert it and update the residual list in matcher-utils.ts.
  it('reports nothing today, because the identifier is never rejoined', () => {
    expect(hits(scanC(SPLICED_IDENT))).toBe(0);
  });

  it('reports the same construct once the splice is removed', () => {
    const rejoined = SPLICED_IDENT.replace(`  ge${BS}\nts(buf);`, '  gets(buf);');
    expect(hits(scanC(rejoined))).toBe(1);
  });
});

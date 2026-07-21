import { describe, expect, it } from 'vitest';
import { allRules } from '@vibeguard/rules';
import { fixers, buildFix, applyFixes } from './fixers.js';

// A finding's match, minimal shape for the fixers (line-anchored).
function match(startLine: number) {
  return { startLine, endLine: startLine, startColumn: 1, endColumn: 1, evidence: '' };
}

/** Apply the fix for the single finding a rule produces on `content`. */
function fixOne(ruleId: string, content: string): string | null {
  const built = buildFix(ruleId, content, match(1));
  if (!built) return null;
  return applyFixes(content, built.edits);
}

describe('fixer registry integrity', () => {
  it('every fixer key is a real rule ID', () => {
    const ids = new Set(allRules.map((r) => r.ruleId));
    const stale = Object.keys(fixers).filter((k) => !ids.has(k));
    expect(stale, `fixers with no matching rule: ${stale.join(', ')}`).toEqual([]);
  });
  it('every fixer declares a title and a valid safety', () => {
    for (const [id, f] of Object.entries(fixers)) {
      expect(f.title, `${id} title`).toBeTruthy();
      expect(['safe', 'needs-review']).toContain(f.safety);
    }
  });
});

describe('golden fixes', () => {
  it('VG-EMB-020: #define DEBUG 1 → 0', () => {
    expect(fixOne('VG-EMB-020', '#define DEBUG 1\n')).toBe('#define DEBUG 0\n');
    expect(fixOne('VG-EMB-020', '#define DEBUG true\n')).toBe('#define DEBUG 0\n');
  });
  it('VG-EMB-021: #define BYPASS_AUTH 1 → 0', () => {
    expect(fixOne('VG-EMB-021', '#define BYPASS_AUTH 1\n')).toBe('#define BYPASS_AUTH 0\n');
  });
  it('VG-EMB-011: MBEDTLS_SSL_VERIFY_NONE → REQUIRED', () => {
    expect(fixOne('VG-EMB-011', 'ssl_conf_authmode(&c, MBEDTLS_SSL_VERIFY_NONE);\n')).toBe(
      'ssl_conf_authmode(&c, MBEDTLS_SSL_VERIFY_REQUIRED);\n',
    );
  });
  it('VG-EMB-011: returns null for setInsecure() (no safe token swap)', () => {
    expect(buildFix('VG-EMB-011', 'client.setInsecure();\n', match(1))).toBeNull();
  });
  it('VG-EMB-010: http:// → https://', () => {
    expect(fixOne('VG-EMB-010', 'http.begin("http://api.example.com/x");\n')).toBe(
      'http.begin("https://api.example.com/x");\n',
    );
  });
  it('VG-RTOS-004: O_DIRECT → O_DIRECT | O_SYNC', () => {
    expect(fixOne('VG-RTOS-004', 'fd = open(path, O_DIRECT);\n')).toBe(
      'fd = open(path, O_DIRECT | O_SYNC);\n',
    );
  });
});

describe('fix determinism and safety', () => {
  it('is idempotent: applying then re-detecting yields no second edit', () => {
    const once = fixOne('VG-EMB-020', '#define DEBUG 1\n')!;
    // The value is now 0, so the fixer finds no `1|true` token to swap.
    expect(buildFix('VG-EMB-020', once, match(1))).toBeNull();
  });
  it('applyFixes rejects overlapping edits wholesale (no partial apply)', () => {
    const overlapping = [
      { start: 0, end: 5, replacement: 'X' },
      { start: 3, end: 8, replacement: 'Y' },
    ];
    expect(applyFixes('abcdefghij', overlapping)).toBeNull();
  });
  it('applyFixes applies disjoint edits bottom-up correctly', () => {
    const edits = [
      { start: 0, end: 1, replacement: 'A' },
      { start: 5, end: 6, replacement: 'F' },
    ];
    expect(applyFixes('abcdefgh', edits)).toBe('AbcdeFgh');
  });
  it('a fixer returns null when its pattern is not on the match line', () => {
    expect(buildFix('VG-EMB-020', 'int x = 1;\n', match(1))).toBeNull();
  });

  it('VG-RTOS-004 fixer is idempotent: null when O_SYNC already present', () => {
    expect(buildFix('VG-RTOS-004', 'open(p, O_DIRECT | O_SYNC);\n', match(1))).toBeNull();
    // never produces a double sync when re-run
    let s = 'fd = open(p, O_DIRECT);\n';
    for (let i = 0; i < 3; i++) {
      const b = buildFix('VG-RTOS-004', s, match(1));
      if (b) s = applyFixes(s, b.edits)!;
    }
    expect(s).not.toMatch(/O_SYNC \| O_SYNC/);
  });

  it('tokenSwap fixes the token at the finding column, not always the first', () => {
    // Two http URLs on one line; the finding anchors the SECOND (column 30).
    const content = 'a("http://x.io"); b("http://y.io");\n';
    const col = content.indexOf('"http://y') + 1; // 1-based column of the 2nd URL's opening quote
    const built = buildFix('VG-EMB-010', content, {
      startLine: 1,
      endLine: 1,
      startColumn: col,
      endColumn: col,
      evidence: '',
    });
    const out = applyFixes(content, built.edits);
    expect(out).toBe('a("http://x.io"); b("https://y.io");\n');
  });
});

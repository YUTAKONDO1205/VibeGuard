import { describe, expect, it } from 'vitest';
import { allRules, getRule, nearestKnownPackage, type RuleMatch } from '@vibeguard/rules';
import { fixers, buildFix, applyFixes } from './fixers.js';

// A finding's match, minimal shape for the fixers (line-anchored).
function match(startLine: number) {
  return { startLine, endLine: startLine, startColumn: 1, endColumn: 1, evidence: '' };
}

/** A match anchored at a specific 1-based column (what the CLI rebuilds). */
function matchAt(startLine: number, startColumn: number) {
  return { startLine, endLine: startLine, startColumn, endColumn: startColumn, evidence: '' };
}

/**
 * Run the REAL rule over `content`. Used to prove two things a hand-built match
 * cannot: that the fixer consumes the coordinates the detector actually emits,
 * and that the rule goes silent once the fix is applied.
 */
function detect(ruleId: string, content: string, language: string): RuleMatch[] {
  const rule = getRule(ruleId);
  if (!rule) throw new Error(`rule ${ruleId} not found`);
  return rule.match({ content, lines: content.split('\n'), language });
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
  // Driven from the DETECTOR's coordinates rather than a hand-built column 1.
  // The fixer is anchored (B4/A2): it edits the token that starts at the reported
  // column and declines otherwise, so a synthetic column that does not point at
  // the URL is no longer a valid stand-in for a real finding.
  it('VG-EMB-010: http:// → https://', () => {
    const content = 'http.begin("http://api.example.com/x");\n';
    const found = detect('VG-EMB-010', content, 'cpp');
    expect(found).toHaveLength(1);
    const built = buildFix('VG-EMB-010', content, found[0]!)!;
    expect(applyFixes(content, built.edits)).toBe('http.begin("https://api.example.com/x");\n');
  });

  // The anchoring contract itself: a column that does not hold the token is not
  // a coordinate this fixer will act on. Without this, a finding raised on the
  // CANONICAL face — whose column is a valid offset but whose original bytes are
  // not the payload — would send the edit forward onto an unrelated URL.
  it('VG-EMB-010: declines a column that does not start the token', () => {
    const content = 'http.begin("http://api.example.com/x");\n';
    expect(buildFix('VG-EMB-010', content, matchAt(1, 1))).toBeNull();
  });

  // The rule excludes loopback with a negative lookahead; the fixer carries the
  // same exclusion, so it can never rewrite a URL the detector passed over.
  it('VG-EMB-010: declines a loopback URL the rule deliberately excludes', () => {
    const content = 'local_get("http://localhost/health");\n';
    expect(detect('VG-EMB-010', content, 'cpp')).toHaveLength(0);
    expect(buildFix('VG-EMB-010', content, matchAt(1, 11))).toBeNull();
  });
  // B4: value semantics vs definedness semantics. Flipping the define to 0 does
  // NOT disable a flag the code consults with #ifdef / defined(), and the rule
  // stops matching afterwards — so the fix would trade a reported finding for a
  // clean scan over an unchanged backdoor. The fixer declines instead.
  it('VG-EMB-021: declines when the flag is consumed by #ifdef', () => {
    const content = '#define BYPASS_AUTH 1\n#ifdef BYPASS_AUTH\n  return AUTH_OK;\n#endif\n';
    expect(detect('VG-EMB-021', content, 'c')).toHaveLength(1);
    expect(buildFix('VG-EMB-021', content, match(1))).toBeNull();
  });

  it('VG-EMB-020: declines when the flag is consumed by #if defined()', () => {
    const content = '#define DEBUG 1\n#if defined(DEBUG)\n  serial_print(secret);\n#endif\n';
    expect(buildFix('VG-EMB-020', content, match(1))).toBeNull();
  });

  // …and still fixes the value-consumed form, which is what the swap is for.
  it('VG-EMB-020: still fixes the value-consumed form', () => {
    expect(fixOne('VG-EMB-020', '#define DEBUG 1\n#if DEBUG\n  x();\n#endif\n')).toBe(
      '#define DEBUG 0\n#if DEBUG\n  x();\n#endif\n',
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
    expect(built).not.toBeNull();
    const out = applyFixes(content, built!.edits);
    expect(out).toBe('a("http://x.io"); b("https://y.io");\n');
  });
});

// --- VG-INJ-020 -----------------------------------------------------------------
// The rule ships TWO shapes under one ID, and only one of them is fixable, so
// most of these tests are about what the fixer REFUSES to do.

const GUARD_K = 'if (k === "__proto__" || k === "constructor" || k === "prototype") continue;';

describe('VG-INJ-020 prototype-pollution guard', () => {
  const MERGE = [
    'function merge(dst, src) {',
    '  for (const k in src) {',
    '    if (typeof src[k] === "object") merge(dst[k], src[k]);',
    '    else dst[k] = src[k];',
    '  }',
    '  return dst;',
    '}',
    '',
  ].join('\n');

  it('inserts the guard using the detector’s own coordinates', () => {
    const matches = detect('VG-INJ-020', MERGE, 'javascript');
    expect(matches).toHaveLength(1);
    const built = buildFix('VG-INJ-020', MERGE, matches[0]!);
    expect(built).not.toBeNull();
    expect(built!.safety).toBe('needs-review');
    const out = applyFixes(MERGE, built!.edits)!;
    expect(out.split('\n')[2]).toBe(`    ${GUARD_K}`);
    // Body indentation is COPIED from the first statement of the loop, not
    // guessed: the guard lines up with the `if` it now precedes.
    expect(out.split('\n')[3]).toBe('    if (typeof src[k] === "object") merge(dst[k], src[k]);');
  });

  it('silences the rule after the fix (real re-scan, not a claim)', () => {
    const matches = detect('VG-INJ-020', MERGE, 'javascript');
    const out = applyFixes(MERGE, buildFix('VG-INJ-020', MERGE, matches[0]!)!.edits)!;
    // The rule's guard vocabulary includes the literal string "__proto__", so
    // the inserted guard is recognised. If this ever fails, the fix would be
    // applied twice by a re-run and this test is the tripwire.
    expect(detect('VG-INJ-020', out, 'javascript')).toEqual([]);
  });

  it('is a no-op on a second application (idempotent)', () => {
    const matches = detect('VG-INJ-020', MERGE, 'javascript');
    const once = applyFixes(MERGE, buildFix('VG-INJ-020', MERGE, matches[0]!)!.edits)!;
    // Replay the SAME (now stale) finding against the fixed bytes: the guard is
    // already there, so no second edit is offered.
    expect(buildFix('VG-INJ-020', once, matches[0]!)).toBeNull();
  });

  it('returns null for a Branch A match (proto-sink write, not a loop)', () => {
    const content = 'const o = {};\no.__proto__ = evil;\n';
    const matches = detect('VG-INJ-020', content, 'javascript');
    expect(matches).toHaveLength(1);
    expect(matches[0]!.startLine).toBe(2);
    expect(buildFix('VG-INJ-020', content, matches[0]!)).toBeNull();
  });

  it('returns null for a Branch A match that shares its line with a real for-in', () => {
    // The adversarial case the column anchor exists for: a `constructor.prototype`
    // sink (no "__proto__" text to short-circuit on) followed by a genuine merge
    // loop. Searching forward from the column would guard the wrong construct.
    const content = 'a.constructor.prototype.x = 1; for (const k in s) { d[k] = s[k]; }\n';
    const col = content.indexOf('.constructor') + 1;
    expect(buildFix('VG-INJ-020', content, matchAt(1, col))).toBeNull();
  });

  it('returns null for a brace-less loop body', () => {
    const content = 'for (const k in src) dst[k] = src[k];\n';
    expect(buildFix('VG-INJ-020', content, matchAt(1, 1))).toBeNull();
  });

  it('guards the loop at the finding column when a line holds two loops', () => {
    const content = 'for (const a in x) { y[a] = x[a]; } for (const b in p) { q[b] = p[b]; }\n';
    const second = content.indexOf('for (const b') + 1;
    const out = applyFixes(content, buildFix('VG-INJ-020', content, matchAt(1, second))!.edits)!;
    expect(out).toBe(
      'for (const a in x) { y[a] = x[a]; } for (const b in p) { ' +
        'if (b === "__proto__" || b === "constructor" || b === "prototype") continue; ' +
        'q[b] = p[b]; }\n',
    );
    // …and the first loop is chosen when the column points there instead.
    const first = content.indexOf('for (const a') + 1;
    const out1 = applyFixes(content, buildFix('VG-INJ-020', content, matchAt(1, first))!.edits)!;
    expect(out1).toBe(
      'for (const a in x) { ' +
        'if (a === "__proto__" || a === "constructor" || a === "prototype") continue; ' +
        'y[a] = x[a]; } for (const b in p) { q[b] = p[b]; }\n',
    );
  });

  it('handles a $-prefixed loop variable verbatim', () => {
    // `$` is a regex/replacement metacharacter; edits are built by slicing, not
    // by String.replace, so `$k` must survive as written.
    const content = 'for (const $k in src) { dst[$k] = src[$k]; }\n';
    const out = applyFixes(content, buildFix('VG-INJ-020', content, matchAt(1, 1))!.edits)!;
    expect(out).toBe(
      'for (const $k in src) { ' +
        'if ($k === "__proto__" || $k === "constructor" || $k === "prototype") continue; ' +
        'dst[$k] = src[$k]; }\n',
    );
  });

  it('preserves CRLF line endings', () => {
    const crlf = MERGE.split('\n').join('\r\n');
    const matches = detect('VG-INJ-020', crlf, 'javascript');
    expect(matches).toHaveLength(1);
    const out = applyFixes(crlf, buildFix('VG-INJ-020', crlf, matches[0]!)!.edits)!;
    expect(out).toContain(`\r\n    ${GUARD_K}\r\n`);
    // No lone LF was introduced anywhere in the file.
    expect(out).not.toMatch(/[^\r]\n/);
  });

  it('does not mistake a `var`-prefixed identifier for a declaration keyword', () => {
    // `for (variable in src)` — the loop variable is `variable`, not `iable`.
    const content = 'for (variable in src) { dst[variable] = src[variable]; }\n';
    const out = applyFixes(content, buildFix('VG-INJ-020', content, matchAt(1, 1))!.edits)!;
    expect(out).toBe(
      'for (variable in src) { ' +
        'if (variable === "__proto__" || variable === "constructor" || variable === "prototype") continue; ' +
        'dst[variable] = src[variable]; }\n',
    );
  });

  it('returns null when the column does not land on a loop header', () => {
    const content = 'const x = 1;\nfor (const k in src) { dst[k] = src[k]; }\n';
    // Column 5 on line 2 is inside `(const k…`, not at `for`.
    expect(buildFix('VG-INJ-020', content, matchAt(2, 5))).toBeNull();
  });
});

// --- VG-AISC-001 ----------------------------------------------------------------

describe('VG-AISC-001 hallucinated-import rename', () => {
  it('renames a near-miss npm import to the detector’s own suggestion', () => {
    const content = 'const express = require("expresss");\n';
    const matches = detect('VG-AISC-001', content, 'javascript');
    expect(matches).toHaveLength(1);
    const built = buildFix('VG-AISC-001', content, matches[0]!);
    expect(built).not.toBeNull();
    expect(built!.safety).toBe('needs-review');
    // The replacement is not merely "some popular name": it is byte-identical to
    // the suggestion the RULE produced for this very match, which is the whole
    // point of sharing `nearestKnownPackage` instead of copying the logic.
    expect(built!.edits).toHaveLength(1);
    expect(built!.edits[0]!.replacement).toBe(matches[0]!.variables?.didYouMean);
    expect(built!.edits[0]!.replacement).toBe(nearestKnownPackage('expresss', 'javascript'));
    // The edit lands INSIDE the quotes. The specifier's start is computed from
    // the match END rather than by indexOf, which is what keeps it right when
    // the specifier text also occurs inside the word `require`.
    const specStart = content.indexOf('"expresss"') + 1;
    expect(built!.edits[0]!.start).toBe(specStart);
    expect(built!.edits[0]!.end).toBe(specStart + 'expresss'.length);
    expect(applyFixes(content, built!.edits)).toBe('const express = require("express");\n');
  });

  it('renames only the import-position occurrence, not other text on the line', () => {
    const content = 'const expresss = require("expresss"); log("expresss");\n';
    const matches = detect('VG-AISC-001', content, 'javascript');
    expect(matches).toHaveLength(1);
    const built = buildFix('VG-AISC-001', content, matches[0]!)!;
    expect(built.edits).toHaveLength(1);
    expect(applyFixes(content, built.edits)).toBe(
      'const expresss = require("express"); log("expresss");\n',
    );
  });

  it('renames only the first path segment inside the string literal', () => {
    const content = 'import r from "expresss/lib/router";\n';
    const matches = detect('VG-AISC-001', content, 'javascript');
    expect(matches).toHaveLength(1);
    const out = applyFixes(content, buildFix('VG-AISC-001', content, matches[0]!)!.edits);
    expect(out).toBe('import r from "express/lib/router";\n');
  });

  it('renames a Python module (unquoted import syntax)', () => {
    const content = 'from numpyy import array\n';
    const matches = detect('VG-AISC-001', content, 'python');
    expect(matches).toHaveLength(1);
    const built = buildFix('VG-AISC-001', content, matches[0]!)!;
    expect(built.edits[0]!.replacement).toBe(nearestKnownPackage('numpyy', 'python'));
    expect(applyFixes(content, built.edits)).toBe('from numpy import array\n');
  });

  it('returns null for a curated hallucination (no suggestion exists)', () => {
    const content = 'const hf = require("huggingface-cli");\n';
    const matches = detect('VG-AISC-001', content, 'javascript');
    expect(matches).toHaveLength(1);
    // Flagged with high confidence but NO didYouMean — there is nothing to
    // rename to, and inventing a target is the line this engine will not cross.
    expect(matches[0]!.variables?.didYouMean).toBeUndefined();
    expect(buildFix('VG-AISC-001', content, matches[0]!)).toBeNull();
  });

  it('fixes the single near-miss when a line also holds a known import', () => {
    const content = 'const a = require("expresss"); const b = require("lodash");\n';
    const matches = detect('VG-AISC-001', content, 'javascript');
    expect(matches).toHaveLength(1);
    const out = applyFixes(content, buildFix('VG-AISC-001', content, matches[0]!)!.edits);
    expect(out).toBe('const a = require("express"); const b = require("lodash");\n');
  });

  it('returns null when one line holds two different near-miss imports', () => {
    const content = 'const a = require("expresss"); const b = require("lodashh");\n';
    const matches = detect('VG-AISC-001', content, 'javascript');
    // Two findings, both spanning the same whole line: the column cannot say
    // which is which, so neither is fixed.
    expect(matches.length).toBe(2);
    for (const m of matches) expect(buildFix('VG-AISC-001', content, m)).toBeNull();
  });

  it('renames every occurrence when the SAME near-miss appears twice on a line', () => {
    const content = 'require("expresss"); require("expresss");\n';
    const matches = detect('VG-AISC-001', content, 'javascript');
    expect(matches).toHaveLength(1); // the rule de-dups by package name
    const built = buildFix('VG-AISC-001', content, matches[0]!)!;
    expect(built.edits).toHaveLength(2);
    expect(applyFixes(content, built.edits)).toBe('require("express"); require("express");\n');
  });

  it('ignores relative and scoped specifiers', () => {
    for (const spec of ['./expresss', '@acme/expresss', 'node:expresss']) {
      const content = `import x from "${spec}";\n`;
      expect(buildFix('VG-AISC-001', content, matchAt(1, 1))).toBeNull();
    }
  });

  it('does not rename a quoted string that is not an import specifier', () => {
    expect(buildFix('VG-AISC-001', 'log("expresss");\n', matchAt(1, 1))).toBeNull();
  });

  it('is a no-op on a second application (idempotent)', () => {
    const content = 'const express = require("expresss");\n';
    const matches = detect('VG-AISC-001', content, 'javascript');
    const once = applyFixes(content, buildFix('VG-AISC-001', content, matches[0]!)!.edits)!;
    expect(buildFix('VG-AISC-001', once, matches[0]!)).toBeNull();
    expect(detect('VG-AISC-001', once, 'javascript')).toEqual([]);
  });
});

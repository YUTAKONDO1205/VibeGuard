// vibeguard:disable-file VG-AUTH-002 VG-INJ-004 VG-SEC-001 VG-SEC-003
// Fixtures embed eval(), AWS-shaped key literals and DEBUG flags — both plain
// and in evaded form — because that is exactly what this suite has to scan to
// prove the canonicalizer closes them. They are not real vulnerabilities. Same
// treatment as matcher-utils.test.ts.
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scan } from '../analyzer.js';
import type { Finding } from '@vibeguard/findings-schema';

/**
 * H7 — canonicalizer soundness.
 *
 * The claim D2 has to earn is that normalization never COSTS a detection:
 *
 *     D′(x) = D(x) ∪ D(N(x))   ⟹   D′(x) ⊇ D(x)
 *
 * The union in `analyzer.ts` makes that true by construction for every input,
 * so what these tests verify is that the implementation matches the
 * construction — not that the property happens to hold on a corpus. The corpus
 * checks below are the empirical backstop, in two halves:
 *
 *   - SUPERSET, on the bytes as they sit on disk: nothing is ever lost.
 *   - EQUALITY, on LF-normalized bytes: nothing is ever invented. The sample
 *     corpus contains no evasions, so a canonical-only finding there is a
 *     manufactured false positive and fails the build. Normalizing line
 *     endings first excludes a pre-existing CRLF defect that is not D2's —
 *     see the `runRegex` describe block for what it is and why it is separate.
 *
 * The last block pins the RESIDUE — the transforms `N` provably cannot
 * collapse. Those tests assert that evasion still works. They exist so the
 * paper's honesty about residual evasion is checked by CI rather than
 * remembered: when a future layer closes one of them, a test flips loudly
 * instead of the claim quietly going stale.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const SAMPLES = join(HERE, '..', '..', '..', '..', 'samples');

function key(f: Finding): string {
  return `${f.ruleId}@${f.startLine}:${f.startColumn}`;
}

function scanBoth(content: string, filePath: string) {
  return {
    on: scan({ targetType: 'snippet', mode: 'standard', content, filePath }),
    off: scan({ targetType: 'snippet', mode: 'standard', content, filePath }, { canonicalize: false }),
  };
}

function sampleFiles(dir: string): Array<{ name: string; path: string; content: string }> {
  return readdirSync(join(SAMPLES, dir)).map((name) => {
    const path = join(SAMPLES, dir, name);
    return { name: `${dir}/${name}`, path, content: readFileSync(path, 'utf8') };
  });
}

const CORPUS = [...sampleFiles('vulnerable'), ...sampleFiles('safe'), ...sampleFiles('context-window')];

describe('H7 — canonicalization never costs a finding (corpus)', () => {
  it('has actually loaded a corpus', () => {
    // Guard against the whole suite silently passing on an empty directory.
    expect(CORPUS.length).toBeGreaterThan(15);
  });

  for (const file of CORPUS) {
    it(`${file.name}: no finding is lost (superset)`, () => {
      // The soundness obligation, on the bytes as they sit on disk.
      const { on, off } = scanBoth(file.content, file.path);
      const onKeys = on.findings.map(key);
      for (const k of off.findings.map(key)) expect(onKeys).toContain(k);
    });

    it(`${file.name}: no finding is manufactured (equality)`, () => {
      // Asserted on the bytes as they sit on disk, CRLF included. This used to
      // require LF-normalizing first, to exclude a `runRegex` defect where a
      // `^\s*`-anchored match on CRLF reported the previous line and got
      // dropped by `skipCommentLines` — the canonicalizer then incidentally
      // rescued it, showing up here as a canonical-only finding. That defect is
      // fixed (see the CRLF parity block below), so the confound is gone and
      // the stronger claim holds directly.
      //
      // The sample corpus contains no evasions, so ANY canonical-only finding
      // here is a canonicalizer-manufactured false positive and fails the build.
      const { on, off } = scanBoth(file.content, file.path);
      expect(on.findings.map(key).sort()).toEqual(off.findings.map(key).sort());
    });

    it(`${file.name}: confidence and audit trail are unchanged`, () => {
      // Confidence is always evaluated against the ORIGINAL context, for both
      // passes. If a canonical context ever leaked into
      // `explainContextConfidence`, the docstring/block-comment signals would
      // go blind (their markers having been blanked) and every E6 number would
      // move. This pins that it does not.
      //
      // This is also the check to cite for "D2 does not move confidence" —
      // NOT the E6 harness, which calls `rule.match()` directly and never
      // constructs an Analyzer, so it cannot observe D2 at all.
      const { on, off } = scanBoth(file.content, file.path);
      const byKey = (fs: Finding[]) =>
        Object.fromEntries(fs.map((f) => [key(f), { c: f.confidence, a: f.confidenceAudit }]));
      expect(byKey(on.findings)).toEqual(byKey(off.findings));
    });
  }
});

describe('CRLF parity for `^\\s*` rules (was a silent false negative)', () => {
  // This block used to pin a DEFECT. It now pins its fix, and the flip is the
  // point: when the underlying bug was closed in `runRegex`, the old
  // "is silently lost on CRLF" assertion failed loudly instead of quietly
  // becoming a lie.
  //
  // What it was: `^` under /m treats a lone `\r` as a line terminator, while
  // `indexToPosition` counts lines by `\n` alone. On CRLF input the two
  // disagreed by one line, so a `^\s*`-anchored match reported the PREVIOUS
  // line as its start — and `runRegex({ skipCommentLines })` then deleted the
  // match whenever that previous line was a comment. `VG-FW-001` disappeared
  // from every CRLF settings file, including `samples/vulnerable/
  // django_settings.py`, a fixture explicitly labelled for that rule.
  //
  // The fix anchors a match at its first non-whitespace character, so position
  // and comment test both describe the payload line. Independent of D2: these
  // assertions hold with the canonicalizer OFF.
  const body = (eol: string) => ['import os', '', '# a comment', 'DEBUG = True', ''].join(eol);
  const off = { canonicalize: false };
  const run = (eol: string, opts?: { canonicalize: boolean }) =>
    scan({ targetType: 'snippet', mode: 'standard', content: body(eol), filePath: 'settings.py' }, opts).findings;

  it('fires on LF input', () => {
    expect(run('\n', off).map((f) => f.ruleId)).toContain('VG-FW-001');
  });

  it('fires on CRLF input too, with the canonicalizer off', () => {
    expect(run('\r\n', off).map((f) => f.ruleId)).toContain('VG-FW-001');
  });

  it('reports the same line number for LF and CRLF', () => {
    // The payload is on line 4 in both encodings. Before the fix, CRLF put it
    // on line 3 — which also meant a `disable-line` on line 4 could not
    // suppress it.
    const lf = run('\n', off).find((f) => f.ruleId === 'VG-FW-001');
    const crlf = run('\r\n', off).find((f) => f.ruleId === 'VG-FW-001');
    expect(lf?.startLine).toBe(4);
    expect(crlf?.startLine).toBe(4);
  });

  it('is unaffected by the canonicalizer either way', () => {
    for (const eol of ['\n', '\r\n']) {
      expect(run(eol).map((f) => f.ruleId)).toContain('VG-FW-001');
    }
  });
});

describe('H7 — the two rule families that forbid in-band comment removal', () => {
  // These are the reason `N(x)` is unioned with `x` instead of replacing it.
  // Both would be destroyed by feeding comment-stripped content to the rules.

  it('still detects a secret that lives inside a comment', () => {
    const src = '# api_key = "AKIAAAAAAAAAAAAAAAAA"\n';
    const { on, off } = scanBoth(src, 'config.py');
    expect(off.findings.map((f) => f.ruleId)).toContain('VG-SEC-001');
    expect(on.findings.map((f) => f.ruleId)).toContain('VG-SEC-001');
  });

  it('still fires rules for which the comment IS the signal', () => {
    // VG-AUTH-002 matches on the comment marker itself.
    const src = '// TODO: fix auth before launch\n';
    const { on, off } = scanBoth(src, 'app.js');
    expect(off.findings.map((f) => f.ruleId)).toContain('VG-AUTH-002');
    expect(on.findings.map((f) => f.ruleId)).toContain('VG-AUTH-002');
  });
});

describe('D2 — evasions the canonicalizer closes', () => {
  // Each case: the transform defeats the pre-D2 engine, and the canonicalizer
  // restores the detection. Both halves are asserted, so a test cannot pass by
  // the transform simply failing to evade in the first place.
  const closed: Array<{ what: string; file: string; plain: string; evaded: string }> = [
    {
      what: 'block comment splitting a call',
      file: 'a.js',
      plain: 'eval(userInput);',
      evaded: 'eval/*x*/(userInput);',
    },
    {
      what: 'constant-folded secret (javascript)',
      file: 'a.js',
      plain: 'const k = "AKIAAAAAAAAAAAAAAAAA";',
      evaded: 'const k = "AKIA" + "AAAAAAAAAAAAAAAA";',
    },
    {
      what: 'constant-folded secret (python)',
      file: 'a.py',
      plain: 'k = "AKIAAAAAAAAAAAAAAAAA"',
      evaded: 'k = "AKIA" + "AAAAAAAAAAAAAAAA"',
    },
    {
      what: 'adjacency-folded secret (python)',
      file: 'a.py',
      plain: 'k = "AKIAAAAAAAAAAAAAAAAA"',
      evaded: 'k = "AKIA" "AAAAAAAAAAAAAAAA"',
    },
    {
      what: 'constant-folded secret (php)',
      file: 'a.php',
      plain: '$k = "AKIAAAAAAAAAAAAAAAAA";',
      evaded: '$k = "AKIA" . "AAAAAAAAAAAAAAAA";',
    },
  ];

  for (const c of closed) {
    it(`closes: ${c.what}`, () => {
      const baseline = scan({ targetType: 'snippet', mode: 'standard', content: c.plain, filePath: c.file }).findings.map((f) => f.ruleId);
      expect(baseline.length).toBeGreaterThan(0);

      const evadedOff = scan({ targetType: 'snippet', mode: 'standard', content: c.evaded, filePath: c.file }, { canonicalize: false }).findings.map((f) => f.ruleId);
      const evadedOn = scan({ targetType: 'snippet', mode: 'standard', content: c.evaded, filePath: c.file }).findings.map((f) => f.ruleId);

      for (const ruleId of baseline) {
        expect(evadedOff).not.toContain(ruleId); // the transform really evades
        expect(evadedOn).toContain(ruleId); // and the canonicalizer restores it
      }
    });
  }
});

describe('D2 — residual evasion, pinned deliberately', () => {
  // `N` collapses a DECIDABLE sub-family of transforms. Folding `x + y` needs
  // runtime values; complete normalization of meaning is undecidable. These
  // still evade, and saying so plainly is the honest form of the claim.
  const residual: Array<{ what: string; file: string; evaded: string; ruleId: string }> = [
    {
      what: 'a variable operand (undecidable without runtime values)',
      file: 'a.js',
      evaded: 'const p = "AKIA"; const k = p + "AAAAAAAAAAAAAAAA";',
      ruleId: 'VG-SEC-001',
    },
    {
      what: 'concatenation split across physical lines',
      file: 'a.js',
      evaded: 'const k = "AKIA" +\n  "AAAAAAAAAAAAAAAA";',
      ruleId: 'VG-SEC-001',
    },
  ];

  for (const r of residual) {
    it(`still evades (known residual): ${r.what}`, () => {
      const found = scan({ targetType: 'snippet', mode: 'standard', content: r.evaded, filePath: r.file }).findings.map((f) => f.ruleId);
      expect(found).not.toContain(r.ruleId);
    });
  }
});

describe('D2 — integration invariants', () => {
  it('reports canonical-only findings at ORIGINAL positions', () => {
    const src = 'const k = "AKIA" + "AAAAAAAAAAAAAAAA";';
    const f = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.find((x) => x.ruleId === 'VG-SEC-001');
    expect(f).toBeDefined();
    expect(f!.startLine).toBe(1);
    // The column must point into the real source line, not into canonical space.
    expect(f!.startColumn).toBeGreaterThan(0);
    expect(f!.startColumn).toBeLessThanOrEqual(src.length);
  });

  it('shows the user their own source in the snippet, not the folded form', () => {
    const src = 'const k = "AKIA" + "AAAAAAAAAAAAAAAA";';
    const f = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.find((x) => x.ruleId === 'VG-SEC-001');
    // Masked (it is a secret), but structurally the original expression.
    expect(f!.snippet).toContain('+');
    expect(f!.snippet).not.toContain('"AKIAAAAAAAAAAAAAAAAA"');
  });

  it('suppresses a canonical-only finding via an ordinary line suppression', () => {
    // Suppressions are parsed from the ORIGINAL content and keyed by line
    // number. This works for canonical-only findings only because
    // canonicalization is line-preserving.
    const src = 'const k = "AKIA" + "AAAAAAAAAAAAAAAA"; // vibeguard:disable-line VG-SEC-001\n';
    const found = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.map((f) => f.ruleId);
    expect(found).not.toContain('VG-SEC-001');
  });

  it('does not report one secret twice when folding shifts the payload left', () => {
    // Regression. Folding rewrites `"-" + "AKIA…"` as `"-AKIA…"` left-aligned
    // in the span, so the canonical match starts at a different column than the
    // original one. Position-equality dedupe misses that and the same secret is
    // reported at both 1:18 and 1:13. Overlap dedupe catches it.
    const src = 'const k = "-" + "AKIAAAAAAAAAAAAAAAAA";';
    const found = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.filter(
      (f) => f.ruleId === 'VG-SEC-001',
    );
    expect(found).toHaveLength(1);
  });

  it('anchors a canonical-only finding to its payload so suppression works on CRLF', () => {
    // Regression. On CRLF the `^\s*` drift makes the canonical match start on
    // line 1; emitted raw, the finding lands on the wrong line and a
    // disable-line comment on the payload line cannot suppress it.
    const disableLine = ['import os', '', '# a comment', 'DEBUG = True  # vibeguard:disable-line VG-FW-001', ''].join('\r\n');
    expect(
      scan({ targetType: 'snippet', mode: 'standard', content: disableLine, filePath: 'settings.py' }).findings.map((f) => f.ruleId),
    ).not.toContain('VG-FW-001');

    const disableNext = ['import os', '', '# vibeguard:disable-next-line VG-FW-001', 'DEBUG = True', ''].join('\r\n');
    expect(
      scan({ targetType: 'snippet', mode: 'standard', content: disableNext, filePath: 'settings.py' }).findings.map((f) => f.ruleId),
    ).not.toContain('VG-FW-001');
  });

  it('does not emit duplicate findings when both passes agree', () => {
    const src = 'const k = "AKIAAAAAAAAAAAAAAAAA"; // x\n';
    const found = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'a.js' }).findings.map(key);
    expect(new Set(found).size).toBe(found.length);
  });

  it('does not double-report when blanking a comment lets `^\\s*` reach further back', () => {
    // Regression. `VG-FW-001` anchors with `^\s*` under the `m` flag, and `\s`
    // matches newlines. On the original text the comment line is non-blank and
    // stops the backward scan, so the match starts on the DEBUG line. Once the
    // comment is blanked the whole line is whitespace, so the canonical match
    // starts two lines earlier — the same finding at a different position.
    // Keying the merge on the payload anchor rather than the raw start is what
    // collapses the pair; without it this file reports DEBUG twice.
    const src = 'import os\n\n# DEBUG left on in a settings module.\nDEBUG = True\n';
    const found = scan({ targetType: 'snippet', mode: 'standard', content: src, filePath: 'settings.py' }).findings.filter(
      (f) => f.ruleId === 'VG-FW-001',
    );
    expect(found).toHaveLength(1);
    // …and the surviving one is the original-pass match, pointing at the real line.
    expect(found[0]!.startLine).toBe(4);
  });
});

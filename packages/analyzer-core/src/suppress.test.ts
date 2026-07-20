// vibeguard:disable-file VG-INJ-006
// Test fixtures contain intentional vulnerable code to exercise suppression.
import { describe, expect, it } from 'vitest';
import { parseSuppressions, isSuppressed, evaluateSuppression } from './suppress.js';
import { scan } from './analyzer.js';

function hasRule(entries: { ruleIds: Set<string> }[] | undefined, id: string): boolean {
  if (!entries) return false;
  return entries.some((e) => e.ruleIds.has(id));
}

describe('parseSuppressions', () => {
  it('returns an empty map when no pragmas are present', () => {
    const m = parseSuppressions('const x = 1;\nconst y = 2;\n');
    expect(m.fileWide.length).toBe(0);
    expect(m.perLine.size).toBe(0);
  });

  it('parses disable-line as the same line (1-based)', () => {
    const src = 'eval(x); // vibeguard:disable-line VG-INJ-004\n';
    const m = parseSuppressions(src);
    expect(hasRule(m.perLine.get(1), 'VG-INJ-004')).toBe(true);
  });

  it('parses disable-next-line as the following line', () => {
    const src = '// vibeguard:disable-next-line\neval(x);\n';
    const m = parseSuppressions(src);
    expect(hasRule(m.perLine.get(2), '*')).toBe(true);
  });

  it('parses disable-file with multiple rule IDs', () => {
    const src = '// vibeguard:disable-file VG-AUTH-003 VG-AUTH-004\n';
    const m = parseSuppressions(src);
    expect(hasRule(m.fileWide, 'VG-AUTH-003')).toBe(true);
    expect(hasRule(m.fileWide, 'VG-AUTH-004')).toBe(true);
    expect(hasRule(m.fileWide, '*')).toBe(false);
  });

  it('treats no-id pragma as wildcard', () => {
    const src = 'eval(x); // vibeguard:disable-line\n';
    const m = parseSuppressions(src);
    expect(hasRule(m.perLine.get(1), '*')).toBe(true);
  });
});

describe('isSuppressed', () => {
  // These four cover the *matching* logic, so they use `low` throughout: the
  // severity gate is inert there and the assertions stay about which entry
  // matches which rule, which is what they were written to pin down. The gate
  // itself has its own describe block below.
  it('matches per-line wildcard', () => {
    const m = parseSuppressions('eval(x); // vibeguard:disable-line\n');
    expect(isSuppressed(m, 'VG-INJ-004', 1, 'low')).toBe(true);
    expect(isSuppressed(m, 'VG-INJ-004', 2, 'low')).toBe(false);
  });

  it('matches per-line specific rule only', () => {
    const m = parseSuppressions('eval(x); // vibeguard:disable-line VG-INJ-004\n');
    expect(isSuppressed(m, 'VG-INJ-004', 1, 'low')).toBe(true);
    expect(isSuppressed(m, 'VG-AUTH-003', 1, 'low')).toBe(false);
  });

  it('matches file-wide rule', () => {
    const m = parseSuppressions('// vibeguard:disable-file VG-INJ-004\n');
    expect(isSuppressed(m, 'VG-INJ-004', 99, 'low')).toBe(true);
    expect(isSuppressed(m, 'VG-AUTH-003', 99, 'low')).toBe(false);
  });
});

describe('severity gate on wildcard suppressions (D5)', () => {
  const FILE_WIDE = '// vibeguard:disable-file\neval(x);\n';
  const PER_LINE = 'eval(x); // vibeguard:disable-line\n';
  const NEXT_LINE = '// vibeguard:disable-next-line\neval(x);\n';

  for (const severity of ['critical', 'high', 'medium'] as const) {
    it(`refuses a file-wide wildcard for ${severity}`, () => {
      const m = parseSuppressions(FILE_WIDE);
      const d = evaluateSuppression(m, 'VG-INJ-004', 2, severity);
      expect(d.suppressed).toBe(false);
      expect(d.overridden).toEqual({ channel: 'pragma', scope: 'file' });
    });

    it(`refuses a per-line wildcard for ${severity}`, () => {
      const m = parseSuppressions(PER_LINE);
      const d = evaluateSuppression(m, 'VG-INJ-004', 1, severity);
      expect(d.suppressed).toBe(false);
      expect(d.overridden).toEqual({ channel: 'pragma', scope: 'line' });
    });

    it(`refuses a disable-next-line wildcard for ${severity}`, () => {
      // Same bucket as disable-line once parsed, but asserted separately because
      // this is the form the editor quick-fix emits, so a regression that only
      // hit this spelling would be the one users met first.
      const m = parseSuppressions(NEXT_LINE);
      const d = evaluateSuppression(m, 'VG-INJ-004', 2, severity);
      expect(d.suppressed).toBe(false);
      expect(d.overridden?.scope).toBe('line');
    });
  }

  for (const severity of ['low', 'info'] as const) {
    it(`still honours a wildcard for ${severity}`, () => {
      expect(isSuppressed(parseSuppressions(FILE_WIDE), 'VG-INJ-004', 2, severity)).toBe(true);
      expect(isSuppressed(parseSuppressions(PER_LINE), 'VG-INJ-004', 1, severity)).toBe(true);
    });

    it(`records nothing when a ${severity} wildcard is honoured`, () => {
      const d = evaluateSuppression(parseSuppressions(FILE_WIDE), 'VG-INJ-004', 2, severity);
      expect(d.suppressed).toBe(true);
      expect(d.overridden).toBeUndefined();
    });
  }

  it('honours an explicit rule ID at critical — the escape hatch', () => {
    const m = parseSuppressions('// vibeguard:disable-file VG-INJ-004\neval(x);\n');
    const d = evaluateSuppression(m, 'VG-INJ-004', 2, 'critical');
    expect(d.suppressed).toBe(true);
    expect(d.overridden).toBeUndefined();
  });

  it('honours an explicit rule ID on a line at critical', () => {
    const m = parseSuppressions('eval(x); // vibeguard:disable-line VG-INJ-004\n');
    expect(isSuppressed(m, 'VG-INJ-004', 1, 'critical')).toBe(true);
  });

  it('lets an explicit entry win over a blanket one in the same file', () => {
    // The blanket entry is refused, the explicit one covers. The finding must be
    // suppressed and must NOT carry an override marker — the refusal is
    // uninteresting once something legitimately silenced the finding.
    const m = parseSuppressions('// vibeguard:disable-file\n// vibeguard:disable-file VG-INJ-004\neval(x);\n');
    const d = evaluateSuppression(m, 'VG-INJ-004', 3, 'critical');
    expect(d.suppressed).toBe(true);
    expect(d.overridden).toBeUndefined();
  });

  it('carries the reason text of the refused entry', () => {
    const m = parseSuppressions('// vibeguard:disable-file reason="b3-suppression-abuse"\neval(x);\n');
    const d = evaluateSuppression(m, 'VG-INJ-004', 2, 'critical');
    expect(d.overridden).toEqual({
      channel: 'pragma',
      scope: 'file',
      reason: 'b3-suppression-abuse',
    });
  });

  it('does not let an unexpired until= wildcard through for critical', () => {
    // until= only controls whether the entry exists at all. A live blanket entry
    // is still a blanket entry, so the b3 arm's
    // `disable-file until=2099-12-31 reason="..."` buys nothing at critical.
    const m = parseSuppressions('// vibeguard:disable-file until=2099-12-31 reason="b3-suppression-abuse"\neval(x);\n', {
      now: new Date('2026-01-01T00:00:00Z'),
    });
    expect(m.fileWide.length).toBe(1);
    expect(isSuppressed(m, 'VG-INJ-004', 2, 'critical')).toBe(false);
    expect(isSuppressed(m, 'VG-INJ-004', 2, 'low')).toBe(true);
  });
});

describe('temporary suppressions (until=)', () => {
  it('captures the expiresAt date', () => {
    const m = parseSuppressions(
      'eval(x); // vibeguard:disable-line VG-INJ-004 until=2099-12-31\n',
      { now: new Date('2026-01-01T00:00:00Z') },
    );
    const entry = m.perLine.get(1)?.[0];
    expect(entry?.expiresAt).toBeDefined();
    expect(entry?.expiresAt?.toISOString().startsWith('2099-12-31')).toBe(true);
  });

  it('still applies before the until date', () => {
    const m = parseSuppressions(
      'eval(x); // vibeguard:disable-line VG-INJ-004 until=2099-12-31\n',
      { now: new Date('2026-01-01T00:00:00Z') },
    );
    expect(isSuppressed(m, 'VG-INJ-004', 1, 'critical')).toBe(true);
  });

  it('drops an expired entry at parse time', () => {
    const m = parseSuppressions(
      'eval(x); // vibeguard:disable-line VG-INJ-004 until=2024-01-01\n',
      { now: new Date('2026-01-01T00:00:00Z') },
    );
    expect(m.perLine.size).toBe(0);
    expect(isSuppressed(m, 'VG-INJ-004', 1, 'low')).toBe(false);
  });

  it('drops an expired file-wide entry', () => {
    const m = parseSuppressions(
      '// vibeguard:disable-file VG-AUTH-003 until=2020-06-15\n',
      { now: new Date('2026-01-01T00:00:00Z') },
    );
    expect(m.fileWide.length).toBe(0);
  });

  it('records reason= text when present', () => {
    const m = parseSuppressions(
      'eval(x); // vibeguard:disable-line VG-INJ-004 reason="ticket #42 cleanup"\n',
    );
    expect(m.perLine.get(1)?.[0]?.reason).toBe('ticket #42 cleanup');
  });

  it('accepts a bare-word reason', () => {
    const m = parseSuppressions(
      'eval(x); // vibeguard:disable-line VG-INJ-004 reason=cleanup\n',
    );
    expect(m.perLine.get(1)?.[0]?.reason).toBe('cleanup');
  });
});

describe('Analyzer suppress integration', () => {
  it('drops a disable-line finding (specific rule)', () => {
    const code = 'const v = eval(input); // vibeguard:disable-line VG-INJ-004\n';
    const r = scan({ targetType: 'snippet', content: code, mode: 'fast', filePath: 'a.js' });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(false);
  });

  it('drops a disable-next-line finding', () => {
    const code = ['// vibeguard:disable-next-line VG-INJ-004', 'const v = eval(input);'].join('\n');
    const r = scan({ targetType: 'snippet', content: code, mode: 'fast', filePath: 'a.js' });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(false);
  });

  it('disable-file removes every finding for the listed rule', () => {
    const code = [
      '// vibeguard:disable-file VG-INJ-004',
      'eval(a);',
      'eval(b);',
    ].join('\n');
    const r = scan({ targetType: 'snippet', content: code, mode: 'fast', filePath: 'a.js' });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(false);
  });

  it('does not suppress a different rule on the same line', () => {
    const code = 'el.innerHTML = data; // vibeguard:disable-line VG-INJ-004\n';
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-006')).toBe(true);
  });

  // VG-INJ-004 (eval) is `critical`, so every blanket form below is refused.
  const WILDCARD_FIXTURES: Record<string, string> = {
    'disable-file': '// vibeguard:disable-file\nconst v = eval(input);\n',
    'disable-line': 'const v = eval(input); // vibeguard:disable-line\n',
    'disable-next-line': '// vibeguard:disable-next-line\nconst v = eval(input);\n',
    'disable-file with until= and reason=':
      '// vibeguard:disable-file until=2099-12-31 reason="b3-suppression-abuse"\nconst v = eval(input);\n',
  };

  for (const [label, code] of Object.entries(WILDCARD_FIXTURES)) {
    it(`reports a critical finding through a blanket ${label}`, () => {
      const r = scan({ targetType: 'snippet', content: code, mode: 'fast', filePath: 'a.js' });
      const f = r.findings.find((x) => x.ruleId === 'VG-INJ-004');
      expect(f).toBeDefined();
      expect(f?.suppressionOverridden?.channel).toBe('pragma');
    });
  }

  it('leaves suppressionOverridden absent on an untouched finding', () => {
    // Absence is the contract, so assert the key is not merely undefined.
    const r = scan({
      targetType: 'snippet',
      content: 'const v = eval(input);\n',
      mode: 'fast',
      filePath: 'a.js',
    });
    const f = r.findings.find((x) => x.ruleId === 'VG-INJ-004');
    expect(f).toBeDefined();
    expect('suppressionOverridden' in (f as object)).toBe(false);
  });

  // Mutation control. The three assertions above only mean something if the
  // blanket pragmas they carry *would* have worked before the gate existed —
  // otherwise the test proves the attack was never possible rather than that it
  // is now stopped. `legacyIsSuppressed` is the pre-D5 predicate verbatim
  // (suppress.ts before this change: wildcard-or-rule-ID, severity-blind), run
  // against the same parsed pragmas the analyzer saw. It must say "suppressed"
  // for exactly the fixtures the analyzer now reports.
  function legacyIsSuppressed(map: ReturnType<typeof parseSuppressions>, ruleId: string, line: number): boolean {
    const covers = (e: { ruleIds: Set<string> }) => e.ruleIds.has('*') || e.ruleIds.has(ruleId);
    return map.fileWide.some(covers) || (map.perLine.get(line) ?? []).some(covers);
  }

  for (const [label, code] of Object.entries(WILDCARD_FIXTURES)) {
    it(`the pre-gate predicate would have dropped the same finding (${label})`, () => {
      const r = scan({ targetType: 'snippet', content: code, mode: 'fast', filePath: 'a.js' });
      const f = r.findings.find((x) => x.ruleId === 'VG-INJ-004');
      expect(f).toBeDefined();
      const map = parseSuppressions(code);
      expect(legacyIsSuppressed(map, 'VG-INJ-004', f!.startLine!)).toBe(true);
    });
  }

  it('the pre-gate predicate agrees with the gate on low/info bands', () => {
    // The control cuts both ways: where the gate is inert, old and new must
    // still agree, or the change did more than it claims to.
    const code = '// vibeguard:disable-file\nconst v = eval(input);\n';
    const map = parseSuppressions(code);
    for (const severity of ['low', 'info'] as const) {
      expect(isSuppressed(map, 'VG-INJ-004', 2, severity)).toBe(legacyIsSuppressed(map, 'VG-INJ-004', 2));
    }
  });
});

/**
 * D8 — the pragma channel's suppression tally.
 *
 * These pin OBSERVABILITY, not a defence. Every finding asserted about below is
 * still suppressed, still absent from `findings`, and still absent from the
 * summary; the assertions are about a scan being able to say that it happened.
 * A test that expected a named suppression to stop working would be asserting
 * the opposite of the design (see `entryCovers`).
 */
describe('suppression tally (D8, pragma channel)', () => {
  it('records a named suppression of a critical finding', () => {
    // VG-INJ-004 (eval) is critical, and the pragma names it — so the escape
    // hatch applies at full strength and the finding is gone. What is new is
    // that the response says one was removed, by which channel, and how many.
    const code = 'const v = eval(input); // vibeguard:disable-line VG-INJ-004\n';
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(false);
    expect(r.summary.critical).toBe(0);
    expect(r.suppressions).toContainEqual({
      ruleId: 'VG-INJ-004',
      channel: 'pragma',
      scope: 'line',
      filePath: 'a.js',
      count: 1,
    });
  });

  it('records a file-scoped named suppression with its scope', () => {
    const code = '// vibeguard:disable-file VG-INJ-004\nconst v = eval(input);\n';
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(false);
    const rec = r.suppressions?.find((s) => s.ruleId === 'VG-INJ-004');
    expect(rec?.scope).toBe('file');
    expect(rec?.channel).toBe('pragma');
  });

  it('records a wildcard suppression in the advisory band', () => {
    // A blanket pragma still works below the security-judgement line (D5 leaves
    // low/info alone), and that legitimate, everyday suppression is recorded on
    // the same terms as any other. The tally is an account of what was removed,
    // not an accusation.
    // VG-CRYPTO-003 (plaintext http:// URL), severity low.
    const code = '// vibeguard:disable-file\nconst endpoint = "http://example.com/api";\n';
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    expect(r.findings.some((f) => f.ruleId === 'VG-CRYPTO-003')).toBe(false);
    expect(r.suppressions).toContainEqual({
      ruleId: 'VG-CRYPTO-003',
      channel: 'pragma',
      scope: 'file',
      filePath: 'a.js',
      count: 1,
    });
  });

  it('aggregates repeated suppressions of the same rule into one row', () => {
    const code =
      '// vibeguard:disable-file VG-INJ-004\nconst a = eval(x);\nconst b = eval(y);\n';
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    const rows = (r.suppressions ?? []).filter((s) => s.ruleId === 'VG-INJ-004');
    expect(rows.length).toBe(1);
    expect(rows[0]?.count).toBe(2);
  });

  it('omits the field entirely when nothing was suppressed', () => {
    // Absence is the contract, exactly as for `degradations`: a clean scan must
    // be byte-identical to what it produced before this channel existed.
    const r = scan({
      targetType: 'snippet',
      content: 'const v = eval(input);\n',
      mode: 'standard',
      filePath: 'a.js',
    });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(true);
    expect('suppressions' in (r as object)).toBe(false);
  });
});

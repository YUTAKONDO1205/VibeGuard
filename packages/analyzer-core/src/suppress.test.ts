// vibeguard:disable-file
// Test fixtures contain intentional vulnerable code to exercise suppression.
import { describe, expect, it } from 'vitest';
import { parseSuppressions, isSuppressed } from './suppress.js';
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
  it('matches per-line wildcard', () => {
    const m = parseSuppressions('eval(x); // vibeguard:disable-line\n');
    expect(isSuppressed(m, 'VG-INJ-004', 1)).toBe(true);
    expect(isSuppressed(m, 'VG-INJ-004', 2)).toBe(false);
  });

  it('matches per-line specific rule only', () => {
    const m = parseSuppressions('eval(x); // vibeguard:disable-line VG-INJ-004\n');
    expect(isSuppressed(m, 'VG-INJ-004', 1)).toBe(true);
    expect(isSuppressed(m, 'VG-AUTH-003', 1)).toBe(false);
  });

  it('matches file-wide rule', () => {
    const m = parseSuppressions('// vibeguard:disable-file VG-INJ-004\n');
    expect(isSuppressed(m, 'VG-INJ-004', 99)).toBe(true);
    expect(isSuppressed(m, 'VG-AUTH-003', 99)).toBe(false);
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
    expect(isSuppressed(m, 'VG-INJ-004', 1)).toBe(true);
  });

  it('drops an expired entry at parse time', () => {
    const m = parseSuppressions(
      'eval(x); // vibeguard:disable-line VG-INJ-004 until=2024-01-01\n',
      { now: new Date('2026-01-01T00:00:00Z') },
    );
    expect(m.perLine.size).toBe(0);
    expect(isSuppressed(m, 'VG-INJ-004', 1)).toBe(false);
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
});

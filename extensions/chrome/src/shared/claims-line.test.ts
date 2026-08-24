// vibeguard:disable-file VG-INJ-001 VG-INJ-006 reason="the SQL-concatenation and innerHTML strings are `snippet` payloads on synthetic findings, fed to a claim counter; they are the NON-claim control this suite needs and are never executed"
import { describe, expect, it } from 'vitest';
import {
  claimsFromFindings,
  summariseClaims,
  type ClaimSourceFinding,
} from '@vibeguard/findings-schema';
import { claimsLine } from './claims-line.js';

/** A claim-bearing finding, in the shape the panel actually hands over. */
function claimBearing(over: Partial<ClaimSourceFinding> = {}): ClaimSourceFinding {
  return {
    ruleId: 'VG-AUTH-009',
    filePath: 'src/admin.ts',
    startLine: 12,
    snippet: 'if (process.env.NODE_ENV !== "production") { requireOwner(session); }',
    evidence: ['requireOwner(session)'],
    ...over,
  };
}

describe('claimsLine — nothing to say', () => {
  it('is null for no findings at all', () => {
    expect(claimsLine([])).toBeNull();
  });

  it('is null when no finding declares a protection', () => {
    // A SQL-concatenation finding is the opposite of a claim that a protection
    // exists. Counting it would invent a protection to be worried about.
    expect(
      claimsLine([
        { ruleId: 'VG-INJ-001', snippet: 'db.query("SELECT * FROM u WHERE id = " + id)' },
        { ruleId: 'VG-XSS-001', snippet: 'el.innerHTML = userInput' },
      ]),
    ).toBeNull();
  });
});

describe('claimsLine — something to say', () => {
  it('reports a claim-bearing finding', () => {
    const line = claimsLine([claimBearing()]);
    expect(line).not.toBeNull();
    expect(line).toContain('1 declared protection');
  });

  it('counts only the claim-bearing findings among the rest', () => {
    const line = claimsLine([
      claimBearing(),
      { ruleId: 'VG-INJ-001', snippet: 'db.query("..." + id)' },
      claimBearing({ ruleId: 'VG-MEM-006', snippet: 'memset(secret, 0, len);' }),
    ]);
    expect(line).toContain('2 declared protection');
  });

  it('is summariseClaims().line verbatim, so this surface cannot drift', () => {
    // The point of the assertion is the identity, not the string: if a future
    // edit composes its own sentence here, this fails even though the panel
    // still renders something plausible.
    const findings = [claimBearing(), claimBearing({ ruleId: 'VG-AUTH-011' })];
    expect(claimsLine(findings)).toBe(summariseClaims(claimsFromFindings(findings)).line);
  });
});

describe('claimsLine — a browser can never settle a claim', () => {
  const findings = [claimBearing(), claimBearing({ ruleId: 'VG-AUTH-010' })];

  it('builds only NOT_OBSERVED claims', () => {
    const states = claimsFromFindings(findings).map((c) => c.state);
    expect(states).toEqual(['NOT_OBSERVED', 'NOT_OBSERVED']);
  });

  it('says unverified, and never that anything was found present', () => {
    const line = claimsLine(findings) ?? '';
    expect(line).toContain('unverified');
    // `summariseClaims` writes this only for a PRESENT claim, which no claim
    // built in a browser can be. If it ever appears here, something upstream
    // started settling claims on a surface that cannot observe an artefact.
    expect(line).not.toContain('verified present');
    expect(line).not.toContain('✓');
  });
});

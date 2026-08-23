import { describe, expect, it } from 'vitest';
import {
  CLAIM_BEARING_RULES,
  claimsFromAssistantProse,
  claimsFromFindings,
  identifierWitness,
  summariseClaims,
} from './claims.js';
import type { ProtectionClaim } from './index.js';

const PROBE = 'if (!session.isAdmin) throw new Error("forbidden");';

describe('CLAIM_BEARING_RULES', () => {
  it('holds only rules whose finding asserts that a protection EXISTS', () => {
    // A finding that SQL is being concatenated is not a claim that a protection
    // is present. Feeding one in would produce a "protection" whose
    // disappearance from the build is good news, reported as a failure.
    for (const id of Object.keys(CLAIM_BEARING_RULES)) {
      expect(id, `${id} is not an auth/memory protection rule`).toMatch(/^VG-(AUTH|MEM)-\d{3}$/);
    }
  });
});

describe('identifierWitness', () => {
  it('prefers a property name, because a minifier keeps those and renames the rest', () => {
    // `session` is renamed to `s`; `isAdmin` is not, because the minifier cannot
    // know who else indexes the object. Taking the longest identifier picks
    // `session` on a tie and yields a witness guaranteed to be absent from the
    // artefact — a claim that always reads LOST.
    expect(identifierWitness('if (…) { … session.isAdmin … }')).toBe('isAdmin');
    expect(identifierWitness('console.assert(session.hasPermission)')).toBe('hasPermission');
  });

  it('returns null rather than a keyword, so the claim stays honestly unchecked', () => {
    expect(identifierWitness("if (process.env.NODE_ENV !== 'production') { }")).toBeNull();
    expect(identifierWitness('if (x) {}')).toBeNull();
  });

  it('refuses host and language property names, which beat the domain name', () => {
    // Measured: `if (import.meta.env.DEV) { if (!session.isOwner) throw }` chose
    // `meta` over `isOwner`, because `.meta` is a property access and the rule
    // is property-first. `meta` is in every bundle that uses `import.meta`, so
    // the claim then resolved PRESENT on a token belonging to the module system
    // — the right verdict for the wrong reason, which is worse than a wrong one
    // because it looks like the mechanism working.
    expect(identifierWitness('if (import.meta.env.DEV) { … session.isOwner … }')).toBe('isOwner');
    expect(identifierWitness('err.message')).toBeNull();
    expect(identifierWitness('res.status')).toBeNull();
  });

  it('falls back to a called function name when there is no property access', () => {
    expect(identifierWitness('assert(is_admin(u))')).toBe('is_admin');
  });
});

describe('claimsFromFindings', () => {
  it('produces a claim only for claim-bearing rules', () => {
    const claims = claimsFromFindings([
      { ruleId: 'VG-AUTH-009', snippet: PROBE, filePath: 'a.js', startLine: 3 },
      { ruleId: 'VG-INJ-001', snippet: 'db.query("SELECT " + x)', filePath: 'a.js' },
    ]);
    expect(claims).toHaveLength(1);
    expect(claims[0]!.claimant).toBe('VG-AUTH-009');
  });

  it('births every claim NOT_OBSERVED, unconditionally', () => {
    // The rule the whole ledger exists for. This function has no access to an
    // artefact, so it has nothing that could settle anything — and a claim that
    // could settle itself would hand the user back the question they could not
    // answer.
    const claims = claimsFromFindings([
      { ruleId: 'VG-AUTH-009', snippet: PROBE },
      { ruleId: 'VG-AUTH-010', evidence: ['console.assert(s.hasPermission)'] },
      { ruleId: 'VG-AUTH-011', snippet: 'assert is_admin(user), "admin required"' },
    ]);
    expect(claims).toHaveLength(3);
    expect(claims.every((c) => c.state === 'NOT_OBSERVED')).toBe(true);
    expect(claims.every((c) => c.crossExaminedAt === undefined)).toBe(true);
    expect(claims.every((c) => c.claimantLayer === 'source')).toBe(true);
  });

  it('carries a probe as well as a witness, because they answer different questions', () => {
    const [claim] = claimsFromFindings([{ ruleId: 'VG-AUTH-009', snippet: PROBE }]);
    // The witness answers "is the defence still there".
    expect(claim!.witness).toBe('isAdmin');
    // The probe answers the prior question "which shipped file is this about",
    // and has to be long enough to identify one.
    expect(claim!.sourceProbe).toBe(PROBE);
    expect(claim!.sourceProbe!.length).toBeGreaterThanOrEqual(20);
  });

  it('still produces a claim when no witness can be extracted', () => {
    // Dropping it would be worse: the claimant has already told the user the
    // protection is there, so the honest output is a claim that can never leave
    // NOT_OBSERVED, not silence.
    const [claim] = claimsFromFindings([
      { ruleId: 'VG-AUTH-009', snippet: "if (process.env.NODE_ENV !== 'production') { }" },
    ]);
    expect(claim).toBeDefined();
    expect(claim!.witness).toBeUndefined();
    expect(claim!.state).toBe('NOT_OBSERVED');
  });
});

describe('claimsFromAssistantProse', () => {
  it('extracts a claim from prose that names an action and a security subject', () => {
    const claims = claimsFromAssistantProse(
      'I added an authorization check so only admins can delete accounts.\nI also renamed a variable.',
    );
    expect(claims.length).toBeGreaterThanOrEqual(1);
    expect(claims.every((c) => c.claimantLayer === 'assistant')).toBe(true);
    // The rename is not a protection claim.
    expect(claims.some((c) => /renamed/.test(c.subject))).toBe(false);
  });

  it('cannot produce anything but NOT_OBSERVED, however confident the prose is', () => {
    const claims = claimsFromAssistantProse(
      'I have fully secured this: authorization is enforced and all input is validated.',
    );
    expect(claims.length).toBeGreaterThan(0);
    expect(claims.every((c) => c.state === 'NOT_OBSERVED')).toBe(true);
    expect(claims.every((c) => c.crossExaminedAt === undefined)).toBe(true);
  });

  it('takes a probe from the caller, because prose does not identify a shipped file', () => {
    const [claim] = claimsFromAssistantProse('I added an authorization check on session.isAdmin.', {
      sourceProbe: PROBE,
      filePath: 'a.js',
    });
    expect(claim!.sourceProbe).toBe(PROBE);
    expect(claim!.filePath).toBe('a.js');
  });
});

describe('summariseClaims', () => {
  const claim = (state: ProtectionClaim['state']): ProtectionClaim => ({
    id: 'x',
    claimant: 'VG-AUTH-009',
    claimantLayer: 'source',
    subject: 's',
    state,
  });

  it('counts the three groups a reader actually distinguishes', () => {
    const s = summariseClaims([claim('LOST'), claim('NOT_OBSERVED'), claim('PRESENT'), claim('REINTRODUCED')]);
    expect(s).toMatchObject({ total: 4, gone: 2, unverified: 1, held: 1 });
    expect(s.line).toContain('2 not in the shipped bytes');
    expect(s.line).toContain('1 unverified');
  });

  it('is empty-stringed at zero, so a caller cannot print a line about nothing', () => {
    expect(summariseClaims([]).line).toBe('');
  });
});

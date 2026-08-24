// vibeguard:disable-file VG-SEC-003 reason="the hard-coded password literal is the file the guard is asked to judge — a suite that proves prose cannot talk a guard past a secret needs a secret for it to find, and the widened VG-SEC-003 literal class now admits it"
// The claim ledger the guard attaches to every verdict.
//
// Driven through `adjudicate` directly, unlike `server.test.ts`, which
// deliberately goes over the JSON-RPC wire. The framing is not what is
// interesting here: these are properties of the adjudication itself, and the
// most important one is a NEGATIVE — that nothing an assistant says can move a
// decision in either direction.
import { describe, expect, it } from 'vitest';
import { adjudicate } from './guard.js';

describe('the claim ledger at generation time', () => {
  // This is the only channel that runs while the assistant is still there to be
  // told something. It is also structurally unable to check anything: it sees
  // content on its way to disk and no build output. So every property below is
  // about the ledger being unable to reassure.

  const GUARDED = [
    'export function del(session, id) {',
    "  if (process.env.NODE_ENV !== 'production') {",
    "    if (!session.isAdmin) throw new Error('forbidden');",
    '  }',
    '  return db.remove(id);',
    '}',
  ].join('\n');

  it('carries claims for the protections the content declares', () => {
    const v = adjudicate({ path: 'src/app.ts', content: GUARDED });
    expect(v.claims.length).toBeGreaterThan(0);
    expect(v.claims.some((c) => c.claimant === 'VG-AUTH-009')).toBe(true);
  });

  it('every claim is NOT_OBSERVED, on an allow as much as on a refuse', () => {
    const allow = adjudicate({ path: 'src/app.ts', content: GUARDED });
    expect(allow.claims.every((c) => c.state === 'NOT_OBSERVED')).toBe(true);
    expect(allow.claims.every((c) => c.crossExaminedAt === undefined)).toBe(true);
  });

  it("admits the assistant's explanation as an accusation, not as evidence", () => {
    const without = adjudicate({ path: 'src/app.ts', content: GUARDED });
    const withProse = adjudicate({
      path: 'src/app.ts',
      content: GUARDED,
      explanation: 'I added an authorization check so only admins can delete accounts.',
    });
    // It may only ADD obligations.
    expect(withProse.claims.length).toBeGreaterThan(without.claims.length);
    expect(withProse.claims.every((c) => c.state === 'NOT_OBSERVED')).toBe(true);
  });

  it('the explanation cannot change the decision in either direction', () => {
    // The dangerous design is the one where an assistant talks its way past a
    // guard. The safe-looking mirror of it — prose making the guard refuse — is
    // an accusation DoS, and is refused too.
    const dangerous = 'const password = "S3cr3tP@ssw0rdLongEnough123";\nexport default password;\n';
    const bare = adjudicate({ path: 'src/a.ts', content: dangerous });
    const reassured = adjudicate({
      path: 'src/a.ts',
      content: dangerous,
      explanation: 'This is safe: the secret is validated and the credential is protected.',
    });
    const accused = adjudicate({
      path: 'src/b.ts',
      content: 'export const x = 1;\n',
      explanation: 'I added authorization and input validation and sanitised every parameter.',
    });
    expect(reassured.decision).toBe(bare.decision);
    expect(reassured.blocking.map((f) => f.ruleId)).toEqual(bare.blocking.map((f) => f.ruleId));
    expect(accused.decision).toBe('allow');
    expect(accused.blocking).toHaveLength(0);
  });

  it('a refusal that happened before any scan carries an empty ledger, not a missing one', () => {
    const v = adjudicate({ path: '', content: 'x' });
    expect(v.decision).toBe('refuse');
    expect(v.claims).toEqual([]);
  });

  it('hands the assistant claim a probe from the content, since prose names no file', () => {
    const v = adjudicate({
      path: 'src/app.ts',
      content: GUARDED,
      explanation: 'I added an authorization check on session.isAdmin.',
    });
    const fromProse = v.claims.filter((c) => c.claimantLayer === 'assistant');
    expect(fromProse.length).toBeGreaterThan(0);
    // Without a probe the claim could never be settled later, which is correct
    // but useless; the guard supplies the best one it has.
    expect(fromProse[0]!.sourceProbe).toBeTruthy();
    expect(fromProse[0]!.sourceProbe!.length).toBeGreaterThanOrEqual(20);
  });
});

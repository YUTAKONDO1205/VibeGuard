// What the analyser is allowed to do with `compileLossEvidence` is: copy it.
// These tests hold the three halves of that — that it copies, that it copies
// NOTHING when nothing was supplied, and that a malformed cell is refused out
// loud rather than repaired or dropped in silence.
//
// The fixture uses two deliberately dull rules (a plaintext URL and a logged
// secret name) rather than the `eval` snippet the neighbouring suites use.
// Both are already covered for test files by the repository's own
// `.vibeguardrc.json` path entry, so this file needs no file-scope suppression
// pragma of its own — and the census in `scripts/check-packaging-invariants.mjs`
// counts those pragmas against a fixed baseline, so adding one here would have
// meant editing that baseline to accommodate a test that never needed it.
import { describe, expect, it } from 'vitest';
import type { CompileLossEvidence, ScanRequest } from '@vibeguard/findings-schema';
import { scan } from './analyzer.js';

/** Plaintext URL — `VG-CRYPTO-003`. The rule this fixture's cell is keyed by. */
const SUBJECT_RULE = 'VG-CRYPTO-003';
/** Logged secret name — `VG-QUAL-003`. A second rule, to watch for spill. */
const OTHER_RULE = 'VG-QUAL-003';

const CONTENT = [
  'const endpoint = "http://api.example.org/v1";',
  'console.log("password", password);',
].join('\n');

const R2_CLANG_O2: CompileLossEvidence = {
  num: 113,
  den: 133,
  corpusId: 'r2',
  vendor: 'clang-18',
  optLevel: '-O2',
};

const request = (extra: Partial<ScanRequest> = {}): ScanRequest => ({
  targetType: 'snippet',
  content: CONTENT,
  mode: 'standard',
  filePath: 'src/client.js',
  ...extra,
});

const supply = (value: unknown, ruleId = SUBJECT_RULE): ScanRequest['compileLossEvidence'] =>
  ({ [ruleId]: value }) as ScanRequest['compileLossEvidence'];

describe('the fixture reaches both rules', () => {
  it('produces a finding for each, so the tests below are not vacuous', () => {
    const ids = scan(request()).findings.map((f) => f.ruleId);
    expect(ids).toContain(SUBJECT_RULE);
    expect(ids).toContain(OTHER_RULE);
  });
});

describe('compileLossEvidence is absent unless a consumer supplied it', () => {
  it('leaves the KEY off every finding when nothing was supplied', () => {
    const r = scan(request());
    expect(r.findings.length).toBeGreaterThan(0);
    for (const f of r.findings) {
      // `in`, not `=== undefined`: the contract is the key's absence, and the
      // two are the same thing in JSON and different things to a consumer
      // enumerating the object. This is the assertion that would catch
      // `compileLossEvidence: undefined` being assigned unconditionally.
      expect('compileLossEvidence' in f).toBe(false);
    }
  });

  it('does not name the field anywhere in the serialised response', () => {
    expect(JSON.stringify(scan(request()))).not.toContain('compileLossEvidence');
  });

  it('reports no rejections when nothing was supplied', () => {
    expect('compileLossEvidenceRejections' in scan(request())).toBe(false);
  });

  it('treats an empty map as "supplied nothing"', () => {
    const r = scan(request({ compileLossEvidence: {} }));
    expect(JSON.stringify(r)).not.toContain('compileLossEvidence');
  });

  it('does not spill a cell onto a rule it was not keyed by', () => {
    const r = scan(request({ compileLossEvidence: supply(R2_CLANG_O2) }));
    const other = r.findings.filter((f) => f.ruleId !== SUBJECT_RULE);
    expect(other.length).toBeGreaterThan(0);
    for (const f of other) expect('compileLossEvidence' in f).toBe(false);
  });
});

describe('compileLossEvidence is copied, not derived', () => {
  it('lands on every finding of the rule it is keyed by, unchanged', () => {
    const r = scan(request({ compileLossEvidence: supply(R2_CLANG_O2) }));
    const hit = r.findings.filter((f) => f.ruleId === SUBJECT_RULE);
    expect(hit.length).toBeGreaterThan(0);
    for (const f of hit) expect(f.compileLossEvidence).toEqual(R2_CLANG_O2);
  });

  it('does not touch confidence, which is the axis it is not allowed to be', () => {
    const shape = (rs: ReturnType<typeof scan>) =>
      rs.findings.map((f) => `${f.ruleId}:${f.severity}:${f.confidence}`);
    expect(shape(scan(request({ compileLossEvidence: supply(R2_CLANG_O2) })))).toEqual(
      shape(scan(request())),
    );
  });

  it('changes no verdict: the same findings, in the same order, either way', () => {
    // The claim that justifies leaving ENGINE_VERSION where it is. If this
    // fails, the constant has to move.
    const strip = (rs: ReturnType<typeof scan>) =>
      JSON.stringify({
        summary: rs.summary,
        findings: rs.findings.map(({ findingId, compileLossEvidence, ...rest }) => rest),
      });
    expect(strip(scan(request({ compileLossEvidence: supply(R2_CLANG_O2) })))).toBe(
      strip(scan(request())),
    );
  });
});

describe('a malformed cell is refused out loud', () => {
  const bad: Array<[string, unknown]> = [
    ['a non-integer numerator', { ...R2_CLANG_O2, num: 113.5 }],
    ['a numerator over its denominator', { ...R2_CLANG_O2, num: 200 }],
    ['a zero denominator', { ...R2_CLANG_O2, num: 0, den: 0 }],
    ['an empty vendor', { ...R2_CLANG_O2, vendor: '' }],
    ['a missing optLevel', { num: 1, den: 2, corpusId: 'r2', vendor: 'clang-18' }],
    ['not an object at all', 'clang-18 -O2'],
  ];

  for (const [label, value] of bad) {
    it(`rejects ${label}, keeps the finding, and says so`, () => {
      const r = scan(request({ compileLossEvidence: supply(value) }));
      const hit = r.findings.filter((f) => f.ruleId === SUBJECT_RULE);
      // The finding survives: a bad annotation must not remove a finding.
      expect(hit.length).toBeGreaterThan(0);
      for (const f of hit) expect('compileLossEvidence' in f).toBe(false);
      // And it is not silent.
      expect(r.compileLossEvidenceRejections).toHaveLength(1);
      expect(r.compileLossEvidenceRejections![0]!.ruleId).toBe(SUBJECT_RULE);
      expect(r.compileLossEvidenceRejections![0]!.detail).toContain(SUBJECT_RULE);
      expect(r.compileLossEvidenceRejections![0]!.detail).toContain('dropped');
    });
  }

  it('keeps the good cells of a partly-bad map', () => {
    const r = scan(
      request({
        compileLossEvidence: {
          [SUBJECT_RULE]: R2_CLANG_O2,
          'VG-NOT-A-RULE': { ...R2_CLANG_O2, den: 0 },
        } as ScanRequest['compileLossEvidence'],
      }),
    );
    expect(r.findings.find((f) => f.ruleId === SUBJECT_RULE)?.compileLossEvidence).toEqual(
      R2_CLANG_O2,
    );
    expect(r.compileLossEvidenceRejections?.map((x) => x.ruleId)).toEqual(['VG-NOT-A-RULE']);
  });

  it('does not affect the summary', () => {
    const plain = scan(request());
    const r = scan(request({ compileLossEvidence: supply({ ...R2_CLANG_O2, den: 0 }) }));
    expect(r.summary).toEqual(plain.summary);
  });
});

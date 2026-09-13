// What the analyser is allowed to do with `compileLossEvidence` is: copy it.
// These tests hold the three halves of that — that it copies, that it copies
// NOTHING when nothing was supplied, and that a malformed cell is refused out
// loud rather than repaired or dropped in silence.
//
// The main fixture uses two deliberately dull rules (a plaintext URL and a logged
// secret name) rather than the `eval` snippet the neighbouring suites use. Both
// are already covered for test files by the repository's own `.vibeguardrc.json`
// path entry, so this file needs no file-scope suppression pragma of its own —
// and the census in `scripts/check-packaging-invariants.mjs` counts those pragmas
// against a fixed baseline, so adding one here would have meant editing that
// baseline to accommodate a test that never needed it.
//
// The last two cases do use the `eval` snippet (`EVAL_SNIPPET`, below), so "rather
// than" above is about the main fixture and not about the file. It arrived with
// those two cases and is kept because they are about which RULE IDS the engine
// loaded, and `VG-INJ-004` is the injection rule that snippet triggers; the same
// `.vibeguardrc.json` path entry covers it, and the pragma census is unaffected —
// `check-packaging-invariants.mjs` passes with it here.
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

// These two went in built by hand rather than through `request()` above. Four
// things were wrong with them and only TWO were type errors, which is worth
// stating exactly because the other two are the kind a reader would assume had
// been caught:
//
//   caught by `tsc -p`  — no `targetType` and no `mode` (TS2345, both cases), and
//                         `rejections[0].detail` on a possibly-empty array
//                         (TS2532)
//   NOT caught by anything — a `language` key `ScanRequest` does not declare, and
//                         an `await` on a synchronous `scan`. Measured: a probe
//                         file with both, as a direct object literal, typechecks
//                         clean. So those two were plain sloppiness that nothing
//                         in this repository would have objected to.
//
// Vitest transpiles without typechecking, so all four ran green here while
// `npm run build` — which is CI's build-test job — failed on the first two. They
// are routed through the same helper as everything else above now, which removes
// all four.
//
// THE CLASS IS NOT CLOSED, and saying so here is the point of this paragraph.
// This file is inside a workspace, so `npm run build` typechecks it. `scripts/`
// is not: no tsconfig in this repository includes `scripts/**/*.ts`, and
// `npm run build` only builds workspaces, so the five `scripts/*.test.ts` files
// CI runs are typechecked by nothing at all. Measured 2026-09-13 with a throwaway
// config extending `tsconfig.base.json`: **17 errors**, one of them the same shape
// as the two above — `scripts/sec-selftest.test.ts:448`, TS2739, an object literal
// missing two required properties. The rest are mostly `noUncheckedIndexedAccess`
// on pre-existing code plus three `.mjs` imports with no declarations. Wiring a
// typecheck over `scripts/` is therefore a real change with 17 pre-existing
// failures behind it, not a one-line addition, and it is not attempted here.
const EVAL_SNIPPET = 'const p = "password123";\neval(p);\n';

describe('a well-formed cell for a rule this engine did not load', () => {
  it('is reported rather than dropped in silence', () => {
    const res = scan(
      request({
        content: EVAL_SNIPPET,
        compileLossEvidence: supply(
          { num: 1, den: 2, corpusId: 'r2', vendor: 'clang-18', optLevel: '-O2' },
          'VG-NOT-A-RULE',
        ),
      }),
    );
    const rejections = res.compileLossEvidenceRejections ?? [];
    expect(rejections.map((r) => r.ruleId)).toEqual(['VG-NOT-A-RULE']);
    expect(rejections[0]?.detail).toMatch(/not a rule this engine loaded/);
    // And the findings are otherwise untouched: this is a report, not a refusal.
    expect(res.findings.length).toBeGreaterThan(0);
    for (const f of res.findings) expect('compileLossEvidence' in f).toBe(false);
  });

  it('says nothing when the id IS a loaded rule', () => {
    const res = scan(
      request({
        content: EVAL_SNIPPET,
        compileLossEvidence: supply(R2_CLANG_O2, 'VG-INJ-004'),
      }),
    );
    expect(res.compileLossEvidenceRejections).toBeUndefined();
  });
});

// vibeguard:disable-file VG-INJ-004
// Fixtures embed vulnerable-looking literals to make the rules fire.
import { describe, expect, it } from 'vitest';
import {
  runRegex,
  REGEX_INPUT_CAP,
  REGEX_MATCH_LIMIT,
  type RuleContext,
  type RuleDefinition,
} from '@vibeguard/rules';
import { isSecurityJudgementSeverity, type Finding, type Severity } from '@vibeguard/findings-schema';
import { Analyzer, scan } from './analyzer.js';
import { canonicalize } from './canonicalizer.js';

/**
 * A1-LIMIT — the per-file match cap stops hiding security findings in silence.
 *
 * The cap itself is not on trial here and is not changed by any of this. It is
 * the bound that keeps A1's availability attack bounded, and every test below
 * asserts that it STILL applies: the finding count stays at REGEX_MATCH_LIMIT.
 * What changed is only whether a reader is told, and that is what these tests
 * pin down.
 *
 * The measurement that motivated the change is reproduced verbatim in the first
 * test. Before A1-LIMIT, a file with 1500 `eval` calls produced exactly 1000
 * critical findings and an EMPTY `degradations` array — a truncated scan whose
 * response was indistinguishable from a complete one. `legacyDegradations`
 * below re-implements that old filter so the silent drop is demonstrated to
 * have been real rather than merely asserted to have been.
 */

/** How many matches of one rule it takes to push past the cap. */
const OVER_LIMIT = REGEX_MATCH_LIMIT + 500;

/**
 * The pre-A1-LIMIT filter, transcribed from the line it replaced:
 *
 *   const reportable = events.filter((e) => e.kind !== 'limitReached');
 *
 * Applied to a response's degradations, it reproduces the old channel exactly:
 * every match-limit report removed, regardless of severity. Kept in the test
 * rather than in the source so the mutation control travels with the assertion
 * it justifies — if someone restores the old behaviour, the tests that compare
 * against this stop distinguishing anything and fail.
 */
function legacyDegradations(degradations: { kind: string }[]): { kind: string }[] {
  return degradations.filter((d) => d.kind !== 'match-limit');
}

/** A rule of any severity that matches one token per line, so the cap is easy to cross. */
function tokenRule(ruleId: string, severity: Severity): RuleDefinition {
  return {
    ruleId,
    name: `token ${severity}`,
    description: 'test rule',
    languages: ['*'],
    category: 'quality',
    severity,
    defaultConfidence: 'high',
    match: (ctx: RuleContext) => runRegex(ctx.content, /VGTOKEN/g),
  };
}

function tokenSource(count: number): string {
  return Array.from({ length: count }, (_, i) => `const a${i} = VGTOKEN;`).join('\n');
}

describe('A1-LIMIT — security-severity truncation is reported', () => {
  it('reproduces the measured silent drop: 1500 evals, 1000 findings, nothing said (old behaviour)', () => {
    const content = Array.from({ length: 1500 }, (_, i) => `eval(userInput${i});`).join('\n');
    // The input cap must NOT be what fires here, or this would be testing D3's
    // truncation instead of the match limit.
    expect(content.length).toBeLessThan(REGEX_INPUT_CAP);

    const r = scan({ targetType: 'file', content, filePath: 'many.js', mode: 'standard' });

    // The cap still applies — A1-LIMIT does not lift it.
    expect(r.findings.length).toBe(REGEX_MATCH_LIMIT);
    expect(r.findings.every((f) => f.severity === 'critical')).toBe(true);
    // 500 critical matches existed in the file and are absent from the report.
    expect(r.findings.length).toBeLessThan(1500);

    // MUTATION CONTROL: under the old filter this response carried no signal at
    // all that anything had been cut. That is the defect, shown rather than
    // claimed.
    expect(legacyDegradations(r.degradations ?? [])).toEqual([]);
    // Under A1-LIMIT it does.
    expect((r.degradations ?? []).some((d) => d.kind === 'match-limit')).toBe(true);
  });

  it('emits exactly one aggregated event per (file, rule), not one per lost match', () => {
    const content = Array.from({ length: 1500 }, (_, i) => `eval(userInput${i});`).join('\n');
    const r = scan({ targetType: 'file', content, filePath: 'many.js', mode: 'standard' });

    const limits = (r.degradations ?? []).filter((d) => d.kind === 'match-limit');
    // One. Not 500 (per lost match), and not one per pattern in the rule.
    //
    // This fixture does NOT exercise the two-pass case: canonicalization is a
    // no-op on it (see the dedup test at the bottom of this file, which asserts
    // that), so `canonicalCtx` is never built and `recordMatchLimit` is reached
    // exactly once. An earlier version of this comment claimed "not 2 (original
    // + canonical pass)" here, which was not something this input could show.
    expect(limits.length).toBe(1);
    expect(limits[0]!.ruleId).toBe('VG-INJ-004');
    expect(limits[0]!.filePath).toBe('many.js');
    // `matchCount` is what WAS reported. The excess is unknowable — matching
    // stopped at the cap — so nothing may claim to know it.
    expect(limits[0]!.matchCount).toBe(REGEX_MATCH_LIMIT);
    expect(limits[0]!.detail).toContain('PARTIAL');
    expect(limits[0]!.detail).not.toContain('500');
    // A truncation is not a crash, and must not be rendered as one.
    expect(r.ruleErrors ?? []).toEqual([]);
  });

  it.each([
    ['critical', true],
    ['high', true],
    ['medium', true],
    ['low', false],
    ['info', false],
  ] as const)('severity %s → reported: %s', (severity, expected) => {
    // The gate must follow the shared predicate, not a list copied beside it.
    expect(isSecurityJudgementSeverity(severity)).toBe(expected);

    const analyzer = new Analyzer({ rules: [tokenRule('VG-TEST-001', severity)] });
    const r = analyzer.scan({
      targetType: 'file',
      content: tokenSource(OVER_LIMIT),
      filePath: 'tokens.js',
      mode: 'standard',
    });

    // Identical on both sides of the gate: the cap fired, findings were lost.
    expect(r.findings.length).toBe(REGEX_MATCH_LIMIT);

    const limits = (r.degradations ?? []).filter((d) => d.kind === 'match-limit');
    expect(limits.length).toBe(expected ? 1 : 0);
  });

  it('says nothing when the cap did not fire', () => {
    const analyzer = new Analyzer({ rules: [tokenRule('VG-TEST-001', 'critical')] });
    const r = analyzer.scan({
      targetType: 'file',
      content: tokenSource(REGEX_MATCH_LIMIT - 1),
      filePath: 'tokens.js',
      mode: 'standard',
    });
    expect(r.findings.length).toBe(REGEX_MATCH_LIMIT - 1);
    expect((r.degradations ?? []).filter((d) => d.kind === 'match-limit')).toEqual([]);
  });

  it('keeps one entry per rule when several rules are all truncated in one file', () => {
    // Aggregation is per (file, rule), so N truncated rules give N entries —
    // bounded by the rule count, never by the match count.
    const analyzer = new Analyzer({
      rules: [tokenRule('VG-TEST-001', 'critical'), tokenRule('VG-TEST-002', 'high')],
    });
    const r = analyzer.scan({
      targetType: 'file',
      content: tokenSource(OVER_LIMIT),
      filePath: 'tokens.js',
      mode: 'standard',
    });
    const limits = (r.degradations ?? []).filter((d) => d.kind === 'match-limit');
    expect(limits.map((d) => d.ruleId).sort()).toEqual(['VG-TEST-001', 'VG-TEST-002']);
  });

  it('does not change the finding set, only the degradation channel', () => {
    // A1-LIMIT is a reporting change. If it moved a single finding it would be
    // altering detection under the cover of observability.
    const content = Array.from({ length: 1500 }, (_, i) => `eval(userInput${i});`).join('\n');
    const r = scan({ targetType: 'file', content, filePath: 'many.js', mode: 'standard' });
    const key = (f: Finding) => `${f.ruleId}:${f.startLine}:${f.severity}`;
    // Same shape as the pre-change engine produced: 1000 VG-INJ-004 criticals
    // on the first 1000 lines.
    expect(r.findings.map(key)).toEqual(
      Array.from({ length: REGEX_MATCH_LIMIT }, (_, i) => `VG-INJ-004:${i + 1}:critical`),
    );
    expect(r.summary.total).toBe(REGEX_MATCH_LIMIT);
  });

  // The dedup inside `recordMatchLimit` only has anything to do when the rule
  // loop runs twice, and that happens only when D2's canonicalization actually
  // rewrote the input — `Analyzer.scan` builds `canonicalCtx` solely when
  // `canonicalize().changed` is true. Every other fixture in this file is
  // canonicalization-invariant, so on all of them `recordMatchLimit` is called
  // once and the dedup branch is dead. Nothing above can distinguish a working
  // dedup from an absent one; this does.
  it('emits one event, not two, when the canonical pass also trips the cap', () => {
    // A line comment is enough to make canonicalization non-trivial (it blanks
    // comment bodies), which is the whole point of the prefix — the 1500 evals
    // below are byte-for-byte the fixture used above.
    const evals = Array.from({ length: 1500 }, (_, i) => `eval(userInput${i});`).join('\n');
    const content = `// forces the canonical pass to run\n${evals}`;

    // The precondition is asserted, not assumed: if canonicalization ever stops
    // rewriting this input, the second pass disappears and this test would go
    // back to proving nothing. Better that it fails loudly here.
    expect(canonicalize(content, 'javascript').changed).toBe(true);
    expect(content.length).toBeLessThan(REGEX_INPUT_CAP);

    const r = scan({ targetType: 'file', content, filePath: 'many.js', mode: 'standard' });

    // Both passes see the same 1500 matches and both hit the cap, so both reach
    // `recordMatchLimit` for (many.js, VG-INJ-004). Exactly one entry may
    // survive: the degradation channel reports that a bound fired, and reporting
    // it twice would imply two distinct truncations to anyone counting.
    const limits = (r.degradations ?? []).filter((d) => d.kind === 'match-limit');
    expect(limits.length).toBe(1);
    expect(limits[0]!.ruleId).toBe('VG-INJ-004');
    expect(limits[0]!.filePath).toBe('many.js');
    expect(limits[0]!.matchCount).toBe(REGEX_MATCH_LIMIT);

    // The cap still bounds the union of both passes, not each pass separately.
    expect(r.findings.length).toBe(REGEX_MATCH_LIMIT);
  });
});

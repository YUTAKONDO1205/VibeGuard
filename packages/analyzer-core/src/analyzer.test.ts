// vibeguard:disable-file VG-AUTH-002 VG-AUTH-004 VG-INJ-001 VG-INJ-004 VG-INJ-006 VG-INJ-007 VG-QUAL-001 VG-SEC-001 VG-SEC-003
// Test fixtures contain intentional vulnerable code to exercise the rules.
import { describe, expect, it } from 'vitest';
import type { Confidence, ScanRequest, Severity } from '@vibeguard/findings-schema';
import type { RuleDefinition } from '@vibeguard/rules';
import { Analyzer, scan } from './analyzer.js';

describe('Analyzer', () => {
  it('returns empty result for empty content', () => {
    const r = scan({ targetType: 'snippet', content: '', mode: 'standard' });
    expect(r.findings).toEqual([]);
    expect(r.summary.total).toBe(0);
  });

  it('detects an inline eval', () => {
    const r = scan({
      targetType: 'snippet',
      content: 'const v = eval("1+1");',
      mode: 'fast',
      filePath: 'inline.js',
    });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(true);
  });

  // Regression: an ES2022 private class field starts with `#`, which the
  // comment-line predicate used to read as a comment regardless of language.
  // runRegex({ skipCommentLines }) drops such matches inside rule.match(),
  // upstream of the confidence chokepoint — so the finding vanished entirely
  // rather than merely being down-ranked, and the severity gate never ran.
  it('detects findings on ES2022 private class field lines', () => {
    const cases: Array<[string, string]> = [
      ['class C { #q = (s) => eval(s); }', 'VG-INJ-004'],
      ['class C { #x = "SELECT * FROM users WHERE id = " + id; }', 'VG-INJ-001'],
      ['class C { #a = { rejectUnauthorized: false }; }', 'VG-AUTH-004'],
    ];
    for (const [content, ruleId] of cases) {
      const r = scan({ targetType: 'snippet', content, mode: 'standard', filePath: 'src/a.js' });
      expect(r.findings.map((f) => f.ruleId)).toContain(ruleId);
    }
  });

  it('still skips a Python # comment', () => {
    const r = scan({
      targetType: 'snippet',
      content: '# eval(user_input)',
      mode: 'standard',
      filePath: 'src/a.py',
    });
    expect(r.findings.map((f) => f.ruleId)).not.toContain('VG-INJ-004');
  });

  it('detects multiple categories in one input', () => {
    const code = `
const AWS = "AKIAIOSFODNN7EXAMPLE";
function go() { eval(input); el.innerHTML = data; }
`;
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    const ruleIds = new Set(r.findings.map((f) => f.ruleId));
    expect(ruleIds.has('VG-INJ-004')).toBe(true);
    expect(ruleIds.has('VG-INJ-006')).toBe(true);
    expect(ruleIds.has('VG-SEC-001')).toBe(true);
  });

  it('orders findings by severity', () => {
    const code = `
// medium first in source, critical second
const slowKey = "abcdefghijklmnopqrstuvwxyz";
const apiKey = "AKIAIOSFODNN7EXAMPLE";
`;
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    if (r.findings.length >= 2) {
      const first = r.findings[0]!;
      const last = r.findings[r.findings.length - 1]!;
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      expect(order.indexOf(first.severity)).toBeLessThanOrEqual(order.indexOf(last.severity));
    }
  });

  it('omits remediation when requested', () => {
    const r = scan({
      targetType: 'snippet',
      content: 'const v = eval(x);',
      mode: 'standard',
      filePath: 'a.js',
      includeRemediation: false,
    });
    for (const f of r.findings) {
      expect(f.remediation).toBeUndefined();
    }
  });

  it('masks the secret category snippet', () => {
    const code = 'const k = "AKIAIOSFODNN7EXAMPLE";';
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    const aws = r.findings.find((f) => f.ruleId === 'VG-SEC-001');
    expect(aws).toBeDefined();
    if (aws?.snippet) {
      expect(aws.snippet).not.toContain('AKIAIOSFODNN7EXAMPLE');
    }
  });

  it('does not crash on unknown language', () => {
    const r = scan({
      targetType: 'snippet',
      content: '<some xml>',
      mode: 'fast',
      language: 'xml',
    });
    expect(r.findings).toBeDefined();
  });

  it('finding remediation has variables interpolated', () => {
    const r = scan({
      targetType: 'snippet',
      content: 'container.innerHTML = data;',
      mode: 'standard',
      filePath: 'a.js',
    });
    const html = r.findings.find((f) => f.ruleId === 'VG-INJ-006');
    expect(html?.remediation?.exampleFix).toBe('container.textContent = userInput;');
  });

  it('fast mode runs only critical/high rules', () => {
    const code = [
      'fs.readFile("/tmp/" + userInput);',
      'try { dangerous(); } catch (e) {}',
    ].join('\n');
    const fast = scan({ targetType: 'snippet', content: code, mode: 'fast', filePath: 'a.js' });
    const std = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    expect(std.findings.length).toBeGreaterThan(fast.findings.length);
    for (const f of fast.findings) {
      expect(['critical', 'high']).toContain(f.severity);
    }
  });

  it('deep mode behaves like standard for now', () => {
    const code = 'fs.readFile("/tmp/" + userInput);';
    const std = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    const deep = scan({ targetType: 'snippet', content: code, mode: 'deep', filePath: 'a.js' });
    expect(deep.findings.length).toBe(std.findings.length);
  });

  it('Analyzer instance reuses configuration', () => {
    const a = new Analyzer();
    const r1 = a.scan({ targetType: 'snippet', content: 'eval(x)', mode: 'fast', filePath: 'a.js' });
    const r2 = a.scan({ targetType: 'snippet', content: 'eval(y)', mode: 'fast', filePath: 'b.js' });
    expect(r1.findings.length).toBeGreaterThan(0);
    expect(r2.findings.length).toBeGreaterThan(0);
  });

  // A rule that throws is skipped so it cannot crash the scan — but skipping it
  // silently drops its findings, which is an undeclared way to suppress them. The
  // crash must instead surface in `ruleErrors` (observable on every channel,
  // including the browser path that discards stderr).
  it('records a throwing rule in ruleErrors and keeps other rules’ findings', () => {
    const boom: RuleDefinition = {
      ruleId: 'VG-TEST-BOOM',
      name: 'boom',
      description: 'throws on match',
      languages: ['*'],
      category: 'quality',
      severity: 'high',
      defaultConfidence: 'high',
      match: () => {
        throw new Error('kaboom');
      },
    };
    const ok: RuleDefinition = {
      ruleId: 'VG-TEST-OK',
      name: 'ok',
      description: 'always matches',
      languages: ['*'],
      category: 'quality',
      severity: 'high',
      defaultConfidence: 'high',
      match: () => [{ startLine: 1, endLine: 1, startColumn: 1, endColumn: 1, evidence: 'x' }],
    };
    // The injected rules are honoured whether or not the language is known;
    // the regression test below pins the case where it is.
    const req: ScanRequest = { targetType: 'snippet', content: 'anything', mode: 'standard' };
    const r = scan(req, { rules: [boom, ok] });
    // The scan did not throw, and the healthy rule still reported.
    expect(r.findings.map((f) => f.ruleId)).toContain('VG-TEST-OK');
    // The crash is observable, not silently swallowed.
    expect(r.ruleErrors).toEqual([{ ruleId: 'VG-TEST-BOOM', message: 'kaboom' }]);
  });

  it('omits ruleErrors entirely when no rule throws', () => {
    const req: ScanRequest = {
      targetType: 'snippet',
      content: 'const v = eval(x);',
      mode: 'standard',
      filePath: 'a.js',
    };
    expect(scan(req).ruleErrors).toBeUndefined();
  });

  // A throw during finding CONSTRUCTION (not inside match()) — e.g. maskSecret on
  // a contract-violating null evidence — used to escape the match()-level guard
  // and kill the whole scan. On the canonical pass that would let the true arm
  // lose findings the false arm keeps, breaking the `D′(x) ⊇ D(x)` union
  // guarantee canonicalizer.ts claims by construction. It must land in
  // ruleErrors like any other crash, and healthy rules must still report.
  it('records a finding-construction throw in ruleErrors without killing the scan', () => {
    const nullEvidence: RuleDefinition = {
      ruleId: 'VG-TEST-NULLEV',
      name: 'null-evidence',
      description: 'returns a match whose evidence violates the string contract',
      languages: ['*'],
      category: 'secrets', // masked category, so maskSecret runs on the evidence
      severity: 'high',
      defaultConfidence: 'high',
      match: () => [
        { startLine: 1, endLine: 1, startColumn: 1, endColumn: 1, evidence: null as unknown as string },
      ],
    };
    const ok: RuleDefinition = {
      ruleId: 'VG-TEST-OK',
      name: 'ok',
      description: 'always matches',
      languages: ['*'],
      category: 'quality',
      severity: 'high',
      defaultConfidence: 'high',
      match: () => [{ startLine: 1, endLine: 1, startColumn: 1, endColumn: 1, evidence: 'x' }],
    };
    const req: ScanRequest = { targetType: 'snippet', content: 'anything', mode: 'standard' };
    const r = scan(req, { rules: [nullEvidence, ok] });
    // The scan did not throw, and the healthy rule still reported.
    expect(r.findings.map((f) => f.ruleId)).toContain('VG-TEST-OK');
    // The construction crash is observable, not a scan-killing escape.
    expect(r.ruleErrors).toEqual([
      { ruleId: 'VG-TEST-NULLEV', message: expect.stringContaining('null') },
    ]);
  });

  // --- Per-match severity override (RuleMatch.severity) --------------------
  // The design-smell rules (VG-SMELL-012/003) escalate a single match to `high`
  // on its content ("admin"/"root" literal, an authorization method) while the
  // rule's static severity stays `medium`/`low`. The override must reach the
  // finding AND the suppression severity gate, or an escalated-to-high match
  // could be silenced by a wildcard `vibeguard:disable` that its base severity
  // would have let through.
  describe('per-match severity override', () => {
    // Base severity 'low'; line 1 escalates to 'high', line 2 stays default.
    const escalating: RuleDefinition = {
      ruleId: 'VG-TEST-ESC',
      name: 'escalating',
      description: 'emits one escalated and one default-severity match',
      languages: ['*'],
      category: 'quality',
      severity: 'low',
      defaultConfidence: 'low',
      match: () => [
        { startLine: 1, endLine: 1, startColumn: 1, endColumn: 1, evidence: 'a', severity: 'high' },
        { startLine: 2, endLine: 2, startColumn: 1, endColumn: 1, evidence: 'b' },
      ],
    };

    it('assembles the finding at the per-match severity, falling back to the rule default', () => {
      const req: ScanRequest = { targetType: 'snippet', content: 'a\nb\n', mode: 'standard' };
      // canonicalize:false — this synthetic rule ignores content and emits fixed
      // matches, so the canonical pass (if it fired) would double-emit rather
      // than dedupe by source overlap the way a content-keyed rule does. The
      // override semantics under test are orthogonal to canonicalization.
      const r = scan(req, { rules: [escalating], canonicalize: false });
      const bySeverity = new Map(r.findings.map((f) => [f.severity, f]));
      expect(bySeverity.get('high')).toBeDefined();
      expect(bySeverity.get('low')).toBeDefined();
      expect(r.findings).toHaveLength(2);
    });

    it('gates a wildcard suppression at the per-match severity, not the rule default', () => {
      // A file-wide wildcard is HONORED for low/info and REFUSED for medium+
      // (the D5 gate). With the override, line 1 (escalated to high) survives
      // the wildcard while line 2 (base low) is suppressed — proof the gate saw
      // the match severity, not the rule's static 'low'.
      const req: ScanRequest = {
        targetType: 'snippet',
        content: '// vibeguard:disable-file\na\nb\n',
        mode: 'standard',
        filePath: 'x.js',
      };
      const r = scan(req, { rules: [escalating], canonicalize: false });
      const highs = r.findings.filter((f) => f.severity === 'high');
      expect(highs).toHaveLength(1);
      expect(highs[0]?.suppressionOverridden).toEqual({ channel: 'pragma', scope: 'file' });
      // The base-low match on line 2 was honoured by the wildcard — no finding.
      expect(r.findings.every((f) => f.severity !== 'low')).toBe(true);
    });
  });

  // --- Context-window confidence (paper item ①) ---------------------------

  it('does not down-rank a high-severity DEBUG=True in a docstring (severity gate)', () => {
    // Pre-gate this resolved to `low` (medium default, docstring -2). VG-FW-001
    // is severity `high`, so the gate now withholds the downgrade entirely: a
    // docstring is exactly the disguise an attacker would use to bury a real
    // setting, so it must not lower a severe finding.
    const code = [
      'def configure():',
      '    """',
      '    Example config:',
      '        DEBUG = True',
      '    """',
      '    DEBUG = False',
      '    return DEBUG',
    ].join('\n');
    const r = scan({
      targetType: 'snippet',
      content: code,
      mode: 'standard',
      filePath: 'settings.py',
      language: 'python',
    });
    const fw = r.findings.find((f) => f.ruleId === 'VG-FW-001');
    expect(fw).toBeDefined();
    // Held at the rule's default — NOT raised to `high`. VG-FW-001 declares
    // defaultConfidence 'medium', and the gate is a bound on downgrading, never
    // a promotion: reading the 'high' floor literally here would manufacture a
    // high-confidence finding out of a docstring. Pins that clamp end-to-end.
    expect(fw?.confidence).toBe('medium');
  });

  it('keeps full confidence for a real DEBUG=True in settings', () => {
    const r = scan({
      targetType: 'snippet',
      content: 'DEBUG = True\n',
      mode: 'standard',
      filePath: 'settings.py',
      language: 'python',
    });
    const fw = r.findings.find((f) => f.ruleId === 'VG-FW-001');
    expect(fw?.confidence).toBe('medium'); // unchanged default
  });

  it('does not lower a high-severity finding on a test path (severity gate)', () => {
    // Pre-gate the test path cost one step (high -> medium). VG-AUTH-004 is
    // severity `high`, so a test/ path no longer moves it: moving a real
    // vulnerability under tests/ must not buy any confidence reduction.
    const code = 'requests.get(url, verify=False)\n';
    const inTest = scan({
      targetType: 'snippet',
      content: code,
      mode: 'standard',
      filePath: 'tests/test_client.py',
      language: 'python',
    });
    const inSrc = scan({
      targetType: 'snippet',
      content: code,
      mode: 'standard',
      filePath: 'client.py',
      language: 'python',
    });
    // Same confidence either side: the test-path disguise buys nothing here.
    expect(inTest.findings.find((f) => f.ruleId === 'VG-AUTH-004')?.confidence).toBe('high');
    expect(inSrc.findings.find((f) => f.ruleId === 'VG-AUTH-004')?.confidence).toBe('high');
  });

  it('does not down-rank rules whose signal is the comment itself (opt-out)', () => {
    const code = '// TODO: validate the auth token before trusting it\nconst x = 1;\n';
    const r = scan({
      targetType: 'snippet',
      content: code,
      mode: 'standard',
      filePath: 'a.js',
      language: 'javascript',
    });
    const todo = r.findings.find((f) => f.ruleId === 'VG-AUTH-002');
    expect(todo).toBeDefined();
    expect(todo?.confidence).toBe('medium'); // opt-out keeps the default
  });
});

// --- m.confidence bypasses the context layer AND its severity gate ----------
//
// Pinning INTENDED behaviour, not an accident: `m.confidence ?? contextConfidence(…)`
// means a rule asserting its own per-match confidence skips the downgrade
// heuristics and the gate that bounds them. That is the design — m.confidence is
// a rule speaking from its own domain knowledge, not a generic guess about the
// surrounding text — but it does mean such a rule takes on the gate's
// responsibility itself. No rule sets it today. This test exists so that the day
// one does, the reviewer is told the security gate does not cover it.

describe('Analyzer: m.confidence bypass (pinned spec)', () => {
  /**
   * Severity `critical` + `defaultConfidence: 'high'` + a match inside a block
   * comment makes the three candidate outcomes mutually distinguishable, so the
   * assertion below identifies which code path ran rather than merely matching a
   * value:
   *   'medium' → m.confidence honoured (the pinned spec);
   *   'high'   → the severity gate ran (m.confidence ignored, gate held);
   *   'low'    → the un-gated context downgrade ran (block comment = −2 steps).
   *
   * The downgrade signal is a `/* … *\/` block, not a `//` line comment, on
   * purpose: this fixture must keep `language` unknown (see the req comment), and
   * once comment detection became a per-language allowlist, a leading `//`/`#`
   * no longer counts as a comment when the language is unknown (fail-safe —
   * the allowlist has no entry, so nothing is a comment).
   * Block-comment detection is language-independent, so it still yields the −2
   * `docstring` step here and keeps the three outcomes distinct.
   */
  function pinRule(over: { confidence?: Confidence; severity?: Severity } = {}): RuleDefinition {
    return {
      ruleId: 'VG-TEST-PIN',
      name: 'pin rule',
      description: 'test-only rule for the m.confidence chokepoint',
      languages: ['*'],
      category: 'quality',
      severity: over.severity ?? 'critical',
      defaultConfidence: 'high',
      match: () => [
        {
          startLine: 2,
          endLine: 2,
          startColumn: 1,
          endColumn: 1,
          evidence: 'dangerous_call()',
          ...(over.confidence ? { confidence: over.confidence } : {}),
        },
      ],
    };
  }

  // No filePath and no `language`, and content that trips none of the
  // detectLanguageFromContent patterns: the analyzer only honours injected
  // `rules` when the language is unknown (otherwise it consults the global
  // registry). The match (line 2) sits inside a `/* … *\/` block opened on line
  // 1, so the context layer has a language-independent `docstring` signal to act
  // on if it is reached.
  const req: ScanRequest = {
    targetType: 'snippet',
    content: '/* pinned\ndangerous_call()\n*/',
    mode: 'standard',
    includeRemediation: false,
  };

  function confidenceOf(rule: RuleDefinition): Confidence | undefined {
    const r = scan(req, { rules: [rule] });
    const f = r.findings.find((x) => x.ruleId === 'VG-TEST-PIN');
    expect(f, 'injected rule did not run — the fixture, not the gate, is broken').toBeDefined();
    return f?.confidence;
  }

  it('honours m.confidence verbatim, applying neither the downgrade nor the severity gate', () => {
    // 'medium' is reachable by no other path here: the gate would say 'high',
    // the un-gated downgrade would say 'low'.
    expect(confidenceOf(pinRule({ confidence: 'medium' }))).toBe('medium');
  });

  it('control: without m.confidence the same critical match goes through the gate', () => {
    expect(confidenceOf(pinRule())).toBe('high');
  });

  it('control: without m.confidence at an ungated severity the block-comment downgrade applies', () => {
    // `low`, not `medium`: since D1c gave `medium` a floor of `medium`, the only
    // severities the gate leaves ungated are `low` and `info`. Picking a floored
    // severity here would silently stop testing the un-gated path.
    expect(confidenceOf(pinRule({ severity: 'low' }))).toBe('low');
  });

  it('control: at a partially floored severity the downgrade is bounded, not refused', () => {
    // The third outcome D1c introduced: `medium` severity is neither ungated
    // (would be `low`) nor exempt (would be `high`) — it lands on the clamp.
    expect(confidenceOf(pinRule({ severity: 'medium' }))).toBe('medium');
  });

  it('m.confidence survives even where the gate would have raised it toward base', () => {
    // The bypass is not "whichever is lower" — the rule's word is final in both
    // directions the heuristics could have pulled.
    expect(confidenceOf(pinRule({ confidence: 'low' }))).toBe('low');
    expect(confidenceOf(pinRule({ confidence: 'high', severity: 'info' }))).toBe('high');
  });

  // --- confidenceAudit (D4) -------------------------------------------------
  //
  // The audit trail rides the same chokepoint, so it is pinned against the same
  // fixture: whatever path `confidence` took, `confidenceAudit` has to describe
  // that path and no other.

  function auditOf(rule: RuleDefinition) {
    const r = scan(req, { rules: [rule] });
    const f = r.findings.find((x) => x.ruleId === 'VG-TEST-PIN');
    expect(f, 'injected rule did not run — the fixture, not the audit, is broken').toBeDefined();
    return f!;
  }

  it('records the downgrade the gate refused (floored) without moving confidence', () => {
    const f = auditOf(pinRule());
    expect(f.confidence).toBe('high'); // unchanged — the gate held
    expect(f.confidenceAudit).toEqual({
      signals: ['docstring'],
      ungated: 'low', // high(2) − docstring(2) = low(0), had the gate not run
      floored: true,
    });
  });

  it('records a real downgrade as not floored at an ungated severity', () => {
    // `low` severity — see the control above for why `medium` no longer qualifies.
    const f = auditOf(pinRule({ severity: 'low' }));
    expect(f.confidence).toBe('low');
    expect(f.confidenceAudit).toEqual({ signals: ['docstring'], ungated: 'low', floored: false });
  });

  it('records a bounded downgrade as floored at a partially floored severity', () => {
    // `floored` is true whenever the gate changed the outcome — including when it
    // only held the downgrade back part of the way, which is the case D1c added.
    const f = auditOf(pinRule({ severity: 'medium' }));
    expect(f.confidence).toBe('medium');
    expect(f.confidenceAudit).toEqual({ signals: ['docstring'], ungated: 'low', floored: true });
  });

  it('omits the key entirely when a rule supplied its own confidence', () => {
    // No context evaluation ran, so there is nothing to audit. Key ABSENT, not
    // present-and-undefined — the distinction the conditional spread protects.
    const f = auditOf(pinRule({ confidence: 'medium' }));
    expect('confidenceAudit' in f).toBe(false);
  });
});

describe('Analyzer: confidenceAudit on real rules', () => {
  const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

  it('marks a critical secret hidden in a comment as floored', () => {
    const r = scan({
      targetType: 'snippet',
      content: `// const key = "${AWS_KEY}";`,
      mode: 'standard',
      filePath: 'src/app.js',
    });
    const sec = r.findings.find((f) => f.ruleId === 'VG-SEC-001');
    expect(sec, 'VG-SEC-001 did not fire — fixture broken').toBeDefined();
    // The whole point: the comment disguise bought the attacker nothing on the
    // confidence axis, AND the attempt is now visible on the finding.
    expect(sec!.confidence).toBe('high');
    expect(sec!.confidenceAudit).toEqual({
      signals: ['comment'],
      ungated: 'low',
      floored: true,
    });
  });

  it('leaves the same secret on a code line with no audit key at all', () => {
    const r = scan({
      targetType: 'snippet',
      content: `const key = "${AWS_KEY}";`,
      mode: 'standard',
      filePath: 'src/app.js',
    });
    const sec = r.findings.find((f) => f.ruleId === 'VG-SEC-001');
    expect(sec!.confidence).toBe('high');
    expect('confidenceAudit' in sec!).toBe(false);
  });
});

describe('Analyzer: an injected rule set is the rule set', () => {
  const probe = (ruleId: string, languages: string[]): RuleDefinition => ({
    ruleId,
    name: 'probe',
    description: 'always matches',
    languages,
    category: 'quality',
    severity: 'high',
    defaultConfidence: 'high',
    match: () => [{ startLine: 1, endLine: 1, startColumn: 1, endColumn: 1, evidence: 'x' }],
  });

  it('honours options.rules when the language IS detected', () => {
    // The regression: the scan used to pre-filter the GLOBAL registry by
    // language, which threw the caller's rules away and ran every shipped rule
    // instead. Because a language is detected for almost any real path, the
    // override only ever appeared to work on unidentifiable input.
    const r = scan(
      { targetType: 'snippet', content: 'const k = 1;', filePath: 't.js', mode: 'standard' },
      { rules: [probe('VG-TEST-ONLY', ['*'])] },
    );
    expect(r.findings.map((f) => f.ruleId)).toEqual(['VG-TEST-ONLY']);
  });

  it('still applies the language filter to the injected rules', () => {
    // Fixing the override must not turn it into "run everything regardless":
    // a rule that declares a language is still skipped for other languages.
    const opts = { rules: [probe('VG-TEST-PY', ['python'])] };
    const onPython = scan({ targetType: 'snippet', content: 'x = 1', filePath: 't.py', mode: 'standard' }, opts);
    const onJs = scan({ targetType: 'snippet', content: 'x = 1', filePath: 't.js', mode: 'standard' }, opts);
    expect(onPython.findings.map((f) => f.ruleId)).toEqual(['VG-TEST-PY']);
    expect(onJs.findings).toEqual([]);
  });

  it('reports a rule count that matches the set that actually ran', () => {
    // `engineVersions.rules` reads this.rules.length. While a different set was
    // silently substituted, that number described neither set.
    const r = scan(
      { targetType: 'snippet', content: 'const k = 1;', filePath: 't.js', mode: 'standard' },
      { rules: [probe('VG-TEST-A', ['*']), probe('VG-TEST-B', ['*'])] },
    );
    expect(r.engineVersions.rules).toBe('2');
    expect(r.findings).toHaveLength(2);
  });
});

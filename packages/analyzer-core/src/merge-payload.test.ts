// vibeguard:disable-file VG-AUTH-004 VG-INJ-004
// Fixtures disable TLS verification and call eval() on purpose: this suite is
// about which of two faces gets to report them.
import { describe, expect, it } from 'vitest';
import { scan } from './analyzer.js';

const scanJs = (content: string): ReturnType<typeof scan> =>
  scan({ targetType: 'file', content, filePath: 'a.js', mode: 'standard' });

const rules = (r: ReturnType<typeof scan>, id: string): number =>
  r.findings.filter((f) => f.ruleId === id).length;

/**
 * The canonical/raw merge deduplicates by SOURCE OVERLAP, and overlap alone was
 * too coarse.
 *
 * Blanking a comment does not only let a pattern reach further BACK — it also
 * lets a canonical match SPAN the blank run. A raw match living inside that
 * comment then overlaps it, and the merge dropped the canonical one as a
 * duplicate. The two are not duplicates: one is the assignment that actually
 * runs, the other is text inside a comment. The real finding disappeared and
 * the comment match stood in its place, wearing its position and its evidence.
 *
 * A raw match may now veto a canonical one only when it sits on text that
 * SURVIVED normalisation.
 */
describe('canonical/raw merge keeps distinct payloads', () => {
  // The construct at the centre of it. `verify=False` sits inside a block
  // comment that splits an assignment the compiler still performs.
  const DECOY = [
    "const https = require('https');",
    '',
    'const options = { rejectUnauthorized/*',
    'verify=False',
    '*/: false };',
    '',
    "https.get('https://example.com', options, (res) => { res.resume(); });",
    '',
  ].join('\n');

  it('reports the assignment that actually runs', () => {
    const r = scanJs(DECOY);
    const real = r.findings.filter((f) => f.startLine === 3);
    expect(real.length).toBe(1);
    expect(real[0]!.ruleId).toBe('VG-AUTH-004');
  });

  it('also keeps the raw match on the comment text — the union may only grow', () => {
    // `D'(x) ⊇ D(x)`: whatever the original pass saw stays. Suppressing the
    // comment match is the user's call, not the merge's.
    const r = scanJs(DECOY);
    expect(rules(r, 'VG-AUTH-004')).toBe(2);
    expect(r.findings.some((f) => f.startLine === 4)).toBe(true);
  });

  // The reason this matters. A reviewer looking at the OLD output saw one
  // finding, on a comment line, and the natural response — suppress the false
  // positive — silenced the file. Now the same pragma removes only what it
  // names.
  it('leaves the real finding standing when the decoy line is suppressed', () => {
    const withPragma = DECOY.replace(
      'verify=False',
      'verify=False // vibeguard:disable-line VG-AUTH-004',
    );
    const r = scanJs(withPragma);
    expect(rules(r, 'VG-AUTH-004')).toBe(1);
    expect(r.findings[0]!.startLine).toBe(3);
  });

  it('shows the user their own source, not the blanked form', () => {
    const r = scanJs(DECOY);
    const real = r.findings.find((f) => f.startLine === 3)!;
    expect(real.snippet).toContain('rejectUnauthorized');
    expect(real.snippet).toContain('*/: false };');
  });
});

/**
 * The dedup the merge exists for must still happen. These are the two cases
 * `mergeCanonicalMatches` documents, and both have the original match sitting
 * on REAL code — which is exactly what separates them from the case above.
 */
describe('canonical/raw merge still deduplicates one finding seen twice', () => {
  it('reports once when both faces match the same code', () => {
    // The comment makes canonicalization a no-op-free pass (`changed` is true),
    // so both faces run; both then match the same `eval(`.
    const content = '// a note\neval(payload);\n';
    const r = scanJs(content);
    expect(rules(r, 'VG-INJ-004')).toBe(1);
    expect(r.findings[0]!.startLine).toBe(2);
  });

  it('reports once when normalisation moves the match', () => {
    // `eval/*x*/(…)` is invisible to the raw face and visible to the canonical
    // one — a canonical-ONLY finding, which must appear exactly once and be
    // anchored to the line the user wrote.
    const r = scanJs('const out = eval/*x*/(payload);\n');
    expect(rules(r, 'VG-INJ-004')).toBe(1);
    expect(r.findings[0]!.startLine).toBe(1);
  });

  it('does not double-report a secret whose literal was folded', () => {
    const r = scanJs('const k = "AKIA" + "IOSFODNN7EXAMPLE";\n');
    // One finding, whichever face produced it — not one per face.
    const secrets = r.findings.filter((f) => f.category === 'secrets');
    expect(secrets.length).toBeLessThanOrEqual(1);
  });
});

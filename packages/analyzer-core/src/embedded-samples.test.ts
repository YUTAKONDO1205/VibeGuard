// VG-EMB 17g — the embedded sample corpus invariant ("E7"), the c/cpp analogue
// of E2/E3. samples/embedded/safe MUST stay at zero findings (no false
// positives, including from the legitimate init-order tripwire), and
// samples/embedded/vulnerable MUST exercise every shipped embedded rule.
//
// This is a SEPARATE count from E2 (samples/vulnerable = 51) and E3
// (samples/safe = 0): the web samples have no c/cpp files and the embedded
// rules are language-gated to c/cpp, so the two corpora cannot perturb each
// other. Kept as a vitest (not only a CI gate) so a regression names the rule.
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scanPath } from './file-scanner.js';

const SAFE = fileURLToPath(new URL('../../../samples/embedded/safe', import.meta.url));
const VULN = fileURLToPath(new URL('../../../samples/embedded/vulnerable', import.meta.url));

// Every embedded rule shipped in 17d–17f. If a rule is added, add it here — the
// coverage assertion is what proves the corpus actually exercises the ruleset
// rather than merely tripping a couple of loud rules.
const EXPECTED_RULES = [
  'VG-MEM-001',
  'VG-MEM-002',
  'VG-MEM-003',
  'VG-MEM-004',
  'VG-MEM-005',
  'VG-EMB-001',
  'VG-EMB-002',
  'VG-EMB-003',
  'VG-EMB-010',
  'VG-EMB-011',
  'VG-EMB-012',
  'VG-EMB-020',
  'VG-EMB-021',
  'VG-EMB-022',
  'VG-EMB-023',
  'VG-EMB-031',
  'VG-RTOS-001',
  'VG-RTOS-002',
  'VG-RTOS-004',
];

describe('embedded sample corpus (E7)', () => {
  it('samples/embedded/safe produces zero findings', async () => {
    const r = await scanPath(SAFE, { config: false });
    const detail = r.findings
      .map((f) => `${f.ruleId} ${f.filePath}:${f.startLine}`)
      .join('\n');
    expect(r.findings.length, `expected 0 findings, got:\n${detail}`).toBe(0);
  });

  it('samples/embedded/vulnerable fires every shipped embedded rule', async () => {
    const r = await scanPath(VULN, { config: false });
    const fired = new Set(r.findings.map((f) => f.ruleId));
    const missing = EXPECTED_RULES.filter((id) => !fired.has(id));
    expect(missing, `these embedded rules did not fire on the corpus: ${missing.join(', ')}`).toEqual(
      [],
    );
  });

  it('samples/embedded/vulnerable stays above the CI floor', async () => {
    const r = await scanPath(VULN, { config: false });
    // Mirrors the `-ge 18` gate in security-scan.yml; a floor, not an exact pin,
    // so adding a rule/fixture moves it up without a brittle failure.
    expect(r.findings.length).toBeGreaterThanOrEqual(18);
  });
});

// 0.2.x — the design-smell / supply-chain / prototype-pollution sample corpus
// invariant ("E8"), the analogue of E2/E3 (web) and E7 (embedded).
//
// SAFE corpora (design-safe, proto-safe) MUST stay at zero findings from the WHOLE
// ruleset — a design smell that fires on well-factored code is a bug, and these
// files are the standing proof it does not. POSITIVE corpora (design-smells,
// proto-pollution) MUST exercise every 0.2.x rule.
//
// SEPARATE counts from E2 (samples/vulnerable = 51), E3 (samples/safe = 0), and E7
// (samples/embedded): all new fixtures live in their own directories so the
// corpora cannot perturb one another. Kept as a vitest (not only a CI gate) so a
// regression names the rule.
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scanPath } from './file-scanner.js';

const url = (p: string): string => fileURLToPath(new URL(`../../../${p}`, import.meta.url));
const DESIGN_SAFE = url('samples/design-safe');
const DESIGN_SMELLS = url('samples/design-smells');
const PROTO_SAFE = url('samples/proto-safe');
const PROTO_POLLUTION = url('samples/proto-pollution');

// Every 0.2.x rule the positive corpora must exercise. Add a rule here when you
// add one — the coverage assertion proves the corpus tests the ruleset rather
// than tripping one loud rule.
const EXPECTED_DESIGN_RULES = ['VG-SMELL-003', 'VG-SMELL-004', 'VG-SMELL-012', 'VG-AISC-001'];
const EXPECTED_PROTO_RULES = ['VG-INJ-020'];

async function findings(dir: string) {
  const r = await scanPath(dir, { config: false });
  return r.findings;
}

describe('design-smell / supply-chain sample corpus (E8)', () => {
  it('samples/design-safe produces zero findings', async () => {
    const f = await findings(DESIGN_SAFE);
    const detail = f.map((x) => `${x.ruleId} ${x.filePath}:${x.startLine}`).join('\n');
    expect(f.length, `expected 0 findings, got:\n${detail}`).toBe(0);
  });

  it('samples/proto-safe produces zero findings', async () => {
    const f = await findings(PROTO_SAFE);
    const detail = f.map((x) => `${x.ruleId} ${x.filePath}:${x.startLine}`).join('\n');
    expect(f.length, `expected 0 findings, got:\n${detail}`).toBe(0);
  });

  it('samples/design-smells fires every shipped single-file design-smell and supply-chain rule', async () => {
    const fired = new Set((await findings(DESIGN_SMELLS)).map((x) => x.ruleId));
    const missing = EXPECTED_DESIGN_RULES.filter((id) => !fired.has(id));
    expect(missing, `these rules did not fire on the corpus: ${missing.join(', ')}`).toEqual([]);
  });

  it('samples/proto-pollution fires VG-INJ-020', async () => {
    const fired = new Set((await findings(PROTO_POLLUTION)).map((x) => x.ruleId));
    const missing = EXPECTED_PROTO_RULES.filter((id) => !fired.has(id));
    expect(missing, `these rules did not fire on the corpus: ${missing.join(', ')}`).toEqual([]);
  });

  it('positive corpora stay above the CI floor', async () => {
    // Mirrors the `-ge` gates in security-scan.yml; floors, not exact pins, so
    // adding a rule/fixture moves them up without a brittle failure.
    expect((await findings(DESIGN_SMELLS)).length).toBeGreaterThanOrEqual(6);
    expect((await findings(PROTO_POLLUTION)).length).toBeGreaterThanOrEqual(1);
  });

  it('escalates admin/authorization design smells to high severity', async () => {
    const f = await findings(DESIGN_SMELLS);
    // VG-SMELL-012 on an "admin" literal and VG-SMELL-003 on an authorization
    // method both escalate to high — proves the per-match severity path is live
    // end-to-end (rule → analyzer assembly), not just in a unit test.
    const highRules = new Set(f.filter((x) => x.severity === 'high').map((x) => x.ruleId));
    expect(highRules.has('VG-SMELL-012')).toBe(true);
    expect(highRules.has('VG-SMELL-003')).toBe(true);
  });
});

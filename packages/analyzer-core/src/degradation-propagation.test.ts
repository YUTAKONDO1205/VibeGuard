// vibeguard:disable-file VG-INJ-001
// Fixtures embed vulnerable-looking literals so rules fire.
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { REGEX_INPUT_CAP } from '@vibeguard/rules';
import { scanPath } from './file-scanner.js';
import { scan } from './analyzer.js';

/**
 * D3 degradations must survive the DIRECTORY WALK, not just the single-file
 * analyzer call.
 *
 * This test exists because that distinction was missed and shipped: `Analyzer.scan`
 * returned degradations correctly and `redos-bounds.test.ts` asserted so, but
 * `scanPath` — the function the CLI and the GitHub Action actually call —
 * aggregated only `ruleErrors` and dropped degradations on the floor. A 77 KB
 * file came back as "1 finding" with nothing indicating that 27 KB of it had
 * never been scanned. The renderer added for it in apps/cli/src/format.ts was
 * unreachable code.
 *
 * Every test in the file below would have failed against that build. The lesson
 * is that testing the library entry point proves nothing about the entry point
 * users have; the aggregating layer needs its own coverage.
 */

let dir: string;
const OVERSIZED = 'big.js';
const SMALL = 'small.js';

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vg-degradation-'));
  const finding = 'const q = "SELECT * FROM users WHERE id = " + userId;\n';
  // Comfortably past the cap so truncation is certain, with a real finding in
  // the part that IS scanned — truncation must not behave like skipping.
  await writeFile(join(dir, OVERSIZED), finding + '// padding\n'.repeat(Math.ceil(REGEX_INPUT_CAP / 5)));
  await writeFile(join(dir, SMALL), finding);
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('scanPath propagates D3 degradations', () => {
  it('reports the truncation that Analyzer.scan reported', async () => {
    const r = await scanPath(dir, { mode: 'standard' });
    // The exact failure that shipped: `degradations` was absent entirely.
    expect(r.degradations, 'scanPath dropped degradations').toBeDefined();
    expect(r.degradations!.length).toBeGreaterThan(0);
    expect(r.degradations![0]!.kind).toBe('input-truncated');
  });

  it('names the file that was cut short', async () => {
    const r = await scanPath(dir, { mode: 'standard' });
    // Without a filePath a directory scan cannot say WHICH file is partial —
    // the reason degradations are a separate channel from ruleErrors, which is
    // keyed by ruleId alone.
    const paths = (r.degradations ?? []).map((d) => d.filePath);
    expect(paths).toContain(OVERSIZED);
    expect(paths).not.toContain(SMALL);
  });

  it('collapses one oversized file to a single entry per kind', async () => {
    const r = await scanPath(dir, { mode: 'standard' });
    // Every rule that looks at the file trips the bound (~54 of them), and 54
    // identical lines would bury the signal. One line per file per kind.
    const forBig = (r.degradations ?? []).filter((d) => d.filePath === OVERSIZED && d.kind === 'input-truncated');
    expect(forBig).toHaveLength(1);
  });

  it('still returns the findings from the scanned prefix', async () => {
    const r = await scanPath(dir, { mode: 'standard' });
    // Truncating is not skipping: the finding at the top of the oversized file
    // must still be reported.
    expect(r.findings.some((f) => f.filePath === OVERSIZED)).toBe(true);
  });

  it('says nothing when no file is oversized', async () => {
    const small = await mkdtemp(join(tmpdir(), 'vg-degradation-small-'));
    try {
      await writeFile(join(small, SMALL), 'const q = "SELECT * FROM u WHERE id = " + id;\n');
      const r = await scanPath(small, { mode: 'standard' });
      // The channel must stay silent on ordinary input, or readers learn to
      // ignore it and it stops being a signal at all.
      expect(r.degradations).toBeUndefined();
    } finally {
      await rm(small, { recursive: true, force: true });
    }
  });

  it('agrees with Analyzer.scan about whether the file degraded', async () => {
    // The aggregating layer must not disagree with the layer it aggregates —
    // that disagreement is exactly what shipped.
    const content = 'const q = "SELECT * FROM u WHERE id = " + id;\n' + '// padding\n'.repeat(Math.ceil(REGEX_INPUT_CAP / 5));
    const direct = scan({ targetType: 'file', content, filePath: OVERSIZED, mode: 'standard' });
    const viaPath = await scanPath(dir, { mode: 'standard' });
    expect((direct.degradations ?? []).length > 0).toBe(true);
    expect((viaPath.degradations ?? []).length > 0).toBe(true);
  });
});

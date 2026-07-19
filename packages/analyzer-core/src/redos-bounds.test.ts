// vibeguard:disable-file
// Fixtures embed vulnerable-looking literals to make the rules fire.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { REGEX_INPUT_CAP } from '@vibeguard/rules';
import { scan } from './analyzer.js';

/**
 * D3 — the regex bounds, tested where they are actually visible to a user: on
 * the scan response.
 *
 * The unit tests in packages/rules/src/matcher-utils.test.ts cover the bounds
 * themselves. What can only be checked here is the pair of properties the bounds
 * were introduced to satisfy:
 *
 *   1. TRANSPARENCY — no bound fires on any input a real scan meets. A guard
 *      that trips on ordinary files is a silent false-negative generator, which
 *      is worse than the ReDoS it was added to prevent. This is asserted over
 *      the whole regression corpus, not over a hand-picked file, because the
 *      claim being made is about the corpus.
 *
 *   2. OBSERVABILITY — when a bound does fire, it reaches `degradations`, which
 *      every output channel surfaces. That is a channel of its own rather than
 *      `ruleErrors`, because a rule error means "the rule crashed and produced
 *      nothing" while a degradation means "the rule ran and reported findings,
 *      but not over the whole input" — and the renderer has to be able to say
 *      which. A bounded scan must never be indistinguishable from a clean one.
 */

const REPO_ROOT = resolve(__dirname, '../../..');

function collectFiles(dir: string): string[] {
  const out: string[] = [];
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) out.push(...collectFiles(full));
    else out.push(full);
  }
  return out;
}

const CORPUS = ['samples', 'test_problem'].flatMap((d) => collectFiles(join(REPO_ROOT, d)));

describe('D3 regex bounds — transparency on the regression corpus', () => {
  it('finds a corpus to check', () => {
    // Guards the tests below from silently passing over an empty list, which is
    // how a "no bound ever fired" claim quietly becomes vacuous.
    expect(CORPUS.length).toBeGreaterThan(0);
  });

  it('never fires a bound on any corpus file', () => {
    const tripped: string[] = [];
    for (const file of CORPUS) {
      const content = readFileSync(file, 'utf8');
      const r = scan({ targetType: 'file', content, filePath: file, mode: 'standard' });
      for (const d of r.degradations ?? []) {
        tripped.push(`${file}: ${d.ruleId} — ${d.detail}`);
      }
    }
    // A failure here means the cap is too low for real code: findings are being
    // lost. Raise REGEX_INPUT_CAP (cost is quadratic) rather than deleting this.
    expect(tripped).toEqual([]);
  });

  it('keeps every corpus file well under the input cap', () => {
    // The transparency above holds because the corpus is far from the bound, not
    // by luck. If a fixture ever approaches the cap, the assertion above becomes
    // fragile and this one says so first.
    const largest = Math.max(...CORPUS.map((f) => readFileSync(f, 'utf8').length));
    expect(largest).toBeLessThan(REGEX_INPUT_CAP / 2);
  });
});

describe('D3 regex bounds — observability when a bound does fire', () => {
  const oversized = () => {
    // A real finding first, then filler past the cap. Both halves matter: the
    // finding proves truncation is not "skip the file", the filler proves the
    // bound engaged.
    const head = 'const q = "SELECT * FROM users WHERE id = " + userId;\n';
    return `${head}${'// padding\n'.repeat(Math.ceil(REGEX_INPUT_CAP / 10))}`;
  };

  it('reports truncation on degradations, not on ruleErrors, and names the file', () => {
    const content = oversized();
    expect(content.length).toBeGreaterThan(REGEX_INPUT_CAP);
    const r = scan({ targetType: 'file', content, filePath: 'big.js', mode: 'standard' });

    const degs = r.degradations ?? [];
    expect(degs.length).toBeGreaterThan(0);
    expect(degs[0]!.kind).toBe('input-truncated');
    // The file must be named — the one thing the ruleId-keyed ruleErrors channel
    // could not express for a directory scan.
    expect(degs[0]!.filePath).toBe('big.js');
    // The message must say the result is partial, not merely "truncated".
    expect(degs[0]!.detail).toContain('PARTIAL');
    // And it must NOT masquerade as a crashed rule.
    expect(r.ruleErrors ?? []).toEqual([]);
  });

  it('still returns the findings inside the truncated prefix', () => {
    const r = scan({ targetType: 'file', content: oversized(), filePath: 'big.js', mode: 'standard' });
    // Truncating must not behave like skipping the file.
    expect(r.findings.length).toBeGreaterThan(0);
  });

  it('does not report the ordinary match limit as a degradation', () => {
    // 1000+ matches of one rule is common and benign. Reporting it here would
    // train readers to ignore the channel, taking the two real bounds with it.
    const content = 'const v = eval("1+1");\n'.repeat(1500);
    expect(content.length).toBeLessThan(REGEX_INPUT_CAP);
    const r = scan({ targetType: 'file', content, filePath: 'many.js', mode: 'standard' });
    expect(r.degradations ?? []).toEqual([]);
  });

  it('is deterministic: the same oversized input yields the same findings every time', () => {
    // The bound that decides the result is `content.length`, so repeated scans
    // must agree exactly. A wobble here means the wall-clock deadline became
    // load-bearing, which would also break E1's four-channel agreement.
    const content = oversized();
    const runs = Array.from({ length: 3 }, () =>
      scan({ targetType: 'file', content, filePath: 'big.js', mode: 'standard' }).findings.map(
        (f) => `${f.ruleId}:${f.startLine}:${f.severity}:${f.confidence}`,
      ),
    );
    for (const r of runs) expect(r).toEqual(runs[0]);
  });
});

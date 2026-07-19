// vibeguard:disable-file
// The CI invariant for the A1 ReDoS defence (L1).
//
// WHAT THIS GUARANTEES, AND WHY IT IS A TIMING TEST AND NOT `recheck`.
// The L1 fix rewrote the shipped rule regexes so none backtracks super-linearly.
// The natural way to keep them that way is "every rule passes recheck" — but
// recheck cannot be a CI dependency here: it ships a JVM jar (fragile on
// Windows, heavy), and its verdict OVER-FLAGS (it calls measured-linear rewrites
// "polynomial" with witnesses that do not actually exploit them). So recheck
// stays the OFFLINE discovery oracle (scripts/sec-a1-catalog.mjs); the CI gate is
// the property that actually matters — DESIGN §11.1's wall-clock budget — checked
// directly by scanning adversarial inputs and asserting the scan stays fast.
//
// This is a timing assertion, so the budget is deliberately loose (a fixed,
// generous ceiling far above a linear scan's real cost and far below the seconds
// a backtracking rule takes). A regression does not creep past it: a rule that
// reverts to `\s`-crossing-newlines jumps from tens of milliseconds to seconds
// on these inputs, which no CI-host variance closes. If this ever flakes near the
// ceiling, the rule got slow — investigate, do not raise the budget.
import { describe, expect, it } from 'vitest';
import { REGEX_INPUT_CAP } from '@vibeguard/rules';
import { scan } from './analyzer.js';

// Adversarial inputs, each just under the input cap so the cap itself does not
// mask a slow rule. They target the ReDoS families the L1 fix addresses:
//   - `\s` crossing newlines: a file that is almost all blank lines.
//   - adjacent variable quantifiers: a long single line of whitespace.
//   - near-miss repetition: tokens that repeatedly enter-then-fail a rule.
const N = REGEX_INPUT_CAP - 100;
const ADVERSARIAL: Array<{ name: string; content: string }> = [
  { name: 'blank-lines', content: '\n'.repeat(N) },
  { name: 'blank-lines-with-near-miss', content: `${'\n'.repeat(N / 2)}\treturn nil\n${'\n'.repeat(N / 2)}` },
  { name: 'space-run', content: `if${' '.repeat(N)}x` },
  { name: 'tab-run', content: `DEBUG${'\t'.repeat(N)}=` },
  { name: 'indented-blank-lines', content: '    \n'.repeat(N / 4) },
  // Near-miss repeats for several rule families at once.
  { name: 'debug-near-miss', content: 'DEBUG = Tru\n'.repeat(N / 12) },
  { name: 'return-near-miss', content: 'return null //\n'.repeat(N / 15) },
  { name: 'cors-near-miss', content: 'cors({ origin: "\n'.repeat(N / 17) },
  { name: 'sql-near-miss', content: '"SELECT FROM t" +\n'.repeat(N / 18) },
  { name: 'html-safe-near-miss', content: 'a.html_saf\n'.repeat(N / 11) },
];

// Per-input ceiling for a FULL scan (all 47 rules over ~50 KB). A linear scan of
// this is tens of ms; a single super-linear rule pushes it to seconds. 1500 ms
// sits an order of magnitude away from both, inside DESIGN §11.1's 3 s single-
// file budget with room for a loaded CI box.
const BUDGET_MS = 1_500;

describe('A1 ReDoS invariant — no rule is super-linear on adversarial input', () => {
  for (const { name, content } of ADVERSARIAL) {
    it(`scans '${name}' (${Math.round(content.length / 1000)}KB) within ${BUDGET_MS}ms`, () => {
      const langs = ['python', 'javascript', 'ruby', 'go', 'php', 'java'];
      for (const language of langs) {
        const t0 = Date.now();
        scan({ targetType: 'file', content, filePath: `adv.${name}`, mode: 'standard', language });
        const elapsed = Date.now() - t0;
        // A failure means some rule regexed super-linearly on this input. The fix
        // is to rewrite that rule (horizontal whitespace + collapse adjacent
        // quantifiers), NOT to raise this budget.
        expect(elapsed, `${name} @ ${language} took ${elapsed}ms`).toBeLessThan(BUDGET_MS);
      }
    });
  }

  it('scans the worst single-line whitespace input under budget in every mode', () => {
    // Modes select different rule subsets (fast = critical/high only); the bound
    // must hold for all of them, not just the full set.
    const content = `x${' '.repeat(N)}`;
    for (const mode of ['fast', 'standard', 'deep'] as const) {
      const t0 = Date.now();
      scan({ targetType: 'file', content, filePath: 'adv.modes', mode, language: 'javascript' });
      expect(Date.now() - t0).toBeLessThan(BUDGET_MS);
    }
  });
});

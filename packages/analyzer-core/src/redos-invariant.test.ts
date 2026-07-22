// vibeguard:disable-file
// vibeguard:disable-file VG-AISC-001
// (The bare wildcard above covers low/info rules on the adversarial strings; the
// D5 severity gate refuses a wildcard for medium+, so VG-AISC-001 — which the
// near-miss import fixtures below trip at `medium` — is named explicitly.)
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
  // VG-EMB C-shaped inputs. The MEM-004/005 pair-scan and the RTOS-001 head
  // scans are hand-rolled loops (not runRegex), so they need their own
  // adversarial coverage: many same-name frees with no barrier between them
  // (the O(pointers × n) shape MAX_PAIR_GAP bounds), and attach-spam sharing one
  // handler definition (the block-dedup path).
  { name: 'free-pair-soup', content: `free(p);${' '.repeat(20)}`.repeat(N / 30) },
  { name: 'free-distinct-soup', content: 'free(a); free(b); free(c); free(d);\n'.repeat(N / 36) },
  { name: 'memcpy-strlen-near-miss', content: 'memcpy(dst, src, strle\n'.repeat(N / 23) },
  { name: 'emb002-underscore-soup', content: 'PASS_'.repeat(N / 5) },
  { name: 'attach-spam', content: `void IRAM_ATTR h(){malloc(1);}\n${'attachInterrupt(0,h,0);\n'.repeat(N / 24)}` },
  { name: 'isr-head-soup', content: 'void IRAM_ATTR h(){\n'.repeat(N / 19) },
  // 0.2.x rule shapes. VG-SMELL-012's lazy dotted-identifier run adjacent to the
  // role-literal alternation; VG-SMELL-003/004 and VG-INJ-020's function-head and
  // for-in scans; VG-AISC-001's import extraction feeding the edit-distance loop.
  { name: 'role-compare-near-miss', content: 'user.role == "admi\n'.repeat(N / 19) },
  { name: 'role-id-run', content: `${'a.'.repeat(N / 4)}role === "x"\n` },
  { name: 'fn-head-soup', content: 'function f(a,b){\n'.repeat(N / 17) },
  { name: 'for-in-head-soup', content: 'for (const k in o){\n'.repeat(N / 20) },
  { name: 'proto-write-near-miss', content: 'a.__proto_\n'.repeat(N / 11) },
  { name: 'import-near-miss-soup', content: "import x from 'expres'\n".repeat(N / 23) },
  { name: 'require-soup', content: "require('lodahs');\n".repeat(N / 19) },
  // The JS-aware blanker's regex-literal + template states (blankJsLiterals).
  { name: 'regex-literal-soup', content: 'const R = /["\']|[a-z]/g;\n'.repeat(N / 26) },
  { name: 'template-soup', content: 'const s = `x ${a} y`;\n'.repeat(N / 22) },
];

// Per-input ceiling for a FULL scan (every rule over ~50 KB). A linear scan of
// this is tens of ms; a single super-linear rule pushes it to seconds. 1500 ms
// sits an order of magnitude away from both, inside DESIGN §11.1's 3 s single-
// file budget with room for a loaded CI box.
const BUDGET_MS = 1_500;

describe('A1 ReDoS invariant — no rule is super-linear on adversarial input', () => {
  for (const { name, content } of ADVERSARIAL) {
    it(`scans '${name}' (${Math.round(content.length / 1000)}KB) within ${BUDGET_MS}ms`, () => {
      const langs = ['python', 'javascript', 'ruby', 'go', 'php', 'java', 'c', 'cpp'];
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

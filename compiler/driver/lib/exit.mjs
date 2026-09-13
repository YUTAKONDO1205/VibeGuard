// Exit codes. interfaces.md §7 — so a caller can branch on the number without
// knowing which component ran.
//
// 0–4, and deliberately not the whole of §7. ★ 2026-09-13 the section grew rows
// for 5 (the harness could not be set up, or refused to write what it produced)
// and 6 (the thing measured is not the thing it was named as), both emitted only
// by the measuring harnesses under compiler/eval/. The driver, the verifier, the
// envelope and the link wrapper keep to 0–4, which is why they are the only five
// here — the same boundary `compiler/schema/observation.schema.json` draws when it
// holds a record's `verdict.exitCode` at 0–4. An eval harness that imported these
// constants and then needed a sixth would be telling you it does not belong on
// this side of that line.
//
// `compiler/schema/exit-codes.test.mjs` checks the section against every literal
// exit in the tree. It does NOT check this file, because this file is a SUBSET on
// purpose and a test that demanded parity would demand the wrong thing.

export const EXIT_OK = 0;          // everything asked for was checked, nothing found
export const EXIT_TOOL_FAILED = 1; // clang failed; its diagnostics passed through unchanged
export const EXIT_FINDINGS = 2;    // findings at or above the policy's failure threshold
export const EXIT_INCOMPLETE = 3;  // a check could not be completed. Never conflated with 0.
export const EXIT_INTEGRITY = 4;   // digest does not match the pin, or the policy is malformed

export const EXIT_NAMES = {
  0: 'ok',
  1: 'tool-failed',
  2: 'findings',
  3: 'incomplete',
  4: 'integrity',
};

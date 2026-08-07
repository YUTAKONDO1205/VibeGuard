// Exit codes. interfaces.md §7 — shared by every executable in compiler/.
//
// Restated here rather than imported so this component has no build-order
// dependency on another one, and asserted against compiler/driver/lib/exit.mjs
// in test/exit.test.mjs so that "restated" can never become "renumbered".

export const EXIT_OK = 0;          // everything asked for was checked, nothing found
export const EXIT_TOOL_FAILED = 1; // the linker failed; its diagnostics passed through unchanged
export const EXIT_FINDINGS = 2;    // findings at or above the policy's failure threshold
export const EXIT_INCOMPLETE = 3;  // a check could not be completed. Never conflated with 0.
export const EXIT_INTEGRITY = 4;   // the observation itself is untrustworthy, or the policy is malformed

export const EXIT_NAMES = { 0: 'ok', 1: 'tool-failed', 2: 'findings', 3: 'incomplete', 4: 'integrity' };

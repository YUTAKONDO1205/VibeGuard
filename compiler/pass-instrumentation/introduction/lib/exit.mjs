// Exit codes. interfaces.md §7, and identical to compiler/driver/lib/exit.mjs.
//
// Restated here rather than imported: the driver is a separate component with
// its own owner, and a cross-component import for five integers would make this
// one fail to load when that one is mid-edit. The numbers are fixed by the
// contract, not by either file, so the duplication cannot drift without the
// contract changing first.

export const EXIT_OK = 0;          // everything asked for was checked, nothing found
export const EXIT_TOOL_FAILED = 1; // the underlying tool failed; diagnostics pass through
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

/**
 * The protection-claim ledger, reduced to the one line a panel can show.
 *
 * ── WHY THIS EXISTS AS ITS OWN FILE ─────────────────────────────────────────
 *
 * Some findings are not "you wrote something dangerous" — they are "you wrote a
 * protection in a form a build step can remove". `VG-AUTH-008` and its
 * siblings, `VG-MEM-006`: the code says a check is there, and whether it is
 * still there after the bundler has run is a different question that nobody has
 * asked yet. Those findings are CLAIMS, and the panel has to say so, because a
 * claim rendered as an ordinary finding reads as something that was checked.
 *
 * The side panel cannot check one. It has a tab, a textarea and a diff; it has
 * no build output, no filesystem and no way to acquire either. So every claim
 * reachable from here is `NOT_OBSERVED` — not as a default that some later
 * branch might improve on, but by construction: `claimsFromFindings` cannot
 * emit any other state, and nothing in this process could settle it if it did.
 *
 * ── AND WHY IT DOES NOT WRITE ITS OWN SENTENCE ──────────────────────────────
 *
 * The wording is `summariseClaims().line`, verbatim. That function's docstring
 * says outright why it is shared: so the CLI, the editor, the browser panel and
 * a PR comment cannot drift into describing the same ledger differently, and —
 * the part that matters — so none of them can independently decide to phrase
 * NOT_OBSERVED as something reassuring. A local rewording here would be exactly
 * that drift, arriving on the surface with the least context to justify it.
 *
 * Pure: no DOM, no chrome.*, no clock. The panel does the rendering.
 */
import {
  claimsFromFindings,
  summariseClaims,
  type ClaimSourceFinding,
} from '@vibeguard/findings-schema';

/**
 * The ledger line for a set of findings, or `null` when there is nothing to say.
 *
 * `null` means "no finding here declares a protection" — it does NOT mean the
 * declared protections are fine, and the caller must render nothing at all
 * rather than an absence-of-claims reassurance.
 */
export function claimsLine(findings: readonly ClaimSourceFinding[]): string | null {
  const claims = claimsFromFindings(findings);
  if (claims.length === 0) return null;
  // Verbatim. See the note above before replacing this with a template string.
  return summariseClaims(claims).line || null;
}

/**
 * Ownership proofs for the search consoles — the single definition.
 *
 * WHY THIS IS CODE AND NOT A FILE IN public/
 *
 * Google Search Console's file method hands you `<token>.html` and asks that it
 * answer at exactly `/<token>.html`. Dropping it in public/ looks like the
 * obvious move and does not work here, for a reason that only shows up in
 * production:
 *
 *   · wrangler.jsonc sets `html_handling: "drop-trailing-slash"`, which makes
 *     the asset layer answer any request for `/x.html` with a 307 to `/x`.
 *     Measured on the live site: `/install.html` → 307 → `/install`. The
 *     verification URL would therefore never return 200, and whether Google
 *     accepts a redirected proof is not something this repository gets to
 *     decide. Turning `html_handling` off to fix one file would un-canonicalise
 *     all six pages, which is the opposite trade.
 *   · scripts/site-copy-lint.mjs treats every `.html` under dist/ that is not
 *     the 404 page as a content page, and every `.html` under public/ as
 *     copy. A one-line token file would be scanned by the copy rules and
 *     counted in the page floor — a second thing to explain forever.
 *
 * Served from the Worker, the answer is a plain 200 at the exact path with the
 * same header table a static page would have carried. Nothing else moves.
 *
 * WHAT NOT TO DO WITH THIS FILE
 *
 * The token stays after verification succeeds: Search Console re-checks it
 * periodically and silently un-verifies the property when it stops answering.
 * Removing an entry here is the same action as removing the property.
 */

/**
 * The path → body table the Worker answers.
 *
 * Both halves are derived from one token, because Google's file content is
 * literally `google-site-verification: <filename>` — writing the string out
 * twice would be two copies of the same secretless secret, and the failure mode
 * of them disagreeing is a verification that fails with both values looking
 * right in the diff. worker/index.test.ts pins that derivation, so a hand-edited
 * body cannot pass.
 *
 * Keys are absolute paths and therefore always start with `/`, which is also
 * why no key can collide with an `Object.prototype` member. The Worker still
 * looks entries up with `hasOwnProperty`, for the same reason `isChannel` does.
 */
const GOOGLE_SEARCH_CONSOLE_TOKEN = 'googlef4f7891287348e76';

export const VERIFICATION_FILES: Record<string, string> = {
  [`/${GOOGLE_SEARCH_CONSOLE_TOKEN}.html`]: `google-site-verification: ${GOOGLE_SEARCH_CONSOLE_TOKEN}.html`,
};

/** True when `path` is one of the verification files, prototype keys excluded. */
export const isVerificationPath = (path: string): boolean =>
  Object.prototype.hasOwnProperty.call(VERIFICATION_FILES, path);

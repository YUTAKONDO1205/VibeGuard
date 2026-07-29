/** Extract a small snippet around a (1-based) line range. Returns the lines as a single string. */
export function extractSnippet(lines: string[], startLine: number, endLine: number, padding = 0): string {
  const from = Math.max(0, startLine - 1 - padding);
  const to = Math.min(lines.length, endLine + padding);
  return lines.slice(from, to).join('\n');
}

/**
 * Characters a secret-looking literal is allowed to be built from.
 *
 * Wider than an alphanumeric token on purpose. A WiFi or OTA password is a
 * PASSWORD, not a base64 key: `Tsu9any0!` is exactly the shape a human picks,
 * and a character class without punctuation walks straight past it. Anything a
 * password policy encourages belongs here.
 */
const SECRET_CHARS = "A-Za-z0-9_\\-+/=.!@#$%^&*()\\[\\]{}<>?,;:~|'";

/** The same set, for the unquoted forms where a quote would end the value. */
const SECRET_CHARS_BARE = 'A-Za-z0-9_\\-+/=.!@#$%^&*?~|';

/**
 * Shortest run treated as secret-shaped.
 *
 * Short enough to catch a real password (`Tsu9any0!` is nine characters), which
 * is what the previous value of 12 missed. The length is not what separates a
 * credential from a placeholder — {@link PLACEHOLDER} is.
 */
const MIN_SECRET_LEN = 6;

/**
 * Values that stay readable, because NAMING them is the finding.
 *
 * `VG-AUTH-003` reports "this is a well-known placeholder". Masking `changeme`
 * to `chan***` deletes the entire message: the reader can no longer see that
 * the value is the default everyone knows. These are worthless to an attacker
 * precisely because they are public, so there is nothing to protect.
 *
 * Matched against the whole value, case-insensitively. Anything not on the list
 * is treated as real — the safe default, since this function only ever runs on
 * findings whose rule declared `category: 'secrets'`.
 */
const PLACEHOLDER =
  /^(?:changeme|change_me|change-me|password|passwd|pass|secret|admin|root|test|testing|example|sample|dummy|placeholder|todo|fixme|xxx+|foo|bar|baz|yourpassword|your_password|your-password|yoursecret|your_secret|your-secret|api[_-]?key|apikey|token|s3cret|letmein|qwerty|abc123|123456+|null|none|undefined)$/i;

const QUOTED = new RegExp(`(["'])([${SECRET_CHARS}]{${MIN_SECRET_LEN},}?)\\1`, 'g');

/**
 * `key: value` / `key=value` where the value is unquoted. `(?!\\/\\/)` keeps
 * `https://long-host-name` out of it — the `:` in a URL scheme is a separator
 * by shape only, and the authority that follows is not a credential.
 */
const UNQUOTED_ASSIGNMENT = new RegExp(
  `([:=][^\\S\\r\\n]*)(?!\\/\\/)([${SECRET_CHARS_BARE}]{${MIN_SECRET_LEN},})`,
  'g',
);

/** The whole string is one bare token — the shape a rule's `evidence` takes. */
const BARE_TOKEN = new RegExp(`^([${SECRET_CHARS_BARE}]{${MIN_SECRET_LEN},})$`);

/**
 * Redact `value`, unless it is a placeholder whose identity IS the finding.
 *
 * Keeps the first four characters so a reader can still correlate a masked
 * value with the credential they are looking for without the value itself
 * travelling into the report.
 */
function mask(value: string): string {
  // Already redacted. `*` is a legitimate password character and stays in
  // SECRET_CHARS, which means a masked value still looks secret-shaped to the
  // next pattern — so idempotence has to be asserted here rather than assumed
  // from the character class. Without this, `KEY=AKIA***` is re-matched as one
  // bare token and collapses to `KEY_***`, destroying the key name.
  if (value.endsWith('***')) return value;
  if (PLACEHOLDER.test(value)) return value;
  return `${value.slice(0, 4)}***`;
}

/**
 * Mask everything except the first 4 characters of a literal-looking secret.
 *
 * Applied only to findings whose rule declares `category: 'secrets'` (see
 * `shouldMaskCategory`), to BOTH the snippet and the evidence. That scoping is
 * what makes it safe to redact aggressively here: inside a secrets finding the
 * matched text is a credential by the rule's own claim, so over-masking costs a
 * few characters of context while under-masking copies the credential into
 * every output format.
 *
 * Three shapes, because quoting is a property of the SOURCE SYNTAX and not of
 * whether a value is a secret — keying redaction off quote characters alone
 * meant an AWS key survived in plaintext whenever it was not written as a
 * quoted string:
 *
 *  - `KEY = "AKIA…"` — quoted. Masked before and now.
 *  - `aws_access_key_id: AKIA…` — a YAML/env/TOML value, unquoted. Previously
 *    passed through verbatim in the `snippet`, which is the field the SARIF
 *    adapter emits; a scan uploaded to GitHub code scanning therefore published
 *    the key it had just found.
 *  - `AKIA…` alone — the shape `evidence` takes when the rule's pattern matches
 *    the token without its surrounding quotes. Also previously verbatim.
 *
 * Length is not the discriminator between a credential and a placeholder;
 * {@link PLACEHOLDER} is. Treating it as one let `WiFi.begin("HomeNet",
 * "Tsu9any0!")` through — nine characters, punctuation, and a real password.
 *
 * Throws on a non-string input, and that is load-bearing: `analyzer.ts` relies
 * on a contract-violating `evidence` failing HERE, inside the per-match guard
 * that records it in `ruleErrors`, rather than passing silently through.
 */
export function maskSecret(snippet: string): string {
  const quoted = snippet.replace(QUOTED, (_full, q: string, val: string) => `${q}${mask(val)}${q}`);
  const assigned = quoted.replace(
    UNQUOTED_ASSIGNMENT,
    (_full, sep: string, val: string) => `${sep}${mask(val)}`,
  );
  const trimmed = assigned.trim();
  if (BARE_TOKEN.test(trimmed)) {
    return assigned.replace(trimmed, mask(trimmed));
  }
  return assigned;
}

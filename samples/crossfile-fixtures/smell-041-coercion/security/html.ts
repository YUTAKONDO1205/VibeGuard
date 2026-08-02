const REPLACEMENTS: ReadonlyArray<readonly [string, string]> = [
  ['&', '&amp;'],
  ['<', '&lt;'],
  ['>', '&gt;'],
  ['"', '&quot;'],
];

export function escapeHtml(value: string): string {
  let out = String(value);
  for (const [from, to] of REPLACEMENTS) out = out.split(from).join(to);
  return out;
}

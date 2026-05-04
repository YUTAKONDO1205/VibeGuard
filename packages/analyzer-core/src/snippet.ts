/** Extract a small snippet around a (1-based) line range. Returns the lines as a single string. */
export function extractSnippet(lines: string[], startLine: number, endLine: number, padding = 0): string {
  const from = Math.max(0, startLine - 1 - padding);
  const to = Math.min(lines.length, endLine + padding);
  return lines.slice(from, to).join('\n');
}

/** Mask everything except the first 4 chars of a literal-looking secret. */
export function maskSecret(snippet: string): string {
  return snippet.replace(/(["'])([A-Za-z0-9_\-+/=]{12,})\1/g, (_full, q, val) => {
    const visible = val.slice(0, 4);
    return `${q}${visible}***${q}`;
  });
}

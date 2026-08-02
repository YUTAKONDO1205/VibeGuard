// `strip` and `quote` used the way every codebase uses them: presentation. The
// return value of neither is safe for a shell, a statement, or a page.
export function stripTrailingWhitespace(value: string): string {
  return String(value).replace(/[^\S\r\n]{1,80}$/, '');
}

export function quoteForDisplay(value: string): string {
  return `“${value}”`;
}

// `escape` IS in the vocabulary, and this function is still not a defence: it
// makes a value safe to embed in a PATTERN, which says nothing about whether it
// is safe for a shell, a statement, or a page. It is named in `NOT_A_GUARD`
// rather than kept out by the word list, because the word is the right word.
export function escapeRegExp(value: string): string {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// A real sanitizer, and one whose name survives the narrowed vocabulary — the
// corpus original used `quotePs`, and `quote` was removed from
// `TRANSFORMER_WORDS` in the same change that added the block test. If this
// fixture used a word the vocabulary no longer knows, it would be silent for the
// wrong reason and would stop pinning anything.
export function sanitizeHostsPath(value: string): string {
  return String(value).replace(/[^A-Za-z0-9._-]/g, '');
}

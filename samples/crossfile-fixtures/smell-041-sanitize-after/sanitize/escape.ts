// The sanitizer the handler calls. Correct, and never on the path that matters.
//
// It takes no request value and reaches no sink, so this file contributes no
// taint flow of its own — the fixture's single flow is the one in `search.ts`.
export function escapeLike(value: string): string {
  return String(value).replace(/[%_\\]/g, (c) => `\\${c}`);
}

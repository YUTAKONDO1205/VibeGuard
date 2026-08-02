// Exported, correct, and referenced by nothing. This directory is a negative
// because there is no unguarded endpoint the sanitizer could have been omitted
// from, not because it is wired up.
export function sanitizeIncidentTitle(raw: string): string {
  return raw.replace(/[<>"'`]/g, '').slice(0, 120);
}

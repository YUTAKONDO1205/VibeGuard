// Written with the orders endpoint, exported, and applied to nothing.
export function sanitizeOrderNote(raw: string): string {
  return raw.replace(/[<>"'`]/g, '').slice(0, 200);
}

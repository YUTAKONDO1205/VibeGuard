// The retired package. Nothing here has been imported by the API since the
// billing rewrite, and this file is kept only because deleting a package is a
// release and nobody has scheduled one.
export function validateInvoicePayload(payload: unknown): boolean {
  if (typeof payload !== 'object' || payload === null) return false;
  const total = (payload as { total?: unknown }).total;
  return typeof total === 'number' && Number.isFinite(total) && total >= 0;
}

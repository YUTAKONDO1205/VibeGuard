// A helper for the signup suite. Exported so the spec files can import it, and
// currently imported by none of them because the last case that used it was
// deleted. That is a tidy-up, not a missing security control.
export function validateSignupInput(body: unknown): boolean {
  if (typeof body !== 'object' || body === null) return false;
  const email = (body as { email?: unknown }).email;
  return typeof email === 'string' && email.includes('@');
}

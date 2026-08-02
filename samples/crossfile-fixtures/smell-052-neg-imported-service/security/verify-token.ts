export function verifyToken(raw: string | undefined): boolean {
  if (!raw || !raw.startsWith('Bearer ')) return false;
  return raw.slice(7).length >= 32;
}

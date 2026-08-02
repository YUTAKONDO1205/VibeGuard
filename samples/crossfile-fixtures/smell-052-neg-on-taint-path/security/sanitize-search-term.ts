export function sanitizeSearchTerm(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  return raw.replace(/[^\w \-]/g, '').slice(0, 64);
}

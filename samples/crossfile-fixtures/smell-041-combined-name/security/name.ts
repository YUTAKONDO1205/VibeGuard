// One helper doing both jobs, which is how a name ends up carrying both words.
// It throws on a value it cannot repair and returns a safe copy otherwise, so
// the transformer reading is the one that describes it.
export function validateAndEscapeName(value: string): string {
  const text = String(value);
  if (text.length === 0 || text.length > 255) throw new Error('name out of range');
  return text.replace(/[^A-Za-z0-9._-]/g, '');
}

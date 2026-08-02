// A real transformer, called on a PROPERTY of a hop rather than on the hop. It
// is what half two of the fixture rests on: the sink consumes the value bare, so
// only the guard's own argument can refuse the premise.
export function sanitizeReleaseName(value: string): string {
  return String(value).replace(/[^A-Za-z0-9._-]/g, '');
}

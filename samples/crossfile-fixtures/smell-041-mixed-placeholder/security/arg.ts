// A real argument sanitiser, so the fixture cannot be read as "the sanitizer was
// inadequate". The defect is entirely that it runs after the process it was
// written for has already been started.
export function sanitizeArg(value: string): string {
  return String(value).replace(/[^A-Za-z0-9._\-/]/g, '');
}

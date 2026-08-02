// The sanitizer whose result the handler computes and then does not use.
//
// It is deliberately a real one — it strips separators and traversal segments —
// so the fixture cannot be read as "the sanitizer was inadequate". The defect
// is entirely that its output is not the value that reached the sink.
export function sanitizeFilename(value: string): string {
  return String(value).replace(/[^A-Za-z0-9._-]/g, '').replace(/^\.+/, '');
}

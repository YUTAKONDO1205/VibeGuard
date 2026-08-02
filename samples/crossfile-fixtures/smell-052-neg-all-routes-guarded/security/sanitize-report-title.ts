// Exported, referenced by nothing, and left alone: every registration in this
// project already carries a guard, so there is no omitted wiring point to blame
// its absence on. See README.md.
export function sanitizeReportTitle(raw: unknown): string {
  if (typeof raw !== 'string') return 'untitled';
  return raw.replace(/[<>"'`]/g, '').slice(0, 120);
}

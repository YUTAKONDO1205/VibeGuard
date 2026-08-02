export interface AuditEntry {
  id: string;
  at: string;
  what: string;
}

export function describeAuditEntry(value: AuditEntry): string {
  return `AuditEntry(${value.id})`;
}

import type { AuditEntry } from '../models/audit-entry.js';

export function auditEntry(what: string, at: string): AuditEntry {
  return { id: `${what}-${at}`, at, what };
}

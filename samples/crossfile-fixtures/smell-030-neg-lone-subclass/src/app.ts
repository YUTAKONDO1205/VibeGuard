import { AuditLogAuthorizer } from './authorization/audit-log-authorizer.js';
import { ExportAuthorizer } from './authorization/export-authorizer.js';
import type { Subject } from './authorization/request-authorizer.js';

export function allowed(kind: string, subject: Subject): boolean {
  if (kind === 'audit') return new AuditLogAuthorizer().authorize(subject);
  return new ExportAuthorizer().authorize(subject);
}

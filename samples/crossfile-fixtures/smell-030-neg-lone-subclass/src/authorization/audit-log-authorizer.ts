import type { Subject } from './request-authorizer.js';

/** Not a subclass of anything. Its presence keeps the fixture from being vacuous. */
export class AuditLogAuthorizer {
  authorize(subject: Subject): boolean {
    if (!subject.permissions.includes('audit:read')) return false;
    return subject.id.startsWith('svc_');
  }
}

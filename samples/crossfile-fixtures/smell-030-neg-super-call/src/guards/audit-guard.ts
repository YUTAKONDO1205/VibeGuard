import { Guard } from './guard.js';
import type { Subject } from './guard.js';

export class AuditGuard extends Guard {
  constructor() {
    super('audit:read');
  }

  hasPermission(subject: Subject): boolean {
    if (subject.suspended) return false;
    return subject.permissions.includes('audit:read') && subject.id.length > 0;
  }
}

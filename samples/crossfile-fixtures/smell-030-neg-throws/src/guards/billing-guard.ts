import { Guard } from './guard.js';
import type { Subject } from './guard.js';

export class BillingGuard extends Guard {
  constructor() {
    super('billing:read');
  }

  isAuthorized(subject: Subject): boolean {
    if (!subject.permissions.includes('billing:read')) return false;
    return subject.tenantId.length > 0;
  }
}

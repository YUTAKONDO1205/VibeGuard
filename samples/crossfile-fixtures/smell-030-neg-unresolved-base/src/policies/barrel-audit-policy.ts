import { KitPolicy } from '../kit/index.js';
import type { Subject } from '../kit/index.js';

export class BarrelAuditPolicy extends KitPolicy {
  isAuthorized(subject: Subject): boolean {
    if (subject.id.length === 0) return false;
    return subject.permissions.includes('audit:read');
  }
}

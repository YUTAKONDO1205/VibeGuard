import { Policy } from './policy.js';
import type { Subject } from './policy.js';

export class TenantPolicy extends Policy {
  private readonly tenantId: string;

  constructor(resourceOwnerId: string, tenantId: string) {
    super(resourceOwnerId);
    this.tenantId = tenantId;
  }

  canAccess(subject: Subject): boolean {
    if (!subject.roles.includes(`tenant:${this.tenantId}`)) return false;
    return subject.roles.includes('reader');
  }
}

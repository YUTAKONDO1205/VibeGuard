import { ForbiddenError, Guard } from './guard.js';
import type { Subject } from './guard.js';

export class TenantScopedGuard extends Guard {
  private readonly tenantId: string;

  constructor(tenantId: string) {
    super('tenant:read');
    this.tenantId = tenantId;
  }

  isAuthorized(subject: Subject): boolean {
    if (subject.tenantId !== this.tenantId) {
      throw new ForbiddenError('cross-tenant access');
    }
    return true;
  }
}

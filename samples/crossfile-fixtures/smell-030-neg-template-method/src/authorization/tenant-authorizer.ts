import { AbstractAuthorizer } from './abstract-authorizer.js';
import type { Subject } from './abstract-authorizer.js';

export class TenantAuthorizer extends AbstractAuthorizer {
  private readonly tenantId: string;

  constructor(tenantId: string) {
    super();
    this.tenantId = tenantId;
  }

  authorize(subject: Subject): boolean {
    if (!subject.permissions.includes('tenant:read')) return false;
    return subject.id.startsWith(this.tenantId);
  }
}

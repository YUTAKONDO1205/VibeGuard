import { BillingGuard } from './guards/billing-guard.js';
import { TenantScopedGuard } from './guards/tenant-scoped-guard.js';
import type { Guard, Subject } from './guards/guard.js';

export function check(kind: string, subject: Subject): boolean {
  const guard: Guard = kind === 'billing' ? new BillingGuard() : new TenantScopedGuard(subject.tenantId);
  return guard.isAuthorized(subject);
}

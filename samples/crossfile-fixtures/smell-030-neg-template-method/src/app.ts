import { ExportAuthorizer } from './authorization/export-authorizer.js';
import { TenantAuthorizer } from './authorization/tenant-authorizer.js';
import type { AbstractAuthorizer, Subject } from './authorization/abstract-authorizer.js';

export function authorizerFor(kind: string, tenantId: string): AbstractAuthorizer {
  if (kind === 'export') return new ExportAuthorizer();
  return new TenantAuthorizer(tenantId);
}

export function allowed(kind: string, tenantId: string, subject: Subject): boolean {
  return authorizerFor(kind, tenantId).authorize(subject);
}

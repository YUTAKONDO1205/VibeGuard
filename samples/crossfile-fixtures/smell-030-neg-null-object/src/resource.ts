import { Policy } from './policy/policy.js';
import { PublicPolicy } from './policy/public-policy.js';
import { TenantPolicy } from './policy/tenant-policy.js';

export function policyFor(kind: string, ownerId: string, tenantId: string): Policy {
  if (kind === 'published') return new PublicPolicy();
  if (kind === 'tenant') return new TenantPolicy(ownerId, tenantId);
  return new Policy(ownerId);
}

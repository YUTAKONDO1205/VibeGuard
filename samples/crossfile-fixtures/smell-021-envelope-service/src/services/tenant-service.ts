import type { Tenant } from '../models/tenant.js';

export function planOf(tenant: Tenant): string {
  return tenant.plan;
}

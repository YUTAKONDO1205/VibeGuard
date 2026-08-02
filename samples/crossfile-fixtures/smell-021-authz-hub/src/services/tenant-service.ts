import { findTenantById } from '../repositories/tenant-repository.js';
import { db } from '../db/client.js';

export async function tenantPlan(tenantId: string): Promise<string> {
  const tenant = await findTenantById(db, tenantId);
  return tenant?.plan ?? 'free';
}

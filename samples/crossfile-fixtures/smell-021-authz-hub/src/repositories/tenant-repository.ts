import type { Db } from '../db/client.js';
import type { Tenant } from '../models/tenant.js';

export async function findTenantById(db: Db, id: string): Promise<Tenant | undefined> {
  const rows = await db.query<Tenant>('select * from tenants where id = $1', [id]);
  return rows[0];
}

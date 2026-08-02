import { db } from '../db/client.js';

export async function listReports(tenantId: string): Promise<unknown[]> {
  return db.query('select * from reports where tenant_id = $1', [tenantId]);
}

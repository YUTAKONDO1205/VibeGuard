import { authorize } from '../security/authorize.js';
import { listReports } from '../services/report-service.js';

export async function adminReports(userId: string, tenantId: string): Promise<unknown> {
  const decision = await authorize(userId, 'reports.readAll', tenantId);
  if (!decision.allowed) return { status: 403, reason: decision.reason };
  return { status: 200, body: await listReports(tenantId) };
}

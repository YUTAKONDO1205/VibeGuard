import type { Response } from 'express';
import { requireAdmin, type AuthedRequest } from '../auth/require-admin';

export async function readAuditLog(req: AuthedRequest, res: Response) {
  requireAdmin(req);
  return res.json({ entries: [] });
}

export async function purgeAuditLog(req: AuthedRequest, res: Response) {
  requireAdmin(req);
  return res.status(204).end();
}

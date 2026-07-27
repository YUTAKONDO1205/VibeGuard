import type { Response } from 'express';
import { requireAdmin, type AuthedRequest } from '../auth/require-admin';

export async function listOrders(req: AuthedRequest, res: Response) {
  requireAdmin(req);
  return res.json({ orders: [] });
}

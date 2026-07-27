import type { Response } from 'express';
import { requireAdmin, type AuthedRequest } from '../auth/require-admin';

export async function renameTeam(req: AuthedRequest, res: Response) {
  requireAdmin(req);
  return res.json({ id: req.params.id, renamed: true });
}

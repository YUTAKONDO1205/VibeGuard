import type { Response } from 'express';
import type { AuthedRequest } from '../types';
import { saveTenantSettings } from '../store';

export async function updateTenant(req: AuthedRequest, res: Response) {
  const saved = await saveTenantSettings(req.body);
  return res.json({ saved });
}
